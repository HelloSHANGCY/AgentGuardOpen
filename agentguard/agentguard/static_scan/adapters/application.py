"""基于入口与配置事实的 Agent 应用适配器。

组合证据：应用入口 + Agent 初始化 + 工具/模型/MCP/Skill 配置。
无明确证据的目录不会被识别为 Agent；模型引用只表示配置声明，不证明已部署。
"""

import ast
from urllib.parse import urlsplit

from ..parsers.py_ast import getenv_info, line_excerpt
from .base import BaseAdapter, DiscoveryResult, build_asset, edge

SECRET_KEY_HINTS = ("secret", "token", "key", "password", "passwd", "credential", "dsn")

AGENT_SIGNALS = ("MCP_SERVICES", "DEFAULT_MODEL", "LLM_BASE", "skill_catalog", "SKILLS_ROOT",
                 "OPENAI_TOOL_ROUTES", "agent_messages")


class ApplicationAdapter(BaseAdapter):
    name = "application"

    def supports(self, facts) -> bool:
        return any(self._is_agent_module(module) for module in facts.py_modules.values())

    @staticmethod
    def _is_agent_module(module) -> bool:
        if module.parse_error:
            return False
        source = module.source or ""
        if "MCP_SERVICES" in module.module_assigns:
            return True
        signals = sum(1 for marker in AGENT_SIGNALS if marker in source)
        return signals >= 3 and "FastAPI(" in source

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        for path, module in sorted(facts.py_modules.items()):
            if not self._is_agent_module(module):
                continue
            entry = facts.index.get(path)
            title = self._app_title(module) or path.rsplit("/", 1)[-1]
            app = build_asset(
                context, "AgentApplication", f"app:{path}", title, relative_path=path,
                content_digest=entry.digest if entry else "",
                discovery_method="entry_and_config", confidence="high",
                metadata={"adapter": self.name, "entry": path, "files": [path],
                          "declared_roles": module.constants.get("SYSTEM_PROMPT").value
                          if "SYSTEM_PROMPT" in module.constants else "",
                          "detection_signals": sorted(marker for marker in AGENT_SIGNALS if marker in module.source)},
            )
            result.assets.append(app)
            result.evidence.append(facts.evidence_for(
                path, line=1, excerpt=f"agent entry {path}", parser="ast", pointer="/entry"))

            self._link_frameworks(facts, result, module, app)
            self._discover_models(facts, context, result, path, module, app)
            self._discover_mcp_services(facts, context, result, path, module, app)
            self._discover_tool_routes(facts, context, result, path, module, app)
            self._link_skills(facts, result, path, module, app)
            self._collect_env_defaults(facts, context, result, path, module, app)
        return result

    @staticmethod
    def _app_title(module) -> str:
        for node in _iter_calls(module.tree):
            if _callee(module, node) == "FastAPI":
                for keyword in node.keywords:
                    if keyword.arg != "title":
                        continue
                    if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        return keyword.value.value
                    if isinstance(keyword.value, ast.Name):
                        value = module.constants.get(keyword.value.id)
                        if value is not None and isinstance(value.value, str):
                            return value.value
        return ""

    def _link_frameworks(self, facts, result, module, app) -> None:
        roots = {(item.module or item.name).split(".")[0] for item in module.imports}
        for root in sorted(roots):
            target = facts.asset_by_logical("Framework", f"framework:pypi:{root}")
            if target is not None:
                result.edges.append(edge(app.asset_id, "USES_FRAMEWORK", target.asset_id,
                                         confidence="high", basis="declared",
                                         metadata={"package": root}))

    def _discover_models(self, facts, context, result, path, module, app) -> None:
        model_id = _const_str(module, "DEFAULT_MODEL")
        base_url = _const_or_env_default(module, "LLM_BASE")
        if not model_id and not base_url:
            return
        provider = "openai-compatible" if base_url else "unknown"
        host = _host_of(base_url)
        identity = f"{model_id or '<unknown>'}@{host or 'unknown'}"
        stub = "stub" in (model_id or "").lower() or "stub" in (base_url or "").lower()
        asset = build_asset(
            context, "ModelReference", f"model:{identity}", model_id or identity,
            relative_path=path, discovery_method="agent_config",
            confidence="high" if model_id else "medium",
            metadata={"adapter": self.name, "model": model_id, "provider": provider,
                      "service_host": host, "base_url_config": bool(base_url),
                      "stub": stub,
                      "note": "配置引用，不代表已部署或已验证权重"},
        )
        result.assets.append(asset)
        evidence_line = _assign_line(module, "DEFAULT_MODEL") or _assign_line(module, "LLM_BASE") or 1
        result.evidence.append(facts.evidence_for(
            path, line=evidence_line, excerpt=line_excerpt(module.source, evidence_line),
            parser="ast", pointer="/model"))
        result.edges.append(edge(app.asset_id, "USES_MODEL", asset.asset_id,
                                 confidence="high", basis="declared"))

    def _discover_mcp_services(self, facts, context, result, path, module, app) -> None:
        services = module.constants.get("MCP_SERVICES")
        if services is None or not isinstance(services.value, dict):
            return
        line = _assign_line(module, "MCP_SERVICES") or 1
        for name, url in services.value.items():
            if not isinstance(url, str):
                continue
            target_id = facts.servers_by_name.get(name)
            evidence = facts.evidence_for(
                path, line=line, excerpt=f"{name} = {_redact_url(url)}",
                parser="ast", pointer=f"/MCP_SERVICES/{name}")
            result.evidence.append(evidence)
            if target_id:
                target = facts.assets.get(target_id)
            else:
                target = build_asset(
                    context, "MCPServer", f"mcp:{name}", name, relative_path=path,
                    discovery_method="agent_config", confidence="medium",
                    metadata={"adapter": self.name, "transport": "http",
                              "endpoint": _host_of(url), "declared_by": app.name},
                )
                result.assets.append(target)
                facts.servers_by_name[name] = target.asset_id
            result.edges.append(edge(app.asset_id, "CONNECTS_TO", target.asset_id,
                                     confidence="high", basis="declared",
                                     evidence_ids=[evidence.evidence_id],
                                     metadata={"endpoint": _host_of(url)}))

    def _discover_tool_routes(self, facts, context, result, path, module, app) -> None:
        routes = module.constants.get("OPENAI_TOOL_ROUTES")
        if routes is None or not isinstance(routes.value, dict):
            return
        line = _assign_line(module, "OPENAI_TOOL_ROUTES") or 1
        for openai_name, route in routes.value.items():
            if not (isinstance(route, (list, tuple)) and len(route) == 2):
                continue
            server, tool_name = str(route[0]), str(route[1])
            tool_asset = facts.asset_by_logical("Tool", f"tool:{server}:{tool_name}") or build_asset(
                context, "Tool", f"tool:{server}:{tool_name}", tool_name, relative_path=path,
                discovery_method="agent_route_table", confidence="medium",
                metadata={"adapter": self.name, "server": server, "declared": True,
                          "openai_name": openai_name},
            )
            if tool_asset.asset_id not in facts.assets:
                result.assets.append(tool_asset)
            evidence = facts.evidence_for(
                path, line=line, excerpt=f"{openai_name} -> {server}.{tool_name}",
                parser="ast", pointer=f"/OPENAI_TOOL_ROUTES/{openai_name}")
            result.evidence.append(evidence)
            result.edges.append(edge(app.asset_id, "EXPOSES_TOOL", tool_asset.asset_id,
                                     confidence="high", basis="declared",
                                     evidence_ids=[evidence.evidence_id]))
            server_id = facts.servers_by_name.get(server)
            if server_id:
                result.edges.append(edge(tool_asset.asset_id, "HANDLED_BY", server_id,
                                         confidence="high", basis="declared"))

    def _link_skills(self, facts, result, path, module, app) -> None:
        if "SKILLS_ROOT" not in module.source and "load_skill" not in module.source:
            return
        line = _assign_line(module, "SKILLS_ROOT") or 1
        for skill in facts.assets_of_kind("Skill"):
            evidence = facts.evidence_for(
                path, line=line, excerpt=f"skill root -> {skill.name}", parser="ast",
                pointer="/SKILLS_ROOT")
            result.evidence.append(evidence)
            result.edges.append(edge(app.asset_id, "LOADS_SKILL", skill.asset_id,
                                     confidence="high" if "SKILLS_ROOT" in module.source else "medium",
                                     basis="declared", evidence_ids=[evidence.evidence_id]))

    def _collect_env_defaults(self, facts, context, result, path, module, app) -> None:
        for name in sorted(module.module_assigns):
            node = module.module_assigns[name]
            info = getenv_info(getattr(node, "value", None))
            if info is None:
                continue
            key, default = info
            node = module.module_assigns[name]
            line = getattr(node, "lineno", 0)
            fact = {"path": path, "line": line, "key": key, "default": default, "symbol": name}
            facts.env_defaults.append(fact)
            if not any(hint in key.lower() for hint in SECRET_KEY_HINTS):
                continue
            secret_id = facts.secret_refs.get(key)
            if secret_id is None:
                secret = build_asset(
                    context, "SecretReference", f"secret:{key}", key, relative_path=path,
                    discovery_method="env_read", confidence="high",
                    metadata={"adapter": self.name, "variable": key,
                              "has_static_default": default is not None},
                )
                result.assets.append(secret)
                facts.secret_refs[key] = secret.asset_id
                secret_id = secret.asset_id
                evidence = facts.evidence_for(
                    path, line=line, excerpt=line_excerpt(module.source, line) or f"getenv {key}",
                    parser="ast", pointer=f"/{name}")
                result.evidence.append(evidence)
            result.edges.append(edge(app.asset_id, "READS_SECRET", secret_id,
                                     confidence="high", basis="declared"))


def _iter_calls(tree):
    import ast
    if tree is None:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _callee(module, node) -> str:
    import ast
    func = node.func
    if isinstance(func, ast.Name):
        return module.aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _const_str(module, name: str) -> str:
    value = module.constants.get(name)
    return value.value if value is not None and isinstance(value.value, str) else ""


def _const_or_env_default(module, name: str) -> str:
    if name in module.constants:
        value = module.constants[name]
        if isinstance(value.value, str):
            return value.value
    info = module.env_read(name)
    if info and isinstance(info[1], str):
        return info[1]
    return ""


def _assign_line(module, name: str) -> int:
    node = module.module_assigns.get(name)
    return getattr(node, "lineno", 0) if node is not None else 0


def _host_of(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return host


def _redact_url(url: str) -> str:
    host = _host_of(url)
    return f"{urlsplit(url).scheme}://{host}" if host else "<invalid-url>"
