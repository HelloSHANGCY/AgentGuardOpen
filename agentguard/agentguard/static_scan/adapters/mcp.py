"""MCP 适配器：源码注册器、通用 mcpServers 配置与隐藏工具证据。

静态对应规则（方案 §2 / §5.2）：
- `create_server` 收集的 Tool 全量进入 registry（可调用集合）；
- `tools/list` 过滤 hidden（声明集合）；
- 两者差异即“隐藏但可调用”的静态证据，规则 MCP-001 据此判定。
"""

import re
from urllib.parse import urlsplit

from ..parsers.py_ast import line_excerpt
from .base import BaseAdapter, DiscoveryResult, build_asset, edge

DISPATCH_MARKERS = ("tools/list", "tools/call")
SECRET_KEY_HINTS = ("secret", "token", "key", "password", "passwd", "credential")


class MCPAdapter(BaseAdapter):
    name = "mcp"

    def supports(self, facts) -> bool:
        if any(module.server_decls for module in facts.py_modules.values() if not module.parse_error):
            return True
        return any(self._generic_servers(doc) for doc in facts.configs.values())

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        dispatch_evidence = self._dispatch_evidence(facts)

        for path, module in facts.py_modules.items():
            if module.parse_error:
                continue
            for server in module.server_decls:
                self._discover_server_source(facts, context, result, path, module, server, dispatch_evidence)

        for path, doc in facts.configs.items():
            for name, config in self._generic_servers(doc).items():
                self._discover_generic(facts, context, result, path, name, config)
        return result

    # ---- 源码注册器 ----

    def _discover_server_source(self, facts, context, result, path, module, server,
                                dispatch_evidence) -> None:
        server_asset = build_asset(
            context, "MCPServer", f"mcp:{server.name}", server.name, relative_path=path,
            discovery_method="source_registration", confidence="high",
            metadata={"adapter": self.name, "transport": "http", "var": server.var_name,
                      "on_start": server.on_start},
        )
        result.assets.append(server_asset)
        server_entry = facts.index.get(path)
        if server_entry is not None:
            server_asset.content_digest = server_entry.digest
        result.evidence.append(facts.evidence_for(
            path, line=server.lineno, excerpt=line_excerpt(module.source, server.lineno),
            parser="ast"))
        facts.servers_by_name[server.name] = server_asset.asset_id

        tool_rows = [tool for tool in module.tool_decls]
        for tool in tool_rows:
            tool_asset = build_asset(
                context, "Tool", f"tool:{server.name}:{tool.name}", tool.name,
                relative_path=path, discovery_method="source_registration",
                confidence="high",
                metadata={"adapter": self.name, "server": server.name,
                          "description": tool.description, "schema": tool.schema,
                          "handler": tool.handler, "handler_file": path,
                          "hidden": bool(tool.hidden)},
            )
            result.assets.append(tool_asset)
            tool_evidence = facts.evidence_for(
                path, line=tool.lineno,
                excerpt=line_excerpt(module.source, tool.lineno) or f"Tool({tool.name!r})",
                parser="ast")
            result.evidence.append(tool_evidence)
            if tool.handler:
                facts.mcp_handlers[(path, tool.handler)] = tool_asset.asset_id
                handler_line = module.functions[tool.handler].lineno if tool.handler in module.functions else tool.lineno
                result.evidence.append(facts.evidence_for(
                    path, line=handler_line, excerpt=f"handler {tool.handler}",
                    parser="ast", pointer=f"/handler/{tool.handler}"))
            result.edges.append(edge(server_asset.asset_id, "EXPOSES_TOOL", tool_asset.asset_id,
                                     confidence="high", basis="declared",
                                     evidence_ids=[tool_evidence.evidence_id]))
            if tool.hidden:
                server_asset.metadata.setdefault("hidden_tools", []).append(tool.name)
                tool_asset.metadata["callable_via_dispatch"] = True
                for item in dispatch_evidence:
                    if item.evidence_id not in tool_asset.metadata.setdefault("dispatch_evidence", []):
                        tool_asset.metadata["dispatch_evidence"].append(item.evidence_id)

        if server.on_start:
            facts.mcp_on_start[(path, server.on_start)] = server_asset.asset_id
            handler_line = module.functions[server.on_start].lineno if server.on_start in module.functions else server.lineno
            result.evidence.append(facts.evidence_for(
                path, line=handler_line, excerpt=f"on_start={server.on_start}",
                parser="ast", pointer=f"/on_start/{server.on_start}"))

        # 若该模块自身就是注册器实现（mcp_base），把 dispatch 证据挂到服务资产备注。
        if not server_asset.metadata.get("dispatch_evidence") and dispatch_evidence:
            server_asset.metadata["dispatch_evidence"] = [item.evidence_id for item in dispatch_evidence]

    # ---- 通用 mcpServers 配置 ----

    @staticmethod
    def _generic_servers(doc) -> dict:
        data = doc.data if isinstance(doc.data, dict) else {}
        servers = data.get("mcpServers", data.get("mcp_servers"))
        return servers if isinstance(servers, dict) else {}

    def _discover_generic(self, facts, context, result, path, name, config) -> None:
        if not isinstance(config, dict):
            return
        url = str(config.get("url") or "")
        command = str(config.get("command") or "")
        transport = "http" if url else ("stdio" if command or config.get("command") else "unknown")
        endpoint = _endpoint_summary(url)
        asset = build_asset(
            context, "MCPServer", f"mcp-config:{path}:{name}" if context.device_id else f"mcp:{name}", name, relative_path=path,
            discovery_method="mcp_config", confidence="high",
            metadata={"adapter": self.name, "transport": transport,
                      "endpoint": endpoint, "command_basename": command.rsplit("/", 1)[-1],
                      "env_names": sorted((config.get("env") or {}).keys()),
                      "has_auth_config": bool(config.get("headers") or config.get("auth")),
                      "config_pointer": f"mcpServers.{name}"},
        )
        result.assets.append(asset)
        facts.servers_by_name.setdefault(name, asset.asset_id)
        facts.servers_by_name[(path, name)] = asset.asset_id
        result.evidence.append(facts.evidence_for(
            path, line=0, excerpt=f"mcpServers.{name}: {transport}",
            parser="config", pointer=f"/mcpServers/{name}"))
        for key in sorted((config.get("env") or {}).keys()):
            secret = self._secret_asset(facts, context, result, path, key, f"mcpServers.{name}.env.{key}")
            if secret:
                result.edges.append(edge(asset.asset_id, "READS_SECRET", secret.asset_id,
                                         confidence="medium", basis="declared"))
        if url:
            endpoint_asset = build_asset(
                context, "Endpoint", f"endpoint:{endpoint}", endpoint, relative_path=path,
                discovery_method="mcp_config", confidence="medium",
                metadata={"adapter": self.name, "protocol": urlsplit(url).scheme,
                          "redacted": endpoint},
            )
            result.assets.append(endpoint_asset)
            result.edges.append(edge(asset.asset_id, "CONNECTS_TO", endpoint_asset.asset_id,
                                     confidence="medium", basis="declared"))

    def _secret_asset(self, facts, context, result, path, key, pointer):
        if not any(hint in key.lower() for hint in SECRET_KEY_HINTS):
            return None
        asset = build_asset(
            context, "SecretReference", f"secret:{key}", key, relative_path=path,
            discovery_method="mcp_config", confidence="high",
            metadata={"adapter": self.name, "variable": key, "pointer": pointer},
        )
        result.assets.append(asset)
        result.evidence.append(facts.evidence_for(
            path, line=0, excerpt=f"env {key}", parser="config", pointer=pointer))
        return asset

    # ---- 注册器实现证据 ----

    @staticmethod
    def _dispatch_evidence(facts):
        evidence = []
        for path, module in facts.py_modules.items():
            source = module.source
            if not all(marker in source for marker in DISPATCH_MARKERS):
                continue
            if "hidden" not in source or "registry" not in source:
                continue
            for lineno, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                if "hidden" in stripped or re.search(r"registry\s*=", stripped) or "registry.get" in stripped:
                    if stripped and not stripped.startswith("#"):
                        evidence.append(facts.evidence_for(
                            path, line=lineno, excerpt=stripped, parser="ast"))
        return evidence[:12]


def _endpoint_summary(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    if parts.username:
        host = f"<credentials>@{host}"
    return host or "<invalid-url>"
