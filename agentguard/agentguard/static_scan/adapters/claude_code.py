"""Claude Code 适配器：项目内 Agent 配置资产（通用 Agent 接入设计 §12）。

识别项目级配置面（用户主目录下的 ~/.claude.json 不在项目扫描范围内）：
- .claude/settings.json、.claude/settings.local.json：权限、Hook 命令、MCP 自动启用开关；
- .mcp.json：MCP server（资产由 MCP 适配器建立，这里补充是否经 AgentGuard 中转）；
- CLAUDE.md / .claude/commands/*.md / .claude/agents/*.md：会进入模型上下文的指令文件；
- .claude/skills/*/SKILL.md：Skill 资产由 Skill 适配器建立，这里建立加载关系。
只读取事实写入资产元数据，风险判定由 rules/agent_config_rules.py 完成。
"""

import posixpath
import re

from .base import BaseAdapter, DiscoveryResult, build_asset, edge

SETTINGS_RE = re.compile(r"(^|/)\.claude/settings(\.local)?\.json$")
MCP_CONFIG_RE = re.compile(r"(^|/)\.(mcp|claude)\.json$")
INSTRUCTIONS_RE = re.compile(r"(^|/)(\.claude/)?CLAUDE(\.local)?\.md$")
COMMAND_RE = re.compile(r"(^|/)\.claude/commands/.+\.md$")
SUBAGENT_RE = re.compile(r"(^|/)\.claude/agents/.+\.md$")
SKILL_RE = re.compile(r"(^|/)\.claude/skills/")
# 经 AgentGuard stdio 包装器中转的 MCP server：终端客户端 `agentguard-endpoint mcp-proxy`，或旧版 agentguard_mcp_stdio.py。
LEGACY_WRAPPER_MARKER = "agentguard_mcp_stdio"
WRAPPER_SUBCOMMAND = "mcp-proxy"
GATEWAY_PATH_RE = re.compile(r"/mcp/[A-Za-z0-9_-]+/?$")


def is_wrapped(spec: dict, command_line: str) -> bool:
    args = [str(arg) for arg in spec.get("args") or []]
    head = args[:args.index("--")] if "--" in args else args
    return LEGACY_WRAPPER_MARKER in command_line or (
        WRAPPER_SUBCOMMAND in head and "agentguard" in command_line.lower())


def project_root(path: str) -> str:
    """配置文件所属的 Claude Code 项目根（.claude/ 的父目录或文件所在目录）。"""
    directory = posixpath.dirname(path)
    parts = directory.split("/") if directory else []
    if ".claude" in parts:
        parts = parts[:parts.index(".claude")]
    return "/".join(parts)


def _hooks(settings: dict) -> list:
    hooks = []
    for event, entries in (settings.get("hooks") or {}).items():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            for hook in entry.get("hooks") or []:
                if isinstance(hook, dict) and hook.get("type", "command") == "command":
                    hooks.append({"event": str(event), "matcher": str(entry.get("matcher") or ""),
                                  "command": str(hook.get("command") or "")})
    return hooks


class ClaudeCodeAdapter(BaseAdapter):
    name = "claude_code"

    def supports(self, facts) -> bool:
        return any(self._kind(entry.path) for entry in facts.index.files)

    @staticmethod
    def _kind(path: str) -> str:
        if SETTINGS_RE.search(path):
            return "settings"
        if MCP_CONFIG_RE.search(path):
            return "mcp_config"
        if INSTRUCTIONS_RE.search(path):
            return "instructions"
        if COMMAND_RE.search(path):
            return "command"
        if SUBAGENT_RE.search(path):
            return "subagent"
        return ""

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        agents: dict = {}

        def agent_for(path: str):
            root = project_root(path)
            if root not in agents:
                asset = build_asset(
                    context, "AgentApplication", f"claude-code:{root or '.'}", f"claude-code:{root or '.'}",
                    relative_path=posixpath.join(root, ".claude") if root else ".claude",
                    discovery_method="claude_code_config", confidence="high",
                    metadata={"adapter": self.name, "agent": "claude-code", "root": root, "hooks": [],
                              "instruction_files": []})
                agents[root] = asset
                result.assets.append(asset)
            return agents[root]

        for entry in sorted(facts.index.files, key=lambda item: item.path):
            kind = self._kind(entry.path)
            if not kind:
                continue
            agent = agent_for(entry.path)
            if kind == "mcp_config":
                self._mcp_config(facts, result, agent, entry.path)
                continue
            metadata = {"adapter": self.name, "claude_code": {"kind": kind}}
            if kind == "settings":
                data = self._json(facts, entry.path)
                hooks = _hooks(data)
                permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
                metadata["claude_code"].update({
                    "hooks": hooks,
                    "permissions": {key: permissions.get(key) for key in ("allow", "ask", "deny", "defaultMode")
                                    if key in permissions},
                    "enable_all_project_mcp": data.get("enableAllProjectMcpServers") is True,
                    "local": entry.path.endswith(".local.json"),
                })
                agent.metadata["hooks"].extend(hooks)
            else:
                doc = facts.markdown.get(entry.path)
                frontmatter = doc.frontmatter if doc else {}
                if kind == "subagent":
                    metadata["claude_code"]["tools"] = frontmatter.get("tools")
                agent.metadata["instruction_files"].append(entry.path)
            asset = build_asset(context, "ConfigArtifact", f"config:{entry.path}", posixpath.basename(entry.path),
                                relative_path=entry.path, content_digest=entry.digest,
                                discovery_method="claude_code_config", confidence="high", metadata=metadata)
            result.assets.append(asset)
            result.edges.append(edge(agent.asset_id, "CONFIGURED_BY", asset.asset_id,
                                     confidence="high", basis="declared"))
            result.evidence.append(facts.evidence_for(entry.path, line=1, excerpt=entry.path,
                                                      parser="claude_code", pointer="/"))

        for skill_dir, skill_md in facts.index.skill_markdowns().items():
            if not SKILL_RE.search(skill_md):
                continue
            skill = facts.asset_by_logical("Skill", f"skill:{skill_dir}")
            if skill is not None:
                result.edges.append(edge(agent_for(skill_md).asset_id, "LOADS_SKILL", skill.asset_id,
                                         confidence="high", basis="declared"))
        return result

    @staticmethod
    def _json(facts, path: str) -> dict:
        doc = facts.configs.get(path)
        return doc.data if doc is not None and isinstance(doc.data, dict) else {}

    def _mcp_config(self, facts, result, agent, path: str) -> None:
        servers = self._json(facts, path).get("mcpServers")
        for name, spec in (servers or {}).items() if isinstance(servers, dict) else []:
            if not isinstance(spec, dict):
                continue
            command_line = " ".join([str(spec.get("command") or "")] + [str(arg) for arg in spec.get("args") or []])
            url = str(spec.get("url") or "")
            server_id = facts.servers_by_name.get((path, name), facts.servers_by_name.get(name))
            server = facts.assets.get(server_id) if server_id else None
            if server is not None:
                server.metadata["claude_code"] = {
                    "config_path": path,
                    "wrapped": is_wrapped(spec, command_line),
                    "via_gateway": bool(url and GATEWAY_PATH_RE.search(url.split("?", 1)[0])),
                    "transport": "http" if url else "stdio",
                }
                result.edges.append(edge(agent.asset_id, "CONNECTS_TO", server.asset_id,
                                         confidence="high", basis="declared"))
