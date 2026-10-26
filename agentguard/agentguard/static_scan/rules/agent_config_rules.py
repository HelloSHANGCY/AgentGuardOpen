"""通用 Agent 配置规则 AG-STATIC-CC-001 ~ 005（通用 Agent 接入设计 §12）。

基于 claude_code 适配器写入的资产元数据判定；与运行时规则联动：
- CC-004（MCP 未经中转）对应运行时 R018；
- CC-005（指令文件注入）命中的文件被 Agent 读取时，运行时结果侧同样会打注入污点。
MCP env 中硬编码的密钥由既有 AG-STATIC-CFG-001 覆盖，这里不重复判定。
"""

from ...core.normalize import command_threats, injection_markers, matching_keywords, parse_command
from .base import make_finding

VERSION = "1.0"


class AgentConfigRuleBase:
    rule_version = VERSION
    category = "agent_config"
    title = "Agent 配置"

    def evaluate(self, facts, context):
        raise NotImplementedError

    @staticmethod
    def settings_assets(facts):
        for asset in facts.assets_of_kind("ConfigArtifact"):
            info = asset.metadata.get("claude_code") or {}
            if info.get("kind") == "settings":
                yield asset, info


class PermissiveAgentPermissionRule(AgentConfigRuleBase):
    rule_id = "AG-STATIC-CC-001"
    title = "Agent 权限过宽：跳过确认或通配授权高危工具"

    def evaluate(self, facts, context):
        findings = []
        for asset, info in self.settings_assets(facts):
            permissions = info.get("permissions") or {}
            reasons = []
            if permissions.get("defaultMode") == "bypassPermissions":
                reasons.append("defaultMode=bypassPermissions")
            allow = permissions.get("allow") if isinstance(permissions.get("allow"), list) else []
            # 通配授权条目来自特征规则库（agent.broad_tool_grant）。
            broad = sorted({str(item) for item in allow
                            if matching_keywords("agent.broad_tool_grant", str(item).strip(), exact=True, first=True)})
            if broad:
                reasons.append("allow=" + ",".join(broad))
            if not reasons:
                continue
            evidence = facts.evidence_for(asset.relative_path, line=0, excerpt="; ".join(reasons),
                                          parser="claude_code", pointer="/permissions")
            findings.append(make_finding(
                self, context, asset.asset_id, "HIGH", "high", evidence=[evidence],
                explanation=f"Claude Code 权限配置允许免确认执行高危工具：{'; '.join(reasons)}",
                remediation="移除 bypassPermissions 与通配授权，改为按命令前缀精确授权（如 Bash(npm test:*)）",
                limitations="仅检查已采集的配置快照；未验证用户级、项目级与受管配置的最终覆盖顺序",
                fingerprint_extra=f"cc-perm:{asset.relative_path}"))
        return findings


class AutoEnableProjectMcpRule(AgentConfigRuleBase):
    rule_id = "AG-STATIC-CC-002"
    title = "自动启用项目内全部 MCP server"

    def evaluate(self, facts, context):
        findings = []
        for asset, info in self.settings_assets(facts):
            if not info.get("enable_all_project_mcp"):
                continue
            evidence = facts.evidence_for(asset.relative_path, line=0, excerpt="enableAllProjectMcpServers: true",
                                          parser="claude_code", pointer="/enableAllProjectMcpServers")
            findings.append(make_finding(
                self, context, asset.asset_id, "MEDIUM", "high", evidence=[evidence],
                explanation="克隆的仓库中新增的 .mcp.json server 将不经用户确认直接启动",
                remediation="关闭 enableAllProjectMcpServers，逐个审核后加入 enabledMcpjsonServers",
                fingerprint_extra=f"cc-mcp-auto:{asset.relative_path}"))
        return findings


class RiskyHookCommandRule(AgentConfigRuleBase):
    rule_id = "AG-STATIC-CC-003"
    title = "Agent Hook 命令包含下载执行或网络外发"

    def evaluate(self, facts, context):
        findings = []
        for asset, info in self.settings_assets(facts):
            for hook in info.get("hooks") or []:
                command = hook.get("command") or ""
                if "agentguard" in command:
                    continue
                threats = command_threats(command)
                network = bool(parse_command(command)["urls"])
                if not threats and not network:
                    continue
                severity = "HIGH" if threats else "MEDIUM"
                evidence = facts.evidence_for(asset.relative_path, line=0,
                                              excerpt=f"{hook.get('event')}: {command[:160]}",
                                              parser="claude_code", pointer=f"/hooks/{hook.get('event')}")
                findings.append(make_finding(
                    self, context, asset.asset_id, severity, "high", evidence=[evidence],
                    explanation=(f"Hook 在 {hook.get('event')} 事件自动执行命令，"
                                 f"{'包含 ' + ','.join(threats) if threats else '会访问外部网络'}；"
                                 "Hook 以用户身份运行且不经过模型或权限确认"),
                    remediation="审查 Hook 来源；Hook 不应下载或外发数据，受管环境启用 allowManagedHooksOnly",
                    fingerprint_extra=f"cc-hook:{asset.relative_path}:{hook.get('event')}:{command[:80]}"))
        return findings


class UnmanagedMcpServerRule(AgentConfigRuleBase):
    rule_id = "AG-STATIC-CC-004"
    title = "MCP server 未经 AgentGuard 中转"

    def evaluate(self, facts, context):
        findings = []
        for asset in facts.assets_of_kind("MCPServer"):
            info = asset.metadata.get("claude_code")
            if not info or info.get("wrapped") or info.get("via_gateway"):
                continue
            evidence = facts.evidence_for(info["config_path"], line=0,
                                          excerpt=f"mcpServers.{asset.name}: {info.get('transport')}",
                                          parser="claude_code", pointer=f"/mcpServers/{asset.name}")
            findings.append(make_finding(
                self, context, asset.asset_id, "MEDIUM", "high", evidence=[evidence],
                explanation=f"{asset.name} 由 Agent 直连，工具清单投毒、隐藏工具与返回注入检查不生效",
                remediation="运行 agentguard-endpoint wrap-mcp 包装 stdio server；HTTP server 登记到网关后改指向 /mcp/<name>",
                limitations="运行时仍由 Hook 按 AG-RUNTIME-018 处理未受管 server",
                fingerprint_extra=f"cc-mcp:{asset.name}"))
        return findings


class AgentInstructionInjectionRule(AgentConfigRuleBase):
    rule_id = "AG-STATIC-CC-005"
    title = "Agent 指令文件包含提示注入"

    def evaluate(self, facts, context):
        findings = []
        for asset in facts.assets_of_kind("ConfigArtifact"):
            info = asset.metadata.get("claude_code") or {}
            if info.get("kind") not in ("instructions", "command", "subagent"):
                continue
            doc = facts.markdown.get(asset.relative_path)
            text = doc.all_text() if doc else ""
            markers = injection_markers(text)
            if not markers:
                continue
            line = next((index for index, row in enumerate(text.splitlines(), 1)
                         if any(marker.lower() in row.lower() for marker in markers)), 0)
            evidence = facts.evidence_for(asset.relative_path, line=line, excerpt=", ".join(markers),
                                          parser="markdown", pointer="/")
            findings.append(make_finding(
                self, context, asset.asset_id, "HIGH", "medium", evidence=[evidence],
                explanation=f"{info.get('kind')} 文件会进入模型上下文，包含注入特征：{', '.join(markers[:4])}",
                remediation="删除隐藏指令；来自第三方仓库的 CLAUDE.md / 命令 / 子 Agent 需人工审查后再使用",
                limitations="基于关键词特征，引用或讨论注入手法的文档可能误报",
                fingerprint_extra=f"cc-inject:{asset.relative_path}"))
        return findings
