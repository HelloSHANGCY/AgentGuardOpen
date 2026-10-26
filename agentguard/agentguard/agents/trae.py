"""Trae 适配器：复用 Claude Code 适配器，只覆盖与 Trae 不同的部分。

Trae（TraeCode / Trae CN，docs.trae.cn「Hook 配置详解」，实测 Trae CN 1.107）的 Hook 协议与 Claude Code 兼容：
同名事件（SessionStart / UserPromptSubmit / PreToolUse / PostToolUse / Stop / Notification，没有 SessionEnd、
PostToolUseFailure 与子 Agent 事件）、同样的 session_id / tool_name / tool_input / tool_use_id 字段、同样的
hookSpecificOutput.permissionDecision（allow / deny / ask，ask 由 Trae 弹出确认），MCP 工具同为
`mcp__<server>__<tool>`。差异：
- 命令执行工具名为 `RunCommand`（Windows 上执行 PowerShell 命令），另附 llm_tool_name（模型侧工具名）与
  workspace_roots；文件工具的参数已由 Trae 转换为 Claude Code 兼容格式，Edit 还覆盖补丁、删除等内部工具；
- 没有 SessionEnd：会话随信封过期结束；ASK 的结论仍由 PostToolUse（批准）或 Stop（未执行）回填；
- trace 以 `tr-<device_id>-<session_id>` 命名，与 Claude Code / Codex 的会话互不混淆。
"""

from ..core.toolmap import classify_trae
from .claude_code import ClaudeCodeAdapter

AGENT = "trae"

CONFIRMATION_TEXT = {
    "APPROVED": "用户在 Trae 确认框中批准，工具已执行",
    "NOT_EXECUTED": "轮次结束时工具未执行：用户在 Trae 中拒绝或中止",
}


class TraeAdapter(ClaudeCodeAdapter):
    agent = AGENT
    trace_prefix = "tr"
    confirmation_text = CONFIRMATION_TEXT

    @staticmethod
    def classify(tool: str, tool_input: dict, cwd: str) -> list:
        return classify_trae(tool, tool_input, cwd)
