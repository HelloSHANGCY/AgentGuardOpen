"""Qoder 适配器：复用 Claude Code 适配器，只覆盖与 Qoder 不同的部分。

Qoder（Qoder IDE / Qoder CN IDE / JetBrains 插件 / Qoder CLI，docs.qoder.com 与 docs.qoder.cn「Hooks」，
实测 Qoder CN 1.106）的 Hook 协议与 Claude Code 兼容：同名事件（SessionStart / UserPromptSubmit / PreToolUse /
PostToolUse / PostToolUseFailure / SubagentStart / SubagentStop / Stop / SessionEnd …，各版本支持的子集不同）、
同样的 session_id / tool_name / tool_input / hookSpecificOutput.permissionDecision（allow / deny / ask），
MCP 工具同为 `mcp__<server>__<tool>`。差异：
- tool_name 是原生工具名（run_in_terminal / read_file / create_file / search_replace / edit_file / delete_file /
  list_dir …），参数也是原生格式（toolmap.classify_qoder 统一映射）；tool_response 在 IDE 中通常是字符串；
- PreToolUse 不保证带 tool_use_id：此时 ASK 的结论按先后顺序由下一个 Post 事件回填；
- trace 以 `qd-<device_id>-<session_id>` 命名，与其他 Agent 的会话互不混淆。
"""

from ..core.toolmap import classify_qoder
from .claude_code import ClaudeCodeAdapter

AGENT = "qoder"

CONFIRMATION_TEXT = {
    "APPROVED": "用户在 Qoder 确认框中批准，工具已执行",
    "NOT_EXECUTED": "轮次结束时工具未执行：用户在 Qoder 中拒绝或中止",
}


class QoderAdapter(ClaudeCodeAdapter):
    agent = AGENT
    trace_prefix = "qd"
    confirmation_text = CONFIRMATION_TEXT
    ask_by_order = True

    @staticmethod
    def classify(tool: str, tool_input: dict, cwd: str) -> list:
        return classify_qoder(tool, tool_input, cwd)
