"""WorkBuddy 适配器：复用 Claude Code 适配器，只覆盖与 WorkBuddy 不同的部分。

WorkBuddy（腾讯桌面端，内嵌 CodeBuddy Code 内核；命令行即 CodeBuddy Code，workbuddy.ai「Hook 参考指南」）的 Hook 协议
与 Claude Code 兼容：同名事件（SessionStart / UserPromptSubmit / PreToolUse / PostToolUse / PostToolUseFailure /
SubagentStart / SubagentStop / Stop / SessionEnd …）、同样的 session_id / cwd / tool_name / tool_input 字段、同样的
hookSpecificOutput.permissionDecision（allow / deny / ask），内置工具与 Claude Code 同名同参，MCP 工具同为
`mcp__<server>__<tool>`。差异：
- 文档中的 PreToolUse 载荷不含 tool_use_id：此时 ASK 的结论按先后顺序由下一个 Post 事件回填；
- 载荷另带 generation_id（一轮对话的标识）等字段，不参与判定；
- 另有代码智能、任务清单、定时任务与团队协作工具（toolmap.classify_workbuddy）；
- trace 以 `wb-<device_id>-<session_id>` 命名，与其他 Agent 的会话互不混淆。
"""

from ..core.toolmap import classify_workbuddy
from .claude_code import ClaudeCodeAdapter

AGENT = "workbuddy"

CONFIRMATION_TEXT = {
    "APPROVED": "用户在 WorkBuddy 确认框中批准，工具已执行",
    "NOT_EXECUTED": "轮次结束时工具未执行：用户在 WorkBuddy 中拒绝或中止",
}


class WorkBuddyAdapter(ClaudeCodeAdapter):
    agent = AGENT
    trace_prefix = "wb"
    confirmation_text = CONFIRMATION_TEXT
    ask_by_order = True

    @staticmethod
    def classify(tool: str, tool_input: dict, cwd: str) -> list:
        return classify_workbuddy(tool, tool_input, cwd)
