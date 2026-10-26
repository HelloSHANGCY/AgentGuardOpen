"""CodeBuddy IDE Hook 适配（codebuddy.cn/docs/ide/Features/Hooks）。

官方七类事件使用 Claude 兼容信封，文件参数也可能使用 filePath / new_str。
没有 tool_use_id 时按顺序关联 ASK 与 Post；并行调用的关联仍需实机验证。
"""

from ..core.toolmap import classify_codebuddy
from .claude_code import ClaudeCodeAdapter, render_pre_tool


class CodeBuddyAdapter(ClaudeCodeAdapter):
    agent = "codebuddy"
    trace_prefix = "cb"
    ask_by_order = True
    confirmation_text = {
        "APPROVED": "用户在 CodeBuddy 确认框中批准，工具已执行",
        "NOT_EXECUTED": "轮次结束时工具未执行：用户在 CodeBuddy 中拒绝或中止",
    }

    @staticmethod
    def classify(tool: str, tool_input: dict, cwd: str) -> list:
        return classify_codebuddy(tool, tool_input, cwd)

    @staticmethod
    def render_pre_tool(decision) -> dict | None:
        output = render_pre_tool(decision)
        if output:
            output["continue"] = decision.decision != "DENY"
        return output
