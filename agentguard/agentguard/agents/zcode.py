"""ZCode 适配器：复用 Claude Code 适配器，只覆盖与 ZCode 不同的部分。

ZCode（Z.ai 桌面端及其内置 glm agent，zcode.z.ai「Hooks」，实测内核 0.13.3）的 Hook 协议与 Claude Code 兼容：
同名事件（SessionStart / UserPromptSubmit / PreToolUse / PermissionRequest / PostToolUse / PostToolUseFailure /
Stop，没有 SessionEnd 与子 Agent 事件）、同样的 session_id / cwd / tool_name / tool_input / tool_use_id 字段、同样的
hookSpecificOutput.permissionDecision（allow / deny / ask，ask 由 ZCode 弹出确认），内置工具与 Claude Code 同名同参，
MCP 工具同为 `mcp__<server>__<tool>`。差异：
- Hook 输出按 schema 校验，不合法时该 Hook 记为失败并放行：只输出 hookSpecificOutput，事件名必须与当前事件一致；
- 没有 SessionEnd：会话随信封过期结束；ASK 的结论由 PostToolUse / PostToolUseFailure（批准）或 Stop（未执行）回填；
- agent_type（Agent 名称）只出现在 SessionStart / UserPromptSubmit / Stop，工具事件不带，不会被误标为子 Agent；
- 另有定时任务、工作流与会话内部状态工具（toolmap.classify_zcode）；
- trace 以 `zc-<device_id>-<session_id>` 命名，与其他 Agent 的会话互不混淆。
"""

from ..core.toolmap import classify_zcode
from .claude_code import ClaudeCodeAdapter

AGENT = "zcode"

CONFIRMATION_TEXT = {
    "APPROVED": "用户在 ZCode 确认框中批准，工具已执行",
    "NOT_EXECUTED": "轮次结束时工具未执行：用户在 ZCode 中拒绝或中止",
}


class ZCodeAdapter(ClaudeCodeAdapter):
    agent = AGENT
    trace_prefix = "zc"
    confirmation_text = CONFIRMATION_TEXT

    @staticmethod
    def classify(tool: str, tool_input: dict, cwd: str) -> list:
        return classify_zcode(tool, tool_input, cwd)
