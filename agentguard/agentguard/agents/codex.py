"""Codex 适配器：复用 Claude Code 适配器，只覆盖与 Codex 不同的部分。

Codex（实测 codex-cli 0.159.2）的 Hook 协议与 Claude Code 兼容：同名事件、同样的
session_id / tool_name / tool_input / tool_use_id 字段，MCP 工具同为 `mcp__<server>__<tool>`。
差异：
- 内置工具只有 `Bash`（{"command"}）与 `apply_patch`（{"command": 补丁正文}）两种名称；
- PreToolUse 只支持 `deny`：输出 `ask`/`allow` 会被判为 Hook 失败并**放行**。因此 ASK 一律渲染为
  deny，并立即记为“未执行”——Codex Hook 无法发起用户确认；
- trace 以 `cx-<device_id>-<session_id>` 命名，与 Claude Code 的 `cc-` 会话互不混淆。
"""

from ..core.toolmap import classify_codex, parse_patch  # noqa: F401  （测试经此导入）
from .claude_code import ClaudeCodeAdapter

AGENT = "codex"

CONFIRMATION_TEXT = {
    "APPROVED": "工具已执行",
    "NOT_EXECUTED": "Codex Hook 不支持发起用户确认，需确认的操作按拒绝处理",
}


def render_pre_tool(decision) -> dict | None:
    if decision is None or decision.decision == "ALLOW":
        return None
    if decision.decision == "DENY":
        reason = (f"Blocked by AgentGuard: {decision.reason_code} ({decision.decision_id}). "
                  "Do not retry this action through other tools.")
    else:
        reason = (f"AgentGuard requires user confirmation: {decision.reason_code} ({decision.decision_id}). "
                  "Codex hooks cannot prompt for confirmation, so the action was not run. "
                  "Tell the user what you wanted to do; they can run it themselves if they approve.")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


class CodexAdapter(ClaudeCodeAdapter):
    agent = AGENT
    trace_prefix = "cx"
    confirmation_text = CONFIRMATION_TEXT

    @staticmethod
    def classify(tool: str, tool_input: dict, cwd: str) -> list:
        return classify_codex(tool, tool_input, cwd)

    @staticmethod
    def render_pre_tool(decision) -> dict | None:
        return render_pre_tool(decision)

    def _on_ask(self, trace_id, state, call_id, decision) -> None:
        # ASK 已渲染为 deny，工具不会执行：立即记结论，不等 Post / Stop。
        self._record_resolution(trace_id, state, call_id, decision.decision_id, "NOT_EXECUTED")
