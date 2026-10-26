"""污点标签模型与传播规则。

标签只能被可信规则增加或降敏；摘要、编码、Base64、JSON 包装不清除污点。
"""

import json

from ..core.normalize import injection_markers, is_sensitive_path, sensitive_content_types
from .anomaly import BehaviorState
from .flow import FlowState
from .provenance import SourceIndex

# 来源标签（见设计 §6.1）
USER_INPUT = "USER_INPUT"
UNTRUSTED_TICKET = "UNTRUSTED_TICKET"
UNTRUSTED_WEB = "UNTRUSTED_WEB"
UNTRUSTED_PR = "UNTRUSTED_PR"
UNTRUSTED_RAG = "UNTRUSTED_RAG"
UNTRUSTED_SKILL = "UNTRUSTED_SKILL"
UNTRUSTED_MCP = "UNTRUSTED_MCP"
SENSITIVE_CONFIG = "SENSITIVE_CONFIG"
PII = "PII"
CREDENTIAL = "CREDENTIAL"
MASS_DATA = "MASS_DATA"
POISONED_RESULT = "POISONED_RESULT"

# 进入网络 Sink 时默认 DENY 的高敏标签（设计 §6.3）。
EGRESS_BLOCKING_LABELS = {SENSITIVE_CONFIG, CREDENTIAL, PII, MASS_DATA}

# 网络型 Sink 工具：内容会离开受控环境。
NETWORK_SINK_TOOLS = {
    ("notes-sync", "sync_note"),
    ("notes-sync", "debug_exec"),
    ("shell-runner", "run"),
}


def result_taints(server: str, tool: str, arguments: dict, result) -> list[str]:
    """工具返回内容的污点标记，由网关在转发后统一计算。"""
    labels: list[str] = []
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)

    if server == "shell-runner" and tool == "read_file":
        if is_sensitive_path(arguments.get("path", "")):
            labels += [SENSITIVE_CONFIG, CREDENTIAL]
    elif server == "customer-db" and tool == "query":
        labels.append(PII)
        if arguments.get("tenant") == "*":
            labels.append(MASS_DATA)
    elif server == "gitlab":
        labels.append(UNTRUSTED_PR)
    elif server == "knowledge":
        labels.append(UNTRUSTED_RAG)
    elif server == "threat-intel":
        labels.append(UNTRUSTED_WEB)
    elif server == "notes-sync":
        labels.append(UNTRUSTED_MCP)

    # 返回内容本身包含敏感值或注入指令时，无论工具类型都补标。
    return content_taints(text, labels)


def content_taints(text: str, labels: list[str] | None = None) -> list[str]:
    """与工具无关的内容污点：敏感配置值 / 注入指令。在已有标签上追加并去重。"""
    labels = list(labels or [])
    for _ in sensitive_content_types(text):
        if _ not in labels and _ in (SENSITIVE_CONFIG, CREDENTIAL):
            labels.append(_)
    if injection_markers(text) and POISONED_RESULT not in labels:
        labels.append(POISONED_RESULT)
    return labels


def capability_taints(calls: list, result_text: str) -> list[str]:
    """通用 Agent 内置工具返回的污点：按能力与资源定来源，再叠加内容检查。"""
    from ..core.capability import FILE_READ, NET_FETCH, NET_SEARCH

    labels: list[str] = []
    for call in calls or []:
        if call.capability == FILE_READ and is_sensitive_path(call.resource):
            for label in (SENSITIVE_CONFIG, CREDENTIAL):
                if label not in labels:
                    labels.append(label)
        elif call.capability in (NET_FETCH, NET_SEARCH) and UNTRUSTED_WEB not in labels:
            labels.append(UNTRUSTED_WEB)
    return content_taints(result_text, labels)


class TaskTaintState:
    """单个任务（trace）的污点与调用历史，供引擎与攻击链使用。"""

    def __init__(self) -> None:
        self.taints: set[str] = set()
        self.tool_history: list[dict] = []
        # 参数来源归因的来源索引：用户指令与工具返回（创新检测实施方案 §3）。
        self.sources = SourceIndex()
        # 数据流溯源：秘密指纹与暂存物（创新检测实施方案 §4）。
        self.flow = FlowState()
        # 行为基线：上一行为符号与用户意图（创新检测实施方案 §5）。
        self.behavior = BehaviorState()

    def observe_call(self, server: str, tool: str, arguments: dict, decision: str) -> None:
        self.tool_history.append({"server": server, "tool": tool, "decision": decision})

    def observe_result(self, labels: list[str]) -> None:
        self.taints.update(labels)

    def has_blocking_taint(self) -> bool:
        return bool(self.taints & EGRESS_BLOCKING_LABELS)
