"""攻击链视图：把一个会话的事件、决策与证据快照组装为按时间排序的链路（设计 §5.7）。

任务 → 上下文/模型轮次 → 工具请求与决策 → 结果污点 → 外联 → 闭合。纯计算，快照由
RuntimeStore.build_trace() 在存储锁内采集；公共攻击链只带证据预览（脱敏 + 截断标记），不含证据原文。
"""

from ..detection import flow as F
from .metrics import scenario_of


def build_trace_view(trace_id: str, events: list, decisions: list, task, state, evidence: dict,
                     calls: dict, preview) -> dict:
    """evidence 为本会话涉及的证据记录（evidence_id -> 记录），preview 把一条记录转为公开预览。"""

    def previews(ids) -> list[dict]:
        return [preview(evidence[item]) for item in (ids or []) if item in evidence]

    decision_by_id = {d.decision_id: d for d in decisions}
    chain = []
    for event in events:
        node = event.as_dict()
        decision = decision_by_id.get(event.decision_id) if event.decision_id else None
        if decision is not None:
            node["decision"] = decision.as_dict()
        node["evidence"] = previews(node.get("evidence_ids"))
        # 有 call_id 却找不到对应 Hook 事件：标注证据不完整，不默默当作完整链路。
        if (event.call_id and event.stage == "TOOL_REQUEST" and event.source == "mcp-gateway"
                and not (calls.get(event.call_id) or {}).get("hook")):
            node["link_note"] = "hook_event_missing"
        chain.append(node)
    # 决策与事件的关联优先用 event.decision_id；缺失时按证据事件补齐，
    # 仍无法挂到链上事件的告警补独立“威胁告警”节点，保证告警不丢失。
    index_by_event = {node["event_id"]: index for index, node in enumerate(chain)}
    attached = {node.get("decision_id") for node in chain if node.get("decision_id")}
    for decision in decisions:
        if decision.decision_id in attached:
            continue
        targets = [index_by_event[event_id] for event_id in (decision.evidence_ids or [])
                   if event_id in index_by_event]
        if targets:
            node = chain[max(targets)]
            if not node.get("decision"):
                node["decision"] = decision.as_dict()
                attached.add(decision.decision_id)
    for decision in decisions:
        if decision.decision_id in attached:
            continue
        chain.append({
            "event_id": f"alert-{decision.decision_id}",
            "trace_id": trace_id,
            "stage": "THREAT_ALERT",
            "source": decision.server or "agentguard-engine",
            "timestamp": decision.created_at,
            "span_id": "",
            "parent_span_id": "",
            "actor": {},
            "component": "agentguard-engine",
            "mcp_server": decision.server,
            "tool": decision.tool,
            "resource": "",
            "labels": list(decision.labels),
            "payload_digest": "",
            "redacted_preview": decision.safe_message,
            "stack": [],
            "decision_id": decision.decision_id,
            "task_id": task.get("task_id", "") if isinstance(task, dict) else "",
            "round": 0,
            "attribution": "unknown",
            "evidence_ids": list(decision.evidence_ids),
            "entry": {},
            "evidence": previews(decision.evidence_ids),
            "decision": decision.as_dict(),
        })
    chain.sort(key=lambda node: node.get("timestamp") or "")
    return {
        "trace_id": trace_id,
        "scenario": scenario_of(trace_id),
        "task": task.as_dict() if hasattr(task, "as_dict") else task,
        "state": state.as_dict() if state else {},
        "chain": chain,
        "stages": F.chain_stages(chain),
    }
