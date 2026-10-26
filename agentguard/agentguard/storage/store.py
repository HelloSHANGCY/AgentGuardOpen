"""统一运行时事件 / 决策存储（设计 §5.7 / §13）；攻击链组装见 trace.py，指标计算见 metrics.py。

- 原始事件只追加，不原地覆盖；决策引用真实存在的 evidence_id；
- 线程安全（同步数据面 + 控制面并发访问）；
- 可选 SQLite 持久化（persist.py，配置了数据目录时开启）：写入异步落盘，启动时加载保留期内最新的数据；
- SSE 订阅者使用线程安全队列，网关侧只承诺实时快照流。
"""

import json
import queue
import threading
import time
from collections import Counter, deque

from ..detection import flow as F
from ..detection import taint as T
from ..models import (
    Decision,
    RuleMatch,
    RuntimeEvent,
    mask_secrets,
    new_id,
    redact_text,
    risk_snippets,
    sha256_digest,
    utc_now_ms,
)
from .metrics import cpu_snapshot, percentiles, scenario_summary
from .persist import RuntimeDB
from .trace import build_trace_view

MAX_EVENTS = 50000
MAX_EVIDENCE = 20000
MAX_EVIDENCE_CHARS = 8000
# 超长证据按 head+tail 保留：尾部片段可定位“风险在末尾”的场景，中间关键命中另存 snippets。
EVIDENCE_TAIL_CHARS = 2000
# 公共查询返回的证据预览长度；超出部分带截断标记。
EVIDENCE_PREVIEW_CHARS = 200
# 工具返回事件上与污点无关的附加标签：从事件恢复会话污点时排除。
NON_TAINT_LABELS = {"GATEWAY_TAINT", "SECRET_LEARNED", "RELAY_BYPASS"}
RESULT_STAGES = ("TOOL_RESULT", "TOOL_RESULT_HOOK")
EVENT_FIELDS = set(RuntimeEvent.__dataclass_fields__)
DECISION_FIELDS = set(Decision.__dataclass_fields__)


def _bounded_content(text: str, limit: int = MAX_EVIDENCE_CHARS,
                     tail: int = EVIDENCE_TAIL_CHARS) -> tuple[str, bool, int]:
    """把脱敏后的超长文本压到存储预算内，返回 (内容, 是否存储截断, 省略字符数)。"""
    if len(text) <= limit:
        return text, False, 0
    marker = f"\n...({len(text) - limit} chars omitted)...\n"
    head_len = max(0, limit - tail - len(marker))
    stored = text[:head_len] + marker + text[-tail:]
    return stored, True, len(text) - head_len - tail


class TaskRuntimeState(T.TaskTaintState):
    """任务级运行时状态：污点 + 历史 + 决策计数。"""

    def __init__(self) -> None:
        super().__init__()
        self.started_at = time.time()
        self.last_seen = self.started_at
        self.rounds = 0   # 通用 Agent 会话内的用户轮次（UserPromptSubmit 计数）
        self.decisions = Counter()
        self.allowed_calls: deque = deque(maxlen=64)  # (timestamp, server) 用于外联父调用关联
        self.pending_asks: dict[str, str] = {}  # call_id -> 等待原生确认的 ASK decision_id
        # 会话起始工作目录（项目根）。Hook 的 cwd 随 Agent 内 cd 变化，越界写入同时以它为工作区（R020）。
        self.workspace = ""

    def as_dict(self) -> dict:
        return {
            "taints": sorted(self.taints),
            "tool_history": self.tool_history[-16:],
            "decisions": dict(self.decisions),
            "started_at": self.started_at,
        }


class RuntimeStore:
    def __init__(self, db_path: str = "", retention_days: float = 7.0) -> None:
        self._lock = threading.RLock()
        self.events: deque = deque(maxlen=MAX_EVENTS)
        self._events_by_id: dict[str, RuntimeEvent] = {}
        self.decisions: deque = deque(maxlen=MAX_EVENTS)
        self._decisions_by_id: dict[str, Decision] = {}
        self.events_by_trace: dict[str, list] = {}
        self.decisions_by_trace: dict[str, list] = {}
        self.tasks: dict = {}
        self.states: dict[str, TaskRuntimeState] = {}
        # 受控证据存储：原文（已脱敏）只在此保留，公共 API 仅返回预览。
        self.evidence: dict[str, dict] = {}
        self._evidence_ids: deque = deque()
        self._trace_links: dict[str, dict] = {}
        self.rule_hits: Counter = Counter()
        self.decision_latencies: deque = deque(maxlen=20000)
        self.forward_latencies: deque = deque(maxlen=20000)
        self._subscribers: list[queue.Queue] = []
        # 设备级暂存物登记表：同一设备跨会话关联分步外发（创新检测实施方案 §4）。
        self._device_artifacts: dict[str, F.DeviceArtifacts] = {}
        self.db = RuntimeDB(db_path, retention_days) if db_path else None
        if self.db is not None:
            self._load()

    # ---- 持久化 ----

    def _save_event(self, event: RuntimeEvent) -> None:
        if self.db is not None:
            self.db.put("events", event.event_id, event.trace_id, event.timestamp, event.as_dict())

    def _save_decision(self, decision: Decision) -> None:
        if self.db is not None:
            self.db.put("decisions", decision.decision_id, decision.trace_id, decision.created_at, decision.as_dict())

    def _save_evidence(self, record: dict) -> None:
        if self.db is not None:
            self.db.put("evidence", record["evidence_id"], record["trace_id"], record["stored_at"], record)

    def set_task(self, trace_id: str, task: dict, replace: bool = True) -> None:
        """登记会话的任务信封（攻击链展示用）；replace=False 时已有则保留。"""
        with self._lock:
            if not replace and trace_id in self.tasks:
                return
            self.tasks[trace_id] = task
            if self.db is not None:
                self.db.put("tasks", trace_id, trace_id, utc_now_ms(), task)

    def _load(self) -> None:
        """启动时加载保留期内最新的数据（不超过内存上限），重建索引与调用关联；会话状态在首次访问时按需恢复。"""
        for record in self.db.load("evidence", MAX_EVIDENCE):
            if record.get("evidence_id"):
                self.evidence[record["evidence_id"]] = record
                self._evidence_ids.append(record["evidence_id"])
        for task in self.db.load("tasks", MAX_EVENTS):
            if task.get("trace_id"):
                self.tasks[task["trace_id"]] = task
        for data in self.db.load("events", MAX_EVENTS):
            try:
                event = RuntimeEvent(**{key: value for key, value in data.items() if key in EVENT_FIELDS})
            except TypeError:
                continue
            self.events.append(event)
            self._events_by_id[event.event_id] = event
            self.events_by_trace.setdefault(event.trace_id, []).append(event.event_id)
            self._relink(event)
        for data in self.db.load("decisions", MAX_EVENTS):
            try:
                decision = Decision(**{key: value for key, value in data.items() if key in DECISION_FIELDS})
                decision.matched_rules = [RuleMatch(**match) for match in decision.matched_rules]
            except TypeError:
                continue
            self.decisions.append(decision)
            self._decisions_by_id[decision.decision_id] = decision
            self.decisions_by_trace.setdefault(decision.trace_id, []).append(decision.decision_id)
            self.rule_hits.update(match.rule_id for match in decision.matched_rules)
            self.decision_latencies.append(decision.latency_ms)

    def _relink(self, event: RuntimeEvent) -> None:
        """加载的事件已带关联结果，这里只重建后续事件关联所需的索引（根节点、轮次、调用）。"""
        link = self._trace_link(event.trace_id)
        if event.stage == "TASK_CREATED":
            link["root"] = event.span_id
        elif event.stage == "MODEL_TURN" and event.round:
            link["rounds"][event.round] = event.span_id
        elif event.stage == "TOOL_REQUEST_HOOK" and event.call_id:
            link["calls"].setdefault(event.call_id, {}).update(hook=event.span_id, round=event.round)
        elif event.stage == "TOOL_REQUEST" and event.source == "mcp-gateway" and event.call_id:
            link["calls"].setdefault(event.call_id, {}).update(gateway=event.span_id, gateway_event=event)
        link["last"][event.stage] = event.span_id

    def _restore_state(self, trace_id: str, state: TaskRuntimeState) -> None:
        """会话状态被清理或服务重启后再次活动：从已有事件与决策恢复轮次、污点与调用历史，
        避免轮次从 1 重新计数、读过凭证的会话丢失污点。参数来源索引与秘密指纹不恢复。"""
        for event_id in self.events_by_trace.get(trace_id, []):
            event = self._events_by_id.get(event_id)
            if event is None:
                continue
            state.rounds = max(state.rounds, int(event.round or 0))
            if event.stage == "TASK_CREATED" and not state.workspace:
                state.workspace = str((event.entry or {}).get("cwd") or "")
            if event.stage in RESULT_STAGES:
                state.taints.update(label for label in event.labels if label not in NON_TAINT_LABELS)
        for decision_id in self.decisions_by_trace.get(trace_id, []):
            decision = self._decisions_by_id.get(decision_id)
            if decision is not None:
                state.decisions[decision.decision] += 1
                state.tool_history.append({"server": decision.server, "tool": decision.tool,
                                           "decision": decision.decision})

    def close(self) -> None:
        if self.db is not None:
            self.db.flush()

    def storage_status(self) -> dict:
        return self.db.status() if self.db is not None else {"path": ""}

    # ---- 订阅 ----

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast(self, kind: str, payload: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait({"kind": kind, "data": payload})
            except queue.Full:
                pass

    # ---- 写入 ----

    def add_event(self, event: RuntimeEvent) -> RuntimeEvent:
        with self._lock:
            self._link_event(event)
            # 事件与证据互引：证据入库时事件尚未创建，这里补上反向 event_id。
            for evidence_id in event.evidence_ids:
                record = self.evidence.get(evidence_id)
                if record is not None and not record.get("event_id"):
                    record["event_id"] = event.event_id
                    self._save_evidence(record)
            if len(self.events) == self.events.maxlen:
                self._events_by_id.pop(self.events[0].event_id, None)
            self.events.append(event)
            self._events_by_id[event.event_id] = event
            self.events_by_trace.setdefault(event.trace_id, []).append(event.event_id)
            self._save_event(event)
            self._broadcast("event", event.as_dict())
        return event

    # ---- 受控证据存储 ----

    def add_evidence(self, kind: str, content, source: str = "", trace_id: str = "",
                     event_id: str = "", labels: list | None = None,
                     collection_truncated: bool = False, origin_source: str = "",
                     role: str = "", original_digest: str = "", original_length: int = 0) -> dict:
        """保存脱敏后的证据；公共查询只暴露 preview/snippets，不暴露 content。

        - collection_truncated：上游只上报了摘要（采集侧截断），入库内容并非全文；
        - original_digest/original_length：上游声明的全文摘要与长度（保真核对用）；
        - 存储预算：脱敏后按 head+tail 保留，超出部分写入 omitted_chars 与关键片段 snippets。
        """
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, default=str)
        masked = mask_secrets(text)
        stored_text, storage_truncated, omitted = _bounded_content(masked)
        preview = redact_text(text, limit=EVIDENCE_PREVIEW_CHARS)["preview"]
        digest = str(original_digest or sha256_digest(text))
        record = {
            "evidence_id": new_id("evd"),
            "kind": str(kind),
            "source": str(source),
            "origin_source": str(origin_source or source),
            "role": str(role),
            "trace_id": str(trace_id),
            "event_id": str(event_id),
            "digest": digest,
            "original_digest": digest,
            "original_length": int(original_length or len(text)),
            "received_length": len(text),
            "stored_length": len(stored_text),
            "omitted_chars": omitted,
            "redacted": masked != text,
            "truncated": bool(collection_truncated or storage_truncated),
            "collection_truncated": bool(collection_truncated),
            "storage_truncated": storage_truncated,
            "preview_truncated": len(stored_text) > EVIDENCE_PREVIEW_CHARS,
            "preview": preview,
            "content": stored_text,
            "snippets": risk_snippets(masked),
            "labels": [str(item) for item in (labels or [])],
            "stored_at": utc_now_ms(),
        }
        with self._lock:
            self.evidence[record["evidence_id"]] = record
            self._evidence_ids.append(record["evidence_id"])
            while len(self._evidence_ids) > MAX_EVIDENCE:
                self.evidence.pop(self._evidence_ids.popleft(), None)
            self._save_evidence(record)
        return record

    @staticmethod
    def evidence_preview(record: dict) -> dict:
        """公共字段：不含 content 原文，只含安全预览、关键片段与截断/脱敏标记。"""
        keys = ("evidence_id", "kind", "source", "origin_source", "role", "trace_id", "event_id",
                "digest", "original_digest", "length", "original_length", "received_length",
                "stored_length", "omitted_chars", "redacted", "truncated", "collection_truncated",
                "storage_truncated", "preview_truncated", "preview", "snippets", "labels", "stored_at")
        return {key: record[key] for key in keys if key in record}

    def get_evidence(self, evidence_id: str, include_content: bool = False) -> dict | None:
        """默认返回预览；单条证据读取使用 include_content 返回脱敏原文。"""
        with self._lock:
            record = self.evidence.get(evidence_id)
            if record is None:
                return None
            return dict(record) if include_content else self.evidence_preview(record)

    def _trace_link(self, trace_id: str) -> dict:
        link = self._trace_links.get(trace_id)
        if link is None:
            link = {"root": "", "started_at": time.time(), "last": {}, "tools": {},
                    "rounds": {}, "calls": {}, "available": {}, "pending": {}}
            self._trace_links[trace_id] = link
        for key in ("rounds", "calls", "available", "pending"):
            link.setdefault(key, {})
        link["last_seen"] = time.time()
        return link

    @staticmethod
    def _bind_gateway_to_hook(gateway_event: RuntimeEvent, hook_event: RuntimeEvent) -> None:
        """把已入库的网关请求修正到对应 Hook 调用；只改关联元数据，不改证据内容。"""
        gateway_event.parent_span_id = hook_event.span_id
        gateway_event.attribution = "exact"
        if hook_event.round:
            gateway_event.round = hook_event.round
        if not gateway_event.call_id:
            gateway_event.call_id = hook_event.call_id
        if not hook_event.call_id:
            hook_event.call_id = gateway_event.call_id

    def _link_event(self, event: RuntimeEvent) -> None:
        """关联父子 span：优先 call_id 精确匹配，其次按 server/tool 双向匹配（支持乱序/迟到）。

        无法归因时标 unknown；内容字段只追加，只有关联元数据可被迟到事件修正。
        """
        trace = event.trace_id
        task = self.tasks.get(trace)
        if not event.task_id and isinstance(task, dict):
            event.task_id = str(task.get("task_id") or "")
        link = self._trace_link(trace)
        stage, source = event.stage, event.source
        tool_key = f"{event.mcp_server}|{event.tool}"
        call = link["calls"].setdefault(event.call_id, {}) if event.call_id else None

        def parent_for_round(round_no: int) -> str:
            return (link["rounds"].get(int(round_no or 0))
                    or link["last"].get("MODEL_TURN") or link["root"])

        if event.parent_span_id:
            event.attribution = event.attribution or "exact"
        elif stage == "TASK_CREATED":
            link["root"] = event.span_id
            event.attribution = "root"
        elif stage == "INGRESS_REQUEST":
            # 入口阻断的根证据：没有应用栈，也不伪造应用父节点。
            event.attribution = "root"
        elif stage == "MODEL_TURN":
            event.parent_span_id = parent_for_round(event.round)
            if event.round:
                link["rounds"][event.round] = event.span_id
            event.attribution = "inferred" if event.parent_span_id else "unknown"
        elif stage == "TOOL_REQUEST_HOOK":
            event.parent_span_id = parent_for_round(event.round)
            event.attribution = "inferred" if event.parent_span_id else "unknown"
            if call is not None:
                call["hook"] = event.span_id
                call["round"] = event.round or call.get("round", 0)
                gateway_event = call.get("gateway_event")
                if gateway_event is not None:
                    self._bind_gateway_to_hook(gateway_event, event)
                    self._save_event(gateway_event)
            else:
                pending = link["pending"].get(tool_key)
                if pending:
                    gateway_event = pending.pop(0)
                    self._bind_gateway_to_hook(gateway_event, event)
                    self._save_event(gateway_event)
                else:
                    link["available"].setdefault(tool_key, []).append(event.span_id)
        elif stage == "TOOL_RESULT_HOOK":
            hook_span = (call or {}).get("hook") or link["last"].get("TOOL_REQUEST_HOOK", "")
            event.parent_span_id = hook_span or link["root"]
            event.attribution = "exact" if (call and call.get("hook")) else (
                "inferred" if event.parent_span_id else "unknown")
        elif stage == "TOOL_REQUEST" and source == "mcp-gateway":
            if call is not None:
                call["gateway"] = event.span_id
                call["gateway_event"] = event
                hook_span = call.get("hook")
                if hook_span:
                    event.parent_span_id = hook_span
                    event.attribution = "exact"
                    event.round = call.get("round", event.round)
                else:
                    event.parent_span_id = parent_for_round(event.round)
                    event.attribution = "inferred" if event.parent_span_id else "unknown"
            else:
                available = link["available"].get(tool_key)
                if available:
                    event.parent_span_id = available.pop(0)
                    event.attribution = "inferred"
                else:
                    link["pending"].setdefault(tool_key, []).append(event)
                    event.parent_span_id = parent_for_round(event.round)
                    event.attribution = "inferred" if event.parent_span_id else "unknown"
        elif stage == "TOOL_RESULT" and source == "mcp-gateway":
            gateway_span = (call or {}).get("gateway") or link["last"].get("TOOL_REQUEST", "")
            event.parent_span_id = gateway_span or link["root"]
            event.attribution = "exact" if (call and call.get("gateway")) else (
                "inferred" if event.parent_span_id else "unknown")
        elif stage in ("EGRESS", "EGRESS_ALLOWED"):
            event.parent_span_id = (link["last"].get("TOOL_RESULT")
                                    or link["last"].get("TOOL_REQUEST") or link["root"])
            event.attribution = "inferred" if event.parent_span_id else "unknown"
        elif stage == "TASK_COMPLETED":
            event.parent_span_id = link["root"]
            event.attribution = "inferred" if event.parent_span_id else "unknown"
        else:
            event.parent_span_id = event.parent_span_id or link["root"]
            event.attribution = "inferred" if event.parent_span_id else "unknown"
        link["last"][stage] = event.span_id

    def add_decision(self, decision: Decision) -> Decision:
        with self._lock:
            if len(self.decisions) == self.decisions.maxlen:
                self._decisions_by_id.pop(self.decisions[0].decision_id, None)
            self.decisions.append(decision)
            self._decisions_by_id[decision.decision_id] = decision
            self.decisions_by_trace.setdefault(decision.trace_id, []).append(decision.decision_id)
            self.rule_hits.update(match.rule_id for match in decision.matched_rules)
            self.decision_latencies.append(decision.latency_ms)
            self._save_decision(decision)
            self._broadcast("decision", decision.as_dict())
        return decision

    def resolve_decision(self, decision_id: str, resolution: str) -> Decision | None:
        """回填 ASK 的事后结论；已有结论的不覆盖。推送同一 decision 频道，控制台据此刷新。"""
        with self._lock:
            decision = self._decisions_by_id.get(decision_id)
            if decision is None or decision.resolution:
                return None
            decision.resolution = resolution
            decision.resolved_at = utc_now_ms()
            self._save_decision(decision)
            self._broadcast("decision", decision.as_dict())
            return decision

    def annotate_decision(self, decision_id: str, assessment: dict, *, only_if_unassessed: bool = False) -> Decision | None:
        """回填大模型异步分析对告警的研判；推送同一 decision 频道。"""
        with self._lock:
            decision = self._decisions_by_id.get(decision_id)
            if decision is None:
                return None
            if only_if_unassessed and (decision.assessment or {}).get("assessment") in (
                    "true_positive", "false_positive", "uncertain"):
                return decision
            decision.assessment = assessment
            self._save_decision(decision)
            self._broadcast("decision", decision.as_dict())
            return decision

    def publish(self, kind: str, payload: dict) -> None:
        """推送非事件 / 决策类的实时消息（如大模型分析结果）。"""
        with self._lock:
            self._broadcast(kind, payload)

    def record_forward_latency(self, ms: float) -> None:
        with self._lock:
            self.forward_latencies.append(ms)

    # ---- 任务状态 ----

    def state_for(self, trace_id: str) -> TaskRuntimeState:
        with self._lock:
            state = self.states.get(trace_id)
            if state is None:
                state = TaskRuntimeState()
                self._restore_state(trace_id, state)
                self.states[trace_id] = state
            state.last_seen = time.time()
            return state

    def device_artifacts(self, device_id: str) -> F.DeviceArtifacts:
        with self._lock:
            return self._device_artifacts.setdefault(device_id, F.DeviceArtifacts())

    def cleanup_states(self, ttl_seconds: int) -> None:
        now = time.time()
        with self._lock:
            # 按最近活动回收：长会话（通用 Agent）持续活动时污点不能因启动时间过久而丢失。
            stale = [trace for trace, state in self.states.items() if now - state.last_seen > ttl_seconds]
            for trace in stale:
                self.states.pop(trace, None)
            stale_links = [trace for trace, link in self._trace_links.items()
                           if now - link.get("last_seen", link.get("started_at", now)) > ttl_seconds]
            for trace in stale_links:
                self._trace_links.pop(trace, None)

    def find_parent_trace_for_server(self, server: str, window_seconds: float = 30.0) -> str | None:
        """给外联事件找最近的同 server 工具调用父任务，找不到即 ORPHAN。"""
        now = time.time()
        with self._lock:
            for trace, state in reversed(list(self.states.items())):
                for ts, srv in reversed(state.allowed_calls):
                    if srv == server and now - ts <= window_seconds:
                        return trace
        return None

    # ---- 查询 ----

    def trace_snapshot(self, trace_id: str) -> tuple[list, dict]:
        """会话的事件（按入库顺序）与决策（decision_id -> Decision），供大模型研判组装上下文。"""
        with self._lock:
            events = [self._events_by_id[event_id] for event_id in self.events_by_trace.get(trace_id, [])
                      if event_id in self._events_by_id]
            decisions = {decision_id: self._decisions_by_id[decision_id]
                         for decision_id in self.decisions_by_trace.get(trace_id, [])
                         if decision_id in self._decisions_by_id}
        return events, decisions

    def turn_event_id(self, trace_id: str, round_no: int) -> str:
        """会话某一轮最近的用户提示词事件（MODEL_TURN）ID；没有则为空。"""
        with self._lock:
            for event_id in reversed(self.events_by_trace.get(trace_id, [])):
                event = self._events_by_id.get(event_id)
                if event is not None and event.stage == "MODEL_TURN" and event.round == round_no:
                    return event.event_id
        return ""

    def recent_calls(self, limit: int) -> tuple[list, dict]:
        """最近的 Hook 工具调用事件与它们的决策（规则建议的误报试跑用）。"""
        with self._lock:
            events = [event for event in list(self.events)[-limit * 4:] if event.stage == "TOOL_REQUEST_HOOK"][-limit:]
            decisions = {event.decision_id: self._decisions_by_id[event.decision_id] for event in events
                         if event.decision_id in self._decisions_by_id}
        return events, decisions

    def event_count(self) -> int:
        with self._lock:
            return len(self.events)

    def get_events(self, trace_id: str = "", stage: str = "", source: str = "", limit: int = 200) -> list[dict]:
        with self._lock:
            selected = list(self.events)
        result = []
        for event in reversed(selected):
            if trace_id and event.trace_id != trace_id:
                continue
            if stage and event.stage != stage:
                continue
            if source and event.source != source:
                continue
            result.append(event.as_dict())
            if len(result) >= limit:
                break
        return result

    def get_decisions(self, trace_id: str = "", decision: str = "", limit: int = 200,
                      anomalous: bool = False, reviewed: bool = False) -> list[dict]:
        with self._lock:
            selected = list(self.decisions)
        result = []
        for item in reversed(selected):
            if trace_id and item.trace_id != trace_id:
                continue
            if decision and item.decision != decision:
                continue
            if anomalous and not (item.anomaly or {}).get("anomalous"):
                continue
            if reviewed and (item.review or {}).get("static", item.decision) == item.decision:
                # 只要大模型复核改变了结论的决策（如静态拦截、模型放行）。
                continue
            result.append({**item.as_dict(), "context": self._decision_context(item)})
            if len(result) >= limit:
                break
        return result

    def _decision_context(self, decision: Decision) -> dict:
        """决策的触发行为摘要（告警展示用）：来源、主体与被拦截的具体对象，取自首个证据事件。"""
        event = next(filter(None, map(self._events_by_id.get, decision.evidence_ids)), None)
        if event is None:
            return {}
        return {"event_id": event.event_id, "stage": event.stage, "source": event.source,
                "component": event.component, "resource": event.resource,
                "preview": event.redacted_preview, "actor": event.actor.get("sub", ""),
                "task_id": event.task_id, "call_id": event.call_id}

    def resolve_trace_id(self, identifier: str) -> str:
        """把 trace_id / task_id / decision_id 统一解析为 trace_id（攻击链查询用）。"""
        ident = str(identifier or "")
        if not ident:
            return ident
        with self._lock:
            if (ident in self.tasks or ident in self.states or ident in self.events_by_trace
                    or ident in self.decisions_by_trace):
                return ident
            for decision in reversed(self.decisions):
                if decision.decision_id == ident:
                    return decision.trace_id
            for trace_id, task in self.tasks.items():
                if isinstance(task, dict) and task.get("task_id") == ident:
                    return trace_id
        return ident

    def build_trace(self, trace_id: str) -> dict:
        """攻击链（见 trace.py）。查询标识支持 trace_id / task_id / decision_id；评测/回放直连网关的 trace
        可能没有 Hook 任务信封，此时仅返回网关侧证据链。"""
        trace_id = self.resolve_trace_id(trace_id)
        with self._lock:
            events = [e for e in self.events if e.trace_id == trace_id]
            decisions = [d for d in self.decisions if d.trace_id == trace_id]
            task = self.tasks.get(trace_id)
            state = self.states.get(trace_id)
            wanted = {item for record in events + decisions for item in (record.evidence_ids or [])}
            evidence = {item: self.evidence[item] for item in wanted if item in self.evidence}
            calls = dict((self._trace_links.get(trace_id) or {}).get("calls") or {})
        return build_trace_view(trace_id, events, decisions, task, state, evidence, calls, self.evidence_preview)

    # ---- 指标 ----

    def metrics(self) -> dict:
        storage = self.storage_status()   # 读库在存储锁外进行，不阻塞数据面
        with self._lock:
            decisions = list(self.decisions)
            event_count = len(self.events)
            rule_hits = dict(self.rule_hits)
            decision_latencies = list(self.decision_latencies)
            forward_latencies = list(self.forward_latencies)
        summary = scenario_summary(decisions)
        return {
            "totals": {"events": event_count, "decisions": len(decisions),
                       "decision_counts": summary["decision_counts"]},
            "scenarios": summary["scenarios"],
            "confusion": summary["confusion"],
            "rates": summary["rates"],
            "rule_hits": rule_hits,
            "decision_latency_ms": percentiles(decision_latencies),
            "forward_latency_ms": percentiles(forward_latencies),
            "cpu": cpu_snapshot(),
            "storage": storage,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
