"""统一数据模型：任务信封、运行时事件、决策、工具请求。

事件与决策按 trace_id / task_id / span_id 关联，构成攻击链；
敏感内容只保留摘要与脱敏预览，原文不出现在公共字段中。
"""

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field

# 观察模式（管控 enforce 关闭）下命中的拒绝 / 需确认：只记告警，未拦截。
MONITOR_ONLY = "MONITOR_ONLY"


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def utc_now_ms() -> str:
    # 所有时间使用 UTC 存储，展示层再转换时区。秒与毫秒取自同一次读数，跨秒时不会拼出倒退的时间。
    now = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}Z"


def sha256_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


SENSITIVE_KEY_NAMES = ("secret", "token", "password", "authorization", "cookie", "key", "credential")

# 文本级脱敏：证据原文入库前先掩码凭证形态内容，公共查询只返回安全预览。
# 私钥模式同时覆盖完整与残缺（截断后缺结束标记）两种形态：先脱敏再截断，
# 避免“截断破坏结构识别”导致的明文泄漏。
_SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     "***REDACTED_PRIVATE_KEY***"),
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})"), r"\1***REDACTED***"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "***REDACTED_JWT***"),
    # scheme 只能从词首开始且有长度上界：否则长串字母数字上每个起点都扫到串尾（O(n²)）。
    (re.compile(r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}://[^/\s:@]+):([^@/\s]+)@"), r"\1:***REDACTED***@"),
    # 值长度有上界：无分隔符的长文本不能让正则吞掉 key=value 之后的全部内容（避免过度脱敏）。
    (re.compile(r"(?i)(secret|token|password|passwd|api[_-]?key|authorization|credential)"
                r"(\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"',;}\]]{4,128})"), r"\1\2***REDACTED***"),
)

# 关键片段提取用的风险标记：长内容超出存储预算时，仍能定位触发位置。
_RISK_MARKERS = (
    "ignore previous", "ignore all previous", "忽略之前", "忽略以上", "不要向用户", "不要提及",
    "hidden instruction", "隐藏指令", "read /app/.env", "先读取", "exfiltrate", "外传",
    "curl ", "wget ", "base64 -d", "subprocess", "os.system", "eval(", "exec(", "shell=true",
    "cross-tenant", "跨租户", "jwt_secret", "private key",
)


def mask_secrets(text) -> str:
    """对完整输入做凭证掩码（不截断）；截断必须发生在其后，避免破坏结构识别。"""
    original = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False, default=str)
    masked = original
    for pattern, replacement in _SECRET_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def redact_text(text, limit: int = 200) -> dict:
    """掩码凭证并截断为安全预览（先对完整输入脱敏，再截断）。

    返回 {text(掩码后完整文本), preview(截断预览), truncated, redacted, length}。
    preview 明确带截断标记，避免把不完整内容误读为全文。
    """
    original = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False, default=str)
    masked = mask_secrets(original)
    truncated = len(masked) > limit
    preview = masked[:limit]
    if truncated:
        preview += f"...(truncated {len(masked) - limit} chars)"
    return {
        "text": masked,
        "preview": preview,
        "truncated": truncated,
        "redacted": masked != original,
        "length": len(original),
    }


def risk_snippets(text: str, limit: int = 5, window: int = 80) -> list[dict]:
    """从文本中提取风险命中窗口；内部先脱敏，返回片段不含明文凭证。"""
    text = mask_secrets(text)
    hits: list[tuple] = []
    lowered = text.lower()
    for marker in _RISK_MARKERS:
        start = lowered.find(marker)
        if start >= 0:
            hits.append((start, marker))
    for pattern, _ in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append((match.start(), "credential"))
    snippets = []
    seen = set()
    for offset, reason in sorted(hits):
        if offset in seen:
            continue
        seen.add(offset)
        snippets.append({
            "offset": offset,
            "reason": reason,
            "text": text[max(0, offset - window): offset + window],
        })
        if len(snippets) >= limit:
            break
    return snippets


def redact_value(value) -> str:
    return redact_text(value, limit=200)["preview"]


def redact_mapping(data: dict) -> dict:
    # 审计副本：敏感键名直接掩码，其余值截断，防止审计面泄露明文凭证。
    redacted = {}
    for key, value in (data or {}).items():
        if any(marker in str(key).lower() for marker in SENSITIVE_KEY_NAMES):
            redacted[str(key)] = "***REDACTED***"
        else:
            redacted[str(key)] = redact_value(value)
    return redacted


@dataclass
class Actor:
    sub: str = "unknown"
    role: str = "unknown"
    team: str = ""
    scope: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"sub": self.sub, "role": self.role, "team": self.team, "scope": dict(self.scope)}


@dataclass
class TaskContext:
    """Hook 在 /run 开始时创建的任务信封，是网关唯一可信的身份来源。"""

    trace_id: str
    task_id: str
    actor: Actor
    intent_summary: str = ""
    intent_digest: str = ""
    intent_evidence_id: str = ""
    active_skill: dict = field(default_factory=dict)
    skill_evidence_id: str = ""
    source_labels: list = field(default_factory=list)
    instance_id: str = ""
    issued_at: str = field(default_factory=utc_now_ms)
    expires_at: float = 0.0
    agent: str = "mcp"
    policy_profile: str = ""   # 为空时按 agent 取默认档案（engine.PROFILE_DEFAULTS）

    def as_dict(self) -> dict:
        intent = redact_text(self.intent_summary, limit=160)
        return {
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "actor": self.actor.as_dict(),
            # 公共任务画像只含脱敏预览；原文经受控证据接口访问。
            "intent_summary": intent["preview"],
            "intent_truncated": intent["truncated"],
            "intent_digest": self.intent_digest,
            "intent_evidence_id": self.intent_evidence_id,
            "active_skill": self.active_skill,
            "skill_evidence_id": self.skill_evidence_id,
            "source_labels": list(self.source_labels),
            "instance_id": self.instance_id,
            "issued_at": self.issued_at,
            "agent": self.agent,
            "policy_profile": self.policy_profile,
        }


@dataclass
class ToolRequest:
    """一次 tools/call 标准化后的请求事实。"""

    trace_id: str
    instance_id: str
    server: str
    tool: str
    arguments: dict = field(default_factory=dict)
    # 通用 Agent 接入：发起方、能力展开、工作目录与 MCP 受管状态（见 capability.py）。
    agent: str = "mcp"
    raw_tool: str = ""
    calls: list = field(default_factory=list)   # list[NormalizedCall]；空则由引擎按 MCP 映射补全
    cwd: str = ""
    unmanaged_server: bool = False
    device_id: str = ""                          # 通用 Agent 的设备（行为基线个性化）


@dataclass
class RuleMatch:
    rule_id: str
    decision: str  # ALLOW / ASK / DENY
    reason_code: str
    severity: str
    detail: str = ""
    # None：旧记录或该检测路径未采集；[]：已采集，本次策略不依赖具体特征命中。
    features: list | None = None
    strategy_title: str = ""


@dataclass
class Decision:
    decision: str  # ALLOW / ASK / DENY
    decision_id: str
    reason_code: str
    severity: str
    matched_rules: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)
    safe_message: str = ""
    labels: list = field(default_factory=list)
    latency_ms: float = 0.0
    rules_version: str = ""
    created_at: str = field(default_factory=utc_now_ms)
    trace_id: str = ""
    server: str = ""
    tool: str = ""
    # ASK 的事后结论（通用 Agent 原生确认）：APPROVED = 用户批准且工具已执行；NOT_EXECUTED = 明确未执行；UNKNOWN = 缺少执行证据。
    resolution: str = ""
    resolved_at: str = ""
    # 参数来源归因（创新检测实施方案 §3）：每个关键参数的来源、片段与指令痕迹。
    provenance: list = field(default_factory=list)
    # 数据流溯源（§4）：出网携带的秘密指纹 / 暂存物 / 直接外发的敏感文件。
    flow: list = field(default_factory=list)
    flow_status: dict = field(default_factory=dict)
    # 行为基线异常分（§5）：最异常的一步转移、基线概率、意图与是否超阈值；未启用时为 None。
    anomaly: dict | None = None
    # 大模型危险审批（llm/judge.py）：静态判定、模型结论与理由；结论不同则 decision 已改为模型结论。
    review: dict | None = None
    # 大模型异步分析对这条告警的研判（真阳性 / 误报 / 不确定），分析完成后回填。
    assessment: dict | None = None

    def as_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "severity": self.severity,
            "matched_rules": [vars(match) for match in self.matched_rules],
            "evidence_ids": list(self.evidence_ids),
            "safe_message": self.safe_message,
            "labels": list(self.labels),
            "latency_ms": round(self.latency_ms, 3),
            "rules_version": self.rules_version,
            "created_at": self.created_at,
            "trace_id": self.trace_id,
            "server": self.server,
            "tool": self.tool,
            "resolution": self.resolution,
            "resolved_at": self.resolved_at,
            "provenance": list(self.provenance),
            "flow": list(self.flow),
            "flow_status": dict(self.flow_status),
            "anomaly": self.anomaly,
            "review": self.review,
            "assessment": self.assessment,
        }


@dataclass
class RuntimeEvent:
    event_id: str
    trace_id: str
    stage: str  # TASK_CREATED / MODEL_TURN / TOOL_REQUEST / TOOL_RESULT / TASK_COMPLETED ...
    source: str  # agent-hook / mcp-gateway
    timestamp: str = field(default_factory=utc_now_ms)
    span_id: str = field(default_factory=lambda: new_id("span"))
    parent_span_id: str = ""
    actor: dict = field(default_factory=dict)
    component: str = ""
    mcp_server: str = ""
    tool: str = ""
    resource: str = ""
    labels: list = field(default_factory=list)
    payload_digest: str = ""
    redacted_preview: str = ""
    # stack 只记录采集点的真实调用帧（{"source","module","file","function","line"}），
    # 不允许把预设调用路径写成实际函数栈。
    stack: list = field(default_factory=list)
    decision_id: str = ""
    task_id: str = ""
    round: int = 0
    # 单次工具调用的唯一标识：贯穿 Hook/Gateway/结果，支持乱序与重复调用精确关联。
    call_id: str = ""
    # 父子关联置信度：root / exact / inferred / unknown，未知不伪造。
    attribution: str = ""
    evidence_ids: list = field(default_factory=list)
    entry: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        # 返回副本：查询/攻击链聚合可能补充 decision 等展示字段，不能污染事件对象本身；
        # 可变字段一并复制，避免调用方原地修改污染后续查询。
        snapshot = dict(vars(self))
        for key in ("labels", "stack", "evidence_ids"):
            snapshot[key] = list(snapshot.get(key) or [])
        for key in ("actor", "entry"):
            snapshot[key] = dict(snapshot.get(key) or {})
        return snapshot
