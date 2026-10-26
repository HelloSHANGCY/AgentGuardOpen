"""静态扫描数据模型：Asset / Edge / Evidence / Finding / Coverage / Scan。

与运行时 ``models.py`` 的 Decision 严格分离：
- severity 表示潜在影响，confidence 表示证据可靠性，两者独立；
- 所有持久化字段只保存脱敏片段与来源位置，不保存明文凭证；
- 资产 ID 由 project_id + kind + 逻辑位置确定，内容指纹单列。
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field

STATIC_MODEL_VERSION = "static-model-0.1"

# 资产类别（方案 §4.1）。
ASSET_KINDS = (
    "AgentApplication",
    "Framework",
    "ModelReference",
    "Skill",
    "MCPServer",
    "Tool",
    "Dependency",
    "Endpoint",
    "SecretReference",
    "ConfigArtifact",
)

# 有限关系枚举（方案 §4.1）。
RELATIONS = (
    "USES_FRAMEWORK",
    "USES_MODEL",
    "LOADS_SKILL",
    "CONNECTS_TO",
    "EXPOSES_TOOL",
    "HANDLED_BY",
    "DEPENDS_ON",
    "READS_SECRET",
    "SENDS_TO",
    "CONFIGURED_BY",
)

BASIS = ("declared", "inferred", "observed_snapshot")

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CONFIDENCES = ("low", "medium", "high")

# 扫描终态：COMPLETED 表示全部阶段成功；PARTIAL 表示有限失败但仍保留结果。
SCAN_STATES = ("QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "INTERRUPTED")
TERMINAL_STATES = ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "INTERRUPTED")
SCAN_PHASES = ("QUEUED", "WAITING_ENDPOINT", "COLLECTING", "SNAPSHOTTING", "DISCOVERING", "ANALYZING", "FINALIZING")

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def digest_text(text: str, length: int = 32) -> str:
    return "sha256:" + hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[:length]


def stable_asset_id(project_id: str, kind: str, logical_key: str) -> str:
    """同一项目内稳定资产 ID：类型 + 适配器逻辑位置，内容哈希单列。"""
    raw = f"{project_id}|{kind}|{logical_key}"
    return "ast-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:20]


def finding_fingerprint(rule_id: str, asset_id: str, locations: list) -> str:
    """同一资产、规则与规范化证据位置形成指纹，用于去重与抑制。"""
    normalized = sorted(str(item) for item in locations)
    raw = json.dumps([rule_id, asset_id, normalized], ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]


def redact_excerpt(text: str, limit: int = 200) -> str:
    """证据片段脱敏：去掉控制字符并截断；调用方负责敏感值掩码。"""
    raw = "".join(ch for ch in str(text or "") if ch >= " " or ch in "\t")
    raw = raw.replace("\r", " ").replace("\n", "\\n")
    return raw[:limit] + ("...(truncated)" if len(raw) > limit else "")


def redact_secret(value: str) -> str:
    """只保留极短前缀用于人工比对，其余掩码；凭证永不落库。"""
    text = str(value or "")
    if len(text) <= 4:
        return "***"
    return text[:2] + "***" + f"(len={len(text)})"


@dataclass
class Evidence:
    evidence_id: str
    scan_id: str
    path: str
    line: int = 0
    column: int = 0
    pointer: str = ""
    excerpt: str = ""
    excerpt_digest: str = ""
    parser: str = ""
    transform_chain: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class Asset:
    asset_id: str
    project_id: str
    scan_id: str
    kind: str
    logical_key: str
    name: str
    version: str = ""
    relative_path: str = ""
    content_digest: str = ""
    discovery_method: str = "static"
    confidence: str = "medium"
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class Edge:
    edge_id: str
    scan_id: str
    source_asset_id: str
    relation: str
    target_asset_id: str
    confidence: str = "medium"
    basis: str = "declared"
    evidence_ids: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class FlowStep:
    """数据流单步：每一步标明 proven / inferred / unresolved。"""

    kind: str  # source / transform / sink / binding
    status: str  # proven / inferred / unresolved
    location: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class Finding:
    finding_id: str
    scan_id: str
    rule_id: str
    rule_version: str
    asset_id: str
    category: str
    severity: str
    confidence: str
    evidence_ids: list = field(default_factory=list)
    flow_steps: list = field(default_factory=list)
    explanation: str = ""
    remediation: str = ""
    limitations: str = ""
    fingerprint: str = ""
    title: str = ""
    created_at: str = field(default_factory=utc_now)

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class Coverage:
    scan_id: str
    indexed_files: int = 0
    parsed_files: int = 0
    failed_files: int = 0
    skipped_files: int = 0
    languages: dict = field(default_factory=dict)
    unresolved_refs: list = field(default_factory=list)
    limit_hits: list = field(default_factory=list)
    vulnerability_db: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class Review:
    review_id: str
    scan_id: str
    finding_id: str
    status: str  # open / confirmed / false_positive / accepted_risk / fixed
    reason: str = ""
    operator: str = ""
    created_at: str = field(default_factory=utc_now)
    expires_at: str = ""

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class ScanRecord:
    scan_id: str
    project_id: str
    source_id: str
    source_path: str = ""
    profile: str = "default"
    status: str = "QUEUED"
    phase: str = "QUEUED"
    progress: int = 0
    source_digest: str = ""
    ruleset_version: str = ""
    adapter_versions: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    vulnerability_db_version: str = ""
    error: str = ""
    cancel_requested: bool = False
    idempotency_key: str = ""
    attempt: int = 0
    worker_id: str = ""
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    started_at: str = ""
    finished_at: str = ""
    heartbeat_at: str = ""
    device_id: str = ""
    agent: str = ""
    collection: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        data = dict(vars(self))
        if self.device_id:
            data["source_path"] = ""  # 私有快照目录不属于设备路径，也不向查询端暴露。
            data["worker_id"] = ""  # 采集租约仅对领取它的设备返回。
        return data


@dataclass
class ScanContext:
    """一次扫描内不可热切换的上下文：规则版本、适配器版本、限额。"""

    scan_id: str
    project_id: str
    source_id: str
    root: str
    profile: str = "default"
    source_digest: str = ""
    ruleset_version: str = ""
    adapter_versions: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    vulnerability_db_version: str = "unavailable"
    device_id: str = ""
    agent: str = ""
    workspace_id: str = ""

    def asset_id(self, kind: str, logical_key: str) -> str:
        namespace = self.project_id
        if self.device_id:
            namespace += f"|device:{self.device_id}:{self.agent}"
            if "project/" in logical_key:
                namespace += "|workspace:" + self.workspace_id
        return stable_asset_id(namespace, kind, logical_key)

    def as_dict(self) -> dict:
        return vars(self)
