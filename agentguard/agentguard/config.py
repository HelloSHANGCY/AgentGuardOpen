"""集中配置：上游映射、白名单、规则版本、密钥。

上游映射只能来自本地受控环境变量，客户端不可通过请求参数选择任意上游。
"""

import json
import os
import re
from dataclasses import dataclass, field

# No implicit upstreams. Administrators register HTTP MCP services through AG_EXTRA_UPSTREAMS.
DEFAULT_UPSTREAMS = {}

# 只读、无副作用的低风险工具：任务上下文缺失时按设计降级放行并打标。
SAFE_READONLY_TOOLS = {
    ("monitoring", "query_metric"),
    ("knowledge", "search"),
    ("gitlab", "get_pr"),
    ("threat-intel", "lookup"),
}

# 有副作用或高风险的 server：清单不可用且无缓存时默认拒绝（fail-closed）。
SIDE_EFFECT_SERVERS = {"shell-runner", "notes-sync", "sandbox-exec", "customer-db"}

# sandbox-exec.run_test 的白名单（与 MCP Server 端 allowlist 保持一致）。
SANDBOX_WHITELIST = ("pytest", "npm test", "go test ./...")

RULES_VERSION = "AG-RUNTIME-2026.08.23.1"


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _load_json_dict(name: str) -> dict:
    raw = os.getenv(name, "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _load_static_sources() -> dict:
    """管理员登记的只读扫描根：source_id -> 绝对路径（JSON 环境变量）。"""
    raw = os.getenv("AG_STATIC_SOURCES", "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items() if isinstance(value, str)}


def _load_static_roots() -> tuple:
    """前端可填/浏览的授权根白名单（JSON 数组）；为空时回退为已登记 sources 的路径。"""
    raw = os.getenv("AG_STATIC_ROOTS", "")
    if not raw:
        return ()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return ()
    if isinstance(data, dict):
        data = list(data.values())
    if not isinstance(data, list):
        return ()
    return tuple(str(item) for item in data if isinstance(item, str) and item)


@dataclass
class Settings:
    upstreams: dict = field(default_factory=lambda: dict(DEFAULT_UPSTREAMS))
    hook_secret: str = field(default_factory=lambda: _env("AG_HOOK_SECRET", "agentguard-dev-secret"))
    task_ttl_seconds: int = field(default_factory=lambda: int(_env("AG_TASK_TTL_SECONDS", "600")))
    manifest_ttl_seconds: int = field(default_factory=lambda: int(_env("AG_MANIFEST_TTL_SECONDS", "300")))
    upstream_timeout_seconds: float = field(default_factory=lambda: float(_env("AG_UPSTREAM_TIMEOUT", "10")))
    c2_hosts: tuple = field(default_factory=lambda: tuple(filter(None, (host.strip() for host in _env("AG_C2_HOSTS", "").split(",")))))
    rules_version: str = RULES_VERSION
    data_dir: str = field(default_factory=lambda: _env("AG_DATA_DIR", ""))
    # 运行时数据（事件 / 决策 / 证据 / 任务信封）的 SQLite 文件；默认放在数据目录或设备目录下，二者都空则只在内存。
    runtime_db_path: str = field(default_factory=lambda: _env("AG_RUNTIME_DB", "") or (
        os.path.join(_env("AG_DATA_DIR", "") or _env("AG_AGENT_DEVICE_DIR", ""), "runtime.db")
        if _env("AG_DATA_DIR", "") or _env("AG_AGENT_DEVICE_DIR", "") else ""))
    # 落盘数据的保留天数：启动只加载保留期内的数据，超期的每小时清理。
    runtime_retention_days: float = field(default_factory=lambda: float(_env("AG_RUNTIME_RETENTION_DAYS", "7")))
    max_body_bytes: int = field(default_factory=lambda: int(_env("AG_MAX_BODY_BYTES", str(2 * 1024 * 1024))))
    # ---- 静态扫描（独立模块，故障不影响网关） ----
    static_enabled: bool = field(default_factory=lambda: _env("AG_STATIC_ENABLED", "1") not in ("0", "false", "False"))
    static_sources: dict = field(default_factory=_load_static_sources)
    static_roots: tuple = field(default_factory=_load_static_roots)
    static_db_path: str = field(default_factory=lambda: _env(
        "AG_STATIC_DB",
        # AG_DATA_DIR 显式置空时同样回退到临时目录，避免写到当前工作目录下的相对路径。
        os.path.join(_env("AG_DATA_DIR", "") or "/tmp/agentguard-static", "static-scan.db")))
    static_admin_token: str = field(default_factory=lambda: _env("AG_STATIC_ADMIN_TOKEN", ""))
    static_scan_timeout: float = field(default_factory=lambda: float(_env("AG_STATIC_SCAN_TIMEOUT", "600")))
    # ---- 通用 Agent 接入（Claude Code 等，见《通用Agent接入设计与实施方案》） ----
    local_test: bool = field(default_factory=lambda: _env("AG_LOCAL_TEST", "0") == "1")
    agent_admin_token: str = field(default_factory=lambda: _env("AG_AGENT_ADMIN_TOKEN", ""))
    # 设备自助接入（终端安装后自动申请、管理员在控制台认证）：off 关闭；设置接入口令时申请须携带。
    agent_enroll: bool = field(default_factory=lambda: _env("AG_AGENT_ENROLL", "on").lower() not in ("off", "0", "false"))
    agent_enroll_key: str = field(default_factory=lambda: _env("AG_AGENT_ENROLL_KEY", ""))
    # 终端客户端下载：脚本包取自 endpoint/ 源码，预构建包取自 dist 目录（默认 endpoint/dist）。
    client_endpoint_dir: str = field(default_factory=lambda: _env("AG_CLIENT_ENDPOINT_DIR", ""))
    client_dist_dir: str = field(default_factory=lambda: _env("AG_CLIENT_DIST_DIR", ""))
    # 设备令牌预置：{"<token>": {"device_id", "actor": {...}, "profile"}}，入库只保留哈希。
    agent_devices: dict = field(default_factory=lambda: _load_json_dict("AG_AGENT_DEVICES"))
    # 管理接口签发的设备令牌（哈希）落盘目录；未设置时随 AG_DATA_DIR，二者都空则只在内存，重启即失效。
    agent_device_dir: str = field(default_factory=lambda: _env("AG_AGENT_DEVICE_DIR", _env("AG_DATA_DIR", "")))
    # 会话级任务信封的滑动有效期：通用 Agent 会话远长于单次 /run。
    agent_session_ttl_seconds: int = field(default_factory=lambda: int(_env("AG_AGENT_SESSION_TTL", "28800")))
    # 经 AgentGuard 中转（stdio 包装器 / HTTP 网关）的 MCP server 名；其余视为未受管（R018）。
    managed_mcp_servers: tuple = field(default_factory=lambda: tuple(
        item.strip() for item in _env("AG_MANAGED_MCP_SERVERS", "").split(",") if item.strip()))
    # 创新检测特性开关（消融评测用）：provenance / flow / anomaly / intent_llm / llm_judge，逗号分隔，列出的即关闭。
    disabled_features: frozenset = field(default_factory=lambda: frozenset(
        item.strip() for item in _env("AG_DISABLED_FEATURES", "").split(",") if item.strip()))

    # 行为基线：真实会话记录与训练出的模型（创新检测实施方案 §5）；未设置时随设备目录，为空则只在内存。
    behavior_dir: str = field(default_factory=lambda: _env("AG_BEHAVIOR_DIR", "") or (
        os.path.join(_env("AG_AGENT_DEVICE_DIR", _env("AG_DATA_DIR", "")), "behavior")
        if _env("AG_AGENT_DEVICE_DIR", _env("AG_DATA_DIR", "")) else ""))

    # 意图识别（intent.py）：配置了密钥才调用大模型分类，否则只用关键词。只发送用户提示词（已掩码凭证）。
    intent_llm_url: str = field(default_factory=lambda: _env("AG_INTENT_LLM_URL", ""))
    intent_llm_model: str = field(default_factory=lambda: _env("AG_INTENT_LLM_MODEL", ""))
    intent_llm_key: str = field(default_factory=lambda: _env("AG_INTENT_LLM_KEY", ""))
    intent_llm_timeout: float = field(default_factory=lambda: float(_env("AG_INTENT_LLM_TIMEOUT", "3")))

    def feature(self, name: str) -> bool:
        return name not in self.disabled_features


def load_settings() -> Settings:
    settings = Settings()
    # AG_UPSTREAM_<name> 形式的覆盖只接受已注册的 server 名，不新增任意上游。
    for name in list(settings.upstreams):
        override = os.getenv(f"AG_UPSTREAM_{name.replace('-', '_')}")
        if override:
            settings.upstreams[name] = override
    # 管理员登记 HTTP MCP 上游：只来自服务端环境变量，名称与 URL 均需合法。
    for name, url in _load_json_dict("AG_EXTRA_UPSTREAMS").items():
        if (isinstance(url, str) and re.match(r"^[A-Za-z0-9_-]{1,64}$", str(name))
                and url.startswith(("http://", "https://")) and name not in settings.upstreams):
            settings.upstreams[str(name)] = url
    return settings
