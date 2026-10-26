"""终端本地快速判定与签名规则包（C/S 架构：服务端主检测 + 终端快速路径）。

服务端仍是权威决策点（污点、来源、数据流、基线、意图都依赖跨事件状态）；终端只做
**高置信、无状态**的拒绝，用于两种情况：
- 服务端可达：命中即本地拒绝，不等服务端；同时把事件带上本地判定实时上报，服务端照常
  评估并记录告警，判定不一致时打 LOCAL_MISMATCH 标签；
- 服务端不可达：本地规则照常生效，其余操作再按控制台配置的降级方式（放行 / 降级表）处理。

一致性约束：本地拒绝 ⊆ 服务端拒绝。规则包里的每条规则都对应服务端在 developer / strict
档案下必然 DENY 的确定性规则（R002 凭证库读取、R004 恶意命令、R017 Agent 配置篡改、
R006 直接外发敏感内容；strict 档案另加 R019 持久化写入、R020 工作区外写入），且两侧共用
同一份能力展开（toolmap / capability）与判定函数（normalize），差别只在模式来自规则包。
规则包中的模式取自服务端特征规则库（rules/library.py，控制台可启停）当前生效的集合，启停后版本随之变化。

规则包只含数据（正则源码与 flags、C2 主机、降级表），不含代码；用设备令牌派生的密钥做
HMAC-SHA256 签名，终端缓存前后都校验。本模块只依赖标准库，终端客户端（endpoint/）原样复制。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

from . import capability as C
from . import normalize as N
from . import toolmap

FORMAT = 1
FLAG_MASK = re.IGNORECASE | re.MULTILINE | re.DOTALL

# 规则键 → (服务端对应规则, 原因码, 严重度)。
RULES = {
    "credential_read": ("AG-RUNTIME-002", "SENSITIVE_FILE_READ", "CRITICAL"),
    "command_threat": ("AG-RUNTIME-004", "COMMAND_INJECTION", "CRITICAL"),
    "direct_egress": ("AG-RUNTIME-006", "SENSITIVE_DATA_EGRESS", "CRITICAL"),
    "agent_config_write": ("AG-RUNTIME-017", "AGENT_CONFIG_TAMPER", "CRITICAL"),
    "persistence_write": ("AG-RUNTIME-019", "PERSISTENCE_WRITE", "HIGH"),
    "workspace_escape": ("AG-RUNTIME-020", "WORKSPACE_ESCAPE_WRITE", "MEDIUM"),
}
# 各策略档案下服务端必然 DENY、因而可以下放的规则。service（业务服务档案）不下放。
PROFILE_RULES = {
    "developer": ("credential_read", "command_threat", "direct_egress", "agent_config_write"),
    "strict": ("credential_read", "command_threat", "direct_egress", "agent_config_write",
               "persistence_write", "workspace_escape"),
}

# 服务不可达且控制台选择“降级拦截”时的能力降级表。
DEFAULT_FAILSAFE = {
    "version": "failsafe/3",
    "deny_tools": ["Bash", "PowerShell", "WebFetch"],
    "deny_mcp": True,
    "write_tools": ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"],
    "deny_write_outside_workspace": True,
}


# ---------- 规则包：生成、版本、签名 ----------

def _sources(patterns) -> list:
    return [[pattern.pattern, pattern.flags & FLAG_MASK] for pattern in patterns]


def build_pack(rules_version: str, profile: str, agent: str, c2_hosts=()) -> dict:
    """从服务端规则库当前生效的特征生成规则包（不含签名）；包格式与旧版终端兼容。"""
    pack = {
        "format": FORMAT,
        "rules_version": rules_version,
        "profile": profile,
        "agent": agent,
        "rules": list(PROFILE_RULES.get(profile, ())),
        "c2_hosts": [host for host in c2_hosts if host],
        "patterns": {
            "credential_store": _sources(N.signatures("path.credential_store")),
            "agent_config": _sources(N.signatures("path.agent_config")),
            "persistence": _sources(N.signatures("path.persistence")),
            "sensitive_content": _sources(N.signatures("content.sensitive")),
            "threats": {kind: _sources(patterns) for kind, patterns in N.threat_patterns().items()},
        },
        "failsafe": dict(DEFAULT_FAILSAFE),
    }
    pack["version"] = pack_version(pack)
    return pack


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pack_version(pack: dict) -> str:
    body = {key: value for key, value in pack.items() if key != "version"}
    return "rp-" + hashlib.sha256(_canonical(body)).hexdigest()[:16]


def signing_key(token: str) -> bytes:
    """签名密钥 = 设备令牌的 SHA-256：服务端只存令牌哈希也能签，终端用自己的令牌验。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest().encode("ascii")


def sign(pack: dict, key: bytes) -> dict:
    return {"pack": pack, "signature": hmac.new(key, _canonical(pack), hashlib.sha256).hexdigest()}


def verify(envelope, key: bytes) -> dict | None:
    """校验签名与版本，通过返回规则包，否则 None。"""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("pack"), dict):
        return None
    pack = envelope["pack"]
    expected = hmac.new(key, _canonical(pack), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(envelope.get("signature") or "")):
        return None
    if pack.get("format") != FORMAT or pack.get("version") != pack_version(pack):
        return None
    return pack


# ---------- 本地判定 ----------

class CompiledPack:
    def __init__(self, pack: dict) -> None:
        patterns = pack.get("patterns") or {}

        def compile_all(items) -> tuple:
            return tuple(re.compile(source, flags & FLAG_MASK) for source, flags in items or [])

        self.version = str(pack.get("version") or "")
        self.profile = str(pack.get("profile") or "")
        self.rules = set(pack.get("rules") or ()) & set(RULES)
        self.c2_hosts = tuple(pack.get("c2_hosts") or ())
        self.credential_store = compile_all(patterns.get("credential_store"))
        self.agent_config = compile_all(patterns.get("agent_config"))
        self.persistence = compile_all(patterns.get("persistence"))
        self.sensitive_content = compile_all(patterns.get("sensitive_content"))
        threats = patterns.get("threats") or {}
        self.threats = {kind: compile_all(threats.get(kind)) for kind in N.THREAT_KINDS}
        self.failsafe = {**DEFAULT_FAILSAFE, **(pack.get("failsafe") or {})}


_COMPILED: dict = {}


def compiled(pack: dict) -> CompiledPack:
    version = str(pack.get("version") or "")
    if version not in _COMPILED:
        _COMPILED.clear()
        _COMPILED[version] = CompiledPack(pack)
    return _COMPILED[version]


def _hit(key: str, detail: str, reason_code: str = "") -> dict:
    rule, reason, severity = RULES[key]
    return {"check": key, "rule": rule, "reason_code": reason_code or reason, "severity": severity,
            "detail": detail[:160]}


def check_calls(rules: CompiledPack, calls: list, cwd: str, roots: tuple = ()) -> list[dict]:
    """对能力展开逐条检查，返回命中列表（首条为主命中）；每条规则最多命中一次。

    roots：cwd 之外同样视为工作区的目录（终端取 CLAUDE_PROJECT_DIR，对应服务端的会话起始目录）。"""
    roots = (cwd,) + tuple(root for root in roots if root)
    hits: dict = {}

    def add(key: str, detail: str, reason_code: str = "") -> None:
        if key in rules.rules and key not in hits:
            hits[key] = _hit(key, detail, reason_code)

    for call in calls:
        if call.capability == C.FILE_READ and N.is_credential_store(call.resource, rules.credential_store):
            add("credential_read", call.resource)
        if call.capability == C.EXEC:
            threats = N.command_threats(call.resource, rules.c2_hosts, rules.threats)
            if threats:
                add("command_threat", ",".join(threats), "C2_CONTACT" if "C2_CONTACT" in threats else "")
        if call.sink and N.sensitive_content_types(call.content, rules.sensitive_content):
            add("direct_egress", call.resource)
        if call.capability == C.FILE_WRITE:
            if N.is_agent_config_path(call.resource, rules.agent_config):
                add("agent_config_write", call.resource)
            if N.is_persistence_path(call.resource, rules.persistence):
                add("persistence_write", call.resource)
            if cwd and call.origin != C.QUOTED_REDIRECT:
                path = N.resolve_path(call.resource, cwd)
                if not (any(N.path_within(path, root) for root in roots) or N.is_scratch_path(path)):
                    add("workspace_escape", path)
    order = list(RULES)
    return sorted(hits.values(), key=lambda hit: order.index(hit["check"]))


def evaluate(pack: dict, agent: str, payload: dict, roots: tuple = ()) -> list[dict]:
    """PreToolUse 负载的本地判定；只覆盖内置工具，MCP 工具交给服务端（清单 / 中转状态）。"""
    if str(payload.get("hook_event_name") or "") != "PreToolUse":
        return []
    tool = str(payload.get("tool_name") or "")
    if not tool or toolmap.parse_mcp_tool(tool) or tool.startswith("mcp__"):
        return []
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    cwd = str(payload.get("cwd") or "")
    calls = toolmap.classify(agent, tool, tool_input, cwd)
    return check_calls(compiled(pack), calls, cwd, roots)


def failsafe_denies(pack: dict | None, agent: str, payload: dict, roots: tuple = ()) -> bool:
    """服务不可达且为“降级拦截”时 PreToolUse 是否拒绝（降级表来自规则包，缺省用内置表）。"""
    table = compiled(pack).failsafe if pack else DEFAULT_FAILSAFE
    tool = str(payload.get("tool_name") or "")
    if tool in table["deny_tools"] or (table["deny_mcp"] and tool.startswith("mcp__")):
        return True
    if tool not in table["write_tools"] or not table["deny_write_outside_workspace"]:
        return False
    data = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    cwd = str(payload.get("cwd") or "")
    if not cwd:
        return True
    if tool == "apply_patch":
        # 解析不出目标文件的补丁按工作区外处理。
        calls = toolmap.parse_patch(str(data.get("command") or ""), cwd)
    else:
        calls = [call for call in toolmap.classify(agent, tool, data, cwd) if call.capability == C.FILE_WRITE]
    paths = [N.resolve_path(call.resource, cwd) for call in calls if call.resource]
    roots = (cwd,) + tuple(root for root in roots if root)
    return not paths or any(not any(N.path_within(path, root) for root in roots) for path in paths)


def deny_output(reason_code: str, reference: str) -> dict:
    """本地拒绝的 Hook 输出：与服务端渲染格式一致，只含原因码与规则编号。"""
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"Blocked by AgentGuard: {reason_code} ({reference}). "
                                    "Do not retry this action through other tools.",
    }}
