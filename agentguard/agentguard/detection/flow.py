"""数据流溯源（创新检测实施方案 §4）。

把会话级的“读过敏感数据”细化为“哪份秘密、以什么形态、流到了哪里”：

- 秘密指纹：敏感读取的返回中抽取秘密值（KEY=VALUE 的值、URL 中的口令、私钥片段、高熵串），
  出网内容按原文、URL 编码、hex 以及其中 base64 片段解码后比对；
- 暂存物：把敏感文件或已暂存文件复制、重定向、打包到其他位置，或写入内容含秘密指纹，
  目标路径登记为派生秘密；暂存物同时登记到设备级表（带 TTL），供同设备其他会话关联；
- 出网检查：只把“作为数据发出去”的文件当作外发来源（-d @f、-F f=@f、-T f、--post-file、
  `$(cat f)`、`cat f | curl`、`< f`、scp 源文件），`source .env && curl …` 这类正常用法不算外发。

全部为字符串与集合运算，不调用模型。
"""

import base64
import binascii
import math
import re
import shlex
import threading
import time
import urllib.parse
from collections import Counter, OrderedDict
from dataclasses import dataclass, field

from ..core import capability as C
from ..core import shell as S
from ..core.normalize import normalize_path, resolve_path, sensitive_content_types, sensitive_path_class
from . import provenance as P

MIN_SECRET_LEN = 8
MAX_SECRETS = 256
MAX_STAGED = 128
ARTIFACT_TTL_SECONDS = 24 * 3600
MAX_DEVICE_ARTIFACTS = 512

SECRET_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*['\"]?([^'\"\s#]+)", re.M)
SECRET_NAME_RE = re.compile(r"secret|token|passw|pwd|key|credential|auth|private|dsn|database_url|conn|api|cert",
                            re.IGNORECASE)
URL_PASSWORD_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^:/\s@]+:([^@\s/]{6,})@", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*(.+?)\s*-----END", re.S)
HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")

# “作为数据发出去”的文件：curl / wget 上传参数、命令替换、管道、输入重定向。
UPLOAD_ARG_RE = re.compile(
    r"(?:^|\s)(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|--json)[\s=]+['\"]?(?:[\w.-]+=)?@([^\s'\";|&)]+)"
    r"|(?:^|\s)(?:-T|--upload-file)[\s=]+['\"]?([^\s'\";|&)]+)"
    r"|--post-file[\s=]+['\"]?([^\s'\";|&)]+)")
SUBST_READ_RE = re.compile(r"\$\(\s*(?:cat|base64|xxd|gzip\s+-c|head|tail)\s+(?:-\S+\s+)*([^\s)|;]+)")
PIPE_READ_RE = re.compile(r"(?:cat|base64|xxd|gzip\s+-c|tar\s+\S+)\s+(?:-\S+\s+)*([^\s|;]+)[^|;\n]*\|\s*"
                          r"(?:curl|wget|nc|ncat|netcat|socat|ssh)\b")
STDIN_READ_RE = re.compile(r"\b(?:nc|ncat|netcat|socat|curl|ssh)\b[^|;\n]*<\s*([^\s<>|;&]+)")
REMOTE_COPY_RE = re.compile(r"\b(?:scp|rsync)\s+((?:[^\s;|&]+\s+)+?)[\w.-]*@?[\w.-]+:\S*")
ARCHIVE_RE = re.compile(r"\btar\s+-?[A-Za-z]*c[A-Za-z]*f\s+(\S+)\s+([^;|&\n]+)|\bzip\s+(?:-\S+\s+)*(\S+\.zip)\s+([^;|&\n]+)")


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def extract_secrets(text: str) -> set:
    """从敏感读取的返回中抽取秘密值；整行 KEY=VALUE 也保留，用于识别 base64 截断外带。"""
    values = set()
    text = str(text or "")
    for line in text.splitlines():
        match = SECRET_ASSIGN_RE.match(line)
        if match and SECRET_NAME_RE.search(match.group(1)) and len(match.group(2)) >= MIN_SECRET_LEN:
            values.add(match.group(2))
            values.add(line.strip())
    values.update(URL_PASSWORD_RE.findall(text))
    for block in PRIVATE_KEY_RE.findall(text):
        body = re.sub(r"\s+", "", block)
        values.update(body[i:i + 40] for i in range(0, min(len(body), 160), 40) if len(body[i:i + 40]) >= 24)
    for token in HIGH_ENTROPY_RE.findall(text):
        if _entropy(token) >= 3.5 and not token.startswith("http"):
            values.add(token)
    return {value for value in values if len(value) >= MIN_SECRET_LEN}


def _decoded_runs(text: str):
    for run in BASE64_RUN_RE.findall(text):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(run + "=" * (-len(run) % 4)).decode("utf-8", "ignore")
            except (binascii.Error, ValueError):
                continue
            if decoded.isprintable() and len(decoded) >= 8:
                yield decoded
                break


def content_hits(text: str, secrets) -> list[tuple[str, str]]:
    """出网内容中的秘密：返回 [(秘密值, 形态)]；形态为 plain / urlencoded / hex / base64。"""
    text = str(text or "")
    if not text or not secrets:
        return []
    lowered = text.lower()
    hits = []
    decoded = list(_decoded_runs(text))
    for secret in secrets:
        if secret in text:
            hits.append((secret, "plain"))
        elif urllib.parse.quote(secret, safe="") in text:
            hits.append((secret, "urlencoded"))
        elif secret.encode().hex() in lowered:
            hits.append((secret, "hex"))
        elif any(secret in item or (len(item) >= 16 and item in secret) for item in decoded):
            hits.append((secret, "base64"))
    return hits


def _resolve(path: str, cwd: str) -> str:
    path = normalize_path(str(path or "").strip("'\""))
    if not path or path.startswith("$"):
        return path
    return resolve_path(path, cwd or "/")


def payload_paths(command: str, cwd: str) -> list[str]:
    """命令中作为数据发出去的文件。"""
    paths = []
    for groups in UPLOAD_ARG_RE.findall(command):
        paths += [item for item in groups if item and item != "-"]
    paths += SUBST_READ_RE.findall(command) + PIPE_READ_RE.findall(command) + STDIN_READ_RE.findall(command)
    for sources in REMOTE_COPY_RE.findall(command):
        paths += [item for item in sources.split() if not item.startswith("-")]
    return list(dict.fromkeys(_resolve(path, cwd) for path in paths if path))


def _is_secret_path(path: str) -> bool:
    return sensitive_path_class(path) in ("credential_store", "project_secret")


@dataclass
class FlowState:
    """会话内的数据流状态；device 为同设备共享的暂存物表（OrderedDict，带锁）。"""

    secrets: dict = field(default_factory=dict)     # 秘密值 -> {event_id, path}
    staged: dict = field(default_factory=dict)      # 路径 -> {event_id, origin, trace_id, at}
    device: "DeviceArtifacts | None" = None
    incomplete_reasons: set = field(default_factory=set)

    def learn(self, text: str, event_id: str, path: str) -> int:
        added = 0
        for value in extract_secrets(text):
            if value not in self.secrets and len(self.secrets) < MAX_SECRETS:
                self.secrets[value] = {"event_id": event_id, "path": path}
                added += 1
        return added

    def stage(self, path: str, record: dict) -> None:
        if path in self.staged or len(self.staged) < MAX_STAGED:
            self.staged[path] = record
        if self.device is not None:
            self.device.put(path, record)

    def staged_record(self, path: str) -> dict | None:
        if path in self.staged:
            return self.staged[path]
        return self.device.get(path) if self.device is not None else None


class DeviceArtifacts:
    """同一设备跨会话共享的暂存物登记表（有界、带 TTL）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: OrderedDict = OrderedDict()

    def put(self, path: str, record: dict) -> None:
        with self._lock:
            self._items[path] = record
            self._items.move_to_end(path)
            while len(self._items) > MAX_DEVICE_ARTIFACTS:
                self._items.popitem(last=False)

    def get(self, path: str) -> dict | None:
        with self._lock:
            record = self._items.get(path)
            if record and time.time() - record.get("at", 0) > ARTIFACT_TTL_SECONDS:
                self._items.pop(path, None)
                return None
            return record


def _commands(calls: list) -> list[str]:
    return [call.resource for call in calls if call.capability == C.EXEC]


def _archive_writes(command: str, cwd: str) -> list[tuple[str, list]]:
    pairs = []
    for tar_dest, tar_src, zip_dest, zip_src in ARCHIVE_RE.findall(command):
        dest, sources = (tar_dest, tar_src) if tar_dest else (zip_dest, zip_src)
        pairs.append((_resolve(dest, cwd), [_resolve(item, cwd) for item in sources.split() if not item.startswith("-")]))
    return pairs


def plan_request(flow: FlowState, calls: list, cwd: str, depth: int = 0) -> list[dict]:
    """Pure prediction: only supported data dependencies produce staged candidates."""
    if depth >= S.MAX_DEPTH:
        return []
    virtual = dict(flow.staged)
    staged = []

    def origin(path):
        if _is_secret_path(path):
            return {"origin": path, "status": "confirmed"}
        return virtual.get(path) or flow.staged_record(path)

    def add(dest, sources, via, certain):
        record = next((origin(src) for src in sources if src != dest and origin(src)), None)
        if not record or _is_secret_path(dest):
            return
        item = {"path": dest, "origin": record.get("origin", sources[0]), "via": via,
                "status": "confirmed" if certain and record.get("status", "confirmed") == "confirmed" else "possible",
                "confirm_on_success": certain and len(structure.commands) == 1}
        virtual[dest] = item
        staged.append(item)

    for command in _commands(calls):
        structure = S.parse(command)
        pipe_sources = []
        for segment in structure.commands:
            tokens = C._strip_wrappers(segment.words)
            if not tokens:
                continue
            name, args = C._command_name(tokens[0]), tokens[1:]
            certain = structure.complete and segment.before not in {"||", "&"}
            if name in C.SHELL_COMMANDS and args and args[0] in C.SHELL_INLINE_FLAGS and len(args) > 1:
                nested_flow = FlowState(secrets=flow.secrets, staged=virtual, device=flow.device)
                for item in plan_request(nested_flow, C.expand_command(args[1]), cwd, depth + 1):
                    virtual[item["path"]] = item
                    staged.append(item)
                continue
            incoming = list(pipe_sources) if segment.before == "|" else []
            inputs = [_resolve(path, cwd) for op, path in segment.redirects if op == "<"]
            paths = [_resolve(path, cwd) for path in C._path_args(args)]
            output_sources = []
            if name in {"cp", "mv", "install"} and len(paths) >= 2:
                add(paths[-1], paths[:-1], name, certain)
            elif name in {"tar", "zip"}:
                for dest, sources in _archive_writes(shlex.join(tokens), cwd):
                    add(dest, sources, "archive", certain)
            elif name in {"cat", "head", "tail", "base64", "xxd", "gzip", "jq"}:
                output_sources = paths + inputs + incoming
            elif name == "tee":
                output_sources = inputs + incoming
                for dest in paths:
                    add(dest, output_sources, "pipe", certain)
            # echo/printf outputs and unrelated reads are intentionally independent.
            for op, dest in segment.redirects:
                if op in {">", ">>"}:
                    add(_resolve(dest, cwd), output_sources, "redirect", certain)
            pipe_sources = output_sources
    for call in calls:
        if call.capability == C.FILE_WRITE and call.content and content_hits(call.content, flow.secrets):
            item = {"path": _resolve(call.resource, cwd), "origin": "content", "via": "content", "status": "confirmed", "confirm_on_success": True}
            staged.append(item)
    return list({item["path"]: item for item in staged}.values())


def commit_staged(flow: FlowState, staged: list[dict], trace_id: str, event_id: str,
                  call_id: str = "", execution: str = "succeeded") -> list[dict]:
    """Commit only with execution evidence; failures/unknown outcomes stay possible."""
    for item in staged:
        status = item.get("status", "confirmed") if execution == "succeeded" and item.get("confirm_on_success", True) else "possible"
        flow.stage(item["path"], {**item, "event_id": event_id, "trace_id": trace_id, "call_id": call_id,
                                  "status": status, "execution": execution, "at": time.time()})
    return staged


def observe_request(flow: FlowState, calls: list, cwd: str, trace_id: str, event_id: str) -> list[dict]:
    """Compatibility helper for observed executions; live adapters use plan/commit separately."""
    return commit_staged(flow, plan_request(flow, calls, cwd), trace_id, event_id)


def observe_result(flow: FlowState, calls: list, text: str, cwd: str, event_id: str) -> int:
    """敏感读取（或已暂存文件、或内容本身含凭证）的返回：学习秘密指纹。"""
    paths = [_resolve(call.resource, cwd) for call in calls if call.capability == C.FILE_READ]
    secret_path = next((path for path in paths if _is_secret_path(path) or flow.staged_record(path)), "")
    if not secret_path and not sensitive_content_types(text):
        return 0
    return flow.learn(text, event_id, secret_path or (paths[0] if paths else ""))


def destination(calls: list, cwd: str) -> str:
    """出网目标：external / local / none（无出网）。识别不出主机的出网按 external 处理。"""
    sinks = [call for call in calls if call.sink]
    if not sinks:
        return "none"
    if any(token.kind == "host" for token in P.key_tokens(calls, cwd)) \
            or any(REMOTE_COPY_RE.search(command) for command in _commands(calls)):
        return "external"
    hosts = [P.split_host(call.resource)[0] for call in calls
             if call.capability == C.NET_FETCH and "://" in call.resource]
    if hosts and all(P._is_local_host(host) for host in hosts):
        return "local"
    return "external"


def egress_hits(flow: FlowState, calls: list, cwd: str) -> list[dict]:
    """出网调用携带的秘密：内容指纹命中、外发暂存物、直接外发敏感文件。"""
    if destination(calls, cwd) != "external":
        return []
    hits = []
    # Request-local candidates allow pre-execution detection of copy-then-upload.
    # They are not persisted and do not claim the request has executed.
    virtual = FlowState(secrets=flow.secrets, staged=dict(flow.staged), device=flow.device)
    for call in calls:
        if not call.sink:
            continue
        for secret, form in content_hits(call.content or call.resource, flow.secrets)[:3]:
            source = flow.secrets.get(secret, {})
            hits.append({"kind": "fingerprint", "form": form, "path": source.get("path", ""),
                         "event_id": source.get("event_id", ""), "preview": secret[:4] + "…"})
    for command in _commands(calls):
        structure = S.parse(command)
        pipeline = ""
        for segment in structure.commands:
            rendered = shlex.join(segment.words)
            rendered += "".join(" " + op + " " + shlex.quote(path) for op, path in segment.redirects)
            pipeline = pipeline + " | " + rendered if segment.before == "|" else rendered
            tokens = C._strip_wrappers(segment.words)
            name = C._command_name(tokens[0]) if tokens else ""
            if name in C.NETWORK_COMMANDS or (name in C.SHELL_COMMANDS and "-c" in tokens):
                for path in payload_paths(pipeline, cwd):
                    record = virtual.staged_record(path)
                    if record:
                        hits.append({"kind": "staged" if record.get("status", "confirmed") == "confirmed" else "possible",
                                     "path": path, "origin": record.get("origin", ""),
                                     "event_id": record.get("event_id", ""), "trace_id": record.get("trace_id", "")})
                    elif _is_secret_path(path):
                        hits.append({"kind": "direct", "path": path})
            for item in plan_request(virtual, [C.NormalizedCall(C.EXEC, rendered)], cwd):
                if not structure.complete or segment.before == "||":
                    item["status"] = "possible"
                virtual.staged[item["path"]] = item
    unique = {}
    for hit in hits:
        unique.setdefault((hit["kind"], hit.get("path"), hit.get("form")), hit)
    return list(unique.values())


def coverage(flow: FlowState, calls: list, hits: list) -> dict:
    """Report observational limits; no match is never proof of harmlessness."""
    reasons = set(flow.incomplete_reasons)
    supported = {"cp", "mv", "install", "tar", "zip", "cat", "head", "tail", "base64", "xxd", "gzip",
                 "jq", "tee", "echo", "printf", "curl", "wget", "nc", "scp", "rsync", "source", "."}
    for command in _commands(calls):
        structure = S.parse(command)
        reasons.update(structure.reasons)
        for segment in structure.commands:
            tokens = C._strip_wrappers(segment.words)
            if not tokens or C._command_name(tokens[0]) not in supported:
                reasons.add("unsupported_command")
            if any("$" in token or "`" in token for token in tokens):
                reasons.add("dynamic_values")
    if len(flow.secrets) >= MAX_SECRETS or len(flow.staged) >= MAX_STAGED:
        reasons.add("state_capacity")
    if any(hit["kind"] == "possible" for hit in hits):
        reasons.add("uncertain_execution")
    known = any(hit["kind"] != "possible" for hit in hits)
    return {"result": "known_secret_match" if known else "observation_incomplete" if reasons else "no_known_secret_match",
            "complete": not reasons, "reasons": sorted(reasons), "proves_absence": False}


# ---------- 攻击阶段（§4.3） ----------

STAGE_ORDER = ("INJECTION", "CRED_ACCESS", "STAGING", "EXECUTION", "PERSISTENCE", "EXFIL")
STAGE_BY_REASON = {
    "INJECTED_INSTRUCTION": "INJECTION", "DATA_DERIVED_TARGET": "INJECTION",
    "UNTRUSTED_SOURCE_HIGH_RISK": "INJECTION", "POISONED_TOOL_DESCRIPTION": "INJECTION",
    "SENSITIVE_FILE_READ": "CRED_ACCESS", "PROJECT_SECRET_READ": "CRED_ACCESS", "MASS_DATA_READ": "CRED_ACCESS",
    "COMMAND_INJECTION": "EXECUTION", "C2_CONTACT": "EXFIL",
    "PERSISTENCE_WRITE": "PERSISTENCE", "AGENT_CONFIG_TAMPER": "PERSISTENCE",
    "SENSITIVE_DATA_EGRESS": "EXFIL", "SECRET_FLOW_EGRESS": "EXFIL", "URL_DATA_EXFIL": "EXFIL",
    "SENSITIVE_SESSION_EGRESS": "EXFIL", "SECRET_FLOW_UNCERTAIN": "EXFIL",
}
STAGE_BY_LABEL = {"POISONED_RESULT": "INJECTION", "SECRET_STAGED": "STAGING", "SECRET_LEARNED": "CRED_ACCESS"}


def chain_stages(chain: list) -> list[dict]:
    """按攻击链节点推断阶段序列：每个阶段取首次出现的节点，并标注是否被拦截。"""
    stages: dict = {}
    for node in chain:
        found = set()
        decision = node.get("decision") or {}
        for rule in decision.get("matched_rules") or []:
            if rule.get("decision") != "ALLOW" and rule.get("reason_code") in STAGE_BY_REASON:
                found.add(STAGE_BY_REASON[rule["reason_code"]])
        found.update(STAGE_BY_LABEL[label] for label in node.get("labels") or [] if label in STAGE_BY_LABEL)
        for stage in found:
            if stage not in stages:
                stages[stage] = {"stage": stage, "event_id": node.get("event_id", ""),
                                 "timestamp": node.get("timestamp", ""),
                                 "blocked": decision.get("decision") in ("DENY", "ASK")
                                 and decision.get("resolution") != "APPROVED"}
    return sorted(stages.values(), key=lambda item: (item["timestamp"], STAGE_ORDER.index(item["stage"])))
