"""参数来源归因（创新检测实施方案 §3）。

提示注入的本质是：高危操作的关键参数（外发目标、执行的命令、写入的位置）来自不可信数据，
而不是用户指令。这里不识别注入文本“长什么样”，而是回溯关键参数“从哪里来”：

- 来源索引：会话内的用户指令（可信）与工具返回（数据），文本归一化后保留在内存；
- 关键参数：只对高危调用抽取（出网目标、反弹地址、持久化 / Agent 配置写入、敏感读取）；
- 归因：USER（用户提示词中出现）/ DATA（只在某条工具返回中出现）/ NONE（模型自行生成）；
- 指令痕迹：DATA 归因时，取参数在来源中出现位置前后的窗口，判断是否在对 Agent 下指令。

全部为字符串匹配，不调用模型；与注入载荷的措辞无关，换语言、换说法同样适用。
"""

import html
import ipaddress
import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field

from ..core import capability as C
from ..core.normalize import (
    injection_markers,
    is_agent_config_path,
    is_persistence_path,
    normalize_path,
    sensitive_path_class,
)
from ..models import redact_text

MAX_DATA_SOURCES = 48
MAX_USER_SOURCES = 16
MAX_SOURCE_CHARS = 16384
WINDOW_CHARS = 300
SNIPPET_CHARS = 320

# 高危类型：决定没有指令痕迹时是否仍需确认（见 §3.2 判定表）。
PAYLOAD_EGRESS = "payload_egress"      # 携带数据的出网：POST / 上传 / nc 重定向 / URL 夹带长串
DOWNLOAD_EXEC = "download_exec"        # 下载后交给解释器执行
REVERSE_SHELL = "reverse_shell"
PERSISTENCE = "persistence"
AGENT_CONFIG = "agent_config"
SENSITIVE_READ = "sensitive_read"
PLAIN_FETCH = "plain_fetch"            # 只读访问链接，不携带数据
DENY_KINDS = {PAYLOAD_EGRESS, DOWNLOAD_EXEC, REVERSE_SHELL, PERSISTENCE, AGENT_CONFIG, SENSITIVE_READ}
CONFIRM_KINDS = {PAYLOAD_EGRESS, DOWNLOAD_EXEC, REVERSE_SHELL}

ZERO_WIDTH_RE = re.compile("[​-‏⁠-⁤﻿]")
PAYLOAD_RE = re.compile(
    r"(?:^|\s)(?:-d|--data(?:-\w+)?|-F|--form(?:-string)?|-T|--upload-file|--post-data|--post-file|--json)(?:[\s=]|$)"
    r"|-X\s*['\"]?(?:POST|PUT|PATCH)\b|--request\s+['\"]?(?:POST|PUT|PATCH)\b", re.IGNORECASE)
SOCKET_TOOL_RE = re.compile(r"(?:^|[\s|;&(])(?:nc|ncat|netcat|socat|telnet)\s+(?:-\S+\s+)*([A-Za-z0-9.\-]+)\s+\d+")
DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/([A-Za-z0-9.\-]+)/\d+")
PIPE_EXEC_RE = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*python[0-9.]*\b|\bsh\s+-c\s+['\"]?\$\(|<\(\s*(?:curl|wget)")
URL_BLOB_RE = re.compile(r"[A-Za-z0-9+/_=%-]{40,}")

# 指令痕迹：称呼 Agent + 祈使动作；流程话术 + 祈使动作；隐藏载体。中英文同时覆盖。
AGENT_ADDRESS_RE = re.compile(
    r"\b(?:ai|a\.i\.|assistants?|agents?|llms?|bots?|copilot|claude|codex|gpt|chatgpt|model)\b"
    r"|助手|智能体|大模型|模型|机器人|自动化")
IMPERATIVE_RE = re.compile(
    r"\b(?:run|execute|exec|send|upload|post|append|write|read|fetch|download|install|submit|sync|forward|"
    r"copy|attach|include|must|should|please|do not tell|don't tell|without telling)\b"
    r"|请|执行|运行|发送|上传|提交|写入|追加|读取|同步|下载|安装|附上|务必|必须|需要")
PROCEDURE_RE = re.compile(r"步骤|先.{0,16}(?:再|然后|后)|为了.{0,24}请|\bfirst\b.{0,60}\bthen\b|\bstep\s*\d|"
                          r"\bbefore (?:continuing|proceeding|you)\b|\bin order to\b", re.IGNORECASE)
HIDDEN_MARKUP_RE = re.compile(r"<!--|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|<\w+[^>]*\shidden\b",
                              re.IGNORECASE)


def normalize_source(text: str) -> tuple[str, bool]:
    """归一化来源文本：解码 HTML 实体与 URL 编码，去掉零宽字符；返回 (文本, 是否含零宽字符)。"""
    raw = str(text or "")[:MAX_SOURCE_CHARS]
    hidden = bool(ZERO_WIDTH_RE.search(raw))
    raw = ZERO_WIDTH_RE.sub("", raw)
    raw = html.unescape(raw)
    if "%" in raw:
        raw = urllib.parse.unquote(raw)
    return raw, hidden


@dataclass
class Source:
    kind: str                 # USER / DATA
    raw: str                  # 归一化后的原文（保留大小写，用于片段）
    text: str                 # 小写，用于匹配
    tool: str = ""
    labels: tuple = ()
    round: int = 0
    event_id: str = ""
    evidence_id: str = ""
    hidden: bool = False      # 原文含零宽字符


class SourceIndex:
    """会话来源索引：用户指令与工具返回，只在内存中，随会话状态一起清理。"""

    def __init__(self) -> None:
        self.user: deque = deque(maxlen=MAX_USER_SOURCES)
        self.data: deque = deque(maxlen=MAX_DATA_SOURCES)

    def _source(self, kind: str, text: str, **meta) -> Source | None:
        raw, hidden = normalize_source(text)
        if not raw.strip():
            return None
        return Source(kind=kind, raw=raw, text=raw.lower(), hidden=hidden, **meta)

    def add_user(self, text: str, round: int = 0, event_id: str = "", evidence_id: str = "") -> None:
        source = self._source("USER", text, round=round, event_id=event_id, evidence_id=evidence_id)
        if source:
            self.user.append(source)

    def add_data(self, text: str, tool: str = "", labels=(), round: int = 0, event_id: str = "",
                 evidence_id: str = "") -> None:
        source = self._source("DATA", text, tool=tool, labels=tuple(labels or ()), round=round,
                              event_id=event_id, evidence_id=evidence_id)
        if source:
            self.data.append(source)


@dataclass
class KeyToken:
    kind: str                       # host / path
    value: str                      # 展示值
    risk: str                       # 高危类型
    variants: list = field(default_factory=list)   # 小写匹配形态


def _is_local_host(host: str, loopback_only: bool = False) -> bool:
    """本机 / 私网地址不作为出网关键参数；反弹 shell 只排除本机（内网主机同样可能是攻击者）。"""
    host = host.strip("[]").lower()
    if host in ("localhost", "") or host.endswith(".localhost"):
        return True
    if not loopback_only and host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if loopback_only:
        return address.is_loopback
    return address.is_loopback or address.is_private or address.is_link_local


def split_host(url: str) -> tuple[str, str]:
    """URL 的主机（小写）与端口。命令里的 URL 常带未展开的变量（localhost:$PORT）或残缺的 IPv6 字面量，
    urlsplit / .port 会抛 ValueError：退回按 netloc 文本切分，不能因解析失败让整个判定出错或丢掉出网目标。
    端口不是数字时视为未知。"""
    try:
        parsed = urllib.parse.urlsplit(url)
        return parsed.hostname or "", str(parsed.port or "")
    except ValueError:
        netloc = re.split(r"[/?#]", url.split("://", 1)[-1], maxsplit=1)[0].rsplit("@", 1)[-1]
        if netloc.startswith("["):
            host, _, rest = netloc[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else ""
        else:
            host, _, port = netloc.partition(":")
        return host.lower(), port if port.isdigit() else ""


def _host_token(host: str, port: str, risk: str) -> KeyToken | None:
    host = host.lower().strip(".")
    if not host or _is_local_host(host, loopback_only=risk == REVERSE_SHELL):
        return None
    variants = [host] + ([f"{host}:{port}"] if port else [])
    return KeyToken("host", f"{host}:{port}" if port else host, risk, variants)


def _path_token(path: str, risk: str, cwd: str) -> KeyToken | None:
    normalized = normalize_path(path)
    if not normalized:
        return None
    variants = {normalized.lower()}
    if normalized.startswith("~/"):
        variants.add("$home" + normalized[1:].lower())
    if cwd and normalized.startswith(cwd.rstrip("/") + "/"):
        variants.add(normalized[len(cwd.rstrip("/")) + 1:].lower())
    name = normalized.rsplit("/", 1)[-1].lower()
    # 有辨识度的文件名（.bashrc、id_rsa、authorized_keys 等）单独作为匹配形态；过短的（.env）不用。
    if len(name) >= 6:
        variants.add(name)
    return KeyToken("path", normalized, risk, sorted(variants, key=len, reverse=True))


def _command_of(call) -> str:
    return call.content or call.resource


def key_tokens(calls: list, cwd: str = "") -> list[KeyToken]:
    """高危调用的关键参数。普通读写、构建测试等调用不产生关键参数。"""
    tokens: list[KeyToken] = []
    commands = [_command_of(call) for call in calls if call.capability == C.EXEC]
    command = "\n".join(commands)
    payload = bool(PAYLOAD_RE.search(command))
    pipe_exec = bool(PIPE_EXEC_RE.search(command))
    for call in calls:
        if call.capability == C.NET_FETCH and "://" in call.resource:
            if call.origin.startswith("bash"):
                risk = DOWNLOAD_EXEC if pipe_exec else PAYLOAD_EGRESS if payload else PLAIN_FETCH
            else:
                risk = PLAIN_FETCH
            if URL_BLOB_RE.search(call.resource.split("://", 1)[-1]):
                risk = PAYLOAD_EGRESS
            token = _host_token(*split_host(call.resource), risk)
            if token:
                tokens.append(token)
        elif call.capability == C.FILE_WRITE:
            path = call.resource
            if is_agent_config_path(path):
                token = _path_token(path, AGENT_CONFIG, cwd)
            elif is_persistence_path(path):
                token = _path_token(path, PERSISTENCE, cwd)
            else:
                token = None
            if token:
                tokens.append(token)
        elif call.capability == C.FILE_READ and sensitive_path_class(call.resource) in ("credential_store",
                                                                                        "project_secret"):
            token = _path_token(call.resource, SENSITIVE_READ, cwd)
            if token:
                tokens.append(token)
    for text in commands:
        for host in DEV_TCP_RE.findall(text):
            token = _host_token(host, "", REVERSE_SHELL)
            if token:
                tokens.append(token)
        for host in SOCKET_TOOL_RE.findall(text):
            token = _host_token(host, "", PAYLOAD_EGRESS if "<" in text or "|" in text else REVERSE_SHELL)
            if token:
                tokens.append(token)
    unique: dict = {}
    for token in tokens:
        key = (token.kind, token.value)
        # 同一参数出现多次时取最危险的类型。
        if key not in unique or (token.risk in DENY_KINDS and unique[key].risk not in DENY_KINDS):
            unique[key] = token
    return list(unique.values())


def instruction_cues(window: str, hidden: bool = False) -> list[str]:
    """来源窗口中“对 Agent 下指令”的痕迹。"""
    cues = []
    lowered = window.lower()
    if injection_markers(window):
        cues.append("INJECTION_MARKER")
    if hidden or HIDDEN_MARKUP_RE.search(window):
        cues.append("HIDDEN_MARKUP")
    imperative = bool(IMPERATIVE_RE.search(lowered))
    if imperative and AGENT_ADDRESS_RE.search(lowered):
        cues.append("AGENT_DIRECTIVE")
    if imperative and PROCEDURE_RE.search(window):
        cues.append("PROCEDURE_DIRECTIVE")
    return cues


def _find(source: Source, variants: list) -> tuple[int, str]:
    for variant in variants:
        index = source.text.find(variant)
        if index >= 0:
            return index, variant
    return -1, ""


def attribute(token: KeyToken, index: SourceIndex, extra_user: list | None = None) -> dict:
    """单个关键参数的来源。DATA 归因取最近一条包含该参数的工具返回。"""
    record = {"token": token.value, "kind": token.kind, "risk": token.risk, "source": "NONE"}
    for text in extra_user or []:
        if any(variant in text.lower() for variant in token.variants):
            record["source"] = "USER"
            return record
    for source in reversed(index.user):
        if _find(source, token.variants)[0] >= 0:
            record.update(source="USER", round=source.round, event_id=source.event_id)
            return record
    for source in reversed(index.data):
        position, variant = _find(source, token.variants)
        if position < 0:
            continue
        start = max(0, position - WINDOW_CHARS)
        window = source.raw[start:position + len(variant) + WINDOW_CHARS]
        record.update(
            source="DATA", tool=source.tool, round=source.round, event_id=source.event_id,
            evidence_id=source.evidence_id, labels=list(source.labels),
            untrusted=any(label.startswith("UNTRUSTED_") or label == "POISONED_RESULT" for label in source.labels),
            cues=instruction_cues(window, source.hidden),
            snippet=redact_text(window, limit=SNIPPET_CHARS)["preview"],
        )
        return record
    return record


def attribute_calls(calls: list, index: SourceIndex | None, cwd: str = "",
                    extra_user: list | None = None) -> list[dict]:
    if index is None:
        return []
    return [attribute(token, index, extra_user) for token in key_tokens(calls, cwd)]
