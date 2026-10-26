"""参数规范化与确定性特征提取。

所有规则都在规范化后的参数上执行：
- 路径：URL 解码、Unicode NFKC、反斜杠统一、`.`/`..` 折叠、绝对路径判定；
- 命令：原文摘要 + 解析出的 URL、管道目标、下载执行结构、反弹连接特征；
- 文本：敏感配置模式与提示注入标记的检测（用于污点与来源标记）。
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import unquote

# ---------- 路径规范化 ----------


def normalize_path(raw: str) -> str:
    """多轮解码 + 规范化，防御 %2e%2e、双重编码、Unicode 分隔符等变体。"""
    path = str(raw or "")
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    path = unicodedata.normalize("NFKC", path).replace("\\", "/")
    # 去掉 file:// 前缀后按 POSIX 规则折叠 ./ 与 ../。
    if path.startswith("file://"):
        path = path[len("file://"):]
    path = _expand_home(path)
    return posixpath.normpath(path)


# 指向用户目录的变量写法（POSIX shell、PowerShell、cmd）统一为 `~`，与 `~/.ssh/...` 等同处理，
# 并据此判定为绝对路径（工作区外写入）。
HOME_VAR_RE = re.compile(
    r"^(?:\$\{?HOME\}?|\$\{?env:(?:USERPROFILE|HOME)\}?|%USERPROFILE%)(?=/|$)", re.IGNORECASE)
APPDATA_VAR_RE = re.compile(r"^(?:\$\{?env:(LOCALAPPDATA|APPDATA)\}?|%(LOCALAPPDATA|APPDATA)%)(?=/|$)", re.IGNORECASE)


# PowerShell 的 $PROFILE（及 $PROFILE.CurrentUserAllHosts 等）指向用户的 profile 脚本。
PS_PROFILE_RE = re.compile(r"^\$\{?profile\}?(\.\w+)?$", re.IGNORECASE)


def _expand_home(path: str) -> str:
    if PS_PROFILE_RE.match(path):
        return "~/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"
    if HOME_VAR_RE.match(path):
        return HOME_VAR_RE.sub("~", path, count=1)
    match = APPDATA_VAR_RE.match(path)
    if match:
        local = (match.group(1) or match.group(2)).upper() == "LOCALAPPDATA"
        return ("~/AppData/Local" if local else "~/AppData/Roaming") + path[match.end():]
    return path


# Windows 盘符路径（规范化后为 `C:/...`）：大小写不敏感，匹配与包含判断按小写进行。
DRIVE_RE = re.compile(r"^[A-Za-z]:/")


def is_absolute(path: str) -> bool:
    return path.startswith(("/", "~")) or bool(DRIVE_RE.match(path))


def resolve_path(path: str, cwd: str) -> str:
    """相对路径以 cwd 为基准展开；两者都先规范化（Windows 的反斜杠路径同样适用）。"""
    path = normalize_path(path)
    if is_absolute(path) or not cwd:
        return path
    return posixpath.normpath(posixpath.join(normalize_path(cwd), path))


def path_within(path: str, root: str) -> bool:
    """规范化路径 path 是否等于 root 或位于其下；盘符路径不区分大小写。"""
    root = normalize_path(root).rstrip("/")
    if DRIVE_RE.match(root) or DRIVE_RE.match(path):
        path, root = path.lower(), root.lower()
    return path == root or path.startswith(root + "/")


# 工作区外仍视为正常写入的临时目录。
SCRATCH_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/", "/dev/null")
WINDOWS_TEMP_RE = re.compile(r"^[a-z]:/(users/[^/]+/appdata/local/temp|windows/temp)(/|$)")


# Agent 自身的工作数据目录（用户主目录下）：Claude Code 计划模式的计划文件、待办、后台任务的临时目录。
# 只放行这几处；记忆（projects/*/memory）、skills、commands、settings 会被后续会话加载，仍按工作区外写入确认。
AGENT_SCRATCH_RE = re.compile(
    r"^(?:~|/users/[^/]+|/home/[^/]+|/root|[a-z]:/users/[^/]+)/\.claude/(?:plans/|todos/|jobs/[^/]+/tmp/)")


def is_scratch_path(path: str) -> bool:
    return path.startswith(SCRATCH_PREFIXES) or bool(WINDOWS_TEMP_RE.match(path.lower())) \
        or bool(AGENT_SCRATCH_RE.match(path.lower()))


def _match(path: str, patterns) -> bool:
    if any(pattern.search(path) for pattern in patterns):
        return True
    # Windows 文件系统不区分大小写：`.SSH/ID_RSA` 与 `.ssh/id_rsa` 是同一文件。
    return bool(DRIVE_RE.match(path)) and any(pattern.search(path.lower()) for pattern in patterns)


def is_system_path(path: str) -> bool:
    """规范化后指向系统目录或 cron 等持久化位置。"""
    SYSTEM_PREFIXES = (
        "/etc", "/usr", "/bin", "/sbin", "/root", "/lib", "/boot",
        "/proc", "/sys", "/dev", "/var/spool/cron", "/etc/cron.d", "/opt/homebrew",
    )
    return path.startswith("/") and any(
        path == prefix or path.startswith(prefix + "/") for prefix in SYSTEM_PREFIXES
    )


def escapes_root(path: str, root: str = "/app/uploads") -> bool:
    """以 root 为基点判断规范化路径是否逃逸上传根目录。"""
    joined = posixpath.normpath(posixpath.join(root, path))
    return not (joined == root or joined.startswith(root + "/"))


# ---------- 特征库 ----------
# 路径 / 命令 / 内容特征不写在代码里：服务端由 rules/library.py 从 YAML 规则包（rules/rulepacks/）加载，按控制台
# 启停状态编译后注入；终端从服务端签名下发的规则包编译（fastpath），判定函数显式传入模式。
# 组名与 rules.library.GROUPS 一致；某组没有启用的特征时为空，视为不命中。

THREAT_KINDS = ("download", "pipe_to_shell", "base64_exec", "reverse_shell")
_SIGNATURES: dict | None = None


_SIGNATURE_OBSERVER = None


def install_signatures(sets: dict, observer=None) -> None:
    global _SIGNATURES, _SIGNATURE_OBSERVER
    _SIGNATURES = dict(sets)
    _SIGNATURE_OBSERVER = observer


_SCOPED_SIGNATURES = ContextVar("agentguard_scoped_signatures", default=None)


@contextmanager
def scoped_signatures(values: dict, observer=None):
    """Use a local rule snapshot without changing global rules or hit observers."""
    token = _SCOPED_SIGNATURES.set((values, observer))
    try:
        yield
    finally:
        _SCOPED_SIGNATURES.reset(token)


def record_signature_hit(group: str, value: str) -> None:
    scoped = _SCOPED_SIGNATURES.get()
    observer = scoped[1] if scoped is not None else _SIGNATURE_OBSERVER
    if observer is not None:
        try:
            observer(group, value)
        except Exception:  # 旁路统计不影响终端或服务端检测。
            pass


def matching_keywords(group: str, text: str, *, exact: bool = False, first: bool = False) -> list:
    lowered = (text or "").lower()
    hits = []
    for word in signatures(group):
        if (word.lower() == lowered) if exact else (word.lower() in lowered):
            record_signature_hit(group, word)
            hits.append(word)
            if first:
                break
    return hits


def signatures(group: str) -> tuple:
    scoped = _SCOPED_SIGNATURES.get()
    if scoped is not None:
        return scoped[0].get(group, ())
    if _SIGNATURES is None:
        _bootstrap()
    return _SIGNATURES.get(group, ())


def _bootstrap() -> None:
    global _SIGNATURES
    try:
        from ..rules.library import bootstrap
    except ImportError:  # 终端副本（agentguard_endpoint.core）不含规则库，特征全部来自签名规则包
        _SIGNATURES = {}
        return
    _SIGNATURES = bootstrap()


# 主机级凭证库：开发机上的云/集群/包源/SSH/GPG 凭证与 AgentGuard 自身令牌（path.credential_store）。
# 任何策略档案下读取都拒绝（区别于项目内 .env 等“项目密钥”，path.sensitive）。
def is_credential_store(path: str, patterns=None) -> bool:
    return _match(normalize_path(path), signatures("path.credential_store") if patterns is None else patterns)


def is_sensitive_path(path: str) -> bool:
    normalized = normalize_path(path)
    return (_match(normalized, signatures("path.sensitive")) or _match(normalized, signatures("path.secret_name_hint"))
            or is_credential_store(normalized))


# 密钥文件的模板/示例（.env.example 等）按约定不含真实值，通用 Agent 场景不按密钥处理。
SECRET_TEMPLATE_RE = re.compile(r"\.(example|sample|template|tmpl|dist|defaults?)$", re.IGNORECASE)


def sensitive_path_class(path: str) -> str:
    """"credential_store"（主机凭证库）/ "project_secret"（密钥文件）/ "template"（密钥文件模板）/
    "name_hint"（仅文件名关键字，业务服务策略；开发机上会误伤 api_key_validator.py 这类源码）/ ""。"""
    normalized = normalize_path(path)
    if is_credential_store(normalized):
        return "credential_store"
    if _match(normalized, signatures("path.sensitive")):
        return "template" if SECRET_TEMPLATE_RE.search(normalized) else "project_secret"
    return "name_hint" if _match(normalized, signatures("path.secret_name_hint")) else ""


# ---------- 通用 Agent：防护自身配置 / 持久化位置 ----------

# Agent 配置与 AgentGuard 客户端：被 Agent 自己改写即可关闭防护（R017，path.agent_config）。
def is_agent_config_path(path: str, patterns=None) -> bool:
    return _match(normalize_path(path), signatures("path.agent_config") if patterns is None else patterns)


# 持久化位置：shell 启动脚本、定时任务、用户服务、登录项、git hooks、SSH 授权（R019，path.persistence）。
def is_persistence_path(path: str, patterns=None) -> bool:
    return _match(normalize_path(path), signatures("path.persistence") if patterns is None else patterns)


# ---------- 命令解析 ----------

URL_RE = re.compile(r"https?://[^\s'\"<>]+")
SYSTEM_C2_PATHS = ("/b", "/collect")


def threat_patterns() -> dict:
    """命令威胁特征（command.*）：服务端取规则库生效集合；终端规则包下发同样的源码与 flags。"""
    return {kind: signatures("command." + kind) for kind in THREAT_KINDS}


def parse_command(cmd: str) -> dict:
    """解析命令结构化特征，规则基于这些特征而非原文子串拼接。"""
    text = str(cmd or "")
    urls = URL_RE.findall(text)
    patterns = threat_patterns()
    return {
        "raw_len": len(text),
        "urls": urls[:8],
        "hosts": [re.sub(r"^https?://|:\d+.*$", "", url) for url in urls[:8]],
        **{kind: any(pattern.search(text) for pattern in patterns[kind]) for kind in THREAT_KINDS},
    }


def command_threats(cmd: str, c2_hosts: tuple = ("c2-sink",), patterns: dict = None) -> list[str]:
    """返回命中的威胁标签列表：DOWNLOAD_EXEC / REVERSE_SHELL / BASE64_EXEC / C2_CONTACT。"""
    text = str(cmd or "")
    patterns = threat_patterns() if patterns is None else patterns

    def hit(kind: str) -> bool:
        return any(pattern.search(text) for pattern in patterns.get(kind) or ())

    threats = []
    if hit("reverse_shell"):
        threats.append("REVERSE_SHELL")
    if hit("base64_exec"):
        threats.append("BASE64_EXEC")
    if hit("download") and hit("pipe_to_shell"):
        threats.append("DOWNLOAD_EXEC")
    hosts = [re.sub(r"^https?://|:\d+.*$", "", url) for url in URL_RE.findall(text)[:8]]
    if any(host in hosts for host in c2_hosts if host):
        threats.append("C2_CONTACT")
    return threats


# ---------- 敏感内容 / 注入标记 ----------

def sensitive_content_types(text: str, patterns=None) -> list[str]:
    """检测文本中的敏感配置/凭证类型（用于 R006 直检与污点标记；特征组 content.sensitive）。"""
    hits = []
    for pattern in signatures("content.sensitive") if patterns is None else patterns:
        if pattern.search(text or ""):
            hits.append("SENSITIVE_CONFIG")
            break
    env_lines = re.findall(r"^[A-Z][A-Z0-9_]{3,}=\S+$", text or "", re.MULTILINE)
    if len(env_lines) >= 3:
        hits.append("ENV_DUMP")
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text or "")
    if len(emails) >= 3:
        hits.append("PII")
    return hits


def injection_markers(text: str) -> list[str]:
    """检测不可信文本中的提示注入标记（Skill 正文 / MCP 描述 / 工具返回；特征组 content.injection_marker）。"""
    return matching_keywords("content.injection_marker", text)


# ---------- Langflow 代码检测（R010） ----------

def langflow_code_threats(code: str) -> list[str]:
    """validate/code 端点的副作用特征（特征组 code.langflow，每条带威胁标签）；
    default 参数求值由 SUBPROCESS_IMPORT+lambda 组合覆盖。"""
    threats = []
    for pattern, name in signatures("code.langflow"):
        if pattern.search(code or "") and name not in threats:
            threats.append(name)
    # CVE-2026-0770 的载荷形态：函数默认参数中触发 lambda + subprocess。
    if re.search(r"def\s+\w+\s*\([^)]*=", code or "", re.DOTALL) and "lambda" in (code or ""):
        threats.append("DEFAULT_PARAM_SIDE_EFFECT")
    return threats
