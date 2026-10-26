"""行为基线异常分（创新检测实施方案 §5）。

每次工具调用离散成行为符号 `能力:资源类别`（例如 `FILE_READ:workspace`、`EXEC:vcs`、`NET_FETCH:external`），
默认训练三阶递归插值马尔可夫模型，并兼容已保存的一阶模型，在线对每一步计算：

- 罕见度：-log2 P(当前符号)，这类动作本身在正常开发中有多少见（主项）；
- 前文修正：max(0, log2 P(当前符号) / P(当前符号 | 最近历史))，在最近历史之后这一步比平时更少见多少；
  按真实分组的有效证据逐级插值较短后缀，默认最多使用三个历史符号；
- 意图偏离：由用户提示词推断意图类别，敏感资源类别不在该意图的预期集合中时加分。
  意图默认由关键词正则推断；可选由大模型异步分类（intent.py），结果回来后覆盖关键词结果。

计数可以是浮点数（训练时按来源或会话时间衰减加权）；旧的一阶模型还可带按设备个性化计数。

异常分只作为软信号（§5.2）：单独出现时只记录，会话已有不可信来源或秘密污点时由 R024 升级为确认。
打分本身全部为查表与字符串运算，不调用模型。
"""

import json
import math
import os
import re
import threading
import time
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass, field

from ..core import capability as C
from ..core import shell as S
from ..core.normalize import (
    is_agent_config_path,
    is_persistence_path,
    is_scratch_path,
    is_system_path,
    normalize_path,
    path_within,
    resolve_path,
    sensitive_path_class,
)
from . import behavior_evidence as E
from . import behavior_markov as M

FEATURE_SCHEMA_VERSION = 3
SEQUENCE_SEMANTICS_VERSION = 2
START = "<start>"
MIN_DETAIL_COUNT = 5
MAX_PENDING = 128
PENDING_TTL = 300.0
BASELINE_PATH = os.path.join(os.path.dirname(__file__), "baseline", "transitions.json")
MAX_RARITY = 12.0
MAX_CONTEXT = 6.0
DEVIATION_BONUS = 3.0
ALPHA = 0.5          # 加性平滑
BACKOFF_K = 20.0     # 上一符号样本量为 K 时，条件分布与频率各占一半（取约等于词表大小）
DEVICE_WEIGHT = 2.0  # 个性化计数相对全局计数的权重

# ---------- 资源类别 ----------

TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
PACKAGE_HOSTS = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com", "crates.io",
                 "proxy.golang.org", "pkg.go.dev", "repo.maven.apache.org", "rubygems.org", "packagist.org")
CODE_HOSTS = ("github.com", "api.github.com", "raw.githubusercontent.com", "gitlab.com", "bitbucket.org",
              "codeberg.org")
DOC_HOST_RE = re.compile(r"(^|\.)(docs?|developer|learn|wiki|readthedocs)\.|\.readthedocs\.io$|^(developer\.mozilla\.org|"
                         r"stackoverflow\.com|man7\.org)$")
LOCAL_HOST_RE = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
                           r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|host\.docker\.internal|[a-z0-9-]+)$")

# EXEC 按命令族归类：第一个非包装命令的名字（含常见子命令）。
COMMAND_FAMILIES = {
    "vcs": {"git", "gh", "hg", "svn"},
    "pkg": {"npm", "npx", "yarn", "pnpm", "pip", "pip3", "uv", "poetry", "pipx", "cargo", "go", "gem", "bundle",
            "composer", "mvn", "gradle", "apt", "apt-get", "brew", "conda"},
    "test": {"pytest", "jest", "vitest", "mocha", "tox", "nox", "rspec", "phpunit", "ctest"},
    "build": {"make", "cmake", "tsc", "webpack", "vite", "rollup", "esbuild", "bazel", "ninja", "gcc", "clang",
              "javac", "rustc"},
    "lint": {"eslint", "prettier", "ruff", "black", "flake8", "mypy", "pylint", "isort", "golangci-lint", "shellcheck",
             "clippy"},
    "container": {"docker", "docker-compose", "podman", "kubectl", "helm", "minikube", "kind"},
    "net": {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "rsync", "telnet", "ftp"},
    "interp": set(C.INTERPRETERS) | {"bash", "sh", "zsh"},
    "fs": {"ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "fd", "tree", "cp", "mv", "rm", "mkdir", "touch",
           "chmod", "ln", "du", "df", "stat", "file", "diff", "sed", "awk", "sort", "uniq", "cut", "tar", "zip",
           "unzip", "gzip", "base64", "xxd", "jq", "tee", "realpath", "dirname", "basename"},
    "shell": {"echo", "printf", "export", "source", ".", "cd", "pwd", "which", "type", "env", "true", "false",
              "sleep", "test", "[", "date", "whoami", "id", "uname", "hostname", "ps", "kill", "lsof", "crontab"},
}
FAMILY_BY_COMMAND = {name: family for family, names in COMMAND_FAMILIES.items() for name in names}
# “python -m pytest”、“npm test”这类调用归入测试 / 构建族。
TEST_HINT_RE = re.compile(r"\b(pytest|unittest|(npm|yarn|pnpm)\s+(run\s+)?test|go\s+test|cargo\s+test|make\s+test)\b")
BUILD_HINT_RE = re.compile(r"\b((npm|yarn|pnpm)\s+run\s+build|go\s+build|cargo\s+build|make(\s+\w+)?$)")


def _host(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        _port = parsed.port  # validate malformed ports without treating them as trusted hosts
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def host_class(url: str) -> str:
    host = _host(url)
    if not host:
        return "external"
    if LOCAL_HOST_RE.match(host) and ("." not in host or host[0].isdigit() or host == "host.docker.internal"):
        return "local"
    if host in PACKAGE_HOSTS:
        return "package"
    if host in CODE_HOSTS or host.endswith(tuple("." + item for item in CODE_HOSTS)):
        return "code_host"
    if DOC_HOST_RE.search(host):
        return "docs"
    return "external"


def path_class(path: str, cwd: str) -> str:
    path = normalize_path(path)
    if not path:
        return "workspace"
    if is_agent_config_path(path):
        return "agent_config"
    if is_persistence_path(path):
        return "persistence"
    secret = sensitive_path_class(path)
    if secret in ("credential_store", "project_secret"):
        return secret
    absolute = resolve_path(path, cwd or "/")
    if cwd and path_within(absolute, cwd):
        return "workspace"
    if absolute.startswith(TMP_PREFIXES) or is_scratch_path(absolute):
        return "tmp"
    if path.startswith(("~", "$HOME")) or re.match(r"^(/(home/[^/]+|root|Users/[^/]+)|[A-Za-z]:/Users/[^/]+)/",
                                                    absolute):
        return "home"
    if is_system_path(absolute):
        return "system"
    return "other"


def command_profile(command: str, depth: int = 0) -> dict:
    """Extract only executable/subcommand semantics; raw parameters never select a family."""
    if depth >= S.MAX_DEPTH:
        return {"family": "unknown", "effect": "unknown", "complete": False}
    structure = S.parse(command)
    profiles = []
    entries = []
    for segment in structure.commands:
        tokens = C._strip_wrappers(segment.words)
        if not tokens:
            continue
        name = C._command_name(tokens[0])
        args = tokens[1:]
        entries.append((segment, tokens))
        if name in C.SHELL_COMMANDS and args and args[0] in C.SHELL_INLINE_FLAGS and len(args) > 1:
            profiles.append(command_profile(args[1], depth + 1))
            continue
        family = FAMILY_BY_COMMAND.get(name, "unknown")
        effect = "unknown"
        if re.fullmatch(r"python[0-9.]*", name) and len(args) > 1 and args[0] == "-m":
            family = "test" if args[1] == "unittest" else FAMILY_BY_COMMAND.get(args[1], "interp")
        if name in {"npm", "yarn", "pnpm", "go", "cargo", "make"}:
            sub = args[1:] if args[:1] == ["run"] else args
            if sub and sub[0] in {"test", "build", "lint"}:
                family = sub[0]
        if name == "git" and args:
            if args[0] in {"status", "diff", "log", "show", "ls-files", "rev-parse", "remote"}:
                effect = "read"
            elif args[0] == "push":
                effect = "remote_write"
            elif args[0] in {"add", "commit", "checkout", "switch", "reset", "merge", "fetch", "pull", "clone"}:
                effect = "local_write"
        if name in {"curl", "wget"}:
            upload = any(a in {"-d", "-F", "-T", "--json", "--form", "--upload-file", "--data"}
                         or a.startswith(("--data", "--post", "--upload-file=", "--form=", "-d", "-F", "-T"))
                         for a in args)
            effect = "upload" if upload else "fetch"
        elif name in {"scp", "rsync"}:
            effect = "upload"
        profiles.append({"family": family, "effect": effect, "complete": structure.complete})
    if not profiles:
        return {"family": "unknown", "effect": "unknown", "complete": structure.complete}
    # A real download followed by a shell is an execution relationship, not a string hint.
    for index, (segment, tokens) in enumerate(entries[:-1]):
        name = C._command_name(tokens[0])
        following, shell_tokens = entries[index + 1]
        if name not in {"curl", "wget", "fetch"} or C._command_name(shell_tokens[0]) not in C.SHELL_COMMANDS:
            continue
        linked = following.before == "|"
        if following.before in {"&&", ";"} and len(shell_tokens) > 1:
            outputs = [path for op, path in segment.redirects if op == ">"]
            output_flags = {"-o", "--output"} if name == "curl" else {"-O", "--output-document"}
            outputs += [tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token in output_flags]
            linked = shell_tokens[1] in outputs
        if linked:
            return {"family": "pipe_exec", "effect": "download_then_exec", "complete": structure.complete}
    return profiles[0]


def command_family(command: str) -> str:
    return command_profile(command)["family"]


def parent_symbol(symbol: str) -> str:
    return symbol.rsplit(":", 1)[0] if symbol.count(":") >= 2 else symbol


def call_symbol(call, cwd: str) -> str:
    cap = call.capability
    if cap == C.EXEC:
        profile = command_profile(call.resource)
        base = f"EXEC:{profile["family"]}"
        return base + (":" + profile["effect"] if profile["effect"] != "unknown" else "")
    if cap in (C.FILE_READ, C.FILE_WRITE):
        return f"{cap}:{path_class(call.resource, cwd)}"
    if cap == C.NET_FETCH:
        return f"NET_FETCH:{host_class(call.resource)}"
    if cap == C.NET_SEARCH:
        return "NET_SEARCH"
    if cap == C.AGENT_SPAWN:
        return "AGENT_SPAWN"
    if cap == C.READONLY:
        return "META"
    return f"{cap}"


def dedupe(seq) -> list[str]:
    """同一步内重复的符号只保留首次出现：一条脚本可能展开出几十个相同类别的读写，不应放大这一步的权重。"""
    out: list[str] = []
    for symbol in seq or []:
        if symbol not in out:
            out.append(symbol)
    return out


def symbols(calls: list, cwd: str) -> list[str]:
    """一次请求的符号序列；Bash 复合命令按子段展开，重复的符号只保留首次出现。"""
    return dedupe(call_symbol(call, cwd) for call in calls or [])


# ---------- 意图 ----------

INTENT_KEYWORDS = {
    "test": r"test|测试|单测|pytest|jest|failing|失败|用例",
    "build": r"build|compile|构建|编译|打包|package|release|发布|bundle",
    "debug": r"debug|bug|fix|error|crash|调试|修复|报错|排查|异常|日志|log",
    "docs": r"doc|readme|how (do|to)|文档|说明|example|示例|教程|summar|总结|解释|explain",
    "refactor": r"refactor|rename|clean|重构|整理|格式|lint|format",
    "deps": r"depend|upgrade|update|install|依赖|升级|安装|版本",
    "ops": r"deploy|server|docker|k8s|kube|部署|运维|上线|服务器|nginx|systemd|cron|ssh|upload|上传|bundle",
    "intel": r"cve|advisory|漏洞|情报|vulnerab|security|安全",
    "transfer": r"upload|post |send|share|sync|上传|发到|发送|提交到|同步到",
}
INTENT_RES = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in INTENT_KEYWORDS.items()}

# 敏感资源类别：只有这些类别参与意图偏离计算；普通工作区读写、构建测试不计。
SENSITIVE_CLASSES = {"FILE_READ:credential_store", "FILE_READ:project_secret", "FILE_WRITE:persistence",
                     "FILE_WRITE:agent_config", "FILE_READ:agent_config", "FILE_WRITE:system", "FILE_WRITE:home",
                     "FILE_READ:home", "NET_FETCH:external", "EXEC:net"}
# 各意图下可以预期的敏感类别（其余敏感类别视为偏离）。
INTENT_EXPECTED = {
    "test": set(),
    "build": {"NET_FETCH:external"},
    "debug": {"FILE_READ:project_secret", "FILE_READ:home", "EXEC:net"},
    "docs": {"NET_FETCH:external"},
    "refactor": set(),
    "deps": {"NET_FETCH:external", "FILE_READ:home"},
    "ops": {"NET_FETCH:external", "EXEC:net", "FILE_WRITE:system", "FILE_READ:home", "FILE_READ:project_secret",
            "FILE_WRITE:home"},
    "intel": {"NET_FETCH:external"},
    "transfer": {"NET_FETCH:external", "EXEC:net"},
    # 只有大模型分类会给出这两类（关键词不推断）：写新代码、版本控制操作，都不预期敏感动作。
    "code": set(),
    "vcs": set(),
}


def infer_intent(text: str) -> list[str]:
    """用户提示词 → 意图类别（可多选）；无法判断时返回空列表，不计偏离。"""
    return [name for name, pattern in INTENT_RES.items() if pattern.search(text or "")]


def deviation(symbol: str, intents: list[str]) -> bool:
    symbol = parent_symbol(symbol)
    if symbol not in SENSITIVE_CLASSES or not intents:
        return False
    return not any(symbol in INTENT_EXPECTED[name] for name in intents)


# ---------- 模型 ----------

def _counts(raw: dict | None) -> tuple[dict, dict]:
    raw = raw or {}
    return dict(raw.get("unigram") or {}), {prev: dict(row) for prev, row in (raw.get("transitions") or {}).items()}


def _merge(base: dict, extra: dict, weight: float) -> dict:
    merged = dict(base)
    for key, value in extra.items():
        merged[key] = merged.get(key, 0.0) + weight * value
    return merged


class _Table:
    """一组（全局或全局 + 设备）计数上的概率查询。"""

    def __init__(self, unigram: dict, transitions: dict, alpha: float, backoff_k: float, coarse=True) -> None:
        self.unigram, self.transitions = unigram, transitions
        self.alpha, self.backoff_k = alpha, backoff_k
        self.total = sum(unigram.values())
        self.size = len(unigram) + 1
        self.row_totals = {prev: sum(row.values()) for prev, row in transitions.items()}
        self.coarse = None
        self.sparse_parents = {parent_symbol(symbol) for symbol, n in unigram.items()
                               if parent_symbol(symbol) != symbol and n < MIN_DETAIL_COUNT}
        if coarse:
            uni, rows = {}, {}
            for symbol, n in unigram.items():
                key = parent_symbol(symbol)
                uni[key] = uni.get(key, 0) + n
            for prev, row in transitions.items():
                target = rows.setdefault(parent_symbol(prev), {})
                for symbol, n in row.items():
                    key = parent_symbol(symbol)
                    target[key] = target.get(key, 0) + n
            self.coarse = _Table(uni, rows, alpha, backoff_k, False)

    def fallback(self, symbol: str) -> bool:
        parent = parent_symbol(symbol)
        return parent != symbol and (self.unigram.get(symbol, 0) < MIN_DETAIL_COUNT or parent in self.sparse_parents)

    def marginal(self, symbol: str) -> float:
        if self.coarse and self.fallback(symbol):
            return self.coarse.marginal(parent_symbol(symbol))
        return (self.unigram.get(symbol, 0.0) + self.alpha) / (self.total + self.alpha * self.size)

    def conditional(self, prev: str, symbol: str) -> float:
        if self.coarse and (self.fallback(symbol) or
                            (prev is not None and self.fallback(prev))):
            return self.coarse.conditional(parent_symbol(prev) if prev is not None else None, parent_symbol(symbol))
        n = self.row_totals.get(prev, 0.0)
        marginal = self.marginal(symbol)
        if n <= 0:
            return marginal
        weight = n / (n + self.backoff_k)
        return weight * self.transitions[prev].get(symbol, 0.0) / n + (1 - weight) * marginal


@dataclass
class Baseline:
    unigram: dict = field(default_factory=dict)        # 符号 -> 计数
    transitions: dict = field(default_factory=dict)    # 上一符号 -> {符号: 计数}
    devices: dict = field(default_factory=dict)        # 设备 -> {"unigram", "transitions"}（个性化）
    alpha: float = ALPHA
    backoff_k: float = BACKOFF_K
    device_weight: float = DEVICE_WEIGHT
    threshold: float = 10.0
    version: str = "empty"
    meta: dict = field(default_factory=dict)
    feature_schema_version: int = FEATURE_SCHEMA_VERSION
    sequence_semantics_version: int = SEQUENCE_SEMANTICS_VERSION
    score_semantics_version: int = 1
    evidence_schema_version: int = 0
    evidence: dict = field(default_factory=dict)
    scoring_config: dict = field(default_factory=dict)
    sequence_model: dict = field(default_factory=dict)
    disabled_reason: str = ""

    @property
    def compatible(self) -> bool:
        return (self.feature_schema_version == FEATURE_SCHEMA_VERSION and
                self.sequence_semantics_version == SEQUENCE_SEMANTICS_VERSION and
                self.score_semantics_version in (1, E.SCORE_VERSION, M.SCORE_VERSION) and not self.disabled_reason)

    @property
    def order(self) -> int:
        return self.scoring_config.get("order", 1) if self.score_semantics_version == M.SCORE_VERSION else 1

    def __post_init__(self) -> None:
        self._device_tables: dict = {}
        if self.score_semantics_version == M.SCORE_VERSION:
            try:
                if self.evidence_schema_version != M.SCHEMA_VERSION or self.devices or self.evidence:
                    raise ValueError("unsupported sequence schema or personalization")
                M.validate(self.unigram, self.sequence_model, self.scoring_config, self.backoff_k)
                self._global = M.Table(self.unigram, self.sequence_model, self.scoring_config, self.backoff_k)
                return
            except (KeyError, ValueError, TypeError, AttributeError, OverflowError, ZeroDivisionError):
                self.disabled_reason = self.disabled_reason or "invalid_sequence_model"
        if self.score_semantics_version == E.SCORE_VERSION:
            try:
                if self.evidence_schema_version != E.SCHEMA_VERSION or self.devices:
                    raise ValueError("unsupported evidence schema or personalization")
                E.validate(self.unigram, self.transitions, self.evidence, parent_symbol,
                           self.scoring_config, self.backoff_k)
                self._global = E.Table(self.unigram, self.transitions, self.evidence, parent_symbol,
                                       self.scoring_config, self.alpha, self.backoff_k)
                return
            except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
                self.disabled_reason = self.disabled_reason or "invalid_evidence_model"
        elif self.score_semantics_version != 1 or self.evidence_schema_version != 0 or self.evidence or self.sequence_model:
            self.disabled_reason = self.disabled_reason or "unsupported_score_semantics"
        self._global = _Table(self.unigram, self.transitions, self.alpha, self.backoff_k)

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        unigram, transitions = _counts(data)
        return cls(unigram=unigram, transitions=transitions, devices=dict(data.get("devices") or {}),
                   alpha=float(data.get("alpha", ALPHA)), backoff_k=float(data.get("backoff_k", BACKOFF_K)),
                   device_weight=float(data.get("device_weight", DEVICE_WEIGHT)),
                   threshold=float(data.get("threshold", 10.0)), version=str(data.get("version", "")),
                   meta=dict(data.get("meta") or {}),
                   feature_schema_version=int(data.get("feature_schema_version", 0)),
                   sequence_semantics_version=int(data.get("sequence_semantics_version", 0)),
                   score_semantics_version=int(data.get("score_semantics_version", 1)),
                   evidence_schema_version=int(data.get("evidence_schema_version", 0)),
                   evidence=data.get("evidence") or {}, scoring_config=data.get("scoring_config") or {},
                   sequence_model=data.get("sequence_model") or {})

    @classmethod
    def load(cls, path: str = BASELINE_PATH) -> "Baseline":
        try:
            with open(path, encoding="utf-8") as handle:
                return cls.from_dict(json.load(handle))
        except (OSError, ValueError, TypeError, AttributeError):
            return cls(disabled_reason="baseline_unavailable")

    def table(self, device: str = "") -> _Table:
        if not device or device not in self.devices:
            return self._global
        if device not in self._device_tables:
            unigram, transitions = _counts(self.devices[device])
            merged_rows = {prev: _merge(self.transitions.get(prev, {}), row, self.device_weight)
                           for prev, row in transitions.items()}
            self._device_tables[device] = _Table(
                _merge(self.unigram, unigram, self.device_weight), {**self.transitions, **merged_rows},
                self.alpha, self.backoff_k)
        return self._device_tables[device]

    def seen(self, symbol: str) -> bool:
        return self.unigram.get(symbol, 0.0) > 0

    def step_score(self, prev: str, cur: str, intents: list[str], device: str = "", *, history=None) -> dict:
        table = self.table(device)
        probability_table = table
        probability_cur, probability_prev = cur, prev
        if self.score_semantics_version == M.SCORE_VERSION and self.compatible:
            probability_prev = M.context(history if history is not None else prev, self.order)
            prev = probability_prev[-1] if probability_prev else None
        if table.coarse and (table.fallback(cur) or (prev is not None and table.fallback(prev))):
            probability_table = table.coarse
            probability_cur = parent_symbol(cur)
            probability_prev = parent_symbol(prev) if prev is not None else None
        marginal = probability_table.marginal(probability_cur)
        conditional = probability_table.conditional(probability_prev, probability_cur)
        rarity = min(MAX_RARITY, -math.log2(marginal))
        context = min(MAX_CONTEXT, max(0.0, math.log2(marginal / conditional)))
        deviates = deviation(cur, intents)
        score = rarity + context + (DEVIATION_BONUS if deviates else 0.0)
        result = {"score": round(score, 2), "prev": prev, "symbol": cur, "rarity": round(rarity, 2),
                  "context": round(context, 2), "marginal": round(marginal, 5), "probability": round(conditional, 5),
                  "unseen": not self.seen(cur), "deviation": deviates, "personalized": table is not self._global}
        if self.score_semantics_version == E.SCORE_VERSION and self.compatible:
            result["evidence"] = {**probability_table.diagnostics(probability_prev),
                                  "level": "fine" if probability_table is table else "coarse"}
        elif self.score_semantics_version == M.SCORE_VERSION and self.compatible:
            result.update(history=list(probability_prev), order=self.order,
                          evidence={**table.diagnostics(probability_prev), "level": "fine"})
        return result


class BehaviorState:
    """会话内的有界行为历史与意图；prev 保留一阶兼容接口。

    意图先按关键词给出；配置了大模型分类时，pending 是进行中的分类（concurrent Future，结果为意图列表，
    None 表示调用失败），在下一次打分前合并：非空则覆盖，空列表（"继续"、"好的"）沿用上一轮的意图，
    失败或超过 deadline 保持关键词结果。
    """

    def __init__(self) -> None:
        self._history = (START,)
        self.model_version = ""
        self.intents: list[str] = []
        self.intent_source = ""
        self.steps = 0
        self.pending = None
        self.deadline = 0.0
        self._prior: tuple[list[str], str] = ([], "")
        self.intent_status = "keyword"
        self.generation = 0
        self.lock = threading.RLock()
        self.inflight: OrderedDict = OrderedDict()
        self.finished: OrderedDict = OrderedDict()
        self.attempts = 0
        self.last_registration = ""

    @property
    def history(self) -> tuple:
        return self._history

    @property
    def prev(self):
        return self._history[-1] if self._history else None

    @prev.setter
    def prev(self, value):
        self._history = (value,) if value is not None else ()

    def append_symbols(self, symbols):
        self._history = (self._history + tuple(symbols))[-M.MAX_ORDER:]

    def set_prompt(self, text: str, pending=None, deadline: float = 0.0) -> None:
        with self.lock:
            self.settle()
            self.generation += 1
            self.intent_status = "pending" if pending is not None else "keyword"
            self._prior = (self.intents, self.intent_source)
            intents = infer_intent(text)
            if intents:
                self.intents, self.intent_source = intents, "keyword"
            self.pending, self.deadline = pending, deadline
            self._pending_generation = self.generation
            if pending is not None:
                pending.add_done_callback(lambda future: setattr(future, "_ag_completed_at", time.time()))

    def settle(self, wait: bool = False) -> None:
        """Merge ready results; blocking wait is only retained for explicit offline callers."""
        with self.lock:
            future = self.pending
            if future is None:
                return
            if self._pending_generation != self.generation:
                self.pending = None
                self.intent_status = "superseded"
                return
            if future.done() and self.deadline and getattr(future, "_ag_completed_at", 0) > self.deadline:
                self.pending = None
                self.intent_status = "timeout"
                return
            if not future.done() and wait:
                try:
                    future.result(timeout=max(0.0, self.deadline - time.time()))
                except Exception:  # 超时 / 调用异常：按失败处理
                    pass
            if not future.done():
                if wait or (self.deadline and time.time() >= self.deadline):
                    self.intent_status = "timeout"
                if wait or (self.deadline and time.time() >= self.deadline):
                    self.pending = None
                return
            self.pending = None
            try:
                labels = future.result()
            except Exception:
                labels = None
            if labels is None:
                self.intent_status = "failed"
                return
            self.intent_status = "settled"
            if labels:
                self.intents, self.intent_source = list(labels), "llm"
            else:
                self.intents, self.intent_source = self._prior

    def register(self, key: str, fingerprint: str, record: dict) -> dict | None:
        """Register an attempt once. State is scoped to one device trace."""
        with self.lock:
            if key in self.inflight or key in self.finished:
                self.last_registration = "duplicate"
                return None
            self.attempts += 1
            version = record.get("model_version", "")
            if version and self.model_version and version != self.model_version:
                self.prev = None
            if version:
                self.model_version = version
            record.update(key=key, fingerprint=fingerprint, sequence=self.attempts, at=time.monotonic(),
                          parallel=bool(self.inflight) and record.get("executes", True), generation=self.generation)
            if self.inflight and record.get("executes", True):
                self.prev = None
                for item in self.inflight.values():
                    item["parallel"] = True
            self.inflight[key] = record
            self.last_registration = "registered"
            return record

    def complete(self, key: str, fingerprint: str, status: str) -> dict | None:
        with self.lock:
            if key and key in self.finished:
                return None
            if not key:
                matches = [k for k, item in self.inflight.items() if item["fingerprint"] == fingerprint]
                if len(matches) != 1:
                    self.prev = None
                    return None
                key = matches[0]
            item = self.inflight.get(key)
            if item is None or (fingerprint and item["fingerprint"] != fingerprint):
                self.prev = None
                return None
            self.inflight.pop(key)
            item["execution"] = status
            stale_model = bool(item.get("model_version") and self.model_version and
                               item["model_version"] != self.model_version)
            item["cut_before"] = item["parallel"] or self.prev is None or stale_model
            item["cut_after"] = item["parallel"] or status in {"unknown", "failed"} or stale_model
            if status in {"succeeded", "failed"}:
                self.steps += 1
                if item["cut_after"] or not item["symbols"]:
                    self.prev = None
                else:
                    self.append_symbols(item["symbols"])
            elif status == "unknown":
                self.prev = None
            self.finished[key] = item
            while len(self.finished) > MAX_PENDING * 2:
                self.finished.popitem(last=False)
            return item



def score_symbols(baseline: Baseline, prev: str, seq: list[str], intents: list[str], device: str = "", *, history=None) -> dict | None:
    """对一步（可能含多个子符号）打分：取最异常的子符号。"""
    worst = None
    components = {name: 0.0 for name in ("rarity", "rarity_intent", "rarity_context", "full")}
    history = M.context(history if history is not None else prev)
    for symbol in seq:
        step = baseline.step_score(prev, symbol, intents, device, history=history)
        values = {"rarity": step["rarity"], "rarity_intent": step["rarity"] + (DEVIATION_BONUS if step["deviation"] else 0),
                  "rarity_context": step["rarity"] + step["context"], "full": step["score"]}
        components = {name: max(components[name], value) for name, value in values.items()}
        if worst is None or step["score"] > worst["score"]:
            worst = step
        prev = symbol
        history = (history + (symbol,))[-M.MAX_ORDER:]
    if worst is None:
        return None
    return {**worst, "components": components, "threshold": baseline.threshold, "intents": list(intents),
            "anomalous": worst["score"] >= baseline.threshold, "baseline": baseline.version}


def score_request(baseline: Baseline, state: BehaviorState, calls: list, cwd: str, device: str = "") -> dict | None:
    """对一次请求打分（不修改状态）。"""
    if not baseline.compatible:
        return {"anomalous": False, "disabled_reason": baseline.disabled_reason or "incompatible_baseline",
                "baseline": baseline.version}
    with state.lock:
        switched = state.model_version and state.model_version != baseline.version
        history = () if state.inflight or switched else state.history
        prev = history[-1] if history else None
        result = score_symbols(baseline, prev, symbols(calls, cwd), state.intents, device, history=history)
        coverage = [command_profile(call.resource)["complete"] for call in calls if call.capability == C.EXEC]
        return {**result, "intent_source": state.intent_source, "intent_status": state.intent_status,
                "parser_complete": all(coverage)} if result else None


def advance(state: BehaviorState, calls: list, cwd: str) -> None:
    seq = symbols(calls, cwd)
    if seq:
        state.append_symbols(seq)
        state.steps += 1


def fit(sessions, *, scoring_mode: str = "legacy", granularity: str = "group",
        backoff_k: float = BACKOFF_K, prior_strength: float = 1.0, order: int = M.DEFAULT_ORDER) -> dict:
    """sessions：[{"weight": 权重, "steps": [{"symbols": [...]} 或 {"cut": True}, …]}]；返回（浮点）频率与转移计数。"""
    if scoring_mode == M.MODE:
        return M.fit(sessions, START, order=order, granularity=granularity,
                     backoff_k=backoff_k, prior_strength=prior_strength)
    if scoring_mode != "legacy":
        return E.fit(sessions, parent_symbol, START, mode=scoring_mode, granularity=granularity,
                     backoff_k=backoff_k, prior_strength=prior_strength)
    unigram: dict = {}
    transitions: dict = {}
    for session in sessions:
        weight = float(session.get("weight", 1.0))
        prev = START
        for step in session["steps"]:
            if step.get("cut"):
                prev = None     # 被剔除的步骤：前后两步之间的转移不计
                continue
            if step.get("cut_before"):
                prev = None
            for symbol in step["symbols"]:
                unigram[symbol] = unigram.get(symbol, 0.0) + weight
                if prev is not None:
                    row = transitions.setdefault(prev, {})
                    row[symbol] = row.get(symbol, 0.0) + weight
                prev = symbol
            if step.get("cut_after"):
                prev = None
    rounded = lambda table: {key: round(value, 4) for key, value in sorted(table.items())}
    return {"unigram": rounded(unigram),
            "transitions": {prev: rounded(row) for prev, row in sorted(transitions.items())}}
