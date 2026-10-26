"""特征规则库：YAML 规则包的加载、校验、启停与注入。

路径 / 命令 / 内容 / 配置特征不写在代码里，而是放在 YAML 规则包中：
- 内置包随镜像发布（rulepacks/*.yaml，只读，规则只能停用不能删除）；
- 自定义包由控制台上传，保存在规则目录 packs/ 下，可整体删除；
- 启停状态单独存放（state.json），不改动规则包本身；变更记录保留最近 100 条。

代码只定义“特征组”（GROUPS，即特征被谁、以什么语义使用），规则包决定每组包含哪些特征。
生效集合编译后注入 normalize（install_signatures），运行时引擎、终端规则包（fastpath）
与静态扫描都从同一份集合取特征，保证“终端本地拒绝 ⊆ 服务端拒绝”。

多进程：网关进程内直接生效；静态扫描子进程从同一规则目录加载，
长驻进程调用 refresh() 按文件变化重新加载（节流）。
规则目录：AG_RULES_DIR，缺省为 <AG_AGENT_DEVICE_DIR 或 AG_DATA_DIR>/rules；都未配置时只在内存中生效。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..core import normalize as N
from .catalog import STRATEGIES
from .hits import HitCounter, ObservedKeyword, ObservedPattern
from .trace import record_feature

FORMAT = 1
BUILTIN_DIR = Path(__file__).resolve().parent / "rulepacks"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
FLAG_BITS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}

MAX_PACK_BYTES = 256 * 1024
MAX_RULES = 500
MAX_ITEMS = 200
MAX_PATTERN_LEN = 512
MAX_KEYWORD_LEN = 200
MAX_TESTS = 20
MAX_SAMPLE_LEN = 4000
MAX_HISTORY = 100
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
TAG_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,40}$")
# 嵌套量词（如 (a+)+、(\w*x)*）是灾难性回溯的典型形态；Python re 无超时，上传时直接拒绝。
NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d*,\d*\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d*,)")


class PackError(ValueError):
    pass


@dataclass(frozen=True)
class Group:
    scope: str      # runtime / static：控制台分区展示
    kind: str       # regex / keyword
    sample: str     # path（规范化后匹配）/ command / text / key / value
    title: str
    used_by: str
    keyword_match: str = "substring"   # 关键字组：substring 子串 / exact 完整匹配（均不区分大小写）
    attach: str = ""                   # tag / severity：组内条目附带规则的标签或定级

    def as_dict(self, name: str) -> dict:
        return {"group": name, "scope": self.scope, "kind": self.kind, "sample": self.sample, "title": self.title,
                "used_by": self.used_by, "keyword_match": self.keyword_match if self.kind == "keyword" else "",
                "attach": self.attach}


_COMMAND_USE = "AG-RUNTIME-004 · 终端快速判定 · AG-STATIC-CC-003 / SKILL-003"
GROUPS = {
    "path.credential_store": Group("runtime", "regex", "path", "主机凭证库路径", "AG-RUNTIME-002 · 终端快速判定"),
    "path.sensitive": Group("runtime", "regex", "path", "项目密钥文件路径",
                            "AG-RUNTIME-002 · 污点来源 · 静态数据流敏感源"),
    "path.secret_name_hint": Group("runtime", "regex", "path", "文件名敏感关键字（宽松）",
                                   "AG-RUNTIME-002（service 档案）· 污点来源"),
    "path.agent_config": Group("runtime", "regex", "path", "Agent / AgentGuard 配置路径",
                               "AG-RUNTIME-017 · 终端快速判定"),
    "path.persistence": Group("runtime", "regex", "path", "持久化位置", "AG-RUNTIME-019 · 终端快速判定（strict）"),
    "command.download": Group("runtime", "regex", "command", "命令 · 下载", _COMMAND_USE),
    "command.pipe_to_shell": Group("runtime", "regex", "command", "命令 · 交给解释器", _COMMAND_USE),
    "command.base64_exec": Group("runtime", "regex", "command", "命令 · 编码载荷执行", _COMMAND_USE),
    "command.reverse_shell": Group("runtime", "regex", "command", "命令 · 反弹连接", _COMMAND_USE),
    "content.sensitive": Group("runtime", "regex", "text", "敏感配置 / 凭证内容",
                               "AG-RUNTIME-006 · 污点标记 · 终端快速判定"),
    "content.injection_marker": Group("runtime", "keyword", "text", "提示注入标记",
                                      "AG-RUNTIME-009 / 022 · 工具返回污点 · AG-STATIC-CC-005"),
    "code.langflow": Group("runtime", "regex", "text", "代码副作用", "离线代码载荷回归", attach="tag"),
    "skill.credential": Group("static", "regex", "text", "Skill 指令 · 读取敏感对象", "AG-STATIC-SKILL-001 / MCP-003"),
    "skill.exfil": Group("static", "regex", "text", "Skill 指令 · 外发动作", "AG-STATIC-SKILL-001 / MCP-003"),
    "skill.conceal": Group("static", "regex", "text", "Skill 指令 · 隐藏操作", "AG-STATIC-SKILL-001 / MCP-003"),
    "skill.override": Group("static", "regex", "text", "Skill 指令 · 覆盖指令", "AG-STATIC-SKILL-001 / MCP-003"),
    "agent.broad_tool_grant": Group("static", "keyword", "value", "Agent 通配授权", "AG-STATIC-CC-001",
                                    keyword_match="exact"),
    "config.sensitive_mount": Group("static", "regex", "text", "宿主敏感挂载", "AG-STATIC-CFG-003", attach="severity"),
    "config.auth_off_when_true": Group("static", "keyword", "key", "鉴权开关（为真即关闭）", "AG-STATIC-CFG-002",
                                       keyword_match="exact"),
    "config.auth_off_when_false": Group("static", "keyword", "key", "鉴权开关（非真即关闭）", "AG-STATIC-CFG-002",
                                        keyword_match="exact"),
    "config.secret_key_hint": Group("static", "keyword", "key", "密钥类键名", "AG-STATIC-CFG-001"),
    "config.weak_secret": Group("static", "keyword", "value", "弱密钥取值", "AG-STATIC-CFG-001", keyword_match="exact"),
    "config.weak_secret_marker": Group("static", "keyword", "value", "占位符片段", "AG-STATIC-CFG-001"),
}


# ---------- 规则包解析与校验 ----------

@dataclass
class Rule:
    rule_id: str
    group: str
    title: str
    description: str
    severity: str
    default_enabled: bool
    sources: list           # regex：[{"re", "flags"}]；keyword：[str]
    compiled: tuple         # regex：编译后的模式；keyword：原文
    tag: str = ""
    tests: dict = field(default_factory=dict)

    def entries(self) -> tuple:
        """注入特征组的条目：附带标签 / 定级的组为 (模式, 值)。"""
        attach = GROUPS[self.group].attach
        if attach == "tag":
            return tuple((item, self.tag) for item in self.compiled)
        if attach == "severity":
            return tuple((item, self.severity) for item in self.compiled)
        return self.compiled

    def fingerprint(self) -> list:
        return [self.rule_id, self.group, self.sources, self.tag, self.severity]

    def as_dict(self) -> dict:
        kind = GROUPS[self.group].kind
        return {"rule_id": self.rule_id, "group": self.group, "title": self.title, "description": self.description,
                "severity": self.severity, "default_enabled": self.default_enabled, "tag": self.tag,
                "patterns": self.sources if kind == "regex" else [],
                "keywords": self.sources if kind == "keyword" else [], "tests": self.tests}

    def snapshot(self, pack) -> dict:
        return {"rule_id": self.rule_id, "title": self.title, "group": self.group,
                "pack": pack.pack_id, "pack_version": pack.version, "tag": self.tag,
                "revision": hashlib.sha256(json.dumps(
                    [pack.pack_id, pack.version, self.fingerprint(), self.title], ensure_ascii=False,
                    sort_keys=True).encode()).hexdigest()[:16]}


@dataclass
class Pack:
    pack_id: str
    name: str
    version: str
    description: str
    builtin: bool
    rules: list
    source: str = ""        # 规则包原文（控制台查看 / 下载）
    path: str = ""

    def summary(self) -> dict:
        return {"pack": self.pack_id, "name": self.name, "version": self.version, "description": self.description,
                "builtin": self.builtin, "rules": len(self.rules)}


def _text(value, where: str, limit: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise PackError(f"{where}: 应为字符串")
    text = str(value).strip()
    if required and not text:
        raise PackError(f"{where}: 不能为空")
    if len(text) > limit:
        raise PackError(f"{where}: 超过 {limit} 字符")
    return text


def _flags(value, where: str) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        value = list(value)
    if not isinstance(value, list) or any(item not in FLAG_BITS for item in value):
        raise PackError(f"{where}: flags 只能是 i / m / s 的组合")
    bits = 0
    for item in value:
        bits |= FLAG_BITS[item]
    return bits


def _flag_letters(bits: int) -> str:
    return "".join(letter for letter, bit in FLAG_BITS.items() if bits & bit)


def _compile(source: str, bits: int, where: str):
    if not source:
        raise PackError(f"{where}: 正则不能为空")
    if len(source) > MAX_PATTERN_LEN:
        raise PackError(f"{where}: 正则超过 {MAX_PATTERN_LEN} 字符")
    if NESTED_QUANTIFIER_RE.search(source):
        raise PackError(f"{where}: 含嵌套量词（如 (a+)+），可能导致灾难性回溯")
    try:
        return re.compile(source, bits)
    except re.error as exc:
        raise PackError(f"{where}: 正则无法编译：{exc}") from None


def match_entry(group: str, item, sample: str) -> bool:
    """单个特征条目是否命中样本；语义与各消费点一致。"""
    spec = GROUPS[group]
    if spec.kind == "keyword":
        if spec.keyword_match == "exact":
            return sample.strip().lower() == item.lower()
        return item.lower() in sample.lower()
    if spec.sample == "path":
        return N._match(N.normalize_path(sample), (item,))
    return bool(item.search(sample))


def rule_hits(rule: Rule, sample: str) -> list:
    """规则内命中样本的特征（正则源码或关键字）。"""
    hits = []
    for item, source in zip(rule.compiled, rule.sources):
        if match_entry(rule.group, item, sample):
            hits.append(source["re"] if isinstance(source, dict) else source)
    return hits


def _rule(data, where: str) -> Rule:
    if not isinstance(data, dict):
        raise PackError(f"{where}: 应为映射")
    allowed = {"id", "group", "title", "description", "severity", "enabled", "flags", "patterns", "keywords",
               "tag", "tests"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PackError(f"{where}: 未知字段 {', '.join(unknown)}")
    rule_id = _text(data.get("id"), f"{where}.id", 64, required=True)
    if not ID_RE.match(rule_id):
        raise PackError(f"{where}.id: 只能包含字母、数字、. _ -，长度 3~64")
    where = f"规则 {rule_id}"
    group = _text(data.get("group"), f"{where}.group", 64, required=True)
    if group not in GROUPS:
        raise PackError(f"{where}.group: 未知特征组 {group}（可选：{', '.join(GROUPS)}）")
    spec = GROUPS[group]
    severity = _text(data.get("severity") or "MEDIUM", f"{where}.severity", 10).upper()
    if severity not in SEVERITIES:
        raise PackError(f"{where}.severity: 只能是 {' / '.join(SEVERITIES)}")
    if spec.attach == "severity" and not data.get("severity"):
        raise PackError(f"{where}.severity: 特征组 {group} 按规则定级，必须填写")
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise PackError(f"{where}.enabled: 应为 true / false")
    tag = _text(data.get("tag"), f"{where}.tag", 41)
    if spec.attach == "tag":
        if not TAG_RE.match(tag):
            raise PackError(f"{where}.tag: 特征组 {group} 需要大写标签（如 EVAL_EXEC）")
    elif tag:
        raise PackError(f"{where}.tag: 特征组 {group} 不使用标签")

    sources, compiled = [], []
    if spec.kind == "regex":
        if data.get("keywords") is not None:
            raise PackError(f"{where}: 正则特征组 {group} 使用 patterns，不使用 keywords")
        items = data.get("patterns")
        if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
            raise PackError(f"{where}.patterns: 应为 1~{MAX_ITEMS} 条正则的列表")
        default_bits = _flags(data.get("flags"), f"{where}.flags")
        for index, item in enumerate(items):
            spot = f"{where}.patterns[{index}]"
            bits = default_bits
            if isinstance(item, dict):
                if set(item) - {"re", "flags"}:
                    raise PackError(f"{spot}: 只支持 re 与 flags 字段")
                bits = _flags(item.get("flags"), f"{spot}.flags") if "flags" in item else default_bits
                item = item.get("re")
            if not isinstance(item, str):
                raise PackError(f"{spot}: 应为正则字符串")
            compiled.append(_compile(item, bits, spot))
            sources.append({"re": item, "flags": _flag_letters(bits)})
    else:
        if data.get("patterns") is not None or data.get("flags") is not None:
            raise PackError(f"{where}: 关键字特征组 {group} 使用 keywords，不使用 patterns / flags")
        items = data.get("keywords")
        if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
            raise PackError(f"{where}.keywords: 应为 1~{MAX_ITEMS} 个关键字的列表")
        for index, item in enumerate(items):
            keyword = _text(item, f"{where}.keywords[{index}]", MAX_KEYWORD_LEN, required=True)
            sources.append(keyword)
            compiled.append(keyword)

    rule = Rule(rule_id=rule_id, group=group, title=_text(data.get("title"), f"{where}.title", 120, required=True),
                description=_text(data.get("description"), f"{where}.description", 1000), severity=severity,
                default_enabled=enabled, sources=sources, compiled=tuple(compiled), tag=tag)
    rule.tests = _check_tests(rule, data.get("tests"), where)
    return rule


def _check_tests(rule: Rule, tests, where: str) -> dict:
    """规则自带的样本自检：match 必须命中、nomatch 不得命中。"""
    if tests is None:
        return {}
    if not isinstance(tests, dict) or set(tests) - {"match", "nomatch"}:
        raise PackError(f"{where}.tests: 只支持 match / nomatch 两个样本列表")
    out = {}
    for key in ("match", "nomatch"):
        samples = tests.get(key) or []
        if not isinstance(samples, list) or len(samples) > MAX_TESTS:
            raise PackError(f"{where}.tests.{key}: 应为不超过 {MAX_TESTS} 条样本的列表")
        clean = [_text(sample, f"{where}.tests.{key}", MAX_SAMPLE_LEN, required=True) for sample in samples]
        for sample in clean:
            hit = bool(rule_hits(rule, sample))
            if key == "match" and not hit:
                raise PackError(f"{where}.tests: 样本应命中但未命中：{sample}")
            if key == "nomatch" and hit:
                raise PackError(f"{where}.tests: 样本不应命中但命中了：{sample}")
        if clean:
            out[key] = clean
    return out


def parse_pack(text: str, builtin: bool = False, path: str = "") -> Pack:
    if len(text.encode("utf-8")) > MAX_PACK_BYTES:
        raise PackError(f"规则包超过 {MAX_PACK_BYTES // 1024} KB")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PackError(f"YAML 解析失败：{str(exc).splitlines()[0]}") from None
    if not isinstance(data, dict):
        raise PackError("规则包顶层应为映射")
    unknown = sorted(set(data) - {"format", "pack", "name", "version", "description", "rules"})
    if unknown:
        raise PackError(f"未知顶层字段 {', '.join(unknown)}")
    if data.get("format") != FORMAT:
        raise PackError(f"format 应为 {FORMAT}")
    pack_id = _text(data.get("pack"), "pack", 64, required=True)
    if not ID_RE.match(pack_id) or pack_id != pack_id.lower():
        raise PackError("pack: 只能包含小写字母、数字、. _ -，长度 3~64")
    if pack_id.startswith("builtin") != builtin:
        raise PackError("pack: builtin 前缀保留给内置规则包" if not builtin else "pack: 内置规则包须以 builtin 开头")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules or len(rules) > MAX_RULES:
        raise PackError(f"rules: 应为 1~{MAX_RULES} 条规则的列表")
    parsed, seen = [], set()
    for index, item in enumerate(rules):
        rule = _rule(item, f"rules[{index}]")
        if rule.rule_id in seen:
            raise PackError(f"规则 {rule.rule_id}: 编号在包内重复")
        seen.add(rule.rule_id)
        parsed.append(rule)
    return Pack(pack_id=pack_id, name=_text(data.get("name") or pack_id, "name", 80),
                version=_text(data.get("version"), "version", 40),
                description=_text(data.get("description"), "description", 500),
                builtin=builtin, rules=parsed, source=text, path=path)


def load_builtin(directory: Path = BUILTIN_DIR) -> list:
    """内置规则包按文件名排序加载；任何错误都直接抛出（不能静默缺少内置特征）。"""
    packs, seen = [], set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            pack = parse_pack(path.read_text(encoding="utf-8"), builtin=True, path=str(path))
        except PackError as exc:
            raise PackError(f"{path.name}: {exc}") from None
        duplicate = seen & {rule.rule_id for rule in pack.rules}
        if duplicate:
            raise PackError(f"{path.name}: 规则编号与其他内置包重复：{', '.join(sorted(duplicate))}")
        seen |= {rule.rule_id for rule in pack.rules}
        packs.append(pack)
    return packs


# ---------- 规则库 ----------

def default_directory() -> str:
    explicit = os.getenv("AG_RULES_DIR", "")
    if explicit:
        return explicit
    base = os.getenv("AG_AGENT_DEVICE_DIR") or os.getenv("AG_DATA_DIR") or ""
    return os.path.join(base, "rules") if base else ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(packs: list, enabled) -> str:
    rows = sorted((pack.pack_id, rule.fingerprint()) for pack in packs for rule in pack.rules if enabled(pack, rule))
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


class RuleLibrary:
    def __init__(self, directory: str = "", builtin_dir: Path = BUILTIN_DIR) -> None:
        self.directory = directory
        self._lock = threading.RLock()
        self._builtin = load_builtin(builtin_dir)
        self._default_digest = _digest(self._builtin, lambda pack, rule: rule.default_enabled)
        self._custom: dict = {}
        self._state = {"rules": {}, "packs": {}, "history": []}
        self.errors: list = []
        self._stamp = None
        self._checked = 0.0
        self._digest_cache = ""
        self.hit_counter = HitCounter(directory)
        self._keyword_ids = {}
        self._load_disk()

    # ---- 持久化 ----

    def _state_path(self) -> str:
        return os.path.join(self.directory, "state.json") if self.directory else ""

    def _packs_dir(self) -> str:
        return os.path.join(self.directory, "packs") if self.directory else ""

    def _disk_stamp(self):
        if not self.directory:
            return None
        rows = []
        for path in [self._state_path()] + sorted(Path(self._packs_dir()).glob("*.yaml")
                                                  if os.path.isdir(self._packs_dir()) else []):
            try:
                stat = os.stat(path)
                rows.append((str(path), stat.st_mtime_ns, stat.st_size))
            except OSError:
                rows.append((str(path), 0, 0))
        return tuple(rows)

    def _load_disk(self) -> None:
        self._digest_cache = ""
        self.errors = []
        self._custom = {}
        self._state = {"rules": {}, "packs": {}, "history": []}
        if not self.directory:
            return
        self._stamp = self._disk_stamp()
        builtin_ids = {rule.rule_id for pack in self._builtin for rule in pack.rules}
        if os.path.isdir(self._packs_dir()):
            for path in sorted(Path(self._packs_dir()).glob("*.yaml")):
                try:
                    pack = parse_pack(path.read_text(encoding="utf-8"), path=str(path))
                    taken = builtin_ids | {rule.rule_id for other in self._custom.values() for rule in other.rules}
                    clash = taken & {rule.rule_id for rule in pack.rules}
                    if clash:
                        raise PackError(f"规则编号已存在：{', '.join(sorted(clash))}")
                    if pack.pack_id in self._custom:
                        raise PackError(f"规则包编号重复：{pack.pack_id}")
                    self._custom[pack.pack_id] = pack
                except (OSError, PackError) as exc:
                    # 自定义包损坏只跳过该包，不影响内置特征。
                    self.errors.append(f"{path.name}: {exc}")
        path = self._state_path()
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as handle:
                    data = json.load(handle)
                for key in ("rules", "packs"):
                    if isinstance(data.get(key), dict):
                        self._state[key] = {str(k): bool(v) for k, v in data[key].items()}
                if isinstance(data.get("history"), list):
                    self._state["history"] = data["history"][-MAX_HISTORY:]
            except (OSError, ValueError, AttributeError) as exc:
                self.errors.append(f"state.json: {exc.__class__.__name__}，启停状态按默认处理")

    def _save_state(self) -> None:
        if not self.directory:
            return
        os.makedirs(self.directory, exist_ok=True)
        tmp = self._state_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self._state, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, self._state_path())
        self._stamp = self._disk_stamp()

    def _record(self, action: str, target: str, detail: str = "") -> None:
        self._state["history"] = (self._state["history"] + [
            {"at": _now(), "action": action, "target": target, "detail": detail}])[-MAX_HISTORY:]

    def refresh(self, min_interval: float = 3.0) -> bool:
        """其他进程改动了规则目录时重新加载并注入；返回是否发生变化。"""
        if not self.directory:
            return False
        now = time.monotonic()
        if now - self._checked < min_interval:
            return False
        self._checked = now
        with self._lock:
            if self._disk_stamp() == self._stamp:
                return False
            self._load_disk()
            self.apply()
            return True

    # ---- 生效集合 ----

    def packs(self) -> list:
        return self._builtin + list(self._custom.values())

    def is_enabled(self, pack: Pack, rule: Rule) -> bool:
        return (self._state["packs"].get(pack.pack_id, True)
                and self._state["rules"].get(rule.rule_id, rule.default_enabled))

    def signatures(self) -> dict:
        with self._lock:
            sets = {name: [] for name in GROUPS}
            keyword_ids = {}
            feature_snapshots = {}
            for pack in self.packs():
                for rule in pack.rules:
                    if self.is_enabled(pack, rule):
                        feature = rule.snapshot(pack)
                        feature_snapshots[rule.rule_id] = feature
                        if GROUPS[rule.group].kind == "keyword":
                            sets[rule.group].extend(rule.entries())
                            for word in rule.compiled:
                                keyword_ids.setdefault((rule.group, word.lower()), set()).add(rule.rule_id)
                        else:
                            attach = GROUPS[rule.group].attach
                            for pattern in rule.compiled:
                                observed = ObservedPattern(pattern, self.hit_counter, rule.rule_id, feature)
                                sets[rule.group].append((observed, rule.tag if attach == "tag" else rule.severity)
                                                       if attach else observed)
            self._keyword_ids = {key: tuple(ids) for key, ids in keyword_ids.items()}
            self._feature_snapshots = feature_snapshots
            for group, items in sets.items():
                if GROUPS[group].kind == "keyword":
                    sets[group] = [ObservedKeyword(word, [feature_snapshots[rule_id]
                                  for rule_id in sorted(keyword_ids[(group, word.lower())])]) for word in items]
            return {name: tuple(items) for name, items in sets.items()}

    def record_keyword_hit(self, group: str, word: str) -> None:
        try:
            features = getattr(word, "features", None)
            if features is None:
                features = [self._feature_snapshots[rule_id]
                            for rule_id in self._keyword_ids.get((group, word.lower()), ())]
            for feature in features:
                record_feature(feature)
                self.hit_counter.record(feature["rule_id"])
        except Exception:
            self.hit_counter.observation_error = "counter unavailable"

    def digest(self) -> str:
        with self._lock:
            if not self._digest_cache:
                self._digest_cache = _digest(self.packs(), self.is_enabled)
            return self._digest_cache

    def is_default(self) -> bool:
        return self.digest() == self._default_digest

    def version(self, base: str) -> str:
        """规则版本：与内置默认一致时为 base，否则追加生效集合摘要，决策与扫描记录可追溯。"""
        digest = self.digest()
        return base if digest == self._default_digest else f"{base}+r{digest[:8]}"

    def apply(self) -> None:
        """注入生效集合；每次启停 / 增删规则包后调用。"""
        with self._lock:
            self._digest_cache = ""
            N.install_signatures(self.signatures(), self.record_keyword_hit)

    # ---- 管理操作 ----

    def _find_rule(self, rule_id: str):
        for pack in self.packs():
            for rule in pack.rules:
                if rule.rule_id == rule_id:
                    return pack, rule
        raise KeyError(rule_id)

    def _find_pack(self, pack_id: str) -> Pack:
        for pack in self.packs():
            if pack.pack_id == pack_id:
                return pack
        raise KeyError(pack_id)

    def set_rule(self, rule_id: str, enabled: bool) -> dict:
        with self._lock:
            pack, rule = self._find_rule(rule_id)
            self._state["rules"][rule_id] = bool(enabled)
            self._record("enable_rule" if enabled else "disable_rule", rule_id, rule.title)
            self._save_state()
            self.apply()
            return self.rule_view(pack, rule)

    def set_pack(self, pack_id: str, enabled: bool) -> dict:
        with self._lock:
            pack = self._find_pack(pack_id)
            self._state["packs"][pack_id] = bool(enabled)
            self._record("enable_pack" if enabled else "disable_pack", pack_id, pack.name)
            self._save_state()
            self.apply()
            return self.pack_view(pack)

    def reset(self) -> None:
        """恢复默认启停（自定义规则包保留）。"""
        with self._lock:
            self._state["rules"], self._state["packs"] = {}, {}
            self._record("reset", "*", "恢复默认启停")
            self._save_state()
            self.apply()

    def add_pack(self, text: str) -> dict:
        """上传自定义规则包；同编号的自定义包整体替换（保留其规则的启停状态）。"""
        pack = parse_pack(text)
        with self._lock:
            if any(item.pack_id == pack.pack_id for item in self._builtin):
                raise PackError(f"规则包编号与内置包冲突：{pack.pack_id}")
            taken = {rule.rule_id for other in self.packs() if other.pack_id != pack.pack_id for rule in other.rules}
            clash = taken & {rule.rule_id for rule in pack.rules}
            if clash:
                raise PackError(f"规则编号已存在：{', '.join(sorted(clash))}")
            replaced = pack.pack_id in self._custom
            if self.directory:
                os.makedirs(self._packs_dir(), exist_ok=True)
                pack.path = os.path.join(self._packs_dir(), pack.pack_id + ".yaml")
                tmp = pack.path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as handle:
                    handle.write(text)
                os.replace(tmp, pack.path)
            old = self._custom.get(pack.pack_id)
            if old is not None:
                kept = {rule.rule_id for rule in pack.rules}
                for rule in old.rules:
                    if rule.rule_id not in kept:
                        self._state["rules"].pop(rule.rule_id, None)
            self._custom[pack.pack_id] = pack
            self._record("replace_pack" if replaced else "add_pack", pack.pack_id,
                         f"{pack.name} · {len(pack.rules)} 条规则")
            self._save_state()
            self.apply()
            return self.pack_view(pack)

    def remove_pack(self, pack_id: str) -> None:
        with self._lock:
            if any(item.pack_id == pack_id for item in self._builtin):
                raise PackError("内置规则包不能删除，只能停用")
            pack = self._custom.pop(pack_id, None)
            if pack is None:
                raise KeyError(pack_id)
            if pack.path and os.path.exists(pack.path):
                os.remove(pack.path)
            for rule in pack.rules:
                self._state["rules"].pop(rule.rule_id, None)
            self._state["packs"].pop(pack_id, None)
            self._record("remove_pack", pack_id, pack.name)
            self._save_state()
            self.apply()

    def export(self, directory: str, extra: dict | None = None) -> None:
        """把当前自定义规则包与启停状态写到另一个规则目录（回放进程加载）；extra 为额外的 {包编号: YAML 原文}。"""
        packs = os.path.join(directory, "packs")
        os.makedirs(packs, exist_ok=True)
        with self._lock:
            sources = {pack.pack_id: pack.source for pack in self._custom.values()}
            state = {"rules": dict(self._state["rules"]), "packs": dict(self._state["packs"]), "history": []}
        sources.update(extra or {})
        for pack_id, text in sources.items():
            with open(os.path.join(packs, pack_id + ".yaml"), "w", encoding="utf-8") as handle:
                handle.write(text)
        with open(os.path.join(directory, "state.json"), "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False)

    def source(self, pack_id: str) -> str:
        with self._lock:
            return self._find_pack(pack_id).source

    def test(self, sample: str, group: str = "") -> list:
        """样本在各规则上的命中（含已停用规则，便于停用前评估影响）。"""
        if group and group not in GROUPS:
            raise PackError(f"未知特征组 {group}")
        sample = str(sample or "")[:MAX_SAMPLE_LEN]
        rows = []
        with self._lock:
            for pack in self.packs():
                for rule in pack.rules:
                    if group and rule.group != group:
                        continue
                    hits = rule_hits(rule, sample)
                    if hits:
                        rows.append({"rule_id": rule.rule_id, "pack": pack.pack_id, "group": rule.group,
                                     "title": rule.title, "severity": rule.severity, "tag": rule.tag,
                                     "enabled": self.is_enabled(pack, rule), "matched": hits[:5]})
        return rows

    # ---- 视图 ----

    def rule_view(self, pack: Pack, rule: Rule) -> dict:
        return {**rule.as_dict(), **rule.snapshot(pack), "enabled": self.is_enabled(pack, rule),
                "rule_enabled": self._state["rules"].get(rule.rule_id, rule.default_enabled)}

    def pack_view(self, pack: Pack) -> dict:
        rules = [self.rule_view(pack, rule) for rule in pack.rules]
        return {**pack.summary(), "enabled": self._state["packs"].get(pack.pack_id, True),
                "enabled_rules": sum(1 for rule in rules if rule["enabled"]), "items": rules}

    def overview(self) -> dict:
        stats = self.hit_counter.snapshot()
        with self._lock:
            packs = [self.pack_view(pack) for pack in self.packs()]
            for pack in packs:
                for rule in pack["items"]:
                    rule["hit_count"] = stats["counts"].get(rule["rule_id"], 0) if stats["counts"] is not None else None
            return {"default": self.is_default(), "digest": self.digest()[:8], "persistent": bool(self.directory),
                    "groups": [spec.as_dict(name) for name, spec in GROUPS.items()],
                    "strategies": STRATEGIES,
                    "packs": packs, "hit_stats": {key: value for key, value in stats.items() if key != "counts"},
                    "errors": list(self.errors), "history": list(reversed(self._state["history"][-30:])),
                    "limits": {"pack_kb": MAX_PACK_BYTES // 1024, "rules": MAX_RULES, "pattern_len": MAX_PATTERN_LEN}}


_LIBRARY: RuleLibrary | None = None
_SINGLETON_LOCK = threading.Lock()


def library() -> RuleLibrary:
    """进程内唯一规则库（规则目录取自环境变量）。"""
    global _LIBRARY
    with _SINGLETON_LOCK:
        if _LIBRARY is None:
            _LIBRARY = RuleLibrary(default_directory())
        return _LIBRARY


def bootstrap() -> dict:
    """normalize 首次取特征时调用：加载规则库并返回生效集合。"""
    lib = library()
    lib.apply()
    return lib.signatures()


def flush_hits() -> None:
    if _LIBRARY is not None:
        _LIBRARY.hit_counter.flush()
