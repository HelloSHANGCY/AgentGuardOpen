"""配置解析：JSON / YAML / TOML / env / Dockerfile / Compose。

先把配置转成统一事实（ConfigFact），规则再基于事实匹配；
YAML 限制别名、深度与节点数，解析失败显式记录而不猜测。
"""

import json
import re
from dataclasses import dataclass, field

import yaml

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

from ...core.normalize import matching_keywords

ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
KEY_LINE_RE = re.compile(r"^\s*[-]?\s*[\"']?([A-Za-z0-9_.\-]+)[\"']?\s*[:=]")



@dataclass
class ConfigFact:
    path: str
    pointer: str
    key: str
    value: object
    line: int = 0
    source_kind: str = ""
    declared: str = ""
    resolved: str = ""
    unresolved: bool = False
    service: str = ""

    def is_sensitive_key(self) -> bool:
        # 密钥类键名片段来自特征规则库（config.secret_key_hint）。
        lowered = self.key.lower()
        return bool(matching_keywords("config.secret_key_hint", lowered, first=True))


@dataclass
class ConfigDoc:
    path: str
    category: str
    data: object = None
    facts: list = field(default_factory=list)
    raw: str = ""
    parse_error: str = ""

    def find(self, predicate) -> list:
        return [fact for fact in self.facts if predicate(fact)]

    def by_key(self, *keys) -> list:
        wanted = {key.lower() for key in keys}
        return [fact for fact in self.facts if fact.key.lower() in wanted]


class _LimitedSafeLoader(yaml.SafeLoader):
    """限制别名数、节点数与嵌套深度，避免 YAML 资源耗尽。"""

    def __init__(self, stream, limits=None):
        super().__init__(stream)
        self._limits = limits
        self._depth = 0
        self._nodes = 0
        self._aliases = 0

    def compose_node(self, parent, index):
        self._depth += 1
        self._nodes += 1
        max_depth = int(getattr(self._limits, "max_yaml_depth", 32))
        max_nodes = int(getattr(self._limits, "max_yaml_nodes", 10000))
        max_aliases = int(getattr(self._limits, "max_yaml_aliases", 200))
        if self._depth > max_depth:
            raise yaml.YAMLError("yaml depth limit exceeded")
        if self._nodes > max_nodes:
            raise yaml.YAMLError("yaml node limit exceeded")
        if self.check_event(yaml.events.AliasEvent):
            self._aliases += 1
            if self._aliases > max_aliases:
                raise yaml.YAMLError("yaml alias limit exceeded")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def parse_config(path: str, text: str, category: str, limits=None) -> ConfigDoc:
    doc = ConfigDoc(path=path, category=category, raw=text)
    try:
        if category in ("yaml", "compose", "lockfile"):
            doc.data = yaml.load(text, Loader=_make_loader(limits)) if path.endswith((".yaml", ".yml")) \
                else _parse_lockfile_text(path, text)
        elif category == "json":
            doc.data = json.loads(text) if text.strip() else {}
            _check_json_depth(doc.data, int(getattr(limits, "max_yaml_depth", 32)))
        elif category == "toml":
            if tomllib is None:
                doc.parse_error = "tomllib_unavailable"
                return doc
            doc.data = tomllib.loads(text)
        elif category == "env":
            doc.data = _parse_env(text)
        elif category == "dockerfile":
            doc.data = _parse_dockerfile(text)
        elif category == "ini":
            doc.data = _parse_ini(text)
        else:
            doc.data = {}
    except yaml.YAMLError as exc:
        doc.parse_error = f"yaml:{str(exc)[:120]}"
        return doc
    except (json.JSONDecodeError, ValueError, TypeError, RecursionError) as exc:
        doc.parse_error = f"{exc.__class__.__name__}:{str(exc)[:120]}"
        return doc
    doc.facts = _flatten(doc.data, path, text)
    return doc


def _make_loader(limits):
    def loader(stream):
        return _LimitedSafeLoader(stream, limits)
    return loader


def _parse_lockfile_text(path: str, text: str) -> object:
    if path.lower().endswith(".json"):
        return json.loads(text or "{}")
    try:
        return tomllib.loads(text) if tomllib else {}
    except (ValueError, TypeError):
        return {}


def _check_json_depth(data, max_depth: int, current: int = 0) -> None:
    if current > max_depth:
        raise ValueError("json depth limit exceeded")
    if isinstance(data, dict):
        for value in data.values():
            _check_json_depth(value, max_depth, current + 1)
    elif isinstance(data, list):
        for value in data:
            _check_json_depth(value, max_depth, current + 1)


def _parse_env(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ENV_LINE_RE.match(line)
        if not match:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[match.group(1)] = value
    return result


def _parse_dockerfile(text: str) -> dict:
    instructions = []
    buffer = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
            continue
        full = (buffer + line).strip()
        buffer = ""
        if not full or full.startswith("#"):
            continue
        parts = full.split(None, 1)
        if not parts:
            continue
        instructions.append({"instruction": parts[0].upper(), "value": parts[1] if len(parts) > 1 else "",
                             "line": len(instructions) + 1})
    return {"instructions": instructions}


def _parse_ini(text: str) -> dict:
    result = {}
    section = "root"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            result.setdefault(section, {})
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            if not isinstance(result.get(section), dict):
                result[section] = {}
            result[section][key.strip()] = value.strip()
    return result


def key_lines(raw: str) -> dict:
    lines = {}
    for index, line in enumerate(raw.splitlines(), 1):
        match = KEY_LINE_RE.match(line)
        if match:
            lines.setdefault(match.group(1), index)
    return lines


def _flatten(data, path: str, raw: str, prefix: str = "", service: str = "", lines=None) -> list:
    facts: list = []
    if lines is None:
        lines = key_lines(raw)
    if isinstance(data, dict):
        for key, value in data.items():
            pointer = f"{prefix}.{key}" if prefix else str(key)
            current_service = service
            if pointer.startswith("services.") and pointer.count(".") == 1:
                current_service = str(key)
            if isinstance(value, dict):
                facts.extend(_flatten(value, path, raw, pointer, current_service, lines))
            elif isinstance(value, list):
                if all(not isinstance(item, (dict, list)) for item in value):
                    facts.append(_fact(path, pointer, str(key), value, lines, current_service))
                else:
                    for index, item in enumerate(value):
                        item_pointer = f"{pointer}[{index}]"
                        if isinstance(item, (dict, list)):
                            facts.extend(_flatten(item, path, raw, item_pointer, current_service, lines))
                        else:
                            facts.append(_fact(path, item_pointer, str(key), item, lines, current_service))
            else:
                facts.append(_fact(path, pointer, str(key), value, lines, current_service))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            facts.extend(_flatten(item, path, raw, f"{prefix}[{index}]", service, lines))
    return facts


def _fact(path, pointer, key, value, lines, service) -> ConfigFact:
    declared = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    resolved, unresolved = _resolve_interpolation(declared)
    return ConfigFact(
        path=path, pointer=pointer, key=key, value=value,
        line=lines.get(key, 0), service=service,
        source_kind=pointer.split(".")[0] if pointer else "",
        declared=declared, resolved=resolved, unresolved=unresolved,
    )


INTERPOLATION_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _resolve_interpolation(value: str) -> tuple:
    """`${VAR:-default}`：有默认值则解析为默认值，否则标 unresolved。

    不继承宿主机环境变量；无法解析时在报告中说明条件。
    """
    if not isinstance(value, str) or "${" not in value:
        return value, False
    unresolved = False

    def replace(match):
        nonlocal unresolved
        if match.group(2) is not None:
            return match.group(2)
        unresolved = True
        return match.group(0)

    resolved = INTERPOLATION_RE.sub(replace, value)
    return resolved, unresolved


def compose_services(doc: ConfigDoc) -> dict:
    if isinstance(doc.data, dict) and isinstance(doc.data.get("services"), dict):
        return doc.data["services"]
    return {}


def env_values(doc: ConfigDoc) -> dict:
    return doc.data if isinstance(doc.data, dict) else {}
