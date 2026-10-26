"""版本化规则数据加载。

一次扫描内规则版本固定（ScanContext.ruleset_version），不可热切换：扫描在独立子进程中执行，
子进程启动时从特征规则库（rules/library.py）加载生效特征。规则库启停后版本追加生效集合摘要。
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from ...core.normalize import matching_keywords

RULESET_PATH = Path(__file__).resolve().parent.parent / "rulesets" / "ruleset.json"
DEFAULT_RULESET_VERSION = "AG-STATIC-2026.09.25.1"


@dataclass
class Ruleset:
    version: str = DEFAULT_RULESET_VERSION
    notes: tuple = ()
    raw: dict = field(default_factory=dict)

    def is_weak_secret(self, value: str) -> bool:
        """默认 / 示例弱密钥（config.weak_secret 完整匹配）或占位符片段（config.weak_secret_marker 子串）。"""
        text = str(value or "").strip().lower()
        if not text:
            return False
        if matching_keywords("config.weak_secret", text, exact=True, first=True):
            return True
        return bool(matching_keywords("config.weak_secret_marker", text, first=True))


_DATA: dict | None = None


def load_ruleset(path: Path = None) -> Ruleset:
    global _DATA
    if path is None and _DATA is not None:
        data = _DATA
    else:
        try:
            data = json.loads((path or RULESET_PATH).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if path is None:
            _DATA = data
    base = str(data.get("ruleset_version") or DEFAULT_RULESET_VERSION)
    return Ruleset(version=_library_version(base), notes=tuple(data.get("notes") or ()), raw=data)


def _library_version(base: str) -> str:
    from ...rules.library import library

    return library().version(base)
