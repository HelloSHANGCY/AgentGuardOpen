"""管理员离线登记的行为符号包；服务不读取用户指定的任意文件路径。"""

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from . import anomaly as A

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SYMBOL_RE = re.compile(r"^[A-Z_]+(?::[a-z0-9_]+)*$")
SOURCE_WEIGHTS = {"corpus": 0.25, "swechat": 0.75}


def encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate(dataset: dict, reserved_groups: list | None = None) -> None:
    """验证当前版本的符号与分区。仅支持已实现转换器的 SWE-chat 数据。"""
    meta = dataset["meta"]
    if (meta.get("feature_schema_version"), meta.get("sequence_semantics_version")) != (
            A.FEATURE_SCHEMA_VERSION, A.SEQUENCE_SEMANTICS_VERSION):
        raise ValueError("数据集提取器版本不兼容，请使用当前版本重新清洗")
    if meta.get("source") != "SALT-NLP/SWE-chat":
        raise ValueError("unsupported dataset source")
    keys, groups = set(), set(reserved_groups or [])
    for partition in ("test", "holdout", "train"):
        sessions = dataset.get(partition, [])
        if not isinstance(sessions, list) or (partition == "train" and not sessions):
            raise ValueError("dataset must contain training sessions")
        current = set()
        for session in sessions:
            if set(session) - {"key", "group", "source", "device", "agent", "steps"}:
                raise ValueError("dataset must contain symbols only")
            key, group = session["key"], session["group"]
            if not all(isinstance(value, str) and 0 < len(value) <= 128 for value in (key, group)):
                raise ValueError("invalid session or group id")
            if key in keys:
                raise ValueError("duplicate dataset sessions")
            keys.add(key)
            if group in groups:
                raise ValueError("dataset partitions contain overlapping repository groups")
            current.add(group)
            if session["source"] != "swechat" or session.get("device") or session.get("agent") != "claude-code":
                raise ValueError("invalid dataset session source")
            if not isinstance(session["steps"], list) or not any(step.get("symbols") for step in session["steps"]):
                raise ValueError("dataset contains an empty session")
            for step in session["steps"]:
                if set(step) - {"cut", "symbols", "intents", "execution", "cut_before", "cut_after"}:
                    raise ValueError("dataset must contain symbols only")
                for flag in ("cut", "cut_before", "cut_after"):
                    if flag in step and not isinstance(step[flag], bool):
                        raise ValueError("invalid sequence boundary")
                if step.get("cut"):
                    if step.get("symbols"):
                        raise ValueError("cut markers cannot contain symbols")
                    continue
                symbols, intents = step["symbols"], step["intents"]
                if (not isinstance(symbols, list) or not symbols or
                        any(not isinstance(s, str) or len(s) > 128 or not SYMBOL_RE.fullmatch(s) for s in symbols)):
                    raise ValueError("invalid behavior symbols")
                if not isinstance(intents, list) or any(intent not in A.INTENT_EXPECTED for intent in intents):
                    raise ValueError("invalid intent labels")
                if step.get("execution") not in {"succeeded", "failed"}:
                    raise ValueError("dataset contains an unconfirmed execution")
        groups.update(current)


def counts(sessions: list) -> dict:
    return {"sessions": len(sessions), "groups": len({s["group"] for s in sessions}),
            "steps": sum(bool(step.get("symbols")) for s in sessions for step in s["steps"])}


def publish(prepared: Path, directory: Path, dataset_id: str, name: str) -> dict:
    """固定分区，省略测试符号与原始输入。重复发布相同内容幂等，拒绝覆盖。"""
    if not ID_RE.fullmatch(dataset_id):
        raise ValueError("invalid dataset id")
    raw = prepared.read_bytes()
    data = json.loads(raw)
    validate(data)
    statistics = {row["session"]: {k: v for k, v in row["counts"].items()
                                  if isinstance(v, int) and not isinstance(v, bool)} for row in data.get("inputs", [])}
    payload = encoded({"train": data["train"], "holdout": data["holdout"], "meta": data["meta"],
                       "training_statistics": statistics})
    manifest = {"format": 1, "id": dataset_id, "name": name, "sha256": digest(payload),
                "prepared_sha256": digest(raw), "meta": data["meta"],
                "train": counts(data["train"]), "holdout": counts(data["holdout"]),
                "reserved_test": {**counts(data.get("test", [])), "sha256": digest(encoded(data.get("test", []))),
                                  "groups_sha256": sorted({s["group"] for s in data.get("test", [])})}}
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / dataset_id
    if target.exists():
        if json.loads((target / "manifest.json").read_bytes()) != manifest or digest((target / "sessions.json").read_bytes()) != manifest["sha256"]:
            raise ValueError("dataset id already registered with different content")
        return manifest
    temporary = Path(tempfile.mkdtemp(prefix=".publish-", dir=directory))
    try:
        (temporary / "sessions.json").write_bytes(payload)
        (temporary / "manifest.json").write_bytes(encoded(manifest))
        os.rename(temporary, target)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return manifest


class DatasetStore:
    def __init__(self, behavior_directory: str):
        self.directory = Path(behavior_directory) / "datasets" if behavior_directory else None

    def _path(self, dataset_id: str) -> Path:
        if not isinstance(dataset_id, str) or not ID_RE.fullmatch(dataset_id) or self.directory is None:
            raise ValueError("数据集未登记")
        path = self.directory / dataset_id
        if path.is_symlink() or any((path / name).is_symlink() for name in ("manifest.json", "sessions.json")):
            raise ValueError("dataset symlinks are not supported")
        return path

    def _manifest(self, dataset_id: str) -> dict:
        data = json.loads((self._path(dataset_id) / "manifest.json").read_bytes())
        if data["id"] != dataset_id or data["format"] != 1:
            raise ValueError("invalid dataset manifest")
        return data

    def list(self) -> list[dict]:
        result = []
        if not self.directory or not self.directory.exists():
            return result
        for path in sorted(self.directory.iterdir()):
            if not ID_RE.fullmatch(path.name) or not path.is_dir():
                continue
            try:
                data = self._manifest(path.name)
                meta = data["meta"]
                compatible = (meta.get("feature_schema_version"), meta.get("sequence_semantics_version")) == (
                    A.FEATURE_SCHEMA_VERSION, A.SEQUENCE_SEMANTICS_VERSION)
                available = compatible and (path / "sessions.json").is_file()
                result.append({"id": data["id"], "name": data["name"], "available": available,
                               "reason": "" if available else "提取器版本不兼容或数据文件缺失，请重新登记",
                               "train": data["train"], "holdout": data["holdout"],
                               "reserved_test": {k: v for k, v in data["reserved_test"].items() if k != "groups_sha256"},
                               "source": meta["source"], "revision": meta.get("revision"),
                               "label_status": meta.get("label_status"), "sha256": data["sha256"]})
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                result.append({"id": path.name, "name": path.name, "available": False, "reason": "数据包登记信息损坏"})
        return result

    def load(self, dataset_id: str, limit: int = 0) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("训练会话上限必须是非负整数")
        try:
            manifest = self._manifest(dataset_id)
            raw = (self._path(dataset_id) / "sessions.json").read_bytes()
            if digest(raw) != manifest["sha256"]:
                raise ValueError("数据集内容哈希不一致，请重新登记")
            data = json.loads(raw)
            if data["meta"] != manifest["meta"] or data.get("test"):
                raise ValueError("invalid registered dataset payload")
            validate(data, manifest["reserved_test"]["groups_sha256"])
            if counts(data["train"]) != manifest["train"] or counts(data["holdout"]) != manifest["holdout"]:
                raise ValueError("dataset counts do not match registration")
            if limit > len(data["train"]):
                raise ValueError("训练会话上限超过数据集可用数量")
            data["train"] = data["train"][:limit] if limit else data["train"]
            training_counts = Counter()
            for session in data["train"]:
                training_counts.update(data["training_statistics"].get(session["key"], {}))
            data["meta"] = {**data["meta"], "registration": {"id": dataset_id, "sha256": manifest["sha256"],
                                                           "prepared_sha256": manifest["prepared_sha256"]},
                            "reserved_test": {k: v for k, v in manifest["reserved_test"].items() if k != "groups_sha256"},
                            "training_limit": len(data["train"]), "requested_training_sessions": limit,
                            "training_counts": dict(training_counts), "train_groups": counts(data["train"])["groups"],
                            "prepared_dataset_sha256": data["meta"].get("dataset_sha256"),
                            "dataset_sha256": digest(encoded({k: data[k] for k in ("train", "holdout")}))}
            return {k: data[k] for k in ("train", "holdout", "meta")}
        except (OSError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("数据集未登记或数据包损坏，请重新登记") from exc
