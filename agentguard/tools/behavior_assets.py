"""校验、导入随 Git 分发的行为基线候选与符号训练数据；不启用模型。"""

import argparse
import gzip
import io
import json
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection.behavior import BUILTIN, LEGACY_BUILTIN, VERSION_RE  # noqa: E402
from agentguard.detection.behavior_datasets import ID_RE, counts, digest, validate  # noqa: E402

BUNDLE = ROOT / "resources" / "behavior"
DEFAULT_DIRECTORY = ROOT / "data" / "benign" / "team-behavior"
MAX_DATASET_BYTES = 64 * 1024 * 1024


def checked_file(root: Path, manifest: dict, name: str) -> bytes:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or "\\" in name:
        raise ValueError("invalid bundle file path")
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("bundle files must remain inside the bundle")
    raw = path.read_bytes()
    expected = manifest["files"][name]
    if len(raw) != expected["bytes"] or digest(raw) != expected["sha256"]:
        raise ValueError(f"bundle checksum mismatch: {name}")
    return raw


def load_bundle(root: Path = BUNDLE) -> tuple[dict, dict[str, bytes]]:
    """先校验完整包，再生成固定目标文件清单；测试分区不进入运行时数据目录。"""
    manifest = json.loads((root / "bundle.json").read_bytes())
    if manifest["format"] != 1:
        raise ValueError("unsupported behavior bundle format")
    for name in manifest["files"]:
        checked_file(root, manifest, name)
    builtin = ROOT / "agentguard" / "detection" / "baseline" / "transitions.json"
    if digest(builtin.read_bytes()) != manifest["builtin"]["sha256"]:
        raise ValueError("built-in baseline differs from the bundle reference")
    if manifest.get("legacy_builtin"):
        legacy = builtin.with_name("transitions.legacy.json")
        if digest(legacy.read_bytes()) != manifest["legacy_builtin"]["sha256"]:
            raise ValueError("legacy built-in baseline differs from the bundle reference")
    outputs = {}
    for dataset in manifest["datasets"]:
        dataset_id = dataset["id"]
        if not ID_RE.fullmatch(dataset_id):
            raise ValueError("invalid bundle dataset id")
        registration = checked_file(root, manifest, dataset["manifest"])
        registered = json.loads(registration)
        compressed = checked_file(root, manifest, dataset["archive"])
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as handle:
            raw = handle.read(MAX_DATASET_BYTES + 1)
        if (len(raw) > MAX_DATASET_BYTES or len(raw) != dataset["payload_bytes"]
                or digest(raw) != registered["sha256"]):
            raise ValueError("dataset payload checksum or size mismatch")
        data = json.loads(raw)
        if (registered["id"] != dataset_id or registered["format"] != 1
                or data["meta"] != registered["meta"] or data.get("test")):
            raise ValueError("invalid registered dataset payload")
        validate(data, registered["reserved_test"]["groups_sha256"])
        if any(counts(data[key]) != registered[key] for key in ("train", "holdout")):
            raise ValueError("dataset partition counts differ from manifest")
        outputs[f"datasets/{dataset_id}/sessions.json"] = raw
        outputs[f"datasets/{dataset_id}/manifest.json"] = registration
    for candidate in manifest["models"]:
        raw = checked_file(root, manifest, candidate["path"])
        model = json.loads(raw)
        version = model["version"]
        if (version in (BUILTIN, LEGACY_BUILTIN) or not VERSION_RE.fullmatch(version) or version != candidate["version"]
                or not A.Baseline.from_dict(model).compatible):
            raise ValueError("expected a compatible candidate baseline")
        if model.get("devices") or model["meta"].get("recorded_sessions"):
            raise ValueError("shared models must not contain local device training data")
        if model["meta"]["external_sessions"] != candidate["training_sessions"]:
            raise ValueError("candidate training count differs from manifest")
        outputs[f"models/{version}.json"] = raw
    return manifest, outputs


def install(directory: Path, root: Path = BUNDLE) -> dict:
    manifest, outputs = load_bundle(root)
    directory = directory.absolute()
    # 所有冲突先检查完；不覆盖已有版本、active.json 或本地会话。
    for name, raw in outputs.items():
        path = directory / name
        current = path
        while current != directory.parent:
            if current.is_symlink():
                raise ValueError("installation symlinks are not supported")
            current = current.parent
        if path.exists() and (not path.is_file() or path.read_bytes() != raw):
            raise ValueError(f"existing behavior asset has different content: {name}")
    written = 0
    for name, raw in outputs.items():
        path = directory / name
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)
        written += 1
    return {"directory": str(directory), "models": len(manifest["models"]),
            "datasets": len(manifest["datasets"]), "written": written, "activated": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "install"))
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY,
                        help="导入到服务的 AG_BEHAVIOR_DIR；默认本地隔离目录")
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            result = install(args.directory)
        else:
            manifest, _ = load_bundle()
            result = {"valid": True, "models": len(manifest["models"]), "datasets": len(manifest["datasets"]),
                      "git_bytes": sum(item["bytes"] for item in manifest["files"].values()),
                      "dataset_counts": [{"id": item["id"], "train": item["train"], "holdout": item["holdout"]}
                                         for item in manifest["datasets"]]}
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (OSError, EOFError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"behavior assets failed: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
