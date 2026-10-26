"""Git 共享行为资源：完整校验、运行时可读、幂等导入且不改启用状态。"""

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import behavior_assets as assets

from agentguard.detection import behavior as B


def test_team_bundle_loads_offline_without_changing_active_model_or_local_records(tmp_path):
    directory = tmp_path / "behavior"
    directory.mkdir()
    active = directory / "active.json"
    active.write_text('{"version":"builtin","at":1}')
    records = directory / B.RECORD_FILE
    records.write_text("")
    original = {path: path.read_bytes() for path in (active, records)}
    result = assets.install(directory)
    assert result["models"] == 6 and result["datasets"] == 1 and result["activated"] is False
    service = B.BehaviorService(str(directory))
    assert service.active_version == "builtin" and service.baseline.compatible
    candidates = [model for model in service.models() if not model["builtin"]]
    assert len(candidates) == 6 and all(model["compatible"] and not model["active"] for model in candidates)
    assert all(model["meta"]["assessment"]["verdict"] == "reject" for model in candidates)
    manifest = service.datasets.list()[0]
    assert manifest["available"] and manifest["train"]["sessions"] == 2983
    assert manifest["holdout"]["sessions"] == 37 and manifest["reserved_test"]["sessions"] == 100
    data = service.datasets.load(manifest["id"], 263)
    assert len(data["train"]) == 263 and len(data["holdout"]) == 37 and "test" not in data
    assert all(path.read_bytes() == raw for path, raw in original.items())
    imported = {path: path.stat().st_mtime_ns for path in directory.rglob("*") if path.is_file()}
    assert assets.install(directory)["written"] == 0
    assert all(path.stat().st_mtime_ns == modified for path, modified in imported.items())


def test_tampered_compressed_payload_is_rejected_before_any_installation(tmp_path):
    bundle = tmp_path / "bundle"
    shutil.copytree(assets.BUNDLE, bundle)
    path = next(bundle.glob("datasets/*/*.gz"))
    path.write_bytes(path.read_bytes() + b"tampered")
    directory = tmp_path / "behavior"
    with pytest.raises(ValueError, match="checksum"):
        assets.install(directory, bundle)
    assert not directory.exists()


def test_existing_candidate_conflict_does_not_partially_import_the_dataset(tmp_path):
    manifest = json.loads((assets.BUNDLE / "bundle.json").read_bytes())
    directory = tmp_path / "behavior"
    conflict = directory / "models" / (manifest["models"][-1]["version"] + ".json")
    conflict.parent.mkdir(parents=True)
    conflict.write_text("existing local candidate")
    with pytest.raises(ValueError, match="different content"):
        assets.install(directory)
    assert not (directory / "datasets").exists()
    assert list(conflict.parent.iterdir()) == [conflict]
    assert conflict.read_text() == "existing local candidate"


def test_installation_rejects_symlinked_model_directory(tmp_path):
    directory, elsewhere = tmp_path / "behavior", tmp_path / "elsewhere"
    directory.mkdir()
    elsewhere.mkdir()
    (directory / "models").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        assets.install(directory)
    assert not list(elsewhere.iterdir()) and not (directory / "datasets").exists()


def test_catalog_cannot_escape_the_shared_bundle(tmp_path):
    bundle = tmp_path / "bundle"
    shutil.copytree(assets.BUNDLE, bundle)
    path = bundle / "bundle.json"
    manifest = json.loads(path.read_bytes())
    manifest["files"]["../outside.json"] = {"bytes": 0, "sha256": "0" * 64}
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="file path"):
        assets.load_bundle(bundle)
