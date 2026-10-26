"""控制台外部数据源：不可变登记、分区隔离、鉴权与候选训练。"""

import copy
import json
from pathlib import Path

import pytest
from test_behavior import ADMIN, make_client

from agentguard.detection import behavior as B
from agentguard.detection.behavior_datasets import DatasetStore, digest, encoded, publish


def prepared():
    def session(key, symbol="EXEC:test"):
        return {"key": key, "group": "repo-" + key, "source": "swechat", "agent": "claude-code", "device": "",
                "steps": [{"symbols": [symbol], "intents": [], "execution": "succeeded"}]}

    return {"meta": {"source": "SALT-NLP/SWE-chat", "feature_schema_version": B.A.FEATURE_SCHEMA_VERSION,
                     "sequence_semantics_version": B.A.SEQUENCE_SEMANTICS_VERSION,
                     "label_status": "unverified_real_development", "dataset_sha256": "prepared-symbol-hash"},
            "train": [session("a"), session("b"), session("c")], "holdout": [session("validation")],
            "test": [session("test", "NET_FETCH:docs")],
            "inputs": [{"session": key, "counts": {"review_flagged_steps": 1}} for key in ("a", "b", "c")]}


def register(tmp_path, data=None):
    path = tmp_path / "prepared.json"
    path.write_bytes(encoded(prepared() if data is None else data))
    directory = tmp_path / "behavior" / "datasets"
    publish(path, directory, "swechat-test", "SWE-chat 测试")
    return DatasetStore(str(directory.parent))


def test_publication_is_immutable_and_test_symbols_never_reach_runtime(tmp_path):
    store = register(tmp_path)
    manifest = store.list()[0]
    assert manifest["available"] and manifest["train"] == {"sessions": 3, "steps": 3, "groups": 3}
    assert manifest["holdout"]["sessions"] == manifest["reserved_test"]["sessions"] == 1
    payload = (store.directory / "swechat-test" / "sessions.json").read_bytes()
    assert b'NET_FETCH:docs' not in payload and '"test":' not in payload.decode()
    data = store.load("swechat-test", 2)
    assert [s["key"] for s in data["train"]] == ["a", "b"]
    assert data["holdout"][0]["key"] == "validation" and "test" not in data
    assert data["meta"]["training_counts"]["review_flagged_steps"] == 2
    assert data["meta"]["prepared_dataset_sha256"] == "prepared-symbol-hash"
    assert data["meta"]["registration"]["sha256"] == digest(payload)
    assert store.load("swechat-test")["meta"]["training_limit"] == 3
    # 幂等发布；不同内容不能覆盖已登记版本。
    path = tmp_path / "prepared.json"
    publish(path, store.directory, "swechat-test", "SWE-chat 测试")
    data = prepared()
    data["train"][0]["steps"][0]["symbols"] = ["META"]
    path.write_bytes(encoded(data))
    with pytest.raises(ValueError, match="different content"):
        publish(path, store.directory, "swechat-test", "SWE-chat 测试")
    with pytest.raises(ValueError, match="超过"):
        store.load("swechat-test", 4)


@pytest.mark.parametrize("mutation,reason", [
    (lambda d: d["meta"].update(sequence_semantics_version=0), "版本不兼容"),
    (lambda d: d["test"][0].update(group="repo-a"), "overlapping"),
    (lambda d: d["holdout"][0].update(group="repo-a"), "overlapping"),
    (lambda d: d["holdout"][0].update(key="a"), "duplicate"),
    (lambda d: d["train"][0]["steps"][0].update(command="echo raw-secret"), "symbols only"),
    (lambda d: d["train"][0]["steps"][0].update(execution="pending"), "unconfirmed"),
])
def test_publication_rejects_incompatible_leaking_and_overlapping_data(tmp_path, mutation, reason):
    data = prepared()
    mutation(data)
    with pytest.raises(ValueError, match=reason):
        register(tmp_path, data)


def test_service_rejects_tampering_and_traversal(tmp_path):
    store = register(tmp_path)
    with pytest.raises(ValueError):
        store.load("../prepared.json")
    path = store.directory / "swechat-test" / "sessions.json"
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="哈希"):
        store.load("swechat-test")
    path.write_bytes(original)
    # 即使同步更新了内容哈希，加载时也重新检查保留测试仓库隔离。
    data = json.loads(original)
    data["train"][0]["group"] = "repo-test"
    path.write_bytes(encoded(data))
    mpath = path.with_name("manifest.json")
    manifest = json.loads(mpath.read_bytes())
    manifest["sha256"] = digest(path.read_bytes())
    mpath.write_bytes(encoded(manifest))
    with pytest.raises(ValueError, match="overlapping"):
        store.load("swechat-test")


def test_unavailable_dataset_stays_visible_with_reason(tmp_path):
    store = register(tmp_path)
    path = store.directory / "swechat-test" / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["meta"]["sequence_semantics_version"] = 0
    path.write_bytes(encoded(manifest))
    assert not store.list()[0]["available"] and store.list()[0]["reason"]
    manifest["meta"] = []
    path.write_bytes(encoded(manifest))
    assert not store.list()[0]["available"] and store.list()[0]["reason"]


def test_api_trains_registered_source_and_preserves_active_model_and_records(monkeypatch, tmp_path):
    store = register(tmp_path)
    directory = str(store.directory.parent)
    recorder = B.BehaviorRecorder(directory)
    recorder.record(device="local", agent="claude-code", trace="normal", intents=[],
                    symbols=["FILE_READ:workspace"], decision="ALLOW")
    records = (Path(directory) / B.RECORD_FILE).read_bytes()
    client = make_client(monkeypatch, Path(directory))
    assert client.get("/v1/admin/baseline").status_code == 401
    overview = client.get("/v1/admin/baseline", headers=ADMIN).json()
    assert overview["datasets"][0]["train"]["sessions"] == 3
    params = {"dataset_id": "swechat-test", "dataset_limit": 2, "use_corpus": False,
              "use_recorded": False, "personalize": False}
    assert client.post("/v1/admin/baseline/train", json={"params": params}).status_code == 401
    response = client.post("/v1/admin/baseline/train", headers=ADMIN, json={"params": params})
    assert response.status_code == 200, response.text
    model = response.json()
    assert model["score_semantics_version"] == 3 and model["order"] == 3
    assert model["meta"]["train_sessions"] == model["meta"]["external_sessions"] == 2
    assert model["meta"]["corpus_sessions"] == model["meta"]["recorded_sessions"] == 0
    assert model["meta"]["holdout_sessions"] == 1
    assert model["meta"]["external_source"]["reserved_test"]["sessions"] == 1
    assert model["meta"]["source_balance"]["sources"]["swechat"]["fraction"] == 1
    assert client.get("/v1/admin/baseline", headers=ADMIN).json()["active"] == overview["active"]
    assert (Path(directory) / B.RECORD_FILE).read_bytes() == records
    restarted = B.BehaviorService(directory)
    assert restarted.get(model["version"]) and restarted.active_version == overview["active"]
    assert restarted.get(model["version"])["unigram"].get("NET_FETCH:docs", 0) == 0
    # 原始计数允许外部数据、内置语料与接入记录一起训练。
    params.update(dataset_balance="raw", use_recorded=True, use_corpus=True, personalize=True, scoring_mode="legacy")
    mixed = client.post("/v1/admin/baseline/train", headers=ADMIN, json={"params": params}).json()
    assert mixed["meta"]["recorded_sessions"] == 1 and mixed["meta"]["corpus_sessions"] == 49
    assert mixed["meta"]["external_sessions"] == 2


@pytest.mark.parametrize("override", [
    {"dataset_id": "../secret"}, {"dataset_id": "missing"}, {"dataset_id": ["swechat-test"]},
    {"dataset_limit": -1}, {"dataset_limit": 1.5}, {"dataset_limit": True}, {"dataset_limit": 4},
    {"dataset_balance": "random"}, {"use_recorded": True}, {"personalize": True},
])
def test_api_rejects_bad_dataset_selections(monkeypatch, tmp_path, override):
    store = register(tmp_path)
    client = make_client(monkeypatch, store.directory.parent)
    params = {"dataset_id": "swechat-test", "use_recorded": False, "personalize": False, **copy.deepcopy(override)}
    response = client.post("/v1/admin/baseline/train", headers=ADMIN, json={"params": params})
    assert response.status_code == 400, response.text
