"""同样本的基线比较：已知混淆结果、无预测正例、版本校验和只读性。"""

import json

import pytest
from test_behavior import ADMIN, make_client

from agentguard.detection import behavior as B
from agentguard.detection.baseline_comparison import classification_metrics, compare_models

VERSION = "m20261017-110000-abcd"


def service_with_candidate(tmp_path):
    service = B.BehaviorService(str(tmp_path))
    model = service.get("builtin")
    model.update(version=VERSION, threshold=30)
    (tmp_path / "models" / (VERSION + ".json")).write_text(json.dumps(model))
    return service


def test_fixed_fixture_results_are_recomputed_once_for_all_versions(monkeypatch, tmp_path):
    service = service_with_candidate(tmp_path)
    original = B.fixture_sessions
    calls = []

    def fixtures():
        calls.append(True)
        return original()

    monkeypatch.setattr(B, "fixture_sessions", fixtures)
    report = compare_models(service, ["builtin", VERSION])
    assert len(calls) == 1
    assert (report["normal_steps"], report["risk_steps"]) == (67, 44)
    builtin, high_threshold = report["models"]
    assert builtin["confusion"] == {"tp": 24, "fp": 0, "fn": 20, "tn": 67}
    assert builtin["metrics"]["accuracy"] == pytest.approx(91 / 111)
    assert builtin["metrics"]["precision"] == 1
    assert builtin["metrics"]["recall"] == pytest.approx(24 / 44)
    assert builtin["metrics"]["f1"] == pytest.approx(48 / 68)
    assert builtin["metrics"]["auc"] == 0.888
    assert builtin["order"] == 3
    assert high_threshold["confusion"]["tp"] == high_threshold["confusion"]["fp"] == 0
    assert high_threshold["metrics"]["precision"] is None and high_threshold["metrics"]["f1"] == 0
    # 阈值不影响排序 AUC；交换版本后样本哈希与各版本结果不变。
    assert high_threshold["metrics"]["auc"] == builtin["metrics"]["auc"]
    swapped = compare_models(service, [VERSION, "builtin"])
    assert swapped["fixture_sha256"] == report["fixture_sha256"]
    assert swapped["models"] == list(reversed(report["models"]))


def test_empty_classification_denominators_remain_undefined():
    assert all(value is None for value in classification_metrics(0, 0, 0, 0).values())
    assert classification_metrics(0, 0, 4, 5)["precision"] is None
    assert classification_metrics(0, 0, 4, 5)["f1"] == 0


def test_compare_endpoint_requires_admin_and_never_writes_models_or_records(monkeypatch, tmp_path):
    service_with_candidate(tmp_path)
    (tmp_path / "active.json").write_text(json.dumps({"version": VERSION}))
    (tmp_path / B.RECORD_FILE).write_text("")
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    client = make_client(monkeypatch, tmp_path)
    assert client.post("/v1/admin/baseline/compare", json={"versions": ["builtin", VERSION]}).status_code == 401
    response = client.post("/v1/admin/baseline/compare", headers=ADMIN, json={"versions": ["builtin", VERSION]})
    assert response.status_code == 200, response.text
    assert response.json()["scope"] == "fixed_fixture_selected_steps_shared_counts"
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert before == after
    assert client.get("/v1/admin/baseline", headers=ADMIN).json()["active"] == VERSION


@pytest.mark.parametrize("versions,status", [
    (None, 400), ([], 400), (["builtin"], 400), (["builtin", "builtin"], 400),
    (["builtin", {}], 400), (["builtin", VERSION, "a", "b"], 400),
    (["builtin", "../active"], 404), (["builtin", "m20261017-110000-ffff"], 404),
])
def test_compare_endpoint_rejects_invalid_selection(monkeypatch, tmp_path, versions, status):
    service_with_candidate(tmp_path)
    client = make_client(monkeypatch, tmp_path)
    response = client.post("/v1/admin/baseline/compare", headers=ADMIN, json={"versions": versions})
    assert response.status_code == status, response.text


def test_compare_endpoint_rejects_incompatible_model(monkeypatch, tmp_path):
    service = service_with_candidate(tmp_path)
    data = service.get(VERSION)
    data["sequence_semantics_version"] = 0
    (tmp_path / "models" / (VERSION + ".json")).write_text(json.dumps(data))
    client = make_client(monkeypatch, tmp_path)
    response = client.post("/v1/admin/baseline/compare", headers=ADMIN, json={"versions": ["builtin", VERSION]})
    assert response.status_code == 400 and "不兼容" in response.json()["detail"]
