"""概率计量、独立证据支持、评分兼容与训练隔离的机制验证。"""

import copy
import json
import math
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A
from agentguard.detection import behavior as B
from agentguard.detection import behavior_evidence as E
from agentguard.detection.baseline_comparison import compare_models


def sessions(count=18, scale=1.0):
    return [{"key": str(i), "source": "swechat", "group": "repo-" + str(i // 2), "device": "",
             "weight": scale * (1 + i % 3), "steps": [
                 {"symbols": ["FILE_READ:workspace"], "intents": []},
                 {"symbols": ["EXEC:test" if i % 2 else "FILE_WRITE:workspace"], "intents": []},
                 {"symbols": ["EXEC:vcs:local_read"], "intents": []}]} for i in range(count)]


def model(items, mode="evidence", **kwargs):
    return B._baseline(A.fit(items, scoring_mode=mode, **kwargs), 8.0)


@pytest.mark.parametrize("granularity", E.GRANULARITIES)
def test_full_probabilities_scores_and_threshold_are_weight_scale_invariant(granularity):
    models = [model(sessions(scale=scale), granularity=granularity) for scale in (0.001, 1, 1000)]
    for baseline in models:
        assert baseline.compatible
    for prev, cur in ((A.START, "FILE_READ:workspace"), ("FILE_READ:workspace", "EXEC:test"),
                      ("never-seen", "NET_FETCH:unknown"), (A.START, "EXEC:vcs:local_read")):
        original = models[0].step_score(prev, cur, ["test"])
        for baseline in models[1:]:
            result = baseline.step_score(prev, cur, ["test"])
            for key in ("score", "rarity", "context", "probability", "marginal"):
                assert result[key] == original[key]
            for key in ("effective_n", "lambda"):
                assert result["evidence"][key] == pytest.approx(original["evidence"][key])
    calibrated = [B.calibrate(sessions(scale=scale), 95, fit_options={
        "scoring_mode": "evidence", "granularity": granularity}) for scale in (0.001, 1, 1000)]
    assert calibrated[0] == calibrated[1] == calibrated[2]


@pytest.mark.parametrize("count", [1, 18])
def test_probability_mass_including_one_unknown_bucket_is_normalized(count):
    baseline = model(sessions(count))
    # 使用各层自身词表；明细回退不是把父类事件复制给每个子类。
    for table in (baseline._global, baseline._global.coarse):
        alphabet = [*table.unigram, "__UNKNOWN__"]
        assert sum(table.marginal(s) for s in alphabet) == pytest.approx(1)
        for prev in (*table.transitions, None, "unseen"):
            assert sum(table.conditional(prev, s) for s in alphabet) == pytest.approx(1)
            assert all(math.isfinite(table.conditional(prev, s)) and table.conditional(prev, s) > 0
                       for s in alphabet)


def test_group_moments_are_aggregated_before_coarsening():
    item = {"source": "corpus", "key": "one", "steps": [{"symbols": [
        "EXEC:vcs:local_read", "EXEC:vcs:local_write", "EXEC:vcs:local_read"]}]}
    counts = A.fit([item], scoring_mode="evidence")
    fine, coarse = counts["evidence"]["fine"], counts["evidence"]["coarse"]
    assert fine["rows"]["EXEC:vcs:local_read"]["group_w2"] == 1
    assert fine["rows"]["EXEC:vcs:local_write"]["group_w2"] == 1
    assert coarse["rows"]["EXEC:vcs"]["sum_w"] == 2
    assert coarse["rows"]["EXEC:vcs"]["group_w2"] == 4
    assert E.effective_n(coarse["rows"]["EXEC:vcs"], "group") == 1


def test_weight_does_not_turn_one_session_into_many_supporting_groups():
    item = sessions(1, scale=10000)[0]
    baseline = model([item])
    row = baseline.step_score(A.START, "FILE_READ:workspace", [])["evidence"]
    assert row["weighted_mass"] == 10000
    assert row["effective_n"] == row["group_support"] == row["session_support"] == 1
    assert row["lambda"] == pytest.approx(1 / 21)
    assert baseline._global.fallback("EXEC:vcs:local_read")
    assert not model([item], mode="backoff")._global.fallback("EXEC:vcs:local_read")


def test_same_repository_repetition_does_not_increase_group_support():
    original = sessions(1)
    expanded = [dict(original[0], key=str(i)) for i in range(20)]
    row = model(expanded)._global.diagnostics(A.START)
    assert row["raw_count"] == row["session_support"] == 20
    assert row["group_support"] == row["effective_n"] == 1
    independent = [dict(item, group=item["key"]) for item in expanded]
    assert model(independent)._global.diagnostics(A.START)["effective_n"] == pytest.approx(20)


def test_duplicate_session_is_deduplicated_but_conflicting_content_is_rejected():
    items = sessions(2)
    original = A.fit(items, scoring_mode="evidence")
    duplicate = A.fit(items + [copy.deepcopy(items[0])], scoring_mode="evidence")
    for key in ("unigram", "transitions"):
        assert original[key] == duplicate[key]
    assert duplicate["evidence"]["dedup"]["duplicate_sessions"] == 1
    assert original["evidence"]["fine"] == duplicate["evidence"]["fine"]
    conflict = copy.deepcopy(items[0])
    conflict["steps"][0]["symbols"] = ["META"]
    with pytest.raises(ValueError, match="conflicting duplicate"):
        A.fit(items + [conflict], scoring_mode="evidence")
    assert B.calibrate(sessions(), 95, fit_options={"scoring_mode": "evidence"}) == B.calibrate(
        sessions() + [copy.deepcopy(sessions()[0])], 95, fit_options={"scoring_mode": "evidence"})


def test_source_namespace_and_identical_behavior_in_independent_sessions_are_preserved():
    one = sessions(1)[0]
    items = [one, dict(one, source="corpus"), dict(one, key="other", group="other")]
    baseline = model(items)
    assert baseline._global.diagnostics(A.START)["group_support"] == 3
    assert baseline._global.diagnostics(A.START)["raw_count"] == 3


@pytest.mark.parametrize("weight", [0, -1, True, float("nan"), float("inf"), 1e-300])
def test_invalid_or_underflowed_weights_are_rejected(weight):
    items = sessions(1)
    items[0]["weight"] = weight
    with pytest.raises(ValueError):
        A.fit(items, scoring_mode="evidence")


def test_cuts_preserve_legacy_transition_boundaries_without_rounding_counts():
    item = {"source": "recorded", "key": "device:trace", "weight": 0.00001234567, "steps": [
        {"symbols": ["A"]}, {"cut": True}, {"symbols": ["B"], "cut_after": True},
        {"symbols": ["C"]}, {"symbols": ["D"], "cut_before": True}, {"symbols": ["E"]}]}
    counts = A.fit([item], scoring_mode="evidence")
    assert counts["unigram"]["A"] == item["weight"]
    assert set(counts["transitions"]) == {A.START, "D"}
    assert set(counts["transitions"]["D"]) == {"E"}
    assert counts["evidence"]["fine"]["global"]["raw_count"] == 5


@pytest.mark.parametrize("flag", ["cut_before", "cut_after"])
def test_empty_boundary_step_cuts_new_scoring_context_as_it_does_fitting(flag):
    item = {"source": "recorded", "key": "empty-boundary", "steps": [
        {"symbols": ["FILE_READ:workspace"], "intents": []},
        {"symbols": [], "intents": [], flag: True},
        {"symbols": ["EXEC:test"], "intents": []}]}
    baseline = model([item])
    assert "FILE_READ:workspace" not in baseline.transitions
    scores = B.score_session(baseline, item)
    assert scores[-1]["prev"] is None and scores[-1]["evidence"]["lambda"] == 0


def test_model_roundtrip_and_missing_evidence_or_unknown_version_rejection():
    counts = A.fit(sessions(), scoring_mode="evidence")
    original = B._baseline(counts, 8.0)
    restored = B._baseline(json.loads(json.dumps(counts)), 8.0)
    assert restored.step_score(A.START, "FILE_READ:workspace", []) == original.step_score(A.START, "FILE_READ:workspace", [])
    for update in ({"score_semantics_version": 99}, {"evidence_schema_version": 99}, {"evidence": {}},
                   {"score_semantics_version": 1}, {"devices": {"d": {}}}):
        invalid = B._baseline({**counts, **update}, 8.0, devices=update.get("devices"))
        assert not invalid.compatible
        assert "证据" in B.incompatibility_reason(invalid)


def test_inconsistent_evidence_is_rejected_without_silent_legacy_scoring():
    counts = A.fit(sessions(), scoring_mode="evidence")
    counts["evidence"]["fine"]["rows"][A.START]["sum_w"] *= 2
    invalid = B._baseline(counts, 8)
    assert not invalid.compatible and invalid.disabled_reason == "invalid_evidence_model"


def test_legacy_scores_and_unmarked_format_remain_identical():
    data = json.loads(pathlib.Path(A.BASELINE_PATH).with_name("transitions.legacy.json").read_text())
    legacy = A.Baseline.from_dict(data)
    explicit = A.Baseline.from_dict({**data, "score_semantics_version": 1})
    assert legacy.compatible and explicit.compatible
    assert B.evaluate(legacy, []) == B.evaluate(explicit, [])
    assert B.evaluate(legacy, [])["fixture_benign_over_threshold"] == 1
    assert B.evaluate(legacy, [])["fixture_risk_over_threshold"] == 33


@pytest.mark.parametrize("mode", E.MODES)
def test_training_threads_evidence_configuration_through_cv_and_persistence(mode, monkeypatch, tmp_path):
    original, groups = A.fit, set()

    def guarded_fit(items, **options):
        nonlocal groups
        groups = {item["group"] for item in items}
        assert options["scoring_mode"] == mode
        return original(items, **options)

    score = B.score_session

    def guarded_score(baseline, item):
        assert item["group"] not in groups
        assert baseline.score_semantics_version == E.SCORE_VERSION
        return score(baseline, item)

    monkeypatch.setattr(A, "fit", guarded_fit)
    monkeypatch.setattr(B, "score_session", guarded_score)
    B.calibrate(sessions(), 95, source_weights={"swechat": 1}, fit_options={"scoring_mode": mode})
    monkeypatch.setattr(A, "fit", original)
    monkeypatch.setattr(B, "score_session", score)
    dataset = {"train": sessions(), "holdout": [], "meta": {}}
    params = {"use_corpus": False, "use_recorded": False, "personalize": False,
              "dataset_id": "data", "scoring_mode": mode, "evidence_k": 50, "evidence_prior": 5}
    result = B.train(params, [], "m20261017-220000-abcd", dataset=dataset, source_weights={"swechat": 1})
    assert result["format"] == 4 and result["backoff_k"] == 50
    assert result["meta"]["scoring"]["prior_strength"] == 5
    baseline = A.Baseline.from_dict(result)
    assert baseline.compatible and baseline.score_semantics_version == 2
    service = B.BehaviorService(str(tmp_path))
    (tmp_path / "models" / (result["version"] + ".json")).write_text(json.dumps(result))
    assert service.active_version == "builtin"
    report = compare_models(service, ["builtin", result["version"]])
    assert report["normal_steps"] == 67 and report["risk_steps"] == 44
    service.activate(result["version"])
    assert B.BehaviorService(str(tmp_path)).active_version == result["version"]
    service.activate("builtin")
    assert B.BehaviorService(str(tmp_path)).active_version == "builtin"


def test_new_mode_rejects_personalization_and_bad_configuration():
    with pytest.raises(ValueError, match="个性化"):
        B.train({"scoring_mode": "evidence", "personalize": True}, [], "x")
    for options in ({"scoring_mode": "unknown"}, {"evidence_granularity": "unknown"},
                    {"evidence_k": 0}, {"evidence_prior": float("nan")}, {"evidence_k": True},
                    {"evidence_k": 1e-300}, {"evidence_prior": 1e-300}):
        with pytest.raises(ValueError):
            B.normalize_params(options)


def test_evidence_training_through_authenticated_api_preserves_active_and_recorded_data(monkeypatch, tmp_path):
    from test_behavior import ADMIN, make_client
    from test_behavior_datasets import register

    store = register(tmp_path)
    directory = store.directory.parent
    (directory / B.RECORD_FILE).write_text("")
    client = make_client(monkeypatch, directory)
    before = client.get("/v1/admin/baseline", headers=ADMIN).json()
    params = {"dataset_id": "swechat-test", "scoring_mode": "evidence", "use_recorded": False,
              "personalize": False, "evidence_k": 5, "evidence_prior": 5}
    assert client.post("/v1/admin/baseline/train", json={"params": params}).status_code == 401
    response = client.post("/v1/admin/baseline/train", json={"params": params}, headers=ADMIN)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["score_semantics_version"] == 2 and result["evidence_schema_version"] == 1
    assert result["meta"]["scoring"]["validation_status"] == "experimental_diagnostic_only"
    assert any(c["id"] == "evidence_validation" and c["level"] == "warn"
               for c in result["meta"]["assessment"]["checks"])
    after = client.get("/v1/admin/baseline", headers=ADMIN).json()
    assert after["active"] == before["active"]
    assert (directory / B.RECORD_FILE).read_bytes() == b""
    trained = next(m for m in after["models"] if m["version"] == result["version"])
    assert trained["score_semantics_version"] == 2 and trained["compatible"]


def test_training_only_tuner_uses_group_isolation_and_trigger_budget_excludes_ties(monkeypatch):
    sys.path.insert(0, str(ROOT / "tools"))
    import behavior_evidence_experiment as X

    original_fit, original_loss = A.fit, X.log_loss
    fitted = set()

    def guarded_fit(rest, **kwargs):
        nonlocal fitted
        fitted = {item["group"] for item in rest}
        return original_fit(rest, **kwargs)

    original_events = X.event_mass

    def guarded_events(held, weights):
        assert not fitted & {item["group"] for item in held}
        return original_events(held, weights)

    monkeypatch.setattr(A, "fit", guarded_fit)
    monkeypatch.setattr(X, "event_mass", guarded_events)
    result = X.tune(sessions())
    assert result["scope"] == "training_only" and len(result["grid"]) == 36
    assert all(math.isfinite(row["weighted_cv_bits_per_symbol"]) for row in result["grid"])
    assert X.log_loss is original_loss
    budget = X.trigger_budget([1, 2, 2, 3], [1, 1, 1, 1], 0.25)
    assert budget["threshold"] == 2.01 and budget["training_weighted_trigger_rate"] == 0.25
