"""高阶概率、生命周期切断、训练/推理一致性及旧模型回滚。"""

import copy
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from agentguard.core import capability as C
from agentguard.detection import anomaly as A
from agentguard.detection import behavior as B
from agentguard.detection import behavior_markov as M


def sessions():
    return [{"source": "toy", "key": f"s{i}", "group": f"g{i}", "weight": 1.,
             "steps": [{"symbols": list("AXBAYC") * 5, "intents": []}]} for i in range(12)]


def model(items=None, **options):
    return B._baseline(A.fit(items or sessions(), scoring_mode=M.MODE, prior_strength=5., **options), 9.24, "new")


def attempt(state, key, symbols, status="succeeded", version="new"):
    state.register(key, key, {"symbols": symbols, "model_version": version, "executes": status != "denied"})
    return state.complete(key, key, status)


def test_third_order_uses_more_than_the_last_symbol():
    baseline = model(order=3, backoff_k=1.)
    table = baseline.table()
    assert table.conditional(("B", "A"), "Y") > table.conditional(("C", "A"), "Y")
    assert baseline.step_score("A", "Y", [], history=("B", "A"))["score"] < \
        baseline.step_score("A", "Y", [], history=("C", "A"))["score"]
    assert baseline.order == 3 and baseline.compatible


@pytest.mark.parametrize("granularity", ["event", "session", "group"])
def test_probability_normalization_unknown_and_weight_scale_invariance(granularity):
    original = sessions()
    left = model(original, granularity=granularity)
    right = model([{**s, "weight": 1234.} for s in original], granularity=granularity)
    vocabulary = list(left.unigram) + ["never-seen"]
    for history in ((), (A.START,), ("A",), ("B", "A"), ("unknown", "C", "A")):
        assert sum(left.table().conditional(history, s) for s in vocabulary) == pytest.approx(1.)
        for symbol in vocabulary:
            p = left.table().conditional(history, symbol)
            assert p > 0 and p == pytest.approx(right.table().conditional(history, symbol), abs=1e-12)


def test_duplicate_identity_does_not_inflate_evidence():
    items = sessions()
    assert model(items).sequence_model == model(items + [items[0]]).sequence_model
    with pytest.raises(ValueError, match="conflicting duplicate"):
        model(items + [{**items[0], "weight": 2.}])


@pytest.mark.parametrize("corruption", ["duplicate", "suffix", "mass", "negative", "schema", "order", "moment"])
def test_invalid_sequence_models_are_disabled(corruption):
    counts = A.fit(sessions(), scoring_mode=M.MODE, prior_strength=5.)
    raw = {**copy.deepcopy(counts), "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
           "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION}
    rows = raw["sequence_model"]["contexts"]
    if corruption == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif corruption == "suffix":
        rows[:] = [row for row in rows if row["history"] != ["A"]]
    elif corruption == "mass":
        rows[0]["evidence"]["sum_w"] *= 2
    elif corruption == "negative":
        rows[0]["counts"]["A"] = -1
    elif corruption == "schema":
        raw["sequence_model"]["schema_version"] = 99
    elif corruption == "order":
        raw["sequence_model"]["order"] = True
    elif corruption == "moment":
        rows[0]["evidence"]["group_w2"] = float("inf")
    result = A.Baseline.from_dict(raw)
    assert not result.compatible and result.disabled_reason == "invalid_sequence_model"
    assert "评分" in B.incompatibility_reason(result)


def test_cut_flags_and_multisymbol_steps_match_online_completion():
    baseline = model()
    steps = [{"symbols": ["A", "X"], "intents": []}, {"symbols": ["B"], "intents": []},
             {"symbols": [], "intents": [], "cut_before": True},
             {"symbols": ["A", "Y"], "intents": []},
             {"symbols": ["C"], "intents": [], "cut_after": True},
             {"symbols": ["A"], "intents": []}]
    offline = B.score_session(baseline, {"steps": steps})
    state, online = A.BehaviorState(), []
    for i, step in enumerate(steps):
        if step.get("cut_before"):
            state.prev = None
        if step["symbols"]:
            online.append(A.score_symbols(baseline, state.prev, step["symbols"], [], history=state.history))
            attempt(state, str(i), step["symbols"], "failed" if step.get("cut_after") else "succeeded")
    assert [s["score"] for s in online] == [s["score"] for s in offline]
    assert [s["history"] for s in online] == [s["history"] for s in offline]


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_failed_or_unknown_result_clears_the_entire_history(status):
    state = A.BehaviorState()
    attempt(state, "first", ["A", "B", "C"])
    result = attempt(state, "bad", ["X"], status)
    assert state.history == () and state.prev is None and result["cut_after"]
    attempt(state, "after", ["Y"])
    assert state.history == ("Y",)


def test_parallel_unmatched_duplicate_and_denied_callbacks():
    state = A.BehaviorState()
    attempt(state, "first", ["A", "B", "C"])
    before = state.history
    attempt(state, "blocked", ["X"], "denied")
    assert state.history == before
    assert state.complete("blocked", "blocked", "succeeded") is None
    assert state.history == before
    for key in ("p1", "p2"):
        state.register(key, key, {"symbols": [key], "executes": True})
    assert state.history == ()
    for key in ("p2", "p1"):
        result = state.complete(key, key, "succeeded")
        assert result["cut_before"] and result["cut_after"] and state.history == ()
    attempt(state, "resume", ["A", "B"])
    assert state.complete("missing", "", "succeeded") is None and state.history == ()


def test_model_switch_cuts_history_without_mutating_during_scoring():
    state = A.BehaviorState()
    attempt(state, "old", ["A", "B", "C"], version="old")
    before = state.history
    baseline = model()
    result = A.score_request(baseline, state, C.expand_command("pytest"), "/workspace")
    assert result["history"] == [] and state.history == before
    state.register("new-call", "new-call", {"symbols": ["EXEC:test"], "executes": True, "model_version": "new"})
    assert state.history == ()
    completed = state.complete("new-call", "new-call", "succeeded")
    assert completed["cut_before"] and state.history == ("EXEC:test",)


def test_training_defaults_and_explicit_legacy_rollback(tmp_path):
    defaults = B.normalize_params(None)
    assert defaults["scoring_mode"] == M.MODE and defaults["markov_order"] == 3
    assert defaults["evidence_prior"] == 5 and not defaults["personalize"]
    trained = B.train({"use_recorded": False}, [], "m20261019-120000-abcd")
    assert trained["format"] == 5 and trained["meta"]["corpus_sessions"] == 49
    assert A.Baseline.from_dict(trained).order == 3
    for value in (0, 9, 1.5, True):
        with pytest.raises(ValueError):
            B.normalize_params({"markov_order": value})
    service = B.BehaviorService(str(tmp_path))
    service.activate(B.LEGACY_BUILTIN)
    assert service.baseline.score_semantics_version == 1 and service.baseline.order == 1
    assert B.BehaviorService(str(tmp_path)).active_version == B.LEGACY_BUILTIN
    service.activate(B.BUILTIN)
    assert service.baseline.compatible
    with pytest.raises(ValueError):
        service.delete(B.LEGACY_BUILTIN)
    assert json.loads((tmp_path / "active.json").read_text())["version"] == B.BUILTIN


def test_single_training_group_uses_explicit_threshold_fallback_without_empty_fit():
    items = sessions()[:1]
    details = {}
    value, scores = B.calibrate(items, 95, fit_options={"scoring_mode": M.MODE}, details=details)
    assert value == M.DEFAULT_THRESHOLD and scores == []
    assert details["status"] == "insufficient_groups" and details["groups"] == 1
