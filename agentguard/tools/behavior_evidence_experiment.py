#!/usr/bin/env python3
"""固定训练分区，按训练侧分组 CV 的条件对数损失选择证据参数；仅生成离线候选。

python3 tools/behavior_evidence_experiment.py --prepared <dataset.json> --out-dir <new-directory>

验证/历史测试只在全部模型冻结后用于诊断；不登记、不启用，不执行原始工具。
"""

import argparse
import hashlib
import itertools
import json
import math
import pathlib
import sys
import time
import uuid
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection import behavior as B  # noqa: E402
from agentguard.detection import behavior_evidence as E  # noqa: E402

SOURCE_WEIGHTS = {"corpus": 0.25, "swechat": 0.75}
K_GRID = (5, 20, 50, 100)
PRIOR_GRID = (1, 5, 20)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n")


def event_mass(sessions, weights):
    events = defaultdict(float)
    for session in sessions:
        weight = weights[(session["source"], session["key"])]
        prev = A.START
        for step in session["steps"]:
            if step.get("cut"):
                prev = None
                continue
            if step.get("cut_before"):
                prev = None
            for symbol in step["symbols"]:
                events[prev, symbol] += weight
                prev = symbol
            if step.get("cut_after"):
                prev = None
    return events


def log_loss(baseline, events):
    # 相同前序/目标的贡献可合并，不必重复查询数十万步；词表仅来自当前训练折。
    loss = 0.0
    for (prev, symbol), mass in events.items():
        table = baseline._global
        if table.coarse and (table.fallback(symbol) or (prev is not None and table.fallback(prev))):
            table = table.coarse
            prev = A.parent_symbol(prev) if prev is not None else None
            symbol = A.parent_symbol(symbol)
        loss -= mass * math.log2(table.conditional(prev, symbol))
    return loss


def trigger_budget(scores, weights, budget):
    """按训练侧分数确定不超过预算的阈值；两位分数的并列点整体排除。"""
    cutoff = B.weighted_percentile(scores, weights, 100 * (1 - budget))
    threshold = round(cutoff + 0.01, 2)
    total = sum(weights)
    rate = sum(w for score, w in zip(scores, weights) if score >= threshold) / total if total else 0.0
    return {"threshold": threshold, "training_weighted_trigger_rate": rate, "budget": budget}


def tune(train):
    """只接受训练会话；不读取留出、测试或攻击标签。"""
    train, _ = E.unique_sessions(train)
    groups = sorted({(item["source"], item.get("group") or item["key"]) for item in train},
                    key=lambda group: (group[1], group[0]))
    if len(groups) < 2:
        raise ValueError("at least two training groups are required")
    folds = min(B.FOLDS, len(groups))
    by_group = {group: index % folds for index, group in enumerate(groups)}
    assignments = [by_group[(item["source"], item.get("group") or item["key"])] for item in train]
    weighted, _ = B.balance_sessions(train, SOURCE_WEIGHTS)
    weights = {(item["source"], item["key"]): item["weight"] for item in weighted}
    options = list(itertools.product(E.GRANULARITIES, K_GRID, PRIOR_GRID))
    losses, mass = {option: 0.0 for option in options}, 0.0
    for fold in range(folds):
        rest = [item for item, assigned in zip(train, assignments) if assigned != fold]
        held = [item for item, assigned in zip(train, assignments) if assigned == fold]
        rest, _ = B.balance_sessions(rest, SOURCE_WEIGHTS)
        counts = A.fit(rest, scoring_mode="evidence")
        events = event_mass(held, weights)
        mass += sum(events.values())
        for granularity, k, prior in options:
            config = {**counts["scoring_config"], "granularity": granularity, "prior_strength": prior}
            baseline = B._baseline({**counts, "scoring_config": config, "backoff_k": k}, 99)
            assert baseline.compatible
            losses[granularity, k, prior] += log_loss(baseline, events)
    rows = [{"granularity": granularity, "k": k, "prior": prior, "weighted_cv_bits_per_symbol": loss / mass}
            for (granularity, k, prior), loss in losses.items()]
    best = {granularity: min((row for row in rows if row["granularity"] == granularity),
                             key=lambda row: (row["weighted_cv_bits_per_symbol"], row["k"], row["prior"]))
            for granularity in E.GRANULARITIES}
    return {"objective": "training_group_cv_weighted_conditional_log_loss_bits", "folds": folds,
            "scope": "training_only", "grid": rows, "best_by_granularity": best}


def diagnostic(baseline, dataset):
    metrics = B.evaluate(baseline, dataset["holdout"])
    test = [score for session in dataset["test"] for score in B.score_session(baseline, session)]
    tp, fp = metrics["fixture_risk_over_threshold"], metrics["fixture_benign_over_threshold"]
    fn = metrics["fixture_risk_steps"] - tp
    return {**metrics, "fixture_f1": 2 * tp / (2 * tp + fp + fn),
            "historical_test_steps": len(test), "historical_test_over_threshold": sum(s["anomalous"] for s in test)}


def run(prepared, out):
    raw = prepared.read_bytes()
    dataset = json.loads(raw)
    train = B.corpus_sessions() + dataset["train"]
    train_groups = {item["group"] for item in dataset["train"]}
    holdout_groups = {item["group"] for item in dataset["holdout"]}
    test_groups = {item["group"] for item in dataset["test"]}
    if train_groups & (holdout_groups | test_groups) or holdout_groups & test_groups:
        raise ValueError("prepared partitions contain overlapping groups")
    out.mkdir(parents=True, exist_ok=False)
    save(out / "protocol.json", {
        "prepared_sha256": hashlib.sha256(raw).hexdigest(), "source_weights": SOURCE_WEIGHTS,
        "k_grid": K_GRID, "prior_grid": PRIOR_GRID, "quantile": 95,
        "additional_diagnostics": "matched training-side weighted trigger budgets 1% and 5%; not verified benign false-positive budgets",
        "selection": "per-granularity minimum training-group CV log loss; group is the declared primary candidate",
        "modes": ["legacy", "backoff_group_k20", "evidence_event", "evidence_session", "evidence_group"],
        "validation_status": "previously_observed_development_data",
        "test_status": "historical_diagnostic_reuse_not_fresh_acceptance",
        "registered": False, "activated": False,
        "code_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
            pathlib.Path(__file__), ROOT / "agentguard/detection/anomaly.py",
            ROOT / "agentguard/detection/behavior.py", ROOT / "agentguard/detection/behavior_evidence.py")}})
    print(json.dumps({"phase": "training_only_parameter_selection", "output": str(out)}), flush=True)
    tuning = tune(train)
    save(out / "tuning.json", tuning)
    weighted, balance = B.balance_sessions(train, SOURCE_WEIGHTS)
    frozen = []
    for name, mode, granularity, k, prior in [
        ("legacy", "legacy", "group", 20, 1), ("backoff_group_k20", "backoff", "group", 20, 1),
        *[("evidence_" + granularity, "evidence", granularity, row["k"], row["prior"])
          for granularity, row in tuning["best_by_granularity"].items()]]:
        options = {} if mode == "legacy" else {"scoring_mode": mode, "granularity": granularity,
                                               "backoff_k": k, "prior_strength": prior}
        cv_details = {}
        threshold, cv_scores = B.calibrate(train, 95, source_weights=SOURCE_WEIGHTS, fit_options=options,
                                           details=cv_details)
        counts = A.fit(weighted, **options)
        version = time.strftime("m%Y%m%d-%H%M%S-", time.gmtime()) + uuid.uuid4().hex[:4]
        model = {"format": 3 if mode == "legacy" else 4,
                 "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
                 "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION,
                 "version": version, "created_at": time.time(), "threshold": threshold,
                 "alpha": A.ALPHA, "backoff_k": k, "device_weight": A.DEVICE_WEIGHT,
                 "devices": {}, "params": {"use_corpus": True, "use_recorded": False, "personalize": False,
                                            "scoring_mode": mode, "evidence_granularity": granularity,
                                            "evidence_k": k, "evidence_prior": prior},
                 "meta": {"train_sessions": len(train), "train_steps": sum(bool(s.get("symbols"))
                           for item in train for s in item["steps"]), "corpus_sessions": len(B.corpus_sessions()),
                          "external_sessions": len(dataset["train"]), "recorded_sessions": 0,
                          "validation_status": "experimental_diagnostic_only", "source_balance": balance,
                          "matched_training_budgets": [trigger_budget(cv_scores, cv_details["weights"], budget)
                                                       for budget in (0.01, 0.05)],
                          "weighted_cv_threshold": threshold, "cv_steps": len(cv_scores)}, **counts}
        save(out / ("model-" + name + ".json"), model)
        frozen.append((name, model))
        print(json.dumps({"phase": "model_frozen", "mode": name, "threshold": threshold, "k": k, "prior": prior}), flush=True)
    # 全部候选冻结后才看诊断集；结果不回流至参数选择。
    rows = []
    for name, data in frozen:
        baseline = A.Baseline.from_dict(data)
        assert baseline.compatible
        row = {"name": name, "version": baseline.version, "threshold": baseline.threshold,
               "backoff_k": baseline.backoff_k, "scoring_config": baseline.scoring_config,
               **diagnostic(baseline, dataset)}
        row["matched_training_budgets"] = []
        for budget in data["meta"]["matched_training_budgets"]:
            alternative = A.Baseline.from_dict({**data, "threshold": budget["threshold"]})
            row["matched_training_budgets"].append({**budget, **diagnostic(alternative, dataset)})
        if name == "legacy":
            # 对照既有已冻结模型，确认实验没有悄悄改变 M0。
            old = prepared.parent / "model-3000-balanced.json"
            if old.is_file():
                original = json.loads(old.read_bytes())
                assert all(data[key] == original[key] for key in ("unigram", "transitions", "threshold"))
                row["m0_matches_frozen_model"] = True
        rows.append(row)
    report = {"protocol": "protocol.json", "primary_candidate": "evidence_group", "models": rows,
              "status": "mechanism_implemented_diagnostic_evaluation_only_no_independent_acceptance",
              "registered": False, "activated": False}
    save(out / "report.json", report)
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--prepared", type=pathlib.Path, required=True)
    parser.add_argument("--out-dir", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    run(args.prepared, args.out_dir)


if __name__ == "__main__":
    main()
