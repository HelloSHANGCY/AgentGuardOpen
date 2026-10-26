"""基线在同一份固定夹具上的只读比较；统计单位是所选步骤，不是完整引擎决策。"""

import hashlib
import json
import time

from . import anomaly as A
from . import behavior as B


def classification_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    return {"accuracy": ratio(tp + tn, tp + fp + fn + tn), "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn), "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "normal_trigger_rate": ratio(fp, fp + tn)}


def compare_models(service: B.BehaviorService, versions: list) -> dict:
    if (not isinstance(versions, list) or not 2 <= len(versions) <= 3 or
            any(not isinstance(version, str) for version in versions) or len(set(versions)) != len(versions)):
        raise ValueError("请选择 2–3 个不同的模型版本")
    models = []
    for version in versions:
        data = service.get(version)
        if data is None:
            raise KeyError(version)
        baseline = A.Baseline.from_dict({**data, "version": version})
        if not baseline.compatible:
            raise ValueError(B.incompatibility_reason(baseline))
        models.append((data, baseline))

    # 每次请求只生成一次样本，所有版本共享同一批特征及标签。
    fixtures = B.fixture_sessions()
    sha = hashlib.sha256(json.dumps(fixtures, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()
    results = []
    for data, baseline in models:
        normal, risk = [], []
        for session in fixtures:
            scores = B.score_session(baseline, session)   # 不传设备：统一使用共享计数。
            if session["malicious"]:
                risk.extend(score for score in scores if score["risk"])
            else:
                normal.extend(scores)
        tp = sum(score["anomalous"] for score in risk)
        fp = sum(score["anomalous"] for score in normal)
        fn, tn = len(risk) - tp, len(normal) - fp
        metrics = {**classification_metrics(tp, fp, fn, tn),
                   "auc": B._auc([score["components"]["full"] for score in risk],
                                 [score["components"]["full"] for score in normal])}
        meta = data.get("meta") or {}
        results.append({"version": baseline.version, "threshold": baseline.threshold,
                        "score_semantics_version": baseline.score_semantics_version,
                        "order": baseline.order,
                        "scoring_config": baseline.scoring_config,
                        "metrics": metrics, "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
                        "training": {"sessions": meta.get("train_sessions"), "steps": meta.get("train_steps")}})
    first = results[0]["confusion"]
    return {"evaluated_at": round(time.time(), 3), "scope": "fixed_fixture_selected_steps_shared_counts",
            "fixture_sha256": sha, "normal_steps": first["fp"] + first["tn"],
            "risk_steps": first["tp"] + first["fn"],
            "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
            "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION, "models": results}
