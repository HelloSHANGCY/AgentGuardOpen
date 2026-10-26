"""行为基线的数据与训练服务（创新检测实施方案 §5）。

- BehaviorRecorder：记录真实会话每一步的行为符号、意图与决策（不含参数原文），供训练使用；
  评测设备的回放不记录，避免评测夹具混入训练数据；
- train()：从内置语料与选定的真实会话训练模型，按会话时间衰减加权，可按设备生成个性化计数；
  阈值用 k 折交叉打分标定；真实会话按会话哈希留出一部分只做评估，另用评测夹具评估区分能力；
- BehaviorService：模型登记、启用（热切换引擎使用的模型）、删除与回滚。

训练只产出候选模型，必须在控制台确认后才启用：不做无人值守的在线学习，
避免攻击者反复执行同一行为把它“训练”成正常。
"""

import hashlib
import json
import math
import os
import re
import threading
import time
from collections import deque

from . import anomaly as A
from . import behavior_evidence as E
from . import behavior_markov as M
from .behavior_datasets import ID_RE, SOURCE_WEIGHTS, DatasetStore

RECORD_FILE = "sessions.jsonl"
MAX_RECORD_BYTES = 64 * 1024 * 1024
MEMORY_RECORDS = 20000
BUILTIN = "builtin"
LEGACY_BUILTIN = "builtin-legacy"
VERSION_RE = re.compile(r"^(builtin(?:-legacy)?|m\d{8}-\d{6}-[0-9a-f]{4})$")
FOLDS = 5
MARGIN = 0.5
FLAGGED_MODES = ("session", "step", "none")
HOLDOUT_MIN = 10           # 真实会话不少于这个数时才留出评估

DEFAULT_PARAMS = {
    "use_corpus": True,          # 内置语料（模拟日常开发会话）
    "use_recorded": True,        # 服务端记录的真实会话
    "dataset_id": "",           # 管理员登记的离线符号包；空 = 不使用
    "dataset_limit": 0,         # 固定训练分区的前 N 个会话；0 = 全部
    "dataset_balance": "balanced",  # balanced = 来源/会话平衡；raw = 原始计数
    "scoring_mode": M.MODE,         # 默认三阶递归插值；旧的一阶模式仍可显式选择
    "markov_order": M.DEFAULT_ORDER,
    "evidence_granularity": "group",  # event / session / group
    "evidence_k": 20,               # 证据回退强度；与旧计数的 BACKOFF_K 不同单位
    "evidence_prior": 5.0,          # 全局先验的总证据强度
    "devices": [],               # 只用这些设备的会话；空 = 全部
    "since_days": 30,            # 只用最近 N 天的会话
    "half_life_days": 14,        # 时间衰减半衰期；0 = 不衰减
    "exclude_flagged": "session",  # 出现过拦截 / 确认时：session 排除整个会话；step 只剔除这些步骤；none 不排除
    "personalize": False,        # 高阶模型共享计数；旧的一阶可显式按设备个性化
    "min_device_sessions": 5,    # 个性化所需的最少会话数
    "quantile": 99,              # 三阶默认训练侧约 1% 触发预算（分组折外分数）
    "threshold": 0,              # 固定阈值；0 = 按分位自动标定
    "holdout": 0.2,              # 真实会话留出比例（只评估，不参与训练）
}


# ---------- 记录 ----------

class BehaviorRecorder:
    def __init__(self, directory: str = "") -> None:
        self._lock = threading.Lock()
        self._path = os.path.join(directory, RECORD_FILE) if directory else ""
        self._memory: deque = deque(maxlen=MEMORY_RECORDS)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def full(self) -> bool:
        return bool(self._path) and os.path.exists(self._path) and os.path.getsize(self._path) >= MAX_RECORD_BYTES

    def record(self, *, device: str, agent: str, trace: str, intents: list, symbols: list, decision: str,
               call_id: str = "", execution: str = "succeeded", sequence: int = 0,
               cut_before: bool = False, cut_after: bool = False, model_version: str = "") -> None:
        if not symbols:
            return
        item = {"t": round(time.time(), 3), "device": device, "agent": agent, "trace": trace,
                "intents": list(intents), "symbols": list(symbols), "decision": decision,
                "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
                "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION,
                "call_id": call_id, "execution": execution, "sequence": sequence,
                "cut_before": cut_before, "cut_after": cut_after, "model_version": model_version}
        with self._lock:
            if not self._path:
                self._memory.append(item)
                return
            if self.full():
                return
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    def records(self) -> list[dict]:
        with self._lock:
            if not self._path:
                return list(self._memory)
            if not os.path.exists(self._path):
                return []
            with open(self._path, encoding="utf-8") as handle:
                lines = handle.readlines()
        items = []
        for line in lines:
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
        return items

    def clear(self, device: str = "") -> int:
        """清空记录；指定设备时只清该设备。"""
        items = self.records()
        kept = [item for item in items if device and item.get("device") != device]
        with self._lock:
            if not self._path:
                self._memory = deque(kept, maxlen=MEMORY_RECORDS)
            else:
                tmp = self._path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as handle:
                    handle.writelines(json.dumps(item, ensure_ascii=False) + "\n" for item in kept)
                os.replace(tmp, self._path)
        return len(items) - len(kept)

    def stats(self) -> dict:
        records = self.records()
        sessions = sessions_from_records(records)
        devices: dict = {}
        for session in sessions:
            row = devices.setdefault(session["device"], {
                "device": session["device"], "agents": set(), "sessions": 0, "steps": 0, "flagged": 0,
                "first": session["first"], "last": session["last"],
                "compatible_sessions": 0, "compatible_steps": 0, "incompatible_records": 0})
            row["agents"].add(session["agent"])
            row["sessions"] += 1
            row["steps"] += len(session["steps"])
            row["flagged"] += session["flagged"]
            row["first"] = min(row["first"], session["first"])
            row["last"] = max(row["last"], session["last"])
        for session in sessions_from_records(records, training=True):
            steps = sum(bool(step.get("symbols")) for step in session["steps"])
            row = devices[session["device"]]
            row["compatible_sessions"] += bool(steps)
            row["compatible_steps"] += steps
        for item in records:
            if not compatible_record(item):
                devices[str(item.get("device") or "")]["incompatible_records"] += 1
        rows = [{**row, "agents": sorted(row["agents"])} for row in devices.values()]
        size = os.path.getsize(self._path) if self._path and os.path.exists(self._path) else 0
        return {"devices": sorted(rows, key=lambda row: -row["last"]), "sessions": len(sessions),
                "steps": sum(len(session["steps"]) for session in sessions), "bytes": size,
                "compatible_sessions": sum(row["compatible_sessions"] for row in rows),
                "compatible_steps": sum(row["compatible_steps"] for row in rows),
                "incompatible_records": sum(row["incompatible_records"] for row in rows),
                "persistent": bool(self._path), "full": self.full()}


def compatible_record(item: dict) -> bool:
    return (item.get("feature_schema_version") == A.FEATURE_SCHEMA_VERSION and
            item.get("sequence_semantics_version") == A.SEQUENCE_SEMANTICS_VERSION)


def sessions_from_records(records: list[dict], *, training: bool = False) -> list[dict]:
    """Reconstruct lifecycle events; legacy records are visible, never silently retrained."""
    latest = {}
    for index, item in enumerate(records):
        key = (item.get("device", ""), item.get("trace", ""), item.get("call_id") or f"row-{index}")
        latest[key] = item
    by_trace: dict = {}
    for item in latest.values():
        if training and not compatible_record(item):
            continue
        trace = str(item.get("trace") or "")
        device = str(item.get("device") or "")
        key = (device, trace)
        session = by_trace.setdefault(key, {
            "key": device + ":" + trace, "source": "recorded", "device": device,
            "agent": str(item.get("agent") or ""), "first": item.get("t", 0), "last": item.get("t", 0),
            "flagged": False, "steps": []})
        flagged = item.get("decision") in ("DENY", "ASK")
        status = item.get("execution", "legacy")
        step = {"intents": list(item.get("intents") or []), "symbols": A.dedupe(item.get("symbols")),
                "flagged": flagged, "cut_before": item.get("cut_before", False),
                "cut_after": item.get("cut_after", False), "execution": status}
        if training and status not in {"succeeded", "failed"}:
            step = {"cut": True, "flagged": flagged}
        session["steps"].append(step)
        session["last"] = max(session["last"], item.get("t", 0))
        session["first"] = min(session["first"], item.get("t", 0))
        session["flagged"] = session["flagged"] or flagged
    return list(by_trace.values())


def corpus_sessions() -> list[dict]:
    from ..agents.claude_code import classify_builtin
    from .behavior_corpus import SESSIONS

    sessions = []
    for index, (prompt, cwd, steps) in enumerate(SESSIONS):
        intents = A.infer_intent(prompt)
        sessions.append({
            "key": f"corpus-{index}", "source": "corpus", "device": "", "agent": "", "flagged": False,
            "steps": [{"intents": intents, "symbols": A.symbols(classify_builtin(tool, args, cwd), cwd)}
                      for tool, args in steps]})
    return sessions


def fixture_sessions() -> list[dict]:
    """评测夹具（只用于评估）：恶意夹具截到首个高风险点，标出该步。"""
    from ..agents.cc_fixtures import CWD, fixtures
    from ..agents.claude_code import classify_builtin

    sessions = []
    for fixture in fixtures():
        current = {"malicious": fixture["malicious"], "steps": []}
        intents: list = []
        for step in fixture["steps"]:
            if "prompt" in step:
                intents = A.infer_intent(step["prompt"]) or intents
            elif "session" in step:
                sessions.append(current)
                current, intents = {"malicious": fixture["malicious"], "steps": []}, []
            elif "pre" in step:
                seq = A.symbols(classify_builtin(step["pre"], step["input"], CWD), CWD)
                current["steps"].append({"intents": intents, "symbols": seq, "risk": bool(step.get("risk"))})
                if step.get("risk"):
                    break
        sessions.append(current)
    return sessions


# ---------- 训练与评估 ----------

def _fraction(key: str) -> float:
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0x100000000


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))] if ordered else 0.0


def _auc(positive: list[float], negative: list[float]) -> float | None:
    if not positive or not negative:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in positive for n in negative)
    return round(wins / (len(positive) * len(negative)), 3)


def score_session(baseline: A.Baseline, session: dict, device: str = "") -> list[dict]:
    history, results = (A.START,), []
    for step in session["steps"]:
        if step.get("cut"):
            history = ()
            continue
        if not step["symbols"]:
            if baseline.score_semantics_version in (E.SCORE_VERSION, M.SCORE_VERSION) and (step.get("cut_before") or step.get("cut_after")):
                history = ()
            continue
        if step.get("cut_before"):
            history = ()
        prev = history[-1] if history else None
        result = A.score_symbols(baseline, prev, step["symbols"], step["intents"], device, history=history)
        results.append({**result, "risk": step.get("risk", False)})
        history = () if step.get("cut_after") else (history + tuple(step["symbols"]))[-M.MAX_ORDER:]
    return results


def _baseline(counts: dict, threshold: float, version: str = "cv", devices: dict | None = None) -> A.Baseline:
    return A.Baseline.from_dict({**counts, "devices": devices or {}, "threshold": threshold, "version": version,
                                 "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
                                 "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION})


def select_sessions(params: dict, records: list[dict], now: float) -> dict:
    corpus = corpus_sessions() if params["use_corpus"] else []
    recorded = []
    skipped = {"old": 0, "flagged": 0, "device": 0, "flagged_steps": 0,
               "incompatible_records": sum(not compatible_record(item) for item in records)}
    report: dict = {}       # 每台设备的会话去向，供控制台解释“为什么只用了 N 个会话”
    if params["use_recorded"]:
        # 历史会话也进入去向报告，避免页面显示有数据、训练时却无声消失。
        for session in sessions_from_records(records):
            row = report.setdefault(session["device"], {
                "device": session["device"], "sessions": 0,
                "selected": not params["devices"] or session["device"] in params["devices"],
                "compatible_sessions": 0, "incompatible_records": 0,
                "old": 0, "flagged": 0, "flagged_steps": 0,
                "train": 0, "holdout": 0, "personalized": False})
            row["sessions"] += 1
        for item in records:
            if not compatible_record(item):
                report[str(item.get("device") or "")]["incompatible_records"] += 1
        for session in sessions_from_records(records, training=True):
            row = report[session["device"]]
            row["compatible_sessions"] += any(step.get("symbols") for step in session["steps"])
            if params["devices"] and session["device"] not in params["devices"]:
                row["selected"] = False
                skipped["device"] += 1
                continue
            if params["since_days"] and now - session["last"] > params["since_days"] * 86400:
                row["old"] += 1
                skipped["old"] += 1
                continue
            if session["flagged"] and params["exclude_flagged"] == "session":
                row["flagged"] += 1
                skipped["flagged"] += 1
                continue
            if session["flagged"] and params["exclude_flagged"] == "step":
                # 只剔除被拦截 / 确认的步骤，并切断它前后的转移；其余步骤照常学习。
                dropped = sum(step["flagged"] for step in session["steps"])
                session["steps"] = [{"cut": True} if step["flagged"] else step for step in session["steps"]]
                row["flagged_steps"] += dropped
                skipped["flagged_steps"] += dropped
                if not any(step.get("symbols") for step in session["steps"]):
                    row["flagged"] += 1
                    skipped["flagged"] += 1
                    continue
            if not any(step.get("symbols") for step in session["steps"]):
                continue
            half_life = params["half_life_days"]
            age_days = max(0.0, (now - session["last"]) / 86400)
            session["weight"] = 0.5 ** (age_days / half_life) if half_life else 1.0
            recorded.append(session)
    # 真实会话足够多时按会话哈希留出一部分，只做评估。
    holdout = [item for item in recorded if len(recorded) >= HOLDOUT_MIN and _fraction(item["key"]) < params["holdout"]]
    held = {item["key"] for item in holdout}
    for item in recorded:
        report[item["device"]]["holdout" if item["key"] in held else "train"] += 1
    train = corpus + [item for item in recorded if item["key"] not in held]
    return {"train": train, "holdout": holdout, "corpus": len(corpus), "recorded": len(recorded) - len(holdout),
            "skipped": skipped, "devices": sorted(report.values(), key=lambda row: row["device"])}


def balance_sessions(train: list[dict], fractions: dict) -> tuple[list[dict], dict]:
    """指定来源比例，每个来源内会话等权；保留原始会话与步数，权重只用于拟合。"""
    if not fractions or any(isinstance(value, bool) or not isinstance(value, (int, float)) or
                            not 0 < value < float("inf") for value in fractions.values()):
        raise ValueError("source fractions must be finite positive numbers")
    grouped: dict = {}
    for item in train:
        steps = sum(bool(step.get("symbols")) for step in item["steps"])
        if steps:
            if item["source"] not in fractions:
                raise ValueError("missing fraction for training source: " + item["source"])
            grouped.setdefault(item["source"], []).append((item, steps))
    total = sum(steps for items in grouped.values() for _, steps in items)
    share_total = sum(fractions[source] for source in grouped)
    weighted, report = [], {}
    for source, items in grouped.items():
        fraction = fractions[source] / share_total
        mass = total * fraction
        report[source] = {"fraction": fraction, "sessions": len(items),
                          "raw_steps": sum(steps for _, steps in items), "weighted_steps": round(mass, 4)}
        weighted.extend({**item, "weight": mass / len(items) / steps} for item, steps in items)
    return weighted, report


def weighted_percentile(values: list[float], weights: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    pairs = sorted(zip(values, weights))
    target = sum(weights) * quantile / 100
    cumulative = 0.0
    for value, weight in pairs:
        cumulative += weight
        if cumulative >= target:
            return value
    return pairs[-1][0]


def calibrate(train: list[dict], quantile: float, component: str = "full", *,
              source_weights: dict | None = None, fit_options: dict | None = None,
              details: dict | None = None) -> tuple[float, list[float]]:
    """k 折交叉打分：每折用其余会话训练的模型打分，取分位数加余量作为阈值。"""
    if fit_options:
        train, _ = E.unique_sessions(train)
    folds = min(FOLDS, len(train))
    assignments = [index % folds for index in range(len(train))]
    if fit_options and train:
        groups = sorted({(item.get("source", ""), item.get("group") or item["key"]) for item in train},
                        key=lambda group: (group[1], group[0]))
        folds = min(FOLDS, len(groups))
        by_group = {group: index % folds for index, group in enumerate(groups)}
        assignments = [by_group[(item.get("source", ""), item.get("group") or item["key"])] for item in train]
        if folds < 2 and fit_options.get("scoring_mode") == M.MODE:
            if details is not None:
                details.update(weights=[], score_count=0, status="insufficient_groups", groups=len(groups))
            return M.DEFAULT_THRESHOLD, []
    elif any(item.get("group") for item in train):
        # 外部语料中的同一仓库只能进入同一折；无 group 的内置会话各自成组。
        groups = sorted({item.get("group") or item["key"] for item in train})
        folds = min(FOLDS, len(groups))
        by_group = {group: index % folds for index, group in enumerate(groups)}
        assignments = [by_group[item.get("group") or item["key"]] for item in train]
    scores = []
    score_weights = []
    weights = {item["key"]: item["weight"] for item in balance_sessions(train, source_weights)[0]} \
        if source_weights is not None else {}
    for fold in range(folds):
        rest = [item for item, assigned in zip(train, assignments) if assigned != fold]
        part = [item for item, assigned in zip(train, assignments) if assigned == fold]
        if source_weights is not None:
            rest = balance_sessions(rest, source_weights)[0]
        baseline = _baseline(A.fit(rest, **(fit_options or {})), 99.0)
        for item in part:
            values = [result["components"][component] for result in score_session(baseline, item)]
            scores.extend(values)
            score_weights.extend([weights.get(item["key"], 1.0)] * len(values))
    percentile = weighted_percentile(scores, score_weights, quantile) if source_weights is not None \
        else _percentile(scores, quantile)
    if details is not None:
        details.update(weights=score_weights, score_count=len(scores))
    margin = 0.01 if fit_options and fit_options.get("scoring_mode") == M.MODE else MARGIN
    return round(percentile + margin, 2), scores


def evaluate(baseline: A.Baseline, holdout: list[dict]) -> dict:
    benign, risk = [], []
    for session in fixture_sessions():
        for result in score_session(baseline, session):
            if not session["malicious"]:
                benign.append(result)
            elif result["risk"]:
                risk.append(result)
    # 个性化设备：风险点在该设备的叠加计数下也要评估一次，取最差的设备（防止投毒藏在个性化计数里）。
    risk_by_device = {}
    for device in sorted(baseline.devices):
        scored = [result for session in fixture_sessions() if session["malicious"]
                  for result in score_session(baseline, session, device) if result["risk"]]
        risk_by_device[device] = sum(item["anomalous"] for item in scored)
    held = [result for item in holdout for result in score_session(baseline, item, item["device"])]
    over = lambda items: sum(item["anomalous"] for item in items)
    component = lambda name: _auc([item["components"][name] for item in risk], [item["components"][name] for item in benign])
    return {
        "holdout_sessions": len(holdout), "holdout_steps": len(held), "holdout_over_threshold": over(held),
        "fixture_benign_steps": len(benign), "fixture_benign_over_threshold": over(benign),
        "fixture_risk_steps": len(risk), "fixture_risk_over_threshold": over(risk),
        "fixture_risk_by_device": risk_by_device,
        "auc": component("full"),
        # 分量消融：只看罕见度 / 罕见度 + 前文 / 完整分数（再加意图偏离）。
        "auc_components": {name: component(name) for name in ("rarity", "rarity_intent", "rarity_context", "full")},
    }


def normalize_params(raw: dict | None) -> dict:
    params = dict(DEFAULT_PARAMS)
    if raw is not None and not isinstance(raw, dict):
        raise ValueError("params must be an object")
    if (raw or {}).get("scoring_mode") in ("legacy", *E.MODES):
        # 显式选择旧模式时保留其原有标定和先验默认值。
        params.update(quantile=95, evidence_prior=1.)
    for key, value in (raw or {}).items():
        if key not in DEFAULT_PARAMS:
            raise ValueError(f"unknown parameter: {key}")
        default = DEFAULT_PARAMS[key]
        if key == "exclude_flagged":
            # 兼容旧的布尔取值：true = 排除整个会话，false = 不排除。
            value = {True: "session", False: "none"}.get(value, value) if isinstance(value, bool) else value
            if value not in FLAGGED_MODES:
                raise ValueError("exclude_flagged must be one of " + " / ".join(FLAGGED_MODES))
        elif key == "dataset_id":
            if not isinstance(value, str) or value and not ID_RE.fullmatch(value):
                raise ValueError("invalid dataset id")
        elif key == "dataset_balance":
            if value not in ("balanced", "raw"):
                raise ValueError("dataset_balance must be balanced or raw")
        elif key == "scoring_mode":
            if value not in ("legacy", *E.MODES, M.MODE):
                raise ValueError("unsupported scoring_mode")
        elif key == "markov_order":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= M.MAX_ORDER:
                raise ValueError("markov_order must be an integer within 1 ~ 8")
        elif key == "evidence_granularity":
            if value not in E.GRANULARITIES:
                raise ValueError("unsupported evidence_granularity")
        elif key == "dataset_limit":
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100000:
                raise ValueError("dataset_limit must be an integer within 0 ~ 100000")
        elif isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be boolean")
        elif isinstance(default, list):
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"{key} must be a list of device ids")
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be a number")
        params[key] = value
    for key in ("evidence_k", "evidence_prior"):
        if not math.isfinite(params[key]) or not E.MIN_STRENGTH <= params[key] <= E.MAX_STRENGTH:
            raise ValueError(key + " must be within 0.001 ~ 100000")
    if not 50 <= params["quantile"] <= 99.9:
        raise ValueError("quantile must be within 50 ~ 99.9")
    if not 0 <= params["threshold"] <= 30:
        raise ValueError("threshold must be within 0 ~ 30 (0 = calibrate automatically)")
    if not 0 <= params["holdout"] < 0.9:
        raise ValueError("holdout must be within 0 ~ 0.9")
    if params["since_days"] < 0 or params["half_life_days"] < 0 or params["min_device_sessions"] < 1:
        raise ValueError("since_days / half_life_days must be >= 0, min_device_sessions >= 1")
    if not params["use_corpus"] and not params["use_recorded"] and not params["dataset_id"]:
        raise ValueError("select at least one data source")
    return params


def _rate(meta: dict, part: str, whole: str) -> float | None:
    return meta[part] / meta[whole] if meta.get(whole) else None


def assess(meta: dict, compare: dict | None) -> dict:
    """把评估指标换成“能不能启用”的检查项：候选模型与当前模型在同一份留出数据和夹具上比较。

    level：ok / warn / fail；任一 fail → 不建议启用；留出评估改善且无 warn → 建议启用；其余需人工判断。
    """
    checks = []

    def add(check_id: str, level: str, candidate, active=None) -> None:
        checks.append({"id": check_id, "level": level, "candidate": candidate, "active": active})

    used = meta["recorded_sessions"] + meta["holdout_sessions"] + meta.get("external_sessions", 0)
    add("data", "ok" if used >= 20 else "warn", used)
    external = meta.get("external_source", {})
    if external.get("label_status") == "unverified_real_development":
        add("external_review", "warn", external.get("training_counts", external.get("counts", {})).get("review_flagged_steps", 0))
    if meta.get("scoring"):
        add("evidence_validation", "warn", meta["scoring"]["validation_status"])
    cur = compare or {}
    # 1) 留出的真实会话：最接近上线后“行为观察”的比例。
    if not meta["holdout_steps"]:
        add("holdout", "warn", None)
    else:
        mine, theirs = _rate(meta, "holdout_over_threshold", "holdout_steps"), _rate(cur, "holdout_over_threshold",
                                                                                     "holdout_steps")
        add("holdout", "ok" if theirs is None or mine <= theirs else "warn", mine, theirs)
    # 2) 正常夹具超阈值：不应明显上升，绝对值不超过 3%。
    mine, theirs = _rate(meta, "fixture_benign_over_threshold", "fixture_benign_steps"), \
        _rate(cur, "fixture_benign_over_threshold", "fixture_benign_steps")
    add("benign", "fail" if mine is not None and mine > 0.03 else
        "ok" if theirs is None or mine is None or mine <= theirs + 0.01 else "warn", mine, theirs)
    # 3) 攻击风险点超阈值：明显下降说明训练数据把攻击行为学成了正常（可能被投毒或排除不彻底）。
    worst = lambda m: min([m["fixture_risk_over_threshold"], *(m.get("fixture_risk_by_device") or {}).values()]) \
        if m.get("fixture_risk_steps") else None
    mine = worst(meta) / meta["fixture_risk_steps"] if worst(meta) is not None else None
    theirs = worst(cur) / cur["fixture_risk_steps"] if worst(cur) is not None else None
    drop = (theirs - mine) if mine is not None and theirs is not None else 0
    add("risk", "fail" if drop > 0.1 else "warn" if drop > 0.03 else "ok", mine, theirs)
    # 4) AUC：排序意义上的区分能力，不受阈值影响。
    mine, theirs = meta.get("auc"), cur.get("auc")
    add("auc", "fail" if mine is not None and mine < 0.8 else
        "warn" if mine is not None and theirs is not None and mine < theirs - 0.02 else "ok", mine, theirs)
    levels = {item["level"] for item in checks}
    holdout_ok = next(item for item in checks if item["id"] == "holdout")["level"] == "ok"
    verdict = "reject" if "fail" in levels else "recommend" if holdout_ok and "warn" not in levels else "review"
    return {"verdict": verdict, "checks": checks}


def train(params: dict, records: list[dict], version: str, now: float | None = None,
          compare: A.Baseline | None = None, *, dataset: dict | None = None,
          source_weights: dict | None = None) -> dict:
    """训练并评估，返回完整模型（含 meta 报告）。不修改任何状态。

    compare：当前启用的模型；给出时在同一份留出数据与夹具上评估它，作为对照。
    """
    params = normalize_params(params)
    if params["dataset_id"] and dataset is None:
        raise ValueError("selected external dataset was not loaded")
    if source_weights is not None and params["personalize"]:
        raise ValueError("source balancing currently requires personalize=false")
    if params["scoring_mode"] != "legacy" and params["personalize"]:
        raise ValueError("证据计数暂不支持设备个性化，请关闭后重试")
    now = time.time() if now is None else now
    data = select_sessions(params, records, now)
    if dataset is not None:
        external, held = dataset["train"], dataset["holdout"]
        keys = [item["key"] for item in external + held]
        if len(keys) != len(set(keys)):
            raise ValueError("external dataset contains duplicate sessions")
        train_groups = {item["group"] for item in external}
        if train_groups & {item["group"] for item in held}:
            raise ValueError("external dataset training and holdout groups overlap")
        data["train"].extend(external)
        data["holdout"].extend(held)
    if not data["train"]:
        skipped = data["skipped"]
        raise ValueError(
            "no training sessions: 没有可用训练会话"
            f"（版本不兼容记录 {skipped['incompatible_records']} 条，"
            f"含拦截/确认会话 {skipped['flagged']} 个，过期会话 {skipped['old']} 个，"
            f"未选设备会话 {skipped['device']} 个）。"
            "请检查数据来源与排除设置，或启用内置语料。"
            "旧版记录只保存了行为符号，无法按当前提取器重算；正常使用 Agent 产生的新会话可参与训练。")
    fit_options, dedup = {}, {}
    if params["scoring_mode"] != "legacy":
        data["train"], dedup = E.unique_sessions(data["train"])
        fit_options = {"scoring_mode": params["scoring_mode"], "granularity": params["evidence_granularity"],
                       "backoff_k": params["evidence_k"], "prior_strength": params["evidence_prior"]}
        if params["scoring_mode"] == M.MODE:
            fit_options["order"] = params["markov_order"]
    devices, shared = {}, data["train"]
    if params["personalize"]:
        by_device: dict = {}
        for item in data["train"]:
            if item["source"] == "recorded" and item["device"]:
                by_device.setdefault(item["device"], []).append(item)
        devices = {device: A.fit(items) for device, items in sorted(by_device.items())
                   if len(items) >= params["min_device_sessions"]}
        # 个性化设备的会话只进入它自己的叠加计数，不进入共享计数：
        # 否则一台设备的常用行为会稀释共享分布，让其他设备的正常行为显得罕见。
        shared = [item for item in data["train"] if item["device"] not in devices] or data["train"]
    for row in data["devices"]:
        row["personalized"] = row["device"] in devices
    calibration = {}
    threshold, cv_scores = calibrate(shared, params["quantile"], source_weights=source_weights,
                                     fit_options=fit_options, details=calibration)
    calibrated_threshold = threshold
    if params["threshold"]:
        threshold = round(float(params["threshold"]), 2)   # 固定阈值：只比较计数变化带来的影响
    weighted, balance = balance_sessions(shared, source_weights) if source_weights is not None else (shared, {})
    counts = A.fit(weighted, **fit_options)
    baseline = _baseline(counts, threshold, version, devices)
    report = {
        "train_sessions": len(data["train"]), "shared_sessions": len(shared), "corpus_sessions": data["corpus"],
        "recorded_sessions": data["recorded"], "skipped": data["skipped"],
        "train_steps": sum(bool(step.get("symbols")) for item in data["train"] for step in item["steps"]),
        "vocabulary": len(counts["unigram"]), "personalized_devices": sorted(devices),
        "device_report": data["devices"], "holdout_min": HOLDOUT_MIN,
        "threshold": threshold,
        "calibrated_threshold": calibrated_threshold,
        "calibration_status": calibration.get("status", "group_cv"),
        "threshold_source": "fixed" if params["threshold"] else
                            "insufficient_groups_fallback" if calibration.get("status") == "insufficient_groups" else
                            "group_cv_trigger_budget" if params["scoring_mode"] == M.MODE else "group_cv_quantile",
        "calibration_margin": 0.01 if params["scoring_mode"] == M.MODE else MARGIN,
        "cv_over_threshold": round(sum(score >= threshold for score in cv_scores) / len(cv_scores), 4)
        if cv_scores else None,
        **evaluate(baseline, data["holdout"]),
    }
    if dataset is not None:
        report.update(external_sessions=len(dataset["train"]),
                      external_steps=sum(bool(step.get("symbols")) for item in dataset["train"] for step in item["steps"]),
                      external_source=dataset["meta"])
    if params["scoring_mode"] == M.MODE:
        global_evidence = next(row["evidence"] for row in counts["sequence_model"]["contexts"] if not row["history"])
        report["scoring"] = {"score_semantics_version": M.SCORE_VERSION,
                             "evidence_schema_version": M.SCHEMA_VERSION, **counts["scoring_config"],
                             "backoff_k": baseline.backoff_k, "global": global_evidence,
                             "effective_n": E.effective_n(global_evidence, params["evidence_granularity"]),
                             "contexts": len(counts["sequence_model"]["contexts"]), "dedup": dedup,
                             "validation_status": "historical_diagnostic_only"}
    elif fit_options:
        report["scoring"] = {"score_semantics_version": E.SCORE_VERSION,
                             "evidence_schema_version": E.SCHEMA_VERSION, **counts["scoring_config"],
                             "backoff_k": baseline.backoff_k, "dedup": dedup,
                             "global": counts["evidence"]["fine"]["global"],
                             "effective_n": E.effective_n(counts["evidence"]["fine"]["global"],
                                                          params["evidence_granularity"]),
                             "validation_status": "experimental_diagnostic_only"}
    if source_weights is not None:
        report["source_balance"] = {"sources": balance, "within_source": "equal_session",
                                    "calibration": "weighted_quantile", "cv_over_threshold": "raw_step_rate"}
    if compare is not None:
        report["compare"] = {"version": compare.version, "threshold": compare.threshold,
                             **evaluate(compare, data["holdout"])}
    report["assessment"] = assess(report, report.get("compare"))
    return {"format": 5 if params["scoring_mode"] == M.MODE else 4 if fit_options else 3,
            "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
            "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION, "version": version, "created_at": round(now, 3), "alpha": A.ALPHA,
            "backoff_k": A.BACKOFF_K, "device_weight": A.DEVICE_WEIGHT, "threshold": threshold,
            "params": params, "meta": report, **counts, "devices": devices}


# ---------- 模型登记与启用 ----------

class BehaviorService:
    def __init__(self, directory: str = "") -> None:
        self._lock = threading.Lock()
        self.directory = directory
        self.recorder = BehaviorRecorder(directory)
        self.datasets = DatasetStore(directory)
        self._models_dir = os.path.join(directory, "models") if directory else ""
        self._memory_models: dict = {}
        if self._models_dir:
            os.makedirs(self._models_dir, exist_ok=True)
        self.load_warning = ""
        self.active_version = self._read_active()
        self.baseline = self._load(self.active_version)

    # 持久化
    def _active_path(self) -> str:
        return os.path.join(self.directory, "active.json") if self.directory else ""

    def _read_active(self) -> str:
        path = self._active_path()
        try:
            with open(path, encoding="utf-8") as handle:
                return str(json.load(handle).get("version") or BUILTIN)
        except (OSError, ValueError, AttributeError):
            return BUILTIN

    def _model_path(self, version: str) -> str:
        return os.path.join(self._models_dir, version + ".json")

    def get(self, version: str) -> dict | None:
        if not VERSION_RE.match(version or ""):
            return None
        if version in (BUILTIN, LEGACY_BUILTIN):
            try:
                path = A.BASELINE_PATH if version == BUILTIN else os.path.join(os.path.dirname(A.BASELINE_PATH), "transitions.legacy.json")
                with open(path, encoding="utf-8") as handle:
                    return {**json.load(handle), "version": version}
            except (OSError, ValueError):
                return None
        if not self._models_dir:
            return self._memory_models.get(version)
        try:
            with open(self._model_path(version), encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return None

    def _load(self, version: str) -> A.Baseline:
        for candidate in (version, BUILTIN):
            data = self.get(candidate)
            if data:
                baseline = A.Baseline.from_dict(data)
                if baseline.compatible:
                    if candidate != version:
                        self.load_warning = "incompatible_or_missing_active_model"
                    self.active_version = candidate
                    return baseline
        return A.Baseline(disabled_reason="no_compatible_baseline")

    def _versions(self) -> list[str]:
        if not self._models_dir:
            return list(self._memory_models)
        return [name[:-5] for name in os.listdir(self._models_dir) if name.endswith(".json")]

    def models(self) -> list[dict]:
        items = []
        for version in dict.fromkeys([BUILTIN, LEGACY_BUILTIN] + self._versions()):
            data = self.get(version)
            if not data:
                continue
            baseline = A.Baseline.from_dict(data)
            items.append({"version": version, "created_at": data.get("created_at"), "builtin": version in (BUILTIN, LEGACY_BUILTIN),
                          "active": version == self.active_version, "threshold": data.get("threshold"),
                          "compatible": baseline.compatible,
                          "feature_schema_version": baseline.feature_schema_version,
                          "sequence_semantics_version": baseline.sequence_semantics_version,
                          "score_semantics_version": baseline.score_semantics_version,
                          "evidence_schema_version": baseline.evidence_schema_version,
                          "order": baseline.order,
                          "incompatibility_reason": incompatibility_reason(baseline),
                          "params": data.get("params") or {}, "meta": data.get("meta") or {}})
        return sorted(items, key=lambda item: (not item["builtin"], -(item["created_at"] or 0)))

    # 操作
    def train(self, params: dict | None) -> dict:
        params = normalize_params(params)
        dataset, source_weights = None, None
        if params["dataset_id"]:
            if params["dataset_balance"] == "balanced":
                if params["use_recorded"] or params["personalize"]:
                    raise ValueError("SWE-chat 来源平衡需关闭真实会话和设备个性化；混合训练请选择原始计数")
                source_weights = SOURCE_WEIGHTS
            dataset = self.datasets.load(params["dataset_id"], params["dataset_limit"])
        version = time.strftime("m%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
        model = train(params, self.recorder.records(), version, compare=self.baseline,
                      dataset=dataset, source_weights=source_weights)
        with self._lock:
            if self._models_dir:
                with open(self._model_path(version), "w", encoding="utf-8") as handle:
                    json.dump(model, handle, ensure_ascii=False)
            else:
                self._memory_models[version] = model
        return model

    def activate(self, version: str) -> dict:
        data = self.get(version)
        if not data:
            raise KeyError(version)
        baseline = A.Baseline.from_dict({**data, "version": version})
        if not baseline.compatible:
            raise ValueError(incompatibility_reason(baseline))
        with self._lock:
            if self._active_path():
                with open(self._active_path(), "w", encoding="utf-8") as handle:
                    json.dump({"version": version, "at": round(time.time(), 3)}, handle)
            self.active_version = version
            self.load_warning = ""
            # 引用替换是原子的：判定线程要么用旧模型、要么用新模型。
            self.baseline = baseline
        return {"version": version, "threshold": baseline.threshold}

    def delete(self, version: str) -> None:
        if version in (BUILTIN, LEGACY_BUILTIN) or version == self.active_version:
            raise ValueError("cannot delete the built-in or the active model")
        if not VERSION_RE.match(version or ""):
            raise KeyError(version)
        with self._lock:
            if self._models_dir:
                if not os.path.exists(self._model_path(version)):
                    raise KeyError(version)
                os.remove(self._model_path(version))
            elif self._memory_models.pop(version, None) is None:
                raise KeyError(version)


def incompatibility_reason(baseline: A.Baseline) -> str:
    if baseline.compatible:
        return ""
    if baseline.disabled_reason in {"invalid_evidence_model", "invalid_sequence_model", "unsupported_score_semantics"}:
        return ("incompatible baseline: 模型评分版本或证据统计不受支持/不完整"
                f"（评分 {baseline.score_semantics_version}，证据 {baseline.evidence_schema_version}）。"
                "请从原始会话重新训练；旧计数无法恢复分组证据。")
    return ("incompatible baseline: 模型的行为特征或执行序列版本不兼容"
            f"（模型 {baseline.feature_schema_version}/{baseline.sequence_semantics_version}，"
            f"当前 {A.FEATURE_SCHEMA_VERSION}/{A.SEQUENCE_SEMANTICS_VERSION}；0 表示旧版未标记）。"
            "请在当前版本重新训练，再启用新模型；旧模型及历史记录会保留。")

