"""加权分布与分组证据分离。分组集中度是置信度代理，不是独立样本数。"""

import hashlib
import json
import math
from collections import Counter, defaultdict

SCHEMA_VERSION = 1
SCORE_VERSION = 2
MODES = ("backoff", "evidence")
GRANULARITIES = ("event", "session", "group")
MIN_SUPPORT = 5
MIN_STRENGTH = 0.001
MAX_STRENGTH = 100000


def unique_sessions(sessions):
    """仅去重相同来源/会话 ID；冲突记录拒绝，不按行为相似性删除独立轨迹。"""
    unique, seen = [], {}
    for session in sessions:
        key, source = session.get("key"), session.get("source", "")
        if not isinstance(key, str) or not key or not isinstance(source, str):
            raise ValueError("evidence training requires a stable session key and source")
        fingerprint = hashlib.sha256(json.dumps(
            {name: session.get(name) for name in ("steps", "group", "weight")},
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).digest()
        identity = source, key
        if identity in seen:
            if seen[identity] != fingerprint:
                raise ValueError("conflicting duplicate session: " + key)
            continue
        seen[identity] = fingerprint
        unique.append(session)
    return unique, {"input_sessions": len(sessions),
                    "unique_sessions": len(unique), "duplicate_sessions": len(sessions) - len(unique)}


class _Support:
    def __init__(self):
        self.raw = 0
        self.mass = self.event_w2 = 0.0
        self.sessions, self.groups = defaultdict(float), defaultdict(float)

    def add(self, key, group, count, weight):
        self.raw += count
        mass = count * weight
        self.mass += mass
        self.event_w2 += count * weight * weight
        self.sessions[key] += mass
        self.groups[group] += mass

    def export(self):
        return {"raw_count": self.raw, "sum_w": self.mass, "event_w2": self.event_w2,
                "session_w2": sum(v * v for v in self.sessions.values()),
                "group_w2": sum(v * v for v in self.groups.values()),
                "session_support": len(self.sessions), "group_support": len(self.groups)}


def effective_n(stats, granularity):
    mass, square = stats.get("sum_w", 0.0), stats.get(granularity + "_w2", 0.0)
    return (mass / math.sqrt(square)) ** 2 if mass > 0 and square > 0 else 0.0


def fold_counts(unigram, transitions, parent):
    uni, rows = {}, {}
    for symbol, n in unigram.items():
        key = parent(symbol)
        uni[key] = uni.get(key, 0.0) + n
    for prev, row in transitions.items():
        target = rows.setdefault(parent(prev), {})
        for symbol, n in row.items():
            key = parent(symbol)
            target[key] = target.get(key, 0.0) + n
    return uni, rows


def fit(sessions, parent, start, *, mode, granularity, backoff_k, prior_strength):
    if mode not in MODES or granularity not in GRANULARITIES:
        raise ValueError("unsupported evidence scoring configuration")
    for value in (backoff_k, prior_strength):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not MIN_STRENGTH <= value <= MAX_STRENGTH:
            raise ValueError("evidence strengths must be within 0.001 ~ 100000")
    sessions = list(sessions)
    sessions, dedup = unique_sessions(sessions)
    unigram, transitions = {}, {}
    supports = {level: {"global": _Support(), "symbols": defaultdict(_Support), "rows": defaultdict(_Support)}
                for level in ("fine", "coarse")}
    grouping = Counter()
    for session in sessions:
        value = session.get("weight", 1.0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < float("inf"):
            raise ValueError("session weight must be finite and positive")
        weight = float(value)
        key = session.get("source", ""), session["key"]
        group_value = session.get("group") or session["key"]
        if not isinstance(group_value, str):
            raise ValueError("evidence group must be a string")
        group = session.get("source", ""), group_value
        grouping["explicit_group" if session.get("group") else "session_fallback"] += 1
        symbols, rows = Counter(), Counter()
        prev = start
        for step in session["steps"]:
            if step.get("cut"):
                prev = None
                continue
            if step.get("cut_before"):
                prev = None
            for symbol in step["symbols"]:
                symbols[symbol] += 1
                unigram[symbol] = unigram.get(symbol, 0.0) + weight
                if prev is not None:
                    rows[prev] += 1
                    row = transitions.setdefault(prev, {})
                    row[symbol] = row.get(symbol, 0.0) + weight
                prev = symbol
            if step.get("cut_after"):
                prev = None
        for level, mapper in (("fine", lambda value: value), ("coarse", parent)):
            support = supports[level]
            if symbols:
                support["global"].add(key, group, sum(symbols.values()), weight)
            # 同一组的子类贡献先合并，再计算二阶矩，不能相加子类 ESS。
            for name, counts in (("symbols", symbols), ("rows", rows)):
                folded = Counter()
                for symbol, count in counts.items():
                    folded[mapper(symbol)] += count
                for symbol, count in folded.items():
                    support[name][symbol].add(key, group, count, weight)
    evidence = {"dedup": dedup, "grouping": dict(grouping)}
    for level, support in supports.items():
        evidence[level] = {"global": support["global"].export(), **{
            name: {symbol: stats.export() for symbol, stats in sorted(support[name].items())}
            for name in ("symbols", "rows")}}
    result = {"unigram": dict(sorted(unigram.items())),
              "transitions": {prev: dict(sorted(row.items())) for prev, row in sorted(transitions.items())},
              "score_semantics_version": SCORE_VERSION, "evidence_schema_version": SCHEMA_VERSION,
              "evidence": evidence, "backoff_k": backoff_k,
              "scoring_config": {"mode": mode, "granularity": granularity, "prior_strength": prior_strength,
                                 "min_support": MIN_SUPPORT}}
    validate(result["unigram"], result["transitions"], evidence, parent, result["scoring_config"], backoff_k)
    return result


def validate(unigram, transitions, evidence, parent, config, backoff_k):
    if config.get("mode") not in MODES or config.get("granularity") not in GRANULARITIES:
        raise ValueError("unsupported evidence configuration")
    for value in (backoff_k, config.get("prior_strength")):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not MIN_STRENGTH <= value <= MAX_STRENGTH:
            raise ValueError("invalid evidence strength")
    minimum = config.get("min_support")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= MAX_STRENGTH:
        raise ValueError("invalid minimum support")

    def check(stats, expected):
        raw, session_count, group_count = (stats[name] for name in ("raw_count", "session_support", "group_support"))
        if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in (raw, session_count, group_count)):
            raise ValueError("invalid evidence support count")
        if not 0 <= group_count <= session_count <= raw:
            raise ValueError("inconsistent evidence support")
        for name in ("sum_w", "event_w2", "session_w2", "group_w2"):
            n = stats[name]
            if isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) or n < 0:
                raise ValueError("invalid evidence moment")
            if (raw > 0) != (n > 0):
                raise ValueError("empty or underflowed evidence moment")
        if not math.isclose(stats["sum_w"], expected, rel_tol=1e-9, abs_tol=0.0):
            raise ValueError("evidence mass does not match weighted counts")
        for granularity, count in (("event", raw), ("session", session_count), ("group", group_count)):
            n = effective_n(stats, granularity)
            if raw and not 1 - 1e-8 <= n <= count + 1e-7:
                raise ValueError("invalid effective evidence size")

    for n in list(unigram.values()) + [n for row in transitions.values() for n in row.values()]:
        if isinstance(n, bool) or not isinstance(n, (int, float)) or not 0 < n < float("inf"):
            raise ValueError("invalid weighted counts")
    coarse_uni, coarse_rows = fold_counts(unigram, transitions, parent)
    for level, uni, rows in (("fine", unigram, transitions), ("coarse", coarse_uni, coarse_rows)):
        data = evidence[level]
        if set(data["symbols"]) != set(uni) or set(data["rows"]) != set(rows):
            raise ValueError("evidence keys do not match weighted counts")
        check(data["global"], sum(uni.values()))
        for symbol, n in uni.items():
            check(data["symbols"][symbol], n)
        for prev, row in rows.items():
            check(data["rows"][prev], sum(row.values()))
    if evidence["fine"]["global"] != evidence["coarse"]["global"]:
        raise ValueError("inconsistent global evidence")


class Table:
    def __init__(self, unigram, transitions, evidence, parent, config, alpha, backoff_k, *, coarse=True):
        self.unigram, self.transitions = unigram, transitions
        self.alpha, self.backoff_k, self.config = alpha, backoff_k, config
        self.parent = parent
        self.total, self.size = sum(unigram.values()), len(unigram) + 1
        self.row_totals = {prev: sum(row.values()) for prev, row in transitions.items()}
        self.evidence = evidence["fine"] if coarse else evidence
        support = self.unigram if config["mode"] == "backoff" else {
            symbol: self._support(symbol) for symbol in unigram}
        self.sparse_parents = {parent(symbol) for symbol, n in support.items()
                               if parent(symbol) != symbol and n < config["min_support"]}
        self._diagnostics = {}
        for prev, stats in self.evidence["rows"].items():
            n = effective_n(stats, config["granularity"])
            self._diagnostics[prev] = {"effective_n": n, "lambda": n / (n + backoff_k),
                                       **{key: stats[key] for key in ("raw_count", "session_support", "group_support")},
                                       "weighted_mass": stats["sum_w"], "granularity": config["granularity"]}
        n, prior = effective_n(self.evidence["global"], config["granularity"]), config["prior_strength"]
        self._unknown = prior / self.size / (n + prior)
        self._marginals = {symbol: (n * count / self.total + prior / self.size) / (n + prior)
                           for symbol, count in unigram.items()}
        self.coarse = None
        if coarse:
            uni, rows = fold_counts(unigram, transitions, parent)
            self.coarse = Table(uni, rows, evidence["coarse"], parent, config, alpha, backoff_k, coarse=False)

    def _support(self, symbol):
        return self.evidence["symbols"].get(symbol, {}).get("group_support", 0)

    def fallback(self, symbol):
        parent = self.parent(symbol)
        n = self.unigram.get(symbol, 0) if self.config["mode"] == "backoff" else self._support(symbol)
        return parent != symbol and (n < self.config["min_support"] or parent in self.sparse_parents)

    def marginal(self, symbol):
        # 每层查询始终预测本层事件；层级选择由 Baseline.step_score 统一完成。
        if self.config["mode"] == "backoff":
            return (self.unigram.get(symbol, 0.0) + self.alpha) / (self.total + self.alpha * self.size)
        return self._marginals.get(symbol, self._unknown)

    def diagnostics(self, prev):
        return self._diagnostics.get(prev, {"effective_n": 0.0, "lambda": 0.0, "weighted_mass": 0.0,
                                            "raw_count": 0, "session_support": 0, "group_support": 0,
                                            "granularity": self.config["granularity"]})

    def conditional(self, prev, symbol):
        n, marginal = self.row_totals.get(prev, 0.0), self.marginal(symbol)
        if n <= 0:
            return marginal
        effective = self.diagnostics(prev)["effective_n"]
        # 直接保留 K 项，避免证据较多时 1 - lambda 的浮点消减使未见转移变成零。
        return (effective * (self.transitions[prev].get(symbol, 0.0) / n) + self.backoff_k * marginal) / (effective + self.backoff_k)
