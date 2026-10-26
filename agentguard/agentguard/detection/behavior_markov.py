"""有限阶递归插值马尔可夫：概率分布与真实分组证据分离。"""

import math
from collections import Counter, defaultdict

from . import behavior_evidence as E

SCORE_VERSION = 3
SCHEMA_VERSION = 1
DEFAULT_ORDER = 3
DEFAULT_THRESHOLD = 11.33
MAX_ORDER = 8
UNKNOWN = "<unknown>"
MODE = "interpolated"


def context(previous, order=MAX_ORDER):
    if previous is None:
        return ()
    if isinstance(previous, str):
        return (previous,)
    return tuple(previous)[-order:]


def fit(sessions, start, *, order=DEFAULT_ORDER, granularity="group", backoff_k=20., prior_strength=5.):
    if isinstance(order, bool) or not isinstance(order, int) or not 1 <= order <= MAX_ORDER:
        raise ValueError("markov order must be an integer within 1 ~ 8")
    if granularity not in E.GRANULARITIES:
        raise ValueError("unsupported evidence granularity")
    sessions, dedup = E.unique_sessions(sessions)
    grouped = defaultdict(list)
    for session in sessions:
        grouped[session.get("source", ""), session.get("group") or session["key"]].append(session)
    rows, supports = defaultdict(Counter), defaultdict(E._Support)
    for group, items in grouped.items():
        for session in items:
            weight = session.get("weight", 1.)
            if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not 0 < weight < math.inf:
                raise ValueError("session weight must be finite and positive")
            history, local = (start,), Counter()
            for step in session["steps"]:
                if step.get("cut"):
                    history = ()
                    continue
                if step.get("cut_before"):
                    history = ()
                for symbol in step.get("symbols", []):
                    if not isinstance(symbol, str) or not symbol or symbol in (start, UNKNOWN):
                        raise ValueError("invalid behavior symbol")
                    for depth in range(len(history) + 1):
                        local[history[-depth:] if depth else (), symbol] += 1
                    history = (history + (symbol,))[-order:]
                if step.get("cut_after"):
                    history = ()
            local_totals = Counter()
            for (history, symbol), n in local.items():
                rows[history][symbol] += weight * n
                local_totals[history] += n
            key = session.get("source", ""), session["key"]
            for history, n in local_totals.items():
                supports[history].add(key, group, n, weight)
    # 空训练数据由调用方拒绝；这里也避免创建看似可用的空模型。
    if not rows.get(()):
        raise ValueError("no behavior symbols to fit")
    sequence = {"schema_version": SCHEMA_VERSION, "order": order, "contexts": [
        {"history": list(history), "counts": dict(sorted(row.items())), "evidence": supports[history].export()}
        for history, row in sorted(rows.items())]}
    result = {"unigram": dict(sorted(rows[()].items())),
              "transitions": {history[0]: dict(sorted(row.items())) for history, row in sorted(rows.items())
                              if len(history) == 1},
              "sequence_model": sequence, "score_semantics_version": SCORE_VERSION,
              "evidence_schema_version": SCHEMA_VERSION, "backoff_k": backoff_k,
              "scoring_config": {"mode": MODE, "order": order, "granularity": granularity,
                                 "prior_strength": prior_strength, "dedup": dedup}}
    validate(result["unigram"], sequence, result["scoring_config"], backoff_k)
    return result


def validate(unigram, sequence, config, backoff_k):
    if config.get("mode") != MODE or config.get("granularity") not in E.GRANULARITIES:
        raise ValueError("unsupported sequence scoring configuration")
    order = sequence.get("order")
    if (sequence.get("schema_version") != SCHEMA_VERSION or isinstance(order, bool) or
            not isinstance(order, int) or not 1 <= order <= MAX_ORDER or config.get("order") != order):
        raise ValueError("invalid markov order or schema")
    for value in (backoff_k, config.get("prior_strength")):
        if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                not math.isfinite(value) or not E.MIN_STRENGTH <= value <= E.MAX_STRENGTH):
            raise ValueError("invalid sequence smoothing strength")
    rows = sequence["contexts"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("missing sequence contexts")
    seen, root = set(), None
    for row in rows:
        history, counts, stats = row["history"], row["counts"], row["evidence"]
        if (not isinstance(history, list) or len(history) > order or
                any(not isinstance(s, str) or not s for s in history)):
            raise ValueError("invalid sequence history")
        key = tuple(history)
        if key in seen:
            raise ValueError("duplicate sequence context")
        seen.add(key)
        if not isinstance(counts, dict) or not counts:
            raise ValueError("empty sequence distribution")
        for symbol, n in counts.items():
            if (not isinstance(symbol, str) or not symbol or symbol == UNKNOWN or
                    isinstance(n, bool) or not isinstance(n, (int, float)) or not 0 < n < math.inf):
                raise ValueError("invalid sequence counts")
        raw, sessions, groups = (stats[name] for name in ("raw_count", "session_support", "group_support"))
        if (any(isinstance(n, bool) or not isinstance(n, int) for n in (raw, sessions, groups)) or
                not 1 <= groups <= sessions <= raw):
            raise ValueError("invalid sequence support")
        for name in ("sum_w", "event_w2", "session_w2", "group_w2"):
            n = stats[name]
            if isinstance(n, bool) or not isinstance(n, (int, float)) or not 0 < n < math.inf:
                raise ValueError("invalid sequence evidence moment")
        if not math.isclose(sum(counts.values()), stats["sum_w"], rel_tol=1e-9):
            raise ValueError("sequence evidence mass differs from counts")
        for level, upper in (("event", raw), ("session", sessions), ("group", groups)):
            if not 1 - 1e-8 <= E.effective_n(stats, level) <= upper + 1e-7:
                raise ValueError("invalid effective sequence evidence")
        if not key:
            root = counts
    if root is None or root != unigram:
        raise ValueError("sequence root differs from marginal counts")
    if any(history and history[1:] not in seen for history in seen):
        raise ValueError("sequence suffix is missing")
    if any(symbol not in unigram for row in rows for symbol in row["counts"]):
        raise ValueError("sequence vocabulary differs from marginal counts")


class Table:
    def __init__(self, unigram, sequence, config, backoff_k):
        self.coarse = None
        self.unigram, self.order, self.backoff_k = unigram, sequence["order"], backoff_k
        self.rows = {tuple(row["history"]): row for row in sequence["contexts"]}
        self.totals = {history: sum(row["counts"].values()) for history, row in self.rows.items()}
        level, prior = config["granularity"], config["prior_strength"]
        self.effective = {history: E.effective_n(row["evidence"], level) for history, row in self.rows.items()}
        self.granularity = level
        n, size, total = self.effective[()], len(unigram) + 1, self.totals[()]
        self.unknown = prior / size / (n + prior)
        self.marginals = {symbol: (n * count / total + prior / size) / (n + prior)
                          for symbol, count in unigram.items()}

    def marginal(self, symbol):
        return self.marginals.get(symbol, self.unknown)

    def conditional(self, previous, symbol):
        history, probability = context(previous, self.order), self.marginal(symbol)
        for depth in range(1, len(history) + 1):
            suffix = history[-depth:]
            row = self.rows.get(suffix)
            if row:
                n = self.effective[suffix]
                probability = (n * row["counts"].get(symbol, 0.) / self.totals[suffix] +
                               self.backoff_k * probability) / (n + self.backoff_k)
        return probability

    def diagnostics(self, previous):
        history = context(previous, self.order)
        while history and history not in self.rows:
            history = history[1:]
        n = self.effective[history] if history else 0.
        stats = self.rows[history]["evidence"]
        return {"effective_n": n, "lambda": n / (n + self.backoff_k),
                "weighted_mass": stats["sum_w"], "granularity": self.granularity,
                "context_length": len(history), "max_order": self.order,
                **{key: stats[key] for key in ("raw_count", "session_support", "group_support")}}
