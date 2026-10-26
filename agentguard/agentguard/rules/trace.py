"""仅采集当前检测调用真正命中的特征，不重跑匹配，也不保存待检原文。"""

from contextvars import ContextVar

_collector = ContextVar("agentguard_feature_hits", default=None)


def record_feature(feature: dict) -> None:
    hits = _collector.get()
    if hits is not None and not any((hit["rule_id"], hit.get("revision")) ==
                                    (feature["rule_id"], feature.get("revision")) for hit in hits):
        hits.append(dict(feature))


def observe_features(check, *args, **kwargs):
    hits = []
    token = _collector.set(hits)
    try:
        return check(*args, **kwargs), hits
    finally:
        _collector.reset(token)
