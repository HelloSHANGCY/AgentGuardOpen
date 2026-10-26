"""评测指标：precision / recall / 漏报率 / accuracy / FPR。

评测单元固定为“标注组件 × 适用风险类别”，用集合去重；
零分母记 N/A（None），不做单一指标替代。
"""


def _rate(numerator: int, denominator: int):
    return round(numerator / denominator, 4) if denominator else None


def evaluate_findings(labels: list, findings: list, asset_path=None) -> dict:
    """labels: [{"path", "category", "expected"(bool, 默认 True)}]。

    asset_path(finding) -> 资产相对路径，用于把 finding 归到标注组件。
    """
    asset_path = asset_path or (lambda finding: "")
    tp = fp = fn = tn = 0
    details = []
    for label in labels:
        expected = bool(label.get("expected", True))
        hit = any(finding.category == label["category"]
                  and _path_matches(asset_path(finding), label["path"])
                  for finding in findings)
        if expected:
            tp += 1 if hit else 0
            fn += 0 if hit else 1
        else:
            fp += 1 if hit else 0
            tn += 0 if hit else 1
        details.append({"path": label["path"], "category": label["category"],
                        "expected": expected, "hit": hit})
    total = tp + fp + fn + tn
    return {
        "units": total, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": _rate(tp, tp + fp),
        "recall": _rate(tp, tp + fn),
        "miss_rate": _rate(fn, tp + fn),
        "accuracy": _rate(tp + tn, total),
        "fpr": _rate(fp, fp + tn),
        "details": details,
    }


def evaluate_assets(labels: list, assets: list) -> dict:
    """资产盘点指标：按类型 + 规范位置/逻辑身份匹配，先去重再计数。"""
    tp = fp = fn = 0
    matched = set()
    for label in labels:
        expected = bool(label.get("expected", True))
        hit = False
        for asset in assets:
            if asset.asset_id in matched:
                continue
            if asset.kind != label["kind"]:
                continue
            if label.get("logical_key") and asset.logical_key != label["logical_key"]:
                continue
            if label.get("path") and not _path_matches(asset.relative_path, label["path"]):
                continue
            matched.add(asset.asset_id)
            hit = True
            break
        if expected:
            tp += 1 if hit else 0
            fn += 0 if hit else 1
        else:
            fp += 1 if hit else 0
    return {
        "units": len(labels), "tp": tp, "fp": fp, "fn": fn,
        "precision": _rate(tp, tp + fp),
        "recall": _rate(tp, tp + fn),
        "miss_rate": _rate(fn, tp + fn),
    }


def _path_matches(actual: str, expected: str) -> bool:
    actual = str(actual or "").replace("\\", "/")
    expected = str(expected or "").replace("\\", "/")
    return actual == expected or actual.startswith(expected.rstrip("/") + "/")
