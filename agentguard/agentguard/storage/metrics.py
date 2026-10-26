"""运行时指标（设计 §13）：回放场景归类、检出 / 误报统计、延迟分位数与进程 / 容器 CPU 采样。

这里都是对快照数据的计算，不持有存储状态；快照由 RuntimeStore.metrics() 在存储锁内采集。
"""

import os
import time
from collections import Counter

MALICIOUS_SCENARIOS = {"C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "M-1", "M-2"}
# 回放语料的全部已知场景前缀，作为场景归类的锚点。
KNOWN_SCENARIOS = MALICIOUS_SCENARIOS | {"B-RD", "B-OPS", "B-SEC", "B-SUP"}


def scenario_of(trace_id: str) -> str:
    """从回放实例号（trace 前缀）推断场景，仅用于指标分组，不做授权依据。

    以已知场景集合为锚，从右剥离实例后缀（数字段、评测 run_id、序号等）：
    B-SUP-7→B-SUP；C1-A-191835-0001→C1-A；M-2-915470→M-2；
    评测实例 C1-B-<run_id>-7→C1-B。未知 trace 原样保留。
    """
    t = str(trace_id or "")
    if t in KNOWN_SCENARIOS:
        return t
    parts = t.split("-")
    for end in range(len(parts) - 1, 0, -1):
        candidate = "-".join(parts[:end])
        if candidate in KNOWN_SCENARIOS:
            return candidate
    return t


def percentiles(values: list, keys=(50, 95, 99)) -> dict:
    if not values:
        return {f"p{key}": 0.0 for key in keys}
    ordered = sorted(values)

    def pct(key):
        return round(ordered[min(len(ordered) - 1, int(len(ordered) * key / 100))], 3)

    return {f"p{key}": pct(key) for key in keys}


def scenario_summary(decisions: list) -> dict:
    """按会话汇总决策：各场景的拦截 / 确认 / 仅放行数，以及据此得到的混淆矩阵与检出率、误报率。"""
    per_trace: dict[str, set] = {}
    for d in decisions:
        per_trace.setdefault(d.trace_id, set()).add(d.decision)
    scenario_rows = {}
    for trace, kinds in per_trace.items():
        scenario = scenario_of(trace)
        row = scenario_rows.setdefault(
            scenario,
            {"tasks": 0, "blocked": 0, "asked": 0, "allowed_only": 0, "malicious": scenario in MALICIOUS_SCENARIOS},
        )
        row["tasks"] += 1
        if "DENY" in kinds:
            row["blocked"] += 1
        elif "ASK" in kinds:
            row["asked"] += 1
        else:
            row["allowed_only"] += 1
    tp = sum(row["blocked"] + row["asked"] for row in scenario_rows.values() if row["malicious"])
    fn = sum(row["allowed_only"] for row in scenario_rows.values() if row["malicious"])
    fp = sum(row["blocked"] + row["asked"] for row in scenario_rows.values() if not row["malicious"])
    tn = sum(row["allowed_only"] for row in scenario_rows.values() if not row["malicious"])
    rates = {}
    if tp + fn > 0:
        rates["detection"] = round(tp / (tp + fn), 4)
    if tp + fp > 0:
        rates["false_positive"] = round(fp / (tp + fp), 4)
    return {"decision_counts": dict(Counter(d.decision for d in decisions)), "scenarios": scenario_rows,
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "rates": rates}


_CPU_BASELINE: dict = {"wall": None, "process": None, "container": None}
_STARTED_AT = time.time()


def _container_usage():
    """容器内全部进程的累计 CPU 秒与 RSS 合计（容器 /proc 按 PID 命名空间隔离；
    非 Linux 或读取失败返回 None，调用方回退到网关进程自身数据）。"""
    try:
        tick = os.sysconf("SC_CLK_TCK")
        page = os.sysconf("SC_PAGESIZE")
        cpu = 0.0
        rss = 0.0
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat", "rb") as fh:
                    raw = fh.read()
                # comm 可含空格/括号，取最后一个 ')' 之后的字段；+11/+12 即 utime/stime。
                fields = raw[raw.rindex(b")") + 2:].split()
                cpu += (int(fields[11]) + int(fields[12])) / tick
                with open(f"/proc/{entry}/statm", "rb") as fh:
                    rss += int(fh.read().split()[1]) * page
            except (OSError, ValueError, IndexError):
                continue
        return cpu, rss / (1024 * 1024)
    except (OSError, ValueError):
        return None, None


def cpu_snapshot() -> dict:
    """进程/容器 CPU 用量。window_* 为相邻两次采样的滑动使用率（100% = 一个核，
    多线程可超 100%）；首次调用无基线返回 None。avg_* 为进程自启动的累计均值，仅存档。"""
    import resource

    usage = resource.getrusage(resource.RUSAGE_SELF)
    wall = time.time()
    process_cpu = usage.ru_utime + usage.ru_stime
    container_cpu, container_rss = _container_usage()
    baseline = _CPU_BASELINE
    delta_wall = wall - baseline["wall"] if baseline["wall"] else 0.0

    def window(now, before):
        if delta_wall <= 0 or now is None or before is None:
            return None
        return round((now - before) / delta_wall * 100, 2)

    snapshot = {
        "process_cpu_seconds": round(process_cpu, 3),
        "uptime_seconds": round(wall - _STARTED_AT, 1),
        "window_cpu_percent": window(process_cpu, baseline["process"]),
        "container_cpu_percent": window(container_cpu, baseline["container"]),
        "avg_cpu_percent": round(process_cpu / (wall - _STARTED_AT) * 100, 2),
        "max_rss_mb": round(usage.ru_maxrss / 1024, 1),
        "container_rss_mb": round(container_rss, 1) if container_rss is not None else None,
    }
    baseline.update(wall=wall, process=process_cpu, container=container_cpu)
    return snapshot
