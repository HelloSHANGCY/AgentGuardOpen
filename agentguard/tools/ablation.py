#!/usr/bin/env python3
"""创新检测消融评测（创新检测实施方案 §6）。

在多组特性开关下，把 Claude Code 夹具集（G-1 ~ G-9 攻击 + 正常开发流量）在进程内回放一遍，
输出检出率、首个高风险点的拒绝率、误报率、正常步骤 ASK 率与引擎判定延迟的对照表：

    python3 tools/ablation.py                       # 基线 / 逐项开启 / 全部开启
    python3 tools/ablation.py --json out.json       # 同时写出逐夹具明细
    python3 tools/ablation.py --scenario G-9        # 只回放一个场景

不依赖模型与网络：服务端以 FastAPI TestClient 在进程内启动，每组配置一个全新实例。
特性通过 AG_DISABLED_FEATURES 关闭（provenance / flow / anomaly）。
"""

import argparse
import json
import os
import pathlib
import statistics
import sys
import warnings
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FEATURES = ("provenance", "flow", "anomaly")
TOKENS = {"developer": "agd_ablation_dev", "strict": "agd_ablation_strict"}
DEVICES = {"developer": "ab-dev", "strict": "ab-strict"}


def configs(features: list) -> list[tuple[str, list]]:
    """(名称, 开启的特性)：基线、逐项开启、全部开启。"""
    rows = [("基线（全部关闭）", [])]
    rows += [(f"+{name}", [name]) for name in features]
    if len(features) > 1:
        rows.append(("全部开启", list(features)))
    return rows


def run_config(enabled: list, scenario: str) -> list[dict]:
    os.environ.update({
        "AG_DISABLED_FEATURES": ",".join([*(name for name in FEATURES if name not in enabled), "intent_llm", "llm_judge"]),
        "AG_AGENT_DEVICES": json.dumps({TOKENS[p]: {"device_id": DEVICES[p], "profile": p} for p in TOKENS}),
        "AG_DATA_DIR": "", "AG_AGENT_DEVICE_DIR": "", "AG_BEHAVIOR_DIR": "", "AG_INTENT_LLM_KEY": "",
        "AG_LOCAL_TEST": "1", "AG_STATIC_ENABLED": "0",
    })
    from fastapi.testclient import TestClient

    from agentguard.agents.cc_fixtures import fixtures
    from agentguard.agents.cc_replay import HookTransport, attach_decisions, replay_fixture
    from agentguard.main import create_app

    rows = []
    with TestClient(create_app()) as client:
        transport = HookTransport("http://testserver", client)
        for fixture in fixtures():
            if scenario not in ("all", fixture["threat"]):
                continue
            profile = fixture.get("profile", "developer")
            row = replay_fixture(fixture, transport, TOKENS[profile], DEVICES[profile], "ab")
            attach_decisions(row, client, "http://testserver")
            rows.append(row)
        latencies = [item["latency_ms"] for item in
                     client.get("/v1/runtime/decisions", params={"limit": 5000}).json()["decisions"]]
    for row in rows:
        row["_engine_latencies"] = latencies
    return rows


def percentile(values: list, q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))]


def summarize(rows: list[dict]) -> dict:
    malicious = [row for row in rows if row["malicious"]]
    benign = [row for row in rows if not row["malicious"]]
    benign_steps = [step for row in benign for step in row["steps"] if "ms" in step]
    by_scenario = defaultdict(lambda: {"n": 0, "tp": 0, "deny": 0})
    for row in malicious:
        item = by_scenario[row["scenario"]]
        item["n"] += 1
        item["tp"] += row["outcome"] == "TP"
        item["deny"] += row["first_risk"] == "deny"
    engine = rows[0]["_engine_latencies"] if rows else []
    hook = [step["ms"] for row in rows for step in row["steps"] if "ms" in step]
    return {
        "malicious": len(malicious), "tp": sum(row["outcome"] == "TP" for row in malicious),
        "deny_at_risk": sum(row["first_risk"] == "deny" for row in malicious),
        "benign": len(benign), "fp": sum(row["outcome"] == "FP" for row in benign),
        "benign_steps": len(benign_steps),
        "benign_ask": sum(step["got"] == "ask" for step in benign_steps),
        "benign_deny": sum(step["got"] == "deny" for step in benign_steps),
        "engine_p50": percentile(engine, 50), "engine_p95": percentile(engine, 95),
        "engine_mean": statistics.fmean(engine) if engine else 0.0,
        "engine_p99": percentile(engine, 99),
        "hook_p50": percentile(hook, 50), "hook_p95": percentile(hook, 95), "hook_p99": percentile(hook, 99),
        "model_services": "disabled; intent classification and judge timings are not measured",
        "by_scenario": dict(by_scenario),
        "misses": sorted(row["fixture"] for row in malicious if row["outcome"] != "TP"),
        "false_positives": sorted(row["fixture"] for row in benign if row["outcome"] == "FP"),
    }


def pct(part: int, whole: int) -> str:
    return f"{part / whole * 100:.1f}%" if whole else "-"


def render(results: list[tuple[str, dict]]) -> str:
    lines = ["| 配置 | 检出率 | 高风险点直接拒绝 | 误报（夹具） | 正常步骤 ASK 率 | 引擎延迟 p50 / p95 |",
             "|---|---|---|---|---|---|"]
    for name, item in results:
        lines.append(
            f"| {name} | {item['tp']}/{item['malicious']}（{pct(item['tp'], item['malicious'])}） "
            f"| {item['deny_at_risk']}/{item['malicious']}（{pct(item['deny_at_risk'], item['malicious'])}） "
            f"| {item['fp']}/{item['benign']} | {pct(item['benign_ask'], item['benign_steps'])} "
            f"| {item['engine_p50']:.2f} / {item['engine_p95']:.2f} ms |")
    scenarios = sorted({key for _, item in results for key in item["by_scenario"]},
                       key=lambda name: (int(name[2:]) if name[2:].isdigit() else 99, name))
    lines += ["", "| 场景 | " + " | ".join(name for name, _ in results) + " |",
              "|---|" + "---|" * len(results)]
    for scenario in scenarios:
        cells = []
        for _, item in results:
            stats = item["by_scenario"].get(scenario, {"n": 0, "tp": 0, "deny": 0})
            cells.append(f"检出 {stats['tp']}/{stats['n']} · 拒绝 {stats['deny']}")
        lines.append(f"| {scenario} | " + " | ".join(cells) + " |")
    for name, item in results:
        if item["misses"] or item["false_positives"]:
            lines.append(f"\n- {name}：漏检 {item['misses'] or '无'}；误报 {item['false_positives'] or '无'}")
    return "\n".join(lines)


def main(argv=None) -> int:
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--features", default=",".join(FEATURES), help="参与对照的特性，逗号分隔")
    parser.add_argument("--scenario", default="all")
    parser.add_argument("--json", help="写出汇总与逐夹具明细")
    args = parser.parse_args(argv)
    features = [name for name in args.features.split(",") if name in FEATURES]
    results, details = [], {}
    for name, enabled in configs(features):
        rows = run_config(enabled, args.scenario)
        results.append((name, summarize(rows)))
        details[name] = [{key: value for key, value in row.items() if not key.startswith("_")} for row in rows]
    print(render(results))
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(
            {"summary": dict(results), "rows": details}, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
