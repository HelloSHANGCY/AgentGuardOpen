#!/usr/bin/env python3
"""真实开发会话误报评测：把 SWE-chat 的 Claude Code 原始会话记录转成 Hook 事件，在进程内回放并统计拦截。

    python3 tools/fetch_swechat_sessions.py --sample 300     # 先抽样下载（需登录 Hugging Face）
    python3 tools/benign_replay.py                           # 回放 manifest 中的全部会话
    python3 tools/benign_replay.py --limit 20 --json out.json
    python3 tools/benign_replay.py --disable provenance,flow,anomaly   # 关闭创新检测做对照

会话来自真实开发者的日常使用，默认视为正常流量：会话内任一步 ASK / DENY 记为误报会话，另按步骤统计
ASK / DENY 率（通用 Agent 接入设计 §16：developer 档案零 DENY、ASK ≤ 5%）。真实会话里也可能有确实危险
的操作（删除目录、curl | sh 安装脚本等），拦截明细按原因码给出样例，需人工复核后再定性为误报。

转换规则（Claude Code 原生会话记录 → Hook 事件）：
- 用户输入 → UserPromptSubmit；斜杠命令还原为“/命令 参数”；元信息、本地命令输出、`!` 命令、中断提示跳过；
- tool_use → PreToolUse；对应 tool_result 成功 → PostToolUse（优先用记录里的结构化 toolUseResult，
  超过 16 KB 按 Hook 客户端口径截断），失败 → PostToolUseFailure；
- 两次用户输入之间 → Stop（一轮回答结束，大模型威胁分析按轮触发）；
- isSidechain（旧版子 Agent 内联记录）→ 子 Agent 调用；记录的 cwd 变化 → 之后的 Hook 负载换工作目录；
- 每个提交者一台设备（purpose=evaluation，不记行为基线、不触发大模型分析），跨会话关联按设备生效。

不依赖模型、网络和 Docker；明细含第三方原始命令，默认只写到 data/benign/ 下（不进仓库）。
"""

import argparse
import json
import os
import pathlib
import re
import statistics
import sys
import threading
import time
import warnings
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DATA = ROOT / "data" / "benign" / "swechat"
FEATURES = ("provenance", "flow", "anomaly")

COMMAND_NAME_RE = re.compile(r"<command-name>(.*?)</command-name>", re.S)
COMMAND_ARGS_RE = re.compile(r"<command-args>(.*?)</command-args>", re.S)
# 由客户端注入、不是用户在输入框里提交给 Agent 的内容。
NOT_PROMPT = ("<local-command-stdout>", "<local-command-stderr>", "<bash-input>", "<bash-stdout>", "<bash-stderr>",
              "[Request interrupted", "Caveat:", "<system-reminder>", "<task-notification>", "<user-memory-input>")
MAX_RESPONSE_CHARS = 16384      # 与 Hook 客户端 shrink 一致


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(block.get("text") or "") for block in content
                         if isinstance(block, dict) and block.get("type") == "text")
    return ""


def _prompt(entry: dict) -> str | None:
    if entry.get("isMeta") or entry.get("isCompactSummary"):
        return None
    content = (entry.get("message") or {}).get("content")
    text = _text(content).strip()
    if not text:
        return None
    name = COMMAND_NAME_RE.search(text)
    if name:
        args = COMMAND_ARGS_RE.search(text)
        return f"{name.group(1).strip()} {args.group(1).strip() if args else ''}".strip()
    if text.startswith(NOT_PROMPT):
        return None
    return text


def _response(entry: dict, block: dict, single: bool):
    structured = entry.get("toolUseResult")
    response = structured if single and structured not in (None, "") else _text(block.get("content")) \
        or block.get("content") or ""
    text = response if isinstance(response, str) else json.dumps(response, ensure_ascii=False, default=str)
    return text[:MAX_RESPONSE_CHARS] if len(text) > MAX_RESPONSE_CHARS else response


def transcript_fixture(path: pathlib.Path, session_id: str, *, raw: bytes | None = None,
                       diagnostics: dict | None = None) -> dict:
    """一份 Claude Code 原生会话记录 → cc_replay 夹具（全部步骤期望放行）。"""
    steps, calls, seen, seen_calls = [], {}, set(), set()
    cwd, current, sidechain = "", "", False
    diagnostics = diagnostics if diagnostics is not None else {}

    def count(key):
        diagnostics[key] = diagnostics.get(key, 0) + 1

    text = (raw if raw is not None else path.read_bytes()).decode("utf-8", errors="replace")
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            count("invalid_json_lines")
            steps.append({"cut": True})
            continue
        if not isinstance(entry, dict) or entry.get("type") not in ("user", "assistant"):
            continue
        uuid = entry.get("uuid")
        if uuid is not None and not isinstance(uuid, str):
            count("invalid_entry_id")
            steps.append({"cut": True})
            continue
        if uuid and uuid in seen:   # 续接会话时记录可能重复
            count("duplicate_entries")
            continue
        seen.add(uuid)
        if not isinstance(entry.get("message"), dict):
            count("invalid_messages")
            steps.append({"cut": True})
            continue
        here = str(entry.get("cwd") or "")
        if here and not cwd:
            cwd = here
        elif here and here != current:
            steps.append({"cwd": here})
        current = here or current
        if bool(entry.get("isSidechain")) != sidechain:
            sidechain = not sidechain
            steps.append({"subagent": "sidechain" if sidechain else None})
        content = (entry.get("message") or {}).get("content")
        blocks = [block for block in content if isinstance(block, dict)] if isinstance(content, list) else []
        if entry["type"] == "assistant":
            for block in blocks:
                if block.get("type") == "tool_use":
                    call_id = block.get("id")
                    if not isinstance(call_id, str) or not call_id or call_id in seen_calls:
                        count("duplicate_or_missing_call_id")
                        if not isinstance(call_id, str) or not call_id:
                            steps.append({"cut": True})
                        continue
                    seen_calls.add(call_id)
                    tool, tool_input = str(block.get("name") or ""), block.get("input") or {}
                    calls[call_id] = (tool, tool_input)
                    steps.append({"pre": tool, "input": tool_input, "expect": "allow", "call": call_id})
            continue
        results = [block for block in blocks if block.get("type") == "tool_result"]
        if not results:
            prompt = None if sidechain else _prompt(entry)
            if prompt:
                if any("prompt" in step for step in steps):
                    steps.append({"stop": True})   # 上一轮回答结束
                steps.append({"prompt": prompt})
            continue
        for block in results:
            result_id = block.get("tool_use_id")
            call = calls.pop(result_id, None) if isinstance(result_id, str) else None
            if call is None:
                count("unmatched_results")
                steps.append({"cut": True})
                continue
            tool, tool_input = call
            if block.get("is_error"):
                steps.append({"fail": tool, "input": tool_input, "call": block.get("tool_use_id"),
                              "error": _text(block.get("content")) or str(block.get("content") or "")})
            else:
                steps.append({"post": tool, "input": tool_input, "call": block.get("tool_use_id"),
                              "response": _response(entry, block, len(results) == 1)})
    if sidechain:
        steps.append({"subagent": None})
    return {"id": f"swe-{session_id[:8]}", "session": session_id, "threat": "BENIGN", "malicious": False,
            "profile": "developer", "cwd": cwd or "/home/dev/project", "steps": steps}


def load_fixtures(data: pathlib.Path, limit: int) -> tuple[list[dict], dict]:
    manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
    fixtures = []
    for row in manifest["sessions"][:limit or None]:
        path = data / (row.get("local_path") or f"transcripts/{row['session_id']}.jsonl")
        if not path.exists():
            continue
        fixture = transcript_fixture(path, row["session_id"])
        fixture["user"] = row.get("user_id") or row["session_id"]
        fixtures.append(fixture)
    return fixtures, manifest


ENDPOINT = "agentguard-endpoint/0.12.0"   # 冒充当前终端：大模型复核可等满审批超时
JUDGE_FIELDS = ("url", "model", "analysis_model", "key", "approval_enabled", "approval_scope", "approval_timeout",
                "analysis_mode", "analysis_timeout", "approval_effort", "analysis_effort")


def _owner(fixture: dict) -> tuple[str, str]:
    """(设备归属, 策略档案)：SWE-chat 会话按提交者分设备，攻击夹具按档案分设备。"""
    profile = fixture.get("profile", "developer")
    return fixture.get("user") or f"fixture-{profile}", profile


def replay(fixtures: list[dict], disabled: list[str], judge: dict | None = None, workers: int = 1,
           analysis_workers: int = 2, llm_concurrency: int = 0) -> tuple[list[dict], list[float], float, dict]:
    """judge 为大模型研判配置（llm-judge.json 的字段）：给出时设备不标为评测用途，静态 ASK / DENY 经模型复核，
    每轮结束按配置的模式异步分析；回放结束后等分析全部完成，分析结果按会话附在结果行上。

    模型接口常有并发上限：同时在途的请求最多 workers（同步复核）+ analysis_workers（异步分析）个，
    两者之和应不超过上限；llm_concurrency 再用信号量兜底（排队时间计入复核超时，所以不要靠它限流）。"""
    owners = sorted({_owner(fixture) for fixture in fixtures})
    devices = {owner: (f"agd_benign_{index:04d}", f"swechat-{index:04d}") for index, owner in enumerate(owners)}
    os.environ.update({
        "AG_DISABLED_FEATURES": ",".join(disabled),
        "AG_AGENT_DEVICES": json.dumps({token: {"device_id": device, "profile": owner[1],
                                                "purpose": "" if judge else "evaluation"}
                                        for owner, (token, device) in devices.items()}),
        "AG_DATA_DIR": "", "AG_AGENT_DEVICE_DIR": "", "AG_BEHAVIOR_DIR": "", "AG_LOCAL_TEST": "1",
        "AG_STATIC_ENABLED": "0", "AG_AGENT_ADMIN_TOKEN": "",
    })
    from fastapi.testclient import TestClient

    from agentguard.agents.cc_replay import HookTransport, attach_decisions, replay_fixture
    from agentguard.llm import judge as J
    from agentguard.main import create_app

    # 批量评测：分析排队上限与记录上限放开。
    J.JudgeService.ANALYSIS_WORKERS = max(1, analysis_workers)
    J.MAX_PENDING = J.MAX_RECORDS = 1_000_000
    if llm_concurrency:
        gate, chat = threading.Semaphore(llm_concurrency), J.chat_json

        def limited(*args, **kwargs):
            with gate:
                return chat(*args, **kwargs)

        J.chat_json = limited   # JudgeService 构造时取用
    rows: list = [None] * len(fixtures)
    engine, lock, done = [], threading.Lock(), [0]
    started = time.monotonic()
    with TestClient(create_app()) as client:
        if judge:
            config = {key: judge[key] for key in JUDGE_FIELDS if key in judge}
            response = client.put("/v1/admin/judge", json={**config, "rule_proposal": False})
            response.raise_for_status()
        transport = HookTransport("http://testserver", client, endpoint=ENDPOINT if judge else "")

        def run(index: int) -> None:
            fixture = fixtures[index]
            token, device = devices[_owner(fixture)]
            row = replay_fixture(fixture, transport, token, device, "br", cwd=fixture.get("cwd", "/home/dev/project"))
            attach_decisions(row, client, "http://testserver")
            row["session"] = fixture.get("session") or fixture["id"]
            latencies, reviews = [], []
            # 决策队列有上限，按会话及时取引擎延迟与复核记录，避免长评测被挤出。
            for trace_id in row["trace_ids"]:
                for item in client.get("/v1/runtime/decisions",
                                       params={"trace_id": trace_id, "limit": 100_000}).json()["decisions"]:
                    if item.get("trace_id") != trace_id:
                        continue
                    latencies.append(item["latency_ms"])
                    if item.get("review"):
                        review = item["review"]
                        reviews.append({"static": review.get("static"), "final": item["decision"],
                                        "reason": review.get("static_reason"), "status": review.get("status"),
                                        "cached": review.get("cached"), "ms": review.get("latency_ms")})
            row["reviews"] = reviews
            rows[index] = row
            with lock:
                engine.extend(latencies)
                done[0] += 1
                if done[0] % 25 == 0 or done[0] == len(fixtures):
                    print(f"[{done[0]}/{len(fixtures)}] {time.monotonic() - started:.0f}s", file=sys.stderr, flush=True)

        with ThreadPoolExecutor(max(1, workers)) as pool:
            list(pool.map(run, range(len(fixtures))))
        status = {}
        if judge:
            while True:
                status = client.get("/v1/admin/judge").json()
                if not status["analysis"]["pending"]:
                    break
                print(f"等待异步分析：剩余 {status['analysis']['pending']}", file=sys.stderr, flush=True)
                time.sleep(10)
            for row in rows:
                row["analyses"] = [
                    {key: record.get(key) for key in ("round", "status", "verdict", "risk", "summary", "alerts",
                                                       "error", "latency_ms")}
                    for trace_id in row["trace_ids"]
                    for record in client.get("/v1/admin/judge/analyses",
                                             params={"trace_id": trace_id, "limit": 1000}).json()["analyses"]]
    return rows, engine, time.monotonic() - started, status


def percentile(values: list, q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))]


def _preview(tool_input) -> str:
    from agentguard.models import redact_text

    text = tool_input.get("command") if isinstance(tool_input, dict) and "command" in tool_input else \
        json.dumps(tool_input, ensure_ascii=False, default=str)
    return redact_text(str(text), 160)["preview"]


def summarize(rows: list[dict], fixtures: list[dict], engine: list[float]) -> dict:
    inputs = {fixture["session"]: [step["input"] for step in fixture["steps"] if "pre" in step]
              for fixture in fixtures}
    steps = [(row, index, step) for row in rows for index, step in enumerate(item for item in row["steps"]
                                                                            if "ms" in item)]
    blocked = [(row, index, step) for row, index, step in steps if step["got"] in ("ask", "deny")]
    by_reason = defaultdict(lambda: {"ask": 0, "deny": 0, "sessions": set(), "examples": []})
    for row, index, step in blocked:
        item = by_reason[step["reason"] or "UNKNOWN"]
        item[step["got"]] += 1
        item["sessions"].add(row["session"])
        if len(item["examples"]) < 5:
            item["examples"].append({"session": row["session"], "tool": step["tool"], "decision": step["got"],
                                     "input": _preview(inputs[row["session"]][index])})
    tools = Counter(step["tool"] for _, _, step in steps)
    blocked_tools = Counter(step["tool"] for _, _, step in blocked)
    latencies = [step["ms"] for _, _, step in steps]
    return {
        "sessions": len(rows), "fp_sessions": sum(row["outcome"] == "FP" for row in rows),
        "deny_sessions": sum(any(step.get("got") == "deny" for step in row["steps"]) for row in rows),
        "steps": len(steps), "ask": sum(step["got"] == "ask" for _, _, step in steps),
        "deny": sum(step["got"] == "deny" for _, _, step in steps),
        "prompts": sum("prompt" in step for fixture in fixtures for step in fixture["steps"]),
        "hook_p50": percentile(latencies, 50), "hook_p95": percentile(latencies, 95),
        "hook_mean": statistics.fmean(latencies) if latencies else 0.0,
        "engine_p50": percentile(engine, 50), "engine_p95": percentile(engine, 95),
        "by_reason": {key: {**value, "sessions": len(value["sessions"])} for key, value in
                      sorted(by_reason.items(), key=lambda item: -(item[1]["ask"] + item[1]["deny"]))},
        "by_tool": {tool: {"steps": count, "blocked": blocked_tools[tool]} for tool, count in tools.most_common()},
    }


def model_summary(rows: list[dict]) -> dict:
    """大模型研判的效果：复核把静态判定改成了什么、异步分析的结论与对静态告警的研判。"""
    reviews = [review for row in rows for review in row.get("reviews") or []]
    done = [review for review in reviews if review["status"] == "ok"]
    fresh = [review["ms"] for review in done if not review.get("cached") and review.get("ms") is not None]
    analyses = [record for row in rows for record in row.get("analyses") or []]
    alerts = defaultdict(Counter)
    for record in analyses:
        for alert in record.get("alerts") or []:
            alerts[alert["reason_code"]][alert["assessment"]] += 1
    return {
        "reviews": len(reviews), "review_failed": len(reviews) - len(done), "review_cached": len(done) - len(fresh),
        "review_p50": percentile(fresh, 50), "review_p90": percentile(fresh, 90),
        "changes": {f"{static}->{final}": count for (static, final), count in
                    Counter((review["static"], review["final"]) for review in done).most_common()},
        "analyses": len(analyses),
        "verdicts": dict(Counter(record["verdict"] if record["status"] == "done" else record["status"]
                                 for record in analyses)),
        "analysis_p50": percentile([record["latency_ms"] for record in analyses if record["status"] == "done"], 50),
        "risky_sessions": sum(any(record.get("verdict") in ("suspicious", "malicious")
                                  for record in row.get("analyses") or []) for row in rows),
        "alerts": {reason: dict(counts) for reason, counts in
                   sorted(alerts.items(), key=lambda item: -sum(item[1].values()))},
        "errors": Counter(record.get("error", "")[:80] for record in analyses if record["status"] != "done")
        .most_common(3),
    }


def attack_summary(rows: list[dict]) -> dict:
    """攻击夹具（cc_fixtures）：同一配置下的检出，大模型复核是否放走了攻击、异步分析是否识别出攻击。"""
    malicious = [row for row in rows if row["malicious"]]
    benign = [row for row in rows if not row["malicious"]]
    released = [row["fixture"] for row in malicious
                if any(review["static"] in ("ASK", "DENY") and review["final"] == "ALLOW"
                       for review in row.get("reviews") or [])]
    return {
        "malicious": len(malicious), "tp": sum(row["outcome"] == "TP" for row in malicious),
        "misses": sorted(row["fixture"] for row in malicious if row["outcome"] != "TP"),
        "released": sorted(released),
        "analysis_flagged": sum(any(record.get("verdict") in ("suspicious", "malicious")
                                    for record in row.get("analyses") or []) for row in malicious),
        "benign": len(benign), "fp": sorted(row["fixture"] for row in benign if row["outcome"] == "FP"),
    }


def render_model(model: dict, attacks: dict | None) -> str:
    lines = ["", "### 大模型研判", "", "| 指标 | 结果 |", "|---|---|",
             f"| 复核次数（缓存命中 / 失败或超时） | {model['reviews']}（{model['review_cached']} / {model['review_failed']}） |",
             f"| 复核延迟 p50 / p90 | {model['review_p50'] / 1000:.1f} / {model['review_p90'] / 1000:.1f} s |",
             "| 复核结论（静态 → 最终） | " + "，".join(f"{key} {value}" for key, value in model["changes"].items())
             + " |",
             f"| 异步分析轮次 / 结论 | {model['analyses']}：" + "，".join(
                 f"{key} {value}" for key, value in model["verdicts"].items()) + " |",
             f"| 分析延迟 p50 | {model['analysis_p50'] / 1000:.1f} s |",
             f"| 被判可疑 / 恶意的会话 | {model['risky_sessions']} |"]
    if model["errors"]:
        lines.append("| 分析失败原因 | " + "；".join(f"{text} ×{count}" for text, count in model["errors"]) + " |")
    if model["alerts"]:
        lines += ["", "| 静态告警原因码 | 模型判真阳性 | 判误报 | 不确定 |", "|---|---|---|---|"]
        lines += [f"| {reason} | {counts.get('true_positive', 0)} | {counts.get('false_positive', 0)} "
                  f"| {counts.get('uncertain', 0)} |" for reason, counts in model["alerts"].items()]
    if attacks:
        lines += ["", "### 攻击夹具（同一配置）", "",
                  f"- 检出 {attacks['tp']}/{attacks['malicious']}；漏检 {attacks['misses'] or '无'}",
                  f"- 静态拦截被模型复核放行的攻击夹具：{attacks['released'] or '无'}",
                  f"- 异步分析判为可疑 / 恶意的攻击夹具：{attacks['analysis_flagged']}/{attacks['malicious']}",
                  f"- 正常夹具误报：{attacks['fp'] or '无'}（共 {attacks['benign']} 条）"]
    return "\n".join(lines)


def pct(part: int, whole: int) -> str:
    return f"{part / whole * 100:.2f}%" if whole else "-"


def render(item: dict, manifest: dict, disabled: list[str], elapsed: float) -> str:
    lines = [f"数据：{manifest['source']}（{manifest['agent']}，种子 {manifest['seed']}，"
             f"工具调用 {manifest['min_tools']}~{manifest['max_tools']} 次的会话）；关闭特性：{','.join(disabled) or '无'}；"
             f"回放耗时 {elapsed:.0f}s", "",
             "| 指标 | 结果 |", "|---|---|",
             f"| 会话 | {item['sessions']}（用户提示 {item['prompts']} 条） |",
             f"| 误报会话（任一步 ASK / DENY） | {item['fp_sessions']}（{pct(item['fp_sessions'], item['sessions'])}） |",
             f"| 含 DENY 的会话 | {item['deny_sessions']}（{pct(item['deny_sessions'], item['sessions'])}） |",
             f"| 工具调用（PreToolUse） | {item['steps']} |",
             f"| 步骤 ASK 率 | {item['ask']}（{pct(item['ask'], item['steps'])}） |",
             f"| 步骤 DENY 率 | {item['deny']}（{pct(item['deny'], item['steps'])}） |",
             f"| PreToolUse 延迟 p50 / p95（进程内 HTTP） | {item['hook_p50']:.2f} / {item['hook_p95']:.2f} ms |",
             f"| 引擎判定延迟 p50 / p95 | {item['engine_p50']:.2f} / {item['engine_p95']:.2f} ms |"]
    if item["by_reason"]:
        lines += ["", "| 原因码 | ASK | DENY | 涉及会话 |", "|---|---|---|---|"]
        lines += [f"| {reason} | {value['ask']} | {value['deny']} | {value['sessions']} |"
                  for reason, value in item["by_reason"].items()]
    lines += ["", "| 工具 | 调用 | 拦截 |", "|---|---|---|"]
    lines += [f"| {tool} | {value['steps']} | {value['blocked']} |"
              for tool, value in list(item["by_tool"].items())[:15]]
    return "\n".join(lines)


def main(argv=None) -> int:
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", default=str(DATA), help="fetch_swechat_sessions.py 的输出目录")
    parser.add_argument("--limit", type=int, default=0, help="只回放 manifest 前 N 个会话（0 = 全部）")
    parser.add_argument("--disable", default="", help=f"关闭的特性，逗号分隔：{','.join(FEATURES)}")
    parser.add_argument("--json", default=str(DATA / "replay.json"), help="写出汇总、拦截样例与逐会话明细")
    parser.add_argument("--examples", action="store_true", help="在终端输出拦截样例（含第三方原始命令，已掩码）")
    parser.add_argument("--judge-config", help="大模型研判配置（llm-judge.json 格式，含密钥）：开启复核与异步分析")
    parser.add_argument("--workers", type=int, default=1, help="并发回放的会话数（大模型复核较慢时调大）")
    parser.add_argument("--analysis-workers", type=int, default=2, help="异步分析并发数")
    parser.add_argument("--llm-concurrency", type=int, default=0,
                        help="模型请求总并发上限（兜底；应保证 workers + analysis-workers 不超过它）")
    parser.add_argument("--attacks", action="store_true", help="同时回放 Claude Code 攻击 / 正常夹具，报告同一配置下的检出")
    args = parser.parse_args(argv)
    disabled = [name for name in args.disable.split(",") if name]
    fixtures, manifest = load_fixtures(pathlib.Path(args.data), args.limit)
    if not fixtures:
        print("没有可回放的会话：先运行 tools/fetch_swechat_sessions.py", file=sys.stderr)
        return 1
    judge = json.loads(pathlib.Path(args.judge_config).read_text(encoding="utf-8")) if args.judge_config else None
    extra = []
    if args.attacks:
        from agentguard.agents.cc_fixtures import fixtures as cc_fixtures

        extra = cc_fixtures()
    rows, engine, elapsed, _ = replay(fixtures + extra, disabled, judge, args.workers, args.analysis_workers,
                                      args.llm_concurrency)
    rows, attack_rows = rows[:len(fixtures)], rows[len(fixtures):]
    item = summarize(rows, fixtures, engine)
    attacks = attack_summary(attack_rows) if extra else None
    model = model_summary(rows) if judge else None
    print(render(item, manifest, disabled, elapsed))
    if judge:
        print(render_model(model, attacks))
    elif attacks:
        print(f"\n攻击夹具：检出 {attacks['tp']}/{attacks['malicious']}，漏检 {attacks['misses'] or '无'}；"
              f"正常夹具误报 {attacks['fp'] or '无'}")
    if args.examples:
        for reason, value in item["by_reason"].items():
            print(f"\n## {reason}")
            for example in value["examples"]:
                print(f"- [{example['decision']}] {example['tool']} {example['session'][:8]}: {example['input']}")
    if args.json:
        out = pathlib.Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        keys = ("session", "outcome", "steps", "reason_codes", "decisions", "reviews", "analyses")
        out.write_text(json.dumps({
            "summary": item, "model": model, "attacks": attacks, "disabled": disabled,
            "judge": {key: value for key, value in (judge or {}).items() if key != "key"},
            "manifest": {key: value for key, value in manifest.items() if key != "sessions"},
            "rows": [{key: row.get(key) for key in keys} for row in rows],
            "attack_rows": [{key: row.get(key) for key in ("fixture", "scenario", "outcome", "first_risk", "steps",
                                                          "reviews", "analyses")} for row in attack_rows],
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n明细：{out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
