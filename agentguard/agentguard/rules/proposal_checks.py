"""规则建议的检查与回放：从会话步骤取样、判断哪些发现是静态规则漏报、在正常语料 / 真实放行调用 / 夹具样本上
试跑候选规则，以及在独立进程中回放 Claude Code 夹具并与基线逐步对比。

都是无状态函数；缓存、并发与流程编排在 proposals.RuleProposals。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from . import library as R

BENIGN_EVENT_WINDOW = 2000
REPLAY_TIMEOUT = 120
EXAMPLES = 5
# 静态规则“已拦住”的结果标签：命中这些标签的工具返回不算漏报。
CAUGHT_RESULT_LABELS = {"POISONED_RESULT", "PROMPT_INJECTION_SUSPECT", "LOCAL_ENFORCED", "RELAY_BYPASS"}
MISSED_SEVERITIES = ("medium", "high", "critical")


def leaves(value, out: list, depth: int = 0) -> None:
    if depth > 6 or len(out) > 200:
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            leaves(item, out, depth + 1)
    elif isinstance(value, list):
        for item in value:
            leaves(item, out, depth + 1)


def step_samples(step: dict) -> list[str]:
    """一个步骤用于匹配的样本：原文、JSON 参数中的各个字符串值、规范化后的资源（去掉能力前缀）。"""
    text = str(step.get("text") or "")
    samples = [text] if text else []
    try:
        leaves(json.loads(text), samples)
    except ValueError:
        pass
    resource = str(step.get("resource") or "")
    if ":" in resource:
        samples.append(resource.split(":", 1)[1])
    return [sample[:R.MAX_SAMPLE_LEN] for sample in dict.fromkeys(samples) if sample.strip()]


def caught(step: dict) -> bool:
    decision = step.get("decision")
    if decision and decision["static"] in ("DENY", "ASK"):
        return True
    return bool(set(step.get("labels") or []) & CAUGHT_RESULT_LABELS)


def missed_findings(record: dict, steps_by_number: dict) -> list[dict]:
    """中危及以上、且至少一步没有被静态规则拦住的发现。"""
    result = []
    for finding in record.get("findings") or []:
        if finding.get("severity") not in MISSED_SEVERITIES:
            continue
        steps = [steps_by_number[n] for n in finding.get("steps") or [] if n in steps_by_number]
        if any(step["kind"] != "prompt" and not caught(step) for step in steps):
            result.append(finding)
    return result


def benign_samples() -> list[str]:
    """内置正常开发语料（行为基线训练集）中的提示词与工具参数。"""
    from ..detection.behavior_corpus import SESSIONS

    samples = []
    for prompt, _cwd, calls in SESSIONS:
        samples.append(prompt)
        for _tool, arguments in calls:
            leaves(arguments, samples)
    return list(dict.fromkeys(samples))


def fixture_samples() -> list[tuple[str, bool, str]]:
    """Claude Code 夹具中的样本：(夹具编号, 是否恶意, 样本)，含提示词、调用参数、工具返回与工具描述。"""
    from ..agents.cc_fixtures import fixtures

    rows = []
    for fixture in fixtures():
        found = []
        for step in fixture["steps"]:
            leaves({key: value for key, value in step.items() if key not in ("expect", "risk", "session")}, found)
        rows += [(fixture["id"], fixture["malicious"], sample[:R.MAX_SAMPLE_LEN])
                 for sample in dict.fromkeys(found) if sample.strip()]
    return rows


def nomatch_samples(library) -> list[tuple[str, str]]:
    """现有规则（内置与自定义）自带的反例样本：(规则编号, 样本)。"""
    if library is None:
        return []
    return [(rule.rule_id, sample) for pack in library.packs() for rule in pack.rules
            for sample in (rule.tests or {}).get("nomatch", [])]


def replay_diff(base: dict, candidate: dict) -> dict:
    """逐步对比回放结果：正常夹具新增拦截 / 需确认为误报，恶意夹具由漏报变为拦住为新增覆盖。"""
    before = {row["fixture"]: row for row in base["rows"]}
    benign, detected, changed = [], [], []
    for row in candidate["rows"]:
        old = before.get(row["fixture"])
        if old is None:
            continue
        for index, (prev, step) in enumerate(zip(old["steps"], row["steps"]), 1):
            if prev["got"] == step["got"]:
                continue
            entry = {"fixture": row["fixture"], "scenario": row["scenario"], "step": index, "tool": step["tool"],
                     "input": step.get("input", ""), "before": prev["got"], "after": step["got"],
                     "reason": step["reason"]}
            if not row["malicious"] and step["got"] in ("ask", "deny"):
                benign.append(entry)
            else:
                changed.append(entry)
        if row["malicious"] and old["outcome"] == "FN" and row["outcome"] == "TP":
            detected.append(row["fixture"])
    return {"fixtures": len(candidate["rows"]), "benign_total": sum(1 for row in candidate["rows"]
                                                                    if not row["malicious"]),
            "benign_blocked": len(benign), "benign_examples": benign[:EXAMPLES * 2],
            "newly_detected": detected, "changed": changed[:EXAMPLES * 2],
            "baseline_fn": sum(1 for row in base["rows"] if row["malicious"] and row["outcome"] == "FN")}


def problems(checks: dict) -> list[str]:
    """检查结果中仍需解决的问题（为空即通过）。"""
    if checks.get("error"):
        return [f"规则校验失败：{checks['error']}"]
    found = []
    if not checks.get("evidence"):
        found.append("未命中本次会话的证据")
    replay = checks.get("replay") or {}
    if replay.get("benign_blocked"):
        found.append(f"回放：正常夹具中 {replay['benign_blocked']} 步会被新增拦截或需确认")
    for key, label in (("fixture_benign_hits", "正常夹具样本"), ("corpus_hits", "正常开发语料"),
                       ("recent_hits", "最近放行的真实调用"), ("nomatch_hits", "现有规则的反例样本")):
        if checks.get(key):
            found.append(f"{label}命中 {checks[key]} 条")
    return found


def candidate_rule(compiled: R.Rule) -> dict:
    """已编译规则 → 回放用规则包中的规则（不带样本自检）。"""
    rule = {"group": compiled.group, "title": compiled.title or "candidate", "severity": compiled.severity}
    if R.GROUPS[compiled.group].kind == "regex":
        rule["patterns"] = [{"re": item["re"], "flags": list(item["flags"])} if item["flags"] else item["re"]
                            for item in compiled.sources]
    else:
        rule["keywords"] = list(compiled.sources)
    return rule


def subprocess_replay(library, extra: dict) -> dict:
    """导出规则目录（现有规则 + extra 中的规则包），在独立进程中回放夹具（见 rules/replay.py）。"""
    with tempfile.TemporaryDirectory(prefix="ag-rule-replay-") as directory:
        library.export(directory, extra)
        done = subprocess.run([sys.executable, "-m", "agentguard.rules.replay", directory], capture_output=True,
                              text=True, timeout=REPLAY_TIMEOUT, cwd=str(Path(__file__).resolve().parents[2]),
                              env={**os.environ, "PYTHONWARNINGS": "ignore"})
    if done.returncode != 0:
        raise RuntimeError((done.stderr.strip().splitlines() or ["replay failed"])[-1][:200])
    return json.loads(done.stdout)


def recent_allowed_samples(store, window: int = BENIGN_EVENT_WINDOW, exclude_trace: str = "") -> list[str]:
    """最近放行（未被拦截 / 需确认）的 Hook 调用参数，作为真实正常样本。"""
    events, decisions = store.recent_calls(window)
    samples = []
    for event in events:
        if exclude_trace and event.trace_id == exclude_trace:
            continue
        decision = decisions.get(event.decision_id)
        if decision is not None and decision.decision in ("DENY", "ASK"):
            continue
        record = None
        for evidence_id in event.evidence_ids:
            record = store.get_evidence(evidence_id, include_content=True)
            if record:
                break
        text = (record or {}).get("content") or event.redacted_preview or ""
        found = []
        try:
            leaves(json.loads(text), found)
        except ValueError:
            found = [text]
        samples.extend(sample[:R.MAX_SAMPLE_LEN] for sample in found if sample.strip())
    return list(dict.fromkeys(samples))
