"""Request-only replay: inspect stored payloads without running any tool or target."""

import json
import time
from collections import Counter

import yaml

from ..config import Settings
from ..core.normalize import (
    escapes_root,
    injection_markers,
    is_system_path,
    langflow_code_threats,
    normalize_path,
    scoped_signatures,
)
from ..core.payloads import BLOCKING_CODE_THREATS, DOT_RUN_RE
from ..detection.engine import OPENAI_ROUTES, ManifestView, RuntimeDecisionEngine
from ..models import Actor, TaskContext, ToolRequest
from ..rules.library import RuleLibrary


def _iter_replay_corpus(records: list[dict], context: dict):
    # Explicit in-memory configuration prevents use of local models, records or credentials.
    engine = RuntimeDecisionEngine(Settings(
        upstreams={}, data_dir="", runtime_db_path="", agent_device_dir="", behavior_dir="",
        intent_llm_key="", c2_hosts=("c2-sink",),
        disabled_features=frozenset({"intent_llm", "llm_judge"}),
    ))
    manifests = context["manifests"]
    poisoned = {server for server, tools in manifests.items()
                if any(injection_markers(tool["description"] or "") for tool in tools if not tool["hidden"])}
    for record in records:
        started = time.monotonic()
        kinds = Counter()
        reasons = []
        trace = record["instance_id"]
        if record["input"].get("exploit"):
            sample = context["http_samples"][trace]
            if "json" in sample:
                threats = set(langflow_code_threats(sample["json"]["code"])) & BLOCKING_CODE_THREATS
                blocked = bool(threats)
                reasons.extend(sorted(threats))
            else:
                name = sample["filename"]
                normalized = normalize_path(name)
                blocked = (normalized.startswith("/") or escapes_root(normalized)
                           or is_system_path(normalized) or bool(DOT_RUN_RE.search(name)))
                reasons.extend(["PATH_TRAVERSAL"] if blocked else [])
            kinds["DENY" if blocked else "ALLOW"] += 1
        else:
            skill = {}
            labels = ["USER_INPUT"]
            skill_name = record["input"].get("skill")
            if skill_name:
                text = context["skills"][skill_name]
                metadata = yaml.safe_load(text.split("---", 2)[1])
                skill = {"name": skill_name, "allowed_tools": metadata.get("allowed-tools") or []}
                if injection_markers(text):
                    labels.append("UNTRUSTED_SKILL")
            task = TaskContext(trace_id=trace, task_id=trace, actor=Actor(**record["actor"]),
                               intent_summary=record["input"]["prompt"], active_skill=skill,
                               source_labels=labels, agent="mcp", policy_profile="service")
            for step in record["trajectory"]:
                for call in step.get("tool_calls") or []:
                    function = call["function"]
                    server, tool = OPENAI_ROUTES[function["name"]]
                    arguments = function["arguments"]
                    if isinstance(arguments, str):
                        arguments = json.loads(arguments)
                    request = ToolRequest(trace_id=trace, instance_id=trace, server=server,
                                          tool=tool, arguments=arguments, agent="mcp")
                    view = ManifestView(known_tools={item["name"] for item in manifests[server] if not item["hidden"]},
                                        poisoned_servers=poisoned)
                    decision = engine.evaluate(request, task, None, view)
                    kinds[decision.decision] += 1
                    reasons.append(decision.reason_code)
                # Stop at the first denied/confirmation-required turn. No execution is invented.
                if kinds["ASK"] or kinds["DENY"]:
                    break
        blocked = bool(kinds["ASK"] or kinds["DENY"])
        outcome = ("TP" if blocked else "FN") if record["malicious"] else ("FP" if blocked else "TN")
        yield {"instance_id": trace, "case": trace, "scenario": record["scenario"],
               "malicious": record["malicious"], "outcome": outcome,
               "decisions": dict(kinds), "reasons": reasons,
               "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
               "effect_ok": None, "business_ok": None}


def iter_replay_corpus(records: list[dict], context: dict, rules: RuleLibrary | None = None):
    """Stream checks with built-in rules, leaving online signatures and counters untouched."""
    rules = rules if rules is not None else RuleLibrary()
    values = rules.signatures()
    results = _iter_replay_corpus(records, context)
    while True:
        # Restore the caller's context before yielding progress or accepting cancellation.
        with scoped_signatures(values, rules.record_keyword_hit):
            try:
                result = next(results)
            except StopIteration:
                return
        yield result


def replay_corpus(records: list[dict], context: dict) -> list[dict]:
    return list(iter_replay_corpus(records, context))
