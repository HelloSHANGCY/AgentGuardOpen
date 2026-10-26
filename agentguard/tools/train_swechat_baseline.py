#!/usr/bin/env python3
"""从已下载的 SWE-chat 训练离线候选基线，不执行工具、不请求模型、不自动启用。

    python3 tools/train_swechat_baseline.py
    python3 tools/train_swechat_baseline.py --register-dir /path/to/behavior

原始会话没有逐调用安全标签；默认只做记录质量清洗，规则命中作为复核标记。
归属与授权沿用确定性规则，行为分数仍是辅助信号。
"""

import argparse
import hashlib
import json
import math
import pathlib
import sys
import time
import uuid
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benign_replay import transcript_fixture  # noqa: E402

from agentguard.core import capability as C  # noqa: E402
from agentguard.core import fastpath as F  # noqa: E402
from agentguard.core.toolmap import classify_builtin  # noqa: E402
from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection import behavior as B  # noqa: E402

SOURCE = "SALT-NLP/SWE-chat"
SOURCE_URL = "https://huggingface.co/datasets/SALT-NLP/SWE-chat"
POLICY_VERSION = "swechat-quality/2"
SOURCE_WEIGHTS = {"corpus": 0.25, "swechat": 0.75}


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def encoded(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def prepare_dataset_code_hashes() -> dict:
    return {name: digest((ROOT / name).read_bytes()) for name in (
        "tools/train_swechat_baseline.py", "tools/swechat_baseline_experiment.py", "tools/fetch_swechat_sessions.py",
        "tools/benign_replay.py", "agentguard/core/toolmap.py", "agentguard/core/capability.py",
        "agentguard/core/fastpath.py", "agentguard/core/normalize.py", "agentguard/core/shell.py", "agentguard/detection/anomaly.py",
        "agentguard/detection/behavior.py")}


def group_key(row: dict) -> str:
    for field in ("repo_id", "user_id", "session_id"):
        if row.get(field):
            return digest(f"{field}:{row[field]}")
    raise ValueError("session_id is required")


def holdout_groups(groups: set[str], ratio: float, seed: int) -> set[str]:
    if not math.isfinite(ratio) or not 0 < ratio < 0.9:
        raise ValueError("holdout must be within (0, 0.9)")
    if len(groups) < 2:
        raise ValueError("at least two independent groups are required")
    ordered = sorted(groups, key=lambda group: digest(f"{seed}:{group}"))
    count = min(len(groups) - 1, max(1, round(len(groups) * ratio)))
    return set(ordered[:count])


def review_reasons(tool: str, calls: list, symbols: list[str], cwd: str, root: str, rules) -> list[str]:
    reasons = {hit["reason_code"] for hit in F.check_calls(rules, calls, cwd, (root,))}
    if tool.startswith("mcp__") or not calls or any(call.capability == C.MCP_CALL for call in calls):
        reasons.add("UNMODELED_TOOL")
    for call in calls:
        if call.sink:
            reasons.add("NETWORK_SINK")
        if call.capability == C.EXEC and not A.command_profile(call.resource)["complete"]:
            reasons.add("INCOMPLETE_COMMAND")
    for symbol in symbols:
        if symbol.startswith("EXEC:unknown"):
            reasons.add("UNMODELED_COMMAND")
        if symbol.startswith("EXEC:pipe_exec"):
            reasons.add("DOWNLOAD_EXEC")
        if symbol.startswith(("FILE_READ:", "FILE_WRITE:")) and symbol.split(":")[1] in {
            "credential_store", "project_secret", "agent_config", "persistence", "system"
        }:
            reasons.add("SENSITIVE_RESOURCE")
    return sorted(reasons)


def exclusion_reasons(tool: str, calls: list, symbols: list[str], cwd: str, root: str, rules, *,
                      cleaning: str = "quality") -> list[str]:
    if cleaning == "strict":
        return review_reasons(tool, calls, symbols, cwd, root, rules)
    reasons = []
    if not tool or not calls or not symbols:
        reasons.append("NO_SYMBOLS")
    if any(call.capability == C.EXEC and not A.command_profile(call.resource)["complete"] for call in calls):
        reasons.append("INCOMPLETE_COMMAND")
    return reasons


def behavior_session(fixture: dict, group: str, rules, *, cleaning: str = "quality",
                     review_exclusions: set[str] | None = None) -> tuple[dict, dict]:
    """使用当前生命周期语义；缺失、过滤、并行、失败不能制造新的相邻转移。"""
    slots, pending, seen = [], {}, set()
    states = {None: A.BehaviorState()}
    context, cwd = None, fixture["cwd"]
    counts = Counter()
    reasons = Counter()
    review_flags = Counter()
    review_marks = []
    for step in fixture["steps"]:
        if step.get("cut"):
            slots.append({"cut": True})
            for state in states.values():
                state.prev = None
        elif "prompt" in step:
            states[None].set_prompt(step["prompt"])
        elif "cwd" in step:
            cwd = step["cwd"]
        elif "subagent" in step:
            slots.append({"cut": True})
            context = step["subagent"]
            if context not in states:
                states[context] = A.BehaviorState()
                states[context].intents = list(states[None].intents)
        elif "pre" in step:
            key = step.get("call")
            if not key or key in seen:
                counts["duplicate_or_missing_call_id"] += 1
                slots.append({"cut": True})
                continue
            seen.add(key)
            counts["calls"] += 1
            calls = classify_builtin(step["pre"], step["input"], cwd)
            symbols = A.symbols(calls, cwd)
            excluded = exclusion_reasons(step["pre"], calls, symbols, cwd, fixture["cwd"], rules, cleaning=cleaning)
            call_hash = digest(f"{fixture['session']}:{key}")
            if call_hash in (review_exclusions or set()):
                excluded.append("REVIEW_EXCLUDED")
            flags = review_reasons(step["pre"], calls, symbols, cwd, fixture["cwd"], rules)
            if flags:
                review_marks.append({"call_hash": call_hash, "reasons": flags})
                review_flags.update(flags)
            state = states[context]
            state.register(key, key, {"symbols": symbols, "intents": list(state.intents), "executes": True})
            pending[key] = (state, len(slots), excluded)
            slots.append({"cut": True})
        elif "post" in step or "fail" in step:
            entry = pending.pop(step.get("call"), None)
            if entry is None:
                continue
            state, index, excluded = entry
            item = state.complete(step["call"], step["call"], "failed" if "fail" in step else "succeeded")
            if excluded:
                counts["excluded_calls"] += 1
                reasons.update(excluded)
            elif item and item["symbols"]:
                slots[index] = {key: item[key] for key in (
                    "symbols", "intents", "execution", "cut_before", "cut_after")}
                counts["kept_steps"] += 1
                counts[item["execution"]] += 1
            else:
                counts["excluded_calls"] += 1
                reasons["NO_SYMBOLS"] += 1
    for _, _, excluded in pending.values():
        counts["excluded_calls"] += 1
        reasons.update(set(excluded) | {"MISSING_RESULT"})
    session = {"key": "swechat-" + digest(fixture["session"]), "source": "swechat", "group": group,
               "device": "", "agent": "claude-code", "steps": slots}
    counts["review_flagged_steps"] = len(review_marks)
    return session, {**dict(counts), "reasons": dict(sorted(reasons.items())),
                     "review_flags": dict(sorted(review_flags.items())), "review_marks": review_marks}


def prepare_dataset(data: pathlib.Path, ratio: float = 0.2, seed: int = 1337, *, cleaning: str = "quality",
                    review_exclusions: set[str] | None = None) -> dict:
    manifest_path = data / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("source") != SOURCE or manifest.get("agent") != "Claude Code":
        raise ValueError("expected the SWE-chat Claude Code manifest")
    rows = sorted(manifest["sessions"], key=lambda row: row["session_id"])
    identifiers = [row["session_id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate session_id in manifest")
    if cleaning not in {"quality", "strict"}:
        raise ValueError("unknown cleaning mode")
    frozen = bool(manifest.get("frozen_split"))
    held = set() if frozen else holdout_groups({group_key(row) for row in rows}, ratio, seed)
    if frozen:
        groups = {name: {group_key(row) for row in rows if row.get("split") == name}
                  for name in ("train", "validation", "test")}
        if any(row.get("split") not in groups for row in rows) or any(
                groups[a] & groups[b] for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))):
            raise ValueError("frozen split contains overlapping groups or unknown partitions")
    pack = F.build_pack("swechat-training", "strict", "claude-code", ("c2-sink",))
    rules = F.compiled(pack)
    train, holdout, test, inputs, hashes = [], [], [], [], set()
    totals, excluded, reviews, diagnostics_total = Counter(), Counter(), Counter(), Counter()
    for index, row in enumerate(rows):
        path = (data / (row.get("local_path") or f"transcripts/{row['session_id']}.jsonl")).resolve()
        if not path.is_relative_to(data.resolve()):
            raise ValueError("transcript path must stay inside the dataset directory")
        # 不静默跳过缺失文件；不能把不完整输入描述为整个清单的训练结果。
        raw = path.read_bytes()
        sha = digest(raw)
        if sha in hashes:
            raise ValueError("duplicate transcript content in manifest")
        hashes.add(sha)
        group = group_key(row)
        diagnostics = {}
        fixture = transcript_fixture(path, row["session_id"], raw=raw, diagnostics=diagnostics)
        diagnostics_total.update(diagnostics)
        session, stats = behavior_session(fixture, group, rules, cleaning=cleaning, review_exclusions=review_exclusions)
        split = row["split"] if frozen else ("validation" if group in held else "train")
        inputs.append({"session": session["key"], "group": group, "split": split,
                       "sha256": sha, "counts": stats})
        totals.update({key: value for key, value in stats.items() if isinstance(value, int)})
        excluded.update(stats["reasons"])
        reviews.update(stats["review_flags"])
        if stats.get("kept_steps"):
            {"train": train, "validation": holdout, "test": test}[split].append(session)
        else:
            totals["empty_sessions"] += 1
            if not stats.get("calls"):
                totals["no_supported_tool_events_sessions"] += 1
        if (index + 1) % 25 == 0 or index + 1 == len(rows):
            print(f"[{index + 1}/{len(rows)}] converted", file=sys.stderr, flush=True)
    if not train or not holdout:
        raise ValueError("screened training and holdout sets must both contain steps")
    meta = {"source": SOURCE, "source_url": SOURCE_URL, "license": "ODC-BY",
            "manifest_sha256": digest(manifest_path.read_bytes()), "inputs_sha256": digest(encoded(inputs)),
            "policy_version": POLICY_VERSION if cleaning == "quality" else "swechat-screen/1",
            "cleaning": cleaning, "review_exclusions_sha256": digest(encoded(sorted(review_exclusions or []))),
            "policy_sha256": F.pack_version(pack),
            "code_sha256": prepare_dataset_code_hashes(),
            "feature_schema_version": A.FEATURE_SCHEMA_VERSION,
            "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION,
            "revision": manifest.get("revision"), "frozen_split": manifest.get("frozen_split"),
            "split": "repository; fallback user; fallback session", "seed": seed, "holdout_ratio": ratio,
            "input_sessions": len(rows), "input_groups": len({item["group"] for item in inputs}),
            "train_groups": len({item["group"] for item in train}),
            "holdout_groups": len({item["group"] for item in holdout}),
            "test_groups": len({item["group"] for item in test}), "test_sessions": len(test),
            "counts": dict(totals), "excluded_reasons": dict(sorted(excluded.items())),
            "review_flags": dict(sorted(reviews.items())), "record_diagnostics": dict(diagnostics_total),
            "record_diagnostics_note": "line-level JSONL parse diagnostics; unsupported document formats may also produce invalid_json_lines",
            "label_status": "unverified_real_development" if cleaning == "quality" else "policy_screened_not_human_verified",
            "holdout_metric": "step_anomaly_trigger_rate_not_verified_false_positive_rate",
            "calibration": "grouped training-only CV; quantile + 0.5; validation/test not used for tuning"}
    if frozen:
        ranks = {"swechat-" + digest(row["session_id"]): row["train_rank"] for row in rows if row["split"] == "train"}
        train.sort(key=lambda item: ranks[item["key"]])
    meta["dataset_sha256"] = digest(encoded({"train": train, "holdout": holdout, "test": test}))
    return {"train": train, "holdout": holdout, "test": test, "meta": meta, "inputs": inputs}


def register_candidate(directory: pathlib.Path, model: dict) -> pathlib.Path:
    version = model["version"]
    if version == B.BUILTIN or not B.VERSION_RE.fullmatch(version) or not A.Baseline.from_dict(model).compatible:
        raise ValueError("expected a compatible candidate version")
    target = directory / "models" / (version + ".json")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(model, ensure_ascii=False, sort_keys=True, indent=1) + "\n")
    return target


def load_review_exclusions(path: pathlib.Path | None) -> set[str]:
    if path is None:
        return set()
    items = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(items, list) or any(not isinstance(item, str) or len(item) != 64 or
                                        any(char not in "0123456789abcdef" for char in item) for item in items):
        raise ValueError("review exclusions must be a JSON array of SHA-256 call hashes")
    return set(items)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=pathlib.Path, default=ROOT / "data/benign/swechat")
    parser.add_argument("--out-dir", type=pathlib.Path)
    parser.add_argument("--holdout", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--quantile", type=float, default=95)
    parser.add_argument("--cleaning", choices=("quality", "strict"), default="quality")
    parser.add_argument("--raw-counts", action="store_true", help="不用来源/会话平衡，仅作对照")
    parser.add_argument("--scoring-mode", choices=("legacy", "backoff", "evidence"), default="legacy")
    parser.add_argument("--evidence-granularity", choices=("event", "session", "group"), default="group")
    parser.add_argument("--evidence-k", type=float, default=20)
    parser.add_argument("--evidence-prior", type=float, default=1)
    parser.add_argument("--review-exclusions", type=pathlib.Path, help="已复核应排除的调用哈希 JSON 数组")
    parser.add_argument("--register-dir", type=pathlib.Path, help="服务端 behavior 目录；只登记候选，不启用")
    args = parser.parse_args(argv)
    try:
        params = B.normalize_params({"use_recorded": False, "personalize": False, "quantile": args.quantile,
                                     "scoring_mode": args.scoring_mode,
                                     "evidence_granularity": args.evidence_granularity,
                                     "evidence_k": args.evidence_k, "evidence_prior": args.evidence_prior})
        exclusions = load_review_exclusions(args.review_exclusions)
        dataset = prepare_dataset(args.data, args.holdout, args.seed, cleaning=args.cleaning, review_exclusions=exclusions)
        version = time.strftime("m%Y%m%d-%H%M%S-", time.gmtime()) + uuid.uuid4().hex[:4]
        model = B.train(params, [], version, compare=A.Baseline.load(), dataset=dataset,
                        source_weights=None if args.raw_counts else SOURCE_WEIGHTS)
        directory = args.out_dir or args.data / "baseline-runs" / version
        directory.mkdir(parents=True, exist_ok=False)
        report = {"version": version, "meta": model["meta"], "source": dataset["meta"],
                  "registered": False, "activated": False}
        for name, value in (("model.json", model), ("dataset.json", dataset)):
            (directory / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=1) + "\n",
                                          encoding="utf-8")
        if args.register_dir:
            target = register_candidate(args.register_dir, model)
            report.update(registered=True, registered_model=str(target))
        (directory / "report.json").write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=1) + "\n",
                                               encoding="utf-8")
        print(json.dumps({"version": version, "directory": str(directory), "registered": report["registered"],
                          "activated": False, "meta": model["meta"]}, ensure_ascii=False, indent=1))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"SWE-chat training failed: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
