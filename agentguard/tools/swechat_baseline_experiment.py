#!/usr/bin/env python3
"""固定仓库验证/测试集，扩充 SWE-chat 并比较嵌套训练规模；只生成候选。

    python3 tools/swechat_baseline_experiment.py --revision <commit> --out-dir <new-directory>
    python3 tools/swechat_baseline_experiment.py --out-dir <same-directory> --resume

旧 300 样本的留出部分只作为开发验证；新测试仓库从未出现在旧 300 样本中。
"""

import argparse
import copy
import json
import os
import pathlib
import sys
import time
import uuid
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import fetch_swechat_sessions as D  # noqa: E402
import train_swechat_baseline as S  # noqa: E402

from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection import behavior as B  # noqa: E402


def save(path: pathlib.Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    temporary.replace(path)


def round_robin(rows: list[dict], seed: int) -> list[dict]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[S.group_key(row)].append(row)
    groups = sorted(grouped, key=lambda group: S.digest(f"{seed}:{group}"))
    for group in groups:
        grouped[group].sort(key=lambda row: S.digest(f"{seed}:{row['session_id']}"))
    return [grouped[group][index] for index in range(max(map(len, grouped.values()), default=0))
            for group in groups if index < len(grouped[group])]


def sampling_plan(eligible: list[dict], original: dict, seed: int, maximum: int,
                  test_count: int = 100) -> dict:
    old = original["sessions"]
    old_groups = {S.group_key(row) for row in old}
    validation_groups = S.holdout_groups(old_groups, 0.2, seed)
    validation = [{**row, "split": "validation"} for row in old if S.group_key(row) in validation_groups]
    initial = [{**row, "split": "train"} for row in old if S.group_key(row) not in validation_groups]
    if maximum < len(initial):
        raise ValueError("maximum training size is smaller than the original training set")
    unseen = [row for row in eligible if S.group_key(row) not in old_groups]
    unseen_groups = sorted({S.group_key(row) for row in unseen}, key=lambda group: S.digest(f"test:{seed}:{group}"))
    if len(unseen_groups) < 2:
        raise ValueError("not enough previously unseen repositories for an independent test")
    test_groups = set(unseen_groups[:min(20, max(1, len(unseen_groups) // 5))])
    test = [{**row, "split": "test"} for row in round_robin(
        [row for row in unseen if S.group_key(row) in test_groups], seed)[:test_count]]
    if len(test) < test_count:
        raise ValueError("not enough independent test sessions")
    used = {row["session_id"] for row in old}
    additional = round_robin([row for row in eligible if row["session_id"] not in used and
                              S.group_key(row) not in validation_groups | test_groups], seed)
    training = initial + [{**row, "split": "train"} for row in additional[:maximum - len(initial)]]
    if len(training) != maximum:
        raise ValueError("not enough independent training sessions")
    for index, row in enumerate(training):
        row["train_rank"] = index
    return {"source": S.SOURCE, "agent": "Claude Code", "seed": seed,
            "frozen_split": {"format": 1, "validation": "previously_observed_development_validation",
                             "test": "previously_unseen_repositories; evaluated_after_all_models_frozen",
                             "training_sizes": sorted({len(initial), maximum, *([1000] if maximum >= 1000 else [])}),
                             "source_weights": S.SOURCE_WEIGHTS, "quantile": 95},
            "sessions": training + validation + test}


def stage_dataset(dataset: dict, size: int) -> dict:
    selected = {**dataset, "train": dataset["train"][:size], "meta": copy.deepcopy(dataset["meta"])}
    if not selected["train"]:
        raise ValueError("no quality-cleaned training sessions for stage")
    selected["meta"].update(training_limit=len(selected["train"]), requested_training_sessions=size,
                            train_groups=len({item["group"] for item in selected["train"]}),
                            dataset_sha256=S.digest(S.encoded({key: selected[key] for key in ("train", "holdout", "test")})))
    keys = {item["key"] for item in selected["train"]}
    counts = Counter()
    for item in dataset["inputs"]:
        if item["session"] in keys:
            counts.update({key: value for key, value in item["counts"].items() if isinstance(value, int)})
    selected["meta"]["training_counts"] = dict(counts)
    return selected


def evaluate_test(baseline: A.Baseline, sessions: list[dict]) -> dict:
    rows = [B.score_session(baseline, session) for session in sessions]
    over = sum(score["anomalous"] for row in rows for score in row)
    steps = sum(map(len, rows))
    return {"sessions": len(rows), "steps": steps, "over_threshold": over,
            "step_trigger_rate": over / steps if steps else None,
            "sessions_over_threshold": sum(any(score["anomalous"] for score in row) for row in rows)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--original", type=pathlib.Path, default=ROOT / "data/benign/swechat")
    parser.add_argument("--out-dir", type=pathlib.Path, required=True)
    parser.add_argument("--revision")
    parser.add_argument("--max-train", type=int, default=3000)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args(argv)
    out = args.out_dir.resolve()
    if out.exists() and not args.resume:
        parser.error("output directory exists; use --resume")
    out.mkdir(parents=True, exist_ok=True)
    data = out / "data"
    data.mkdir(exist_ok=True)
    plan_path = out / "sampling-plan.json"
    if plan_path.is_file():
        manifest = json.loads(plan_path.read_text())
        if args.revision and args.revision != manifest["revision"]:
            raise ValueError("resume revision differs from the frozen sampling plan")
        if manifest["frozen_split"]["source_weights"] != S.SOURCE_WEIGHTS:
            raise ValueError("source weights differ from the frozen sampling plan")
    else:
        rows, revision = D.read_sessions(args.revision)
        eligible = [row for row in rows if row["agent"] == "Claude Code" and row["transcript_path"] and
                    5 <= (row["tool_call_count"] or 0) <= 600]
        original_bytes = (args.original / "manifest.json").read_bytes()
        original = json.loads(original_bytes)
        manifest = sampling_plan(eligible, original, original["seed"], args.max_train)
        manifest.update(revision=revision, original_manifest_sha256=S.digest(original_bytes),
                        eligible=len(eligible))
        save(plan_path, manifest)
    status = {"phase": "download", "revision": manifest["revision"], "activated": False,
              "partitions": dict(Counter(row["split"] for row in manifest["sessions"]))}
    save(out / "status.json", status)
    print(json.dumps(status), flush=True)
    # 旧数据硬链接复用，只读使用；所有新增下载与原清单隔离。
    original_bytes = (args.original / "manifest.json").read_bytes()
    if S.digest(original_bytes) != manifest["original_manifest_sha256"]:
        raise ValueError("original validation manifest differs from the frozen sampling plan")
    old = json.loads(original_bytes)
    originals = {row["session_id"]: args.original / (row.get("local_path") or row["transcript_path"])
                 for row in old["sessions"]}
    for row in manifest["sessions"]:
        source = originals.get(row["session_id"])
        target = (data / row["transcript_path"]).resolve()
        if not target.is_relative_to(data.resolve()):
            raise ValueError("transcript path escapes experiment data directory")
        if source and not source.resolve().is_relative_to(args.original.resolve()):
            raise ValueError("original transcript path escapes original dataset directory")
        if source and source.is_file() and not target.exists():
            metadata = args.original / ".cache/huggingface/download" / source.relative_to(args.original)
            metadata = metadata.with_suffix(metadata.suffix + ".metadata")
            cached_revision = metadata.read_text().splitlines()[0] if metadata.is_file() else old.get("revision")
            if cached_revision == manifest["revision"]:
                target.parent.mkdir(parents=True, exist_ok=True)
                os.link(source, target)
    D.download_rows(manifest["sessions"], data, manifest["revision"], args.workers)
    save(data / "manifest.json", manifest)
    if args.download_only:
        status["phase"] = "downloaded"
        save(out / "status.json", status)
        return 0
    status["phase"] = "prepare"
    save(out / "status.json", status)
    prepared_path = out / "dataset.json"
    if prepared_path.is_file():
        dataset = json.loads(prepared_path.read_text())
        if dataset["meta"]["code_sha256"] != S.prepare_dataset_code_hashes():
            raise ValueError("prepared dataset code differs; use a new experiment directory")
        if dataset["meta"]["manifest_sha256"] != S.digest((data / "manifest.json").read_bytes()):
            raise ValueError("prepared dataset manifest differs from the frozen input")
        paths = {"swechat-" + S.digest(row["session_id"]): data / row["local_path"] for row in manifest["sessions"]}
        for item in dataset["inputs"]:
            if S.digest(paths[item["session"]].read_bytes()) != item["sha256"]:
                raise ValueError("prepared transcript content differs from the frozen input")
    else:
        dataset = S.prepare_dataset(data, seed=manifest["seed"])
        save(prepared_path, dataset)
    status["phase"] = "train"
    save(out / "status.json", status)
    models = []
    sizes = sorted(set(manifest["frozen_split"]["training_sizes"]))
    for size in sizes:
        stage = stage_dataset(dataset, size)
        for mode in ("raw", "balanced"):
            path = out / f"model-{size}-{mode}.json"
            if path.is_file():
                model = json.loads(path.read_text())
                if (model["meta"]["external_source"]["dataset_sha256"] != stage["meta"]["dataset_sha256"] or
                        bool(model["meta"].get("source_balance")) != (mode == "balanced") or
                        not A.Baseline.from_dict(model).compatible):
                    raise ValueError("saved candidate differs from the frozen stage")
            else:
                version = time.strftime("m%Y%m%d-%H%M%S-", time.gmtime()) + uuid.uuid4().hex[:4]
                model = B.train({"use_recorded": False, "personalize": False,
                                 "quantile": manifest["frozen_split"]["quantile"]}, [], version, dataset=stage,
                                source_weights=S.SOURCE_WEIGHTS if mode == "balanced" else None,
                                compare=A.Baseline.load())
                save(path, model)
            models.append((size, mode, model))
            status.update(completed_models=len(models), total_models=len(sizes) * 2)
            save(out / "status.json", status)
            print(f"trained {size} {mode}: threshold={model['threshold']}, assessment={model['meta']['assessment']['verdict']}",
                  flush=True)
    # 所有候选与训练参数已经冻结，至此才访问独立测试分数。
    status["phase"] = "test"
    save(out / "status.json", status)
    rows = []
    for size, mode, model in models:
        rows.append({"training_sessions": model["meta"]["external_sessions"], "requested_training_sessions": size,
                     "mode": mode, "version": model["version"],
                     "model_sha256": S.digest((out / f"model-{size}-{mode}.json").read_bytes()),
                     "threshold": model["threshold"], "training_steps": model["meta"]["external_steps"],
                     "validation_steps": model["meta"]["holdout_steps"],
                     "validation_over_threshold": model["meta"]["holdout_over_threshold"],
                     "test": evaluate_test(A.Baseline.from_dict(model), dataset["test"]),
                     "fixture_benign": [model["meta"]["fixture_benign_over_threshold"], model["meta"]["fixture_benign_steps"]],
                     "fixture_risk": [model["meta"]["fixture_risk_over_threshold"], model["meta"]["fixture_risk_steps"]],
                     "auc": model["meta"]["auc"], "assessment": model["meta"]["assessment"]})
    report = {"source": dataset["meta"], "metric": "anomaly_trigger_rate_not_verified_false_positive_rate",
              "activated": False, "builtin_test": evaluate_test(A.Baseline.load(), dataset["test"]), "rows": rows}
    save(out / "report.json", report)
    status["phase"] = "complete"
    save(out / "status.json", status)
    print(json.dumps({"phase": "complete", "report": str(out / "report.json"), "models": len(rows)}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
