#!/usr/bin/env python3
"""Replay the fixed corpus through local checks. No HTTP, shell or tool execution."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentguard.testing.corpus import load_corpus  # noqa: E402
from agentguard.testing.replay import replay_corpus  # noqa: E402


def main():
    records, context, manifest = load_corpus()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["all", *manifest["by_scenario"]], default="all")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    selected = [r for r in records if args.scenario in ("all", r["scenario"])][:args.limit]
    results = replay_corpus(selected, context)
    report = {"dataset_id": manifest["dataset_id"], "total": len(results),
              "rules_source": "builtin",
              "scope": "offline_request_checks", "tool_execution": False,
              "side_effects_verified": False, "business_success_verified": False,
              "network_boundary_verified": False, "full_acceptance_verified": False,
              "outcomes": dict(Counter(row["outcome"] for row in results)), "rows": results}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, ensure_ascii=False, indent=2))
    return int(any(row["outcome"] in ("FP", "FN") for row in results))


if __name__ == "__main__":
    sys.exit(main())
