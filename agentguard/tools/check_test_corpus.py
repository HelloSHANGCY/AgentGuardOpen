#!/usr/bin/env python3
"""Verify the complete offline regression corpus without Docker or network."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentguard.testing.corpus import load_corpus  # noqa: E402


def main():
    rows, _, manifest = load_corpus()
    print(json.dumps({"dataset_id": manifest["dataset_id"], "integrity": "pass", "total": len(rows),
                      "benign": manifest["benign"], "malicious": manifest["malicious"],
                      "by_scenario": manifest["by_scenario"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
