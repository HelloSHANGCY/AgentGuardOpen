"""Load the fixed synthetic corpus as data, checking integrity before use."""

import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

DATASET = Path(__file__).resolve().parents[2] / "resources/testing/range-v1"


def load_corpus(directory: Path = DATASET) -> tuple[list[dict], dict, dict]:
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("dataset_id") != "range-v1":
        raise ValueError("unsupported corpus manifest")
    contents = {}
    for name in ("events.jsonl.gz", "context.json"):
        data = (directory / name).read_bytes()
        expected = manifest["files"][name]
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError(f"corpus integrity mismatch: {name}")
        contents[name] = data
    rows = [json.loads(line) for line in gzip.decompress(contents["events.jsonl.gz"]).decode("utf-8").splitlines()]
    if (len(rows) != manifest["total"] or len({row["instance_id"] for row in rows}) != len(rows)
            or [row["t"] for row in rows] != list(range(len(rows)))
            or any(type(row["malicious"]) is not bool for row in rows)
            or sum(row["malicious"] for row in rows) != manifest["malicious"]
            or sum(not row["malicious"] for row in rows) != manifest["benign"]
            or dict(Counter(row["scenario"] for row in rows)) != manifest["by_scenario"]):
        raise ValueError("corpus population mismatch")
    return rows, json.loads(contents["context.json"]), manifest
