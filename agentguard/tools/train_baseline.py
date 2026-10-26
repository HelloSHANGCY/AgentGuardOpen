#!/usr/bin/env python3
"""重新生成内置行为基线 agentguard/detection/baseline/transitions.json（创新检测实施方案 §5）。

    python3 tools/train_baseline.py            # 用内置语料训练并写出内置模型
    python3 tools/train_baseline.py --check    # 只打印评估报告，不写文件

默认模型使用随项目分发的 SWE-chat 固定训练分区加 49 个内置会话，采用三阶递归插值；
原始一阶模型保存在 transitions.legacy.json，可在控制台启用 builtin-legacy 回滚。
训练与评估逻辑在 agentguard/detection/behavior.py，两处共用。
"""

import argparse
import gzip
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection import behavior as B  # noqa: E402
from agentguard.detection import behavior_datasets as D  # noqa: E402

DATASET_ID = "swechat-quality-20261017"
BUILTIN_PARAMS = {"use_corpus": True, "use_recorded": False, "personalize": False,
                  "dataset_id": DATASET_ID, "scoring_mode": "interpolated", "markov_order": 3,
                  "evidence_k": 20, "evidence_prior": 5, "quantile": 99, "threshold": 0}


def build() -> dict:
    directory = ROOT / "resources" / "behavior" / "datasets" / DATASET_ID
    manifest = json.loads((directory / "manifest.json").read_bytes())
    raw = gzip.decompress((directory / "sessions.json.gz").read_bytes())
    if D.digest(raw) != manifest["sha256"]:
        raise ValueError("packaged training dataset checksum mismatch")
    dataset = json.loads(raw)
    D.validate(dataset, manifest["reserved_test"]["groups_sha256"])
    model = B.train(BUILTIN_PARAMS, [], B.BUILTIN, now=0, dataset=dataset, source_weights=D.SOURCE_WEIGHTS)
    model.pop("created_at", None)   # 内置模型可复现：不带时间戳
    model["meta"]["promotion"] = {"selection": "user_requested_default",
                                   "validation": "historical_diagnostic_only",
                                   "dataset_sha256": manifest["sha256"],
                                   "rollback": B.LEGACY_BUILTIN}
    model["meta"]["training_code_sha256"] = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (
            pathlib.Path(__file__), ROOT / "agentguard/detection/anomaly.py",
            ROOT / "agentguard/detection/behavior.py", ROOT / "agentguard/detection/behavior_markov.py",
            ROOT / "agentguard/detection/behavior_evidence.py")}
    return model


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=A.BASELINE_PATH)
    parser.add_argument("--check", action="store_true", help="只打印，不写文件")
    args = parser.parse_args(argv)
    model = build()
    print(json.dumps(model["meta"], ensure_ascii=False, indent=1))
    if not args.check:
        pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.out).write_text(json.dumps(model, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                                          encoding="utf-8")
        print(f"written {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
