"""把离线清洗结果登记到服务的 behavior/datasets；不修改模型或会话记录。"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentguard.detection.behavior_datasets import publish


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared", type=Path, help="train_swechat_baseline / swechat_baseline_experiment 的 dataset.json")
    parser.add_argument("--directory", type=Path, required=True, help="服务 AG_BEHAVIOR_DIR 下的 datasets 目录或待复制的暂存目录")
    parser.add_argument("--id", required=True, help="唯一登记 ID；相同 ID 不允许覆盖其他内容")
    parser.add_argument("--name", default="SWE-chat")
    args = parser.parse_args()
    manifest = publish(args.prepared, args.directory, args.id, args.name)
    print(json.dumps({k: manifest[k] for k in ("id", "name", "sha256", "train", "holdout")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
