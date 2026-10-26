#!/usr/bin/env python3
"""从 SWE-chat（SALT-NLP/SWE-chat，ODC-BY，需在 Hugging Face 同意条款）抽取带意图标签的用户提示词，
用于意图识别的离线评测（创新检测实施方案 §5 意图偏离）。

    python3 -m venv .venv-intent && . .venv-intent/bin/activate
    pip install -U huggingface_hub pyarrow
    hf auth login                       # 交互输入令牌，不要写进命令行或文件
    python3 tools/fetch_swechat_prompts.py --list          # 先看文件结构
    python3 tools/fetch_swechat_prompts.py --max-groups 5  # 试抽前 5 个行组
    python3 tools/fetch_swechat_prompts.py                 # 抽取全部提示词

conversations.parquet 约 6.4 GB（1161 个行组）。先远程读取几个小列定位带意图标签的行，
再只读取这些行组的 content 列，不落地整个文件。
输出 data/intent/swechat_prompts.jsonl（已在 .gitignore 中，原始提示词不进仓库）。
"""

import argparse
import json
import pathlib
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = "SALT-NLP/SWE-chat"
REMOTE = f"datasets/{REPO}/conversations.parquet"
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "intent" / "swechat_prompts.jsonl"
META = ["session_id", "turn_number", "is_first_turn", "agent", "language", "prompt_intent", "prompt_pushback"]
MAX_CHARS = 2000      # 意图只看开头；超长的日志粘贴截断


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="只列出数据集文件")
    parser.add_argument("--max-groups", type=int, default=0, help="最多处理几个行组（0 = 全部）")
    parser.add_argument("--workers", type=int, default=8, help="并发读取的线程数")
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args(argv)

    import pyarrow.parquet as pq
    from huggingface_hub import HfApi, HfFileSystem

    if args.list:
        for item in HfApi().list_repo_tree(REPO, repo_type="dataset", recursive=True):
            print(item.path, getattr(item, "size", ""))
        return 0
    local = threading.local()

    def parquet():
        # 每个线程一个远程文件句柄：fsspec 文件对象不是线程安全的。
        if not hasattr(local, "file"):
            local.file = pq.ParquetFile(HfFileSystem().open(REMOTE, "rb", block_size=8 << 20))
        return local.file

    def extract(group: int) -> list[dict]:
        meta = parquet().read_row_group(group, columns=META).to_pylist()
        rows = [index for index, row in enumerate(meta) if row.get("prompt_intent")]
        if not rows:
            return []
        content = parquet().read_row_group(group, columns=["content"]).column("content")
        return [{**meta[index], "row_group": group, "content": text[:MAX_CHARS]}
                for index in rows if (text := content[index].as_py())]

    total = parquet().metadata.num_row_groups
    groups = list(range(total))[:args.max_groups or total]
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    kept = done = 0
    with open(out_path, "w", encoding="utf-8") as out, ThreadPoolExecutor(args.workers) as pool:
        for future in as_completed([pool.submit(extract, group) for group in groups]):
            for row in future.result():
                out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            kept += len(future.result())
            done += 1
            if done % 50 == 0 or done == len(groups):
                print(f"[{done}/{len(groups)}] 累计 {kept} 条", flush=True)
    print(f"written {out_path} ({kept} prompts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
