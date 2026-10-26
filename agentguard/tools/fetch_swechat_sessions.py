#!/usr/bin/env python3
"""从 SWE-chat（SALT-NLP/SWE-chat，ODC-BY，需在 Hugging Face 同意条款）抽样下载真实 Claude Code 会话的原始记录，
作为正常开发流量的误报评测集（tools/benign_replay.py 回放）。

    hf auth login                                   # 交互输入令牌，不要写进命令行或文件
    python3 tools/fetch_swechat_sessions.py --list-agents
    python3 tools/fetch_swechat_sessions.py --sample 300 --seed 1337

先读 sessions.parquet（每会话一行，体积小）按 Agent 与工具调用数筛选并按种子抽样，再逐个下载
transcripts/{session_id}.jsonl（Claude Code 原生会话记录，与 Hook 负载同源）。
输出到 data/benign/swechat/（已在 .gitignore 中，原始会话不进仓库）：manifest.json 记录抽样参数与会话元数据，
transcripts/ 存原始记录。已下载的文件不重复下载，同一种子与参数得到同一批会话。
--sample 小于上次时，manifest 只列本次抽到的会话，回放以 manifest 为准。
"""

import argparse
import json
import pathlib
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = "SALT-NLP/SWE-chat"
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "benign" / "swechat"
COLUMNS = ["session_id", "agent", "user_id", "repo_id", "tool_call_count", "transcript_path", "created_at"]


def read_sessions(revision: str | None = None) -> tuple[list[dict], str]:
    import pyarrow as pa
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download

    path = pathlib.Path(hf_hub_download(REPO, "sessions.parquet", repo_type="dataset", revision=revision))
    resolved_revision = path.parent.name
    table = pq.read_table(path, columns=COLUMNS)
    table = table.set_column(COLUMNS.index("created_at"), "created_at", table["created_at"].cast(pa.string()))
    return table.to_pylist(), resolved_revision


def download_rows(rows: list[dict], out: pathlib.Path, revision: str, workers: int = 8) -> None:
    from huggingface_hub import hf_hub_download

    out.mkdir(parents=True, exist_ok=True)

    def fetch(row: dict) -> None:
        relative = pathlib.Path(row["transcript_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("transcript path must stay inside the dataset directory")
        path = out / relative
        if not path.is_file():
            path = pathlib.Path(hf_hub_download(REPO, str(relative), repo_type="dataset", revision=revision,
                                              local_dir=out))
        row["local_path"] = str(path.relative_to(out))

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(fetch, row) for row in rows]):
            future.result()
            done += 1
            if done % 50 == 0 or done == len(rows):
                print(f"[{done}/{len(rows)}] downloaded", flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list-agents", action="store_true", help="只统计各 Agent 的会话数")
    parser.add_argument("--agent", default="Claude Code")
    parser.add_argument("--sample", type=int, default=300, help="抽样会话数（0 = 全部符合条件的会话）")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--min-tools", type=int, default=5, help="工具调用数下限：过短的会话没有评测价值")
    parser.add_argument("--max-tools", type=int, default=600, help="工具调用数上限：控制单会话回放时间")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", default=str(OUT))
    parser.add_argument("--revision", help="固定数据集 commit；默认解析当前 revision 后固定下载")
    args = parser.parse_args(argv)

    sessions, revision = read_sessions(args.revision)
    if args.list_agents:
        counts = {}
        for row in sessions:
            counts[row["agent"]] = counts.get(row["agent"], 0) + 1
        for agent, count in sorted(counts.items(), key=lambda item: -item[1]):
            print(f"{count:6d}  {agent}")
        return 0

    eligible = sorted((row for row in sessions if row["agent"] == args.agent and row["transcript_path"]
                       and args.min_tools <= (row["tool_call_count"] or 0) <= args.max_tools),
                      key=lambda row: row["session_id"])
    chosen = random.Random(args.seed).sample(eligible, min(args.sample, len(eligible))) if args.sample else eligible
    print(f"符合条件 {len(eligible)} 个会话，抽取 {len(chosen)} 个")

    out = pathlib.Path(args.out)
    download_rows(chosen, out, revision, args.workers)
    manifest = {"source": REPO, "agent": args.agent, "seed": args.seed, "sample": args.sample,
                "min_tools": args.min_tools, "max_tools": args.max_tools, "eligible": len(eligible), "revision": revision,
                "sessions": sorted(chosen, key=lambda row: row["session_id"])}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"written {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
