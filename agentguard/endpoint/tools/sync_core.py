#!/usr/bin/env python3
"""把服务端 agentguard/core/ 下的无状态判定模块复制进终端客户端（agentguard_endpoint/core/）。

终端与服务端共用同一份能力展开与判定代码，保证“本地拒绝 ⊆ 服务端拒绝”。这些模块只依赖
标准库与彼此（相对导入），可原样复制；两边的 __init__.py 各自维护，不同步。改动服务端 core/ 后执行本脚本；
tests/test_endpoint.py 会校验两份内容一致。

    python3 endpoint/tools/sync_core.py          # 同步
    python3 endpoint/tools/sync_core.py --check  # 只检查，不一致时退出码 1
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.normpath(os.path.join(HERE, "..", "..", "agentguard", "core"))
CORE = os.path.normpath(os.path.join(HERE, "..", "agentguard_endpoint", "core"))


def modules() -> list[str]:
    return sorted(name for name in os.listdir(SERVER) if name.endswith(".py") and name != "__init__.py")


def stale() -> list[str]:
    out = []
    for name in modules():
        source, target = os.path.join(SERVER, name), os.path.join(CORE, name)
        with open(source, "rb") as handle:
            wanted = handle.read()
        try:
            with open(target, "rb") as handle:
                current = handle.read()
        except FileNotFoundError:
            current = None
        if current != wanted:
            out.append(name)
    return out


def main(argv: list) -> int:
    names = stale()
    if "--check" in argv:
        for name in names:
            print(f"out of sync: core/{name}")
        return 1 if names else 0
    for name in names:
        shutil.copy2(os.path.join(SERVER, name), os.path.join(CORE, name))
        print(f"synced core/{name}")
    if not names:
        print("core is up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
