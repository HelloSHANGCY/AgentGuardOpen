#!/usr/bin/env python3
"""AgentGuard 终端客户端入口（脚本形式；PyInstaller 也以此为入口打包 exe）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentguard_endpoint.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
