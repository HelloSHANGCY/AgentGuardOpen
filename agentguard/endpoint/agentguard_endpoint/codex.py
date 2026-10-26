"""Codex 专属：定位 codex 可执行文件，经 `codex app-server` 登记 Hook 信任（Windows / Linux / macOS）。

Codex 的用户级 Hook（$CODEX_HOME/hooks.json）要登记信任后才会执行，信任记录在 config.toml 的
hooks.state."<key>".trusted_hash 中。TUI 里的 /hooks 审核和下面的 app-server 调用（hooks/list +
config/batchWrite）写法相同；Windows 上的 Codex 桌面版没有 /hooks，只能用后一种方式。

Windows 上 Codex 用 `powershell.exe -NoProfile -Command <command>` 执行 Hook 命令（实测 codex-cli
0.159），因此 Hook 命令按 PowerShell 语法写成 `& "<exe>" hook --agent codex`。
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import threading

from . import config as cfg

MARKER = "agentguard"
APP_SERVER_TIMEOUT = 30


def find_codex(explicit: str = "") -> str:
    """codex 可执行文件：显式指定 > PATH > Codex 桌面版内置（Windows）> VS Code 扩展内置，同类取最新。"""
    if explicit:
        return explicit
    found = shutil.which("codex")
    if found:
        return found
    patterns = [os.path.expanduser("~/.vscode*/extensions/openai.chatgpt-*/bin/*/codex" + (".exe" if cfg.WINDOWS else ""))]
    if cfg.WINDOWS:
        local = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
        patterns.insert(0, os.path.join(local, "OpenAI", "Codex", "bin", "*", "codex.exe"))
    for pattern in patterns:
        candidates = sorted(glob.glob(pattern), key=os.path.getmtime)
        if candidates:
            return candidates[-1]
    return ""


def version(codex: str) -> str:
    try:
        out = subprocess.run([codex, "--version"], capture_output=True, text=True, timeout=15,
                             encoding="utf-8", errors="replace").stdout.strip()
        return out.split()[-1] if out else ""
    except (OSError, subprocess.SubprocessError):
        return ""


class AppServer:
    """`codex app-server` 的最小 JSON-RPC（stdio，换行分隔）客户端，只用于读 Hook 列表与写配置。"""

    def __init__(self, codex: str, home: str) -> None:
        self.proc = subprocess.Popen([codex, "app-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
                                     env={**os.environ, "CODEX_HOME": home})
        # app-server 无响应时不能让安装卡住。
        self.watchdog = threading.Timer(APP_SERVER_TIMEOUT, self.proc.kill)
        self.watchdog.start()
        self.next_id = 0
        self.call("initialize", {"clientInfo": {"name": "agentguard-endpoint", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "initialized"})

    def _send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def call(self, method: str, params: dict) -> dict:
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        for line in self.proc.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message["result"]
        raise RuntimeError(f"{method}: app-server exited")

    def hooks(self, cwd: str) -> list:
        data = self.call("hooks/list", {"cwds": [cwd]})["data"]
        return [hook for entry in data for hook in entry["hooks"]]

    def close(self) -> None:
        self.watchdog.cancel()
        self.proc.kill()
        self.proc.wait()


def _ours(hooks: list) -> list:
    return [hook for hook in hooks if MARKER in str(hook.get("command", "")).lower()]


def trust_hooks(codex: str, home: str, events) -> list:
    """登记 AgentGuard Hook 的信任哈希；返回仍未生效的 hook key 或事件（空表示全部 trusted / managed）。"""
    server = AppServer(codex, home)
    cwd = os.path.expanduser("~")
    try:
        pending = {hook["key"]: {"trusted_hash": hook["currentHash"]} for hook in _ours(server.hooks(cwd))
                   if hook.get("trustStatus") not in ("trusted", "managed")}
        if pending:
            server.call("config/batchWrite", {"edits": [{"keyPath": "hooks.state", "mergeStrategy": "upsert",
                                                         "value": pending}]})
        status = _ours(server.hooks(cwd))
    finally:
        server.close()
    registered = {hook["eventName"][:1].upper() + hook["eventName"][1:] for hook in status}
    return ([hook["key"] for hook in status if hook.get("trustStatus") not in ("trusted", "managed")]
            + sorted(set(events) - registered))
