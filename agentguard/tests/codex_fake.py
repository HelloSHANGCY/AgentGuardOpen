"""最小 codex app-server 替身（测试共用）：hooks/list 按 hooks.json 计算 key/hash，config/batchWrite 记录
hooks.state 与其他改动（_edits），config/read 返回一个 stdio 与一个远程 MCP server。"""

import pathlib

FAKE_CODEX = r'''#!/usr/bin/env python3
"""最小 codex app-server 替身：hooks/list 按 hooks.json 计算 key/hash，config/batchWrite 记录 hooks.state。"""
import hashlib, json, os, sys
home = os.environ["CODEX_HOME"]
state_path = os.path.join(home, "trust-state.json")
if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.159.2"); sys.exit(0)
def state():
    try: return json.load(open(state_path))
    except OSError: return {}
def hooks():
    try: data = json.load(open(os.path.join(home, "hooks.json")))
    except OSError: return []
    out, trusted = [], state()
    snake = lambda name: "".join("_" + c.lower() if c.isupper() else c for c in name).lstrip("_")
    for event, groups in data.get("hooks", {}).items():
        for gi, group in enumerate(groups):
            for hi, hook in enumerate(group.get("hooks", [])):
                key = f"{home}/hooks.json:{snake(event)}:{gi}:{hi}"
                digest = "sha256:" + hashlib.sha256(json.dumps([group.get("matcher"), hook], sort_keys=True).encode()).hexdigest()
                out.append({"key": key, "eventName": event[0].lower() + event[1:], "command": hook["command"],
                            "currentHash": digest, "isManaged": False,
                            "trustStatus": "trusted" if trusted.get(key, {}).get("trusted_hash") == digest else "untrusted"})
    return out
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg: continue
    method, params, result = msg["method"], msg.get("params") or {}, {}
    if method == "hooks/list":
        result = {"data": [{"cwd": params["cwds"][0], "hooks": hooks(), "warnings": [], "errors": []}]}
    elif method == "config/batchWrite":
        current = state()
        for edit in params["edits"]:
            if edit["keyPath"] == "hooks.state":
                current.update(edit["value"])
            else:
                current.setdefault("_edits", []).append(edit)
        json.dump(current, open(state_path, "w"))
        result = {"status": "ok"}
    elif method == "config/read":
        result = {"config": {"mcp_servers": {"notes": {"command": "npx", "args": ["-y", "notes-mcp"]},
                                             "remote": {"url": "https://mcp.example/x"}}}}
    print(json.dumps({"id": msg["id"], "result": result}), flush=True)
'''


def install_fake_codex(directory: pathlib.Path) -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "codex"
    path.write_text(FAKE_CODEX)
    path.chmod(0o755)
    return path
