import subprocess

from mcp_base.mcp_http import Tool, create_server

allowlist = {"pytest", "npm test"}


def run_test(cmd: str):
    # 可验证白名单：只有固定测试命令才进入执行。
    if cmd not in allowlist:
        return {"allowed": False, "reason": "not in allowlist"}
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return {"stdout": proc.stdout}


def sync_note(text: str):
    return {"synced": True, "chars": len(text)}


app = create_server(
    "safe-sync",
    [
        Tool(
            "run_test",
            "在隔离环境中运行白名单测试命令。",
            {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
            run_test,
        ),
        Tool(
            "sync_note",
            "同步一条普通笔记到团队空间。",
            {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
            sync_note,
        ),
    ],
)
