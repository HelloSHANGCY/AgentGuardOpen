"""Claude Code Hook 客户端端到端：真实 HTTP 服务 + 子进程运行客户端脚本。

验证：服务端决策原样渲染到 stdout；控制台「设备管理」的启停与不可达处理随响应下发并缓存；
服务不可达时按缓存执行（默认不拦截，failsafe 按能力降级表拒绝），事件写入本地缓冲；
服务恢复后在非关键事件上补报并标记 AUDIT_DELAYED。
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CLIENT = ROOT / "tools" / "replay_hook_client.py"
TOKEN = "agd_client_test"
ADMIN = {"x-ag-admin-token": "adm-client-test"}
CWD = "/home/dev/project"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    import uvicorn

    os.environ["AG_AGENT_DEVICES"] = json.dumps({TOKEN: {"device_id": "dev-client", "profile": "developer"}})
    os.environ["AG_AGENT_ADMIN_TOKEN"] = ADMIN["x-ag-admin-token"]
    from agentguard.main import create_app

    app = create_app()
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    instance = uvicorn.Server(config)
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    for _ in range(100):
        if instance.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    instance.should_exit = True
    thread.join(timeout=5)
    os.environ.pop("AG_AGENT_DEVICES", None)
    os.environ.pop("AG_AGENT_ADMIN_TOKEN", None)


def run_hook(url: str, spool: pathlib.Path, payload: dict, **env) -> dict | None:
    environment = dict(os.environ, AGENTGUARD_URL=url, AGENTGUARD_TOKEN=TOKEN, AGENTGUARD_SPOOL=str(spool),
                       HOME=str(spool.parent))
    environment.update(env)
    payload = {"session_id": "cli-1", "cwd": CWD, **payload}
    done = subprocess.run([sys.executable, str(CLIENT)], input=json.dumps(payload), capture_output=True,
                          text=True, env=environment, timeout=20)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout) if done.stdout.strip() else None


def pre(tool: str, tool_input: dict) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}


def test_client_renders_server_decisions(server, tmp_path):
    spool = tmp_path / "spool.jsonl"
    # 代理变量被篡改也不影响：客户端直连 AgentGuard，不读 HTTP(S)_PROXY。
    denied = run_hook(server, spool, pre("Read", {"file_path": "/home/dev/.ssh/id_rsa"}),
                      HTTP_PROXY="http://127.0.0.1:9", http_proxy="http://127.0.0.1:9")
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert run_hook(server, spool, pre("Bash", {"command": "pytest -q"})) is None
    # 大返回被截断并附摘要，服务端仍正常处理。
    big = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {"file_path": f"{CWD}/a.txt"},
           "tool_response": "x" * 50000}
    assert run_hook(server, spool, big) is None
    assert not spool.exists()


def write_control(home: pathlib.Path, **control) -> pathlib.Path:
    path = home / ".agentguard" / "cc-control.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(control))
    return path


def test_client_unreachable_follows_cached_control(server, tmp_path):
    spool = tmp_path / "spool.jsonl"
    down = f"http://127.0.0.1:{_free_port()}"
    # 无缓存 / open（默认）：不拦截，只缓冲审计。
    assert run_hook(down, spool, pre("Bash", {"command": "ls"}), AGENTGUARD_TIMEOUT_PRE="0.3") is None
    # failsafe：按能力降级表拒绝执行、出网、MCP 与工作区外写入。
    control = write_control(tmp_path, enabled=True, fail_mode="failsafe")
    for tool, tool_input in [("Bash", {"command": "ls"}), ("WebFetch", {"url": "https://x"}),
                             ("mcp__github__create_issue", {}), ("Write", {"file_path": "/etc/x", "content": ""})]:
        result = run_hook(down, spool, pre(tool, tool_input), AGENTGUARD_TIMEOUT_PRE="0.3")
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny", tool
        assert "AGENTGUARD_UNAVAILABLE" in result["hookSpecificOutput"]["permissionDecisionReason"]
    for tool, tool_input in [("Read", {"file_path": f"{CWD}/a.py"}),
                             ("Write", {"file_path": f"{CWD}/a.py", "content": ""}), ("Grep", {"pattern": "x"})]:
        assert run_hook(down, spool, pre(tool, tool_input), AGENTGUARD_TIMEOUT_PRE="0.3") is None, tool
    # 已停止：直接放行，不缓冲。
    write_control(tmp_path, enabled=False, fail_mode="failsafe")
    assert run_hook(down, spool, pre("Bash", {"command": "ls"}), AGENTGUARD_TIMEOUT_PRE="0.3") is None
    lines = spool.read_text().splitlines()
    assert len(lines) == 8 and all(json.loads(line)["_ag"]["delayed"] for line in lines)

    # 服务恢复：非关键事件触发补报，缓冲清空，服务端记录 AUDIT_DELAYED。
    assert run_hook(server, spool, {"hook_event_name": "Stop"}) is None
    assert not spool.exists()
    import httpx

    chain = httpx.get(f"{server}/v1/runtime/traces/cc-dev-client-cli-1").json()["chain"]
    delayed = [node for node in chain if "AUDIT_DELAYED" in node["labels"]]
    assert len(delayed) == 8 and sum("LOCAL_DENY" in node["labels"] for node in delayed) == 4
    # 服务端响应附带的管控配置覆盖本地缓存。
    cached = json.loads(control.read_text())
    assert cached["enabled"] is True and cached["fail_mode"] == "open"


def test_client_misconfigured_token_follows_fail_mode(server, tmp_path):
    spool = tmp_path / "spool.jsonl"
    assert run_hook(server, spool, pre("Bash", {"command": "ls"}), AGENTGUARD_TOKEN="bad") is None
    write_control(tmp_path, enabled=True, fail_mode="failsafe")
    result = run_hook(server, spool, pre("Bash", {"command": "ls"}), AGENTGUARD_TOKEN="bad")
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_console_stops_and_restarts_hook(server, tmp_path):
    import httpx

    spool = tmp_path / "spool.jsonl"
    secret = pre("Read", {"file_path": "/home/dev/.ssh/id_rsa"})
    url = f"{server}/v1/admin/hooks"
    assert httpx.get(url, trust_env=False).status_code == 401
    try:
        stopped = httpx.put(url + "/claude-code", json={"enabled": False}, headers=ADMIN, trust_env=False).json()
        assert stopped["enabled"] is False and stopped["updated_at"]
        # 已停止：服务端直接放行且不记录，客户端缓存停止状态；服务不可达时也直接放行、不缓冲。
        assert run_hook(server, spool, dict(secret, session_id="stopped-1")) is None
        assert json.loads((tmp_path / ".agentguard" / "cc-control.json").read_text())["enabled"] is False
        assert httpx.get(f"{server}/v1/runtime/traces/cc-dev-client-stopped-1", trust_env=False).json()["chain"] == []
        down = f"http://127.0.0.1:{_free_port()}"
        assert run_hook(down, spool, pre("Bash", {"command": "ls"}), AGENTGUARD_TIMEOUT_PRE="0.3") is None
        assert not spool.exists()

        assert httpx.put(url + "/claude-code", json={"fail_mode": "closed"}, headers=ADMIN,
                         trust_env=False).status_code == 400
        assert httpx.put(url + "/cursor", json={"enabled": True}, headers=ADMIN, trust_env=False).status_code == 404
        overview = httpx.get(url, headers=ADMIN, trust_env=False).json()
        agent = next(a for a in overview["agents"] if a["agent"] == "claude-code")
        assert agent["enabled"] is False and agent["devices"] == 1 and agent["last_seen"]
        device = next(d for d in overview["devices"] if d["device_id"] == "dev-client")
        assert device["client"].startswith("cc-hook/") and overview["fail_modes"] == ["open", "failsafe"]
    finally:
        httpx.put(url + "/claude-code", json={"enabled": True, "fail_mode": "open"}, headers=ADMIN, trust_env=False)
    denied = run_hook(server, spool, dict(secret, session_id="stopped-2"))
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
