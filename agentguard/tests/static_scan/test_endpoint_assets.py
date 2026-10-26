"""终端资产采集及真实 HTTP/子进程端到端；所有目录、令牌和服务均为临时测试资源。"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "endpoint"))

from agentguard.core.asset_snapshot import AGENT_DIRS, MAX_FILE_BYTES, allowed_path
from agentguard.static_scan.repository import Repository
from agentguard.static_scan.worker import ScanWorker
from agentguard_endpoint import static_scan

ENTRY = ROOT / "endpoint" / "agentguard-endpoint.py"


def write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("agent", list(AGENT_DIRS))
def test_collect_selected_agent_only_and_exclude_private_files(tmp_path, monkeypatch, agent):
    monkeypatch.delenv("CODEX_HOME", raising=False)
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for folders in AGENT_DIRS.values():
        write(home, f"{folders[0]}/settings.json", '{"model":"test-model"}')
        write(home, f"{folders[0]}/skills/demo/SKILL.md", "---\nname: demo\n---\nSafe helper")
        write(home, f"{folders[0]}/auth.json", '{"api_key":"do-not-collect"}')
        write(home, f"{folders[0]}/history.json", '{"chat":"do-not-collect"}')
    write(home, ".agentguard/device-token", "never-read-device-token")
    write(home, ".ssh/id_rsa", "never-read-private-key")
    write(project, f"{AGENT_DIRS[agent][0]}/mcp.json", '{"mcpServers": {}}')
    write(project, "private.py", "never-read-workspace-source")
    user = static_scan.collect(agent, "user", str(project), str(home))
    assert user["files"] and not any(f["path"].startswith("project/") for f in user["files"])
    result = static_scan.collect(agent, "user_project", str(project), str(home))
    assert result["workspace_id"]
    assert any(f["path"].startswith("project/") for f in result["files"])
    assert all(allowed_path(agent, f["path"]) for f in result["files"])
    assert "never-read" not in json.dumps(result) and "do-not-collect" not in json.dumps(result)
    assert {"user", "project"} == {f["path"].split("/")[0] for f in result["files"]}


def test_symlinks_fifos_invalid_json_and_limits_are_coverage_gaps(tmp_path, monkeypatch):
    monkeypatch.delenv("CODEX_HOME", raising=False)
    home = tmp_path / "home"
    write(home, ".claude/settings.json", '{"env":{"API_KEY":"sensitive-local-value"}}')
    write(home, ".claude/settings.local.json", "{")
    write(home, ".claude/skills/demo/SKILL.md", "Safe helper")
    write(home, ".claude/skills/demo/big.py", "x" * (MAX_FILE_BYTES + 1))
    write(home, ".claude/skills/demo/binary.py", "\x00")
    private = write(tmp_path, "outside/private.md", "never-collect-target")
    (home / ".claude/skills/demo/link.md").symlink_to(private)
    (home / ".claude/skills/external").symlink_to(private.parent, target_is_directory=True)
    os.mkfifo(home / ".claude/skills/demo/fifo.py")
    result = static_scan.collect("claude-code", "user_project", str(tmp_path / "gone"), str(home))
    raw = json.dumps(result)
    assert "sensitive-local-value" not in raw and "never-collect-target" not in raw
    assert {"symlink", "special_file", "invalid_config", "file_too_large", "binary", "workspace_unavailable"} <= {
        item["reason"] for item in result["skipped"]}
    monkeypatch.setattr(static_scan, "MAX_FILES", 1)
    bounded = static_scan.collect("claude-code", "user", home=str(home))
    assert len(bounded["files"]) <= 1 and any(item["reason"] == "max_files" for item in bounded["skipped"])
    # Agent 目录本身为链接时也不能遍历或读取目标。
    linked_home = tmp_path / "linked-home"
    linked_home.mkdir()
    (linked_home / ".claude").symlink_to(home / ".claude", target_is_directory=True)
    assert not static_scan.collect("claude-code", "user", home=str(linked_home))["files"]


def test_custom_codex_home_and_secret_environment_references(tmp_path, monkeypatch):
    home, codex_home = tmp_path / "home", tmp_path / "custom-codex"
    home.mkdir()
    write(codex_home, "config.toml", 'model="test"\n[mcp_servers.demo]\ncommand="python"\n[mcp_servers.demo.env]\nAPI_KEY="${EXTERNAL_KEY}"\n')
    write(codex_home, "auth.json", '{"api_key":"never-upload"}')
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    result = static_scan.collect("codex", "user", home=str(home))
    assert [item["path"] for item in result["files"]] == ["user/.codex/config.toml"]
    assert "${EXTERNAL_KEY}" in result["files"][0]["content"]
    assert "never-upload" not in json.dumps(result)


def test_collection_uses_requested_file_limit_before_read_and_after_redaction(tmp_path, monkeypatch):
    home = tmp_path / "home"
    path = ".claude/skills/data/catalog.json"
    content = json.dumps({"data": "x" * (800 * 1024)})
    write(home, path, content)
    default = static_scan.collect("claude-code", "user", home=str(home))
    assert default["files"] == []
    assert default["skipped"] == [{"path": "user/" + path, "reason": "file_too_large"}]
    limits = {"max_file_parse_bytes": 1024 * 1024}
    raised = static_scan.collect("claude-code", "user", home=str(home), limits=limits)
    assert len(raised["files"]) == 1 and raised["skipped"] == []
    assert len(raised["files"][0]["content"].encode()) > MAX_FILE_BYTES
    monkeypatch.setattr(static_scan, "sanitize_text", lambda *args: "x" * (1024 * 1024 + 1))
    assert static_scan.collect("claude-code", "user", home=str(home), limits=limits)["files"] == []
    with pytest.raises(ValueError):
        static_scan.collect("claude-code", "user", home=str(home), limits={"max_file_parse_bytes": 10**10})


def test_background_launch_is_detached_throttled_and_has_no_token_in_arguments(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(static_scan.cfg, "user_dir", lambda: str(tmp_path))
    monkeypatch.setattr(static_scan.subprocess, "Popen", lambda args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.delenv("CODEBUDDY_PROJECT_DIR", raising=False)
    static_scan.maybe_launch("claude-code", {"cwd": str(tmp_path)})
    static_scan.maybe_launch("claude-code", {"cwd": str(tmp_path)})
    assert len(calls) == 1
    arguments, options = calls[0]
    assert arguments[-5:] == ["static-scan", "--agent", "claude-code", "--workspace", str(tmp_path)]
    assert "--token" not in arguments
    assert options["stdin"] == options["stdout"] == options["stderr"] == subprocess.DEVNULL
    assert options.get("start_new_session") or options.get("creationflags")
    # 异常 cwd（例如包含 NUL）导致操作系统拒绝创建进程时，辅助扫描不能打断 Hook。
    monkeypatch.setattr(static_scan.cfg, "user_dir", lambda: str(tmp_path / "invalid"))
    def cannot_spawn(*args, **kwargs):
        raise ValueError("embedded null byte")
    monkeypatch.setattr(static_scan.subprocess, "Popen", cannot_spawn)
    assert static_scan.maybe_launch("claude-code", {"cwd": "/bad\x00path"}) is None


@pytest.fixture
def live_server(tmp_path, monkeypatch):
    import uvicorn

    monkeypatch.setenv("AG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AG_AGENT_DEVICE_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AG_RUNTIME_DB", str(tmp_path / "runtime.db"))
    monkeypatch.setenv("AG_STATIC_DB", str(tmp_path / "static.db"))
    monkeypatch.setenv("AG_STATIC_ENABLED", "1")
    monkeypatch.setenv("AG_EVAL_DB", str(tmp_path / "eval.db"))
    monkeypatch.setenv("AG_STATIC_ADMIN_TOKEN", "static-test")
    monkeypatch.setenv("AG_AGENT_ADMIN_TOKEN", "device-test")
    monkeypatch.setenv("AG_AGENT_DEVICES", json.dumps({"local-device-test": {"device_id": "test-host", "agents": ["claude-code", "codex"]}}))
    monkeypatch.setenv("AG_INTENT_LLM_KEY", "")
    from agentguard.main import create_app

    app = create_app()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.02)
        assert server.started
        yield f"http://127.0.0.1:{port}", Repository(str(tmp_path / "static.db"))
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()


def test_real_hook_background_collection_cli_and_worker(live_server, tmp_path):
    url, repository = live_server
    home = tmp_path / "endpoint-user"
    write(home, ".claude/settings.json", '{"permissions":{"defaultMode":"bypassPermissions"}}')
    write(home, ".claude/skills/helper/SKILL.md", "---\nname: helper\n---\nSafe helper")
    write(home, ".codex/config.toml", '[mcp_servers.demo]\ncommand="python"\n[mcp_servers.demo.env]\nAPI_KEY="private-codex-value"\n')
    env = dict(os.environ, HOME=str(home), AGENTGUARD_HOME=str(home / ".agentguard"),
               AGENTGUARD_SYSTEM_DIR=str(home / ".system"), AGENTGUARD_URL=url, AGENTGUARD_TOKEN="local-device-test")
    env.pop("CODEX_HOME", None)
    headers = {"X-AG-Admin": "static-test"}
    with httpx.Client(base_url=url, timeout=10) as client:
        scan_id = client.post("/v1/static/scans", headers=headers,
                              json={"device_id": "test-host", "agent": "claude-code"}).json()["scan_id"]
        # 停用运行时检测后，资产采集仍可用；不依赖模型审批，也不改变 Hook 输出。
        client.put("/v1/admin/hooks/claude-code", headers={"X-AG-Admin-Token": "device-test"}, json={"enabled": False})
        hook = subprocess.run([sys.executable, str(ENTRY), "hook", "--agent", "claude-code"],
                              input=json.dumps({"hook_event_name": "SessionStart", "session_id": "test", "cwd": str(home)}),
                              capture_output=True, text=True, env=env, timeout=10)
        assert hook.returncode == 0 and not hook.stdout.strip(), hook.stderr
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            record = repository.get_scan(scan_id)
            if record.phase == "QUEUED" and record.source_path:
                break
            time.sleep(0.05)
        assert record.source_path, record.as_dict()
        assert ScanWorker(repository, {}).run_once()
        report = client.get(f"/v1/static/scans/{scan_id}/report", headers=headers).json()
        assert report["scan"]["device_id"] == "test-host" and report["scan"]["agent"] == "claude-code"
        assert "AG-STATIC-CC-001" in {item["rule_id"] for item in report["findings"]}
        codex_id = client.post("/v1/static/scans", headers=headers,
                               json={"device_id": "test-host", "agent": "codex"}).json()["scan_id"]
        command = subprocess.run([sys.executable, str(ENTRY), "static-scan", "--agent", "codex"],
                                 capture_output=True, text=True, env=env, timeout=30)
        assert command.returncode == 0, command.stderr
        assert json.loads(command.stdout)["scan_id"] == codex_id
        assert ScanWorker(repository, {}).run_once()
        assets = repository.get_assets(codex_id, limit=1000)["items"]
        assert {"MCPServer", "AgentApplication", "SecretReference"} <= {item.kind for item in assets}
        report_text = client.get(f"/v1/static/scans/{codex_id}/report", headers=headers).text
        assert "private-codex-value" not in report_text
        assert not list((Path(repository.path).parent / "device-snapshots").glob("*"))


def test_idle_resident_receives_multiple_agents_and_stops_during_long_poll(live_server, tmp_path):
    """真实常驻子进程先空闲等待，管理端创建任务；全程不发送 Hook、不手动运行 static-scan。"""
    from agentguard_endpoint import task_runner

    url, repository = live_server
    home = tmp_path / "idle-user"
    user_dir = home / ".agentguard"
    write(home, ".claude/settings.json", '{"permissions":{"defaultMode":"bypassPermissions"}}')
    write(home, ".codex/config.toml", '[mcp_servers.demo]\ncommand="python"\n')
    write(home, ".claude/skills/data/catalog.json", json.dumps({"catalog": "x" * (800 * 1024)}))
    write(user_dir, "install.json", json.dumps({"agents": ["claude-code", "codex"]}))
    write(user_dir, task_runner.CONFIG, '{"enabled":true}')
    env = dict(os.environ, HOME=str(home), AGENTGUARD_HOME=str(user_dir), AGENTGUARD_SYSTEM_DIR=str(home / ".system"),
               AGENTGUARD_URL=url, AGENTGUARD_TOKEN="local-device-test")
    env.pop("CODEX_HOME", None)
    command = [sys.executable, str(ENTRY), "task-runner"]
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    headers = {"X-AG-Admin": "static-test"}
    try:
        with httpx.Client(base_url=url, timeout=10) as client:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                devices = client.get("/v1/static/devices", headers=headers).json()["devices"]
                device = next(row for row in devices if row["device_id"] == "test-host")
                if device.get("scan_channel"):
                    break
                time.sleep(0.02)
            assert device["scan_channel"]["agents"] == ["claude-code", "codex"]
            assert device["seen_agents"] == {}
            assert subprocess.run(command, env=env, capture_output=True, timeout=3).returncode == 0
            assert process.poll() is None  # 单实例锁不会启动第二个常驻任务进程。
            for agent in ("claude-code", "codex"):
                scan_id = client.post("/v1/static/scans", headers=headers,
                                      json={"device_id": "test-host", "agent": agent,
                                            "limits": {"max_file_parse_bytes": 1024 * 1024}}).json()["scan_id"]
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    record = repository.get_scan(scan_id)
                    if record.source_path:
                        break
                    time.sleep(0.02)
                assert record.source_path, record.as_dict()
                assert ScanWorker(repository, {}).run_once()
                report = client.get(f"/v1/static/scans/{scan_id}/report", headers=headers).json()
                assert report["coverage"]["failed_files"] == 0
                assert report["scan"]["agent"] == agent
                assert report["scan"]["limits"]["max_file_parse_bytes"] == 1024 * 1024
                assert report["coverage"]["skipped_files"] == 0
                if agent == "claude-code":
                    assert report["scan"]["collection"]["bytes"] > 800 * 1024
            before = time.monotonic()
            stopped = subprocess.run(command + ["--stop"], env=env, capture_output=True, timeout=4)
            assert stopped.returncode == 0, stopped.stderr.decode()
            process.wait(timeout=2)
            assert time.monotonic() - before < 3  # 等待连接不能让升级/卸载阻塞到 25 秒以后。
            status = subprocess.run(command + ["--status"], env=env, capture_output=True, text=True, timeout=3)
            assert json.loads(status.stdout)["running"] is False
    finally:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)


def test_disconnected_long_poll_does_not_claim_a_new_offline_task(live_server):
    from urllib.parse import urlparse

    url, repository = live_server
    address = urlparse(url)
    connection = socket.create_connection((address.hostname, address.port), timeout=3)
    connection.sendall((f"GET /v1/agents/static-scan/poll?agents=claude-code&wait=25 HTTP/1.1\r\n"
                        f"Host: {address.netloc}\r\nAuthorization: Bearer local-device-test\r\n\r\n").encode())
    headers = {"X-AG-Admin": "static-test"}
    with httpx.Client(base_url=url, timeout=5) as client:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            row = client.get("/v1/static/devices", headers=headers).json()["devices"][0]
            if row.get("scan_channel"):
                break
            time.sleep(0.02)
        assert row.get("scan_channel")
        connection.close()
        time.sleep(0.1)
        scan_id = client.post("/v1/static/scans", headers=headers,
                              json={"device_id": "test-host", "agent": "claude-code"}).json()["scan_id"]
        time.sleep(0.2)
        assert repository.get_scan(scan_id).phase == "WAITING_ENDPOINT"
