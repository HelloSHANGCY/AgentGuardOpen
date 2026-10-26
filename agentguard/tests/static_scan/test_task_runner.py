"""后台任务安装生命周期、自启动范围、断线重连与本地项目上下文。"""

import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "endpoint"))
from agentguard_endpoint import autostart, install, static_scan, task_runner


@pytest.fixture
def runner_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp_path / "client"))
    monkeypatch.setenv("AGENTGUARD_SYSTEM_DIR", str(tmp_path / "system"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return tmp_path


def test_enable_registers_only_installed_client_and_never_passes_token_in_arguments(runner_home, monkeypatch):
    calls = []
    monkeypatch.delenv("AGENTGUARD_TASK_RUNNER")
    monkeypatch.setenv("AGENTGUARD_TOKEN", "do-not-place-in-argv")
    monkeypatch.setattr(autostart, "register", lambda command: calls.append(command) or "test-login")
    monkeypatch.setattr(task_runner, "start", lambda: True)
    task_runner.enable(str(runner_home / "installed client"), "/custom/python")
    assert calls[0][0] == "/custom/python"
    assert calls[0][1] == str(runner_home / "installed client/agentguard-endpoint.py")
    assert "task-runner" in calls[0] and "--config-dir" in calls[0]
    assert "do-not-place-in-argv" not in json.dumps(task_runner.settings())


def test_linux_user_service_and_desktop_fallback_are_scoped_and_removed(runner_home, monkeypatch):
    monkeypatch.setattr(autostart.cfg, "WINDOWS", False)
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart.shutil, "which", lambda _: "/bin/systemctl")
    monkeypatch.setattr(autostart, "_run", lambda args: True)
    command = ["/a b/client", "task-runner", "--config-dir", "/custom/100%/$name"]
    assert autostart.register(command) == "systemd-user"
    unit = next((runner_home / "xdg/systemd/user").glob("*.service"))
    assert 'ExecStart="/a b/client"' in unit.read_text() and '100%%/$$name' in unit.read_text()
    monkeypatch.setattr(autostart, "_run", lambda args: False)
    assert autostart.register(command) == "desktop-login"
    desktop = next((runner_home / "xdg/autostart").glob("*.desktop"))
    assert "--autostart" in desktop.read_text()
    autostart.remove()
    assert not unit.exists() and not desktop.exists()


def test_windows_login_registry_command_has_correct_argument_quoting(runner_home, monkeypatch):
    captured = []

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    registry = SimpleNamespace(HKEY_CURRENT_USER=1, KEY_SET_VALUE=2, REG_SZ=3,
        CreateKeyEx=lambda *args: Key(), OpenKey=lambda *args: Key(),
        SetValueEx=lambda *args: captured.append(args), DeleteValue=lambda *args: captured.append(args))
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(autostart.cfg, "WINDOWS", True)
    assert autostart.register([r"C:\Program Files\AgentGuard\client.exe", "task-runner"]) == "windows-login"
    assert captured[0][-1].startswith('"C:\\Program Files\\AgentGuard\\client.exe" task-runner')
    assert captured[0][-1].endswith("--autostart")
    autostart.remove()
    assert captured[-1][-1] == autostart.identity()


def test_reconnect_after_network_failure_does_not_need_hook_or_relaunch(runner_home, monkeypatch):
    stopped = threading.Event()
    attempts = []
    monkeypatch.setattr(task_runner.cfg, "load", lambda agent: {"agent": agent, "url": "http://local", "token": "test"})

    class Stop:
        def is_set(self):
            return stopped.is_set()

        def wait(self, seconds):
            attempts.append(seconds)

    calls = []

    def request(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise OSError("disconnected")
        return {"job": {"agent": "claude-code", "scan_id": "scan-reconnected"}}

    monkeypatch.setattr(task_runner.net, "request", request)
    monkeypatch.setattr(static_scan, "upload_job", lambda *args: stopped.set())
    task_runner._serve(["claude-code"], Stop(), lambda *args, **kwargs: None)
    assert len(calls) == 2 and 2 <= attempts[0] < 3


def test_workspace_cache_is_local_agent_specific_and_expires(runner_home, monkeypatch):
    for name in ("CLAUDE_PROJECT_DIR", "CODEBUDDY_PROJECT_DIR", "TRAE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    project = str(runner_home / "project")
    assert static_scan.remember_workspace("codex", {"cwd": project}) == project
    assert static_scan.recent_workspace("codex") == project
    assert static_scan.recent_workspace("claude-code") == ""
    task_runner._write("static-workspace-codex.json", {"path": project, "at": time.time() - 86401})
    assert static_scan.recent_workspace("codex") == ""
    assert static_scan.remember_workspace("codex", {"cwd": "/bad\x00path"}) == ""


def test_partial_uninstall_keeps_other_agent_and_last_uninstall_disables_channel(runner_home, monkeypatch):
    task_runner._write("install.json", {"agents": ["claude-code", "codex"]})
    task_runner._write(task_runner.CONFIG, {"enabled": True})
    task_runner.forget_agent("claude-code", False)
    assert task_runner.installed_agents() == ["codex"] and task_runner.settings()["enabled"]
    task_runner.forget_agent("codex", False)
    assert not task_runner.installed_agents() and not task_runner.settings()["enabled"]


def test_custom_install_uninstall_registration_cannot_overwrite_default_instance(runner_home, monkeypatch):
    custom_key = install.uninstall_key()
    assert custom_key.startswith(install.UNINSTALL_KEY + "-")
    monkeypatch.setattr(install.cfg, "user_dir", lambda: str(Path.home() / ".agentguard"))
    assert install.uninstall_key() == install.UNINSTALL_KEY
    assert custom_key != install.uninstall_key()
