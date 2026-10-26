"""回归测试默认不登记真实系统启动项、不遗留安装器后台进程。"""

import pytest


@pytest.fixture(autouse=True)
def isolate_endpoint_autostart(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_TASK_RUNNER", "0")


@pytest.fixture(autouse=True)
def synthetic_mcp_registry(monkeypatch):
    from agentguard import config

    names = ("customer-db", "shell-runner", "notes-sync", "threat-intel",
             "gitlab", "monitoring", "knowledge", "sandbox-exec")
    monkeypatch.setattr(config, "DEFAULT_UPSTREAMS", {
        name: f"http://mcp-{name}:8000/mcp" for name in names
    })
    monkeypatch.setenv("AG_C2_HOSTS", "c2-sink")
