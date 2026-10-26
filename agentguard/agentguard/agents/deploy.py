"""客户端部署配置与一键安装 / 卸载脚本（控制台「设备管理 → 客户端部署」）。

安装参数在服务端统一设置，终端不必再逐项传参：
- server_url：终端访问服务端的地址（空表示取请求地址，即管理员打开控制台所用的地址）；
- agents：要接入的 Agent（终端上未安装的 Agent 跳过，系统级安装除外）；
- scope：user（当前用户）/ machine（所有用户、受管 Hook，需要管理员 / root）；
- wait：安装后等待管理员认证的秒数；self_test：认证后自动自检。

一键脚本只负责下载客户端并调用 `setup --url <地址>` / `uninstall --all --purge`；客户端运行时再从
GET /v1/agents/deploy 取最新配置，修改配置后无需重新分发脚本。运行参数（上传方式、超时）属于管控配置，
见 control.py。配置了 AG_AGENT_DEVICE_DIR / AG_DATA_DIR 时持久化到 client-deploy.json。
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone

from .devices import AGENTS

SCOPES = ("user", "machine")
MAX_WAIT = 3600
DEFAULT_DEPLOY = {"server_url": "", "agents": list(AGENTS), "scope": "user", "wait": 600, "self_test": True}
URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~\-/]*)?$")
TEMPLATES = os.path.join(os.path.dirname(__file__), "installers")
# 一键脚本：(模板, 动作)。install.cmd 是 Windows 上可双击运行的包装，内部调用 install.ps1。
SCRIPTS = {
    "install.sh": ("posix.sh", "setup"), "uninstall.sh": ("posix.sh", "uninstall"),
    "install.ps1": ("windows.ps1", "setup"), "uninstall.ps1": ("windows.ps1", "uninstall"),
    "install.cmd": ("windows.cmd", "install"), "uninstall.cmd": ("windows.cmd", "uninstall"),
}
LINUX_BINARY = "agentguard-endpoint-linux-x64.tar.gz"
WINDOWS_PACKAGE = "agentguard-endpoint-windows-x64.zip"


def validate_deploy(changes: dict) -> dict:
    if not isinstance(changes, dict):
        raise ValueError("deploy config must be an object")
    out = {}
    for key, value in changes.items():
        if key == "server_url":
            value = str(value or "").strip().rstrip("/")
            if value and not URL_RE.match(value):
                raise ValueError("server_url must be http(s)://host[:port][/path]")
        elif key == "agents":
            if not isinstance(value, list) or not value or any(agent not in AGENTS for agent in value):
                raise ValueError("unknown agent")
            value = [agent for agent in AGENTS if agent in value]
        elif key == "scope":
            if value not in SCOPES:
                raise ValueError("scope must be user or machine")
        elif key == "wait":
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_WAIT:
                raise ValueError(f"wait must be an integer number of seconds in 0-{MAX_WAIT}")
        elif key == "self_test":
            if not isinstance(value, bool):
                raise ValueError("self_test must be boolean")
        else:
            raise ValueError(f"unknown deploy key: {key}")
        out[key] = value
    return out


class DeployConfig:
    def __init__(self, data_dir: str = "") -> None:
        self._lock = threading.Lock()
        self._path = os.path.join(data_dir, "client-deploy.json") if data_dir else ""
        self._config = {**DEFAULT_DEPLOY, "updated_at": ""}
        if self._path and os.path.exists(self._path):
            try:
                with open(self._path, encoding="utf-8") as handle:
                    data = json.load(handle)
                known = {key: value for key, value in data.items() if key in DEFAULT_DEPLOY}
                self._config.update(validate_deploy(known), updated_at=str(data.get("updated_at") or ""))
            except (OSError, ValueError):
                pass

    def get(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._config))

    def update(self, changes: dict) -> dict:
        changes = validate_deploy(changes)
        with self._lock:
            self._config.update(changes, updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
            if self._path:
                tmp = self._path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as handle:
                    json.dump(self._config, handle)
                os.replace(tmp, self._path)
            return json.loads(json.dumps(self._config))


def server_url(config: dict, request_base: str) -> str:
    return config.get("server_url") or request_base.rstrip("/")


def render(name: str, url: str, config: dict, published: set) -> str | None:
    """生成一键脚本；name 不在 SCRIPTS 中时返回 None。"""
    if name not in SCRIPTS:
        return None
    template, action = SCRIPTS[name]
    with open(os.path.join(TEMPLATES, template), encoding="utf-8") as handle:
        text = handle.read()
    values = {"URL": url, "SCOPE": config["scope"], "ACTION": action,
              "LINUX_BINARY": LINUX_BINARY if LINUX_BINARY in published else "",
              "WINDOWS_PACKAGE": WINDOWS_PACKAGE if WINDOWS_PACKAGE in published else ""}
    for key, value in values.items():
        text = text.replace(f"__AG_{key}__", value)
    if name.endswith(".cmd"):
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text
