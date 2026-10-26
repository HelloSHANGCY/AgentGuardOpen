"""任务通道随当前用户登录启动；只管理 AgentGuard 自己的启动项。"""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

from . import config as cfg

MARKER = "AgentGuard endpoint scan task channel"


def identity():
    return "agentguard-endpoint-" + hashlib.sha256(os.path.abspath(cfg.user_dir()).encode()).hexdigest()[:12]


def _config_home():
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


def _run(args):
    try:
        return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=5, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _quote(value, systemd=False):
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    value = value.replace("$", "$$" if systemd else "\\$").replace("`", "\\`")
    return '"' + value + '"'


def register(command):
    if any(any(char in arg for char in ("\n", "\r", "\x00")) for arg in command):
        raise OSError("unsupported autostart path")
    name = identity()
    if cfg.WINDOWS:
        import winreg

        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                               0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, subprocess.list2cmdline(command + ["--autostart"]))
        return "windows-login"
    if sys.platform == "darwin":
        path = Path.home() / "Library/LaunchAgents" / ("ai." + name + ".plist")
        path.parent.mkdir(parents=True, exist_ok=True)
        label = "ai." + name
        path.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": command,
                                        "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                                        "ThrottleInterval": 10}))
        _run(["launchctl", "bootout", "gui/" + str(os.getuid()), str(path)])
        if _run(["launchctl", "bootstrap", "gui/" + str(os.getuid()), str(path)]):
            return "launchd"
        return "macos-login"
    path = _config_home() / "systemd/user" / (name + ".service")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {MARKER}\n[Unit]\nDescription={MARKER}\nAfter=network-online.target\n\n"
                    "[Service]\nType=simple\nExecStart=" + " ".join(_quote(arg, True) for arg in command)
                    + "\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n", encoding="utf-8")
    if shutil.which("systemctl") and _run(["systemctl", "--user", "daemon-reload"]) \
            and _run(["systemctl", "--user", "enable", "--now", path.name]):
        return "systemd-user"
    # 没有用户 systemd 的桌面会话仍可在登录后启动；当前安装立即启动由调用方保证。
    path = _config_home() / "autostart" / (name + ".desktop")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {MARKER}\n[Desktop Entry]\nType=Application\nName=AgentGuard Endpoint\n"
                    + "Exec=" + " ".join(_quote(arg) for arg in command + ["--autostart"])
                    + "\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n", encoding="utf-8")
    return "desktop-login"


def remove():
    name = identity()
    if cfg.WINDOWS:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
        return
    if sys.platform == "darwin":
        path = Path.home() / "Library/LaunchAgents" / ("ai." + name + ".plist")
        if path.exists():
            _run(["launchctl", "bootout", "gui/" + str(os.getuid()), str(path)])
            path.unlink()
        return
    paths = [_config_home() / "systemd/user" / (name + ".service"),
             _config_home() / "autostart" / (name + ".desktop")]
    for path in paths:
        if path.is_file() and MARKER in path.read_text(encoding="utf-8"):
            if path.suffix == ".service" and shutil.which("systemctl"):
                _run(["systemctl", "--user", "disable", "--now", path.name])
            path.unlink()
    if shutil.which("systemctl"):
        _run(["systemctl", "--user", "daemon-reload"])
