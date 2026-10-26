"""终端配置与本地文件位置。

文件名与评测用的 tools/replay_hook_client.py（原 clients/claude_code/agentguard_cc_hook.py）一致，
按旧版客户端安装过的主机重新执行 install 即可改用本客户端：
- 系统级（管理员安装，所有用户共用）：Windows `%ProgramData%\\AgentGuard\\`，其他平台 `/etc/agentguard/`；
- 用户级：`~/.agentguard/`（Windows 为 `%USERPROFILE%\\.agentguard\\`）。
设备令牌按主机签发、覆盖主机上的全部 Agent，存于 `device-token`；Codex 旧版单独签发的
`codex-device-token` 若存在则优先（兼容），安装器以新令牌安装时会删除它。
令牌、地址等配置按“环境变量 > 用户级 > 系统级”取值；缓存（管控配置、规则包、缓冲）总在用户级，
因为 Hook 以当前用户身份运行，不一定能写系统目录。

环境变量：
  AGENTGUARD_URL          服务端地址，默认 http://127.0.0.1:18080
  AGENTGUARD_TOKEN        设备令牌；或 AGENTGUARD_TOKEN_FILE 指向令牌文件
  AGENTGUARD_HOME         用户级目录（默认 ~/.agentguard），测试或多实例时使用
  AGENTGUARD_SYSTEM_DIR   系统级目录（默认见上），测试或非标准部署时使用
  AGENTGUARD_TIMEOUT_PRE  PreToolUse 超时秒数，默认 1.5；其他事件 AGENTGUARD_TIMEOUT，默认 1.0
  AGENTGUARD_UPLOAD_MODE  full（默认，服务端脱敏）/ digest（工具返回只传摘要）
上传方式与超时通常在控制台设置（管控配置，随服务端响应下发并缓存），上面三个环境变量只用于本机临时覆盖。
"""

from __future__ import annotations

import json
import os
import sys

AGENTS = ("claude-code", "codex", "trae", "qoder", "zcode", "workbuddy", "codebuddy")
# Agent → 本地文件名（配置 / 令牌 / 缓冲 / 管控缓存 / 规则包缓存）。
AGENT_FILES = {
    "claude-code": {"config": "cc-hook.json", "token": "device-token", "spool": "spool.jsonl",
                    "control": "cc-control.json", "rules": "cc-rules.json", "auth": "cc-auth.json"},
    "codex": {"config": "codex-hook.json", "token": "codex-device-token", "spool": "codex-spool.jsonl",
              "control": "codex-control.json", "rules": "codex-rules.json", "auth": "codex-auth.json"},
    "trae": {"config": "trae-hook.json", "token": "device-token", "spool": "trae-spool.jsonl",
             "control": "trae-control.json", "rules": "trae-rules.json", "auth": "trae-auth.json"},
    "qoder": {"config": "qoder-hook.json", "token": "device-token", "spool": "qoder-spool.jsonl",
              "control": "qoder-control.json", "rules": "qoder-rules.json", "auth": "qoder-auth.json"},
    "zcode": {"config": "zcode-hook.json", "token": "device-token", "spool": "zcode-spool.jsonl",
              "control": "zcode-control.json", "rules": "zcode-rules.json", "auth": "zcode-auth.json"},
    "workbuddy": {"config": "workbuddy-hook.json", "token": "device-token", "spool": "workbuddy-spool.jsonl",
                  "control": "workbuddy-control.json", "rules": "workbuddy-rules.json",
                  "auth": "workbuddy-auth.json"},
    "codebuddy": {"config": "codebuddy-hook.json", "token": "device-token", "spool": "codebuddy-spool.jsonl",
                  "control": "codebuddy-control.json", "rules": "codebuddy-rules.json",
                  "auth": "codebuddy-auth.json"},
}
SHARED_TOKEN = "device-token"
# Trae 的全局数据目录：Trae CN 为 ~/.trae-cn，Trae（国际版）为 ~/.trae；全局 Hook 配置是其中的 hooks.json。
TRAE_DIRS = (".trae-cn", ".trae")
# Qoder 的用户级配置目录：Qoder CN 为 ~/.qoder-cn（实测 1.106，旧版文档写作 ~/.lingma），Qoder（国际版）与 Qoder CLI
# 共用 ~/.qoder；Hook 定义在其中的 settings.json。
QODER_DIRS = (".qoder", ".qoder-cn", ".lingma")
# ZCode 的数据目录 ~/.zcode（桌面端与内置 Agent 共用）；用户级配置是其中的 cli/config.json，Hook 定义在它的 hooks 下。
ZCODE_DIRS = (".zcode",)
ZCODE_CONFIG = os.path.join("cli", "config.json")
# WorkBuddyAI 国际版使用 ~/.workbuddy-ai（Windows 5.7.6 实机核对），国内版使用 ~/.workbuddy（Windows 5.7.7 实机核对），
# Hook 定义在其中的 settings.json。已有目录全部安装，默认使用 WorkBuddyAI。
WORKBUDDY_DIRS = (".workbuddy-ai", ".workbuddy")
# CodeBuddy IDE 的全局 Hook 配置（与 CodeBuddy Code CLI 共用）；编辑器 .codebuddycn 目录不用于 Hook。
CODEBUDDY_DIRS = (".codebuddy",)
DEFAULT_URL = "http://127.0.0.1:18080"
WINDOWS = sys.platform == "win32"


def system_dir() -> str:
    if os.environ.get("AGENTGUARD_SYSTEM_DIR"):
        return os.environ["AGENTGUARD_SYSTEM_DIR"]
    if WINDOWS:
        return os.path.join(os.environ.get("ProgramData") or r"C:\ProgramData", "AgentGuard")
    return "/etc/agentguard"


def user_dir() -> str:
    return os.environ.get("AGENTGUARD_HOME") or os.path.join(os.path.expanduser("~"), ".agentguard")


def install_dir(machine: bool) -> str:
    """exe / 脚本的安装位置。"""
    if WINDOWS:
        if machine:
            return os.path.join(os.environ.get("ProgramFiles") or r"C:\Program Files", "AgentGuard")
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "Programs", "AgentGuard")
    return "/opt/agentguard" if machine else os.path.join(user_dir(), "bin")


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def load(agent: str = "claude-code") -> dict:
    files = AGENT_FILES[agent]
    config: dict = {"agent": agent}
    for directory in (system_dir(), user_dir()):
        config.update(_read_json(os.path.join(directory, files["config"])))
    env = {
        "url": "AGENTGUARD_URL", "token": "AGENTGUARD_TOKEN", "token_file": "AGENTGUARD_TOKEN_FILE",
        "timeout_pre": "AGENTGUARD_TIMEOUT_PRE", "timeout": "AGENTGUARD_TIMEOUT", "upload_mode": "AGENTGUARD_UPLOAD_MODE",
    }
    for key, name in env.items():
        if os.environ.get(name):
            config[key] = os.environ[name]
    config.setdefault("url", DEFAULT_URL)
    config.setdefault("upload_mode", "full")
    home = user_dir()
    for key in ("spool", "control", "rules", "auth"):
        config[key] = os.path.join(home, files[key])
    if not config.get("token"):
        names = list(dict.fromkeys((files["token"], SHARED_TOKEN)))
        candidates = ([config["token_file"]] if config.get("token_file") else []) + [
            os.path.join(directory, name) for directory in (home, system_dir()) for name in names]
        for path in candidates:
            token = _read_text(path)
            if token:
                config["token"] = token
                break
    return config


# 服务端管控配置中的运行参数 → 本机覆盖它的环境变量。
CONTROL_SETTINGS = {"upload_mode": "AGENTGUARD_UPLOAD_MODE", "timeout_pre": "AGENTGUARD_TIMEOUT_PRE",
                    "timeout": "AGENTGUARD_TIMEOUT"}


def apply_control(config: dict, control: dict) -> dict:
    """运行参数优先级：环境变量 > 服务端管控配置（缓存）> 本地配置文件 > 默认值。"""
    for key, env in CONTROL_SETTINGS.items():
        value = control.get(key)
        if value not in (None, "") and not os.environ.get(env):
            config[key] = value
    return config


HOST_CACHE_SECONDS = 3600


def host_info(config: dict) -> dict:
    """主机名 / 系统 / 登录用户 / 出网 IP / MAC：随请求上报（X-AG-Host），控制台按主机展示设备。

    出网 IP 每个进程取一次（不发包，开销可忽略）；MAC 按 IP 缓存在 host.json，一小时内 IP 不变则复用，
    避免每个 Hook 事件都枚举网卡。
    """
    import getpass
    import platform
    import time

    from . import netinfo

    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 — 取不到用户名不影响上报
        user = ""
    ip = netinfo.outbound_ip(config.get("url") or DEFAULT_URL)
    cache_path = os.path.join(user_dir(), "host.json")
    cache = _read_json(cache_path)
    if cache.get("ip") == ip and time.time() - float(cache.get("at") or 0) < HOST_CACHE_SECONDS:
        mac = str(cache.get("mac") or "")
    else:
        mac = netinfo.mac_for(ip)
        write_json(cache_path, {"ip": ip, "mac": mac, "at": time.time()})
    return {"hostname": platform.node(), "os": f"{platform.system()} {platform.release()}".strip(), "user": user,
            "ip": ip, "mac": mac}


def read_json(path: str) -> dict:
    return _read_json(path)


def write_json(path: str, data) -> bool:
    """原子写入；失败不抛出（Hook 路径上任何本地 I/O 失败都不能影响 Agent）。"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False)
        os.replace(path + ".tmp", path)
        return True
    except OSError:
        return False
