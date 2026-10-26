"""与服务端的 HTTP 通信、规则包缓存与本地缓冲。"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from . import CLIENT
from . import config as cfg
from .core import fastpath

MAX_SPOOL_BYTES = 2 * 1024 * 1024
FLUSH_BATCH = 20
# 令牌未被接受（待认证 / 已拒绝 / 已吊销 / 设备不允许该 Agent）后的退避：期间 Hook 不联系服务端，
# 事件直接写入缓冲；到期后再试一次，认证通过即恢复并补报。
AUTH_BACKOFF_SECONDS = 30


class Unauthorized(OSError):
    """服务端拒绝了设备令牌（401）。属于 NETWORK_ERRORS：Hook 按服务不可达处理，事件写入缓冲。"""


NETWORK_ERRORS = (OSError, ValueError, urllib.error.URLError)

# 直连 AgentGuard，不读 HTTP(S)_PROXY：Hook 继承 Agent 进程环境，代理变量可被篡改或
# 指向其他代理，决策请求不能因此被转发到其他地址。
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_HOST_HEADER: list = []


def host_header(config: dict) -> str:
    if not _HOST_HEADER:
        try:
            info = cfg.host_info(config)
        except Exception:  # noqa: BLE001 — 主机信息只用于展示，取不到也照常上报事件
            info = {}
        _HOST_HEADER.append(urllib.parse.urlencode(info))
    return _HOST_HEADER[0]


def request(config: dict, method: str, path: str, payload=None, timeout: float = 1.0, headers=None) -> dict:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    req = urllib.request.Request(
        config["url"].rstrip("/") + path, data=data, method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {config.get('token', '')}",
                 "User-Agent": CLIENT, "X-AG-Host": host_header(config), **(headers or {})})
    try:
        with OPENER.open(req, timeout=timeout) as response:
            body = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise Unauthorized(f"HTTP 401: {_detail(exc)}") from None
        raise urllib.error.URLError(f"HTTP {exc.code}: {_detail(exc)}") from None
    return body if isinstance(body, dict) else {}


def _detail(exc) -> str:
    try:
        return str(json.loads(exc.read() or b"{}").get("detail") or exc.reason)
    except (OSError, ValueError, AttributeError):
        return str(exc.reason)


def whoami(config: dict, timeout: float = 3.0) -> dict:
    return request(config, "GET", f"/v1/agents/whoami?agent={config['agent']}", timeout=timeout)


def post_hook(config: dict, payload: dict, timeout: float) -> dict:
    marked = cfg.read_json(config["auth"]).get("at")
    if marked and time.time() - float(marked) < AUTH_BACKOFF_SECONDS:
        raise Unauthorized("device token not accepted (backing off)")
    try:
        result = request(config, "POST", f"/v1/agents/{config['agent']}/hook", payload, timeout)
    except Unauthorized:
        cfg.write_json(config["auth"], {"at": time.time()})
        raise
    if marked:
        try:
            os.remove(config["auth"])
        except OSError:
            pass
    return result


# ---------- 自助接入 ----------

def enroll(config: dict, agents: list, key: str = "", timeout: float = 5.0) -> dict:
    """申请接入（令牌由本机生成）；已认证时返回 status=approved。"""
    headers = {"X-AG-Enroll-Key": key} if key else None
    return request(config, "POST", "/v1/agents/enroll", {"agents": agents}, timeout, headers)


def enroll_status(config: dict, timeout: float = 5.0) -> dict:
    return request(config, "GET", "/v1/agents/enroll", timeout=timeout)


def deploy(url: str, timeout: float = 5.0) -> dict:
    """服务端的客户端部署配置（一键安装用，无需令牌）。"""
    return request({"url": url, "agent": ""}, "GET", "/v1/agents/deploy", timeout=timeout)


def report_uninstall(config: dict, timeout: float = 5.0) -> dict:
    """一键卸载后上报：服务端把设备标记为已卸载并停用令牌。"""
    return request(config, "POST", "/v1/agents/uninstall", {}, timeout)


# ---------- 管控配置缓存 ----------

def read_control(config: dict) -> dict:
    return cfg.read_json(config["control"])


def save_control(config: dict, control) -> None:
    if isinstance(control, dict) and control != read_control(config):
        cfg.write_json(config["control"], control)


# ---------- 规则包 ----------

def load_pack(config: dict) -> dict | None:
    """读取并校验本地缓存的规则包；签名不符（被改动 / 令牌已更换）视为没有规则包。"""
    if not config.get("token"):
        return None
    return fastpath.verify(cfg.read_json(config["rules"]), fastpath.signing_key(config["token"]))


def sync_pack(config: dict, timeout: float = 3.0) -> dict | None:
    """从服务端拉取规则包，校验通过后缓存；返回新规则包，失败返回 None。"""
    envelope = request(config, "GET", f"/v1/agents/rules?agent={config['agent']}", timeout=timeout)
    pack = fastpath.verify(envelope, fastpath.signing_key(config.get("token", "")))
    if pack is not None:
        cfg.write_json(config["rules"], envelope)
    return pack


def pack_outdated(config: dict, control: dict, pack: dict | None) -> bool:
    wanted = (control or {}).get("rules")
    return bool(wanted) and (pack is None or pack.get("version") != wanted)


# ---------- 本地缓冲 ----------

def spool(config: dict, payload: dict, local_action: str, failsafe: str = "") -> None:
    path = config["spool"]
    try:
        if os.path.exists(path) and os.path.getsize(path) > MAX_SPOOL_BYTES:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = dict(payload)
        payload["_ag"] = dict(payload.get("_ag") or {}, delayed=True, spooled_at=time.time(),
                              local_action=local_action, failsafe=failsafe)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def spooled_count(config: dict, session_id: str) -> int:
    try:
        with open(config["spool"], encoding="utf-8") as handle:
            return sum(1 for line in handle if session_id and session_id in line)
    except OSError:
        return 0


def flush_spool(config: dict, timeout: float) -> int:
    path = config["spool"]
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return 0
    sent = 0
    for line in lines[:FLUSH_BATCH]:
        try:
            post_hook(config, json.loads(line), timeout)
        except NETWORK_ERRORS:
            break
        sent += 1
    try:
        rest = lines[sent:]
        if rest:
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(rest)
        else:
            os.remove(path)
    except OSError:
        pass
    return sent
