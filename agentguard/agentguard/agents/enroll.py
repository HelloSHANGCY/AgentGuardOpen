"""设备自助接入：终端安装后自动申请，管理员在控制台核对后认证（通用 Agent 接入设计 §18.3）。

令牌由终端在本机生成，服务端只保存它的 SHA-256（与管理员签发的令牌相同）；令牌不经管理员之手，
也不需要复制粘贴：
1. 终端生成 `agd_` 令牌，带着它（Bearer）调用 POST /v1/agents/enroll 申请接入，上报主机信息与要接入的 Agent；
2. 申请进入待认证队列，控制台展示主机名、系统、用户、IP / MAC、来源地址与核对码；
3. 管理员核对（核对码同时显示在终端安装输出中）后认证：以该哈希创建设备，令牌随即生效；
   拒绝则记为已拒绝，终端查询到后停止重试。

核对码由令牌哈希派生（终端可本地算出），用来确认控制台里的这条申请确实来自要接入的那台主机。
申请接口无需鉴权，按总量与来源地址限流；待认证申请 14 天无联系过期，已拒绝的记录保留 7 天。
可用 AG_AGENT_ENROLL=off 关闭自助接入，或设置 AG_AGENT_ENROLL_KEY 要求申请携带接入口令。
"""

import json
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from .devices import AGENTS, _hash, _valid_ip, parse_host

TOKEN_RE = re.compile(r"^agd_[A-Za-z0-9_-]{32,64}$")
MAX_PENDING = 200
MAX_PENDING_PER_SOURCE = 20
PENDING_TTL = timedelta(days=14)
REJECTED_TTL = timedelta(days=7)


def verification_code(token_hash: str) -> str:
    """核对码：令牌哈希前 8 位（大写，XXXX-XXXX），终端用同样方式本地计算。"""
    return f"{token_hash[:4]}-{token_hash[4:8]}".upper()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


class EnrollmentError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class EnrollmentQueue:
    def __init__(self, data_dir: str = "") -> None:
        self._lock = threading.Lock()
        self._by_hash: dict[str, dict] = {}
        self._path = os.path.join(data_dir, "agent-enrollments.json") if data_dir else ""
        if self._path and os.path.exists(self._path):
            try:
                with open(self._path, encoding="utf-8") as handle:
                    data = json.load(handle)
                self._by_hash = {key: value for key, value in data.items() if isinstance(value, dict)}
            except (OSError, ValueError):
                pass

    def _save(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self._by_hash, handle)
        os.replace(tmp, self._path)

    def _expire(self) -> None:
        now = _now()
        for key, entry in list(self._by_hash.items()):
            ttl = REJECTED_TTL if entry["status"] == "rejected" else PENDING_TTL
            if datetime.fromisoformat(entry["last_seen"]) + ttl < now:
                del self._by_hash[key]

    def request(self, token: str, agents, host_header: str, remote_ip: str, client: str) -> dict:
        """登记或刷新一条申请；同一令牌重复申请时合并 Agent、更新主机信息与最近联系时间。"""
        if not TOKEN_RE.match(token or ""):
            raise EnrollmentError(400, "token must match agd_<32-64 url-safe chars>")
        if not isinstance(agents, list) or not agents or any(agent not in AGENTS for agent in agents):
            raise EnrollmentError(400, "unknown agent")
        token_hash = _hash(token)
        host = parse_host(host_header)
        remote_ip = remote_ip if _valid_ip(remote_ip or "") else ""
        now = _iso(_now())
        with self._lock:
            self._expire()
            entry = self._by_hash.get(token_hash)
            if entry is None:
                pending = [item for item in self._by_hash.values() if item["status"] == "pending"]
                if len(pending) >= MAX_PENDING:
                    raise EnrollmentError(429, "too many pending enrollments")
                if remote_ip and sum(item.get("remote_ip") == remote_ip for item in pending) >= MAX_PENDING_PER_SOURCE:
                    raise EnrollmentError(429, "too many pending enrollments from this address")
                entry = {"enrollment_id": "enr-" + secrets.token_hex(6), "code": verification_code(token_hash),
                         "status": "pending", "agents": [], "host": {}, "remote_ip": "", "client": "",
                         "created_at": now}
                self._by_hash[token_hash] = entry
            if entry["status"] == "pending":
                entry["agents"] = [agent for agent in AGENTS if agent in set(entry["agents"]) | set(agents)]
                entry["host"] = host or entry["host"]
                entry["remote_ip"] = remote_ip or entry["remote_ip"]
                entry["client"] = str(client or "")[:64] or entry["client"]
            entry["last_seen"] = now
            self._save()
            return dict(entry)

    def status(self, token: str) -> dict | None:
        with self._lock:
            entry = self._by_hash.get(_hash(token or ""))
            return dict(entry) if entry else None

    def list(self) -> list[dict]:
        with self._lock:
            self._expire()
            return sorted((dict(entry) for entry in self._by_hash.values() if entry["status"] == "pending"),
                          key=lambda entry: entry["created_at"], reverse=True)

    def _find(self, enrollment_id: str) -> tuple[str, dict]:
        for token_hash, entry in self._by_hash.items():
            if entry["enrollment_id"] == enrollment_id and entry["status"] == "pending":
                return token_hash, entry
        raise KeyError(enrollment_id)

    def take(self, enrollment_id: str) -> tuple[str, dict]:
        """认证：取出待认证申请（令牌哈希, 申请），由调用方据此创建设备。"""
        with self._lock:
            token_hash, entry = self._find(enrollment_id)
            del self._by_hash[token_hash]
            self._save()
            return token_hash, entry

    def restore(self, token_hash: str, entry: dict) -> None:
        """创建设备失败（如设备 ID 冲突）时放回队列。"""
        with self._lock:
            self._by_hash[token_hash] = entry
            self._save()

    def reject(self, enrollment_id: str) -> dict:
        with self._lock:
            _, entry = self._find(enrollment_id)
            entry["status"] = "rejected"
            entry["last_seen"] = _iso(_now())
            self._save()
            return dict(entry)


def suggested_device_id(host: dict, taken) -> str:
    """按主机名生成设备 ID（满足 DEVICE_ID_RE），与已有设备重名时加序号。"""
    base = re.sub(r"[^a-z0-9_.-]+", "-", str(host.get("hostname") or "").lower()).strip("-.")[:40] or "host"
    candidate, index = base, 2
    while candidate in taken:
        candidate, index = f"{base}-{index}", index + 1
    return candidate

