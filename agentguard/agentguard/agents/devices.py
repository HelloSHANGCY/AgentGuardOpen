"""设备注册：设备令牌 → 可信 actor、策略档案与设备级管控（通用 Agent 接入设计 §9 / §18）。

设备 = 安装了终端客户端的一台主机：一个令牌覆盖该主机上允许接入的全部 Agent（agents），
trace 仍按 Agent 区分（cc- / cx-）。启停、本地快速判定、服务不可达处理按“Agent 全局默认 +
设备覆盖（overrides，未设置的项跟随默认）”生效。旧数据中单个 agent 字段视为只允许该 Agent。

通用 Agent 没有 JWT 这类服务端可校验的身份，身份来源改为管理员签发的设备令牌：
- Hook 负载中自报的任何身份字段一律忽略，actor 只取令牌绑定值；
- 只保存令牌的 SHA-256，签发接口仅在创建时返回一次明文；
- 配置了 AG_AGENT_DEVICE_DIR / AG_DATA_DIR 时持久化到 agent-devices.json（仅哈希），重启后仍有效。
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qs

from ..detection.engine import KNOWN_PROFILES, PROFILE_DEVELOPER

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")
# 已接入的 Agent（与 agents/api.py 中的适配器一一对应）；令牌只能调用设备允许的 Agent 的 Hook 接口。
AGENTS = ("claude-code", "codex", "trae", "qoder", "zcode", "workbuddy", "codebuddy")
# 管控项：Agent 全局默认（control.py）与设备覆盖共用同一组键。
FAIL_MODES = ("open", "failsafe")
UPLOAD_MODES = ("full", "digest")
# 运行参数（终端客户端按缓存的管控配置执行，环境变量可在本机临时覆盖）：工具返回上传方式与 Hook 请求超时。
TIMEOUT_KEYS = ("timeout_pre", "timeout")
TIMEOUT_RANGE = (0.3, 10.0)
CONTROL_KEYS = ("enabled", "enforce", "fail_mode", "local_rules", "result_guard", "upload_mode") + TIMEOUT_KEYS
# 终端上报的主机信息（X-AG-Host 头，查询串格式）：只用于展示，不参与鉴权或决策。
# ip / mac 为终端自报（出网网卡），另记服务端看到的来源地址 remote_ip。
HOST_FIELDS = ("hostname", "os", "user", "ip", "mac")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
SEEN_FLUSH_SECONDS = 60


def validate_control(changes: dict, allow_null: bool = False) -> dict:
    """校验管控项；allow_null 时 None 表示删除设备覆盖、恢复跟随默认。"""
    if not isinstance(changes, dict):
        raise ValueError("control must be an object")
    out = {}
    for key, value in changes.items():
        if key not in CONTROL_KEYS:
            raise ValueError(f"unknown control key: {key}")
        if value is None and allow_null:
            out[key] = None
        elif key == "fail_mode":
            if value not in FAIL_MODES:
                raise ValueError("unknown fail_mode")
            out[key] = value
        elif key == "upload_mode":
            if value not in UPLOAD_MODES:
                raise ValueError("unknown upload_mode")
            out[key] = value
        elif key in TIMEOUT_KEYS:
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not TIMEOUT_RANGE[0] <= value <= TIMEOUT_RANGE[1]:
                raise ValueError(f"{key} must be a number of seconds in {TIMEOUT_RANGE[0]}-{TIMEOUT_RANGE[1]}")
            out[key] = round(float(value), 1)
        elif not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")
        else:
            out[key] = value
    return out


def parse_host(header: str) -> dict:
    try:
        values = parse_qs(str(header or "")[:512], max_num_fields=8)
    except ValueError:
        return {}
    host = {key: values[key][0][:64] for key in HOST_FIELDS if values.get(key)}
    if "ip" in host and not _valid_ip(host["ip"]):
        del host["ip"]
    if "mac" in host:
        host["mac"] = host["mac"].lower().replace("-", ":")
        if not MAC_RE.match(host["mac"]):
            del host["mac"]
    return host


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class Device:
    device_id: str
    actor: dict = field(default_factory=dict)
    profile: str = PROFILE_DEVELOPER
    agents: list = field(default_factory=lambda: list(AGENTS))
    # "evaluation"：评测 worker 临时签发的设备，不受控制台启停影响（启停只管真实接入的设备）。
    purpose: str = ""
    overrides: dict = field(default_factory=dict)
    created_at: str = ""
    # 终端执行一键卸载（uninstall --all --purge）后上报的时间：令牌随即停用，记录保留供管理员查看后删除。
    uninstalled_at: str = ""

    @property
    def agent(self) -> str:
        """主 Agent（列表首项）：兼容只认单个 Agent 的调用方。"""
        return self.agents[0]

    def allows(self, agent: str) -> bool:
        return agent in self.agents

    def public(self) -> dict:
        return {**asdict(self), "agent": self.agent}


class DeviceRegistry:
    def __init__(self, preset: dict | None = None, data_dir: str = "") -> None:
        self._lock = threading.Lock()
        self._by_hash: dict[str, Device] = {}
        # 最近上报：device_id -> {last_seen, client, host, seen_agents}，供控制台按设备展示接入状态。
        # 持久化到 agent-devices-seen.json，同一设备最多每 SEEN_FLUSH_SECONDS 写一次，主机信息变化时立即写。
        self._seen: dict[str, dict] = {}
        self._seen_flushed = 0.0
        self._path = os.path.join(data_dir, "agent-devices.json") if data_dir else ""
        self._seen_path = os.path.join(data_dir, "agent-devices-seen.json") if data_dir else ""
        self._load()
        self._load_seen()
        for token, spec in (preset or {}).items():
            if isinstance(spec, dict) and token:
                self._by_hash[_hash(str(token))] = self._device(spec)

    @staticmethod
    def _device(spec: dict) -> Device:
        device_id = str(spec.get("device_id") or "dev-" + secrets.token_hex(4))
        if not DEVICE_ID_RE.match(device_id):
            raise ValueError("invalid device_id")
        actor = spec.get("actor") if isinstance(spec.get("actor"), dict) else {}
        profile = str(spec.get("profile") or PROFILE_DEVELOPER)
        if profile not in KNOWN_PROFILES:
            raise ValueError("unknown profile")
        agents = spec.get("agents")
        if agents is None:
            agents = [spec["agent"]] if spec.get("agent") else list(AGENTS)
        if not isinstance(agents, list) or not agents or any(agent not in AGENTS for agent in agents):
            raise ValueError("unknown agent")
        overrides = validate_control(spec.get("overrides") or {})
        purpose = str(spec.get("purpose") or "")
        if purpose not in ("", "evaluation"):
            raise ValueError("unknown purpose")
        return Device(
            device_id=device_id,
            actor={
                "sub": str(actor.get("sub") or device_id),
                "role": str(actor.get("role") or "developer"),
                "team": str(actor.get("team") or ""),
                "scope": dict(actor.get("scope") or {}),
            },
            profile=profile,
            agents=[agent for agent in AGENTS if agent in agents],
            purpose=purpose,
            overrides=overrides,
            created_at=str(spec.get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")),
            uninstalled_at=str(spec.get("uninstalled_at") or ""),
        )

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as handle:
                data = json.load(handle)
            for token_hash, spec in data.items():
                self._by_hash[token_hash] = self._device(spec)
        except (OSError, ValueError):
            pass

    def _load_seen(self) -> None:
        if not self._seen_path or not os.path.exists(self._seen_path):
            return
        try:
            with open(self._seen_path, encoding="utf-8") as handle:
                data = json.load(handle)
            known = {device.device_id for device in self._by_hash.values()}
            self._seen = {key: value for key, value in data.items() if key in known and isinstance(value, dict)}
        except (OSError, ValueError):
            pass

    def _save_seen(self, force: bool = False) -> None:
        now = time.monotonic()
        if not self._seen_path or (not force and now - self._seen_flushed < SEEN_FLUSH_SECONDS):
            return
        self._seen_flushed = now
        try:
            tmp = self._seen_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self._seen, handle)
            os.replace(tmp, self._seen_path)
        except OSError:
            pass

    def _save(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump({key: device.public() for key, device in self._by_hash.items()}, handle)
        os.replace(tmp, self._path)

    def register(self, spec: dict) -> tuple[Device, str]:
        token = "agd_" + secrets.token_urlsafe(32)
        return self.adopt(spec, _hash(token)), token

    def adopt(self, spec: dict, token_hash: str) -> Device:
        """以已知的令牌哈希创建设备：自助接入时令牌由终端生成，服务端只有哈希。"""
        device = self._device(spec)
        with self._lock:
            if any(existing.device_id == device.device_id for existing in self._by_hash.values()):
                raise ValueError("device_id already registered")
            if token_hash in self._by_hash and not self._by_hash[token_hash].uninstalled_at:
                raise ValueError("token already registered")
            self._by_hash[token_hash] = device
            self._save()
        return device

    def devices(self) -> list[Device]:
        with self._lock:
            return list(self._by_hash.values())

    def device_ids(self) -> set:
        with self._lock:
            return {device.device_id for device in self._by_hash.values()}

    def update(self, device_id: str, changes: dict) -> Device:
        """修改策略档案、允许的 Agent 与设备覆盖（overrides 中 None 表示恢复跟随默认）；先整体校验再写入。"""
        if not isinstance(changes, dict):
            raise ValueError("invalid changes")
        profile = changes.get("profile")
        if profile is not None and profile not in KNOWN_PROFILES:
            raise ValueError("unknown profile")
        agents = changes.get("agents")
        if agents is not None and (not isinstance(agents, list) or not agents
                                   or any(agent not in AGENTS for agent in agents)):
            raise ValueError("unknown agent")
        overrides = validate_control(changes.get("overrides") or {}, allow_null=True)
        with self._lock:
            device = next((item for item in self._by_hash.values() if item.device_id == device_id), None)
            if device is None:
                raise KeyError(device_id)
            if profile is not None:
                device.profile = profile
            if agents is not None:
                device.agents = [agent for agent in AGENTS if agent in agents]
            for key, value in overrides.items():
                if value is None:
                    device.overrides.pop(key, None)
                else:
                    device.overrides[key] = value
            self._save()
            return device

    def revoke(self, device_id: str) -> bool:
        with self._lock:
            keys = [key for key, device in self._by_hash.items() if device.device_id == device_id]
            for key in keys:
                self._by_hash.pop(key)
            self._seen.pop(device_id, None)
            if keys:
                self._save()
                self._save_seen(force=True)
            return bool(keys)

    def authenticate(self, token: str) -> Device | None:
        if not token:
            return None
        with self._lock:
            device = self._by_hash.get(_hash(token))
            return None if device is None or device.uninstalled_at else device

    def mark_uninstalled(self, token: str) -> Device | None:
        """终端一键卸载：标记设备已卸载并停用令牌（之后的请求按未认证处理）。"""
        with self._lock:
            device = self._by_hash.get(_hash(token or ""))
            if device is None or device.uninstalled_at:
                return None
            device.uninstalled_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._save()
            return device

    def touch(self, device_id: str, client: str = "", agent: str = "", host: str = "", remote_ip: str = "",
              scan_agents: list | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            seen = self._seen.setdefault(device_id, {"last_seen": "", "client": "", "host": {}, "seen_agents": {}})
            seen["last_seen"] = now
            if client:
                seen["client"] = client[:64]
            if agent:
                seen["seen_agents"][agent] = now
            if scan_agents is not None:
                seen["scan_channel"] = {"last_seen": now, "agents": list(scan_agents)}
            parsed = parse_host(host)
            changed = bool(parsed) and parsed != seen.get("host")
            if parsed:
                seen["host"] = parsed
            if remote_ip and _valid_ip(remote_ip) and remote_ip != seen.get("remote_ip"):
                seen["remote_ip"] = remote_ip
                changed = True
            self._save_seen(force=changed)

    def list(self) -> list[dict]:
        empty = {"last_seen": "", "client": "", "host": {}, "seen_agents": {}, "remote_ip": ""}
        with self._lock:
            return [{**device.public(), **json.loads(json.dumps(self._seen.get(device.device_id, empty)))}
                    for device in self._by_hash.values()]
