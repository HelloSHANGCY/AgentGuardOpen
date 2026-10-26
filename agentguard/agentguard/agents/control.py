"""终端管控：Agent 全局默认 + 设备覆盖（控制台「设备管理」）。

每个 Agent 有一份全局默认；设备可以覆盖其中任意项（Device.overrides），未覆盖的项跟随默认。

Hook 常驻在 Agent 配置中，启停不改动终端上的任何文件：
- 停止：服务端对该 Agent 的 Hook / MCP 中转请求直接放行，不检测、不记录；
- 拦截（enforce，默认开启）：关闭后为观察模式：照常检测并记录事件、决策与行为基线数据，命中的拒绝 / 需确认
  只记告警（标签 MONITOR_ONLY），不向 Agent 输出决策、MCP 中转照常转发；下发给终端的配置同时关闭本地快速判定、
  服务不可达时按 open 处理（旧版客户端无需升级也不会拦截）；大模型危险审批不再复核（不拦截则无需复核）；
- 每次响应都附带当前管控配置，客户端缓存在本地；服务不可达时按缓存执行：
  open（默认）不拦截，只把事件写入本地缓冲；failsafe 按客户端降级表拒绝高风险操作；
- 返回内容拦截（result_guard，默认开启）：MCP 中转与网关检出 tools/call 返回含注入指令时，不把原文交给 Agent，
  替换为拦截说明并记 DENY 决策，原文进入证据库供溯源；关闭后只打污点、记录事件，返回原样交回；观察模式下不生效；
- 本地快速判定（local_rules，默认开启）：终端按服务端签名下发的规则包本地拒绝高置信威胁，
  服务端可达与不可达时都生效（fastpath.py）；
- 运行参数：工具返回上传方式（upload_mode：full 原文 / digest 只传摘要）与 Hook 请求超时
  （timeout_pre：PreToolUse，timeout：其他事件），终端按缓存的配置执行，本机环境变量可临时覆盖。
配置了 AG_AGENT_DEVICE_DIR / AG_DATA_DIR 时持久化到 agent-hook-control.json。
"""

import json
import os
import threading
from datetime import datetime, timezone

from .devices import AGENTS, FAIL_MODES, UPLOAD_MODES, validate_control  # noqa: F401
from .devices import CONTROL_KEYS as KEYS

DEFAULT_CONTROL = {"enabled": True, "enforce": True, "fail_mode": "open", "local_rules": True, "result_guard": True,
                   "upload_mode": "full", "timeout_pre": 1.5, "timeout": 1.0}


def effective(defaults: dict, device) -> dict:
    """设备上某个 Agent 实际生效的管控配置；评测设备始终启用并拦截（控制台启停只管真实接入的设备）。"""
    control = {**defaults, **{key: value for key, value in device.overrides.items() if key in KEYS}}
    if device.purpose == "evaluation":
        control["enabled"] = control["enforce"] = True
    if not control.get("enforce", True):
        # 观察模式：终端也不能拦截。按旧字段下发，未识别 enforce 的旧版客户端同样遵守。
        control["local_rules"], control["fail_mode"] = False, "open"
        control["result_guard"] = False
    return control


class HookControl:
    def __init__(self, data_dir: str = "") -> None:
        self._lock = threading.Lock()
        self._path = os.path.join(data_dir, "agent-hook-control.json") if data_dir else ""
        self._agents = {agent: {**DEFAULT_CONTROL, "updated_at": ""} for agent in AGENTS}
        self._load()

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as handle:
                data = json.load(handle)
            for agent, item in data.items():
                if agent in self._agents and isinstance(item, dict):
                    self._apply(agent, item, item.get("updated_at") or "")
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self._agents, handle)
        os.replace(tmp, self._path)

    def _apply(self, agent: str, changes: dict, updated_at: str) -> None:
        # 先整体校验再写入，非法请求不留下部分修改。
        changes = validate_control({key: value for key, value in changes.items() if key in KEYS})
        current = self._agents[agent]
        for key in KEYS:
            if key in changes:
                current[key] = changes[key]
        current["updated_at"] = updated_at

    def get(self, agent: str) -> dict:
        with self._lock:
            return dict(self._agents[agent])

    def all(self) -> dict:
        with self._lock:
            return {agent: dict(item) for agent, item in self._agents.items()}

    def update(self, agent: str, changes: dict) -> dict:
        if agent not in self._agents:
            raise KeyError(agent)
        with self._lock:
            self._apply(agent, changes, datetime.now(timezone.utc).isoformat(timespec="seconds"))
            self._save()
            return dict(self._agents[agent])
