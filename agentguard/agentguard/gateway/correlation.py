"""Hook 与 MCP 中转的调用关联（通用 Agent 接入设计 §8.2）。

受管 MCP 调用先经过 Agent Hook（有会话上下文、无强制力），再经过 stdio 包装器 /
HTTP 网关（有强制力、无会话上下文）。Hook 侧登记待关联项，中转侧按
(server, tool, 参数摘要) 在时间窗口内认领，拿到 trace_id 与 call_id：
- 唯一匹配才认领并移除；相同参数的并行候选不按先后强行关联；
- 认领不到时中转侧按“无任务上下文”处理（副作用工具 fail-closed）。
"""

import hashlib
import json
import threading
import time
from collections import deque

DEFAULT_WINDOW_SECONDS = 30.0
MAX_PENDING = 4096


def arguments_digest(arguments) -> str:
    canonical = json.dumps(arguments or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PendingCalls:
    def __init__(self, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._items: deque = deque(maxlen=MAX_PENDING)

    def register(self, trace_id: str, server: str, tool: str, arguments, call_id: str,
                 confirmed_ask: bool = False) -> None:
        """confirmed_ask：Hook 侧预判为 ASK 并已交由用户在 Agent 原生界面确认。"""
        with self._lock:
            if any(item["trace_id"] == trace_id and item["call_id"] == call_id for item in self._items):
                return
            self._items.append({"at": time.time(), "trace_id": trace_id, "server": server, "tool": tool,
                                "digest": arguments_digest(arguments), "call_id": call_id,
                                "confirmed_ask": confirmed_ask})

    def take_unclaimed(self, trace_id: str, call_id: str) -> dict | None:
        """移除并返回仍未被中转认领的待关联项：工具已执行却未经中转，即中转被绕过。"""
        with self._lock:
            for item in self._items:
                if item["trace_id"] == trace_id and item["call_id"] == call_id:
                    self._items.remove(item)
                    return item
        return None

    def claim(self, server: str, tool: str, arguments, trace_prefix: str | tuple[str, ...] = "") -> dict | None:
        """trace_prefix 非空时只认领该前缀的会话（stdio 包装器只能认领本设备会话）。"""
        digest = arguments_digest(arguments)
        now = time.time()
        with self._lock:
            while self._items and now - self._items[0]["at"] > self.window_seconds:
                self._items.popleft()
            matches = [item for item in self._items
                       if (not trace_prefix or item["trace_id"].startswith(trace_prefix))
                       and item["server"] == server and item["tool"] == tool and item["digest"] == digest]
            if len(matches) == 1:
                self._items.remove(matches[0])
                return matches[0]
        return None
