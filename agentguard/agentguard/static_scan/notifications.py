"""设备扫描等待连接的进程内唤醒；SQLite 队列始终是任务真相。"""

import asyncio
import threading
from contextlib import contextmanager


class DeviceScanNotifications:
    def __init__(self):
        self._lock = threading.Lock()
        self._listeners = {}

    @contextmanager
    def subscribe(self, device_id):
        listener = (asyncio.get_running_loop(), asyncio.Event())
        with self._lock:
            if sum(len(items) for items in self._listeners.values()) >= 256 \
                    or len(self._listeners.get(device_id, ())) >= 4:
                raise OverflowError("too many device scan connections")
            self._listeners.setdefault(device_id, set()).add(listener)
        try:
            yield listener[1]
        finally:
            with self._lock:
                self._listeners[device_id].discard(listener)
                if not self._listeners[device_id]:
                    self._listeners.pop(device_id)

    def notify(self, device_id):
        with self._lock:
            listeners = list(self._listeners.get(device_id, ()))
        for loop, event in listeners:
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:  # 等待连接所属的事件循环已经关闭。
                pass
