"""Task Context Service（设计 §5.2）。

Hook 在 /run 开始时同步创建任务信封；网关凭 X-Trace-Id 查询服务端上下文，
不信任请求方自报的身份头。信封带 TTL，过期即失效。
"""

import threading
import time

from ..models import Actor, TaskContext, new_id, sha256_digest, utc_now_ms


class TaskContextService:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._tasks: dict[str, TaskContext] = {}

    def create(self, trace_id: str, actor: dict, prompt: str = "", skill: dict | None = None,
               source_labels: list | None = None, instance_id: str = "", agent: str = "mcp",
               policy_profile: str = "", ttl_seconds: int | None = None) -> TaskContext:
        task = TaskContext(
            trace_id=trace_id,
            task_id=new_id("task"),
            actor=Actor(
                sub=str(actor.get("sub", "unknown")),
                role=str(actor.get("role", "unknown")),
                team=str(actor.get("team", "")),
                scope=dict(actor.get("scope") or {}),
            ),
            intent_summary=str(prompt or ""),
            intent_digest=sha256_digest(prompt or ""),
            active_skill=dict(skill or {}),
            source_labels=list(source_labels or ["USER_INPUT"]),
            instance_id=instance_id,
            issued_at=utc_now_ms(),
            expires_at=time.time() + (ttl_seconds or self.ttl_seconds),
            agent=agent,
            policy_profile=policy_profile,
        )
        with self._lock:
            self._tasks[trace_id] = task
        return task

    def get(self, trace_id: str) -> TaskContext | None:
        with self._lock:
            task = self._tasks.get(trace_id)
            if task and task.expires_at < time.time():
                # 过期信封视为缺失，副作用工具将 fail-closed。
                self._tasks.pop(trace_id, None)
                return None
            return task

    def touch(self, trace_id: str, ttl_seconds: int | None = None) -> TaskContext | None:
        """滑动续期：通用 Agent 的会话远长于单次 /run，每个 Hook 事件刷新一次有效期。"""
        with self._lock:
            task = self._tasks.get(trace_id)
            if task is None or task.expires_at < time.time():
                return None
            task.expires_at = time.time() + (ttl_seconds or self.ttl_seconds)
            return task

    def complete(self, trace_id: str) -> bool:
        with self._lock:
            return self._tasks.pop(trace_id, None) is not None

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [task.as_dict() for task in self._tasks.values()]
