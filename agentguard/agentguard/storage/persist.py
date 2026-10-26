"""运行时数据持久化：事件、决策、证据与任务信封写入 SQLite，重启后加载回内存。

- 内存仍是查询与决策的热路径；这里只负责落盘与恢复，不参与 Hook 同步路径；
- 写入经队列交给后台线程，约每 200 毫秒批量提交一次（WAL），进程崩溃最多丢失这一批；
- 同一条记录可多次写入（ASK 回填结论、分析回写研判、迟到事件修正关联），按主键覆盖、保留原写入顺序；
- 按保留天数与每表条数上限清理，启动时清理一次，之后每小时一次。
"""

import json
import os
import queue
import sqlite3
import threading
import time

TABLES = ("events", "decisions", "evidence", "tasks")
# 磁盘上每表最多保留的条数（内存上限的数倍；启动只加载内存上限内最新的一部分）。
MAX_ROWS = {"events": 200000, "decisions": 200000, "evidence": 80000, "tasks": 50000}
BATCH_SECONDS = 0.2
BATCH_ROWS = 1000
QUEUE_LIMIT = 100000
PRUNE_INTERVAL = 3600


def iso_cutoff(days: float, now: float | None = None) -> str:
    """与 utc_now_ms 同格式的时间下界，字符串比较即时间比较。"""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime((now or time.time()) - days * 86400)) + ".000Z"


class RuntimeDB:
    def __init__(self, path: str, retention_days: float = 7.0) -> None:
        self.path = path
        self.retention_days = max(0.1, float(retention_days))
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        fresh = not os.path.exists(path)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        if fresh:
            try:
                os.chmod(path, 0o600)   # 证据含脱敏后的工具返回原文
            except OSError:
                pass
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        for table in TABLES:
            self._conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (key TEXT UNIQUE NOT NULL, trace_id TEXT, "
                               f"ts TEXT, data TEXT NOT NULL)")
            self._conn.execute(f"CREATE INDEX IF NOT EXISTS {table}_ts ON {table}(ts)")
        self._conn.commit()
        self._db_lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue(maxsize=QUEUE_LIMIT)
        self.stats = {"written": 0, "dropped": 0, "errors": 0, "pruned": 0, "loaded": {}}
        self._last_prune = 0.0
        self.prune()
        self._thread = threading.Thread(target=self._writer, name="runtime-db", daemon=True)
        self._thread.start()

    # ---- 写入 ----

    def put(self, table: str, key: str, trace_id: str, ts: str, data: dict) -> None:
        """入队一条记录（调用方已持有快照，后续修改需再次 put）。队列满时丢弃并计数，不阻塞调用方。"""
        try:
            self._queue.put_nowait((table, key, trace_id, ts, json.dumps(data, ensure_ascii=False, default=str)))
        except queue.Full:
            self.stats["dropped"] += 1

    def _writer(self) -> None:
        while True:
            batch = [self._queue.get()]
            deadline = time.time() + BATCH_SECONDS
            while len(batch) < BATCH_ROWS:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break
            self._write(batch)
            for _ in batch:
                self._queue.task_done()
            if time.time() - self._last_prune > PRUNE_INTERVAL:
                self.prune()

    def _write(self, batch: list) -> None:
        try:
            with self._db_lock:
                for table, key, trace_id, ts, data in batch:
                    self._conn.execute(
                        f"INSERT INTO {table}(key, trace_id, ts, data) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET data = excluded.data", (key, trace_id, ts, data))
                self._conn.commit()
            self.stats["written"] += len(batch)
        except sqlite3.Error:
            self.stats["errors"] += 1

    def flush(self, timeout: float = 5.0) -> bool:
        """等待队列写完（测试与退出时用）。"""
        deadline = time.time() + timeout
        while self._queue.unfinished_tasks:
            if time.time() > deadline:
                return False
            time.sleep(0.01)
        return True

    def prune(self) -> None:
        self._last_prune = time.time()
        cutoff = iso_cutoff(self.retention_days)
        try:
            with self._db_lock:
                removed = 0
                for table in TABLES:
                    removed += self._conn.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,)).rowcount
                    removed += self._conn.execute(
                        f"DELETE FROM {table} WHERE rowid <= (SELECT MAX(rowid) FROM {table}) - ?",
                        (MAX_ROWS[table],)).rowcount
                self._conn.commit()
            self.stats["pruned"] += removed
        except sqlite3.Error:
            self.stats["errors"] += 1

    # ---- 读取 ----

    def load(self, table: str, limit: int) -> list[dict]:
        """保留期内最新的 limit 条，按原写入顺序返回；损坏的行跳过。"""
        with self._db_lock:
            rows = self._conn.execute(
                f"SELECT data FROM (SELECT rowid, data FROM {table} WHERE ts >= ? ORDER BY rowid DESC LIMIT ?) "
                "ORDER BY rowid", (iso_cutoff(self.retention_days), limit)).fetchall()
        result = []
        for (data,) in rows:
            try:
                item = json.loads(data)
            except ValueError:
                continue
            if isinstance(item, dict):
                result.append(item)
        self.stats["loaded"][table] = len(result)
        return result

    def status(self) -> dict:
        with self._db_lock:
            counts = {table: self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES}
        try:
            size = sum(os.path.getsize(self.path + suffix) for suffix in ("", "-wal") if os.path.exists(self.path + suffix))
        except OSError:
            size = 0
        return {"path": self.path, "retention_days": self.retention_days, "rows": counts,
                "size_mb": round(size / (1024 * 1024), 2), "pending": self._queue.qsize(), **self.stats}
