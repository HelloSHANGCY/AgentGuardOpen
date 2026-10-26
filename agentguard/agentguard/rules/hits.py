"""特征匹配计数：检测路径只更新内存，后台批量写入共享 SQLite。

按实际成功的匹配调用累计，不保存被匹配的文本；不同服务/扫描进程共享同一规则目录。
统计故障不改变匹配结果，规则自检与样本测试使用原始模式，不经过计数包装。
"""

import atexit
import os
import sqlite3
import threading
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone

from .trace import record_feature


class HitCounter:
    def __init__(self, directory: str = ""):
        self.path = os.path.join(directory, "hits.sqlite3") if directory else ""
        self.since = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.error = ""
        self.observation_error = ""
        self._counts = Counter()
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._closed = False

    def record(self, rule_id: str):
        # 不进行磁盘操作，也不获取规则库/运行时存储的锁。
        with self._lock:
            if self._closed:
                return
            self._counts[rule_id] += 1
            if self.path and self._thread is None:
                self._thread = threading.Thread(target=self._run, name="rule-hit-counter", daemon=True)
                self._thread.start()
                atexit.register(self.close)

    def _run(self):
        while not self._stop.wait(1):
            self.flush()

    def _connect(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=0.25)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS hits (rule_id TEXT PRIMARY KEY, count INTEGER NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO metadata VALUES ('since', ?)", (self.since,))
            conn.commit()
            return conn
        except Exception:
            conn.close()
            raise

    def flush(self) -> bool:
        if not self.path:
            return True
        with self._flush_lock:
            with self._lock:
                batch = self._counts
                self._counts = Counter()
            try:
                with closing(self._connect()) as conn, conn:
                    conn.executemany("INSERT INTO hits VALUES (?, ?) ON CONFLICT(rule_id) "
                                     "DO UPDATE SET count=count+excluded.count", batch.items())
                self.error = ""
                return True
            except (OSError, sqlite3.Error) as exc:
                with self._lock:
                    self._counts.update(batch)
                self.error = exc.__class__.__name__
                return False

    def snapshot(self) -> dict:
        if self.observation_error:
            return {"counts": None, "since": self.since, "persistent": bool(self.path),
                    "error": self.observation_error}
        if not self.path:
            with self._lock:
                counts = dict(self._counts)
            return {"counts": counts, "since": self.since, "persistent": False, "error": ""}
        if self.flush():
            try:
                with closing(self._connect()) as conn:
                    counts = dict(conn.execute("SELECT rule_id, count FROM hits"))
                    since = conn.execute("SELECT value FROM metadata WHERE key='since'").fetchone()[0]
                return {"counts": counts, "since": since, "persistent": True, "error": ""}
            except (OSError, sqlite3.Error) as exc:
                self.error = exc.__class__.__name__
        return {"counts": None, "since": self.since, "persistent": True, "error": self.error}

    def close(self):
        self._stop.set()
        with self._lock:
            self._closed = True
        if self._thread is not None and self._thread.ident is not None:
            self._thread.join(timeout=2)
        self.flush()
        atexit.unregister(self.close)


class ObservedKeyword(str):
    """关键词仍可作为普通字符串使用，命中时携带该生效集合的元数据。"""

    def __new__(cls, word, features):
        value = super().__new__(cls, word)
        value.features = tuple(features)
        return value


class ObservedPattern:
    """保留正则的匹配语义、源码及 flags，旁路记录成功匹配。"""

    def __init__(self, pattern, counter: HitCounter, rule_id: str, feature=None):
        self._pattern, self._counter, self._rule_id = pattern, counter, rule_id
        self._feature = feature

    def __getattr__(self, name):
        return getattr(self._pattern, name)

    def _match(self, method, *args, **kwargs):
        result = getattr(self._pattern, method)(*args, **kwargs)
        if result:
            if self._feature is not None:
                record_feature(self._feature)
            try:
                self._counter.record(self._rule_id)
            except Exception:  # 统计不可影响检测结果。
                self._counter.observation_error = "counter unavailable"
        return result

    def search(self, *args, **kwargs):
        return self._match("search", *args, **kwargs)

    def match(self, *args, **kwargs):
        return self._match("match", *args, **kwargs)

    def fullmatch(self, *args, **kwargs):
        return self._match("fullmatch", *args, **kwargs)
