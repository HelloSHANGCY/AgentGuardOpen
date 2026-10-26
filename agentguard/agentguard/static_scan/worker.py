"""独立扫描 worker：领取任务、子进程隔离、进度、取消与恢复。

- 初版单 worker、单扫描并发，通过数据库事务领取任务；
- 解析在独立子进程中执行，取消/超时终止整个进程组；
- worker 重启后不静默丢弃遗留任务：先标为中断，再由新任务重跑；
- 静态 worker 故障不影响网关健康。
"""

import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

from .inputs import Limits
from .models import TERMINAL_STATES, ScanRecord, utc_now
from .repository import Repository
from .rules.ruleset import load_ruleset
from .scanner import ScanCancelled, run_scan
from .snapshots import cleanup_snapshot

QUEUE_LIMIT = 20
DEFAULT_PARSE_TIMEOUT = 600.0


class ScanWorker:
    def __init__(self, repository: Repository, sources: dict, limits: Limits = None,
                 timeout: float = None, poll_interval: float = 1.0, worker_id: str = "",
                 ruleset=None) -> None:
        self.repository = repository
        self.sources = dict(sources or {})
        self.limits = limits or Limits()
        self.timeout = float(timeout or self.limits.scan_timeout_seconds or DEFAULT_PARSE_TIMEOUT)
        self.poll_interval = poll_interval
        self.worker_id = worker_id or f"worker-{os.getpid()}"
        self.ruleset = ruleset or load_ruleset()
        self.running = True

    # ---- 生命周期 ----

    def recover(self) -> int:
        recovered = self.repository.mark_stale_running(stale_seconds=int(self.timeout))
        for record in self.repository.list_scans(limit=1000):
            if record.status in TERMINAL_STATES:
                cleanup_snapshot(self.repository, record)
        return recovered

    def run_once(self) -> bool:
        """领取并执行一个任务，返回是否有任务被领取。"""
        self.repository.expire_device_scans()
        record = self.repository.claim_next_scan(self.worker_id)
        if record is None:
            return False
        self.execute_subprocess(record)
        return True

    def serve_forever(self) -> None:
        self.recover()
        while self.running:
            try:
                claimed = self.run_once()
            except Exception as exc:  # worker 自身错误不退出循环
                print(f"static-scan worker error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
                claimed = False
            if not claimed:
                time.sleep(self.poll_interval)

    # ---- 子进程执行 ----

    def execute_subprocess(self, record: ScanRecord) -> None:
        command = [sys.executable, "-m", "agentguard.static_scan.worker",
                   "--db", self.repository.path, "--run-scan", record.scan_id,
                   "--sources", json.dumps(self.sources, ensure_ascii=False)]
        package_root = str(pathlib.Path(__file__).resolve().parents[2])
        env = dict(os.environ)
        env["PYTHONPATH"] = package_root + os.pathsep + env.get("PYTHONPATH", "")
        started = time.monotonic()
        try:
            process = subprocess.Popen(command, start_new_session=True, cwd=package_root, env=env)
        except OSError as exc:
            self.repository.update_scan(record.scan_id, status="FAILED", error=f"spawn failed: {exc}",
                                        finished_at=utc_now())
            cleanup_snapshot(self.repository, record)
            return
        try:
            while process.poll() is None:
                if self.repository.is_cancel_requested(record.scan_id):
                    _terminate(process)
                    self.repository.update_scan(record.scan_id, status="CANCELLED",
                                                error="cancelled by operator",
                                                finished_at=utc_now())
                    return
                if time.monotonic() - started > self.timeout:
                    _terminate(process)
                    self.repository.update_scan(record.scan_id, status="PARTIAL",
                                                error="scan timeout; partial results may exist",
                                                finished_at=utc_now())
                    return
                time.sleep(0.5)
        finally:
            if process.poll() is None:
                _terminate(process)
            cleanup_snapshot(self.repository, record)
        current = self.repository.get_scan(record.scan_id)
        if current is not None and current.status not in ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED"):
            self.repository.update_scan(record.scan_id, status="FAILED",
                                        error=f"child exited with code {process.returncode}",
                                        finished_at=utc_now())

    # ---- 进程内执行（CLI 单次 / 测试） ----

    def run_inprocess(self, record: ScanRecord) -> object:
        return run_scan(record.scan_id, self.repository, self.sources, self.limits, self.ruleset)


def _terminate(process) -> None:
    """终止解析子进程组，确保其子进程一并回收。"""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            process.terminate()
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=5)


def run_child(scan_id: str, db_path: str, sources: dict) -> int:
    repository = Repository(db_path)
    record = repository.get_scan(scan_id)
    if record is None:
        print(f"scan not found: {scan_id}", file=sys.stderr)
        return 2
    if repository.is_cancel_requested(scan_id):
        repository.update_scan(scan_id, status="CANCELLED", error="cancelled before start",
                               finished_at=utc_now())
        return 0
    try:
        run_scan(scan_id, repository, sources, Limits(), load_ruleset())
        return 0
    except ScanCancelled:
        repository.update_scan(scan_id, status="CANCELLED", error="cancelled by operator",
                               finished_at=utc_now())
        return 0
    except Exception as exc:
        repository.update_scan(scan_id, status="FAILED", error=f"{exc.__class__.__name__}: {str(exc)[:240]}",
                               finished_at=utc_now())
        print(f"scan failed: {exc}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AgentGuard static scan worker")
    parser.add_argument("--db", default=os.getenv("AG_STATIC_DB", "/tmp/agentguard-static/static-scan.db"))
    parser.add_argument("--sources", default=os.getenv("AG_STATIC_SOURCES", "{}"))
    parser.add_argument("--run-scan", default="")
    parser.add_argument("--once", action="store_true", help="领取一个任务后退出")
    parser.add_argument("--poll", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=float(os.getenv("AG_STATIC_SCAN_TIMEOUT", "600")))
    args = parser.parse_args(argv)
    try:
        sources = json.loads(args.sources or "{}")
    except json.JSONDecodeError as exc:
        print(f"invalid --sources JSON: {exc}", file=sys.stderr)
        return 2
    repository = Repository(args.db)
    if args.run_scan:
        return run_child(args.run_scan, args.db, sources)
    worker = ScanWorker(repository, sources, timeout=args.timeout, poll_interval=args.poll)
    if args.once:
        worker.recover()
        worker.run_once()
        return 0
    worker.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
