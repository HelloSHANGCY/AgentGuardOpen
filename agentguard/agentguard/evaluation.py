"""Authenticated evaluation queue for Hook fixtures and the frozen offline corpus."""
import argparse
import fcntl
import hmac
import json
import os
import signal
import sqlite3
import subprocess
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import httpx
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from .agents import cc_fixtures
from .agents.cc_replay import HookTransport, attach_decisions, replay_fixture
from .rules.library import RuleLibrary
from .testing.corpus import DATASET, load_corpus
from .testing.replay import iter_replay_corpus

SCENARIOS = cc_fixtures.SCENARIOS
CORPUS_MANIFEST = json.loads((DATASET / "manifest.json").read_text(encoding="utf-8"))
SUITES = {"claude-code": SCENARIOS, "offline-corpus": ("all", *CORPUS_MANIFEST["by_scenario"])}
SUITE_LIMITS = {"claude-code": 500, "offline-corpus": CORPUS_MANIFEST["total"]}
SUITE_DEFAULTS = {"claude-code": 100, "offline-corpus": CORPUS_MANIFEST["total"]}
IMPORT_SUITES = ("claude-code-e2e",)
CC_NOTE = ("Claude Code 夹具经真实 Hook 客户端子进程回放到网关（不依赖模型）。恶意夹具以首个高风险点被 ASK/DENY "
           "计为检出；正常夹具任一步 ASK/DENY 计为误报。“逐步期望一致”要求每一步决策都与夹具期望相同；"
           "延迟为 PreToolUse 端到端口径（含客户端进程启动）。评测设备在结束后吊销。")
CORPUS_NOTE = ("固定靶场离线数据集 range-v1，使用内置规则与快照上下文，仅检查保存的工具请求、代码载荷和上传文件名。"
               "恶意样本出现 ASK/DENY 计为检出，正常样本出现 ASK/DENY 计为误报。"
               "不执行工具或载荷，不伪造工具返回，不写入在线审计、训练记录或模型。"
               "样本耗时为本地检测耗时；副作用、真实业务成功、网络隔离、Beacon 和完整验收均未验证。")
ACTIVE = ("QUEUED", "RUNNING", "CANCELLING")


@dataclass
class EvaluationConfig:
    local_test: bool = field(default_factory=lambda: os.getenv("AG_LOCAL_TEST", "0") == "1")
    db: str = field(default_factory=lambda: os.getenv("AG_EVAL_DB", "/tmp/agentguard-evaluation/jobs.db"))
    token: str = field(default_factory=lambda: os.getenv("AG_EVAL_ADMIN_TOKEN", ""))
    gateway: str = field(default_factory=lambda: os.getenv("AG_EVAL_GATEWAY", "http://127.0.0.1:8080"))
    hook_script: str = field(default_factory=lambda: os.getenv("AG_EVAL_CC_HOOK", str(Path(__file__).resolve().parents[1] / "tools/replay_hook_client.py")))
    agent_admin_token: str = field(default_factory=lambda: os.getenv("AG_AGENT_ADMIN_TOKEN", ""))
    timeout: float = field(default_factory=lambda: float(os.getenv("AG_EVAL_TIMEOUT", "1800")))


class StartEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite: Literal["claude-code", "offline-corpus"] = "claude-code"
    scenario: str = "all"
    limit: StrictInt = Field(default=100, ge=1, le=5200)

    @model_validator(mode="before")
    @classmethod
    def default_limit_for_suite(cls, value):
        if isinstance(value, dict) and "limit" not in value:
            suite = value.get("suite", "claude-code")
            if isinstance(suite, str) and suite in SUITE_DEFAULTS:
                return {**value, "limit": SUITE_DEFAULTS[suite]}
        return value

    @model_validator(mode="after")
    def scenario_in_suite(self):
        if self.scenario not in SUITES[self.suite]:
            raise ValueError(f"scenario {self.scenario!r} not in suite {self.suite}")
        if self.limit > SUITE_LIMITS[self.suite]:
            raise ValueError(f"limit exceeds {SUITE_LIMITS[self.suite]} for suite {self.suite}")
        return self


class ImportEvaluation(BaseModel):
    """外部驱动（真实 Agent 端到端）的结果导入；行字段与回放行一致。"""
    model_config = ConfigDict(extra="forbid")
    suite: Literal["claude-code-e2e"]
    params: dict = Field(default_factory=dict)
    rows: list[dict] = Field(max_length=500)
    note: str = Field(default="", max_length=2000)
    started_at: float | None = None
    finished_at: float | None = None


def _matrix(rows):
    counts = Counter(row["outcome"] for row in rows)
    tp, fn, fp, tn = (counts[k] for k in ("TP", "FN", "FP", "TN"))
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "unknown": counts["UNKNOWN"],
            "errors": counts["ERROR"], "evaluated": tp + fn + fp + tn,
            "detection_rate": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "precision": tp / (tp + fp) if tp + fp else None}


def _grouped(rows, key):
    groups: dict = {}
    for row in rows:
        groups.setdefault(key(row), []).append(row)
    return groups


def _percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def summarize(rows):
    result = _matrix(rows)
    latencies = [value for row in rows for value in row.get("latencies_ms") or []]
    if latencies:
        # Claude Code 套件：PreToolUse 端到端（Hook 客户端进程启动 → 服务端决策 → 输出）延迟。
        result["latency"] = {"p50": _percentile(latencies, 0.5), "p95": _percentile(latencies, 0.95),
                             "max": max(latencies), "samples": len(latencies)}
    result["by_scenario"] = {name: _matrix(items) for name, items in sorted(_grouped(rows, lambda r: r.get("scenario") or "?").items())}
    result["by_type"] = {name: _matrix(items) for name, items in sorted(_grouped(rows, lambda r: "malicious" if r.get("malicious") else "benign").items())}
    decisions = Counter()
    for row in rows:
        decisions.update(row.get("decisions") or {})
    result["decision_counts"] = {name: decisions[name] for name in ("ALLOW", "ASK", "DENY")}
    result["unknown_reasons"] = dict(Counter(row.get("unknown_reason") or "unspecified" for row in rows if row["outcome"] == "UNKNOWN"))
    result["error_reasons"] = dict(Counter(row.get("error") or "unspecified" for row in rows if row["outcome"] == "ERROR"))
    effects = Counter(str(row.get("effect_ok")) for row in rows)
    result["effect_checks"] = {"passed": effects["True"], "failed": effects["False"], "not_checked": effects["None"]}
    business = Counter(str(row.get("business_ok")) for row in rows)
    result["business_checks"] = {"passed": business["True"], "failed": business["False"], "not_checked": business["None"]}
    return result


class EvaluationRepository:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, status TEXT, cancel INTEGER DEFAULT 0, data TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS worker (id INTEGER PRIMARY KEY, heartbeat REAL)")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def heartbeat(self):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO worker VALUES (1, ?)", (time.time(),))

    def online(self):
        with self.connect() as db:
            row = db.execute("SELECT heartbeat FROM worker WHERE id=1").fetchone()
        return bool(row and time.time() - row[0] < 45)

    def cancel_requested(self, run_id):
        # Do not deserialize thousands of stored results for each cancellation check.
        with self.connect() as db:
            row = db.execute("SELECT cancel FROM jobs WHERE id=?", (run_id,)).fetchone()
        return bool(row and row[0])

    def create(self, params):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM jobs WHERE status IN ('QUEUED','RUNNING','CANCELLING')").fetchone():
                raise ValueError("已有评测任务，请等待完成或取消")
            job = {"run_id": uuid.uuid4().hex, "params": params, "created_at": time.time(),
                   "phase": "等待执行", "total": 0, "completed": 0, "rows": [], "error": "",
                   "summary": summarize([])}
            db.execute("INSERT INTO jobs(id,status,data) VALUES (?, 'QUEUED', ?)",
                       (job["run_id"], json.dumps(job)))
        return self.get(job["run_id"])

    def import_run(self, body):
        rows = body["rows"]
        job = {"run_id": uuid.uuid4().hex, "params": {**body["params"], "suite": body["suite"]},
               "created_at": body.get("started_at") or time.time(), "started_at": body.get("started_at"),
               "finished_at": body.get("finished_at") or time.time(), "phase": "已导入", "total": len(rows),
               "completed": len(rows), "rows": rows, "error": "", "note": body.get("note", "")}
        job["summary"] = summarize(rows)
        status = "PARTIAL" if any(r.get("outcome") in ("UNKNOWN", "ERROR") for r in rows) else "COMPLETED"
        with self.connect() as db:
            db.execute("INSERT INTO jobs(id,status,data) VALUES (?, ?, ?)", (job["run_id"], status, json.dumps(job)))
        return self.get(job["run_id"])

    def get(self, run_id):
        with self.connect() as db:
            row = db.execute("SELECT status,cancel,data FROM jobs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        return {**json.loads(row[2]), "status": row[0], "cancel_requested": bool(row[1])}

    def recent(self):
        with self.connect() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM jobs ORDER BY rowid DESC LIMIT 20")]
        return [{k: v for k, v in self.get(i).items() if k != "rows"} for i in ids]

    def save(self, job, status=None):
        job["summary"] = summarize(job["rows"])
        with self.connect() as db:
            if status:
                db.execute("UPDATE jobs SET status=?,data=? WHERE id=?", (status, json.dumps(job), job["run_id"]))
            else:
                db.execute("UPDATE jobs SET data=? WHERE id=?", (json.dumps(job), job["run_id"]))

    def cancel(self, run_id):
        with self.connect() as db:
            db.execute("UPDATE jobs SET cancel=1,status=CASE WHEN status='QUEUED' THEN 'CANCELLED' ELSE 'CANCELLING' END WHERE id=? AND status IN ('QUEUED','RUNNING','CANCELLING')", (run_id,))

    def claim(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT id FROM jobs WHERE status='QUEUED' ORDER BY rowid LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET status='RUNNING' WHERE id=?", row)
        return self.get(row[0])


def build_evaluation_api(config=None, repository=None):
    config = config or EvaluationConfig()
    repo = repository or EvaluationRepository(config.db)
    router = APIRouter(prefix="/v1/evaluations")

    def authorize(token):
        if config.local_test and not config.token:
            return
        if not config.token:
            raise HTTPException(503, "评测未启用：请启用本地测试模式或配置评测令牌")
        if not token or not hmac.compare_digest(token.encode(), config.token.encode()):
            raise HTTPException(401, "评测管理令牌无效")

    def get_job(run_id):
        job = repo.get(run_id)
        if job is None:
            raise HTTPException(404, "评测不存在")
        return job

    @router.get("/options")
    def options():
        return {"enabled": config.local_test or bool(config.token), "auth_required": bool(config.token),
                "local_test": config.local_test, "worker_online": repo.online(), "scenarios": SCENARIOS,
                "suites": SUITES, "max_limit": 500, "suite_limits": SUITE_LIMITS,
                "suite_defaults": SUITE_DEFAULTS,
                "datasets": {"offline-corpus": {key: CORPUS_MANIFEST[key] for key in
                             ("dataset_id", "total", "malicious", "benign", "by_scenario")}}}

    @router.post("", status_code=202)
    def create(body: StartEvaluation, x_ag_eval_token: str | None = Header(default=None)):
        authorize(x_ag_eval_token)
        if not repo.online():
            raise HTTPException(503, "评测 worker 未就绪")
        try:
            return repo.create(body.model_dump())
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.post("/import", status_code=201)
    def import_run(body: ImportEvaluation, x_ag_eval_token: str | None = Header(default=None)):
        authorize(x_ag_eval_token)
        job = repo.import_run(body.model_dump())
        return {k: v for k, v in job.items() if k != "rows"}

    @router.get("")
    def recent(x_ag_eval_token: str | None = Header(default=None)):
        authorize(x_ag_eval_token)
        return {"runs": repo.recent()}

    @router.get("/{run_id}")
    def detail(run_id: str, x_ag_eval_token: str | None = Header(default=None)):
        authorize(x_ag_eval_token)
        job = get_job(run_id)
        return {**job, "rows": job["rows"][-100:]}

    @router.post("/{run_id}/cancel")
    def cancel(run_id: str, x_ag_eval_token: str | None = Header(default=None)):
        authorize(x_ag_eval_token)
        get_job(run_id)
        repo.cancel(run_id)
        return {"status": repo.get(run_id)["status"]}

    @router.get("/{run_id}/report")
    def report(run_id: str, x_ag_eval_token: str | None = Header(default=None)):
        authorize(x_ag_eval_token)
        job = get_job(run_id)
        if job["status"] in ACTIVE:
            raise HTTPException(409, "任务结束后可下载报告")
        return JSONResponse(job, headers={"Content-Disposition": f'attachment; filename="evaluation-{job["run_id"]}.json"'})

    return router


class EvaluationStopped(Exception):
    pass


class EvaluationWorker:
    def __init__(self, config, repo, client=None):
        self.config, self.repo = config, repo
        self.client = client or httpx.Client(timeout=20, trust_env=False)
        self.stopping = False

    def recover(self):
        # Caller holds the OS file lock, so no previous worker still owns these jobs.
        with self.repo.connect() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM jobs WHERE status IN ('RUNNING','CANCELLING')")]
        for run_id in ids:
            job = self.repo.get(run_id)
            job.update(error="评测进程中断，请重新启动评测", phase="执行中断", finished_at=time.time())
            self.repo.save(job, "INTERRUPTED")

    def run_offline_corpus(self, job, check):
        """Read the bundled snapshot and inspect locally, without contacting the gateway."""
        job.update(phase="校验离线数据集")
        self.repo.save(job)
        try:
            records, context, manifest = load_corpus()
        except (OSError, ValueError, KeyError):
            raise RuntimeError("离线数据集加载或完整性校验失败，请检查随项目发布的数据文件") from None
        check()
        params = job["params"]
        selected = [row for row in records if params["scenario"] in ("all", row["scenario"])][:params["limit"]]
        if not selected:
            raise RuntimeError("所选场景没有离线样本")
        rules = RuleLibrary()
        job.update(total=len(selected), phase="离线请求检测中", scope="offline_request_checks",
                   rules_source="builtin", rulepack_digest=rules.digest(),
                   dataset={key: manifest[key] for key in
                            ("dataset_id", "schema_version", "snapshot_date", "seed", "total", "malicious", "benign", "files")},
                   tool_execution=False, side_effects_verified=False, business_success_verified=False,
                   network_boundary_verified=False, full_acceptance_verified=False)
        self.repo.save(job)
        last_saved = time.monotonic()
        results = iter_replay_corpus(selected, context, rules=rules)
        for _ in selected:
            check()
            job["rows"].append(next(results))
            job["completed"] = len(job["rows"])
            # Batch persistence keeps a 5,200-row run responsive without rewriting it per row.
            if job["completed"] % 50 == 0 or time.monotonic() - last_saved >= .5:
                self.repo.save(job)
                last_saved = time.monotonic()


    def run_claude_code(self, job, check):
        """Claude Code 夹具回放：临时签发评测设备，经 Hook 客户端回放，结束后吊销。"""
        try:
            self.client.get(self.config.gateway + "/health", timeout=5).raise_for_status()
        except httpx.HTTPError:
            raise RuntimeError("网关未就绪，请先启动 AgentGuard") from None
        params = job["params"]
        items = [f for f in cc_fixtures.fixtures() if params["scenario"] in ("all", f["threat"])][:params["limit"]]
        if not items:
            raise RuntimeError("所选场景没有夹具")
        run_tag = job["run_id"][:8]
        headers = {"X-AG-Admin-Token": self.config.agent_admin_token} if self.config.agent_admin_token else {}
        devices = {}
        try:
            for profile in sorted({item["profile"] for item in items}):
                device_id = f"eval-{run_tag}-{profile[:3]}"
                response = self.client.post(self.config.gateway + "/v1/admin/devices", headers=headers, timeout=5, json={
                    "device_id": device_id, "profile": profile, "purpose": "evaluation",
                    "actor": {"sub": "evaluator", "role": "developer", "team": "eval"}})
                if response.status_code in (401, 503):
                    raise RuntimeError("设备签发失败：请启用本地测试模式或为 worker 配置 AG_AGENT_ADMIN_TOKEN")
                response.raise_for_status()
                devices[profile] = (device_id, response.json()["token"])
            transport = HookTransport(self.config.gateway, self.client, self.config.hook_script)
            job.update(total=len(items), phase="回放中（" + transport.mode + "）")
            self.repo.save(job)
            for item in items:
                check()
                device_id, token = devices[item["profile"]]
                started = time.monotonic()
                try:
                    row = replay_fixture(item, transport, token, device_id, run_tag)
                    attach_decisions(row, self.client, self.config.gateway)
                except (httpx.HTTPError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                    row = {"trace_id": f"cc-{device_id}-{item['id']}-{run_tag}", "fixture": item["id"],
                           "scenario": item["threat"], "malicious": item["malicious"], "outcome": "ERROR",
                           "error": type(exc).__name__, "unknown_reason": "request_error", "decisions": {},
                           "decision_ids": [], "effect_ok": None, "business_ok": None}
                row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
                job["rows"].append(row)
                job["completed"] = len(job["rows"])
                self.repo.save(job)
        finally:
            for device_id, _ in devices.values():
                try:
                    self.client.delete(self.config.gateway + "/v1/admin/devices/" + device_id, headers=headers, timeout=5)
                except httpx.HTTPError:
                    pass

    def execute(self, job):
        started = time.monotonic()
        last_heartbeat = 0

        def check():
            nonlocal last_heartbeat
            if time.monotonic() - last_heartbeat >= 5:
                self.repo.heartbeat()
                last_heartbeat = time.monotonic()
            if self.stopping or self.repo.cancel_requested(job["run_id"]):
                raise EvaluationStopped()
            if time.monotonic() - started > self.config.timeout:
                raise TimeoutError()

        final_status = "FAILED"
        try:
            check()
            suite = job["params"].get("suite")
            job.update(phase="准备评测", started_at=time.time(),
                       note=CORPUS_NOTE if suite == "offline-corpus" else CC_NOTE)
            self.repo.save(job)
            if suite == "offline-corpus":
                self.run_offline_corpus(job, check)
            elif suite == "claude-code":
                self.run_claude_code(job, check)
            else:
                raise RuntimeError("此评测套件已移除，请新建受支持的评测任务")
            check()
            final_status = "PARTIAL" if any(r["outcome"] in ("UNKNOWN", "ERROR") for r in job["rows"]) else "COMPLETED"
        except EvaluationStopped:
            final_status = "CANCELLED"
        except TimeoutError:
            job["error"] = "评测超过时间上限"
            final_status = "TIMED_OUT"
        except RuntimeError as exc:
            job["error"] = str(exc)
        except Exception as exc:
            job["error"] = "评测执行失败：" + type(exc).__name__
        finally:
            job.update(phase="已结束", finished_at=time.time())
            self.repo.save(job, final_status)


def main():
    argparse.ArgumentParser(description="AgentGuard dedicated evaluation worker").parse_args()
    config = EvaluationConfig()
    if not config.token and not config.local_test:
        raise SystemExit("请设置 AG_LOCAL_TEST=1 或 AG_EVAL_ADMIN_TOKEN 后启动评测 worker")
    repo = EvaluationRepository(config.db)
    with open(config.db + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker = EvaluationWorker(config, repo)
        def stop(*_):
            worker.stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            worker.recover()
            while not worker.stopping:
                repo.heartbeat()
                job = repo.claim()
                if job:
                    worker.execute(job)
                else:
                    time.sleep(1)
        finally:
            with repo.connect() as db:
                db.execute("DELETE FROM worker")
            worker.client.close()


if __name__ == "__main__":
    main()
