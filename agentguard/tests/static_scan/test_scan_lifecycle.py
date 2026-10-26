"""扫描生命周期、仓储、报告、CLI 与 API 测试。"""

import json
import pathlib
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from conftest import FIXTURES

from agentguard.static_scan.api import build_static_api
from agentguard.static_scan.cli import main as cli_main
from agentguard.static_scan.models import Review, ScanRecord, new_id
from agentguard.static_scan.reports import build_report, render_markdown
from agentguard.static_scan.repository import Repository
from agentguard.static_scan.scanner import run_scan
from agentguard.static_scan.worker import ScanWorker


def test_scan_assets_and_coverage(malicious_scan):
    repository, scan_id = malicious_scan
    scan = repository.get_scan(scan_id)
    assert scan.status in ("COMPLETED", "PARTIAL")
    coverage = repository.get_coverage(scan_id)
    assert coverage.indexed_files > 0
    assert coverage.parsed_files > 0
    kinds = {asset.kind for asset in repository.get_assets(scan_id, limit=500)["items"]}
    assert {"AgentApplication", "MCPServer", "Tool", "Skill", "ModelReference",
            "ConfigArtifact", "Dependency"} <= kinds
    edges = repository.get_edges(scan_id)
    relations = {edge["relation"] for edge in edges}
    assert {"EXPOSES_TOOL", "CONNECTS_TO", "LOADS_SKILL", "USES_MODEL", "CONFIGURED_BY"} <= relations


def test_idempotency_and_queue(tmp_path):
    repository = Repository(str(tmp_path / "idem.db"))
    record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="local",
                        idempotency_key="key-1")
    repository.create_scan(record)
    found = repository.find_scan_by_idempotency("p", "key-1")
    assert found is not None and found.scan_id == record.scan_id
    assert repository.active_scan_count() == 1


def test_claim_cancel_and_stale_recovery(tmp_path):
    repository = Repository(str(tmp_path / "life.db"))
    record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="local")
    repository.create_scan(record)
    claimed = repository.claim_next_scan("worker-1")
    assert claimed.status == "RUNNING" and claimed.attempt == 1
    assert repository.request_cancel(record.scan_id)
    assert repository.is_cancel_requested(record.scan_id)
    worker = ScanWorker(repository, {"local": str(FIXTURES / "benign")}, timeout=30)
    worker.execute_subprocess(claimed)
    assert repository.get_scan(record.scan_id).status == "CANCELLED"

    stale = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="local")
    repository.create_scan(stale)
    repository.claim_next_scan("worker-2")
    repository.update_scan(stale.scan_id, heartbeat_at="2000-01-01T00:00:00Z")
    assert repository.mark_stale_running(stale_seconds=1) == 1
    assert repository.get_scan(stale.scan_id).status == "INTERRUPTED"
    assert repository.requeue_scan(stale.scan_id)
    requeued = repository.get_scan(stale.scan_id)
    assert requeued.status == "QUEUED"
    assert repository.claim_next_scan("worker-3").attempt == 2


def test_worker_subprocess_runs_scan(tmp_path):
    repository = Repository(str(tmp_path / "worker.db"))
    record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="local")
    repository.create_scan(record)
    worker = ScanWorker(repository, {"local": str(FIXTURES / "malicious")}, timeout=120)
    worker.execute_subprocess(record)
    scan = repository.get_scan(record.scan_id)
    assert scan.status in ("COMPLETED", "PARTIAL")
    assert repository.get_assets(record.scan_id, limit=1)["total"] > 0


def test_diff_reports_stable_assets(tmp_path):
    # 两次扫描使用同一数据库才能比较
    repository = Repository(str(tmp_path / "diff.db"))
    ids = []
    for _ in range(2):
        record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="local")
        repository.create_scan(record)
        run_scan(record.scan_id, repository, {"local": str(FIXTURES / "malicious")})
        ids.append(record.scan_id)
    result = repository.diff(ids[1], ids[0])
    assert result["assets"]["added"] == []
    assert result["assets"]["removed"] == []
    assert result["findings"]["added"] == []


def test_review_and_report(malicious_scan):
    repository, scan_id = malicious_scan
    finding = repository.get_findings(scan_id, limit=1)["items"][0]
    repository.add_review(Review(review_id=new_id("review"), scan_id=scan_id,
                                 finding_id=finding.finding_id, status="false_positive",
                                 reason="测试环境样例", operator="tester"))
    assert repository.list_reviews(scan_id)
    report = build_report(repository, scan_id)
    assert report["summary"]["findings"] > 0
    assert report["coverage"]["indexed_files"] > 0
    markdown = render_markdown(report)
    assert "静态扫描报告" in markdown
    assert "人工复核" in markdown
    assert "不代表" in markdown


def test_runtime_binding_display_only(malicious_scan):
    repository, scan_id = malicious_scan
    server = next(asset for asset in repository.get_assets(scan_id, "MCPServer", limit=50)["items"]
                  if asset.name == "shadow-sync")
    repository.add_runtime_binding("malicious", server.asset_id, "shadow-sync")
    matches = repository.assets_for_runtime_server("malicious", "shadow-sync")
    assert matches
    assert matches[0]["asset"]["asset_id"] == server.asset_id
    assert matches[0]["findings"]
    assert repository.assets_for_runtime_server("malicious", "unknown-server") == []


def test_graph_is_bounded(malicious_scan):
    repository, scan_id = malicious_scan
    app = next(asset for asset in repository.get_assets(scan_id, "AgentApplication", limit=10)["items"])
    graph = repository.get_graph(scan_id, app.asset_id, depth=1, limit=10)
    assert graph["nodes"]
    assert len(graph["nodes"]) <= 10
    assert graph["center"] == app.asset_id


def test_cli_scan_and_report(tmp_path):
    db = str(tmp_path / "cli.db")
    report = str(tmp_path / "report.json")
    code = cli_main(["scan", "--source", str(FIXTURES / "malicious"), "--project", "cli",
                     "--db", db, "--in-process", "--report", report, "--format", "json"])
    assert code == 0
    assert pathlib.Path(report).exists()
    payload = json.loads(pathlib.Path(report).read_text(encoding="utf-8"))
    assert payload["summary"]["findings"] > 0
    code = cli_main(["report", "--db", db, "--scan-id", payload["scan"]["scan_id"], "--format", "md"])
    assert code == 0


def test_static_api_queue_query_and_auth(tmp_path):
    repository = Repository(str(tmp_path / "api.db"))
    settings = type("S", (), {"static_sources": {"local": str(FIXTURES / "malicious")},
                              "static_admin_token": "admin-secret"})()
    app = FastAPI()
    app.include_router(build_static_api(settings, repository))
    client = TestClient(app)

    assert client.post("/v1/static/scans", json={"source_id": "local"}).status_code == 401
    bad = client.post("/v1/static/scans", json={"source_id": "nope"},
                      headers={"X-AG-Admin": "admin-secret"})
    assert bad.status_code == 400
    created = client.post("/v1/static/scans", json={"source_id": "local", "project_id": "api"},
                          headers={"X-AG-Admin": "admin-secret"})
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]
    again = client.post("/v1/static/scans",
                        json={"source_id": "local", "project_id": "api", "idempotency_key": "k"},
                        headers={"X-AG-Admin": "admin-secret"})
    assert again.status_code == 202
    same = client.post("/v1/static/scans",
                       json={"source_id": "local", "project_id": "api", "idempotency_key": "k"},
                       headers={"X-AG-Admin": "admin-secret"})
    assert same.status_code == 200 and same.json()["idempotent"] is True
    assert client.get(f"/v1/static/scans/{scan_id}",
                      headers={"X-AG-Admin": "admin-secret"}).status_code == 200
    cancelled = client.post(f"/v1/static/scans/{scan_id}/cancel",
                            headers={"X-AG-Admin": "admin-secret"})
    assert cancelled.status_code == 200


def test_scan_failure_on_missing_source(tmp_path):
    repository = Repository(str(tmp_path / "fail.db"))
    record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="missing")
    repository.create_scan(record)
    with pytest.raises(Exception):
        run_scan(record.scan_id, repository, {"other": str(tmp_path)})
    assert repository.get_scan(record.scan_id).status == "FAILED"
