"""前端指定路径：白名单校验、目录浏览接口、持久化与扫描器解析。"""

import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentguard.static_scan.api import build_static_api
from agentguard.static_scan.models import ScanRecord, new_id
from agentguard.static_scan.repository import Repository
from agentguard.static_scan.scanner import run_scan


class _Settings:
    def __init__(self, roots=(), sources=None, token=""):
        self.static_roots = tuple(roots)
        self.static_sources = dict(sources or {})
        self.static_admin_token = token


def _client(tmp_path, roots=(), sources=None, token=""):
    repository = Repository(str(tmp_path / "api.db"))
    app = FastAPI()
    app.include_router(build_static_api(_Settings(roots, sources, token), repository))
    return TestClient(app), repository


def test_scan_with_path_inside_root(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "app.py").write_text("print('x')\n", encoding="utf-8")
    client, repository = _client(tmp_path, roots=[str(root)])
    response = client.post("/v1/static/scans", json={"path": str(root / "sub"), "project_id": "p"})
    assert response.status_code == 202
    record = repository.get_scan(response.json()["scan_id"])
    assert record.source_path == os.path.realpath(root / "sub")
    assert record.source_id.startswith("path-")


def test_scan_path_outside_root_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    client, _ = _client(tmp_path, roots=[str(root)])
    response = client.post("/v1/static/scans", json={"path": str(outside)})
    assert response.status_code == 400
    assert "outside authorized roots" in response.json()["detail"]


def test_scan_path_escape_missing_and_symlink_rejected(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    link.symlink_to(outside)
    client, _ = _client(tmp_path, roots=[str(root)])
    assert client.post("/v1/static/scans", json={"path": str(root / "sub" / ".." / "..")}).status_code == 400
    assert client.post("/v1/static/scans", json={"path": str(link)}).status_code == 400
    assert client.post("/v1/static/scans", json={"path": str(root / "missing")}).status_code == 400
    assert client.post("/v1/static/scans", json={"path": ""}).status_code == 400


def test_registered_source_still_works_without_roots(tmp_path):
    source = tmp_path / "registered"
    source.mkdir()
    client, repository = _client(tmp_path, sources={"app": str(source)})
    response = client.post("/v1/static/scans", json={"source_id": "app"})
    assert response.status_code == 202
    record = repository.get_scan(response.json()["scan_id"])
    assert record.source_path == os.path.realpath(source)
    assert client.post("/v1/static/scans", json={"source_id": "nope"}).status_code == 400


def test_browse_lists_only_dirs_within_roots(tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "b.txt").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside)
    client, _ = _client(tmp_path, roots=[str(root)])
    data = client.get("/v1/static/browse").json()
    assert data["roots"] == [os.path.realpath(root)]
    assert [entry["name"] for entry in data["entries"]] == ["root"]
    data = client.get("/v1/static/browse", params={"path": str(root)}).json()
    assert [entry["name"] for entry in data["entries"]] == ["a"]
    assert data["parent"] == ""
    sub = client.get("/v1/static/browse", params={"path": str(root / "a")}).json()
    assert sub["parent"] == os.path.realpath(root)
    assert client.get("/v1/static/browse", params={"path": str(outside)}).status_code == 400


def test_admin_token_protects_path_endpoints(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    client, _ = _client(tmp_path, roots=[str(root)], token="secret")
    assert client.get("/v1/static/sources").status_code == 401
    assert client.get("/v1/static/browse", params={"path": str(root)}).status_code == 401
    assert client.post("/v1/static/scans", json={"path": str(root)}).status_code == 401
    headers = {"X-AG-Admin": "secret"}
    assert client.get("/v1/static/sources", headers=headers).status_code == 200
    assert client.get("/v1/static/browse", params={"path": str(root)}, headers=headers).status_code == 200


def test_run_scan_uses_stored_source_path(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.py").write_text("import os\n", encoding="utf-8")
    repository = Repository(str(tmp_path / "scan.db"))
    record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="path-x",
                        source_path=str(root))
    repository.create_scan(record)
    run_scan(record.scan_id, repository, {})
    current = repository.get_scan(record.scan_id)
    assert current.status in ("COMPLETED", "PARTIAL")
    coverage = repository.get_coverage(record.scan_id)
    assert coverage is not None and coverage.indexed_files >= 1


def test_run_scan_reports_missing_source_path(tmp_path):
    repository = Repository(str(tmp_path / "scan.db"))
    record = ScanRecord(scan_id=new_id("scan"), project_id="p", source_id="path-x",
                        source_path=str(tmp_path / "gone"))
    repository.create_scan(record)
    try:
        run_scan(record.scan_id, repository, {})
    except Exception:
        pass
    assert repository.get_scan(record.scan_id).status == "FAILED"


def test_schema_migration_adds_source_path(tmp_path):
    db_path = tmp_path / "migrate.db"
    repository = Repository(str(db_path))
    with repository.connect() as connection:
        connection.execute("ALTER TABLE scans DROP COLUMN source_path")
    Repository(str(db_path))
    with repository.connect() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    assert "source_path" in columns
