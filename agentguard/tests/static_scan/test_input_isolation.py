"""输入隔离测试：越界、限额、不执行待检内容。"""

import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from conftest import FIXTURES, scan_directory

from agentguard.static_scan.inputs import InputError, Limits, authorized_source, read_verified_text, snapshot_root
from agentguard.static_scan.inventory import FileEntry

EXEC_PROBE = "/tmp/ag_static_exec_probe"


def test_scan_never_executes_target_code(tmp_path):
    if os.path.exists(EXEC_PROBE):
        os.remove(EXEC_PROBE)
    repository, scan_id = scan_directory(FIXTURES / "malicious", tmp_path / "iso.db")
    assert repository.get_findings(scan_id, limit=1)["total"] > 0
    assert not os.path.exists(EXEC_PROBE), "扫描器执行了待检代码"


def test_unauthorized_source_rejected(tmp_path):
    with pytest.raises(InputError):
        authorized_source("not-registered", {"local": str(tmp_path)})
    with pytest.raises(InputError):
        authorized_source("local", {"local": str(tmp_path / "missing")})


def test_read_verified_blocks_traversal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    entry = FileEntry(path="../outside.txt", size=6, digest="sha256:deadbeef", category="text")
    with pytest.raises(InputError):
        read_verified_text(str(root), entry)


def test_depth_limit_records_gap(tmp_path):
    current = tmp_path
    for index in range(6):
        current = current / f"d{index}"
        current.mkdir()
    (current / "deep.py").write_text("x = 1\n", encoding="utf-8")
    index = snapshot_root(str(tmp_path), Limits(max_depth=3))
    assert not any(entry.path.endswith("deep.py") for entry in index.files)
    assert any(hit["limit"] == "max_depth" for hit in index.limit_hits)
    assert index.truncated


def test_binary_content_skipped(tmp_path):
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    index = snapshot_root(str(tmp_path), Limits())
    blob = index.get("blob.dat")
    assert blob is not None
    assert blob.parse_skip in ("unsupported_binary", "binary_suffix")


def test_deep_ast_and_yaml_alias_bomb_are_bounded(tmp_path):
    deep = tmp_path / "deep.py"
    deep.write_text("x = " + "(" * 400 + "1" + ")" * 400 + "\n", encoding="utf-8")
    yaml_bomb = tmp_path / "bomb.yaml"
    yaml_bomb.write_text(
        "a: &a [1,2,3,4,5,6,7,8,9]\n"
        "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
        "d: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n",
        encoding="utf-8")
    repository, scan_id = scan_directory(tmp_path, tmp_path / "limits.db")
    scan = repository.get_scan(scan_id)
    assert scan.status in ("COMPLETED", "PARTIAL")
    coverage = repository.get_coverage(scan_id)
    assert coverage.indexed_files >= 2


def test_api_rejects_unregistered_source(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from agentguard.static_scan.api import build_static_api
    from agentguard.static_scan.repository import Repository

    repository = Repository(str(tmp_path / "api.db"))
    settings = type("S", (), {"static_sources": {}, "static_admin_token": ""})()
    app = FastAPI()
    app.include_router(build_static_api(settings, repository))
    client = TestClient(app)
    response = client.post("/v1/static/scans", json={"source_id": "../../etc"})
    assert response.status_code == 400
