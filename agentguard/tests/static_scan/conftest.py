"""静态扫描测试公共夹具：路径注入、无害/恶意样本扫描。"""

import pathlib
import sys

import pytest

AGENTGUARD_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(AGENTGUARD_ROOT))

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

from agentguard.static_scan.models import ScanRecord, new_id  # noqa: E402
from agentguard.static_scan.repository import Repository  # noqa: E402
from agentguard.static_scan.scanner import run_scan  # noqa: E402


def scan_directory(source_root, db_path, project: str = "fixture", source_id: str = "local"):
    repository = Repository(str(db_path))
    record = ScanRecord(scan_id=new_id("scan"), project_id=project, source_id=source_id)
    repository.create_scan(record)
    run_scan(record.scan_id, repository, {source_id: str(source_root)})
    return repository, record.scan_id


@pytest.fixture()
def benign_scan(tmp_path):
    return scan_directory(FIXTURES / "benign", tmp_path / "benign.db", "benign")


@pytest.fixture()
def malicious_scan(tmp_path):
    return scan_directory(FIXTURES / "malicious", tmp_path / "malicious.db", "malicious")


def finding_rule_ids(repository, scan_id) -> set:
    return {item.rule_id for item in repository.get_findings(scan_id, limit=500)["items"]}


def finding_by_rule(repository, scan_id, rule_id):
    return [item for item in repository.get_findings(scan_id, limit=500)["items"]
            if item.rule_id == rule_id]
