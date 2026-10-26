"""评测指标：恶意样本召回、良性样本误报与资产盘点。"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentguard.static_scan.metrics import evaluate_assets, evaluate_findings


def _path_resolver(repository, scan_id):
    cache = {}

    def resolve(finding):
        asset_id = finding.asset_id
        if not asset_id:
            return ""
        if asset_id not in cache:
            asset = repository.get_asset(scan_id, asset_id)
            cache[asset_id] = asset.relative_path if asset else ""
        return cache[asset_id]

    return resolve


def test_malicious_fixture_recall_and_benign_false_positive(malicious_scan, benign_scan):
    repository, scan_id = malicious_scan
    findings = repository.get_findings(scan_id, limit=500)["items"]
    labels = [
        {"path": "mcp/shadow/server.py", "category": "mcp_malicious"},
        {"path": "skills/packer", "category": "skill_malicious"},
        {"path": "skills/cred-helper", "category": "skill_malicious"},
        {"path": "docker-compose.yml", "category": "config"},
        {"path": "requirements.txt", "category": "supply_chain"},
    ]
    result = evaluate_findings(labels, findings, _path_resolver(repository, scan_id))
    assert result["recall"] == 1.0
    assert result["miss_rate"] == 0.0
    assert result["precision"] == 1.0

    benign_repository, benign_id = benign_scan
    benign_findings = benign_repository.get_findings(benign_id, limit=500)["items"]
    negatives = [
        {"path": "mcp/safe_sync/server.py", "category": "code", "expected": False},
        {"path": "skills/safe-helper/SKILL.md", "category": "skill_malicious", "expected": False},
        {"path": "skills/quoted-sample/SKILL.md", "category": "skill_malicious", "expected": False},
        {"path": "docker-compose.yml", "category": "config", "expected": False},
        {"path": "app.py", "category": "mcp_malicious", "expected": False},
    ]
    benign_result = evaluate_findings(negatives, benign_findings,
                                      _path_resolver(benign_repository, benign_id))
    assert benign_result["fpr"] == 0.0
    assert benign_result["tn"] == len(negatives)


def test_asset_inventory_recall(malicious_scan):
    repository, scan_id = malicious_scan
    assets = repository.get_assets(scan_id, limit=500)["items"]
    labels = [
        {"kind": "Skill", "logical_key": "skill:skills/packer"},
        {"kind": "Skill", "logical_key": "skill:skills/cred-helper"},
        {"kind": "MCPServer", "logical_key": "mcp:shadow-sync"},
        {"kind": "Tool", "logical_key": "tool:shadow-sync:admin_shell"},
        {"kind": "AgentApplication", "logical_key": "app:app.py"},
        {"kind": "ModelReference", "path": "app.py"},
    ]
    result = evaluate_assets(labels, assets)
    assert result["recall"] == 1.0
    assert result["miss_rate"] == 0.0
