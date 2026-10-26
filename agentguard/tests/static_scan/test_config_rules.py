"""配置基线规则的正负样本测试。"""

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from conftest import finding_by_rule, finding_rule_ids

from agentguard.static_scan.parsers.config import parse_config


def test_large_json_catalog_parses_without_repeated_full_document_traversal():
    data = {"entries": [{"name": f"font-{index}", "url": f"https://example.test/{index}",
                         "metadata": {"license": "OFL"}} for index in range(4000)]}
    text = json.dumps(data, indent=2)
    assert len(text.encode()) > 256 * 1024
    started = time.monotonic()
    doc = parse_config("catalog.json", text, "json")
    assert time.monotonic() - started < 2
    assert not doc.parse_error and len(doc.facts) == 12000
    license_fact = next(fact for fact in doc.facts if fact.pointer == "entries[3999].metadata.license")
    assert license_fact.value == license_fact.resolved == "OFL" and license_fact.line > 0


def test_weak_and_conditional_secret_detected(malicious_scan):
    repository, scan_id = malicious_scan
    findings = finding_by_rule(repository, scan_id, "AG-STATIC-CFG-001")
    titles = " ".join(item.title for item in findings)
    assert "代码内弱默认密钥：JWT_SECRET" in titles
    assert "条件默认弱密钥" in titles
    severities = {item.severity for item in findings}
    assert "HIGH" in severities


def test_weak_secret_evidence_is_redacted(malicious_scan):
    repository, scan_id = malicious_scan
    findings = finding_by_rule(repository, scan_id, "AG-STATIC-CFG-001")
    for finding in findings:
        for evidence in repository.get_evidence(scan_id, finding.evidence_ids):
            assert "change-me-weak-secret" not in evidence["excerpt"]
            assert "***" in evidence["excerpt"] or "len=" in evidence["excerpt"]


def test_auth_disabled_and_privileged_container(malicious_scan):
    repository, scan_id = malicious_scan
    rules = finding_rule_ids(repository, scan_id)
    assert "AG-STATIC-CFG-002" in rules
    assert "AG-STATIC-CFG-003" in rules
    privileged = finding_by_rule(repository, scan_id, "AG-STATIC-CFG-003")
    titles = " ".join(item.title + item.explanation for item in privileged)
    assert "docker.sock" in titles or "敏感路径" in titles
    assert any(item.severity in ("HIGH", "CRITICAL") for item in privileged)


def test_gateway_bypass_detected(malicious_scan):
    repository, scan_id = malicious_scan
    findings = finding_by_rule(repository, scan_id, "AG-STATIC-CFG-004")
    targets = " ".join(item.title for item in findings)
    assert "shadow-sync" in targets
    assert "langflow" in targets


def test_insecure_remote_mcp_and_model_rce(malicious_scan):
    repository, scan_id = malicious_scan
    transport = finding_by_rule(repository, scan_id, "AG-STATIC-CFG-005")
    assert any("remote-tools" in item.title or "remote" in item.explanation for item in transport)
    rce = finding_by_rule(repository, scan_id, "AG-STATIC-CFG-007")
    explanations = " ".join(item.explanation for item in rce)
    assert "trust_remote_code" in explanations
    assert "yaml.load" in explanations
    kinds = {asset.kind for asset in repository.get_assets(scan_id, limit=500)["items"]}
    assert {"Endpoint", "SecretReference"} <= kinds


def test_unpinned_dependency_and_vulnerable_version(malicious_scan):
    repository, scan_id = malicious_scan
    assert finding_by_rule(repository, scan_id, "AG-STATIC-CFG-008")
    vuln = finding_by_rule(repository, scan_id, "AG-STATIC-SUPPLY-001")
    assert any("requests" in item.title and "CVE-2024-35195" in item.title for item in vuln)


def test_benign_config_has_no_high_risk_config_findings(benign_scan):
    repository, scan_id = benign_scan
    rules = finding_rule_ids(repository, scan_id)
    assert "AG-STATIC-CFG-003" not in rules
    assert "AG-STATIC-CFG-004" not in rules
    # 允许列表约束的命令执行不应报 CODE-001
    assert "AG-STATIC-CODE-001" not in rules
    for item in repository.get_findings(scan_id, limit=200)["items"]:
        assert item.severity not in ("HIGH", "CRITICAL")


def test_benign_quoted_sample_is_downgraded_or_absent(benign_scan):
    repository, scan_id = benign_scan
    findings = finding_by_rule(repository, scan_id, "AG-STATIC-SKILL-001")
    for item in findings:
        assert item.severity in ("LOW", "MEDIUM", "INFO")
        assert "代码块" in item.limitations or "引用" in item.limitations
