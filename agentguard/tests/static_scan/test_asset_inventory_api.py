"""跨扫描资产总览：快照替换、来源隔离、风险统计与分页。"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentguard.static_scan.api import build_static_api
from agentguard.static_scan.models import Asset, Coverage, Finding, ScanRecord
from agentguard.static_scan.repository import Repository


class Settings:
    static_admin_token = ""
    static_sources = {}


def client_repo(tmp_path, token=""):
    repository = Repository(str(tmp_path / "inventory.db"))
    settings = Settings()
    settings.static_admin_token = token
    app = FastAPI()
    app.include_router(build_static_api(settings, repository))
    return TestClient(app), repository


def snapshot(repo, scan_id, *, source="source-a", project="p", status="COMPLETED", day=1,
             assets=("a",), severities=(), device="", agent=""):
    scan = ScanRecord(scan_id, project, source, status=status, created_at=f"2026-10-{day:02}T01:00:00Z",
                      finished_at=f"2026-10-{day:02}T01:01:00Z", device_id=device, agent=agent,
                      source_path="/private/snapshot" if device else "/authorized/path")
    repo.create_scan(scan)
    repo.save_results(scan_id, [Asset(a, project, scan_id, "Skill", a, f"name-{a}", version="1.0") for a in assets],
                      [], [], [Finding(f"f-{i}", scan_id, f"rule-{i % 2}", "1", assets[0], "code", sev, "high")
                               for i, sev in enumerate(severities)], Coverage(scan_id))


def test_latest_successful_snapshot_replaces_assets_and_findings(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "old", assets=("a", "removed"), severities=("CRITICAL",))
    snapshot(repo, "new", assets=("a", "added"), day=2, severities=("LOW",))
    snapshot(repo, "failed", assets=("failed-asset",), status="FAILED", day=3)
    snapshot(repo, "running", assets=("running-asset",), status="RUNNING", day=4)
    snapshot(repo, "cancelled", assets=("cancelled-asset",), status="CANCELLED", day=5)
    data = client.get("/v1/static/inventory").json()
    assert {(a["scan_id"], a["asset_id"]) for a in data["items"]} == {("new", "a"), ("new", "added")}
    assert data["summary"] == {"assets": 2, "risky_assets": 1, "high_risk_assets": 0,
                               "findings": 1, "sources": 1, "partial_sources": 0}


def test_partial_snapshot_retains_coverage_gap_and_does_not_reuse_old_risk(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "old", severities=("CRITICAL",))
    snapshot(repo, "partial", day=2, status="PARTIAL", assets=("a", "b"), severities=("INFO",))
    data = client.get("/v1/static/inventory").json()
    assert {a["asset_id"]: a["risk_state"] for a in data["items"]} == {"a": "risk", "b": "unknown"}
    assert data["summary"]["partial_sources"] == 1
    assert data["items"][0]["risk"]["top"] == "INFO"
    assert client.get("/v1/static/inventory?risk=clear").json()["total"] == 0
    assert client.get("/v1/static/inventory?risk=unknown").json()["total"] == 1


def test_project_source_device_and_agent_namespaces_remain_distinct(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "a")
    snapshot(repo, "b", project="other")
    snapshot(repo, "c", source="source-b")
    snapshot(repo, "d", device="device-1", agent="codex")
    snapshot(repo, "e", device="device-2", agent="codex")
    snapshot(repo, "f", device="device-2", agent="trae")
    data = client.get("/v1/static/inventory").json()
    assert data["summary"]["assets"] == data["summary"]["sources"] == 6
    assert len({(a["scan_id"], a["asset_id"]) for a in data["items"]}) == 6
    assert "/private/snapshot" not in str(data)


def test_pagination_filters_and_top_risks_use_full_scoped_snapshot(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "high", assets=("x", "y", "z"), severities=("HIGH", "HIGH", "INFO"))
    snapshot(repo, "critical", source="b", severities=("CRITICAL",))
    data = client.get("/v1/static/inventory?limit=1&offset=1").json()
    assert data["total"] == 4 and len(data["items"]) == 1
    assert data["summary"]["assets"] == 4
    assert data["top_risks"][0]["scan_id"] == "critical"
    assert data["top_risks"][1]["risk"] == {"count": 3, "rules": 2, "top": "HIGH",
                                           "severity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 1}}
    scoped = client.get("/v1/static/inventory?scan_id=high&kind=Skill&risk=clear&q=NAME-Y").json()
    assert scoped["total"] == 1 and scoped["items"][0]["asset_id"] == "y"
    assert scoped["summary"]["assets"] == 3 and scoped["summary"]["sources"] == 1
    assert scoped["kinds"] == [{"kind": "Skill", "count": 3}]


def test_empty_latest_snapshot_removes_previous_assets(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "old")
    snapshot(repo, "empty", day=2, assets=())
    data = client.get("/v1/static/inventory").json()
    assert data["items"] == data["kinds"] == data["top_risks"] == []
    assert data["summary"]["assets"] == 0 and data["summary"]["sources"] == 1


def test_inventory_is_not_limited_to_recent_scan_list_window(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "old-source")
    for i in range(55):
        snapshot(repo, f"new-{i}", source="busy-source", day=2, assets=(str(i),))
    data = client.get("/v1/static/inventory").json()
    assert {a["scan_id"] for a in data["items"]} == {"old-source", "new-54"}


def test_inventory_counts_assets_and_risks_beyond_old_2000_row_window(tmp_path):
    client, repo = client_repo(tmp_path)
    asset_ids = tuple(f"asset-{i:04}" for i in range(2005))
    snapshot(repo, "large", assets=asset_ids)
    with repo.connect() as connection:
        connection.execute("INSERT INTO findings(finding_id,scan_id,asset_id,rule_id,severity) VALUES(?,?,?,?,?)",
                           ("tail-risk", "large", asset_ids[-1], "tail-rule", "CRITICAL"))
    data = client.get("/v1/static/inventory?limit=1").json()
    assert data["total"] == data["summary"]["assets"] == 2005
    assert data["summary"]["risky_assets"] == data["summary"]["high_risk_assets"] == 1
    assert data["items"][0]["asset_id"] == asset_ids[-1]
    assert data["top_risks"][0]["risk"]["count"] == 1


def test_inventory_empty_auth_and_invalid_pagination(tmp_path):
    client, _ = client_repo(tmp_path, token="inventory-test")
    assert client.get("/v1/static/inventory").status_code == 401
    headers = {"X-AG-Admin": "inventory-test"}
    assert client.get("/v1/static/inventory", headers=headers).json()["total"] == 0
    for query in ("limit=0", "limit=201", "offset=-1"):
        assert client.get("/v1/static/inventory?" + query, headers=headers).status_code == 422
    assert client.get("/v1/static/inventory?risk=fake", headers=headers).status_code == 400


def test_device_agent_groups_merge_projects_but_keep_agents_and_devices_separate(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "a", device="device-1", agent="codex", severities=("HIGH",))
    snapshot(repo, "b", project="other", source="other-source", device="device-1", agent="codex",
             assets=("a", "b"), severities=("CRITICAL", "LOW"))
    snapshot(repo, "c", device="device-1", agent="trae")
    snapshot(repo, "d", device="device-2", agent="codex")
    snapshot(repo, "e")
    snapshot(repo, "f", project="other")
    data = client.get("/v1/static/inventory?view=groups").json()
    assert data["total"] == data["summary"]["groups"] == 5
    assert data["summary"]["device_agents"] == 3
    group = data["items"][0]
    assert (group["device_id"], group["agent"], group["assets"], group["findings"]) == ("device-1", "codex", 3, 3)
    assert group["risky_assets"] == group["high_risk_assets"] == 2
    assert group["kinds"] == [{"kind": "Skill", "count": 3}]
    assert group["risk"] == {"top": "CRITICAL", "severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0}}
    assert set(group["projects"]) == {"p", "other"}
    detail = client.get("/v1/static/inventory", params={"group_id": group["group_id"]}).json()
    assert detail["total"] == 3
    assert {(a["scan_id"], a["asset_id"]) for a in detail["items"]} == {("a", "a"), ("b", "a"), ("b", "b")}
    assert detail["summary"]["sources"] == 2
    assert detail["group"] == group
    assert "/private/snapshot" not in str(data)


def test_group_identity_survives_new_snapshot_and_retains_empty_and_partial_sources(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "old", device="d", agent="codex", severities=("CRITICAL",))
    original = client.get("/v1/static/inventory?view=groups").json()["items"][0]
    snapshot(repo, "empty", device="d", agent="codex", day=2, assets=())
    snapshot(repo, "failed", device="d", agent="codex", day=3, status="FAILED")
    group = client.get("/v1/static/inventory?view=groups").json()["items"][0]
    assert group["group_id"] == original["group_id"]
    assert group["assets"] == group["findings"] == 0
    assert group["sources"][0]["scan_id"] == "empty"
    detail = client.get("/v1/static/inventory", params={"group_id": group["group_id"]}).json()
    assert detail["items"] == [] and detail["summary"]["sources"] == 1
    snapshot(repo, "partial", device="d", agent="codex", day=4, assets=(), status="PARTIAL")
    group = client.get("/v1/static/inventory?view=groups&risk=unknown").json()["items"][0]
    assert group["group_id"] == original["group_id"] and group["risk_state"] == "unknown"
    assert group["scan_status"] == "PARTIAL" and group["partial_sources"] == 1


def test_group_filters_and_pagination_do_not_change_full_summary_or_top_risks(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "a", device="d-1", agent="codex", severities=("CRITICAL",))
    snapshot(repo, "b", device="d-2", agent="trae", severities=("HIGH",))
    snapshot(repo, "c", device="d-3", agent="codex")
    data = client.get("/v1/static/inventory?view=groups&limit=1&offset=1").json()
    assert data["total"] == 3 and len(data["items"]) == 1
    assert data["summary"]["assets"] == 3 and data["summary"]["groups"] == 3
    assert data["top_risks"][0]["device_id"] == "d-1"
    data = client.get("/v1/static/inventory?view=groups&agent=codex&q=D-3&kind=Skill&risk=clear").json()
    assert data["total"] == 1 and data["items"][0]["device_id"] == "d-3"
    assert data["summary"]["assets"] == 3
    assert client.get("/v1/static/inventory?view=groups&q=%").json()["total"] == 0


def test_unknown_group_and_foreign_scan_never_fall_back_to_global_assets(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "a", device="d-1", agent="codex")
    snapshot(repo, "b", device="d-2", agent="codex")
    group = client.get("/v1/static/inventory?view=groups&q=d-1").json()["items"][0]
    for params in ({"group_id": "no-such-group"}, {"group_id": group["group_id"], "scan_id": "b"}):
        data = client.get("/v1/static/inventory", params=params).json()
        assert data["items"] == [] and data["summary"]["sources"] == data["total"] == 0
    assert client.get("/v1/static/inventory?group_id=no-such-group").json()["group"] is None


def test_group_aggregation_is_complete_beyond_asset_page_and_preserves_scan_namespace(tmp_path):
    client, repo = client_repo(tmp_path)
    snapshot(repo, "a", device="d", agent="codex", assets=tuple(f"a-{i}" for i in range(2005)))
    snapshot(repo, "b", device="d", agent="codex", project="other", assets=("a-2004",))
    with repo.connect() as connection:
        connection.execute("INSERT INTO findings(finding_id,scan_id,asset_id,rule_id,severity) VALUES(?,?,?,?,?)",
                           ("tail-risk", "a", "a-2004", "tail-rule", "CRITICAL"))
    group = client.get("/v1/static/inventory?view=groups&limit=1").json()["items"][0]
    assert group["assets"] == 2006 and group["findings"] == group["risky_assets"] == 1
    detail = client.get("/v1/static/inventory", params={"group_id": group["group_id"], "q": "a-2004"}).json()
    assert detail["total"] == 2
    assert {row["scan_id"]: row["risk"]["count"] for row in detail["items"]} == {"a": 1, "b": 0}


def test_groups_empty_auth_and_invalid_view(tmp_path):
    client, _ = client_repo(tmp_path, token="group-test")
    assert client.get("/v1/static/inventory?view=groups").status_code == 401
    headers = {"X-AG-Admin": "group-test"}
    data = client.get("/v1/static/inventory?view=groups", headers=headers).json()
    assert data["total"] == data["summary"]["device_agents"] == data["summary"]["groups"] == 0
    for query in ("view=no-such-view", "view=groups&scan_id=a", "view=groups&group_id=a"):
        assert client.get("/v1/static/inventory?" + query, headers=headers).status_code == 400
