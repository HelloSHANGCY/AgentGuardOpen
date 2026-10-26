"""行为基线数据与训练服务（创新检测实施方案 §5）：真实会话记录、手动训练、启用与回滚。"""

import json
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from agentguard.detection import behavior as B

CWD = "/home/dev/project"
TOKEN = "agd_behavior_dev"
ADMIN = {"X-AG-Admin-Token": "adm"}


def make_client(monkeypatch, tmp_path=None):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AG_AGENT_DEVICES", json.dumps({TOKEN: {"device_id": "bh-dev", "profile": "developer"}}))
    monkeypatch.setenv("AG_AGENT_ADMIN_TOKEN", "adm")
    monkeypatch.setenv("AG_DATA_DIR", "")
    monkeypatch.setenv("AG_BEHAVIOR_DIR", str(tmp_path) if tmp_path else "")
    monkeypatch.setenv("AG_DISABLED_FEATURES", "")
    from agentguard.main import create_app

    return TestClient(create_app())


def bash(client, token, session, command, call_id):
    body = {"session_id": session, "hook_event_name": "PreToolUse", "cwd": CWD, "tool_name": "Bash",
            "tool_input": {"command": command}, "tool_use_id": call_id}
    response = client.post("/v1/agents/claude-code/hook", json=body, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    result = response.json()
    if result["action"] != "deny":
        body.update(hook_event_name="PostToolUse", tool_response="ok")
        assert client.post("/v1/agents/claude-code/hook", json=body,
                           headers={"Authorization": f"Bearer {token}"}).status_code == 200
    return result


def test_recorder_keeps_symbols_only_and_skips_evaluation_devices(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path)
    bash(client, TOKEN, "bh-1", "pytest -q tests/test_secret_token_abc.py", "c1")
    issued = client.post("/v1/admin/devices", headers=ADMIN,
                         json={"device_id": "eval-bh", "profile": "developer", "purpose": "evaluation"}).json()
    bash(client, issued["token"], "bh-e", "git status", "c2")
    overview = client.get("/v1/admin/baseline", headers=ADMIN).json()
    assert overview["active"] == "builtin" and overview["data"]["sessions"] == 1
    row = overview["data"]["devices"][0]
    assert row["device"] == "bh-dev" and row["steps"] == 1 and row["registered"]
    stored = (tmp_path / B.RECORD_FILE).read_text(encoding="utf-8")
    assert "EXEC:test" in stored and "secret_token" not in stored and "eval-bh" not in stored


def test_recorder_file_round_trip_and_clear(tmp_path):
    recorder = B.BehaviorRecorder(str(tmp_path))
    for index in range(3):
        recorder.record(device="d1" if index < 2 else "d2", agent="codex", trace=f"t{index}", intents=["test"],
                        symbols=["EXEC:test"], decision="DENY" if index == 0 else "ALLOW")
    sessions = B.sessions_from_records(B.BehaviorRecorder(str(tmp_path)).records())
    assert len(sessions) == 3 and sum(item["flagged"] for item in sessions) == 1
    assert recorder.stats()["persistent"] and recorder.stats()["bytes"] > 0
    assert recorder.clear("d1") == 2 and recorder.stats()["sessions"] == 1
    assert recorder.clear() == 1 and recorder.records() == []
    # 参数原文从不进入记录：接口只接受符号。
    recorder.record(device="d1", agent="x", trace="t", intents=[], symbols=[], decision="ALLOW")
    assert recorder.records() == []


def fake_records(count, device="dev-a", flagged=0, now=None, symbols=("FILE_READ:home", "EXEC:vcs")):
    now = now or time.time()
    items = []
    for index in range(count):
        for step, symbol in enumerate(symbols):
            items.append({"t": now - 60, "device": device, "agent": "codex", "trace": f"{device}-{index}",
                          "intents": [], "symbols": [symbol],
                          "feature_schema_version": B.A.FEATURE_SCHEMA_VERSION,
                          "sequence_semantics_version": B.A.SEQUENCE_SEMANTICS_VERSION, "execution": "succeeded",
                          "decision": "ASK" if index < flagged and step == 1 else "ALLOW"})
    return items


def test_train_selects_data_and_reports():
    now = time.time()
    records = fake_records(20, flagged=3, now=now) + fake_records(4, device="dev-b", now=now - 90 * 86400)
    model = B.train({"since_days": 30, "scoring_mode": "legacy", "personalize": True}, records, "m20261003-120000-abcd", now=now)
    meta = model["meta"]
    assert meta["skipped"] == {"old": 4, "flagged": 3, "device": 0, "flagged_steps": 0, "incompatible_records": 0}
    # 17 条可用真实会话：按哈希留出约 20% 只做评估。
    assert meta["holdout_sessions"] + meta["recorded_sessions"] == 17 and meta["holdout_sessions"] > 0
    assert meta["corpus_sessions"] == 49 and meta["personalized_devices"] == ["dev-a"]
    assert set(meta["auc_components"]) == {"rarity", "rarity_intent", "rarity_context", "full"}
    # 个性化后，dev-a 自己的常见行为（读家目录）不再罕见。
    baseline = B.A.Baseline.from_dict(model)
    assert baseline.step_score(B.A.START, "FILE_READ:home", [], "dev-a")["rarity"] < \
        baseline.step_score(B.A.START, "FILE_READ:home", [])["rarity"]
    # 每台设备的会话去向：控制台据此解释“为什么只用了 N 个会话”。
    report = {row["device"]: row for row in meta["device_report"]}
    assert report["dev-a"]["flagged"] == 3 and report["dev-a"]["train"] + report["dev-a"]["holdout"] == 17
    assert report["dev-a"]["personalized"] and report["dev-b"]["old"] == 4 and not report["dev-b"]["personalized"]
    only_recorded = B.train({"use_corpus": False, "devices": ["dev-b"], "since_days": 0}, records, "x", now=now)
    assert only_recorded["meta"]["train_sessions"] == 4 and only_recorded["meta"]["skipped"]["device"] == 20
    assert not {row["device"]: row for row in only_recorded["meta"]["device_report"]}["dev-a"]["selected"]


def test_flagged_step_mode_keeps_the_rest_of_the_session():
    now = time.time()
    records = fake_records(3, flagged=3, now=now, symbols=("EXEC:test", "EXEC:net", "EXEC:vcs"))
    strict = B.train({"use_corpus": False, "personalize": False}, records + fake_records(1, device="dev-c", now=now), "x",
                     now=now)
    assert strict["meta"]["skipped"]["flagged"] == 3 and strict["meta"]["recorded_sessions"] == 1
    for legacy, mode in ((True, "session"), (False, "none")):
        assert B.normalize_params({"exclude_flagged": legacy})["exclude_flagged"] == mode
    model = B.train({"use_corpus": False, "exclude_flagged": "step"}, records, "x", now=now)
    meta = model["meta"]
    assert meta["recorded_sessions"] == 3 and meta["skipped"]["flagged_steps"] == 3
    # 被确认的那一步不进入计数，前后两步之间的转移也被切断。
    assert "EXEC:net" not in model["unigram"] and "EXEC:vcs" not in model["transitions"].get("EXEC:test", {})
    assert round(model["unigram"]["EXEC:vcs"], 2) == 3     # 时间衰减：60 秒前的会话权重略小于 1


def test_repeated_symbols_in_one_step_count_once():
    records = [{"t": time.time(), "device": "d", "agent": "x", "trace": "t", "intents": [], "decision": "ALLOW",
                "symbols": ["EXEC:interp"] + ["FILE_READ:workspace", "FILE_READ:other"] * 30}]
    steps = B.sessions_from_records(records)[0]["steps"]
    assert steps[0]["symbols"] == ["EXEC:interp", "FILE_READ:workspace", "FILE_READ:other"]


def test_assessment_compares_against_active_model_on_same_data():
    now = time.time()
    records = fake_records(30, now=now)
    active = B.A.Baseline.load(str(pathlib.Path(B.A.BASELINE_PATH).with_name("transitions.legacy.json")))
    model = B.train({"min_device_sessions": 3, "scoring_mode": "legacy", "personalize": True}, records, "x", now=now, compare=active)
    meta = model["meta"]
    # 当前模型在同一份留出数据上重新评估（内置模型自身的 meta 里没有留出数据）。
    assert meta["compare"]["version"] == "builtin" and meta["compare"]["holdout_steps"] == meta["holdout_steps"] > 0
    checks = {item["id"]: item for item in meta["assessment"]["checks"]}
    assert set(checks) == {"data", "holdout", "benign", "risk", "auc"}
    # 个性化后，该设备常见的“读家目录”不再触发观察：留出评估优于内置模型。
    assert checks["holdout"]["level"] == "ok" and checks["holdout"]["candidate"] < checks["holdout"]["active"]
    assert meta["assessment"]["verdict"] in ("recommend", "review")
    # 训练数据把攻击步骤学成常见：风险点召回明显下降 → 不建议启用。
    poisoned = fake_records(40, now=now, symbols=("FILE_READ:credential_store", "EXEC:net", "NET_FETCH:external",
                                                  "FILE_WRITE:persistence", "FILE_READ:project_secret"))
    for params in ({"personalize": False}, {"min_device_sessions": 3}):
        # 投毒数据进入共享计数或某台设备的个性化计数，都应在风险点检查中暴露出来。
        bad = B.train({"scoring_mode": "legacy", "personalize": True, **params}, poisoned, "y", now=now, compare=active)["meta"]["assessment"]
        assert bad["verdict"] == "reject", params
        assert next(item for item in bad["checks"] if item["id"] == "risk")["level"] == "fail"
    # 固定阈值：沿用当前模型的阈值，排除分位标定的抽样波动。
    fixed = B.train({"threshold": active.threshold}, fake_records(3, now=now), "f", now=now, compare=active)
    assert fixed["threshold"] == active.threshold and fixed["params"]["threshold"] == active.threshold
    # 没有留出数据时只能人工判断。
    few = B.train({}, fake_records(3, now=now), "z", now=now, compare=active)["meta"]["assessment"]
    assert few["verdict"] != "recommend"
    assert next(item for item in few["checks"] if item["id"] == "holdout")["candidate"] is None


@pytest.mark.parametrize("params", [
    {"quantile": 10}, {"unknown": 1}, {"use_corpus": False, "use_recorded": False}, {"personalize": "yes"},
    {"devices": "dev-a"}, {"holdout": 0.95}, {"exclude_flagged": "all"}, {"threshold": 99},
])
def test_train_rejects_bad_params(params):
    with pytest.raises(ValueError):
        B.train(params, [], "x")


def test_train_requires_data():
    with pytest.raises(ValueError):
        B.train({"use_corpus": False}, [], "x")


def test_train_activate_rollback_via_api(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path)
    for index in range(6):
        bash(client, TOKEN, f"bh-s{index}", "cat ~/.gitconfig", f"c{index}")
    assert client.post("/v1/admin/baseline/train", json={"params": {"quantile": 5}}, headers=ADMIN).status_code == 400
    assert client.post("/v1/admin/baseline/train", json={}).status_code == 401
    trained = client.post("/v1/admin/baseline/train", headers=ADMIN,
                          json={"params": {"min_device_sessions": 3, "scoring_mode": "legacy", "personalize": True}}).json()
    version = trained["version"]
    assert trained["meta"]["recorded_sessions"] == 6 and trained["meta"]["personalized_devices"] == ["bh-dev"]
    overview = client.get("/v1/admin/baseline", headers=ADMIN).json()
    assert overview["active"] == "builtin" and [m["version"] for m in overview["models"]] == ["builtin", "builtin-legacy", version]

    # 启用前：读家目录配置对该设备仍偏罕见；启用后：个性化模型把它视为常见，并在决策里标出模型版本。
    assert client.post("/v1/admin/baseline/activate", json={"version": version}, headers=ADMIN).status_code == 200
    result = bash(client, TOKEN, "bh-next", "cat ~/.gitconfig", "c9")
    decision = next(item for item in client.get("/v1/runtime/decisions").json()["decisions"]
                    if item["decision_id"] == result["decision_id"])
    assert decision["anomaly"]["baseline"] == version and decision["anomaly"]["personalized"]

    assert client.delete(f"/v1/admin/baseline/models/{version}", headers=ADMIN).status_code == 400   # 正在使用
    assert client.delete("/v1/admin/baseline/models/builtin", headers=ADMIN).status_code == 400
    assert client.delete("/v1/admin/baseline/models/..%2Factive", headers=ADMIN).status_code in (404, 405)
    assert client.post("/v1/admin/baseline/activate", json={"version": "../x"}, headers=ADMIN).status_code == 404

    # 重启后仍是已启用的模型；回滚到内置模型后可以删除候选模型。
    restarted = B.BehaviorService(str(tmp_path))
    assert restarted.active_version == version and restarted.baseline.version == version
    assert client.post("/v1/admin/baseline/activate", json={"version": "builtin"}, headers=ADMIN).status_code == 200
    assert client.delete(f"/v1/admin/baseline/models/{version}", headers=ADMIN).status_code == 200
    assert client.delete("/v1/admin/baseline/records", headers=ADMIN).json()["removed"] == 14


def test_legacy_and_flagged_data_are_explained_without_rewriting_records(monkeypatch, tmp_path):
    legacy = fake_records(31)
    for item in legacy:
        for field in ("feature_schema_version", "sequence_semantics_version", "execution"):
            item.pop(field)
    records = legacy + fake_records(3, device="dev-new", flagged=3)
    record_path = tmp_path / B.RECORD_FILE
    record_path.write_text("".join(json.dumps(item) + "\n" for item in records))
    original = record_path.read_bytes()
    client = make_client(monkeypatch, tmp_path)
    overview = client.get("/v1/admin/baseline", headers=ADMIN).json()
    data = overview["data"]
    assert (data["sessions"], data["compatible_sessions"], data["compatible_steps"]) == (34, 3, 6)
    assert data["incompatible_records"] == 62
    assert overview["extractor"] == {"feature_schema_version": B.A.FEATURE_SCHEMA_VERSION,
                                      "sequence_semantics_version": B.A.SEQUENCE_SEMANTICS_VERSION}

    trained = client.post("/v1/admin/baseline/train", headers=ADMIN, json={}).json()
    assert trained["compatible"] and trained["feature_schema_version"] == B.A.FEATURE_SCHEMA_VERSION
    assert trained["sequence_semantics_version"] == B.A.SEQUENCE_SEMANTICS_VERSION
    assert trained["meta"]["recorded_sessions"] == 0
    assert trained["meta"]["skipped"]["flagged"] == 3
    rows = {row["device"]: row for row in trained["meta"]["device_report"]}
    assert rows["dev-a"]["sessions"] == 31 and rows["dev-a"]["incompatible_records"] == 62
    assert rows["dev-a"]["train"] == rows["dev-a"]["compatible_sessions"] == 0
    assert rows["dev-new"]["compatible_sessions"] == rows["dev-new"]["flagged"] == 3

    empty = client.post("/v1/admin/baseline/train", headers=ADMIN, json={"params": {"use_corpus": False}})
    assert empty.status_code == 400
    assert "版本不兼容记录 62 条" in empty.json()["detail"]
    assert "含拦截/确认会话 3 个" in empty.json()["detail"]
    selected = client.post("/v1/admin/baseline/train", headers=ADMIN,
                           json={"params": {"use_corpus": False, "exclude_flagged": "step"}}).json()
    assert selected["meta"]["recorded_sessions"] == 3
    assert selected["meta"]["skipped"]["flagged_steps"] == 3
    assert selected["meta"]["train_steps"] == 3  # 排除步骤的 cut 标记不计入训练步数。
    assert record_path.read_bytes() == original


def test_legacy_model_is_preserved_and_current_candidate_can_activate(monkeypatch, tmp_path):
    version = "m20261011-084540-261b"
    model = json.loads(pathlib.Path(B.A.BASELINE_PATH).read_text())
    model.update(version=version)
    model.pop("feature_schema_version")
    model.pop("sequence_semantics_version")
    models = tmp_path / "models"
    models.mkdir()
    path = models / (version + ".json")
    path.write_text(json.dumps(model))
    original = path.read_bytes()
    (tmp_path / "active.json").write_text(json.dumps({"version": version}))
    client = make_client(monkeypatch, tmp_path)
    overview = client.get("/v1/admin/baseline", headers=ADMIN).json()
    assert overview["active"] == B.BUILTIN and overview["model_compatible"] and overview["load_warning"]
    old = next(m for m in overview["models"] if m["version"] == version)
    assert not old["compatible"] and old["feature_schema_version"] == old["sequence_semantics_version"] == 0
    assert "重新训练" in old["incompatibility_reason"]
    rejected = client.post("/v1/admin/baseline/activate", headers=ADMIN, json={"version": version})
    assert rejected.status_code == 400 and "当前 3/2" in rejected.json()["detail"]

    trained = client.post("/v1/admin/baseline/train", headers=ADMIN, json={}).json()
    assert client.get("/v1/admin/baseline", headers=ADMIN).json()["active"] == B.BUILTIN
    activated = client.post("/v1/admin/baseline/activate", headers=ADMIN, json={"version": trained["version"]})
    assert activated.status_code == 200
    restarted = B.BehaviorService(str(tmp_path))
    assert restarted.active_version == trained["version"] and restarted.baseline.compatible
    assert not restarted.load_warning and path.read_bytes() == original


def test_more_calls_in_one_session_increase_steps_not_session_count():
    recorder = B.BehaviorRecorder()
    for index in range(4):
        recorder.record(device="dev", agent="codex", trace="session-a" if index < 3 else "session-b",
                        call_id=f"c{index}", intents=[], symbols=["EXEC:test"], decision="ALLOW")
    stats = recorder.stats()
    assert stats["sessions"] == stats["compatible_sessions"] == 2
    assert stats["steps"] == stats["compatible_steps"] == 4
