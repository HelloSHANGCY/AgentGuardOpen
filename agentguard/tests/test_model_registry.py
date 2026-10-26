"""模型接入与用途绑定：实际调用选择、迁移、持久化、密钥边界与原子更新。"""

import json
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from test_judge import SECRET_READ, FakeModel, Session, analyses, permission, wait_for

from agentguard.detection import intent as I
from agentguard.llm import registry as R


def spec(name="模型 A", provider="供应商 A", key="opaque-provider-a-key-0001", **changes):
    return {"name": name, "provider": provider, "url": "https://a.example.test/v1", "model": "shared-model",
            "key": key, "effort": "off", "usages": {}, **changes}


@pytest.fixture()
def runtime(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from agentguard import main
    from agentguard.llm import judge as J

    for name, value in {"AG_LOCAL_TEST": "1", "AG_AGENT_ADMIN_TOKEN": "", "AG_INTENT_LLM_KEY": "",
                        "AG_DATA_DIR": "", "AG_AGENT_DEVICE_DIR": str(tmp_path), "AG_STATIC_ENABLED": "0",
                        "AG_AGENT_DEVICES": json.dumps({"agd_judge_dev": {"device_id": "dev-judge",
                          "actor": {"sub": "alice"}, "profile": "developer"}})}.items():
        monkeypatch.setenv(name, value)
    fake, engines = FakeModel(), []

    def chat(url, *args):
        result = fake(url, *args)
        fake.calls[-1]["url"] = url
        return result

    monkeypatch.setattr(J, "chat_json", chat)
    factory = main.RuntimeDecisionEngine

    def capture(settings):
        engine = factory(settings)
        engines.append(engine)
        return engine

    monkeypatch.setattr(main, "RuntimeDecisionEngine", capture)
    with TestClient(main.create_app()) as client:
        yield client, engines[0], fake
    for engine in engines:
        engine.intents._pool.shutdown(wait=True)
        engine.judge._review_pool.shutdown(wait=True)
        engine.judge._analysis_pool.shutdown(wait=True)


def create(client, **changes):
    response = client.post("/v1/admin/models", json=spec(**changes))
    assert response.status_code == 200, response.text
    return response.json()


def test_provider_presets_cover_common_openai_compatible_services():
    from agentguard.llm.providers import PRESETS

    providers = {preset["provider"]: preset for preset in PRESETS}
    assert {"OpenCode Go", "DeepSeek", "OpenAI", "通义千问", "智谱 AI", "Moonshot Kimi",
            "SiliconFlow", "OpenRouter", "Google Gemini"} <= providers.keys()
    assert providers["DeepSeek"]["url"] == "https://api.deepseek.com/chat/completions"
    assert [model["id"] for model in providers["DeepSeek"]["models"]][:1] == ["deepseek-flash"]
    assert len({preset["id"] for preset in PRESETS}) == len(PRESETS)
    assert all(preset["url"].startswith("https://") and preset["base_urls"] for preset in PRESETS)


def test_discovery_uses_stored_key_only_for_unchanged_url(runtime, monkeypatch):
    client, _, _ = runtime
    calls = []

    def fake_discover(url, key, provider=""):
        calls.append((url, key, provider))
        return {"provider": provider, "models_url": url, "models": [], "count": 0, "with_efforts": 0}

    monkeypatch.setattr(R, "discover_models", fake_discover)
    model = create(client, url="https://api.deepseek.com/chat/completions", key="stored-discovery-key-1234")
    response = client.post("/v1/admin/models/discover", json={
        "config": {"url": "https://api.deepseek.com/chat/completions"}, "model_id": model["model_id"]})
    assert response.status_code == 200 and calls[0][1] == "stored-discovery-key-1234"
    response = client.post("/v1/admin/models/discover", json={
        "config": {"url": "https://evil.example.test/v1/chat/completions"}, "model_id": model["model_id"]})
    assert response.status_code == 400 and len(calls) == 1


def test_multiple_providers_and_keys_optional_usages_and_restart(runtime, tmp_path):
    client, engine, _ = runtime
    first = create(client)
    second = create(client, name="另一个密钥", key="opaque-provider-a-key-0002")
    third = create(client, provider="供应商 B", url="https://b.example.test/v1")
    assert len({first["model_id"], second["model_id"], third["model_id"]}) == 3
    listing = client.get("/v1/admin/models").json()
    assert len(listing["models"]) == 3 and listing["bindings"] == {}
    assert all(not row["usages"] for row in listing["models"])
    assert "opaque-provider" not in json.dumps(listing)
    assert engine.models.resolve("approval")["key"] == ""
    path = tmp_path / "llm-models.json"
    assert path.stat().st_mode & 0o077 == 0
    loaded = R.ModelRegistry(str(path))
    assert len(loaded.overview()["models"]) == 3 and loaded.managed
    assert client.get("/v1/admin/judge").json()["approval"]["enabled"] is False


def test_go_presets_validate_existing_bindings_and_overrides_atomically(runtime, tmp_path):
    from agentguard.llm.providers import GO_URL

    client, _, _ = runtime
    preset = client.get("/v1/admin/models").json()["presets"][0]
    assert preset["provider"] == "OpenCode Go" and preset["url"] == GO_URL
    assert all(model["id"].startswith(("deepseek-", "glm-")) for model in preset["models"])
    model = create(client, provider="OpenCode Go", url=GO_URL, model="glm-5.2", effort="default",
                   usages={"intent": {}, "analysis": {"effort": "off"}})
    url = "/v1/admin/models/" + model["model_id"]
    path = tmp_path / "llm-models.json"
    before = path.read_bytes()
    for config in ({"model": "glm-5.3"}, {"usages": {"analysis": {"effort": "xhigh"}}},
                   {"model": "glm-5.3", "usages": {"intent": {}}}, {"effort": "minimal"}):
        response = client.put(url, json=config)
        assert response.status_code == 400 and path.read_bytes() == before
    assert client.put(url, json={"model": "glm-5.3", "usages": {"analysis": {"effort": "max"}}}).status_code == 200
    assert R.ModelRegistry(str(path)).resolve("analysis")["effort"] == "max"
    second = create(client, provider="OpenCode Go", url=GO_URL, model="deepseek-flash", effort="low",
                    key="another-go-key-0002")
    assert second["model_id"] != model["model_id"] and second["key_set"]


def test_go_wire_headers_follow_one_trace_across_intent_review_analysis_and_proposals(runtime, monkeypatch):
    from test_opencode_go import reply

    from agentguard.llm import client as C
    from agentguard.llm import prompts as P
    from agentguard.llm.providers import GO_URL

    client, engine, fake = runtime
    create(client, url=GO_URL, model="glm-5.2", effort="off", usages={"intent": {"timeout": 5}})
    create(client, url=GO_URL, model="deepseek-flash", effort="high", usages={"approval": {}})
    create(client, url=GO_URL, model="glm-5.3", effort="max", usages={"analysis": {}})
    engine.judge.chat = C.chat_json
    engine.models.chat = C.chat_json
    sent = []

    def urlopen(request, timeout):
        body = json.loads(request.data)
        system, user = [message["content"] for message in body["messages"]]
        kind = "intent" if system == I.SYSTEM else "test" if '"ok": true' in system else "judge"
        sent.append((kind, body["model"], request.get_header("X-opencode-session")))
        if kind == "intent":
            return reply({"intents": ["test"]})
        if kind == "test":
            return reply({"ok": True})
        return reply(fake(request.full_url, body["model"], "fake", timeout, system, user, body["max_tokens"]))

    monkeypatch.setattr(C.urllib.request, "urlopen", urlopen)
    assert client.put("/v1/admin/intent", json={"enabled": True}).status_code == 200
    assert client.put("/v1/admin/judge", json={"approval_enabled": True, "analysis_mode": "full"}).status_code == 200
    first = Session(client, "go-session-a")
    first.send("UserPromptSubmit", prompt="运行测试")
    first.pre(*SECRET_READ)
    first.send("Stop")
    wait_for(lambda: len(analyses(client)) == 1 and analyses(client)[0]["status"] == "done")
    wait_for(lambda: len([call for call in sent if call[0] == "intent"]) == 1)
    assert {model for _, model, _ in sent} == {"glm-5.2", "deepseek-flash", "glm-5.3"}
    headers_a = {header for _, _, header in sent}
    assert len(headers_a) == 1
    first.send("UserPromptSubmit", prompt="再次运行测试")
    wait_for(lambda: len([call for call in sent if call[0] == "intent"]) == 2)
    assert {header for _, _, header in sent} == headers_a
    record = analyses(client)[0]
    engine.judge.proposals.propose = lambda store, record, steps, chat, render, **kw: (chat(P.SYSTEM_ANALYSIS, "json"), [])[1]
    engine.judge._propose(SimpleNamespace(publish=lambda *args: None), record, [], dict(engine.judge._config))
    assert sent[-1][2] in headers_a

    second = Session(client, "go-session-b")
    second.send("UserPromptSubmit", prompt="运行测试")
    wait_for(lambda: len([call for call in sent if call[0] == "intent"]) == 3)
    assert sent[-1][2] not in headers_a
    result = client.post("/v1/admin/models/test", json={"config": spec(url=GO_URL, model="deepseek-flash")})
    assert result.json()["ok"] and sent[-1][0] == "test" and sent[-1][2] not in headers_a


def test_api_purpose_conflicts_are_explicit_and_update_is_atomic(runtime, tmp_path):
    client, _, _ = runtime
    first = create(client, usages={"approval": {"timeout": 12}})
    second = create(client, name="B", provider="B", key="opaque-provider-b-key-0002")
    path = tmp_path / "llm-models.json"
    before = path.read_bytes()
    rejected = client.put("/v1/admin/models/" + second["model_id"], json={"name": "修改应回滚", "usages": {"approval": {}}})
    assert rejected.status_code == 409 and path.read_bytes() == before
    listing = client.get("/v1/admin/models").json()
    assert next(m for m in listing["models"] if m["model_id"] == second["model_id"])["name"] == "B"
    changed = client.put("/v1/admin/models/" + second["model_id"], json={"usages": {"approval": {}}, "replace_usages": True})
    assert changed.status_code == 200
    listing = client.get("/v1/admin/models").json()
    assert listing["bindings"]["approval"]["model_id"] == second["model_id"]
    assert next(m for m in listing["models"] if m["model_id"] == first["model_id"])["usages"] == {}
    assert R.ModelRegistry(str(path)).resolve("approval")["key"] == "opaque-provider-b-key-0002"


def test_actual_review_and_analysis_use_independent_suppliers_and_keys(runtime):
    client, _, fake = runtime
    review = create(client, usages={"approval": {"timeout": 12, "effort": "low"}})
    analysis = create(client, name="分析模型", provider="供应商 B", key="opaque-provider-b-key-0002",
                      url="https://b.example.test/v1", model="analysis-model", effort="high",
                      usages={"analysis": {"timeout": 45}})
    response = client.put("/v1/admin/judge", json={"approval_enabled": True, "analysis_mode": "full"})
    assert response.status_code == 200
    assert response.json()["approval"]["model_id"] == review["model_id"]
    assert response.json()["analysis"]["model_id"] == analysis["model_id"]
    session = Session(client)
    session.send("UserPromptSubmit", prompt="跑一下测试")
    session.send("PreToolUse", tool_name=SECRET_READ[0], tool_input=SECRET_READ[1], tool_use_id="modern-call",
                 _ag={"client": "agentguard-endpoint/0.12.0"})
    session.send("Stop")
    wait_for(lambda: [r for r in analyses(client) if r["status"] == "done"])
    approval_call, analysis_call = fake.of("review")[0], fake.of("analysis")[0]
    assert (approval_call["url"], approval_call["key"], approval_call["timeout"], approval_call["effort"]) == (
        "https://a.example.test/v1", "opaque-provider-a-key-0001", 12, "low")
    assert (analysis_call["url"], analysis_call["key"], analysis_call["timeout"], analysis_call["effort"]) == (
        "https://b.example.test/v1", "opaque-provider-b-key-0002", 45, "high")
    assert client.get("/v1/admin/judge").json()["approval"]["hook_timeout"] == 13


def test_intent_switches_classifier_without_restart_and_never_inherits_other_keys(runtime, monkeypatch):
    client, engine, _ = runtime
    first = create(client, usages={"intent": {"timeout": 4}})
    second = create(client, name="意图 B", provider="B", key="opaque-intent-b-key-0002", url="https://b.example.test/v1")
    seen = []
    monkeypatch.setattr(I.LlmIntentClassifier, "classify", lambda self, text: seen.append((self.url, self.key, self.timeout)) or ["docs"])
    assert client.put("/v1/admin/intent", json={"enabled": True}).status_code == 200
    from agentguard.detection.anomaly import BehaviorState

    engine.intents.submit(BehaviorState(), "测试意图")
    wait_for(lambda: len(seen) == 1)
    assert seen[0] == ("https://a.example.test/v1", "opaque-provider-a-key-0001", 4)
    assert client.put("/v1/admin/models/" + second["model_id"], json={"usages": {"intent": {"timeout": 6}}, "replace_usages": True}).status_code == 200
    engine.intents.submit(BehaviorState(), "第二次")
    wait_for(lambda: len(seen) == 2)
    assert seen[1] == ("https://b.example.test/v1", "opaque-intent-b-key-0002", 6)
    assert client.put("/v1/admin/models/" + second["model_id"], json={"usages": {}}).status_code == 200
    assert engine.intents.status()["provider"] == "keyword" and not engine.intents.status()["key_set"]
    assert not client.get("/v1/admin/models").json()["models"][0]["usages"]
    assert first["key_set"]


def test_switching_review_binding_invalidates_cached_result(runtime):
    client, _, fake = runtime
    first = create(client, usages={"approval": {}})
    client.put("/v1/admin/judge", json={"approval_enabled": True})
    session = Session(client)
    session.send("UserPromptSubmit", prompt="查看 ssh 配置")
    assert permission(session.pre(*SECRET_READ)) == "none"
    assert permission(session.pre(*SECRET_READ)) == "none"
    assert len(fake.of("review")) == 1
    second = create(client, name="新的审批模型", key="opaque-provider-a-key-0002", usages={"approval": {}}, replace_usages=True)
    session.pre(*SECRET_READ)
    assert len(fake.of("review")) == 2 and fake.of("review")[-1]["key"] == "opaque-provider-a-key-0002"
    assert first["model_id"] != second["model_id"]


def test_old_configuration_is_imported_without_enabling_or_read_writes(runtime, tmp_path):
    client, _, _ = runtime
    client.put("/v1/admin/intent", json={"key": "old-intent-key-1111", "model": "old-intent"})
    client.put("/v1/admin/judge", json={"key": "old-judge-key-2222", "model": "old-review", "analysis_model": "old-analysis",
                                      "approval_effort": "low", "analysis_effort": "high"})
    listing = client.get("/v1/admin/models").json()
    assert not (tmp_path / "llm-models.json").exists() and listing["managed"] is False
    assert len(listing["models"]) == 3
    created = create(client, name="备用")
    listing = client.get("/v1/admin/models").json()
    loaded = R.ModelRegistry(str(tmp_path / "llm-models.json"))
    assert loaded.resolve("intent")["key"] == "old-intent-key-1111"
    assert loaded.resolve("analysis")["model"] == "old-analysis"
    assert loaded.resolve("approval")["effort"] == "low" and loaded.resolve("analysis")["effort"] == "high"
    assert created["usages"] == {} and listing["managed"]
    assert not client.get("/v1/admin/judge").json()["approval"]["enabled"]
    assert client.put("/v1/admin/judge", json={"model": "unexpected-legacy-edit"}).status_code == 400
    assert client.put("/v1/admin/intent", json={"key": "unexpected-old-key"}).status_code == 400


def test_unbinding_does_not_fall_back_to_legacy_key_or_disable_other_purpose(runtime):
    client, _, fake = runtime
    client.put("/v1/admin/judge", json={"key": "legacy-judge-key-2222", "approval_enabled": True})
    listing = client.get("/v1/admin/models").json()
    old_id = listing["bindings"]["approval"]["model_id"]
    client.put("/v1/admin/models/" + old_id, json={"usages": {"analysis": {}}})
    status = client.get("/v1/admin/judge").json()
    assert status["approval"]["enabled"] and not status["approval"]["active"] and not status["approval"]["key_set"]
    assert status["analysis"]["key_set"] and status["key_set"]
    assert client.put("/v1/admin/judge", json={"analysis_mode": "full"}).status_code == 200
    session = Session(client)
    session.send("UserPromptSubmit", prompt="看 ssh 配置")
    assert permission(session.pre(*SECRET_READ)) == "deny" and fake.of("review") == []
    assert client.put("/v1/admin/judge", json={"approval_enabled": True}).status_code == 400


def test_rule_proposals_use_analysis_connection(runtime):
    client, engine, _ = runtime
    create(client, usages={"approval": {}})
    create(client, name="B", provider="B", url="https://b.example.test/v1", key="opaque-provider-b-key-0002", usages={"analysis": {"effort": "high"}})
    seen = []
    engine.judge.chat = lambda *args: seen.append(args) or {}
    engine.judge.proposals.propose = lambda store, record, steps, chat, render, **kw: (chat("system", "user"), [])[1]
    record = {"analysis_id": "test-proposals"}
    engine.judge._propose(SimpleNamespace(publish=lambda *args: None), record, [], dict(engine.judge._config))
    assert seen[0][:3] == ("https://b.example.test/v1", "shared-model", "opaque-provider-b-key-0002")
    assert seen[0][-1] == "high"


def test_preserve_replace_clear_delete_key_and_no_secret_echo(runtime):
    client, engine, _ = runtime
    model = create(client)
    url = "/v1/admin/models/" + model["model_id"]
    assert client.put(url, json={"name": "改名", "key": ""}).status_code == 200
    assert engine.models._models[model["model_id"]]["key"] == "opaque-provider-a-key-0001"
    assert client.put(url, json={"key": "opaque-replacement-key-2222"}).status_code == 200
    assert client.get("/v1/admin/models").json()["models"][0]["key_hint"] == "…2222"
    assert client.put(url, json={"clear_key": True}).json()["key_set"] is False
    assert client.delete(url).status_code == 200 and client.get("/v1/admin/models").json()["models"] == []
    bound = create(client, usages={"analysis": {}})
    assert client.delete("/v1/admin/models/" + bound["model_id"]).status_code == 409


def test_connection_test_uses_unsaved_key_without_persistence_and_redacts_before_truncating(runtime, tmp_path):
    client, engine, _ = runtime
    model = create(client)
    before = (tmp_path / "llm-models.json").read_bytes()
    seen = []
    engine.models.chat = lambda *args: seen.append(args) or {"ok": True}
    response = client.post("/v1/admin/models/test", json={"model_id": model["model_id"], "config": {"key": "test-only-key-2222", "model": "test-model"}})
    assert response.json()["ok"] and seen[0][1:3] == ("test-model", "test-only-key-2222")
    assert (tmp_path / "llm-models.json").read_bytes() == before
    long_key = "opaque-provider-key-" + "x" * 400

    def failure(*args):
        raise RuntimeError("provider rejected " + long_key)

    engine.models.chat = failure
    result = client.post("/v1/admin/models/test", json={"model_id": model["model_id"], "config": {"key": long_key}}).json()
    assert not result["ok"] and "opaque-provider-key" not in result["error"] and "[REDACTED]" in result["error"]


@pytest.mark.parametrize("changes", [
    {"surprise": True}, {"provider": ""}, {"model": "bad model"}, {"url": "ftp://host"},
    {"url": "https://user:password@example.test/v1"}, {"key": "has space"}, {"clear_key": "yes"},
    {"usages": ["approval"]}, {"usages": {"unknown": {}}}, {"usages": {"intent": {"effort": "high"}}},
    {"usages": {"approval": {"timeout": True}}}, {"usages": {"analysis": {"timeout": 1}}},
    {"usages": {"analysis": {"mode": "full"}}}, {"effort": "ultra"},
])
def test_invalid_edit_keeps_saved_bytes(runtime, tmp_path, changes):
    client, _, _ = runtime
    model = create(client)
    before = (tmp_path / "llm-models.json").read_bytes()
    assert client.put("/v1/admin/models/" + model["model_id"], json=changes).status_code == 400
    assert (tmp_path / "llm-models.json").read_bytes() == before


def test_persistence_failure_keeps_previous_model_and_binding(tmp_path, monkeypatch):
    registry = R.ModelRegistry(str(tmp_path / "models.json"))
    model = registry.save(spec(usages={"approval": {}}))
    before = registry.overview()

    def failure(*args):
        raise OSError("disk failure")

    monkeypatch.setattr(R.os, "replace", failure)
    with pytest.raises(OSError):
        registry.save({"name": "must not survive", "usages": {}}, model["model_id"])
    assert registry.overview() == before


def test_corrupt_registry_does_not_restore_legacy_credentials(tmp_path):
    path = tmp_path / "models.json"
    path.write_text('{"version": 1, "models": {}, "bindings": []}')
    with pytest.raises(ValueError, match="could not be loaded"):
        R.ModelRegistry(str(path), legacy_loader=lambda: {"intent": spec()})


def test_admin_auth_covers_all_model_endpoints(runtime, monkeypatch):
    from fastapi.testclient import TestClient

    from agentguard.main import create_app

    monkeypatch.setenv("AG_LOCAL_TEST", "0")
    monkeypatch.setenv("AG_AGENT_ADMIN_TOKEN", "registry-admin")
    with TestClient(create_app()) as client:
        for method, path, payload in [("GET", "/v1/admin/models", None), ("POST", "/v1/admin/models", spec()),
                                      ("PUT", "/v1/admin/models/missing", {}), ("DELETE", "/v1/admin/models/missing", None),
                                      ("POST", "/v1/admin/models/test", {"config": spec()}),
                                      ("POST", "/v1/admin/models/discover", {"config": spec()})]:
            response = client.request(method, path, **({"json": payload} if payload is not None else {}))
            assert response.status_code == 401
        assert client.get("/v1/admin/models", headers={"X-AG-Admin-Token": "registry-admin"}).status_code == 200
