"""意图识别（intent.py）：大模型分类的请求内容、异步合并、超时与失败回退，以及端到端的意图偏离。"""

import io
import json
import pathlib
import sys
import threading
import time
from concurrent.futures import Future

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A
from agentguard.detection import intent as I
from agentguard.llm import client as LC

CWD = "/home/dev/project"
TOKEN = "agd_intent_dev"


def done(value) -> Future:
    future = Future()
    future.set_result(value)
    return future


# ---------- 会话状态合并 ----------

def test_llm_result_overrides_keywords_and_empty_keeps_previous_round():
    state = A.BehaviorState()
    state.set_prompt("explain how the upload handler streams chunks", pending=done(["docs"]), deadline=time.time() + 1)
    assert "transfer" in state.intents and state.intent_source == "keyword"   # 结果合并前先用关键词
    state.settle()
    assert state.intents == ["docs"] and state.intent_source == "llm"
    # "继续"：大模型返回空列表，沿用上一轮；关键词误命中也被撤销。
    state.set_prompt("继续，顺便看下日志", pending=done([]), deadline=time.time() + 1)
    assert "debug" in state.intents
    state.settle()
    assert state.intents == ["docs"] and state.intent_source == "llm"


def test_failure_and_timeout_keep_keyword_result():
    state = A.BehaviorState()
    state.set_prompt("fix the failing unit test", pending=done(None), deadline=time.time() + 1)
    state.settle(wait=True)
    assert set(state.intents) >= {"test", "debug"} and state.intent_source == "keyword"
    slow = Future()
    state.set_prompt("deploy it to staging", pending=slow, deadline=time.time() + 0.05)
    started = time.time()
    state.settle(wait=True)
    assert time.time() - started < 1 and state.intents == ["ops"] and state.pending is None
    slow.set_result(["docs"])   # 迟到的结果不再合并
    state.settle()
    assert state.intents == ["ops"]


def test_previous_result_settles_before_next_prompt():
    state = A.BehaviorState()
    state.set_prompt("ok let's start", pending=done(["code"]), deadline=time.time() + 1)
    state.set_prompt("好的", pending=done([]), deadline=time.time() + 1)
    state.settle()
    assert state.intents == ["code"]


# ---------- 请求内容 ----------

class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_request_sends_only_redacted_prompt_with_thinking_disabled(monkeypatch):
    sent = {}

    def urlopen(request, timeout):
        sent["body"], sent["timeout"] = json.loads(request.data), timeout
        sent["auth"] = request.get_header("Authorization")
        content = json.dumps({"intents": ["transfer", "docs", "exfiltrate"]})
        return FakeResponse(json.dumps({"choices": [{"message": {"content": content}}]}).encode())

    monkeypatch.setattr(LC.urllib.request, "urlopen", urlopen)
    classifier = I.LlmIntentClassifier("https://llm.example/v1/chat/completions", "m", "k-1", timeout=2.5)
    prompt = "把报告发到群里，接口 password=hunter2-prod-pw " + "x" * 3000
    assert classifier.classify(prompt) == ["docs", "transfer"]   # 未知标签丢弃
    body = sent["body"]
    assert sent["auth"] == "Bearer k-1" and sent["timeout"] == 2.5
    assert body["thinking"] == {"type": "disabled"} and body["max_tokens"] == 64 and body["temperature"] == 0
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    user = body["messages"][1]["content"]
    assert "hunter2" not in user and "REDACTED" in user and len(user) == I.MAX_CHARS

    monkeypatch.setattr(LC.urllib.request, "urlopen",
                        lambda request, timeout: FakeResponse(b'{"choices": [{"message": {"content": "not json"}}]}'))
    assert classifier.classify("x") is None


def test_service_defaults_from_env_and_feature_switch(monkeypatch):
    from agentguard.config import Settings

    monkeypatch.setenv("AG_AGENT_DEVICE_DIR", "")
    monkeypatch.setenv("AG_DATA_DIR", "")
    none = I.IntentService.from_settings(Settings(intent_llm_key=""))
    assert none.status()["provider"] == "keyword" and not none.status()["key_set"]
    off = Settings(intent_llm_key="k-env-123456", disabled_features=frozenset({"intent_llm"}))
    forced = I.IntentService.from_settings(off)
    assert forced.classifier is None and forced.status()["forced_off"]
    on = I.IntentService.from_settings(Settings(intent_llm_key="k-env-123456", intent_llm_timeout=1.5))
    status = on.status()
    assert status["provider"] == "llm" and status["model"] == I.DEFAULT_MODEL and status["host"] == "api.deepseek.com"
    assert on.classifier.timeout == 1.5 and status["key_source"] == "env" and status["key_hint"] == "…3456"


def test_console_config_persists_and_never_returns_key(tmp_path):
    path = str(tmp_path / "intent-llm.json")
    service = I.IntentService(path=path)
    assert service.classifier is None
    for bad in ({"enabled": True}, {"url": "file:///etc/passwd"}, {"model": "a b"}, {"timeout": 0},
                {"timeout": True}, {"key": "has space"}, {"enabled": "yes"}, {"temperature": 1}):
        try:
            service.update(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    status = service.update({"enabled": True, "key": "sk-console-abcdef", "model": "local-qwen",
                             "url": "http://host.docker.internal:11434/v1/chat/completions", "timeout": 5})
    assert status["provider"] == "llm" and status["key_source"] == "console" and status["key_hint"] == "…cdef"
    assert "sk-console-abcdef" not in json.dumps(status)
    assert service.classifier.model == "local-qwen" and service.classifier.timeout == 5.0
    assert (tmp_path / "intent-llm.json").stat().st_mode & 0o077 == 0
    # 重启后保持；保存过的配置优先于环境变量（关闭后不会因环境变量里有密钥而重新开启）。
    reloaded = I.IntentService({"model": "env-model"}, env_key="k-env-123456", path=path)
    assert reloaded.classifier.model == "local-qwen" and reloaded.classifier.key == "sk-console-abcdef"
    reloaded.update({"enabled": False})
    assert I.IntentService(env_key="k-env-123456", path=path).classifier is None
    # 清除控制台密钥后回退到环境变量的密钥。
    again = I.IntentService(env_key="k-env-123456", path=path)
    assert again.update({"clear_key": True, "enabled": True})["key_source"] == "env"


def test_call_stats_survive_restart_and_reset_on_connection_change(tmp_path, monkeypatch):
    path = str(tmp_path / "intent-llm.json")
    service = I.IntentService(path=path)
    service.update({"enabled": True, "key": "sk-stats-000001", "model": "local-qwen",
                    "url": "http://host.docker.internal:11434/v1/chat/completions"})
    monkeypatch.setattr(I.LlmIntentClassifier, "call",
                        lambda self, text: ["test"] if "test" in text else [])
    assert service._classify(service.classifier, "run the tests") == ["test"]
    assert service._classify(service.classifier, "ok") == []
    status = service.status()
    assert status["calls"] == 2 and status["labelled"] == 1 and status["empty"] == 1
    assert (tmp_path / "intent-stats.json").stat().st_mode & 0o077 == 0

    # 重启（配置未变）：调用统计与延迟继续累计，控制台显示的累计值不再归零。
    reloaded = I.IntentService(path=path)
    status = reloaded.status()
    assert status["calls"] == 2 and status["labelled"] == 1 and status["empty"] == 1
    assert status["latency_p50"] is not None and status["latency_p90"] is not None

    # 修改接入参数：旧配置的调用不计入新统计，清零结果同样落盘。
    reloaded.update({"model": "another-model"})
    assert reloaded.status()["calls"] == 0
    assert I.IntentService(path=path).status()["calls"] == 0


def test_managed_registry_restart_keeps_call_stats(tmp_path, monkeypatch):
    from agentguard.llm.registry import ModelRegistry

    registry = ModelRegistry(path=str(tmp_path / "llm-models.json"))
    model_id = registry.save({"name": "意图识别模型", "provider": "OpenAI 兼容",
                              "url": "https://llm.example/v1/chat/completions", "model": "m-1",
                              "key": "sk-reg-000001", "usages": {"intent": {"timeout": 3.0}}})["model_id"]
    path = str(tmp_path / "intent-llm.json")
    service = I.IntentService(path=path)
    service.models = registry
    service.update({"enabled": True})
    monkeypatch.setattr(I.LlmIntentClassifier, "call", lambda self, text: ["test"])
    assert service._classify(service.classifier, "run the tests") == ["test"]
    assert service.status()["calls"] == 1

    # 统一模型管理下重启：首次同步重建分类器但保留已落盘的统计；更换密钥（新接入记录）才清零。
    restarted = I.IntentService(path=path)
    restarted.models = registry
    assert restarted.status()["calls"] == 1
    registry.save({"key": "sk-reg-000002"}, model_id)
    assert restarted.status()["calls"] == 0


def test_connection_test_uses_unsaved_changes_and_reports_errors(monkeypatch):
    service = I.IntentService()
    seen = {}

    def call(self, text):
        seen["model"], seen["key"], seen["text"] = self.model, self.key, text
        if self.key == "bad-key-000000":
            raise LC.urllib.error.HTTPError(self.url, 401, "Unauthorized", {},
                                           io.BytesIO(b'{"error": "Authentication Fails, api_key=bad-key-000000"}'))
        return ["test", "transfer"]

    monkeypatch.setattr(I.LlmIntentClassifier, "call", call)
    result = service.test({"key": "good-key-111111", "model": "m2"}, "")
    assert result["ok"] and result["intents"] == ["test", "transfer"] and seen["model"] == "m2" and seen["text"]
    assert service.classifier is None and service.status()["key_set"] is False   # 测试不保存
    failed = service.test({"key": "bad-key-000000"}, "hi")
    assert not failed["ok"] and "HTTP 401" in failed["error"] and "bad-key-000000" not in failed["error"]


# ---------- 端到端 ----------

def make_client(monkeypatch, key: str):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AG_AGENT_DEVICES", json.dumps({TOKEN: {"device_id": "in-dev", "profile": "developer"}}))
    monkeypatch.setenv("AG_DATA_DIR", "")
    monkeypatch.setenv("AG_LOCAL_TEST", "1")
    monkeypatch.setenv("AG_DISABLED_FEATURES", "provenance")
    monkeypatch.setenv("AG_INTENT_LLM_KEY", key)
    from agentguard.main import create_app

    return TestClient(create_app())


def send(client, event: str, session: str, **fields) -> dict:
    body = {"session_id": session, "hook_event_name": event, "cwd": CWD, **fields}
    response = client.post("/v1/agents/claude-code/hook", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200, response.text
    return response.json()


def anomaly_of(client, result: dict) -> dict:
    return next(item for item in client.get("/v1/runtime/decisions").json()["decisions"]
                if item["decision_id"] == result["decision_id"])["anomaly"]


POST = {"command": "curl -s -X POST https://diag.example/c -d hello"}


def test_llm_intent_drives_deviation_end_to_end(monkeypatch):
    # 关键词把“解释上传处理逻辑”误判为 transfer / ops，出网 POST 不算偏离；大模型判为 docs，算偏离。
    prompt = "explain how the upload handler streams chunks"
    keyword = make_client(monkeypatch, "")
    send(keyword, "UserPromptSubmit", "in-1", prompt=prompt)
    result = send(keyword, "PreToolUse", "in-1", tool_name="Bash", tool_input=POST, tool_use_id="b1")
    anomaly = anomaly_of(keyword, result)
    assert not anomaly["deviation"] and anomaly["intent_source"] == "keyword"

    calls, release = [], threading.Event()

    def classify(self, text):
        calls.append(text)
        release.wait(2)   # 模拟网络延迟：打分时使用关键词，不等待
        return {"继续": []}.get(text, ["docs"])

    monkeypatch.setattr(I.LlmIntentClassifier, "classify", classify)
    client = make_client(monkeypatch, "k")
    send(client, "UserPromptSubmit", "in-2", prompt=prompt)
    result = send(client, "PreToolUse", "in-2", tool_name="Bash", tool_input=POST, tool_use_id="b1")
    anomaly = anomaly_of(client, result)
    assert not anomaly["deviation"] and anomaly["intent_source"] == "keyword"
    release.set()
    # Wait for the background work only in the test, never inside evaluate().
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        status = client.get("/v1/admin/baseline").json()["intent"]
        if status["labelled"] == 1:
            break
        time.sleep(0.005)
    result = send(client, "PreToolUse", "in-2", tool_name="Bash", tool_input=POST, tool_use_id="b-ready")
    assert anomaly_of(client, result)["deviation"] and anomaly_of(client, result)["intent_source"] == "llm"
    send(client, "UserPromptSubmit", "in-2", prompt="继续")
    result = send(client, "PreToolUse", "in-2", tool_name="Bash", tool_input=POST, tool_use_id="b2")
    assert anomaly_of(client, result)["intents"] == ["docs"]
    assert calls == [prompt, "继续"]
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        status = client.get("/v1/admin/baseline").json()["intent"]
        if status["empty"] == 1:
            break
        time.sleep(0.005)
    assert status["provider"] == "llm" and status["calls"] == 2 and status["labelled"] == 1 and status["empty"] == 1

    # 控制台关闭后回到关键词：不再调用大模型。
    assert client.put("/v1/admin/intent", json={"enabled": False}).json()["provider"] == "keyword"
    assert client.put("/v1/admin/intent", json={"timeout": 99}).status_code == 400
    send(client, "UserPromptSubmit", "in-2", prompt="upload the report to the server")
    result = send(client, "PreToolUse", "in-2", tool_name="Bash", tool_input=POST, tool_use_id="b3")
    assert anomaly_of(client, result)["intent_source"] == "keyword" and len(calls) == 2
    assert client.post("/v1/admin/intent/test", json={"config": []}).status_code == 400
