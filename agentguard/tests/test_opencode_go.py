"""Go 的 DeepSeek / GLM 请求协议、能力边界与并发会话隔离；不调用真实供应商。"""

import io
import json
import pathlib
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from agentguard.llm import client as C
from agentguard.llm.providers import GO_MODELS, GO_URL, validate_connection


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def reply(data):
    return Response(json.dumps({"choices": [{"message": {
        "reasoning_content": "This must not be parsed as the final answer.",
        "content": json.dumps(data),
    }}]}).encode())


@pytest.mark.parametrize("profile", GO_MODELS, ids=lambda model: model["id"])
def test_every_supported_model_sends_json_bearer_user_agent_and_native_effort(monkeypatch, profile):
    sent = []

    def urlopen(request, timeout):
        sent.append((request, timeout))
        return reply({"ok": True})

    monkeypatch.setattr(C.urllib.request, "urlopen", urlopen)
    for effort in profile["efforts"]:
        assert C.session_call("conversation-a", C.chat_json, GO_URL, profile["id"], "test-key", 4,
                              "Return JSON", "check", 64, effort) == {"ok": True}
        request, timeout = sent[-1]
        body = json.loads(request.data)
        assert request.full_url == GO_URL and timeout == 4
        assert request.get_header("Authorization") == "Bearer test-key"
        assert request.get_header("User-agent") == "AgentGuard/1.0"
        assert body["model"] == profile["id"] and body["response_format"] == {"type": "json_object"}
        if effort == "off":
            assert body["thinking"] == {"type": "disabled"} and body["max_tokens"] == 64
            assert "reasoning_effort" not in body
        elif effort == "default":
            assert "thinking" not in body and "reasoning_effort" not in body
        else:
            assert body["thinking"] == {"type": "enabled"} and "temperature" not in body
            if effort == "enabled":
                assert "reasoning_effort" not in body
            else:
                assert body["reasoning_effort"] == effort
    assert len({request.get_header("X-opencode-session") for request, _ in sent}) == 1


def test_sessions_are_stable_isolated_and_reset_after_errors(monkeypatch):
    sent = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def urlopen(request, timeout):
        with lock:
            sent.append((json.loads(request.data)["messages"][1]["content"], request.get_header("X-opencode-session")))
        return reply({"ok": True})

    monkeypatch.setattr(C.urllib.request, "urlopen", urlopen)

    def run(session):
        barrier.wait(timeout=3)
        for _ in range(2):
            C.session_call(session, C.chat_json, GO_URL, "deepseek-flash", "test-key", 3, "json", session, 64)

    with ThreadPoolExecutor(2) as pool:
        list(pool.map(run, ["a\r\nprivate-session", "b"]))
    headers = {text.splitlines()[0]: header for text, header in sent}
    assert len(set(headers.values())) == 2
    assert all(len({h for text, h in sent if text.startswith(session)}) == 1 for session in ("a", "b"))
    assert all(header.startswith("ag-") and len(header) == 67 for _, header in sent)

    with pytest.raises(RuntimeError):
        C.session_call("failed-session", lambda: (_ for _ in ()).throw(RuntimeError()))
    for _ in range(2):
        C.chat_json(GO_URL, "deepseek-flash", "test-key", 3, "json", "standalone", 64)
    assert sent[-1][1] != sent[-2][1] and sent[-1][1] not in headers.values()


@pytest.mark.parametrize("url", ["https://opencode.ai/inference/go/v1/", "https://opencode.ai/zen/go/v1",
                                 "https://opencode.ai/zen/go/v1/chat/completions/"])
def test_base_urls_and_legacy_go_route(monkeypatch, url):
    def urlopen(request, timeout):
        assert request.full_url.endswith("/chat/completions")
        assert request.get_header("X-opencode-session")
        return reply({"ok": True})

    monkeypatch.setattr(C.urllib.request, "urlopen", urlopen)
    assert C.chat_json(url, "glm-5.2", "test-key", 3, "json", "test", 64) == {"ok": True}


@pytest.mark.parametrize("url,model,effort", [
    (GO_URL, "glm-5.3", "off"), (GO_URL, "glm-5.3-flash", "off"),
    (GO_URL, "glm-5.1", "max"), (GO_URL, "deepseek-flash", "xhigh"),
    (GO_URL, "glm-5.2", "minimal"), (GO_URL, "opencode-go/glm-5.2", "default"),
    (GO_URL, "kimi-k3", "default"), (GO_URL.replace("chat/completions", "messages"), "glm-5.2", "default"),
    (GO_URL.replace("chat/completions", "responses"), "glm-5.2", "default"),
    (GO_URL.replace("https:", "http:"), "glm-5.2", "default"),
])
def test_unsupported_go_config_fails_before_network(monkeypatch, url, model, effort):
    def unexpected(*args, **kwargs):
        raise AssertionError("must not reach network")

    monkeypatch.setattr(C.urllib.request, "urlopen", unexpected)
    with pytest.raises(ValueError):
        C.chat_json(url, model, "test-key", 3, "json", "test", 64, effort)


def test_custom_provider_label_cannot_enable_go_headers(monkeypatch):
    def urlopen(request, timeout):
        assert request.get_header("X-opencode-session") is None
        return reply({"ok": True})

    monkeypatch.setattr(C.urllib.request, "urlopen", urlopen)
    for url in ("https://api.deepseek.com/v1", "https://opencode.ai.evil.test/inference/go/v1",
                "https://proxy.example/v1"):
        validate_connection(url, "custom-model", "xhigh")
        assert C.session_call("private-session", C.chat_json, url, "custom-model", "test-key", 3,
                              "json", "test", 64, "xhigh") == {"ok": True}
