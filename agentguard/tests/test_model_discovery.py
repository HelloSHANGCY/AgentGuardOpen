"""模型发现：按供应商接口解析模型列表、思考强度与过滤规则；不访问真实网络。"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from agentguard.llm import discovery


def test_models_url_follows_custom_hosts_and_dashscope_path():
    assert discovery.models_endpoint("https://api.openai.com/v1/chat/completions") == \
        "https://api.openai.com/v1/models"
    assert discovery.models_endpoint("https://proxy.example.test/v1") == "https://proxy.example.test/v1/models"
    assert discovery.models_endpoint("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
                                     {"id": "dashscope"}) == \
        "https://dashscope.aliyuncs.com/api/v1/models?page_size=100"


def test_deepseek_effort_metadata_and_non_chat_filter(monkeypatch):
    payload = {"data": [
        {"id": "deepseek-new", "effort": {"supported_levels": ["low", "high", "max"]}},
        {"id": "deepseek-embedding"},
        {"id": "deepseek-new"},
    ]}
    monkeypatch.setattr(discovery, "_request_json", lambda url, key: payload)
    result = discovery.discover_models("https://api.deepseek.com/chat/completions", "secret")
    assert result["models_url"] == "https://api.deepseek.com/models"
    assert result["models"] == [{"id": "deepseek-new", "efforts": ["off", "default", "low", "high", "max"],
                                 "effort_source": "metadata"}]
    assert result["with_efforts"] == 1


def test_openrouter_reasoning_metadata_and_mandatory_models(monkeypatch):
    payload = {"data": [
        {"id": "openai/gpt-5", "reasoning": {"supported_efforts": ["high", "medium", "low"]},
         "architecture": {"output_modalities": ["text"]}},
        {"id": "openai/always-on", "reasoning": {"supported_efforts": ["high", "medium"], "mandatory": True},
         "architecture": {"output_modalities": ["text"]}},
        {"id": "openai/image-only", "architecture": {"output_modalities": ["image"]}},
    ]}
    monkeypatch.setattr(discovery, "_request_json", lambda url, key: payload)
    result = discovery.discover_models("https://openrouter.ai/api/v1/chat/completions", "secret", "OpenRouter")
    levels = {model["id"]: model["efforts"] for model in result["models"]}
    assert levels["openai/gpt-5"] == ["default", "high", "medium", "low"]
    assert levels["openai/always-on"] == ["default", "high", "medium"]
    assert "openai/image-only" not in levels


def test_dashscope_uses_official_models_endpoint_and_capabilities(monkeypatch):
    payload = {"output": {"models": [
        {"model": "qwen3.8-max", "capabilities": ["TG", "Reasoning"]},
        {"model": "qwen-image", "capabilities": ["IG"]},
    ]}}
    monkeypatch.setattr(discovery, "_request_json", lambda url, key: payload)
    result = discovery.discover_models("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "secret")
    assert result["models_url"] == "https://dashscope.aliyuncs.com/api/v1/models?page_size=100"
    assert [model["id"] for model in result["models"]] == ["qwen3.8-max"]


def test_opencode_go_only_returns_chat_completions_presets(monkeypatch):
    payload = {"data": [{"id": "deepseek-v4.1-flash"}, {"id": "gpt-6-astra"}]}
    monkeypatch.setattr(discovery, "_request_json", lambda url, key: payload)
    result = discovery.discover_models("https://opencode.ai/inference/go/v1/chat/completions", "secret")
    assert [model["id"] for model in result["models"]] == ["deepseek-v4.1-flash"]
    assert result["models"][0]["efforts"] == ["off", "default", "low", "high", "max"]


def test_unknown_provider_keeps_manual_effort_selection(monkeypatch):
    payload = {"data": [{"id": "custom-chat"}]}
    monkeypatch.setattr(discovery, "_request_json", lambda url, key: payload)
    result = discovery.discover_models("https://llm.example.test/v1/chat/completions", "secret", "自定义")
    assert result["models"] == [{"id": "custom-chat", "efforts": [], "effort_source": "unknown"}]
    assert result["with_efforts"] == 0
