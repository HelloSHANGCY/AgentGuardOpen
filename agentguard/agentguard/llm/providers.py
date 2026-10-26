"""模型供应商预设：OpenCode Go 的模型能力，以及常用 OpenAI 兼容服务的接入地址。"""

from urllib.parse import urlsplit

GO_URL = "https://opencode.ai/inference/go/v1/chat/completions"
GO_ROOTS = ("/inference/go/v1", "/zen/go/v1")
# 官方文档与公开 models 列表，2026-10-14。只纳入 DeepSeek / GLM 文本模型。
DEEPSEEK_MODELS = [
    {"id": model, "efforts": ["off", "default", "low", "high", "max"]}
    for model in ("deepseek-flash", "deepseek-v4.1-flash", "deepseek-v4-flash", "deepseek-v4-pro")
]
GO_MODELS = DEEPSEEK_MODELS + [
    {"id": "glm-5.3-flash", "efforts": ["default", "low", "high", "max"]},
    {"id": "glm-5.3", "efforts": ["default", "low", "high", "max"]},
    {"id": "glm-5.2", "efforts": ["off", "default", "high", "max"]},
    {"id": "glm-5.1", "efforts": ["off", "default", "enabled"]},
]
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
# 常用 OpenAI 兼容服务：预填接入地址，模型 ID 由用户按账号实际可用模型填写。
# 未提供模型清单的预设只预填接入地址，不限制思考等级或模型 ID。
PROVIDER_PRESETS = [
    {"id": "deepseek", "provider": "DeepSeek", "url": DEEPSEEK_URL,
     "base_urls": ["https://api.deepseek.com", "https://api.deepseek.com/v1"], "models": DEEPSEEK_MODELS},
    {"id": "openai", "provider": "OpenAI", "url": "https://api.openai.com/v1/chat/completions",
     "base_urls": ["https://api.openai.com/v1"], "models": []},
    {"id": "dashscope", "provider": "通义千问", "url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
     "base_urls": ["https://dashscope.aliyuncs.com/compatible-mode/v1"], "models": []},
    {"id": "zhipu", "provider": "智谱 AI", "url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
     "base_urls": ["https://open.bigmodel.cn/api/paas/v4"], "models": []},
    {"id": "moonshot", "provider": "Moonshot Kimi", "url": "https://api.moonshot.cn/v1/chat/completions",
     "base_urls": ["https://api.moonshot.cn/v1", "https://api.moonshot.ai/v1"], "models": []},
    {"id": "siliconflow", "provider": "SiliconFlow", "url": "https://api.siliconflow.cn/v1/chat/completions",
     "base_urls": ["https://api.siliconflow.cn/v1"], "models": []},
    {"id": "openrouter", "provider": "OpenRouter", "url": "https://openrouter.ai/api/v1/chat/completions",
     "base_urls": ["https://openrouter.ai/api/v1"], "models": []},
    {"id": "gemini", "provider": "Google Gemini",
     "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
     "base_urls": ["https://generativelanguage.googleapis.com/v1beta/openai"], "models": []},
]
PRESETS = [{"id": "opencode-go", "provider": "OpenCode Go", "url": GO_URL,
            "base_urls": ["https://opencode.ai" + root for root in GO_ROOTS], "models": GO_MODELS}] + PROVIDER_PRESETS


def is_opencode_go(url):
    parsed = urlsplit(url)
    return parsed.hostname == "opencode.ai" and any(
        parsed.path.rstrip("/") == root or parsed.path.startswith(root + "/") for root in GO_ROOTS)


def go_model(url, model):
    if not is_opencode_go(url):
        return None
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.query or parsed.fragment
            or parsed.path.rstrip("/") not in {path for root in GO_ROOTS for path in (root, root + "/chat/completions")}):
        raise ValueError("OpenCode Go 请使用 HTTPS Chat Completions 接口")
    profile = next((item for item in GO_MODELS if item["id"] == model), None)
    if profile is None:
        raise ValueError("OpenCode Go 当前支持 DeepSeek / GLM 预设模型，模型 ID 不加 opencode-go/ 前缀")
    return profile


def validate_connection(url, model, effort):
    profile = go_model(url, model)
    if profile and effort not in profile["efforts"]:
        if effort == "off":
            raise ValueError(f"{model} 不支持关闭思考，不能用于固定关闭思考的意图识别")
        raise ValueError(f"{model} 不支持思考等级 {effort}，请选择服务商默认或该模型支持的等级")
