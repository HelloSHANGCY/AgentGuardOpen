"""OpenCode Go 的 Chat Completions 预设与模型能力。其他接口保持通用接入。"""

from urllib.parse import urlsplit

GO_URL = "https://opencode.ai/inference/go/v1/chat/completions"
GO_ROOTS = ("/inference/go/v1", "/zen/go/v1")
# 官方文档与公开 models 列表，2026-10-14。只纳入 DeepSeek / GLM 文本模型。
GO_MODELS = [
    {"id": model, "efforts": ["off", "default", "low", "high", "max"]}
    for model in ("deepseek-flash", "deepseek-v4.1-flash", "deepseek-v4-flash", "deepseek-v4-pro")
] + [
    {"id": "glm-5.3-flash", "efforts": ["default", "low", "high", "max"]},
    {"id": "glm-5.3", "efforts": ["default", "low", "high", "max"]},
    {"id": "glm-5.2", "efforts": ["off", "default", "high", "max"]},
    {"id": "glm-5.1", "efforts": ["off", "default", "enabled"]},
]
PRESETS = [{"id": "opencode-go", "provider": "OpenCode Go", "url": GO_URL,
            "base_urls": ["https://opencode.ai" + root for root in GO_ROOTS], "models": GO_MODELS}]


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
