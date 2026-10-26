"""从供应商模型列表接口发现可用模型与思考强度。

不同供应商的列表接口和元数据并不统一：
- OpenAI 兼容服务通常返回 `{"data": [{"id": ...}]}`；
- DeepSeek 在模型对象里返回 `effort.supported_levels`；
- OpenRouter 返回 `reasoning.supported_efforts`；
- 阿里云百炼使用 `output.models`，且列表地址与 Chat Completions 地址不同。

模型列表只用于控制台预填，不改变接入记录的校验规则；供应商没有提供思考强度
元数据时返回空列表，界面保留完整选项由用户按实际模型选择。
"""

import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

from .client import EFFORTS, MODEL_RE, USER_AGENT, error_text
from .providers import PRESETS

MAX_MODELS = 500
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
NON_CHAT_MARKERS = (
    "embed", "embedding", "rerank", "whisper", "tts", "speech", "transcribe",
    "moderation", "dall-e", "image", "video", "veo", "sora", "ocr",
)


def preset_for_url(url):
    """按 Chat Completions 地址匹配内置供应商预设。"""
    base = url.strip().rstrip("/")
    if base.endswith("/chat/completions"):
        base = base[:-len("/chat/completions")]
    for preset in PRESETS:
        if base in preset["base_urls"]:
            return preset
    return None


def models_endpoint(url, preset=None):
    """由 Chat Completions 地址推导模型列表地址，保留用户自定义域名与代理。"""
    parsed = urlsplit(url.strip())
    if preset and preset.get("id") == "dashscope":
        return urlunsplit((parsed.scheme, parsed.netloc, "/api/v1/models", "page_size=100", ""))
    path = parsed.path.rstrip("/")
    if path.endswith("/chat/completions"):
        path = path[:-len("/chat/completions")]
    if not path.endswith("/models"):
        path = path.rstrip("/") + "/models"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _request_json(url, key, timeout=15):
    request = urllib.request.Request(url, method="GET", headers={
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError(error_text(exc, (key,))) from exc
    except Exception as exc:  # noqa: BLE001 - 网络错误统一转成控制台可读文本
        raise ValueError(error_text(exc, (key,))) from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("供应商返回的模型列表过大")
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise ValueError("供应商没有返回 JSON 模型列表") from exc


def _model_items(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("data"), list):
        return payload["data"]
    output = payload.get("output")
    if isinstance(output, dict) and isinstance(output.get("models"), list):
        return output["models"]
    if isinstance(payload.get("models"), list):
        return payload["models"]
    return []


def _model_id(item):
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return ""
    for key in ("id", "model", "name"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().removeprefix("models/")
    return ""


def _is_chat_model(item, model_id):
    lowered = model_id.lower()
    if any(marker in lowered for marker in NON_CHAT_MARKERS):
        return False
    if not isinstance(item, dict):
        return True
    architecture = item.get("architecture")
    if isinstance(architecture, dict):
        modalities = architecture.get("output_modalities")
        if isinstance(modalities, list) and modalities and "text" not in modalities:
            return False
    capabilities = item.get("capabilities")
    if isinstance(capabilities, list) and capabilities:
        # 百炼的文本生成 / 深度思考 / 视觉理解能力；排除图像、视频、语音和向量模型。
        if not {"TG", "Reasoning", "VU"}.intersection(capabilities):
            return False
    methods = item.get("supported_generation_methods")
    if isinstance(methods, list) and methods and "generateContent" not in methods:
        return False
    return True


def _levels(values):
    result = []
    if not isinstance(values, list):
        return result
    for value in values:
        level = str(value).lower()
        if level == "none":
            level = "off"
        if level in EFFORTS and level not in result:
            result.append(level)
    return result


def _preset_efforts(preset, model_id):
    if not isinstance(preset, dict):
        return []
    profile = next((item for item in preset.get("models", []) if item.get("id") == model_id), None)
    return list(profile.get("efforts", [])) if profile else []


def _infer_efforts(provider, model_id):
    """供应商没有返回思考强度时，按官方文档中的模型系列补全明确能力。"""
    provider = (provider or "").lower()
    model_id = model_id.lower()
    if "moonshot" in provider or "kimi" in provider or model_id.startswith("kimi-"):
        if model_id.startswith("kimi-k3"):
            return ["default", "low", "high", "max"]
        if model_id.startswith("kimi-k2.7"):
            return ["default"]  # 思考始终开启，不暴露级别
        if model_id.startswith("kimi-k2.6") or model_id.startswith("kimi-k2.5"):
            return ["off", "default"]
        return []
    if "gemini" in provider or model_id.startswith("gemini-"):
        # Gemini 3 / 2.5 Pro 不能关闭思考；2.5 Flash 系列可以通过 none 关闭。
        if model_id.startswith("gemini-2.5-flash"):
            return ["off", "default", "minimal", "low", "medium", "high"]
        return ["default", "minimal", "low", "medium", "high"]
    return []


def _efforts(item, preset, provider, model_id):
    preset_levels = _preset_efforts(preset, model_id)
    if preset_levels:
        return preset_levels, "preset"
    if isinstance(item, dict):
        effort = item.get("effort")
        if isinstance(effort, dict):
            levels = _levels(effort.get("supported_levels"))
            if levels:
                # DeepSeek 的 thinking 开关和 reasoning_effort 是分开的。
                return ["off", "default", *[level for level in levels if level not in ("off", "default")]], "metadata"
        reasoning = item.get("reasoning")
        if isinstance(reasoning, dict):
            levels = _levels(reasoning.get("supported_efforts"))
            if levels:
                result = ["default", *[level for level in levels if level not in ("off", "default")]]
                if "off" in levels and not reasoning.get("mandatory"):
                    result.insert(0, "off")
                return result, "metadata"
    inferred = _infer_efforts(provider, model_id)
    return (inferred, "inferred") if inferred else ([], "unknown")


def discover_models(url, key, provider=""):
    """调用供应商模型列表接口，返回可预填的模型与思考强度。"""
    preset = preset_for_url(url)
    endpoint = models_endpoint(url, preset)
    payload = _request_json(endpoint, key)
    items = _model_items(payload)
    if not items:
        raise ValueError("供应商没有返回可用模型列表")

    models, seen = [], set()
    for item in items:
        model_id = _model_id(item)
        if not model_id or len(model_id) > 128 or not MODEL_RE.fullmatch(model_id):
            continue
        if not _is_chat_model(item, model_id) or model_id in seen:
            continue
        # OpenCode Go 的 Chat Completions 只开放内置预设；其他端点族由各自协议接入。
        if preset and preset.get("id") == "opencode-go" and not _preset_efforts(preset, model_id):
            continue
        efforts, source = _efforts(item, preset, provider, model_id)
        seen.add(model_id)
        models.append({"id": model_id, "efforts": efforts, "effort_source": source})
        if len(models) >= MAX_MODELS:
            break

    models.sort(key=lambda item: item["id"])
    return {
        "provider": preset["provider"] if preset else provider,
        "models_url": endpoint,
        "models": models,
        "count": len(models),
        "with_efforts": sum(1 for item in models if item["efforts"]),
    }
