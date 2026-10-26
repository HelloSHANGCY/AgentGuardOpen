"""OpenAI 兼容 Chat Completions 的最小客户端：意图识别与大模型研判共用。

只依赖标准库（urllib）；默认接 DeepSeek。接口地址可以填完整地址，也可以只填基础地址（如 https://host/v1）。

思考等级：off 关闭思考（DeepSeek 的 thinking=disabled，temperature=0）；default 不发送任何思考参数，由服务商决定；
minimal ~ max 同时发送 reasoning_effort 与 thinking=enabled；enabled 只开启思考、不发送强度。
OpenCode Go 按模型能力校验思考等级。开启思考时放大输出 token 上限
（思考过程也计入）、不再指定 temperature（推理模型通常只接受默认值）。
"""

import hashlib
import json
import re
import urllib.error
import urllib.request
import uuid
from contextvars import ContextVar

from ..models import mask_secrets
from .providers import is_opencode_go, validate_connection

DEFAULT_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_MODEL = "deepseek-flash"
MODEL_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")
# 部分第三方接口在 Cloudflare 后面，会拦截 Python 默认的 User-Agent（HTTP 403，error code 1010）。
USER_AGENT = "AgentGuard/1.0"
EFFORTS = ("off", "default", "enabled", "minimal", "low", "medium", "high", "xhigh", "max")
THINKING_TOKENS = 8000    # 开启思考时额外给的输出 token
_SESSION = ContextVar("llm_session", default="")


def session_call(session_id, call, *args):
    """在线程执行调用时设置会话上下文，结束或异常后恢复，避免并发会话串用。"""
    token = _SESSION.set(session_id)
    try:
        return call(*args)
    finally:
        _SESSION.reset(token)


def chat_endpoint(url: str) -> str:
    """接口地址填的是基础地址（如 https://host/v1）时补全 /chat/completions。"""
    url = url.strip().rstrip("/")
    return url if url.endswith("/chat/completions") else url + "/chat/completions"


def thinking_params(effort: str, max_tokens: int, url: str = "", model: str = "") -> dict:
    """思考等级对应的请求参数（见模块说明）。"""
    validate_connection(url, model, effort)
    if effort == "off":
        return {"temperature": 0, "max_tokens": max_tokens, "thinking": {"type": "disabled"}}
    if effort == "default":
        return {"max_tokens": max_tokens + THINKING_TOKENS}
    if effort == "enabled":
        return {"max_tokens": max_tokens + THINKING_TOKENS, "thinking": {"type": "enabled"}}
    return {"max_tokens": max_tokens + THINKING_TOKENS, "reasoning_effort": effort, "thinking": {"type": "enabled"}}


def complete(url: str, key: str, body: dict, timeout: float) -> str:
    """发送一次 Chat Completions 请求，返回首条回复的文本；网络或 HTTP 错误原样抛出。"""
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": USER_AGENT}
    if is_opencode_go(url):
        effort = "off" if body.get("thinking", {}).get("type") == "disabled" else body.get("reasoning_effort", "default")
        validate_connection(url, body.get("model"), effort)
        session_id = _SESSION.get() or uuid.uuid4().hex
        headers["x-opencode-session"] = "ag-" + hashlib.sha256(str(session_id).encode()).hexdigest()
    request = urllib.request.Request(
        chat_endpoint(url), data=json.dumps(body).encode(), method="POST",
        headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read())
    return data["choices"][0]["message"].get("content") or ""


def chat_json(url: str, model: str, key: str, timeout: float, system: str, user: str, max_tokens: int,
              effort: str = "off") -> dict:
    """调用 Chat Completions 并把回复解析为 JSON 对象；调用或解析失败抛出异常。

    要求 JSON 输出时，部分接口（OpenAI 规则）检查的是用户消息里有没有出现 "json"，系统提示词不算，
    所以用户消息末尾再写一遍。
    """
    body = {"model": model, **thinking_params(effort, max_tokens, url, model), "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user + "\n\nAnswer with the JSON object only."}]}
    content = complete(url, key, body, timeout).strip()
    # 个别模型仍会包一层 ```json 代码块。
    content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content)
    result = json.loads(content)
    if not isinstance(result, dict):
        raise ValueError("reply is not a JSON object")
    return result


def error_text(exc: Exception, secrets=()) -> str:
    """给控制台展示的错误原因（掩码凭证、截断）；HTTP 错误带上响应体。"""
    if isinstance(exc, urllib.error.HTTPError):
        try:
            detail = exc.read().decode("utf-8", "replace")
        except Exception:
            detail = ""
        message = f"HTTP {exc.code} {detail}"
    else:
        message = f"{type(exc).__name__}: {exc}"
    for secret in secrets:
        if secret:
            message = message.replace(secret, "[REDACTED]")
    return mask_secrets(message)[:300]


def clean_url(url) -> str:
    """控制台提交的接口地址；不合法时抛 ValueError。"""
    if not isinstance(url, str) or len(url) > 512 or not re.match(r"^https?://[^\s/]+", url):
        raise ValueError("url must be an http(s) URL")
    return url.strip()


def clean_key(key) -> str:
    """控制台提交的密钥（可为空，表示不修改）；不合法时抛 ValueError。"""
    if not isinstance(key, str) or len(key) > 512 or any(ch.isspace() for ch in key):
        raise ValueError("invalid key")
    return key
