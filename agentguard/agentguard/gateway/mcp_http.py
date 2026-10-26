"""MCP Streamable HTTP 传输辅助（通用 Agent 接入设计 §8.4）。

MCP 服务可通过单次 POST 返回 JSON，也可按 Streamable HTTP 规范：
- 在 initialize 响应头返回 Mcp-Session-Id，后续请求必须携带；
- 对 POST 以 text/event-stream 返回，响应消息在某个 `data:` 事件中。
这里统一解析两种形态，并只透传协议必需的头，客户端不能借此指定上游。
"""

import json

SESSION_HEADER = "Mcp-Session-Id"
PROTOCOL_HEADER = "MCP-Protocol-Version"
PASSTHROUGH_HEADERS = (SESSION_HEADER, PROTOCOL_HEADER)


def passthrough_headers(headers) -> dict:
    """从请求/响应头中挑出协议必需的头（大小写不敏感）。"""
    picked = {}
    for name in PASSTHROUGH_HEADERS:
        value = headers.get(name) if headers is not None else None
        if value:
            picked[name] = str(value)[:256]
    return picked


def parse_jsonrpc(response, request_id=None) -> dict:
    """解析上游响应：JSON 直接返回；SSE 取与 request_id 匹配的响应消息。"""
    content_type = (response.headers.get("content-type") or "").lower()
    if "text/event-stream" not in content_type:
        return response.json()
    fallback = None
    data_lines: list[str] = []

    def flush():
        nonlocal fallback
        if not data_lines:
            return None
        try:
            message = json.loads("\n".join(data_lines))
        except ValueError:
            return None
        finally:
            data_lines.clear()
        if isinstance(message, dict) and ("result" in message or "error" in message):
            if request_id is None or message.get("id") == request_id:
                return message
            fallback = fallback or message
        return None

    for line in response.text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
        elif not line.strip():
            found = flush()
            if found is not None:
                return found
    found = flush()
    if found is not None:
        return found
    if fallback is not None:
        return fallback
    raise ValueError("no JSON-RPC response in event stream")
