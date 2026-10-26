"""MCP Security Gateway（设计 §5.3；通用 Agent 接入设计 §8）。

对外统一入口 POST /mcp/{server_name}，固定管线：
JSON-RPC 校验 -> 解析 server/method/tool/arguments -> 读取任务上下文 ->
引擎决策 -> ALLOW 转发一次并检查返回 / ASK 暂停 / DENY 协议级阻断。
决策与返回检查由 McpInspector 完成，与 stdio 包装器路径共用。

硬性约束：
- 被拒绝请求不转发；上游由本地受控映射决定，客户端不可指定任意上游；
- 非幂等工具超时不重试；返回值同样经过污点与投毒检查，会话开启返回内容拦截时投毒返回替换为拦截说明；
- DENY 响应只含原因码与 decision_id，不回显参数与命令正文；
- 无 X-Trace-Id 的调用（通用 Agent 经 HTTP 直连）按参数摘要认领 Hook 登记的会话。
"""

import json
import time

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from ..config import Settings
from ..detection import taint as T
from ..detection.engine import RuntimeDecisionEngine
from ..models import RuntimeEvent, new_id, redact_text, sha256_digest
from ..storage.context import TaskContextService
from ..storage.store import RuntimeStore
from .correlation import PendingCalls
from .inspector import McpInspector
from .manifest import ManifestRegistry
from .mcp_http import parse_jsonrpc, passthrough_headers
from .stacks import capture_stack

# JSON-RPC 应用层错误码（协议兼容的自定义区间）
BLOCKED_CODE = -32040
ASK_CODE = -32041
UPSTREAM_ERROR_CODE = -32050
PROTOCOL_CODE = -32600

# 直接透传的协议方法；resources/prompts 的返回内容同样可能携带注入，需检查后再返回。
PASSTHROUGH_METHODS = {"initialize", "tools/list", "ping", "resources/list", "resources/templates/list",
                       "prompts/list", "completion/complete", "logging/setLevel"}
CONTENT_METHODS = {"resources/read", "prompts/get"}


def blocked_payload(request_id, decision) -> dict:
    # 协议级阻断：不回显参数、命令正文或内部策略细节。
    return {
        "jsonrpc": "2.0", "id": request_id,
        "error": {
            "code": BLOCKED_CODE if decision.decision == "DENY" else ASK_CODE,
            "message": "Blocked by AgentGuard policy",
            "data": {"decision_id": decision.decision_id, "reason_code": decision.reason_code},
        },
    }


def build_gateway(settings: Settings, store: RuntimeStore, contexts: TaskContextService,
                  manifests: ManifestRegistry, engine: RuntimeDecisionEngine,
                  pending: PendingCalls | None = None, inspector: McpInspector | None = None) -> APIRouter:
    router = APIRouter()
    client = httpx.Client(timeout=settings.upstream_timeout_seconds)
    pending = pending or PendingCalls()
    inspector = inspector or McpInspector(settings, store, contexts, manifests, engine, pending)

    def make_event(trace_id, stage, source, **kwargs) -> RuntimeEvent:
        return RuntimeEvent(event_id=new_id("evt"), trace_id=trace_id, stage=stage, source=source, **kwargs)

    @router.post("/mcp/{server}")
    async def mcp_proxy(server: str, request: Request, x_trace_id: str | None = Header(default=None),
                        x_instance_id: str | None = Header(default=None),
                        x_ag_call_id: str | None = Header(default=None, alias="X-AG-Call-Id")):
        # 异步读 body；阻塞的上游访问与决策在线程池执行，不卡事件循环。
        try:
            body = json.loads(await request.body())
        except Exception:
            body = None
        return await run_in_threadpool(handle, server, body, x_trace_id or "", x_instance_id or "",
                                       str(request.url.path), x_ag_call_id or "",
                                       passthrough_headers(request.headers))

    @router.get("/mcp/{server}")
    def mcp_stream(server: str):
        # Streamable HTTP：不提供服务端主动推送流，按规范返回 405。
        return Response(status_code=405, headers={"Allow": "POST"})

    def handle(server: str, body, trace_id_hint: str, x_instance_id: str, path: str,
               call_id: str = "", session_headers: dict | None = None):
        received = time.perf_counter()
        session_headers = session_headers or {}
        trace_id = trace_id_hint or new_id("trace")

        # 上游只来自本地受控映射，未知 server 一律拒绝。
        endpoint = settings.upstreams.get(server)
        if endpoint is None:
            store.add_event(make_event(trace_id, "TOOL_REQUEST", "mcp-gateway", component="mcp-gateway",
                                       mcp_server=server, labels=["UNKNOWN_SERVER"],
                                       redacted_preview=path, stack=capture_stack(source="gateway")))
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {
                "code": PROTOCOL_CODE, "message": "unknown mcp server"}}, status_code=404)

        if not isinstance(body, dict):
            store.add_event(make_event(trace_id, "TOOL_REQUEST", "mcp-gateway", mcp_server=server,
                                       labels=["INVALID_JSONRPC"], stack=capture_stack(source="gateway")))
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {
                "code": PROTOCOL_CODE, "message": "invalid JSON-RPC"}})

        method = body.get("method")
        request_id = body.get("id")

        # 通知（无 id）：转发后按规范返回 202，不产生决策。
        if isinstance(method, str) and method.startswith("notifications/") and "id" not in body:
            try:
                client.post(endpoint, json=body, headers=session_headers)
            except httpx.HTTPError:
                pass
            return Response(status_code=202)

        # initialize / tools/list 直接转发，同时刷新运行时清单（网关自举，不依赖 Agent 调用）。
        if method in PASSTHROUGH_METHODS:
            if method == "tools/list":
                manifests.fetch(server, endpoint)
            return _forward(client, endpoint, body, store, trace_id, server, session_headers)

        if method in CONTENT_METHODS:
            return _forward_content(client, endpoint, body, store, trace_id, server, session_headers)

        if method != "tools/call":
            return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": {
                "code": -32601, "message": "method not found"}})

        params = body.get("params") or {}
        tool = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not tool or not isinstance(arguments, dict):
            store.add_event(make_event(trace_id, "TOOL_REQUEST", "mcp-gateway", mcp_server=server,
                                       labels=["INVALID_PARAMS"], redacted_preview=json.dumps(params)[:200],
                                       stack=capture_stack(source="gateway")))
            return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": {
                "code": -32602, "message": "invalid params"}})

        confirmed_ask = False
        if not trace_id_hint:
            # 通用 Agent 直连：认领 Hook 侧登记的会话与 call_id；认领不到按无上下文处理。
            claimed = inspector.claim(server, tool, arguments)
            if claimed:
                trace_id = claimed["trace_id"]
                call_id = call_id or claimed["call_id"]
                confirmed_ask = bool(claimed.get("confirmed_ask"))

        manifest = manifests.ensure(server, endpoint) or manifests.get_cached(server)
        decision = inspector.inspect_request(trace_id, server, tool, arguments, manifest,
                                             instance_id=x_instance_id, call_id=call_id,
                                             confirmed_ask=confirmed_ask)

        if decision.decision != "ALLOW":
            return JSONResponse(blocked_payload(request_id, decision))

        # ALLOW：只转发一次；失败返回标准工具错误，不自动重试。
        forward_started = time.perf_counter()
        try:
            upstream = client.post(endpoint, json=body, headers={
                "X-Trace-Id": trace_id,
                **({"X-Instance-Id": x_instance_id} if x_instance_id else {}),
                **session_headers,
            })
        except httpx.HTTPError as exc:
            inspector.inspect_result(trace_id, server, tool, arguments, "", decision_id=decision.decision_id,
                                     call_id=call_id)
            store.add_event(make_event(trace_id, "TOOL_RESULT", "mcp-gateway", mcp_server=server, tool=tool,
                                       labels=["UPSTREAM_ERROR"], decision_id=decision.decision_id,
                                       redacted_preview=type(exc).__name__))
            return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": {
                "code": UPSTREAM_ERROR_CODE, "message": "upstream unavailable"}})
        store.record_forward_latency((time.perf_counter() - forward_started) * 1000)
        store.state_for(trace_id).allowed_calls.append((time.time(), server))

        try:
            payload = parse_jsonrpc(upstream, request_id)
            result_text = json.dumps(payload.get("result", payload), ensure_ascii=False, default=str)
        except Exception:
            payload = {"jsonrpc": "2.0", "id": request_id, "error": {"code": UPSTREAM_ERROR_CODE,
                       "message": "invalid upstream response"}}
            result_text = ""
        check = inspector.inspect_result(trace_id, server, tool, arguments, result_text,
                                         decision_id=decision.decision_id, call_id=call_id,
                                         block_poisoned=inspector.result_guard_for(trace_id),
                                         execution="unknown" if not result_text else "failed" if "error" in payload else "")
        if check.replacement is not None:
            # 结果与错误体都可能携带注入文本：一律替换为带拦截说明的结果。
            payload = {"jsonrpc": "2.0", "id": request_id, "result": check.replacement}
        decision.latency_ms = decision.latency_ms + (time.perf_counter() - received) * 1000
        return JSONResponse(payload, headers=passthrough_headers(upstream.headers))

    return router


def _forward(client: httpx.Client, endpoint: str, body: dict, store: RuntimeStore, trace_id: str, server: str,
             session_headers: dict | None = None) -> JSONResponse:
    try:
        upstream = client.post(endpoint, json=body, headers=session_headers or {})
        return JSONResponse(parse_jsonrpc(upstream, body.get("id")), headers=passthrough_headers(upstream.headers))
    except (httpx.HTTPError, ValueError):
        store.add_event(RuntimeEvent(event_id=new_id("evt"), trace_id=trace_id, stage="TOOL_RESULT",
                                     source="mcp-gateway", mcp_server=server, labels=["UPSTREAM_ERROR"],
                                     stack=capture_stack(source="gateway")))
        return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "error": {
            "code": UPSTREAM_ERROR_CODE, "message": "upstream unavailable"}})


def _forward_content(client: httpx.Client, endpoint: str, body: dict, store: RuntimeStore, trace_id: str,
                     server: str, session_headers: dict) -> JSONResponse:
    """resources/read、prompts/get：转发后检查返回内容，注入内容打污点但不改写返回。"""
    response = _forward(client, endpoint, body, store, trace_id, server, session_headers)
    try:
        payload = json.loads(response.body)
        text = json.dumps(payload.get("result", ""), ensure_ascii=False, default=str)
    except ValueError:
        return response
    labels = T.content_taints(text, [T.UNTRUSTED_MCP])
    state = store.state_for(trace_id)
    state.observe_result(labels)
    event = store.add_event(RuntimeEvent(event_id=new_id("evt"), trace_id=trace_id, stage="TOOL_RESULT",
                                         source="mcp-gateway", mcp_server=server, tool=str(body.get("method")),
                                         labels=labels, payload_digest=sha256_digest(text),
                                         redacted_preview=redact_text(text, limit=160)["preview"],
                                         stack=capture_stack(source="gateway")))
    state.sources.add_data(text, tool=f"{server}/{body.get('method')}", labels=labels, event_id=event.event_id)
    return response
