"""端到端集成测试：真实 HTTP 上游 stub + 网关全管线。

验证三个强制点：
1. ALLOW 决策恰好转发一次且返回上游结果；
2. DENY 决策不触达上游（stub 调用计数不增长）；
3. 隐藏工具（不在 tools/list 清单中）默认拒绝。
"""

import json
import os
import pathlib
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))



def _free_port() -> int:
    # 固定端口在共享主机上可能被占用；由系统分配空闲端口，AG_TEST_STUB_PORT 可覆盖。
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


PORT = int(os.getenv("AG_TEST_STUB_PORT") or _free_port())
os.environ["AG_UPSTREAM_customer_db"] = f"http://127.0.0.1:{PORT}/mcp"
os.environ["AG_HOOK_SECRET"] = "test-secret"


class StubMCPHandler(BaseHTTPRequestHandler):
    calls: list[dict] = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        StubMCPHandler.calls.append(body)
        method = body.get("method")
        if method == "tools/list":
            result = {"tools": [{"name": "query", "description": "按租户查询", "inputSchema": {}}]}
        elif method == "tools/call":
            result = {"rows": [{"tenant": body["params"]["arguments"]["tenant"]}], "pii": True}
        else:
            result = {}
        payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())


def start_stub() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), StubMCPHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def tool_call(client, server_name: str, tool: str, args: dict, trace_id: str = "C2-A-1") -> dict:
    return client.post(f"/mcp/{server_name}", headers={"X-Trace-Id": trace_id}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }).json()


def test_gateway_enforcement_pipeline():
    from fastapi.testclient import TestClient

    stub = start_stub()
    try:
        from agentguard.main import create_app

        client = TestClient(create_app())

        # 1) Hook 创建任务信封（lwang，scope=acme）。
        created = client.post("/v1/runtime/tasks", headers={"X-AG-Secret": "test-secret"}, json={
            "trace_id": "C2-A-1",
            "actor": {"sub": "lwang", "role": "support-agent", "team": "support", "scope": {"tenant": "acme"}},
            "prompt": "请处理 ACME 工单 8842",
        })
        assert created.status_code == 200

        # 2) 作用域内查询：ALLOW，恰好转发一次并返回上游结果。
        before = len(StubMCPHandler.calls)
        allowed = tool_call(client, "customer-db", "query", {"tenant": "acme"})
        assert allowed.get("result", {}).get("rows"), allowed
        forwarded = [c for c in StubMCPHandler.calls[before:] if c.get("method") == "tools/call"]
        assert len(forwarded) == 1

        # 3) 跨租户查询：DENY，协议级错误 + 不转发。
        before = len(StubMCPHandler.calls)
        blocked = tool_call(client, "customer-db", "query", {"tenant": "globex"})
        assert blocked["error"]["code"] == -32040
        assert blocked["error"]["data"]["reason_code"] == "CROSS_TENANT_ACCESS"
        assert "decision_id" in blocked["error"]["data"]
        # 响应不回显租户参数与内部策略细节。
        assert "globex" not in json.dumps(blocked)
        assert not [c for c in StubMCPHandler.calls[before:] if c.get("method") == "tools/call"]

        # 4) 隐藏工具（stub 的 tools/list 只有 query）：默认拒绝。
        hidden = tool_call(client, "customer-db", "export_all", {"tenant": "*"})
        assert hidden["error"]["data"]["reason_code"] == "HIDDEN_TOOL"

        # 5) 决策与证据可查询，evidence_ids 指向真实存在的事件。
        decisions = client.get("/v1/runtime/decisions?trace_id=C2-A-1").json()["decisions"]
        assert any(d["decision"] == "DENY" and d["reason_code"] == "CROSS_TENANT_ACCESS" for d in decisions)
        events = client.get("/v1/runtime/events?trace_id=C2-A-1").json()["events"]
        event_ids = {e["event_id"] for e in events}
        for decision in decisions:
            assert set(decision["evidence_ids"]) <= event_ids

        # 6) 攻击链包含任务创建 -> 请求 -> 决策 -> 结果的完整链路。
        trace = client.get("/v1/runtime/traces/C2-A-1").json()
        stages = [node["stage"] for node in trace["chain"]]
        assert "TASK_CREATED" in stages and "TOOL_REQUEST" in stages

        # 7) 网关事件只记录网关自身真实栈（source=gateway），不冒充应用调用路径；
        #    应用栈由 Hook 事件单独标注（此测试未安装 Hook，故不出现 app 帧）。
        gateway_events = [e for e in events if e["source"] == "mcp-gateway" and e["stack"]]
        assert gateway_events
        for event in gateway_events:
            assert all(frame["source"] == "gateway" for frame in event["stack"])
            assert any(frame["function"] == "handle" for frame in event["stack"])
            assert all(not frame["function"].startswith("opspilot:") for frame in event["stack"])
        # 工具参数/结果证据进入受控存储：攻击链内嵌预览，且不含证据原文。
        evidence_nodes = [node for node in trace["chain"] if node["evidence"]]
        assert evidence_nodes
        assert all("content" not in item for node in evidence_nodes for item in node["evidence"])
    finally:
        stub.shutdown()
