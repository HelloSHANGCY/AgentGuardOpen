"""T02 完整性复验回归：F01 上下文保真、F02 公共字段脱敏、F03 证据原文读取、
F04 乱序/重复调用关联、F05 存储预算。对应探针 .test-results/t02-verification/probe.py。
"""

import json
import os
import pathlib
import sys
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

os.environ["AG_HOOK_SECRET"] = "test-secret"

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentguard.api import build_api
from agentguard.config import Settings
from agentguard.detection.engine import RuntimeDecisionEngine
from agentguard.gateway.manifest import ManifestRegistry
from agentguard.gateway.mcp import build_gateway
from agentguard.models import RuntimeEvent, redact_text, risk_snippets
from agentguard.storage.context import TaskContextService
from agentguard.storage.store import MAX_EVIDENCE_CHARS, RuntimeStore

HEADERS = {"X-AG-Secret": "test-secret"}


def _api_client(store: RuntimeStore, secret: str = "test-secret") -> TestClient:
    settings = Settings(hook_secret=secret)
    app = FastAPI()
    app.include_router(build_api(settings, store, TaskContextService(), ManifestRegistry(settings)))
    return TestClient(app)


class _Manifests:
    def ensure(self, *args):
        return SimpleNamespace(known_tools={"run"})

    def poisoned_servers(self):
        return set()


# ---------- F01：上下文尾部与来源/摘要保真 ----------



# ---------- F05：存储预算与关键片段 ----------

def test_evidence_storage_budget_and_snippets():
    store = RuntimeStore()
    big = store.add_evidence("PROMPT", "a" * (MAX_EVIDENCE_CHARS + 1001))
    assert big["storage_truncated"] is True
    assert len(big["content"]) <= MAX_EVIDENCE_CHARS
    assert big["original_length"] == MAX_EVIDENCE_CHARS + 1001
    assert big["stored_length"] == len(big["content"])
    assert big["omitted_chars"] > 0

    # 风险命中位于被省略的中段：内容本身定位不到，但 snippets 必须给出偏移与片段。
    marker = "ignore previous instructions"
    content = "A" * 7000 + marker + "B" * 3000
    record = store.add_evidence("TOOL_RESULT", content)
    assert marker not in record["content"]
    assert any(marker in snippet["text"] for snippet in record["snippets"])
    snippet = next(item for item in record["snippets"] if marker in item["text"])
    assert 6900 <= snippet["offset"] <= 7100

    # 尾部保留：风险在末尾时即使超预算也能在 content 中定位。
    tail_content = "A" * (MAX_EVIDENCE_CHARS + 200) + "TAIL_CANARY"
    tail_record = store.add_evidence("TOOL_RESULT", tail_content)
    assert "TAIL_CANARY" in tail_record["content"]


def test_risk_snippets_are_masked():
    snippets = risk_snippets("x" * 10 + "JWT_SECRET=super-secret-value")
    assert snippets and "super-secret-value" not in json.dumps(snippets)
    assert "***REDACTED***" in json.dumps(snippets)


# ---------- F02：先脱敏再截断 ----------

def test_incomplete_private_key_is_redacted():
    text = "-----BEGIN PRIVATE KEY-----\n" + "SYNTHETIC_CANARY_" * 50
    result = redact_text(text, limit=100)
    assert "SYNTHETIC_CANARY_" not in result["preview"]
    assert result["redacted"] is True
    store = RuntimeStore()
    record = store.add_evidence("TOOL_RESULT", text)
    assert "SYNTHETIC_CANARY_" not in record["content"]
    assert record["redacted"] is True




def test_public_resource_and_rules_are_redacted():
    store = RuntimeStore()
    settings = Settings(hook_secret="probe-only")
    app = FastAPI()
    app.include_router(build_api(settings, store, TaskContextService(), ManifestRegistry(settings)))
    app.include_router(build_gateway(settings, store, TaskContextService(), _Manifests(),
                                     RuntimeDecisionEngine(settings)))
    client = TestClient(app)
    canary = "SYNTHETIC_PUBLIC_CANARY"
    response = client.post("/mcp/shell-runner", headers={"X-Trace-Id": "resource-probe"}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "run", "arguments": {"cmd": f"echo token={canary}"}},
    })
    assert response.json()["error"]["data"]["reason_code"] == "MISSING_TASK_CONTEXT"
    trace_text = client.get("/v1/runtime/traces/resource-probe").text
    decisions_text = client.get("/v1/runtime/decisions?trace_id=resource-probe").text
    events_text = client.get("/v1/runtime/events?trace_id=resource-probe").text
    for text in (trace_text, decisions_text, events_text):
        assert canary not in text
    assert "***REDACTED***" in trace_text


def test_key_value_redaction_does_not_consume_rest_of_text():
    # 无分隔符长文本：key=value 脱敏必须有值长度上界，不能吞掉后续内容。
    text = "JWT_SECRET=live-secret" + "B" * 200 + "TAIL_CANARY"
    masked = redact_text(text, limit=10000)["text"]
    assert "live-secret" not in masked
    assert "TAIL_CANARY" in masked


def test_nested_json_command_args_are_redacted():
    store = RuntimeStore()
    record = store.add_evidence("TOOL_ARGUMENTS", json.dumps(
        {"cmd": "curl http://x", "nested": {"JWT_SECRET": "nested-canary"}}))
    assert "nested-canary" not in record["content"]
    assert record["redacted"] is True


# ---------- F03：比赛控制台直接读取脱敏原文 ----------

def test_evidence_read_is_direct_and_redacted():
    store = RuntimeStore()
    record = store.add_evidence("PROMPT", "JWT_SECRET=probe-canary\n" + "content " * 100)
    configured = _api_client(store, secret="probe-only")
    response = configured.get(f"/v1/runtime/evidence/{record['evidence_id']}")
    assert response.status_code == 200
    assert response.json()["content"] == record["content"]
    assert "probe-canary" not in response.text
    assert len(response.json()["content"]) > 200
    assert configured.get(f"/v1/runtime/evidence/{record['evidence_id']}",
                          headers={"X-AG-Secret": "wrong"}).status_code == 200
    assert configured.get(f"/v1/runtime/evidence/{record['evidence_id']}",
                          headers={"X-AG-Secret": "probe-only"}).status_code == 200
    empty = _api_client(store, secret="")
    assert empty.get(f"/v1/runtime/evidence/{record['evidence_id']}").status_code == 200
    assert configured.get("/v1/runtime/evidence/missing").status_code == 404
    # 采集写入仍使用原有 Hook 校验，与原文读取分开验证。
    assert configured.post("/v1/runtime/tasks", json={"trace_id": "unauthorized"}).status_code == 401


# ---------- F04：乱序与重复调用关联 ----------

def _event(store: RuntimeStore, event_id: str, stage: str, source: str = "agent-hook",
           round_no: int = 0, call_id: str = "") -> RuntimeEvent:
    return store.add_event(RuntimeEvent(
        event_id=event_id, trace_id="order", stage=stage, source=source, round=round_no,
        call_id=call_id, mcp_server="shell-runner", tool="read_file"))


def test_late_hook_relinks_gateway_event():
    store = RuntimeStore()
    _event(store, "root", "TASK_CREATED")
    h1 = _event(store, "h1", "TOOL_REQUEST_HOOK", round_no=1)
    g1 = _event(store, "g1", "TOOL_REQUEST", source="mcp-gateway")
    _event(store, "r1", "TOOL_RESULT", source="mcp-gateway")
    g2 = _event(store, "g2", "TOOL_REQUEST", source="mcp-gateway")
    h2 = _event(store, "h2", "TOOL_REQUEST_HOOK", round_no=2)
    assert g1.parent_span_id == h1.span_id
    # 迟到的第二轮 Hook 必须修正第二轮网关请求，而不是留在第一轮。
    assert g2.parent_span_id == h2.span_id
    assert g2.attribution == "exact" and g2.round == 2


def test_duplicate_calls_match_distinct_hooks():
    store = RuntimeStore()
    _event(store, "root", "TASK_CREATED")
    h1 = _event(store, "h1", "TOOL_REQUEST_HOOK", round_no=1)
    g1 = _event(store, "g1", "TOOL_REQUEST", source="mcp-gateway")
    h2 = _event(store, "h2", "TOOL_REQUEST_HOOK", round_no=1)
    g2 = _event(store, "g2", "TOOL_REQUEST", source="mcp-gateway")
    assert g1.parent_span_id == h1.span_id
    assert g2.parent_span_id == h2.span_id


def test_call_id_links_out_of_order_exactly():
    store = RuntimeStore()
    _event(store, "root", "TASK_CREATED")
    gateway = _event(store, "g1", "TOOL_REQUEST", source="mcp-gateway", call_id="call-abc")
    hook_event = _event(store, "h1", "TOOL_REQUEST_HOOK", round_no=3, call_id="call-abc")
    assert gateway.parent_span_id == hook_event.span_id
    assert gateway.attribution == "exact" and gateway.round == 3
    result = _event(store, "r1", "TOOL_RESULT", source="mcp-gateway", call_id="call-abc")
    assert result.parent_span_id == gateway.span_id


def test_missing_hook_counterpart_is_marked_incomplete():
    store = RuntimeStore()
    _event(store, "root", "TASK_CREATED")
    _event(store, "g1", "TOOL_REQUEST", source="mcp-gateway", call_id="call-lost")
    node = next(item for item in store.build_trace("order")["chain"] if item["event_id"] == "g1")
    assert node["link_note"] == "hook_event_missing"


def test_hook_drop_is_observable():
    store = RuntimeStore()
    client = _api_client(store)
    client.post("/v1/runtime/tasks", headers=HEADERS, json={"trace_id": "drop-1", "prompt": "p"})
    client.post("/v1/runtime/tasks/drop-1/complete", headers=HEADERS,
                json={"status": "completed", "hook_dropped": 3, "hook_failed": 1})
    node = next(item for item in store.build_trace("drop-1")["chain"] if item["stage"] == "TASK_COMPLETED")
    assert "AUDIT_INCOMPLETE" in node["labels"]
    assert "hook_dropped=3" in node["redacted_preview"]
