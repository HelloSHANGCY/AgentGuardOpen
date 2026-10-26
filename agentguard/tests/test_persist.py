"""运行时数据持久化（persist.py）：事件 / 决策 / 证据 / 任务信封写入 SQLite，重启后加载回内存，
回填与迟到关联的修改同样落盘，会话再次活动时恢复轮次与污点，按保留期与条数清理。"""

import json
import pathlib
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from agentguard.models import Decision, RuleMatch, RuntimeEvent, new_id  # noqa: E402
from agentguard.storage import persist as P  # noqa: E402
from agentguard.storage.store import RuntimeStore  # noqa: E402

TRACE = "cc-dev-persist-s-1"


def reopen(store: RuntimeStore, path) -> RuntimeStore:
    store.close()
    return RuntimeStore(db_path=str(path))


def event(stage, **fields):
    return RuntimeEvent(event_id=new_id("evt"), trace_id=fields.pop("trace_id", TRACE), stage=stage,
                        source=fields.pop("source", "agent-hook"), **fields)


def test_round_trip_keeps_backfills_links_and_restores_state(tmp_path):
    path = tmp_path / "runtime.db"
    store = RuntimeStore(db_path=str(path))
    store.set_task(TRACE, {"trace_id": TRACE, "task_id": "task-1", "instance_id": "dev-1"})
    store.add_event(event("TASK_CREATED"))
    store.add_event(event("MODEL_TURN", round=1))
    store.add_event(event("MODEL_TURN", round=2))
    # 网关请求先到、Hook 请求后到：迟到关联修正网关事件，修正结果也要落盘。
    gateway = store.add_event(event("TOOL_REQUEST", source="mcp-gateway", mcp_server="kb", tool="search",
                                    call_id="call-1", round=2))
    hook = store.add_event(event("TOOL_REQUEST_HOOK", mcp_server="kb", tool="search", call_id="call-1", round=2))
    evidence = store.add_evidence("TOOL_RESULT", "aws_secret_access_key=abc", source="agent-hook", trace_id=TRACE)
    store.add_event(event("TOOL_RESULT_HOOK", call_id="call-1", round=2, evidence_ids=[evidence["evidence_id"]],
                          labels=["CREDENTIAL", "UNTRUSTED_MCP", "SECRET_LEARNED"]))
    decision = store.add_decision(Decision(
        decision="ASK", decision_id=new_id("dec"), reason_code="OUTSIDE_WORKSPACE", severity="MEDIUM",
        matched_rules=[RuleMatch("AG-R1", "ASK", "OUTSIDE_WORKSPACE", "MEDIUM")], trace_id=TRACE,
        tool="Write", evidence_ids=[hook.event_id], latency_ms=1.5))
    store.resolve_decision(decision.decision_id, "APPROVED")
    store.annotate_decision(decision.decision_id, {"assessment": "false_positive", "note": "开发者要求"})

    loaded = reopen(store, path)
    assert [e["stage"] for e in loaded.get_events(limit=10)][::-1] == [
        "TASK_CREATED", "MODEL_TURN", "MODEL_TURN", "TOOL_REQUEST", "TOOL_REQUEST_HOOK", "TOOL_RESULT_HOOK"]
    assert loaded._events_by_id[gateway.event_id].parent_span_id == hook.span_id
    saved = loaded.get_decisions(trace_id=TRACE)[0]
    assert saved["resolution"] == "APPROVED" and saved["assessment"]["assessment"] == "false_positive"
    assert saved["matched_rules"][0]["rule_id"] == "AG-R1" and saved["context"]["call_id"] == "call-1"
    assert loaded.get_evidence(evidence["evidence_id"], include_content=True)["content"] == evidence["content"]
    assert loaded.get_evidence(evidence["evidence_id"])["event_id"]          # 证据反向关联同样保存
    assert loaded.resolve_trace_id(decision.decision_id) == TRACE == loaded.resolve_trace_id("task-1")
    chain = loaded.build_trace(TRACE)
    assert chain["task"]["task_id"] == "task-1"
    assert not any(node.get("link_note") for node in chain["chain"])
    assert loaded.metrics()["rule_hits"] == {"AG-R1": 1}
    # 会话再次活动：轮次接着往下数，污点恢复（不含附加标签）。
    state = loaded.state_for(TRACE)
    assert state.rounds == 2 and state.taints == {"CREDENTIAL", "UNTRUSTED_MCP"}
    assert state.tool_history == [{"server": "", "tool": "Write", "decision": "ASK"}]
    # 加载的数据不会被再次写入，修改后覆盖原行、不新增。
    loaded.resolve_decision(decision.decision_id, "NOT_EXECUTED")   # 已有结论，不覆盖
    loaded.close()
    rows = sqlite3.connect(path).execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
    assert rows == 1


def test_retention_row_limit_and_corrupt_rows(tmp_path, monkeypatch):
    path = tmp_path / "runtime.db"
    db = P.RuntimeDB(str(path), retention_days=7)
    old = P.iso_cutoff(8)
    db.put("events", "evt-old", TRACE, old, {"event_id": "evt-old", "trace_id": TRACE, "stage": "X", "source": "s"})
    for index in range(5):
        key = f"evt-{index}"
        db.put("events", key, TRACE, P.iso_cutoff(0), {"event_id": key, "trace_id": TRACE, "stage": "X",
                                                       "source": "s", "unknown_field": 1})
    db.flush()
    with db._db_lock:
        db._conn.execute("INSERT INTO events(key, trace_id, ts, data) VALUES ('bad', ?, ?, '{broken')",
                         (TRACE, P.iso_cutoff(0)))
        db._conn.commit()
    assert [item["event_id"] for item in db.load("events", 3)] == ["evt-3", "evt-4"]   # 损坏行跳过
    store = RuntimeStore(db_path=str(path))      # 未知字段忽略，超期的不加载
    assert [e["event_id"] for e in store.get_events(limit=10)] == ["evt-4", "evt-3", "evt-2", "evt-1", "evt-0"]
    monkeypatch.setitem(P.MAX_ROWS, "events", 2)
    store.db.prune()
    assert store.db.status()["rows"]["events"] == 2
    keys = [row[0] for row in sqlite3.connect(path).execute("SELECT key FROM events ORDER BY rowid")]
    assert keys == ["evt-4", "bad"]


def test_memory_only_without_path():
    store = RuntimeStore()
    store.add_event(event("TASK_CREATED"))
    assert store.db is None and store.metrics()["storage"] == {"path": ""}


@pytest.fixture()
def app_factory(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AG_AGENT_DEVICES", json.dumps({
        "agd_persist": {"device_id": "dev-persist", "actor": {"sub": "alice"}, "profile": "developer"}}))
    monkeypatch.setenv("AG_DATA_DIR", "")
    monkeypatch.setenv("AG_AGENT_DEVICE_DIR", str(tmp_path))
    monkeypatch.setenv("AG_LOCAL_TEST", "1")
    monkeypatch.setenv("AG_AGENT_ADMIN_TOKEN", "")
    monkeypatch.setenv("AG_INTENT_LLM_KEY", "")
    from agentguard.main import create_app

    return lambda: TestClient(create_app())


def test_hook_session_survives_restart(app_factory):
    def send(client, event_name, **fields):
        body = {"session_id": "s-1", "hook_event_name": event_name, "cwd": "/home/dev/project", **fields}
        response = client.post("/v1/agents/claude-code/hook", json=body,
                               headers={"Authorization": "Bearer agd_persist"})
        assert response.status_code == 200, response.text
        return response.json()

    with app_factory() as client:
        send(client, "UserPromptSubmit", prompt="改一下 hosts")
        result = send(client, "PreToolUse", tool_name="Write", tool_use_id="toolu_1",
                      tool_input={"file_path": "/etc/hosts.d/x.conf", "content": "1"})
        send(client, "Stop")
        trace_id = client.get("/v1/runtime/decisions?limit=5").json()["decisions"][0]["trace_id"]
    with app_factory() as client:
        decisions = client.get("/v1/runtime/decisions?decision=ASK").json()["decisions"]
        assert [item["decision_id"] for item in decisions] == [result["decision_id"]]
        assert client.get(f"/v1/runtime/traces/{trace_id}").json()["task"]["instance_id"] == "dev-persist"
        assert client.get("/v1/runtime/metrics").json()["storage"]["loaded"]["decisions"] == 1
        send(client, "UserPromptSubmit", prompt="继续")
        turns = client.get(f"/v1/runtime/events?trace_id={trace_id}&stage=MODEL_TURN").json()["events"]
        assert [item["round"] for item in turns] == [2, 1]
