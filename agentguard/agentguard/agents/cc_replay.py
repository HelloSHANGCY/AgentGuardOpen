"""Claude Code 夹具回放（评测 worker 与测试共用）。

Hook 事件经真实 Hook 客户端子进程发送（与 Claude Code 调用方式一致，延迟为端到端口径）；
客户端脚本不可用时退回直接 HTTP。清单上报与中转检查模拟 stdio 包装器，直接调用接口。
每个夹具一条结果行，使用统一评测字段（outcome / decisions / effect_ok / elapsed_ms），
额外带逐步明细 `steps` 与 PreToolUse 延迟 `latencies_ms`。
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter

import httpx

REASON_RE = re.compile(r": ([A-Z0-9_]+) \((dec-[^)]+)\)")
BLOCKING = ("ask", "deny")


def _matches(expect: str, got: str) -> bool:
    if expect == "block":
        return got in BLOCKING
    if expect in ("allow", "defer"):
        # 放行与受管 MCP 预判放行在 Hook 输出上一致（都不输出），按“未拦截”比较。
        return got == "allow"
    return expect == got


class HookTransport:
    """把一条 Hook 负载交给服务端，返回 (Hook 输出 JSON 或 None, 耗时 ms)。"""

    def __init__(self, base_url: str, client: httpx.Client, hook_script: str = "", spool_dir: str = "",
                 endpoint: str = ""):
        self.base_url = base_url.rstrip("/")
        self.client = client
        # 直接 HTTP 时冒充的终端客户端标识（agentguard-endpoint/x.y.z）：服务端据此决定大模型复核最多等多久。
        self.endpoint = endpoint
        self.hook_script = hook_script if hook_script and os.path.exists(hook_script) else ""
        self.spool_dir = spool_dir or tempfile.mkdtemp(prefix="ag-cc-replay-")
        self.mode = "hook-client" if self.hook_script else "http"

    def send(self, payload: dict, token: str) -> tuple[dict | None, float]:
        started = time.monotonic()
        if self.hook_script:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.spool_dir,
                   "AGENTGUARD_URL": self.base_url, "AGENTGUARD_TOKEN": token,
                   "AGENTGUARD_SPOOL": os.path.join(self.spool_dir, "spool.jsonl")}
            done = subprocess.run([sys.executable, self.hook_script], input=json.dumps(payload), text=True,
                                  capture_output=True, env=env, timeout=10)
            elapsed = (time.monotonic() - started) * 1000
            text = done.stdout.strip()
            return (json.loads(text) if text else None), elapsed
        if self.endpoint:
            payload = {**payload, "_ag": {**(payload.get("_ag") or {}), "client": self.endpoint}}
        response = self.client.post(self.base_url + "/v1/agents/claude-code/hook", json=payload,
                                    headers={"Authorization": f"Bearer {token}"}, timeout=10)
        response.raise_for_status()
        return response.json().get("output"), (time.monotonic() - started) * 1000

    def api(self, path: str, body: dict, token: str) -> dict:
        response = self.client.post(self.base_url + path, json=body,
                                    headers={"Authorization": f"Bearer {token}"}, timeout=10)
        response.raise_for_status()
        return response.json()


def _action(output: dict | None) -> tuple[str, str, str]:
    specific = (output or {}).get("hookSpecificOutput") or {}
    decision = specific.get("permissionDecision")
    if not decision:
        return "allow", "", ""
    match = REASON_RE.search(str(specific.get("permissionDecisionReason") or ""))
    return decision, (match.group(1) if match else ""), (match.group(2) if match else "")


def replay_fixture(fixture: dict, transport: HookTransport, token: str, device_id: str, run_tag: str,
                   cwd: str = "/home/dev/project") -> dict:
    session_id = f"{fixture['id']}-{run_tag}"
    trace_ids = [f"cc-{device_id}-{session_id}"]
    counter, agent_id, last_call = 0, None, {}
    steps, latencies, notes = [], [], []

    def payload(event: str, **fields) -> dict:
        body = {"session_id": session_id, "hook_event_name": event, "cwd": cwd,
                "transcript_path": f"/tmp/{session_id}.jsonl", **fields}
        if agent_id:
            body.update(agent_id=agent_id, agent_type="general-purpose")
        return body

    transport.send(payload("SessionStart", source="startup"), token)
    for step in fixture["steps"]:
        if "prompt" in step:
            transport.send(payload("UserPromptSubmit", prompt=step["prompt"]), token)
        elif "session" in step:
            # 同一设备上开启新会话（跨会话关联场景）：结束当前会话，后续步骤归属新会话。
            agent_id = None
            transport.send(payload("SessionEnd", reason="other"), token)
            session_id = f"{fixture['id']}-{run_tag}-{step['session']}"
            trace_ids.append(f"cc-{device_id}-{session_id}")
            transport.send(payload("SessionStart", source="startup"), token)
        elif "stop" in step:
            # 一轮回答结束（Claude Code 的 Stop 事件）：触发该轮的异步分析。
            transport.send(payload("Stop", stop_hook_active=False), token)
        elif "cwd" in step:
            # 会话中途切换工作目录（真实会话记录逐条带 cwd），之后的 Hook 负载使用新目录。
            cwd = step["cwd"]
        elif "subagent" in step:
            agent_id = step["subagent"]
            if agent_id:
                transport.send(payload("SubagentStart"), token)
        elif "manifest" in step:
            transport.api(f"/v1/runtime/mcp/manifests/{step['manifest']}", {"tools": step["tools"]}, token)
        elif "relay" in step:
            body = {"server": step["relay"], "tool": step["tool"], "arguments": step["arguments"]}
            result = transport.api("/v1/runtime/mcp/inspect-request", body, token)
            ok = result.get("decision") == step["expect"]
            steps.append({"tool": f"relay:{step['relay']}/{step['tool']}", "expect": step["expect"],
                          "got": result.get("decision"), "reason": result.get("reason_code", ""), "ok": ok})
            if not ok:
                notes.append(f"relay {step['tool']}: {result.get('decision')}")
            if result.get("disabled"):
                notes.append(f"relay {step['tool']}: hook disabled")
            elif result.get("decision") == "ALLOW" and "result" in step and result.get("trace_id"):
                transport.api("/v1/runtime/mcp/inspect-result",
                              {**body, "trace_id": result["trace_id"], "call_id": result.get("call_id", ""),
                               "decision_id": result["decision_id"], "result": step["result"]}, token)
        elif "pre" in step:
            counter += 1
            call_id = f"toolu_{run_tag}_{counter}"
            last_call[step.get("call") or step["pre"]] = call_id
            output, elapsed = transport.send(
                payload("PreToolUse", tool_name=step["pre"], tool_input=step["input"], tool_use_id=call_id), token)
            got, reason, decision_id = _action(output)
            latencies.append(round(elapsed, 2))
            ok = _matches(step["expect"], got)
            steps.append({"tool": step["pre"], "expect": step["expect"], "got": got, "reason": reason,
                          "decision_id": decision_id, "risk": bool(step.get("risk")), "ok": ok,
                          "ms": round(elapsed, 2), "trace_id": trace_ids[-1]})
            if not ok:
                notes.append(f"{step['pre']}: expect {step['expect']}, got {got}")
        elif "post" in step:
            transport.send(payload("PostToolUse", tool_name=step["post"], tool_input=step["input"],
                                   tool_response=step["response"],
                                   tool_use_id=last_call.get(step.get("call") or step["post"], "")), token)
        elif "fail" in step:
            transport.send(payload("PostToolUseFailure", tool_name=step["fail"], tool_input=step["input"],
                                   error=step["error"], tool_use_id=last_call.get(step.get("call") or step["fail"], "")),
                           token)
    agent_id = None
    transport.send(payload("SessionEnd", reason="other"), token)

    blocked_any = any(item["got"] in BLOCKING for item in steps if "ms" in item)
    risk = next((item for item in steps if item.get("risk")), None)
    if fixture["malicious"]:
        detected = bool(risk and risk["got"] in BLOCKING)
        outcome = "TP" if detected else "FN"
    else:
        outcome = "FP" if blocked_any else "TN"
    return {
        # 多会话夹具以高风险点所在会话为主 trace，trace_ids 保留全部会话。
        "trace_id": (risk or {}).get("trace_id") or trace_ids[0], "trace_ids": trace_ids,
        "fixture": fixture["id"], "scenario": fixture["threat"],
        "malicious": fixture["malicious"], "profile": fixture.get("profile", "developer"),
        "outcome": outcome, "first_risk": (risk or {}).get("got"), "first_risk_reason": (risk or {}).get("reason", ""),
        "steps": steps, "latencies_ms": latencies,
        # 逐步决策与期望一致（含非高风险步骤），用来发现“拦对了但拦在了错误位置”的情况。
        "effect_ok": not notes, "effect_note": "; ".join(notes)[:300] or "all_steps_match",
        "business_ok": None if fixture["malicious"] else not blocked_any,
        "unknown_reason": "",
    }


def attach_decisions(row: dict, client: httpx.Client, base_url: str) -> None:
    decisions = []
    for trace_id in row.get("trace_ids") or [row["trace_id"]]:
        response = client.get(base_url.rstrip("/") + "/v1/runtime/decisions",
                              params={"trace_id": trace_id, "limit": 200}, timeout=10)
        response.raise_for_status()
        decisions += [item for item in response.json()["decisions"] if item.get("trace_id") == trace_id]
    row["decision_ids"] = [item["decision_id"] for item in decisions]
    row["decisions"] = dict(Counter(item["decision"] for item in decisions))
    row["reason_codes"] = sorted({item.get("reason_code") for item in decisions if item.get("decision") != "ALLOW"})
