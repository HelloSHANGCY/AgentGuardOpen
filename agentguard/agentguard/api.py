"""查询面 API、内部汇聚 API、SSE 与控制台静态页（设计 §5.8 / §10）。

- 数据面（/mcp/{server}）见 gateway/mcp.py；
- /v1/runtime/tasks* 供 Agent Hook 创建/闭合任务与上报模型轮次事件；
- SSE 第一版只承诺实时快照流，无断线重放。
"""

import asyncio
import json
import os

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse

from .config import Settings
from .gateway.manifest import ManifestRegistry
from .gateway.stacks import normalize_stack
from .models import RuntimeEvent, new_id, redact_text, sha256_digest
from .storage.context import TaskContextService
from .storage.store import RuntimeStore

# 控制台前端位于包外（agentguard/console），镜像内只复制构建产物 dist；AG_CONSOLE_DIR 可覆盖。
CONSOLE_DIR = os.getenv("AG_CONSOLE_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "console")
CONSOLE_INDEX = CONSOLE_DIR + "/dist/index.html"


def build_api(settings: Settings, store: RuntimeStore, contexts: TaskContextService,
              manifests: ManifestRegistry) -> APIRouter:
    router = APIRouter()

    def check_hook_secret(x_ag_secret: str | None) -> None:
        # Hook -> 网关的共享密钥只防外部直写；网络分区才是主要边界。
        if settings.hook_secret and x_ag_secret != settings.hook_secret:
            raise HTTPException(status_code=401, detail="invalid hook secret")


    def context_evidence(trace_id: str, items, source: str) -> list[str]:
        """把 Hook 上报的上下文（Skill/模型消息/工具参数/结果）存入受控证据存储。"""
        evidence_ids = []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if content is None:
                content = item.get("preview") or ""
            if not content and not item.get("digest") and not item.get("labels"):
                continue  # 空上下文不产生无意义证据
            record = store.add_evidence(
                kind=str(item.get("kind") or "CONTEXT"), content=content, source=source,
                trace_id=trace_id, labels=item.get("labels") or [],
                collection_truncated=bool(item.get("truncated")),
                origin_source=str(item.get("source") or source),
                role=str(item.get("role") or ""),
                original_digest=str(item.get("digest") or ""),
                original_length=int(item.get("length") or 0),
            )
            evidence_ids.append(record["evidence_id"])
        return evidence_ids

    # ---------- Hook 数据面 ----------

    @router.post("/v1/runtime/tasks")
    def create_task(body: dict, x_ag_secret: str | None = Header(default=None)):
        check_hook_secret(x_ag_secret)
        trace_id = str(body.get("trace_id") or "")
        if not trace_id:
            raise HTTPException(status_code=400, detail="trace_id required")
        prompt = str(body.get("prompt") or "")
        skill = dict(body.get("skill") or {})
        if skill.get("body_preview"):
            skill["body_preview"] = redact_text(str(skill["body_preview"]), limit=400)["preview"]
        task = contexts.create(
            trace_id=trace_id,
            actor=body.get("actor") or {},
            prompt=prompt,
            skill=skill,
            source_labels=body.get("source_labels"),
            instance_id=str(body.get("instance_id") or ""),
        )
        # 提示词与 Skill 正文进入受控证据存储；任务信封只保留预览与摘要。
        prompt_record = store.add_evidence(
            kind="PROMPT", content=prompt, source="agent-hook", trace_id=trace_id,
            labels=list(task.source_labels), origin_source="user-input", role="user",
            original_digest=task.intent_digest, original_length=len(prompt))
        task.intent_evidence_id = prompt_record["evidence_id"]
        evidence_ids = [prompt_record["evidence_id"]]
        if skill:
            skill_record = store.add_evidence(
                kind="SKILL_METADATA", content=json.dumps(skill, ensure_ascii=False),
                source="agent-hook", trace_id=trace_id,
                labels=["UNTRUSTED_SKILL"] if "UNTRUSTED_SKILL" in task.source_labels else [],
                origin_source=f"skills/{skill.get('name', '')}", role="system")
            task.skill_evidence_id = skill_record["evidence_id"]
            evidence_ids.append(skill_record["evidence_id"])
        evidence_ids += context_evidence(trace_id, body.get("context"), "agent-hook")
        store.set_task(trace_id, task.as_dict(), replace=False)
        store.add_event(RuntimeEvent(
            event_id=new_id("evt"), trace_id=trace_id, stage="TASK_CREATED", source="agent-hook",
            actor=task.actor.as_dict(), component="mcp-client",
            labels=list(task.source_labels),
            payload_digest=task.intent_digest,
            redacted_preview=prompt_record["preview"],
            stack=normalize_stack(body.get("stack"), "app"),
            evidence_ids=evidence_ids,
        ))
        return {"task_id": task.task_id, "trace_id": trace_id, "expires_in": settings.task_ttl_seconds}

    @router.post("/v1/runtime/tasks/{trace_id}/events")
    def task_event(trace_id: str, body: dict, x_ag_secret: str | None = Header(default=None)):
        check_hook_secret(x_ag_secret)
        task = contexts.get(trace_id)
        stage = str(body.get("stage") or "MODEL_TURN")
        evidence_ids = context_evidence(trace_id, body.get("context"), "agent-hook")
        if body.get("tool_plan") is not None:
            plan = store.add_evidence(kind="TOOL_PLAN", content=json.dumps(body["tool_plan"], ensure_ascii=False),
                                      source="agent-hook", trace_id=trace_id, labels=["TOOL_PLAN"])
            evidence_ids.append(plan["evidence_id"])
        summary = str(body.get("summary", ""))
        store.add_event(RuntimeEvent(
            event_id=new_id("evt"), trace_id=trace_id, stage=stage, source="agent-hook",
            actor=task.actor.as_dict() if task else {},
            component="mcp-client", mcp_server=str(body.get("server") or ""),
            tool=str(body.get("tool") or ""), round=int(body.get("round") or 0),
            call_id=str(body.get("call_id") or ""),
            labels=[str(item) for item in (body.get("labels") or [])],
            payload_digest=sha256_digest(summary),
            redacted_preview=redact_text(summary, limit=160)["preview"],
            stack=normalize_stack(body.get("stack"), "app"),
            evidence_ids=evidence_ids,
        ))
        return {"accepted": True}

    @router.post("/v1/runtime/tasks/{trace_id}/complete")
    def complete_task(trace_id: str, body: dict, x_ag_secret: str | None = Header(default=None)):
        check_hook_secret(x_ag_secret)
        contexts.complete(trace_id)
        state = store.state_for(trace_id)
        # Hook 队列丢弃/上报失败必须显式可见，不能默默展示为完整链路。
        dropped = int(body.get("hook_dropped") or 0)
        failed = int(body.get("hook_failed") or 0)
        labels = [str(body.get("status") or "completed")]
        preview = f"tools={len(state.tool_history)}"
        if dropped or failed:
            labels.append("AUDIT_INCOMPLETE")
            preview += f",hook_dropped={dropped},hook_failed={failed}"
        store.add_event(RuntimeEvent(
            event_id=new_id("evt"), trace_id=trace_id, stage="TASK_COMPLETED", source="agent-hook",
            labels=labels, redacted_preview=preview,
            stack=normalize_stack(body.get("stack"), "app"),
        ))
        return {"closed": True}






    # ---------- 查询面 ----------

    @router.get("/v1/runtime/events")
    def list_events(trace_id: str = "", stage: str = "", source: str = "", limit: int = 200):
        # total：服务端当前保存的事件总数，控制台据此提示还有多少更早的事件未加载。
        limit = max(1, min(limit, 5000))
        return {"events": store.get_events(trace_id, stage, source, limit), "total": store.event_count()}

    @router.get("/v1/runtime/decisions")
    def list_decisions(trace_id: str = "", decision: str = "", limit: int = 200, anomalous: bool = False,
                       reviewed: bool = False):
        # anomalous=1：只返回行为基线超阈值的决策（控制台「行为观察」）；
        # reviewed=1：只返回大模型危险审批改变了结论的决策（如静态拦截、模型放行）。
        return {"decisions": store.get_decisions(trace_id, decision, limit, anomalous, reviewed)}

    @router.get("/v1/runtime/traces/{trace_id}")
    def get_trace(trace_id: str):
        # 攻击链内嵌 evidence 预览；原文由单条证据接口按需读取。
        return store.build_trace(trace_id)

    @router.get("/v1/runtime/evidence/{evidence_id}")
    def get_evidence(evidence_id: str):
        # 比赛控制台按需直接读取脱敏原文。
        record = store.get_evidence(evidence_id, include_content=True)
        if record is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        return record

    @router.get("/v1/runtime/metrics")
    def get_metrics():
        return store.metrics()

    @router.get("/v1/runtime/policies")
    def get_policies():
        return {
            "rules_version": settings.rules_version,
            "manifests": manifests.snapshot(),
            "upstreams": sorted(settings.upstreams),
        }

    @router.get("/v1/runtime/stream")
    async def stream(request: Request):
        q = store.subscribe()

        async def generator():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = q.get_nowait()
                        yield f"event: {item['kind']}\ndata: {json.dumps(item['data'], ensure_ascii=False)}\n\n"
                    except Exception:
                        await asyncio.sleep(0.3)
            finally:
                store.unsubscribe(q)

        return StreamingResponse(generator(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache"})

    # ---------- 控制台 ----------

    @router.get("/", include_in_schema=False)
    @router.get("/console", include_in_schema=False)
    def console():
        if not os.path.exists(CONSOLE_INDEX):
            return HTMLResponse(
                "<h1>AgentGuard 控制台未构建</h1>"
                "<p>请在 agentguard/console 执行 <code>npm install && npm run build</code>，"
                "或使用 <code>make console-build</code>。</p>",
                status_code=503)
        return FileResponse(CONSOLE_INDEX)

    return router
