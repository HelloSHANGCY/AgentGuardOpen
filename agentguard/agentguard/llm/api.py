"""大模型辅助研判与规则建议的接口（控制台「大模型研判」页、威胁中心）。

- GET/PUT /v1/admin/judge、POST .../test、GET .../analyses、POST .../analyze：危险审批与异步分析的配置、
  连接测试、分析记录与手动分析（见 judge.py；密钥只写不读）；
- GET /v1/admin/judge/proposals、POST .../proposals/{id}/approve|reject|check、POST .../analyses/{id}/propose：
  大模型规则建议的查看、审批与手动发起（见 rules/proposals.py）；
- GET /v1/runtime/analyses：威胁中心读取判为可疑 / 恶意的分析（只读，不含配置与密钥）。
"""

from fastapi import APIRouter, Header, HTTPException
from starlette.concurrency import run_in_threadpool

from ..admin import require_admin
from ..rules.api import sync_rules_version
from ..rules.library import PackError
from .registry import BindingConflict


def build_llm_api(settings, store, engine) -> APIRouter:
    router = APIRouter()

    def authorize_admin(token: str | None) -> None:
        require_admin(settings, token)

    # ---------- 大模型辅助研判：危险审批与异步分析（llm/judge.py；密钥只写不读） ----------

    judge = engine.judge
    models = engine.models

    @router.get("/v1/admin/models")
    def list_models(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return models.overview()

    def save_model(body, model_id=None):
        try:
            return models.save(body, model_id)
        except BindingConflict as exc:
            raise HTTPException(409, str(exc))
        except KeyError:
            raise HTTPException(404, "model not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/v1/admin/models")
    def create_model(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return save_model(body)

    @router.put("/v1/admin/models/{model_id}")
    def update_model(model_id: str, body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return save_model(body, model_id)

    @router.delete("/v1/admin/models/{model_id}")
    def delete_model(model_id: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            models.delete(model_id)
            return {"deleted": model_id}
        except BindingConflict as exc:
            raise HTTPException(409, str(exc))
        except KeyError:
            raise HTTPException(404, "model not found")

    @router.post("/v1/admin/models/discover")
    async def discover_models(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        config = body.get("config")
        if not isinstance(config, dict):
            raise HTTPException(400, "config must be an object")
        model_id = body.get("model_id")
        if model_id is not None and not isinstance(model_id, str):
            raise HTTPException(400, "model_id must be a string")
        try:
            return await run_in_threadpool(models.discover, config, model_id)
        except KeyError:
            raise HTTPException(404, "model not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/v1/admin/models/test")
    async def test_model(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return await run_in_threadpool(models.test, body.get("config", {}), body.get("model_id"))
        except KeyError:
            raise HTTPException(404, "model not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.get("/v1/admin/judge")
    def judge_status(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return judge.status()

    @router.put("/v1/admin/judge")
    def judge_update(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return judge.update(body if isinstance(body, dict) else {})
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/v1/admin/judge/test")
    async def judge_test(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        # 用当前配置叠加未保存的修改复核一条样例调用，保存前确认接口、模型与密钥可用。
        authorize_admin(x_ag_admin_token)
        config = (body or {}).get("config") if isinstance(body, dict) else None
        if config is not None and not isinstance(config, dict):
            raise HTTPException(400, "config must be an object")
        try:
            return await run_in_threadpool(judge.test, config or {})
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.get("/v1/admin/judge/analyses")
    def judge_analyses(trace_id: str = "", verdict: str = "", limit: int = 200,
                       x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        trace_id = store.resolve_trace_id(trace_id) if trace_id else ""
        return {"analyses": judge.analyses(trace_id, verdict, max(1, min(limit, 1000)))}

    # ---------- 规则建议：分析发现漏报后由模型提议、人工审批后写入规则库（rules/proposals.py） ----------

    @router.get("/v1/admin/judge/proposals")
    def list_proposals(status: str = "", x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return {"proposals": judge.proposals.list(status), "summary": judge.proposals.summary()}

    @router.post("/v1/admin/judge/analyses/{analysis_id}/propose")
    def propose_rules(analysis_id: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return judge.propose_for(store, analysis_id)
        except KeyError:
            raise HTTPException(404, "analysis not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/v1/admin/judge/proposals/{proposal_id}/{action}")
    def decide_proposal(proposal_id: str, action: str, body: dict | None = None,
                        x_ag_admin_token: str | None = Header(default=None)):
        # approve 可带修改后的规则（YAML 原文或映射），校验通过后写入 llm-generated 规则包并立即生效。
        authorize_admin(x_ag_admin_token)
        body = body if isinstance(body, dict) else {}
        note = str(body.get("note") or "")
        try:
            if action == "approve":
                result = judge.proposals.approve(proposal_id, body.get("rule"), note)
                sync_rules_version(settings, judge.proposals.library)
                return result
            if action == "reject":
                return judge.proposals.reject(proposal_id, note)
            if action == "check":
                # 修改后重新检查（证据、样本级误报、夹具回放），不改动建议本身。
                return judge.proposals.check(proposal_id, body.get("rule"))
        except KeyError:
            raise HTTPException(404, "proposal not found")
        except (PackError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        raise HTTPException(404, "unknown action")

    @router.get("/v1/runtime/analyses")
    def risky_analyses(limit: int = 200):
        # 威胁中心只读：异步分析判为可疑 / 恶意的会话（与 /v1/runtime/decisions 同级开放，不含配置与密钥）。
        return {"analyses": judge.risky(max(1, min(limit, 500)))}

    @router.post("/v1/admin/judge/analyze")
    def judge_analyze(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        # 手动分析一个会话（round 为 0 或省略时分析整个会话），不受异步分析模式限制。
        authorize_admin(x_ag_admin_token)
        body = body if isinstance(body, dict) else {}
        trace_id = store.resolve_trace_id(str(body.get("trace_id") or "").strip())
        round_no = body.get("round") or 0
        if not trace_id or isinstance(round_no, bool) or not isinstance(round_no, int) or round_no < 0:
            raise HTTPException(400, "trace_id required; round must be a non-negative integer")
        events, _ = store.trace_snapshot(trace_id)
        if not events:
            raise HTTPException(404, "session not found")
        agent = next((event.component for event in events if event.source == "agent-hook"), "")
        device_id = next((str(task.get("instance_id") or "") for task in [store.tasks.get(trace_id)]
                          if isinstance(task, dict)), "")
        try:
            return judge.analyze(store, trace_id, round_no, agent, device_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    return router
