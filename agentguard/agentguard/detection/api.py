"""行为基线与意图识别的管理接口（控制台「行为基线」页；创新检测实施方案 §5）。

- GET /v1/admin/baseline：真实会话数据统计、模型列表与当前启用版本；
- POST /v1/admin/baseline/train、/activate，DELETE .../models/{version}、.../records：手动训练、启用与回滚、清理；
- GET/PUT /v1/admin/intent、POST .../test：可选的大模型意图分类（密钥只写不读）。
"""

from fastapi import APIRouter, Header, HTTPException
from starlette.concurrency import run_in_threadpool

from ..admin import require_admin
from . import anomaly as A
from . import behavior as B
from .baseline_comparison import compare_models


def build_detection_api(settings, engine, devices) -> APIRouter:
    router = APIRouter()

    def authorize_admin(token: str | None) -> None:
        require_admin(settings, token)

    # ---------- 行为基线：真实会话数据、手动训练、启用与回滚（创新检测实施方案 §5） ----------

    behavior = engine.behavior

    @router.get("/v1/admin/baseline")
    async def baseline_overview(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        data = await run_in_threadpool(behavior.recorder.stats)
        datasets = await run_in_threadpool(behavior.datasets.list)
        known = {device["device_id"]: device for device in devices.list()}
        for row in data["devices"]:
            row["registered"] = row["device"] in known
            row["actor"] = (known.get(row["device"]) or {}).get("actor", {}).get("sub", "")
        return {"active": behavior.active_version, "models": behavior.models(), "data": data, "datasets": datasets,
                "defaults": B.DEFAULT_PARAMS, "enabled": engine.feature("anomaly"), "intent": engine.intents.status(),
                "extractor": {"feature_schema_version": A.FEATURE_SCHEMA_VERSION,
                              "sequence_semantics_version": A.SEQUENCE_SEMANTICS_VERSION},
                "model_compatible": behavior.baseline.compatible,
                "disabled_reason": behavior.baseline.disabled_reason, "load_warning": behavior.load_warning}

    @router.post("/v1/admin/baseline/compare")
    async def baseline_compare(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return await run_in_threadpool(compare_models, behavior, body.get("versions"))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except KeyError:
            raise HTTPException(404, "model not found")

    @router.post("/v1/admin/baseline/train")
    async def baseline_train(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            model = await run_in_threadpool(behavior.train, body.get("params") if isinstance(body, dict) else None)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        # 只返回报告，计数表留在服务端；训练结果是候选模型，需要显式启用。
        return {"version": model["version"], "created_at": model["created_at"], "threshold": model["threshold"],
                "compatible": True, "feature_schema_version": model["feature_schema_version"],
                "sequence_semantics_version": model["sequence_semantics_version"],
                "score_semantics_version": model.get("score_semantics_version", 1),
                "evidence_schema_version": model.get("evidence_schema_version", 0),
                "scoring_config": model.get("scoring_config", {}),
                "order": model.get("scoring_config", {}).get("order", 1),
                "params": model["params"], "meta": model["meta"]}

    @router.post("/v1/admin/baseline/activate")
    def baseline_activate(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return behavior.activate(str((body or {}).get("version") or ""))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except KeyError:
            raise HTTPException(404, "model not found")

    @router.delete("/v1/admin/baseline/models/{version}")
    def baseline_delete(version: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            behavior.delete(version)
        except KeyError:
            raise HTTPException(404, "model not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"deleted": version}

    @router.delete("/v1/admin/baseline/records")
    def baseline_clear(device: str = "", x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return {"removed": behavior.recorder.clear(device)}

    # ---------- 意图识别：可选的大模型分类（开关、接口、模型、密钥、超时；密钥只写不读） ----------

    @router.get("/v1/admin/intent")
    def intent_status(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return engine.intents.status()

    @router.put("/v1/admin/intent")
    def intent_update(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return engine.intents.update(body if isinstance(body, dict) else {})
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/v1/admin/intent/test")
    async def intent_test(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        # 用当前配置叠加未保存的修改分类一条样例，便于保存前确认接口与密钥可用。
        authorize_admin(x_ag_admin_token)
        body = body if isinstance(body, dict) else {}
        text = body.get("text") or ""
        config = {} if body.get("config") is None else body["config"]
        if not isinstance(text, str) or len(text) > 2000 or not isinstance(config, dict):
            raise HTTPException(400, "text must be a string of at most 2000 chars, config an object")
        try:
            return await run_in_threadpool(engine.intents.test, config, text)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    return router
