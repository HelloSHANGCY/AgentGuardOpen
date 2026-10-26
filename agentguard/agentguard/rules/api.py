"""特征规则库管理接口（控制台「规则库」）。

- GET    /v1/admin/rules：特征组、规则包与各规则启停状态、加载错误、最近变更；
- PUT    /v1/admin/rules/{rule_id}：启停单条规则；
- POST   /v1/admin/rules/test：样本测试，列出命中的规则（含已停用规则，便于评估停用影响）；
- POST   /v1/admin/rules/reset：恢复默认启停（自定义规则包保留）；
- POST   /v1/admin/rule-packs：上传自定义规则包（YAML 原文），同编号自定义包整体替换；
- PUT    /v1/admin/rule-packs/{pack_id}：启停整个规则包；
- GET    /v1/admin/rule-packs/{pack_id}/source：规则包原文；
- DELETE /v1/admin/rule-packs/{pack_id}：删除自定义规则包（内置包只能停用）。

停用规则会削弱检测，与设备管理共用管理令牌（AG_AGENT_ADMIN_TOKEN；本地测试模式且未配置时免令牌）。
变更立即注入当前进程，并同步运行时规则版本：决策记录与终端规则包随之更新版本。
"""

from fastapi import APIRouter, Header, HTTPException

from ..admin import require_admin
from ..config import RULES_VERSION
from .library import MAX_PACK_BYTES, PackError, RuleLibrary


def sync_rules_version(settings, library: RuleLibrary) -> None:
    settings.rules_version = library.version(RULES_VERSION)


def build_rules_api(settings, library: RuleLibrary) -> APIRouter:
    router = APIRouter()

    def authorize_admin(token: str | None) -> None:
        require_admin(settings, token, "rule admin")

    def changed(result):
        sync_rules_version(settings, library)
        return result

    def enabled_flag(body) -> bool:
        value = (body or {}).get("enabled") if isinstance(body, dict) else None
        if not isinstance(value, bool):
            raise HTTPException(400, "enabled 应为 true / false")
        return value

    @router.get("/v1/admin/rules")
    def overview(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        if library.refresh(min_interval=0):
            sync_rules_version(settings, library)
        return {**library.overview(), "runtime_version": settings.rules_version}

    @router.put("/v1/admin/rules/{rule_id}")
    def set_rule(rule_id: str, body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return changed(library.set_rule(rule_id, enabled_flag(body)))
        except KeyError:
            raise HTTPException(404, "rule not found")

    @router.post("/v1/admin/rules/test")
    def test_sample(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        body = body if isinstance(body, dict) else {}
        try:
            return {"hits": library.test(str(body.get("sample") or ""), str(body.get("group") or ""))}
        except PackError as exc:
            raise HTTPException(400, str(exc))

    @router.post("/v1/admin/rules/reset")
    def reset(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        library.reset()
        return changed({"default": library.is_default()})

    @router.post("/v1/admin/rule-packs", status_code=201)
    def upload_pack(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        content = (body or {}).get("content") if isinstance(body, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise HTTPException(400, "content 应为规则包 YAML 原文")
        if len(content.encode("utf-8")) > MAX_PACK_BYTES:
            raise HTTPException(413, f"规则包超过 {MAX_PACK_BYTES // 1024} KB")
        try:
            return changed(library.add_pack(content))
        except PackError as exc:
            raise HTTPException(400, str(exc))

    @router.put("/v1/admin/rule-packs/{pack_id}")
    def set_pack(pack_id: str, body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return changed(library.set_pack(pack_id, enabled_flag(body)))
        except KeyError:
            raise HTTPException(404, "rule pack not found")

    @router.get("/v1/admin/rule-packs/{pack_id}/source")
    def pack_source(pack_id: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            return {"pack": pack_id, "content": library.source(pack_id)}
        except KeyError:
            raise HTTPException(404, "rule pack not found")

    @router.delete("/v1/admin/rule-packs/{pack_id}")
    def delete_pack(pack_id: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            library.remove_pack(pack_id)
        except KeyError:
            raise HTTPException(404, "rule pack not found")
        except PackError as exc:
            raise HTTPException(400, str(exc))
        return changed({"deleted": pack_id})

    return router
