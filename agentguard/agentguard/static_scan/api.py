"""静态扫描 API 路由（方案 §6）。

API 只负责校验、排队、查询；扫描由独立 worker 执行。
扫描根只能是管理员登记的 source_id，或 AG_STATIC_ROOTS 白名单内、由前端填写的路径；
两者最终都映射为只读目录，请求不能传白名单外的宿主机路径或可执行命令。
"""

import hmac
import json
import os

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response

from ..admin import require_admin
from ..core.asset_snapshot import SCOPES, snapshot_file_limit
from .inputs import InputError, effective_roots, is_within_roots, path_source_id, resolve_scan_root
from .models import Review, ScanRecord, new_id
from .reports import build_report, dump_json, render_markdown
from .snapshots import cleanup_snapshot

QUEUE_LIMIT = 20
BROWSE_LIMIT = 500


def build_static_api(settings, repository, devices=None) -> APIRouter:
    router = APIRouter(prefix="/v1/static")

    def check_admin(request: Request, x_ag_admin: str | None) -> None:
        """管理面鉴权：配置了 static_admin_token 时必须匹配。

        未配置令牌时仅作为本地开发模式，部署文档要求显式配置。
        """
        token = getattr(settings, "static_admin_token", "")
        if token:
            if not x_ag_admin or not hmac.compare_digest(x_ag_admin.encode(), token.encode()):
                raise HTTPException(status_code=401, detail="invalid static admin token")
        elif devices is not None:
            # 接入设备的管理/快照读写不能因未单独设置 static token 而绕过统一管理鉴权。
            require_admin(settings, x_ag_admin or request.headers.get("x-ag-admin-token"), "static admin")

    @router.get("/sources")
    def list_sources(request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        return {"sources": sorted(getattr(settings, "static_sources", {}) or {}),
                "roots": list(effective_roots(settings)),
                "admin_token_configured": bool(getattr(settings, "static_admin_token", "")
                                               or getattr(settings, "agent_admin_token", ""))}

    @router.get("/devices")
    def list_devices(request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        return {"devices": [{key: item.get(key) for key in
                             ("device_id", "agents", "host", "last_seen", "client", "seen_agents", "scan_channel")}
                            for item in (devices.list() if devices else [])
                            if not item.get("uninstalled_at") and item.get("purpose") != "evaluation"]}

    @router.get("/browse")
    def browse(request: Request, path: str = "",
               x_ag_admin: str | None = Header(default=None)):
        """浏览授权根白名单内的目录，供前端选择扫描路径（只列目录，不读文件内容）。"""
        check_admin(request, x_ag_admin)
        roots = effective_roots(settings)
        if not roots:
            raise HTTPException(status_code=400, detail="no authorized roots configured")
        if not path.strip():
            entries = [{"name": os.path.basename(root) or root, "path": root, "is_dir": True}
                       for root in roots if os.path.isdir(root)]
            return {"path": "", "parent": "", "roots": list(roots), "entries": entries}
        try:
            current = resolve_scan_root(path, roots)
        except InputError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        try:
            names = sorted(os.listdir(current), key=str.lower)
        except OSError as exc:
            raise HTTPException(status_code=400, detail=f"cannot list directory: {exc.strerror or exc}")
        entries = []
        for name in names:
            real = os.path.realpath(os.path.join(current, name))
            if not is_within_roots(real, roots) or not os.path.isdir(real):
                continue
            entries.append({"name": name, "path": real, "is_dir": True})
            if len(entries) >= BROWSE_LIMIT:
                break
        parent = os.path.dirname(current)
        if parent == current or not is_within_roots(parent, roots):
            parent = ""
        return {"path": current, "parent": parent, "roots": list(roots), "entries": entries}

    @router.post("/scans", status_code=202)
    def create_scan(body: dict, request: Request, response: Response,
                    x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        source_id = str(body.get("source_id") or "")
        raw_path = str(body.get("path") or "").strip()
        sources = getattr(settings, "static_sources", {}) or {}
        source_path = ""
        device_id, agent = str(body.get("device_id") or ""), str(body.get("agent") or "")
        collection = {}
        limits = {}
        if device_id:
            device = next((item for item in devices.devices() if item.device_id == device_id), None) if devices else None
            if device is None or device.uninstalled_at or device.purpose == "evaluation":
                raise HTTPException(404, "device not found")
            if not device.allows(agent):
                raise HTTPException(400, "agent not allowed for this device")
            if raw_path or source_id:
                raise HTTPException(400, "device scan cannot specify server path or source_id")
            scope = body.get("scope", "user")
            if scope not in SCOPES:
                raise HTTPException(400, "invalid device scan scope")
            source_id = f"device:{device_id}:{agent}"
            collection = {"scope": scope}
            try:
                limits = {"max_file_parse_bytes": snapshot_file_limit(body.get("limits"))}
            except ValueError as exc:
                raise HTTPException(400, str(exc))
        elif raw_path:
            roots = effective_roots(settings)
            if not roots:
                raise HTTPException(status_code=400, detail="no authorized roots configured")
            try:
                source_path = resolve_scan_root(raw_path, roots)
            except InputError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            # 自定义路径不接受客户端指定 source_id，避免与已登记来源混淆。
            source_id = path_source_id(source_path)
        elif source_id not in sources:
            raise HTTPException(status_code=400, detail="source_id not registered")
        else:
            source_path = os.path.realpath(str(sources[source_id]))
        project_id = str(body.get("project_id") or "default")
        idempotency_key = str(body.get("idempotency_key") or "")
        if idempotency_key:
            existing = repository.find_scan_by_idempotency(project_id, idempotency_key)
            if existing is not None:
                response.status_code = 200
                return {"scan_id": existing.scan_id, "status": existing.status, "idempotent": True}
        repository.expire_device_scans()
        if repository.active_scan_count() >= QUEUE_LIMIT:
            raise HTTPException(status_code=429, detail="static scan queue is full")
        record = ScanRecord(
            scan_id=new_id("scan"), project_id=project_id, source_id=source_id,
            source_path=source_path, profile=str(body.get("profile") or "default"),
            idempotency_key=idempotency_key,
            device_id=device_id, agent=agent if device_id else "", collection=collection, limits=limits,
            phase="WAITING_ENDPOINT" if device_id else "QUEUED",
        )
        repository.create_scan(record)
        return {"scan_id": record.scan_id, "status": record.status, "idempotent": False}

    @router.get("/scans")
    def list_scans(request: Request, project_id: str = "", limit: int = 50,
                   x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        repository.expire_device_scans()
        return {"scans": [record.as_dict() for record in repository.list_scans(project_id, limit)]}

    @router.get("/inventory")
    def asset_inventory(request: Request, scan_id: str = "", kind: str = "", q: str = "",
                        risk: str = "", limit: int = Query(default=20, ge=1, le=200),
                        offset: int = Query(default=0, ge=0), view: str = "assets", group_id: str = "",
                        agent: str = "", x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if risk not in ("", "risk", "clear", "unknown"):
            raise HTTPException(status_code=400, detail="invalid asset risk state")
        if view not in ("assets", "groups") or view == "groups" and (scan_id or group_id):
            raise HTTPException(status_code=400, detail="invalid inventory view or scope")
        return repository.get_asset_inventory(scan_id, kind, q.strip(), risk, limit, offset,
                                              view=view, group_id=group_id, agent=agent)

    @router.get("/scans/{scan_id}")
    def get_scan(scan_id: str, request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        repository.expire_device_scans()
        record = repository.get_scan(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="scan not found")
        coverage = repository.get_coverage(scan_id)
        return {"scan": record.as_dict(), "coverage": coverage.as_dict() if coverage else None}

    @router.post("/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str, request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        cancelled = repository.request_cancel(scan_id)
        record = repository.get_scan(scan_id)
        if record.status == "CANCELLED":
            cleanup_snapshot(repository, record)
        return {"cancelled": cancelled}

    @router.post("/scans/{scan_id}/retry")
    def retry_scan(scan_id: str, request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if repository.active_scan_count() >= QUEUE_LIMIT:
            raise HTTPException(status_code=429, detail="static scan queue is full")
        record = repository.get_scan(scan_id)
        if record.status in ("INTERRUPTED", "FAILED", "CANCELLED"):
            cleanup_snapshot(repository, record)
        return {"requeued": repository.requeue_scan(scan_id)}

    @router.get("/scans/{scan_id}/assets")
    def list_assets(scan_id: str, request: Request, kind: str = "", q: str = "",
                    limit: int = 50, offset: int = 0, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return repository.get_assets(scan_id, kind, limit, offset, q)

    @router.get("/scans/{scan_id}/findings")
    def list_findings(scan_id: str, request: Request, severity: str = "", category: str = "",
                      asset_id: str = "", limit: int = 50, offset: int = 0,
                      x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return repository.get_findings(scan_id, severity, category, asset_id, limit, offset)

    @router.get("/scans/{scan_id}/findings/{finding_id}")
    def get_finding(scan_id: str, finding_id: str, request: Request,
                    x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        finding = repository.get_finding(scan_id, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        asset = repository.get_asset(scan_id, finding.asset_id) if finding.asset_id else None
        return {**finding.as_dict(), "asset": asset.as_dict() if asset else None,
                "evidence": repository.get_evidence(scan_id, finding.evidence_ids)}

    @router.get("/scans/{scan_id}/graph")
    def get_graph(scan_id: str, request: Request, center: str = "", depth: int = 2,
                  limit: int = 200, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return repository.get_graph(scan_id, center, depth, limit)

    @router.get("/scans/{scan_id}/report")
    def get_report(scan_id: str, request: Request, format: str = "json",
                   x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        try:
            data = build_report(repository, scan_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="scan not found")
        if format == "md":
            return Response(content=render_markdown(data), media_type="text/markdown; charset=utf-8")
        return Response(content=dump_json(data), media_type="application/json; charset=utf-8")

    @router.get("/scans/{scan_id}/diff")
    def diff(scan_id: str, request: Request, base_scan_id: str = "",
             x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if not base_scan_id:
            raise HTTPException(status_code=400, detail="base_scan_id required")
        if repository.get_scan(scan_id) is None or repository.get_scan(base_scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return repository.diff(scan_id, base_scan_id)

    @router.post("/scans/{scan_id}/findings/{finding_id}/reviews", status_code=201)
    def create_review(scan_id: str, finding_id: str, body: dict, request: Request,
                      x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_finding(scan_id, finding_id) is None:
            raise HTTPException(status_code=404, detail="finding not found")
        status = str(body.get("status") or "open")
        if status not in ("open", "confirmed", "false_positive", "accepted_risk", "fixed"):
            raise HTTPException(status_code=400, detail="invalid review status")
        review = Review(
            review_id=new_id("review"), scan_id=scan_id, finding_id=finding_id, status=status,
            reason=str(body.get("reason") or "")[:500],
            operator=str(body.get("operator") or "unknown"),
            expires_at=str(body.get("expires_at") or ""),
        )
        repository.add_review(review)
        return review.as_dict()

    @router.get("/scans/{scan_id}/reviews")
    def list_reviews(scan_id: str, request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        if repository.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return {"reviews": repository.list_reviews(scan_id)}

    @router.get("/scans/{scan_id}/export")
    def export_json(scan_id: str, request: Request, x_ag_admin: str | None = Header(default=None)):
        """自有 JSON 规范格式（后续可映射 CycloneDX）。"""
        check_admin(request, x_ag_admin)
        try:
            data = build_report(repository, scan_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="scan not found")
        return json.loads(dump_json(data))

    # ---- 运行时关联展示（不自动改变 ALLOW/ASK/DENY） ----

    @router.post("/bindings", status_code=201)
    def create_binding(body: dict, request: Request, x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        project_id = str(body.get("project_id") or "")
        asset_id = str(body.get("asset_id") or "")
        runtime_server = str(body.get("runtime_server") or "")
        if not (project_id and asset_id and runtime_server):
            raise HTTPException(status_code=400, detail="project_id/asset_id/runtime_server required")
        return repository.add_runtime_binding(
            project_id, asset_id, runtime_server, str(body.get("basis") or "reviewed"))

    @router.get("/bindings")
    def list_bindings(request: Request, project_id: str = "", asset_id: str = "",
                      x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        return {"bindings": repository.list_runtime_bindings(project_id, asset_id)}

    @router.get("/runtime-assets")
    def runtime_assets(request: Request, project_id: str, server: str,
                       x_ag_admin: str | None = Header(default=None)):
        check_admin(request, x_ag_admin)
        return {"matches": repository.assets_for_runtime_server(project_id, server),
                "note": "只有经过审核的绑定才关联；同名 server 不自动跨环境合并"}

    return router
