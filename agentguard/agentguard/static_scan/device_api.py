"""设备端采集接口：使用设备令牌，只能领取与回传本设备所允许 Agent 的任务。"""

import asyncio
import json
import re

from fastapi import APIRouter, Header, HTTPException, Query, Request

from ..core.asset_snapshot import (
    AGENT_DIRS,
    MAX_BODY_BYTES,
    MAX_CONFIGURABLE_FILE_BYTES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    PROTOCOL,
    allowed_path,
    sanitize_text,
    snapshot_file_limit,
)
from .snapshots import cleanup_snapshot, stage_snapshot


def build_device_scan_api(repository, devices) -> APIRouter:
    router = APIRouter(prefix="/v1/agents")

    def authenticate(agent, authorization):
        token = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else ""
        device = devices.authenticate(token)
        if device is None:
            raise HTTPException(401, "invalid device token")
        if (agent and not device.allows(agent)) or device.purpose == "evaluation":
            raise HTTPException(403, "agent not allowed for this device")
        return device

    def job_payload(record):
        return {"job": {"scan_id": record.scan_id, "lease": record.worker_id, "protocol": PROTOCOL,
                        "agent": record.agent, "scope": record.collection.get("scope", "user"),
                        "limits": {"max_file_parse_bytes": snapshot_file_limit(record.limits)}} if record else None}

    @router.get("/static-scan/poll")
    async def poll(request: Request, agents: str, wait: float = Query(default=25, ge=0, le=25),
                   max_file_bytes: int = Query(default=MAX_FILE_BYTES, ge=MAX_FILE_BYTES, le=MAX_CONFIGURABLE_FILE_BYTES),
                   authorization: str | None = Header(default=None)):
        selected = tuple(dict.fromkeys(agents.split(",")))
        if not selected or len(selected) > len(AGENT_DIRS) or any(agent not in AGENT_DIRS for agent in selected):
            raise HTTPException(400, "invalid installed agents")
        device = authenticate("", authorization)
        allowed = tuple(agent for agent in selected if device.allows(agent))
        if not allowed:
            raise HTTPException(403, "no installed agent allowed for this device")
        devices.touch(device.device_id, request.headers.get("user-agent", ""),
                      host=request.headers.get("x-ag-host", ""), remote_ip=request.client.host if request.client else "",
                      scan_agents=list(allowed))
        deadline = asyncio.get_running_loop().time() + wait
        try:
            with repository.device_notifications.subscribe(device.device_id) as event:
                while True:
                    if await request.is_disconnected():
                        return job_payload(None)
                    device = authenticate("", authorization)  # 等待期间吊销的令牌不能领取任务。
                    allowed = tuple(agent for agent in selected if device.allows(agent))
                    if not allowed:
                        raise HTTPException(403, "no installed agent allowed for this device")
                    event.clear()
                    record = await asyncio.to_thread(repository.claim_device_scans, device.device_id, allowed, max_file_bytes)
                    if record is not None:
                        return job_payload(record)
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0 or await request.is_disconnected():
                        return job_payload(None)
                    try:
                        # 多进程/其他实例写入同一数据库时，短周期复核兜底，不依赖进程内通知。
                        await asyncio.wait_for(event.wait(), timeout=min(2, remaining))
                    except asyncio.TimeoutError:
                        pass
        except OverflowError:
            raise HTTPException(429, "too many device scan connections", headers={"Retry-After": "5"})

    @router.get("/{agent}/static-scan")
    def claim(agent: str, request: Request,
              max_file_bytes: int = Query(default=MAX_FILE_BYTES, ge=MAX_FILE_BYTES, le=MAX_CONFIGURABLE_FILE_BYTES),
              authorization: str | None = Header(default=None)):
        device = authenticate(agent, authorization)
        devices.touch(device.device_id, request.headers.get("user-agent", ""),
                      host=request.headers.get("x-ag-host", ""),
                      remote_ip=request.client.host if request.client else "")
        record = repository.claim_device_scan(device.device_id, agent, max_file_bytes)
        return job_payload(record)

    @router.post("/{agent}/static-scan/{scan_id}")
    async def upload(agent: str, scan_id: str, request: Request, authorization: str | None = Header(default=None)):
        device = authenticate(agent, authorization)
        record = repository.get_scan(scan_id)
        if record is None or record.device_id != device.device_id or record.agent != agent:
            raise HTTPException(404, "scan not found")
        if record.status != "RUNNING" or record.phase != "COLLECTING" or record.cancel_requested:
            raise HTTPException(409, "scan no longer collecting")
        file_limit = snapshot_file_limit(record.limits)
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > MAX_BODY_BYTES:
                raise HTTPException(413, "snapshot payload too large")
            raw.extend(chunk)
        try:
            body = json.loads(raw)
        except (ValueError, RecursionError):
            raise HTTPException(400, "invalid snapshot JSON")
        if not isinstance(body, dict) or body.get("protocol") != PROTOCOL:
            raise HTTPException(400, "unsupported snapshot protocol")
        lease = body.get("lease")
        if not isinstance(lease, str) or lease != record.worker_id:
            raise HTTPException(409, "invalid or expired collection lease")
        files = body.get("files")
        if not isinstance(files, list) or len(files) > MAX_FILES:
            raise HTTPException(400, "snapshot file count limit exceeded")
        clean, seen, total = [], set(), 0
        for item in files:
            if not isinstance(item, dict) or not allowed_path(agent, item.get("path")):
                raise HTTPException(400, "invalid snapshot file path")
            path, content = item["path"], item.get("content")
            if record.collection.get("scope") == "user" and path.startswith("project/"):
                raise HTTPException(400, "project files outside requested scope")
            if path in seen or not isinstance(content, str) or "\x00" in content:
                raise HTTPException(400, "duplicate path or invalid text")
            try:
                size = len(content.encode("utf-8"))
            except UnicodeError:
                raise HTTPException(400, "invalid snapshot text encoding")
            if size > file_limit:
                raise HTTPException(413, "snapshot file size limit exceeded")
            try:
                content = sanitize_text(path, content)
            except (ValueError, RecursionError):
                raise HTTPException(400, "invalid snapshot configuration")
            size = len(content.encode("utf-8"))
            if size > file_limit:
                raise HTTPException(413, "sanitized snapshot file size limit exceeded")
            total += size
            if total > MAX_TOTAL_BYTES:
                raise HTTPException(413, "snapshot total size limit exceeded")
            seen.add(path)
            clean.append({"path": path, "content": content})
        skipped = body.get("skipped", [])
        if not isinstance(skipped, list):
            raise HTTPException(400, "invalid collection coverage")
        # 不回显或落库任意终端异常文本，覆盖缺口只接受固定原因与授权相对路径。
        reasons = {"symlink", "special_file", "file_too_large", "total_bytes", "max_files", "max_depth",
                   "read_failed", "invalid_config", "binary", "workspace_unavailable", "collection_timeout"}
        gaps = []
        for item in skipped[:40]:
            if isinstance(item, dict) and item.get("reason") in reasons:
                path = item.get("path", "")
                if path == "" or allowed_path(agent, path):
                    gaps.append({"path": path[:240], "reason": item["reason"]})
        collection = {"scope": record.collection.get("scope", "user"), "protocol": PROTOCOL,
                      "files": len(clean), "bytes": total, "skipped": gaps,
                      "skipped_total": min(len(skipped), 10000),
                      "client": request.headers.get("user-agent", "")[:64]}
        workspace_id = body.get("workspace_id", "")
        if isinstance(workspace_id, str) and re.fullmatch(r"[a-f0-9]{20}", workspace_id):
            collection["workspace_id"] = workspace_id
        error = "未发现可扫描的 Agent 资产，请确认当前用户、Agent 配置与扫描范围" if not clean else ""
        root = stage_snapshot(repository, scan_id, clean) if clean else ""
        if not repository.receive_device_snapshot(scan_id, lease, root, collection, error):
            record.source_path = root
            cleanup_snapshot(repository, record)
            raise HTTPException(409, "scan cancelled or collection lease expired")
        return {"accepted": True, "files": len(clean), "status": "FAILED" if error else "QUEUED"}

    return router
