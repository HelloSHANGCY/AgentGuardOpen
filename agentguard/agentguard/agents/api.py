"""通用 Agent 数据面与设备管理接口（通用 Agent 接入设计 §9）。

- POST /v1/agents/{agent}/hook：Hook 客户端上报原始负载，同步返回决策与 Hook 输出；
- POST /v1/runtime/mcp/{inspect-request,inspect-result,manifests/{server}}：stdio 包装器的
  调用前决策、返回检查与清单上报（设备令牌鉴权，只能认领 / 写入本设备的会话与清单）；
- POST/GET/DELETE /v1/admin/devices：设备令牌签发、查询与吊销（管理令牌鉴权）；
- GET /v1/agents/rules?agent=：终端本地快速判定的签名规则包（设备令牌鉴权，按 Agent 与设备策略档案生成）；
- POST/GET/PUT/DELETE /v1/admin/devices：设备（安装了终端客户端的主机）签发、查询、修改与吊销；
- GET /v1/admin/hooks、PUT /v1/admin/hooks/{agent}：各 Agent 的全局默认管控（设备可单独覆盖）；
- GET /v1/agents/client[/{name}]：终端客户端下载（脚本包现场打包，预构建包取自 endpoint/dist，见 packages.py）；
- GET /v1/agents/deploy、/v1/agents/{install,uninstall}.{sh,ps1,cmd}：客户端部署配置与一键安装 / 卸载脚本，
  GET/PUT /v1/admin/deploy：修改部署配置（见 deploy.py）；POST /v1/agents/uninstall：终端一键卸载后上报，
  设备标记为已卸载、令牌停用；
- POST/GET /v1/agents/enroll：终端自助申请接入与查询认证状态（令牌由终端生成，见 enroll.py）；
  GET /v1/admin/enrollments、POST .../{id}/approve、DELETE .../{id}：待认证设备的查看、认证与拒绝；

行为基线与意图识别的管理接口见 detection/api.py，大模型研判与规则建议见 llm/api.py。

设备令牌覆盖该主机上允许的全部 Agent；终端经 X-AG-Host 头上报主机名 / 系统 / 用户（只用于展示）。
"""

import hmac
import json
from types import SimpleNamespace
from urllib.parse import urlencode

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import FileResponse, Response
from starlette.concurrency import run_in_threadpool

from ..admin import require_admin
from ..core import fastpath
from ..detection.engine import PROFILE_DEVELOPER, PROFILE_STRICT
from ..gateway.inspector import McpInspector
from ..gateway.mcp import blocked_payload
from .claude_code import ClaudeCodeAdapter
from .codebuddy import CodeBuddyAdapter
from .codex import CodexAdapter
from .control import FAIL_MODES, HookControl, effective
from .control import KEYS as CONTROL_KEYS
from .deploy import SCRIPTS, URL_RE, DeployConfig, server_url
from .deploy import render as render_script
from .devices import DeviceRegistry
from .enroll import EnrollmentError, EnrollmentQueue, suggested_device_id
from .packages import ClientPackages
from .qoder import QoderAdapter
from .trae import TraeAdapter
from .workbuddy import WorkBuddyAdapter
from .zcode import ZCodeAdapter

MAX_HOOK_BODY = 256 * 1024


def build_agent_api(settings, store, contexts, manifests, engine, inspector: McpInspector,
                    devices: DeviceRegistry, controls: HookControl | None = None,
                    enrollments: EnrollmentQueue | None = None, packages: ClientPackages | None = None,
                    deploy: DeployConfig | None = None) -> APIRouter:
    router = APIRouter()
    controls = controls or HookControl()
    enrollments = enrollments or EnrollmentQueue()
    packages = packages or ClientPackages(settings.client_endpoint_dir, settings.client_dist_dir)
    deploy = deploy or DeployConfig()
    # 兼容 Claude Code Hook 协议的 Agent 共用一套适配逻辑；设备令牌覆盖主机上允许的 Agent。
    adapters = {adapter.agent: adapter for adapter in (
        ClaudeCodeAdapter(settings, store, contexts, manifests, engine, inspector),
        CodexAdapter(settings, store, contexts, manifests, engine, inspector),
        TraeAdapter(settings, store, contexts, manifests, engine, inspector),
        QoderAdapter(settings, store, contexts, manifests, engine, inspector),
        ZCodeAdapter(settings, store, contexts, manifests, engine, inspector),
        WorkBuddyAdapter(settings, store, contexts, manifests, engine, inspector),
        CodeBuddyAdapter(settings, store, contexts, manifests, engine, inspector))}

    def trace_prefixes(device) -> list[str]:
        return [adapters[agent].trace_id(device.device_id, "") for agent in device.agents]

    def agent_of_trace(device, trace_id: str) -> str:
        return next((agent for agent, prefix in zip(device.agents, trace_prefixes(device))
                     if trace_id.startswith(prefix)), device.agent)

    def requested_agent(device, agent: str) -> str:
        if not agent:
            return device.agent
        if not device.allows(agent):
            raise HTTPException(403, "agent not allowed for this device")
        return agent

    def authorize_admin(token: str | None) -> None:
        require_admin(settings, token, "device admin")

    def client_ip(request: Request) -> str:
        # 服务端看到的来源地址（直连时即终端地址；经反向代理 / NAT 时为其出口地址，不信任转发头）。
        return request.client.host if request.client else ""

    def device_token(authorization: str | None) -> str:
        if authorization and authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return ""

    packs: dict = {}

    def rule_pack(device, agent: str) -> dict:
        # 规则包取决于 Agent、策略档案与规则库生效集合（规则版本随启停变化），按三者缓存。
        key = (agent, device.profile, settings.rules_version)
        if key not in packs:
            if len(packs) > 64:
                packs.clear()
            packs[key] = fastpath.build_pack(settings.rules_version, device.profile, agent,
                                             tuple(settings.c2_hosts))
        return packs[key]

    def result_guard_for(trace_id: str) -> bool:
        """HTTP 网关路径：按 trace 前缀找到设备与 Agent（取最长前缀，device_id 可含连字符），读其管控配置。"""
        best = None
        for device in devices.devices():
            if device.uninstalled_at:
                continue
            for agent, prefix in zip(device.agents, trace_prefixes(device)):
                if trace_id.startswith(prefix) and (best is None or len(prefix) > len(best[2])):
                    best = (device, agent, prefix)
        if best is None:
            return False
        control = control_for(best[0], best[1])
        return bool(control["enabled"] and control["result_guard"])

    inspector.result_guard_for = result_guard_for

    def control_for(device, agent: str = "") -> dict:
        agent = agent or device.agent
        defaults = controls.get(agent)
        control = effective({key: defaults[key] for key in CONTROL_KEYS}, device)
        # 大模型危险审批开启时放宽 PreToolUse 超时，复核结论须在终端超时（按 fail-open 放行）之前返回；
        # 观察模式不复核。
        if control["enforce"]:
            control = engine.judge.hook_control(control)
        # 附带当前规则包版本：终端发现与本地缓存不一致时再拉取。
        return {**control, "rules": rule_pack(device, agent)["version"]}

    @router.post("/v1/agents/{agent}/hook")
    async def agent_hook(agent: str, request: Request, authorization: str | None = Header(default=None),
                         user_agent: str | None = Header(default=None), x_ag_host: str | None = Header(default=None)):
        adapter = adapters.get(agent)
        if adapter is None:
            raise HTTPException(404, "unknown agent")
        device = devices.authenticate(device_token(authorization))
        if device is None or not device.allows(agent):
            raise HTTPException(401, "invalid device token")
        devices.touch(device.device_id, user_agent or "", agent, x_ag_host or "", client_ip(request))
        # 每次响应附带管控配置，客户端缓存后用于服务不可达时的处理；已停止则不检测、不记录。
        control = control_for(device, agent)
        if not control["enabled"]:
            return {"output": None, "disabled": True, "control": control,
                    "static_scan": bool(settings.static_enabled)}
        body = await request.body()
        if len(body) > MAX_HOOK_BODY:
            raise HTTPException(413, "hook payload too large")
        try:
            raw = json.loads(body)
        except ValueError:
            raise HTTPException(400, "invalid json")
        if not isinstance(raw, dict):
            raise HTTPException(400, "invalid hook payload")
        try:
            result = await run_in_threadpool(adapter.handle, raw, device, control["enforce"])
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {**result, "control": control, "static_scan": bool(settings.static_enabled)}

    def authenticate(authorization: str | None):
        device = devices.authenticate(device_token(authorization))
        if device is None:
            raise HTTPException(401, "invalid device token")
        return device

    @router.get("/v1/agents/whoami")
    def whoami(request: Request, agent: str = "", authorization: str | None = Header(default=None),
               user_agent: str | None = Header(default=None), x_ag_host: str | None = Header(default=None)):
        # 令牌校验：安装器 / 自检用来确认令牌有效，同时登记主机信息（不计入 Agent 的最近上报）。
        device = authenticate(authorization)
        agent = requested_agent(device, agent)
        devices.touch(device.device_id, user_agent or "", "", x_ag_host or "", client_ip(request))
        return {"device": device.public(), "control": control_for(device, agent)}

    @router.get("/v1/agents/rules")
    def agent_rules(agent: str = "", authorization: str | None = Header(default=None)):
        token = device_token(authorization)
        device = authenticate(authorization)
        return fastpath.sign(rule_pack(device, requested_agent(device, agent)), fastpath.signing_key(token))

    # ---------- 设备自助接入 ----------

    def enrollment_view(entry: dict) -> dict:
        return {key: entry[key] for key in ("enrollment_id", "code", "status", "agents", "created_at")}

    @router.get("/v1/agents/client")
    def client_packages():
        return {"packages": packages.list()}

    @router.get("/v1/agents/client/{name}")
    def client_package(name: str):
        found = packages.get(name)
        if found is None:
            raise HTTPException(404, "no such client package")
        content, media = found
        headers = {"Content-Disposition": f'attachment; filename="{name}"'}
        if isinstance(content, str):
            return FileResponse(content, media_type=media, headers=headers)
        return Response(content, media_type=media, headers=headers)

    def deploy_url(request: Request) -> str:
        url = server_url(deploy.get(), str(request.base_url))
        if not URL_RE.match(url):
            raise HTTPException(400, "cannot derive the server URL; set it in Devices > Client deployment")
        return url

    def public_deploy(request: Request) -> dict:
        config = deploy.get()
        return {"server_url": deploy_url(request), "agents": config["agents"], "scope": config["scope"],
                "wait": config["wait"], "self_test": config["self_test"],
                "enroll": {"enabled": settings.agent_enroll, "key_required": bool(settings.agent_enroll_key)}}

    @router.get("/v1/agents/deploy")
    def get_public_deploy(request: Request):
        return public_deploy(request)

    def install_script(script: str):
        def handler(request: Request):
            published = {item["name"] for item in packages.list()}
            text = render_script(script, deploy_url(request), deploy.get(), published)
            headers = {"Content-Disposition": f'attachment; filename="agentguard-{script}"'} \
                if script.endswith(".cmd") else {}
            return Response(text, media_type="text/plain; charset=utf-8", headers=headers)
        return handler

    for script in SCRIPTS:
        router.add_api_route(f"/v1/agents/{script}", install_script(script), methods=["GET"])

    @router.post("/v1/agents/uninstall")
    def report_uninstall(authorization: str | None = Header(default=None)):
        device = devices.mark_uninstalled(device_token(authorization))
        if device is None:
            raise HTTPException(401, "invalid device token")
        return {"device_id": device.device_id, "uninstalled_at": device.uninstalled_at}

    @router.get("/v1/admin/deploy")
    def get_deploy(request: Request, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return {**deploy.get(), "effective_url": server_url(deploy.get(), str(request.base_url))}

    @router.put("/v1/admin/deploy")
    def update_deploy(body: dict, request: Request, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            config = deploy.update(body if isinstance(body, dict) else {})
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {**config, "effective_url": server_url(config, str(request.base_url))}

    @router.post("/v1/agents/enroll")
    def enroll(request: Request, body: dict, authorization: str | None = Header(default=None),
               user_agent: str | None = Header(default=None), x_ag_host: str | None = Header(default=None),
               x_ag_enroll_key: str | None = Header(default=None)):
        token = device_token(authorization)
        device = devices.authenticate(token)
        if device is not None:
            # 已认证：令牌已是设备令牌，告知终端直接使用。
            return {"status": "approved", "device": device.public()}
        if not settings.agent_enroll:
            raise HTTPException(403, "self enrollment disabled; ask the admin for a device token")
        expected = settings.agent_enroll_key
        if expected and not hmac.compare_digest((x_ag_enroll_key or "").encode(), expected.encode()):
            raise HTTPException(401, "invalid enrollment key")
        agents = (body or {}).get("agents") if isinstance(body, dict) else None
        try:
            entry = enrollments.request(token, agents, x_ag_host or "", client_ip(request), user_agent or "")
        except EnrollmentError as exc:
            raise HTTPException(exc.status, str(exc))
        return enrollment_view(entry)

    @router.get("/v1/agents/enroll")
    def enroll_status(authorization: str | None = Header(default=None)):
        token = device_token(authorization)
        device = devices.authenticate(token)
        if device is not None:
            return {"status": "approved", "device": device.public()}
        entry = enrollments.status(token)
        if entry is None:
            raise HTTPException(404, "no enrollment for this token")
        return enrollment_view(entry)

    def enrollment_rows() -> list[dict]:
        taken = devices.device_ids()
        return [{**entry, "suggested_device_id": suggested_device_id(entry["host"], taken)}
                for entry in enrollments.list()]

    @router.get("/v1/admin/enrollments")
    def list_enrollments(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return {"enrollments": enrollment_rows()}

    @router.post("/v1/admin/enrollments/{enrollment_id}/approve")
    def approve_enrollment(enrollment_id: str, body: dict, x_ag_admin_token: str | None = Header(default=None)):
        # 认证：以申请的令牌哈希创建设备；设备 ID、策略档案、允许的 Agent、使用人由管理员确定。
        authorize_admin(x_ag_admin_token)
        body = body if isinstance(body, dict) else {}
        try:
            token_hash, entry = enrollments.take(enrollment_id)
        except KeyError:
            raise HTTPException(404, "enrollment not found")
        spec = {"device_id": body.get("device_id") or suggested_device_id(entry["host"], devices.device_ids()),
                "profile": body.get("profile"), "agents": body.get("agents") or entry["agents"],
                "actor": body.get("actor") if isinstance(body.get("actor"), dict)
                else {"sub": entry["host"].get("user") or ""}}
        try:
            device = devices.adopt(spec, token_hash)
        except ValueError as exc:
            enrollments.restore(token_hash, entry)
            raise HTTPException(400, str(exc))
        # 主机信息随申请一并转入设备的最近上报，认证后控制台立即可见。
        devices.touch(device.device_id, entry.get("client", ""), "", urlencode(entry["host"]), entry.get("remote_ip", ""))
        return next(row for row in device_rows() if row["device_id"] == device.device_id)

    @router.delete("/v1/admin/enrollments/{enrollment_id}")
    def reject_enrollment(enrollment_id: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            entry = enrollments.reject(enrollment_id)
        except KeyError:
            raise HTTPException(404, "enrollment not found")
        return {"rejected": entry["enrollment_id"]}

    def mcp_fields(body: dict) -> tuple[str, str, dict]:
        server, tool = str(body.get("server") or ""), str(body.get("tool") or "")
        arguments = body.get("arguments") if isinstance(body.get("arguments"), dict) else None
        if not server or not tool or arguments is None:
            raise HTTPException(400, "server, tool and arguments required")
        return server, tool, arguments

    @router.post("/v1/runtime/mcp/inspect-request")
    def mcp_inspect_request(body: dict, authorization: str | None = Header(default=None),
                            user_agent: str | None = Header(default=None)):
        device = authenticate(authorization)
        server, tool, arguments = mcp_fields(body)
        devices.touch(device.device_id, user_agent or "")
        # 包装器不区分 Agent：依次按设备允许的各 Agent 的 trace 前缀认领 Hook 会话。
        claimed = inspector.claim(server, tool, arguments, trace_prefix=tuple(trace_prefixes(device)))
        # 认领不到 Hook 会话：归入设备主 Agent 的未关联 trace，按无任务上下文 fail-closed。
        trace_id = claimed["trace_id"] if claimed else trace_prefixes(device)[0] + "unlinked"
        call_id = claimed["call_id"] if claimed else ""
        agent = agent_of_trace(device, trace_id)
        control = control_for(device, agent)
        if not control["enabled"]:
            return {"decision": "ALLOW", "disabled": True, "control": control}
        decision = inspector.inspect_request(
            trace_id, server, tool, arguments, inspector.manifest_for(server, device.device_id),
            instance_id=device.device_id, call_id=call_id,
            confirmed_ask=bool(claimed and claimed.get("confirmed_ask")),
            device_id=device.device_id, agent=agent, enforce=control["enforce"])
        result = {"decision": decision.decision, "decision_id": decision.decision_id,
                  "reason_code": decision.reason_code, "trace_id": trace_id, "call_id": call_id,
                  "control": control}
        if not control["enforce"] and decision.decision != "ALLOW":
            # 观察模式：决策已记为告警（MONITOR_ONLY），中转照常转发。
            result.update(decision="ALLOW", observed=decision.decision)
        if result["decision"] != "ALLOW":
            result["error"] = blocked_payload(body.get("request_id"), decision)["error"]
        return result

    @router.post("/v1/runtime/mcp/inspect-result")
    def mcp_inspect_result(body: dict, authorization: str | None = Header(default=None)):
        device = authenticate(authorization)
        server, tool, arguments = mcp_fields(body)
        trace_id = str(body.get("trace_id") or "")
        if not any(trace_id.startswith(prefix) for prefix in trace_prefixes(device)):
            raise HTTPException(403, "trace does not belong to device")
        control = control_for(device, agent_of_trace(device, trace_id))
        if not control["enabled"]:
            return {"labels": [], "disabled": True}
        result = body.get("result")
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        check = inspector.inspect_result(trace_id, server, tool, arguments, text[:MAX_HOOK_BODY],
                                         decision_id=str(body.get("decision_id") or ""),
                                         call_id=str(body.get("call_id") or ""),
                                         block_poisoned=control["result_guard"],
                                         execution=str(body.get("execution") or ""))
        if check.replacement is not None:
            # 返回内容拦截：中转用 replace 替换交给 Agent 的返回，原文已入证据库。
            return {"labels": check.labels, "replace": check.replacement, "event_id": check.event_id,
                    "evidence_id": check.evidence_id}
        return {"labels": check.labels}

    @router.post("/v1/runtime/mcp/manifests/{server}")
    def mcp_manifest(server: str, body: dict, authorization: str | None = Header(default=None)):
        device = authenticate(authorization)
        tools = body.get("tools")
        if not isinstance(tools, list):
            raise HTTPException(400, "tools list required")
        manifest = manifests.register(f"{device.device_id}:{server}", tools)
        return {"server": server, "tools": sorted(manifest.tools), "poisoned_tools": sorted(manifest.poisoned_tools)}

    @router.post("/v1/admin/devices")
    def register_device(body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        try:
            device, token = devices.register(body or {})
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        # 明文令牌只在签发时返回一次。
        return {"device": device.public(), "token": token}

    def device_rows() -> list[dict]:
        """设备列表，附各 Agent 实际生效的管控配置（全局默认叠加设备覆盖）。"""
        defaults = controls.all()
        rows = devices.list()
        for row in rows:
            view = SimpleNamespace(overrides=row["overrides"], purpose=row["purpose"])
            row["effective"] = {agent: effective({key: defaults[agent][key] for key in CONTROL_KEYS}, view)
                                for agent in row["agents"]}
        return rows

    @router.get("/v1/admin/devices")
    def list_devices(x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        return {"devices": device_rows()}

    @router.put("/v1/admin/devices/{device_id}")
    def update_device(device_id: str, body: dict, x_ag_admin_token: str | None = Header(default=None)):
        # 修改策略档案、允许的 Agent 与设备覆盖；overrides 中的 null 表示恢复跟随全局默认。
        # 策略档案对之后新建的会话生效，进行中的会话保留建立时的档案。
        authorize_admin(x_ag_admin_token)
        try:
            device = devices.update(device_id, body if isinstance(body, dict) else {})
        except KeyError:
            raise HTTPException(404, "device not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return next(row for row in device_rows() if row["device_id"] == device.device_id)

    @router.delete("/v1/admin/devices/{device_id}")
    def revoke_device(device_id: str, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        if not devices.revoke(device_id):
            raise HTTPException(404, "device not found")
        return {"revoked": device_id}

    @router.get("/v1/admin/hooks")
    def hook_overview(request: Request, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        listed = device_rows()
        agents = []
        for agent, control in controls.all().items():
            owned = [device for device in listed if agent in device["agents"]]
            agents.append({"agent": agent, **control, "devices": len(owned),
                           "last_seen": max((device["seen_agents"].get(agent, "") for device in owned), default="")})
        return {"agents": agents, "devices": listed, "fail_modes": list(FAIL_MODES),
                "profiles": [PROFILE_DEVELOPER, PROFILE_STRICT], "enrollments": enrollment_rows(),
                "enroll": {"enabled": settings.agent_enroll, "key_required": bool(settings.agent_enroll_key)},
                "clients": packages.list(),
                "deploy": {**deploy.get(), "effective_url": server_url(deploy.get(), str(request.base_url))}}

    @router.put("/v1/admin/hooks/{agent}")
    def update_hook(agent: str, body: dict, x_ag_admin_token: str | None = Header(default=None)):
        authorize_admin(x_ag_admin_token)
        if agent not in adapters:
            raise HTTPException(404, "unknown agent")
        try:
            return {"agent": agent, **controls.update(agent, {k: body[k] for k in CONTROL_KEYS if k in body})}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    return router
