"""Hook 入口：Claude Code / Codex / Trae / Qoder / ZCode / WorkBuddy / CodeBuddy 每个 Hook 事件启动一次本进程（协议兼容，见通用 Agent 接入设计 §6.2）。

处理顺序（PreToolUse）：
1. 本地快速判定：控制台未停用且开启了“本地快速判定”时，按缓存的签名规则包检查；命中即拒绝，
   并把事件带上本地判定（_ag.local）实时上报，上报失败写入缓冲，恢复后补报；
2. 未命中：原始负载送服务端，按服务端给出的 Hook 输出执行；
3. 服务端不可达：按缓存的管控配置处理——已停止则放行；open（默认）放行；failsafe 按规则包中的
   降级表拒绝高风险操作。除已停止外，事件写入本地缓冲。
其他事件只转发；在非关键路径事件（非 PreToolUse / UserPromptSubmit）上补报缓冲、按需更新规则包。

始终 exit 0，通过 JSON 输出表达决策。stdin / stdout 按 UTF-8 字节处理：Windows 控制台的
默认编码（如 cp936）与 Agent 传入的 UTF-8 JSON 不一致。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

from . import CLIENT, static_scan
from . import config as cfg
from . import transport as net
from .core import fastpath

MAX_RESPONSE_CHARS = 16384
# 本地已拒绝时上报的超时：决策已作出，上报只为实时审计，不能明显拖慢 Agent。
LOCAL_REPORT_TIMEOUT = 0.5
NON_CRITICAL = ("PreToolUse", "UserPromptSubmit")


def shrink(payload: dict, upload_mode: str) -> dict:
    """工具返回按上限截断，附全文摘要与长度，供服务端核对。"""
    if "tool_response" not in payload:
        return payload
    response = payload["tool_response"]
    text = response if isinstance(response, str) else json.dumps(response, ensure_ascii=False, default=str)
    meta = payload.setdefault("_ag", {})
    meta["response_length"] = len(text)
    meta["response_digest"] = "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]
    if upload_mode == "digest":
        payload["tool_response"] = ""
        meta["response_truncated"] = True
    elif len(text) > MAX_RESPONSE_CHARS:
        payload["tool_response"] = text[:MAX_RESPONSE_CHARS]
        meta["response_truncated"] = True
    return payload


def read_payload(stream) -> dict | None:
    raw = stream.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(raw.lstrip("﻿"))
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def project_roots() -> tuple:
    """Claude Code 传给 Hook 进程的项目根目录（ZCode 同样设置 CLAUDE_PROJECT_DIR，WorkBuddy 为
    CODEBUDDY_PROJECT_DIR）：与服务端的会话起始目录一致，Agent cd 进子目录后写项目根不算越界。"""
    return (os.environ.get("CLAUDE_PROJECT_DIR", ""), os.environ.get("CODEBUDDY_PROJECT_DIR", ""))


def local_check(config: dict, control: dict, payload: dict) -> tuple[dict | None, dict | None]:
    """返回 (规则包, 主命中)；控制台停用 Hook 或关闭本地快速判定时不检查。"""
    pack = net.load_pack(config)
    if pack is None or control.get("enabled") is False or control.get("local_rules") is False:
        return pack, None
    try:
        hits = fastpath.evaluate(pack, config["agent"], payload, project_roots())
    except Exception:  # noqa: BLE001 — 本地判定出错不能影响 Agent，交给服务端
        return pack, None
    return pack, (hits[0] if hits else None)


def handle(payload: dict, agent: str) -> dict | None:
    """处理一个 Hook 事件，返回要写到 stdout 的 Hook 输出（None 表示不输出）。"""
    config = cfg.load(agent)
    control = net.read_control(config)
    cfg.apply_control(config, control)
    event = str(payload.get("hook_event_name") or "")
    timeout = float(config.get("timeout_pre") or 1.5) if event == "PreToolUse" else float(config.get("timeout") or 1.0)
    payload = shrink(payload, str(config.get("upload_mode")))
    payload.setdefault("_ag", {})["client"] = CLIENT
    if event == "SessionEnd":
        payload["_ag"]["spooled"] = net.spooled_count(config, str(payload.get("session_id") or ""))

    pack, hit = local_check(config, control, payload) if event == "PreToolUse" else (None, None)
    if hit is not None:
        payload["_ag"]["local"] = {key: hit[key] for key in ("rule", "reason_code", "severity", "check")}
        payload["_ag"]["local"]["pack"] = pack.get("version", "")
        try:
            net.save_control(config, net.post_hook(config, payload, min(timeout, LOCAL_REPORT_TIMEOUT)).get("control"))
        except net.NETWORK_ERRORS:
            net.spool(config, payload, "deny")
        return fastpath.deny_output(hit["reason_code"], f"endpoint {hit['rule']}")

    try:
        result = net.post_hook(config, payload, timeout)
    except net.NETWORK_ERRORS:
        if control.get("enabled") is False:
            return None
        failsafe = control.get("fail_mode") == "failsafe"
        if event == "PreToolUse" and pack is None:
            pack = net.load_pack(config)
        deny = event == "PreToolUse" and failsafe and fastpath.failsafe_denies(pack, agent, payload, project_roots())
        table = (pack or {}).get("failsafe", fastpath.DEFAULT_FAILSAFE).get("version", "")
        net.spool(config, payload, "deny" if deny else "pass", table)
        return fastpath.deny_output("AGENTGUARD_UNAVAILABLE", table) if deny else None

    control = result.get("control") if isinstance(result.get("control"), dict) else control
    net.save_control(config, control)
    if event not in NON_CRITICAL:
        # 补报与规则包更新放在非关键路径事件上，不增加 PreToolUse 延迟。
        net.flush_spool(config, timeout)
        if result.get("static_scan"):
            static_scan.maybe_launch(agent, payload)
        if net.pack_outdated(config, control, net.load_pack(config)):
            try:
                net.sync_pack(config, timeout=max(timeout, 2.0))
            except net.NETWORK_ERRORS:
                pass
    if result.get("disabled"):
        return None
    output = result.get("output")
    return output if isinstance(output, dict) and output else None


def route(agent: str, payload: dict) -> str | None:
    """Trae 开启「导入 Claude Code 中的 Hooks」后，也会执行 ~/.claude/settings.json 里的 AgentGuard Hook（--agent
    claude-code）。这类事件（带 Trae 独有的 workspace_roots 与 TRAE_PROJECT_DIR）按 Trae 处理；Trae 自己的
    AgentGuard Hook 已安装时交给它，同一事件不处理两次。"""
    if agent != "claude-code" or "workspace_roots" not in payload or "TRAE_PROJECT_DIR" not in os.environ:
        return agent
    for name in cfg.TRAE_DIRS:
        try:
            with open(os.path.join(os.path.expanduser("~"), name, "hooks.json"), encoding="utf-8") as handle:
                if "--agent trae" in handle.read():
                    return None
        except OSError:
            continue
    return "trae"


def main(agent: str) -> int:
    payload = read_payload(getattr(sys.stdin, "buffer", sys.stdin))
    if payload is None:
        return 0
    try:
        agent = route(agent, payload)
        if agent is None:
            return 0
        output = handle(payload, agent)
    except Exception:  # noqa: BLE001 — 任何意外都不能让 Hook 以非零码退出、阻断 Agent
        return 0
    if output:
        if agent == "codebuddy":
            decision = (output.get("hookSpecificOutput") or {}).get("permissionDecision")
            if decision in ("deny", "ask"):
                # 本地快速拒绝、离线 failsafe 与服务端输出遵循同一 CodeBuddy 协议。
                output["continue"] = decision != "deny"
        # 纯 ASCII 输出：与控制台编码无关。
        data = json.dumps(output).encode("ascii")
        out = getattr(sys.stdout, "buffer", None)
        if out is not None:
            out.write(data)
            out.flush()
        else:
            sys.stdout.write(data.decode("ascii"))
    return 0
