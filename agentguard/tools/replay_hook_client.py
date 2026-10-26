#!/usr/bin/env python3
"""评测与夹具回放用的 Hook 客户端：Claude Code 与 Codex 共用（通用 Agent 接入设计 §6.2 / §7.4）。

评测 worker（agentguard/evaluation.py，AG_EVAL_CC_HOOK）与 Claude Code 夹具回放经它把 Hook 负载送到服务端，
只做转发、不做本地判定，评测结果只反映服务端检测。终端部署请使用 endpoint/（agentguard-endpoint），
它在此基础上增加了本地快速判定、自助接入与 MCP 包装器；两者本地文件名一致，可以互认。

两者的 Hook 协议兼容。Agent 由 `--agent claude-code|codex`（或 AGENTGUARD_AGENT）指定，
默认 claude-code；不同 Agent 使用各自的设备令牌、配置文件与本地缓冲，互不混用。
Agent 每个 Hook 事件启动一次本进程：从 stdin 读原始 Hook JSON，附设备令牌
原样转发给 AgentGuard，再把服务端给出的 Hook 输出写到 stdout。

设计约束：
- 只依赖标准库，控制冷启动；不含任何放行规则，决策全部在服务端；
- 内部超时明显短于 Claude Code 为 Hook 配置的 timeout，不可达时的处理由本进程自己给出；
- 启停与服务不可达时的处理由控制台「设备管理」统一配置：服务端每次响应附带管控配置，
  本进程缓存到本地；服务不可达时按缓存执行——已停止则直接放行；open（默认）不拦截；
  failsafe 按能力降级表处理 PreToolUse（执行 / 出网 / MCP / 工作区外写入拒绝，其余放行）。
  除已停止外，事件写入本地有界缓冲，恢复后补报（服务端标记 AUDIT_DELAYED）；
- 始终 exit 0，通过 JSON 输出表达决策，避免退出码语义随版本变化。

配置（环境变量优先，其次 /etc/agentguard/<前缀>-hook.json、~/.agentguard/<前缀>-hook.json；
前缀 Claude Code 为 cc，Codex 为 codex；令牌文件分别为 device-token、codex-device-token）：
  AGENTGUARD_URL          服务端地址，默认 http://127.0.0.1:18080
  AGENTGUARD_TOKEN        设备令牌；或 AGENTGUARD_TOKEN_FILE 指向令牌文件
  AGENTGUARD_CONTROL_FILE 管控配置缓存，默认 ~/.agentguard/cc-control.json（Codex 为 codex-control.json）
  AGENTGUARD_TIMEOUT_PRE  PreToolUse 超时秒数，默认 1.5；其他事件 AGENTGUARD_TIMEOUT，默认 1.0
  AGENTGUARD_SPOOL        本地缓冲文件，默认 ~/.agentguard/spool.jsonl（Codex 为 codex-spool.jsonl）
  AGENTGUARD_UPLOAD_MODE  full（默认，服务端脱敏）/ digest（工具返回只传摘要）
"""

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

CLIENT_VERSION = "cc-hook/0.3"
MAX_RESPONSE_CHARS = 16384
MAX_SPOOL_BYTES = 2 * 1024 * 1024
FLUSH_BATCH = 20
# Agent → 本地文件前缀（配置 / 令牌 / 缓冲）。
AGENT_FILES = {
    "claude-code": {"config": "cc-hook.json", "token": "device-token", "spool": "spool.jsonl",
                    "control": "cc-control.json"},
    "codex": {"config": "codex-hook.json", "token": "codex-device-token", "spool": "codex-spool.jsonl",
              "control": "codex-control.json"},
}

# 服务不可达且管控配置为 failsafe 时的能力降级表：这是客户端唯一的“策略”，版本随事件上报。
FAILSAFE_VERSION = "failsafe/2"
FAIL_CLOSED_TOOLS = {"Bash", "WebFetch"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"}
PATCH_PREFIXES = ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ")


def agent_name(argv: list) -> str:
    agent = os.environ.get("AGENTGUARD_AGENT") or "claude-code"
    if "--agent" in argv[:-1]:
        agent = argv[argv.index("--agent") + 1]
    return agent if agent in AGENT_FILES else "claude-code"


def load_config(agent: str = "claude-code") -> dict:
    files = AGENT_FILES[agent]
    config: dict = {"agent": agent}
    config_files = ("/etc/agentguard/" + files["config"], os.path.expanduser("~/.agentguard/" + files["config"]))
    token_files = ("/etc/agentguard/" + files["token"], os.path.expanduser("~/.agentguard/" + files["token"]))
    for path in config_files:
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                config.update(data)
        except (OSError, ValueError):
            continue
    env = {
        "url": "AGENTGUARD_URL", "token": "AGENTGUARD_TOKEN", "token_file": "AGENTGUARD_TOKEN_FILE",
        "control_file": "AGENTGUARD_CONTROL_FILE", "timeout_pre": "AGENTGUARD_TIMEOUT_PRE",
        "timeout": "AGENTGUARD_TIMEOUT", "spool": "AGENTGUARD_SPOOL", "upload_mode": "AGENTGUARD_UPLOAD_MODE",
    }
    for key, name in env.items():
        if os.environ.get(name):
            config[key] = os.environ[name]
    config.setdefault("url", "http://127.0.0.1:18080")
    config.setdefault("control_file", os.path.expanduser("~/.agentguard/" + files["control"]))
    config.setdefault("spool", os.path.expanduser("~/.agentguard/" + files["spool"]))
    config.setdefault("upload_mode", "full")
    if not config.get("token"):
        for path in ([config["token_file"]] if config.get("token_file") else []) + list(token_files):
            try:
                with open(path, encoding="utf-8") as handle:
                    config["token"] = handle.read().strip()
                break
            except OSError:
                continue
    return config


def read_control(config: dict) -> dict:
    try:
        with open(config["control_file"], encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_control(config: dict, control) -> None:
    """缓存服务端下发的管控配置；未变化时不写盘。"""
    if not isinstance(control, dict) or control == read_control(config):
        return
    path = config["control_file"]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as handle:
            json.dump(control, handle)
        os.replace(path + ".tmp", path)
    except OSError:
        pass


def failsafe_denies(payload: dict) -> bool:
    """服务不可达且为 failsafe 时 PreToolUse 是否拒绝（设计 §7.4）。"""
    tool = str(payload.get("tool_name") or "")
    if tool in FAIL_CLOSED_TOOLS or tool.startswith("mcp__"):
        return True
    if tool in WRITE_TOOLS:
        data = payload.get("tool_input") or {}
        cwd = os.path.normpath(str(payload.get("cwd") or "/nonexistent"))
        if tool == "apply_patch":
            # Codex 补丁：逐个目标文件判断，相对路径以 cwd 为基准；解析不出目标按工作区外处理。
            lines = str(data.get("command") or "").splitlines()
            paths = [line.split(": ", 1)[1].strip() for line in lines if line.startswith(PATCH_PREFIXES)]
        else:
            paths = [str(data.get("file_path") or data.get("notebook_path") or "")]
        paths = [os.path.normpath(os.path.join(cwd, os.path.expanduser(p))) for p in paths if p]
        return not paths or any(not (p == cwd or p.startswith(cwd.rstrip("/") + "/")) for p in paths)
    return False


def deny_output(reason: str) -> dict:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"Blocked by AgentGuard: {reason}. Do not retry this action through other tools.",
    }}


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


# 直连 AgentGuard，不读 HTTP(S)_PROXY：Hook 继承 Agent 进程环境，代理变量可被篡改或
# 指向其他代理，决策请求不能因此被转发到其他地址。
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def post(config: dict, payload: dict, timeout: float) -> dict:
    request = urllib.request.Request(
        config["url"].rstrip("/") + f"/v1/agents/{config.get('agent', 'claude-code')}/hook",
        data=json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {config.get('token', '')}",
                 "User-Agent": CLIENT_VERSION},
        method="POST",
    )
    with OPENER.open(request, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def spool(config: dict, payload: dict, local_action: str) -> None:
    path = config["spool"]
    try:
        if os.path.exists(path) and os.path.getsize(path) > MAX_SPOOL_BYTES:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = dict(payload)
        payload["_ag"] = dict(payload.get("_ag") or {}, delayed=True, spooled_at=time.time(),
                              local_action=local_action, failsafe=FAILSAFE_VERSION)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def spooled_count(config: dict, session_id: str) -> int:
    try:
        with open(config["spool"], encoding="utf-8") as handle:
            return sum(1 for line in handle if session_id and session_id in line)
    except OSError:
        return 0


def flush_spool(config: dict, timeout: float) -> None:
    path = config["spool"]
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return
    if not lines:
        return
    sent = 0
    for line in lines[:FLUSH_BATCH]:
        try:
            post(config, json.loads(line), timeout)
        except (OSError, ValueError, urllib.error.URLError):
            break
        sent += 1
    try:
        rest = lines[sent:]
        if rest:
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(rest)
        else:
            os.remove(path)
    except OSError:
        pass


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0
    config = load_config(agent_name(sys.argv))
    event = str(payload.get("hook_event_name") or "")
    timeout = float(config.get("timeout_pre") or 1.5) if event == "PreToolUse" else float(config.get("timeout") or 1.0)
    payload = shrink(payload, str(config.get("upload_mode")))
    payload.setdefault("_ag", {})["client"] = CLIENT_VERSION
    if event == "SessionEnd":
        payload["_ag"]["spooled"] = spooled_count(config, str(payload.get("session_id") or ""))

    try:
        result = post(config, payload, timeout)
    except (OSError, ValueError, urllib.error.URLError):
        control = read_control(config)
        if control.get("enabled") is False:
            return 0
        failsafe = control.get("fail_mode") == "failsafe"
        deny = event == "PreToolUse" and failsafe and failsafe_denies(payload)
        spool(config, payload, "deny" if deny else "pass")
        if deny:
            sys.stdout.write(json.dumps(deny_output("AGENTGUARD_UNAVAILABLE")))
        return 0

    if not isinstance(result, dict):
        return 0
    save_control(config, result.get("control"))
    if result.get("disabled"):
        return 0
    output = result.get("output")
    if output:
        sys.stdout.write(json.dumps(output, ensure_ascii=False))
    # 补报放在非关键路径事件上，不增加 PreToolUse 延迟。
    if event not in ("PreToolUse", "UserPromptSubmit"):
        flush_spool(config, timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
