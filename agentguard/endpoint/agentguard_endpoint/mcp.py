"""stdio MCP 包装器与 MCP 配置改写（通用 Agent 接入设计 §8.3）。

包装器（`mcp-proxy`，由 wrap-mcp 写入 Agent 的 MCP 配置，原命令放在 -- 之后）：

    agentguard-endpoint mcp-proxy --agent claude-code --server github -- npx -y @modelcontextprotocol/server-github

以子进程启动原 MCP server，在 Agent 与 server 之间逐行转发 JSON-RPC：
- tools/call 请求：先调 /v1/runtime/mcp/inspect-request，非 ALLOW 直接回 JSON-RPC 错误，请求不写入子进程；
  服务不可达时按 Hook 管控配置的本地缓存处理（与 Hook 共用缓存文件）：已停止或 open（默认）直接转发，
  failsafe 拒绝；设备管理中停止该设备或 Agent 时服务端直接放行；
- tools/call 响应：先调 inspect-result 打污点；检出注入且管控开启返回内容拦截（result_guard）时，按服务端下发的
  拦截说明替换整条返回（结果或错误体），原文只进服务端证据库；否则原样返回（由后续调用的规则生效）；
- tools/list 响应：上报清单，服务端做投毒扫描与隐藏工具判定；
- 其余消息（initialize、通知、server→client 请求等）原样透传。

令牌、地址与管控缓存与该 Agent 的 Hook 相同（config.load），中转决策才能认领到 Hook 登记的会话。

配置改写（wrap-mcp / unwrap-mcp）：Claude Code 改写 JSON 配置（~/.claude.json 含 projects.*.mcpServers、项目
.mcp.json），Codex 经 `codex app-server` 改写 $CODEX_HOME/config.toml 的 mcp_servers。远程（HTTP）server 不包装，
提示由管理员登记到网关。旧版 clients/mcp_stdio 包装器写入的条目会被识别：wrap 时迁移为新格式，unwrap 时还原。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading

from . import config as cfg
from . import transport as net

BLOCKED_CODE = -32040
UNAVAILABLE_CODE = -32042
SUBCOMMAND = "mcp-proxy"
LEGACY_WRAPPER = "agentguard_mcp_stdio.py"
# Codex config/batchWrite 的 keyPath 按点分隔：带点或引号的 server 名无法安全表达，提示手动处理。
CODEX_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
WRAP_AGENTS = ("claude-code", "codex")


# ---------- 包装器 ----------

class Relay:
    def __init__(self, server: str, command: list[str], config: dict) -> None:
        self.server = server
        self.config = config
        self.timeout = float(os.environ.get("AGENTGUARD_MCP_TIMEOUT") or config.get("mcp_timeout") or 3.0)
        self.out_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.inflight: dict = {}         # request id -> 已放行 tools/call 的检查上下文
        self.list_requests: set = set()  # tools/list 的 request id
        if cfg.WINDOWS:
            # npx / uvx 等在 Windows 上是 .cmd，按名字启动需要先解析出完整路径。
            command = [shutil.which(command[0]) or command[0]] + command[1:]
        self.child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=None, bufsize=0)

    def call(self, path: str, payload: dict) -> dict:
        return net.request(self.config, "POST", path, payload, self.timeout)

    # ---------- 输出 ----------

    def to_agent(self, message) -> None:
        data = message if isinstance(message, (bytes, bytearray)) else (json.dumps(message) + "\n").encode()
        with self.out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def to_child(self, data: bytes) -> None:
        try:
            self.child.stdin.write(data)
            self.child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    @staticmethod
    def error(request_id, code: int, message: str, data: dict | None = None) -> dict:
        error = {"code": code, "message": message}
        if data:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": error}

    # ---------- Agent → server ----------

    def gate(self, message: dict):
        """返回 None 表示放行（已登记检查上下文），否则返回要回给 Agent 的错误。"""
        request_id = message.get("id")
        params = message.get("params") or {}
        tool = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        try:
            verdict = self.call("/v1/runtime/mcp/inspect-request", {
                "server": self.server, "tool": tool, "arguments": arguments, "request_id": request_id})
        except net.NETWORK_ERRORS:
            control = net.read_control(self.config)
            if control.get("enabled") is False or control.get("fail_mode") != "failsafe":
                return None
            return self.error(request_id, UNAVAILABLE_CODE, "Blocked by AgentGuard: service unavailable",
                              {"reason_code": "AGENTGUARD_UNAVAILABLE"})
        net.save_control(self.config, verdict.get("control"))
        if verdict.get("disabled"):
            return None
        if verdict.get("decision") != "ALLOW":
            error = verdict.get("error") or {"code": BLOCKED_CODE, "message": "Blocked by AgentGuard policy",
                                             "data": {"decision_id": verdict.get("decision_id"),
                                                      "reason_code": verdict.get("reason_code")}}
            return {"jsonrpc": "2.0", "id": request_id, "error": error}
        with self.state_lock:
            self.inflight[json.dumps(request_id)] = {
                "tool": tool, "arguments": arguments, "trace_id": verdict.get("trace_id"),
                "call_id": verdict.get("call_id"), "decision_id": verdict.get("decision_id")}
        return None

    def from_agent(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self.to_child(line)
            return
        messages = message if isinstance(message, list) else [message]
        forward = []
        for item in messages:
            if isinstance(item, dict) and item.get("method") == "tools/call" and "id" in item:
                blocked = self.gate(item)
                if blocked is not None:
                    self.to_agent(blocked)
                    continue
            elif isinstance(item, dict) and item.get("method") == "tools/list" and "id" in item:
                with self.state_lock:
                    self.list_requests.add(json.dumps(item["id"]))
            forward.append(item)
        if not forward:
            return
        payload = forward if isinstance(message, list) else forward[0]
        self.to_child((json.dumps(payload) + "\n").encode())

    # ---------- server → Agent ----------

    def from_child(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            self.to_agent(line)
            return
        blocked = False
        for item in message if isinstance(message, list) else [message]:
            if isinstance(item, dict) and "id" in item and ("result" in item or "error" in item):
                replacement = self.observe_response(item)
                if isinstance(replacement, dict) and isinstance(replacement.get("content"), list):
                    # 返回内容拦截：结果与错误体都可能携带注入文本，一律替换为服务端下发的拦截说明。
                    item.pop("error", None)
                    item["result"], blocked = replacement, True
        if blocked:
            self.to_agent(message)
            return
        self.to_agent(line if line.endswith(b"\n") else line + b"\n")

    def observe_response(self, item: dict):
        """上报返回 / 清单；返回服务端下发的拦截替换结果（未拦截为 None）。"""
        key = json.dumps(item.get("id"))
        with self.state_lock:
            context = self.inflight.pop(key, None)
            is_list = key in self.list_requests
            self.list_requests.discard(key)
        try:
            if context is not None:
                verdict = self.call("/v1/runtime/mcp/inspect-result", {
                    "server": self.server, "tool": context["tool"], "arguments": context["arguments"],
                    "trace_id": context["trace_id"], "call_id": context["call_id"],
                    "decision_id": context["decision_id"], "result": item.get("result", item.get("error")),
                    "execution": "failed" if "error" in item or
                    isinstance(item.get("result"), dict) and item["result"].get("isError") else "succeeded"})
                return verdict.get("replace") if isinstance(verdict, dict) else None
            elif is_list:
                tools = (item.get("result") or {}).get("tools") or []
                self.call(f"/v1/runtime/mcp/manifests/{self.server}", {"tools": tools})
        except net.NETWORK_ERRORS:
            # 结果侧上报失败不阻断返回；清单缺失会使后续调用在服务端 fail-closed。
            pass
        return None

    # ---------- 主循环 ----------

    def pump_child(self) -> None:
        for line in iter(self.child.stdout.readline, b""):
            self.from_child(line)

    def run(self) -> int:
        reader = threading.Thread(target=self.pump_child, daemon=True)
        reader.start()
        for line in iter(sys.stdin.buffer.readline, b""):
            if line.strip():
                self.from_agent(line)
        try:
            self.child.stdin.close()
        except OSError:
            pass
        code = self.child.wait()
        reader.join(timeout=2)
        return code


def proxy_main(argv: list[str]) -> int:
    """`mcp-proxy [--agent A] --server NAME -- COMMAND [ARGS...]`（不经 argparse：-- 之后的参数原样保留）。"""
    usage = f"usage: agentguard-endpoint {SUBCOMMAND} [--agent AGENT] --server NAME -- COMMAND [ARGS...]"
    if "--" not in argv:
        print(usage, file=sys.stderr)
        return 2
    split = argv.index("--")
    options, command = argv[:split], argv[split + 1:]
    values = dict(zip(options[::2], options[1::2]))
    server, agent = values.get("--server", ""), values.get("--agent", "claude-code")
    if not server or not command or agent not in cfg.AGENTS or len(options) % 2:
        print(usage, file=sys.stderr)
        return 2
    return Relay(server, command, cfg.load(agent)).run()


# ---------- 配置改写 ----------

def _wrapper_head(spec) -> list[str] | None:
    """包装器部分（命令 + `--` 之前的参数）；不是本客户端或旧版 clients/mcp_stdio 的包装返回 None。"""
    if not isinstance(spec, dict):
        return None
    args = [str(arg) for arg in spec.get("args") or []]
    if "--" not in args or args.index("--") + 1 >= len(args):
        return None
    head = [str(spec.get("command") or "")] + args[:args.index("--")]
    return head if SUBCOMMAND in head or any(part.endswith(LEGACY_WRAPPER) for part in head) else None


def unwrap_spec(spec) -> dict | None:
    """包装过的 server 还原为原命令；没有包装返回 None。"""
    if _wrapper_head(spec) is None:
        return None
    args = [str(arg) for arg in spec.get("args") or []]
    split = args.index("--")
    return {**spec, "command": args[split + 1], "args": args[split + 2:]}


def wrap_spec(name: str, spec, launcher: list[str], agent: str) -> dict | None:
    """stdio server 改为经包装器启动；远程 server、无命令或已是新格式时返回 None。旧格式先还原再包装。"""
    if not isinstance(spec, dict) or is_remote(spec):
        return None
    head = _wrapper_head(spec)
    if head is not None:
        if SUBCOMMAND in head:
            return None
        spec = unwrap_spec(spec)
    if not spec.get("command"):
        return None
    return {**spec, "command": launcher[0],
            "args": launcher[1:] + [SUBCOMMAND, "--agent", agent, "--server", name, "--", str(spec["command"])]
            + [str(arg) for arg in spec.get("args") or []]}


def is_remote(spec) -> bool:
    return isinstance(spec, dict) and bool(spec.get("url") or spec.get("type") in ("http", "sse"))


def rewrite_json_servers(data: dict, change) -> tuple[int, list]:
    """对 mcpServers 与 projects.*.mcpServers（~/.claude.json 的本地作用域）逐个应用 change；返回 (改动数, 远程名)。"""
    count, remote = 0, []
    scopes = [data.get("mcpServers")] + [project.get("mcpServers") for project in (data.get("projects") or {}).values()
                                         if isinstance(project, dict)]
    for servers in scopes:
        for name, spec in (servers or {}).items() if isinstance(servers, dict) else []:
            if is_remote(spec):
                remote.append(name)
                continue
            updated = change(name, spec)
            if updated is not None:
                servers[name] = updated
                count += 1
    return count, remote


def default_claude_configs() -> list[str]:
    candidates = [os.path.join(os.path.expanduser("~"), ".claude.json"), os.path.join(os.getcwd(), ".mcp.json")]
    return [path for path in candidates if os.path.exists(path)]


def launcher_for_install(agent: str) -> list[str] | None:
    """已安装客户端的启动命令（取安装记录，用户级优先）；未安装返回 None。"""
    from . import install as ins

    for directory in (cfg.user_dir(), cfg.system_dir()):
        record = cfg.read_json(os.path.join(directory, ins.INSTALL_RECORD))
        target = record.get("target")
        if target and agent in (record.get("agents") or []):
            launcher = ins.client_command(target)
            if os.path.exists(launcher[-1]):
                return launcher
    return None


def _report_remote(remote: list) -> None:
    for name in sorted(set(remote)):
        print(f"  remote server '{name}': ask the AgentGuard admin to register it in AG_EXTRA_UPSTREAMS, "
              f"then point its url at <agentguard>/mcp/{name}")


def _rewrite_claude(paths: list, change, verb: str, dry_run: bool) -> int:
    from . import install as ins

    for path in paths or default_claude_configs():
        data = ins.load_json(path)
        count, remote = rewrite_json_servers(data, change)
        if count:
            ins.write_json(path, data, dry_run)
        print(f"{path}: {verb} {count} stdio server(s)")
        if verb == "wrapped":
            _report_remote(remote)
    return 0


def _rewrite_codex(change, verb: str, codex_bin: str, dry_run: bool) -> int:
    from . import codex as cx

    codex = cx.find_codex(codex_bin)
    if not codex:
        print("error: codex executable not found; pass --codex-bin", file=sys.stderr)
        return 1
    home = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
    server = cx.AppServer(codex, home)
    try:
        servers = (server.call("config/read", {"cwd": os.getcwd()})["config"] or {}).get("mcp_servers") or {}
        edits, remote = [], []
        for name, spec in servers.items():
            if is_remote(spec):
                remote.append(name)
                continue
            updated = change(name, spec)
            if updated is None:
                continue
            if not CODEX_NAME_RE.match(name):
                print(f"  skip '{name}': name is not a plain TOML key; rewrite it manually")
                continue
            edits.append({"keyPath": f"mcp_servers.{name}", "mergeStrategy": "replace",
                          "value": {key: value for key, value in updated.items() if value is not None}})
        if dry_run:
            print(json.dumps(edits, indent=2, ensure_ascii=False))
        elif edits:
            server.call("config/batchWrite", {"edits": edits})
    finally:
        server.close()
    print(f"{os.path.join(home, 'config.toml')}: {verb} {len(edits)} stdio server(s)")
    if verb == "wrapped":
        _report_remote(remote)
    return 0


def _check_agent(agent: str) -> bool:
    if agent in WRAP_AGENTS:
        return True
    print(f"error: MCP wrapping supports {', '.join(WRAP_AGENTS)}; for {agent}, register remote MCP servers "
          "on the AgentGuard gateway instead", file=sys.stderr)
    return False


def cmd_wrap(args) -> int:
    if not _check_agent(args.agent):
        return 2
    launcher = launcher_for_install(args.agent)
    if launcher is None:
        if not args.dry_run:
            print(f"error: AgentGuard endpoint is not installed for {args.agent}; run `install` first",
                  file=sys.stderr)
            return 1
        launcher = ["agentguard-endpoint"]

    def change(name, spec):
        return wrap_spec(name, spec, launcher, args.agent)

    if args.agent == "codex":
        return _rewrite_codex(change, "wrapped", args.codex_bin, args.dry_run)
    return _rewrite_claude(args.paths, change, "wrapped", args.dry_run)


def cmd_unwrap(args) -> int:
    if not _check_agent(args.agent):
        return 2

    def change(_name, spec):
        return unwrap_spec(spec)

    if args.agent == "codex":
        return _rewrite_codex(change, "unwrapped", args.codex_bin, args.dry_run)
    return _rewrite_claude(args.paths, change, "unwrapped", args.dry_run)
