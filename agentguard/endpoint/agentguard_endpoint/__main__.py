"""命令行入口：`agentguard-endpoint <子命令>`（exe）或 `python agentguard-endpoint.py <子命令>`（脚本）。

    hook        --agent claude-code|codex|trae|qoder|zcode|workbuddy|codebuddy   Hook 事件入口（由 Agent 调用）
    setup       --url URL                           一键安装：按服务端的客户端部署配置安装全部 Agent、申请接入、
                [--agents a,b] [--scope S]          等待认证并自检（服务端生成的一键脚本调用它）
    install     --agent ... --url URL [--token T]   安装 Hook，写入令牌与地址，拉取规则包；
                [--machine] [--prefix DIR]          不带令牌时在本机生成令牌并申请接入，管理员在控制台认证；
                                                    --machine 需管理员 / root（Codex 写 /etc/codex/requirements.toml）
                [--codex-bin EXE] [--wait S] [--dry-run]
    enroll      --agent ... [--wait S] [--new]      重新申请接入 / 等待认证
    uninstall   --agent ... [--machine]             从 Agent 配置移除 AgentGuard Hook
                --all [--purge]                     一键卸载：移除所有 Agent 的 Hook；--purge 另删客户端、令牌与缓存，
                                                    并通知服务端标记设备已卸载
    status      --agent ...                         配置、连通性、管控配置与规则包
    sync-rules  --agent ...                         立即拉取规则包
    static-scan --agent ... [--workspace DIR]       领取一个设备资产扫描任务，脱敏采集并上传快照
    task-runner [--background|--stop|--status]      常驻接收服务端扫描任务（安装后自动启用）
    self-test   --agent ... [--offline]             用合成事件验证拒绝 / 放行语义
    check       --agent ... --tool T --input JSON   只做本地判定（不联系服务端）
    wrap-mcp    --agent claude-code|codex [FILE...] 改写 MCP 配置，stdio server 经包装器中转（Claude Code 默认
                [--dry-run] [--codex-bin EXE]       ~/.claude.json 与 ./.mcp.json；Codex 经 app-server 改写）
    unwrap-mcp  --agent claude-code|codex [FILE...] 还原 wrap-mcp 的改写（也识别旧版 clients/ 包装器）
    mcp-proxy   [--agent A] --server NAME -- CMD... stdio MCP 包装器（由 wrap-mcp 写入配置，Agent 启动）
"""

from __future__ import annotations

import argparse
import sys

from . import VERSION, hook, install, mcp, oneclick, static_scan, task_runner
from .config import AGENTS


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv and sys.stdin is not None and sys.stdin.isatty():
        # 在资源管理器中双击 exe：没有 Hook 负载，给出用法而不是等待标准输入。
        print(f"AgentGuard endpoint {VERSION}\n\nThis program is started by Claude Code / Codex hooks. To install it, use "
              "the one-click installer from the AgentGuard console (Devices > Client deployment), or run:\n"
              "  agentguard-endpoint setup --url http://<server>:18080\n  agentguard-endpoint --help")
        if install.cfg.WINDOWS:
            input("\npress Enter to close")
        return 0
    if not argv or argv[0] == "hook":
        # Hook 路径不经 argparse：参数错误也不能让 Agent 看到非零退出码。
        rest = argv[1:]
        agent = rest[rest.index("--agent") + 1] if "--agent" in rest[:-1] else "claude-code"
        return hook.main(agent if agent in AGENTS else "claude-code")
    if argv[0] == mcp.SUBCOMMAND:
        # -- 之后是原 MCP server 的命令行，原样保留，不经 argparse。
        return mcp.proxy_main(argv[1:])

    parser = argparse.ArgumentParser(prog="agentguard-endpoint", description="AgentGuard endpoint client")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="subcommand", required=True)

    def command(name: str):
        parser_ = sub.add_parser(name)
        parser_.add_argument("--agent", choices=AGENTS, default="claude-code")
        parser_.add_argument("--codex-requirements", default=install.CODEX_REQUIREMENTS,
                             help=argparse.SUPPRESS)   # Codex 受管配置位置（测试用）
        return parser_

    p = command("install")
    p.add_argument("--url")
    p.add_argument("--token")
    p.add_argument("--token-file")
    p.add_argument("--machine", action="store_true", help="machine-wide install (administrator)")
    p.add_argument("--prefix", help="client install directory")
    p.add_argument("--python", help="python used by the hook in script mode (default: current)")
    p.add_argument("--codex-bin", default="", help="codex executable used to register hook trust (default: auto)")
    p.add_argument("--enroll-key", default="", help="enrollment key, if the server requires one")
    p.add_argument("--wait", type=float, default=0, help="without --token: seconds to wait for approval")
    p.add_argument("--dry-run", action="store_true")
    p = command("setup")
    p.add_argument("--url", required=True, help="AgentGuard server URL")
    p.add_argument("--agents", default="", help="comma-separated agents (default: from the server deployment config)")
    p.add_argument("--scope", choices=("user", "machine"), help="default: from the server deployment config")
    p.add_argument("--wait", type=float, help="seconds to wait for approval (default: from the server)")
    p.add_argument("--no-self-test", action="store_true")
    p.add_argument("--enroll-key", default="", help="enrollment key, if the server requires one")
    p.add_argument("--codex-bin", default="", help="codex executable used to register hook trust (default: auto)")
    p = command("uninstall")
    p.add_argument("--machine", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--all", action="store_true", help="all agents, user and machine-wide")
    p.add_argument("--purge", action="store_true", help="with --all: also remove the client, token and caches")
    p.add_argument("--url", default="", help=argparse.SUPPRESS)
    p.add_argument("--pause", action="store_true", help=argparse.SUPPRESS)
    p = command("enroll")
    p.add_argument("--url")
    p.add_argument("--enroll-key", default="")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for approval")
    p.add_argument("--new", action="store_true", help="apply again with a new host token")
    command("status")
    command("sync-rules")
    p = command("static-scan")
    p.add_argument("--workspace", default="", help="current project absolute path for an optional project asset scan")
    p = sub.add_parser("task-runner", help="background server-dispatched scan task channel")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--background", action="store_true", help="start detached and return")
    mode.add_argument("--stop", action="store_true", help="stop the background task channel")
    mode.add_argument("--status", action="store_true", help="show local task channel status")
    mode.add_argument("--autostart", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--config-dir", default="", help=argparse.SUPPRESS)
    p.add_argument("--system-dir", default="", help=argparse.SUPPRESS)
    p = command("self-test")
    p.add_argument("--offline", action="store_true", help="simulate an unreachable server to verify local rules")
    p.add_argument("--command", help="hook command to test (default: the installed one)")
    p = command("check")
    p.add_argument("--tool", required=True)
    p.add_argument("--input", required=True, help="tool_input JSON")
    p.add_argument("--cwd")
    for name in ("wrap-mcp", "unwrap-mcp"):
        p = command(name)
        p.add_argument("paths", nargs="*", help="Claude Code MCP config files (default: ~/.claude.json, ./.mcp.json)")
        p.add_argument("--codex-bin", default="", help="codex executable used to rewrite config.toml (default: auto)")
        p.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    if args.subcommand == "uninstall" and args.all:
        return oneclick.cmd_uninstall_all(args)
    if args.subcommand == "uninstall" and args.purge:
        parser.error("--purge requires --all")
    handlers = {"install": install.cmd_install, "uninstall": install.cmd_uninstall, "status": install.cmd_status,
                "setup": oneclick.cmd_setup,
                "sync-rules": install.cmd_sync_rules, "enroll": install.cmd_enroll, "self-test": install.cmd_self_test,
                "static-scan": static_scan.cmd_scan,
                "task-runner": task_runner.cmd_runner,
                "check": install.cmd_check, "wrap-mcp": mcp.cmd_wrap, "unwrap-mcp": mcp.cmd_unwrap}
    return handlers[args.subcommand](args)


if __name__ == "__main__":
    sys.exit(main())
