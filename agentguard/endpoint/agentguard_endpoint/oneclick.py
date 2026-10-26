"""一键安装（setup）与一键卸载（uninstall --all）。

setup 由服务端生成的一键脚本调用（/v1/agents/install.{sh,ps1,cmd}），安装参数取自服务端的客户端部署配置
（GET /v1/agents/deploy，控制台「设备管理 → 客户端部署」），命令行参数可逐项覆盖：
1. 按配置的 Agent 逐个安装 Hook；用户级安装跳过本机未安装的 Agent，系统级安装不检测（面向所有用户）；
2. 沿用本机已有的主机令牌，否则生成新令牌，一次申请接入全部 Agent，按配置等待管理员认证；
3. 认证后拉取规则包并自检。

uninstall --all 移除本机所有 Agent 的 AgentGuard Hook（用户级与系统级，后者需要管理员 / root）和 Windows
「设置 → 应用」中的卸载入口；--purge 另外删除客户端、令牌与本地缓存，并通知服务端把设备标记为已卸载
（令牌随即停用）。
"""

from __future__ import annotations

import argparse
import getpass
import glob
import os
import shutil
import subprocess
import sys

from . import codex as cx
from . import config as cfg
from . import install as ins
from . import task_runner
from . import transport as net


def is_admin() -> bool:
    if cfg.WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def agent_present(agent: str) -> bool:
    """本机（当前用户）是否装有该 Agent：可执行文件、配置目录或 VS Code 扩展任一存在即算。"""
    home = os.path.expanduser("~")
    if agent == "codex":
        codex_home = os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")
        return bool(cx.find_codex()) or os.path.isdir(codex_home)
    if agent == "trae":
        return bool(shutil.which("trae") or shutil.which("trae-cn")
                    or any(os.path.isdir(os.path.join(home, name)) for name in cfg.TRAE_DIRS))
    if agent == "qoder":
        return bool(any(shutil.which(name) for name in ("qoder", "qoder-cn", "qodercn", "qodercli"))
                    or any(os.path.isdir(os.path.join(home, name)) for name in cfg.QODER_DIRS))
    if agent == "zcode":
        return bool(shutil.which("zcode") or any(os.path.isdir(os.path.join(home, name)) for name in cfg.ZCODE_DIRS))
    if agent == "workbuddy":
        return bool(any(shutil.which(name) for name in ("workbuddy", "workbuddy-ai"))
                    or any(os.path.isdir(os.path.join(home, name)) for name in cfg.WORKBUDDY_DIRS))
    if agent == "codebuddy":
        return bool(any(shutil.which(name) for name in ("codebuddy", "buddy", "buddycn"))
                    or any(os.path.isdir(os.path.join(home, name)) for name in (*cfg.CODEBUDDY_DIRS, ".codebuddycn")))
    return bool(shutil.which("claude") or os.path.isdir(os.path.join(home, ".claude"))
                or os.path.exists(os.path.join(home, ".claude.json"))
                or glob.glob(os.path.join(home, ".vscode*", "extensions", "anthropic.claude-code-*")))


def _enroll_key(args, deploy: dict) -> str:
    key = args.enroll_key or os.environ.get("AGENTGUARD_ENROLL_KEY", "")
    if key or not (deploy.get("enroll") or {}).get("key_required"):
        return key
    if sys.stdin and sys.stdin.isatty():
        try:
            return getpass.getpass("enrollment key (ask the AgentGuard admin): ").strip()
        except (EOFError, KeyboardInterrupt):
            return ""
    print("warning: the server requires an enrollment key; pass --enroll-key or set AGENTGUARD_ENROLL_KEY")
    return ""


def cmd_setup(args) -> int:
    url = args.url.rstrip("/")
    try:
        deploy = net.deploy(url)
    except net.NETWORK_ERRORS as exc:
        print(f"error: cannot read the deployment config from {url}: {exc}", file=sys.stderr)
        return 1
    agents = [agent for agent in (args.agents.split(",") if args.agents else deploy.get("agents") or [])
              if agent in cfg.AGENTS]
    machine = (args.scope or deploy.get("scope")) == "machine"
    wait = float(deploy.get("wait", 600) if args.wait is None else args.wait)
    self_test = bool(deploy.get("self_test", True)) and not args.no_self_test
    print(f"AgentGuard endpoint setup: server {url}, {'machine-wide' if machine else 'current user'}, "
          f"agents: {', '.join(agents) or '-'}")
    if machine and not is_admin():
        print("error: machine-wide install needs administrator / root rights", file=sys.stderr)
        return 1
    if not machine:
        missing = [agent for agent in agents if not agent_present(agent)]
        for agent in missing:
            print(f"skip {agent}: not found on this host (rerun the installer after installing it)")
        agents = [agent for agent in agents if agent not in missing]
    if not agents:
        print("error: none of the configured agents is installed on this host", file=sys.stderr)
        return 1

    token = next((cfg.load(agent).get("token") for agent in agents if cfg.load(agent).get("token")), "") \
        or ins.new_token()
    for agent in agents:
        print(f"\n== {agent}")
        # Trae / Qoder / ZCode / WorkBuddy / CodeBuddy 没有受管配置、Windows 上 Codex 暂不支持系统级安装：按当前用户安装。
        agent_machine = machine and ins.machine_supported(agent)
        if machine and not agent_machine:
            print(f"note: machine-wide install is not supported for {agent} here; installing for the current user")
        code = ins.install_agent(agent, agent_machine, token, url, codex_bin=args.codex_bin)
        if code:
            return code

    try:
        task_runner.enable(cfg.install_dir(agent_machine))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print()
    config = cfg.load(agents[0])
    status = ins.enroll_flow(config, _enroll_key(args, deploy), wait, agents)
    if status != "approved":
        print("\nhooks are installed; they start enforcing once the device is approved "
              "(events until then are buffered and reported afterwards)")
        return 0 if status == "pending" else 1
    for agent in agents:
        ins.activate(cfg.load(agent))
    failed = 0
    if self_test:
        for agent in agents:
            print(f"\n== self-test {agent}")
            code = ins.cmd_self_test(argparse.Namespace(agent=agent, offline=False, command=None,
                                                        codex_requirements=ins.CODEX_REQUIREMENTS))
            failed += code == 1
    print("\nrestart the agents (Codex desktop: quit and reopen) and start a new session to take effect")
    if "trae" in agents:
        print("Trae: enable global hooks once in Trae > Settings > Hooks (confirm the security prompt)")
    if "qoder" in agents:
        print("Qoder: hooks load at startup only - fully quit and reopen Qoder")
    if "zcode" in agents:
        print("ZCode: hooks are read when a session starts - start a new session (task)")
    if "workbuddy" in agents:
        print("WorkBuddy: hooks load at startup only - fully quit and reopen WorkBuddy")
    if "codebuddy" in agents:
        print("CodeBuddy IDE: reload the window and start a new session; check project .codebuddy hook overrides")
    print("uninstall: " + uninstall_hint())
    return 1 if failed else 0


def uninstall_hint() -> str:
    if cfg.WINDOWS:
        return "Settings > Apps > AgentGuard Endpoint, or `agentguard-endpoint uninstall --all --purge`"
    return "`agentguard-endpoint uninstall --all --purge` (machine-wide install: with sudo)"


# ---------- 一键卸载 ----------

def _remove_agent_hooks(agent: str, machine: bool, requirements: str) -> int:
    if machine and agent == "codex" and not cfg.WINDOWS:
        return ins.remove_requirements(requirements, False)
    if machine and agent in ins.USER_ONLY:
        return 0
    return sum(_remove_hooks_from(path, machine, agent) for path in ins.settings_paths(agent, machine))


def _remove_hooks_from(path: str, machine: bool, agent: str = "claude-code") -> int:
    try:
        settings = ins.load_json(path)
    except ValueError:
        print(f"warning: {path} is not valid JSON; remove the AgentGuard hooks manually")
        return 0
    removed = ins.remove_hooks(settings, agent)
    if not removed:
        return 0
    if machine:
        settings.pop("allowManagedHooksOnly", None)
    if settings or os.path.exists(path + ".agentguard.bak"):
        ins.write_json(path, settings, False)
    else:
        os.remove(path)   # 文件由 AgentGuard 创建，移除后为空：一并删除
        print(f"removed {path}")
    return removed


def _safe_dir(path: str) -> bool:
    """只删除明确属于 AgentGuard 的目录：不是根目录、家目录或其上级。"""
    path = os.path.abspath(path)
    home = os.path.abspath(os.path.expanduser("~"))
    return (os.path.isdir(path) and len(path.replace("\\", "/").rstrip("/").split("/")) >= 3
            and path != home and not home.startswith(path.rstrip(os.sep) + os.sep))


def _client_dir(path: str) -> bool:
    return _safe_dir(path) and any(os.path.exists(os.path.join(path, name))
                                   for name in (ins.EXE_NAME, ins.ENTRY_SCRIPT))


def _delete_tree(path: str) -> None:
    """删除目录；Windows 上正在运行的 exe 删不掉时，退出后由独立进程延迟删除。"""
    try:
        shutil.rmtree(path)
        print(f"removed {path}")
        return
    except OSError:
        if not cfg.WINDOWS:
            raise
    flags = 0x00000008 | 0x08000000   # DETACHED_PROCESS | CREATE_NO_WINDOW
    subprocess.Popen(f'cmd.exe /c ping -n 3 127.0.0.1 >nul & rmdir /s /q "{path}"', creationflags=flags,
                     close_fds=True)
    print(f"removing {path} after exit")


def _purge(scopes: list) -> list:
    """删除客户端、令牌与缓存；返回删除失败的路径。"""
    failed = []
    targets = []
    for machine in scopes:
        config_dir = cfg.system_dir() if machine else cfg.user_dir()
        target = cfg.read_json(os.path.join(config_dir, ins.INSTALL_RECORD)).get("target") or cfg.install_dir(machine)
        if _client_dir(target):
            targets.append(target)
        targets.append(config_dir)
    for path in dict.fromkeys(targets):
        if not os.path.isdir(path):
            continue
        name = os.path.basename(os.path.abspath(path)).lower()
        try:
            if _client_dir(path) or (name in (".agentguard", "agentguard") and _safe_dir(path)):
                _delete_tree(path)
            else:
                # 非标准位置（AGENTGUARD_HOME / AGENTGUARD_SYSTEM_DIR 指向的目录）：只删 AgentGuard 自己的文件。
                for item in os.listdir(path):
                    if item in ("device-token", "host.json", ins.INSTALL_RECORD) or item.startswith(("cc-", "codex-", "task-runner", "static-workspace-")) \
                            or item in ("spool.jsonl", "bin"):
                        full = os.path.join(path, item)
                        shutil.rmtree(full) if os.path.isdir(full) else os.remove(full)
                print(f"cleaned {path}")
        except OSError as exc:
            failed.append(f"{path} ({exc})")
    return failed


def _unwrap_mcp_configs() -> None:
    from . import mcp

    claude = os.path.join(os.path.expanduser("~"), ".claude.json")
    codex_home = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
    wrapped_claude = mcp.SUBCOMMAND in ins._read_text(claude)
    wrapped_codex = mcp.SUBCOMMAND in ins._read_text(os.path.join(codex_home, "config.toml"))
    if wrapped_claude:
        mcp._rewrite_claude([claude], lambda _name, spec: mcp.unwrap_spec(spec), "unwrapped", False)
    if wrapped_codex:
        try:
            mcp._rewrite_codex(lambda _name, spec: mcp.unwrap_spec(spec), "unwrapped", "", False)
        except (OSError, RuntimeError, KeyError, ValueError) as exc:
            print(f"warning: cannot restore Codex MCP servers ({exc}); run `unwrap-mcp --agent codex` first")
    if wrapped_claude or wrapped_codex:
        print("note: project-level .mcp.json files wrapped with `wrap-mcp` are not restored automatically; "
              "run `unwrap-mcp <file>` in those projects")


def _machine_install_present(requirements: str) -> bool:
    """系统级安装：有安装记录，或受管配置中有 AgentGuard Hook（都只需读权限）。"""
    if os.path.exists(os.path.join(cfg.system_dir(), ins.INSTALL_RECORD)):
        return True
    if not cfg.WINDOWS and ins.REQ_BEGIN in ins._read_text(requirements):
        return True
    try:
        hooks = ins.load_json(ins.settings_path("claude-code", True)).get("hooks") or {}
    except (OSError, ValueError):
        return False
    return any(ins.is_ours(entry) for entries in hooks.values() if isinstance(entries, list) for entry in entries)


def _finish(args, code: int) -> int:
    if args.pause and sys.stdin and sys.stdin.isatty():
        try:
            input("press Enter to close")
        except (EOFError, KeyboardInterrupt):
            pass
    return code


def cmd_uninstall_all(args) -> int:
    print("AgentGuard endpoint uninstall: all agents")
    machine_installed = _machine_install_present(args.codex_requirements)
    if machine_installed and not is_admin():
        # 先检查再动手：只删用户级而留下系统级 Hook，或停用令牌而 Hook 还在，都会留下半卸载状态。
        print(f"error: a machine-wide install was found ({cfg.system_dir()}, {cfg.install_dir(True)}); "
              "rerun the uninstaller as administrator / with sudo. Nothing was changed.", file=sys.stderr)
        return _finish(args, 1)
    failed, removed = [], 0
    try:
        task_runner.remove()
    except OSError as exc:
        print(f"error: cannot stop background scan task channel: {exc}", file=sys.stderr)
        return _finish(args, 1)
    for machine in (False, True):
        for agent in cfg.AGENTS:
            try:
                removed += _remove_agent_hooks(agent, machine, args.codex_requirements)
            except PermissionError as exc:
                failed.append(str(exc.filename or exc))
    print(f"removed {removed} AgentGuard hook entr{'y' if removed == 1 else 'ies'}")
    if failed:
        print("error: cannot modify (permission denied):\n  " + "\n  ".join(failed), file=sys.stderr)
        print("the device token was kept; rerun the uninstaller as administrator / with sudo", file=sys.stderr)
        return _finish(args, 1)
    ins.unregister_uninstaller()
    if args.purge:
        # 删除客户端后，经包装器启动的 MCP server 会起不来：先还原用户级 MCP 配置。
        _unwrap_mcp_configs()
        config = cfg.load(cfg.AGENTS[0])
        if args.url and not config.get("url"):
            config["url"] = args.url
        if config.get("token"):
            try:
                result = net.report_uninstall(config)
                print(f"device {result.get('device_id')} marked as uninstalled at {config['url']}; its token is disabled")
            except net.NETWORK_ERRORS as exc:
                print(f"warning: cannot notify {config['url']} ({exc}); revoke the device in the console")
        failed = _purge([False, True] if machine_installed else [False])
    if failed:
        print("error: could not remove:\n  " + "\n  ".join(failed), file=sys.stderr)
    else:
        print("AgentGuard endpoint uninstalled" + ("" if args.purge else " (client files and token kept; "
                                                   "add --purge to remove them)"))
    print("restart the agents (Codex desktop: quit and reopen) for the change to take effect")
    return _finish(args, 1 if failed else 0)
