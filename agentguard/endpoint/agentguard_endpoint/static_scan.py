"""按需后台采集 Agent 资产；不执行扫描目标，不读取整个用户目录。"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import config as cfg
from . import transport as net
from .core.asset_snapshot import (
    AGENT_DIRS,
    ASSET_DIRS,
    CONFIG_FILES,
    MAX_BODY_BYTES,
    MAX_CONFIGURABLE_FILE_BYTES,
    MAX_DEPTH,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    PROTOCOL,
    allowed_path,
    sanitize_text,
    snapshot_file_limit,
)

POLL_SECONDS = 30
COLLECT_SECONDS = 60
MAX_ENTRIES = MAX_FILES * 8


def _linked(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _read(root: Path, relative: Path, file_limit: int = MAX_FILE_BYTES) -> bytes:
    """POSIX 逐级打开且不跟随链接；Windows 复核路径并拒绝 reparse 目录。"""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fds = []
    try:
        if os.open in os.supports_dir_fd:
            directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
            parent = os.open(root, directory_flags)
            fds.append(parent)
            for part in relative.parts[:-1]:
                parent = os.open(part, directory_flags, dir_fd=parent)
                fds.append(parent)
            descriptor = os.open(relative.parts[-1], flags, dir_fd=parent)
        else:
            current = root
            for part in relative.parts:
                current = current / part
                if _linked(current):
                    raise OSError("symlink")
            if os.path.normcase(os.path.realpath(current)) != os.path.normcase(os.path.abspath(current)):
                raise OSError("symlink")
            descriptor = os.open(current, flags)
        fds.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("special_file")
        if before.st_size > file_limit:
            raise OSError("file_too_large")
        chunks, size = [], 0
        while size <= file_limit:
            chunk = os.read(descriptor, min(65536, file_limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        if size > file_limit:
            raise OSError("file_too_large")
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise OSError("read_failed")
        return b"".join(chunks)
    finally:
        for descriptor in reversed(fds):
            os.close(descriptor)


def collect(agent: str, scope: str, workspace: str = "", home: str = "", codex_home: str = "", limits=None) -> dict:
    file_limit = snapshot_file_limit(limits)
    started, files, skipped, seen = time.monotonic(), [], [], set()
    total, entries, stopped = 0, 0, False
    home_root = Path(os.path.abspath(home or os.path.expanduser("~")))

    def gap(path, reason):
        if len(skipped) < 100:
            skipped.append({"path": path if allowed_path(agent, path) else "", "reason": reason})

    def visit(root: Path, relative: Path, prefix: str, alias: str = "", depth=0):
        nonlocal total, entries, stopped
        if stopped:
            return
        logical = prefix + "/" + (alias or relative.as_posix())
        if time.monotonic() - started > COLLECT_SECONDS:
            gap("", "collection_timeout")
            stopped = True
            return
        path = root / relative
        if not path.exists() and not _linked(path):
            return
        entries += 1
        if entries > MAX_ENTRIES or len(files) >= MAX_FILES:
            gap("", "max_files")
            stopped = True
            return
        if _linked(root) or any(_linked(root.joinpath(*relative.parts[:i])) for i in range(1, len(relative.parts) + 1)):
            gap(logical, "symlink")
            return
        try:
            if path.is_dir():
                if depth >= MAX_DEPTH:
                    gap(logical, "max_depth")
                    return
                with os.scandir(path) as children:
                    for child in children:
                        entries += 1
                        if entries > MAX_ENTRIES or time.monotonic() - started > COLLECT_SECONDS:
                            gap("", "max_files" if entries > MAX_ENTRIES else "collection_timeout")
                            stopped = True
                            break
                        # 不遍历未知目录；只下钻明确的资产目录及其子目录。
                        child_alias = (alias + "/" + child.name) if alias else ""
                        child_logical = prefix + "/" + (child_alias or (relative / child.name).as_posix())
                        if child.name.startswith(".") or child.name in {"node_modules", "__pycache__", "venv", "dist", "build"}:
                            continue
                        if child.is_symlink():
                            gap(child_logical, "symlink")
                        elif child.is_dir(follow_symlinks=False) or allowed_path(agent, child_logical):
                            visit(root, relative / child.name, prefix, child_alias, depth + 1)
                        if stopped:
                            break
                return
            if not allowed_path(agent, logical) or logical in seen:
                return
            raw = _read(root, relative, file_limit)
            if b"\x00" in raw:
                gap(logical, "binary")
                return
            text = sanitize_text(logical, raw.decode("utf-8-sig"))
            size = len(text.encode("utf-8"))
            if size > file_limit:
                gap(logical, "file_too_large")
                return
            if total + size > MAX_TOTAL_BYTES:
                gap(logical, "total_bytes")
                stopped = True
                return
            total += size
            seen.add(logical)
            files.append({"path": logical, "content": text})
        except (ValueError, UnicodeError, RecursionError):
            gap(logical, "invalid_config")
        except OSError as exc:
            reason = str(exc) if str(exc) in {"symlink", "special_file", "file_too_large"} else "read_failed"
            gap(logical, reason)

    def agent_root(root, prefix):
        for folder in AGENT_DIRS.get(agent, ()):
            # CODEX_HOME 与 Hook 安装器一致，只在终端本地解析，映射为协议内固定 .codex 路径。
            custom_home = codex_home or os.environ.get("CODEX_HOME")
            actual = Path(custom_home) if prefix == "user" and folder == ".codex" and custom_home else root / folder
            for name in sorted(CONFIG_FILES | ASSET_DIRS):
                if actual == root / folder:
                    visit(root, Path(folder) / name, prefix)
                else:
                    visit(actual, Path(name), prefix, folder + "/" + name)
            if agent == "zcode":
                visit(root, Path(folder) / "cli/config.json", prefix)
        names = (".claude.json", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md") if agent == "claude-code" else (("AGENTS.md",) if agent == "codex" else ())
        for name in names:
            visit(root, Path(name), prefix)

    agent_root(home_root, "user")
    workspace_id = ""
    if scope == "user_project":
        if workspace and os.path.isabs(workspace) and os.path.isdir(workspace):
            project = Path(os.path.abspath(workspace))
            if project != home_root and project != Path(project.anchor):
                agent_root(project, "project")
                workspace_id = hashlib.sha256(str(project).encode("utf-8")).hexdigest()[:20]
            else:
                gap("", "workspace_unavailable")
        else:
            gap("", "workspace_unavailable")
    return {"protocol": PROTOCOL, "files": files, "skipped": skipped, "workspace_id": workspace_id}


def run_once(agent: str, workspace: str = "") -> dict:
    config = cfg.load(agent)
    job = net.request(config, "GET", f"/v1/agents/{agent}/static-scan?max_file_bytes={MAX_CONFIGURABLE_FILE_BYTES}",
                      timeout=5.0).get("job")
    if not job:
        return {"status": "idle"}
    return upload_job(config, job, workspace)


def upload_job(config: dict, job: dict, workspace: str = "") -> dict:
    agent = config["agent"]
    if job.get("protocol") != PROTOCOL:
        raise ValueError("unsupported asset snapshot protocol")
    if job.get("agent", agent) != agent or job.get("scope", "user") not in ("user", "user_project"):
        raise ValueError("invalid asset snapshot task")
    snapshot = collect(agent, job.get("scope", "user"), workspace, codex_home=config.get("asset_codex_home", ""),
                       limits=job.get("limits"))
    snapshot["lease"] = job["lease"]
    # JSON 转义可能放大文本；发送前保证协议包本身也不超限。
    while len(json.dumps(snapshot, ensure_ascii=False).encode("utf-8")) > MAX_BODY_BYTES and snapshot["files"]:
        snapshot["files"].pop()
        if len(snapshot["skipped"]) < 100:
            snapshot["skipped"].append({"path": "", "reason": "total_bytes"})
    result = net.request(config, "POST", f"/v1/agents/{agent}/static-scan/{job['scan_id']}", snapshot, timeout=20.0)
    return {"scan_id": job["scan_id"], **result}


def cmd_scan(args) -> int:
    try:
        print(json.dumps(run_once(args.agent, args.workspace), ensure_ascii=True))
        return 0
    except net.NETWORK_ERRORS as exc:
        print(f"asset collection failed: {exc}", file=sys.stderr)
        return 1


def maybe_launch(agent: str, payload: dict) -> None:
    """后台任务独立于 Hook 输出；锁与节流避免每个事件都创建采集进程。"""
    workspace = remember_workspace(agent, payload)
    lock = Path(cfg.user_dir()) / ("static-scan-" + agent + ".lock")
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        try:
            age = time.time() - lock.stat().st_mtime
            if age < POLL_SECONDS:
                return
            lock.unlink()
        except FileNotFoundError:
            pass
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        from . import task_runner

        runner = task_runner.settings()
        if runner:
            if runner.get("enabled") and os.environ.get("AGENTGUARD_TASK_RUNNER") != "0" and not task_runner.running():
                task_runner.launch()
            return
        command = ([sys.executable] if getattr(sys, "frozen", False) else
                   [sys.executable, str(Path(__file__).resolve().parents[1] / "agentguard-endpoint.py")])
        command += ["static-scan", "--agent", agent]
        if workspace:
            command += ["--workspace", workspace]
        options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS} if cfg.WINDOWS else {"start_new_session": True}
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, **options)
    except (OSError, ValueError):
        pass  # 采集辅助功能失败不影响 Hook 决策。


def remember_workspace(agent: str, payload: dict) -> str:
    roots = payload.get("workspace_roots")
    first = roots[0] if isinstance(roots, list) and roots else ""
    workspace = (os.environ.get("CLAUDE_PROJECT_DIR") or os.environ.get("CODEBUDDY_PROJECT_DIR")
                 or os.environ.get("TRAE_PROJECT_DIR") or first or payload.get("cwd") or "")
    if not isinstance(workspace, str) or len(workspace) > 4096 or "\x00" in workspace or not os.path.isabs(workspace):
        return ""
    cfg.write_json(os.path.join(cfg.user_dir(), f"static-workspace-{agent}.json"), {"path": workspace, "at": time.time()})
    return workspace


def recent_workspace(agent: str) -> str:
    value = cfg.read_json(os.path.join(cfg.user_dir(), f"static-workspace-{agent}.json"))
    try:
        age = time.time() - float(value.get("at", 0))
    except (ValueError, TypeError):
        return ""
    path = value.get("path")
    return path if 0 <= age <= 86400 and isinstance(path, str) and os.path.isabs(path) and "\x00" not in path else ""
