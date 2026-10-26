"""独立设备扫描任务通道：等待下发、断线退避、单实例与安装/卸载生命周期。"""

from __future__ import annotations

import json
import os
import random
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

from . import VERSION, autostart, static_scan
from . import config as cfg
from . import transport as net

CONFIG = "task-runner.json"
STATE = "task-runner-state.json"
LOCK = "task-runner.lock"
WAIT_SECONDS = 25


def _path(name):
    return Path(cfg.user_dir()) / name


def _write(name, data):
    path = _path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temporary = handle.name
        json.dump(data, handle, ensure_ascii=True)
    try:
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def settings():
    return cfg.read_json(str(_path(CONFIG)))


def _acquire():
    _path(LOCK).parent.mkdir(parents=True, exist_ok=True)
    handle = open(_path(LOCK), "a+b")
    try:
        if cfg.WINDOWS:
            import msvcrt

            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return handle
    except OSError:
        handle.close()
        return None


def running():
    if not _path(LOCK).exists():
        return False
    handle = _acquire()
    if handle is None:
        return True
    handle.close()
    return False


def installed_agents():
    agents = set()
    for directory in (cfg.system_dir(), cfg.user_dir()):
        agents.update(agent for agent in cfg.read_json(os.path.join(directory, "install.json")).get("agents", [])
                      if agent in cfg.AGENTS)
    return [agent for agent in cfg.AGENTS if agent in agents]


def start():
    config = settings()
    if not config.get("enabled") or running():
        return running()
    if not launch():
        return False
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if running():
            return True
        time.sleep(0.05)
    return False


def launch():
    command = settings().get("command")
    if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
        return False
    options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS} if cfg.WINDOWS else {"start_new_session": True}
    subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     close_fds=True, **options)
    return True


def _wait_exit(pid, deadline):
    if not isinstance(pid, int) or pid <= 0 or pid == os.getpid():
        return
    if cfg.WINDOWS:
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.OpenProcess(0x00100000, False, pid)  # 只等待退出，不发送终止信号。
        if handle:
            try:
                if kernel.WaitForSingleObject(handle, max(0, int((deadline - time.monotonic()) * 1000))) == 258:
                    raise OSError("background scan task channel did not exit")
            finally:
                kernel.CloseHandle(handle)
        return
    while time.monotonic() < deadline:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]:
                return
        except ChildProcessError:
            pass
        try:
            os.kill(pid, 0)
            status = Path(f"/proc/{pid}/stat")
            if status.exists() and status.read_text().split(") ", 1)[-1].startswith("Z"):
                return
        except ProcessLookupError:
            return
        time.sleep(0.05)


def stop():
    config = settings()
    if not config and not running():
        return
    pid = cfg.read_json(str(_path(STATE))).get("pid")
    _write(CONFIG, {**config, "enabled": False})
    deadline = time.monotonic() + 8
    while running() and time.monotonic() < deadline:
        time.sleep(0.05)
    if running():
        raise OSError("background scan task channel did not stop; client files were kept")
    pid = cfg.read_json(str(_path(STATE))).get("pid") or pid
    _wait_exit(pid, deadline)


def enable(target, python=""):
    from .install import client_command

    command = client_command(target, python) + ["task-runner", "--config-dir", cfg.user_dir(),
                                               "--system-dir", cfg.system_dir()]
    codex_home = os.environ.get("CODEX_HOME") or settings().get("codex_home", "")
    _write(CONFIG, {"enabled": True, "command": command, "version": VERSION, "codex_home": codex_home})
    if os.environ.get("AGENTGUARD_TASK_RUNNER") == "0":
        return  # 本机临时停用/隔离测试，不登记系统启动项，也不自动创建进程。
    try:
        mode = autostart.register(command)
    except OSError as exc:
        mode = "manual"
        print(f"warning: cannot register background scan autostart ({exc.__class__.__name__})")
    _write(CONFIG, {**settings(), "autostart": mode})
    if not start():
        raise OSError("cannot start background scan task channel")
    print(f"background scan task channel: running ({mode})")


def remove():
    stop()
    if os.environ.get("AGENTGUARD_TASK_RUNNER") != "0":
        autostart.remove()


def forget_agent(agent, machine):
    was_enabled = settings().get("enabled")
    stop()
    directory = cfg.system_dir() if machine else cfg.user_dir()
    path = os.path.join(directory, "install.json")
    record = cfg.read_json(path)
    if record:
        record["agents"] = [item for item in record.get("agents", []) if item != agent]
        cfg.write_json(path, record)
    if not installed_agents():
        remove()
    elif was_enabled:
        _write(CONFIG, {**settings(), "enabled": True})
        if os.environ.get("AGENTGUARD_TASK_RUNNER") != "0":
            start()


def _groups():
    groups = {}
    for agent in installed_agents():
        config = cfg.load(agent)
        if config.get("token"):
            key = (config["url"], config["token"])
            groups.setdefault(key, []).append(agent)
    return groups


def _serve(agents, stopped, update):
    backoff = 2
    while not stopped.is_set():
        config = cfg.load(agents[0])
        try:
            update("waiting")
            job = net.request(config, "GET", "/v1/agents/static-scan/poll?" + urllib.parse.urlencode(
                {"agents": ",".join(agents), "wait": WAIT_SECONDS,
                 "max_file_bytes": static_scan.MAX_CONFIGURABLE_FILE_BYTES}), timeout=WAIT_SECONDS + 10).get("job")
            if stopped.is_set():
                return
            backoff = 2
            if job:
                agent = job.get("agent")
                if agent not in agents:
                    raise ValueError("scan task outside installed agents")
                upload_config = cfg.load(agent)
                if (upload_config["url"], upload_config.get("token")) != (config["url"], config.get("token")):
                    raise ValueError("device configuration changed during task delivery")
                upload_config["asset_codex_home"] = settings().get("codex_home", "")
                update("collecting", job.get("scan_id", ""))
                static_scan.upload_job(upload_config, job, static_scan.recent_workspace(agent))
                update("uploaded", job["scan_id"])
        except Exception as exc:  # noqa: BLE001 — 单次采集或网络故障不能结束后台任务通道。
            update("reconnecting", error=exc.__class__.__name__)
            stopped.wait((min(backoff, 10) if isinstance(exc, net.Unauthorized) else backoff) + random.random())
            backoff = min(60, backoff * 2)


def run():
    if not settings().get("enabled"):
        return 0
    lock = _acquire()
    if lock is None:
        return 0
    sessions, statuses, wanted = {}, {}, {}
    mutex = threading.Lock()
    refreshed, persisted = 0, 0

    def update(key, status, scan_id="", error=""):
        with mutex:
            statuses[key] = {"agents": list(key[1]), "status": status, "scan_id": str(scan_id)[:64],
                             "error": error, "at": time.time()}

    try:
        while settings().get("enabled"):
            if time.monotonic() - refreshed >= 5:
                wanted = {(server, tuple(agents)): (server, token) for (server, token), agents in _groups().items()}
                refreshed = time.monotonic()
            for key, (thread, stopped) in list(sessions.items()):
                if key not in wanted or not thread.is_alive():
                    stopped.set()
                    sessions.pop(key)
                    with mutex:
                        statuses.pop(key, None)
            for key in wanted:
                if key not in sessions:
                    stopped = threading.Event()
                    thread = threading.Thread(target=_serve, args=(list(key[1]), stopped,
                        lambda status, scan_id="", error="", key=key: update(key, status, scan_id, error)), daemon=True)
                    sessions[key] = thread, stopped
                    thread.start()
            if time.monotonic() - persisted >= 2:
                with mutex:
                    channels = list(statuses.values())
                _write(STATE, {"pid": os.getpid(), "version": VERSION, "at": time.time(), "channels": channels})
                persisted = time.monotonic()
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        for _, stopped in sessions.values():
            stopped.set()
        _write(STATE, {"pid": os.getpid(), "version": VERSION, "stopped_at": time.time(), "channels": []})
        lock.close()
    return 0


def cmd_runner(args):
    if args.config_dir:
        os.environ["AGENTGUARD_HOME"] = args.config_dir
    if args.system_dir:
        os.environ["AGENTGUARD_SYSTEM_DIR"] = args.system_dir
    if args.stop:
        stop()
        return 0
    if args.status:
        print(json.dumps({"enabled": bool(settings().get("enabled")), "running": running(),
                          **cfg.read_json(str(_path(STATE)))}, ensure_ascii=True))
        return 0
    if args.background:
        config = settings()
        if config.get("command") and not config.get("enabled"):
            _write(CONFIG, {**config, "enabled": True})
        return 0 if start() else 1
    if args.autostart:
        return 0 if not settings().get("enabled") or start() else 1
    return run()
