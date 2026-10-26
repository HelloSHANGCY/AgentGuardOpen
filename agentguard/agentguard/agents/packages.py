"""终端客户端下载（GET /v1/agents/client、/v1/agents/client/{name}）。

终端主机直接从服务端取客户端，不必另行分发：
- agentguard-endpoint.tar.gz：脚本形态（只依赖标准库，Python 3.8+），由 endpoint/ 源码现场打包，总是可用；
- 预构建包：endpoint/dist/ 下的 agentguard-endpoint-<平台>.{tar.gz,zip}（build_linux.sh / build_windows.ps1
  的产物，例如 linux-x64 二进制、windows-x64 exe），存在才提供。

客户端代码不含任何密钥，下载无需鉴权；文件名按白名单匹配，不接受路径。
"""

from __future__ import annotations

import gzip
import io
import os
import re
import tarfile
import threading
from datetime import datetime, timezone

SCRIPT_PACKAGE = "agentguard-endpoint.tar.gz"
DIST_NAME_RE = re.compile(r"^agentguard-endpoint-([a-z0-9]+-[a-z0-9_]+)\.(tar\.gz|zip)$")
TOP = "agentguard-endpoint"
VERSION_RE = re.compile(r'^VERSION = "([^"]+)"', re.M)


def default_endpoint_dir() -> str:
    # 仓库与镜像中 endpoint/ 都与 agentguard/ 包同级。
    return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "endpoint"))


class ClientPackages:
    def __init__(self, endpoint_dir: str = "", dist_dir: str = "") -> None:
        self.endpoint_dir = endpoint_dir or default_endpoint_dir()
        self.dist_dir = dist_dir or os.path.join(self.endpoint_dir, "dist")
        self._lock = threading.Lock()
        self._script: tuple[str, bytes] | None = None   # (源码指纹, tar.gz)

    def version(self) -> str:
        try:
            with open(os.path.join(self.endpoint_dir, "agentguard_endpoint", "__init__.py"), encoding="utf-8") as fh:
                match = VERSION_RE.search(fh.read())
            return match.group(1) if match else ""
        except OSError:
            return ""

    def _sources(self) -> list[tuple[str, str]]:
        """(包内路径, 本地路径)：入口脚本、README 与 agentguard_endpoint/ 下的 .py。"""
        files = [(name, os.path.join(self.endpoint_dir, name)) for name in ("agentguard-endpoint.py", "README.md")]
        package = os.path.join(self.endpoint_dir, "agentguard_endpoint")
        for root, dirs, names in os.walk(package):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for name in sorted(names):
                if name.endswith(".py"):
                    path = os.path.join(root, name)
                    files.append((os.path.relpath(path, self.endpoint_dir).replace(os.sep, "/"), path))
        return [(arc, path) for arc, path in files if os.path.isfile(path)]

    def script_package(self) -> bytes | None:
        sources = self._sources()
        if not any(arc == "agentguard-endpoint.py" for arc, _ in sources):
            return None
        fingerprint = "|".join(f"{arc}:{os.path.getmtime(path)}:{os.path.getsize(path)}" for arc, path in sources)
        with self._lock:
            if self._script and self._script[0] == fingerprint:
                return self._script[1]
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for arc, path in sources:
                    with open(path, "rb") as handle:
                        data = handle.read()
                    info = tarfile.TarInfo(f"{TOP}/{arc}")
                    info.size, info.mode = len(data), 0o755 if arc == "agentguard-endpoint.py" else 0o644
                    tar.addfile(info, io.BytesIO(data))
            blob = gzip.compress(raw.getvalue(), mtime=0)
            self._script = (fingerprint, blob)
            return blob

    def _dist(self) -> list[str]:
        try:
            return sorted(name for name in os.listdir(self.dist_dir)
                          if DIST_NAME_RE.match(name) and os.path.isfile(os.path.join(self.dist_dir, name)))
        except OSError:
            return []

    def list(self) -> list[dict]:
        version = self.version()
        packages = []
        script = self.script_package()
        if script is not None:
            packages.append({"name": SCRIPT_PACKAGE, "platform": "any", "kind": "script", "size": len(script),
                             "version": version, "requires": "python3 >= 3.8"})
        for name in self._dist():
            path = os.path.join(self.dist_dir, name)
            built = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat(timespec="seconds")
            packages.append({"name": name, "platform": DIST_NAME_RE.match(name).group(1), "kind": "binary",
                             "size": os.path.getsize(path), "built_at": built})
        return packages

    def get(self, name: str) -> tuple[bytes | str, str] | None:
        """(内容或文件路径, 媒体类型)；没有该包时返回 None。"""
        if name == SCRIPT_PACKAGE:
            script = self.script_package()
            return (script, "application/gzip") if script is not None else None
        if name in self._dist():
            media = "application/zip" if name.endswith(".zip") else "application/gzip"
            return os.path.join(self.dist_dir, name), media
        return None
