"""上游 MCP 运行时工具清单（设计 §5.3）。

网关在首次可用时自行完成 initialize + tools/list，形成带时间与过期时间的
运行时清单；同时扫描工具描述中的提示注入标记（AG-RUNTIME-009 的来源侧）。
清单刷新失败时继续使用未过期的最后可信版本；没有任何可信清单时返回 None，
由引擎对副作用工具默认拒绝。
"""

import threading
import time

import httpx

from ..config import Settings
from ..core.normalize import injection_markers
from ..rules.trace import observe_features
from .mcp_http import SESSION_HEADER, parse_jsonrpc, passthrough_headers


class ServerManifest:
    def __init__(self, server: str, tools: dict[str, dict]) -> None:
        self.server = server
        self.tools = tools           # tool name -> {description, inputSchema}
        self.fetched_at = time.time()
        self.poisoned_tools: set[str] = set()
        self.poisoned_features: list[dict] = []

    @property
    def known_tools(self) -> set:
        return set(self.tools)

    def as_dict(self) -> dict:
        return {
            "server": self.server,
            "tools": sorted(self.tools),
            "poisoned_tools": sorted(self.poisoned_tools),
            "fetched_at": self.fetched_at,
            "expired": time.time() - self.fetched_at > 3600,
        }


class ManifestRegistry:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.Client(timeout=settings.upstream_timeout_seconds)
        self._lock = threading.Lock()
        self._cache: dict[str, ServerManifest] = {}

    def scan_poison(self, manifest: ServerManifest) -> None:
        for name, spec in manifest.tools.items():
            markers, features = observe_features(injection_markers, spec.get("description", ""))
            if markers:
                manifest.poisoned_tools.add(name)
                for feature in features:
                    if feature not in manifest.poisoned_features:
                        manifest.poisoned_features.append(feature)

    def fetch(self, server: str, endpoint: str) -> ServerManifest | None:
        """initialize + tools/list；成功则更新缓存，失败保留旧缓存。"""
        try:
            init = self._client.post(endpoint, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agentguard"}},
            })
            # Streamable HTTP server 在 initialize 下发会话：后续请求必须携带，并先完成初始化通知。
            headers = passthrough_headers(init.headers)
            if SESSION_HEADER in headers:
                self._client.post(endpoint, headers=headers,
                                  json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            response = self._client.post(endpoint, headers=headers,
                                         json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            payload = parse_jsonrpc(response, 2)
            tools = {tool["name"]: tool for tool in (payload.get("result") or {}).get("tools", []) if tool.get("name")}
            manifest = ServerManifest(server, tools)
            self.scan_poison(manifest)
            with self._lock:
                self._cache[server] = manifest
            return manifest
        except Exception:
            return self.get_cached(server)

    def register(self, key: str, tools: list) -> ServerManifest:
        """stdio 包装器上报的 tools/list（网关无法主动拉取本机进程的清单）。

        key 由调用方按设备命名空间化（device_id:server），设备上报不能覆盖网关自拉的清单。
        """
        specs = {str(tool["name"]): tool for tool in tools or [] if isinstance(tool, dict) and tool.get("name")}
        manifest = ServerManifest(key, specs)
        self.scan_poison(manifest)
        with self._lock:
            self._cache[key] = manifest
        return manifest

    def get_cached(self, server: str) -> ServerManifest | None:
        with self._lock:
            return self._cache.get(server)

    def ensure(self, server: str, endpoint: str) -> ServerManifest | None:
        """返回可信清单：缓存未过期直接用，否则刷新；全部失败返回 None。"""
        cached = self.get_cached(server)
        if cached and time.time() - cached.fetched_at < self.settings.manifest_ttl_seconds:
            return cached
        return self.fetch(server, endpoint)

    def poisoned_servers(self) -> set:
        with self._lock:
            return {server for server, manifest in self._cache.items() if manifest.poisoned_tools}

    def snapshot(self) -> dict:
        with self._lock:
            return {server: manifest.as_dict() for server, manifest in self._cache.items()}
