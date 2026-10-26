"""网关主入口：组装 MCP 数据面、查询面与控制台。

部署形态见 Dockerfile / start.sh：网关与独立扫描、评测 worker。
事件与决策统一汇聚到本进程的 RuntimeStore。

应用由工厂函数创建（uvicorn --factory agentguard.main:create_app），导入本模块没有副作用。
"""

import threading
from contextlib import asynccontextmanager

import anyio.to_thread
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .agents.api import build_agent_api
from .agents.control import HookControl
from .agents.deploy import DeployConfig
from .agents.devices import DeviceRegistry
from .agents.enroll import EnrollmentQueue
from .api import CONSOLE_DIR, build_api
from .config import load_settings
from .detection.api import build_detection_api
from .detection.engine import RuntimeDecisionEngine
from .evaluation import build_evaluation_api
from .gateway.correlation import PendingCalls
from .gateway.inspector import McpInspector
from .gateway.manifest import ManifestRegistry
from .gateway.mcp import build_gateway
from .llm.api import build_llm_api
from .rules.api import build_rules_api, sync_rules_version
from .rules.library import library as rule_library
from .static_scan.api import build_static_api
from .static_scan.device_api import build_device_scan_api
from .static_scan.repository import Repository
from .storage.context import TaskContextService
from .storage.store import RuntimeStore


def create_app() -> FastAPI:
    settings = load_settings()
    # 特征规则库：加载内置与自定义规则包、按控制台启停状态注入，规则版本随生效集合变化。
    rules = rule_library()
    rules.apply()
    sync_rules_version(settings, rules)
    store = RuntimeStore(db_path=settings.runtime_db_path, retention_days=settings.runtime_retention_days)
    contexts = TaskContextService(ttl_seconds=settings.task_ttl_seconds)
    manifests = ManifestRegistry(settings)
    engine = RuntimeDecisionEngine(settings)
    engine.judge.attach_rules(rules)

    app = FastAPI(title="AgentGuard Runtime Gateway", version="0.1.0", lifespan=_lifespan(store, settings))
    # Hook 与 MCP 中转共享调用关联表与检查器，三条路径判定一致（通用 Agent 接入设计 §8）。
    pending = PendingCalls()
    inspector = McpInspector(settings, store, contexts, manifests, engine, pending)
    devices = DeviceRegistry(settings.agent_devices, data_dir=settings.agent_device_dir)
    app.include_router(build_gateway(settings, store, contexts, manifests, engine, pending, inspector))
    app.include_router(build_api(settings, store, contexts, manifests))
    controls = HookControl(data_dir=settings.agent_device_dir)
    enrollments = EnrollmentQueue(data_dir=settings.agent_device_dir)
    app.include_router(build_agent_api(settings, store, contexts, manifests, engine, inspector, devices, controls,
                                       enrollments, deploy=DeployConfig(data_dir=settings.agent_device_dir)))
    app.include_router(build_detection_api(settings, engine, devices))
    app.include_router(build_llm_api(settings, store, engine))
    app.include_router(build_evaluation_api())
    app.include_router(build_rules_api(settings, rules))
    if settings.static_enabled:
        # 静态扫描查询面：独立 SQLite，worker 故障或扫描超时不阻塞网关。
        repository = Repository(settings.static_db_path)
        app.include_router(build_static_api(settings, repository, devices))
        app.include_router(build_device_scan_api(repository, devices))
    # 控制台静态资源：Vite 构建产物（离线打包，运行时无需外网）。
    app.mount("/console/assets", StaticFiles(directory=f"{CONSOLE_DIR}/dist/assets", check_dir=False),
              name="console-assets")

    @app.get("/health")
    def health():
        return {"status": "ok", "component": "agentguard-gateway"}

    return app


def _cleanup_loop(store: RuntimeStore, max_age: float, stop: threading.Event) -> None:
    # 状态清理：任务信封与污点状态按 TTL 回收，避免内存增长。
    while not stop.wait(60):
        store.cleanup_states(max_age)


def _lifespan(store: RuntimeStore, settings):
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Hook 请求在线程池中同步处理；大模型危险审批可能让单个请求等待数十秒，放大线程池避免互相排队。
        anyio.to_thread.current_default_thread_limiter().total_tokens = 200
        stop = threading.Event()
        threading.Thread(target=_cleanup_loop, args=(store, settings.task_ttl_seconds * 3, stop), daemon=True).start()
        try:
            yield
        finally:
            stop.set()
            rule_library().hit_counter.flush()
            # 退出前把排队中的运行时数据写完。
            store.close()

    return lifespan

