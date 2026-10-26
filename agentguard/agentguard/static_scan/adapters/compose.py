"""Compose 适配器：MCP 服务、配置归属与条件启动关系。

只读取配置，不运行 Compose；对同一 server 的同名映射不自动跨环境合并。
"""

from ..parsers.config import compose_services
from .base import BaseAdapter, DiscoveryResult, build_asset, edge

MCP_NAME_PREFIXES = ("mcp-", "mcp_")


class ComposeAdapter(BaseAdapter):
    name = "compose"

    def supports(self, facts) -> bool:
        return any(doc.category == "compose" for doc in facts.configs.values())

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        for path, doc in sorted(facts.configs.items()):
            if doc.category != "compose":
                continue
            config_id = facts.asset_by_logical("ConfigArtifact", f"config:{path}")
            services = compose_services(doc)
            evidence = facts.evidence_for(path, line=0, excerpt=f"services={len(services)}",
                                          parser="config", pointer="/services")
            result.evidence.append(evidence)
            for service_name, service in services.items():
                if not isinstance(service, dict) or not _is_mcp_service(service_name, service):
                    continue
                canonical = _canonical_name(service_name)
                target_id = (facts.servers_by_name.get(canonical)
                             or facts.servers_by_name.get(service_name))
                if target_id is None:
                    target = build_asset(
                        context, "MCPServer", f"mcp:{canonical}", canonical,
                        relative_path=path, discovery_method="compose_service",
                        confidence="medium",
                        metadata={"adapter": self.name, "transport": "http",
                                  "service": service_name,
                                  "image": str(service.get("image") or service.get("build") or "")},
                    )
                    result.assets.append(target)
                    facts.servers_by_name[canonical] = target.asset_id
                    target_id = target.asset_id
                if config_id is not None:
                    result.edges.append(edge(target_id, "CONFIGURED_BY", config_id.asset_id,
                                             confidence="high", basis="declared",
                                             evidence_ids=[evidence.evidence_id],
                                             metadata={"service": service_name}))
        return result


def _is_mcp_service(service_name: str, service: dict) -> bool:
    if service_name.startswith(MCP_NAME_PREFIXES):
        return True
    environment = service.get("environment") or {}
    if isinstance(environment, dict):
        server = str(environment.get("SERVER", ""))
        if "server" in server.lower():
            return True
    if isinstance(environment, list):
        for item in environment:
            if str(item).upper().startswith("SERVER="):
                return True
    command = " ".join(service.get("command") or []) if isinstance(service.get("command"), list) else str(service.get("command") or "")
    return "uvicorn" in command and "server" in command


def _canonical_name(service_name: str) -> str:
    for prefix in MCP_NAME_PREFIXES:
        if service_name.startswith(prefix):
            return service_name[len(prefix):]
    return service_name
