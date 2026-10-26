"""Langflow flow JSON 适配器。

能静态解析的组件才建资产；动态字段缺失记录 gap，不推断为完整流程。
"""

from urllib.parse import urlsplit

from .base import BaseAdapter, DiscoveryResult, build_asset, edge

FLOW_KEYS = ("nodes",)
AGENT_NODE_MARKERS = ("agent", "llm", "openai", "chat", "model", "tool")


class LangflowAdapter(BaseAdapter):
    name = "langflow"

    def supports(self, facts) -> bool:
        return any(self._flow_nodes(doc) is not None for doc in facts.configs.values())

    @staticmethod
    def _flow_nodes(doc):
        if not isinstance(doc.data, dict):
            return None
        data = doc.data
        if isinstance(data.get("data"), dict) and isinstance(data["data"].get("nodes"), list):
            return data["data"]
        if isinstance(data.get("nodes"), list):
            return data
        return None

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        for path, doc in sorted(facts.configs.items()):
            flow = self._flow_nodes(doc)
            if flow is None:
                continue
            name = str(doc.data.get("name") or path.rsplit("/", 1)[-1])
            entry = facts.index.get(path)
            app = build_asset(
                context, "AgentApplication", f"flow:{path}", name, relative_path=path,
                content_digest=entry.digest if entry else "",
                discovery_method="flow_json", confidence="medium",
                metadata={"adapter": self.name, "format": "langflow", "files": [path],
                          "node_count": len(flow.get("nodes") or []),
                          "dynamic_fields": self._dynamic_gaps(flow)},
            )
            result.assets.append(app)
            result.evidence.append(facts.evidence_for(
                path, line=0, excerpt=f"langflow flow {name}", parser="config", pointer="/data"))

            for node in flow.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                self._discover_node(facts, context, result, path, app, node)
        return result

    def _discover_node(self, facts, context, result, path, app, node) -> None:
        node_type = str(node.get("type") or "")
        node_id = str(node.get("id") or node_type)
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        marker = (node_type + " " + str(data.get("model") or "")).lower()
        declared_tools = data.get("mcp_tools")

        if any(part in marker for part in AGENT_NODE_MARKERS) and data:
            model = str(data.get("model") or data.get("model_name") or "")
            base_url = str(data.get("base_url") or data.get("api_base") or "")
            if model or base_url:
                host = _host_of(base_url)
                identity = f"{node_type or 'component'}:{model or host or node_id}"
                model_asset = build_asset(
                    context, "ModelReference", f"model:{identity}", model or node_type,
                    relative_path=path, discovery_method="flow_json", confidence="medium",
                    metadata={"adapter": self.name, "model": model, "provider": node_type,
                              "service_host": host, "stub": "stub" in (model + base_url).lower(),
                              "node_id": node_id},
                )
                result.assets.append(model_asset)
                result.evidence.append(facts.evidence_for(
                    path, line=0, excerpt=f"node {node_id} model={model or host}",
                    parser="config", pointer=f"/data/nodes/{node_id}"))
                result.edges.append(edge(app.asset_id, "USES_MODEL", model_asset.asset_id,
                                         confidence="medium", basis="declared"))

        if isinstance(declared_tools, list):
            for server_name in declared_tools:
                target_id = facts.servers_by_name.get(str(server_name))
                if target_id is None:
                    target = build_asset(
                        context, "MCPServer", f"mcp:{server_name}", str(server_name),
                        relative_path=path, discovery_method="flow_json", confidence="low",
                        metadata={"adapter": self.name, "declared_by": app.name,
                                  "note": "flow 声明引用，未找到对应服务实现"},
                    )
                    result.assets.append(target)
                    facts.servers_by_name.setdefault(str(server_name), target.asset_id)
                    target_id = target.asset_id
                evidence = facts.evidence_for(
                    path, line=0, excerpt=f"node {node_id} mcp_tools -> {server_name}",
                    parser="config", pointer=f"/data/nodes/{node_id}/mcp_tools")
                result.evidence.append(evidence)
                result.edges.append(edge(app.asset_id, "CONNECTS_TO", target_id,
                                         confidence="medium", basis="declared",
                                         evidence_ids=[evidence.evidence_id]))

    @staticmethod
    def _dynamic_gaps(flow) -> list:
        gaps = []
        for node in flow.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            data = node.get("data")
            if data is None:
                gaps.append(f"node {node.get('id')} 无 data，动态字段留缺口")
            elif isinstance(data, str):
                gaps.append(f"node {node.get('id')} data 为字符串，未能静态解析")
        return gaps[:20]


def _host_of(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return host
