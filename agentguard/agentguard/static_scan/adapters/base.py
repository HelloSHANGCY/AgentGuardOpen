"""适配器协议与合并工具。

适配器是管理员部署的代码，不接受待检项目自带插件。
"""

from dataclasses import dataclass, field
from typing import Protocol

from ..models import Asset, Edge, Evidence

ADAPTER_VERSIONS = {
    "framework": "0.1",
    "skill": "0.1",
    "mcp": "0.1",
    "compose": "0.1",
    "application": "0.1",
    "langflow": "0.1",
    "claude_code": "0.1",
}


@dataclass
class DiscoveryResult:
    assets: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    gaps: list = field(default_factory=list)

    def extend(self, other: "DiscoveryResult") -> None:
        self.assets.extend(other.assets)
        self.edges.extend(other.edges)
        self.evidence.extend(other.evidence)
        self.gaps.extend(other.gaps)


class AssetAdapter(Protocol):
    name: str

    def supports(self, facts) -> bool:
        ...

    def discover(self, facts, context) -> DiscoveryResult:
        ...


class BaseAdapter:
    name = "base"

    def supports(self, facts) -> bool:
        return True

    def discover(self, facts, context) -> DiscoveryResult:
        return DiscoveryResult()


def build_asset(context, kind: str, logical_key: str, name: str, relative_path: str = "",
                content_digest: str = "", discovery_method: str = "static",
                confidence: str = "medium", version: str = "", metadata: dict = None) -> Asset:
    return Asset(
        asset_id=context.asset_id(kind, logical_key),
        project_id=context.project_id, scan_id=context.scan_id, kind=kind,
        logical_key=logical_key, name=str(name or logical_key), version=version,
        relative_path=relative_path, content_digest=content_digest,
        discovery_method=discovery_method, confidence=confidence, metadata=metadata or {},
    )


def merge_result(facts, result: DiscoveryResult) -> None:
    for evidence in result.evidence:
        facts.add_evidence(evidence)
    for asset in result.assets:
        facts.add_asset(asset)
    for edge in result.edges:
        facts.add_edge(edge.source_asset_id, edge.relation, edge.target_asset_id,
                       confidence=edge.confidence, basis=edge.basis,
                       evidence_ids=edge.evidence_ids, metadata=edge.metadata)
    for gap in result.gaps:
        facts.gaps.append(gap)


def edge(source_asset_id: str, relation: str, target_asset_id: str, scan_id: str = "",
         confidence: str = "medium", basis: str = "declared", evidence_ids: list = None,
         metadata: dict = None) -> Edge:
    return Edge(edge_id="", scan_id=scan_id, source_asset_id=source_asset_id, relation=relation,
                target_asset_id=target_asset_id, confidence=confidence, basis=basis,
                evidence_ids=list(evidence_ids or []), metadata=metadata or {})


def evidence(evidence_id: str, scan_id: str, path: str, **kwargs) -> Evidence:
    return Evidence(evidence_id=evidence_id, scan_id=scan_id, path=path, **kwargs)
