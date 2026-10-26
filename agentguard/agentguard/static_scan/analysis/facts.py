"""扫描事实存储与资产/证据构建。

FactStore 汇总解析结果（AST、配置、Markdown、依赖、数据流），
同时作为适配器与规则的共享写入面：适配器写资产/证据，规则读事实并写 finding。
"""

from dataclasses import dataclass, field

from ..inventory import FileIndex
from ..models import Asset, Edge, Evidence, digest_text, redact_excerpt

# 规则按最具体资产归属：Tool > MCPServer > Skill > AgentApplication ...
ASSET_PRIORITY = (
    "Tool", "MCPServer", "Skill", "SecretReference", "ModelReference",
    "AgentApplication", "Framework", "Dependency", "Endpoint", "ConfigArtifact",
)


class EvidenceFactory:
    """证据去重与稳定 ID：同一路径/行列/片段只保留一条。"""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._by_key: dict = {}

    def make(self, path: str, line: int = 0, excerpt: str = "", parser: str = "",
             pointer: str = "", column: int = 0, transform_chain: list = None) -> Evidence:
        clean = redact_excerpt(excerpt, 240)
        key = (path, int(line), pointer, digest_text(clean))
        existing = self._by_key.get(key)
        if existing is not None:
            return existing
        evidence = Evidence(
            evidence_id="ev-" + digest_text(f"{self.scan_id}|{key}", 20),
            scan_id=self.scan_id, path=path, line=int(line), column=int(column),
            pointer=pointer, excerpt=clean, excerpt_digest=digest_text(clean),
            parser=parser, transform_chain=list(transform_chain or []),
        )
        self._by_key[key] = evidence
        return evidence


@dataclass
class FactStore:
    context: object
    limits: object
    index: FileIndex
    evidence_factory: EvidenceFactory
    py_modules: dict = field(default_factory=dict)
    configs: dict = field(default_factory=dict)
    markdown: dict = field(default_factory=dict)
    dependencies: list = field(default_factory=list)
    summaries: object = None
    decode_budget: object = None
    assets: dict = field(default_factory=dict)
    edges: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    gaps: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    mcp_handlers: dict = field(default_factory=dict)  # (module path, func) -> tool asset_id
    mcp_on_start: dict = field(default_factory=dict)
    servers_by_name: dict = field(default_factory=dict)
    env_defaults: list = field(default_factory=list)  # 代码内 os.getenv 默认值事实
    secret_refs: dict = field(default_factory=dict)  # 变量名 -> asset_id
    vulnerability_db: dict = field(default_factory=dict)
    collection: dict = field(default_factory=dict)
    _assets_by_path: dict = field(default_factory=dict)

    # ---- 适配器写入面 ----

    def add_asset(self, asset: Asset) -> Asset:
        existing = self.assets.get(asset.asset_id)
        if existing is not None:
            existing.metadata.update(asset.metadata)
            if not existing.relative_path:
                existing.relative_path = asset.relative_path
            if not existing.version:
                existing.version = asset.version
            return existing
        self.assets[asset.asset_id] = asset
        self._index_asset_path(asset)
        return asset

    def _index_asset_path(self, asset: Asset) -> None:
        for path in [asset.relative_path] + list(asset.metadata.get("files") or []):
            if path:
                self._assets_by_path.setdefault(path, []).append(asset.asset_id)
        handler = asset.metadata.get("handler")
        handler_file = asset.metadata.get("handler_file")
        if handler and handler_file:
            self._assets_by_path.setdefault(handler_file, []).append(asset.asset_id)

    def add_edge(self, source_asset_id: str, relation: str, target_asset_id: str,
                 confidence: str = "medium", basis: str = "declared",
                 evidence_ids: list = None, metadata: dict = None) -> Edge | None:
        if not source_asset_id or not target_asset_id:
            return None
        key = (source_asset_id, relation, target_asset_id, basis)
        if key in self.edges:
            existing = self.edges[key]
            for evidence_id in evidence_ids or []:
                if evidence_id not in existing.evidence_ids:
                    existing.evidence_ids.append(evidence_id)
            return existing
        edge = Edge(edge_id="edge-" + digest_text("|".join(key), 16), scan_id=self.context.scan_id,
                    source_asset_id=source_asset_id, relation=relation, target_asset_id=target_asset_id,
                    confidence=confidence, basis=basis, evidence_ids=list(evidence_ids or []),
                    metadata=metadata or {})
        self.edges[key] = edge
        return edge

    def add_evidence(self, evidence: Evidence) -> Evidence:
        self.evidence[evidence.evidence_id] = evidence
        return evidence

    def evidence_for(self, path: str, line: int = 0, excerpt: str = "", parser: str = "",
                     pointer: str = "", column: int = 0, transform_chain: list = None) -> Evidence:
        evidence = self.evidence_factory.make(path, line, excerpt, parser, pointer, column, transform_chain)
        return self.add_evidence(evidence)

    # ---- 查询面 ----

    def asset_for_path(self, path: str, kinds=None) -> Asset | None:
        candidates = [self.assets[asset_id] for asset_id in self._assets_by_path.get(path, [])
                      if asset_id in self.assets]
        if kinds:
            wanted = set(kinds)
            candidates = [asset for asset in candidates if asset.kind in wanted] or candidates
        if not candidates:
            return None
        return sorted(candidates, key=lambda asset: ASSET_PRIORITY.index(asset.kind)
                      if asset.kind in ASSET_PRIORITY else 99)[0]

    def assets_of_kind(self, *kinds) -> list:
        wanted = set(kinds)
        return [asset for asset in self.assets.values() if asset.kind in wanted]

    def asset_by_logical(self, kind: str, logical_key: str) -> Asset | None:
        target = self.context.asset_id(kind, logical_key)
        return self.assets.get(target)

    def asset_by_name(self, kind: str, name: str) -> Asset | None:
        for asset in self.assets.values():
            if asset.kind == kind and asset.name == name:
                return asset
        return None

    def configs_of(self, *categories: str) -> list:
        wanted = set(categories)
        return [doc for doc in self.configs.values() if doc.category in wanted]

    def config_facts(self, predicate=None) -> list:
        facts = []
        for doc in self.configs.values():
            for fact in doc.facts:
                if predicate is None or predicate(fact):
                    facts.append(fact)
        return facts

    def flows_for(self, module_path: str) -> list:
        if self.summaries is None:
            return []
        return self.summaries.flows_for(module_path)

    def skill_owner(self, path: str) -> str:
        entry = self.index.get(path)
        return entry.skill_dir if entry else ""

    def file_text(self, path: str) -> str:
        module = self.py_modules.get(path)
        if module is not None:
            return module.source
        doc = self.configs.get(path)
        if doc is not None:
            return doc.raw
        markdown = self.markdown.get(path)
        if markdown is not None:
            return ""
        entry = self.index.get(path)
        return entry.path if entry else ""

    def handler_of(self, module_path: str, function: str) -> str:
        """函数是否绑定为 MCP 工具/启动回调；返回工具资产 ID。"""
        return self.mcp_handlers.get((module_path, function), "")

    def is_mcp_on_start(self, module_path: str, function: str) -> bool:
        return (module_path, function) in self.mcp_on_start
