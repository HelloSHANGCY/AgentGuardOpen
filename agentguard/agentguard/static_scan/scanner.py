"""扫描编排：快照 → 解析 → 资产发现 → 数据流 → 规则 → 持久化。

阶段推进通过数据库心跳暴露进度；有限失败进入 PARTIAL 并保留已有结果。
"""

import os
from dataclasses import replace

from ..core.asset_snapshot import snapshot_file_limit
from ..rules.library import flush_hits
from .adapters import DEFAULT_ADAPTERS
from .adapters.base import ADAPTER_VERSIONS, build_asset, merge_result
from .analysis.decode import DecodeBudget
from .analysis.facts import EvidenceFactory, FactStore
from .analysis.summaries import build_summaries
from .inputs import InputError, Limits, authorized_source, read_verified_text, snapshot_root
from .inventory import CONFIG_CATEGORIES
from .models import SEVERITY_RANK, Coverage, ScanContext, utc_now
from .parsers.config import parse_config
from .parsers.deps import parse_dockerfile, parse_lockfile, parse_package_json, parse_requirements
from .parsers.markdown import parse_markdown
from .parsers.py_ast import parse_python
from .rules import evaluate_all
from .rules.ruleset import load_ruleset
from .snapshots import cleanup_snapshot

MAX_UNRESOLVED_REFS = 50


class ScanCancelled(Exception):
    pass


class ScanFailed(Exception):
    pass


def run_scan(scan_id: str, repository, sources: dict, limits: Limits = None,
             ruleset=None, progress=None) -> object:
    try:
        return _run_scan(scan_id, repository, sources, limits, ruleset, progress)
    finally:
        flush_hits()
        cleanup_snapshot(repository, repository.get_scan(scan_id))


def _run_scan(scan_id: str, repository, sources: dict, limits=None, ruleset=None, progress=None):
    """同步执行一次扫描；调用方负责子进程隔离与超时终止。"""
    record = repository.get_scan(scan_id)
    if record is None:
        raise ScanFailed(f"scan not found: {scan_id}")
    limits = limits or Limits()
    if record.device_id:
        limits = replace(limits, max_file_parse_bytes=snapshot_file_limit(record.limits))
    ruleset = ruleset or load_ruleset()

    def emit(phase: str, percent: int) -> None:
        repository.update_scan(scan_id, phase=phase, progress=max(0, min(100, int(percent))),
                               heartbeat_at=utc_now())
        if progress:
            progress(phase, percent)

    def check_cancel() -> None:
        if repository.is_cancel_requested(scan_id):
            raise ScanCancelled("cancel requested")

    try:
        if record.source_path:
            # API 创建时已按授权根白名单校验；此处复核目录仍存在。
            root = os.path.realpath(record.source_path)
            if not os.path.isdir(root):
                raise InputError("设备快照不可用，请重新采集" if record.device_id else
                                 f"source path is not a directory: {record.source_path!r}")
        else:
            root = authorized_source(record.source_id, sources)
    except Exception as exc:
        repository.update_scan(scan_id, status="FAILED", phase="QUEUED", error=str(exc)[:300],
                               finished_at=utc_now())
        raise ScanFailed(str(exc))

    context = ScanContext(
        scan_id=scan_id, project_id=record.project_id, source_id=record.source_id,
        root=root, profile=record.profile or "default",
        ruleset_version=ruleset.version, adapter_versions=dict(ADAPTER_VERSIONS),
        limits=limits.as_dict(),
        device_id=record.device_id, agent=record.agent,
        workspace_id=record.collection.get("workspace_id", ""),
    )

    emit("SNAPSHOTTING", 5)
    index = snapshot_root(root, limits)
    context.source_digest = index.snapshot_signature()
    repository.update_scan(scan_id, source_digest=context.source_digest,
                           source_id=record.source_id)
    check_cancel()

    emit("DISCOVERING", 15)
    facts = _parse_project(context, index, limits)
    check_cancel()

    adapters_run = []
    _create_config_artifacts(facts, context)
    for adapter_cls in DEFAULT_ADAPTERS:
        adapter = adapter_cls()
        if not adapter.supports(facts):
            continue
        result = adapter.discover(facts, context)
        merge_result(facts, result)
        adapters_run.append(adapter.name)
    context.adapter_versions = {name: ADAPTER_VERSIONS.get(name, "0.1") for name in adapters_run}
    if record.device_id:
        _device_assets(facts, context, record)
    facts.notes.append(f"adapters={','.join(adapters_run) or 'none'}")
    check_cancel()

    emit("ANALYZING", 60)
    facts.summaries = build_summaries(facts.py_modules, limits, facts.decode_budget)
    findings = evaluate_all(facts, context, ruleset)
    findings = _dedupe_findings(findings)
    facts.vulnerability_db = facts.vulnerability_db or {"status": "unavailable"}

    emit("FINALIZING", 90)
    check_cancel()
    coverage = _build_coverage(facts, index)
    repository.save_results(scan_id, list(facts.assets.values()), list(facts.edges.values()),
                            list(facts.evidence.values()), findings, coverage)
    status = "PARTIAL" if _is_partial(facts, index) else "COMPLETED"
    repository.update_scan(
        scan_id, status=status, phase="FINALIZING", progress=100,
        ruleset_version=ruleset.version,
        adapter_versions=context.adapter_versions,
        vulnerability_db_version=str(facts.vulnerability_db.get("db_version", "")),
        finished_at=utc_now(), heartbeat_at=utc_now(),
        # 单文件失败等覆盖缺口已保存在 coverage.notes，不属于整次任务异常。
        error="",
    )
    return repository.get_scan(scan_id)


def _device_assets(facts, context, record):
    """来源由管理面任务指定，终端上传不能冒认别的设备/Agent。"""
    facts.collection = record.collection
    agent = build_asset(context, "AgentApplication", f"device:{record.device_id}:{record.agent}", record.agent,
                        discovery_method="device_snapshot", confidence="high",
                        metadata={"device_id": record.device_id, "agent": record.agent,
                                  "scope": record.collection.get("scope"), "basis": "observed_snapshot"})
    facts.add_asset(agent)
    for asset in list(facts.assets.values()):
        asset.metadata.update({"device_id": record.device_id, "agent": record.agent})
        if asset.asset_id == agent.asset_id:
            continue
        relation = {"ConfigArtifact": "CONFIGURED_BY", "Skill": "LOADS_SKILL", "MCPServer": "CONNECTS_TO"}.get(asset.kind)
        if relation:
            facts.add_edge(agent.asset_id, relation, asset.asset_id, confidence="high", basis="observed_snapshot")
    gaps = record.collection.get("skipped", [])
    facts.notes.append(f"设备={record.device_id}; Agent={record.agent}; 范围={record.collection.get('scope')}")
    facts.notes.append("设备提供的只读脱敏快照；未覆盖账号凭证、会话历史、外部 MCP 源码及未采集文件")
    for gap in gaps:
        facts.gaps.append(f"collection_gap:{gap.get('path') or '.'}:{gap.get('reason')}")
        limit = {"max_files": "max_files", "max_depth": "max_depth", "total_bytes": "max_total_bytes",
                 "file_too_large": "max_file_parse_bytes", "collection_timeout": "collection_timeout"}.get(gap.get("reason"))
        if limit:
            facts.index.limit_hits.append({"limit": limit, "path": gap.get("path", "")})
    omitted = record.collection.get("skipped_total", len(gaps)) - len(gaps)
    if omitted > 0:
        facts.gaps.append(f"collection_gap:.:additional_skipped={omitted}")


# ---------- 解析 ----------

def _parse_project(context: ScanContext, index, limits: Limits) -> FactStore:
    facts = FactStore(context=context, limits=limits, index=index,
                      evidence_factory=EvidenceFactory(context.scan_id))
    facts.decode_budget = DecodeBudget(limits)
    for entry in index.files:
        if entry.parse_skip:
            continue
        if entry.category not in ("python", "markdown", "skill_md") and entry.category not in CONFIG_CATEGORIES:
            continue
        text = read_verified_text(context.root, entry, limits)
        if text is None:
            facts.gaps.append(f"read_failed:{entry.path}:{entry.read_error}")
            continue
        try:
            if entry.category == "python":
                module = parse_python(entry.path, text, facts.decode_budget)
                facts.py_modules[entry.path] = module
                if module.parse_error:
                    facts.gaps.append(f"parse_error:{entry.path}:{module.parse_error}")
                if module.decode_limit_hit:
                    facts.notes.append(f"decode_limit:{entry.path}")
            elif entry.category in ("markdown", "skill_md"):
                facts.markdown[entry.path] = parse_markdown(entry.path, text)
            else:
                doc = parse_config(entry.path, text, entry.category, limits)
                facts.configs[entry.path] = doc
                if doc.parse_error:
                    facts.gaps.append(f"parse_error:{entry.path}:{doc.parse_error}")
                _collect_dependencies(facts, entry.path, doc)
        except RecursionError:
            facts.gaps.append(f"parse_error:{entry.path}:RecursionError")
        except Exception as exc:  # 单个文件解析失败不终止扫描
            facts.gaps.append(f"parse_error:{entry.path}:{exc.__class__.__name__}:{str(exc)[:80]}")
    _dedupe_dependencies(facts)
    return facts


def _collect_dependencies(facts: FactStore, path: str, doc) -> None:
    name = os.path.basename(path).lower()
    if doc.category == "requirements":
        facts.dependencies.extend(parse_requirements(path, doc.raw))
    elif doc.category == "lockfile":
        facts.dependencies.extend(parse_lockfile(path, doc.raw))
    elif doc.category == "dockerfile":
        deps, _unpinned = parse_dockerfile(path, doc.raw)
        facts.dependencies.extend(deps)
    elif doc.category == "json" and name == "package.json":
        facts.dependencies.extend(parse_package_json(path, doc.raw))


def _dedupe_dependencies(facts: FactStore) -> None:
    seen = set()
    unique = []
    for dep in facts.dependencies:
        key = (dep.ecosystem, dep.name.lower(), dep.version, dep.specifier, dep.source_path, dep.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dep)
    facts.dependencies = unique


def _create_config_artifacts(facts: FactStore, context: ScanContext) -> None:
    for entry in facts.index.files:
        if entry.category not in CONFIG_CATEGORIES:
            continue
        asset = build_asset(
            context, "ConfigArtifact", f"config:{entry.path}", os.path.basename(entry.path),
            relative_path=entry.path, content_digest=entry.digest,
            discovery_method="file_index", confidence="high",
            metadata={"category": entry.category, "adapter": "scanner"},
        )
        facts.add_asset(asset)
        facts.add_evidence(facts.evidence_for(
            entry.path, line=1, excerpt=entry.path, parser="file_index", pointer="/"))


# ---------- 结果整理 ----------

def _dedupe_findings(findings: list) -> list:
    seen = {}
    for finding in findings:
        key = (finding.rule_id, finding.asset_id, finding.fingerprint)
        if key in seen:
            continue
        seen[key] = finding
    ordered = sorted(seen.values(), key=lambda item: (-SEVERITY_RANK.get(item.severity, 0),
                                                      item.rule_id, item.asset_id))
    return ordered


def _build_coverage(facts: FactStore, index) -> Coverage:
    parsed = (sum(not module.parse_error for module in facts.py_modules.values()) + len(facts.markdown)
              + sum(not doc.parse_error for doc in facts.configs.values()))
    failed = sum(1 for gap in facts.gaps if gap.startswith(("parse_error:", "read_failed:")))
    skipped = (len(index.skipped) + sum(1 for entry in index.files if entry.parse_skip)
               + facts.collection.get("skipped_total", len(facts.collection.get("skipped", []))))
    unresolved = []
    if facts.summaries:
        for summary in facts.summaries.functions.values():
            for item in summary.unresolved:
                marker = f"{summary.module}:{summary.name}:{item}"
                if marker not in unresolved:
                    unresolved.append(marker)
    limit_hits = list(index.limit_hits)
    if facts.decode_budget and facts.decode_budget.decode_ops:
        limit_hits.append({"limit": "decode_operations", "count": facts.decode_budget.decode_ops})
    return Coverage(
        scan_id=facts.context.scan_id, indexed_files=len(index.files), parsed_files=parsed,
        failed_files=failed, skipped_files=skipped, languages=index.language_counts(),
        unresolved_refs=unresolved[:MAX_UNRESOLVED_REFS], limit_hits=limit_hits,
        vulnerability_db=dict(facts.vulnerability_db),
        notes=(facts.notes + facts.gaps)[:100],
    )


def _is_partial(facts: FactStore, index) -> bool:
    if index.truncated or any(gap.startswith(("parse_error:", "read_failed:", "collection_gap:")) for gap in facts.gaps):
        return True
    vuln = facts.vulnerability_db or {}
    if vuln.get("status") in ("unavailable", "stale"):
        return True
    return any(gap.startswith("rule ") for gap in facts.gaps)
