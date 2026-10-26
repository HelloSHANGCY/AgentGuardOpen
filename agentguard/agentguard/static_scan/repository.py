"""静态扫描独立 SQLite 存储：表、迁移、分页与事务。

API 与 worker 只通过数据库协调，不共享 Python 字典；
静态查询和 worker 故障不影响网关健康。
"""

import hashlib
import json
import os
import sqlite3
from collections import deque
from contextlib import contextmanager

from ..core.asset_snapshot import LEASE_SECONDS, MAX_FILE_BYTES, WAIT_SECONDS
from .models import Asset, Coverage, Finding, Review, ScanRecord, new_id, utc_now
from .notifications import DeviceScanNotifications

SCHEMA_VERSION = 3
MAX_JSON_FIELD = 16 * 1024
MAX_FLOW_STEPS = 40


def _inventory_groups(sources, aggregates):
    """设备按 device_id/agent 合并项目快照；目录按 project_id/source_id 保持独立。"""
    groups, by_scan = {}, {}
    severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    for source in sources:
        key = ("device", source["device_id"], source["agent"]) if source["device_id"] else (
            "source", source["project_id"], source["source_id"])
        if key not in groups:
            groups[key] = {"group_id": hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest(),
                           "device_id": source["device_id"], "agent": source["agent"],
                           "projects": [], "sources": [], "assets": 0, "risky_assets": 0,
                           "high_risk_assets": 0, "findings": 0, "kinds": {},
                           "risk": {"top": "", "severity": dict.fromkeys(severities, 0)},
                           "last_scanned_at": "", "partial_sources": 0}
        group = groups[key]
        by_scan[source["scan_id"]] = group
        group["sources"].append({field: source[field] for field in (
            "scan_id", "project_id", "source_id", "device_id", "agent", "status", "created_at", "finished_at")})
        if source["project_id"] not in group["projects"]:
            group["projects"].append(source["project_id"])
        group["partial_sources"] += source["status"] == "PARTIAL"
        group["last_scanned_at"] = max(group["last_scanned_at"], source["finished_at"] or source["created_at"] or "")
    for row in aggregates:
        group = by_scan[row["scan_id"]]
        for field in ("assets", "risky_assets", "high_risk_assets", "findings"):
            group[field] += row[field]
        group["kinds"][row["kind"]] = group["kinds"].get(row["kind"], 0) + row["assets"]
        for severity in severities:
            group["risk"]["severity"][severity] += row[severity.lower() + "_count"]
    for group in groups.values():
        group["kinds"] = sorted(({"kind": kind, "count": count} for kind, count in group["kinds"].items()),
                                key=lambda item: (-item["count"], item["kind"]))
        group["risk"]["top"] = next((s for s in severities if group["risk"]["severity"][s]),
                                     "UNKNOWN" if group["findings"] else "")
        group["risk_state"] = "risk" if group["findings"] else "unknown" if group["partial_sources"] else "clear"
        group["scan_status"] = "PARTIAL" if group["partial_sources"] else "COMPLETED"
    return sorted(groups.values(), key=lambda group: (
        (*severities, "UNKNOWN", "").index(group["risk"]["top"]), -group["findings"], group["group_id"]))


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_path TEXT DEFAULT '',
    profile TEXT,
    status TEXT NOT NULL,
    phase TEXT,
    progress INTEGER DEFAULT 0,
    source_digest TEXT DEFAULT '',
    ruleset_version TEXT DEFAULT '',
    adapter_versions TEXT DEFAULT '{}',
    limits TEXT DEFAULT '{}',
    vulnerability_db_version TEXT DEFAULT '',
    error TEXT DEFAULT '',
    cancel_requested INTEGER DEFAULT 0,
    idempotency_key TEXT DEFAULT '',
    attempt INTEGER DEFAULT 0,
    worker_id TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT,
    started_at TEXT DEFAULT '',
    finished_at TEXT DEFAULT '',
    heartbeat_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_idem ON scans(project_id, idempotency_key);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT,
    scan_id TEXT NOT NULL,
    project_id TEXT,
    kind TEXT NOT NULL,
    logical_key TEXT,
    name TEXT,
    version TEXT DEFAULT '',
    relative_path TEXT DEFAULT '',
    content_digest TEXT DEFAULT '',
    discovery_method TEXT DEFAULT '',
    confidence TEXT DEFAULT '',
    metadata TEXT DEFAULT '{}',
    PRIMARY KEY (asset_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_assets_scan_kind ON assets(scan_id, kind);
CREATE INDEX IF NOT EXISTS idx_assets_scan_path ON assets(scan_id, relative_path);

CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT,
    scan_id TEXT NOT NULL,
    source_asset_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    confidence TEXT DEFAULT '',
    basis TEXT DEFAULT '',
    evidence_ids TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    PRIMARY KEY (edge_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_scan ON edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(scan_id, source_asset_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(scan_id, target_asset_id);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT,
    scan_id TEXT NOT NULL,
    path TEXT,
    line INTEGER DEFAULT 0,
    "column" INTEGER DEFAULT 0,
    pointer TEXT DEFAULT '',
    excerpt TEXT DEFAULT '',
    excerpt_digest TEXT DEFAULT '',
    parser TEXT DEFAULT '',
    transform_chain TEXT DEFAULT '[]',
    PRIMARY KEY (evidence_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id, path);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT,
    scan_id TEXT NOT NULL,
    rule_id TEXT,
    rule_version TEXT DEFAULT '',
    asset_id TEXT DEFAULT '',
    category TEXT DEFAULT '',
    severity TEXT DEFAULT '',
    confidence TEXT DEFAULT '',
    evidence_ids TEXT DEFAULT '[]',
    flow_steps TEXT DEFAULT '[]',
    explanation TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    limitations TEXT DEFAULT '',
    fingerprint TEXT DEFAULT '',
    title TEXT DEFAULT '',
    created_at TEXT,
    review_status TEXT DEFAULT 'open',
    PRIMARY KEY (finding_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_sev ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan_cat ON findings(scan_id, category);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(scan_id, fingerprint);

CREATE TABLE IF NOT EXISTS coverage (
    scan_id TEXT PRIMARY KEY,
    indexed_files INTEGER DEFAULT 0,
    parsed_files INTEGER DEFAULT 0,
    failed_files INTEGER DEFAULT 0,
    skipped_files INTEGER DEFAULT 0,
    languages TEXT DEFAULT '{}',
    unresolved_refs TEXT DEFAULT '[]',
    limit_hits TEXT DEFAULT '[]',
    vulnerability_db TEXT DEFAULT '{}',
    notes TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS reviews (
    review_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT DEFAULT '',
    operator TEXT DEFAULT '',
    created_at TEXT,
    expires_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reviews_finding ON reviews(scan_id, finding_id);

CREATE TABLE IF NOT EXISTS runtime_bindings (
    binding_id TEXT PRIMARY KEY,
    project_id TEXT,
    asset_id TEXT,
    runtime_server TEXT,
    basis TEXT DEFAULT '',
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_bindings_asset ON runtime_bindings(asset_id);
"""

SCAN_FIELDS = ("scan_id", "project_id", "source_id", "source_path", "profile", "status", "phase",
               "progress", "source_digest", "ruleset_version", "adapter_versions", "limits",
               "vulnerability_db_version", "error", "cancel_requested", "idempotency_key",
               "attempt", "worker_id", "created_at", "updated_at", "started_at", "finished_at",
               "heartbeat_at", "device_id", "agent", "collection")
SCAN_JSON_FIELDS = ("adapter_versions", "limits", "collection")


def _json(data) -> str:
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) > MAX_JSON_FIELD:
        text = json.dumps({"_truncated": True, "preview": text[:MAX_JSON_FIELD // 2]},
                          ensure_ascii=False)
    return text


def _loads(text, fallback):
    try:
        return json.loads(text) if text else fallback
    except (TypeError, json.JSONDecodeError):
        return fallback


class Repository:
    def __init__(self, path: str) -> None:
        self.path = path
        self.device_notifications = DeviceScanNotifications()
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def init_schema(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
            if "source_path" not in columns:
                connection.execute("ALTER TABLE scans ADD COLUMN source_path TEXT DEFAULT ''")
            for name, default in (("device_id", "''"), ("agent", "''"), ("collection", "'{}'")):
                if name not in columns:
                    connection.execute(f"ALTER TABLE scans ADD COLUMN {name} TEXT DEFAULT {default}")
            connection.execute("INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?)",
                               (str(SCHEMA_VERSION),))

    # ---- 扫描任务 ----

    def create_scan(self, record: ScanRecord) -> ScanRecord:
        with self.connect() as connection:
            connection.execute(
                f"INSERT OR REPLACE INTO scans({','.join(SCAN_FIELDS)}) "
                f"VALUES({','.join('?' for _ in SCAN_FIELDS)})",
                tuple(_json(getattr(record, name)) if name in SCAN_JSON_FIELDS
                      else getattr(record, name) for name in SCAN_FIELDS))
        if record.device_id:
            self.device_notifications.notify(record.device_id)
        return record

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return _scan_from_row(row) if row else None

    def find_scan_by_idempotency(self, project_id: str, key: str) -> ScanRecord | None:
        if not key:
            return None
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE project_id=? AND idempotency_key=? ORDER BY created_at DESC LIMIT 1",
                (project_id, key)).fetchone()
        return _scan_from_row(row) if row else None

    def list_scans(self, project_id: str = "", limit: int = 50) -> list:
        with self.connect() as connection:
            if project_id:
                rows = connection.execute(
                    "SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
                    (project_id, int(limit))).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
        return [_scan_from_row(row) for row in rows]

    def active_scan_count(self) -> int:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM scans WHERE status IN ('QUEUED','RUNNING')").fetchone()
        return int(row["n"]) if row else 0

    def claim_next_scan(self, worker_id: str) -> ScanRecord | None:
        """数据库事务领取任务，保证单 worker 单扫描并发。"""
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scans WHERE status='QUEUED' AND phase='QUEUED' "
                "AND cancel_requested=0 ORDER BY created_at LIMIT 1").fetchone()
            if row is None:
                connection.rollback()
                return None
            connection.execute(
                "UPDATE scans SET status='RUNNING', phase='SNAPSHOTTING', attempt=attempt+1, "
                "worker_id=?, started_at=COALESCE(NULLIF(started_at,''), ?), heartbeat_at=?, "
                "updated_at=?, error='' WHERE scan_id=? AND status='QUEUED'",
                (worker_id, now, now, now, row["scan_id"]))
            updated = connection.execute("SELECT * FROM scans WHERE scan_id=?", (row["scan_id"],)).fetchone()
        return _scan_from_row(updated)

    def update_scan(self, scan_id: str, **fields) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now()
        columns = []
        values = []
        for name, value in fields.items():
            if name not in SCAN_FIELDS:
                continue
            columns.append(f"{name}=?")
            values.append(_json(value) if name in SCAN_JSON_FIELDS else value)
        if not columns:
            return
        values.append(scan_id)
        with self.connect() as connection:
            connection.execute(f"UPDATE scans SET {','.join(columns)} WHERE scan_id=?", tuple(values))

    def heartbeat(self, scan_id: str) -> None:
        self.update_scan(scan_id, heartbeat_at=utc_now())

    def request_cancel(self, scan_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scans SET cancel_requested=1, updated_at=?, "
                "status=CASE WHEN status='QUEUED' OR phase='COLLECTING' THEN 'CANCELLED' ELSE status END, "
                "finished_at=CASE WHEN status='QUEUED' OR phase='COLLECTING' THEN ? ELSE finished_at END "
                "WHERE scan_id=? AND status IN ('QUEUED','RUNNING')", (utc_now(), utc_now(), scan_id))
        return cursor.rowcount > 0

    def is_cancel_requested(self, scan_id: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return bool(row and row["cancel_requested"])

    def requeue_scan(self, scan_id: str) -> bool:
        """中断/失败/取消的任务可以新 attempt 重跑，不静默丢弃。"""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if row is None or row["status"] not in ("INTERRUPTED", "FAILED", "CANCELLED"):
                return False
            collection = _loads(row["collection"], {})
            if row["device_id"]:
                collection = {"scope": collection.get("scope", "user")}
                for table in ("assets", "edges", "evidence", "findings", "coverage"):
                    connection.execute(f"DELETE FROM {table} WHERE scan_id=?", (scan_id,))
            cursor = connection.execute(
                "UPDATE scans SET status='QUEUED', phase=CASE WHEN device_id != '' THEN 'WAITING_ENDPOINT' ELSE 'QUEUED' END, "
                "source_path=CASE WHEN device_id != '' THEN '' ELSE source_path END, progress=0, error='', "
                "cancel_requested=0, worker_id='', heartbeat_at='', finished_at='', collection=?, updated_at=? "
                "WHERE scan_id=? AND status IN ('INTERRUPTED','FAILED','CANCELLED')",
                (_json(collection), utc_now(), scan_id))
        if cursor.rowcount and row["device_id"]:
            self.device_notifications.notify(row["device_id"])
        return cursor.rowcount > 0

    def mark_stale_running(self, stale_seconds: int = 120) -> int:
        """worker 重启后把心跳过期的执行中任务标为中断，不静默丢弃。"""
        cutoff = _utc_shift(-stale_seconds)
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scans SET status='INTERRUPTED', phase='QUEUED', error='interrupted: worker heartbeat lost', "
                "updated_at=?, finished_at=? WHERE status='RUNNING' AND phase != 'COLLECTING' "
                "AND heartbeat_at != '' AND heartbeat_at < ?",
                (utc_now(), utc_now(), cutoff))
        return cursor.rowcount

    def expire_device_scans(self) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                "UPDATE scans SET status='FAILED', error='等待终端超时，请确认客户端版本与设备连接后重试', "
                "updated_at=?, finished_at=? WHERE device_id != '' AND status='QUEUED' "
                "AND phase='WAITING_ENDPOINT' AND updated_at < ?", (now, now, _utc_shift(-WAIT_SECONDS)))
            connection.execute(
                "UPDATE scans SET status='INTERRUPTED', error='终端采集中断，请重试', updated_at=?, finished_at=? "
                "WHERE device_id != '' AND status='RUNNING' AND phase='COLLECTING' AND heartbeat_at < ?",
                (now, now, _utc_shift(-LEASE_SECONDS)))

    def claim_device_scan(self, device_id: str, agent: str, max_file_bytes: int = MAX_FILE_BYTES) -> ScanRecord | None:
        return self.claim_device_scans(device_id, (agent,), max_file_bytes)

    def claim_device_scans(self, device_id: str, agents, max_file_bytes: int = MAX_FILE_BYTES) -> ScanRecord | None:
        if not agents:
            return None
        self.expire_device_scans()
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                f"SELECT * FROM scans WHERE device_id=? AND agent IN ({','.join('?' for _ in agents)}) AND status='QUEUED' "
                "AND phase='WAITING_ENDPOINT' AND cancel_requested=0 "
                "AND COALESCE(json_extract(limits, '$.max_file_parse_bytes'), ?) <= ? ORDER BY created_at LIMIT 1",
                (device_id, *agents, MAX_FILE_BYTES, max_file_bytes)).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE scans SET status='RUNNING', phase='COLLECTING', progress=2, attempt=attempt+1, "
                "worker_id=?, started_at=?, heartbeat_at=?, updated_at=? WHERE scan_id=?",
                (new_id("lease"), now, now, now, row["scan_id"]))
            row = connection.execute("SELECT * FROM scans WHERE scan_id=?", (row["scan_id"],)).fetchone()
        return _scan_from_row(row)

    def receive_device_snapshot(self, scan_id: str, lease: str, source_path: str, collection: dict,
                                error: str = "") -> bool:
        """取消、重试或超时已改变租约时拒收；快照准备好后才进入普通 worker 队列。"""
        now = utc_now()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE scans SET status=?, phase=?, progress=?, source_path=?, collection=?, error=?, "
                "worker_id='', updated_at=?, finished_at=? WHERE scan_id=? AND worker_id=? "
                "AND status='RUNNING' AND phase='COLLECTING' AND cancel_requested=0 AND heartbeat_at >= ?",
                ("FAILED" if error else "QUEUED", "COLLECTING" if error else "QUEUED", 0 if error else 5,
                 source_path, _json(collection), error, now, now if error else "", scan_id, lease,
                 _utc_shift(-LEASE_SECONDS)))
        return cursor.rowcount > 0

    # ---- 结果写入 ----

    def save_results(self, scan_id: str, assets: list, edges: list, evidence: list,
                     findings: list, coverage: Coverage) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for table in ("assets", "edges", "evidence", "findings", "coverage"):
                connection.execute(f"DELETE FROM {table} WHERE scan_id=?", (scan_id,))
            connection.executemany(
                "INSERT OR REPLACE INTO assets(asset_id, scan_id, project_id, kind, logical_key, name, "
                "version, relative_path, content_digest, discovery_method, confidence, metadata) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                [(item.asset_id, item.scan_id, item.project_id, item.kind, item.logical_key, item.name,
                  item.version, item.relative_path, item.content_digest, item.discovery_method,
                  item.confidence, _json(item.metadata)) for item in assets])
            connection.executemany(
                "INSERT OR REPLACE INTO edges(edge_id, scan_id, source_asset_id, relation, "
                "target_asset_id, confidence, basis, evidence_ids, metadata) VALUES(?,?,?,?,?,?,?,?,?)",
                [(item.edge_id or new_id("edge"), item.scan_id, item.source_asset_id, item.relation,
                  item.target_asset_id, item.confidence, item.basis,
                  _json(item.evidence_ids), _json(item.metadata)) for item in edges])
            connection.executemany(
                "INSERT OR REPLACE INTO evidence(evidence_id, scan_id, path, line, \"column\", "
                "pointer, excerpt, excerpt_digest, parser, transform_chain) VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(item.evidence_id, item.scan_id, item.path, int(item.line), int(item.column),
                  item.pointer, item.excerpt, item.excerpt_digest, item.parser,
                  _json(item.transform_chain)) for item in evidence])
            connection.executemany(
                "INSERT OR REPLACE INTO findings(finding_id, scan_id, rule_id, rule_version, asset_id, "
                "category, severity, confidence, evidence_ids, flow_steps, explanation, remediation, "
                "limitations, fingerprint, title, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(item.finding_id, item.scan_id, item.rule_id, item.rule_version, item.asset_id,
                  item.category, item.severity, item.confidence, _json(item.evidence_ids),
                  _json(item.flow_steps[:MAX_FLOW_STEPS]), item.explanation, item.remediation,
                  item.limitations, item.fingerprint, item.title, item.created_at) for item in findings])
            connection.execute(
                "INSERT OR REPLACE INTO coverage(scan_id, indexed_files, parsed_files, failed_files, "
                "skipped_files, languages, unresolved_refs, limit_hits, vulnerability_db, notes) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (coverage.scan_id, coverage.indexed_files, coverage.parsed_files,
                 coverage.failed_files, coverage.skipped_files, _json(coverage.languages),
                 _json(coverage.unresolved_refs), _json(coverage.limit_hits),
                 _json(coverage.vulnerability_db), _json(coverage.notes)))

    # ---- 查询 ----

    def get_asset_inventory(self, scan_id: str = "", kind: str = "", query: str = "",
                            risk: str = "", limit: int = 20, offset: int = 0, *,
                            view: str = "assets", group_id: str = "", agent: str = "") -> dict:
        """各项目/来源的最近完成快照；重复扫描替换旧快照，失败任务不覆盖结果。

        总览和分页在同一读事务中生成，不把未加载的风险当成零风险。
        PARTIAL 的零命中资产标记为 unknown，不宣称扫描通过。
        """
        cte = """
        WITH ranked_scans AS (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY project_id, source_id, device_id, agent
                ORDER BY created_at DESC, rowid DESC
            ) AS position FROM scans WHERE status IN ('COMPLETED', 'PARTIAL')
        ), latest AS (SELECT * FROM ranked_scans WHERE position=1), risks AS (
            SELECT f.scan_id, f.asset_id, COUNT(*) AS risk_count,
                COUNT(DISTINCT f.rule_id) AS rule_count,
                MIN(CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END) AS risk_rank,
                SUM(f.severity='CRITICAL') AS critical_count, SUM(f.severity='HIGH') AS high_count,
                SUM(f.severity='MEDIUM') AS medium_count, SUM(f.severity='LOW') AS low_count,
                SUM(f.severity='INFO') AS info_count
            FROM findings f JOIN latest s ON s.scan_id=f.scan_id GROUP BY f.scan_id, f.asset_id
        ), inventory AS (
            SELECT a.*, s.source_id, s.device_id, s.agent, s.status AS scan_status,
                s.created_at AS scan_created_at, s.finished_at AS last_scanned_at,
                COALESCE(r.risk_count, 0) AS risk_count, COALESCE(r.rule_count, 0) AS rule_count,
                COALESCE(r.risk_rank, 6) AS risk_rank,
                COALESCE(r.critical_count, 0) AS critical_count, COALESCE(r.high_count, 0) AS high_count,
                COALESCE(r.medium_count, 0) AS medium_count, COALESCE(r.low_count, 0) AS low_count,
                COALESCE(r.info_count, 0) AS info_count,
                CASE WHEN r.risk_count > 0 THEN 'risk' WHEN s.status='PARTIAL' THEN 'unknown'
                    ELSE 'clear' END AS risk_state
            FROM assets a JOIN latest s ON s.scan_id=a.scan_id
            LEFT JOIN risks r ON r.scan_id=a.scan_id AND r.asset_id=a.asset_id
        )
        """
        with self.connect() as connection:
            connection.execute("BEGIN")
            sources = connection.execute(cte + "SELECT * FROM latest ORDER BY created_at DESC, scan_id").fetchall()
            groups = []
            if view == "groups" or group_id:
                aggregates = connection.execute(cte + """
                    SELECT scan_id, kind, COUNT(*) AS assets, SUM(risk_count>0) AS risky_assets,
                        SUM(risk_rank<2) AS high_risk_assets, SUM(risk_count) AS findings,
                        SUM(critical_count) AS critical_count, SUM(high_count) AS high_count,
                        SUM(medium_count) AS medium_count, SUM(low_count) AS low_count,
                        SUM(info_count) AS info_count, MIN(risk_rank) AS risk_rank
                    FROM inventory GROUP BY scan_id, kind
                """).fetchall()
                groups = _inventory_groups(sources, aggregates)
            selected = next((group for group in groups if group["group_id"] == group_id), None)
            scope, params = ("scan_id=?", [scan_id]) if scan_id else ("1=1", [])
            if group_id:
                if selected is None:
                    scope, params = "0=1", []
                elif selected["device_id"]:
                    scope += " AND device_id=? AND agent=?"
                    params.extend([selected["device_id"], selected["agent"]])
                else:
                    scope += " AND device_id='' AND project_id=? AND source_id=?"
                    params.extend([selected["projects"][0], selected["sources"][0]["source_id"]])
            return self._read_asset_inventory(connection, cte, sources, groups, selected, scope, params,
                                              scan_id, kind, query, risk, limit, offset, view, agent)

    def _read_asset_inventory(self, connection, cte, sources, groups, selected, scope, params,
                              scan_id, kind, query, risk, limit, offset, view, agent):
        where, filtered_params = [scope], list(params)
        if kind:
            where.append("kind=?")
            filtered_params.append(kind)
        if risk:
            where.append("risk_state=?")
            filtered_params.append(risk)
        if query:
            where.append("instr(lower(COALESCE(name,'') || ' ' || asset_id || ' ' || "
                         "COALESCE(relative_path,'') || ' ' || COALESCE(version,'') || ' ' || "
                         "project_id || ' ' || source_id || ' ' || device_id || ' ' || agent), lower(?)) > 0")
            filtered_params.append(query)
        clause = " AND ".join(where)
        order = "ORDER BY risk_rank, risk_count DESC, kind, name, scan_id, asset_id"
        summary = dict(connection.execute(cte + f"""
                SELECT COUNT(*) AS assets, COALESCE(SUM(risk_count>0),0) AS risky_assets,
                    COALESCE(SUM(risk_rank<2),0) AS high_risk_assets,
                    COALESCE(SUM(risk_count),0) AS findings
                FROM inventory WHERE {scope}
        """, params).fetchone())
        scoped_sources = selected["sources"] if selected else sources if scope != "0=1" else []
        scoped_sources = [row for row in scoped_sources if not scan_id or row["scan_id"] == scan_id]
        summary["sources"] = len(scoped_sources)
        summary["partial_sources"] = sum(row["status"] == "PARTIAL" for row in scoped_sources)
        kinds = [dict(row) for row in connection.execute(
            cte + f"SELECT kind, COUNT(*) AS count FROM inventory WHERE {scope} GROUP BY kind ORDER BY count DESC, kind",
            params).fetchall()]
        source_data = [{key: row[key] for key in ("scan_id", "project_id", "source_id", "device_id", "agent",
                                                "status", "created_at", "finished_at")} for row in sources]
        if view == "groups":
            # 汇总不受资产分页窗口影响；空快照也保留设备-Agent 行。
            summary["groups"] = len(groups)
            summary["device_agents"] = sum(bool(group["device_id"]) for group in groups)
            filtered = [group for group in groups
                        if (not risk or group["risk_state"] == risk)
                        and (not agent or group["agent"] == agent)
                        and (not kind or any(item["kind"] == kind for item in group["kinds"]))
                        and (not query or query.casefold() in " ".join(
                            [group["device_id"], group["agent"], *group["projects"],
                             *(source["source_id"] for source in group["sources"])]).casefold())]
            return {"items": filtered[offset:offset + limit], "total": len(filtered), "summary": summary,
                    "kinds": kinds, "top_risks": [group for group in groups if group["findings"]][:5],
                    "sources": source_data, "updated_at": utc_now()}
        total = connection.execute(cte + f"SELECT COUNT(*) FROM inventory WHERE {clause}", filtered_params).fetchone()[0]
        rows = connection.execute(cte + f"SELECT * FROM inventory WHERE {clause} {order} LIMIT ? OFFSET ?",
                                  filtered_params + [limit, offset]).fetchall()
        top = connection.execute(cte + f"SELECT * FROM inventory WHERE {scope} AND risk_count>0 {order} LIMIT 5",
                                 params).fetchall()

        def item(row):
            return {**_asset_from_row(row).as_dict(), "source_id": row["source_id"],
                    "device_id": row["device_id"], "agent": row["agent"], "scan_status": row["scan_status"],
                    "scan_created_at": row["scan_created_at"], "last_scanned_at": row["last_scanned_at"],
                    "risk_state": row["risk_state"],
                    "risk": {"count": row["risk_count"], "rules": row["rule_count"],
                             "top": ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "")[row["risk_rank"]],
                             "severity": {s: row[s.lower() + "_count"] for s in
                                          ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}}}

        return {"items": [item(row) for row in rows], "total": total, "summary": summary, "kinds": kinds,
                "top_risks": [item(row) for row in top], "updated_at": utc_now(),
                "sources": source_data, **({"group": selected} if groups or scope == "0=1" else {})}

    def get_assets(self, scan_id: str, kind: str = "", limit: int = 50, offset: int = 0,
                   query: str = "") -> dict:
        where = ["scan_id=?"]
        params: list = [scan_id]
        if kind:
            where.append("kind=?")
            params.append(kind)
        if query:
            where.append("(name LIKE ? OR logical_key LIKE ? OR relative_path LIKE ?)")
            like = f"%{query}%"
            params.extend([like, like, like])
        clause = " AND ".join(where)
        with self.connect() as connection:
            total = connection.execute(f"SELECT COUNT(*) AS n FROM assets WHERE {clause}", params).fetchone()["n"]
            rows = connection.execute(
                f"SELECT * FROM assets WHERE {clause} ORDER BY kind, name, asset_id LIMIT ? OFFSET ?",
                params + [int(limit), int(offset)]).fetchall()
        return {"total": int(total), "items": [_asset_from_row(row) for row in rows]}

    def get_asset(self, scan_id: str, asset_id: str):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM assets WHERE scan_id=? AND asset_id=?", (scan_id, asset_id)).fetchone()
        return _asset_from_row(row) if row else None

    def get_findings(self, scan_id: str, severity: str = "", category: str = "",
                     asset_id: str = "", limit: int = 50, offset: int = 0) -> dict:
        where = ["scan_id=?"]
        params: list = [scan_id]
        if severity:
            where.append("severity=?")
            params.append(severity)
        if category:
            where.append("category=?")
            params.append(category)
        if asset_id:
            where.append("asset_id=?")
            params.append(asset_id)
        clause = " AND ".join(where)
        with self.connect() as connection:
            total = connection.execute(f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", params).fetchone()["n"]
            rows = connection.execute(
                f"SELECT * FROM findings WHERE {clause} "
                "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, rule_id, finding_id "
                "LIMIT ? OFFSET ?", params + [int(limit), int(offset)]).fetchall()
        return {"total": int(total), "items": [_finding_from_row(row) for row in rows]}

    def get_finding(self, scan_id: str, finding_id: str):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE scan_id=? AND finding_id=?", (scan_id, finding_id)).fetchone()
        return _finding_from_row(row) if row else None

    def get_evidence(self, scan_id: str, evidence_ids: list) -> list:
        if not evidence_ids:
            return []
        placeholders = ",".join("?" for _ in evidence_ids)
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM evidence WHERE scan_id=? AND evidence_id IN ({placeholders})",
                [scan_id] + list(evidence_ids)).fetchall()
        return [dict(row) for row in rows]

    def get_coverage(self, scan_id: str) -> Coverage | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM coverage WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            return None
        return Coverage(
            scan_id=row["scan_id"], indexed_files=row["indexed_files"], parsed_files=row["parsed_files"],
            failed_files=row["failed_files"], skipped_files=row["skipped_files"],
            languages=_loads(row["languages"], {}), unresolved_refs=_loads(row["unresolved_refs"], []),
            limit_hits=_loads(row["limit_hits"], []), vulnerability_db=_loads(row["vulnerability_db"], {}),
            notes=_loads(row["notes"], []))

    def get_edges(self, scan_id: str) -> list:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM edges WHERE scan_id=?", (scan_id,)).fetchall()
        return [dict(row) for row in rows]

    def get_graph(self, scan_id: str, center: str = "", depth: int = 2, limit: int = 200) -> dict:
        limit = max(1, min(int(limit), 2000))
        depth = max(0, min(int(depth), 5))
        with self.connect() as connection:
            assets = {row["asset_id"]: _asset_from_row(row) for row in connection.execute(
                "SELECT * FROM assets WHERE scan_id=?", (scan_id,)).fetchall()}
            edges = [dict(row) for row in connection.execute(
                "SELECT * FROM edges WHERE scan_id=?", (scan_id,)).fetchall()]
        adjacency: dict = {}
        for edge in edges:
            adjacency.setdefault(edge["source_asset_id"], []).append(edge)
            adjacency.setdefault(edge["target_asset_id"], []).append(edge)

        if center and center in assets:
            selected = {center}
            frontier = deque([(center, 0)])
            while frontier and len(selected) < limit:
                node, level = frontier.popleft()
                if level >= depth:
                    continue
                for edge in adjacency.get(node, []):
                    other = edge["target_asset_id"] if edge["source_asset_id"] == node else edge["source_asset_id"]
                    if other in assets and other not in selected:
                        selected.add(other)
                        frontier.append((other, level + 1))
                    if len(selected) >= limit:
                        break
        elif center:
            return {"center": center, "nodes": [], "edges": [], "truncated": False, "note": "center not found"}
        else:
            selected = set(list(assets)[:limit])
        nodes = [assets[asset_id] for asset_id in selected if asset_id in assets]
        node_ids = {node.asset_id for node in nodes}
        selected_edges = [edge for edge in edges
                          if edge["source_asset_id"] in node_ids and edge["target_asset_id"] in node_ids]
        return {"center": center, "nodes": nodes, "edges": selected_edges,
                "truncated": len(selected) >= limit}

    def add_review(self, review: Review) -> Review:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reviews(review_id, scan_id, finding_id, status, reason, "
                "operator, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?)",
                (review.review_id or new_id("review"), review.scan_id, review.finding_id,
                 review.status, review.reason, review.operator, review.created_at, review.expires_at))
            connection.execute("UPDATE findings SET review_status=? WHERE scan_id=? AND finding_id=?",
                               (review.status, review.scan_id, review.finding_id))
        return review

    def list_reviews(self, scan_id: str) -> list:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM reviews WHERE scan_id=? ORDER BY created_at DESC", (scan_id,)).fetchall()
        return [dict(row) for row in rows]

    # ---- 运行时关联（先做展示，不自动生成策略） ----

    def add_runtime_binding(self, project_id: str, asset_id: str, runtime_server: str,
                            basis: str = "reviewed") -> dict:
        binding = {
            "binding_id": new_id("bind"), "project_id": project_id, "asset_id": asset_id,
            "runtime_server": runtime_server, "basis": basis, "created_at": utc_now(),
        }
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO runtime_bindings(binding_id, project_id, asset_id, "
                "runtime_server, basis, created_at) VALUES(?,?,?,?,?,?)",
                (binding["binding_id"], project_id, asset_id, runtime_server, basis, binding["created_at"]))
        return binding

    def list_runtime_bindings(self, project_id: str = "", asset_id: str = "") -> list:
        where = []
        params: list = []
        if project_id:
            where.append("project_id=?")
            params.append(project_id)
        if asset_id:
            where.append("asset_id=?")
            params.append(asset_id)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM runtime_bindings {clause} ORDER BY created_at DESC", params).fetchall()
        return [dict(row) for row in rows]

    def assets_for_runtime_server(self, project_id: str, runtime_server: str) -> list:
        """同名 server 不自动跨环境合并：只有已审核绑定才关联。"""
        bindings = [item for item in self.list_runtime_bindings(project_id)
                    if item["runtime_server"] == runtime_server]
        result = []
        for binding in bindings:
            scan = self.latest_scan_for_project(project_id)
            if scan is None:
                continue
            asset = self.get_asset(scan.scan_id, binding["asset_id"])
            if asset is None:
                continue
            findings = [item for item in self.get_findings(scan.scan_id, asset_id=asset.asset_id,
                                                           limit=100)["items"]]
            result.append({
                "binding": binding,
                "scan_id": scan.scan_id,
                "asset": asset.as_dict(),
                "findings": [{"finding_id": item.finding_id, "rule_id": item.rule_id,
                              "severity": item.severity, "title": item.title}
                             for item in findings],
                "note": "静态声明/推断关系，不代表运行时实际调用轨迹",
            })
        return result

    def latest_scan_for_project(self, project_id: str) -> ScanRecord | None:
        scans = self.list_scans(project_id, limit=1)
        return scans[0] if scans else None

    def diff(self, scan_id: str, base_scan_id: str) -> dict:
        with self.connect() as connection:
            current_assets = {row["asset_id"]: _asset_from_row(row) for row in connection.execute(
                "SELECT * FROM assets WHERE scan_id=?", (scan_id,)).fetchall()}
            base_assets = {row["asset_id"]: _asset_from_row(row) for row in connection.execute(
                "SELECT * FROM assets WHERE scan_id=?", (base_scan_id,)).fetchall()}
            current_findings = {row["fingerprint"]: dict(row) for row in connection.execute(
                "SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()}
            base_findings = {row["fingerprint"]: dict(row) for row in connection.execute(
                "SELECT * FROM findings WHERE scan_id=?", (base_scan_id,)).fetchall()}
        added = [current_assets[key] for key in current_assets.keys() - base_assets.keys()]
        removed = [base_assets[key] for key in base_assets.keys() - current_assets.keys()]
        changed = [current_assets[key] for key in current_assets.keys() & base_assets.keys()
                   if current_assets[key].content_digest != base_assets[key].content_digest
                   or current_assets[key].version != base_assets[key].version]
        findings_added = [current_findings[key] for key in current_findings.keys() - base_findings.keys()]
        findings_removed = [base_findings[key] for key in base_findings.keys() - current_findings.keys()]
        return {
            "scan_id": scan_id, "base_scan_id": base_scan_id,
            "assets": {"added": added, "removed": removed, "changed": changed},
            "findings": {"added": findings_added, "removed": findings_removed},
        }


# ---------- 行映射 ----------

def _scan_from_row(row) -> ScanRecord:
    data = dict(row)
    return ScanRecord(
        scan_id=data["scan_id"], project_id=data["project_id"], source_id=data["source_id"],
        source_path=data.get("source_path") or "",
        profile=data.get("profile") or "default", status=data["status"], phase=data.get("phase") or "QUEUED",
        progress=int(data.get("progress") or 0), source_digest=data.get("source_digest") or "",
        ruleset_version=data.get("ruleset_version") or "",
        adapter_versions=_loads(data.get("adapter_versions"), {}),
        limits=_loads(data.get("limits"), {}),
        vulnerability_db_version=data.get("vulnerability_db_version") or "",
        error=data.get("error") or "", cancel_requested=bool(data.get("cancel_requested")),
        idempotency_key=data.get("idempotency_key") or "", attempt=int(data.get("attempt") or 0),
        worker_id=data.get("worker_id") or "", created_at=data.get("created_at") or "",
        updated_at=data.get("updated_at") or "", started_at=data.get("started_at") or "",
        finished_at=data.get("finished_at") or "", heartbeat_at=data.get("heartbeat_at") or "",
        device_id=data.get("device_id") or "", agent=data.get("agent") or "",
        collection=_loads(data.get("collection"), {}))


def _asset_from_row(row) -> Asset:
    return Asset(asset_id=row["asset_id"], project_id=row["project_id"], scan_id=row["scan_id"],
                 kind=row["kind"], logical_key=row["logical_key"], name=row["name"],
                 version=row["version"] or "", relative_path=row["relative_path"] or "",
                 content_digest=row["content_digest"] or "", discovery_method=row["discovery_method"] or "",
                 confidence=row["confidence"] or "", metadata=_loads(row["metadata"], {}))


def _finding_from_row(row) -> Finding:
    return Finding(
        finding_id=row["finding_id"], scan_id=row["scan_id"], rule_id=row["rule_id"],
        rule_version=row["rule_version"] or "", asset_id=row["asset_id"] or "",
        category=row["category"] or "", severity=row["severity"] or "",
        confidence=row["confidence"] or "", evidence_ids=_loads(row["evidence_ids"], []),
        flow_steps=_loads(row["flow_steps"], []), explanation=row["explanation"] or "",
        remediation=row["remediation"] or "", limitations=row["limitations"] or "",
        fingerprint=row["fingerprint"] or "", title=row["title"] or "",
        created_at=row["created_at"] or "")


def _utc_shift(seconds: int) -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))
