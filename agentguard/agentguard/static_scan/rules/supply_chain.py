"""供应链风险 AG-STATIC-SUPPLY-001（方案 §5.4）。

使用本地离线漏洞库快照；查询失败、版本不明或库过旧标 unknown/stale。
精确版本命中表示组件受影响，不自动证明漏洞可利用。
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .base import make_finding

VERSION = "1.0"
SNAPSHOT_PATH = Path(__file__).resolve().parent.parent / "rulesets" / "vuln_snapshot.json"
DEFAULT_MAX_AGE_DAYS = 3650  # 内置演示库按固定版本评估；外部库可用环境变量收紧


class KnownVulnerabilityRule:
    rule_id = "AG-STATIC-SUPPLY-001"
    rule_version = VERSION
    category = "supply_chain"
    title = "依赖命中已知漏洞"

    def evaluate(self, facts, context):
        snapshot, status = load_snapshot()
        facts.vulnerability_db = status
        findings = []
        if not snapshot:
            return findings
        entries = snapshot.get("entries") or []
        stale = status.get("status") == "stale"
        for dep in facts.dependencies:
            if not dep.version or dep.ecosystem == "docker":
                continue
            for entry in entries:
                if str(entry.get("ecosystem")) != dep.ecosystem:
                    continue
                if str(entry.get("name")).lower() != dep.name.lower():
                    continue
                if not version_matches(dep.version, str(entry.get("affected") or "")):
                    continue
                asset = (facts.asset_by_logical("Framework", f"framework:{dep.ecosystem}:{dep.name}")
                         or facts.asset_by_logical("Dependency", f"dep:{dep.ecosystem}:{dep.name}"))
                evidence = facts.evidence_for(
                    dep.source_path, line=dep.line,
                    excerpt=f"{dep.coordinate()} 命中 {entry.get('id')}",
                    parser="dependency", pointer=f"/{dep.name}")
                severity = str(entry.get("severity") or "HIGH")
                limitations = "精确版本命中表示组件受影响，不自动证明漏洞可利用；未验证运行入口可达性"
                confidence = "high"
                if stale:
                    confidence = "low"
                    limitations += "；漏洞库快照已过期，结果仅供参考"
                findings.append(make_finding(
                    self, context, asset.asset_id if asset else "", severity, confidence,
                    evidence=[evidence],
                    explanation=f"{dep.name}=={dep.version} 命中 {entry.get('id')}（{entry.get('summary', '')}）",
                    remediation=f"升级到修复版本 {entry.get('fixed') or '厂商建议版本'} 或确认不受影响",
                    limitations=limitations,
                    fingerprint_extra=f"cve:{entry.get('id')}:{dep.name}:{dep.version}",
                    title=f"已知漏洞：{dep.name} {entry.get('id')}"))
        return findings


def load_snapshot(path: str = "") -> tuple:
    target = Path(path or os.getenv("AG_STATIC_VULN_DB") or SNAPSHOT_PATH)
    if not target.exists():
        return None, {"status": "unavailable", "db_version": "", "source": str(target),
                      "reason": "vulnerability database not found"}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, {"status": "unavailable", "db_version": "", "source": str(target),
                      "reason": f"invalid snapshot: {exc.__class__.__name__}"}
    generated_at = str(data.get("generated_at") or "")
    max_age = int(data.get("max_age_days") or os.getenv("AG_STATIC_VULN_MAX_AGE_DAYS")
                  or DEFAULT_MAX_AGE_DAYS)
    status = {
        "status": "ok",
        "db_version": str(data.get("db_version") or ""),
        "generated_at": generated_at,
        "source": str(data.get("source") or target.name),
        "entry_count": len(data.get("entries") or []),
    }
    age = _age_days(generated_at)
    if age is None:
        status["status"] = "unknown"
        status["reason"] = "missing generated_at"
    elif age > max_age:
        status["status"] = "stale"
        status["age_days"] = age
        status["max_age_days"] = max_age
    return data, status


def _age_days(generated_at: str):
    if not generated_at:
        return None
    try:
        moment = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - moment).days


def version_key(version: str) -> tuple:
    parts = []
    for token in re.split(r"[.\-+_]", str(version or "")):
        number = re.match(r"(\d+)", token)
        parts.append(int(number.group(1)) if number else 0)
    return tuple(parts)


def version_matches(version: str, affected: str) -> bool:
    """支持逗号 AND、`||` OR 与 < <= == >= > != 表达式。"""
    if not affected:
        return False
    for branch in str(affected).split("||"):
        if all(_clause_matches(version, clause.strip()) for clause in branch.split(",") if clause.strip()):
            return True
    return False


def _clause_matches(version: str, clause: str) -> bool:
    match = re.match(r"^(<=|>=|==|!=|<|>)\s*(.+)$", clause)
    if not match:
        return False
    operator, target = match.group(1), match.group(2).strip()
    left, right = version_key(version), version_key(target)
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    return False
