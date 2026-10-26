"""JSON / Markdown 报告导出（方案 §6）。

报告明确“已发现”“未知/未覆盖”“人工复核”，不以零 finding 宣称无风险。
"""

import json

from .models import SEVERITY_RANK, utc_now

DISCLAIMER = ("本报告为静态扫描结果，只代表授权目录快照中的声明/推断证据；"
              "未执行任何待检代码。未发现风险不代表资产安全。")

REVIEW_SECTION = ("以下结论需要人工复核：低置信度命中、未知变换的数据流、"
                  "未覆盖文件/语言与达到限额的分析。")


def build_report(repository, scan_id: str, include_evidence: bool = True,
                 max_findings: int = 2000) -> dict:
    scan = repository.get_scan(scan_id)
    if scan is None:
        raise KeyError(f"scan not found: {scan_id}")
    assets = repository.get_assets(scan_id, limit=10000)
    findings = repository.get_findings(scan_id, limit=max_findings)
    coverage = repository.get_coverage(scan_id)
    reviews = repository.list_reviews(scan_id)
    evidence_map = {}
    if include_evidence:
        evidence_ids = []
        for finding in findings["items"]:
            evidence_ids.extend(finding.evidence_ids)
        evidence_map = {item["evidence_id"]: item
                        for item in repository.get_evidence(scan_id, sorted(set(evidence_ids)))}

    by_severity: dict = {}
    by_category: dict = {}
    for finding in findings["items"]:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1

    finding_rows = []
    for finding in findings["items"]:
        asset = repository.get_asset(scan_id, finding.asset_id) if finding.asset_id else None
        finding_rows.append({
            **finding.as_dict(),
            "asset": asset.as_dict() if asset else None,
            "evidence": [evidence_map[evidence_id] for evidence_id in finding.evidence_ids
                         if evidence_id in evidence_map],
        })
    finding_rows.sort(key=lambda item: (-SEVERITY_RANK.get(item["severity"], 0),
                                        item["rule_id"], item["asset_id"]))

    return {
        "report_version": "1.0",
        "generated_at": utc_now(),
        "scan": scan.as_dict(),
        "summary": {
            "assets": assets["total"],
            "findings": findings["total"],
            "by_severity": by_severity,
            "by_category": by_category,
            "reviews": len(reviews),
        },
        "coverage": coverage.as_dict() if coverage else None,
        "assets": [asset.as_dict() for asset in assets["items"]],
        "findings": finding_rows,
        "reviews": reviews,
        "disclaimer": DISCLAIMER,
        "review_notice": REVIEW_SECTION,
    }


def render_markdown(report: dict) -> str:
    scan = report.get("scan") or {}
    summary = report.get("summary") or {}
    coverage = report.get("coverage") or {}
    lines = [
        f"# AgentGuard 静态扫描报告：{scan.get('project_id', '')}",
        "",
        f"- scan_id：`{scan.get('scan_id', '')}`",
        f"- 状态：**{scan.get('status', '')}**（phase={scan.get('phase', '')}）",
        f"- source_id：`{scan.get('source_id', '')}`",
        f"- 源快照摘要：`{scan.get('source_digest', '')}`",
        f"- 规则版本：`{scan.get('ruleset_version', '')}`",
        f"- 漏洞库：`{(coverage.get('vulnerability_db') or {}).get('db_version', 'unavailable')}`"
        f"（状态 {(coverage.get('vulnerability_db') or {}).get('status', 'unknown')}）",
        f"- 生成时间：{report.get('generated_at', '')}",
        "",
        "## 资产统计",
        "",
        f"- 索引文件：{coverage.get('indexed_files', 0)}；已解析：{coverage.get('parsed_files', 0)}；"
        f"失败：{coverage.get('failed_files', 0)}；跳过：{coverage.get('skipped_files', 0)}",
        f"- 资产总数：{summary.get('assets', 0)}；风险条目：{summary.get('findings', 0)}",
        f"- 按等级：{_inline(summary.get('by_severity'))}",
        f"- 按类别：{_inline(summary.get('by_category'))}",
        "",
        "## 覆盖缺口与未知",
        "",
    ]
    limit_hits = coverage.get("limit_hits") or []
    notes = coverage.get("notes") or []
    unresolved = coverage.get("unresolved_refs") or []
    if not (limit_hits or notes or unresolved):
        lines.append("- 无显式覆盖缺口记录（仍需结合支持语言范围理解）")
    for item in limit_hits[:20]:
        lines.append(f"- 达到限额：{item}")
    for item in unresolved[:20]:
        lines.append(f"- 未解析引用：{item}")
    for item in notes[:30]:
        lines.append(f"- 说明：{item}")
    lines.extend(["", "## 风险详情", ""])
    if not report.get("findings"):
        lines.append("未发现规则命中的风险条目；这**不代表**资产安全，请结合覆盖缺口与人工复核结论。")
    for finding in report.get("findings", [])[:200]:
        lines.extend(_finding_markdown(finding))
    reviews = report.get("reviews") or []
    lines.extend(["", "## 人工复核", ""])
    if reviews:
        for review in reviews:
            lines.append(f"- `{review.get('finding_id', '')}` -> {review.get('status', '')}"
                         f"（{review.get('operator', '')}，{review.get('reason', '')}）")
    else:
        lines.append("- 尚无人工复核记录；低置信度条目应进入复核队列。")
    lines.extend(["", "## 边界说明", "", f"- {report.get('disclaimer', '')}",
                  f"- {report.get('review_notice', '')}", ""])
    return "\n".join(lines)


def dump_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, default=str)


def _finding_markdown(finding: dict) -> list:
    asset = finding.get("asset") or {}
    lines = [
        f"### [{finding.get('severity')}] {finding.get('title') or finding.get('rule_id')}",
        "",
        f"- 规则：`{finding.get('rule_id')}`（v{finding.get('rule_version')}）"
        f"；类别：{finding.get('category')}；置信度：{finding.get('confidence')}",
        f"- 资产：{asset.get('kind', '-')} `{asset.get('name', '-')}`"
        f"（{asset.get('relative_path', '-')}）",
        f"- 说明：{finding.get('explanation', '')}",
        f"- 建议：{finding.get('remediation', '')}",
        f"- 限制：{finding.get('limitations', '')}",
    ]
    steps = finding.get("flow_steps") or []
    if steps:
        lines.append("- 数据流：")
        for step in steps[:12]:
            lines.append(f"  - [{step.get('status')}] {step.get('kind')} {step.get('location')}"
                         f"：{step.get('detail')}")
    evidence = finding.get("evidence") or []
    if evidence:
        lines.append("- 证据：")
        for item in evidence[:8]:
            location = item.get("path", "")
            if item.get("line"):
                location += f":{item['line']}"
            lines.append(f"  - `{location}` {item.get('pointer', '')}：{item.get('excerpt', '')}")
    lines.append("")
    return lines


def _inline(data) -> str:
    if not data:
        return "无"
    return "、".join(f"{key}={value}" for key, value in sorted(data.items()))
