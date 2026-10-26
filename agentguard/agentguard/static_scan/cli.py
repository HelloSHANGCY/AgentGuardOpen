"""离线静态扫描入口。

用法：
    python -m agentguard.static_scan.cli scan --source <授权目录> --project <id> [--report out.json]
    python -m agentguard.static_scan.cli show --scan-id <id> [--graph-center <asset_id>]
    python -m agentguard.static_scan.cli report --scan-id <id> --format md --out report.md
    python -m agentguard.static_scan.cli diff --scan-id <new> --base <old>
    python -m agentguard.static_scan.cli worker --sources '{"project": "/data/project"}'
"""

import argparse
import json
import os
import sys

from .inputs import Limits
from .models import ScanRecord, new_id
from .reports import build_report, dump_json, render_markdown
from .repository import Repository
from .worker import ScanWorker

DEFAULT_DB = os.getenv("AG_STATIC_DB", "/tmp/agentguard-static/static-scan.db")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard.static_scan.cli",
                                     description="AgentGuard 静态资产与风险扫描")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="扫描授权目录")
    scan.add_argument("--source", required=True, help="管理员授权的只读目录")
    scan.add_argument("--project", default="default")
    scan.add_argument("--source-id", default="local")
    scan.add_argument("--profile", default="default")
    scan.add_argument("--db", default=DEFAULT_DB)
    scan.add_argument("--report", default="")
    scan.add_argument("--format", choices=["json", "md"], default="json")
    scan.add_argument("--timeout", type=float, default=float(os.getenv("AG_STATIC_SCAN_TIMEOUT", "600")))
    scan.add_argument("--in-process", action="store_true", help="当前进程内执行（不隔离，仅调试）")

    show = sub.add_parser("show", help="查询扫描结果")
    show.add_argument("--scan-id", required=True)
    show.add_argument("--db", default=DEFAULT_DB)
    show.add_argument("--kind", default="")
    show.add_argument("--severity", default="")
    show.add_argument("--category", default="")
    show.add_argument("--limit", type=int, default=50)
    show.add_argument("--graph-center", default="")
    show.add_argument("--depth", type=int, default=2)

    report = sub.add_parser("report", help="导出 JSON/Markdown 报告")
    report.add_argument("--scan-id", required=True)
    report.add_argument("--db", default=DEFAULT_DB)
    report.add_argument("--format", choices=["json", "md"], default="md")
    report.add_argument("--out", default="")

    diff = sub.add_parser("diff", help="快照差异")
    diff.add_argument("--scan-id", required=True)
    diff.add_argument("--base", required=True)
    diff.add_argument("--db", default=DEFAULT_DB)

    worker = sub.add_parser("worker", help="运行扫描 worker")
    worker.add_argument("--db", default=DEFAULT_DB)
    worker.add_argument("--sources", default=os.getenv("AG_STATIC_SOURCES", "{}"))
    worker.add_argument("--once", action="store_true")
    worker.add_argument("--timeout", type=float, default=float(os.getenv("AG_STATIC_SCAN_TIMEOUT", "600")))

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "show":
        return _show(args)
    if args.command == "report":
        return _report(args)
    if args.command == "diff":
        return _diff(args)
    if args.command == "worker":
        return _worker(args)
    return 2


def _scan(args) -> int:
    source = os.path.abspath(args.source)
    if not os.path.isdir(source):
        print(f"source not found or not a directory: {source}", file=sys.stderr)
        return 2
    repository = Repository(args.db)
    sources = {args.source_id: source}
    record = ScanRecord(scan_id=new_id("scan"), project_id=args.project, source_id=args.source_id,
                        profile=args.profile)
    repository.create_scan(record)
    print(f"scan_id={record.scan_id} source={source}")
    if args.in_process:
        from .rules.ruleset import load_ruleset
        from .scanner import run_scan

        run_scan(record.scan_id, repository, sources, Limits(), load_ruleset())
    else:
        worker = ScanWorker(repository, sources, timeout=args.timeout)
        worker.execute_subprocess(record)
    current = repository.get_scan(record.scan_id)
    coverage = repository.get_coverage(record.scan_id)
    print(f"status={current.status} phase={current.phase} error={current.error or '-'}")
    if coverage:
        print(f"files indexed={coverage.indexed_files} parsed={coverage.parsed_files} "
              f"failed={coverage.failed_files} skipped={coverage.skipped_files}")
    findings = repository.get_findings(record.scan_id, limit=1000)
    print(f"assets={repository.get_assets(record.scan_id, limit=1)['total']} findings={findings['total']}")
    if args.report:
        data = build_report(repository, record.scan_id)
        text = dump_json(data) if args.format == "json" else render_markdown(data)
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"report written: {args.report}")
    return 0 if current.status in ("COMPLETED", "PARTIAL") else 1


def _show(args) -> int:
    repository = Repository(args.db)
    scan = repository.get_scan(args.scan_id)
    if scan is None:
        print(f"scan not found: {args.scan_id}", file=sys.stderr)
        return 2
    print(json.dumps(scan.as_dict(), ensure_ascii=False, indent=2))
    if args.graph_center:
        graph = repository.get_graph(args.scan_id, args.graph_center, args.depth)
        print(json.dumps(graph, ensure_ascii=False, indent=2, default=str))
        return 0
    assets = repository.get_assets(args.scan_id, args.kind, args.limit)
    print(f"\nassets ({assets['total']}):")
    for asset in assets["items"]:
        print(f"  [{asset.kind}] {asset.name}  {asset.relative_path}")
    findings = repository.get_findings(args.scan_id, args.severity, args.category, limit=args.limit)
    print(f"\nfindings ({findings['total']}):")
    for finding in findings["items"]:
        print(f"  [{finding.severity}/{finding.confidence}] {finding.rule_id} "
              f"{finding.title} -> {finding.asset_id or '-'}")
        print(f"      {finding.explanation[:160]}")
    coverage = repository.get_coverage(args.scan_id)
    if coverage:
        print(f"\ncoverage: {json.dumps(coverage.as_dict(), ensure_ascii=False)[:800]}")
    return 0


def _report(args) -> int:
    repository = Repository(args.db)
    try:
        data = build_report(repository, args.scan_id)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    text = dump_json(data) if args.format == "json" else render_markdown(data)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"report written: {args.out}")
    else:
        print(text)
    return 0


def _diff(args) -> int:
    repository = Repository(args.db)
    result = repository.diff(args.scan_id, args.base)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


def _worker(args) -> int:
    try:
        sources = json.loads(args.sources or "{}")
    except json.JSONDecodeError as exc:
        print(f"invalid --sources JSON: {exc}", file=sys.stderr)
        return 2
    repository = Repository(args.db)
    worker = ScanWorker(repository, sources, timeout=args.timeout)
    if args.once:
        worker.recover()
        worker.run_once()
        return 0
    worker.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
