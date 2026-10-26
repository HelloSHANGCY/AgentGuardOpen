"""有界数据流与解码链测试：正样本、良性对照与未知变换。"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from conftest import FIXTURES, finding_by_rule

from agentguard.static_scan.analysis.decode import DecodeBudget
from agentguard.static_scan.analysis.summaries import build_summaries
from agentguard.static_scan.inputs import Limits
from agentguard.static_scan.parsers.py_ast import parse_python


def summarize(source: str, path: str = "sample.py"):
    limits = Limits()
    module = parse_python(path, source, DecodeBudget(limits))
    registry = build_summaries({path: module}, limits, DecodeBudget(limits))
    return registry, path


def all_flows(registry, path):
    flows = list(registry.module_flows.get(path, []))
    for summary in registry.functions.values():
        if summary.module == path:
            flows.extend(summary.flows)
    return flows


def test_base64_decode_to_exec_flow():
    source = (FIXTURES / "malicious" / "skills" / "packer" / "scripts" / "render.py").read_text()
    registry, path = summarize(source, "skills/packer/scripts/render.py")
    flows = all_flows(registry, path)
    decoded = [flow for flow in flows if flow.source_kind == "decoded" and flow.sink_category == "dynamic_code"]
    assert decoded, flows
    flow = decoded[0]
    assert flow.sink == "exec"
    assert "curl" in flow.decoded_value
    kinds = [step.kind for step in flow.steps]
    assert "transform" in kinds and "sink" in kinds


def test_env_sensitive_to_network_with_default_alias():
    source = (FIXTURES / "malicious" / "mcp" / "shadow" / "server.py").read_text()
    registry, path = summarize(source, "mcp/shadow/server.py")
    summary = registry.summary_for(path, "bootstrap_telemetry")
    assert summary is not None
    flows = [flow for flow in summary.flows
             if flow.sink_category == "network" and flow.sensitive
             and flow.source_kind in ("env", "env_container")]
    assert flows, summary.flows
    assert flows[0].sink == "httpx.post"
    assert flows[0].status == "proven"


def test_parameter_to_shell_flow():
    source = (FIXTURES / "malicious" / "mcp" / "shadow" / "server.py").read_text()
    registry, path = summarize(source, "mcp/shadow/server.py")
    summary = registry.summary_for(path, "admin_shell")
    flows = [flow for flow in summary.flows if flow.sink_category == "command"]
    assert flows and flows[0].external and flows[0].source_kind == "parameter"
    assert not flows[0].guard


def test_allowlist_guard_marks_flow():
    source = (FIXTURES / "benign" / "mcp" / "safe_sync" / "server.py").read_text()
    registry, path = summarize(source, "mcp/safe_sync/server.py")
    summary = registry.summary_for(path, "run_test")
    flows = [flow for flow in summary.flows if flow.sink_category == "command"]
    assert flows
    assert flows[0].guard == "membership"


def test_unknown_transform_degrades_status():
    source = (
        "import subprocess\n\n"
        "def handler(data):\n"
        "    transformed = obfuscate(data)\n"
        "    subprocess.run(transformed, shell=True)\n"
    )
    registry, path = summarize(source)
    summary = registry.summary_for(path, "handler")
    flows = [flow for flow in summary.flows if flow.sink_category == "command"]
    assert flows
    assert flows[0].status == "unresolved"


def test_unrelated_env_and_http_do_not_trigger_exfil():
    source = (
        "import os\n"
        "import httpx\n\n"
        "TOKEN = os.getenv('API_TOKEN')\n\n"
        "def fetch(url):\n"
        "    return httpx.get(url)\n"
    )
    registry, path = summarize(source)
    flows = all_flows(registry, path)
    assert not [flow for flow in flows if flow.sink_category == "network" and flow.sensitive]


def test_skill_rules_fire_on_fixture(malicious_scan):
    repository, scan_id = malicious_scan
    assert finding_by_rule(repository, scan_id, "AG-STATIC-SKILL-002")
    assert finding_by_rule(repository, scan_id, "AG-STATIC-SKILL-003")
    assert finding_by_rule(repository, scan_id, "AG-STATIC-MCP-001")
    assert finding_by_rule(repository, scan_id, "AG-STATIC-MCP-002")
    assert finding_by_rule(repository, scan_id, "AG-STATIC-MCP-003")
    assert finding_by_rule(repository, scan_id, "AG-STATIC-SKILL-001")
