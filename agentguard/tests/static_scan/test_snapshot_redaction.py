"""设备快照脱敏不能破坏可解析源码、证据行号或危险代码检测。"""

import ast

import pytest

from agentguard.core.asset_snapshot import SECRET_MARKER, sanitize_text
from agentguard.static_scan.models import ScanRecord
from agentguard.static_scan.repository import Repository
from agentguard.static_scan.scanner import run_scan


@pytest.mark.parametrize("source", [
    'def check(tokens: list[str]):\n    if tokens:\n        return tokens[0]\n',
    'import os\napi_key = os.getenv("API_KEY")\nif not api_key:\n    print("missing")\n',
    'tokens = [part for part in "a b".split() if part]\ncount = len(tokens)\n',
    'def validate(design_tokens: dict[str, str]):\n    return design_tokens.get("primary")\n',
    'tokens: list[str] = []\nfor token in tokens:\n    print(token)\n',
    'if "token: value" in document:\n    print(document)\n',
])
def test_python_control_flow_annotations_and_expressions_remain_valid(source):
    result = sanitize_text("user/.agents/skills/demo/script.py", source)
    ast.parse(result)
    assert result.count("\n") == source.count("\n")
    assert sanitize_text("script.py", result) == result
    if 'os.getenv("API_KEY")' in source:
        assert 'os.getenv("API_KEY")' in result


@pytest.mark.parametrize("source", [
    'api_key = "private-value"\n',
    'password: str = "private-value"\n',
    'if (token := "private-value"):\n    print(token)\n',
    'client = Client(api_key="private-value")\n',
    'config = {"env": {"API_KEY": "private-value"}}\n',
    'config = {"headers": {"X-Custom": "private-value"}}\n',
    'config["api_key"] = "private-value"\n',
    'args = ["--api-key", "private-value"]\n',
    'def helper(password="private-value", *, token="private-value"):\n    return password\n',
    'api_key = os.getenv("API_KEY", "private-value")\n',
    'api_key = ("private-"\n           "value")\n',
    'password = """private-value\nsecond-line\n"""\n',
    'password = b"private-value"\n',
    'api_key = f"private-value-{suffix}"\n',
    'label = "中文"; api_key = "private-value"\r\nprint(label)\r\n',
    '# api_key=private-value\nprint("safe")\n',
    'password = ("private-"  # token=private-value\n            "value")\nprint("safe")\n',
])
def test_python_credentials_are_masked_without_changing_syntax_or_line_numbers(source):
    result = sanitize_text("script.py", source)
    ast.parse(result)
    assert "private-value" not in result and "private-" not in result
    assert SECRET_MARKER in result
    assert result.count("\n") == source.count("\n")
    assert sanitize_text("script.py", result) == result
    if "os.getenv" in source:
        assert 'os.getenv("API_KEY"' in result


def test_original_invalid_python_stays_a_coverage_gap_without_uploading_literals():
    source = 'password = "private-value"\nif True print("payload")\n'
    result = sanitize_text("script.py", source)
    assert "private-value" not in result
    with pytest.raises(SyntaxError):
        ast.parse(result)


def test_snapshot_scan_retains_dangerous_code_and_counts_only_successfully_parsed_files(tmp_path):
    repository = Repository(str(tmp_path / "scan.db"))
    root = tmp_path / "snapshot"
    scripts = root / "user/.agents/skills/demo"
    scripts.mkdir(parents=True)
    (scripts / "SKILL.md").write_text("---\nname: demo\n---\nTest helper\n")
    source = ('import os\napi_key = os.getenv("API_KEY", "private-value")\n'
              'def run(tokens: list[str], command):\n    os.system(command)\n')
    (scripts / "safe_parse.py").write_text(sanitize_text("safe_parse.py", source))
    (scripts / "invalid.py").write_text('if True print("invalid")\n')
    repository.create_scan(ScanRecord("scan-redaction", "test", "device:test:codex",
                                      source_path=str(root), device_id="test", agent="codex"))
    record = run_scan("scan-redaction", repository, {})
    coverage = repository.get_coverage(record.scan_id)
    assert record.status == "PARTIAL" and record.error == ""
    assert coverage.failed_files == 1 and coverage.parsed_files == 2
    assert any("invalid.py:ast:SyntaxError" in note for note in coverage.notes)
    assert not any("safe_parse.py:ast:" in note for note in coverage.notes)
    findings = repository.get_findings(record.scan_id)["items"]
    assert "AG-STATIC-CODE-001" in {item.rule_id for item in findings}
