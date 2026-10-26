"""文件索引、Skill 归属、稳定 ID 与限额测试。"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from agentguard.static_scan.inputs import Limits, ensure_within, read_verified_text, snapshot_root
from agentguard.static_scan.inventory import classify
from agentguard.static_scan.models import stable_asset_id


def test_category_classification():
    assert classify("skills/a/SKILL.md") == "skill_md"
    assert classify("app/main.py") == "python"
    assert classify("requirements.txt") == "requirements"
    assert classify("services/api/requirements/base.txt") == "requirements"
    assert classify("poetry.lock") == "lockfile"
    assert classify("docker-compose.yml") == "compose"
    assert classify("docker-compose.agentguard.yml") == "compose"
    assert classify("Dockerfile") == "dockerfile"
    assert classify(".env.example") == "env"
    assert classify("deploy/managed-host.env") == "env"
    assert classify("flows/support.json") == "json"
    assert classify("config/app.yaml") == "yaml"
    assert classify("pyproject.toml") == "toml"
    assert classify("scripts/run.sh") == "shell"


def test_snapshot_excludes_and_skill_ownership(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("x", encoding="utf-8")
    skill = tmp_path / "skills" / "alpha"
    (skill / "scripts").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: alpha\n---\nbody\n", encoding="utf-8")
    (skill / "scripts" / "run.py").write_text("print('x')\n", encoding="utf-8")
    nested = skill / "nested"
    nested.mkdir()
    (nested / "SKILL.md").write_text("---\nname: nested\n---\nbody\n", encoding="utf-8")

    index = snapshot_root(str(tmp_path), Limits())
    paths = {entry.path for entry in index.files}
    assert "skills/alpha/scripts/run.py" in paths
    assert "skills/alpha/SKILL.md" in paths
    assert ".git/config" not in paths
    assert "node_modules/pkg.js" not in paths
    assert index.owner("skills/alpha/scripts/run.py") == "skills/alpha"
    assert index.owner("skills/alpha/nested/SKILL.md") == "skills/alpha/nested"
    assert index.owner("README.md") is None
    assert not index.truncated
    assert index.snapshot_signature().startswith("sha256:")


def test_symlink_and_special_files_rejected(tmp_path):
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(target)
    (tmp_path / "escape").symlink_to("/etc/passwd")
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")

    index = snapshot_root(str(tmp_path), Limits())
    paths = {entry.path for entry in index.files}
    assert paths == {"outside.txt", "real.py"}
    reasons = {item["path"]: item["reason"] for item in index.unsafe}
    assert reasons.get("link.txt") == "symlink"
    assert reasons.get("escape") == "symlink"


def test_file_size_and_depth_limits(tmp_path):
    (tmp_path / "big.py").write_text("x = '" + "a" * 100 + "'\n", encoding="utf-8")
    limits = Limits(max_file_parse_bytes=20)
    index = snapshot_root(str(tmp_path), limits)
    entry = index.get("big.py")
    assert entry.parse_skip == "file_too_large"


def test_read_verified_detects_change(tmp_path):
    path = tmp_path / "a.py"
    path.write_text("x = 1\n", encoding="utf-8")
    index = snapshot_root(str(tmp_path), Limits())
    entry = index.get("a.py")
    assert read_verified_text(str(tmp_path), entry) == "x = 1\n"
    path.write_text("x = 2\n", encoding="utf-8")
    assert read_verified_text(str(tmp_path), entry) is None
    assert entry.read_error == "digest_changed"


def test_ensure_within_blocks_traversal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    import pytest

    with pytest.raises(Exception):
        ensure_within(str(root), str(outside))
    assert ensure_within(str(root), str(root / "inside.txt")).startswith(str(root))


def test_stable_asset_id_is_deterministic():
    first = stable_asset_id("proj", "Skill", "skill:skills/a")
    second = stable_asset_id("proj", "Skill", "skill:skills/a")
    other = stable_asset_id("proj", "Skill", "skill:skills/b")
    assert first == second
    assert first != other
