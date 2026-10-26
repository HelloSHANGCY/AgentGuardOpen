"""The complete frozen corpus must work without the original range source or services."""

import json
import shutil
from collections import Counter

import httpx
import pytest

from agentguard.testing.corpus import DATASET, load_corpus
from agentguard.testing.replay import replay_corpus


def test_complete_corpus_replays_without_network(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("offline corpus attempted a network request")

    monkeypatch.setattr(httpx.Client, "send", no_network)
    records, context, manifest = load_corpus()
    assert manifest["total"] == 5200
    assert manifest["benign"] == 5120 and manifest["malicious"] == 80
    assert len(manifest["by_scenario"]) == 11
    results = replay_corpus(records, context)
    assert len(results) == 5200
    assert Counter(row["outcome"] for row in results) == {"TP": 80, "TN": 5120}
    assert all(row["effect_ok"] is None and row["business_ok"] is None for row in results)


@pytest.mark.parametrize("name", ["events.jsonl.gz", "context.json"])
def test_modified_payload_fails_integrity_check(tmp_path, name):
    shutil.copytree(DATASET, tmp_path / "corpus")
    target = tmp_path / "corpus" / name
    target.write_bytes(target.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="integrity mismatch"):
        load_corpus(tmp_path / "corpus")


def test_modified_population_fails_integrity_check(tmp_path):
    shutil.copytree(DATASET, tmp_path / "corpus")
    path = tmp_path / "corpus/manifest.json"
    manifest = json.loads(path.read_text())
    manifest["total"] = 5199
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="population mismatch"):
        load_corpus(tmp_path / "corpus")


def test_offline_iteration_restores_live_signatures_and_does_not_count_online_hits():
    from agentguard.core import normalize as normalize
    from agentguard.rules.library import RuleLibrary
    from agentguard.testing.replay import iter_replay_corpus

    live = RuleLibrary()
    # An empty active rule set must not disable the isolated built-in corpus checks.
    with normalize.scoped_signatures({}, live.record_keyword_hit):
        assert not normalize.is_sensitive_path('/app/.env')
        records, context, _ = load_corpus()
        results = iter_replay_corpus([row for row in records if row['scenario'] == 'C2-B'][:2], context)
        assert next(results)['outcome'] == 'TP'
        assert not normalize.is_sensitive_path('/app/.env')
        results.close()
        assert not normalize.is_sensitive_path('/app/.env')
    assert sum(live.hit_counter.snapshot()['counts'].values()) == 0
