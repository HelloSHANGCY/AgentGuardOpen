"""Evaluation authentication, isolation and generic Hook worker lifecycle."""
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agentguard.evaluation import (
    EvaluationConfig,
    EvaluationRepository,
    EvaluationWorker,
    StartEvaluation,
    build_evaluation_api,
    summarize,
)


@pytest.fixture
def environment(tmp_path):
    config = EvaluationConfig(db=str(tmp_path / 'evaluation.db'), token='test-admin', local_test=False)
    repo = EvaluationRepository(config.db)
    app = FastAPI()
    app.include_router(build_evaluation_api(config, repo))
    return config, repo, TestClient(app)


def test_auth_validation_and_single_job(environment):
    config, repo, client = environment
    headers = {'X-AG-Eval-Token': config.token}
    assert client.post('/v1/evaluations', json={}).status_code == 401
    assert client.get('/v1/evaluations').status_code == 401
    assert client.post('/v1/evaluations', json={}, headers=headers).status_code == 503
    repo.heartbeat()
    for body in [{'scenario': '; rm -rf /'}, {'limit': 501}, {'limit': True}, {'suite': 'opspilot'}, {'target': 'http://other'}, {'command': 'echo x'}]:
        assert client.post('/v1/evaluations', json=body, headers=headers).status_code == 422
    first = client.post('/v1/evaluations', json={}, headers=headers)
    assert first.status_code == 202
    run_id = first.json()['run_id']
    assert client.post('/v1/evaluations', json={}, headers=headers).status_code == 409
    assert client.get(f'/v1/evaluations/{run_id}/report', headers=headers).status_code == 409
    assert client.post(f'/v1/evaluations/{run_id}/cancel', headers=headers).json()['status'] == 'CANCELLED'
    assert repo.claim() is None
    assert client.post('/v1/evaluations', json={}, headers=headers).status_code == 202
    config.token = ''
    assert client.get('/v1/evaluations', headers=headers).status_code == 503

def test_summary_groups_scenarios_and_reasons():
    rows = [
        {'outcome': 'TP', 'scenario': 'C2-B', 'malicious': True, 'decisions': {'DENY': 1}, 'effect_ok': True},
        {'outcome': 'TN', 'scenario': 'B-RD', 'malicious': False, 'decisions': {}, 'business_ok': True, 'effect_ok': True},
        {'outcome': 'UNKNOWN', 'scenario': 'B-RD', 'malicious': False, 'unknown_reason': 'no_decisions_for_trace'},
        {'outcome': 'ERROR', 'scenario': 'C2-A', 'malicious': True, 'error': 'ReadTimeout'},
    ]
    result = summarize(rows)
    assert result['by_scenario']['C2-B']['tp'] == 1
    assert result['by_scenario']['B-RD']['tn'] == 1 and result['by_scenario']['B-RD']['unknown'] == 1
    assert result['by_type']['malicious']['tp'] == 1 and result['by_type']['benign']['tn'] == 1
    assert result['decision_counts'] == {'ALLOW': 0, 'ASK': 0, 'DENY': 1}
    assert result['unknown_reasons'] == {'no_decisions_for_trace': 1}
    assert result['error_reasons'] == {'ReadTimeout': 1}
    assert result['effect_checks'] == {'passed': 2, 'failed': 0, 'not_checked': 2}
    assert result['business_checks'] == {'passed': 1, 'failed': 0, 'not_checked': 3}

def test_fpr_uses_negative_population():
    result = summarize([{'outcome': k} for k in ['TP', 'TP', 'FP', 'TN', 'TN', 'TN', 'UNKNOWN', 'ERROR']])
    assert result['false_positive_rate'] == .25
    assert result['precision'] == 2 / 3
    assert result['evaluated'] == 6

def test_local_mode_without_token_supports_task_lifecycle(environment):
    config, repo, client = environment
    config.local_test = True
    config.token = ''
    repo.heartbeat()
    options = client.get('/v1/evaluations/options').json()
    assert options['enabled'] and not options['auth_required']
    response = client.post('/v1/evaluations', json={'limit': 1})
    assert response.status_code == 202
    run_id = response.json()['run_id']
    assert client.get('/v1/evaluations').status_code == 200
    assert client.get(f'/v1/evaluations/{run_id}').status_code == 200
    assert client.post(f'/v1/evaluations/{run_id}/cancel').status_code == 200
    assert client.get(f'/v1/evaluations/{run_id}/report').status_code == 200

def test_explicit_token_still_enforced_in_local_mode(environment):
    config, repo, client = environment
    config.local_test = True
    repo.heartbeat()
    assert client.get('/v1/evaluations/options').json()['auth_required']
    assert client.post('/v1/evaluations', json={}).status_code == 401
    assert client.post('/v1/evaluations', json={}, headers={'X-AG-Eval-Token':'wrong'}).status_code == 401
    assert client.post('/v1/evaluations', json={}, headers={'X-AG-Eval-Token':config.token}).status_code == 202


def test_removed_suite_cannot_be_enqueued(environment):
    config, repo, client = environment
    repo.heartbeat()
    assert set(client.get('/v1/evaluations/options').json()['suites']) == {'claude-code', 'offline-corpus'}
    assert client.post('/v1/evaluations', json={'suite': 'opspilot'},
                       headers={'X-AG-Eval-Token': config.token}).status_code == 422


@pytest.mark.parametrize('suite', ['claude-code', 'offline-corpus'])
@pytest.mark.parametrize('mode,status', [('cancel', 'CANCELLED'), ('timeout', 'TIMED_OUT'),
                                       ('failure', 'FAILED'), ('complete', 'COMPLETED')])
def test_worker_lifecycle_without_target_services(environment, monkeypatch, suite, mode, status):
    config, repo, _ = environment
    config.timeout = -1 if mode == 'timeout' else 10
    job = repo.create(StartEvaluation(suite=suite).model_dump())
    worker = EvaluationWorker(config, repo)

    def run(job, check):
        if mode == 'cancel':
            repo.cancel(job['run_id'])
        if mode == 'failure':
            raise RuntimeError('fixture failure')
        check()

    monkeypatch.setattr(worker, 'run_offline_corpus' if suite == 'offline-corpus' else 'run_claude_code', run)
    try:
        worker.execute(repo.claim())
        assert repo.get(job['run_id'])['status'] == status
        assert repo.create(StartEvaluation().model_dump())
    finally:
        worker.client.close()


def test_offline_options_validation_and_defaults(environment):
    config, repo, client = environment
    options = client.get('/v1/evaluations/options').json()
    assert options['suite_limits'] == {'claude-code': 500, 'offline-corpus': 5200}
    assert options['suite_defaults']['offline-corpus'] == 5200
    assert len(options['suites']['offline-corpus']) == 12
    assert options['datasets']['offline-corpus']['malicious'] == 80
    assert StartEvaluation(suite='offline-corpus').limit == 5200
    assert StartEvaluation().limit == 100
    repo.heartbeat()
    headers = {'X-AG-Eval-Token': config.token}
    for body in [{'suite': 'offline-corpus', 'scenario': 'G-1'}, {'suite': 'claude-code', 'scenario': 'C2-B'},
                 {'suite': 'offline-corpus', 'limit': 5201}, {'suite': 'offline-corpus', 'limit': True},
                 {'suite': 'offline-corpus', 'dataset_path': '/tmp/other'}]:
        assert client.post('/v1/evaluations', json=body, headers=headers).status_code == 422


def test_full_offline_job_report_without_network_execution_or_online_writes(environment, monkeypatch, tmp_path):
    config, repo, client = environment
    repo.heartbeat()
    headers = {'X-AG-Eval-Token': config.token}
    response = client.post('/v1/evaluations', json={'suite': 'offline-corpus'}, headers=headers)
    assert response.status_code == 202
    run_id = response.json()['run_id']
    worker = EvaluationWorker(config, repo)
    untouched = tmp_path / 'online-data'
    monkeypatch.setenv('AG_DATA_DIR', str(untouched))
    monkeypatch.setenv('AG_AGENT_DEVICE_DIR', str(untouched))
    monkeypatch.setenv('AG_BEHAVIOR_DIR', str(untouched))

    def forbidden(*args, **kwargs):
        raise AssertionError('offline evaluation must not send requests or execute processes')

    saves = []
    save = repo.save

    def track_save(job, status=None):
        saves.append(job['completed'])
        return save(job, status)

    monkeypatch.setattr(repo, 'save', track_save)
    try:
        with monkeypatch.context() as isolated:
            isolated.setattr(httpx.Client, 'send', forbidden)
            isolated.setattr(subprocess, 'Popen', forbidden)
            worker.execute(repo.claim())
        job = repo.get(run_id)
        assert job['status'] == 'COMPLETED', job['error']
        assert job['total'] == job['completed'] == len(job['rows']) == 5200
        assert job['summary']['tp'] == 80 and job['summary']['tn'] == 5120
        assert job['summary']['fp'] == job['summary']['fn'] == 0
        assert job['summary']['by_type']['malicious']['tp'] == 80
        assert job['summary']['effect_checks'] == {'passed': 0, 'failed': 0, 'not_checked': 5200}
        assert job['summary']['business_checks'] == {'passed': 0, 'failed': 0, 'not_checked': 5200}
        assert job['scope'] == 'offline_request_checks'
        for key in ['tool_execution', 'side_effects_verified', 'business_success_verified',
                    'network_boundary_verified', 'full_acceptance_verified']:
            assert job[key] is False
        assert all(not row.get('trace_id') and row['case'] == row['instance_id'] for row in job['rows'])
        assert not untouched.exists()
        assert 0 < len(saves) < 200 and any(0 < n < 5200 for n in saves)
        detail = client.get(f'/v1/evaluations/{run_id}', headers=headers).json()
        assert len(detail['rows']) == 100 and detail['completed'] == 5200
        report = client.get(f'/v1/evaluations/{run_id}/report', headers=headers).json()
        assert len(report['rows']) == 5200
        assert report['dataset']['dataset_id'] == 'range-v1'
        assert report['dataset']['files']['events.jsonl.gz']['sha256']
    finally:
        worker.client.close()


@pytest.mark.parametrize('scenario,limit,outcome', [('C2-B', 5, 'TP'), ('B-OPS', 3, 'TN')])
def test_offline_scenario_limit_and_sample_labels(environment, scenario, limit, outcome):
    config, repo, _ = environment
    job = repo.create(StartEvaluation(suite='offline-corpus', scenario=scenario, limit=limit).model_dump())
    worker = EvaluationWorker(config, repo)
    try:
        worker.execute(repo.claim())
        result = repo.get(job['run_id'])
        assert result['status'] == 'COMPLETED', result['error']
        assert result['completed'] == result['total'] == limit
        assert all(row['scenario'] == scenario and row['outcome'] == outcome for row in result['rows'])
        assert all(row['malicious'] == (outcome == 'TP') for row in result['rows'])
        assert set(result['summary']['by_scenario']) == {scenario}
    finally:
        worker.client.close()


def test_offline_cancellation_preserves_published_results(environment, monkeypatch):
    config, repo, _ = environment
    job = repo.create(StartEvaluation(suite='offline-corpus').model_dump())
    save = repo.save

    def cancel_after_progress(job, status=None):
        save(job, status)
        if status is None and job['completed']:
            repo.cancel(job['run_id'])

    monkeypatch.setattr(repo, 'save', cancel_after_progress)
    worker = EvaluationWorker(config, repo)
    try:
        worker.execute(repo.claim())
        result = repo.get(job['run_id'])
        assert result['status'] == 'CANCELLED'
        assert 0 < result['completed'] < result['total']
        assert result['completed'] == len(result['rows']) == result['summary']['evaluated']
        assert repo.create(StartEvaluation(suite='offline-corpus', limit=1).model_dump())
    finally:
        worker.client.close()


def test_offline_integrity_failure_is_reported_and_releases_queue(environment, monkeypatch):
    import agentguard.evaluation as evaluation

    config, repo, _ = environment
    job = repo.create(StartEvaluation(suite='offline-corpus').model_dump())

    def invalid_corpus():
        raise ValueError('corpus integrity mismatch')

    monkeypatch.setattr(evaluation, 'load_corpus', invalid_corpus)
    worker = EvaluationWorker(config, repo)
    try:
        worker.execute(repo.claim())
        result = repo.get(job['run_id'])
        assert result['status'] == 'FAILED'
        assert '完整性校验失败' in result['error']
        assert result['completed'] == 0 and result['rows'] == []
        assert repo.create(StartEvaluation(suite='offline-corpus').model_dump())
    finally:
        worker.client.close()


def test_old_running_job_is_interrupted_and_old_queued_suite_fails(environment):
    config, repo, _ = environment
    job = repo.create({'suite': 'opspilot'})
    worker = EvaluationWorker(config, repo)
    try:
        worker.execute(repo.claim())
        assert repo.get(job['run_id'])['status'] == 'FAILED'
        assert '已移除' in repo.get(job['run_id'])['error']
        job = repo.create(StartEvaluation().model_dump())
        repo.claim()
        worker.recover()
        assert repo.get(job['run_id'])['status'] == 'INTERRUPTED'
    finally:
        worker.client.close()


def test_service_has_no_implicit_target_upstreams(monkeypatch):
    from agentguard import config

    monkeypatch.setattr(config, 'DEFAULT_UPSTREAMS', {})
    monkeypatch.delenv('AG_EXTRA_UPSTREAMS', raising=False)
    monkeypatch.delenv('AG_C2_HOSTS', raising=False)
    settings = config.load_settings()
    assert settings.upstreams == {} and settings.c2_hosts == ()
    monkeypatch.setenv('AG_EXTRA_UPSTREAMS', '{"docs":"http://mcp.example/mcp"}')
    assert config.load_settings().upstreams == {'docs': 'http://mcp.example/mcp'}
