#!/usr/bin/env python3
"""Four scoring ablations with training-only calibration and session bootstrap.

    python3 tools/benchmark_detection.py --out /tmp/detection-benchmark

Writes JSON and Markdown. No network, model calls, activation or training-record
updates. The built-in regression fixtures do not establish independent generalization.
"""

import argparse
import hashlib
import json
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection import behavior as B  # noqa: E402

COMPONENTS = ('rarity', 'rarity_intent', 'rarity_context', 'full')


def average_precision(positive, negative):
    if not positive:
        return None
    groups = {}
    for label, values in ((1, positive), (0, negative)):
        for score in values:
            groups.setdefault(score, [0, 0])[label] += 1
    seen = tp = area = 0
    for score in sorted(groups, reverse=True):
        negatives, positives = groups[score]
        seen += negatives + positives
        tp += positives
        area += positives / len(positive) * tp / seen
    return round(area, 4)


def interval(sessions, component, threshold, risk, samples):
    rng = random.Random(20261011)
    population = [session for session in sessions if session['malicious'] == risk and session['scores']]
    rates = []
    for _ in range(samples):
        rows = [row for session in rng.choices(population, k=len(population)) for row in session['scores']
                if not risk or row['risk']]
        if rows:
            rates.append(sum(row['components'][component] >= threshold for row in rows) / len(rows))
    return [round(B._percentile(rates, q), 4) for q in (2.5, 97.5)] if rates else None


def run(samples=500):
    train = B.corpus_sessions()
    fixtures = B.fixture_sessions()
    baseline = B._baseline(A.fit(train), 99)
    scored = [{'malicious': session['malicious'], 'scores': B.score_session(baseline, session)} for session in fixtures]
    groups = {}
    for name in COMPONENTS:
        threshold, cv = B.calibrate(train, 95, name)
        benign = [row['components'][name] for session in scored if not session['malicious'] for row in session['scores']]
        risk = [row['components'][name] for session in scored if session['malicious']
                for row in session['scores'] if row['risk']]
        groups[name] = {
            'threshold': threshold, 'cv_steps': len(cv),
            'cv_over_threshold': sum(score >= threshold for score in cv),
            'benign_steps': len(benign), 'benign_over_threshold': sum(score >= threshold for score in benign),
            'risk_steps': len(risk), 'risk_over_threshold': sum(score >= threshold for score in risk),
            'roc_auc': B._auc(risk, benign), 'pr_auc_average_precision': average_precision(risk, benign),
            'benign_rate_session_bootstrap_95': interval(scored, name, threshold, False, samples),
            'risk_recall_session_bootstrap_95': interval(scored, name, threshold, True, samples),
        }
    snapshot = json.dumps({'train': train, 'fixtures': fixtures}, sort_keys=True, ensure_ascii=False)
    count = baseline.unigram
    return {
        'feature_schema_version': A.FEATURE_SCHEMA_VERSION,
        'sequence_semantics_version': A.SEQUENCE_SEMANTICS_VERSION,
        'snapshot_sha256': hashlib.sha256(snapshot.encode()).hexdigest(),
        'intent_source': 'frozen_keyword', 'train_sessions': len(train), 'fixture_sessions': len(fixtures),
        'calibration': '5-fold session CV on built-in training only, 95th percentile + 0.5',
        'test_threshold_tuning': False, 'independent_generalization_verified': False,
        'bootstrap_samples': samples, 'bootstrap_seed': 20261011, 'groups': groups,
        'vocabulary': len(count), 'symbol_unknown_steps': sum('EXEC:unknown' in step['symbols']
            for session in train for step in session['steps']),
        'detail_symbol_steps': sum(any(A.parent_symbol(symbol) != symbol for symbol in step['symbols'])
            for session in train for step in session['steps']),
        'selection': 'retain full scoring structure; alternatives are observational candidates only',
    }


def render(report):
    lines = ['# AgentGuard 行为模型四组消融', '',
             f"特征版本：{report['feature_schema_version']}；序列语义版本：{report['sequence_semantics_version']}。",
             f"训练会话：{report['train_sessions']}；评测会话：{report['fixture_sessions']}。",
             f"数据快照 SHA-256：`{report['snapshot_sha256']}`。", '',
             '各组独立使用训练语料交叉打分的 95 分位 + 0.5 校准阈值；没有按评测结果调阈值。', '',
             '| 分数 | 阈值 | 良性超阈值 | 风险超阈值 | ROC-AUC | PR-AUC（AP） | 风险召回会话 bootstrap 95% 区间 |',
             '|---|---:|---:|---:|---:|---:|---|']
    for name, item in report['groups'].items():
        lines.append(f"| {name} | {item['threshold']:.2f} | {item['benign_over_threshold']}/{item['benign_steps']} "
                     f"| {item['risk_over_threshold']}/{item['risk_steps']} | {item['roc_auc']} "
                     f"| {item['pr_auc_average_precision']} | {item['risk_recall_session_bootstrap_95']} |")
    lines += ['', f"词表：{report['vocabulary']}；包含细分类的训练步骤：{report['detail_symbol_steps']}；"
              f"EXEC:unknown 训练步骤：{report['symbol_unknown_steps']}。", '',
              '阈值超出描述的是异常模型信号，完整引擎的 ASK/DENY 另行回放统计。',
              '置信区间对现有会话做重采样，不能消除夹具选择偏差；67 个良性步骤不足以验证低误报目标。',
              '本报告没有证明独立泛化收益。保留完整评分结构，不自动启用其他消融模型。', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True, help='Output prefix for .json and .md')
    parser.add_argument('--bootstrap', type=int, default=500)
    args = parser.parse_args(argv)
    if not 1 <= args.bootstrap <= 10000:
        parser.error('--bootstrap must be within 1..10000')
    report = run(args.bootstrap)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    args.out.with_suffix('.md').write_text(render(report))
    print(render(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
