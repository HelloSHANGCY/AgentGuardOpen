import test from 'node:test';
import assert from 'node:assert/strict';
import { chartValue, comparisonRows, defaultVersions, formatMetric, sourceLabel } from '../src/utils/baselineComparison.js';

test('未定义指标保持为空，不转换成零分雷达轴或柱值', () => {
  for (const value of [null, undefined, NaN, Infinity, false, '0.8']) {
    assert.equal(chartValue(value), null);
    assert.equal(formatMetric(value), '—');
  }
  assert.equal(chartValue(0), 0);
  assert.equal(formatMetric(0), '0.00%');
  assert.ok(comparisonRows(null, null).every(row => row.delta === '—' && row.tone === 'neutral'));
});

test('AUC 图中缩放为百分制，表格保持原始 0–1 单位', () => {
  assert.equal(chartValue(0.852), 85.2);
  assert.equal(formatMetric(0.852, 'auc'), '0.852');
  const row = comparisonRows({metrics: {auc: 0.916}}, {metrics: {auc: 0.852}}).find(row => row.key === 'auc');
  assert.equal(row.delta, '−0.064');
  assert.equal(row.tone, 'worse');
});

test('交换 A/B 后百分点符号和改善方向同步反转', () => {
  const a = {metrics: {f1: 0.8461538461538461}}, b = {metrics: {f1: 0.7692307692307693}};
  const before = comparisonRows(a, b).find(row => row.key === 'f1');
  const after = comparisonRows(b, a).find(row => row.key === 'f1');
  assert.equal(before.delta, '−7.69 pp');
  assert.equal(before.tone, 'worse');
  assert.equal(after.delta, '+7.69 pp');
  assert.equal(after.tone, 'better');
});

test('正常步骤超阈值率下降标记为改善，阈值和规模变化保持中性', () => {
  const a = {metrics: {normal_trigger_rate: 0.18}, threshold: 8, training: {steps: 264}};
  const b = {metrics: {normal_trigger_rate: 0.02}, threshold: 9, training: {steps: 270114}};
  const rows = comparisonRows(a, b);
  assert.equal(rows.find(row => row.key === 'normal_trigger_rate').tone, 'better');
  assert.equal(rows.find(row => row.key === 'threshold').tone, 'neutral');
  assert.equal(rows.find(row => row.key === 'steps').tone, 'neutral');
  assert.equal(rows.find(row => row.key === 'steps').delta, '+269,850');
});

test('浮点误差不显示虚假的差值或改善颜色', () => {
  const row = comparisonRows({metrics: {accuracy: 0.1 + 0.2}}, {metrics: {accuracy: 0.3}})[0];
  assert.equal(row.delta, '0.00 pp');
  assert.equal(row.tone, 'neutral');
});

test('默认使用内置与当前启用版本，过滤不兼容版本并补充第三版本', () => {
  const models = [{version: 'builtin'}, {version: 'newest'}, {version: 'old-active'}, {version: 'legacy', compatible: false}];
  assert.deepEqual(defaultVersions(models, 'old-active'), {a: 'builtin', b: 'old-active', c: 'newest'});
  assert.deepEqual(defaultVersions(models, 'builtin'), {a: 'builtin', b: 'newest', c: 'old-active'});
  assert.deepEqual(defaultVersions([{version: 'legacy', compatible: false}], 'legacy'), {a: '', b: '', c: ''});
});

test('模型来源区分内置、SWE-chat、接入和只用内置语料的重训', () => {
  assert.equal(sourceLabel({version: 'builtin'}), '内置');
  assert.equal(sourceLabel({version: 'builtin-legacy', builtin: true}), '原始一阶内置');
  assert.equal(sourceLabel({version: 'builtin', builtin: true, meta: {external_sessions: 2983}}), '内置 · SWE-chat 2983');
  assert.equal(sourceLabel({meta: {external_sessions: 2983}}), 'SWE-chat 2983');
  assert.equal(sourceLabel({meta: {recorded_sessions: 7}}), '接入 7');
  assert.equal(sourceLabel({meta: {corpus_sessions: 49}}), '内置重训');
});
