import test from 'node:test';
import assert from 'node:assert/strict';
import { buildThreatStatistics, matchesThreatVisualization, threatTimestamp } from '../src/utils/threatStatistics.js';

const now = '2026-10-18T08:00:00Z';
const decision = (id, at, severity = 'HIGH', extra = {}) => ({decision_id: id, created_at: at, severity, decision: 'DENY', reason_code: 'COMMAND_INJECTION', ...extra});
const group = (items, extra = {}) => ({items, severity: 'CRITICAL', disposition: 'DENY', count: items.length, source: {key: 'codex', label: 'Codex'}, ...extra});

test('展开合并记录，按每次实际时间与级别分桶，不使用组合最高级别', () => {
  const stats = buildThreatStatistics([group([
    decision('one', '2026-10-18T06:10:00Z', 'LOW'),
    decision('two', '2026-10-18T07:30:00Z', 'CRITICAL'),
    decision('old', '2026-10-16T08:00:00Z'),
  ])], '24h', now);
  assert.equal(stats.total, 2);
  assert.equal(stats.buckets[22].LOW, 1);
  assert.equal(stats.buckets[23].CRITICAL, 1);
  assert.equal(stats.severities.CRITICAL, 1);
  assert.equal(stats.blocked, 2);
  assert.equal(stats.categories[0].count, 2);
});

test('同一决策去重，模型告警独立计数，复核放行和用户批准不计为阻断', () => {
  const d = decision('same', now);
  const stats = buildThreatStatistics([
    group([d, {...d}]), group([d]),
    group([decision('same', now, 'HIGH', {decision: undefined})], {analysis: {agent: 'codex'}, source: {key: 'judge', label: '大模型研判'}}),
    group([decision('release', now, 'LOW', {decision: 'ALLOW', review: {static: 'DENY'}})]),
    group([decision('approved', now, 'MEDIUM', {decision: 'ASK', resolution: 'APPROVED'})]),
  ], '24h', now);
  assert.equal(stats.total, 4);
  assert.equal(stats.blocked, 1);
  assert.equal(stats.buckets.reduce((sum, row) => sum + row.total, 0), stats.total);
});

test('时间窗口边界包含首尾，排除未来、缺失和无效时间，支持 UTC 无时区格式', () => {
  const stats = buildThreatStatistics([group([
    decision('start', '2026-10-17T08:00:00Z'),
    decision('before', '2026-10-17T07:59:59.999Z'),
    decision('end', '2026-10-18T08:00:00'),
    decision('future', '2026-10-18T08:00:00.001Z'),
    decision('missing', ''), decision('invalid', 'bad'),
  ])], '24h', now);
  assert.equal(stats.total, 2);
  assert.equal(stats.buckets[0].total, 1);
  assert.equal(stats.buckets[23].total, 1);
  assert.equal(threatTimestamp('2026-10-18 08:00:00'), Date.parse(now));
  assert.equal(threatTimestamp('2026-10-18T16:00:00+08:00'), Date.parse(now));
});

test('24小时、7天、30天范围独立聚合，其他类型保留所有尾部计数和原因', () => {
  const records = [group(Array.from({length: 9}, (_, i) => decision('type' + i, now, 'HIGH', {reason_code: 'TYPE_' + i}))),
    group([decision('week', '2026-10-13T08:00:00Z'), decision('month', '2026-09-23T08:00:00Z')])];
  assert.equal(buildThreatStatistics(records, '24h', now).total, 9);
  assert.equal(buildThreatStatistics(records, '7d', now).total, 10);
  const stats = buildThreatStatistics(records, '30d', now);
  assert.equal(stats.total, 11);
  assert.equal(stats.categories.reduce((sum, item) => sum + item.count, 0), stats.total);
  assert.equal(stats.categories.at(-1).key, '__other__');
  assert.ok(stats.categories.at(-1).codes.length >= 3);
});

test('热点按实际来源、主体、分析 Agent 区分，缺失主体不虚构设备，会话去重', () => {
  const stats = buildThreatStatistics([
    group([decision('a', now, 'LOW', {trace_id: 't1', context: {actor: 'alice'}}), decision('b', now, 'CRITICAL', {trace_id: 't1', context: {actor: 'alice'}})]),
    group([decision('c', now, 'HIGH', {trace_id: 't2', context: {actor: 'bob'}}), decision('d', now)]),
  ], '24h', now);
  assert.equal(stats.hotspots.length, 3);
  assert.equal(stats.hotspots[0].actor, 'alice');
  assert.equal(stats.hotspots[0].sessions, 1);
  assert.equal(stats.hotspots[0].severity, 'CRITICAL');
  assert.equal(stats.hotspots.find(row => !row.actor).sessions, 0);
});

test('联动筛选同时匹配时段和原始类型或主体，清空筛选恢复全部组合', () => {
  const alert = group([decision('old', '2026-10-13T08:00:00Z', 'HIGH', {reason_code: 'OLD'}), decision('a', now, 'LOW', {context: {actor: 'alice'}})]);
  const category = {kind: 'category', codes: ['OLD'], period: '24h'};
  assert.equal(matchesThreatVisualization(alert, category, now), false);
  assert.equal(matchesThreatVisualization(alert, {...category, period: '7d'}, now), true);
  const key = buildThreatStatistics([alert], '24h', now).hotspots[0].key;
  assert.equal(matchesThreatVisualization(alert, {kind: 'hotspot', key, period: '24h'}, now), true);
  assert.equal(matchesThreatVisualization(alert, {kind: 'hotspot', key: 'another', period: '24h'}, now), false);
  assert.equal(matchesThreatVisualization(alert, null, now), true);
});

test('空数据保留真实零，无效级别单列，不更改输入', () => {
  const records = [group([decision('a', now, 'NEW_LEVEL')])];
  const snapshot = JSON.stringify(records);
  const stats = buildThreatStatistics(records, '24h', now);
  assert.equal(stats.severities.UNKNOWN, 1);
  assert.equal(stats.total, 1);
  assert.equal(JSON.stringify(records), snapshot);
  const empty = buildThreatStatistics([], '24h', now);
  assert.equal(empty.total, 0);
  assert.equal(empty.blocked, 0);
  assert.ok(empty.buckets.every(bucket => bucket.total === 0));
  assert.equal(buildThreatStatistics(records, '24h', '').total, 0);
});
