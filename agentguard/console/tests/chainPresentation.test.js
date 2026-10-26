import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDetectionStages, chronologicalItems } from '../src/utils/chainPresentation.js';

test('阶段使用对应原始事件的决策，不混用同一调用的更强决策', () => {
  const request = { event_id: 'request', decision: { decision: 'ALLOW', severity: 'INFO' } };
  const result = { event_id: 'result', decision: { decision: 'DENY', severity: 'CRITICAL' } };
  const item = { key: 'call', events: [request, result], decision: result.decision };
  const steps = buildDetectionStages([{ stage: 'CRED_ACCESS', event_id: 'request' }], [item]);
  assert.equal(steps.length, 6);
  assert.equal(steps.find(s => s.stage === 'CRED_ACCESS').decision, request.decision);
  assert.equal(steps.find(s => s.stage === 'CRED_ACCESS').item, item);
  assert.equal(steps.find(s => s.stage === 'INJECTION').hit, undefined);
});

test('事件缺失时保留真实阶段命中，不猜测跳转目标', () => {
  const hit = { stage: 'EXFIL', event_id: 'absent' };
  const steps = buildDetectionStages([hit], [{ key: 'other', events: [{ event_id: 'other' }] }]);
  const step = steps.find(s => s.stage === 'EXFIL');
  assert.equal(step.hit, hit);
  assert.equal(step.item, undefined);
  assert.equal(step.decision, undefined);
  assert.equal(buildDetectionStages().filter(s => s.hit).length, 0);
});

test('风险按实际时间排序，支持时区偏移并保持输入数组不变', () => {
  const items = [
    { key: 'pending', timestamp: '2026-10-16T10:02:00+08:00' },
    { key: 'first', timestamp: '2026-10-16T02:00:00Z' },
    { key: 'second', timestamp: '2026-10-16T10:01:00+08:00' },
  ];
  assert.deepEqual(chronologicalItems(items).map(i => i.key), ['first', 'second', 'pending']);
  assert.equal(items[0].key, 'pending');
});

test('同一时间的节点顺序稳定，无效时间不遮盖已知记录', () => {
  const items = [
    { key: 'unknown', timestamp: '' },
    { key: 'a', timestamp: '2026-10-16T02:00:00Z' },
    { key: 'b', timestamp: '2026-10-16T02:00:00Z' },
    { key: 'invalid', timestamp: 'not-a-date' },
  ];
  assert.deepEqual(chronologicalItems(items).map(i => i.key), ['a', 'b', 'unknown', 'invalid']);
});
