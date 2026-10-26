import test from 'node:test';
import assert from 'node:assert/strict';
import { auditHash, parseAuditHash } from '../src/utils/auditNavigation.js';

test('运行审计入口与旧事件书签使用同一页面', () => {
  for (const hash of ['#/audit', '#/audit/', '#/events', '#/chain', '#/audit/sessions']) {
    assert.deepEqual(parseAuditHash(hash), { page: 'events', identifier: '' });
  }
  assert.equal(auditHash(), '#/audit');
});

test('旧链路书签保留会话标识并生成审计详情链接', () => {
  const old = parseAuditHash('#/chain/session-01');
  assert.deepEqual(old, { page: 'chain', identifier: 'session-01' });
  assert.equal(auditHash(old.identifier), '#/audit/sessions/session-01');
});

test('会话标识中的斜杠、百分号与中文只解码一次', () => {
  for (const identifier of ['trace/a b', '原始会话#1', 'literal%2Fvalue', 'decision?round=2']) {
    assert.deepEqual(parseAuditHash(auditHash(identifier)), { page: 'chain', identifier });
    assert.deepEqual(parseAuditHash('#/chain/' + encodeURIComponent(identifier)), { page: 'chain', identifier });
  }
});

test('无效编码与其他页面不冒充审计详情', () => {
  for (const hash of ['#/chain/%E0%A4%A', '#/audit/sessions/%ZZ', '#/audit/unknown', '#/metrics/runtime', '#/threat']) {
    assert.equal(parseAuditHash(hash), null);
  }
});
