import test from 'node:test';
import assert from 'node:assert/strict';
import { ruleHash, parseRuleHash } from '../src/utils/ruleNavigation.js';

test('规则库旧入口与特征、策略详情书签兼容', () => {
  assert.deepEqual(parseRuleHash('#/rules'), {tab:'features', identifier:'', revision:''});
  assert.deepEqual(parseRuleHash(ruleHash('strategies', 'AG-RUNTIME-002')), {tab:'strategies', identifier:'AG-RUNTIME-002', revision:''});
  assert.deepEqual(parseRuleHash(ruleHash('features', 'SIG-CRED-001', 'abc123')), {tab:'features', identifier:'SIG-CRED-001', revision:'abc123'});
});

test('特征标识与版本中的特殊字符只编码解码一次', () => {
  const id = '自定义/%3F?#', revision = 'v 1&next=value';
  assert.deepEqual(parseRuleHash(ruleHash('features', id, revision)), {tab:'features', identifier:id, revision});
});

test('错误编码、未知页签和其他页面不生成规则详情', () => {
  for (const hash of ['#/rules/features/%ZZ', '#/rules/unknown/abc', '#/audit/sessions/abc']) {
    assert.equal(parseRuleHash(hash), null);
  }
});
