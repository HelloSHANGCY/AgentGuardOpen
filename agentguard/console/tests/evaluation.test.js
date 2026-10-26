import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evalOptions, evalSuite, evalScenario, evalLimit, evalParams,
  suiteNames, suiteScenarios, runSuite, evalMaxLimit,
} from '../src/store/evaluation.js';

test('默认评测使用通用 Hook 夹具，参数只包含套件、场景和上限', () => {
  assert.equal(evalSuite.value, 'claude-code');
  evalScenario.value = 'G-1';
  evalLimit.value = 10;
  assert.deepEqual(evalParams.value, { suite: 'claude-code', scenario: 'G-1', limit: 10 });
  evalScenario.value = 'all';
  evalLimit.value = 100;
});

test('套件场景取自服务端，历史缺少套件标识时保持未知', () => {
  evalOptions.value = { suites: { 'claude-code': ['all', 'G-1', 'BENIGN'] } };
  assert.deepEqual(suiteScenarios.value, ['all', 'G-1', 'BENIGN']);
  assert.equal(suiteNames['claude-code'], 'Claude Code 夹具');
  assert.equal(runSuite({ params: {} }), 'legacy');
  assert.equal(runSuite({ params: { suite: 'claude-code' } }), 'claude-code');
  evalOptions.value = {};
});

test('离线数据集参数支持全量 5200 条，Hook 上限保持 500 条', () => {
  evalOptions.value = { suites: { 'claude-code': ['all', 'G-1'], 'offline-corpus': ['all', 'C2-B', 'B-OPS'] },
    suite_limits: { 'claude-code': 500, 'offline-corpus': 5200 }, max_limit: 500 };
  evalSuite.value = 'offline-corpus';
  evalLimit.value = 5200;
  assert.equal(suiteNames['offline-corpus'], '靶场离线数据集');
  assert.equal(evalMaxLimit.value, 5200);
  assert.deepEqual(suiteScenarios.value, ['all', 'C2-B', 'B-OPS']);
  assert.deepEqual(evalParams.value, { suite: 'offline-corpus', scenario: 'all', limit: 5200 });
  evalSuite.value = 'claude-code';
  assert.equal(evalMaxLimit.value, 500);
  evalLimit.value = 100;
  evalOptions.value = {};
});
