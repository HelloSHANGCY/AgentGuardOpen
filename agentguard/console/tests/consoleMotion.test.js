import test from 'node:test';
import assert from 'node:assert/strict';
import { motionMilliseconds } from '../src/utils/motion.js';

test('开发与压缩构建的 CSS 时间单位得到相同毫秒数', () => {
  for (const token of ['400ms', ' 400ms ', '.4s', '0.4s']) assert.equal(motionMilliseconds(token), 400);
  assert.equal(motionMilliseconds('1.2s'), 1200);
  assert.equal(motionMilliseconds('160ms'), 160);
});

test('零时长保留，缺失与无效时间使用默认值', () => {
  for (const token of ['0ms', '0s']) assert.equal(motionMilliseconds(token), 0);
  for (const token of ['', undefined, 'fast', '-1ms', '400']) assert.equal(motionMilliseconds(token), 400);
  assert.equal(motionMilliseconds('', 240), 240);
});
