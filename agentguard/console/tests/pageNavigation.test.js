import test from 'node:test';
import assert from 'node:assert/strict';
import { createPageNavigation } from '../src/utils/pageNavigation.js';

test('普通切换同步生效，拒绝离开时保留原页', () => {
  const navigation = createPageNavigation('threat');
  navigation.page.value = 'models';
  assert.equal(navigation.page.value, 'models');
  navigation.registerGuard(() => false);
  navigation.page.value = 'events';
  assert.equal(navigation.page.value, 'models');
});

test('等待编辑确认时不切页，确认后才应用对应页面参数', async () => {
  const navigation = createPageNavigation('models');
  let resolve, applied = false;
  navigation.registerGuard(() => new Promise(done => { resolve = done; }));
  const result = navigation.navigate('chain', () => { applied = true; });
  assert.equal(navigation.page.value, 'models');
  assert.equal(applied, false);
  resolve(true);
  assert.equal(await result, true);
  assert.equal(navigation.page.value, 'chain');
  assert.equal(applied, true);
});

test('取消编辑确认不会应用目标页面参数', async () => {
  const navigation = createPageNavigation('models');
  let applied = false;
  navigation.registerGuard(async () => false);
  assert.equal(await navigation.navigate('chain', () => { applied = true; }), false);
  assert.equal(navigation.page.value, 'models');
  assert.equal(applied, false);
});

test('连续导航仅应用最后一次请求，较慢的旧确认不会覆盖新页面', async () => {
  const navigation = createPageNavigation('models');
  const decisions = [];
  navigation.registerGuard(() => new Promise(resolve => decisions.push(resolve)));
  const first = navigation.navigate('events');
  const second = navigation.navigate('rules');
  decisions[1](true);
  assert.equal(await second, true);
  decisions[0](true);
  assert.equal(await first, false);
  assert.equal(navigation.page.value, 'rules');
});

test('旧编辑器注销时不会移除后来注册的离开检查', () => {
  const navigation = createPageNavigation('models');
  const unregisterFirst = navigation.registerGuard(() => true);
  const unregisterSecond = navigation.registerGuard(() => false);
  unregisterFirst();
  navigation.page.value = 'events';
  assert.equal(navigation.page.value, 'models');
  unregisterSecond();
  navigation.page.value = 'events';
  assert.equal(navigation.page.value, 'events');
});
