import { customRef } from 'vue';

// 保持现有 tab.value 接口，所有页面切换先经过编辑器注册的离开检查。
export function createPageNavigation(initial) {
  let value = initial, notify, guard, revision = 0;
  function navigate(next, after = () => {}) {
    const current = ++revision;
    const commit = allowed => {
      if (current !== revision || !allowed) return false;
      if (next !== value) { value = next; notify(); }
      after();
      return true;
    };
    const result = next === value || !guard ? true : guard(next);
    return result && typeof result.then === 'function' ? result.then(commit) : commit(result);
  }
  const page = customRef((track, trigger) => {
    notify = trigger;
    return { get() { track(); return value; }, set(next) { navigate(next); } };
  });
  function registerGuard(check) {
    guard = check;
    return () => { if (guard === check) guard = undefined; };
  }
  return { page, navigate, registerGuard };
}
