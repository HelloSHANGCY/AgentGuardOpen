/* 只动画可见的内容区；保留 v-show 页面的筛选、滚动和表单状态。 */
import { motionMilliseconds } from '../utils/motion';

const TARGETS = [
  '.console-page-head', '.tc-overview', '.tc-tools', '.tc-panel',
  '.ef-overview', '.ef-panel', '.rl-overview > *', '.rl-filters', '.rl-workspace',
  '.baseline-overview > *', '.baseline-workspace > *', '.baseline-models', '.baseline-result',
  '.bc-controls', '.bc-charts > *', '.bc-table-card',
  '.js-kpis > *', '.js-chart-panel', '.judge-card', '.judge-overview > *', '.intent-card',
  '.mt-latest-grid', '.mt-history-overview', '.mt-history-body', '.mt-kpi-grid', '.mt-result-grid',
  '.mt-runtime-overview', '.mt-chart-panel', '.mt-runtime-details', '.mt-run-content',
  '.sa-summary > *', '.sa-panel', '.coverage-grid', '.graph-wrap', '.form-card',
  '.inventory-toolbar', '.device-table', '.device-card-view', '.device-enrollments',
  '.deployment-card', '.deployment-approval', '.policy-picker', '.policy-detail', '.models-card',
  '.deployment-overview', '.deployment-flow-controls', '.deployment-graph-panel', '.deployment-inspector',
  '.deployment-volume-panel', '.deployment-method-picker', '.deployment-method-content',
  '.ac-stages', '.ac-review', '.ac-timeline', '[data-motion-item]',
].join(',');
const BOUNDARIES = '.el-tab-pane, [data-motion-scope]';
const controllers = new WeakMap();

function createMotion(root) {
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const running = new Map(), pending = new Map();
  let seen = new WeakSet(), frame;

  function cancelWithin(scope) {
    for (const [element, animation] of running) {
      if (scope === root || scope === element || scope.contains(element)) {
        animation.cancel();
        running.delete(element);
      }
    }
  }

  function enter(scope, reset) {
    if (preference.matches || !scope.isConnected) return;
    const all = [...scope.querySelectorAll(TARGETS)];
    if (scope.matches(TARGETS)) all.unshift(scope);
    if (reset) {
      cancelWithin(scope);
      if (scope === root) seen = new WeakSet();
      else all.forEach(element => seen.delete(element));
    }
    const visible = all.filter(element => {
      if (seen.has(element) || element.closest('.el-overlay, .el-popper, [role="dialog"]')) return false;
      const rect = element.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.top < window.innerHeight;
    });
    // 同一内容区只移动一层，避免外层与内层叠加淡入。
    const targets = visible.filter(element => !visible.some(parent => parent !== element && parent.contains(element)));
    visible.forEach(element => seen.add(element));
    const style = getComputedStyle(root);
    const duration = motionMilliseconds(style.getPropertyValue('--motion-enter'));
    const easing = style.getPropertyValue('--ease-out').trim() || 'ease-out';
    targets.forEach((element, index) => {
      if (!element.animate) return;
      const animation = element.animate([
        {opacity: 0, transform: 'translateY(8px)'},
        {opacity: 1, transform: 'none'},
      ], {duration, delay: Math.min(index * 40, 160), easing, fill: 'backwards'});
      animation.id = 'console-enter';
      running.set(element, animation);
      const release = () => { if (running.get(element) === animation) running.delete(element); };
      animation.finished.then(release, release);
    });
  }

  function schedule(scope = root, reset = false) {
    pending.set(scope, reset || pending.get(scope) || false);
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = undefined;
      if (pending.get(root)) enter(root, true);
      else {
        for (const [target, replay] of pending) if (target !== root) enter(target, replay);
        if (pending.has(root)) enter(root, false);
      }
      pending.clear();
    });
  }

  const observer = new MutationObserver(records => {
    if (preference.matches) return;
    for (const record of records) {
      const target = record.target;
      if (record.type === 'attributes') {
        if ((target.matches(BOUNDARIES) || target.parentElement === root) && target.style.display !== 'none') {
          schedule(target, true);
        }
      } else if (!target.closest('.el-table') && [...record.addedNodes].some(node => node.nodeType === 1 && (node.matches(TARGETS) || node.querySelector(TARGETS)))) {
        // 异步数据仅为新出现的面板播放一次；表格实时更新不会重播整个页面。
        schedule();
      }
    }
  });
  observer.observe(root, {subtree: true, childList: true, attributes: true, attributeFilter: ['style']});
  const onPreference = () => {
    cancelWithin(root);
    pending.clear();
    cancelAnimationFrame(frame);
    frame = undefined;
  };
  preference.addEventListener('change', onPreference);
  schedule(root, true);
  return {
    replay: () => schedule(root, true),
    destroy() {
      observer.disconnect();
      preference.removeEventListener('change', onPreference);
      onPreference();
    },
  };
}

export default {
  mounted(root) { controllers.set(root, createMotion(root)); },
  updated(root, binding) {
    if (binding.value !== binding.oldValue) controllers.get(root)?.replay();
  },
  beforeUnmount(root) { controllers.get(root)?.destroy(); controllers.delete(root); },
};
