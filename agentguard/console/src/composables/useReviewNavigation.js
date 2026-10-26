import { computed, nextTick, ref } from 'vue';

// 详情使用打开时的筛选/排序快照，后台刷新不会偷偷换掉正在复核的记录。
export function useReviewNavigation({ rows, key, open, selector }) {
  const snapshot = ref([]), selectedKey = ref('');
  let origin = null;
  const position = computed(() => snapshot.value.findIndex(row => key(row) === selectedKey.value));
  const hasPrevious = computed(() => position.value > 0);
  const hasNext = computed(() => position.value >= 0 && position.value < snapshot.value.length - 1);
  const caption = computed(() => position.value >= 0 ? `${position.value + 1} / ${snapshot.value.length}` : '');
  function begin(row) {
    snapshot.value = [...rows.value];
    selectedKey.value = key(row);
    origin = document.activeElement;
    open(row);
  }
  function move(offset) {
    const row = snapshot.value[position.value + offset];
    if (row) { selectedKey.value = key(row); open(row); }
  }
  async function restoreFocus() {
    await nextTick();
    if (origin?.isConnected && origin !== document.body && origin.checkVisibility()) origin.focus({ preventScroll: true });
    else {
      const buttons = [...document.querySelectorAll(selector)];
      const button = buttons.find(el => el.dataset.reviewKey === selectedKey.value && el.checkVisibility()) || buttons.find(el => el.checkVisibility());
      button?.focus({ preventScroll: true });
    }
  }
  return { begin, move, restoreFocus, hasPrevious, hasNext, caption };
}
