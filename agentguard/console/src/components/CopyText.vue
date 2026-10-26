<template>
  <span class="copy-text">
    <span class="mono">{{ text || '-' }}</span>
    <button v-if="text" type="button" class="copy-btn" :title="'复制 ' + text" :aria-label="'复制 ' + text" @click.stop="copy">
      <el-icon aria-hidden="true"><component :is="copied ? Check : DocumentCopy" /></el-icon>
    </button>
  </span>
</template>

<script setup>
// 标识符（trace / 决策 ID / 证据 ID 等）旁的一键复制，复制成功后短暂显示对勾。
import { ref, onBeforeUnmount } from "vue";
import { ElMessage } from "element-plus";
import { Check, DocumentCopy } from "../icons";

const props = defineProps({ text: { type: String, default: "" } });
const copied = ref(false);
let resetTimer;
onBeforeUnmount(() => clearTimeout(resetTimer));

async function copy() {
  try {
    await navigator.clipboard.writeText(props.text);
    copied.value = true;
    clearTimeout(resetTimer);
    resetTimer = setTimeout(() => { copied.value = false; }, 1200);
  } catch {
    ElMessage.warning("复制失败，请手动选择文本");
  }
}
</script>
