<template>
  <section class="deployment-command">
    <div class="deployment-command-head">
      <div class="deployment-command-title">
        <span v-if="number" class="deployment-step-number">{{ number }}</span>
        <h4>{{ title }}</h4>
      </div>
      <el-button link :aria-label="'复制' + title + '配置'" @click="copy">
        <el-icon class="btn-ic" aria-hidden="true"><component :is="copied ? Check : DocumentCopy" /></el-icon>{{ copied ? '已复制' : '复制' }}
      </el-button>
    </div>
    <div class="deployment-command-context"><span>{{ context }}</span><span>{{ format }}</span></div>
    <pre><code>{{ code }}</code></pre>
  </section>
</template>

<script setup>
import { ref, onBeforeUnmount } from 'vue';
import { ElMessage } from 'element-plus';
import { Check, DocumentCopy } from '../icons';

const props = defineProps({
  title: { type: String, required: true },
  code: { type: String, required: true },
  context: { type: String, default: '' },
  format: { type: String, default: 'bash' },
  number: { type: Number, default: 0 },
});
const copied = ref(false);
let timer;
onBeforeUnmount(() => clearTimeout(timer));
async function copy() {
  try {
    await navigator.clipboard.writeText(props.code);
    copied.value = true;
    clearTimeout(timer);
    timer = setTimeout(() => { copied.value = false; }, 1600);
  } catch {
    ElMessage.warning('复制失败，请手动选择配置文本');
  }
}
</script>
