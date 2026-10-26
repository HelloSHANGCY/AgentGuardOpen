<template>
  <div class="judge-intent">
    <el-alert v-if="error" :title="error" type="error" show-icon class="intent-alert" @close="$emit('dismiss-error')" />
    <section v-if="status" class="intent-card" aria-labelledby="judge-intent-title">
      <div class="intent-head">
        <div><h3 id="judge-intent-title">意图识别方式</h3><strong class="intent-mode">{{ status.provider === 'llm' ? status.model || '未绑定模型' : '关键词识别' }}</strong></div>
        <el-switch :model-value="status.enabled && !status.forced_off" :loading="saving" :disabled="disabled || status.forced_off"
                   aria-label="大模型意图识别开关" @change="$emit('toggle', $event)" />
      </div>
      <el-alert v-if="status.forced_off" title="大模型意图识别已由服务端强制关闭" type="warning" show-icon :closable="false" class="intent-alert" />
      <div class="intent-columns">
        <dl class="intent-details">
          <div><dt>已配置模型</dt><dd class="mono">{{ status.model || '—' }}</dd></div>
          <div><dt>服务接口</dt><dd class="mono">{{ status.host || '—' }}</dd></div>
          <div><dt>超时</dt><dd>{{ status.timeout ?? '—' }}<span v-if="status.timeout != null"> 秒</span></dd></div>
        </dl>
        <div class="intent-metrics">
          <dl class="intent-stats" aria-label="意图识别调用统计">
            <div><dt>调用次数</dt><dd>{{ status.calls ?? '—' }}</dd></div>
            <div><dt>识别出意图</dt><dd>{{ status.labelled ?? '—' }}</dd></div>
            <div><dt>无意图 / 失败</dt><dd>{{ status.empty ?? '—' }} / {{ status.failed ?? '—' }}</dd></div>
          </dl>
          <dl class="intent-latencies" aria-label="意图识别延迟">
            <div><dt>P50 延迟</dt><dd>{{ status.latency_p50 ?? '—' }}<small v-if="status.latency_p50 != null"> 秒</small></dd></div>
            <div><dt>P90 延迟</dt><dd>{{ status.latency_p90 ?? '—' }}<small v-if="status.latency_p90 != null"> 秒</small></dd></div>
          </dl>
        </div>
      </div>
    </section>
    <el-skeleton v-else-if="loading" :rows="4" animated />
  </div>
</template>

<script setup>
defineProps({
  status: { type: Object, default: null },
  error: { type: String, default: '' },
  loading: Boolean,
  saving: Boolean,
  disabled: Boolean,
});
defineEmits(['toggle', 'dismiss-error']);
</script>

<style scoped>
.intent-card { min-width: 0; padding: var(--space-4); border: 1px solid var(--line); border-radius: var(--radius-panel); background: var(--panel); }
.intent-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--line-2); }
.intent-head > div { min-width: 0; }
.intent-head h3 { margin: 0; color: var(--title); font-size: var(--font-heading); font-weight: 500; }
.intent-mode { display: block; margin-top: 8px; color: var(--title); font-size: 16px; overflow-wrap: anywhere; }
.intent-head .el-switch { flex: none; }
.intent-alert { margin-bottom: 12px; }
.intent-card > .intent-alert { margin-top: 12px; }
.intent-columns { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr); gap: 24px; margin-top: 16px; }
.intent-columns dl { margin: 0; }
.intent-columns dt { color: var(--muted); font-size: 12px; }
.intent-columns dd { margin: 0; color: var(--title); overflow-wrap: anywhere; }
.intent-details { display: grid; align-content: start; gap: 12px; }
.intent-details > div { display: grid; grid-template-columns: 84px minmax(0, 1fr); gap: 8px; }
.intent-metrics { min-width: 0; padding-left: 24px; border-left: 1px solid var(--line-2); }
.intent-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.intent-stats dd { margin-top: 4px; font-size: 24px; font-weight: 600; line-height: 1.5; }
.intent-latencies { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding-top: 12px; }
.intent-latencies dd { margin-top: 4px; font: 16px var(--mono); }
.intent-latencies small { color: var(--muted); font: 12px var(--font-sans); }
@media (max-width: 1000px) {
  .intent-columns { grid-template-columns: minmax(0, 1fr); gap: 16px; }
  .intent-metrics { padding: 16px 0 0; border-left: 0; border-top: 1px solid var(--line-2); }
}
</style>
