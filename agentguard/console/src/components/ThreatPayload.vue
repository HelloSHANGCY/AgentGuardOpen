<template>
  <div class="tc-payload">
    <section v-if="command" class="dd-section tc-command-section" aria-label="执行命令">
      <h4 class="dd-section-title">执行命令</h4>
      <pre class="tc-command-code"><code>{{ command }}</code></pre>
    </section>
    <section class="dd-section" :aria-label="contentTitle">
      <div class="tc-content-heading">
        <h4 class="dd-section-title">{{ contentTitle }}</h4>
        <div class="tc-payload-status">
          <el-tag v-if="record?.redacted" size="small" type="info" effect="plain">已脱敏</el-tag>
          <el-tag v-if="record?.collection_truncated" size="small" type="warning" effect="plain">采集截断</el-tag>
          <el-tag v-if="record?.storage_truncated" size="small" type="warning" effect="plain">存储截断</el-tag>
          <el-tag v-if="record?.truncated && !record.collection_truncated && !record.storage_truncated" size="small" type="warning" effect="plain">记录截断</el-tag>
          <el-button v-if="error" size="small" :loading="loading" @click="load">重新读取</el-button>
        </div>
      </div>
      <el-alert v-if="error" class="tc-payload-error" :title="error" type="warning" show-icon :closable="false" />
      <el-skeleton v-if="loading && !loaded" :rows="3" animated />
      <pre v-else-if="content" class="tc-payload-content"><template v-for="(part, index) in parts" :key="index"><mark v-if="part.match" class="tc-command-mark">{{ part.text }}</mark><template v-else>{{ part.text }}</template></template></pre>
      <p v-else-if="!loading && !error" class="tc-note">暂无已采集的参数内容</p>
    </section>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { requestJson } from '../api/client';
import { executionCommand, highlightCommand } from '../utils/threatContent';

const props = defineProps({ detail: {type: Object, required: true} });
const record = ref(null), loaded = ref(false), loading = ref(false), error = ref('');
let controller, evidence;
const currentRecords = computed(() => record.value ? [{...record.value, event_id: props.detail.context?.event_id, decision_id: props.detail.decision_id}] : []);
const command = computed(() => executionCommand(props.detail, currentRecords.value));
const content = computed(() => loaded.value ? record.value?.content || '' : props.detail.context?.preview || '');
const parts = computed(() => highlightCommand(content.value, command.value));
const contentTitle = computed(() => (String(props.detail.context?.stage || '').includes('RESULT') ? '原始返回' : '原始参数') + (loaded.value ? '' : '摘要'));

async function resolveEvidence(signal) {
  const detail = props.detail;
  const trace = await requestJson('/v1/runtime/traces/' + encodeURIComponent(detail.trace_id), {signal});
  const nodes = trace.chain || [];
  const node = nodes.find(item => item.event_id === detail.context?.event_id)
    || nodes.find(item => (detail.evidence_ids || []).includes(item.event_id) || item.decision_id === detail.decision_id);
  const records = node?.evidence || [];
  // 优先对应触发事件上的参数 / 返回证据，禁止按命令内容猜测另一条调用。
  return records.find(item => ['TOOL_ARGUMENTS', 'TOOL_RESULT', 'INGRESS_REQUEST', 'EGRESS_REQUEST'].includes(item.kind))
    || records[0]
    || nodes.flatMap(item => item.evidence || []).find(item => (detail.evidence_ids || []).includes(item.evidence_id));
}
async function load() {
  controller?.abort();
  const request = new AbortController();
  controller = request;
  loading.value = true;
  error.value = '';
  try {
    const selected = evidence || await resolveEvidence(request.signal);
    if (request.signal.aborted) return;
    evidence = selected;
    if (!selected?.evidence_id) throw new Error('missing evidence');
    if (selected.preview_truncated === false && selected.stored_length <= 200 && !selected.truncated) {
      // 短证据预览本身就是完整文本，无需重复请求。
      record.value = {...selected, content: selected.preview || ''};
    } else {
      const data = await requestJson('/v1/runtime/evidence/' + encodeURIComponent(selected.evidence_id), {
        signal: request.signal,
      });
      if (request.signal.aborted) return;
      record.value = data;
    }
    loaded.value = true;
  } catch (e) {
    if (request.signal.aborted) return;
    error.value = e.status === 404 || e.message === 'missing evidence' ? '未找到该告警的参数原文' : '参数原文读取失败';
  } finally {
    if (controller === request) loading.value = false;
  }
}
watch(() => props.detail.decision_id, () => {
  record.value = null;
  evidence = null;
  loaded.value = false;
  load();
}, {immediate: true});
onBeforeUnmount(() => controller?.abort());
</script>
