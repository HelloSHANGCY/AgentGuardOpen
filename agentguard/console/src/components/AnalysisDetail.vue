<template>
  <div class="dd-body">
    <div v-if="r.status === 'failed'" class="dd-callout dd-callout-DENY">
      <div class="dd-callout-label">分析失败</div><div class="dd-callout-text">{{ r.error }}</div>
    </div>
    <div v-else-if="r.status === 'pending'" class="dd-callout">
      <div class="dd-callout-label">分析中</div><div class="dd-callout-text">分析中</div>
    </div>
    <div v-if="r.coverage && r.status !== 'pending'" class="dd-callout" :class="{ 'dd-callout-ASK': !r.coverage.complete }" role="status">
      <div class="dd-callout-label">告警研判覆盖</div>
      <div class="dd-callout-text">{{ r.coverage.assessed }} / {{ r.coverage.total }} 条有结论 · {{ r.coverage.complete ? '已完成' : '部分未完成' }}</div>
    </div>
    <div v-if="r.summary" class="dd-callout" :class="{ 'dd-callout-DENY': r.verdict === 'malicious', 'dd-callout-ASK': r.verdict === 'suspicious' }">
      <div class="dd-callout-label">摘要</div><div class="dd-callout-text">{{ r.summary }}</div>
    </div>

    <section class="dd-section" v-if="r.findings?.length">
      <h4 class="dd-section-title">发现 <span class="dd-count">{{ r.findings.length }}</span></h4>
      <ul class="dd-list">
        <li v-for="(f, i) in r.findings" :key="i" class="dd-rule">
          <div class="dd-rule-head">
            <span class="sev-tag" :class="'sev-' + riskSev(f.severity)">{{ f.severity.toUpperCase() }}</span>
            <span>{{ f.title }}</span>
            <span v-if="f.steps.length" class="code-hint">{{ f.steps.map((n) => '#' + n).join(' ') }}</span>
          </div>
          <pre v-if="f.detail" class="dd-code">{{ f.detail }}</pre>
        </li>
      </ul>
    </section>

    <section class="dd-section" v-if="r.unassessed?.length">
      <h4 class="dd-section-title">未完成研判 <span class="dd-count">{{ r.unassessed.length }}</span></h4>
      <ul class="dd-list">
        <li v-for="a in r.unassessed" :key="a.decision_id" class="dd-rule">
          <div class="dd-rule-head"><el-tag size="small" type="warning" effect="plain">{{ assessmentText(a) }}</el-tag>
            <span class="code-hint">#{{ a.step }}</span><span class="mono">{{ a.tool }}</span><span>{{ threatText(a.reason_code) }}</span></div>
          <pre class="dd-code">{{ a.note }}</pre>
        </li>
      </ul>
    </section>

    <section class="dd-section" v-if="r.alerts?.length">
      <h4 class="dd-section-title">静态告警研判 <span class="dd-count">{{ r.alerts.length }}</span></h4>
      <ul class="dd-list">
        <li v-for="a in r.alerts" :key="a.decision_id" class="dd-rule">
          <div class="dd-rule-head">
            <el-tag size="small" :type="ASSESSMENT_TAG[a.assessment]" effect="plain">{{ ASSESSMENT_TEXT[a.assessment] }}</el-tag>
            <span class="code-hint">#{{ a.step }}</span>
            <span class="mono">{{ a.tool }}</span>
            <span>{{ threatText(a.reason_code) }}</span>
          </div>
          <pre v-if="a.note" class="dd-code">{{ a.note }}</pre>
        </li>
      </ul>
    </section>

    <div v-if="r.recommendation" class="dd-callout dd-callout-ALLOW">
      <div class="dd-callout-label">建议</div><div class="dd-callout-text">{{ r.recommendation }}</div>
    </div>
    <p v-if="r.status === 'done' && r.coverage?.complete !== false && !r.findings?.length && !r.alerts?.length" class="muted">没有发现问题</p>

    <MoreFields>
      <dl class="dd-kv">
        <dt>trace</dt><dd><CopyText :text="r.trace_id" /></dd>
        <dt>分析 ID</dt><dd><CopyText :text="r.analysis_id" /></dd>
        <dt>模型</dt><dd><span class="mono">{{ r.model || '-' }}</span><template v-if="r.effort"> · 思考{{ EFFORT_TEXT[r.effort] }}</template></dd>
        <dt>步数</dt><dd class="mono">{{ r.steps }}</dd>
        <template v-if="r.batches"><dt>分析批次</dt><dd class="mono">{{ r.batches.length }}</dd></template>
        <template v-for="b in (r.batches || []).filter(item => item.error)" :key="b.batch">
          <dt>批次 {{ b.batch }} 错误</dt><dd>{{ b.error }}</dd>
        </template>
        <dt>耗时</dt><dd class="mono">{{ (r.latency_ms / 1000).toFixed(1) }} s</dd>
      </dl>
    </MoreFields>
  </div>
</template>

<script setup>
// 大模型异步分析记录的详情正文：「大模型研判」与「威胁中心」共用。
import { computed } from "vue";
import CopyText from "./CopyText.vue";
import MoreFields from "./MoreFields.vue";
import { threatText, ASSESSMENT_TEXT, ASSESSMENT_TAG, assessmentText, EFFORT_TEXT, riskSev } from "../utils/format";

const props = defineProps({ record: { type: Object, required: true } });
const r = computed(() => props.record);
</script>
