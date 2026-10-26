<template>
  <div>
    <div class="dd-callout" :class="problems.length ? 'dd-callout-ASK' : 'dd-callout-ALLOW'">
      <div class="dd-callout-label">{{ title }}</div>
      <div class="dd-callout-text" v-if="problems.length">{{ problems.join('\n') }}</div>
      <div class="dd-callout-text" v-else>检查全部通过</div>
    </div>

    <section class="dd-section" v-if="c.evidence?.length">
      <h4 class="dd-section-title">命中本次证据 <span class="dd-count">{{ c.evidence.length }}</span></h4>
      <ul class="dd-list">
        <li v-for="e in c.evidence" :key="e.step" class="dd-rule">
          <div class="dd-rule-head"><span class="code-hint">#{{ e.step }}</span><span class="mono">{{ e.matched.join('  ') }}</span></div>
          <pre class="dd-code">{{ e.sample }}</pre>
        </li>
      </ul>
    </section>

    <section class="dd-section">
      <h4 class="dd-section-title">Claude Code 夹具回放</h4>
      <p v-if="replay.error" class="fs-12 c-med">回放失败：{{ replay.error }}</p>
      <p v-else-if="replay.skipped" class="fs-12 muted">{{ replay.skipped }}</p>
      <template v-else>
        <p class="fs-12">
          <span :class="replay.benign_blocked ? 'c-crit' : 'c-ok'">正常夹具新增拦截 / 需确认 {{ replay.benign_blocked }} 步</span>
          （共 {{ replay.benign_total }} 个正常夹具）·
          <span :class="{ 'c-ok': replay.newly_detected?.length }">新覆盖恶意夹具 {{ replay.newly_detected?.length || 0 }} 个</span>
          （基线漏报 {{ replay.baseline_fn }} 个，共 {{ replay.fixtures }} 个夹具）
        </p>
        <ul class="dd-list" v-if="replay.benign_examples?.length">
          <li v-for="(e, i) in replay.benign_examples" :key="'b' + i" class="dd-rule">
            <div class="dd-rule-head"><span class="mono">{{ e.fixture }}</span><span class="code-hint">第 {{ e.step }} 步 {{ e.tool }}</span>
              <span class="c-crit">{{ e.before }} → {{ e.after }}</span></div>
            <pre class="dd-code">{{ e.input }}</pre>
          </li>
        </ul>
        <p v-if="replay.newly_detected?.length" class="fs-12 mono">{{ replay.newly_detected.join('  ') }}</p>
        <p v-if="replay.changed?.length" class="fs-11 muted">恶意夹具中判定变化的步骤：
          {{ replay.changed.map((e) => `${e.fixture}#${e.step} ${e.before}→${e.after}`).join('；') }}</p>
      </template>
    </section>

    <section class="dd-section">
      <h4 class="dd-section-title">样本检查</h4>
      <dl class="dd-kv">
        <dt>正常夹具样本</dt><dd :class="{ 'c-crit': c.fixture_benign_hits }">命中 {{ c.fixture_benign_hits ?? '-' }} / {{ c.fixture_benign_total ?? '-' }}</dd>
        <dt>恶意夹具</dt><dd>覆盖 {{ c.fixture_malicious_hits ?? 0 }} 个<span v-if="c.fixture_malicious?.length" class="mono muted">（{{ c.fixture_malicious.join('、') }}）</span></dd>
        <dt>现有规则反例</dt><dd :class="{ 'c-med': c.nomatch_hits }">命中 {{ c.nomatch_hits ?? '-' }} / {{ c.nomatch_total ?? '-' }}</dd>
        <dt>正常开发语料</dt><dd :class="{ 'c-med': c.corpus_hits }">命中 {{ c.corpus_hits }} / {{ c.corpus_total }}</dd>
        <dt>近期放行调用</dt><dd :class="{ 'c-med': c.recent_hits }">命中 {{ c.recent_hits }} / {{ c.recent_total }}</dd>
      </dl>
      <pre v-if="examples.length" class="dd-code">{{ examples.join('\n') }}</pre>
    </section>
  </div>
</template>

<script setup>
// 规则建议的检查结果：证据命中、夹具回放对比与样本级误报 / 覆盖。
import { computed } from "vue";

const props = defineProps({
  checks: { type: Object, required: true },
  problems: { type: Array, default: () => [] },
  title: { type: String, default: "检查结果" },
});
const c = computed(() => props.checks || {});
const replay = computed(() => c.value.replay || {});
const examples = computed(() => [
  ...(c.value.fixture_benign_examples || []).map((e) => `[正常夹具 ${e.fixture}] ${e.sample}`),
  ...(c.value.nomatch_examples || []).map((e) => `[${e.rule_id} 反例] ${e.sample}`),
  ...(c.value.corpus_examples || []).map((e) => `[语料] ${e}`),
  ...(c.value.recent_examples || []).map((e) => `[近期放行] ${e}`),
]);
</script>
