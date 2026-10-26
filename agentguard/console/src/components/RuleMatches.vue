<template>
  <ul class="dd-list rule-matches">
    <li v-for="(rule, index) in items" :key="index" class="dd-rule">
      <dl class="rm-fields">
        <dt>触发策略</dt>
        <dd><a :href="ruleHash('strategies', rule.rule_id)" @click="go($event, rule.rule_id, 'strategies')">{{ rule.strategy_title || rule.rule_id }}</a><span v-if="rule.strategy_title" class="mono rm-id">{{ rule.rule_id }}</span><span v-if="rule.decision" class="dec-tag" :class="'dec-tag-' + rule.decision">{{ decisionName(rule.decision) }}</span><span v-if="rule.severity" class="sev-tag" :class="'sev-' + rule.severity">{{ severityText(rule.severity) }}</span></dd>
        <template v-if="rule.reason_code"><dt>判定原因</dt><dd>{{ threatText(rule.reason_code) }}</dd></template>
        <dt>命中特征</dt>
        <dd v-if="rule.features?.length" class="rm-features">
          <div v-for="feature in rule.features" :key="feature.rule_id + ':' + feature.revision" class="rm-feature">
            <a :href="ruleHash('features', feature.rule_id, feature.revision)" @click="go($event, feature.rule_id, 'features', feature.revision)">{{ feature.title || feature.rule_id }}</a><span class="mono rm-id">{{ feature.rule_id }}</span>
            <span class="rm-version" :title="'特征版本 ' + (feature.revision || '未记录')">{{ feature.pack_version ? 'v' + feature.pack_version : feature.revision }}</span>
          </div>
        </dd>
        <dd v-else class="muted">{{ rule.features == null ? '未记录具体特征' : '无直接特征命中' }}</dd>
      </dl>
      <pre v-if="rule.detail" class="dd-code">{{ rule.detail }}</pre>
    </li>
  </ul>
</template>

<script setup>
import { decisionName, threatText } from '../utils/format';
import { ruleHash } from '../utils/ruleNavigation';
import { openRuleTarget } from '../store/runtime';
defineProps({ items: { type: Array, default: () => [] } });
const emit = defineEmits(['navigate']);
const severityText = value => ({CRITICAL:'严重', HIGH:'高危', MEDIUM:'中危', LOW:'低危', INFO:'信息'}[value] || value);
async function go(event, id, page, revision = '') {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button) return;
  event.preventDefault();
  if (await openRuleTarget(id, page, revision)) emit('navigate');
}
</script>

<style scoped>
.rm-fields { display:grid; grid-template-columns:70px minmax(0,1fr); gap:7px 12px; margin:0; font-size:12px; }
.rm-fields dt { color:var(--muted); }
.rm-fields dd { display:flex; align-items:center; flex-wrap:wrap; gap:6px 8px; margin:0; min-width:0; overflow-wrap:anywhere; }
.rm-fields a { color:var(--brand); text-decoration:none; }
.rm-fields a:hover { text-decoration:underline; }
.rm-fields a:focus-visible { outline:2px solid var(--brand); outline-offset:3px; }
.rm-fields .rm-features { display:grid; gap:6px; }
.rm-feature { display:flex; align-items:baseline; flex-wrap:wrap; gap:4px 8px; }
.rm-id, .rm-version { color:var(--muted); font-size:12px; }
.rule-matches .dd-code { max-height:160px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; }
</style>
