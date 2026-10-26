<template>
  <div class="ac-risk-detail">
    <div class="ac-detail-result">
      <span
        class="dec-tag"
        :class="
          item.resultBlocked
            ? 'dec-tag-DENY'
            : item.evidenceGap && !item.risk
              ? 'dec-tag-NONE'
              : item.decision
                ? dispositionTag(item.decision)
                : 'dec-tag-NONE'
        "
        >{{ outcome }}</span
      >
      <h3>{{ headline }}</h3>
    </div>
    <dl class="ac-detail-summary">
      <dt>涉及调用</dt>
      <dd>{{ item.title }}</dd>
      <template v-if="item.resource"
        ><dt>涉及对象</dt>
        <dd class="mono">{{ item.resource }}</dd></template
      >
      <dt>所处位置</dt>
      <dd>{{ item.round > 0 ? "第 " + item.round + " 轮" : "轮次外事件" }} · {{ fmt(item.timestamp) }}</dd>
      <template v-if="item.linkNote"
        ><dt>关联情况</dt>
        <dd>{{ linkNoteName(item.linkNote) }}</dd></template
      >
    </dl>
    <section class="ac-evidence-section" aria-label="节点原始证据">
      <h3>
        原始证据 <span class="muted">{{ item.events.length }} 条事件</span>
      </h3>

      <details
        v-for="(e, index) in item.events"
        :key="e.event_id"
        class="ac-evidence-event"
        @toggle="setOpen(e.event_id, $event.target.open)"
      >
        <summary>
          <span class="ac-evidence-index">{{ index + 1 }}</span
          ><b>{{ stageName(e) }}</b>
          <span v-if="e.decision" class="dec-tag" :class="dispositionTag(e.decision)">{{
            dispositionLabel(e.decision)
          }}</span>
          <span v-if="e.labels?.includes('RESULT_BLOCKED')" class="c-crit">返回已拦截</span>
          <time class="muted">{{ fmtTime(e.timestamp) }}</time
          ><el-icon><ArrowRight /></el-icon>
        </summary>
        <div v-if="opened.has(e.event_id)" class="ac-evidence-body">
          <ChainEventDetail :n="e" />
          <details class="ac-event-fields">
            <summary>标识与关联字段</summary>
            <dl>
              <dt>事件 ID</dt>
              <dd><CopyText :text="e.event_id" /></dd>
              <template v-if="e.call_id"
                ><dt>调用 ID</dt>
                <dd><CopyText :text="e.call_id" /></dd
              ></template>
              <template v-if="e.decision_id || e.decision?.decision_id"
                ><dt>决策 ID</dt>
                <dd><CopyText :text="e.decision_id || e.decision.decision_id" /></dd
              ></template>
              <template v-if="e.resource"
                ><dt>资源</dt>
                <dd class="mono">{{ e.resource }}</dd></template
              >
            </dl>
          </details>
        </div>
      </details>
      <details v-if="item.decision?.matched_rules?.length" class="ac-rule-details">
        <summary>命中详情 · {{ item.decision.matched_rules.length }} 条</summary>
        <RuleMatches :items="item.decision.matched_rules" />
      </details>
    </section>
  </div>
</template>

<script setup>
import { computed, ref } from "vue";
import ChainEventDetail from "./ChainEventDetail.vue";
import CopyText from "../../components/CopyText.vue";
import RuleMatches from "../../components/RuleMatches.vue";
import {
  fmt,
  fmtTime,
  stageName,
  dispositionTag,
  dispositionLabel,
  threatText,
  linkNoteName,
} from "../../utils/format";
const props = defineProps({ item: { type: Object, required: true } });
const opened = ref(new Set());
function setOpen(id, open) {
  const next = new Set(opened.value);
  open ? next.add(id) : next.delete(id);
  opened.value = next;
}
const outcome = computed(() =>
  props.item.resultBlocked
    ? "返回已拦截"
    : props.item.evidenceGap && !props.item.risk
      ? props.item.unresolvedDecision
        ? "决策未关联"
        : "关联证据缺失"
      : props.item.decision
        ? dispositionLabel(props.item.decision)
        : props.item.unresolvedDecision
          ? "决策未关联"
          : props.item.evidenceGap
            ? "关联证据缺失"
            : "威胁告警",
);
const headline = computed(() => {
  const item = props.item;
  if (item.resultBlocked) return "工具返回内容被拦截";
  if (item.evidenceGap && !item.risk) return item.unresolvedDecision ? "关联决策未找到" : "调用关联证据缺失";
  if (item.decision?.reason_code) return threatText(item.decision.reason_code);
  return item.unresolvedDecision
    ? "关联决策未找到"
    : item.evidenceGap
      ? "调用关联证据缺失"
      : "节点处置与证据";
});
</script>
