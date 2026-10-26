<template>
  <section class="ac-stages" aria-label="检测阶段定位">
    <div class="ac-section-heading">
      <h3><el-icon aria-hidden="true"><Connection /></el-icon>检测阶段</h3>
      <span class="muted fs-12">命中 {{ steps.filter((step) => step.hit).length }} / {{ steps.length }} 个阶段</span>
    </div>
    <div class="ac-stage-viewport" role="region" aria-label="检测阶段图" tabindex="0">
      <ol class="ac-stage-map">
        <li
          v-for="(step, index) in steps"
          :key="step.stage"
          :class="{ reached: step.hit, linked: step.hit && steps[index + 1]?.hit }"
          :data-stage="step.stage"
        >
          <div v-if="step.hit" class="ac-stage-evidence" :data-severity="step.decision?.severity">
            <span class="ac-stage-signal" aria-hidden="true"></span>
            <span>{{ CHAIN_SEVERITIES[step.decision?.severity] || '检测命中' }}</span>
            <time :title="fmt(step.hit.timestamp)">{{ fmtTime(step.hit.timestamp) }}</time>
          </div>
          <button
            type="button"
            class="ac-stage-node"
            :class="{ selected: step.item && selectedKey === step.item.key }"
            :disabled="!step.item"
            :aria-label="step.label + '：' + (step.item ? '查看命中节点' : step.hit ? '关联事件缺失' : '未见证据')"
            :aria-pressed="step.item ? selectedKey === step.item.key : undefined"
            :title="step.hit ? fmt(step.hit.timestamp) : '当前记录未见该阶段证据'"
            @click="$emit('select', step.item)"
          >
            <span class="ac-stage-number">{{ index + 1 }}</span>
            <span class="ac-stage-label">{{ step.label }}</span>
          </button>
          <span class="ac-stage-status">{{
            step.hit ? (step.item ? (step.decision ? dispositionLabel(step.decision) : '检测命中') : '关联事件缺失') : '未见证据'
          }}</span>
        </li>
      </ol>
    </div>
    <div class="ac-stage-legend" aria-label="检测阶段图例">
      <span><i class="ac-legend-line hit" aria-hidden="true"></i>命中阶段关联</span>
      <span><i class="ac-legend-line" aria-hidden="true"></i>未见阶段证据</span>
      <span v-for="(label, severity) in CHAIN_SEVERITIES" :key="severity" :data-severity="severity">
        <i class="ac-legend-dot" aria-hidden="true"></i>{{ label }}
      </span>
    </div>
  </section>
</template>

<script setup>
import { CHAIN_SEVERITIES } from "../../utils/chainPresentation";
import { fmt, fmtTime, dispositionLabel } from "../../utils/format";
defineProps({ steps: { type: Array, required: true }, selectedKey: { type: String, default: "" } });
defineEmits(["select"]);
</script>
