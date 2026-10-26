<template>
  <div v-if="view" class="tc-score-cell" :class="{ 'tc-score-alert': view.anomalous }" :title="view.summary">
    <div class="tc-score-line">
      <span class="mono tc-score">{{ view.score }}</span>
      <span class="tc-score-state">{{ view.stateText }}</span>
    </div>
    <div class="tc-score-track" role="progressbar" aria-label="风险评分，行为基线偏离程度"
         aria-valuemin="0" :aria-valuemax="view.scale" :aria-valuenow="view.score" :aria-valuetext="view.summary">
      <span class="tc-score-fill" :style="{ width: view.scorePercent + '%' }" aria-hidden="true"></span>
      <span v-if="view.thresholdPercent !== null" class="tc-score-marker" :style="{ left: view.thresholdPercent + '%' }" aria-hidden="true"></span>
    </div>
  </div>
  <span v-else class="mono tc-score tc-score-empty" :title="hint">—</span>
</template>

<script setup>
import { computed } from "vue";
import { anomalyScoreHint, anomalyScoreView } from "../utils/threatContent";

const props = defineProps({
  record: { type: Object, default: null },
  scale: { type: Number, default: 0 },
});
const view = computed(() => anomalyScoreView(props.record, props.scale));
const hint = computed(() => anomalyScoreHint(props.record));
</script>
