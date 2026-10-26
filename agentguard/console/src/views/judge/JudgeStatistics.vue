<template>
  <section class="js-statistics" aria-labelledby="judge-statistics-title">
    <div class="js-heading"><h3 id="judge-statistics-title">研判统计</h3><span class="js-scope">最近 {{ JUDGE_RECORD_LIMIT }} 条记录 · 已加载 {{ statistics.total }} 条</span></div>
    <div class="js-kpis">
      <article class="js-kpi"><div class="js-kpi-main"><span class="js-label">研判记录</span><strong>{{ number(statistics.total) }}<small>次</small></strong></div><el-icon class="js-kpi-icon" aria-hidden="true"><Brain /></el-icon>
        <p>已完成 {{ number(statistics.done) }} · 分析中 {{ number(statistics.outcomes.pending) }} · 失败 {{ number(statistics.outcomes.failed) }}</p></article>
      <article class="js-kpi"><div class="js-kpi-main"><span class="js-label">恶意判定</span><strong>{{ number(statistics.outcomes.malicious) }}<small>次</small></strong></div><el-icon class="js-kpi-icon js-icon-danger" aria-hidden="true"><WarningFilled /></el-icon>
        <p>占已完成 {{ proportion(statistics.outcomes.malicious) }}</p></article>
      <article class="js-kpi"><div class="js-kpi-main"><span class="js-label">可疑判定</span><strong>{{ number(statistics.outcomes.suspicious) }}<small>次</small></strong></div><el-icon class="js-kpi-icon js-icon-warning" aria-hidden="true"><QuestionFilled /></el-icon>
        <p>占已完成 {{ proportion(statistics.outcomes.suspicious) }}</p></article>
      <article class="js-kpi"><div class="js-kpi-main"><span class="js-label">平均研判时延</span><strong>{{ seconds(statistics.latencyAverageMs) }}<small v-if="statistics.latencyAverageMs != null">s</small></strong></div><el-icon class="js-kpi-icon" aria-hidden="true"><Timer /></el-icon>
        <p>P95 {{ seconds(statistics.latencyP95Ms) }}<template v-if="statistics.latencyP95Ms != null"> s</template> · 样本 {{ number(statistics.latencySamples) }} 条</p></article>
    </div>
    <div class="js-charts">
      <section class="js-chart-panel" aria-labelledby="judge-outcomes-title">
        <div class="js-chart-heading"><h3 id="judge-outcomes-title">研判结论分布</h3><span class="js-scope">{{ statistics.total }} 条</span></div>
        <div v-if="statistics.total" class="js-outcomes">
          <button v-for="item in outcomes" :key="item.key" type="button" class="js-outcome" :class="{selected: selectedVerdict === item.key}" :disabled="!item.count || item.key === 'unknown'"
                  :aria-label="'筛选分析结论：' + item.label + '（' + item.count + ' 条）'" :aria-pressed="selectedVerdict === item.key" @click="$emit('select-verdict', item.key)">
            <span class="js-outcome-label">{{ item.label }}</span><span class="js-bar-track" aria-hidden="true"><span class="js-bar" :style="{width: item.count / maxOutcome * 100 + '%', background: item.color}" /></span><span class="js-outcome-count mono">{{ number(item.count) }}</span>
          </button>
        </div>
        <el-empty v-else description="暂无研判记录" :image-size="48" />
      </section>
      <section class="js-chart-panel" aria-labelledby="judge-volume-title">
        <div class="js-chart-heading"><h3 id="judge-volume-title">近 7 天研判量</h3><span class="js-scope">{{ weekTotal }} 次</span></div>
        <div v-if="weekTotal" class="js-volume" role="img" :aria-label="statistics.days.map(day => day.date + '：' + day.total + ' 次，完成 ' + day.done + '，分析中 ' + day.pending + '，失败 ' + day.failed).join('；')">
          <div v-for="day in statistics.days" :key="day.date" class="js-day" :data-date="day.date" :title="day.date + ' · ' + day.total + ' 次'">
            <span class="js-day-count mono">{{ number(day.total) }}</span>
            <div class="js-day-track"><div class="js-day-stack" :style="{height: day.total / maxDay * 100 + '%'}"><span v-for="item in dayStates" :key="item.key" :data-state="item.key" :title="item.label + '：' + number(day[item.key]) + ' 次'" :style="{height: day.total ? day[item.key] / day.total * 100 + '%' : '0%', background: item.color}" /></div></div>
            <span class="js-day-label">{{ day.date.slice(5) }}</span>
          </div>
        </div>
        <el-empty v-else description="近 7 天暂无研判记录" :image-size="48" />
        <div class="js-legend" v-if="weekTotal"><span v-for="item in dayStates" :key="item.key" :data-state="item.key"><i :style="{background: item.color}" aria-hidden="true" />{{ item.label }}</span></div>
      </section>
    </div>
  </section>
</template>

<script setup>
import {computed, ref, watch, onMounted, onBeforeUnmount} from "vue";
import {Brain, WarningFilled, QuestionFilled, Timer} from "../../icons";
import {buildJudgeStatistics, JUDGE_RECORD_LIMIT} from "../../utils/judgeStatistics";

const props = defineProps({records: {type: Array, default: () => []}, active: Boolean, selectedVerdict: {type: String, default: ""}});
defineEmits(["select-verdict"]);
const now = ref(new Date());
const statistics = computed(() => buildJudgeStatistics(props.records, now.value));
const number = value => value.toLocaleString("zh-CN");
const seconds = value => value == null ? "—" : (value / 1000).toLocaleString("zh-CN", {maximumFractionDigits: value < 1000 ? 3 : 2});
const proportion = value => statistics.value.done ? (value / statistics.value.done * 100).toFixed(1) + "%" : "—";
const outcomes = computed(() => [
  {key: "benign", label: "正常", color: "var(--chart-ok)"},
  {key: "suspicious", label: "可疑", color: "var(--chart-med)"},
  {key: "malicious", label: "恶意", color: "var(--chart-crit)"},
  {key: "pending", label: "分析中", color: "var(--chart-info)"},
  {key: "failed", label: "失败", color: "var(--neutral)"},
  ...(statistics.value.outcomes.unknown ? [{key: "unknown", label: "未分类", color: "var(--neutral)"}] : []),
].map(item => ({...item, count: statistics.value.outcomes[item.key]})));
const dayStates = computed(() => [
  {key: "done", label: "已完成", color: "var(--chart-ok)"},
  {key: "pending", label: "分析中", color: "var(--chart-info)"},
  {key: "failed", label: "失败", color: "var(--chart-crit)"},
  ...(statistics.value.days.some(day => day.unknown) ? [{key: "unknown", label: "未分类", color: "var(--neutral)"}] : []),
]);
const maxOutcome = computed(() => Math.max(1, ...outcomes.value.map(item => item.count)));
const maxDay = computed(() => Math.max(1, ...statistics.value.days.map(day => day.total)));
const weekTotal = computed(() => statistics.value.days.reduce((total, day) => total + day.total, 0));
watch(() => props.active, active => { if (active) now.value = new Date(); });
let timer;
onMounted(() => { timer = setInterval(() => { if (props.active) now.value = new Date(); }, 60000); });
onBeforeUnmount(() => clearInterval(timer));
</script>

<style scoped>
.js-statistics { margin-bottom: 20px; }
.js-heading, .js-chart-heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
.js-heading h3, .js-chart-heading h3 { margin: 0; color: var(--title); font-size: 14px; font-weight: 500; }
.js-scope, .js-label { color: var(--muted); font-size: 12px; }
.js-kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
.js-kpi { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 16px 12px; padding: 20px; min-width: 0;
  border: 1px solid var(--line); border-radius: 12px; background: var(--panel); box-shadow: var(--shadow-panel); }
.js-kpi-main { display: grid; gap: 8px; }
.js-kpi strong { color: var(--title); font-size: 30px; font-weight: 600; line-height: 1.2; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.js-kpi strong small { margin-left: 5px; color: var(--muted); font-size: 12px; font-weight: 400; }
.js-kpi p { grid-column: 1 / -1; margin: 0; color: var(--muted); font-size: 12px; line-height: 1.6; }
.js-kpi-icon { box-sizing: border-box; width: 40px; height: 40px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface-code); color: var(--brand); font-size: 20px; }
.js-icon-danger { border-color: var(--crit-line); background: var(--crit-bg); color: var(--crit); }
.js-icon-warning { border-color: var(--med-line); background: var(--med-bg); color: var(--med); }
.js-charts { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); margin-top: 16px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel); overflow: hidden; }
.js-chart-panel { min-width: 0; padding: 18px 20px; }
.js-chart-panel + .js-chart-panel { border-left: 1px solid var(--line-2); }
.js-outcomes { display: grid; gap: 5px; }
.js-outcome { display: grid; grid-template-columns: 48px minmax(0, 1fr) 45px; align-items: center; gap: 12px; min-height: 30px; padding: 2px 6px;
  border: 1px solid transparent; border-radius: 6px; background: none; color: var(--text); font: inherit; font-size: 12px; text-align: left; cursor: pointer;
  transition: border-color var(--motion-fast) var(--ease-out), background var(--motion-fast) var(--ease-out); }
.js-outcome:hover:not(:disabled), .js-outcome.selected { border-color: var(--line); background: var(--surface-code); }
.js-outcome:focus-visible { outline: 2px solid var(--brand); outline-offset: 1px; }
.js-outcome:disabled { cursor: default; }
.js-bar-track { height: 8px; border-radius: 4px; background: var(--surface-code); overflow: hidden; }
.js-bar { display: block; height: 100%; border-radius: inherit; transition: width var(--motion-panel) var(--ease-out); }
.js-outcome-count { text-align: right; }
.js-volume { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 12px; }
.js-day { display: grid; grid-template-rows: 20px 108px 20px; gap: 4px; min-width: 0; text-align: center; font-size: 12px; }
.js-day-count { color: var(--text); }
.js-day-label { color: var(--muted); }
.js-day-track { display: flex; flex-direction: column; justify-content: flex-end; border-bottom: 1px solid var(--line); }
.js-day-stack { display: flex; flex-direction: column; justify-content: flex-end; width: 60%; max-width: 32px; margin: 0 auto; border-radius: 4px 4px 0 0; overflow: hidden;
  transform-origin: bottom; }
.js-day-stack > span { display: block; flex: none; }
.js-legend { display: flex; flex-wrap: wrap; justify-content: center; gap: 14px; margin-top: 12px; color: var(--muted); font-size: 12px; }
.js-legend > span { display: inline-flex; align-items: center; gap: 5px; }
.js-legend i { width: 7px; height: 7px; border-radius: 2px; }
@media (prefers-reduced-motion: no-preference) {
  .js-day { transition: opacity var(--motion-fast) var(--ease-out); }
  .js-day-count { transition: color var(--motion-fast) var(--ease-out), scale var(--motion-fast) var(--ease-out); }
  .js-day-label { transition: color var(--motion-fast) var(--ease-out); }
  .js-day-stack { transition: height var(--motion-panel) var(--ease-out), translate var(--motion-fast) var(--ease-out), box-shadow var(--motion-fast) var(--ease-out);
    animation: js-bar-rise var(--motion-enter) var(--ease-out) backwards; }
  .js-day-stack > span { transition: height var(--motion-panel) var(--ease-out), opacity var(--motion-fast) var(--ease-out), filter var(--motion-fast) var(--ease-out); }
  .js-day:nth-child(2) .js-day-stack { animation-delay: 45ms; }
  .js-day:nth-child(3) .js-day-stack { animation-delay: 90ms; }
  .js-day:nth-child(4) .js-day-stack { animation-delay: 135ms; }
  .js-day:nth-child(5) .js-day-stack { animation-delay: 180ms; }
  .js-day:nth-child(6) .js-day-stack { animation-delay: 225ms; }
  .js-day:nth-child(7) .js-day-stack { animation-delay: 270ms; }
  .js-legend > span { transition: color var(--motion-fast) var(--ease-out); }
  .js-legend i { transition: scale var(--motion-fast) var(--ease-out); }
}
@media (hover: hover) and (pointer: fine) {
  /* 悬停聚焦：当前日期抬起，其余日期淡出让位；图例联动亮出对应分段。 */
  .js-volume:has(.js-day:hover) .js-day:not(:hover) { opacity: .55; }
  .js-day:hover .js-day-stack { box-shadow: 0 8px 16px color-mix(in srgb, var(--brand) 16%, transparent); }
  .js-day:hover .js-day-count { color: var(--title); }
  .js-day:hover .js-day-label { color: var(--text); }
  .js-day-stack > span:hover { filter: brightness(1.12); }
  .js-legend > span:hover { color: var(--text); }
  .js-chart-panel:has(.js-legend [data-state]:hover) .js-day-stack > span { opacity: .25; }
  .js-chart-panel:has(.js-legend [data-state="done"]:hover) .js-day-stack > [data-state="done"],
  .js-chart-panel:has(.js-legend [data-state="pending"]:hover) .js-day-stack > [data-state="pending"],
  .js-chart-panel:has(.js-legend [data-state="failed"]:hover) .js-day-stack > [data-state="failed"],
  .js-chart-panel:has(.js-legend [data-state="unknown"]:hover) .js-day-stack > [data-state="unknown"] { opacity: 1; filter: saturate(1.15); }
}
@media (prefers-reduced-motion: no-preference) {
  @media (hover: hover) and (pointer: fine) {
    .js-day:hover .js-day-stack { translate: 0 -2px; }
    .js-day:hover .js-day-count { scale: 1.06; }
    .js-legend > span:hover i { scale: 1.35; }
  }
}
@keyframes js-bar-rise { from { transform: scaleY(0); } to { transform: none; } }
.js-chart-panel :deep(.el-empty) { padding: 24px 0; }
@media (max-width: 1100px) { .js-kpis { gap: 12px; } .js-kpi { padding: 16px; gap: 12px 8px; } .js-kpi strong { font-size: 26px; } .js-kpi-icon { width: 34px; height: 34px; } }
@media (max-width: 900px) { .js-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } .js-charts { grid-template-columns: minmax(0, 1fr); } .js-chart-panel + .js-chart-panel { border-left: 0; border-top: 1px solid var(--line-2); } }
</style>
