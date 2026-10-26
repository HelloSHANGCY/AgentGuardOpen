<template>
  <div ref="rootEl" class="baseline-comparison">
    <section class="bc-card bc-controls" aria-labelledby="bc-title">
      <div class="bc-heading">
        <h3 id="bc-title">基线版本比较
          <el-tooltip content="所有版本使用当前同一份固定夹具、共享计数重新评估。正常步骤为负类，攻击夹具标记的风险步骤为正类，超阈值为预测正类。准确率、精确率、召回率和 F1 仅描述这些步骤，不代表完整引擎的拦截效果或真实业务误报率。AUC 在图中乘以 100；pp 表示百分点。" :show-after="200">
            <button type="button" class="bc-help" aria-label="基线比较评估口径">?</button>
          </el-tooltip>
        </h3>
        <div class="bc-actions"><span class="bc-muted">{{ eligible.length }} 个可比较版本</span>
          <el-button size="small" :disabled="!versionA || !versionB" @click="swap">交换 A/B</el-button>
          <el-button size="small" :loading="loading" :disabled="selectedVersions.length < 2" @click="load(true)"><el-icon class="btn-ic"><Refresh /></el-icon>重新评估</el-button>
        </div>
      </div>
      <div class="bc-selectors">
        <label><span>基线 A</span><el-select v-model="versionA" size="small" aria-label="基线 A 版本">
          <el-option v-for="model in models" :key="model.version" :label="optionLabel(model)" :value="model.version" :disabled="model.compatible === false || model.version === versionB" />
        </el-select></label>
        <label><span>对比 B</span><el-select v-model="versionB" size="small" aria-label="对比 B 版本">
          <el-option v-for="model in models" :key="model.version" :label="optionLabel(model)" :value="model.version" :disabled="model.compatible === false || model.version === versionA" />
        </el-select></label>
      </div>
      <div v-if="report" class="bc-evidence">
        <el-tag size="small" type="info" effect="plain">固定夹具 · {{ report.normal_steps + report.risk_steps }} 个步骤</el-tag>
        <span>正常 {{ report.normal_steps }} · 风险 {{ report.risk_steps }} · 共享计数</span>
        <span class="bc-time" :title="`样本 SHA-256：${report.fixture_sha256}`">{{ evaluatedAt }}</span>
      </div>
    </section>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon class="bc-error" />
    <el-empty v-if="eligible.length < 2" description="至少需要两个兼容的模型版本" :image-size="64" />
    <div v-else v-loading="loading" class="bc-content">
      <div class="bc-charts">
        <section class="bc-card bc-radar-card" aria-labelledby="bc-radar-title">
          <div class="bc-heading"><h3 id="bc-radar-title"><el-icon aria-hidden="true"><Radar /></el-icon>五维能力对比</h3><span class="bc-muted">0–100</span></div>
          <el-select v-model="extraVersion" size="small" aria-label="雷达额外版本 C">
            <el-option label="不添加额外版本" value="" />
            <el-option v-for="model in eligible" :key="model.version" :label="`C · ${optionLabel(model)}`" :value="model.version" :disabled="[versionA, versionB].includes(model.version)" />
          </el-select>
          <div class="bc-radar-wrap">
            <div ref="radarEl" class="bc-radar" role="img" :aria-label="radarDescription" />
            <p v-if="pairReady && !completeRadar.length" class="bc-chart-empty">{{ entries.some(entry => entry.complete) ? '已隐藏全部版本' : '当前版本缺少完整的五项指标' }}</p>
          </div>
          <div class="bc-legend" aria-label="雷达图版本图例">
            <button v-for="entry in entries" :key="entry.role" type="button" :aria-pressed="!hidden[entry.role]" :disabled="!entry.complete"
                    :title="entry.complete ? entry.version : '缺少完整指标：' + entry.version" @click="hidden[entry.role] = !hidden[entry.role]">
              <span :class="['bc-marker', `bc-marker-${entry.role}`]" aria-hidden="true" />
              <span class="bc-legend-name">{{ entry.label }}</span><span class="mono">F1 {{ formatMetric(entry.result?.metrics?.f1) }}</span>
            </button>
          </div>
          <p v-for="entry in entries.filter(item => item.result && !item.complete)" :key="entry.role" class="bc-muted bc-missing" role="status">{{ entry.role }} 缺少完整指标，雷达未绘制</p>
        </section>
        <section class="bc-card bc-bars-card" aria-labelledby="bc-bars-title">
          <div class="bc-heading"><h3 id="bc-bars-title"><el-icon aria-hidden="true"><DataAnalysis /></el-icon>A/B 指标对比</h3><span class="bc-muted">B − A</span></div>
          <div ref="barEl" class="bc-bars" role="img" :aria-label="barDescription" />
          <div class="bc-pair-legend"><span v-for="entry in entries.slice(0, 2)" :key="entry.role" :title="entry.version"><i :class="['bc-marker', `bc-marker-${entry.role}`]" aria-hidden="true" />{{ entry.label }}</span></div>
          <div v-if="pairReady" class="bc-confusion" aria-label="所选步骤混淆计数">
            <div v-for="entry in entries.slice(0, 2)" :key="entry.role"><b>{{ entry.role }}</b><span v-for="key in ['tp', 'fp', 'fn', 'tn']" :key="key">{{ key.toUpperCase() }} <strong class="mono">{{ entry.result.confusion[key] }}</strong></span></div>
          </div>
        </section>
      </div>
      <section class="bc-card bc-table-card" aria-labelledby="bc-table-title">
        <div class="bc-heading"><h3 id="bc-table-title">指标明细</h3><span class="bc-muted">差值 B − A</span></div>
        <el-table :data="rows" size="small" aria-label="基线 A 与对比 B 指标明细">
          <el-table-column label="指标" min-width="180"><template #default="{row}">{{ row.label }}<span v-if="row.higher !== null" class="bc-direction">{{ row.higher ? '↑' : '↓' }}</span></template></el-table-column>
          <el-table-column label="基线 A" min-width="140" align="right"><template #default="{row}"><span class="mono">{{ row.a }}</span></template></el-table-column>
          <el-table-column label="对比 B" min-width="140" align="right"><template #default="{row}"><span class="mono">{{ row.b }}</span></template></el-table-column>
          <el-table-column label="差值 B − A" min-width="160" align="right"><template #default="{row}"><span :class="['mono', `bc-${row.tone}`]">{{ row.delta }}</span></template></el-table-column>
        </el-table>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue';
import { DataAnalysis, Radar, Refresh } from '../icons';
import { compareBaselines } from '../store/baseline';
import echarts from '../utils/echarts';
import { themeColor } from '../utils/theme';
import { RADAR_METRICS, chartValue, comparisonRows, defaultVersions, formatMetric, isNumber, sourceLabel } from '../utils/baselineComparison';

const props = defineProps({ models: {type: Array, default: () => []}, active: {type: String, default: ''} });
const versionA = ref(''), versionB = ref(''), extraVersion = ref('');
const report = ref(null), loading = ref(false), error = ref('');
const rootEl = ref(null), radarEl = ref(null), barEl = ref(null);
const hidden = reactive({A: false, B: false, C: false});
const eligible = computed(() => props.models.filter(model => model.compatible !== false));
const selectedVersions = computed(() => [...new Set([versionA.value, versionB.value, extraVersion.value].filter(Boolean))]);
const optionLabel = model => `${sourceLabel(model)} · ${model.version}${model.active ? ' · 使用中' : ''}${model.compatible === false ? ' · 不兼容' : ''}`;
const byVersion = computed(() => new Map((report.value?.models || []).map(model => [model.version, model])));
const entries = computed(() => [versionA.value, versionB.value, extraVersion.value].filter(Boolean).map((version, index) => {
  const role = ['A', 'B', 'C'][index], result = byVersion.value.get(version);
  return {version, role, result, label: `${role} · ${sourceLabel(props.models.find(model => model.version === version))}`,
    complete: !!result && RADAR_METRICS.every(metric => isNumber(result.metrics[metric.key]))};
}));
const pairReady = computed(() => !!byVersion.value.get(versionA.value) && !!byVersion.value.get(versionB.value));
const rows = computed(() => comparisonRows(byVersion.value.get(versionA.value), byVersion.value.get(versionB.value)));
const completeRadar = computed(() => entries.value.filter(entry => entry.complete && !hidden[entry.role]));
const evaluatedAt = computed(() => report.value ? new Date(report.value.evaluated_at * 1000).toLocaleString('zh-CN', {hour12: false}) : '');
const barDescription = computed(() => '固定夹具步骤的 A/B 指标柱状图。' + rows.value.slice(0, 5).map(row => `${row.label}：A ${row.a}，B ${row.b}`).join('；'));
const radarDescription = computed(() => '固定夹具五维雷达图。' + completeRadar.value.map(entry =>
  entry.label + '，' + RADAR_METRICS.map(metric => metric.label + formatMetric(entry.result.metrics[metric.key], metric.kind)).join('，')).join('；'));

let controller, requestId = 0, alive = true, observer, radarChart, barChart, frame;
const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
watch(() => props.models, () => {
  const available = eligible.value.map(model => model.version), defaults = defaultVersions(props.models, props.active);
  if (!available.includes(versionA.value)) versionA.value = defaults.a;
  if (!available.includes(versionB.value) || versionB.value === versionA.value) versionB.value = defaults.b !== versionA.value ? defaults.b : available.find(version => version !== versionA.value) || '';
  if (!extraVersion.value && !report.value) extraVersion.value = defaults.c;
  if (!available.includes(extraVersion.value) || [versionA.value, versionB.value].includes(extraVersion.value)) extraVersion.value = '';
}, {immediate: true});

async function load(force = false) {
  const versions = selectedVersions.value;
  if (versions.length < 2) return;
  if (!force && versions.every(version => byVersion.value.has(version))) {
    // 交换 A/B 只改变顺序与差值，不重复计算已有的同样本结果。
    ++requestId; controller?.abort(); loading.value = false; error.value = ''; scheduleRender(); return;
  }
  const id = ++requestId;
  controller?.abort(); controller = new AbortController(); loading.value = true; error.value = '';
  try {
    const data = await compareBaselines(versions, controller.signal);
    if (alive && id === requestId) report.value = data;
  } catch (cause) {
    if (alive && id === requestId && cause.name !== 'AbortError') error.value = cause.message;
  } finally {
    if (alive && id === requestId) { loading.value = false; scheduleRender(); }
  }
}
function swap() { [versionA.value, versionB.value] = [versionB.value, versionA.value]; }
watch([versionA, versionB, extraVersion], () => {
  if ([versionA.value, versionB.value].includes(extraVersion.value)) extraVersion.value = '';
  load();
}, {flush: 'post'});

function renderCharts() {
  if (!alive) return;
  if (!pairReady.value) { radarChart?.clear(); barChart?.clear(); return; }
  if (!radarEl.value?.clientWidth || !barEl.value?.clientWidth) return;
  const palette = {A: themeColor('--chart-info'), B: themeColor('--chart-low'), C: themeColor('--chart-high')};
  const colors = {text: themeColor('--text'), muted: themeColor('--muted'), line: themeColor('--line'), panel: themeColor('--panel')};
  const textStyle = {fontFamily: getComputedStyle(document.body).fontFamily};
  const measure = document.createElement('canvas').getContext('2d');
  measure.font = `12px ${textStyle.fontFamily}`;
  const labelWidth = Math.max(...RADAR_METRICS.map(metric => measure.measureText(metric.axis).width));
  const radius = Math.floor(Math.min(radarEl.value.clientHeight * 0.38,
    Math.max(45, (radarEl.value.clientWidth / 2 - labelWidth - 8) / Math.cos(Math.PI / 10) - 12)));
  const tooltip = {confine: true, renderMode: 'richText', backgroundColor: colors.panel, borderColor: colors.line, textStyle: {color: colors.text}};
  const common = {animation: !motion.matches, animationDuration: 700, animationDurationUpdate: 350, animationEasing: 'cubicOut', textStyle};
  radarChart ||= echarts.init(radarEl.value);
  barChart ||= echarts.init(barEl.value);
  radarChart.resize(); barChart.resize();
  radarChart.setOption({...common,
    tooltip: {...tooltip, trigger: 'item', formatter: item => `${item.name}\n` + RADAR_METRICS.map((metric, index) =>
      `${metric.label}  ${formatMetric(item.value[index] / 100, metric.kind)}`).join('\n')},
    radar: {center: ['50%', '51%'], radius, splitNumber: 4,
      indicator: RADAR_METRICS.map(metric => ({name: metric.axis, min: 0, max: 100})),
      axisName: {color: colors.muted, fontSize: 12}, axisNameGap: 12,
      axisLine: {lineStyle: {color: colors.line}}, splitLine: {lineStyle: {color: colors.line}},
      splitArea: {areaStyle: {color: ['transparent', themeColor('--brand-bg')]}}},
    series: [{type: 'radar', animationDelay: index => index * 90, data: completeRadar.value.map(entry => ({name: entry.label,
      value: RADAR_METRICS.map(metric => chartValue(entry.result.metrics[metric.key])),
      symbol: {A: 'circle', B: 'rect', C: 'triangle'}[entry.role], symbolSize: 5,
      lineStyle: {color: palette[entry.role], width: 2, type: {A: 'solid', B: 'dashed', C: 'dotted'}[entry.role]},
      itemStyle: {color: palette[entry.role]}, areaStyle: {color: palette[entry.role], opacity: 0.07}}))}]}, true);
  const pair = entries.value.slice(0, 2);
  barChart.setOption({...common, grid: {left: 8, right: 16, top: 32, bottom: 12, containLabel: true},
    tooltip: {...tooltip, trigger: 'axis', axisPointer: {type: 'shadow'}, formatter: items => {
      if (!items.length) return '';
      const metric = RADAR_METRICS[items[0].dataIndex];
      return metric.label + '\n' + items.map(item => `${item.seriesName}  ${formatMetric(pair[item.seriesIndex].result.metrics[metric.key], metric.kind)}`).join('\n');
    }},
    xAxis: {type: 'category', data: RADAR_METRICS.map(metric => metric.axis), axisTick: {show: false}, axisLine: {lineStyle: {color: colors.line}}, axisLabel: {color: colors.muted, fontSize: 12, interval: 0}},
    yAxis: {type: 'value', min: 0, max: 100, interval: 20, axisLabel: {color: colors.muted, fontSize: 12}, splitLine: {lineStyle: {color: colors.line, type: 'dashed'}}},
    series: pair.map(entry => ({name: entry.label, type: 'bar', barMaxWidth: 25, barGap: '35%', animationDelay: index => index * 70,
      itemStyle: {color: palette[entry.role], borderRadius: [3, 3, 0, 0]},
      label: {show: true, position: 'top', color: colors.muted, fontSize: 11, formatter: item => isNumber(item.value) ? item.value.toFixed(1) : ''},
      data: RADAR_METRICS.map(metric => chartValue(entry.result.metrics[metric.key]))}))}, true);
}
function scheduleRender() { if (alive) { cancelAnimationFrame(frame); frame = requestAnimationFrame(renderCharts); } }
watch([entries, completeRadar, pairReady], scheduleRender, {flush: 'post'});
onMounted(async () => {
  await nextTick();
  if (!alive) return;
  observer = new ResizeObserver(scheduleRender); observer.observe(rootEl.value);
  motion.addEventListener('change', scheduleRender); load();
});
onBeforeUnmount(() => {
  alive = false; ++requestId; controller?.abort(); observer?.disconnect(); cancelAnimationFrame(frame);
  motion.removeEventListener('change', scheduleRender); radarChart?.dispose(); barChart?.dispose();
});
</script>

<style scoped>
.baseline-comparison { --bc-a: var(--chart-info); --bc-b: var(--chart-low); --bc-c: var(--chart-high); }
.bc-card { min-width: 0; padding: var(--space-4); border: 1px solid var(--line); border-radius: var(--radius-panel); background: var(--panel); }
.bc-heading, .bc-heading h3, .bc-actions { display: flex; align-items: center; gap: 8px; }
.bc-heading { justify-content: space-between; margin-bottom: 14px; flex-wrap: wrap; }
.bc-heading h3 { margin: 0; color: var(--title); font-size: 14px; font-weight: 500; }
.bc-heading h3 > .el-icon { color: var(--muted); font-size: 16px; }
.bc-muted { color: var(--muted); font-size: 12px; }
.bc-actions { flex-wrap: wrap; gap: 10px; }
.bc-help { display: inline-grid; place-items: center; flex: none; width: 17px; height: 17px; padding: 0; border: 1px solid var(--muted); border-radius: 50%; color: var(--muted); background: transparent; cursor: help; font-size: 11px; }
.bc-selectors { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.bc-selectors label { min-width: 0; display: grid; gap: 6px; color: var(--muted); font-size: 12px; }
.bc-evidence { display: flex; align-items: center; flex-wrap: wrap; gap: 8px 14px; margin-top: 12px; color: var(--muted); font-size: 12px; }
.bc-time { margin-left: auto; font-family: var(--mono); }
.bc-error, .bc-content { margin-top: 16px; }
.bc-charts { display: grid; grid-template-columns: minmax(320px, .8fr) minmax(0, 1.2fr); gap: 16px; }
.bc-radar-wrap { position: relative; }
.bc-radar { height: 280px; width: 100%; }
.bc-bars { height: 320px; width: 100%; }
.bc-chart-empty { position: absolute; inset: 40% 0 auto; text-align: center; color: var(--muted); font-size: 12px; }
.bc-marker { display: inline-block; flex: none; width: 8px; height: 8px; background: var(--bc-a); }
.bc-marker-A { background: var(--bc-a); border-radius: 50%; }
.bc-marker-B { background: var(--bc-b); border-radius: 1px; }
.bc-marker-C { background: var(--bc-c); clip-path: polygon(50% 0, 100% 100%, 0 100%); }
.bc-legend { display: grid; gap: 6px; margin-top: 4px; }
.bc-legend button { display: flex; align-items: center; min-width: 0; gap: 8px; padding: 5px 8px; border: 1px solid var(--line-2); border-radius: 6px; background: transparent; color: var(--text); cursor: pointer; font-size: 12px; }
.bc-legend button[aria-pressed="false"], .bc-legend button:disabled { opacity: .45; }
.bc-legend button:disabled { cursor: not-allowed; }
.bc-legend-name { flex: 1; min-width: 0; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-legend .mono { flex: none; color: var(--muted); font-size: 11px; }
.bc-legend button:focus-visible, .bc-help:focus-visible { outline: 2px solid var(--brand); outline-offset: 3px; }
.bc-pair-legend { display: flex; justify-content: center; flex-wrap: wrap; gap: 8px 20px; margin: 10px 0 20px; font-size: 12px; }
.bc-pair-legend > span { display: inline-flex; align-items: center; gap: 6px; }
.bc-confusion { display: grid; gap: 8px; padding-top: 12px; border-top: 1px solid var(--line-2); font-size: 12px; color: var(--muted); }
.bc-confusion > div { display: grid; grid-template-columns: 20px repeat(4, minmax(0, 1fr)); align-items: center; gap: 8px; }
.bc-confusion b, .bc-confusion strong { color: var(--text); font-weight: 500; }
.bc-missing { margin: 8px 0 0; }
.bc-table-card { margin-top: 16px; }
.bc-direction { color: var(--muted); margin-left: 6px; font-size: 12px; }
.bc-better { color: var(--ok); }
.bc-worse { color: var(--crit); }
.bc-neutral { color: var(--muted); }
@media (max-width: 1100px) {
  .bc-charts { grid-template-columns: minmax(300px, .85fr) minmax(0, 1.15fr); }
  .bc-bars { height: 300px; }
}
@media (max-width: 900px) {
  .bc-charts, .bc-selectors { grid-template-columns: minmax(0, 1fr); }
  .bc-radar { height: 300px; }
}
</style>
