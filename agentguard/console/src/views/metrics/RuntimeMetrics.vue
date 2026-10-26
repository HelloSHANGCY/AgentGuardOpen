<template>
  <div class="mt-runtime">
    <div class="mt-service-bar"><div class="mt-runtime-heading"><h3 class="mt-section-heading"><el-icon aria-hidden="true"><DataLine /></el-icon>运行概览</h3><span class="mt-note">快照 {{ metrics.generated_at ? fmt(metrics.generated_at) : '尚未获取' }}</span></div><el-button size="small" :loading="refreshing" :disabled="refreshing" @click="reload"><el-icon class="btn-ic" aria-hidden="true"><Refresh /></el-icon>刷新指标</el-button></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon class="my-12" />
    <div class="mt-runtime-overview" v-loading="refreshing && !metrics.generated_at">
      <section class="mt-overview-cell"><div class="mt-card-head"><h3>会话流量</h3><el-icon class="mt-stat-icon" aria-hidden="true"><Connection /></el-icon></div><div class="mt-big">{{ number(totals.tasks) }}<small>个会话</small></div><dl class="mt-inline-stats"><div><dt>有拦截</dt><dd>{{ number(totals.blocked) }}</dd></div><div><dt>仅待确认</dt><dd>{{ number(totals.asked) }}</dd></div><div><dt>全放行</dt><dd>{{ number(totals.allowed_only) }}</dd></div></dl><p class="mt-note">事件 {{ number(metrics.totals?.events) }} 条 · 决策 {{ number(metrics.totals?.decisions) }} 次</p></section>
      <section class="mt-overview-cell"><div class="mt-card-head"><h3>回放场景归类（推算）</h3><el-icon class="mt-stat-icon" aria-hidden="true"><Aim /></el-icon></div><dl class="mt-rate-pair"><div><dt>检出率</dt><dd>{{ pct(metrics.rates?.detection) }}</dd></div><div><dt>误发现率 FDR</dt><dd>{{ pct(metrics.rates?.false_positive) }}</dd></div></dl><p class="mt-note mono">TP {{ confusion.tp ?? 0 }} · FP {{ confusion.fp ?? 0 }} · FN {{ confusion.fn ?? 0 }} · TN {{ confusion.tn ?? 0 }}</p></section>
      <section class="mt-overview-cell"><div class="mt-card-head"><h3>决策延迟 P95</h3><el-icon class="mt-stat-icon" aria-hidden="true"><Timer /></el-icon></div><div class="mt-big">{{ number(metrics.decision_latency_ms?.p95) }}<small>ms</small></div><dl class="mt-performance-kv"><div><dt>决策延迟 P50</dt><dd>{{ number(metrics.decision_latency_ms?.p50) }} ms</dd></div><div><dt>转发增量 P95</dt><dd>{{ number(metrics.forward_latency_ms?.p95) }} ms</dd></div></dl></section>
      <section class="mt-overview-cell"><div class="mt-card-head"><h3>{{ hasContainerCPU ? '容器 CPU' : '网关进程 CPU' }}</h3><el-icon class="mt-stat-icon" aria-hidden="true"><Cpu /></el-icon></div><div class="mt-big">{{ cpuText }}<small>%</small></div><dl class="mt-performance-kv"><div><dt>{{ metrics.cpu?.container_rss_mb != null ? '容器内存' : '进程内存峰值' }}</dt><dd>{{ number(metrics.cpu?.container_rss_mb ?? metrics.cpu?.max_rss_mb) }} MB</dd></div><div><dt>决策 P99</dt><dd>{{ number(metrics.decision_latency_ms?.p99) }} ms</dd></div></dl></section>
    </div>

    <div class="mt-runtime-charts" v-loading="refreshing && !metrics.generated_at">
      <section class="mt-chart-panel"><div class="mt-card-head"><h3><el-icon aria-hidden="true"><DataAnalysis /></el-icon>{{ scenarioScope === 'risk' ? '各场景风险会话' : '各场景会话结果' }}</h3><el-select v-model="scenarioScope" size="small" class="mt-chart-select" aria-label="场景图表范围"><el-option label="风险会话" value="risk" /><el-option label="全部会话" value="all" /></el-select></div><div ref="chartScenario" v-show="chartScenarios.length" class="mt-chart" role="img" aria-label="各场景有拦截、仅待确认和全放行的会话数，完整数值见下方场景统计" /><el-empty v-if="!chartScenarios.length" :description="scenarioScope === 'risk' ? '暂无风险会话' : '暂无场景统计'" :image-size="64" /></section>
      <section class="mt-chart-panel"><div class="mt-card-head"><h3><el-icon aria-hidden="true"><TrendCharts /></el-icon>规则命中排行</h3><el-select v-model="ruleLimit" size="small" class="mt-chart-select" aria-label="规则图表条数"><el-option v-for="limit in [5, 10, 20]" :key="limit" :label="'前 ' + limit + ' 条'" :value="limit" /></el-select></div><div ref="chartRules" v-show="chartRuleRows.length" class="mt-chart" :style="{height: Math.max(300, chartRuleRows.length * 24 + 48) + 'px'}" role="img" :aria-label="'规则命中次数前 ' + ruleLimit + ' 名，完整数值见下方规则明细'" /><el-empty v-if="!chartRuleRows.length" description="暂无规则命中" :image-size="64" /></section>
    </div>
    <section class="mt-runtime-details">
      <el-tabs v-model="tableTab" aria-label="运行指标明细">
        <el-tab-pane label="场景统计" name="scenarios"><div class="mt-table-tools"><el-input v-model="scenarioQuery" size="small" clearable aria-label="搜索运行场景" placeholder="搜索场景名称"><template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template></el-input><span class="mt-note">{{ filteredScenarios.length }} 个场景</span></div><el-table :data="pagedScenarios" size="small" class="mt-runtime-scenarios" empty-text="没有匹配的场景"><el-table-column label="场景" min-width="230"><template #default="{row}"><span class="mono mt-wrap">{{ row.name }}</span></template></el-table-column><el-table-column label="场景标签" width="120"><template #default="{row}"><el-tag size="small" effect="plain" :type="row.malicious ? 'danger' : benignScenarios.has(row.name) ? 'success' : 'info'">{{ row.malicious ? '已知恶意' : benignScenarios.has(row.name) ? '已知正常' : '其他 / 未标注' }}</el-tag></template></el-table-column><el-table-column prop="tasks" label="会话数" width="105" /><el-table-column prop="blocked" label="有拦截" width="100" /><el-table-column prop="asked" label="仅待确认" width="100" /><el-table-column prop="allowed_only" label="全放行" width="100" /></el-table><div class="mt-pager" v-if="filteredScenarios.length > 10"><el-pagination background size="small" layout="total, prev, pager, next" :pager-count="5" :total="filteredScenarios.length" :page-size="10" v-model:current-page="scenarioPage" /></div></el-tab-pane>
        <el-tab-pane label="规则明细" name="rules"><div class="mt-table-tools"><el-input v-model="ruleQuery" size="small" clearable aria-label="搜索命中规则" placeholder="搜索规则编号"><template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template></el-input><span class="mt-note">{{ filteredRules.length }} 条规则 · 共命中 {{ totalRuleHits }} 次</span></div><el-table :data="pagedRuleRows" size="small" class="mt-runtime-rules" empty-text="没有匹配的规则"><el-table-column label="规则编号" min-width="240"><template #default="{row}"><span class="mono mt-wrap">{{ row.name }}</span></template></el-table-column><el-table-column prop="hits" label="命中次数" width="120" /><el-table-column label="占全部规则命中" min-width="160"><template #default="{row}">{{ pct(totalRuleHits ? row.hits/totalRuleHits : null) }}</template></el-table-column></el-table><div class="mt-pager" v-if="filteredRules.length > 10"><el-pagination background size="small" layout="total, prev, pager, next" :pager-count="5" :total="filteredRules.length" :page-size="10" v-model:current-page="rulePage" /></div></el-tab-pane>
      </el-tabs>
    </section>
  </div>
</template>
<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount, nextTick } from "vue";
import echarts from "../../utils/echarts";
import { themeColor as cssVar } from "../../utils/theme";
import { api } from "../../api/client";
import { metrics, scenarioRows, cpuVal } from "../../store/runtime";
import { fmt, pct as formatPct } from "../../utils/format";

const chartScenario = ref(null), chartRules = ref(null), refreshing = ref(false), error = ref('');
const tableTab = ref('scenarios'), scenarioQuery = ref(''), ruleQuery = ref(''), scenarioPage = ref(1), rulePage = ref(1);
const scenarioScope = ref('risk'), ruleLimit = ref(10);
const benignScenarios = new Set(['B-RD','B-OPS','B-SEC','B-SUP']);
const confusion = computed(() => metrics.value.confusion || {});
const cpuText = computed(() => cpuVal.value === '-' ? '—' : cpuVal.value);
const pct = value => value == null ? '—' : formatPct(value);
const sortedScenarios = computed(() => [...scenarioRows.value].sort((a,b) => b.tasks-a.tasks || a.name.localeCompare(b.name)));
const totals = computed(() => sortedScenarios.value.reduce((sum,r) => {
  for (const key of ['tasks','blocked','asked','allowed_only']) sum[key] += Number(r[key] || 0);
  return sum;
},{tasks:0,blocked:0,asked:0,allowed_only:0}));
const hasContainerCPU = computed(() => metrics.value.cpu?.container_cpu_percent != null);
const ruleRows = computed(() => Object.entries(metrics.value.rule_hits || {}).map(([name,hits]) => ({name,hits})).sort((a,b) => b.hits-a.hits || a.name.localeCompare(b.name)));
const totalRuleHits = computed(() => ruleRows.value.reduce((n,r) => n+r.hits,0));
const chartScenarios = computed(() => scenarioScope.value === 'all' ? sortedScenarios.value.slice(0,12)
  : [...sortedScenarios.value].filter(row => row.blocked || row.asked).sort((a,b) => (b.blocked+b.asked)-(a.blocked+a.asked) || a.name.localeCompare(b.name)).slice(0,12));
const chartRuleRows = computed(() => ruleRows.value.slice(0,ruleLimit.value));
const filteredScenarios = computed(() => sortedScenarios.value.filter(r => r.name.toLowerCase().includes(scenarioQuery.value.trim().toLowerCase())));
const filteredRules = computed(() => ruleRows.value.filter(r => r.name.toLowerCase().includes(ruleQuery.value.trim().toLowerCase())));
const pagedScenarios = computed(() => filteredScenarios.value.slice((scenarioPage.value-1)*10,scenarioPage.value*10));
const pagedRuleRows = computed(() => filteredRules.value.slice((rulePage.value-1)*10,rulePage.value*10));
watch(scenarioQuery, () => { scenarioPage.value = 1; });
watch(ruleQuery, () => { rulePage.value = 1; });
watch(() => filteredScenarios.value.length, n => { scenarioPage.value = Math.min(scenarioPage.value,Math.max(1,Math.ceil(n/10))); });
watch(() => filteredRules.value.length, n => { rulePage.value = Math.min(rulePage.value,Math.max(1,Math.ceil(n/10))); });
const number = value => value == null || !Number.isFinite(Number(value)) ? '—' : Number(value).toLocaleString('zh-CN',{maximumFractionDigits:1});
let chart1, chart2, chart1Sig = '', chart2Sig = '', observer, frame, alive = true;
const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
async function revealDetail(kind, name) {
  tableTab.value = kind;
  if (kind === 'scenarios') scenarioQuery.value = name; else ruleQuery.value = name;
  await nextTick();
  document.querySelector('.mt-runtime .el-tab-pane:not([style*="display: none"]) .mt-table-tools')?.scrollIntoView({block:'nearest'});
}
const shortLabel = value => String(value).length > 22 ? String(value).slice(0,21) + '…' : value;
function renderCharts() {
  if (!alive) return;
  const axis = {color:cssVar('--muted'),fontSize:12};
  const split = {lineStyle:{color:cssVar('--line'),type:'dashed'}};
  const motion = !motionPreference.matches;
  const textStyle = {fontFamily:getComputedStyle(document.body).fontFamily};
  if (chartScenario.value?.clientWidth && chartScenarios.value.length) {
    const sig = motion + '|' + scenarioScope.value + '|' + JSON.stringify(chartScenarios.value);
    const entering = !chart1;
    if (!chart1) { chart1 = echarts.init(chartScenario.value); chart1.on('click', event => revealDetail('scenarios', event.name)); }
    chart1.resize();
    if (sig !== chart1Sig) {
      chart1Sig = sig;
      chart1.setOption({animation:motion, animationDuration:entering ? 600 : 240, animationDurationUpdate:240, animationEasing:'cubicOut', animationDelay: idx => Math.min(idx * 30, 150), textStyle, grid:{left:8,right:20,top:42,bottom:12,containLabel:true}, tooltip:{trigger:'axis',confine:true,renderMode:'richText',backgroundColor:cssVar('--panel'),borderColor:cssVar('--line'),textStyle:{color:cssVar('--text')}},legend:{top:0,itemWidth:9,itemHeight:9,icon:'circle',textStyle:axis},
        xAxis:{type:'value',minInterval:1,axisLabel:axis,splitLine:split},yAxis:{type:'category',inverse:true,data:chartScenarios.value.map(r=>r.name),axisLabel:{...axis,fontFamily:'monospace',formatter:shortLabel}},
        series:[{name:'有拦截',field:'blocked',color:'--chart-crit'},{name:'仅待确认',field:'asked',color:'--chart-med'},...(scenarioScope.value === 'all' ? [{name:'全放行',field:'allowed_only',color:'--chart-ok'}] : [])].map(s=>({name:s.name,type:'bar',stack:'total',barMaxWidth:18,itemStyle:{color:cssVar(s.color),borderRadius:3},data:chartScenarios.value.map(r=>r[s.field] || 0)}))},true);
    }
  }
  if (chartRules.value?.clientWidth && chartRuleRows.value.length) {
    const sig = motion + '|' + ruleLimit.value + '|' + JSON.stringify(chartRuleRows.value);
    const entering = !chart2;
    if (!chart2) { chart2 = echarts.init(chartRules.value); chart2.on('click', event => revealDetail('rules', event.name)); }
    chart2.resize();
    if (sig !== chart2Sig) {
      chart2Sig = sig;
      chart2.setOption({animation:motion, animationDuration:entering ? 600 : 240, animationDurationUpdate:240, animationEasing:'cubicOut', animationDelay: idx => Math.min(idx * 30, 150), textStyle,grid:{left:8,right:56,top:16,bottom:12,containLabel:true},tooltip:{trigger:'axis',confine:true,renderMode:'richText',backgroundColor:cssVar('--panel'),borderColor:cssVar('--line'),textStyle:{color:cssVar('--text')}},
        xAxis:{type:'value',minInterval:1,axisLabel:axis,splitLine:split},yAxis:{type:'category',inverse:true,data:chartRuleRows.value.map(r=>r.name),axisLabel:{...axis,fontFamily:'monospace',formatter:shortLabel}},
        series:[{name:'命中次数',type:'bar',barMaxWidth:16,itemStyle:{color:cssVar('--chart-brand'),borderRadius:[0,3,3,0]},label:{show:true,position:'right',color:cssVar('--muted'),fontSize:12,formatter:p => Number(p.value).toLocaleString('zh-CN',{notation:'compact',maximumFractionDigits:1})},data:chartRuleRows.value.map(r=>r.hits)}]},true);
    }
  }
}
function scheduleRender() { if (!alive) return; cancelAnimationFrame(frame); frame = requestAnimationFrame(renderCharts); }
watch([chartScenarios,chartRuleRows,scenarioScope], scheduleRender, {flush:'post'});
async function reload() {
  if (refreshing.value) return;
  refreshing.value = true; error.value = '';
  try { const snapshot = await api('/v1/runtime/metrics'); if (alive) metrics.value = snapshot; }
  catch (e) { if (alive) error.value = '指标加载失败：' + e.message; }
  finally { if (alive) refreshing.value = false; }
}
onMounted(async () => {
  await nextTick();
  if (!alive) return;
  observer = new ResizeObserver(scheduleRender);
  if (chartScenario.value) observer.observe(chartScenario.value);
  if (chartRules.value) observer.observe(chartRules.value);
  motionPreference.addEventListener('change', scheduleRender);
  scheduleRender(); reload();
});
onBeforeUnmount(() => { alive = false; motionPreference.removeEventListener('change', scheduleRender); observer?.disconnect(); cancelAnimationFrame(frame); chart1?.dispose(); chart2?.dispose(); });
</script>
