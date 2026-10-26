<template>
  <section class="tv-visualizations" aria-label="威胁可视化">
    <article ref="trendPanel" class="tv-panel tv-trend" data-motion-item>
      <header class="tv-heading">
        <h3><TrendCharts aria-hidden="true" />威胁趋势<span class="tv-period-title">{{ statistics.window.title }}</span></h3>
        <div class="tv-heading-actions">
          <el-button v-if="selection" link @click="emit('select', null)">清除图表筛选</el-button>
          <span class="tv-scope">已加载记录</span>
          <div class="tv-periods" role="group" aria-label="图表时间范围">
            <button v-for="item in THREAT_PERIODS" :key="item.key" type="button" :aria-pressed="period === item.key" :class="{active: period === item.key}" @click="changePeriod(item.key)">{{ item.label }}</button>
          </div>
        </div>
      </header>
      <template v-if="loaded">
        <div class="tv-trend-summary">
          <span>期间触发 <strong class="mono">{{ number(statistics.total) }}</strong> 次</span>
          <span>严重 <strong class="tv-critical mono">{{ number(statistics.severities.CRITICAL) }}</strong></span>
          <span>高危 <strong class="tv-high mono">{{ number(statistics.severities.HIGH) }}</strong></span>
          <span>已阻断 <strong class="tv-blocked mono">{{ number(statistics.blocked) }}</strong></span>
          <span class="tv-stack-label">按风险级别堆积</span>
        </div>
        <div v-if="statistics.total" ref="trendElement" class="tv-trend-chart" role="img" :aria-label="statistics.window.title + '风险趋势，共触发' + statistics.total + '次，已阻断' + statistics.blocked + '次。可展开趋势数据表查看各时段。'"></div>
        <div v-else class="tv-empty tv-trend-chart"><TrendCharts aria-hidden="true" /><span>{{ error ? '暂时无法读取风险数据' : '所选时段暂无已加载风险记录' }}</span></div>
        <details v-if="statistics.total" class="tv-data-table">
          <summary>趋势数据表</summary>
          <div class="tv-data-scroll" tabindex="0" aria-label="各时段风险次数">
            <table><thead><tr><th>时段</th><th v-for="item in series" :key="item.key">{{ item.label }}</th><th>合计</th></tr></thead>
              <tbody><tr v-for="bucket in statistics.buckets" :key="bucket.start"><th>{{ fullTime(bucket.start) }} — {{ fullTime(bucket.end) }}</th><td v-for="item in series" :key="item.key">{{ bucket[item.key] }}</td><td>{{ bucket.total }}</td></tr></tbody>
            </table>
          </div>
        </details>
      </template>
      <el-skeleton v-else class="tv-loading" :rows="4" animated />
    </article>

    <div class="tv-secondary">
      <article class="tv-panel tv-distribution" data-motion-item>
        <header class="tv-heading"><h3><DataAnalysis aria-hidden="true" />风险类型分布</h3><span class="tv-scope">{{ statistics.window.title }}</span></header>
        <div v-if="loaded && statistics.total" class="tv-types">
          <button v-for="(item, index) in statistics.categories" :key="item.key" type="button" class="tv-type" :class="{selected: selected('category', item.key)}" :aria-pressed="selected('category', item.key)" :title="categoryLabel(item) + '：' + item.count + ' 次'" @click="selectCategory(item)">
            <span class="tv-type-copy"><span class="ellipsis">{{ categoryLabel(item) }}</span><span class="mono">{{ number(item.count) }}<small>{{ (item.count / statistics.total * 100).toFixed(1) }}%</small></span></span>
            <span class="tv-bar"><i :style="{width: item.count / statistics.total * 100 + '%', background: categoryColors[index]}" /></span>
          </button>
        </div>
        <div v-else-if="loaded" class="tv-empty tv-secondary-empty"><DataAnalysis aria-hidden="true" /><span>暂无类型分布</span></div>
        <el-skeleton v-else class="tv-loading" :rows="4" animated />
        <footer class="tv-footer"><span>合计 <strong class="mono">{{ loaded ? number(statistics.total) : '—' }}</strong> 次触发</span><span>{{ loaded ? statistics.categories.length : '—' }} 项</span></footer>
      </article>

      <article class="tv-panel tv-hotspots" :class="{'tv-radar-running': radarActive}" data-motion-item>
        <header class="tv-heading"><h3><Aim aria-hidden="true" />风险来源热点</h3><span class="tv-status" :class="{paused, stale: error}"><i />{{ error ? '更新失败' : paused ? '已暂停' : '随记录更新' }}</span></header>
        <div v-if="loaded && statistics.total" class="tv-hotspot-content">
          <div class="tv-radar">
            <svg viewBox="0 0 300 272" aria-label="来源触发量，圆点大小表示触发次数" role="group">
              <g class="tv-radar-grid" aria-hidden="true">
                <circle cx="150" cy="136" r="112" /><circle cx="150" cy="136" r="78" /><circle cx="150" cy="136" r="43" />
                <path d="M38 136H262M150 24V248M71 57L229 215M71 215L229 57" />
              </g>
              <g class="tv-radar-sweep" aria-hidden="true">
                <path v-for="(slice, index) in sweepSlices" :key="index" :d="slice" :opacity="(index + 1) * .016" />
                <path class="tv-radar-beam" d="M150 136V24" />
              </g>
              <g v-for="(item, index) in topHotspots" :key="item.key" class="tv-radar-node" :class="{selected: selected('hotspot', item.key)}" :style="{'--node-color': severityColor(item.severity), '--node-delay': (-index * .45) + 's'}" role="button" tabindex="0" :aria-label="hotspotLabel(item) + '，' + item.count + '次触发，筛选该来源'" :aria-pressed="selected('hotspot', item.key)" @click="selectHotspot(item)" @keydown.enter.prevent="selectHotspot(item)" @keydown.space.prevent="selectHotspot(item)">
                <title>{{ hotspotLabel(item) }} · {{ severityLabels[item.severity] }} · {{ item.count }} 次触发</title>
                <line x1="150" y1="136" :x2="point(index).x" :y2="point(index).y" aria-hidden="true" />
                <circle class="tv-node-target" :cx="point(index).x" :cy="point(index).y" r="22" />
                <circle class="tv-node-halo" :cx="point(index).x" :cy="point(index).y" :r="nodeRadius(item) + 5" />
                <circle class="tv-node-dot" :cx="point(index).x" :cy="point(index).y" :r="nodeRadius(item)" />
                <text :x="point(index).x" :y="point(index).y + 4" text-anchor="middle">{{ index + 1 }}</text>
              </g>
              <g class="tv-radar-center" aria-hidden="true"><circle cx="150" cy="136" r="38" /><text x="150" y="134" text-anchor="middle" class="tv-radar-total">{{ number(statistics.total) }}</text><text x="150" y="154" text-anchor="middle">次触发</text></g>
            </svg>
          </div>
          <ol class="tv-hotspot-list">
            <li v-for="(item, index) in topHotspots" :key="item.key">
              <button type="button" :class="{selected: selected('hotspot', item.key)}" :aria-pressed="selected('hotspot', item.key)" :title="hotspotLabel(item)" @click="selectHotspot(item)">
                <span class="tv-hotspot-rank mono" :style="{color: severityColor(item.severity)}">{{ index + 1 }}</span>
                <span class="tv-hotspot-copy"><strong class="ellipsis">{{ item.sourceLabel }}</strong><small class="ellipsis">{{ hotspotActor(item) }}<span v-if="item.sessions"> · {{ item.sessions }} 个会话</span></small></span>
                <span class="tv-hotspot-count" :style="{color: severityColor(item.severity), background: severityBackground(item.severity)}"><span class="mono">{{ number(item.count) }}</span> 次</span>
              </button>
            </li>
          </ol>
        </div>
        <div v-else-if="loaded" class="tv-empty tv-secondary-empty"><Aim aria-hidden="true" /><span>暂无风险来源</span></div>
        <el-skeleton v-else class="tv-loading" :rows="4" animated />
        <footer class="tv-footer"><span>涉及 {{ loaded ? number(statistics.hotspots.length) : '—' }} 个来源主体</span><span>TOP {{ topHotspots.length }} · 按触发次数</span></footer>
      </article>
    </div>
  </section>
</template>

<script setup>
import { computed, ref, watch, onMounted, onBeforeUnmount, nextTick } from 'vue';
import * as echarts from 'echarts';
import { TrendCharts, DataAnalysis, Aim } from '../../icons';
import { threatText, fmt, AGENT_NAMES, tab } from '../../store/runtime';
import { buildThreatStatistics, THREAT_PERIODS, THREAT_SEVERITIES } from '../../utils/threatStatistics';
import './visualizations.css';

const props = defineProps({ records: {type: Array, default: () => []}, updatedAt: String, loaded: Boolean, error: String, paused: Boolean, selection: Object });
const emit = defineEmits(['select']);
const period = ref('24h');
const pageVisible = ref(document.visibilityState !== 'hidden');
const radarActive = computed(() => !props.paused && !props.error && tab.value === 'threat' && pageVisible.value);
const updateVisibility = () => { pageVisible.value = document.visibilityState !== 'hidden'; };
// 扇形仅作视觉扫描；热点位置与大小仍由现有来源统计决定。
const sweepPoint = degrees => {
  const angle = degrees * Math.PI / 180;
  return [150 + Math.cos(angle) * 112, 136 + Math.sin(angle) * 112];
};
const sweepSlices = Array.from({length: 10}, (_, index) => {
  const start = sweepPoint(-160 + index * 7), end = sweepPoint(-153 + index * 7);
  return `M150 136L${start.join(' ')}A112 112 0 0 1 ${end.join(' ')}Z`;
});
const statistics = computed(() => buildThreatStatistics(props.records, period.value, props.updatedAt));
const severityLabels = {CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '信息', UNKNOWN: '未分级'};
const tone = {CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info', UNKNOWN: 'neutral'};
const severityColor = key => `var(--${tone[key] || 'neutral'})`;
const severityBackground = key => `var(--${tone[key] || 'neutral'}-bg)`;
const categoryColors = ['var(--chart-crit)', 'var(--chart-high)', 'var(--chart-med)', 'var(--chart-info)', 'var(--observe)', 'var(--chart-low)', 'var(--chart-edge)'];
const number = value => Number(value).toLocaleString('zh-CN');
const categoryLabel = item => item.key === '__other__' ? '其他类型' : item.key === '__unknown__' ? '未提供原因' : threatText(item.key);
const hotspotActor = item => [AGENT_NAMES[item.agent] || item.agent, item.actor].filter(Boolean).join(' · ') || '未提供主体';
const hotspotLabel = item => item.sourceLabel + ' · ' + hotspotActor(item);
const topHotspots = computed(() => statistics.value.hotspots.slice(0, 5));
const selected = (kind, key) => props.selection?.kind === kind && props.selection?.key === key;
function selectCategory(item) { emit('select', selected('category', item.key) ? null : {kind: 'category', key: item.key, codes: item.codes, label: categoryLabel(item), period: period.value}); }
function selectHotspot(item) { emit('select', selected('hotspot', item.key) ? null : {kind: 'hotspot', key: item.key, label: hotspotLabel(item), period: period.value}); }
function changePeriod(key) { if (period.value !== key) { period.value = key; emit('select', null); } }
function point(index) {
  const angle = (-70 + index * 360 / Math.max(3, topHotspots.value.length)) * Math.PI / 180;
  return {x: 150 + Math.cos(angle) * 95, y: 136 + Math.sin(angle) * 95};
}
const nodeRadius = item => 8 + Math.sqrt(item.count / (topHotspots.value[0]?.count || 1)) * 8;
const series = computed(() => THREAT_SEVERITIES.filter(key => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(key) || statistics.value.severities[key]).map(key => ({key, label: severityLabels[key]})));
const fullTime = time => fmt(new Date(time).toISOString()).slice(5, 16);
const trendElement = ref(null);
const trendPanel = ref(null);
const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
let chart, observer, frame, signature = '', alive = true;
const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
function render() {
  if (!alive || !trendElement.value?.clientWidth || !statistics.value.total) return;
  const motion = !preference.matches;
  const nextSignature = JSON.stringify([motion, period.value, statistics.value.buckets]);
  const entering = !chart;
  if (!chart) chart = echarts.init(trendElement.value);
  chart.resize();
  if (signature === nextSignature) return;
  signature = nextSignature;
  const text = {color: css('--muted'), fontSize: 12};
  const labels = statistics.value.buckets.map(bucket => {
    const date = new Date(bucket.start);
    return period.value === '24h' ? `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}` : `${date.getMonth() + 1}/${date.getDate()}`;
  });
  chart.setOption({
    animation: motion, animationDuration: entering ? 600 : 240, animationDurationUpdate: 240, animationEasing: 'cubicOut',
    textStyle: {fontFamily: getComputedStyle(document.body).fontFamily},
    grid: {left: 16, right: 22, top: 12, bottom: 44, containLabel: true},
    tooltip: {trigger: 'axis', confine: true, renderMode: 'richText', backgroundColor: css('--panel'), borderColor: css('--line'), textStyle: {color: css('--text')}, axisPointer: {type: 'line', lineStyle: {color: css('--brand-line'), type: 'dashed'}}},
    legend: {bottom: 0, itemWidth: 10, itemHeight: 10, itemGap: 20, icon: 'circle', textStyle: text},
    xAxis: {type: 'category', boundaryGap: false, data: labels, axisLine: {lineStyle: {color: css('--line')}}, axisTick: {show: false}, axisLabel: {...text, hideOverlap: true}},
    yAxis: {type: 'value', minInterval: 1, axisLabel: text, splitLine: {lineStyle: {color: css('--line'), type: 'dashed'}}},
    series: series.value.map(item => ({name: item.label, type: 'line', stack: 'risks', smooth: false, showSymbol: false, symbol: 'circle', symbolSize: 7,
      lineStyle: {width: 1.8}, itemStyle: {color: css('--chart-' + (tone[item.key] === 'neutral' ? 'edge' : tone[item.key]))}, areaStyle: {opacity: .2},
      emphasis: {focus: 'series'}, data: statistics.value.buckets.map(bucket => bucket[item.key]),
    })),
  }, true);
}
function schedule() { if (!alive) return; cancelAnimationFrame(frame); frame = requestAnimationFrame(render); }
watch([statistics, trendElement], async () => {
  if (!statistics.value.total || !trendElement.value) { chart?.dispose(); chart = undefined; signature = ''; }
  await nextTick(); schedule();
}, {flush: 'post'});
onMounted(() => {
  observer = new ResizeObserver(schedule);
  // 父容器同时覆盖侧栏收起、缩放、空态切换与 v-show 页面再显示。
  observer.observe(trendPanel.value);
  document.addEventListener('visibilitychange', updateVisibility);
  preference.addEventListener('change', schedule); schedule();
});
onBeforeUnmount(() => { alive = false; document.removeEventListener('visibilitychange', updateVisibility); preference.removeEventListener('change', schedule); observer?.disconnect(); cancelAnimationFrame(frame); chart?.dispose(); });
</script>
