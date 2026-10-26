<template>
  <div>
    <div class="graph-toolbar">
      <template v-if="staticGraphCenter">
        <el-button size="small" plain @click="staticGraphCenter = ''">返回全图</el-button>
        <span class="muted fs-12">以 <b>{{ centerAsset ? centerAsset.name : staticGraphCenter }}</b> 为中心</span>
        <el-radio-group v-model="depth" size="small">
          <el-radio-button :value="1">直接关联</el-radio-button>
          <el-radio-button :value="2">2 跳内</el-radio-button>
        </el-radio-group>
      </template>
      <div class="grow"></div>
      <span class="muted fs-11" v-if="hiddenCount">已隐藏 {{ hiddenCount }} 个无关联节点</span>
      <el-checkbox v-if="!staticGraphCenter" v-model="hideIsolated" size="small">隐藏无关联节点</el-checkbox>
    </div>
    <div class="graph-wrap">
      <div ref="chartEl" class="graph-box"></div>
      <aside class="graph-side" v-if="selected">
        <div class="graph-side-head">
          <span class="kind-dot" :style="{ background: kindColor(selected.kind) }"></span>
          <span class="muted fs-11">{{ kindName(selected.kind) }}</span>
          <div class="grow"></div>
          <button type="button" class="copy-btn" aria-label="关闭" @click="selected = null"><el-icon><Close /></el-icon></button>
        </div>
        <div class="graph-side-name">{{ selected.name }} <span v-if="selected.version" class="muted mono fs-11">{{ selected.version }}</span></div>
        <div class="mono muted fs-11 graph-side-path">{{ selected.relative_path }}</div>
        <div class="graph-side-sec">
          <template v-if="selectedFindings.length">
            <div class="fs-12 mb-6">风险 <b>{{ selectedFindings.length }}</b> 条</div>
            <div v-for="f in selectedFindings.slice(0, 5)" :key="f.finding_id" class="graph-side-finding">
              <span class="sev-tag" :class="'sev-' + f.severity">{{ f.severity }}</span>
              <span class="ellipsis" :title="f.title">{{ f.title || f.rule_id }}</span>
            </div>
          </template>
          <div v-else class="muted fs-12">未命中风险规则</div>
        </div>
        <div class="graph-side-actions">
          <el-button v-if="selected.asset_id !== staticGraphCenter" size="small" plain
                     @click="staticGraphCenter = selected.asset_id">以此为中心展开</el-button>
          <el-button v-if="selectedFindings.length" size="small" type="primary" plain
                     @click="showAssetFindings(selected.asset_id)">查看风险</el-button>
        </div>
      </aside>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onBeforeUnmount } from "vue";
import echarts from "../../utils/echarts";
import { themeColor as cssVar } from "../../utils/theme";
import {
  staticView, staticScanId, staticScan, staticError, staticJson, staticGraphCenter,
  staticAssetById, staticRiskByAsset, staticAllFindings, showAssetFindings,
} from "../../store/static";
import { kindName, kindColor, kindRank, relationName, severityName, sevRank } from "../../utils/staticText";

const chartEl = ref(null);
const hideIsolated = ref(true);
// 中心模式默认只看直接关联：app.py 这类枢纽节点会让 2 跳几乎覆盖全图。
const depth = ref(1);
const selected = ref(null);
const graph = ref({ nodes: [], edges: [] });
let chart = null;

const centerAsset = computed(() => staticAssetById.value.get(staticGraphCenter.value));
const selectedFindings = computed(() => !selected.value ? [] : staticAllFindings.value
  .filter((f) => f.asset_id === selected.value.asset_id)
  .sort((a, b) => sevRank(a.severity) - sevRank(b.severity)));

const sevColor = (s) => cssVar({ CRITICAL: "--crit", HIGH: "--high", MEDIUM: "--med", LOW: "--low", INFO: "--info" }[s] || "--neutral");

// 全图模式下，无任何连线的节点（多为 Dockerfile、独立依赖）默认隐藏，避免占满画布四周。
const linked = computed(() => {
  const ids = new Set();
  for (const e of graph.value.edges) { ids.add(e.source_asset_id); ids.add(e.target_asset_id); }
  return ids;
});
const visibleNodes = computed(() => (hideIsolated.value && !staticGraphCenter.value)
  ? graph.value.nodes.filter((n) => linked.value.has(n.asset_id) || staticRiskByAsset.value.has(n.asset_id))
  : graph.value.nodes);
const hiddenCount = computed(() => graph.value.nodes.length - visibleNodes.value.length);

async function load() {
  if (!staticScanId.value) return;
  try {
    const query = staticGraphCenter.value ? "&center=" + encodeURIComponent(staticGraphCenter.value) : "";
    const data = await staticJson(`/v1/static/scans/${encodeURIComponent(staticScanId.value)}/graph?depth=${depth.value}&limit=500${query}`);
    graph.value = { nodes: data.nodes || [], edges: data.edges || [] };
    draw();
  } catch (e) {
    // 图谱失败不阻断其他视图；错误进入静态页统一提示。
    staticError.value = "加载图谱失败：" + e.message;
  }
}

async function draw() {
  await nextTick();
  if (!chartEl.value) return;
  // 视图切换会销毁并重建 DOM：实例与当前节点不一致时必须重建，避免二次进入空白。
  if (chart && (chart.isDisposed() || chart.getDom() !== chartEl.value)) { chart.dispose(); chart = null; }
  chart = chart || echarts.init(chartEl.value);
  chart.resize();
  chartObserver?.disconnect();
  chartObserver = new ResizeObserver(() => onResize());
  chartObserver.observe(chartEl.value);
  const nodes = visibleNodes.value;
  const ids = new Set(nodes.map((n) => n.asset_id));
  const kinds = [...new Set(nodes.map((n) => n.kind))].sort((a, b) => kindRank(a) - kindRank(b));
  const categoryIndex = new Map(kinds.map((kind, index) => [kind, index]));
  const risks = staticRiskByAsset.value;
  chart.setOption({
    animation: !motionPreference.matches, animationDuration:700, animationDurationUpdate:350, animationEasing:'cubicOut',
    tooltip: {
      confine: true, backgroundColor: cssVar("--panel"), borderColor: cssVar("--line"),
      textStyle: { color: cssVar("--text"), fontSize: 12 },
      formatter: (p) => {
        if (p.dataType === "edge") return relationName(p.data.relation);
        const r = risks.get(p.data.id);
        return `${kindName(p.data.kind)}：${p.data.name}` + (r ? `<br/>风险 ${r.count} 条 · 最高 ${severityName(r.top)}` : "");
      },
    },
    legend: { data: kinds.map(kindName), type: "scroll", top: 4, left: "center", itemWidth: 12, itemHeight: 8,
              textStyle: { fontSize: 12, color: cssVar("--text") } },
    series: [{
      type: "graph", layout: "force", roam: true, draggable: true,
      force: { layoutAnimation:!motionPreference.matches, repulsion: 220, edgeLength: 90, gravity: 0.12 },
      label: { show: true, position: "right", fontSize: 12, color: cssVar("--text"), formatter: (p) => p.data.name },
      labelLayout: { hideOverlap: true },
      emphasis: { focus: "adjacency", label: { fontWeight: 700 } },
      edgeSymbol: ["none", "arrow"], edgeSymbolSize: 6,
      lineStyle: { color: cssVar("--chart-edge"), width: 1.2, curveness: 0.08 },
      categories: kinds.map((kind) => ({ name: kindName(kind), itemStyle: { color: kindColor(kind) } })),
      data: nodes.map((node) => {
        const r = risks.get(node.asset_id);
        const center = node.asset_id === staticGraphCenter.value;
        return {
          id: node.asset_id, name: node.name, kind: node.kind,
          category: categoryIndex.get(node.kind),
          symbolSize: (node.kind === "AgentApplication" || center ? 26 : 16) + (r ? 4 : 0),
          itemStyle: {
            color: kindColor(node.kind),
            ...(r ? { borderColor: sevColor(r.top), borderWidth: 3 } : {}),
            ...(center ? { shadowBlur: 10, shadowColor: cssVar("--chart-glow") } : {}),
          },
          label: r ? { color: sevColor(r.top), fontWeight: 600 } : undefined,
        };
      }),
      links: graph.value.edges
        .filter((e) => ids.has(e.source_asset_id) && ids.has(e.target_asset_id))
        .map((e) => ({ source: e.source_asset_id, target: e.target_asset_id, relation: e.relation })),
    }],
  }, true);
  chart.off("click");
  chart.on("click", (p) => {
    if (p.dataType === "node") selected.value = staticAssetById.value.get(p.data.id)
      || { asset_id: p.data.id, name: p.data.name, kind: p.data.kind };
  });
  chart.off("dblclick");
  chart.on("dblclick", (p) => { if (p.dataType === "node") staticGraphCenter.value = p.data.id; });
}

const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
let chartObserver;
const onResize = () => { if (chart && !chart.isDisposed()) chart.resize(); };

// 只在扫描完成状态变化时重新取图，避免扫描进行中的轮询反复重排布局。
watch([staticView, staticScanId, () => staticScan.value?.status, staticGraphCenter, depth], ([view]) => {
  if (view === "graph") load();
}, { flush: "post", immediate: true });
// 风险数据可能晚于图谱返回，到达后补上描边。
watch([hideIsolated, staticRiskByAsset], draw);
watch(staticScanId, () => { selected.value = null; });
// 侧栏出现/消失会改变画布宽度。
watch(selected, () => nextTick(onResize));

onMounted(() => {
  window.addEventListener("resize", onResize);
  motionPreference.addEventListener('change', draw);
});
onBeforeUnmount(() => {
  window.removeEventListener("resize", onResize);
  motionPreference.removeEventListener('change', draw);
  chartObserver?.disconnect();
  if (chart && !chart.isDisposed()) chart.dispose();
  chart = null;
});
</script>
