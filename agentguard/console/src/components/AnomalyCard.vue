<template>
  <div class="an-card" :class="{ 'an-card-alert': hasScore && a.anomalous === true }">
    <header class="an-head">
      <span class="an-status" :class="{ 'an-status-alert': hasScore && a.anomalous === true }"><i aria-hidden="true"></i>{{ statusText }}</span>
      <div v-if="hasScore" class="an-flags">
        <span v-if="a.personalized" class="an-flag">设备个性化</span>
        <span v-if="a.unseen" class="an-flag an-flag-warning">未见行为</span>
        <span v-if="a.deviation" class="an-flag an-flag-warning">意图偏离</span>
        <span v-if="a.parser_complete === false" class="an-flag an-flag-warning">解析不完整</span>
      </div>
    </header>
    <template v-if="hasScore">
      <dl class="an-metrics">
        <div class="an-metric an-score"><dt>异常分</dt><dd :class="{ 'an-score-alert': a.anomalous === true }">{{ numberText(a.score) }}</dd></div>
        <div class="an-metric"><dt>异常阈值</dt><dd>{{ numberText(a.threshold) }}</dd></div>
        <div class="an-metric"><dt>转移概率</dt><dd>{{ percentText(a.probability) }}</dd></div>
        <div class="an-metric"><dt>动作占比</dt><dd>{{ percentText(a.marginal) }}</dd></div>
      </dl>
      <div v-if="hasThreshold || hasBreakdown" class="an-visuals" :class="{ 'an-visuals-single': !hasThreshold || !hasBreakdown }">
        <section v-if="hasThreshold" class="an-threshold-visual" aria-label="阈值偏离图">
          <div class="an-chart-heading"><h5>阈值偏离</h5><span class="an-delta">{{ deltaText }}</span></div>
          <div class="an-bullet" role="img" :aria-label="`当前异常分 ${numberText(a.score)}，异常阈值 ${numberText(a.threshold)}，${deltaText}`">
            <div class="an-bullet-track">
              <span class="an-bullet-zone" :style="{ width: thresholdPosition + '%' }"></span>
              <span class="an-bullet-value" :style="{ width: scorePosition + '%' }"></span>
              <span class="an-bullet-marker" :style="{ left: thresholdPosition + '%' }"></span>
              <span class="an-bullet-dot" :style="{ left: scorePosition + '%' }"></span>
            </div>
            <div class="an-chart-scale"><span>0</span><span>{{ numberText(scoreScale) }} 分</span></div>
          </div>
          <div class="an-chart-legend"><span><i class="an-legend-current" aria-hidden="true"></i>当前 {{ numberText(a.score) }}</span><span><i class="an-legend-threshold" aria-hidden="true"></i>阈值 {{ numberText(a.threshold) }}</span></div>
        </section>
        <section v-if="hasBreakdown" class="an-dimensions" aria-label="评分维度雷达图">
          <div class="an-chart-heading"><h5>评分维度</h5><span class="an-dimension-scale">0–{{ numberText(dimensionScale) }} 分</span></div>
          <svg class="an-radar" viewBox="0 0 300 190" role="group" :aria-label="radarLabel">
            <polygon v-for="level in radarLevels" :key="level" class="an-radar-grid" :points="radarPolygon(level)" />
            <line v-for="(dimension, index) in dimensions" :key="dimension.key" class="an-radar-axis"
                  x1="150" y1="106" :x2="radarPoint(index, 1).x" :y2="radarPoint(index, 1).y" />
            <text class="an-radar-tick" x="156" y="111">0</text>
            <text v-for="level in radarLevels" :key="'tick-' + level" class="an-radar-tick"
                  x="156" :y="106 - 82 * level + 4">{{ numberText(dimensionScale * level) }}</text>
            <polygon v-if="completeDimensions" class="an-radar-area" :points="radarValuePolygon" />
            <g v-for="(point, index) in radarPoints" :key="point.key">
              <circle v-if="point.valid" class="an-radar-point" :cx="point.x" :cy="point.y" r="3.5" tabindex="0" role="img"
                      :aria-label="point.label + ' ' + numberText(point.value) + ' 分'">
                <title>{{ point.label }}：{{ numberText(point.value) }} 分</title>
              </circle>
              <text class="an-radar-label" :x="radarLabels[index].x" :y="radarLabels[index].y" :text-anchor="radarLabels[index].anchor">{{ point.label }}</text>
            </g>
          </svg>
          <dl class="an-parts" aria-label="评分构成">
            <div v-for="dimension in dimensions" :key="dimension.key" :class="'an-dimension-' + dimension.key">
              <dt>{{ dimension.label }}</dt>
              <dd>{{ numberText(dimension.value) }}</dd>
            </div>
          </dl>
        </section>
      </div>
      <div class="an-flow" aria-label="行为转移">
        <div class="an-node"><span class="an-label">{{ a.order > 1 ? `最近行为（最多 ${a.order} 个符号）` : '上一行为' }}</span><strong :title="a.history?.join(' → ') || a.prev || undefined">{{ previousText }}</strong></div>
        <span class="an-arrow" aria-hidden="true">→</span>
        <div class="an-node an-node-current"><span class="an-label">当前行为</span><strong :title="a.symbol || undefined">{{ symbolText(a.symbol) }}</strong></div>
      </div>
    </template>
    <dl class="an-meta">
      <template v-if="!hasScore"><dt>状态原因</dt><dd>{{ reasonText }}</dd></template>
      <template v-if="hasScore"><dt>识别意图</dt><dd>{{ intents.join('、') || '未识别' }}</dd></template>
      <template v-if="a.baseline"><dt>基线模型</dt><dd class="mono">{{ a.baseline }}</dd></template>
    </dl>
  </div>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({ a: { type: Object, required: true } });
const isNumber = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;
const numberText = (value) => isNumber(value) ? String(value) : "—";
const percentText = (value) => isNumber(value) && value <= 1 ? `${(value * 100).toFixed(2)}%` : "—";
const hasScore = computed(() => !props.a.skipped_reason && !props.a.disabled_reason && isNumber(props.a.score));
const hasBreakdown = computed(() => isNumber(props.a.rarity) || isNumber(props.a.context));
const hasThreshold = computed(() => isNumber(props.a.threshold));
const scoreScale = computed(() => {
  const largest = Math.max(props.a.score, props.a.threshold);
  const padded = largest * 1.2;
  return Math.max(1, Math.ceil(Number.isFinite(padded) ? padded : largest));
});
const position = (value, scale) => isNumber(value) ? Math.min(100, value / scale * 100) : 0;
const scorePosition = computed(() => position(props.a.score, scoreScale.value));
const thresholdPosition = computed(() => position(props.a.threshold, scoreScale.value));
const deltaText = computed(() => {
  const delta = props.a.score - props.a.threshold;
  if (delta === 0) return "与阈值持平";
  const absolute = Math.abs(delta);
  const amount = absolute < 0.01 ? "<0.01" : Number(absolute.toFixed(2));
  return `${delta > 0 ? "高于" : "低于"}阈值 ${amount} 分`;
});
const dimensionValues = computed(() => [
  { key: "rarity", label: "罕见度", value: props.a.rarity },
  { key: "context", label: "前文修正", value: props.a.context },
  { key: "deviation", label: "意图偏离", value: typeof props.a.deviation === "boolean" ? (props.a.deviation ? 3 : 0) : undefined },
]);
const dimensionScale = computed(() => Math.max(1, ...dimensionValues.value.filter((item) => isNumber(item.value)).map((item) => Math.ceil(item.value))));
const dimensions = dimensionValues;
const radarLevels = [0.25, 0.5, 0.75, 1];
const radarLabels = [{ x: 150, y: 14, anchor: "middle" }, { x: 236, y: 170, anchor: "start" }, { x: 64, y: 170, anchor: "end" }];
const radarPoint = (index, ratio) => ({ x: 150 + Math.sin(index * Math.PI * 2 / 3) * 82 * ratio,
  y: 106 - Math.cos(index * Math.PI * 2 / 3) * 82 * ratio });
const pointsText = (points) => points.map((point) => `${point.x.toFixed(2)},${point.y.toFixed(2)}`).join(" ");
const radarPolygon = (ratio) => pointsText(dimensions.value.map((_, index) => radarPoint(index, ratio)));
const radarPoints = computed(() => dimensions.value.map((dimension, index) => ({ ...dimension, valid: isNumber(dimension.value),
  ...radarPoint(index, position(dimension.value, dimensionScale.value) / 100) })));
const completeDimensions = computed(() => radarPoints.value.every((point) => point.valid));
const radarValuePolygon = computed(() => pointsText(radarPoints.value));
const radarLabel = computed(() => "评分维度雷达图，" + dimensions.value.map((dimension) =>
  `${dimension.label} ${numberText(dimension.value)} 分`).join("，"));
const statusText = computed(() => props.a.disabled_reason ? "基线不可用" : !hasScore.value ? "未评分"
  : props.a.anomalous === true ? "达到异常阈值" : props.a.anomalous === false ? "未达异常阈值" : "已评分");
const REASON_TEXT = { hard_deny: "已命中拒绝规则", incompatible_baseline: "基线版本不兼容", baseline_unavailable: "基线模型不可用" };
const reasonText = computed(() => {
  const reason = props.a.skipped_reason || props.a.disabled_reason;
  return REASON_TEXT[reason] || reason || "未附带评分数据";
});

const CAP_TEXT = {
  EXEC: "执行", FILE_READ: "读取", FILE_WRITE: "写入", NET_FETCH: "访问", NET_SEARCH: "网页搜索",
  AGENT_SPAWN: "启动子 Agent", META: "任务管理", MCP_CALL: "MCP 调用",
};
const CLASS_TEXT = {
  workspace: "工作区", project_secret: "项目密钥", credential_store: "主机凭证", persistence: "持久化位置",
  agent_config: "Agent 配置", tmp: "临时目录", home: "家目录", system: "系统路径", other: "其他路径",
  local: "本机/内网", package: "包仓库", code_host: "代码托管", docs: "文档站", external: "外部主机",
  vcs: "版本控制", pkg: "包管理", test: "测试", build: "构建", lint: "检查格式化", container: "容器",
  net: "网络工具", interp: "解释器", fs: "文件命令", shell: "Shell 内建", local_bin: "本地脚本",
  pipe_exec: "下载即执行", unknown: "未分类",
};
const EFFECT_TEXT = { read: "只读", local_write: "本地写入", remote_write: "远程写入", upload: "上传", fetch: "下载", download_then_exec: "下载后执行" };
const INTENT_TEXT = {
  test: "测试", build: "构建", debug: "调试", docs: "文档", refactor: "重构", deps: "依赖", ops: "运维",
  intel: "情报", transfer: "传输", code: "编码", vcs: "版本控制",
};
const intents = computed(() => (Array.isArray(props.a.intents) ? props.a.intents : [])
  .filter((intent) => typeof intent === "string").map((intent) => INTENT_TEXT[intent] || intent));
const symbolText = (s) => {
  if (s === "<start>") return "会话开始";
  if (typeof s !== "string" || !s) return "未记录";
  const [cap, cls, ...effects] = s.split(":");
  const clsText = cap === "EXEC" && cls === "other" ? "其他命令" : CLASS_TEXT[cls] || cls;
  return [CAP_TEXT[cap] || cap, cls ? clsText : "", ...effects.map((effect) => EFFECT_TEXT[effect] || effect)].filter(Boolean).join(" · ");
};
const previousText = computed(() => Array.isArray(props.a.history)
  ? props.a.history.map(symbolText).join(' → ') || '上下文未知'
  : props.a.prev === null ? "上下文未知" : symbolText(props.a.prev));
</script>

<style scoped>
.an-card { --an-accent:var(--info); container-type:inline-size; min-width:0; border:1px solid var(--line); border-radius:10px; background:var(--panel); overflow:hidden; }
.an-card-alert { --an-accent:var(--crit); }
.an-head { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px 12px; padding:12px 16px; border-bottom:1px solid var(--line-2); background:var(--surface-soft); }
.an-status { display:inline-flex; align-items:center; gap:7px; color:var(--an-accent); font-size:12px; font-weight:500; }
.an-status i { width:6px; height:6px; border-radius:50%; background:currentColor; }
.an-status-alert, .an-score-alert { color:var(--crit)!important; }
.an-flags { display:flex; align-items:center; flex-wrap:wrap; gap:6px; }
.an-flag { padding:2px 6px; border:1px solid var(--line); border-radius:5px; color:var(--muted); background:var(--panel); font-size:12px; line-height:18px; }
.an-flag-warning { color:var(--med); border-color:var(--med-line); background:var(--med-bg); }
.an-metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); margin:0; padding:16px; }
.an-metric { min-width:0; padding:0 12px; }
.an-metric:first-child { padding-left:0; }
.an-metric + .an-metric { border-left:1px solid var(--line-2); }
.an-card dt, .an-label { color:var(--muted); font-size:12px; line-height:20px; }
.an-card dd { margin:0; min-width:0; overflow-wrap:anywhere; }
.an-metric dd { margin-top:4px; color:var(--title); font-size:20px; font-weight:600; line-height:32px; font-variant-numeric:tabular-nums; }
.an-score dd { color:var(--an-accent); font-size:26px; }
.an-visuals { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:16px; margin:0 16px 16px; padding:14px 0; border-top:1px solid var(--line-2); border-bottom:1px solid var(--line-2); }
.an-visuals-single { grid-template-columns:minmax(0,1fr); }
.an-threshold-visual, .an-dimensions { min-width:0; }
.an-threshold-visual { display:flex; flex-direction:column; justify-content:center; }
.an-dimensions { padding-left:16px; border-left:1px solid var(--line-2); }
.an-visuals-single .an-dimensions { padding-left:0; border-left:0; }
.an-chart-heading { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:4px 8px; margin-bottom:14px; }
.an-chart-heading h5 { margin:0; color:var(--title); font-size:12px; font-weight:500; }
.an-delta { color:var(--an-accent); font-size:12px; font-variant-numeric:tabular-nums; }
.an-dimension-scale { color:var(--muted); font-size:12px; }
.an-bullet { padding-top:8px; }
.an-bullet-track { position:relative; height:12px; background:var(--surface-code); border-radius:4px; }
.an-bullet-zone, .an-bullet-value { position:absolute; top:0; bottom:0; left:0; border-radius:4px; }
.an-bullet-zone { background:var(--line-2); }
.an-bullet-value { background:var(--an-accent); opacity:.85; }
.an-bullet-marker { position:absolute; top:-6px; bottom:-6px; width:0; border-left:2px dashed var(--muted); transform:translateX(-1px); }
.an-bullet-dot { position:absolute; top:50%; width:10px; height:10px; border:2px solid var(--panel); border-radius:50%; background:var(--an-accent); box-shadow:0 0 0 1px var(--an-accent); transform:translate(-50%,-50%); }
.an-chart-scale { display:flex; justify-content:space-between; margin-top:10px; color:var(--muted); font-size:12px; font-variant-numeric:tabular-nums; }
.an-chart-legend { display:flex; align-items:center; flex-wrap:wrap; gap:8px 14px; margin-top:14px; font-size:12px; color:var(--muted); }
.an-chart-legend > span { display:inline-flex; align-items:center; gap:6px; }
.an-legend-current { width:7px; height:7px; border-radius:50%; background:var(--an-accent); }
.an-legend-threshold { width:10px; border-top:2px dashed var(--muted); }
.an-flow { display:grid; grid-template-columns:minmax(0,1fr) 20px minmax(0,1fr); align-items:center; gap:12px; margin:0 16px 16px; padding:12px; border:1px solid var(--line-2); border-radius:7px; background:var(--surface-soft); }
.an-node { display:flex; flex-direction:column; gap:4px; min-width:0; }
.an-node strong { color:var(--text); font-size:13px; font-weight:500; line-height:1.65; overflow-wrap:anywhere; }
.an-node-current { padding-left:10px; border-left:2px solid var(--line); }
.an-node-current strong { color:var(--an-accent); }
.an-arrow { color:var(--faint); text-align:center; font-size:20px; }
.an-radar { display:block; width:100%; max-width:330px; height:auto; margin:0 auto 8px; overflow:visible; }
.an-radar-grid { fill:none; stroke:var(--line); stroke-width:1; }
.an-radar-axis { stroke:var(--line); stroke-width:1; }
.an-radar-tick { fill:var(--muted); font-size:10px; }
.an-radar-label { fill:var(--muted); font-size:14px; }
.an-radar-area { fill:var(--an-accent); fill-opacity:.18; stroke:var(--an-accent); stroke-width:2; stroke-linejoin:round; }
.an-radar-point { fill:var(--panel); stroke:var(--an-accent); stroke-width:1.5; }
.an-radar-point:focus-visible { outline:none; stroke-width:4; }
.an-parts { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; margin:0; text-align:center; }
.an-parts > div { min-width:0; }
.an-parts dd { margin-top:3px; color:var(--text); font-size:13px; font-variant-numeric:tabular-nums; }
.an-meta { display:grid; grid-template-columns:max-content minmax(0,1fr); gap:6px 14px; margin:0; padding:12px 16px; border-top:1px solid var(--line-2); font-size:12px; line-height:20px; }
@container (max-width:540px) {
  .an-metrics { grid-template-columns:repeat(2,minmax(0,1fr)); row-gap:12px; }
  .an-metric:nth-child(3) { border-left:0; padding-left:0; }
  .an-visuals { grid-template-columns:minmax(0,1fr); }
  .an-dimensions { padding:14px 0 0; border-left:0; border-top:1px solid var(--line-2); }
  .an-visuals-single .an-dimensions { padding-top:0; border-top:0; }
}
@container (max-width:360px) {
  .an-flow { grid-template-columns:minmax(0,1fr); gap:6px; }
  .an-arrow { transform:rotate(90deg); justify-self:start; }
}
</style>
