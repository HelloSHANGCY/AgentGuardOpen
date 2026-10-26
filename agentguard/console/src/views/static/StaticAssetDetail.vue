<template>
  <el-dialog :model-value="modelValue" @update:model-value="$emit('update:modelValue',$event)" class="sa-detail-dialog" width="900px" :close-on-click-modal="false" align-center destroy-on-close>
    <template #header><div class="sa-detail-title"><span class="sa-detail-icon"><el-icon aria-hidden="true"><Files /></el-icon></span><div><h3>{{ asset?.name || '资产详情' }}</h3><span>{{ asset ? kindName(asset.kind) : '' }}<template v-if="asset?.version"> · {{ asset.version }}</template></span></div></div></template>
    <template v-if="asset">
      <div class="sa-detail-grid">
        <section class="sa-portrait" aria-label="资产风险分布">
          <h4>风险分布 <span>{{ asset.risk.rules }} 条规则命中</span></h4>
          <div class="sa-donut sa-risk-donut" :style="{background: riskGradient}" role="img" :aria-label="'该资产命中 ' + asset.risk.count + ' 条风险'"><div><strong>{{ asset.risk.count }}</strong><span>风险条目</span></div></div>
          <div class="sa-severity-list"><div v-for="severity in SEVERITIES" :key="severity"><i :style="{background: assetRiskColor(severity)}" /><span>{{ severityName(severity) }}</span><b>{{ asset.risk.severity[severity] || 0 }}</b></div></div>
          <div class="sa-detail-state"><span v-if="asset.risk.count" class="sev-tag" :class="'sev-' + asset.risk.top">最高等级 · {{ severityName(asset.risk.top) }}</span><span v-else class="sa-risk-state" :class="asset.risk_state">{{ assetRiskName(asset) }}</span></div>
        </section>
        <section class="sa-detail-info" aria-label="资产信息">
          <dl class="sa-fields">
            <div><dt>资产 ID</dt><dd><CopyText :text="asset.asset_id" /></dd></div>
            <div><dt>类型</dt><dd>{{ kindName(asset.kind) }}</dd></div><div><dt>版本</dt><dd class="mono">{{ asset.version || '—' }}</dd></div>
            <div><dt>项目</dt><dd>{{ asset.project_id }}</dd></div><div><dt>发现方式</dt><dd>{{ discoveryName(asset.discovery_method) }}</dd></div>
            <div><dt>识别置信度</dt><dd>{{ confidenceName(asset.confidence) }}</dd></div><div><dt>扫描状态</dt><dd><el-tag size="small" effect="plain" :type="asset.scan_status === 'PARTIAL' ? 'warning' : 'success'">{{ scanStatusName(asset.scan_status) }}</el-tag></dd></div>
            <div><dt>扫描来源</dt><dd>{{ sourceName(asset, AGENT_NAMES) }}</dd></div>
            <div><dt>最近扫描</dt><dd class="mono">{{ fmt(asset.last_scanned_at || asset.scan_created_at) || '—' }}</dd></div>
            <div><dt>扫描 ID</dt><dd><CopyText :text="asset.scan_id" /></dd></div>
            <div v-if="asset.relative_path" class="sa-field-wide"><dt>来源文件</dt><dd class="mono">{{ asset.relative_path }}</dd></div>
          </dl>
          <el-alert v-if="asset.scan_status === 'PARTIAL'" title="扫描部分完成，存在覆盖缺口" type="warning" show-icon :closable="false" />
        </section>
      </div>
      <section class="sa-detail-findings" aria-label="关联风险">
        <div class="sa-panel-head"><h4>关联风险</h4><span>{{ findings.length }} / {{ findingsTotal }} 条</span></div>
        <el-alert v-if="error" :title="error" type="error" :closable="false"><el-button link type="primary" @click="loadFindings">重试</el-button></el-alert>
        <div v-else-if="loading" class="sa-empty">加载中…</div>
        <div v-else-if="!findings.length" class="sa-empty">{{ asset.risk_state === 'unknown' ? '已分析范围未检出风险，扫描覆盖不足' : '当前扫描结果未检出风险条目' }}</div>
        <div v-else class="sa-detail-finding-list"><div v-for="finding in findings" :key="finding.finding_id"><span class="sev-tag" :class="'sev-' + finding.severity">{{ severityName(finding.severity) }}</span><span>{{ finding.title || ruleTitle(finding.rule_id) }}</span><code>{{ finding.rule_id }}</code></div></div>
      </section>
      <details v-if="asset.content_digest || Object.keys(asset.metadata || {}).length" class="sa-metadata"><summary>资产元数据</summary><dl v-if="asset.content_digest"><dt>内容指纹</dt><dd class="mono">{{ asset.content_digest }}</dd></dl><pre v-if="Object.keys(asset.metadata || {}).length">{{ JSON.stringify(asset.metadata,null,2) }}</pre></details>
    </template>
    <template #footer><div class="sa-detail-actions"><el-button @click="$emit('update:modelValue',false)">关闭</el-button><el-button v-if="asset" plain @click="navigate('graph')"><el-icon aria-hidden="true"><Share /></el-icon>关联图谱</el-button><el-button v-if="asset" type="primary" @click="navigate('findings')">查看风险详情<el-icon aria-hidden="true"><ArrowRight /></el-icon></el-button></div></template>
  </el-dialog>
</template>

<script setup>
import {computed, ref, watch} from "vue";
import CopyText from "../../components/CopyText.vue";
import {AGENT_NAMES} from "../../store/runtime";
import {staticJson, openStaticAssetContext} from "../../store/static";
import {SEVERITIES, severityName, kindName, discoveryName, confidenceName, scanStatusName, ruleTitle} from "../../utils/staticText";
import {sourceName, assetRiskName, assetRiskColor} from "../../utils/staticInventory";
import {fmt} from "../../utils/format";
const props = defineProps({modelValue: Boolean, asset: Object});
const emit = defineEmits(["update:modelValue"]);
const findings = ref([]), findingsTotal = ref(0), loading = ref(false), error = ref("");
let sequence = 0;
const riskGradient = computed(() => {
  if (!props.asset?.risk.count) return "var(--line-2)";
  let position = 0;
  const parts = SEVERITIES.filter(s => props.asset.risk.severity[s]).map(s => {
    const start = position; position += props.asset.risk.severity[s] / props.asset.risk.count * 100;
    return `${assetRiskColor(s)} ${start}% ${position}%`;
  });
  if (position < 100) parts.push(`var(--muted) ${position}% 100%`);
  return "conic-gradient(" + parts.join(",") + ")";
});
async function loadFindings() {
  const current = ++sequence, asset = props.asset;
  findings.value = []; findingsTotal.value = asset?.risk.count || 0; error.value = "";
  if (!props.modelValue || !asset) return;
  loading.value = true;
  try {
    const query = new URLSearchParams({asset_id: asset.asset_id, limit: "5"});
    const data = await staticJson(`/v1/static/scans/${encodeURIComponent(asset.scan_id)}/findings?${query}`);
    if (current !== sequence) return;
    findings.value = data.items || []; findingsTotal.value = data.total;
  } catch (e) { if (current === sequence) error.value = "加载关联风险失败：" + e.message; }
  finally { if (current === sequence) loading.value = false; }
}
watch(() => [props.modelValue, props.asset?.scan_id, props.asset?.asset_id], loadFindings);
function navigate(view) { emit("update:modelValue",false); openStaticAssetContext(props.asset,view); }
</script>
