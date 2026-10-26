<template>
  <section class="sa-panel sa-group-detail" :aria-busy="loading" aria-label="设备 Agent 资产详情">
    <div class="sa-group-heading">
      <el-button plain @click="$emit('back')">返回资产清单</el-button>
      <h3>{{ inventoryGroupName(current, AGENT_NAMES) }}</h3>
      <el-tag v-if="!missing && current.partial_sources" type="warning" effect="plain" size="small">部分完成</el-tag>
      <time class="mono muted">{{ fmt(current.last_scanned_at) }}</time>
    </div>
    <div v-if="!missing" class="sa-group-metrics">
      <div v-for="item in metrics" :key="item.label"><span>{{ item.label }}</span><strong>{{ item.value.toLocaleString() }}</strong></div>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon class="sa-error"><el-button link type="primary" @click="load">重试</el-button></el-alert>
    <el-alert v-if="missing" title="该分组已不在最近扫描结果中，请返回资产清单刷新" type="warning" :closable="false" class="sa-error" />
    <div class="sa-panel-head"><h4>组内资产</h4><span>{{ data?.total || 0 }} / {{ missing ? 0 : current.assets }} 个</span></div>
    <div class="sa-filters">
      <el-input v-model="query" aria-label="搜索组内资产" placeholder="名称 / ID / 路径 / 版本" clearable><template #prefix><el-icon><Search /></el-icon></template></el-input>
      <el-select v-model="source" aria-label="筛选组内扫描来源" placeholder="全部项目 / 来源" clearable>
        <el-option v-for="item in current.sources" :key="item.scan_id" :value="item.scan_id" :label="item.project_id + ' · ' + item.source_id" />
      </el-select>
      <el-select v-model="kind" aria-label="筛选组内资产类型" placeholder="全部类型" clearable><el-option v-for="item in current.kinds" :key="item.kind" :value="item.kind" :label="kindName(item.kind) + ' · ' + item.count" /></el-select>
      <el-radio-group v-model="risk" class="sa-risk-switch" size="small" aria-label="筛选组内风险状态"><el-radio-button value="">全部</el-radio-button><el-radio-button value="risk">有风险</el-radio-button><el-radio-button value="clear">未检出</el-radio-button><el-radio-button value="unknown">覆盖不足</el-radio-button></el-radio-group>
      <el-button text @click="reset">重置</el-button>
    </div>
    <el-table v-loading="loading" :data="data?.items || []" stripe size="small" class="sa-table sa-group-assets" max-height="580" :row-key="row => row.scan_id + '/' + row.asset_id" @row-click="$emit('select-asset',$event)" :empty-text="loading ? '加载中…' : '暂无符合条件的组内资产'">
      <el-table-column label="资产" min-width="240"><template #default="{row}"><button type="button" class="sa-asset-name" :aria-label="'查看资产 ' + row.name" @click.stop="$emit('select-asset',row)">{{ row.name || row.asset_id }}</button><span class="sa-asset-meta mono" :title="row.asset_id">{{ row.asset_id }}<template v-if="row.version"> · {{ row.version }}</template></span></template></el-table-column>
      <el-table-column label="类型" width="132"><template #default="{row}"><span class="sa-kind"><i :style="{background: kindColor(row.kind)}" />{{ kindName(row.kind) }}</span></template></el-table-column>
      <el-table-column label="风险" width="100"><template #default="{row}"><span v-if="row.risk.count" class="sev-tag" :class="'sev-' + row.risk.top">{{ severityName(row.risk.top) }}</span><span v-else class="sa-risk-state" :class="row.risk_state">{{ assetRiskName(row) }}</span></template></el-table-column>
      <el-table-column label="风险条目" width="84" align="right"><template #default="{row}"><button v-if="row.risk.count" type="button" class="sa-count" :style="{color: assetRiskColor(row.risk.top)}" :aria-label="'查看 ' + row.name + ' 的风险详情'" @click.stop="openStaticAssetContext(row)">{{ row.risk.count }}</button><span v-else class="muted mono">0</span></template></el-table-column>
      <el-table-column label="项目 / 来源" min-width="180"><template #default="{row}"><span class="sa-source" :title="row.source_id">{{ row.project_id }} · {{ row.source_id }}</span><span class="sa-asset-meta" :class="{'c-high': row.scan_status === 'PARTIAL'}">{{ scanStatusName(row.scan_status) }}</span></template></el-table-column>
      <el-table-column label="最近扫描" width="114"><template #default="{row}"><time class="mono sa-time" :title="fmt(row.last_scanned_at || row.scan_created_at)">{{ fmt(row.last_scanned_at || row.scan_created_at).slice(5,16) }}</time></template></el-table-column>
      <el-table-column label="详情" width="56" fixed="right" align="center"><template #default="{row}"><el-button link type="primary" :aria-label="'打开资产详情 ' + row.name" @click.stop="$emit('select-asset',row)"><el-icon><ArrowRight /></el-icon></el-button></template></el-table-column>
    </el-table>
    <div class="sa-pagination"><el-pagination v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[10,20,50]" :total="data?.total || 0" layout="total, sizes, prev, pager, next" size="small" /></div>
  </section>
</template>

<script setup>
import {computed, ref, watch, onBeforeUnmount} from "vue";
import {AGENT_NAMES} from "../../store/runtime";
import {staticJson, openStaticAssetContext} from "../../store/static";
import {inventoryGroupName, assetRiskName, assetRiskColor} from "../../utils/staticInventory";
import {kindName, kindColor, severityName, scanStatusName} from "../../utils/staticText";
import {fmt} from "../../utils/format";
const props = defineProps({group: {type: Object, required: true}, snapshot: Object});
defineEmits(["back", "select-asset"]);
const data = ref(null), loading = ref(false), error = ref(""), missing = ref(false);
const query = ref(""), source = ref(""), kind = ref(""), risk = ref(""), page = ref(1), pageSize = ref(20);
const current = computed(() => data.value?.group || props.group);
const metrics = computed(() => [
  {label: "已扫描资产", value: current.value.assets}, {label: "风险资产", value: current.value.risky_assets},
  {label: "风险条目", value: current.value.findings}, {label: "扫描来源", value: current.value.sources.length},
]);
let sequence = 0, timer;
async function load() {
  const request = ++sequence;
  loading.value = true; error.value = "";
  const params = new URLSearchParams({group_id: props.group.group_id, limit: String(pageSize.value), offset: String((page.value - 1) * pageSize.value)});
  for (const [key, value] of Object.entries({scan_id: source.value, kind: kind.value, q: query.value.trim(), risk: risk.value})) if (value) params.set(key,value);
  try {
    const result = await staticJson("/v1/static/inventory?" + params);
    if (request !== sequence) return;
    if (source.value && !result.group?.sources.some(item => item.scan_id === source.value)) { source.value = ""; return load(); }
    const last = Math.max(1,Math.ceil(result.total / pageSize.value));
    if (page.value > last) { page.value = last; return load(); }
    data.value = result; missing.value = !result.group;
  } catch (e) { if (request === sequence) error.value = "加载组内资产失败：" + e.message; }
  finally { if (request === sequence) loading.value = false; }
}
function reset() { query.value = ""; source.value = ""; kind.value = ""; risk.value = ""; page.value = 1; }
watch([query,source,kind,risk,pageSize], () => { page.value = 1; }, {flush: "sync"});
watch([query,source,kind,risk,page,pageSize], () => { ++sequence; clearTimeout(timer); timer = setTimeout(load,220); });
watch(() => props.snapshot, () => { ++sequence; clearTimeout(timer); load(); });
watch(() => props.group.group_id, () => { reset(); clearTimeout(timer); load(); }, {immediate: true});
onBeforeUnmount(() => { ++sequence; clearTimeout(timer); });
</script>
