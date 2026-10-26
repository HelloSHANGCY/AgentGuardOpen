<template>
  <div class="sa-inventory" :aria-busy="inventoryLoading">
    <el-alert v-if="inventoryError" :title="inventoryError" type="error" :closable="false" show-icon class="sa-error">
      <el-button link type="primary" @click="loadInventory">重试</el-button>
    </el-alert>
    <div class="sa-snapshot">
      <span>最近扫描快照 <el-tag v-if="data.summary.partial_sources" effect="plain" type="warning" size="small">{{ data.summary.partial_sources }} 个来源部分完成</el-tag></span>
      <time v-if="data.updated_at">更新于 {{ fmt(data.updated_at) }}</time>
    </div>
    <div class="sa-summary">
      <div v-for="metric in metrics" :key="metric.label" class="sa-summary-card" :class="metric.tone">
        <div><span>{{ metric.label }}</span><strong>{{ inventory ? metric.value.toLocaleString() : '—' }}</strong></div>
        <el-icon aria-hidden="true"><component :is="metric.icon" /></el-icon>
      </div>
    </div>

    <StaticGroupDetail v-if="selectedGroup" :group="selectedGroup" :snapshot="inventory" @back="selectedGroup = null" @select-asset="selectAsset" />
    <div v-else class="sa-grid">
      <section class="sa-panel sa-list" aria-label="已扫描资产清单">
        <div class="sa-panel-head"><h3><el-icon aria-hidden="true"><Files /></el-icon>已扫描资产清单</h3><span>{{ data.total }} / {{ data.summary.groups }} 组</span></div>
        <div class="sa-filters">
          <el-input v-model="inventoryQuery" aria-label="搜索设备和 Agent" placeholder="设备 ID / Agent / 项目 / 目录" clearable>
            <template #prefix><el-icon><Search /></el-icon></template>
          </el-input>
          <el-select v-model="inventoryAgent" aria-label="筛选扫描 Agent" placeholder="全部 Agent" clearable>
            <el-option v-for="agent in agents" :key="agent" :value="agent" :label="AGENT_NAMES[agent] || agent" />
          </el-select>
          <el-select v-model="inventoryKind" aria-label="筛选资产类型" placeholder="全部类型" clearable>
            <el-option v-for="kind in data.kinds" :key="kind.kind" :value="kind.kind" :label="kindName(kind.kind) + ' · ' + kind.count" />
          </el-select>
          <el-radio-group v-model="inventoryRisk" class="sa-risk-switch" size="small" aria-label="筛选资产风险状态">
            <el-radio-button value="">全部</el-radio-button><el-radio-button value="risk">有风险</el-radio-button>
            <el-radio-button value="clear">未检出</el-radio-button><el-radio-button value="unknown">覆盖不足</el-radio-button>
          </el-radio-group>
          <el-button text @click="resetInventoryFilters">重置</el-button>
        </div>
        <el-table v-loading="inventoryLoading" :data="data.items" stripe class="sa-table sa-group-table" size="small" max-height="620"
                  row-key="group_id" @row-click="selectGroup"
                  :empty-text="inventoryLoading ? '加载中…' : inventory ? '暂无符合条件的扫描分组' : '资产数据尚未加载'">
          <el-table-column label="接入设备 / 扫描目录" min-width="180">
            <template #default="{row}"><button class="sa-asset-name" type="button" :aria-label="'查看分组 ' + inventoryGroupName(row, AGENT_NAMES)" @click.stop="selectGroup(row)">{{ row.device_id || row.sources[0]?.source_id || '授权目录' }}</button><span class="sa-asset-meta" :title="row.projects.join(' / ')">{{ row.projects.join(' / ') }}</span></template>
          </el-table-column>
          <el-table-column label="Agent" width="100"><template #default="{row}"><span class="sa-group-agent">{{ row.device_id ? AGENT_NAMES[row.agent] || row.agent || '未知 Agent' : '目录扫描' }}</span></template></el-table-column>
          <el-table-column label="资产数" width="65" align="right"><template #default="{row}"><span class="mono">{{ row.assets.toLocaleString() }}</span></template></el-table-column>
          <el-table-column label="风险资产" width="75" align="right"><template #default="{row}"><span class="mono" :style="{color: row.risky_assets ? assetRiskColor(row.risk.top) : undefined}">{{ row.risky_assets }}</span></template></el-table-column>
          <el-table-column label="风险条目" width="75" align="right"><template #default="{row}"><span class="mono" :style="{color: row.findings ? assetRiskColor(row.risk.top) : undefined}">{{ row.findings }}</span></template></el-table-column>
          <el-table-column label="风险 / 扫描状态" width="112"><template #default="{row}"><span v-if="row.findings" class="sev-tag" :class="'sev-' + row.risk.top">{{ severityName(row.risk.top) }}</span><span v-else class="sa-risk-state" :class="row.risk_state">{{ assetRiskName(row) }}</span><span v-if="row.partial_sources" class="sa-asset-meta c-high">部分完成</span></template></el-table-column>
          <el-table-column label="最近扫描" width="114"><template #default="{row}"><time class="mono sa-time" :title="fmt(row.last_scanned_at)">{{ fmt(row.last_scanned_at).slice(5,16) || '—' }}</time></template></el-table-column>
          <el-table-column label="详情" width="48" fixed="right" align="center"><template #default="{row}"><el-button link type="primary" :aria-label="'打开分组详情 ' + inventoryGroupName(row, AGENT_NAMES)" @click.stop="selectGroup(row)"><el-icon><ArrowRight /></el-icon></el-button></template></el-table-column>
        </el-table>
        <div class="sa-pagination"><el-pagination v-model:current-page="inventoryPage" v-model:page-size="inventoryPageSize" :page-sizes="[10,20,50]" :total="data.total" layout="total, sizes, prev, pager, next" size="small" /></div>
      </section>
      <aside class="sa-sidebar">
        <section class="sa-panel" aria-label="资产类型分布">
          <div class="sa-panel-head"><h3><el-icon aria-hidden="true"><Collection /></el-icon>资产类型分布</h3><span>{{ data.kinds.length }} 类</span></div>
          <div class="sa-distribution">
            <div class="sa-donut" :style="{background: typeDonut(data.kinds)}" role="img" :aria-label="'资产总数 ' + data.summary.assets + '，共 ' + data.kinds.length + ' 种类型'"><div><strong>{{ inventory ? data.summary.assets.toLocaleString() : '—' }}</strong><span>已扫描资产</span></div></div>
            <div class="sa-type-legend"><button v-for="item in data.kinds" :key="item.kind" type="button" :class="{on: inventoryKind === item.kind}" :aria-pressed="inventoryKind === item.kind" @click="inventoryKind = inventoryKind === item.kind ? '' : item.kind"><i :style="{background: kindColor(item.kind)}" /><span>{{ kindName(item.kind) }}</span><b>{{ item.count }}</b></button><span v-if="!data.kinds.length" class="muted">暂无类型数据</span></div>
          </div>
        </section>
        <section class="sa-panel" aria-label="重点风险分组">
          <div class="sa-panel-head"><h3><el-icon aria-hidden="true"><Warning /></el-icon>重点风险分组</h3><span>最高等级 / 条目数</span></div>
          <div v-if="data.top_risks.length" class="sa-top-list"><button v-for="(asset,index) in data.top_risks" :key="asset.group_id" type="button" @click="selectGroup(asset)"><div><span class="sa-rank">{{ String(index + 1).padStart(2,'0') }}</span><strong>{{ inventoryGroupName(asset, AGENT_NAMES) }}</strong><span class="sev-tag" :class="'sev-' + asset.risk.top">{{ severityName(asset.risk.top) }}</span></div><div class="sa-top-track"><span :style="{width: asset.findings / maxRiskCount * 100 + '%', background: assetRiskColor(asset.risk.top)}" /></div><div class="sa-top-meta"><span>{{ asset.risky_assets }} 个风险资产</span><b>{{ asset.findings }} 条</b></div></button></div>
          <div v-else class="sa-empty">{{ inventory ? '当前扫描结果未检出风险分组' : '资产数据尚未加载' }}</div>
        </section>
      </aside>
    </div>
    <StaticAssetDetail v-model="detailOpen" :asset="selected" />
  </div>
</template>

<script setup>
import {computed, ref, watch, onMounted, onBeforeUnmount} from "vue";
import {AGENT_NAMES} from "../../store/runtime";
import {inventory, inventoryLoading, inventoryError, inventoryAgent, inventoryKind, inventoryQuery, inventoryRisk,
  inventoryPage, inventoryPageSize, loadInventory, resetInventoryFilters} from "../../store/staticInventory";
import {fmt} from "../../utils/format";
import {kindName, kindColor, severityName} from "../../utils/staticText";
import {inventoryGroupName, assetRiskName, assetRiskColor, typeDonut} from "../../utils/staticInventory";
import StaticAssetDetail from "./StaticAssetDetail.vue";
import StaticGroupDetail from "./StaticGroupDetail.vue";

const empty = {items: [], sources: [], kinds: [], top_risks: [], total: 0,
  summary: {assets: 0, sources: 0, risky_assets: 0, high_risk_assets: 0, partial_sources: 0, groups: 0, device_agents: 0}};
const data = computed(() => inventory.value || empty);
const metrics = computed(() => [
  {label: "已扫描资产", value: data.value.summary.assets, icon: "Files", tone: "brand"},
  {label: "设备—Agent", value: data.value.summary.device_agents, icon: "Monitor", tone: "brand"},
  {label: "风险资产", value: data.value.summary.risky_assets, icon: "Warning", tone: "warning"},
  {label: "严重 / 高危资产", value: data.value.summary.high_risk_assets, icon: "Aim", tone: "critical"},
]);
const maxRiskCount = computed(() => Math.max(1,...data.value.top_risks.map(a => a.findings)));
const agents = computed(() => [...new Set(data.value.sources.map(source => source.agent).filter(Boolean))].sort());
const selectedGroup = ref(null);
function selectGroup(group) { selectedGroup.value = group; }
const selected = ref(null), detailOpen = ref(false);
function selectAsset(asset) { selected.value = asset; detailOpen.value = true; }
let timer;
watch([inventoryAgent, inventoryKind, inventoryQuery, inventoryRisk, inventoryPage, inventoryPageSize], () => {
  clearTimeout(timer); timer = setTimeout(loadInventory, 220);
});
onMounted(loadInventory);
onBeforeUnmount(() => clearTimeout(timer));
</script>
