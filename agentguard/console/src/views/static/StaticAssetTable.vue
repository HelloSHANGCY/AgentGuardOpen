<template>
  <el-table :data="staticAssetRows" size="small" class="mt-8 asset-table" max-height="680"
            row-key="row_key" :tree-props="{ children: 'children' }" default-expand-all
            :row-class-name="({ row }) => row.is_group ? 'asset-group-row' : ''"
            :empty-text="staticAssets.length ? '没有符合筛选条件的资产' : '暂无资产'">
    <el-table-column :label="staticAssetGrouped ? '类型 / 名称' : '名称'" min-width="220">
      <template #default="{ row }">
        <span v-if="row.is_group" class="asset-group-label">
          <span class="kind-dot" :style="{ background: kindColor(row.kind) }"></span>{{ kindName(row.kind) }}
          <span class="muted">· {{ row.children.length }}</span>
          <span v-if="groupRisk(row)" class="muted fs-11">· {{ groupRisk(row) }} 个有风险</span>
        </span>
        <span v-else class="asset-name" :title="row.name + ' · 发现方式：' + discoveryName(row.discovery_method)">{{ row.name || '-' }}</span>
      </template>
    </el-table-column>
    <el-table-column v-if="!staticAssetGrouped" label="类型" width="120">
      <template #default="{ row }"><span class="kind-dot" :style="{ background: kindColor(row.kind) }"></span>{{ kindName(row.kind) }}</template>
    </el-table-column>
    <el-table-column label="风险" width="130">
      <template #default="{ row }">
        <template v-if="!row.is_group">
          <button v-if="risk(row)" type="button" class="risk-link" :title="'查看该资产的 ' + risk(row).count + ' 条风险'"
                  @click.stop="showAssetFindings(row.asset_id)">
            <span class="sev-tag" :class="'sev-' + risk(row).top">{{ risk(row).top }}</span>
            <span>{{ risk(row).count }} 条</span>
          </button>
          <span v-else class="muted">-</span>
        </template>
      </template>
    </el-table-column>
    <el-table-column label="版本" width="110">
      <template #default="{ row }"><span v-if="!row.is_group" class="mono fs-11">{{ row.version || '-' }}</span></template>
    </el-table-column>
    <el-table-column label="来源文件" min-width="260">
      <template #default="{ row }"><span v-if="!row.is_group" class="mono fs-11 muted">{{ row.relative_path }}</span></template>
    </el-table-column>
    <el-table-column label="置信度" width="70">
      <template #default="{ row }">
        <span v-if="!row.is_group" :class="{ muted: row.confidence !== 'high' }">{{ confidenceName(row.confidence) }}</span>
      </template>
    </el-table-column>
    <el-table-column width="44" align="center">
      <template #default="{ row }">
        <el-button v-if="!row.is_group" link type="primary" title="在图谱中以该资产为中心查看"
                   @click.stop="showAssetInGraph(row.asset_id)"><el-icon><Share /></el-icon></el-button>
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup>
import {
  staticAssetRows, staticAssets, staticAssetGrouped, staticRiskByAsset, showAssetFindings, showAssetInGraph,
} from "../../store/static";
import { kindName, kindColor, discoveryName, confidenceName } from "../../utils/staticText";

const risk = (row) => staticRiskByAsset.value.get(row.asset_id);
const groupRisk = (row) => row.children.filter((a) => staticRiskByAsset.value.has(a.asset_id)).length;
</script>
