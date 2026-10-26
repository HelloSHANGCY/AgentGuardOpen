<template>
  <div class="stat-cards static-cards" v-if="staticCoverage">
    <div class="card">
      <el-icon><Folder /></el-icon>
      <div>
        <div class="k">索引文件</div>
        <div class="v">{{ staticCoverage.indexed_files }}</div>
        <div class="sub">解析 {{ staticCoverage.parsed_files }} · 失败
          <b :class="{ 'c-crit': staticCoverage.failed_files }">{{ staticCoverage.failed_files }}</b>
          · 跳过 {{ staticCoverage.skipped_files ?? 0 }}</div>
      </div>
    </div>
    <div class="card">
      <el-icon><Files /></el-icon>
      <div>
        <div class="k">识别资产</div>
        <div class="v">{{ staticAssets.length }}</div>
        <div class="sub">{{ riskyAssets }} 个资产存在风险</div>
      </div>
    </div>
    <div class="card" :class="staticStats.critical ? 'tone-crit' : (staticStats.findings ? 'tone-med' : 'tone-ok')">
      <el-icon><WarningFilled /></el-icon>
      <div>
        <div class="k">风险条目</div>
        <div class="v">{{ staticStats.findings }}</div>
        <div class="sub">{{ ruleCount }} 条规则命中</div>
      </div>
    </div>
    <div class="card sev-card">
      <div class="k">严重度分布</div>
      <div class="sev-bar" v-if="staticStats.findings">
        <span v-for="s in SEVERITIES" :key="s" v-show="staticStats.severity[s]" :class="'sev-seg-' + s"
              :style="{ flex: staticStats.severity[s] }"></span>
      </div>
      <div class="sev-chips">
        <button v-for="s in SEVERITIES" :key="s" type="button" class="sev-chip" :class="['sev-chip-' + s, { on: staticSeverity === s }]"
                :disabled="!staticStats.severity[s]" :aria-pressed="staticSeverity === s" @click="pickSeverity(s)">
          {{ severityName(s) }} <b>{{ staticStats.severity[s] }}</b>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";
import { staticCoverage, staticStats, staticAssets, staticAllFindings, staticRiskByAsset, staticSeverity, staticView } from "../../store/static";
import { SEVERITIES, severityName } from "../../utils/staticText";

const riskyAssets = computed(() => staticRiskByAsset.value.size);
const ruleCount = computed(() => new Set(staticAllFindings.value.map((f) => f.rule_id)).size);

// 点击等级：切到风险视图并按该等级筛选；再次点击取消。
function pickSeverity(s) {
  staticSeverity.value = staticSeverity.value === s ? "" : s;
  staticView.value = "findings";
}
</script>
