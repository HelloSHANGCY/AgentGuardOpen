<template>
  <div>
    <template v-if="staticRuleGrouped">
      <div v-for="g in staticFindingGroups" :key="g.rule_id" class="rule-group" :class="{ open: isOpen(g) }">
        <div class="threat rule-group-head" :data-sev="g.top" role="button" tabindex="0" :aria-expanded="isOpen(g)"
             @click="toggle(g)" @keydown.enter="toggle(g)" @keydown.space.prevent="toggle(g)">
          <div class="threat-head">
            <span class="sev-tag" :class="'sev-'+g.top" :title="'最高等级：' + severityName(g.top)">{{ g.top }}</span>
            <div class="grow-min">
              <div class="reason">{{ g.title }}</div>
              <div class="meta">
                <span class="mono">{{ g.rule_id }}</span>
                <span>{{ categoryName(g.items[0].category) }}</span>
                <span v-if="Object.keys(g.severity).length > 1">
                  {{ SEVERITIES.filter((s) => g.severity[s]).map((s) => severityName(s) + ' ' + g.severity[s]).join(' · ') }}</span>
              </div>
            </div>
            <span class="group-count">{{ g.items.length }} 处</span>
            <el-icon class="row-chevron group-chevron" aria-hidden="true"><ArrowRight /></el-icon>
          </div>
        </div>
        <div v-if="isOpen(g)" class="rule-group-items">
          <StaticFindingRow v-for="f in g.items" :key="f.finding_id" :f="f" :show-rule="false" @open="openDetail" />
        </div>
      </div>
    </template>
    <template v-else>
      <StaticFindingRow v-for="f in pagedFindings" :key="f.finding_id" :f="f" @open="openDetail" />
      <div class="pager" v-if="staticFindings.length > 20">
        <el-pagination background size="small" :total="staticFindings.length"
                       v-model:current-page="page" v-model:page-size="pageSize"
                       :page-sizes="[20, 50, 100]"
                       layout="total, sizes, prev, pager, next"></el-pagination>
      </div>
    </template>
    <el-empty v-if="!staticFindings.length" :image-size="80"
              :description="emptyText"></el-empty>

    <el-dialog v-model="detailVisible" class="detail-dialog" width="720px" top="6vh" append-to-body destroy-on-close>
      <template #header>
        <div v-if="detail" class="dd-head">
          <div class="dd-title-row">
            <span class="sev-tag" :class="'sev-'+detail.severity">{{ detail.severity }}</span>
            <span class="dd-title">{{ detail.title || detail.rule_id }}</span>
          </div>
          <div class="dd-subtitle">
            {{ categoryName(detail.category) }} · 置信度{{ confidenceName(detail.confidence) }}
          </div>
        </div>
      </template>
      <div v-if="detail" class="dd-body">
        <section class="dd-section">
          <h4 class="dd-section-title">概要</h4>
          <dl class="dd-kv">
            <template v-if="detailAsset">
              <dt>资产</dt><dd>{{ kindName(detailAsset.kind) }} · <b>{{ detailAsset.name }}</b>
                <span v-if="detailAsset.version" class="muted"> {{ detailAsset.version }}</span></dd>
              <dt>位置</dt><dd><CopyText :text="detailAsset.relative_path" /></dd>
            </template>
            <template v-else><dt>资产</dt><dd><CopyText :text="detail.asset_id || ''" /></dd></template>
            <dt>规则</dt><dd><span class="mono">{{ detail.rule_id }}</span> <span class="muted">{{ ruleTitle(detail.rule_id) }}</span></dd>
          </dl>
        </section>

        <section class="dd-section" v-if="detail.explanation">
          <h4 class="dd-section-title">说明</h4>
          <p class="dd-prose">{{ detail.explanation }}</p>
        </section>
        <section class="dd-section" v-if="detail.remediation">
          <h4 class="dd-section-title">修复建议</h4>
          <div class="dd-callout dd-callout-ALLOW"><div class="dd-callout-text">{{ detail.remediation }}</div></div>
        </section>

        <section class="dd-section" v-if="(detail.flow_steps||[]).length">
          <h4 class="dd-section-title">数据流 <span class="dd-count">{{ detail.flow_steps.length }}</span></h4>
          <ol class="dd-steps">
            <li v-for="(st, i) in detail.flow_steps" :key="i" :data-kind="st.kind">
              <div class="dd-step-head">
                <span class="dd-step-kind">{{ stepKind(st.kind) }}</span>
                <el-tag size="small" effect="plain" :type="st.status === 'proven' ? 'danger' : 'info'">{{ stepStatus(st.status) }}</el-tag>
                <span class="mono muted">{{ st.location }}</span>
              </div>
              <div v-if="st.detail" class="dd-step-detail">{{ st.detail }}</div>
            </li>
          </ol>
        </section>

        <section class="dd-section">
          <h4 class="dd-section-title">证据 <span class="dd-count" v-if="detail.evidence">{{ detail.evidence.length }}</span></h4>
          <div v-if="!detail.evidence" class="muted">加载中…</div>
          <div v-else-if="!detail.evidence.length" class="muted">无证据片段</div>
          <div v-for="(e, i) in detail.evidence || []" :key="i" class="dd-evidence">
            <div class="dd-evidence-loc">
              <CopyText :text="e.path + (e.line ? ':' + e.line : '')" />
              <span v-if="e.pointer" class="code-hint">{{ e.pointer }}</span>
            </div>
            <pre v-if="e.excerpt" class="dd-code">{{ e.excerpt }}</pre>
          </div>
        </section>

        <section class="dd-section" v-if="detail.limitations">
          <h4 class="dd-section-title">检测局限</h4>
          <p class="dd-prose muted">{{ detail.limitations }}</p>
        </section>
        <MoreFields>
          <dl class="dd-kv">
            <dt>Finding ID</dt><dd><CopyText :text="detail.finding_id" /></dd>
            <dt>资产 ID</dt><dd><CopyText :text="detail.asset_id || ''" /></dd>
          </dl>
        </MoreFields>
      </div>
      <template #footer>
        <template v-if="detail && detail.asset_id">
          <el-button size="small" plain @click="jump(showAssetInGraph)"><el-icon class="btn-ic"><Share /></el-icon>在图谱中查看</el-button>
          <el-button v-if="staticAssetFilter !== detail.asset_id" size="small" plain @click="jump(showAssetFindings)">只看该资产的风险</el-button>
        </template>
        <el-button size="small" @click="detailVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, watch } from "vue";
import CopyText from "../../components/CopyText.vue";
import MoreFields from "../../components/MoreFields.vue";
import StaticFindingRow from "./StaticFindingRow.vue";
import {
  staticFindings, staticAllFindings, staticFindingGroups, staticRuleGrouped, staticSeverity, staticScanId,
  staticScan, staticPolling,
  staticAssetFilter, staticFindingQuery, staticAssetById, loadStaticFindingDetail, showAssetFindings, showAssetInGraph,
} from "../../store/static";
import { SEVERITIES, severityName, ruleTitle, categoryName, confidenceName, kindName } from "../../utils/staticText";

// 平铺模式分页，默认每页 20 条；筛选/换扫描/记录变少时回到有效页。
const page = ref(1), pageSize = ref(20);
const emptyText = computed(() => {
  if (staticAllFindings.value.length) return '没有符合筛选条件的风险条目';
  if (!staticScanId.value) return '暂无扫描记录';
  if (staticPolling.value) return staticScan.value?.phase === 'WAITING_ENDPOINT' ? '等待终端采集资产' : '扫描尚未完成';
  if (['FAILED', 'CANCELLED', 'INTERRUPTED'].includes(staticScan.value?.status)) return '本次扫描未完成';
  return '本次扫描没有风险条目';
});
const pagedFindings = computed(() =>
  staticFindings.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value));
watch([staticSeverity, staticScanId, staticAssetFilter, staticFindingQuery, pageSize], () => { page.value = 1; });

// 聚合模式：默认收起；分组很少或已按资产/关键字收窄时全部展开。
const expanded = ref(new Set());
const narrowed = computed(() => staticFindingGroups.value.length <= 3 || !!staticAssetFilter.value || !!staticFindingQuery.value.trim());
const isOpen = (g) => narrowed.value || expanded.value.has(g.rule_id);
const toggle = (g) => {
  const next = new Set(expanded.value);
  if (isOpen(g) && !narrowed.value) next.delete(g.rule_id); else next.add(g.rule_id);
  expanded.value = next;
};
watch(staticScanId, () => { expanded.value = new Set(); });

const stepKind = (k) => ({ source: "来源", transform: "传播", sink: "汇点" }[k] || k);
const stepStatus = (st) => ({ proven: "已证实", inferred: "推断" }[st] || st || "未知");

// 详情独立弹窗；打开时按需拉取证据明细（不预载全部证据）。
const detail = ref(null), detailVisible = ref(false);
const detailAsset = computed(() => detail.value && staticAssetById.value.get(detail.value.asset_id));
const openDetail = async (finding) => {
  detail.value = finding;
  detailVisible.value = true;
  await loadStaticFindingDetail(finding);
};
const jump = (fn) => { const id = detail.value.asset_id; detailVisible.value = false; fn(id); };
</script>
