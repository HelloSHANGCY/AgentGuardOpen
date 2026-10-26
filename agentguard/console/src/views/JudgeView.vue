<template>
  <section v-show="tab === 'judge'" class="judge-page">
    <ConsolePageHeader title="大模型研判" class="judge-page-head">

      <div class="judge-head-actions"><el-button size="small" :disabled="busy" @click="tab = 'models'">模型管理</el-button><el-button size="small" :loading="refreshing || intentRefreshing" :disabled="busy" @click="reload"><el-icon class="btn-ic"><Refresh /></el-icon>刷新</el-button><el-button v-if="recordTab !== 'intent'" size="small" type="primary" :disabled="!canAnalyze || busy" @click="openManual">手动分析</el-button></div>
    </ConsolePageHeader>
    <div class="eval-controls" v-if="adminNeedsToken">
      <label>管理令牌<el-input size="small" v-model="adminToken" type="password" show-password autocomplete="off" aria-label="管理令牌" placeholder="AG_AGENT_ADMIN_TOKEN，仅保存在当前页面" @keyup.enter="reload" /></label>
      <el-button size="small" type="primary" :disabled="!adminToken || refreshing" @click="reload">加载</el-button>
    </div>
    <el-alert v-if="judgeError && recordTab !== 'intent'" :title="judgeError" type="error" show-icon class="my-12" @close="judgeError = ''" />
    <el-alert v-if="st?.forced_off && recordTab !== 'intent'" type="warning" show-icon :closable="false" class="my-12" title="大模型研判已由服务端强制关闭" />
    <template v-if="judgeLoaded && st && recordTab !== 'intent'">
      <el-alert v-if="!st.key_set && !st.forced_off" type="info" show-icon :closable="false" class="my-12" title="模型密钥未配置" />
      <JudgeStatistics :records="judgeAnalyses" :active="tab === 'judge'" :selected-verdict="fVerdict" @select-verdict="selectStatisticsVerdict" />
    </template>
      <el-tabs v-model="recordTab" class="judge-tabs" aria-label="大模型研判管理">
        <el-tab-pane label="分析记录" name="analyses">
          <section v-if="judgeLoaded && st" class="judge-card judge-records" aria-labelledby="judge-records-title">
            <div class="judge-card-head"><h3 id="judge-records-title">分析记录 <span class="judge-note">{{ filteredRows.length }} 条{{ filtersActive ? '匹配' : '已加载' }}</span></h3><el-button v-if="filtersActive" link type="primary" size="small" @click="resetFilters">清除筛选</el-button></div>
            <div class="judge-filters"><div><label for="judge-verdict">结论</label><el-select id="judge-verdict" v-model="fVerdict" placeholder="全部结论" clearable size="small" aria-label="筛选分析结论"><el-option v-for="(label, key) in VERDICT_TEXT" :key="key" :label="label" :value="key" /></el-select></div>
              <div class="judge-search"><label for="judge-search">搜索记录</label><el-input id="judge-search" v-model="fJudgeText" placeholder="会话 ID、摘要或发现" size="small" clearable aria-label="搜索分析记录"><template #prefix><el-icon><Search /></el-icon></template></el-input></div></div>
            <div class="judge-analysis-table">
                    <el-table :data="pagedRows" size="small" row-key="analysis_id" class="alert-table" @row-click="openDetail"
                :empty-text="emptyText">
        <el-table-column label="时间" width="140">
          <template #default="{ row }">
            <div class="mono" :title="fmt(row.finished_at || row.created_at)">{{ fmtTime(row.finished_at || row.created_at) }}</div>
            <div class="muted fs-11 mono">{{ fmt(row.finished_at || row.created_at).slice(0, 10) }}</div>
          </template>
        </el-table-column>
        <el-table-column label="结论" width="96">
          <template #default="{ row }">
            <el-tag size="small" :type="VERDICT_TAG[verdictOf(row)]" effect="dark">{{ VERDICT_TEXT[verdictOf(row)] }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="风险" width="64">
          <template #default="{ row }">{{ RISK_TEXT[row.risk] || '-' }}</template>
        </el-table-column>
        <el-table-column label="摘要" min-width="250">
          <template #default="{ row }">
            <div class="ellipsis" :title="row.summary || row.error">{{ row.summary || row.error || '-' }}</div>
            <div v-if="row.findings?.length" class="muted fs-11 ellipsis">{{ row.findings.map((f) => f.title).join('；') }}</div>
          </template>
        </el-table-column>
        <el-table-column label="范围" width="110">
          <template #default="{ row }">{{ row.round ? `第 ${row.round} 轮` : '整个会话' }}
            <div class="muted fs-11">{{ TRIGGER_TEXT[row.trigger] || row.trigger }}</div></template>
        </el-table-column>
        <el-table-column label="会话 / Agent" min-width="180">
          <template #default="{ row }">
            <el-button link type="primary" class="mono ellipsis al-trace" :title="'查看会话链路：' + row.trace_id"
                       @click.stop="openChain(row.trace_id)">{{ scenarioOf(row.trace_id) }}</el-button>
            <div class="judge-agent"><AgentIcon v-if="row.agent" :agent="row.agent" :size="22" />{{ AGENT_NAMES[row.agent] || row.agent || '-' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="86" fixed="right"><template #default="{row}"><el-button link type="primary" size="small" @click.stop="openDetail(row)">查看详情</el-button></template></el-table-column>
      </el-table>
            </div>
            <div class="judge-analysis-cards">
              <p v-if="!pagedRows.length" class="judge-empty">{{ emptyText }}</p>
              <article v-for="row in pagedRows" :key="row.analysis_id" class="judge-analysis-card">
                <div class="judge-card-head"><el-tag size="small" :type="VERDICT_TAG[verdictOf(row)]" effect="plain">{{ VERDICT_TEXT[verdictOf(row)] }}</el-tag><span class="judge-note">{{ fmt(row.finished_at || row.created_at) }}</span></div>
                <p class="judge-mobile-summary">{{ row.summary || row.error || (row.status === 'pending' ? '分析中，完成后自动更新' : '暂无摘要') }}</p><p v-if="row.findings?.length" class="judge-note">{{ row.findings.map(f => f.title).join('；') }}</p>
                <div class="judge-mobile-meta"><span class="judge-agent"><AgentIcon v-if="row.agent" :agent="row.agent" :size="22" />{{ AGENT_NAMES[row.agent] || row.agent || '未知 Agent' }}</span><span>{{ row.round ? `第 ${row.round} 轮` : '整个会话' }} · {{ TRIGGER_TEXT[row.trigger] || row.trigger }}</span><span v-if="row.risk">风险 {{ RISK_TEXT[row.risk] || row.risk }}</span></div>
                <div class="judge-mobile-actions"><el-button link type="primary" size="small" class="mono" :title="row.trace_id" @click="openChain(row.trace_id)">{{ scenarioOf(row.trace_id) }}</el-button><el-button size="small" @click="openDetail(row)">查看详情</el-button></div>
              </article>
            </div>
            <div class="judge-pager" v-if="filteredRows.length > 10"><el-pagination background size="small" :total="filteredRows.length" v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[10, 20, 50]" :pager-count="5" layout="total, sizes, prev, pager, next" /></div>
          </section>
          <el-skeleton v-else-if="refreshing && !adminNeedsToken" :rows="5" animated />
        </el-tab-pane>
        <el-tab-pane label="意图识别" name="intent">
          <IntentPanel :status="intentStatus" :error="intentError" :loading="intentRefreshing" :saving="intentSaving" :disabled="busy"
                       @toggle="toggleIntent" @dismiss-error="intentError = ''" />
        </el-tab-pane>
        <el-tab-pane :label="proposalPending ? `规则建议 · ${proposalPending}` : '规则建议'" name="proposals"><section v-if="judgeLoaded && st" class="judge-card judge-proposals"><RuleProposals /></section><el-skeleton v-else-if="refreshing && !adminNeedsToken" :rows="5" animated /></el-tab-pane>
        <el-tab-pane label="运行配置" name="settings">
          <template v-if="judgeLoaded && st">
          <div class="judge-overview">
            <section class="judge-card" aria-labelledby="judge-review-summary"><div class="judge-card-head"><h3 id="judge-review-summary">危险审批</h3><el-tag size="small" effect="plain" :type="st.approval.active ? 'success' : 'info'">{{ st.approval.active ? '运行中' : '未运行' }}</el-tag></div>
              <strong class="judge-summary-model mono">{{ st.approval.model || '未绑定模型' }}</strong><p class="judge-note">{{ SCOPE_TEXT[st.approval.scope] }}</p>
              <dl class="judge-stats"><div><dt>复核调用</dt><dd>{{ st.approval.calls }}</dd></div><div><dt>改为放行</dt><dd>{{ st.approval.released }}</dd></div><div><dt>超时 / 失败</dt><dd>{{ st.approval.timeouts }} / {{ st.approval.failed }}</dd></div></dl>
              <div class="judge-card-foot"><el-button link type="primary" size="small" @click="scrollSetting('judge-review-title')">配置审批</el-button></div>
            </section>
            <section class="judge-card" aria-labelledby="judge-analysis-summary"><div class="judge-card-head"><h3 id="judge-analysis-summary">异步分析</h3><el-tag size="small" effect="plain" :type="st.analysis.active ? 'success' : 'info'">{{ st.analysis.active ? MODE_TEXT[st.analysis.mode] : '未运行' }}</el-tag></div>
              <strong class="judge-summary-model mono">{{ st.analysis.model || '未绑定模型' }}</strong>
              <dl class="judge-stats"><div><dt>已完成</dt><dd>{{ st.analysis.done }}</dd></div><div><dt>可疑 / 恶意</dt><dd>{{ st.analysis.verdicts.suspicious }} / {{ st.analysis.verdicts.malicious }}</dd></div><div><dt>排队中</dt><dd>{{ st.analysis.pending }}</dd></div></dl>
              <div class="judge-card-foot"><span class="judge-note">失败 {{ st.analysis.failed }} · P90 {{ st.analysis.latency_p90 ?? '—' }} 秒</span><el-button link type="primary" size="small" @click="scrollSetting('judge-async-title')">配置分析</el-button></div>
            </section>
            <section class="judge-card" aria-labelledby="judge-proposal-summary"><div class="judge-card-head"><h3 id="judge-proposal-summary">规则建议</h3><el-tag size="small" effect="plain" :type="st.proposals.enabled && !st.forced_off ? 'success' : 'info'">{{ st.proposals.enabled && !st.forced_off ? '自动生成已开' : '自动生成已关' }}</el-tag></div>
              <div class="judge-pending"><strong>{{ proposalPending }}</strong><span>条待审批</span></div>
              <div class="judge-card-foot"><span class="judge-note">已批准 {{ st.proposals.approved }} · 校验未通过 {{ st.proposals.invalid || 0 }}</span><el-button link type="primary" size="small" @click="recordTab = 'proposals'">查看建议</el-button></div>
            </section>
          </div>
          <div class="judge-settings-grid">
            <section class="judge-card" aria-labelledby="judge-review-title"><div class="judge-card-head"><h3 id="judge-review-title">危险审批</h3><el-switch :model-value="st.approval.enabled" :loading="saving" :disabled="st.forced_off || busy || !st.approval.key_set && !st.approval.enabled" aria-label="危险审批开关" @change="v => save({approval_enabled: v})" /></div>

              <el-form label-position="top" size="small" class="judge-runtime-form" @submit.prevent><el-form-item label="复核范围"><el-select :model-value="st.approval.scope" :disabled="st.forced_off || busy" aria-label="复核范围" @change="v => save({approval_scope: v})"><el-option v-for="(label,key) in SCOPE_TEXT" :key="key" :label="label" :value="key" /></el-select></el-form-item></el-form>
              <el-alert v-if="st.approval.scope === 'all'" type="warning" :closable="false" show-icon title="当前范围包含严重拦截" />
              <dl class="judge-config-kv"><div><dt>服务接口</dt><dd class="mono">{{ st.approval.host || '—' }}</dd></div><div><dt>模型 / 思考</dt><dd>{{ st.approval.model || '未绑定模型' }} · {{ EFFORT_TEXT[st.approval.effort] }}</dd></div><div><dt>放行 / 确认 / 拦截</dt><dd>{{ st.approval.released }} / {{ st.approval.confirm }} / {{ st.approval.denied }}</dd></div><div><dt>维持 / 缓存命中</dt><dd>{{ st.approval.upheld }} / {{ st.approval.cached }}</dd></div><div><dt>超时 / 失败</dt><dd>{{ st.approval.timeouts }} / {{ st.approval.failed }}</dd></div><div><dt>延迟 P50 / P90</dt><dd>{{ st.approval.latency_p50 ?? '—' }} / {{ st.approval.latency_p90 ?? '—' }} 秒</dd></div><div><dt>审批等待上限</dt><dd>{{ st.approval.timeout }} 秒</dd></div></dl>
            </section>
            <section class="judge-card" aria-labelledby="judge-async-title"><div class="judge-card-head"><h3 id="judge-async-title">异步分析与规则建议</h3><el-tag size="small" effect="plain" type="info">后台执行</el-tag></div>

              <el-form label-position="top" size="small" class="judge-runtime-form" @submit.prevent><el-form-item label="分析模式"><el-radio-group :model-value="st.analysis.mode" :disabled="st.forced_off || busy" aria-label="异步分析模式" @change="v => save({analysis_mode: v})"><el-radio-button v-for="(label,key) in MODE_TEXT" :key="key" :value="key" :disabled="!st.analysis.key_set && key !== 'off'">{{ label }}</el-radio-button></el-radio-group></el-form-item></el-form>
              <div class="judge-proposal-setting"><div><label for="judge-proposal-toggle">自动生成规则建议</label></div><el-switch id="judge-proposal-toggle" :model-value="st.proposals.enabled" :loading="saving" :disabled="st.forced_off || busy" aria-label="发现漏报时生成规则建议" @change="v => save({rule_proposal: v})" /></div>
              <dl class="judge-config-kv"><div><dt>服务接口</dt><dd class="mono">{{ st.analysis.host || '—' }}</dd></div><div><dt>模型 / 思考</dt><dd>{{ st.analysis.model || '未绑定模型' }} · {{ EFFORT_TEXT[st.analysis.effort] }}</dd></div><div><dt>分析超时</dt><dd>{{ st.analysis.timeout }} 秒</dd></div><div><dt>完成 / 失败 / 排队</dt><dd>{{ st.analysis.done }} / {{ st.analysis.failed }} / {{ st.analysis.pending }}</dd></div><div><dt>无威胁跳过 / 积压丢弃</dt><dd>{{ st.analysis.skipped }} / {{ st.analysis.dropped || 0 }}</dd></div><div><dt>延迟 P50 / P90</dt><dd>{{ st.analysis.latency_p50 ?? '—' }} / {{ st.analysis.latency_p90 ?? '—' }} 秒</dd></div></dl>
            </section>
          </div>
          <el-alert v-if="operationError" :title="operationError" type="error" :closable="false" show-icon class="my-12" />
          </template>
          <el-skeleton v-else-if="refreshing && !adminNeedsToken" :rows="5" animated />
        </el-tab-pane>
      </el-tabs>
    <el-dialog v-model="detailVisible" class="detail-dialog judge-detail-dialog" width="min(780px, 94vw)" top="6vh" :close-on-click-modal="!manualRunning && !proposing" :close-on-press-escape="!manualRunning && !proposing" :show-close="!manualRunning && !proposing" append-to-body destroy-on-close>
      <template #header="{titleId}">
        <div v-if="detail" :id="titleId" class="dd-head">
          <div class="dd-title-row">
            <el-tag size="small" :type="VERDICT_TAG[verdictOf(detail)]" effect="dark">{{ VERDICT_TEXT[verdictOf(detail)] }}</el-tag>
            <span v-if="detail.risk" class="sev-tag" :class="'sev-' + riskSev(detail.risk)">风险 {{ RISK_TEXT[detail.risk] }}</span>
            <span class="dd-title">{{ detail.round ? `第 ${detail.round} 轮` : '整个会话' }} · {{ scenarioOf(detail.trace_id) }}</span>
          </div>
          <div class="dd-subtitle">{{ AGENT_NAMES[detail.agent] || detail.agent || '-' }} · {{ TRIGGER_TEXT[detail.trigger] || detail.trigger }}
            · {{ fmt(detail.finished_at || detail.created_at) }}</div>
        </div>
      </template>
      <div v-if="detail?.proposals" class="dd-callout mb-10" :class="{ 'dd-callout-ASK': detail.proposals.count }">
        <div class="dd-callout-label">规则建议</div>
        <div class="dd-callout-text">{{ proposalText(detail.proposals) }}
          <el-button v-if="detail.proposals.count" link type="primary" size="small" @click="showProposals">去审批</el-button></div>
      </div>
      <el-alert v-if="detailError" :title="detailError" type="error" :closable="false" show-icon class="my-12" /><AnalysisDetail v-if="detail" :record="detail" />
      <template #footer>
        <div class="judge-dialog-actions">
        <el-button size="small" :disabled="manualRunning || proposing" @click="detailVisible = false">关闭</el-button>
        <el-button v-if="detail?.status === 'done' && detail.findings?.length" size="small"
                   :loading="proposing || detail.proposals?.status === 'running'" :disabled="!canAnalyze || busy || detail?.status === 'pending'"
                   @click="runPropose">生成规则建议</el-button>
        <el-button size="small" :loading="manualRunning" :disabled="!canAnalyze || busy || detail?.status === 'pending'" @click="reanalyze">重新分析</el-button>
        <el-button size="small" type="primary" @click="viewChain">
          查看会话链路<el-icon class="el-icon--right"><ArrowRight /></el-icon></el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="manualVisible" title="手动分析会话" width="min(500px, 94vw)" top="6vh" class="detail-dialog" :close-on-click-modal="false" :close-on-press-escape="!manualRunning" :show-close="!manualRunning" append-to-body>

      <el-form label-position="top" size="small" :disabled="manualRunning" class="judge-manual-form" @submit.prevent="runManual"><el-form-item label="会话 / 决策 ID"><el-input v-model="manualTrace" placeholder="输入 trace ID 或决策 ID" aria-label="手动分析的会话" clearable /></el-form-item><el-alert v-if="manualError" :title="manualError" type="error" :closable="false" show-icon /></el-form>
      <template #footer><el-button size="small" :disabled="manualRunning" @click="manualVisible = false">取消</el-button><el-button size="small" type="primary" :disabled="!manualTrace.trim() || !canAnalyze || manualRunning" :loading="manualRunning" @click="runManual">提交分析</el-button></template>
    </el-dialog>
  </section>
</template>

<script setup>
import { ref, computed, watch, onUnmounted, nextTick } from "vue";
import { ElMessage } from "element-plus";
import AnalysisDetail from "../components/AnalysisDetail.vue";
import RuleProposals from "../components/RuleProposals.vue";
import AgentIcon from "../components/AgentIcon.vue";
import JudgeStatistics from "./judge/JudgeStatistics.vue";
import IntentPanel from "./judge/IntentPanel.vue";
import {
  tab, analysisTick, proposalTick, AGENT_NAMES, fmt, fmtTime, scenarioOf, openChain,
  VERDICT_TEXT, VERDICT_TAG, RISK_TEXT,
} from "../store/runtime";
import { riskSev } from "../utils/format";
import { adminToken, adminNeedsToken } from "../store/devices";
import { intentStatus, intentError, refreshIntent, updateIntent } from "../store/intent";
import {
  judgeStatus, judgeAnalyses, judgeLoaded, judgeError, SCOPE_TEXT, MODE_TEXT, EFFORT_TEXT,
  refreshJudge, updateJudge, analyzeSession, proposalPending, proposeRules,
} from "../store/judge";

const st = judgeStatus;
const refreshing = ref(false), saving = ref(false), manualRunning = ref(false), proposing = ref(false);
const intentRefreshing = ref(false), intentSaving = ref(false);
const busy = computed(() => refreshing.value || saving.value || manualRunning.value || proposing.value || intentRefreshing.value || intentSaving.value);
const canAnalyze = computed(() => !!st.value?.analysis?.key_set && !st.value.forced_off);
const operationError = ref(""), manualError = ref(""), detailError = ref("");
const TRIGGER_TEXT = { full: "全量分析", threat: "威胁分析", manual: "手动分析" };
const verdictOf = (r) => (r.status === "done" && r.coverage?.complete === false ? "partial"
  : r.status === "done" ? r.verdict : r.status);

// ---- 开关与配置 ----
async function scrollSetting(id) {
  recordTab.value = "settings"; await nextTick();
  document.getElementById(id)?.scrollIntoView({block: "nearest"});
}
async function save(changes) {
  if (busy.value || st.value?.forced_off) return;
  operationError.value = "";
  saving.value = true;
  try {
    if (await updateJudge(changes)) ElMessage.success("已保存");
    else operationError.value = judgeError.value;
  } finally { saving.value = false; }
}

async function toggleIntent(enabled) {
  if (busy.value || !intentStatus.value || intentStatus.value.forced_off) return;
  if (enabled && !intentStatus.value.key_set) { tab.value = "models"; return; }
  intentSaving.value = true;
  try {
    if (await updateIntent({ enabled })) ElMessage.success(enabled ? "已开启大模型意图识别" : "已切回关键词");
  } finally { intentSaving.value = false; }
}

// ---- 分析记录 ----
const fVerdict = ref(""), fJudgeText = ref("");
const filtersActive = computed(() => !!fVerdict.value || !!fJudgeText.value.trim());
const resetFilters = () => { fVerdict.value = ""; fJudgeText.value = ""; };
async function selectStatisticsVerdict(verdict) {
  recordTab.value = "analyses"; fVerdict.value = verdict; fJudgeText.value = ""; page.value = 1;
  await nextTick(); document.querySelector("#judge-records-title")?.scrollIntoView({block: "nearest"});
}
const emptyText = computed(() => filtersActive.value ? "没有匹配的分析记录，请调整筛选条件。"
  : st.value?.analysis.mode === "off" ? "自动分析已关闭，可通过“手动分析”提交会话。" : "暂无分析记录，任务完成后会在这里显示。");
const filteredRows = computed(() => judgeAnalyses.value.filter((r) => {
  if (fVerdict.value && verdictOf(r) !== fVerdict.value) return false;
  if (fJudgeText.value) {
    const hay = [r.trace_id, r.summary, r.error, ...(r.findings || []).map((f) => f.title)].join(" ").toLowerCase();
    if (!hay.includes(fJudgeText.value.trim().toLowerCase())) return false;
  }
  return true;
}));
const page = ref(1), pageSize = ref(20);
const pagedRows = computed(() => filteredRows.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value));
watch([fVerdict, fJudgeText, pageSize], () => { page.value = 1; });
watch(filteredRows, rows => { page.value = Math.min(page.value, Math.max(1, Math.ceil(rows.length / pageSize.value))); });

const detailId = ref(""), detailVisible = ref(false);
const detailSnapshot = ref(null);
const detail = computed(() => judgeAnalyses.value.find((r) => r.analysis_id === detailId.value) || detailSnapshot.value);
const openDetail = (row) => { detailId.value = row.analysis_id; detailSnapshot.value = row; detailError.value = ""; detailVisible.value = true; };
const viewChain = () => { if (detail.value) { detailVisible.value = false; openChain(detail.value.trace_id); } };

const manualTrace = ref(""), manualVisible = ref(false);
function openManual() { if (!canAnalyze.value || busy.value) return; manualError.value = ""; manualVisible.value = true; }
async function runManual() {
  const trace = manualTrace.value.trim();
  if (!trace || !canAnalyze.value || busy.value) return;
  manualError.value = "";
  manualRunning.value = true;
  try {
    const record = await analyzeSession(trace);
    if (record) {
      ElMessage.success("已提交分析，完成后自动更新"); manualTrace.value = ""; manualVisible.value = false;
      recordTab.value = "analyses"; resetFilters(); page.value = 1; openDetail(record);
    } else manualError.value = judgeError.value;
  } finally { manualRunning.value = false; }
}
async function reanalyze() {
  if (!detail.value || !canAnalyze.value || busy.value || detail.value.status === "pending") return;
  detailError.value = "";
  manualRunning.value = true;
  try {
    const record = await analyzeSession(detail.value.trace_id, detail.value.round);
    if (record) openDetail(record);
    else detailError.value = judgeError.value;
  } finally { manualRunning.value = false; }
}

// ---- 规则建议 ----
const recordTab = ref("analyses");
const proposalText = (p) => ({
  running: "模型正在根据本次发现提议规则…",
  failed: "生成失败：" + p.error,
  done: p.count ? `已生成 ${p.count} 条规则建议，待审批。` : "没有可以写成特征规则的发现，或建议未通过校验 / 与现有规则重复。",
}[p.status] || "");
const showProposals = () => { detailVisible.value = false; recordTab.value = "proposals"; };
async function runPropose() {
  if (!detail.value || !canAnalyze.value || busy.value || detail.value.proposals?.status === "running") return;
  detailError.value = "";
  proposing.value = true;
  try {
    if (await proposeRules(detail.value.analysis_id)) ElMessage.success("已提交，生成后自动刷新");
    else detailError.value = judgeError.value;
  } finally { proposing.value = false; }
}
let proposalTimer = null;
watch(proposalTick, () => {
  if (tab.value !== "judge" || recordTab.value === "intent" || proposalTimer) return;
  proposalTimer = setTimeout(() => { proposalTimer = null; reload(); }, 300);
});

// 进入页面时加载；分析完成有 SSE 推送，另在有排队记录时每 3 秒兜底刷新。
async function reload() {
  if (recordTab.value === "intent") {
    if (intentRefreshing.value || intentSaving.value || manualVisible.value) return;
    intentRefreshing.value = true;
    try { await refreshIntent(); } finally { intentRefreshing.value = false; }
    return;
  }
  if (refreshing.value || saving.value || manualRunning.value || proposing.value || intentSaving.value || manualVisible.value) return;
  refreshing.value = true;
  try { await refreshJudge(); } finally { refreshing.value = false; }
}
watch([tab, recordTab], ([t]) => { if (t === "judge") reload(); }, { immediate: true });
let tickTimer = null;
watch(analysisTick, () => {
  if (tab.value !== "judge" || recordTab.value === "intent" || tickTimer) return;
  tickTimer = setTimeout(() => { tickTimer = null; reload(); }, 500);
});
const poller = setInterval(() => {
  if (tab.value === "judge" && recordTab.value !== "intent" && document.visibilityState === "visible"
    && judgeAnalyses.value.some((r) => r.status === "pending" || r.proposals?.status === "running")) reload();
}, 3000);
onUnmounted(() => { clearInterval(poller); clearTimeout(tickTimer); clearTimeout(proposalTimer); });
</script>

<style scoped>
.judge-page-head, .judge-head-actions, .judge-card-head, .judge-card-foot, .judge-proposal-setting, .judge-mobile-actions { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.judge-page-head { margin-bottom: 16px; align-items: flex-start; }
.judge-head-actions { flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
.judge-head-actions .el-button + .el-button { margin-left: 0; }
.judge-note { margin: 4px 0 0; color: var(--muted); font-size: 12px; line-height: 1.7; }
.judge-overview { margin-bottom: 16px; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.judge-card { min-width: 0; padding:var(--space-4); background: var(--panel); border: 1px solid var(--line); border-radius:var(--radius-panel); }
.judge-overview .judge-card { display: flex; flex-direction: column; }
.judge-card h3 { margin: 0; color: var(--title); font-size: 14px; font-weight: 500; }
.judge-card-head { margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
.judge-summary-model { display: block; color: var(--title); font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
.judge-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 12px 0; }
.judge-stats dt { font-size: 12px; color: var(--muted); }
.judge-stats dd { margin: 2px 0 0; color: var(--title); font-size: 20px; font-weight: 600; overflow-wrap: anywhere; }
.judge-card-foot { flex-wrap: wrap; gap: 4px 12px; margin-top: auto; padding-top: 10px; border-top: 1px solid var(--line-2); }
.judge-card-foot .judge-note { margin-top: 0; }
.judge-pending { display: flex; align-items: baseline; gap: 8px; margin: 10px 0 4px; color: var(--muted); font-size: 13px; }
.judge-pending strong { font-size: 32px; color: var(--title); line-height: 1.4; }
.judge-overview .judge-card:last-child > .judge-note { margin-bottom: 18px; }
.judge-tabs { margin-top: 16px; }
.judge-tabs :deep(.el-tabs__item) { height: var(--control-tab-height); font-size: 13px; }
.judge-tabs :deep(.el-tabs__header) { margin-bottom: 16px; }
.judge-records h3 .judge-note { margin-left: 8px; font-weight: 400; }
.judge-filters { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px; margin: 16px 0; }
.judge-filters > div { width: 160px; min-width: 0; }
.judge-filters .judge-search { flex: 1; max-width: 420px; min-width: 180px; }
.judge-filters label { display: block; margin-bottom: 4px; color: var(--muted); font-size: 12px; }
.judge-analysis-table :deep(.el-table__row) { cursor: pointer; }
.judge-analysis-cards { display: none; }
.judge-agent { display: inline-flex; align-items: center; flex-wrap: wrap; gap: 4px; color: var(--muted); font-size: 12px; }
.judge-agent :deep(.agent-icon) { padding: 2px; border-radius: 6px; }
.judge-pager { display: flex; justify-content: flex-end; margin: 16px 0 10px; }
.judge-settings-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; align-items: start; }
.judge-runtime-form { margin-top: 18px; }
.judge-runtime-form :deep(.el-form-item__content) { display: block; }
.judge-runtime-form :deep(.el-form-item__label) { color: var(--text); }
.judge-config-kv { display: grid; gap: 10px; margin: 18px 0; font-size: 12px; }
.judge-config-kv > div { display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 8px; }
.judge-config-kv dt { color: var(--muted); }
.judge-config-kv dd { margin: 0; overflow-wrap: anywhere; }
.judge-proposal-setting { padding: 14px 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.judge-proposal-setting .el-switch { flex: none; }
.judge-proposal-setting label { font-size: 13px; color: var(--text); cursor: pointer; }
.judge-dialog-actions { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 8px; }
.judge-dialog-actions .el-button + .el-button { margin-left: 0; }
.judge-manual-form { margin-top: 20px; }
.judge-empty { padding: 24px 8px; text-align: center; color: var(--muted); font-size: 12px; }
@media (max-width: 1100px) {
  .judge-overview { gap: 12px; }
  .judge-card { padding: 16px; }
  .judge-page-head { flex-wrap: wrap; }
  .judge-head-actions { justify-content: flex-start; }
  .judge-stats { grid-template-columns: 1fr 1fr; }
  .judge-stats > div:last-child { grid-column: 1 / -1; }
}
@media (max-width: 760px) {
  .judge-overview, .judge-settings-grid { grid-template-columns: minmax(0, 1fr); gap: 12px; }
  .judge-stats { grid-template-columns: repeat(3, minmax(0, 1fr)); margin-top: 12px; }
  .judge-stats > div:last-child { grid-column: auto; }
  .judge-card-foot { margin-top: 10px; }
}
@media (max-width: 600px) {
  .judge-card { padding: 14px; }
  .judge-analysis-table { display: none; }
  .judge-analysis-cards { display: grid; gap: 12px; }
  .judge-analysis-card { min-width: 0; border: 1px solid var(--line); border-radius: 10px; padding: 12px; }
  .judge-analysis-card .judge-card-head { margin-bottom: 8px; }
  .judge-mobile-summary { margin: 8px 0; color: var(--title); overflow-wrap: anywhere; font-size: 13px; line-height: 1.8; }
  .judge-mobile-meta { display: flex; flex-wrap: wrap; gap: 6px 12px; margin: 12px 0; color: var(--muted); font-size: 12px; }
  .judge-mobile-actions > .el-button:first-child { min-width: 0; flex: 1; justify-content: flex-start; }
  .judge-mobile-actions > .el-button:first-child :deep(span) { overflow: hidden; text-overflow: ellipsis; }
  .judge-mobile-actions > .el-button:last-child { flex: none; }
  .judge-filters { display: grid; grid-template-columns: minmax(0, 1fr); }
  .judge-filters > div, .judge-filters .judge-search { width: 100%; max-width: none; min-width: 0; }
  .judge-page :deep(.el-button--small) { min-height: var(--control-height); }
  .judge-head-actions .el-button { min-height: var(--control-height); }
  .judge-stats dd { font-size: 18px; }
  .judge-tabs :deep(.el-tabs__item) { padding: 0 12px; }
  .judge-pager :deep(.el-pagination__total), .judge-pager :deep(.el-pagination__sizes) { display: none; }
  .judge-pager :deep(.el-pagination) { gap: 4px; }
  .judge-config-kv > div { grid-template-columns: 118px minmax(0, 1fr); }
}
</style>
