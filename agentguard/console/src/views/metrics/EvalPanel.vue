<template>
  <div class="mt-evaluation">
    <div class="mt-service-bar">
      <el-radio-group v-model="evaluationView" size="small" class="mt-view-switch" aria-label="评测视图">
        <el-radio-button value="current"><el-icon aria-hidden="true"><DataLine /></el-icon>当前评测</el-radio-button>
        <el-radio-button value="history"><el-icon aria-hidden="true"><Timer /></el-icon>任务历史<span class="mt-tab-count">{{ evalRuns.length }}</span></el-radio-button>
      </el-radio-group>
      <div class="mt-actions"><el-tag size="small" effect="plain" :type="serviceTag">{{ serviceText }}</el-tag><el-button size="small" :loading="evalRefreshing" :disabled="evalBusy || evalCancelling || evalRefreshing" @click="refreshEvaluation()"><el-icon class="btn-ic" aria-hidden="true"><Refresh /></el-icon>刷新</el-button><el-button size="small" type="primary" :disabled="!canStart" @click="openCreate"><el-icon class="btn-ic" aria-hidden="true"><Plus /></el-icon>新建评测</el-button></div>
    </div>
    <div v-if="evalOptions.auth_required" class="mt-token-row"><label for="mt-eval-token">评测管理令牌</label><el-input id="mt-eval-token" size="small" v-model="evalToken" type="password" show-password autocomplete="off" aria-label="评测管理令牌" placeholder="仅保存在当前页面" :disabled="working" @keyup.enter="refreshEvaluation()" /><el-button size="small" :disabled="!evalToken || working" @click="refreshEvaluation()">加载任务</el-button></div>
    <el-alert v-if="evalError" :title="evalError" type="error" :closable="false" show-icon class="my-12" />
    <el-alert v-if="activeRun && activeRun.run_id !== evalRunId" type="info" :closable="false" show-icon class="my-12"><template #title>另有评测{{ evalStatus(activeRun.status) }}</template><el-button link type="primary" size="small" @click="selectRun(activeRun.run_id)">查看执行任务</el-button></el-alert>
    <div v-if="evaluationView === 'current' && latestBySuite.length" class="mt-latest-grid" aria-label="各套件最近结束的评测">
      <section v-for="item in latestBySuite" :key="item.suite" class="mt-latest-card">
        <div class="mt-card-head"><h3><el-icon aria-hidden="true"><Collection /></el-icon>{{ suiteNames[item.suite] }}</h3><el-tag size="small" effect="plain" :type="statusTag(item.run.status)">{{ evalStatus(item.run.status) }}</el-tag></div>
        <p class="mt-note mt-latest-meta">{{ scenarioLabel(item.run.params.scenario || 'all') }} · 已处理 {{ item.run.completed || 0 }} 条</p>
        <dl class="mt-rate-pair"><div><dt>检出率</dt><dd>{{ pct(item.detection_rate) }}</dd></div><div><dt>误报率 FPR</dt><dd>{{ pct(item.false_positive_rate) }}</dd></div></dl>
        <div class="mt-card-foot"><span class="mt-note">缺少证据 {{ item.unknown || 0 }} · 请求失败 {{ item.errors || 0 }}</span><el-button link type="primary" size="small" :disabled="evalBusy || evalCancelling" :aria-label="'查看 ' + suiteNames[item.suite] + ' 最近结果'" @click="selectRun(item.run.run_id)">查看结果</el-button></div>
      </section>
    </div>

    <section v-if="evaluationView === 'history'" class="mt-history" aria-labelledby="mt-history-title">
      <div class="mt-history-overview">
        <div class="mt-history-stat"><span>最近评测任务</span><strong>{{ number(evalRuns.length) }}<small>次</small></strong><el-icon aria-hidden="true"><Timer /></el-icon></div>
        <div class="mt-history-stat"><span>已完成任务</span><strong>{{ number(completedRuns) }}<small>次</small></strong><el-icon aria-hidden="true"><CircleCheckFilled /></el-icon></div>
        <div class="mt-history-stat"><span>执行中任务</span><strong>{{ number(runningRuns) }}<small>次</small></strong><el-icon aria-hidden="true"><Refresh /></el-icon></div>
        <div class="mt-history-stat"><span>累计处理条次</span><strong>{{ number(processedSamples) }}<small>条次</small></strong><el-icon aria-hidden="true"><Document /></el-icon></div>
      </div>
      <div class="mt-history-body">
        <div class="mt-card-head"><h3 id="mt-history-title"><el-icon aria-hidden="true"><List /></el-icon>评测任务历史</h3><span class="mt-note">{{ filteredRuns.length }} / {{ evalRuns.length }} 条 · 最近 20 条</span></div>
        <div class="mt-history-filters">
          <el-input v-model="historyQuery" size="small" clearable aria-label="搜索评测任务" placeholder="搜索套件、场景或任务 ID"><template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template></el-input>
          <el-select v-model="historySuite" size="small" aria-label="筛选任务套件" placeholder="全部套件"><el-option label="全部套件" value="" /><el-option v-for="suite in historySuites" :key="suite" :label="suiteNames[suite] || suite" :value="suite" /></el-select>
          <el-select v-model="historyStatus" size="small" aria-label="筛选任务状态" placeholder="全部状态"><el-option label="全部状态" value="" /><el-option v-for="status in historyStatuses" :key="status" :label="evalStatus(status)" :value="status" /></el-select>
          <el-button size="small" plain :disabled="!historyFiltering" @click="resetHistory">重置</el-button>
        </div>
        <el-table :data="pagedRuns" stripe size="small" class="mt-history-table" :row-class-name="({row}) => row.run_id === evalRunId ? 'mt-selected-run' : ''" :empty-text="historyFiltering ? '没有匹配的任务' : '暂无评测任务'">
          <el-table-column label="任务 ID" min-width="160"><template #default="{row}"><span class="mt-run-id mono" :title="row.run_id">{{ row.run_id }}</span></template></el-table-column>
          <el-table-column label="套件" min-width="145"><template #default="{row}">{{ suiteNames[runSuite(row)] || runSuite(row) }}</template></el-table-column>
          <el-table-column label="场景" min-width="125"><template #default="{row}">{{ scenarioLabel(row.params?.scenario || 'all') }}</template></el-table-column>
          <el-table-column label="已处理 / 总数" width="115" align="right"><template #default="{row}">{{ number(row.completed || 0) }} / {{ number(row.total) }}</template></el-table-column>
          <el-table-column label="检出率" width="90" align="right"><template #default="{row}">{{ pct(row.summary?.detection_rate) }}</template></el-table-column>
          <el-table-column label="误报率 FPR" width="105" align="right"><template #default="{row}">{{ pct(row.summary?.false_positive_rate) }}</template></el-table-column>
          <el-table-column label="时间" width="165"><template #default="{row}"><span class="mt-note">{{ stamp(row.created_at) }}</span></template></el-table-column>
          <el-table-column label="状态" width="95"><template #default="{row}"><el-tag size="small" effect="plain" :type="statusTag(row.status)">{{ evalStatus(row.status) }}</el-tag></template></el-table-column>
          <el-table-column label="操作" width="90" fixed="right"><template #default="{row}"><el-button link type="primary" size="small" :disabled="evalBusy || evalCancelling || evalDownloading" :aria-label="'查看评测任务 ' + row.run_id" @click="selectRun(row.run_id)">查看报告</el-button></template></el-table-column>
        </el-table>
        <div v-if="filteredRuns.length > 10" class="mt-pager"><el-pagination v-model:current-page="historyPage" :total="filteredRuns.length" :page-size="10" :pager-count="5" layout="total, prev, pager, next" size="small" aria-label="评测任务历史分页" /></div>
      </div>
    </section>
    <div v-show="evaluationView === 'current'" class="mt-eval-workspace">
      <div class="mt-run-content">
        <section v-if="job" class="mt-job" aria-labelledby="mt-job-title">
          <div class="mt-job-head"><div class="mt-job-heading"><h3 id="mt-job-title"><el-icon aria-hidden="true"><DataAnalysis /></el-icon>{{ suiteNames[runSuite(job)] || runSuite(job) }}<el-tag size="small" effect="plain" :type="statusTag(job.status)">{{ evalStatus(job.status) }}</el-tag></h3><p class="mt-note mono mt-run-id" :title="job.run_id">{{ job.run_id }}</p></div><div class="mt-actions"><el-button v-if="isEvalActive(job.status)" size="small" :loading="evalCancelling" :disabled="working || job.status === 'CANCELLING'" @click="cancelEvaluation">取消评测</el-button><el-button v-else size="small" :loading="evalDownloading" :disabled="working" @click="downloadEvaluation"><el-icon class="btn-ic" aria-hidden="true"><Document /></el-icon>下载报告</el-button></div></div>
          <div class="mt-job-meta"><span>{{ scenarioLabel(job.params?.scenario || 'all') }}</span><span>回放上限 {{ job.params?.limit ?? job.total ?? '—' }}</span><span v-if="job.dataset">数据集 {{ job.dataset.dataset_id }}</span><span v-if="job.rules_source === 'builtin'">规则：内置</span><span>开始 {{ stamp(job.started_at || job.created_at) }}</span><span v-if="job.finished_at">结束 {{ stamp(job.finished_at) }}</span></div>
          <div class="mt-progress-label" role="status" aria-live="polite"><span>{{ job.phase || evalStatus(job.status) }}<span v-if="evalRefreshing" class="mt-note"> · 更新中</span></span><span>已处理 {{ job.completed || 0 }} / {{ job.total || '待确定' }}</span></div><el-progress :percentage="progress" :status="progressStatus" :stroke-width="7" />
          <el-alert v-if="job.error" :title="job.error" type="error" :closable="false" show-icon class="my-12" />
          <el-tabs v-model="resultTab" class="mt-result-tabs" aria-label="本次评测结果">
            <el-tab-pane label="结果总览" name="overview">
              <div class="mt-kpi-grid"><div class="mt-kpi"><span>检出率</span><strong>{{ pct(sm.detection_rate) }}</strong><el-icon aria-hidden="true"><Aim /></el-icon></div><div class="mt-kpi"><span>误报率 FPR</span><strong>{{ pct(sm.false_positive_rate) }}</strong><el-icon aria-hidden="true"><Warning /></el-icon></div><div class="mt-kpi"><span>精确率</span><strong>{{ pct(sm.precision) }}</strong><el-icon aria-hidden="true"><CircleCheckFilled /></el-icon></div><div class="mt-kpi"><span>已归类样本</span><strong>{{ number(sm.evaluated ?? matrixTotal) }}</strong><el-icon aria-hidden="true"><Document /></el-icon></div></div>

              <div class="mt-result-grid">
                <section class="mt-result-block"><h4>样本归类</h4><table class="mt-matrix"><thead><tr><th scope="col">样本</th><th scope="col">{{ isOffline ? '检出 / 判定' : '检出 / 阻断' }}</th><th scope="col">放行</th></tr></thead><tbody><tr><th scope="row">恶意</th><td><b>TP {{ sm.tp ?? 0 }}</b><span>检出</span></td><td><b class="c-crit">FN {{ sm.fn ?? 0 }}</b><span>漏检</span></td></tr><tr><th scope="row">正常</th><td><b class="c-crit">FP {{ sm.fp ?? 0 }}</b><span>误报</span></td><td><b>TN {{ sm.tn ?? 0 }}</b><span>正常放行</span></td></tr></tbody></table><dl class="mt-inline-stats"><div><dt>缺少证据</dt><dd>{{ sm.unknown ?? 0 }}</dd></div><div><dt>请求失败</dt><dd>{{ sm.errors ?? 0 }}</dd></div></dl></section>
                <section class="mt-result-block"><h4>结果核验</h4><div class="mt-check-block"><b>{{ isCC ? '逐步期望一致' : '副作用核验' }}</b><dl class="mt-inline-stats"><div><dt>通过</dt><dd>{{ sm.effect_checks?.passed ?? 0 }}</dd></div><div><dt>失败</dt><dd class="c-crit">{{ sm.effect_checks?.failed ?? 0 }}</dd></div><div><dt>未核验</dt><dd>{{ sm.effect_checks?.not_checked ?? 0 }}</dd></div></dl></div><div class="mt-check-block"><b>{{ isCC ? '正常流程零拦截' : '业务断言' }}</b><dl class="mt-inline-stats"><div><dt>通过</dt><dd>{{ sm.business_checks?.passed ?? 0 }}</dd></div><div><dt>失败</dt><dd class="c-crit">{{ sm.business_checks?.failed ?? 0 }}</dd></div><div><dt>{{ isCC ? '不适用 / 未核验' : '未核验' }}</dt><dd>{{ sm.business_checks?.not_checked ?? 0 }}</dd></div></dl></div></section>
              </div>
              <div class="mt-measurements"><div><h4>决策次数</h4><dl class="mt-inline-stats"><div><dt>放行</dt><dd>{{ sm.decision_counts?.ALLOW ?? 0 }}</dd></div><div><dt>待确认</dt><dd>{{ sm.decision_counts?.ASK ?? 0 }}</dd></div><div><dt>拦截</dt><dd>{{ sm.decision_counts?.DENY ?? 0 }}</dd></div></dl></div><div v-if="sm.latency"><h4>{{ isCC ? 'PreToolUse 端到端延迟' : '决策延迟' }} <span class="mt-note">ms · {{ sm.latency.samples ?? '—' }} 个采样</span></h4><dl class="mt-inline-stats"><div><dt>P50</dt><dd>{{ number(sm.latency.p50) }}</dd></div><div><dt>P95</dt><dd>{{ number(sm.latency.p95) }}</dd></div><div><dt>最大</dt><dd>{{ number(sm.latency.max) }}</dd></div></dl></div></div>
              <details v-if="issueRows.length" class="mt-disclosure"><summary>缺少证据与请求失败的原因 · {{ issueRows.length }} 类</summary><ul class="mt-reasons"><li v-for="(r,i) in issueRows" :key="i"><span>{{ r.type }}</span><code>{{ r.reason }}</code><b>{{ r.count }}</b></li></ul></details>
              <details v-if="job.note" class="mt-disclosure"><summary>任务备注</summary><p v-if="job.note" class="mt-note mt-wrap">{{ job.note }}</p></details>
            </el-tab-pane>
            <el-tab-pane label="样本明细" name="samples">
              <div class="mt-sample-filters"><div class="mt-search-field"><label for="mt-sample-query">搜索样本</label><el-input id="mt-sample-query" v-model="sampleQuery" size="small" clearable aria-label="搜索评测样本" placeholder="场景、样本编号、任务证据或原因" /></div><div><label for="mt-sample-outcome">结果</label><el-select id="mt-sample-outcome" v-model="sampleOutcome" size="small" clearable aria-label="筛选评测结果" placeholder="全部结果"><el-option v-for="o in ['TP','FP','FN','TN','UNKNOWN','ERROR']" :key="o" :value="o" :label="evalOutcome(o)" /></el-select></div><div><label for="mt-sample-check">核验</label><el-select id="mt-sample-check" v-model="sampleCheck" size="small" clearable aria-label="筛选评测核验" placeholder="全部核验"><el-option label="存在核验失败" value="failed" /><el-option label="存在未核验" value="unchecked" /></el-select></div></div>
              <div class="mt-table-caption"><span class="mt-note">已加载最近 {{ loadedRows.length }} 条 · {{ filteredRows.length }} 条{{ sampleFiltering ? '匹配' : '可查看' }}</span><el-button v-if="sampleFiltering" link type="primary" size="small" @click="clearSampleFilters">清除筛选</el-button></div>
              <el-table :data="pagedRows" size="small" class="mt-sample-table" :empty-text="sampleFiltering ? '没有匹配的样本' : '尚无已完成样本'">
                <el-table-column label="场景 / 用例" min-width="175"><template #default="{row}"><div>{{ scenarioLabel(row.scenario) }}</div><div v-if="row.fixture || row.case || row.instance_id" class="mt-note mono mt-wrap">{{ row.fixture || row.case || row.instance_id }}</div></template></el-table-column>
                <el-table-column label="结果" width="100"><template #default="{row}"><el-tag size="small" effect="plain" :type="outcomeTag(row.outcome)">{{ evalOutcome(row.outcome) }}</el-tag></template></el-table-column>
                <el-table-column label="决策次数" min-width="125"><template #default="{row}"><span class="mono mt-wrap">{{ decisionText(row.decisions) }}</span></template></el-table-column>
                <el-table-column :label="isCC ? '逐步期望 / 零拦截' : '副作用 / 业务断言'" min-width="150"><template #default="{row}"><div class="mt-check-tags"><el-tag size="small" effect="plain" :type="checkTagType(row.effect_ok)">{{ checkText(row.effect_ok) }}</el-tag><span>/</span><el-tag size="small" effect="plain" :type="checkTagType(row.business_ok)">{{ checkText(row.business_ok) }}</el-tag></div></template></el-table-column>
                <el-table-column label="耗时 ms" width="90"><template #default="{row}">{{ number(row.elapsed_ms) }}</template></el-table-column>
                <el-table-column label="证据" width="102" fixed="right"><template #default="{row}"><el-button link type="primary" size="small" @click="openSample(row)">查看明细</el-button><el-button link type="primary" size="small" :disabled="!row.trace_id" @click="openChain(row.trace_id)">会话链路</el-button></template></el-table-column>
              </el-table><div class="mt-pager" v-if="filteredRows.length > 10"><el-pagination size="small" background :pager-count="5" layout="total, sizes, prev, pager, next" :page-sizes="[10,20,50]" :total="filteredRows.length" v-model:current-page="samplePage" v-model:page-size="samplePageSize" /></div>
            </el-tab-pane>
            <el-tab-pane label="分场景结果" name="scenarios"><el-table :data="scenarioBreakdown" size="small" empty-text="暂无分场景结果" class="mt-breakdown-table"><el-table-column label="场景" min-width="160"><template #default="{row}">{{ scenarioLabel(row.name) }}</template></el-table-column><el-table-column label="TP / FP / FN / TN" min-width="155"><template #default="{row}"><span class="mono mt-wrap">{{ row.tp }} / {{ row.fp }} / {{ row.fn }} / {{ row.tn }}</span></template></el-table-column><el-table-column label="未知 / 错误" width="105"><template #default="{row}">{{ row.unknown || 0 }} / {{ row.errors || 0 }}</template></el-table-column><el-table-column label="检出率" width="90"><template #default="{row}">{{ pct(row.detection_rate) }}</template></el-table-column><el-table-column label="误报率 FPR" width="105"><template #default="{row}">{{ pct(row.false_positive_rate) }}</template></el-table-column><el-table-column label="精确率" width="90"><template #default="{row}">{{ pct(row.precision) }}</template></el-table-column></el-table></el-tab-pane>
          </el-tabs>
        </section>
        <section v-else class="mt-job mt-job-empty"><el-skeleton v-if="evalLoading || evalRefreshing" :rows="7" animated /><el-empty v-else :description="evalRunId ? '任务加载失败' : '暂无选中任务'" :image-size="80" /></section>
      </div>
    </div>
    <el-dialog v-model="createVisible" title="新建评测" class="detail-dialog metrics-run-dialog" width="min(640px, 94vw)" top="6vh" append-to-body :close-on-click-modal="false" :close-on-press-escape="!evalBusy" :show-close="!evalBusy">
      <el-form size="small" label-position="top" :disabled="evalBusy" @submit.prevent="submitCreate">
        <el-form-item label="评测套件"><el-radio-group v-model="evalSuite" aria-label="评测套件"><el-radio-button v-for="s in startSuites" :key="s" :value="s">{{ suiteNames[s] || s }}</el-radio-button></el-radio-group></el-form-item>
        <el-form-item label="场景"><el-select v-model="createScenario" aria-label="评测场景"><el-option v-for="s in suiteScenarios" :key="s" :value="s" :label="scenarioLabel(s)" /></el-select></el-form-item>
        <div class="mt-create-fields">
          <el-form-item label="最多回放条数"><el-input-number :key="evalSuite" v-model="createLimit" :min="1" :max="evalMaxLimit" :precision="0" aria-label="最多回放条数" /></el-form-item>
        </div>
      </el-form>
      <el-alert v-if="evalError" :title="evalError" type="error" :closable="false" show-icon class="my-12" /><template #footer><el-button size="small" :disabled="evalBusy" @click="createVisible = false">取消</el-button><el-button size="small" type="primary" :loading="evalBusy" :disabled="!canStart || !validParams" @click="submitCreate">开始评测</el-button></template>
    </el-dialog>
    <el-dialog v-model="sampleVisible" title="评测样本明细" class="detail-dialog metrics-sample-dialog" width="min(800px, 94vw)" top="6vh" append-to-body><template v-if="detail"><div class="mt-detail-heading"><el-tag size="small" :type="outcomeTag(detail.outcome)" effect="plain">{{ evalOutcome(detail.outcome) }}</el-tag><b>{{ scenarioLabel(detail.scenario) }}</b></div><dl class="mt-detail-kv"><dt v-if="detail.trace_id">任务证据</dt><dd v-if="detail.trace_id" class="mono">{{ detail.trace_id }}</dd><dt v-if="detail.fixture || detail.case || detail.instance_id">夹具 / 样本</dt><dd v-if="detail.fixture || detail.case || detail.instance_id" class="mono">{{ detail.fixture || detail.case || detail.instance_id }}</dd><dt v-if="detail.reasons?.length">判定依据</dt><dd v-if="detail.reasons?.length" class="mono mt-wrap">{{ detail.reasons.join(' · ') }}</dd><dt>决策计数</dt><dd>{{ decisionText(detail.decisions) }}</dd><dt>样本耗时</dt><dd>{{ number(detail.elapsed_ms) }} ms</dd><dt>{{ isCC ? '逐步期望' : '副作用核验' }}</dt><dd>{{ checkText(detail.effect_ok) }}<span v-if="detail.effect_note" class="mt-note mono"> · {{ detail.effect_note }}</span></dd><dt>{{ isCC ? '零拦截' : '业务断言' }}</dt><dd>{{ checkText(detail.business_ok) }}<span v-if="detail.business_note" class="mt-note mono"> · {{ detail.business_note }}</span></dd><dt v-if="detail.first_risk">首个高风险点</dt><dd v-if="detail.first_risk">{{ detail.first_risk }} · {{ detail.first_risk_reason }}</dd><dt v-if="detail.unknown_reason || detail.error">缺少证据 / 错误</dt><dd v-if="detail.unknown_reason || detail.error" class="mono">{{ detail.unknown_reason || detail.error }}</dd></dl><details class="mt-disclosure"><summary>原始样本数据</summary><pre class="mt-json mono">{{ JSON.stringify(detail,null,2) }}</pre></details></template><template #footer><el-button size="small" @click="sampleVisible = false">关闭</el-button><el-button size="small" type="primary" :disabled="!detail?.trace_id" @click="viewSampleChain">查看会话链路</el-button></template></el-dialog>
  </div>
</template>
<script setup>
import { computed, ref, watch, onMounted, onBeforeUnmount } from "vue";
import { tab, metricsTab, openChain } from "../../store/runtime";
import { pct as formatPct, fmt } from "../../utils/format";
import { evalOptions, evalToken, evalScenario, evalSuite, evalLimit, evalParams, evalMaxLimit, evalBusy, evalCancelling, evalRefreshing, evalLoading, evalLoaded, evalDownloading, suiteNames, runSuite, suiteScenarios, latestBySuite, evalRuns, evalRunId, evalJob, evalError, evalActive, isEvalActive, evalStatus, evalOutcome, refreshEvaluation, loadEvaluation, startEvaluation, cancelEvaluation, downloadEvaluation } from "../../store/evaluation";

const working = computed(() => evalBusy.value || evalCancelling.value || evalRefreshing.value || evalLoading.value || evalDownloading.value);
const startSuites = computed(() => Object.keys(evalOptions.value.suites || {}).filter(s => ['claude-code', 'offline-corpus'].includes(s)));
const canStart = computed(() => evalLoaded.value && evalOptions.value.enabled && evalOptions.value.worker_online && (!evalOptions.value.auth_required || !!evalToken.value.trim()) && !working.value && !evalActive.value && startSuites.value.length > 0);
const serviceText = computed(() => !evalLoaded.value ? '正在连接' : typeof evalOptions.value.enabled !== 'boolean' ? '状态未获取' : !evalOptions.value.enabled ? '评测未启用' : !evalOptions.value.worker_online ? '执行服务离线' : evalActive.value ? '有任务执行中' : '执行服务就绪');
const serviceTag = computed(() => evalOptions.value.enabled && evalOptions.value.worker_online ? 'success' : 'info');

const statusTag = s => ['FAILED','TIMED_OUT','INTERRUPTED'].includes(s) ? 'danger' : ['RUNNING','QUEUED','CANCELLING','PARTIAL'].includes(s) ? 'warning' : s === 'COMPLETED' ? 'success' : 'info';
const outcomeTag = s => ['FP','FN','ERROR'].includes(s) ? 'danger' : s === 'UNKNOWN' ? 'warning' : 'success';
const THREATS = {'G-1':'间接注入','G-2':'凭证读取','G-3':'下载执行','G-4':'恶意 MCP','G-5':'持久化','G-6':'篡改防护','G-7':'未受管 MCP','G-8':'子 Agent','G-9':'改写注入','G-10':'数据流外带',BENIGN:'正常开发'};
Object.assign(THREATS, {'B-OPS':'运维排障','B-RD':'研发协作','B-SEC':'安全检查','B-SUP':'客户支持',
  'C1-A':'代码载荷','C1-B':'上传路径','C2-A':'越权调用','C2-B':'数据外带','C2-C':'下载执行','C2-D':'技能注入','M-1':'恶意 MCP'});
const scenarioLabel = s => s === 'all' ? '全部场景' : THREATS[s] ? s + ' ' + THREATS[s] : s || '—';
const stamp = value => value ? fmt(typeof value === 'number' ? new Date(value*1000).toISOString() : value).replace(/\.000$/,'') : '—';
const pct = value => value == null ? '—' : formatPct(value);
const number = value => value === null || value === undefined || !Number.isFinite(Number(value)) ? '—' : Number(value).toLocaleString('zh-CN',{maximumFractionDigits:1});

const activeRun = computed(() => evalRuns.value.find(r => isEvalActive(r.status)));
const evaluationView = ref('current');
const historyQuery = ref(''), historySuite = ref(''), historyStatus = ref(''), historyPage = ref(1);
const historySuites = computed(() => [...new Set(evalRuns.value.map(runSuite))]);
const historyStatuses = computed(() => [...new Set(evalRuns.value.map(run => run.status))]);
const completedRuns = computed(() => evalRuns.value.filter(run => run.status === 'COMPLETED').length);
const runningRuns = computed(() => evalRuns.value.filter(run => isEvalActive(run.status)).length);
const processedSamples = computed(() => evalRuns.value.reduce((sum, run) => sum + (Number(run.completed) || 0), 0));
const historyFiltering = computed(() => !!historyQuery.value.trim() || !!historySuite.value || !!historyStatus.value);
function resetHistory() { historyQuery.value = historySuite.value = historyStatus.value = ''; }
const filteredRuns = computed(() => {
  const q = historyQuery.value.trim().toLowerCase();
  return evalRuns.value.filter(r => (!historySuite.value || runSuite(r) === historySuite.value)
    && (!historyStatus.value || r.status === historyStatus.value)
    && (!q || [r.run_id,suiteNames[runSuite(r)],r.params?.scenario,scenarioLabel(r.params?.scenario),evalStatus(r.status)].some(v => String(v || '').toLowerCase().includes(q))));
});
const pagedRuns = computed(() => filteredRuns.value.slice((historyPage.value - 1) * 10, historyPage.value * 10));
watch([historyQuery, historySuite, historyStatus], () => { historyPage.value = 1; });
watch(() => filteredRuns.value.length, count => { historyPage.value = Math.min(historyPage.value, Math.max(1, Math.ceil(count / 10))); });
function selectRun(id) {
  if (evalBusy.value || evalCancelling.value || evalDownloading.value) return;
  evalRunId.value = id; evaluationView.value = 'current'; loadEvaluation();
}
const job = computed(() => evalJob.value?.run_id === evalRunId.value ? evalJob.value : null);
const sm = computed(() => job.value?.summary || {});
const matrixTotal = computed(() => ['tp','fp','fn','tn'].reduce((n,k) => n + (sm.value[k] || 0),0));
const isOffline = computed(() => runSuite(job.value) === 'offline-corpus');
const isCC = computed(() => runSuite(job.value).startsWith('claude-code'));
const progress = computed(() => job.value?.total ? Math.max(0,Math.min(100,Math.round(job.value.completed*100/job.value.total))) : 0);
const progressStatus = computed(() => ['FAILED','TIMED_OUT','INTERRUPTED'].includes(job.value?.status) ? 'exception' : undefined);
const resultTab = ref('overview');
const scenarioBreakdown = computed(() => Object.entries(sm.value.by_scenario || {}).map(([name,s]) => ({name,...s})));
const issueRows = computed(() => [...Object.entries(sm.value.unknown_reasons || {}).map(([reason,count]) => ({type:'缺少证据',reason,count})),...Object.entries(sm.value.error_reasons || {}).map(([reason,count]) => ({type:'请求失败',reason,count}))]);
const decisionText = counts => ['ALLOW','ASK','DENY'].filter(k => counts?.[k]).map(k => k + '×' + counts[k]).join(' ') || '—';
const checkText = value => value === true ? '通过' : value === false ? '失败' : '未核验';
const checkTagType = value => value === true ? 'success' : value === false ? 'danger' : 'info';
const sampleQuery = ref(''), sampleOutcome = ref(''), sampleCheck = ref(''), samplePage = ref(1), samplePageSize = ref(10);
const loadedRows = computed(() => job.value?.rows || []);
const sampleFiltering = computed(() => Boolean(sampleQuery.value.trim() || sampleOutcome.value || sampleCheck.value));
const filteredRows = computed(() => {
  const q = sampleQuery.value.trim().toLowerCase();
  return loadedRows.value.filter(r => {
    if (sampleOutcome.value && r.outcome !== sampleOutcome.value) return false;
    if (sampleCheck.value === 'failed' && r.effect_ok !== false && r.business_ok !== false) return false;
    if (sampleCheck.value === 'unchecked' && r.effect_ok != null && r.business_ok != null) return false;
    return !q || [r.trace_id,r.scenario,scenarioLabel(r.scenario),r.fixture,r.case,r.instance_id,r.reasons?.join(' '),r.first_risk,r.first_risk_reason,r.effect_note,r.business_note,r.unknown_reason,r.error].some(v => String(v || '').toLowerCase().includes(q));
  });
});
const pagedRows = computed(() => filteredRows.value.slice((samplePage.value-1)*samplePageSize.value,samplePage.value*samplePageSize.value));
function clearSampleFilters() { sampleQuery.value = sampleOutcome.value = sampleCheck.value = ''; samplePage.value = 1; }
watch([sampleQuery,sampleOutcome,sampleCheck,samplePageSize], () => { samplePage.value = 1; });
watch(() => filteredRows.value.length, n => { samplePage.value = Math.min(samplePage.value,Math.max(1,Math.ceil(n/samplePageSize.value))); });
watch(evalRunId, () => { resultTab.value = 'overview'; clearSampleFilters(); });
const createVisible = ref(false), sampleVisible = ref(false), detail = ref(null);
const createScenario = computed({ get: () => evalParams.value.scenario, set: value => { evalScenario.value = value; } });
const createLimit = computed({ get: () => evalParams.value.limit, set: value => { evalLimit.value = value; } });
watch(evalSuite, suite => {
  evalScenario.value = 'all';
  evalLimit.value = evalOptions.value.suite_defaults?.[suite] || Math.min(100, evalMaxLimit.value);
});
watch(startSuites, suites => { if (suites.length && !suites.includes(evalSuite.value)) evalSuite.value = suites[0]; });
watch(suiteScenarios, scenarios => { if (!scenarios.includes(evalScenario.value)) evalScenario.value = scenarios[0] || 'all'; });
const validParams = computed(() => {
  const { suite, scenario, limit } = evalParams.value;
  return startSuites.value.includes(suite) && suiteScenarios.value.includes(scenario) && Number.isInteger(limit) && limit >= 1 && limit <= evalMaxLimit.value;
});
function openCreate() { if (canStart.value) { evalError.value = ''; createVisible.value = true; } }
async function submitCreate() { if (canStart.value && validParams.value && await startEvaluation()) { createVisible.value = false; evaluationView.value = 'current'; resultTab.value = 'overview'; resetHistory(); } }
function openSample(row) { detail.value = row; sampleVisible.value = true; }
function viewSampleChain() { if (detail.value?.trace_id) { sampleVisible.value = false; openChain(detail.value.trace_id); } }
const visible = () => tab.value === 'metrics' && metricsTab.value === 'eval';
let timer;
watch([tab,metricsTab], () => { if (visible()) refreshEvaluation(); });
onMounted(() => { if (visible()) refreshEvaluation(); timer = setInterval(() => { if (visible() && evalActive.value && !working.value && !createVisible.value) refreshEvaluation({quiet:true}); },2000); });
onBeforeUnmount(() => clearInterval(timer));
</script>
