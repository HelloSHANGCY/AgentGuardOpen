<template>
  <section v-show="tab === 'threat'" class="threat-page">
    <ConsolePageHeader title="威胁中心" class="tc-header">
      <template #title-extra>
        <el-popover placement="bottom-start" trigger="click" :width="330">
          <template #reference>
            <button type="button" class="tc-help" aria-label="数据范围说明">
              <el-icon aria-hidden="true"><QuestionFilled /></el-icon>
            </button>
          </template>
          <p class="tc-scope-title">当前加载范围</p>
          <p class="tc-scope-text">
            最近 400 条阻断、400 条需确认决策、200 条模型放行、200 条行为观察，以及最近 200 条风险研判。
          </p>
          <p class="tc-scope-text">
            同一会话、原因、来源、工具、对象和处置相同的重复触发合并，级别取最高值，时间取最近一次。概览与筛选只针对这些已加载记录，不代表全部历史数据；正常放行可在运行审计中查看。
          </p>
          <p class="tc-scope-text">图表按每次触发的时间和级别统计，包含模型研判与行为观察；同一决策只计一次。“已阻断”只统计实际 DENY 决策。热点按来源与主体汇总，圆点大小表示触发次数，不表示地理位置。点击类型或热点可筛选对应时段的记录。</p>
        </el-popover>
      </template>
      <el-button :loading="threatsLoading" @click="refreshRecords">
        <el-icon v-if="!threatsLoading" class="btn-ic" aria-hidden="true"><Refresh /></el-icon>刷新记录
      </el-button>
    </ConsolePageHeader>

    <div class="tc-overview">
      <div class="tc-summary" aria-label="风险记录概览">
        <button
          v-for="card in summaryCards"
          :key="card.key"
          type="button"
          class="tc-summary-card"
          :class="['tc-tone-' + card.tone, { active: scope === card.key }]"
          :aria-pressed="scope === card.key"
          :aria-label="'查看' + card.label"
          @click="setScope(card.key)"
        >
          <div class="tc-summary-copy">
            <span class="tc-summary-label">{{ card.label }}</span>
            <div class="tc-summary-value">
              {{ recordsUpdatedAt ? countText(card.count) : "—" }}<small>条</small>
            </div>
            <span v-if="card.caption && recordsUpdatedAt" class="tc-summary-caption">{{ card.caption }}</span>
          </div>
          <el-icon class="tc-summary-icon" aria-hidden="true"><component :is="card.icon" /></el-icon>
        </button>
      </div>
      <div v-if="latestBlockedAlert" class="tc-latest">
        <div class="tc-latest-mark">
          <el-icon aria-hidden="true"><CircleClose /></el-icon><span>最近阻断</span>
        </div>
        <div class="tc-latest-content">
          <strong>{{ threatText(latestBlockedAlert.latest.reason_code) }}</strong>
          <span class="ellipsis">{{ latestBlockedAlert.source.label }}</span>
        </div>
        <time class="tc-note mono tc-latest-time" :datetime="latestBlockedAlert.last_at">{{ fmtTime(latestBlockedAlert.last_at).slice(0, 8) }}</time>
        <el-button link type="primary" size="small" @click="openDetail(latestBlockedAlert)">
          查看详情<el-icon class="el-icon--right" aria-hidden="true"><ArrowRight /></el-icon>
        </el-button>
      </div>
    </div>
    <el-alert v-if="analysesUnavailable" class="tc-partial" title="模型研判记录读取失败" type="warning" show-icon :closable="false" />

    <ThreatVisualizations :records="records" :updated-at="recordsUpdatedAt" :loaded="!!recordsUpdatedAt || !!threatsError" :error="threatsError" :paused="isPaused" :selection="visualizationSelection" @select="visualizationSelection = $event" />

    <div class="tc-tools">
      <div class="tc-search-row">
        <el-input
          v-model="fText"
          class="tc-search"
          placeholder="搜索告警、对象、工具、来源或会话"
          clearable
          aria-label="搜索风险记录"
        ><template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template></el-input>
        <div class="tc-severity-filter" role="group" aria-label="筛选风险级别">
          <button type="button" :class="{ active: !fSev }" :aria-pressed="!fSev" @click="fSev = ''">全部</button>
          <button
            v-for="(label, key) in severityLabels"
            :key="key"
            type="button"
            :class="['tc-filter-' + key, { active: fSev === key }]"
            :aria-pressed="fSev === key"
            @click="fSev = fSev === key ? '' : key"
          >{{ label }}</button>
        </div>
        <el-select v-model="fDecision" class="tc-primary-select" placeholder="全部处置" clearable aria-label="筛选具体处置" @change="scope = 'all'">
          <el-option v-for="(item, key) in DISPOSITIONS" :key="key" :label="item.label" :value="key" />
        </el-select>
        <el-select v-model="fSource" class="tc-primary-select" placeholder="全部来源" clearable aria-label="筛选记录来源">
          <el-option v-for="item in sourceOptions" :key="item.key" :label="item.label" :value="item.key" />
        </el-select>
        <div class="tc-filter-actions">
          <el-button class="tc-follow-button" :type="isPaused ? 'primary' : 'default'" :disabled="!recordsUpdatedAt" @click="toggleFollowing">
            <el-icon class="btn-ic" aria-hidden="true"><VideoPlay v-if="isPaused" /><VideoPause v-else /></el-icon>{{ isPaused ? '恢复实时' : '暂停实时' }}
          </el-button>
          <FilterToggle v-model="advancedOpen" controls="threat-advanced-filters" :count="advancedCount" />
          <el-button text :disabled="!hasFilters" @click="resetFilters"><el-icon class="btn-ic" aria-hidden="true"><RefreshLeft /></el-icon>重置</el-button>
        </div>
      </div>
      <el-collapse-transition>
      <div v-show="advancedOpen" id="threat-advanced-filters" class="tc-filter-grid">
        <label><span>场景 / 会话</span>
          <el-select v-model="fScenario" placeholder="全部场景 / 会话" clearable filterable aria-label="筛选场景或会话">
            <el-option v-for="item in scenarios" :key="item" :label="item" :value="item" />
          </el-select>
        </label>
        <label><span>排序方式</span>
          <el-select v-model="sortBy" aria-label="风险记录排序">
            <el-option label="最近发生" value="recent" /><el-option label="风险级别优先" value="severity" /><el-option label="触发次数优先" value="count" />
          </el-select>
        </label>
        <label><span>大模型研判</span>
          <el-select v-model="judgmentFilter" placeholder="全部研判结果" clearable aria-label="筛选大模型研判结果">
            <el-option v-for="item in judgmentOptions" :key="item.key" :label="item.label" :value="item.key" />
          </el-select>
        </label>
      </div>
      </el-collapse-transition>
      <div v-if="activeFilters.length" class="tc-filter-chips" aria-label="已选筛选条件">
        <el-tag v-for="item in activeFilters" :key="item.key" type="info" effect="plain" size="small" closable @close="item.clear()">{{ item.label }}</el-tag>
      </div>
    </div>

    <div class="tc-panel" :class="{ 'tc-is-paused': isPaused, 'tc-is-compact': compact }">
      <div ref="listHeading" class="tc-list-heading">
        <div class="tc-list-caption">
          <el-icon class="tc-stream-icon" aria-hidden="true"><DataLine /></el-icon>
          <h3>实时风险记录</h3>
          <span class="tc-stream-state" :class="{ paused: isPaused }"><i v-if="!isPaused" class="dot" :class="{ on: sseOn }" aria-hidden="true"></i>{{ isPaused ? '已暂停' : '实时' }}</span>
          <span class="tc-result-count" aria-live="polite">{{ countText(visibleAlerts.length) }} / {{ countText(scopeCount) }} 条</span>
        </div>
        <div class="tc-list-actions">
          <div class="tc-update" aria-live="polite">
            <span :class="{ 'tc-stale': threatsError }"><i class="dot" :class="{ on: !isPaused && sseOn }" aria-hidden="true"></i>{{ streamStatus }}</span>
            <span v-if="recordsUpdatedAt" class="mono">{{ fmtTime(recordsUpdatedAt).slice(0, 8) }}</span>
          </div>
          <div class="tc-density" role="group" aria-label="表格密度">
            <button type="button" aria-label="舒适视图" title="舒适视图" :aria-pressed="!compact" :class="{ active: !compact }" @click="compact = false"><el-icon aria-hidden="true"><Tickets /></el-icon></button>
            <button type="button" aria-label="紧凑视图" title="紧凑视图" :aria-pressed="compact" :class="{ active: compact }" @click="compact = true"><el-icon aria-hidden="true"><Operation /></el-icon></button>
          </div>
          <el-popover placement="bottom-end" trigger="click" :width="170">
            <template #reference><el-button class="tc-columns-button"><el-icon class="btn-ic" aria-hidden="true"><Grid /></el-icon>列</el-button></template>
            <div class="tc-column-options" role="group" aria-label="显示表格列">
              <el-checkbox v-model="columns.source">来源 / Agent</el-checkbox>
              <el-checkbox v-model="columns.count">触发次数</el-checkbox>
              <el-checkbox v-model="columns.scenario">场景 / 会话</el-checkbox>
              <el-checkbox v-model="columns.judgment">大模型研判</el-checkbox>
            </div>
          </el-popover>
        </div>
      </div>
      <div class="tc-queue-tabs" role="group" aria-label="按处置分类">
        <button v-for="item in scopeOptions" :key="item.key" type="button" :class="{ active: scope === item.key }" :aria-pressed="scope === item.key" @click="setScope(item.key)">
          {{ item.label }}<span>{{ recordsUpdatedAt ? countText(item.count) : "—" }}</span>
        </button>
      </div>
      <el-table
        v-if="runtimeLoaded"
        :data="pagedAlerts"
        size="small"
        stripe
        row-key="key"
        class="alert-table tc-table"
        :row-class-name="rowClass"
        @row-click="openDetail"
      >
        <el-table-column label="时间" width="112">
          <template #default="{ row }">
            <time class="mono tc-row-time" :datetime="row.last_at" :title="fmt(row.last_at)">{{ fmtTime(row.last_at).slice(0, 8) }}</time>
            <div class="tc-note mono tc-row-secondary">{{ fmt(row.last_at).slice(0, 10) }}</div>
          </template>
        </el-table-column>
        <el-table-column label="级别" width="88">
          <template #default="{ row }"><span class="sev-tag" :class="'sev-' + row.severity" :title="row.severity"><i aria-hidden="true"></i>{{ severityLabels[row.severity] || row.severity }}</span></template>
        </el-table-column>
        <el-table-column key="score" label="风险评分" width="140" align="right">
          <template #header>
            <span class="tc-score-heading">风险评分
              <el-popover placement="bottom" trigger="click" :width="330">
                <template #reference><button type="button" class="tc-help tc-score-help" aria-label="风险评分说明"><el-icon aria-hidden="true"><QuestionFilled /></el-icon></button></template>
                <p>风险评分表示行为基线偏离程度，由服务端行为模型按这一步相对历史基线的罕见度、前文与意图偏离给出，数值越高偏离越大。</p>
                <p>进度条填充为当前评分，虚线为异常阈值；填充越过虚线即超阈值，并在数值旁标出超出的分值。</p>
                <p>评分用于和“级别”对照参考，不代表风险等级，也不影响处置结果。未评分或基线不可用时显示“—”；仅阈值缺失或无效时只显示评分并注明“阈值不可用”。</p>
                <p>合并记录展示最近一次发生的评分，与详情默认展示的记录一致。</p>
              </el-popover>
            </span>
          </template>
          <template #default="{ row }"><ThreatScoreCell :record="row.latest" :scale="scoreScale" /></template>
        </el-table-column>
        <el-table-column label="告警" min-width="235">
          <template #default="{ row }">
            <div class="al-title ellipsis" :title="threatText(row.latest.reason_code)">{{ threatText(row.latest.reason_code) }}</div>
            <div v-if="row.analysis" class="tc-note tc-row-secondary ellipsis" :title="row.target.object">{{ row.target.object }}</div>
          </template>
        </el-table-column>
        <el-table-column v-if="columns.source" key="source" label="来源 / Agent" min-width="130">
          <template #default="{ row }">
            <div class="tc-row-source">
              <AgentIcon v-if="agentFor(row)" :agent="agentFor(row)" :size="22" />
              <el-icon v-else aria-hidden="true"><component :is="row.analysis ? 'DataAnalysis' : 'Connection'" /></el-icon>
              <span class="ellipsis" :title="sourceLabel(row)">{{ sourceLabel(row) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="处置" width="124">
          <template #default="{ row }"><span class="dec-tag" :class="'dec-tag-' + DISPOSITIONS[row.disposition].tag">{{ DISPOSITIONS[row.disposition].label }}</span></template>
        </el-table-column>
        <el-table-column v-if="columns.judgment" key="judgment" min-width="150">
          <template #header>
            <span class="tc-judgment-heading">大模型研判
              <el-popover placement="bottom" trigger="click" :width="350">
                <template #reference><button type="button" class="tc-help tc-judgment-help" aria-label="大模型研判标签说明"><el-icon aria-hidden="true"><QuestionFilled /></el-icon></button></template>
                <p>“真实威胁 / 误报 / 不确定”来自模型对具体告警的研判；“正常 / 可疑 / 恶意”来自会话分析；“复核”结果来自危险审批。</p>
                <p>合并记录优先显示最新一次发生的结果。最新记录没有结果、较早记录已有结果时显示“部分已研判”，点击查看对应发生记录。</p>
                <p>“暂无结果”表示当前记录没有直接关联的模型结果。模型研判与实际处置分别展示。</p>
              </el-popover>
            </span>
          </template>
          <template #default="{ row }">
            <button v-if="row.judgment.hasResult || row.judgment.hasDetails" type="button" class="tc-judgment-button"
                    :aria-label="'查看大模型研判：' + row.judgment.label" :title="judgmentDescription(row.judgment)"
                    @click.stop="openJudgment(row)">
              <el-tag size="small" effect="plain" :type="row.judgment.type">{{ row.judgment.label }}<el-icon aria-hidden="true"><ArrowRight /></el-icon></el-tag>
            </button>
            <span v-else class="tc-note tc-judgment-empty">{{ row.judgment.label }}</span>
            <div v-if="row.judgment.source" class="tc-note tc-row-secondary tc-judgment-source">{{ row.judgment.source }}<template v-if="row.judgment.totalCount > 1 && row.judgment.key !== 'partial'"> · {{ row.judgment.analyzedCount }}/{{ row.judgment.totalCount }}</template></div>
          </template>
        </el-table-column>
        <el-table-column v-if="columns.count" key="count" label="触发次数" width="88" align="right">
          <template #default="{ row }"><span class="mono tc-count" :title="'首次发生：' + fmt(row.first_at)">{{ countText(row.count) }}</span></template>
        </el-table-column>
        <el-table-column v-if="columns.scenario" key="scenario" label="场景 / 会话" min-width="155">
          <template #default="{ row }"><el-button link type="primary" class="mono ellipsis al-trace" :title="'查看会话链路：' + row.latest.trace_id" @click.stop="openChain(row.latest.trace_id)">{{ scenarioOf(row.latest.trace_id) || "未提供会话" }}</el-button></template>
        </el-table-column>
        <el-table-column label="操作" width="88" fixed="right" align="center">
          <template #default="{ row }">
            <div class="tc-row-actions">
              <el-button text circle size="small" :aria-label="'查看详情：' + threatText(row.latest.reason_code)" title="查看详情" :data-review-key="row.key" @click.stop="openDetail(row)"><el-icon aria-hidden="true"><View /></el-icon></el-button>
              <el-button text circle size="small" aria-label="查看会话链路" title="查看会话链路" :disabled="!row.latest.trace_id" @click.stop="openChain(row.latest.trace_id)"><el-icon aria-hidden="true"><Share /></el-icon></el-button>
            </div>
          </template>
        </el-table-column>
        <template #empty>
          <div class="tc-empty">
            <el-icon aria-hidden="true"><component :is="threatsError && !recordsUpdatedAt ? 'Warning' : hasFilters ? 'Search' : CircleCheck" /></el-icon>
            <strong>{{ emptyTitle }}</strong>
            <el-button v-if="threatsError && !recordsUpdatedAt" size="small" @click="refreshRecords">重新加载</el-button>
            <el-button v-else-if="hasFilters" size="small" @click="resetFilters">重置筛选</el-button>
          </div>
        </template>
      </el-table>
      <el-skeleton v-else class="tc-skeleton" :rows="5" animated />
      <div class="tc-table-footer">
        <span class="tc-note">{{ visibleAlerts.length ? "第 " + ((page - 1) * pageSize + 1) + "–" + Math.min(page * pageSize, visibleAlerts.length) + " 条，共 " + countText(visibleAlerts.length) + " 条匹配记录" : "共 0 条匹配记录" }}</span>
        <el-pagination v-if="visibleAlerts.length > 10" class="tc-pagination" aria-label="风险记录分页" background size="small" :total="visibleAlerts.length" v-model:current-page="page" v-model:page-size="pageSize" :page-sizes="[10, 20, 50, 100]" :pager-count="5" layout="sizes, prev, pager, next" />
      </div>
    </div>

    <el-drawer
      v-model="detailVisible"
      class="detail-drawer tc-drawer"
      size="min(860px, 100vw)"
      @closed="review.restoreFocus"
      :title="detail ? threatText(detail.reason_code) : '风险详情'"
      append-to-body
      destroy-on-close
    >
      <template #header="{ titleId }">
        <div v-if="detail" class="dd-head">
          <div class="dd-title-row">
            <span class="sev-tag" :class="'sev-' + detail.severity">{{
              severityLabels[detail.severity] || detail.severity
            }}</span
            ><span class="dec-tag" :class="'dec-tag-' + DISPOSITIONS[alert.disposition].tag">{{
              DISPOSITIONS[alert.disposition].label
            }}</span>
            <h3 :id="titleId" class="dd-title">{{ threatText(detail.reason_code) }}</h3>
          </div>
          <div class="dd-subtitle">
            <span class="mono">{{ detail.reason_code }}</span> · {{ sourceLabel(alert) }} ·
            {{ fmt(detail.created_at)
            }}<template v-if="alert.count > 1">
              · 当前第 {{ alert.items.findIndex((d) => d.decision_id === detail.decision_id) + 1 }} /
              {{ alert.count }} 条发生记录</template
            >
          </div>
        </div>
      </template>
      <template v-if="detail">
        <div v-if="detail.resolved_at" class="dd-callout tc-disposition"><div class="dd-callout-label">处置时间</div><div class="dd-callout-text">{{ fmt(detail.resolved_at) }}</div></div>
        <AnalysisDetail v-if="alert.analysis" :record="alert.analysis" />
        <el-tabs v-else v-model="detailTab" class="tc-detail-tabs">
          <el-tab-pane label="行为概览" name="overview">
            <div
              v-if="detail.review"
              class="dd-callout"
              :class="'dd-callout-' + (detail.review.status === 'ok' ? detail.review.verdict : 'ASK')"
            >
              <div class="dd-callout-label">
                大模型危险审批 · 静态判定{{ decisionName(detail.review.static) }}
              </div>
              <div v-if="detail.review.status === 'ok'" class="dd-callout-text">
                {{ REVIEW_TEXT[detail.review.verdict]
                }}<template v-if="detail.review.verdict !== detail.review.static">（已改判）</template>：{{
                  detail.review.reason
                }}<span class="muted fs-11">
                  · {{ detail.review.model }} ·
                  {{ detail.review.cached ? "缓存" : detail.review.latency_ms + " ms" }}</span
                >
              </div>
              <div v-else class="dd-callout-text">
                {{ detail.review.status === "timeout" ? "复核超时" : "复核失败" }}，维持静态判定<span
                  class="muted fs-11"
                >
                  · {{ detail.review.error }}</span
                >
              </div>
            </div>
            <div
              v-if="detail.assessment"
              class="dd-callout"
              :class="detail.assessment.assessment === 'false_positive' ? 'dd-callout-ALLOW' : ''"
            >
              <div class="dd-callout-label">大模型异步分析 · 事后研判</div>
              <div class="dd-callout-text">
                {{ assessmentText(detail.assessment) }}：{{ detail.assessment.note }}
              </div>
            </div>
            <section class="dd-section">
              <h4 class="dd-section-title">触发行为</h4>
              <dl class="dd-kv tc-context">
                <dt>来源</dt>
                <dd>
                  {{ alert.source.label
                  }}<span v-if="detail.context?.actor" class="muted"> · {{ detail.context.actor }}</span>
                </dd>
                <dt>工具</dt>
                <dd class="mono">{{ [detail.server, detail.tool].filter(Boolean).join(" / ") || "—" }}</dd>
                <template v-if="!executionCommand(detail)">
                  <dt>{{ alertTarget(detail).verb || "对象" }}</dt>
                  <dd class="mono">{{ alertTarget(detail).object || "—" }}</dd>
                </template>
                <dt>会话</dt>
                <dd><CopyText :text="detail.trace_id" /></dd>
              </dl>
            </section>
            <ThreatPayload :detail="detail" />
            <div
              v-if="detail.safe_message && detail.decision !== 'ALLOW'"
              class="dd-callout tc-agent-message"
              :class="'dd-callout-' + detail.decision"
            >
              <div class="dd-callout-label">返回给 Agent 的提示</div>
              <div class="dd-callout-text">{{ detail.safe_message }}</div>
            </div>
            <div class="tc-evidence-links">
              <span class="tc-note"
                >{{ (detail.matched_rules || []).length }} 条策略 ·
                {{ (detail.provenance || []).length }} 条指令来源 ·
                {{ (detail.flow || []).length }} 条数据流证据<template v-if="detail.anomaly">
                  · 含行为异常评分</template
                ></span
              ><el-button size="small" @click="detailTab = 'evidence'"
                >查看检测证据<el-icon class="el-icon--right"><ArrowRight /></el-icon
              ></el-button>
            </div>
            <MoreFields
              ><dl class="dd-kv">
                <dt>决策 ID</dt>
                <dd><CopyText :text="detail.decision_id" /></dd>
                <dt>规则版本</dt>
                <dd class="mono">{{ detail.rules_version || "—" }}</dd>
                <dt>决策耗时</dt>
                <dd class="mono">
                  {{ typeof detail.latency_ms === "number" ? detail.latency_ms.toFixed(2) + " ms" : "—" }}
                </dd>
              </dl>
              <template v-if="(detail.evidence_ids || []).length"
                ><div class="dd-callout-label mt-10">证据事件 · {{ detail.evidence_ids.length }}</div>
                <div class="dd-chips">
                  <span v-for="id in detail.evidence_ids" :key="id" class="dd-chip"
                    ><CopyText :text="id"
                  /></span></div></template
            ></MoreFields>
          </el-tab-pane>
          <el-tab-pane label="检测证据" name="evidence">
            <section v-if="(detail.provenance || []).length" class="dd-section">
              <h4 class="dd-section-title">
                指令来源 <span class="dd-count">{{ detail.provenance.length }}</span>
              </h4>
              <ProvenanceList :items="detail.provenance" />
            </section>
            <section v-if="(detail.flow || []).length" class="dd-section">
              <h4 class="dd-section-title">
                数据流证据 <span class="dd-count">{{ detail.flow.length }}</span>
              </h4>
              <FlowList :items="detail.flow" />
            </section>
            <section v-if="detail.anomaly" class="dd-section">
              <h4 class="dd-section-title">行为基线</h4>
              <AnomalyCard :a="detail.anomaly" />
            </section>
            <section class="dd-section">
              <h4 class="dd-section-title">
                命中详情 <span class="dd-count">{{ (detail.matched_rules || []).length }}</span>
              </h4>
              <RuleMatches v-if="(detail.matched_rules || []).length" :items="detail.matched_rules" @navigate="detailVisible = false" />
              <p v-else class="tc-note">这条记录未附带规则明细。</p>
            </section>
          </el-tab-pane>
          <el-tab-pane v-if="alert.count > 1" :label="'发生记录（' + alert.count + '）'" name="occurrences">

            <el-table
              :data="pagedOccurrences"
              size="small"
              row-key="decision_id"
              max-height="320"
              :row-class-name="
                ({ row }) => (row.decision_id === detail.decision_id ? 'tc-selected-occurrence' : '')
              "
              ><el-table-column label="发生时间" min-width="195"
                ><template #default="{ row }"
                  ><span class="mono">{{ fmt(row.created_at) }}</span></template
                ></el-table-column
              ><el-table-column label="级别" width="85"
                ><template #default="{ row }"
                  ><span class="sev-tag" :class="'sev-' + row.severity">{{
                    severityLabels[row.severity] || row.severity
                  }}</span></template
                ></el-table-column
              ><el-table-column label="决策 ID" min-width="165"
                ><template #default="{ row }"
                  ><span class="mono ellipsis tc-occurrence-id" :title="row.decision_id">{{
                    row.decision_id
                  }}</span></template
                ></el-table-column
              ><el-table-column label="操作" width="100"
                ><template #default="{ row }"
                  ><el-button link type="primary" size="small" @click="selectOccurrence(row)">{{
                    row.decision_id === detail.decision_id ? "当前记录" : "查看此记录"
                  }}</el-button></template
                ></el-table-column
              ></el-table
            >
            <div v-if="alert.count > 10" class="tc-occurrence-pager">
              <el-pagination
                background
                size="small"
                layout="prev, pager, next"
                :pager-count="5"
                :total="alert.count"
                :page-size="10"
                v-model:current-page="occurrencePage"
              />
            </div>
          </el-tab-pane>
        </el-tabs>
      </template>
      <template #footer>
        <div class="review-navigation" aria-label="风险记录导航">
          <el-button size="small" :disabled="!review.hasPrevious" @click="review.move(-1)">上一条</el-button>
          <span class="mono" role="status">{{ review.caption }}</span>
          <el-button size="small" :disabled="!review.hasNext" @click="review.move(1)">下一条</el-button>
        </div>
        <el-button size="small" @click="detailVisible = false">关闭</el-button
        ><el-button size="small" type="primary" :disabled="!detail?.trace_id" @click="viewChain"
          >查看会话链路<el-icon class="el-icon--right"><ArrowRight /></el-icon></el-button
      ></template>
    </el-drawer>
  </section>
</template>

<script setup>
import { ref, computed, watch, reactive } from "vue";
import { Bell, CircleClose, CircleCheck, ChatDotRound, VideoPlay, VideoPause, RefreshLeft, Tickets, Operation, Grid, View } from "../icons";
import { useReviewNavigation } from "../composables/useReviewNavigation";
import AgentIcon from "../components/AgentIcon.vue";
import CopyText from "../components/CopyText.vue";
import RuleMatches from "../components/RuleMatches.vue";
import MoreFields from "../components/MoreFields.vue";
import ProvenanceList from "../components/ProvenanceList.vue";
import FlowList from "../components/FlowList.vue";
import AnomalyCard from "../components/AnomalyCard.vue";
import AnalysisDetail from "../components/AnalysisDetail.vue";
import ThreatPayload from "../components/ThreatPayload.vue";
import ThreatScoreCell from "../components/ThreatScoreCell.vue";
import ThreatVisualizations from "./threat/ThreatVisualizations.vue";
import { matchesThreatVisualization, THREAT_PERIODS } from "../utils/threatStatistics";
import { executionCommand, anomalyScale } from "../utils/threatContent";
import { judgmentDescription, judgmentFilterLabel } from "../utils/threatJudgment";
import { assessmentText } from "../utils/format";
import {
  tab,
  sseOn,
  freshId,
  fScenario,
  fSev,
  fText,
  fDecision,
  fSource,
  DISPOSITIONS,
  alerts,
  filterAlerts,
  runtimeLoaded,
  alertTarget,
  threatsLoading,
  threatsUpdatedAt,
  threatsError,
  analysesUnavailable,
  refreshThreats,
  fmt,
  fmtTime,
  scenarioOf,
  threatText,
  decisionName,
  openChain,
  REVIEW_TEXT,
  AGENT_NAMES,
} from "../store/runtime";
import "./threat.css";

// ASK 在 Agent 原生确认流程中处理，控制台只展示结果。

const severityLabels = { CRITICAL: "严重", HIGH: "高危", MEDIUM: "中危", LOW: "低危" };
const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const reviewDispositions = new Set(["APPROVED", "UNKNOWN", "LLM_RELEASED", "LLM_FLAGGED"]);
const scope = ref("all"),
  sortBy = ref("recent");
const compact = ref(false);
const columns = reactive({ source: true, count: true, scenario: false, judgment: true });
const judgmentFilter = ref("");
const visualizationSelection = ref(null);
// 仅固定本页的已加载记录；后台订阅与其他运行时视图继续更新。
const pausedSnapshot = ref(null);
const isPaused = computed(() => pausedSnapshot.value !== null);
const records = computed(() => pausedSnapshot.value?.alerts || alerts.value);
const recordsUpdatedAt = computed(() => pausedSnapshot.value?.updatedAt || threatsUpdatedAt.value);
// 评分进度条使用当前列表的统一刻度，保证不同记录的长度可横向对比。
const scoreScale = computed(() => anomalyScale(records.value.map((a) => a.latest)));
const judgmentOptions = computed(() => [...new Map(records.value.map(row => [row.judgment.key,
  { key: row.judgment.key, label: judgmentFilterLabel(row.judgment) }])).values()]);
const pendingCount = computed(() => {
  if (!isPaused.value) return 0;
  const known = new Set(records.value.flatMap((a) => a.items.map((d) => d.decision_id)));
  return new Set(alerts.value.flatMap((a) => a.items.map((d) => d.decision_id)).filter((id) => !known.has(id))).size;
});
const streamStatus = computed(() => {
  if (threatsError.value) return recordsUpdatedAt.value ? "更新失败 · 保留记录" : "数据加载失败";
  if (isPaused.value) return pendingCount.value ? "已暂停 · 新增 " + countText(pendingCount.value) + " 条" : "列表已暂停";
  return sseOn.value ? "实时推送中" : "每 5 秒轮询";
});
function toggleFollowing() {
  if (isPaused.value) {
    pausedSnapshot.value = null;
    page.value = 1;
    refreshThreats();
  } else {
    pausedSnapshot.value = { alerts: alerts.value, updatedAt: threatsUpdatedAt.value };
  }
}
async function refreshRecords() {
  const snapshot = pausedSnapshot.value;
  await refreshThreats();
  if (snapshot && pausedSnapshot.value === snapshot && !threatsError.value) {
    pausedSnapshot.value = { alerts: alerts.value, updatedAt: threatsUpdatedAt.value };
  }
}
const matchesScope = (a, key) =>
  key === "all" ||
  (key === "blocked"
    ? a.disposition === "DENY"
    : key === "pending"
      ? a.disposition === "ASK"
      : key === "review"
        ? reviewDispositions.has(a.disposition)
        : a.disposition === "OBSERVE");
const scopeCounts = computed(() =>
  Object.fromEntries(
    ["all", "blocked", "pending", "review", "observations"].map((key) => [
      key,
      records.value.filter((a) => matchesScope(a, key)).length,
    ]),
  ),
);
const scopeOptions = computed(() =>
  [
    { key: "all", label: "全部记录" },
    { key: "blocked", label: "已阻断" },
    { key: "pending", label: "待确认" },
    { key: "review", label: "建议复核" },
    { key: "observations", label: "行为观察" },
  ].map((item) => ({ ...item, count: scopeCounts.value[item.key] })),
);
const summaryCards = computed(() => [
  {
    key: "all",
    label: "全部记录",
    count: scopeCounts.value.all,
    tone: "brand",
    icon: Bell,
    caption:
      "涉及 " +
      new Set(records.value.map((a) => a.latest.trace_id)).size +
      " 个会话 · 含 " +
      scopeCounts.value.observations +
      " 条观察",
  },
  {
    key: "blocked",
    label: "已阻断",
    count: scopeCounts.value.blocked,
    tone: "crit",
    icon: CircleClose,
    caption:
      records.value.filter((a) => a.disposition === "DENY").reduce((n, a) => n + a.count, 0) +
      " 次阻断",
  },
  {
    key: "pending",
    label: "待确认",
    count: scopeCounts.value.pending,
    tone: "med",
    icon: ChatDotRound,
  },
  {
    key: "review",
    label: "建议复核",
    count: scopeCounts.value.review,
    tone: "brand",
    icon: "Search",
  },
]);

const sourceOptions = computed(() => [
  ...new Map(records.value.map((a) => [a.source.key, a.source])).values(),
]);
const scenarios = computed(() => [...new Set(records.value.map((a) => scenarioOf(a.latest.trace_id)))].filter(Boolean).sort());
const scopeCount = computed(() => scopeCounts.value[scope.value]);
const latestBlockedAlert = computed(() =>
  records.value.find((a) => a.disposition === "DENY") || null,
);
const agentFor = (row) => row.analysis?.agent || (AGENT_NAMES[row.source.key] ? row.source.key : "");
const sourceLabel = (row) =>
  row.analysis
    ? row.source.label + " · " + (AGENT_NAMES[row.analysis.agent] || row.analysis.agent || "未知 Agent")
    : row.source.label;
const countText = (n) => Number(n).toLocaleString("zh-CN");
function setScope(key) {
  scope.value = key;
  fDecision.value = "";
}
function resetFilters() {
  scope.value = "all";
  sortBy.value = "recent";
  visualizationSelection.value = null;
  fScenario.value = fSev.value = fText.value = fDecision.value = fSource.value = "";
  judgmentFilter.value = "";
}
const advancedOpen = ref(false);
const advancedCount = computed(() => Number(!!fScenario.value) + Number(sortBy.value !== "recent") + Number(!!judgmentFilter.value));
const hasFilters = computed(
  () =>
    scope.value !== "all" ||
    !!visualizationSelection.value ||
    !!(fScenario.value || fSev.value || fText.value || fDecision.value || fSource.value || judgmentFilter.value) || sortBy.value !== "recent",
);
const activeFilters = computed(() =>
  [
    { key: 'judgment', label: '研判：' + (judgmentOptions.value.find(item => item.key === judgmentFilter.value)?.label || '所选结论'), value: judgmentFilter.value, clear: () => { judgmentFilter.value = ''; } },
    {
      key: "visualization",
      label: (THREAT_PERIODS.find(item => item.key === visualizationSelection.value?.period)?.title || "") + " · " + (visualizationSelection.value?.label || ""),
      value: visualizationSelection.value,
      clear: () => { visualizationSelection.value = null; },
    },
    {
      key: "text",
      label: "搜索：" + fText.value,
      value: fText.value,
      clear: () => {
        fText.value = "";
      },
    },
    {
      key: "severity",
      label: "级别：" + severityLabels[fSev.value],
      value: fSev.value,
      clear: () => {
        fSev.value = "";
      },
    },
    {
      key: "disposition",
      label: "处置：" + DISPOSITIONS[fDecision.value]?.label,
      value: fDecision.value,
      clear: () => {
        fDecision.value = "";
      },
    },
    {
      key: "source",
      label: "来源：" + sourceOptions.value.find((s) => s.key === fSource.value)?.label,
      value: fSource.value,
      clear: () => {
        fSource.value = "";
      },
    },
    {
      key: "scenario",
      label: "会话：" + fScenario.value,
      value: fScenario.value,
      clear: () => {
        fScenario.value = "";
      },
    },
    { key:"sort", label:"排序：" + ({severity:"风险优先", count:"重复次数优先"}[sortBy.value] || sortBy.value), value:sortBy.value !== "recent", clear:() => { sortBy.value = "recent"; } },
  ].filter((item) => item.value),
);
const visibleAlerts = computed(() =>
  filterAlerts(records.value)
    .filter(a => !judgmentFilter.value || a.judgment.key === judgmentFilter.value)
    .filter((a) => matchesScope(a, scope.value))
    .filter((a) => matchesThreatVisualization(a, visualizationSelection.value, recordsUpdatedAt.value))
    .sort((a, b) => {
      const delta =
        sortBy.value === "severity"
          ? (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0)
          : sortBy.value === "count"
            ? b.count - a.count
            : 0;
      return delta || (b.last_at || "").localeCompare(a.last_at || "");
    }),
);
const emptyTitle = computed(() =>
  threatsError.value && !threatsUpdatedAt.value
    ? "暂时无法加载风险记录"
    : hasFilters.value
      ? "没有匹配的记录"
      : "暂无风险记录",
);

const rowClass = ({ row }) =>
  "al-row al-sev-" +
  (row.severity || "low").toLowerCase() +
  (!isPaused.value && row.items.some((d) => d.decision_id === freshId.value) ? " fresh" : "");
const page = ref(1),
  pageSize = ref(20);
const listHeading = ref(null);
const pagedAlerts = computed(() =>
  visibleAlerts.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value),
);
watch([fScenario, fSev, fText, fDecision, fSource, judgmentFilter, scope, sortBy, pageSize, visualizationSelection], () => {
  page.value = 1;
});
// 在底部翻页或更改每页条数后，从新一页的开头继续阅读。
watch([page, pageSize], () => {
  if (tab.value === "threat" && listHeading.value?.getBoundingClientRect().top < 0) {
    listHeading.value.scrollIntoView({ block: "start" });
  }
}, { flush: "post" });
watch(
  () => visibleAlerts.value.length,
  (total) => {
    page.value = Math.min(page.value, Math.max(1, Math.ceil(total / pageSize.value)));
  },
);

// 打开时保留该组合的快照，后台刷新不会替换正在阅读的发生记录。
const alert = ref(null),
  detailVisible = ref(false),
  detailTab = ref("overview"),
  selectedId = ref(""),
  occurrencePage = ref(1);
const detail = computed(
  () => alert.value?.items.find((d) => d.decision_id === selectedId.value) || alert.value?.latest || null,
);
const pagedOccurrences = computed(() =>
  (alert.value?.items || []).slice((occurrencePage.value - 1) * 10, occurrencePage.value * 10),
);
function showDetail(row) {
  alert.value = row;
  selectedId.value = row.latest.decision_id;
  detailTab.value = "overview";
  occurrencePage.value = 1;
  detailVisible.value = true;
}
const review = reactive(useReviewNavigation({rows:visibleAlerts, key:row => row.key, open:showDetail, selector:'.tc-table [data-review-key]'}));
function openDetail(row) { review.begin(row); }
function openJudgment(row) {
  review.begin(row);
  if (row.judgment.decisionId) selectedId.value = row.judgment.decisionId;
}
function selectOccurrence(row) {
  selectedId.value = row.decision_id;
  detailTab.value = "overview";
}
function viewChain() {
  if (!detail.value) return;
  detailVisible.value = false;
  openChain(detail.value.trace_id);
}
watch(tab, (value) => {
  if (value !== "threat") detailVisible.value = false;
});
</script>
