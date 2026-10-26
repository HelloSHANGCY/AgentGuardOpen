<template>
  <section v-show="tab === 'events'" class="events-page">
    <ConsolePageHeader title="运行审计" class="ef-header">

      <div class="ef-header-tools">
        <el-button size="small" plain :aria-expanded="lookupOpen" aria-controls="audit-session-lookup"
                   @click="lookupOpen = !lookupOpen">查找会话</el-button>
        <div class="ef-update" aria-live="polite">
          <span
            ><i class="dot" :class="{ on: !eventsPaused && !eventsError }" aria-hidden="true"></i
            >{{ eventsPaused ? "已暂停列表更新" : "实时跟随 · 每 5 秒补齐" }}</span
          ><span :class="{ 'ef-stale': eventsError }">{{
            eventsError
              ? eventsUpdatedAt
                ? "更新失败 · 保留当前记录"
                : "事件加载失败"
              : eventsCheckedAt
                ? "检查于 " + fmtTime(eventsCheckedAt).slice(0, 8)
                : "正在读取事件"
          }}</span>
        </div>
        <el-button size="small" :loading="eventsLoading" @click="refreshEvents"
          ><el-icon v-if="!eventsLoading" class="btn-ic"><Refresh /></el-icon
          >{{ eventsPaused ? "检查新事件" : "刷新事件" }}</el-button
        >
      </div>
    </ConsolePageHeader>

    <form v-if="lookupOpen" id="audit-session-lookup" class="ef-session-lookup" @submit.prevent="lookupSession">
      <label for="audit-session-identifier">会话链路</label>
      <el-input id="audit-session-identifier" v-model="sessionLookup" size="small" clearable
                placeholder="会话 trace ID、任务 ID 或决策 ID" aria-label="查找会话链路" />
      <el-button size="small" type="primary" native-type="submit" :disabled="!sessionLookup.trim()">查看链路</el-button>
    </form>

    <el-alert
      v-if="eventsError"
      class="ef-error"
      :title="eventsError"
      type="error"
      show-icon
      :closable="false"
    />
    <el-alert
      v-if="eventDecisionsUnavailable"
      class="ef-error"
      title="决策记录读取失败"
      type="warning"
      show-icon
      :closable="false"
    />
    <div class="ef-overview" aria-label="当前加载范围概览">
      <div>
        <span class="ef-note">已加载原始事件</span
        ><strong>{{ eventsUpdatedAt ? number(events.length) : "—" }}<small>条</small></strong
        ><span class="ef-note"
          >服务端保留 {{ eventsUpdatedAt ? number(eventsTotal) : "—" }} 条 · 当前上限
          {{ number(eventsLoadedWindow) }}</span
        >
      </div>
      <div>
        <span class="ef-note">风险相关事件</span
        ><strong>{{ eventsUpdatedAt ? number(riskCount) : "—" }}<small>条</small></strong
        >
      </div>
      <div>
        <span class="ef-note">涉及会话</span
        ><strong>{{ eventsUpdatedAt ? number(sessionCount) : "—" }}<small>个</small></strong
        ><span class="ef-note">共 {{ sourceCount }} 类来源</span>
      </div>
    </div>

    <div class="ef-panel">
      <div class="ef-stream-bar" :class="{ paused: eventsPaused }">
        <div class="ef-stream-message" aria-live="polite">
          <strong>{{ eventsPaused ? "当前列表已固定" : "跟随事件更新" }}</strong
          ><span v-if="pendingWindowChanged" class="ef-pending"
            >已取回最近 {{ number(pendingEventsMeta.window) }} 条范围，尚未应用</span
          >
        </div>
        <el-button
          v-if="eventsPaused && pendingEventsChanged"
          size="small"
          type="primary"
          plain
          @click="loadPendingEvents"
          >{{ newEventCount ? "加载 " + number(newEventCount) + " 条新事件" : "应用已取回记录" }}</el-button
        >
        <el-button size="small" @click="eventsPaused = !eventsPaused"
          ><el-icon class="btn-ic"><VideoPlay v-if="eventsPaused" /><VideoPause v-else /></el-icon
          >{{ eventsPaused ? "恢复跟随" : "暂停更新" }}</el-button
        >
      </div>

      <div class="ef-tools">
        <div class="ef-primary-tools">
          <div class="ef-scopes" role="group" aria-label="事件查看范围">
            <button
              type="button"
              :class="{ active: !onlyBlocked }"
              :aria-pressed="!onlyBlocked"
              @click="onlyBlocked = false"
            >
              全部事件<span>{{ number(eventRows.length) }}</span></button
            ><button
              type="button"
              :class="{ active: onlyBlocked }"
              :aria-pressed="onlyBlocked"
              @click="onlyBlocked = true"
            >
              风险相关<span>{{ number(riskCount) }}</span>
            </button>
          </div>
          <el-input
            v-model="eText"
            class="ef-search"
            size="small"
            clearable
            aria-label="搜索事件"
            placeholder="搜索摘要、资源、工具、标签或会话"
            ><template #prefix
              ><el-icon aria-hidden="true"><Search /></el-icon></template
          ></el-input>
          <FilterToggle v-model="advancedOpen" controls="event-advanced-filters" :count="advancedCount" />
          <el-button size="small" :disabled="!hasFilter" @click="clearFilters">重置筛选</el-button>
        </div>
        <el-collapse-transition>
        <div v-show="advancedOpen" id="event-advanced-filters" class="ef-advanced-filters"><div class="ef-filter-grid">
          <label
            ><span>原始决策</span
            ><el-select
              v-model="eDecision"
              placeholder="全部决策"
              clearable
              size="small"
              aria-label="筛选事件原始决策"
              ><el-option
                v-for="(label, key) in decisionNames"
                :key="key"
                :label="label"
                :value="key" /></el-select
          ></label>
          <label
            ><span>事件来源</span
            ><el-select
              v-model="eSource"
              placeholder="全部来源"
              clearable
              size="small"
              aria-label="筛选事件来源"
              ><el-option
                v-for="(label, key) in sourceNames"
                :key="key"
                :label="label"
                :value="key" /></el-select
          ></label>
          <label
            ><span>事件阶段</span
            ><el-select
              v-model="eStage"
              placeholder="全部阶段"
              clearable
              filterable
              size="small"
              aria-label="筛选事件阶段"
              ><el-option
                v-for="stage in eventStages"
                :key="stage"
                :label="stageName({ stage })"
                :value="stage" /></el-select
          ></label>
          <label class="ef-trace-filter"
            ><span>会话（精确匹配）</span
            ><el-input
              v-model="eTrace"
              placeholder="完整 trace ID"
              clearable
              size="small"
              aria-label="精确筛选事件会话"
          /></label>
          <label
            ><span>时间顺序</span
            ><el-select v-model="eOrder" size="small" aria-label="事件时间排序"
              ><el-option label="最新优先" value="recent" /><el-option
                label="最早优先"
                value="oldest" /></el-select
          ></label>
        </div>
        <div class="ef-secondary-tools">
          <el-checkbox
            v-model="hideHookDup"
            size="small"

            >隐藏 Hook 重复事件</el-checkbox
          >

          <label class="ef-window"
            ><span>加载范围</span
            ><el-select v-model="eventsWindow" size="small" aria-label="事件加载范围"
              ><el-option
                v-for="n in EVENT_WINDOWS"
                :key="n"
                :value="n"
                :label="'最近 ' + number(n) + ' 条'" /></el-select
          ></label>
        </div>
        </div>
        </el-collapse-transition>
        <div v-if="activeFilters.length" class="ef-filter-chips" aria-label="已选事件筛选">
          <el-tag
            v-for="item in activeFilters"
            :key="item.key"
            type="info"
            effect="plain"
            size="small"
            closable
            @close="item.clear()"
            >{{ item.label }}</el-tag
          >
        </div>
      </div>

      <div ref="listHeading" class="ef-list-heading">
        <div>
          <h3>
            事件记录 <span>{{ number(filteredEvents.length) }} 条匹配</span>
          </h3>
        </div>
        <el-pagination
          v-if="filteredEvents.length > 20"
          class="ef-pagination"
          aria-label="事件记录顶部分页"
          v-model:current-page="ePage"
          v-model:page-size="ePageSize"
          :page-sizes="[20, 50, 100]"
          :total="filteredEvents.length"
          :pager-count="5"
          layout="sizes, prev, pager, next"
          size="small"
          background
        />
      </div>
      <p v-if="timeRange" class="ef-time-range">
        <span>当前记录时间</span><span class="mono">{{ timeRange }}</span
        ><span v-if="eventsPaused && eventsUpdatedAt"
          >· 展示于 {{ fmtTime(eventsUpdatedAt).slice(0, 8) }}</span
        >
      </p>
      <!-- 当前页自然展开，避免固定高度导致人工排查只能看到少量事件。 -->
      <el-table
        v-if="eventsLoaded"
        :data="pagedEvents"
        size="small"
        row-key="event_id"
        :row-class-name="rowClass"
        class="events-table ef-table"
        @row-click="openDetail"
      >
        <el-table-column label="发生时间" width="147"
          ><template #default="{ row }"
            ><div class="mono" :title="fmt(row.timestamp)">{{ fmtTime(row.timestamp) }}</div>
            <div class="ef-note mono">{{ fmt(row.timestamp).slice(0, 10) }}</div></template
          ></el-table-column
        >
        <el-table-column label="阶段与来源" min-width="175"
          ><template #default="{ row }"
            ><div class="ef-stage" :title="row.stage">{{ stageName(row) }}</div>
            <div class="ef-source">
              <AgentIcon v-if="agentFor(row)" :agent="agentFor(row)" :size="24" /><el-icon
                v-else
                aria-hidden="true"
                ><component :is="row.sourceKind === 'judge' ? 'DataAnalysis' : 'Connection'" /></el-icon
              ><span class="ellipsis">{{ sourceNames[row.sourceKind] || row.source }}</span>
            </div></template
          ></el-table-column
        >
        <el-table-column label="决策 / 处置" width="165" class-name="ef-decision-column"
          ><template #default="{ row }"
            ><template v-if="row.decision"
              ><span class="dec-tag" :class="dispositionTag(row.decision)">{{
                dispositionLabel(row.decision)
              }}</span
              ><span v-if="row.inherited" class="ef-inherited">关联调用结论</span>
              <div class="ef-note ef-decision-reason" :title="row.decision.reason_code">
                {{ row.decision.reason_code ? threatText(row.decision.reason_code) : "未附带原因码" }}
              </div></template
            ><template v-else
              ><el-tag type="info" size="small" effect="plain">{{
                row.unresolvedDecision ? "未关联决策" : "无决策"
              }}</el-tag>
              </template
            ></template
          ></el-table-column
        >
        <el-table-column label="工具与资源" min-width="200"
          ><template #default="{ row }"
            ><div class="ellipsis" :title="toolLabel(row)">{{ toolLabel(row) }}</div>
            <div v-if="row.resource" class="mono ef-note ellipsis" :title="row.resource">
              {{ row.resource }}
            </div></template
          ></el-table-column
        >
        <el-table-column label="摘要（脱敏）" min-width="235"
          ><template #default="{ row }"
            ><div class="ef-preview" :title="row.redacted_preview">
              {{ codeListText(row.redacted_preview) || "未提供摘要" }}
            </div>
            <div v-if="riskLabels(row).length" class="ef-labels">
              <el-tag
                v-for="label in riskLabels(row)"
                :key="label"
                size="small"
                type="danger"
                effect="plain"
                :title="label"
                >{{ threatText(label) }}</el-tag
              >
            </div></template
          ></el-table-column
        >
        <el-table-column label="会话" min-width="145"
          ><template #default="{ row }"
            ><el-button
              v-if="row.trace_id"
              link
              type="primary"
              class="mono ef-trace"
              :title="'查看会话链路：' + row.trace_id"
              @click.stop="openChain(row.trace_id)"
              >{{ row.trace_id }}</el-button
            ><span v-else class="ef-note">未提供会话</span>
            <div v-if="row.round" class="ef-note">第 {{ row.round }} 轮</div></template
          ></el-table-column
        >
        <el-table-column label="操作" width="76" fixed="right"
          ><template #default="{ row }"
            ><el-button
              link
              type="primary"
              size="small"
              :aria-label="'查看事件详情：' + row.event_id"
              @click.stop="openDetail(row)" :data-review-key="row.event_id"
              >详情</el-button
            ></template
          ></el-table-column
        >
        <template #empty
          ><div class="ef-empty">
            <el-icon aria-hidden="true"
              ><component
                :is="eventsError && !eventsUpdatedAt ? 'Warning' : hasFilter ? 'Search' : 'List'" /></el-icon
            ><strong>{{ emptyTitle }}</strong>

            <el-button v-if="eventsError && !eventsUpdatedAt" size="small" @click="refreshEvents"
              >重新加载事件</el-button
            ><el-button v-else-if="hasFilter" size="small" @click="clearFilters"
              >查看全部已加载事件</el-button
            >
          </div></template
        >
      </el-table>
      <el-skeleton v-else class="ef-skeleton" :rows="5" animated />
      <div class="ef-list-footer">
        <span class="ef-note">{{ pageCaption }}</span
        ><el-pagination
          v-if="filteredEvents.length > 20"
          class="ef-pagination"
          aria-label="事件记录底部分页"
          v-model:current-page="ePage"
          v-model:page-size="ePageSize"
          :page-sizes="[20, 50, 100]"
          :total="filteredEvents.length"
          :pager-count="5"
          layout="sizes, prev, pager, next"
          size="small"
          background
        />
      </div>
    </div>

    <el-drawer
      v-model="detailVisible"
      class="detail-drawer ef-drawer"
      size="min(860px, 100vw)"
      @closed="review.restoreFocus"
      title="事件详情"
      append-to-body
      destroy-on-close
    >
      <template #header="{ titleId }"
        ><div v-if="detail" class="dd-head">
          <h3 :id="titleId" class="dd-title">事件详情 · {{ stageName(detail) }}</h3>
          <div class="dd-subtitle">
            {{ sourceNames[detail.sourceKind] || detail.source }} · {{ fmt(detail.timestamp) }}
          </div>
        </div></template
      >
      <template v-if="detail">

        <dl class="dd-kv ef-context">
          <dt>会话</dt>
          <dd><CopyText :text="detail.trace_id" /></dd>
          <dt>工具</dt>
          <dd>{{ toolLabel(detail) }}</dd>
          <dt v-if="detail.resource">资源</dt>
          <dd v-if="detail.resource" class="mono">{{ detail.resource }}</dd>
        </dl>
        <ChainEventDetail :n="detail" />
        <section v-if="detail.decision?.matched_rules?.length" class="dd-section ef-rules">
          <h4 class="dd-section-title">
            命中详情 <span class="dd-count">{{ detail.decision.matched_rules.length }}</span>
          </h4>
          <RuleMatches :items="detail.decision.matched_rules" @navigate="detailVisible = false" />
        </section>
        <MoreFields title="事件标识与详细字段"
          ><dl class="dd-kv">
            <dt>事件 ID</dt>
            <dd><CopyText :text="detail.event_id" /></dd>
            <dt>决策 ID</dt>
            <dd>
              <CopyText
                v-if="detail.decision_id || detail.decision?.decision_id"
                :text="detail.decision_id || detail.decision.decision_id"
              /><span v-else>—</span>
            </dd>
            <dt>调用 ID</dt>
            <dd><CopyText v-if="detail.call_id" :text="detail.call_id" /><span v-else>—</span></dd>
            <dt>任务 ID</dt>
            <dd><CopyText v-if="detail.task_id" :text="detail.task_id" /><span v-else>—</span></dd>
            <dt>span</dt>
            <dd><CopyText v-if="detail.span_id" :text="detail.span_id" /><span v-else>—</span></dd>
            <dt>父 span</dt>
            <dd>
              <CopyText v-if="detail.parent_span_id" :text="detail.parent_span_id" /><span v-else>—</span>
            </dd>
          </dl></MoreFields
        >
      </template>
      <template #footer>
        <div class="review-navigation" aria-label="事件记录导航">
          <el-button size="small" :disabled="!review.hasPrevious" @click="review.move(-1)">上一条</el-button>
          <span class="mono" role="status">{{ review.caption }}</span>
          <el-button size="small" :disabled="!review.hasNext" @click="review.move(1)">下一条</el-button>
        </div>
        <el-button size="small" @click="detailVisible = false">关闭</el-button
        ><el-button size="small" :disabled="!detail?.trace_id" @click="filterSession">仅看此会话</el-button
        ><el-button size="small" type="primary" :disabled="!detail?.trace_id" @click="viewChain"
          >查看会话链路<el-icon class="el-icon--right"><ArrowRight /></el-icon></el-button
      ></template>
    </el-drawer>
  </section>
</template>

<script setup>
import { ref, computed, watch, reactive } from "vue";
import { VideoPause, VideoPlay } from "../icons";
import { useReviewNavigation } from "../composables/useReviewNavigation";
import AgentIcon from "../components/AgentIcon.vue";
import CopyText from "../components/CopyText.vue";
import RuleMatches from "../components/RuleMatches.vue";
import MoreFields from "../components/MoreFields.vue";
import ChainEventDetail from "./chain/ChainEventDetail.vue";
const lookupOpen = ref(false), sessionLookup = ref("");
function lookupSession() { if (sessionLookup.value.trim()) openChain(sessionLookup.value); }
import {
  tab,
  events,
  eventRows,
  eventDecisionsUnavailable,
  eventsLoading,
  eventsLoaded,
  eventsError,
  eventsUpdatedAt,
  eventsCheckedAt,
  onlyBlocked,
  eText,
  eDecision,
  eSource,
  eStage,
  eTrace,
  eOrder,
  hideHookDup,
  eventsPaused,
  eventsLoadedWindow,
  filteredEvents,
  pagedEvents,
  ePage,
  ePageSize,
  eventsWindow,
  eventsTotal,
  EVENT_WINDOWS,
  eventStages,
  newEventCount,
  pendingEventsChanged,
  pendingEventsMeta,
  loadPendingEvents,
  refreshEvents,
  openChain,
  fmt,
  fmtTime,
  codeListText,
  dispositionTag,
  dispositionLabel,
  stageName,
  isRiskLabel,
  threatText,
  AGENT_NAMES,
  EVENT_SOURCE_NAMES,
} from "../store/runtime";
import "./events.css";

const sourceNames = EVENT_SOURCE_NAMES;
const decisionNames = {
  DENY: "拦截 · DENY",
  ASK: "需确认 · ASK",
  ALLOW: "放行 · ALLOW",
  NONE: "无决策",
  UNRESOLVED: "未关联决策",
};
const number = (n) => Number(n).toLocaleString("zh-CN");
const riskCount = computed(() => eventRows.value.filter((row) => row.risk).length);
const sessionCount = computed(() => new Set(events.value.map((row) => row.trace_id).filter(Boolean)).size);
const sourceCount = computed(() => new Set(eventRows.value.map((row) => row.sourceKind)).size);
const timeRange = computed(() => {
  const times = events.value
    .map((row) => row.timestamp)
    .filter(Boolean)
    .sort();
  return times.length ? fmt(times[0]) + " ～ " + fmt(times[times.length - 1]) : "";
});
const pendingWindowChanged = computed(
  () =>
    eventsPaused.value &&
    pendingEventsMeta.value &&
    pendingEventsMeta.value.window !== eventsLoadedWindow.value,
);

const advancedOpen = ref(false);
const advancedCount = computed(() => [eDecision.value, eSource.value, eStage.value, eTrace.value].filter(Boolean).length + Number(hideHookDup.value) + Number(eOrder.value !== 'recent'));
const hasFilter = computed(
  () =>
    onlyBlocked.value ||
    !!(eDecision.value || eSource.value || eStage.value || eTrace.value || eText.value || hideHookDup.value) || eOrder.value !== "recent",
);
function clearFilters() {
  onlyBlocked.value = false;
  eDecision.value = eSource.value = eStage.value = eTrace.value = eText.value = "";
  hideHookDup.value = false;
  eOrder.value = "recent";
}
const activeFilters = computed(() =>
  [
    {
      key: "risk",
      label: "范围：风险相关",
      value: onlyBlocked.value,
      clear: () => {
        onlyBlocked.value = false;
      },
    },
    {
      key: "text",
      label: "搜索：" + eText.value,
      value: eText.value,
      clear: () => {
        eText.value = "";
      },
    },
    {
      key: "decision",
      label: "决策：" + decisionNames[eDecision.value],
      value: eDecision.value,
      clear: () => {
        eDecision.value = "";
      },
    },
    {
      key: "source",
      label: "来源：" + sourceNames[eSource.value],
      value: eSource.value,
      clear: () => {
        eSource.value = "";
      },
    },
    {
      key: "stage",
      label: "阶段：" + stageName({ stage: eStage.value }),
      value: eStage.value,
      clear: () => {
        eStage.value = "";
      },
    },
    {
      key: "trace",
      label: "会话：" + eTrace.value,
      value: eTrace.value,
      clear: () => {
        eTrace.value = "";
      },
    },
    {
      key: "duplicate",
      label: "隐藏 Hook 重复事件",
      value: hideHookDup.value,
      clear: () => {
        hideHookDup.value = false;
      },
    },
    { key:"sort", label:"排序：最早优先", value:eOrder.value !== "recent", clear:() => { eOrder.value = "recent"; } },
  ].filter((item) => item.value),
);
const riskLabels = (row) =>
  (row.labels || []).filter((label) => isRiskLabel(label) && label !== row.decision?.reason_code).slice(0, 2);
const agentFor = (row) =>
  AGENT_NAMES[row.sourceKind]
    ? row.sourceKind
    : row.sourceKind === "judge" && AGENT_NAMES[row.component]
      ? row.component
      : "";
const toolLabel = (row) =>
  [row.mcp_server || AGENT_NAMES[row.component] || row.component, row.tool].filter(Boolean).join(" / ") ||
  "未提供工具";
const rowClass = ({ row }) => (row.risk ? "ev-row-" + (row.decision?.decision || "alert").toLowerCase() : "");
const pageCaption = computed(() =>
  filteredEvents.value.length
    ? "第 " +
      ((ePage.value - 1) * ePageSize.value + 1) +
      "–" +
      Math.min(ePage.value * ePageSize.value, filteredEvents.value.length) +
      " 条，共 " +
      number(filteredEvents.value.length) +
      " 条匹配事件"
    : "共 0 条匹配事件",
);
const emptyTitle = computed(() =>
  eventsError.value && !eventsUpdatedAt.value
    ? "暂时无法加载事件"
    : hasFilter.value
      ? "没有匹配的事件"
      : "暂无事件记录",
);

const listHeading = ref(null);
watch(
  [ePage, ePageSize],
  () => {
    if (tab.value === "events" && listHeading.value?.getBoundingClientRect().top < 0)
      listHeading.value.scrollIntoView({ block: "start" });
  },
  { flush: "post" },
);
// 查看详情保留打开时的快照，实时刷新不会替换正在阅读的证据。
const detail = ref(null),
  detailVisible = ref(false);
function showDetail(row) {
  detail.value = row;
  detailVisible.value = true;
}
const review = reactive(useReviewNavigation({rows:filteredEvents, key:row => row.event_id, open:showDetail, selector:'.ef-table [data-review-key]'}));
function openDetail(row) { review.begin(row); }
function filterSession() {
  if (!detail.value?.trace_id) return;
  clearFilters();
  eTrace.value = detail.value.trace_id;
  detailVisible.value = false;
  ePage.value = 1;
  listHeading.value?.scrollIntoView({ block: "start" });
}
function viewChain() {
  if (!detail.value?.trace_id) return;
  detailVisible.value = false;
  openChain(detail.value.trace_id);
}
watch(tab, (value) => {
  if (value === "events") refreshEvents();
  else detailVisible.value = false;
});
</script>
