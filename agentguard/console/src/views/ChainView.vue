<template>
  <section v-show="tab === 'chain'" class="chain-page">
    <nav class="ac-breadcrumb" aria-label="会话链路导航">
      <button type="button" @click="returnToAudit">运行审计</button>
      <el-icon aria-hidden="true"><ArrowRight /></el-icon><span aria-current="page">会话链路</span>
    </nav>
    <ConsolePageHeader title="会话链路" class="ac-header">

      <div class="ac-header-actions">
        <el-button size="small" plain @click="returnFromChain">{{ chainReturnLabel }}</el-button>
        <span v-if="chainUpdatedAt && currentLoaded" class="muted fs-12">
          {{ chainError ? "保留上次记录 · " : "更新于 " }}{{ fmtTime(chainUpdatedAt) }}
        </span>
        <el-button v-if="currentLoaded" size="small" :loading="chainLoading" @click="openChain(chainId)">
          <el-icon class="btn-ic"><Refresh /></el-icon>刷新链路
        </el-button>
        <el-button v-if="currentLoaded" size="small" plain @click="copyLink">
          <el-icon class="btn-ic"><Link /></el-icon>复制链接
        </el-button>
      </div>
    </ConsolePageHeader>
    <div v-show="!hasChain || showLookup" class="ac-lookup">
      <form class="ac-lookup-form" @submit.prevent="lookup">
        <label for="chain-identifier">查找会话</label>
        <el-input
          id="chain-identifier"
          v-model="chainInput"
          clearable
          size="small"
          placeholder="输入会话 trace ID、任务 ID 或决策 ID"
          aria-label="查找会话链路"
        >
          <template #prefix
            ><el-icon><Search /></el-icon
          ></template>
        </el-input>
        <el-button size="small" type="primary" native-type="submit" :disabled="!chainInput.trim()"
          >查看链路</el-button
        >
      </form>
      <div v-if="recentBlockedTraces.length" class="ac-recent">
        <span class="muted">最近拦截会话</span>
        <button
          v-for="tr in recentBlockedTraces"
          :key="tr"
          type="button"
          :title="tr"
          :class="{ active: chain.trace_id === tr && currentLoaded }"
          @click="openChain(tr)"
        >
          <span class="mono">{{ tr }}</span
          ><el-icon><ArrowRight /></el-icon>
        </button>
      </div>
    </div>
    <el-alert
      v-if="chainError"
      class="ac-error"
      type="error"
      :closable="false"
      show-icon
      :title="chainError"
    />
    <el-skeleton v-if="chainLoading && !currentLoaded" class="ac-loading" :rows="8" animated />
    <template v-else-if="hasChain">
      <section class="ac-focus-intro" aria-label="排查起点">
        <div class="ac-session-line">
          <span class="muted mono" :title="chain.trace_id || chainId"
            >会话 {{ chain.trace_id || chainId }}</span
          >
          <el-button size="small" text :aria-expanded="showLookup" @click="showLookup = !showLookup">{{
            showLookup ? "收起查询" : "切换会话"
          }}</el-button>
        </div>
        <div class="ac-intro-main">
          <div>
            <h3>{{ focusHeadline }}</h3>
          </div>
          <el-button v-if="recommended" type="primary" @click="openDetail(recommended)"
            >{{ view.stats.pending ? "查看待确认节点" : risks.length ? "查看风险节点" : "核对证据缺口"
            }}<el-icon class="ac-cta-icon"><ArrowRight /></el-icon
          ></el-button>
          <el-button v-else-if="readingMode !== 'full'" plain @click="readingMode = 'full'">查看完整链路</el-button>
        </div>
        <div class="ac-summary-counts">
          <span>{{ view.stats.risks }} 个风险相关节点</span
          ><span v-if="view.stats.pending">{{ view.stats.pending }} 个待确认</span
          ><span v-if="view.stats.gaps">{{ view.stats.gaps }} 处证据缺口</span>
        </div>
      </section>
      <details :key="chainLoadedId" class="ac-background">
        <summary>
          会话背景<el-icon><ArrowRight /></el-icon>
        </summary>
        <div class="ac-context-layout">
          <section class="ac-context" aria-label="会话概览">
            <div class="ac-section-heading">
              <h3>会话概览</h3>
              <el-tag v-if="!chain.task" type="warning" size="small" effect="plain">未登记任务上下文</el-tag>
              <span v-else class="ac-context-agent muted fs-12">
                <template v-if="chain.task.agent"
                  ><AgentIcon v-if="AGENT_NAMES[chain.task.agent]" :agent="chain.task.agent" :size="22" />
                  {{ AGENT_NAMES[chain.task.agent] || chain.task.agent }} · </template
                >已登记任务上下文
              </span>
            </div>
            <dl class="ac-context-grid">
              <div class="ac-trace">
                <dt>会话 ID</dt>
                <dd><CopyText :text="chain.trace_id || chainId" /></dd>
              </div>
              <div>
                <dt>用户</dt>
                <dd>
                  {{ chain.task?.actor?.sub || "未记录" }}
                  <span v-if="chain.task?.actor?.role" class="muted"> · {{ chain.task.actor.role }}</span>
                </dd>
              </div>
              <div>
                <dt>Skill</dt>
                <dd>{{ chain.task?.active_skill?.name || "未记录" }}</dd>
              </div>
              <div class="ac-time-range">
                <dt>时间范围</dt>
                <dd class="mono">{{ timeRange }}</dd>
              </div>
            </dl>
            <p v-if="view.stats.durationMs !== null && view.stats.events > 1" class="ac-span-note muted">
              事件跨度 {{ durationText }}
            </p>
            <details v-if="chain.task || chain.state?.taints?.length" class="ac-task-details">
              <summary>
                任务上下文与累计标签<el-icon><ArrowRight /></el-icon>
              </summary>
              <dl class="ac-context-more">
                <template v-if="chain.task?.intent_summary">
                  <dt>用户提示词摘要</dt>
                  <dd class="ac-prompt">
                    {{ chain.task.intent_summary }}
                    <el-tag v-if="chain.task.intent_truncated" size="small" type="info" effect="plain"
                      >已截断</el-tag
                    >
                  </dd>
                </template>
                <template v-if="Object.keys(chain.task?.actor?.scope || {}).length">
                  <dt>权限范围</dt>
                  <dd class="ac-chips">
                    <el-tag
                      v-for="(v, k) in chain.task.actor.scope"
                      :key="k"
                      size="small"
                      effect="plain"
                      type="info"
                      >{{ k }}={{ Array.isArray(v) ? v.join(", ") : v }}</el-tag
                    >
                  </dd>
                </template>
                <template v-if="chain.task?.source_labels?.length">
                  <dt>来源标签</dt>
                  <dd class="ac-chips">
                    <el-tag
                      v-for="l in chain.task.source_labels"
                      :key="l"
                      size="small"
                      type="info"
                      effect="plain"
                      >{{ threatText(l) }}</el-tag
                    >
                  </dd>
                </template>
                <template v-if="chain.state?.taints?.length">
                  <dt>累计污点标签</dt>
                  <dd class="ac-chips">
                    <el-tag
                      v-for="l in chain.state.taints"
                      :key="l"
                      size="small"
                      type="warning"
                      effect="plain"
                      >{{ threatText(l) }}</el-tag
                    >
                  </dd>
                </template>
                <template v-if="knownScenario"
                  ><dt>评测场景标识</dt>
                  <dd class="mono">{{ knownScenario }}</dd></template
                >
              </dl>
            </details>
          </section>
        </div>
      </details>
      <ChainStages :steps="stageSteps" :selected-key="selectedKey" @select="jumpTo" />
      <div class="ac-reading-modes" aria-label="会话链路阅读方式">
        <button
          type="button"
          :aria-pressed="readingMode === 'focus'"
          :class="{ active: readingMode === 'focus' }"
          @click="readingMode = 'focus'"
        >
          关键风险 <span>{{ risks.length }}</span>
        </button>
        <button
          v-if="gaps.length"
          type="button"
          :aria-pressed="readingMode === 'gaps'"
          :class="{ active: readingMode === 'gaps' }"
          @click="readingMode = 'gaps'"
        >
          证据缺口 <span>{{ gaps.length }}</span>
        </button>
        <button
          type="button"
          :aria-pressed="readingMode === 'full'"
          :class="{ active: readingMode === 'full' }"
          @click="readingMode = 'full'"
        >
          完整过程 <span>{{ view.all.length }}</span>
        </button>
      </div>
      <section
        v-if="readingMode !== 'full'"
        class="ac-review"
        :aria-label="readingMode === 'gaps' ? '证据缺口摘要' : '关键风险摘要'"
      >
        <div class="ac-review-heading">
          <h3><el-icon aria-hidden="true"><List /></el-icon>{{ readingMode === "gaps" ? "证据缺口" : "关键风险" }}</h3>
          <span class="muted fs-12">{{ reviewRows.length }} 个节点 · 按发生时间排序</span>
        </div>
        <ol v-if="reviewItems.length" class="ac-review-list">
          <li v-for="item in reviewItems" :key="item.key" :data-severity="item.decision?.severity">
            <button
              type="button"
              class="ac-review-item"
              :class="{ selected: selectedKey === item.key }"
              :aria-label="'查看节点证据：' + item.title"
              @click="openDetail(item)"
            >
              <span class="ac-review-content">
                <span class="ac-review-top">
                  <span class="ac-review-badges">
                    <span class="ac-review-stage">{{ itemStage(item) }}</span>
                    <span v-if="itemRule(item)" class="ac-review-rule mono" :title="item.decision.matched_rules.map(rule => rule.rule_id).filter(Boolean).join(' · ')">{{ itemRule(item) }}</span>
                    <span v-if="CHAIN_SEVERITIES[item.decision?.severity]" class="sev-tag" :class="'sev-' + item.decision.severity">
                      <i aria-hidden="true"></i>{{ CHAIN_SEVERITIES[item.decision.severity] }}
                    </span>
                  </span>
                  <time :datetime="item.timestamp" :title="fmt(item.timestamp)"><el-icon aria-hidden="true"><Timer /></el-icon>{{ fmtTime(item.timestamp) }}</time>
                </span>
                <strong class="ac-review-title">{{ itemHeadline(item) }}</strong>
                <span class="ac-review-target" :title="[item.title, item.resource].filter(Boolean).join(' · ')">
                  {{ item.title }}<template v-if="item.resource"> · {{ item.resource }}</template>
                </span>
                <span class="ac-review-bottom">
                  <span class="ac-review-meta">
                    <span class="dec-tag" :class="outcomeClass(item)">{{ outcomeText(item) }}</span>
                    <span>节点 N{{ nodeNumbers.get(item.key) }} · {{ roundName(item) }}</span>
                    <span>{{ item.events.length }} 条原始事件</span>
                  </span>
                  <span class="ac-review-link">查看证据<el-icon aria-hidden="true"><ArrowRight /></el-icon></span>
                </span>
              </span>
            </button>
          </li>
        </ol>
        <el-empty v-else description="当前记录未见拦截、需确认或威胁告警节点">
          <el-button size="small" plain @click="readingMode = 'full'">查看完整过程</el-button>
        </el-empty>
        <div v-if="reviewRows.length > 20" class="ac-review-pagination">
          <el-pagination
            v-model:current-page="reviewPage"
            v-model:page-size="reviewSize"
            :total="reviewRows.length"
            :page-sizes="[20, 50, 100]"
            layout="total, sizes, prev, pager, next"
            :pager-count="5"
            size="small"
            aria-label="风险摘要分页"
            @current-change="scrollToReview"
            @size-change="scrollToReview"
          />
        </div>
      </section>
      <div v-else class="ac-workspace">
        <section class="ac-timeline" aria-label="链路时间线">
          <div class="ac-controls">
            <div class="ac-section-heading">
              <div>
                <h3>
                  链路时间线 <span class="muted">{{ filtered.length }} / {{ view.all.length }} 个节点</span>
                </h3>
              </div>
              <el-button size="small" plain :disabled="!pageItems.length" @click="togglePage">{{
                pageExpanded ? "收起本页" : "展开本页"
              }}</el-button>
            </div>
            <div class="ac-timeline-options">
              <el-switch
                v-model="detailedNodes"
                size="small"
                active-text="显示节点摘要"
                aria-label="显示节点摘要"
              />
              <span class="muted fs-12"
                >{{ view.stats.calls }} 次工具调用 · {{ view.stats.events }} 条原始事件</span
              >
            </div>
            <details class="ac-advanced">
              <summary>搜索与筛选{{ hasFilters ? " · 已启用" : "" }}</summary>
              <div class="ac-filter-row">
                <el-input
                  v-model="search"
                  clearable
                  size="small"
                  placeholder="搜索工具、资源、摘要、标签或事件 ID"
                  aria-label="搜索链路节点"
                  ><template #prefix
                    ><el-icon><Search /></el-icon></template
                ></el-input>
                <el-select
                  v-model="nodeType"
                  size="small"
                  placeholder="全部节点类型"
                  aria-label="筛选节点类型"
                >
                  <el-option label="全部节点类型" value="" />
                  <el-option v-for="(name, type) in typeName" :key="type" :label="name" :value="type" />
                </el-select>
                <el-button size="small" plain :disabled="!hasFilters" @click="resetFilters"
                  >重置筛选</el-button
                >
              </div>
              <div class="ac-scopes" aria-label="节点显示范围">
                <button
                  v-for="s in scopes"
                  :key="s.key"
                  type="button"
                  :aria-pressed="scope === s.key"
                  :class="{ active: scope === s.key }"
                  @click="scope = s.key"
                >
                  {{ s.name }} <span>{{ s.count }}</span>
                </button>
              </div>
            </details>
            <div v-if="filtered.length" ref="listHeading" class="ac-list-heading">
              <span class="muted fs-12"
                >第 {{ (page - 1) * pageSize + 1 }}–{{
                  Math.min(page * pageSize, filtered.length)
                }}
                个节点</span
              >
              <el-pagination
                v-model:current-page="page"
                v-model:page-size="pageSize"
                :page-sizes="[20, 50, 100]"
                :total="filtered.length"
                size="small"
                layout="sizes, prev, pager, next"
                :pager-count="5"
                aria-label="会话链路顶部分页"
                @current-change="scrollToList"
                @size-change="scrollToList"
              />
            </div>
          </div>
          <ol v-if="pageItems.length" class="ac-flow">
            <template v-for="block in blocks" :key="block.key">
              <li v-if="block.heading" class="ac-round">
                <h4>{{ block.heading }}</h4>
              </li>
              <li
                v-for="item in block.items"
                :key="item.key"
                :id="nodeId(item.key)"
                class="ac-node"
                :class="{ risk: item.risk, gap: item.evidenceGap, selected: selectedKey === item.key }"
                :data-decision="item.decision?.decision || ''"
                :data-type="item.type"
              >
                <button
                  type="button"
                  class="ac-node-main"
                  :aria-expanded="expanded.has(item.key)"
                  :aria-controls="nodeId(item.key) + '-details'"
                  :aria-label="'查看节点：' + item.title"
                  @click="toggle(item.key)"
                >
                  <div class="ac-node-heading">
                    <span class="ac-node-type">{{ typeName[item.type] }}</span
                    ><strong>{{ item.title }}</strong>
                    <span class="ac-node-time mono" :title="fmt(item.timestamp)">{{
                      fmtTime(item.timestamp)
                    }}</span>
                    <span class="ac-node-toggle"
                      >{{ item.events.length }} 条原始事件<el-icon :class="{ open: expanded.has(item.key) }"
                        ><ArrowRight /></el-icon
                    ></span>
                  </div>
                  <div v-if="!detailedNodes && (item.risk || item.evidenceGap)" class="ac-node-brief">
                    <span class="dec-tag" :class="outcomeClass(item)">{{ outcomeText(item) }}</span
                    ><span>{{ itemHeadline(item) }}</span>
                  </div>
                  <div v-if="detailedNodes" class="ac-node-tags">
                    <span v-if="item.decision" class="dec-tag" :class="dispositionTag(item.decision)">{{
                      item.resultBlocked && item.decision.decision === "ALLOW"
                        ? "请求放行"
                        : dispositionLabel(item.decision)
                    }}</span>
                    <span
                      v-if="item.decision?.severity"
                      class="sev-tag"
                      :class="'sev-' + item.decision.severity"
                      >{{ item.decision.severity }}</span
                    >
                    <span v-if="item.decision?.reason_code" class="ac-reason">{{
                      threatText(item.decision.reason_code)
                    }}</span>
                    <el-tag v-if="item.alert" size="small" type="danger" effect="plain">威胁告警</el-tag>
                    <el-tag v-if="item.resultBlocked" size="small" type="danger" effect="plain"
                      >返回已拦截</el-tag
                    >
                    <el-tag v-if="item.linkNote" size="small" type="warning" effect="plain">{{
                      linkNoteName(item.linkNote)
                    }}</el-tag>
                    <el-tag v-if="item.unresolvedDecision" size="small" type="warning" effect="plain"
                      >决策未关联</el-tag
                    >
                    <el-tag
                      v-if="item.decision?.anomaly?.anomalous"
                      size="small"
                      type="warning"
                      effect="plain"
                      >行为异常 {{ item.decision.anomaly.score }}</el-tag
                    >
                    <el-tag
                      v-for="l in riskLabels(item)"
                      :key="l"
                      size="small"
                      type="danger"
                      effect="plain"
                      :title="l"
                      >{{ threatText(l) }}</el-tag
                    >
                    <span v-if="!item.decision && !item.unresolvedDecision" class="muted">无关联决策</span>
                  </div>
                  <div
                    v-if="detailedNodes && item.resource"
                    class="ac-node-resource mono"
                    :title="item.resource"
                  >
                    {{ item.resource }}
                  </div>
                  <div v-for="(l, i) in detailedNodes ? item.lines : []" :key="i" class="ac-node-line">
                    <span v-if="l.label">{{ l.label }}</span
                    ><span class="mono" :title="l.text">{{ codeListText(l.text) }}</span>
                  </div>
                </button>
                <div
                  v-if="expanded.has(item.key)"
                  :id="nodeId(item.key) + '-details'"
                  class="ac-node-details"
                >
                  <div class="ac-detail-heading">
                    <span>原始事件</span>
                    <el-button size="small" text @click="collapse(item)">收起节点</el-button>
                  </div>
                  <div v-for="e in item.events" :key="e.event_id" class="ac-raw-event">
                    <ChainEventDetail :n="e" />
                    <details class="ac-event-fields">
                      <summary>事件标识与关联字段</summary>
                      <dl>
                        <dt>事件 ID</dt>
                        <dd><CopyText :text="e.event_id" /></dd>
                        <dt>发生时间</dt>
                        <dd class="mono">{{ fmt(e.timestamp) }}</dd>
                        <template v-if="e.call_id"
                          ><dt>调用 ID</dt>
                          <dd><CopyText :text="e.call_id" /></dd
                        ></template>
                        <template v-if="e.decision_id || e.decision?.decision_id"
                          ><dt>决策 ID</dt>
                          <dd><CopyText :text="e.decision_id || e.decision.decision_id" /></dd
                        ></template>
                        <template v-if="e.resource"
                          ><dt>资源</dt>
                          <dd class="mono">{{ e.resource }}</dd></template
                        >
                      </dl>
                    </details>
                  </div>
                </div>
              </li>
            </template>
          </ol>
          <el-empty v-else :description="view.all.length ? '没有匹配的链路节点' : '当前会话暂无事件记录'">
            <el-button v-if="hasFilters" size="small" @click="resetFilters">清除节点筛选</el-button>
          </el-empty>
          <div v-if="filtered.length" class="ac-list-footer">
            <span class="muted fs-12">共 {{ filtered.length }} 个节点</span>
            <el-pagination
              v-model:current-page="page"
              v-model:page-size="pageSize"
              :page-sizes="[20, 50, 100]"
              :total="filtered.length"
              size="small"
              layout="sizes, prev, pager, next"
              :pager-count="5"
              aria-label="会话链路底部分页"
              @current-change="scrollToList"
              @size-change="scrollToList"
            />
          </div>
        </section>
        <aside class="ac-navigation" aria-label="链路定位">
          <div class="ac-navigation-card">
            <h3>快速定位</h3>
            <label for="chain-round">跳转轮次</label>
            <el-select
              id="chain-round"
              v-model="roundTarget"
              size="small"
              placeholder="选择轮次"
              aria-label="跳转链路轮次"
              @change="jumpRound"
            >
              <el-option v-for="r in roundOptions" :key="r.key" :label="r.label" :value="r.key" />
            </el-select>
            <div class="ac-risk-heading">
              <b>风险相关 {{ risks.length }}</b
              ><span class="muted">{{ riskPosition }}</span>
            </div>
            <div class="ac-risk-actions">
              <el-button size="small" :disabled="!previousRisk" @click="jumpTo(previousRisk)"
                >上一风险</el-button
              >
              <el-button size="small" :disabled="!nextRisk" @click="jumpTo(nextRisk)">下一风险</el-button>
            </div>
          </div>
        </aside>
      </div>
      <el-dialog
        v-model="detailVisible"
        :title="detailItem?.risk ? '风险节点详情' : '关联证据详情'"
        width="960px"
        top="6vh"
        class="ac-focus-dialog"
        append-to-body
        destroy-on-close
      >
        <ChainRiskDetail v-if="detailItem" :key="detailItem.key" :item="detailItem" />
        <template #footer
          ><el-button @click="detailVisible = false">关闭</el-button
          ><el-button type="primary" @click="locateDetail">在完整链路中查看前后经过</el-button></template
        >
      </el-dialog>
    </template>
    <el-empty v-else-if="chainError" description="暂时无法加载会话链路">
      <el-button size="small" type="primary" :loading="chainLoading" @click="openChain(chainId)"
        >重新加载链路</el-button
      >
    </el-empty>
    <el-empty v-else-if="chainId" :description="chainNotFound ? '未找到该会话链路' : '该标识暂无链路记录'">

      <el-button size="small" :loading="chainLoading" @click="openChain(chainId)">重新查询</el-button>
    </el-empty>
    <el-empty v-else description="暂无会话链路">
      <div class="ac-empty-actions">
        <el-button size="small" @click="tab = 'threat'">前往威胁中心</el-button>
        <el-button size="small" @click="tab = 'events'">前往运行审计</el-button>
      </div>
    </el-empty>
  </section>
</template>

<script setup>
import { computed, ref, watch, nextTick } from "vue";
import { ElMessage } from "element-plus";
import ChainEventDetail from "./chain/ChainEventDetail.vue";
import ChainRiskDetail from "./chain/ChainRiskDetail.vue";
import ChainStages from "./chain/ChainStages.vue";
import CopyText from "../components/CopyText.vue";
import AgentIcon from "../components/AgentIcon.vue";
import { buildChainView } from "../utils/chainGroups";
import { buildDetectionStages, chronologicalItems, CHAIN_SEVERITIES } from "../utils/chainPresentation";
import {
  tab,
  chainInput,
  chain,
  chainId,
  chainLoading,
  chainLoadedId,
  chainError,
  chainNotFound,
  chainUpdatedAt,
  recentBlockedTraces,
  AGENT_NAMES,
  isRiskLabel,
  threatText,
  dispositionTag,
  dispositionLabel,
  openChain,
  returnFromChain,
  returnToAudit,
  chainReturnLabel,
  stageName,
  linkNoteName,
} from "../store/runtime";
import { fmt, fmtTime, codeListText, MALICIOUS } from "../utils/format";
import "./chain/chain.css";

const currentLoaded = computed(() => !!chainLoadedId.value && chainLoadedId.value === chainId.value);
const hasChain = computed(
  () =>
    currentLoaded.value &&
    !!(chain.value.task || chain.value.chain?.length || chain.value.state?.taints?.length),
);
const view = computed(() => buildChainView(chain.value.chain, stageName));
const readingMode = ref("focus"),
  showLookup = ref(false),
  detailedNodes = ref(false);
const reviewPage = ref(1),
  reviewSize = ref(20),
  detailVisible = ref(false),
  detailItem = ref(null);
const isPending = (item) => item.decision?.decision === "ASK" && !item.decision.resolution;
const risks = computed(() => view.value.all.filter((i) => i.risk));
const gaps = computed(() => view.value.all.filter((i) => i.evidenceGap));
const isInterception = (item) => item.decision?.decision === "DENY" || item.resultBlocked || item.alert;
const reviewPriority = (item) =>
  isPending(item) ? 0 : isInterception(item) ? 1 : item.decision?.resolution === "UNKNOWN" ? 2 : 3;
const orderedRisks = computed(() => [...risks.value].sort((a, b) => reviewPriority(a) - reviewPriority(b)));
const recommended = computed(() => orderedRisks.value[0] || gaps.value[0]);
const focusHeadline = computed(() =>
  view.value.stats.pending
    ? "有 " + view.value.stats.pending + " 个待确认节点"
    : risks.value.length
      ? "发现 " + risks.value.length + " 个风险相关节点"
      : gaps.value.length
        ? "有 " + gaps.value.length + " 处证据缺口"
        : "当前记录未见风险处置",
);

const reviewRows = computed(() => chronologicalItems(readingMode.value === "gaps" ? gaps.value : risks.value));
const nodeNumbers = computed(() => new Map(view.value.all.map((item, index) => [item.key, index + 1])));
const itemStage = (item) => stageSteps.value.filter((step) => step.item?.key === item.key).map((step) => step.label).join(' · ') || typeName[item.type];
const itemRule = (item) => {
  const ids = [...new Set((item.decision?.matched_rules || []).map((rule) => rule.rule_id).filter(Boolean))];
  return ids.length > 1 ? ids[0] + ' +' + (ids.length - 1) : ids[0];
};
const reviewItems = computed(() =>
  reviewRows.value.slice((reviewPage.value - 1) * reviewSize.value, reviewPage.value * reviewSize.value),
);
function itemHeadline(item) {
  if (readingMode.value === "gaps" || !item.risk)
    return item.unresolvedDecision ? "关联决策未找到" : "调用关联证据缺失";
  if (item.resultBlocked) return "工具返回内容被拦截";
  const reason = item.decision?.reason_code,
    label = reason && threatText(reason);
  return label && label !== reason ? label : item.alert ? "记录了威胁告警" : "工具调用触发风险处置";
}
const outcomeText = (item) =>
  item.resultBlocked
    ? "返回已拦截"
    : item.evidenceGap && !item.risk
      ? item.unresolvedDecision
        ? "决策未关联"
        : "关联证据缺失"
      : item.decision
        ? dispositionLabel(item.decision)
        : item.unresolvedDecision
          ? "决策未关联"
          : item.evidenceGap
            ? "关联证据缺失"
            : "威胁告警";
const outcomeClass = (item) =>
  item.resultBlocked
    ? "dec-tag-DENY"
    : item.evidenceGap && !item.risk
      ? "dec-tag-NONE"
      : item.decision
        ? dispositionTag(item.decision)
        : "dec-tag-NONE";
function openDetail(item) {
  detailItem.value = item;
  detailVisible.value = true;
}
async function locateDetail() {
  const item = detailItem.value;
  detailVisible.value = false;
  await jumpTo(item);
}
async function scrollToReview() {
  await nextTick();
  document
    .querySelector(".ac-review")
    ?.scrollIntoView({ behavior: reducedMotion() ? "instant" : "smooth", block: "start" });
}
watch([readingMode, reviewSize], () => {
  reviewPage.value = 1;
});
watch(
  () => reviewRows.value.length,
  (count) => {
    reviewPage.value = Math.min(reviewPage.value, Math.max(1, Math.ceil(count / reviewSize.value)));
  },
);
watch(tab, () => {
  detailVisible.value = false;
});
const typeName = { start: "任务开始", model: "模型", call: "工具调用", event: "独立事件", end: "任务结束" };
const knownScenario = computed(() =>
  MALICIOUS.has(chain.value.scenario) || ["B-RD", "B-OPS", "B-SEC", "B-SUP"].includes(chain.value.scenario)
    ? chain.value.scenario
    : "",
);
const timeRange = computed(() => {
  const times = (chain.value.chain || [])
    .map((e) => e.timestamp)
    .filter(Boolean)
    .sort();
  return times.length ? fmt(times[0]) + " ～ " + fmt(times[times.length - 1]) : "未记录";
});
const durationText = computed(() => {
  const ms = view.value.stats.durationMs;
  if (ms < 1000) return ms + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(1) + " 秒";
  if (ms < 3600000) return Math.floor(ms / 60000) + " 分 " + Math.floor((ms % 60000) / 1000) + " 秒";
  return Math.floor(ms / 3600000) + " 小时 " + Math.floor((ms % 3600000) / 60000) + " 分";
});
const search = ref(""),
  nodeType = ref(""),
  scope = ref("all");
const page = ref(1),
  pageSize = ref(20),
  listHeading = ref(null);
const expanded = ref(new Set()),
  selectedKey = ref(""),
  roundTarget = ref("");
const scopes = computed(() => [
  { key: "all", name: "全部节点", count: view.value.all.length },
  { key: "risk", name: "风险相关", count: view.value.stats.risks },
  { key: "gap", name: "证据缺口", count: view.value.stats.gaps },
]);
const filtered = computed(() =>
  view.value.all.filter((item) => {
    if ((scope.value === "risk" && !item.risk) || (scope.value === "gap" && !item.evidenceGap)) return false;
    if (nodeType.value && nodeType.value !== item.type) return false;
    const text = search.value.trim().toLowerCase();
    if (!text) return true;
    const hay = [
      item.title,
      item.resource,
      item.key,
      ...item.lines.map((l) => l.text),
      ...item.labels.flatMap((l) => [l, threatText(l)]),
      item.decision?.reason_code,
      threatText(item.decision?.reason_code || ""),
      ...item.events.flatMap((e) => [e.event_id, e.call_id, e.tool, e.mcp_server, e.source]),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.includes(text);
  }),
);
const pageItems = computed(() =>
  filtered.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value),
);
const roundName = (item) => (item.round > 0 ? "第 " + item.round + " 轮" : "轮次外");
const blocks = computed(() => {
  const out = [];
  for (const item of pageItems.value) {
    const key = item.type === "start" || item.type === "end" ? item.key : "r" + item.round;
    let block = out[out.length - 1];
    if (!block || block.key !== key) {
      const first = view.value.all.find(
        (n) => n.type !== "start" && n.type !== "end" && n.round === item.round,
      );
      block = {
        key,
        heading:
          item.type === "start" || item.type === "end"
            ? ""
            : roundName(item) + (first !== item ? "（续）" : ""),
        items: [],
      };
      out.push(block);
    }
    block.items.push(item);
  }
  return out;
});
const hasFilters = computed(() => !!search.value || !!nodeType.value || scope.value !== "all");
function resetFilters() {
  search.value = "";
  nodeType.value = "";
  scope.value = "all";
}
watch([search, nodeType, scope, pageSize], () => {
  page.value = 1;
});
watch(
  () => filtered.value.length,
  (count) => {
    page.value = Math.min(page.value, Math.max(1, Math.ceil(count / pageSize.value)));
  },
);
watch(chainLoadedId, () => {
  readingMode.value = risks.value.length ? "focus" : gaps.value.length ? "gaps" : "full";
  showLookup.value = false;
  detailedNodes.value = false;
  detailVisible.value = false;
  reviewPage.value = 1;
  resetFilters();
  page.value = 1;
  expanded.value = new Set();
  selectedKey.value = "";
  roundTarget.value = "";
});
watch(view, (v) => {
  const keys = new Set(v.all.map((i) => i.key));
  expanded.value = new Set([...expanded.value].filter((key) => keys.has(key)));
  if (!keys.has(selectedKey.value)) selectedKey.value = "";
});
const nodeId = (key) => "chain-node-" + encodeURIComponent(key);
function toggle(key) {
  const next = new Set(expanded.value);
  next.has(key) ? next.delete(key) : next.add(key);
  expanded.value = next;
  selectedKey.value = key;
}
async function collapse(item) {
  const next = new Set(expanded.value);
  next.delete(item.key);
  expanded.value = next;
  await nextTick();
  document.getElementById(nodeId(item.key))?.querySelector(".ac-node-main")?.focus({ preventScroll: true });
}
const pageExpanded = computed(
  () => pageItems.value.length > 0 && pageItems.value.every((i) => expanded.value.has(i.key)),
);
function togglePage() {
  const next = new Set(expanded.value);
  for (const item of pageItems.value) pageExpanded.value ? next.delete(item.key) : next.add(item.key);
  expanded.value = next;
}
const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
async function scrollToList() {
  await nextTick();
  if (listHeading.value?.getBoundingClientRect().top < 0)
    listHeading.value.scrollIntoView({ behavior: reducedMotion() ? "instant" : "smooth", block: "start" });
}
async function jumpTo(item) {
  if (!item) return;
  if (!view.value.all.some((n) => n.key === item.key)) {
    ElMessage.info("当前链路中未找到该节点，请刷新后重试");
    return;
  }
  readingMode.value = "full";
  resetFilters();
  await nextTick();
  const index = filtered.value.findIndex((n) => n.key === item.key);
  page.value = Math.floor(index / pageSize.value) + 1;
  selectedKey.value = item.key;
  expanded.value = new Set([...expanded.value, item.key]);
  roundTarget.value = "";
  await nextTick();
  const el = document.getElementById(nodeId(item.key));
  el?.scrollIntoView({ behavior: reducedMotion() ? "instant" : "smooth", block: "start" });
  el?.querySelector(".ac-node-main")?.focus({ preventScroll: true });
}
const selectedIndex = computed(() => view.value.all.findIndex((i) => i.key === selectedKey.value));
const previousRisk = computed(() =>
  [...risks.value].reverse().find((i) => view.value.all.indexOf(i) < selectedIndex.value),
);
const nextRisk = computed(() => risks.value.find((i) => view.value.all.indexOf(i) > selectedIndex.value));
const riskPosition = computed(() => {
  const index = risks.value.findIndex((i) => i.key === selectedKey.value);
  return index >= 0 ? index + 1 + " / " + risks.value.length : "按节点顺序";
});
const roundOptions = computed(() =>
  view.value.rounds.map((r) => ({
    key: r.items[0].key,
    label: roundName(r.items[0]) + " · " + r.items.length + " 个节点",
  })),
);
const jumpRound = (key) => jumpTo(view.value.all.find((i) => i.key === key));
const riskLabels = (item) =>
  item.labels
    .filter((l) => isRiskLabel(l) && l !== item.decision?.reason_code && l !== "RESULT_BLOCKED")
    .slice(0, 2);
const stageSteps = computed(() => buildDetectionStages(chain.value.stages, view.value.all));
function lookup() {
  if (chainInput.value.trim()) openChain(chainInput.value);
}
async function copyLink() {
  try {
    await navigator.clipboard.writeText(location.href);
    ElMessage.success("已复制会话链路链接");
  } catch {
    ElMessage.warning("复制失败，请手动复制地址栏链接");
  }
}
</script>
