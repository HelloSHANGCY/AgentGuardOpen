// 运行时视图共享状态：威胁中心 / 运行审计 / 会话链路 / 策略，以及 SSE 与轮询。
import { ref, computed, watch, nextTick } from "vue";
import { ElNotification } from "element-plus";
import { api } from "../api/client";
import { createPageNavigation } from "../utils/pageNavigation";
import { auditHash, parseAuditHash } from "../utils/auditNavigation";
import { ruleHash, parseRuleHash } from "../utils/ruleNavigation";
import { deploymentHash, parseDeploymentHash } from "../utils/deploymentNavigation";
import { threatJudgment, judgmentDescription } from "../utils/threatJudgment";
import {
  fmt, fmtTime, codeListText, scenarioOf, isMalicious, decisionName, pct, isRiskLabel, stageName, nodeKind, threatText,
  stackSourceName, frameSource, frameText, attributionName, linkNoteName,
  dispositionOf, DISPOSITIONS, dispositionTag, dispositionLabel,
  REVIEW_TEXT, VERDICT_TEXT, VERDICT_TAG, RISK_TEXT, ASSESSMENT_TEXT,
} from "../utils/format";

export {
  fmt, fmtTime, codeListText, scenarioOf, isMalicious, decisionName, pct, isRiskLabel, stageName, nodeKind, threatText,
  stackSourceName, frameSource, frameText, attributionName, linkNoteName,
  dispositionOf, DISPOSITIONS, dispositionTag, dispositionLabel,
  REVIEW_TEXT, VERDICT_TEXT, VERDICT_TAG, RISK_TEXT, ASSESSMENT_TEXT,
};

const pageNavigation = createPageNavigation("threat");
export const tab = pageNavigation.page;
export const registerPageLeaveGuard = pageNavigation.registerGuard;
export const sseOn = ref(false);
export const threats = ref([]);
// 行为观察：行为基线超阈值、但规则放行的步骤（创新检测实施方案 §5.2），只展示不拦截。
export const observations = ref([]);
// 大模型异步分析判为可疑 / 恶意的会话（每个会话轮次取最近一次分析），作为会话级告警并入威胁中心。
export const riskyAnalyses = ref([]);
export const events = ref([]);
// 事件与其决策一起更新，暂停时保留同一批快照，独立于威胁中心的有限告警窗口。
export const eventDecisions = ref([]);
export const eventsLoading = ref(false), eventsLoaded = ref(false), eventsError = ref("");
export const eventsUpdatedAt = ref(""), eventsCheckedAt = ref("");
export const eventDecisionsUnavailable = ref(false);
// 事件流：前端筛选 + 分页；加载范围为最近 N 条，eventsTotal 为服务端保存的事件总数。
export const EVENT_WINDOWS = [400, 1000, 2000, 5000];
export const eventsWindow = ref(400);
export const eventsLoadedWindow = ref(400);
export const eventsTotal = ref(0);
export const ePage = ref(1);
export const ePageSize = ref(20);
export const metrics = ref({});
// 侧栏显示的规则版本（/v1/runtime/policies）。
export const policies = ref({ manifests: {} });
export const freshId = ref("");
export const fScenario = ref(""), fSev = ref(""), fText = ref(""), fDecision = ref(""), fSource = ref("");
export const onlyBlocked = ref(false), eText = ref("");
export const eDecision = ref(""), eSource = ref(""), eStage = ref(""), hideHookDup = ref(false);
export const eTrace = ref(""), eOrder = ref("recent");
// 暂停时仍在后台拉取，新数据先放在 pendingEvents，由用户决定何时加载，避免正在阅读的行跳走。
export const eventsPaused = ref(false), pendingEvents = ref(null);
export const pendingEventsMeta = ref(null);
export const chainInput = ref("");
export const chain = ref({});
export const chainId = ref(""), chainLoading = ref(false);
export const chainLoadedId = ref(""), chainError = ref(""), chainNotFound = ref(false), chainUpdatedAt = ref("");
export const chainOrigin = ref(null);
const CHAIN_ORIGIN_NAMES = { events: "运行审计", threat: "威胁中心", metrics: "评测与指标", judge: "大模型研判",
  baseline: "行为基线", rules: "规则库", terminals: "终端管控", models: "模型管理", static: "静态资产" };
export const chainReturnLabel = computed(() => "返回" + (CHAIN_ORIGIN_NAMES[chainOrigin.value?.page] || "运行审计"));
export const runtimeError = ref(""), runtimeLoaded = ref(false);
export const threatsLoading = ref(false), threatsUpdatedAt = ref(""), threatsError = ref("");
export const analysesUnavailable = ref(false);
// 大模型异步分析完成的推送计数：「大模型研判」页据此刷新。
export const analysisTick = ref(0);
// 规则建议生成完成的推送计数：「大模型研判」页据此刷新。
export const proposalTick = ref(0);

export const stats = computed(() => {
  const list = threats.value;
  const denied = list.filter((t) => t.decision === "DENY");
  return {
    denied: denied.length,
    critical: denied.filter((t) => t.severity === "CRITICAL").length,
    asked: list.filter((t) => t.decision === "ASK" && !t.resolution).length,
    approved: list.filter((t) => t.resolution === "APPROVED").length,
    notExecuted: list.filter((t) => t.resolution === "NOT_EXECUTED").length,
    released: list.filter((t) => t.decision === "ALLOW").length,
    allowed: (metrics.value.totals?.decision_counts?.ALLOW) || 0,
    traceBlocked: new Set(denied.map((t) => t.trace_id)).size,
    alerts: alerts.value.filter((a) => a.disposition !== "OBSERVE").length,
    observed: alerts.value.filter((a) => a.disposition === "OBSERVE").length,
    flagged: riskyAnalyses.value.length,
    sessions: new Set([...list, ...riskyAnalyses.value].map((t) => t.trace_id)).size,
  };
});

export const lastBlocked = computed(() => threats.value.find((t) => t.decision === "DENY") || null);

export const scenarios = computed(() => [...new Set(alerts.value.map((a) => scenarioOf(a.latest.trace_id)))].filter(Boolean).sort());

// ---- 同一会话、原因、来源、工具、对象与处置的重复触发合并；不同处置分别保留，避免掩盖执行结果。 ----
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

// 已接入的通用 Agent（Hook 事件的 component）。
export const AGENT_NAMES = { "claude-code": "Claude Code", codex: "Codex", trae: "Trae", qoder: "Qoder", zcode: "ZCode", workbuddy: "WorkBuddy", codebuddy: "CodeBuddy" };

// 告警主体：哪个 Agent / 哪个入口发起的行为。
export const alertSource = (d) => {
  const ctx = d.context || {};
  if (AGENT_NAMES[ctx.component]) return { key: ctx.component, label: AGENT_NAMES[ctx.component] };
  if (ctx.source === "mcp-gateway" || (!ctx.source && d.server)) return { key: "gateway", label: "MCP 网关" };
  if (/guard/.test(ctx.source || "")) return { key: "guard", label: "Guard" };
  if (ctx.source === "agent-hook") return { key: "hook", label: "Agent Hook" };
  return { key: "other", label: "入口" };
};

// 触发对象：resource 形如 "exec:<cmd>" / "file_read:<path>"，拆成动作与对象；没有 resource 时退回请求摘要。
const ACTION_VERB = {
  exec: "执行命令", file_read: "读取文件", file_write: "写入文件", mcp_call: "调用 MCP 工具",
  net_fetch: "访问网址", net_search: "联网搜索", egress: "出网",
};
export const alertTarget = (d) => {
  const ctx = d.context || {};
  const m = /^([a-z_]+):(.*)$/s.exec(ctx.resource || "");
  if (m && ACTION_VERB[m[1]]) return { verb: ACTION_VERB[m[1]], object: m[2] };
  const tool = [d.server, d.tool].filter(Boolean).join(" / ");
  // 工具返回阶段的摘要是返回内容而非请求，不当作触发对象。
  const preview = /RESULT/.test(ctx.stage || "") ? "" : ctx.preview;
  return { verb: tool ? "调用 " + tool : "", object: ctx.resource || preview || "" };
};

// 分析告警：一个会话轮次一条；级别取模型给出的风险，未给出时恶意按 HIGH、可疑按 MEDIUM。
const RISK_SEV = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
const analysisAlert = (r) => {
  const severity = RISK_SEV[r.risk] || (r.verdict === "malicious" ? "HIGH" : "MEDIUM");
  const d = { decision_id: r.analysis_id, trace_id: r.trace_id, created_at: r.finished_at || r.created_at, severity,
              reason_code: "LLM_ANALYSIS_" + r.verdict.toUpperCase(), context: { component: r.agent } };
  return { key: ["analysis", r.trace_id, r.round].join("|"), latest: d, items: [d], count: 1, severity,
           disposition: "LLM_FLAGGED", first_at: d.created_at, last_at: d.created_at, analysis: r,
           source: { key: "judge", label: "大模型研判" },
           target: { verb: r.round ? `第 ${r.round} 轮` : "整个会话", object: r.summary || "" } };
};

export const alerts = computed(() => {
  const groups = new Map();
  // threats 按时间倒序，第一条即该组最近一次。
  const merged = [...threats.value, ...observations.value]
    .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  for (const d of merged) {
    const target = alertTarget(d);
    const source = alertSource(d), disposition = dispositionOf(d);
    const key = JSON.stringify([d.trace_id, d.reason_code, source.key, d.server, d.tool, target.object, disposition]);
    let a = groups.get(key);
    if (!a) {
      a = { key, latest: d, items: [], count: 0, severity: d.severity, disposition,
            first_at: d.created_at, last_at: d.created_at, source, target };
      groups.set(key, a);
    }
    a.items.push(d);
    a.count += 1;
    a.first_at = d.created_at;
    if ((SEV_RANK[d.severity] || 0) > (SEV_RANK[a.severity] || 0)) a.severity = d.severity;
  }
  return [...groups.values(), ...riskyAnalyses.value.map(analysisAlert)]
    .map(a => ({ ...a, judgment: threatJudgment(a) }))
    .sort((a, b) => (b.last_at || "").localeCompare(a.last_at || ""));
});

// 允许威胁中心在暂停时对固定快照应用同一套筛选条件。
export const filterAlerts = (records) => records.filter((a) => {
  const d = a.latest;
  if (fScenario.value && scenarioOf(d.trace_id) !== fScenario.value) return false;
  if (fSev.value && a.severity !== fSev.value) return false;
  if (fDecision.value && a.disposition !== fDecision.value) return false;
  if (fSource.value && a.source.key !== fSource.value) return false;
  if (fText.value.trim()) {
    const hay = [d.reason_code, threatText(d.reason_code), d.tool, d.server, d.trace_id, a.target.object,
      a.source.label, AGENT_NAMES[a.analysis?.agent], d.context?.actor, judgmentDescription(a.judgment || threatJudgment(a)),
      ...(a.analysis?.findings || []).map((f) => f.title)].join(" ").toLowerCase();
    if (!hay.includes(fText.value.trim().toLowerCase())) return false;
  }
  return true;
});
export const filteredAlerts = computed(() => filterAlerts(alerts.value));

export const recentBlockedTraces = computed(() =>
  [...new Set(threats.value.filter((t) => t.decision === "DENY").map((t) => t.trace_id))].slice(0, 8));

// 事件来源归类：网关 / Agent Hook / Guard（Langflow 入口与出网）。
// Claude Code / Codex 等通用 Agent 的 Hook 事件按 Agent 单独归类：内置工具的拦截记录只在 Hook 侧产生。
export const eventSource = (e) => (e.source === "mcp-gateway" ? "gateway"
  : e.source === "agent-hook" ? (AGENT_NAMES[e.component] ? e.component : "hook")
    : e.source === "llm-judge" ? "judge"
    : /guard/.test(e.source || "") ? "guard" : "other");
export const EVENT_SOURCE_NAMES = { gateway: "MCP 网关", hook: "Agent Hook", ...AGENT_NAMES, guard: "Guard", judge: "大模型研判", other: "其他" };
const eventCallKey = (e) => JSON.stringify([e.trace_id, e.call_id]);

// 事件与决策精确关联：优先 event.decision_id，其次决策 evidence_ids 中登记的事件 ID；
// 同一 call_id 下任一事件被拦截/待确认，整次调用的其余事件继承该结论（标记 inherited）。
// 决策未出现在已加载窗口时明确标为未关联，不能推断为放行。
export const eventRows = computed(() => {
  const byId = new Map(), byEvent = new Map();
  for (const d of eventDecisions.value) {
    byId.set(d.decision_id, d);
    for (const id of d.evidence_ids || []) if (!byEvent.has(id)) byEvent.set(id, d);
  }
  const rows = events.value.map((e) => {
    const decision = byId.get(e.decision_id) || byEvent.get(e.event_id) || null;
    return { ...e, decision, unresolvedDecision: !!e.decision_id && !decision, inherited: false, sourceKind: eventSource(e) };
  });
  const rank = { DENY: 3, ASK: 2, ALLOW: 1 };
  const callDecision = new Map();
  for (const r of rows) {
    if (!r.call_id || !r.decision) continue;
    const key = eventCallKey(r), prev = callDecision.get(key);
    if (!prev || rank[r.decision.decision] > rank[prev.decision]) callDecision.set(key, r.decision);
  }
  for (const r of rows) {
    // 已有明确决策 ID 的事件保留未关联状态，不用同调用的另一条决策覆盖。
    if (!r.decision && !r.decision_id && r.call_id && callDecision.has(eventCallKey(r))) {
      r.decision = callDecision.get(eventCallKey(r));
      r.inherited = true;
    }
    r.risk = r.stage === "THREAT_ALERT" || ["DENY", "ASK"].includes(r.decision?.decision);
  }
  return rows;
});

export const eventStages = computed(() => [...new Set(events.value.map((e) => e.stage))].sort());

// 有网关侧副本的 call_id：只有这些调用的 Hook 事件才算“重复”。
const gatewayCopies = computed(() => new Set(events.value
  .filter((e) => e.source === "mcp-gateway" && e.call_id && ["TOOL_REQUEST", "TOOL_RESULT"].includes(e.stage))
  .map((e) => eventCallKey(e) + "|" + e.stage)));

export const filteredEvents = computed(() => eventRows.value.filter((e) => {
  if (onlyBlocked.value && !e.risk) return false;
  if (eDecision.value && (e.decision?.decision || (e.unresolvedDecision ? "UNRESOLVED" : "NONE")) !== eDecision.value) return false;
  if (eSource.value && e.sourceKind !== eSource.value) return false;
  if (eStage.value && e.stage !== eStage.value) return false;
  if (eTrace.value.trim() && e.trace_id !== eTrace.value.trim()) return false;
  // 同一次调用在网关与 Hook 两侧各记一次；隐藏 Hook 侧的请求/返回副本。
  if (hideHookDup.value && e.call_id && /_HOOK$/.test(e.stage) && gatewayCopies.value.has(eventCallKey(e) + "|" + e.stage.replace(/_HOOK$/, ""))) return false;
  if (eText.value.trim()) {
    const hay = [e.trace_id, e.stage, stageName(e), e.tool, e.mcp_server, e.component, e.resource, e.task_id,
      e.event_id, e.call_id, e.redacted_preview, codeListText(e.redacted_preview),
      EVENT_SOURCE_NAMES[e.sourceKind], e.decision?.reason_code, threatText(e.decision?.reason_code),
      ...(e.labels || []).map(threatText)]
      .join(" ").toLowerCase();
    if (!hay.includes(eText.value.trim().toLowerCase())) return false;
  }
  return true;
}).sort((a, b) => eOrder.value === "oldest"
  ? (a.timestamp || "").localeCompare(b.timestamp || "")
  : (b.timestamp || "").localeCompare(a.timestamp || "")));

export const pagedEvents = computed(() => {
  const pageCount = Math.max(1, Math.ceil(filteredEvents.value.length / ePageSize.value));
  const page = Math.min(ePage.value, pageCount);
  return filteredEvents.value.slice((page - 1) * ePageSize.value, page * ePageSize.value);
});
// 筛选条件变化回到第一页；加载范围变化立即重新拉取。
watch([onlyBlocked, eText, eDecision, eSource, eStage, eTrace, eOrder, hideHookDup, ePageSize], () => { ePage.value = 1; });
watch(() => filteredEvents.value.length, n => { ePage.value = Math.min(ePage.value, Math.max(1, Math.ceil(n / ePageSize.value))); });
watch(eDecision, d => { if (["ALLOW", "NONE", "UNRESOLVED"].includes(d)) onlyBlocked.value = false; });
watch(onlyBlocked, value => { if (value && ["ALLOW", "NONE", "UNRESOLVED"].includes(eDecision.value)) eDecision.value = ""; });
watch(eventsWindow, () => refreshEvents());

export const newEventCount = computed(() => {
  if (!pendingEvents.value) return 0;
  const seen = new Set(events.value.map((e) => e.event_id));
  const newest = events.value.reduce((latest, e) => e.timestamp > latest ? e.timestamp : latest, "");
  return pendingEvents.value.filter((e) => !seen.has(e.event_id)
    && (pendingEventsMeta.value?.window === eventsLoadedWindow.value || !newest || e.timestamp > newest)).length;
});

const decisionSignature = decisions => JSON.stringify(decisions.map(d => [d.decision_id, d.decision, d.resolution, d.review, d.assessment]));
export const pendingEventsChanged = computed(() => !!pendingEvents.value && (
  pendingEventsMeta.value?.window !== eventsLoadedWindow.value
  || pendingEventsMeta.value?.decisionsUnavailable !== eventDecisionsUnavailable.value
  || pendingEvents.value.length !== events.value.length
  || pendingEvents.value.some((e, i) => e.event_id !== events.value[i]?.event_id)
  || decisionSignature(pendingEventsMeta.value?.decisions || []) !== decisionSignature(eventDecisions.value)
));

watch(eventsPaused, (paused) => { if (!paused) { loadPendingEvents(); refreshEvents(); } });

function applyEventSnapshot(snapshot) {
  if (eventsLoadedWindow.value !== snapshot.window) ePage.value = 1;
  events.value = snapshot.events;
  eventDecisions.value = snapshot.decisions;
  eventDecisionsUnavailable.value = snapshot.decisionsUnavailable;
  eventsTotal.value = snapshot.total;
  eventsLoadedWindow.value = snapshot.window;
  eventsUpdatedAt.value = snapshot.updatedAt;
}

export function loadPendingEvents() {
  if (pendingEvents.value && pendingEventsMeta.value) {
    applyEventSnapshot({ ...pendingEventsMeta.value, events: pendingEvents.value });
    ePage.value = 1;
  }
  pendingEvents.value = null;
  pendingEventsMeta.value = null;
}

export const scenarioRows = computed(() => Object.entries(metrics.value.scenarios || {}).map(([name, r]) => ({ name, ...r })));

export const c = () => metrics.value.confusion || {};

// 滑动 CPU：优先容器全部进程口径，读不到 /proc 时回退网关进程；首采无基线显示 '-'。
export const cpuVal = computed(() => {
  const cpu = metrics.value.cpu || {};
  const v = cpu.container_cpu_percent ?? cpu.window_cpu_percent;
  return v === undefined || v === null ? "-" : Number(v).toFixed(1);
});

// ---- 威胁中心：决策告警、模型研判与行为观察；正常流量不进入本页 ----
let threatsRefresh = null;
export function refreshThreats() {
  if (threatsRefresh) return threatsRefresh;
  threatsLoading.value = true;
  threatsRefresh = fetchThreats().finally(() => {
    threatsLoading.value = false;
    threatsRefresh = null;
  });
  return threatsRefresh;
}

async function fetchThreats() {
  try {
    const [denied, asked, released, observed, analyses, m] = await Promise.all([
      api("/v1/runtime/decisions?decision=DENY&limit=400"),
      api("/v1/runtime/decisions?decision=ASK&limit=400"),
      // 静态拦截 / 待确认、经大模型复核放行的，仍作为告警展示（处置为“模型放行”）。
      api("/v1/runtime/decisions?decision=ALLOW&reviewed=true&limit=200"),
      api("/v1/runtime/decisions?decision=ALLOW&anomalous=true&limit=200"),
      // 分析记录读取失败（如大模型研判未启用的旧版服务端）不影响其余告警。
      api("/v1/runtime/analyses?limit=200").catch(() => ({ analyses: [], unavailable: true })),
      api("/v1/runtime/metrics"),
    ]);
    threats.value = [...(denied.decisions || []), ...(asked.decisions || []), ...(released.decisions || [])]
      .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    // 放行决策的主原因码是默认放行，这里换成观察原因码并降为 LOW，便于和告警区分。
    const releasedIds = new Set((released.decisions || []).map((d) => d.decision_id));
    observations.value = (observed.decisions || []).filter((d) => !releasedIds.has(d.decision_id)).map((d) => ({
      ...d, observed: true, reason_code: "BEHAVIOR_ANOMALY_OBSERVED", severity: "LOW", safe_message: "",
    }));
    riskyAnalyses.value = analyses.analyses || [];
    analysesUnavailable.value = !!analyses.unavailable;
    metrics.value = m;
    threatsUpdatedAt.value = new Date().toISOString();
    threatsError.value = "";
    runtimeError.value = "";
  } catch (e) {
    threatsError.value = "运行时数据加载失败：" + e.message;
    runtimeError.value = threatsError.value;
  } finally {
    runtimeLoaded.value = true;
  }
}

let eventsRefresh = null, eventsRefreshWindow = 0, eventsSequence = 0;
export function refreshEvents() {
  const requestedWindow = eventsWindow.value;
  if (eventsRefresh && eventsRefreshWindow === requestedWindow) return eventsRefresh;
  const sequence = ++eventsSequence;
  eventsLoading.value = true;
  eventsRefreshWindow = requestedWindow;
  const request = fetchEvents(requestedWindow, sequence).finally(() => {
    if (eventsRefresh === request) eventsRefresh = null;
    if (sequence === eventsSequence) { eventsLoading.value = false; eventsLoaded.value = true; }
  });
  eventsRefresh = request;
  return request;
}

async function fetchEvents(requestedWindow, sequence) {
  try {
    const [data, decisions] = await Promise.all([
      api("/v1/runtime/events?limit=" + requestedWindow),
      api("/v1/runtime/decisions?limit=" + requestedWindow).catch(() => ({ decisions: [], unavailable: true })),
    ]);
    if (sequence !== eventsSequence) return;
    const snapshot = { events: data.events || [], decisions: decisions.decisions || [],
      decisionsUnavailable: !!decisions.unavailable, total: data.total ?? (data.events || []).length,
      window: requestedWindow, updatedAt: new Date().toISOString() };
    eventsCheckedAt.value = snapshot.updatedAt;
    if (eventsPaused.value && eventsUpdatedAt.value) {
      const { events: records, ...meta } = snapshot;
      pendingEvents.value = records;
      pendingEventsMeta.value = meta;
    } else {
      applyEventSnapshot(snapshot);
      pendingEvents.value = null;
      pendingEventsMeta.value = null;
    }
    eventsError.value = "";
  } catch (e) {
    if (sequence === eventsSequence) eventsError.value = "运行审计加载失败：" + e.message;
  }
}

let chainSequence = 0;
export async function openChain(trace) {
  const identifier = String(trace || "").trim();
  if (!identifier) return;
  const origin = { page: tab.value, index: historyIndex, scroll: window.scrollY };
  let sequence, retain;
  const allowed = await pageNavigation.navigate("chain", () => {
    if (origin.page !== "chain") chainOrigin.value = origin;
    sequence = ++chainSequence;
    retain = chainLoadedId.value === identifier;
    chainId.value = identifier;
    chainInput.value = identifier;
    chainLoading.value = true;
    chainError.value = "";
    chainNotFound.value = false;
  });
  if (!allowed) return;
  if (origin.page !== "chain" || !retain) nextTick(() => window.scrollTo({ top: 0, behavior: "instant" }));
  try {
    const snapshot = await api("/v1/runtime/traces/" + encodeURIComponent(identifier));
    if (sequence !== chainSequence) return;
    chain.value = snapshot;
    chainLoadedId.value = identifier;
    chainUpdatedAt.value = new Date().toISOString();
  } catch (e) {
    if (sequence !== chainSequence) return;
    if (!retain || e.status === 404) {
      chain.value = { trace_id: identifier };
      chainLoadedId.value = "";
      chainUpdatedAt.value = "";
    }
    chainNotFound.value = e.status === 404;
    if (!chainNotFound.value) chainError.value = "会话链路加载失败：" + e.message;
  } finally {
    if (sequence === chainSequence) chainLoading.value = false;
  }
}

export function returnFromChain() {
  const origin = chainOrigin.value;
  if (origin && Number.isInteger(origin.index) && origin.index < historyIndex) {
    history.go(origin.index - historyIndex);
  } else {
    tab.value = "events";
  }
}

export function returnToAudit() {
  if (chainOrigin.value?.page === "events") returnFromChain();
  else tab.value = "events";
}

export async function loadPolicies() {
  try {
    policies.value = await api("/v1/runtime/policies");
  } catch (e) {
    runtimeError.value = "规则版本加载失败：" + e.message;
  }
}

// ---- 页面状态同步到 URL hash；运行审计包含会话详情，兼容 #/events 与 #/chain/<trace>。 ----
export const TABS = ["threat", "events", "chain", "metrics", "deployment", "rules", "static", "terminals", "baseline", "judge", "models"];
export const deploymentPage = ref("architecture"), deploymentMethod = ref("docker");

export const TERMINAL_PAGES = [
  { key: "devices", label: "设备列表", icon: "List" },
  { key: "policies", label: "防护策略", icon: "Shield" },
  { key: "deploy", label: "客户端部署", icon: "Download" },
];
export const terminalTab = ref("devices");

// 评测与指标页的二级页签：评测任务 / 运行指标。
export const METRICS_TABS = ["eval", "runtime"];
export const metricsTab = ref("eval");
export const rulesTab = ref("features");
export const rulesTarget = ref("");
export const rulesRevision = ref("");

export function openRuleTarget(identifier, page = "features", revision = "") {
  return pageNavigation.navigate("rules", () => {
    rulesTab.value = page;
    rulesTarget.value = identifier;
    rulesRevision.value = revision;
  });
}

const hashFor = () => {
  if (tab.value === "events" || tab.value === "chain") return auditHash(tab.value === "chain" ? chainId.value : "");
  if (tab.value === "metrics") return "#/metrics/" + metricsTab.value;
  if (tab.value === "deployment") return deploymentHash(deploymentPage.value, deploymentMethod.value);
  if (tab.value === "terminals") return "#/terminals/" + terminalTab.value;
  if (tab.value === "rules") return ruleHash(rulesTab.value, rulesTarget.value, rulesRevision.value);
  return "#/" + tab.value;
};

let historyIndex = 0;
let applyingHash = false;
let pendingHash = null;
function applyHash() {
  const requested = location.hash;
  if (pendingHash === requested) return;
  let [name, ...rest] = requested.replace(/^#\/?/, "").split("/");
  if (!name) name = "threat";
  const audit = parseAuditHash(requested);
  const ruleRoute = parseRuleHash(requested);
  const deploymentRoute = parseDeploymentHash(requested);
  if (name === "rules" && !ruleRoute) return;
  if (audit) name = audit.page;
  const legacyTerminal = ["hooks", "devices", "client-deploy"].includes(name);
  if (legacyTerminal) {
    rest = [name === "client-deploy" ? "deploy" : "devices"];
    name = "terminals";
  }
  if (name === "llm") name = "models";
  if (name === "range") name = "deployment";
  if (!TABS.includes(name)) { history.replaceState(history.state, "", hashFor()); return; }
  let id;
  try { id = audit ? audit.identifier : decodeURIComponent(rest.join("/")); } catch { return; }
  const targetIndex = history.state?.agentguardPageIndex;
  const previousIndex = historyIndex;
  const previousPage = tab.value;
  const origin = chainOrigin.value;
  pendingHash = requested;
  const result = pageNavigation.navigate(name, () => {
    applyingHash = true;
    if (name === "chain") chainOrigin.value = history.state?.agentguardChainOrigin || null;
    if (name === "chain" && id && id !== chainId.value) openChain(id);
    if (name === "metrics" && METRICS_TABS.includes(id)) metricsTab.value = id;
    if (name === "terminals") terminalTab.value = TERMINAL_PAGES.some(page => page.key === id) ? id : "devices";
    if (name === "deployment") {
      deploymentPage.value = deploymentRoute?.page || "architecture";
      deploymentMethod.value = deploymentRoute?.method || "docker";
    }
    if (name === "rules") {
      rulesTab.value = ruleRoute.tab;
      rulesTarget.value = ruleRoute.identifier;
      rulesRevision.value = ruleRoute.revision;
    }
    historyIndex = Number.isInteger(targetIndex) ? targetIndex : previousIndex + 1;
    history.replaceState({...history.state, agentguardPageIndex:historyIndex}, "", hashFor());
    if (previousPage === "chain" && origin?.page === name) {
      nextTick(() => window.scrollTo({ top: origin.scroll || 0, behavior: "instant" }));
    }
    // Vue watch 在本轮微任务中处理相关页签，防止恢复历史时额外插入一条记录。
    Promise.resolve().then(() => { applyingHash = false; });
  });
  const finish = allowed => {
    if (pendingHash !== requested) return;
    pendingHash = null;
    if (!allowed && location.hash === requested) {
      if (Number.isInteger(targetIndex) && targetIndex !== previousIndex) history.go(previousIndex - targetIndex);
      else history.replaceState({...history.state, agentguardPageIndex:previousIndex}, "", hashFor());
    }
  };
  if (result && typeof result.then === 'function') result.then(finish);
  else finish(result);
}

watch([tab, chainId, metricsTab, terminalTab, rulesTab, rulesTarget, rulesRevision, deploymentPage, deploymentMethod], () => {
  if (applyingHash) return;
  const next = hashFor();
  if (location.hash !== next) history.pushState({...history.state, agentguardPageIndex:++historyIndex,
    agentguardChainOrigin:tab.value === "chain" && chainOrigin.value ? {...chainOrigin.value} : null}, "", next);
});

// ---- 实时：SSE 推送 + 轮询兜底 ----
let runtimeStarted = false;
let refreshTimer = null;
let pendingCritical = [];
let notifyTimer = null;

// 回放时一秒可能进来几十条决策：合并为一次刷新，避免请求风暴。
function scheduleRefresh() {
  if (refreshTimer) return;
  refreshTimer = setTimeout(async () => {
    refreshTimer = null;
    // 事件可能发生在当前请求取样之后：等正在进行的刷新结束，再读取一次新数据。
    if (threatsRefresh) await threatsRefresh;
    await refreshThreats();
    if (tab.value === "events") {
      if (eventsRefresh) await eventsRefresh;
      if (tab.value === "events") refreshEvents();
    }
  }, 400);
}

// CRITICAL 通知同样合并：窗口内多条只弹一次，并注明条数。
function notifyCritical(d) {
  pendingCritical.push(d);
  if (notifyTimer) return;
  notifyTimer = setTimeout(() => {
    const [first, ...more] = pendingCritical;
    pendingCritical = []; notifyTimer = null;
    ElNotification({
      title: more.length ? `已拦截 ${more.length + 1} 条高危行为` : "已拦截高危行为",
      type: "error", duration: 4500, position: "bottom-right",
      message: `${first.reason_code} · ${first.server || ""}${first.tool ? "/" + first.tool : ""} · ${first.trace_id}`
        + (more.length ? ` 等 ${more.length + 1} 条` : ""),
    });
  }, 800);
}

function connectSSE() {
  const es = new EventSource("/v1/runtime/stream");
  es.onopen = () => { sseOn.value = true; };
  es.onerror = () => { sseOn.value = false; };
  es.addEventListener("decision", (ev) => {
    const d = JSON.parse(ev.data);
    if (d.decision === "DENY") {
      freshId.value = d.decision_id;
      setTimeout(() => { if (freshId.value === d.decision_id) freshId.value = ""; }, 2200);
      if (d.severity === "CRITICAL") notifyCritical(d);
    }
    scheduleRefresh();
  });
  es.addEventListener("analysis", (ev) => {
    analysisTick.value += 1;
    const r = JSON.parse(ev.data);
    if (r.status !== "done") return;
    // 判为正常也刷新：重新分析可能撤下该轮之前的可疑 / 恶意告警。
    if (r.verdict === "suspicious" || r.verdict === "malicious") {
      freshId.value = r.analysis_id;
      setTimeout(() => { if (freshId.value === r.analysis_id) freshId.value = ""; }, 2200);
    }
    if (r.verdict === "malicious") {
      ElNotification({ title: "大模型研判发现恶意会话", type: "warning", duration: 4500, position: "bottom-right",
                       message: `${scenarioOf(r.trace_id)}${r.round ? ` · 第 ${r.round} 轮` : ""}` });
    }
    scheduleRefresh();
  });
  es.addEventListener("proposal", (ev) => {
    proposalTick.value += 1;
    const r = JSON.parse(ev.data);
    if (r.status === "done" && r.count) {
      ElNotification({ title: `大模型提议了 ${r.count} 条新规则`, type: "info", duration: 4500, position: "bottom-right",
                       message: "在「大模型研判 · 规则建议」中审批" });
    }
  });
}

export function startRuntime() {
  if (runtimeStarted) return;
  runtimeStarted = true;
  historyIndex = Number.isInteger(history.state?.agentguardPageIndex) ? history.state.agentguardPageIndex : 0;
  history.replaceState({...history.state, agentguardPageIndex:historyIndex}, "");
  applyHash();
  window.addEventListener("popstate", applyHash);
  window.addEventListener("hashchange", applyHash);
  refreshThreats().then(() => { refreshEvents(); connectSSE(); loadPolicies(); });
  // 决策由 SSE 推送，断线时轮询兜底；事件流每 5 秒补齐无决策的原始事件。
  setInterval(() => {
    if (!sseOn.value) refreshThreats();
    // 无决策的会话、模型与工具事件不会触发 decision 推送，需要定期补齐。
    if (tab.value === "events") refreshEvents();
  }, 5000);
}
