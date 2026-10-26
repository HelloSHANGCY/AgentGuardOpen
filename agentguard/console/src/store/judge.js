// 大模型辅助研判（/v1/admin/judge/*）：危险审批与异步分析的配置、统计、分析记录与手动分析，
// 以及规则建议的审批。管理令牌与设备管理共用。
import { ref } from "vue";
import { adminJson, adminNeedsToken, adminToken } from "./devices";
import { EFFORT_TEXT } from "../utils/format";
import { JUDGE_RECORD_LIMIT } from "../utils/judgeStatistics";

export const judgeStatus = ref(null);
export const judgeAnalyses = ref([]);
export const judgeLoaded = ref(false);
export const judgeError = ref("");
// 规则建议：分析发现静态规则漏报时模型提议的特征规则，待人工审批。
export const judgeProposals = ref([]);
export const proposalPending = ref(0);
export const PROPOSAL_STATUS = {
  pending: { label: "待审批", tag: "warning" }, approved: { label: "已批准", tag: "success" },
  rejected: { label: "已拒绝", tag: "info" },
};

export const SCOPE_TEXT = {
  ask: "只复核“需确认”",
  noncritical: "需确认 + 非严重拦截",
  all: "全部拦截与需确认",
};
export const MODE_TEXT = { off: "关闭", threat: "威胁分析", full: "全量分析" };
export { EFFORT_TEXT };

function fail(e) {
  if (e.status === 401) adminNeedsToken.value = true;
  judgeError.value = e.message;
}

export async function refreshJudge() {
  try {
    const [status, list, proposals] = await Promise.all([
      adminJson("/judge"), adminJson("/judge/analyses?limit=" + JUDGE_RECORD_LIMIT), adminJson("/judge/proposals")]);
    judgeStatus.value = status;
    judgeAnalyses.value = list.analyses || [];
    judgeProposals.value = proposals.proposals || [];
    proposalPending.value = proposals.summary?.pending || 0;
    judgeError.value = "";
    judgeLoaded.value = true;
  } catch (e) { fail(e); }
}

export async function updateJudge(changes) {
  try {
    judgeStatus.value = await adminJson("/judge", { method: "PUT", body: JSON.stringify(changes) });
    judgeError.value = "";
    return true;
  } catch (e) { fail(e); return false; }
}

export async function testJudge(config) {
  try {
    return await adminJson("/judge/test", { method: "POST", body: JSON.stringify({ config }) });
  } catch (e) { return { ok: false, error: e.message }; }
}

export async function analyzeSession(traceId, round = 0) {
  try {
    const record = await adminJson("/judge/analyze", { method: "POST", body: JSON.stringify({ trace_id: traceId, round }) });
    judgeError.value = "";
    await refreshJudge();
    return record;
  } catch (e) { fail(e); return null; }
}

// 侧栏角标：定时取待审批的规则建议数（未提供管理令牌时跳过）。
let proposalTimer = null;
export function startProposalPolling(intervalMs = 30000) {
  if (proposalTimer) return;
  const tick = async () => {
    if (document.visibilityState !== "visible" || (adminNeedsToken.value && !adminToken.value)) return;
    try {
      const data = await adminJson("/judge/proposals?status=pending");
      proposalPending.value = data.summary?.pending || 0;
    } catch { /* 角标失败不提示 */ }
  };
  tick();
  proposalTimer = setInterval(tick, intervalMs);
}

export async function proposeRules(analysisId) {
  try {
    const record = await adminJson("/judge/analyses/" + encodeURIComponent(analysisId) + "/propose", { method: "POST" });
    judgeError.value = "";
    await refreshJudge();
    return record;
  } catch (e) { fail(e); return null; }
}

// rule：修改后的规则 YAML 原文（不改则省略）；返回更新后的建议，失败抛出（由弹窗显示校验错误）。
export async function decideProposal(proposalId, action, { rule, note } = {}) {
  const body = { note: note || "", ...(rule ? { rule } : {}) };
  const item = await adminJson("/judge/proposals/" + encodeURIComponent(proposalId) + "/" + action,
    { method: "POST", body: JSON.stringify(body) });
  await refreshJudge();
  return item;
}

// 修改后重新检查：返回 {checks, problems, yaml}，不改动建议。失败抛出。
export async function checkProposal(proposalId, rule) {
  return adminJson("/judge/proposals/" + encodeURIComponent(proposalId) + "/check",
    { method: "POST", body: JSON.stringify(rule ? { rule } : {}) });
}
