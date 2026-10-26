// 场景评测状态：令牌只驻留页面内存，所有结果按独立 run_id 查询。
import { ref, computed } from "vue";
import { requestJson } from "../api/client.js";

export const evalOptions = ref({}), evalToken = ref(""), evalScenario = ref("all"), evalSuite = ref("claude-code");
export const evalLimit = ref(100), evalBusy = ref(false), evalCancelling = ref(false);
export const evalParams = computed(() => ({
  suite: evalSuite.value, scenario: evalScenario.value, limit: evalLimit.value,
}));
export const evalRefreshing = ref(false), evalLoading = ref(false), evalLoaded = ref(false), evalDownloading = ref(false);
export const evalRuns = ref([]), evalRunId = ref(""), evalJob = ref(null), evalError = ref("");
export const isEvalActive = s => ["QUEUED", "RUNNING", "CANCELLING"].includes(s);
export const evalActive = computed(() => evalRuns.value.some(r => isEvalActive(r.status)) || isEvalActive(evalJob.value?.status));
export const evalStatus = s => ({
  QUEUED: "等待执行", RUNNING: "执行中", CANCELLING: "正在取消", CANCELLED: "已取消",
  COMPLETED: "已完成", PARTIAL: "部分完成", FAILED: "执行失败", TIMED_OUT: "已超时", INTERRUPTED: "已中断",
}[s] || s);
export const suiteNames = { "claude-code": "Claude Code 夹具", "offline-corpus": "靶场离线数据集", "claude-code-e2e": "Claude Code 端到端" };
export const runSuite = run => run?.params?.suite || "legacy";
export const suiteScenarios = computed(() => (evalOptions.value.suites || {})[evalSuite.value] || evalOptions.value.scenarios || ["all"]);
export const evalMaxLimit = computed(() => evalOptions.value.suite_limits?.[evalSuite.value] || evalOptions.value.max_limit || 500);
// 最近一次已结束的任务不代表验收通过；卡片同时展示状态、场景与样本量。
export const latestBySuite = computed(() => {
  const seen = {};
  for (const run of evalRuns.value) {
    const suite = runSuite(run);
    if (!seen[suite] && !isEvalActive(run.status) && run.summary) seen[suite] = run;
  }
  return Object.keys(suiteNames).filter(k => seen[k]).map(k => ({suite:k, run:seen[k], ...seen[k].summary}));
});
export const evalOutcome = s => ({ TP: "检出", FP: "误报", FN: "漏检", TN: "正常放行", UNKNOWN: "缺少证据", ERROR: "请求失败" }[s] || s);
const evaluationJson = (path, options = {}) => requestJson("/v1/evaluations" + path,
  {...options, headers:{"Content-Type":"application/json", "X-AG-Eval-Token":evalToken.value}}, "评测请求失败，请检查参数");

let loadSequence = 0;
export async function loadEvaluation({quiet = false} = {}) {
  const selected = evalRunId.value, sequence = ++loadSequence;
  if (!selected) { evalJob.value = null; evalLoading.value = false; return true; }
  evalLoading.value = true;
  if (!quiet) evalError.value = "";
  try {
    const job = await evaluationJson("/" + encodeURIComponent(selected));
    if (sequence === loadSequence && selected === evalRunId.value) evalJob.value = job;
    return true;
  } catch (e) {
    if (sequence === loadSequence && selected === evalRunId.value) evalError.value = e.message;
    return false;
  } finally { if (sequence === loadSequence) evalLoading.value = false; }
}
let refreshPromise = null;
export function refreshEvaluation({quiet = false} = {}) {
  if (refreshPromise) return refreshPromise;
  evalRefreshing.value = true;
  refreshPromise = (async () => {
    try {
      evalOptions.value = await evaluationJson("/options");
      if (evalOptions.value.enabled && (!evalOptions.value.auth_required || evalToken.value)) {
        evalRuns.value = (await evaluationJson("")).runs || [];
        if (!evalRuns.value.some(r => r.run_id === evalRunId.value)) evalRunId.value = evalRuns.value[0]?.run_id || "";
        if (!quiet) evalError.value = "";
        return await loadEvaluation({quiet});
      }
      evalRuns.value = []; evalRunId.value = ""; evalJob.value = null;
      return true;
    } catch (e) { evalError.value = e.message; return false; }
    finally { evalLoaded.value = true; evalRefreshing.value = false; refreshPromise = null; }
  })();
  return refreshPromise;
}
export async function startEvaluation() {
  if (evalBusy.value || evalCancelling.value || evalRefreshing.value || evalActive.value) return false;
  evalBusy.value = true; evalError.value = "";
  try {
    const job = await evaluationJson("", {method:"POST", body:JSON.stringify(evalParams.value)});
    ++loadSequence; evalLoading.value = false;
    evalRunId.value = job.run_id; evalJob.value = job;
    evalRuns.value = [job, ...evalRuns.value.filter(r => r.run_id !== job.run_id)].slice(0,20);
    return true;
  } catch (e) { evalError.value = e.message; return false; }
  finally { evalBusy.value = false; }
}
export async function cancelEvaluation() {
  const selected = evalRunId.value;
  if (!selected || evalCancelling.value || evalBusy.value || evalRefreshing.value || evalLoading.value || !isEvalActive(evalJob.value?.status) || evalJob.value?.status === 'CANCELLING') return;
  evalCancelling.value = true; evalError.value = "";
  try {
    await evaluationJson("/" + encodeURIComponent(selected) + "/cancel", {method:"POST"});
    await refreshEvaluation();
  } catch (e) { evalError.value = e.message; }
  finally { evalCancelling.value = false; }
}
export async function downloadEvaluation() {
  const selected = evalRunId.value;
  if (!selected || evalDownloading.value || evalLoading.value || isEvalActive(evalJob.value?.status)) return;
  evalDownloading.value = true; evalError.value = "";
  try {
    const data = await evaluationJson("/" + encodeURIComponent(selected) + "/report");
    const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)], {type:"application/json"}));
    const a = Object.assign(document.createElement("a"), {href:url, download:"evaluation-" + data.run_id + ".json"});
    a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
  } catch (e) { evalError.value = e.message; }
  finally { evalDownloading.value = false; }
}
