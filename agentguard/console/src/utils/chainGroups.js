// 攻击链分组：把原始事件流整理成“任务开始 → 各轮（模型规划 / 工具调用 / 独立事件）→ 任务结束”。
// 同一 call_id 的网关请求、Hook 请求、网关返回、Hook 返回合并为一次工具调用；原始事件保留在 events 中供展开查看。

const DECISION_RANK = { DENY: 3, ASK: 2, ALLOW: 1 };

const byTime = (a, b) => (a.timestamp || "").localeCompare(b.timestamp || "");

// 同一轮内先“模型规划”再“工具调用”：网关与 Hook 时钟有毫秒级偏差，单纯按时间排序会颠倒因果。
const inRoundOrder = (a, b) => (a.type === "model" ? 0 : 1) - (b.type === "model" ? 0 : 1) || byTime(a, b);

// 取一组事件中最严重的决策，作为整组的结论。
function strongestDecision(events) {
  let best = null;
  for (const e of events) {
    const d = e.decision;
    if (d && (!best || (DECISION_RANK[d.decision] || 0) > (DECISION_RANK[best.decision] || 0))) best = d;
  }
  return best;
}

// 从可能被截断的 JSON 预览中提取字段；截断时 JSON.parse 会失败，因此用正则兜底。
function extractString(preview, key) {
  const m = new RegExp(`"${key}"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`).exec(preview || "");
  if (!m) return "";
  try { return JSON.parse(`"${m[1]}"`); } catch { return m[1]; }
}

function extractAll(preview, key) {
  const re = new RegExp(`"${key}"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`, "g");
  const out = [];
  let m;
  while ((m = re.exec(preview || ""))) out.push(m[1]);
  return out;
}

function summarizeModel(item) {
  const n = item.events[0];
  const preview = n.redacted_preview || "";
  if ((n.labels || []).includes("FINAL_ANSWER")) {
    item.title = "模型回答";
    item.lines = [{ label: "回答", text: extractString(preview, "content_head") || preview }];
    return;
  }
  item.title = "模型规划";
  const names = extractAll(preview, "name");
  const args = extractString(preview, "args_preview");
  item.lines = names.length
    ? [{ label: "计划调用", text: names.join("、") + (args ? "  " + args : "") }]
    : [{ label: "内容", text: preview }];
}

function summarizeCall(item) {
  const pick = (stage) => item.events.find((e) => e.stage === stage);
  const req = pick("TOOL_REQUEST") || pick("TOOL_REQUEST_HOOK");
  const res = pick("TOOL_RESULT") || pick("TOOL_RESULT_HOOK");
  const any = req || item.events[0];
  item.title = [any.mcp_server, any.tool].filter(Boolean).join(" · ") || "工具调用";
  item.resource = (req && req.resource) || "";
  item.lines = [];
  if (req && req.redacted_preview) item.lines.push({ label: "参数", text: req.redacted_preview });
  if (item.resultBlocked) {
    item.lines.push({ label: "处置", text: "返回侧记录为拦截；不代表工具未执行" });
  } else if (item.decision && item.decision.decision === "DENY") {
    const text = req?.decision?.decision === "DENY" ? (req.stage === "TOOL_REQUEST" ? "网关请求侧记录为拦截" : "Hook 请求侧记录为拦截")
      : "记录为拦截，执行情况以原始事件为准";
    item.lines.push({ label: "处置", text });
  } else if (item.decision && item.decision.decision === "ASK") {
    const confirm = pick("USER_CONFIRMATION");
    const resolution = { APPROVED: "用户已批准并执行", NOT_EXECUTED: "本次未执行", UNKNOWN: "执行结果未知" };
    item.lines.push({ label: "确认", text: resolution[item.decision.resolution]
      || confirm?.redacted_preview || "需用户确认，尚无确认结果记录" });
  }
  if (res && res.redacted_preview) {
    item.lines.push({ label: "返回", text: extractString(res.redacted_preview, "result_head") || res.redacted_preview });
  }
}

function summarizeEvent(item, stageName) {
  const n = item.events[0];
  item.title = stageName(n);
  item.resource = n.resource || n.mcp_server || n.component || "";
  item.lines = n.redacted_preview ? [{ label: "", text: n.redacted_preview }] : [];
}

export function buildChainView(events, stageName) {
  const sorted = [...(events || [])].sort(byTime);
  const items = [];
  const calls = new Map();
  let start = null, end = null;
  const firstStart = sorted.find((n) => n.stage === "TASK_CREATED");
  const lastEnd = [...sorted].reverse().find((n) => n.stage === "TASK_COMPLETED");

  for (const n of sorted) {
    if (n === firstStart) { start = { key: n.event_id, type: "start", events: [n] }; continue; }
    if (n === lastEnd) { end = { key: n.event_id, type: "end", events: [n] }; continue; }
    if (n.call_id) {
      const callKey = JSON.stringify([n.trace_id || "", n.call_id]);
      let item = calls.get(callKey);
      if (!item) {
        item = { key: "call-" + callKey, type: "call", events: [], round: 0 };
        calls.set(callKey, item);
        items.push(item);
      }
      item.events.push(n);
      item.round = Math.max(item.round, n.round || 0);
      continue;
    }
    items.push({ key: n.event_id, type: n.stage === "MODEL_TURN" ? "model" : "event", events: [n], round: n.round || 0 });
  }

  for (const item of [...items, start, end].filter(Boolean)) {
    item.timestamp = item.events[0].timestamp;
    item.decision = strongestDecision(item.events);
    item.linkNote = item.events.find((e) => e.link_note)?.link_note || "";
    item.unresolvedDecision = item.events.some((e) => e.decision_id && !e.decision);
    item.evidenceGap = !!item.linkNote || item.unresolvedDecision;
    item.alert = item.events.some((e) => e.stage === "THREAT_ALERT");
    // 返回侧决策可能作为独立告警挂接；调用上仍保留请求放行决策，不能因此掩盖已拦截的返回。
    item.resultBlocked = item.events.some((e) => (e.labels || []).includes("RESULT_BLOCKED")
      || e.decision?.reason_code === "POISONED_RESULT_BLOCKED");
    item.risk = item.alert || item.resultBlocked || ["DENY", "ASK"].includes(item.decision?.decision);
    item.labels = [...new Set(item.events.flatMap((e) => e.labels || []))];
    if (item.type === "call") summarizeCall(item);
    else if (item.type === "model") summarizeModel(item);
    else if (item.type === "start") {
      item.title = "任务开始";
      item.lines = [{ label: "提示词", text: item.events[0].redacted_preview || "" }];
    } else if (item.type === "end") {
      item.title = "任务结束";
      const preview = item.events[0].redacted_preview || "";
      const tools = /tools=(\d+)/.exec(preview);
      item.lines = tools ? [{ label: "", text: `共发起 ${tools[1]} 次工具调用` }] : (preview ? [{ label: "", text: preview }] : []);
    } else summarizeEvent(item, stageName);
  }

  // 按轮次分段；轮次 0 表示不属于任何模型轮次的独立事件（如入口请求、孤儿外联）。
  const roundMap = new Map();
  for (const item of items) {
    if (!roundMap.has(item.round)) roundMap.set(item.round, []);
    roundMap.get(item.round).push(item);
  }
  const rounds = [...roundMap.entries()].sort((a, b) => a[0] - b[0])
    .map(([round, list]) => ({ round, items: list.sort(inRoundOrder) }));

  const all = [start, ...rounds.flatMap((r) => r.items), end].filter(Boolean);
  const first = sorted[0]?.timestamp, last = sorted[sorted.length - 1]?.timestamp;
  const duration = Date.parse(last) - Date.parse(first);
  const stats = {
    rounds: rounds.filter((r) => r.round > 0).length,
    calls: items.filter((i) => i.type === "call").length,
    denied: all.filter((i) => i.decision?.decision === "DENY").length,
    asked: all.filter((i) => i.decision?.decision === "ASK").length,
    pending: all.filter((i) => i.decision?.decision === "ASK" && !i.decision.resolution).length,
    gaps: all.filter((i) => i.evidenceGap).length,
    risks: all.filter((i) => i.risk).length,
    events: sorted.length,
    durationMs: Number.isFinite(duration) ? Math.max(0, duration) : null,
  };
  return { start, rounds, end, stats, all };
}
