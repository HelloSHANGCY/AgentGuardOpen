// 场景/展示层纯函数：运行时与静态资产视图共用。
export const MALICIOUS = new Set(["C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "M-1", "M-2"]);

const KNOWN = new Set(["C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "M-1", "M-2",
                       "B-RD", "B-OPS", "B-SEC", "B-SUP"]);

// 服务端时间一律为 UTC（ISO 8601，带 Z 或 +00:00）；展示时转成浏览器本地时区。
// 不带时区的 ISO 字符串按 UTC 解释（服务端约定），带毫秒的保留毫秒。
const pad = (n, width = 2) => String(n).padStart(width, "0");
const NO_ZONE_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;
export const fmt = (ts) => {
  if (!ts) return "";
  const text = String(ts);
  const date = new Date(NO_ZONE_RE.test(text) ? text.replace(" ", "T") + "Z" : text);
  if (Number.isNaN(date.getTime())) return text.replace("T", " ").replace("Z", "");
  const ms = /\d{2}:\d{2}:\d{2}\.\d/.test(text) ? "." + pad(date.getMilliseconds(), 3) : "";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${ms}`;
};

// 同一条攻击链内只看时分秒（含毫秒），日期放在任务卡片里。
export const fmtTime = (ts) => fmt(ts).slice(11);

export const scenarioOf = (t) => {
  t = String(t || "");
  if (KNOWN.has(t)) return t;
  // 与后端 store.scenario_of 一致：从右剥离实例后缀，锚定已知场景前缀。
  const parts = t.split("-");
  for (let end = parts.length - 1; end > 0; end -= 1) {
    const candidate = parts.slice(0, end).join("-");
    if (KNOWN.has(candidate)) return candidate;
  }
  return t;
};

export const isMalicious = (s) => MALICIOUS.has(s);

export const decisionName = (d) => ({ DENY: "拦截", ASK: "待确认", ALLOW: "放行" }[d] || d);

// 处置：DENY 即已阻断；ASK 按事后回填区分仍在等待、用户批准并已执行、未执行（用户拒绝或非交互模式）。
// observed：行为基线超阈值但规则放行的决策（威胁中心「行为观察」），不是拦截。
// 大模型危险审批把静态拦截 / 待确认改判为放行的，处置记为“模型放行”。
export const llmReleased = (d) => d?.decision === "ALLOW" && !!d.review?.static && d.review.static !== "ALLOW";
export const dispositionOf = (d) => (d?.observed ? "OBSERVE" : llmReleased(d) ? "LLM_RELEASED"
  : d && d.decision === "ASK" && d.resolution ? d.resolution : d?.decision || "");
export const DISPOSITIONS = {
  DENY: { label: "已阻断", tag: "DENY" },
  ASK: { label: "待确认", tag: "ASK" },
  APPROVED: { label: "用户批准·已执行", tag: "APPROVED" },
  NOT_EXECUTED: { label: "未执行", tag: "NONE" },
  UNKNOWN: { label: "执行结果未知", tag: "NONE" },
  OBSERVE: { label: "行为观察", tag: "OBSERVE" },
  LLM_RELEASED: { label: "模型放行", tag: "APPROVED" },
  // 威胁中心中的大模型异步分析告警：会话级结论，不对应单次决策。
  LLM_FLAGGED: { label: "模型研判", tag: "ASK" },
};
// 事件流 / 攻击链沿用“拦截 / 待确认 / 放行”，只把已有确认结论的 ASK 换成结论。
export const dispositionTag = (d) => "dec-tag-" + (DISPOSITIONS[dispositionOf(d)]?.tag || d?.decision);
export const dispositionLabel = (d) => (d?.resolution && d.decision === "ASK"
  ? DISPOSITIONS[d.resolution].label : llmReleased(d) ? DISPOSITIONS.LLM_RELEASED.label : decisionName(d?.decision));

// 大模型研判：复核结论与异步分析的结论 / 风险 / 告警研判。
export const REVIEW_TEXT = { ALLOW: "放行", ASK: "需确认", DENY: "拦截" };
export const VERDICT_TEXT = { benign: "正常", suspicious: "可疑", malicious: "恶意", partial: "部分完成", pending: "分析中", failed: "失败" };
export const VERDICT_TAG = { benign: "success", suspicious: "warning", malicious: "danger", partial: "warning", pending: "info", failed: "info" };
export const RISK_TEXT = { none: "无", low: "低", medium: "中", high: "高", critical: "严重" };
export const ASSESSMENT_TEXT = { true_positive: "真实威胁", false_positive: "误报", uncertain: "不确定" };
export const ASSESSMENT_TAG = { true_positive: "danger", false_positive: "success", uncertain: "info" };
export const ASSESSMENT_STATUS_TEXT = { missing: "未返回结论", failed: "研判失败" };
export function assessmentText(record) {
  return ASSESSMENT_STATUS_TEXT[record?.status] || ASSESSMENT_TEXT[record?.assessment] || "结论未知";
}
// 思考等级：off 关闭；default 不发送思考参数，由服务商决定；其余对应 reasoning_effort。
export const EFFORT_TEXT = {
  off: "关闭", default: "服务商默认", enabled: "开启", minimal: "最低", low: "低", medium: "中", high: "高", xhigh: "超高", max: "最高",
};
export const riskSev = (r) => ({ critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" }[r] || "INFO");

export const pct = (v) => v === undefined || v === null ? "-" : (v * 100).toFixed(1) + "%";

export const isRiskLabel = (l) =>
  /CROSS_TENANT|SENSITIVE|C2|EGRESS|ORPHAN|POISON|HIDDEN|UNTRUSTED|COMMAND|TRAVERSAL|CODE_EXEC|MASS_DATA|MISSING|CAT1|SECRET_STAGED/.test(l);

// 威胁类型/标签的中文展示：业内通用写法（C2、Langflow、eval、shell 等）保留英文；
// 未收录的标签（工具名、阶段名等）原样返回，原始代码通过 title 保留。
const THREAT_TEXT = {
  C2: "C2",
  C2_CONTACT: "C2 外联",
  C2_TARGET: "C2 目标",
  EGRESS: "外联",
  ALLOWLIST_EGRESS: "白名单出网",
  EGRESS_POLICY_DENIED: "出网策略拒绝",
  ORPHAN: "孤儿任务",
  ORPHAN_EGRESS: "孤儿任务外联",
  ORPHAN_EGRESS_EXFIL: "孤儿任务数据外传",
  SENSITIVE: "敏感数据",
  SENSITIVE_CONFIG: "敏感配置",
  SENSITIVE_FIELDS: "敏感字段",
  SENSITIVE_FILE_READ: "敏感文件读取",
  SENSITIVE_DATA_EGRESS: "敏感数据外传",
  SENSITIVE_READ_ADMIN: "管理员敏感读取",
  MASS_DATA: "批量数据",
  MASS_DATA_READ: "批量数据读取",
  CROSS_TENANT: "跨租户",
  CROSS_TENANT_ACCESS: "跨租户访问",
  POISON: "工具投毒",
  POISONED_TOOL_DESCRIPTION: "工具描述投毒",
  POISONED_RESULT: "工具结果投毒",
  POISONED_RESULT_BLOCKED: "投毒返回已拦截",
  RESULT_BLOCKED: "返回已拦截",
  HIDDEN: "隐藏工具",
  HIDDEN_TOOL: "隐藏工具调用",
  UNMODELED_TOOL: "未建模工具调用",
  UNTRUSTED: "不可信来源",
  UNTRUSTED_WEB: "不可信网页",
  UNTRUSTED_SOURCE_HIGH_RISK: "不可信来源高风险操作",
  INJECTED_INSTRUCTION: "数据中的指令驱动高危操作",
  DATA_DERIVED_TARGET: "操作目标来自不可信数据",
  SECRET_FLOW_EGRESS: "秘密数据流外发",
  BEHAVIOR_ANOMALY: "行为异常（叠加不可信来源/秘密）",
  BEHAVIOR_ANOMALY_OBSERVED: "行为异常（观察）",
  SENSITIVE_SESSION_EGRESS: "读过秘密的会话访问外部",
  FLOW_CHECKED_LOCAL: "数据流核验后放行（本机）",
  SECRET_STAGED: "秘密暂存",
  LLM_RELEASED: "大模型复核放行",
  LLM_CONFIRM: "大模型复核改为确认",
  LLM_DENIED: "大模型复核拦截",
  LLM_UPHELD: "大模型复核维持",
  LLM_REVIEW_FAILED: "大模型复核失败",
  BENIGN: "研判正常",
  SUSPICIOUS: "研判可疑",
  MALICIOUS: "研判恶意",
  LLM_ANALYSIS_MALICIOUS: "大模型研判为恶意会话",
  LLM_ANALYSIS_SUSPICIOUS: "大模型研判为可疑会话",
  SECRET_LEARNED: "已登记秘密指纹",
  COMMAND: "命令注入",
  COMMAND_INJECTION: "命令注入",
  TRAVERSAL: "路径穿越",
  CODE_EXEC: "代码执行",
  LANGFLOW_CODE_EXEC: "Langflow 代码执行",
  CAT1: "注入类攻击",
  EVAL_EXEC: "eval 执行",
  BASE64_EXEC: "Base64 编码执行",
  DOWNLOAD_EXEC: "下载执行",
  DYNAMIC_IMPORT: "动态导入",
  SUBPROCESS_IMPORT: "subprocess 导入",
  POPEN_CALL: "popen 调用",
  OS_SYSTEM: "os.system 调用",
  SHELL_TRUE: "shell=True",
  REVERSE_SHELL: "反弹 Shell",
  ENV_DUMP: "环境变量导出",
  DEFAULT_PARAM_SIDE_EFFECT: "默认参数副作用",
  PII: "个人隐私信息",
  CREDENTIAL: "凭证",
  CREDENTIAL_READ: "凭证读取",
  SECRET: "密钥",
  TOKEN: "令牌",
  PASSWORD: "口令",
  KEY: "密钥",
  MISSING: "缺少上下文",
  MISSING_TASK_CONTEXT: "缺少任务上下文",
  NO_TASK_CONTEXT: "缺少任务上下文",
  CONTEXT_MISSING_READONLY: "缺少上下文（只读）",
  MANIFEST_UNAVAILABLE: "工具清单不可用",
  OPS_COMMAND: "运维命令执行",
  SANDBOX_WHITELIST: "沙箱白名单",
  SANDBOX_WHITELIST_MISMATCH: "沙箱白名单不匹配",
  SKILL_CAPABILITY_VIOLATION: "Skill 能力越权",
  ROLE_ELEVATION_REQUIRED: "需要角色提权",
  SCOPED_READ: "受控读取",
  SCOPED_READONLY: "受控只读",
  SCOPED_FILE_READ: "受控文件读取",
  NOTE_SYNC: "笔记同步",
  // 通用 Agent 接入（Claude Code / Codex / Trae / Qoder / ZCode / WorkBuddy / CodeBuddy）
  PROJECT_SECRET_READ: "读取项目密钥文件",
  URL_DATA_EXFIL: "URL 夹带数据外传",
  AGENT_CONFIG_TAMPER: "篡改 Agent/防护配置",
  UNMANAGED_MCP_SERVER: "未受管 MCP server",
  RELAY_BYPASS: "绕过 MCP 中转",
  UNTRUSTED_SOURCE_CONFIRM: "不可信来源后需确认",
  PERSISTENCE_WRITE: "写入持久化位置",
  WORKSPACE_ESCAPE_WRITE: "越出工作区写入",
  STRICT_CONFIRM: "严格模式需确认",
  DEFER_TO_NATIVE: "交由 Agent 原生权限",
  USER_CONFIRMED: "用户已确认",
  PROMPT_INJECTION_SUSPECT: "疑似直接注入",
  UNTRUSTED_MCP: "不可信 MCP 返回",
  AUDIT_DELAYED: "审计补报",
  AUDIT_INCOMPLETE: "审计不完整",
  AGENTGUARD_UNAVAILABLE: "防护服务不可达",
  MONITOR_ONLY: "仅观察（未拦截）",
  // 终端本地快速判定（规则包）
  LOCAL_ENFORCED: "终端本地拦截",
  LOCAL_MISMATCH: "终端与服务端判定不一致",
  LOCAL_RULE: "终端规则拦截",
  LOCAL_DENY: "终端降级拒绝",
  LOCAL_PASS: "终端降级放行",
  APPROVED: "用户批准",
  NOT_EXECUTED: "未执行",
  TOOL_FAILED: "工具执行失败",
  INTERRUPTED: "被中断",
};

export const threatText = (code) => THREAT_TEXT[code] || code;

// 形如 "SUBPROCESS_IMPORT,SHELL_TRUE" 的规则码列表翻译成中文，其余文本原样返回。
export const codeListText = (text) => (/^[A-Z0-9_]+(,[A-Z0-9_]+)+$/.test(text || "")
  ? text.split(",").map(threatText).join("、") : text);

export const stageName = (n) => ({
  TASK_CREATED: "任务创建", MODEL_TURN: "模型轮次", TOOL_REQUEST: "工具请求(网关)", TOOL_REQUEST_HOOK: "工具请求(Hook)",
  TOOL_RESULT: "工具返回(网关)", TOOL_RESULT_HOOK: "工具返回(Hook)", EGRESS: "出网请求", EGRESS_ALLOWED: "合法出网",
  TASK_COMPLETED: "任务结束", LANGFLOW_REQUEST: "Langflow 请求", INGRESS_REQUEST: "入口请求",
  THREAT_ALERT: "威胁告警", SESSION_START: "会话开始", TURN_COMPLETED: "轮次结束",
  SUBAGENT_COMPLETED: "子 Agent 结束", CONTEXT_COMPACT: "上下文压缩", AGENT_EVENT: "Agent 事件",
  AGENT_NOTIFICATION: "Agent 通知", USER_CONFIRMATION: "用户确认", SUBAGENT_STARTED: "子 Agent 启动",
  LLM_ANALYSIS: "大模型研判",
}[n.stage] || n.stage);

export const nodeKind = (n) => n.decision ? n.decision.decision.toLowerCase()
  : (n.stage === "TASK_COMPLETED" ? "end" : "");

// 栈帧来源标签：应用上报 / 网关自身 / Guard 自身分别标注，不混用。
export const stackSourceName = (s) => ({
  app: "应用栈", gateway: "网关栈", guard: "Guard 栈",
}[s] || (s ? s + " 栈" : "应用栈"));

export const frameSource = (f) => (typeof f === "string" ? "app" : (f.source || "app"));

export const frameText = (f) => typeof f === "string"
  ? f
  : `${f.file || f.module || "?"}:${f.line || "?"} ${f.function || ""}()`;

export const attributionName = (a) => ({
  root: "根节点", exact: "精确关联", inferred: "推断关联", unknown: "无法归因",
}[a] || a);

export const linkNoteName = (n) => ({
  hook_event_missing: "证据不完整",
  gateway_event_missing: "证据不完整",
}[n] || n);
