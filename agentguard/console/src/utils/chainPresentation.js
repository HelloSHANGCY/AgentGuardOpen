export const DETECTION_STAGES = [
  { stage: "INJECTION", label: "提示注入" },
  { stage: "CRED_ACCESS", label: "凭证访问" },
  { stage: "STAGING", label: "数据暂存" },
  { stage: "EXECUTION", label: "命令执行" },
  { stage: "PERSISTENCE", label: "持久化" },
  { stage: "EXFIL", label: "数据外带" },
];

export const CHAIN_SEVERITIES = {
  CRITICAL: "严重", HIGH: "高危", MEDIUM: "中危", LOW: "低危", INFO: "信息",
};

// 阶段命中只使用服务端记录；精确关联到事件，避免混用同一调用中的其他决策。
export function buildDetectionStages(hits = [], items = []) {
  const eventIndex = new Map();
  for (const item of items) {
    for (const event of item.events) eventIndex.set(event.event_id, { item, event });
  }
  return DETECTION_STAGES.map((definition) => {
    const hit = hits.find((entry) => entry.stage === definition.stage);
    const linked = hit && eventIndex.get(hit.event_id);
    return { ...definition, hit, item: linked?.item, decision: linked?.event.decision };
  });
}

export function chronologicalItems(items) {
  return [...items].sort((a, b) => {
    const first = Date.parse(a.timestamp), second = Date.parse(b.timestamp);
    if (Number.isFinite(first) && Number.isFinite(second)) return first - second;
    if (Number.isFinite(first)) return -1;
    if (Number.isFinite(second)) return 1;
    return 0;
  });
}
