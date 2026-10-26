import { kindColor } from "./staticText";

export const sourceName = (source, agentNames = {}) => source.device_id
  ? `${source.device_id} / ${agentNames[source.agent] || source.agent}` : source.source_id || "—";
export const inventoryGroupName = (group, agentNames = {}) => group.device_id
  ? `${group.device_id} / ${agentNames[group.agent] || group.agent || '未知 Agent'}`
  : `${group.projects[0]} / ${group.sources[0]?.source_id || '授权目录'}`;
export const assetRiskName = (asset) => ({risk: "有风险", clear: "未检出", unknown: "覆盖不足"}[asset.risk_state] || "未知");
export const assetRiskColor = (severity) => ({CRITICAL: "var(--crit)", HIGH: "var(--high)", MEDIUM: "var(--med)",
  LOW: "var(--low)", INFO: "var(--info)"}[severity] || "var(--muted)");

export function typeDonut(kinds = []) {
  const total = kinds.reduce((sum, item) => sum + item.count, 0);
  if (!total) return "var(--line-2)";
  let position = 0;
  return "conic-gradient(" + kinds.map(item => {
    const start = position; position += item.count / total * 100;
    return `${kindColor(item.kind)} ${start}% ${position}%`;
  }).join(",") + ")";
}
