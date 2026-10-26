const HOUR = 60 * 60 * 1000;
export const THREAT_PERIODS = [
  { key: '24h', label: '24时', title: '近 24 小时', bins: 24, step: HOUR },
  { key: '7d', label: '7天', title: '近 7 天', bins: 7, step: 24 * HOUR },
  { key: '30d', label: '30天', title: '近 30 天', bins: 30, step: 24 * HOUR },
];
export const THREAT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];
const severityRank = Object.fromEntries(THREAT_SEVERITIES.map((key, i) => [key, 6 - i]));

// 与控制台时间约定一致：没有时区的服务端 ISO 时间按 UTC 读取。
export function threatTimestamp(value) {
  if (!value) return NaN;
  const text = String(value);
  return Date.parse(/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(text)
    ? text.replace(' ', 'T') + 'Z' : text);
}
export function threatWindow(period, asOf) {
  const config = THREAT_PERIODS.find(item => item.key === period) || THREAT_PERIODS[0];
  const end = threatTimestamp(asOf);
  return { ...config, start: end - config.bins * config.step, end };
}

function occurrence(alert, item) {
  const source = alert.source || {};
  const actor = item.context?.actor || '';
  const agent = alert.analysis?.agent || '';
  return {
    alert, item, time: threatTimestamp(item.created_at),
    category: item.reason_code || '__unknown__',
    severity: THREAT_SEVERITIES.includes(item.severity) ? item.severity : 'UNKNOWN',
    hotspot: JSON.stringify([source.key || 'unknown', actor, agent]),
    sourceLabel: source.label || '未提供来源', actor, agent,
  };
}

export function buildThreatStatistics(alerts = [], period = '24h', asOf) {
  const window = threatWindow(period, asOf);
  const buckets = Array.from({ length: window.bins }, (_, i) => ({
    start: window.start + i * window.step, end: window.start + (i + 1) * window.step,
    total: 0, ...Object.fromEntries(THREAT_SEVERITIES.map(key => [key, 0])),
  }));
  const categories = new Map(), hotspots = new Map(), seen = new Set();
  let total = 0, blocked = 0;
  const severities = Object.fromEntries(THREAT_SEVERITIES.map(key => [key, 0]));
  for (const alert of alerts) {
    for (const item of alert.items || []) {
      // 分析记录和运行决策是不同事件，不按会话去重；同一决策只计一次。
      const identity = item.decision_id && (alert.analysis ? 'analysis:' : 'decision:') + item.decision_id;
      if (identity && seen.has(identity)) continue;
      if (identity) seen.add(identity);
      const row = occurrence(alert, item);
      if (!Number.isFinite(window.end) || !Number.isFinite(row.time) || row.time < window.start || row.time > window.end) continue;
      const bucket = buckets[Math.min(window.bins - 1, Math.floor((row.time - window.start) / window.step))];
      bucket[row.severity]++; bucket.total++; severities[row.severity]++; total++;
      // 模型告警、观察、用户批准和“未执行”都不计入实际阻断。
      if (item.decision === 'DENY') blocked++;
      const category = categories.get(row.category) || { key: row.category, codes: [row.category], count: 0 };
      category.count++; categories.set(row.category, category);
      const hotspot = hotspots.get(row.hotspot) || {
        key: row.hotspot, sourceLabel: row.sourceLabel, actor: row.actor, agent: row.agent,
        count: 0, blocked: 0, severity: row.severity, sessions: new Set(),
      };
      hotspot.count++;
      if (item.decision === 'DENY') hotspot.blocked++;
      if (item.trace_id) hotspot.sessions.add(item.trace_id);
      if (severityRank[row.severity] > severityRank[hotspot.severity]) hotspot.severity = row.severity;
      hotspots.set(row.hotspot, hotspot);
    }
  }
  const ranked = [...categories.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
  const visibleCategories = ranked.slice(0, 6);
  if (ranked.length > 6) visibleCategories.push({
    key: '__other__', codes: ranked.slice(6).map(row => row.key),
    count: ranked.slice(6).reduce((sum, row) => sum + row.count, 0),
  });
  return { window, buckets, total, blocked, severities, categories: visibleCategories,
    hotspots: [...hotspots.values()].map(row => ({ ...row, sessions: row.sessions.size }))
      .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key)),
  };
}

export function matchesThreatVisualization(alert, selection, asOf) {
  if (!selection) return true;
  const window = threatWindow(selection.period, asOf);
  return (alert.items || []).some(item => {
    const row = occurrence(alert, item);
    if (!Number.isFinite(window.end) || !Number.isFinite(row.time) || row.time < window.start || row.time > window.end) return false;
    if (selection.kind === 'category') return selection.codes.includes(row.category);
    return selection.kind === 'hotspot' && row.hotspot === selection.key;
  });
}
