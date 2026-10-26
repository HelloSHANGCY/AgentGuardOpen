// 与分析记录使用同一批数据；不混用服务启动以来的调用计数。
export const JUDGE_RECORD_LIMIT = 500;

const OUTCOMES = ["benign", "suspicious", "malicious", "pending", "failed", "unknown"];
const localDay = date => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
const recordTime = value => {
  if (typeof value !== "string" || !value) return null;
  // 与控制台的时间格式保持一致：没有时区的服务端时间按 UTC 读取。
  const text = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(value) ? value.replace(" ", "T") + "Z" : value;
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date;
};

export function buildJudgeStatistics(records = [], now = new Date()) {
  const outcomes = Object.fromEntries(OUTCOMES.map(key => [key, 0]));
  const days = Array.from({length: 7}, (_, index) => {
    const date = new Date(now); date.setHours(0, 0, 0, 0); date.setDate(date.getDate() - 6 + index);
    return {date: localDay(date), total: 0, done: 0, pending: 0, failed: 0, unknown: 0};
  });
  const byDay = new Map(days.map(day => [day.date, day]));
  const rows = records.filter(record => record && typeof record === "object");
  const latencies = [];
  let done = 0;
  for (const record of rows) {
    const outcome = record.status === "done" && ["benign", "suspicious", "malicious"].includes(record.verdict)
      ? record.verdict : ["pending", "failed"].includes(record.status) ? record.status : "unknown";
    outcomes[outcome] += 1;
    if (record.status === "done") {
      done += 1;
      if (typeof record.latency_ms === "number" && Number.isFinite(record.latency_ms) && record.latency_ms >= 0) latencies.push(record.latency_ms);
    }
    const created = recordTime(record.created_at);
    const day = created && byDay.get(localDay(created));
    if (day) {
      day.total += 1;
      day[["done", "pending", "failed"].includes(record.status) ? record.status : "unknown"] += 1;
    }
  }
  latencies.sort((a, b) => a - b);
  return {
    total: rows.length, done, outcomes, days,
    latencySamples: latencies.length,
    latencyAverageMs: latencies.length ? latencies.reduce((sum, value) => sum + value, 0) / latencies.length : null,
    latencyP95Ms: latencies.length ? latencies[Math.ceil(latencies.length * .95) - 1] : null,
  };
}
