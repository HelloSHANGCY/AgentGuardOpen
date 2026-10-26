import test from "node:test";
import assert from "node:assert/strict";
import {buildJudgeStatistics} from "../src/utils/judgeStatistics.js";

process.env.TZ = "Asia/Shanghai";
const now = new Date("2026-10-16T04:00:00Z");

test("仅完成记录计入研判结论和时延，失败与排队不伪装为成功", () => {
  const records = [
    {status: "done", verdict: "benign", latency_ms: 800},
    {status: "done", verdict: "malicious", latency_ms: 1200},
    {status: "done", verdict: "suspicious", latency_ms: 1000},
    {status: "pending", verdict: "malicious", latency_ms: 0},
    {status: "failed", verdict: "malicious", latency_ms: 50000},
  ];
  const stats = buildJudgeStatistics(records, now);
  assert.equal(stats.total, 5);
  assert.equal(stats.done, 3);
  assert.deepEqual(stats.outcomes, {benign: 1, malicious: 1, suspicious: 1, pending: 1, failed: 1, unknown: 0});
  assert.equal(stats.latencySamples, 3);
  assert.equal(stats.latencyAverageMs, 1000);
  assert.equal(stats.latencyP95Ms, 1200);
});

test("缺少或无效时延不按零计算，真实零毫秒仍是有效样本", () => {
  const records = [undefined, {status: "done", verdict: "benign", latency_ms: 0},
    ...[null, undefined, "800", -1, Infinity, NaN].map(latency_ms => ({status: "done", verdict: "benign", latency_ms}))];
  const stats = buildJudgeStatistics(records, now);
  assert.equal(stats.total, 7);
  assert.equal(stats.latencySamples, 1);
  assert.equal(stats.latencyAverageMs, 0);
  assert.equal(stats.latencyP95Ms, 0);
  assert.equal(buildJudgeStatistics([{status: "done", verdict: "benign"}], now).latencyAverageMs, null);
  assert.equal(buildJudgeStatistics([], now).latencyP95Ms, null);
});

test("按创建时间的本地日期归入最近七天，跨午夜完成不改变归属", () => {
  const records = [
    {status: "done", verdict: "benign", created_at: "2026-10-15T16:01:00Z", finished_at: "2026-10-16T16:00:00Z"},
    {status: "failed", created_at: "2026-10-15T15:59:00Z"},
    {status: "pending", created_at: "2026-10-16T00:01:00"},
    {status: "done", verdict: "benign", created_at: "2026-10-09T15:59:00Z"},
    {status: "pending", created_at: "2026-10-16T16:01:00Z"},
    {status: "pending", created_at: "invalid"},
  ];
  const stats = buildJudgeStatistics(records, now);
  assert.deepEqual(stats.days.map(day => day.date), ["2026-10-10", "2026-10-11", "2026-10-12", "2026-10-13", "2026-10-14", "2026-10-15", "2026-10-16"]);
  assert.equal(stats.days[5].failed, 1);
  assert.deepEqual(stats.days[6], {date: "2026-10-16", total: 2, done: 1, pending: 1, failed: 0, unknown: 0});
  assert.equal(stats.days.reduce((sum, day) => sum + day.total, 0), 3);
  assert.equal(stats.total, 6);
});

test("P95 使用最近秩，统计不会改动原始记录顺序或内容", () => {
  const records = Array.from({length: 20}, (_, i) => ({status: "done", verdict: "benign", latency_ms: 20 - i}));
  const snapshot = JSON.stringify(records);
  const stats = buildJudgeStatistics(records, now);
  assert.equal(stats.latencyAverageMs, 10.5);
  assert.equal(stats.latencyP95Ms, 19);
  assert.equal(JSON.stringify(records), snapshot);
});

test("异常状态或结论保留为未分类，不隐藏记录数量", () => {
  const stats = buildJudgeStatistics([{status: "done", verdict: "future"}, {status: "cancelled"}], now);
  assert.equal(stats.total, 2);
  assert.equal(stats.done, 1);
  assert.equal(stats.outcomes.unknown, 2);
});

test("跨夏令时切换仍生成七个完整的本地日历日", () => {
  process.env.TZ = "America/New_York";
  try {
    const stats = buildJudgeStatistics([
      {status: "done", verdict: "benign", created_at: "2026-11-01T01:30:00-04:00"},
      {status: "done", verdict: "benign", created_at: "2026-11-01T01:30:00-05:00"},
    ], new Date("2026-11-03T17:00:00Z"));
    assert.deepEqual(stats.days.map(day => day.date), ["2026-10-28", "2026-10-29", "2026-10-30", "2026-10-31", "2026-11-01", "2026-11-02", "2026-11-03"]);
    assert.equal(stats.days[4].total, 2);
  } finally { process.env.TZ = "Asia/Shanghai"; }
});
