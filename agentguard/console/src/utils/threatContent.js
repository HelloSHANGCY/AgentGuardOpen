// 只解析记录，不执行命令或将原文当 HTML 渲染。
export function executionCommand(detail, items = []) {
  const current = items.find(item => isCurrentCall(item, detail) && item.kind === 'TOOL_ARGUMENTS');
  if (current && !current.preview_only) {
    const command = commandArgument(current.content);
    if (command) return command;
  }
  const resource = String(detail?.context?.resource || '');
  if (resource.startsWith('exec:')) return resource.slice(5);
  const tool = String(detail?.tool || '').toLowerCase();
  return /^(bash|shell|exec|execute|run_command|run_terminal_cmd|command)$/.test(tool)
    ? commandArgument(detail?.context?.preview) : '';
}

function commandArgument(content) {
  try {
    const value = JSON.parse(content);
    if (!value || typeof value !== 'object') return '';
    const args = value.arguments || value.input || value;
    return typeof args.command === 'string' ? args.command : typeof args.cmd === 'string' ? args.cmd : '';
  } catch { return ''; }
}

export function isCurrentCall(item, detail) {
  if (!detail || item.kind !== 'TOOL_ARGUMENTS') return false;
  return !!((item.event_id && (item.event_id === detail.context?.event_id || (detail.evidence_ids || []).includes(item.event_id)))
    || (item.evidence_id && (detail.evidence_ids || []).includes(item.evidence_id))
    || (item.decision_id && item.decision_id === detail.decision_id)
    || (item.call_id && item.call_id === detail.context?.call_id));
}

// 风险评分：直接读取后端决策记录中的行为基线异常分，缺失或未评分时返回 null，由展示层统一显示“—”。
const hasScore = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const round2 = (value) => Number(value.toFixed(2));

export function anomalyScore(record) {
  const anomaly = record?.anomaly;
  if (!anomaly || anomaly.skipped_reason || anomaly.disabled_reason) return null;
  return hasScore(anomaly.score) ? anomaly.score : null;
}

// 异常阈值：非正数、非数字或非有限值都视为不可用，避免进度条除零。
export function anomalyThreshold(record) {
  const threshold = record?.anomaly?.threshold;
  return hasScore(threshold) && threshold > 0 ? threshold : null;
}

function deltaPhrase(delta) {
  if (delta === 0) return '已达阈值';
  return (delta > 0 ? '超过 ' : '低于 ') + Math.abs(delta) + ' 分';
}

export function anomalyScoreHint(record) {
  const anomaly = record?.anomaly || {};
  const score = anomalyScore(record);
  if (score === null) {
    if (anomaly.disabled_reason) return '行为基线偏离程度：基线模型不可用，本步未评分';
    if (anomaly.skipped_reason === 'hard_deny') return '行为基线偏离程度：已命中拒绝规则，本步未评分';
    return '行为基线偏离程度：本条记录没有评分数据';
  }
  const threshold = anomalyThreshold(record);
  if (threshold === null) return '行为基线偏离程度：评分 ' + score + '，异常阈值不可用';
  return '行为基线偏离程度：评分 ' + score + ' / 阈值 ' + threshold + '，'
    + deltaPhrase(round2(score - threshold));
}

// 进度条刻度：留 20% 余量，保证最高分或阈值也不会把填充顶到单元格边缘。
const headroom = (largest) => {
  const padded = largest * 1.2;
  return Math.max(1, Math.ceil(Number.isFinite(padded) ? padded : largest));
};

// 列表统一刻度：取当前记录中评分与阈值的最大值并留 20% 余量，
// 让各行进度条可横向对比；缺阈值的行也不会因自身拉伸而显得接近阈值。
export function anomalyScale(records) {
  const largest = (records || []).reduce((max, record) => {
    const score = anomalyScore(record);
    if (score === null) return max;
    return Math.max(max, score, anomalyThreshold(record) ?? 0);
  }, 0);
  return headroom(largest);
}

// 进度条视图：只计算展示比例与差值，评分和阈值均来自后端记录。
export function anomalyScoreView(record, columnScale = 0) {
  const score = anomalyScore(record);
  if (score === null) return null;
  const threshold = anomalyThreshold(record);
  const delta = threshold === null ? null : round2(score - threshold);
  // 优先使用列表统一刻度；单独调用时退回与详情阈值图一致的逐行刻度。
  const scale = hasScore(columnScale) && columnScale > 0
    ? columnScale : headroom(Math.max(score, threshold ?? 0));
  const percent = (value) => Math.max(0, Math.min(100, value / scale * 100));
  return {
    score, threshold, delta, scale,
    anomalous: typeof record?.anomaly?.anomalous === 'boolean'
      ? record.anomaly.anomalous : delta !== null && delta >= 0,
    scorePercent: percent(score),
    thresholdPercent: threshold === null ? null : percent(threshold),
    stateText: threshold === null ? '阈值不可用'
      : delta === 0 ? '已达阈值' : (delta > 0 ? '超过 ' : '低于 ') + Math.abs(delta),
    summary: anomalyScoreHint(record),
  };
}

export function highlightCommand(content, command) {
  const text = String(content ?? '');
  if (!command) return [{text, match: false}];
  const needles = [...new Set([command, JSON.stringify(command).slice(1, -1)])].filter(Boolean);
  const result = [];
  let offset = 0;
  while (offset < text.length) {
    let position = -1, needle = '';
    for (const candidate of needles) {
      const next = text.indexOf(candidate, offset);
      if (next >= 0 && (position < 0 || next < position || (next === position && candidate.length > needle.length))) {
        position = next; needle = candidate;
      }
    }
    if (position < 0) { result.push({text: text.slice(offset), match: false}); break; }
    if (position > offset) result.push({text: text.slice(offset, position), match: false});
    result.push({text: text.slice(position, position + needle.length), match: true});
    offset = position + needle.length;
  }
  return result.length ? result : [{text, match: false}];
}
