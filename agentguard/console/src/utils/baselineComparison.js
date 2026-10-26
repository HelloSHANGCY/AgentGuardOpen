export const RADAR_METRICS = [
  { key: 'accuracy', label: '准确率', axis: '准确率', kind: 'percent', higher: true },
  { key: 'precision', label: '精确率', axis: '精确率', kind: 'percent', higher: true },
  { key: 'recall', label: '召回率', axis: '召回率', kind: 'percent', higher: true },
  { key: 'f1', label: 'F1 分数', axis: 'F1', kind: 'percent', higher: true },
  { key: 'auc', label: 'AUC', axis: 'AUC × 100', kind: 'auc', higher: true },
];

export const isNumber = value => typeof value === 'number' && Number.isFinite(value);
export const chartValue = value => isNumber(value) ? Number((value * 100).toFixed(4)) : null;
export function formatMetric(value, kind = 'percent') {
  if (!isNumber(value)) return '—';
  if (kind === 'percent') return (value * 100).toFixed(2) + '%';
  if (kind === 'integer') return value.toLocaleString('zh-CN');
  return value.toFixed(kind === 'auc' ? 3 : 2);
}

export function comparisonRows(a, b) {
  const metrics = [...RADAR_METRICS,
    { key: 'normal_trigger_rate', label: '正常步骤超阈值率', kind: 'percent', higher: false },
    { key: 'threshold', label: '异常阈值', kind: 'number', higher: null },
    { key: 'sessions', label: '训练会话', kind: 'integer', higher: null },
    { key: 'steps', label: '训练步骤', kind: 'integer', higher: null },
  ];
  const value = (model, key) => key === 'threshold' ? model?.threshold
    : ['sessions', 'steps'].includes(key) ? model?.training?.[key] : model?.metrics?.[key];
  return metrics.map(metric => {
    const av = value(a, metric.key), bv = value(b, metric.key);
    const raw = isNumber(av) && isNumber(bv) ? bv - av : null;
    const delta = raw !== null && Math.abs(raw) < 1e-10 ? 0 : raw;
    const scale = metric.kind === 'percent' ? 100 : 1;
    const decimals = metric.kind === 'integer' ? 0 : metric.kind === 'auc' ? 3 : 2;
    return { ...metric, a: formatMetric(av, metric.kind), b: formatMetric(bv, metric.kind),
      delta: delta === null ? '—' : (delta > 0 ? '+' : delta < 0 ? '−' : '')
        + Math.abs(delta * scale).toLocaleString('zh-CN', {minimumFractionDigits: decimals, maximumFractionDigits: decimals})
        + (metric.kind === 'percent' ? ' pp' : ''),
      tone: delta === null || delta === 0 || metric.higher === null ? 'neutral'
        : (metric.higher ? delta > 0 : delta < 0) ? 'better' : 'worse',
    };
  });
}

export function sourceLabel(model) {
  if (model?.version === 'builtin-legacy') return '原始一阶内置';
  if (model?.meta?.external_sessions && model?.builtin) return '内置 · SWE-chat ' + model.meta.external_sessions;
  if (model?.builtin || model?.version === 'builtin') return '内置';
  if (model?.meta?.external_sessions) return 'SWE-chat ' + model.meta.external_sessions;
  return model?.meta?.recorded_sessions ? '接入 ' + model.meta.recorded_sessions : '内置重训';
}

export function defaultVersions(models, active) {
  const available = models.filter(model => model.compatible !== false).map(model => model.version);
  const a = available.includes('builtin') ? 'builtin' : available[0] || '';
  const b = available.includes(active) && active !== a ? active : available.find(version => version !== a) || '';
  return { a, b, c: available.find(version => version !== a && version !== b) || '' };
}
