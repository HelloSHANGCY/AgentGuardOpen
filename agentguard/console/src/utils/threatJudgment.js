import { ASSESSMENT_TEXT, ASSESSMENT_TAG, ASSESSMENT_STATUS_TEXT, assessmentText, VERDICT_TEXT, VERDICT_TAG } from './format.js';

// 仅使用记录自身携带的模型结果；不把同会话的结论推断成某条调用的告警研判。
function decisionJudgment(decision) {
  const assessment = decision?.assessment;
  if (assessment && typeof assessment === 'object') {
    const verdict = assessment.assessment;
    const incomplete = !!ASSESSMENT_STATUS_TEXT[assessment.status];
    return {
      key: incomplete ? 'assessment_' + assessment.status : ASSESSMENT_TEXT[verdict] ? 'assessment_' + verdict : 'unknown',
      label: assessmentText(assessment),
      type: incomplete ? 'warning' : ASSESSMENT_TAG[verdict] || 'info', source: '告警研判',
      note: assessment.note || '', model: assessment.model || '',
      decisionId: decision.decision_id, hasResult: !incomplete, hasDetails: true,
    };
  }
  const review = decision?.review;
  if (!review || typeof review !== 'object') return null;
  const state = review.status === 'ok' ? review.verdict : review.status;
  const labels = { ALLOW: '复核放行', ASK: '复核需确认', DENY: '复核拦截', timeout: '复核超时', failed: '复核失败', error: '复核失败' };
  const types = { ALLOW: 'success', ASK: 'warning', DENY: 'danger', timeout: 'warning', failed: 'info', error: 'info' };
  return {
    key: labels[state] ? 'review_' + (state === 'error' ? 'failed' : state) : 'unknown',
    label: labels[state] || '结论未知', type: types[state] || 'info', source: '危险审批',
    note: review.status === 'ok' ? review.reason || '' : review.error || '',
    model: review.model || '', decisionId: decision.decision_id,
  };
}

export function threatJudgment(alert) {
  if (alert.analysis) {
    const record = alert.analysis;
    const state = record.status === 'done' && record.coverage?.complete === false ? 'partial'
      : record.status === 'done' ? record.verdict : record.status;
    const recognized = !!VERDICT_TEXT[state];
    const source = record.round ? `第 ${record.round} 轮分析` : '会话分析';
    return {
      key: state === 'partial' || recognized ? 'analysis_' + state : 'unknown',
      label: state === 'partial' ? '部分完成' : VERDICT_TEXT[state] || '结论未知',
      type: state === 'partial' ? 'warning' : VERDICT_TAG[state] || 'info', source,
      note: record.status === 'failed' ? record.error || '' : record.summary || '',
      model: record.model || '', decisionId: alert.latest?.decision_id,
      hasResult: true, analyzedCount: 1, totalCount: 1,
    };
  }
  const items = alert.items?.length ? alert.items : [alert.latest].filter(Boolean);
  const analyzed = items.map(decisionJudgment).filter(Boolean);
  const analyzedCount = analyzed.filter(item => item.hasResult !== false).length;
  const latest = decisionJudgment(alert.latest);
  if (latest) return { hasResult: true, ...latest, analyzedCount, totalCount: items.length };
  if (analyzedCount) return {
    ...analyzed.find(item => item.hasResult !== false), key: 'partial', label: '部分已研判', type: 'warning',
    source: `${analyzedCount} / ${items.length} 条有结果`,
    hasResult: true, analyzedCount, totalCount: items.length,
  };
  if (analyzed.length) return { ...analyzed[0], analyzedCount: 0, totalCount: items.length };
  return { key: 'unlinked', label: '暂无结果', type: 'info', source: '', note: '', model: '',
    hasResult: false, analyzedCount: 0, totalCount: items.length };
}

export function judgmentDescription(judgment) {
  return [judgment.source, judgment.label, judgment.note, judgment.model].filter(Boolean).join(' · ');
}

export function judgmentFilterLabel(judgment) {
  if (judgment.key.startsWith('assessment_')) return '告警研判 · ' + judgment.label;
  if (judgment.key.startsWith('analysis_')) return '会话分析 · ' + judgment.label;
  if (judgment.key.startsWith('review_')) return '危险审批 · ' + judgment.label;
  return judgment.label;
}
