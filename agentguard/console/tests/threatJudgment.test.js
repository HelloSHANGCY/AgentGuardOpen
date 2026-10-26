import test from 'node:test';
import assert from 'node:assert/strict';
import { threatJudgment, judgmentDescription, judgmentFilterLabel } from '../src/utils/threatJudgment.js';

const alertFor = latest => ({ latest, items: [latest] });

test('告警研判保留具体结论与模型依据，标签不改变实际处置', () => {
  for (const [assessment, label] of [['true_positive', '真实威胁'], ['false_positive', '误报'], ['uncertain', '不确定']]) {
    const latest = Object.freeze({ decision_id: 'd-1', decision: 'DENY', assessment: {assessment, note: '调用与任务目标一致', model: 'judge-model'} });
    const result = threatJudgment(alertFor(latest));
    assert.equal(result.label, label);
    assert.equal(result.source, '告警研判');
    assert.equal(result.decisionId, 'd-1');
    assert.equal(latest.decision, 'DENY');
    assert.match(judgmentDescription(result), /调用与任务目标一致/);
    assert.match(judgmentFilterLabel(result), /^告警研判/);
  }
});

test('最新一次没有结果时不借用早期的误报结论，并定位到真正已有研判的发生记录', () => {
  const latest = {decision_id: 'latest', decision: 'DENY'};
  const older = {decision_id: 'older', assessment: {assessment: 'false_positive', note: '旧调用属于任务授权范围'}};
  const result = threatJudgment({latest, items: [latest, older]});
  assert.equal(result.key, 'partial');
  assert.equal(result.label, '部分已研判');
  assert.equal(result.decisionId, 'older');
  assert.equal(result.analyzedCount, 1);
  assert.equal(result.totalCount, 2);
});

test('较早记录的相反结论不覆盖最新一次的直接研判', () => {
  const latest = {decision_id: 'latest', assessment: {assessment: 'true_positive'}};
  const older = {decision_id: 'older', assessment: {assessment: 'false_positive'}};
  const result = threatJudgment({latest, items: [latest, older]});
  assert.equal(result.label, '真实威胁');
  assert.equal(result.decisionId, 'latest');
  assert.equal(result.analyzedCount, 2);
});

test('会话分析与具体告警研判分开，失败和进行中不伪装成正常结论', () => {
  for (const [status, verdict, label] of [['done','malicious','恶意'], ['done','suspicious','可疑'], ['done','benign','正常'], ['pending','','分析中'], ['failed','benign','失败']]) {
    const result = threatJudgment({ latest: {decision_id:'analysis-row'}, analysis: {status, verdict, round:3, summary:'本轮会话摘要', error:'服务未响应'} });
    assert.equal(result.label, label);
    assert.equal(result.source, '第 3 轮分析');
    assert.match(judgmentFilterLabel(result), /^会话分析/);
    if (status === 'failed') assert.equal(result.note, '服务未响应');
  }
  assert.equal(threatJudgment({analysis:{status:'done',verdict:'invalid'}}).label, '结论未知');
  assert.equal(threatJudgment({analysis:{status:'done',verdict:'benign',round:0}}).source, '会话分析');
});

test('危险审批使用复核标签，超时与失败不推断为放行或拦截', () => {
  for (const [review, label] of [[{status:'ok',verdict:'ALLOW'},'复核放行'], [{status:'ok',verdict:'DENY'},'复核拦截'], [{status:'ok',verdict:'ASK'},'复核需确认'], [{status:'timeout',verdict:'ALLOW'},'复核超时'], [{status:'error',verdict:'DENY'},'复核失败']]) {
    const latest = {decision_id:'d-1',decision:'DENY',review};
    const result = threatJudgment(alertFor(latest));
    assert.equal(result.label, label);
    assert.equal(result.source, '危险审批');
    assert.equal(latest.decision, 'DENY');
  }
});

test('风险级别和规则命中不能代替模型结果；缺失和未知保持明确状态', () => {
  const result = threatJudgment(alertFor({decision_id:'d-1',decision:'DENY',severity:'CRITICAL',labels:['MALICIOUS']}));
  assert.equal(result.label, '暂无结果');
  assert.equal(result.hasResult, false);
  assert.equal(result.analyzedCount, 0);
  assert.equal(threatJudgment(alertFor({assessment:{assessment:'new_kind'}})).label, '结论未知');
});

test('模型漏回与调用失败显示明确状态，不伪装成模型不确定或已研判数量', () => {
  for (const [status, label] of [['missing', '未返回结论'], ['failed', '研判失败']]) {
    const latest = {decision_id:'d-missing', decision:'DENY', assessment:{assessment:'', status, note:'补查仍无结论'}};
    const older = {decision_id:'d-ok', assessment:{assessment:'false_positive'}};
    const result = threatJudgment({latest, items:[latest, older]});
    assert.equal(result.label, label);
    assert.equal(result.hasResult, false);
    assert.equal(result.hasDetails, true);
    assert.equal(result.analyzedCount, 1);
    assert.equal(result.decisionId, 'd-missing');
    assert.match(judgmentDescription(result), /补查仍无结论/);
    const noResults = threatJudgment({latest:{decision_id:'new'}, items:[{decision_id:'new'},latest]});
    assert.equal(noResults.label, label);
    assert.equal(noResults.analyzedCount, 0);
  }
});

test('会话只有部分告警完成时不显示整体正常标签', () => {
  const result = threatJudgment({analysis:{status:'done', verdict:'benign', coverage:{total:3,assessed:2,complete:false}}});
  assert.equal(result.label, '部分完成');
  assert.equal(result.type, 'warning');
});
