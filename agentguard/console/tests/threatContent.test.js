import test from 'node:test';
import assert from 'node:assert/strict';
import { anomalyScale, anomalyScore, anomalyScoreHint, anomalyScoreView, executionCommand, highlightCommand, isCurrentCall } from '../src/utils/threatContent.js';

const detail = {decision_id:'d1', context:{event_id:'e1', resource:'exec:short summary'}, evidence_ids:['e1']};

test('当前调用的完整参数优先于截断的资源摘要', () => {
  const command = 'python3 - <<\'PY\'\nprint("完整命令")\nPY';
  const records = [{kind:'TOOL_ARGUMENTS', event_id:'e-other', content:JSON.stringify({command:'other'})},
    {kind:'TOOL_ARGUMENTS', event_id:'e1', content:JSON.stringify({command})}];
  assert.equal(executionCommand(detail, records), command);
});

test('相似的其他调用不参与原文或命令关联', () => {
  assert.equal(executionCommand(detail, [{kind:'TOOL_ARGUMENTS', event_id:'e2', content:'{"command":"wrong"}'}]), 'short summary');
  assert.equal(isCurrentCall({kind:'TOOL_RESULT', event_id:'e1'}, detail), false);
  assert.equal(isCurrentCall({kind:'TOOL_ARGUMENTS', evidence_id:'evd1'}, {...detail,evidence_ids:['evd1']}), true);
});

test('JSON 转义后的多行命令整段高亮并保留原文', () => {
  const command = 'python3 - <<\'PY\'\nprint("x\\y")\nPY';
  const content = JSON.stringify({command, timeout:1000});
  const parts = highlightCommand(content, command);
  assert.equal(parts.map(part => part.text).join(''), content);
  assert.deepEqual(parts.filter(part => part.match).map(part => part.text), [JSON.stringify(command).slice(1,-1)]);
});

test('命令中的正则符号和 HTML 作为普通文本匹配', () => {
  const command = 'echo "$HOME" | sed "s/[a-z]+/<script>/g"';
  const text = `开始\n${command}\n${command}\n结束`;
  const parts = highlightCommand(text, command);
  assert.equal(parts.filter(part => part.match).length, 2);
  assert.equal(parts.map(part => part.text).join(''), text);
  assert.equal(highlightCommand('echo $HOME', '.*')[0].match, false);
});

test('没有命令、空文本与不完整 JSON 保持可展示', () => {
  assert.deepEqual(highlightCommand('', ''), [{text:'',match:false}]);
  assert.deepEqual(highlightCommand('原始内容', ''), [{text:'原始内容',match:false}]);
  assert.equal(executionCommand({tool:'Bash',context:{preview:'{"command":"cut'}}), '');
  assert.equal(executionCommand({context:{resource:'file_read:/tmp/example.txt'}}), '');
});

test('风险评分与差值沿用后端精度，不额外补零', () => {
  const over = anomalyScoreView({anomaly:{score:8.48, threshold:8.21, anomalous:true}});
  assert.equal(over.score, 8.48);
  assert.equal(over.delta, 0.27);
  assert.match(over.summary, /8\.48 \/ 阈值 8\.21，超过 0\.27 分/);

  const below = anomalyScoreView({anomaly:{score:2.6, threshold:8.21, anomalous:false}});
  assert.equal(below.score, 2.6);
  assert.equal(below.delta, -5.61);
  assert.match(below.summary, /2\.6 \/ 阈值 8\.21，低于 5\.61 分/);
  // 0 是有效评分，只有缺失/未评分才返回 null。
  assert.equal(anomalyScore({anomaly:{score:0, threshold:8.21}}), 0);
});

test('缺失或未评分的风险评分不生成进度条', () => {
  for (const record of [{}, {anomaly:null},
    {anomaly:{anomalous:false, skipped_reason:'hard_deny'}},
    {anomaly:{anomalous:false, disabled_reason:'baseline_unavailable'}},
    {anomaly:{score:'8.48'}}, {anomaly:{score:Number.NaN}}]) {
    assert.equal(anomalyScore(record), null);
    assert.equal(anomalyScoreView(record), null);
  }
});

test('风险评分提示同时给出评分、阈值与差值', () => {
  assert.equal(anomalyScoreHint({anomaly:{score:8.48, threshold:8.21, anomalous:true}}),
    '行为基线偏离程度：评分 8.48 / 阈值 8.21，超过 0.27 分');
  assert.equal(anomalyScoreHint({anomaly:{score:2.6, threshold:8.21, anomalous:false}}),
    '行为基线偏离程度：评分 2.6 / 阈值 8.21，低于 5.61 分');
  assert.equal(anomalyScoreHint({anomaly:{score:8.21, threshold:8.21, anomalous:true}}),
    '行为基线偏离程度：评分 8.21 / 阈值 8.21，已达阈值');
  assert.equal(anomalyScoreHint({anomaly:{score:8.48}}), '行为基线偏离程度：评分 8.48，异常阈值不可用');
  assert.equal(anomalyScoreHint({anomaly:{skipped_reason:'hard_deny'}}), '行为基线偏离程度：已命中拒绝规则，本步未评分');
  assert.equal(anomalyScoreHint({anomaly:{disabled_reason:'baseline_unavailable'}}), '行为基线偏离程度：基线模型不可用，本步未评分');
  assert.equal(anomalyScoreHint({}), '行为基线偏离程度：本条记录没有评分数据');
});

test('进度条按评分与阈值的较大值留余量，超阈值不溢出单元格', () => {
  const over = anomalyScoreView({anomaly:{score:8.48, threshold:8.21, anomalous:true}});
  assert.equal(over.scale, 11);
  assert.equal(over.delta, 0.27);
  assert.equal(over.stateText, '超过 0.27');
  assert.equal(over.anomalous, true);
  assert.ok(over.scorePercent > over.thresholdPercent);
  assert.ok(over.scorePercent <= 100 && over.thresholdPercent <= 100);

  const below = anomalyScoreView({anomaly:{score:2.6, threshold:8.21, anomalous:false}});
  assert.equal(below.scale, 10);
  assert.equal(below.delta, -5.61);
  assert.equal(below.stateText, '低于 5.61');
  assert.ok(Math.abs(below.scorePercent - 26) < 1e-9);
  assert.ok(Math.abs(below.thresholdPercent - 82.1) < 1e-9);

  const equal = anomalyScoreView({anomaly:{score:8.21, threshold:8.21, anomalous:true}});
  assert.equal(equal.delta, 0);
  assert.equal(equal.stateText, '已达阈值');
});

test('阈值缺失或非正数时不画阈值线且按不可用处理', () => {
  for (const threshold of [undefined, null, 0, -1, '8.21', Number.NaN, Number.POSITIVE_INFINITY]) {
    const view = anomalyScoreView({anomaly:{score:8.48, threshold}});
    assert.equal(view.threshold, null);
    assert.equal(view.thresholdPercent, null);
    assert.equal(view.stateText, '阈值不可用');
    assert.match(view.summary, /异常阈值不可用/);
    assert.ok(Number.isFinite(view.scorePercent) && view.scorePercent > 0 && view.scorePercent < 100);
  }
  assert.equal(anomalyScoreView({}), null);
  assert.equal(anomalyScoreView({anomaly:{anomalous:false, skipped_reason:'hard_deny'}}), null);
});

test('列表统一刻度让不同记录与阈值位置可横向对比', () => {
  const scale = anomalyScale([
    {anomaly:{score:8.48, threshold:8.21}},
    {anomaly:{score:2.6, threshold:8.21}},
    {anomaly:{score:6.5}},
    {anomaly:{skipped_reason:'hard_deny'}},
  ]);
  assert.equal(scale, 11);

  const noThreshold = anomalyScoreView({anomaly:{score:3.2}}, scale);
  assert.equal(noThreshold.thresholdPercent, null);
  assert.equal(noThreshold.scale, 11);
  assert.ok(Math.abs(noThreshold.scorePercent - 3.2 / 11 * 100) < 1e-9);

  const below = anomalyScoreView({anomaly:{score:2.6, threshold:8.21}}, scale);
  assert.ok(Math.abs(below.thresholdPercent - 8.21 / 11 * 100) < 1e-9);
  assert.ok(below.scorePercent < below.thresholdPercent);
  assert.equal(anomalyScale([]), 1);
});
