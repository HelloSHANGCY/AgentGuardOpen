import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { deploymentHash, parseDeploymentHash } from '../src/utils/deploymentNavigation.js';
import { deploymentDefaults, deploymentCoreLinks, deploymentNodes, deploymentEdges, deploymentFlows, deploymentVolumes, deploymentMethods } from '../src/data/deployment.js';

const root = new URL('../../../', import.meta.url);
const source = path => readFileSync(new URL(path, root), 'utf8');

test('部署方式可直接打开与还原，旧靶场书签转入组件架构', () => {
  for (const hash of ['#/deployment', '#/deployment/', '#/deployment/architecture', '#/range']) {
    assert.deepEqual(parseDeploymentHash(hash), { page: 'architecture', method: 'docker' });
  }
  for (const method of ['docker', 'source']) {
    assert.deepEqual(parseDeploymentHash(deploymentHash('methods', method)), { page: 'methods', method });
  }
  assert.equal(deploymentHash(), '#/deployment');
  assert.deepEqual(parseDeploymentHash('#/deployment/methods'), { page: 'methods', method: 'docker' });
});

test('未知方式与其他页面不冒充部署链接', () => {
  for (const hash of ['#/deployment/unknown', '#/deployment/methods/k8s', '#/deployment/methods/docker/extra', '#/terminals/deploy', '#/metrics']) {
    assert.equal(parseDeploymentHash(hash), null);
  }
});

test('标准部署入口和数据卷与当前编排一致', () => {
  const compose = source(deploymentDefaults.compose);
  assert.ok(compose.includes('"' + deploymentDefaults.binding + '"'));
  for (const volume of deploymentVolumes) assert.ok(compose.includes(volume.name + ':' + volume.path));
  assert.equal(deploymentVolumes.length, 3);
  assert.ok(source('agentguard/Dockerfile').includes('EXPOSE 8080\n'));
});

test('图中连接、链路节点与代码来源全部可解析', () => {
  const ids = new Set(deploymentNodes.map(node => node.id));
  const edges = new Set(deploymentEdges.map(edge => edge.id));
  assert.equal(ids.size, deploymentNodes.length);
  assert.equal(edges.size, deploymentEdges.length);
  for (const edge of [...deploymentEdges, ...deploymentCoreLinks]) assert.ok(ids.has(edge.from) && ids.has(edge.to));
  for (const flow of deploymentFlows) {
    assert.ok(ids.has(flow.focus));
    assert.ok(flow.nodes.every(id => ids.has(id)));
    assert.ok(flow.edges.every(id => edges.has(id)));
    assert.ok(deploymentEdges.filter(edge => flow.edges.includes(edge.id)).every(edge => flow.nodes.includes(edge.from) && flow.nodes.includes(edge.to)));
  }
  for (const node of deploymentNodes) {
    for (const path of node.sources) assert.ok(existsSync(new URL(path, root)), path);
  }
});

test('页面公开的接入路径和 worker 入口在当前代码中存在', () => {
  assert.ok(source('agentguard/agentguard/agents/api.py').includes('/v1/agents/{agent}/hook'));
  for (const endpoint of ['inspect-request', 'inspect-result']) {
    assert.ok(source('agentguard/agentguard/agents/api.py').includes('/v1/runtime/mcp/' + endpoint));
  }
  const entry = source('agentguard/start.sh');
  assert.ok(entry.includes('agentguard.static_scan.worker'));
  assert.ok(entry.includes('AG_EVAL_ADMIN_TOKEN') && entry.includes('AG_LOCAL_TEST'));
  assert.ok(entry.includes('agentguard.evaluation'));
});

test('远程返回到 Agent 的链路必须经过返回内容检查', () => {
  for (const id of ['http', 'response', 'llm']) {
    const flow = deploymentFlows.find(item => item.id === id);
    const edges = deploymentEdges.filter(edge => flow.edges.includes(edge.id));
    const remote = id === 'llm' ? 'model' : 'remote-mcp';
    assert.ok(edges.some(edge => edge.from === remote && edge.to === 'result-check' && edge.kind === 'response'));
    const checked = new Set(['result-check']);
    for (let i = 0; i < deploymentNodes.length; i++) {
      for (const edge of edges) if (edge.kind === 'response' && checked.has(edge.from)) checked.add(edge.to);
    }
    assert.ok(checked.has('agent'), id + ' delivers checked content to Agent');
    const withoutCheck = edges.filter(edge => edge.from !== 'result-check' && edge.to !== 'result-check');
    const reachable = new Set([remote]);
    for (let i = 0; i < deploymentNodes.length; i++) {
      for (const edge of withoutCheck) if (reachable.has(edge.from)) reachable.add(edge.to);
    }
    assert.equal(reachable.has('agent'), false, id + ' cannot bypass result inspection');
  }
});

test('LLM 仅展示返回接入关系，示意状态与请求方向明确', () => {
  assert.equal(deploymentNodes.find(node => node.id === 'model').status, 'design');
  assert.equal(deploymentFlows.find(flow => flow.id === 'llm').status, 'design');
  assert.equal(deploymentEdges.find(edge => edge.id === 'llm-result').status, 'design');
  assert.ok(deploymentEdges.every(edge => edge.to !== 'model'));
});

test('源码示例为各进程配置相同数据库，Docker 命令使用现有入口', () => {
  const docker = deploymentMethods.find(method => method.id === 'docker');
  assert.ok(docker.steps.some(step => step.code === 'docker compose -f ' + deploymentDefaults.compose + ' up -d --build'));
  const local = deploymentMethods.find(method => method.id === 'source');
  const processes = local.steps.slice(1);
  assert.equal(processes.length, 3);
  for (const step of processes) {
    assert.ok(step.code.includes('export AG_DATA_DIR="$HOME/.local/share/agentguard-dev"'));
    assert.ok(step.code.includes('export AG_STATIC_DB="$AG_DATA_DIR/static-scan.db"'));
    assert.ok(step.code.includes('export AG_EVAL_DB="$AG_DATA_DIR/evaluation.db"'));
  }
});
