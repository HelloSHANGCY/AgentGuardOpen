<template>
  <section v-show="tab === 'deployment'" class="project-deployment-page" :class="{ 'has-focused-flow': flowFocused }" @keydown.esc="helpVisible = false">
    <ConsolePageHeader title="部署架构">
      <template #title-extra>
        <el-popover v-model:visible="helpVisible" placement="bottom-start" trigger="click" :width="350">
          <template #reference>
            <button type="button" class="deployment-help" aria-label="部署架构说明" :aria-expanded="helpVisible"><QuestionFilled aria-hidden="true" /></button>
          </template>
          <p>图中按客户端、AgentGuard 服务端和远程服务展示逻辑架构。Hook 与 MCP 接入运行时检查，静态扫描接收授权资产快照。</p>
          <p>客户端接入会修改配置：Hook 注册工具执行回调，stdio MCP 包装启动命令，HTTP MCP 改写服务地址。服务端核心框表示统一管理与审计关联，静态扫描仍使用独立 worker 和数据库。</p>
          <p>蓝色表示请求，紫色表示返回。远程返回先进入内容安全检查，再交付客户端 Agent。LLM 虚线表示返回内容的接入关系，具体覆盖取决于客户端提供的响应事件。</p>
          <p>流动动画演示所选链路的方向，不表示实时流量。运行进程与持久化配置可在下方展开查看。</p>
        </el-popover>
      </template>
      <el-button @click="openClientDeploy"><el-icon class="btn-ic" aria-hidden="true"><Monitor /></el-icon>客户端部署</el-button>
    </ConsolePageHeader>

    <el-tabs v-model="deploymentPage" class="deployment-tabs" aria-label="项目部署内容">
      <el-tab-pane name="architecture" label="组件架构">
        <div class="deployment-flow-controls">
          <el-radio-group v-model="flowId" aria-label="查看部署链路">
            <el-radio-button v-for="item in deploymentFlows" :key="item.id" :value="item.id">{{ item.label }}</el-radio-button>
          </el-radio-group>
          <div class="deployment-legend" aria-label="连接线图例"><span><i class="is-request" />请求</span><span><i class="is-response" />返回</span><span><i class="is-core" />核心关联</span><span><i class="is-data" />资产快照</span><span><i class="is-design" />接入示意</span></div>
        </div>

        <ol v-if="flow.steps.length" class="deployment-flow-steps" :aria-label="flow.label + '处理顺序'">
          <li v-for="(step, index) in flow.steps" :key="step"><span>{{ index + 1 }}</span>{{ step }}<ArrowRight v-if="index < flow.steps.length - 1" aria-hidden="true" /></li>
        </ol>

        <div class="deployment-architecture" data-motion-scope>
          <section class="deployment-graph-panel" aria-label="系统组件与连接关系">
            <div class="deployment-panel-head"><h3>客户端与服务端</h3><span>{{ flow.label }}<span v-if="flow.status === 'design'" class="deployment-design-badge">接入示意</span></span></div>
            <div class="deployment-graph-scroll" tabindex="0" aria-label="部署组件图，可横向滚动">
              <div class="deployment-canvas" :class="{ 'is-flow-running': flowRunning }" :data-flow="flowId">
                <div v-for="zone in deploymentDiagram.zones" :key="zone.id" class="deployment-zone" :class="'is-' + zone.id" :style="nodeStyle(zone)"><span>{{ zone.label }}</span></div>
                <div class="deployment-integration-frame" :class="{ 'is-active': activeNodes.has('hook') || activeNodes.has('stdio') }" :style="nodeStyle(deploymentDiagram.integration)"><span id="deployment-integration-label">{{ deploymentDiagram.integration.label }}</span></div>
                <div class="deployment-core-frame" :style="nodeStyle(deploymentDiagram.core)" aria-hidden="true" />
                <svg class="deployment-edges" :viewBox="'0 0 ' + deploymentDiagram.width + ' ' + deploymentDiagram.height" preserveAspectRatio="none" aria-hidden="true">
                  <defs>
                    <marker id="deployment-arrow" class="deployment-marker-neutral" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" /></marker>
                    <marker id="deployment-arrow-active" class="deployment-marker-active" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" /></marker>
                    <marker id="deployment-arrow-response" class="deployment-marker-response" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" /></marker>
                  </defs>
                  <path v-for="link in coreLinks" :key="link.id" :d="link.path" class="deployment-core-link" :data-core-link="link.to"
                        :class="{ 'is-active': activeNodes.has(link.to) }"><title>{{ link.relation }}</title></path>
                  <path v-for="edge in flowingEdges" :key="edge.id" :d="edge.path" class="deployment-edge"
                        :data-edge-id="edge.id"
                        :class="[edge.kind, { 'is-design': edge.status === 'design', 'is-active': activeEdges.has(edge.id), 'is-selected': selectedEdges.has(edge.id) }]"
                        :marker-end="edgeMarker(edge)" />
                  <g v-if="flowRunning" class="deployment-flow-particles">
                    <path v-for="(edge, index) in flowingEdges" :key="flowId + edge.id" :d="edge.path" :data-edge-id="edge.id"
                          class="deployment-flow-particle" :class="edge.kind" :style="{ '--flow-delay': (-index * .22) + 's' }" />
                  </g>
                </svg>
                <span v-for="edge in deploymentEdges.filter(item => item.label && activeEdges.has(item.id))" :key="edge.id + '-label'"
                      class="deployment-edge-label" :class="edge.kind" :style="pointStyle(edge)">{{ edge.label }}</span>
                <button v-for="node in deploymentNodes" :key="node.id" type="button" class="deployment-node"
                        :class="{ 'is-gateway': node.id === 'gateway', 'is-result': node.id === 'result-check', 'is-design': node.status === 'design', 'is-active': activeNodes.has(node.id), 'is-selected': selectedId === node.id }"
                        :style="nodeStyle(node)" :aria-label="'查看' + node.title + '组件'" :aria-pressed="selectedId === node.id"
                        :aria-describedby="node.integration ? 'deployment-integration-label' : undefined"
                        aria-controls="deployment-component-detail" @click="selectNode(node.id)">
                  <el-icon aria-hidden="true"><component :is="node.icon" /></el-icon>
                  <span><span v-if="node.role === 'core'" class="deployment-core-badge">服务端核心</span><strong>{{ node.title }}</strong><span>{{ node.caption }}</span></span>
                </button>
              </div>
            </div>
          </section>

          <aside id="deployment-component-detail" class="deployment-inspector" aria-label="组件详情" aria-live="polite">
            <div class="deployment-inspector-title"><el-icon aria-hidden="true"><component :is="selectedNode.icon" /></el-icon><h3>{{ selectedNode.title }}</h3></div>
            <p class="deployment-description">{{ selectedNode.description }}</p>
            <dl class="deployment-facts">
              <div v-for="[label, value] in selectedNode.facts" :key="label"><dt>{{ label }}</dt><dd>{{ value }}</dd></div>
            </dl>
            <div v-if="selectedNode.sources.length" class="deployment-source"><h4>代码位置</h4><code v-for="source in selectedNode.sources" :key="source">{{ source }}</code></div>
            <el-button v-if="selectedNode.action" class="deployment-component-action" @click="openComponent(selectedNode.action)">{{ selectedNode.action === 'models' ? '前往模型管理' : '前往客户端部署' }}<el-icon class="btn-ic" aria-hidden="true"><ArrowRight /></el-icon></el-button>
          </aside>
        </div>

        <details class="deployment-runtime-details">
          <summary>运行与持久化</summary>
          <div class="deployment-overview" aria-label="默认 Docker 部署参数">
            <div><span>服务部署</span><strong>1 <small>个容器</small></strong><code>agentguard</code></div>
            <div><span>默认入口</span><strong class="mono">18080 <ArrowRight aria-hidden="true" /> 8080</strong><code>127.0.0.1</code></div>
            <div><span>持久化</span><strong>{{ deploymentVolumes.length }} <small>个数据卷</small></strong><span>SQLite / 配置文件</span></div>
          </div>
          <section class="deployment-volume-panel">
          <div class="deployment-panel-head"><h3>数据卷与挂载</h3><code>{{ deploymentDefaults.compose }}</code></div>
          <div class="deployment-volume-content">
            <el-table :data="deploymentVolumes" empty-text="没有数据卷" class="deployment-volume-table">
              <el-table-column label="命名数据卷" min-width="170"><template #default="{ row }"><code>{{ row.name }}</code></template></el-table-column>
              <el-table-column label="容器内目录" min-width="255"><template #default="{ row }"><code>{{ row.path }}</code></template></el-table-column>
              <el-table-column prop="content" label="保存内容" min-width="270" />
            </el-table>
          </div>
          </section>
        </details>
      </el-tab-pane>

      <el-tab-pane name="methods" label="部署方式">
        <div class="deployment-method-layout" data-motion-scope>
          <aside class="deployment-method-picker" aria-label="选择部署方式">
            <button v-for="method in deploymentMethods" :key="method.id" type="button" :class="{ 'is-selected': deploymentMethod === method.id }"
                    :aria-pressed="deploymentMethod === method.id" @click="deploymentMethod = method.id">
              <el-icon aria-hidden="true"><component :is="method.icon" /></el-icon><span><strong>{{ method.title }}</strong><span>{{ method.summary }}</span></span><ArrowRight aria-hidden="true" />
            </button>
            <section class="deployment-method-facts">
              <h3>运行环境</h3>
              <ul><li v-for="item in method.requirements" :key="item">{{ item }}</li></ul>
              <dl class="deployment-facts"><div v-for="[label, value] in method.facts" :key="label"><dt>{{ label }}</dt><dd>{{ value }}</dd></div></dl>
              <h4>默认控制台</h4><code>{{ method.address }}</code>
            </section>
          </aside>
          <div class="deployment-method-content">
            <section class="deployment-run-steps" :aria-label="method.title + '部署步骤'">
              <DeploymentCommand v-for="(step, index) in method.steps" :key="method.id + step.title" v-bind="step" :number="index + 1" />
            </section>
            <section class="deployment-configuration">
              <h3>接入与配置</h3>
              <el-collapse v-model="expandedConfiguration">
                <el-collapse-item v-for="(item, index) in method.configurations" :key="method.id + item.title" :name="method.id + index" :title="item.title">
                  <DeploymentCommand v-bind="item" />
                </el-collapse-item>
              </el-collapse>
            </section>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </section>
</template>

<script setup>
import { computed, ref, watch, onMounted, onBeforeUnmount } from 'vue';
import { tab, deploymentPage, deploymentMethod, terminalTab } from '../store/runtime';
import { deploymentDefaults, deploymentDiagram, deploymentCoreLinks, deploymentNodes, deploymentEdges, deploymentFlows, deploymentVolumes, deploymentMethods } from '../data/deployment';
import DeploymentCommand from '../components/DeploymentCommand.vue';
import './deployment.css';

const flowId = ref('all'), selectedId = ref('gateway'), expandedConfiguration = ref([]);
const helpVisible = ref(false);
const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
const reducedMotion = ref(motionPreference.matches), pageVisible = ref(document.visibilityState === 'visible');
const updateVisibility = () => { pageVisible.value = document.visibilityState === 'visible'; };
const updateMotionPreference = () => { reducedMotion.value = motionPreference.matches; };
const flow = computed(() => deploymentFlows.find(item => item.id === flowId.value) || deploymentFlows[0]);
const flowFocused = computed(() => flowId.value !== 'all');
const activeNodes = computed(() => new Set(flow.value.nodes));
const activeEdges = computed(() => new Set(flow.value.edges));
const coreLinks = computed(() => [...deploymentCoreLinks].sort((a, b) => Number(activeNodes.value.has(a.to)) - Number(activeNodes.value.has(b.to))));
const flowingEdges = computed(() => deploymentEdges.filter(edge => activeEdges.value.has(edge.id)));
const flowRunning = computed(() => flowFocused.value && tab.value === 'deployment' && deploymentPage.value === 'architecture' && pageVisible.value && !reducedMotion.value);
const selectedNode = computed(() => deploymentNodes.find(item => item.id === selectedId.value) || deploymentNodes[0]);
const selectedEdges = computed(() => new Set(deploymentEdges.filter(edge => activeEdges.value.has(edge.id) && [edge.from, edge.to].includes(selectedId.value)).map(edge => edge.id)));
const method = computed(() => deploymentMethods.find(item => item.id === deploymentMethod.value) || deploymentMethods[0]);
const pointStyle = point => ({ left: point.x / deploymentDiagram.width * 100 + '%', top: point.y / deploymentDiagram.height * 100 + '%' });
const nodeStyle = node => ({ ...pointStyle(node), width: node.width / deploymentDiagram.width * 100 + '%', height: node.height / deploymentDiagram.height * 100 + '%' });
const edgeMarker = edge => 'url(#deployment-arrow' + (edge.kind === 'response' ? '-response' : flowFocused.value ? '-active' : '') + ')';

watch(flowId, () => { selectedId.value = flow.value.focus; }, { flush: 'sync' });
watch(deploymentMethod, () => { expandedConfiguration.value = []; });
onMounted(() => {
  document.addEventListener('visibilitychange', updateVisibility);
  motionPreference.addEventListener('change', updateMotionPreference);
});
onBeforeUnmount(() => {
  document.removeEventListener('visibilitychange', updateVisibility);
  motionPreference.removeEventListener('change', updateMotionPreference);
});
function selectNode(id) {
  if (!activeNodes.value.has(id)) flowId.value = 'all';
  selectedId.value = id;
}
function openClientDeploy() { terminalTab.value = 'deploy'; tab.value = 'terminals'; }
function openComponent(target) { if (target === 'terminals') openClientDeploy(); else tab.value = target; }
</script>
