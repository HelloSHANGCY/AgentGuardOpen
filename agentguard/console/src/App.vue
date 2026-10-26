<template>
  <div class="layout" :class="{'side-collapsed': sideCollapsed}">
    <aside class="side">
      <div class="brand">
        <div class="brand-mark"><ShieldCheck aria-hidden="true" /></div>
        <div>
          <div class="name">AgentGuard</div>
          <div class="sub">运行时防护控制台</div>
        </div>
      </div>
      <nav aria-label="主导航">
        <template v-for="n in navItems" :key="n.key">
          <div v-if="n.children" class="nav-group">
            <button type="button" :class="{active: tab === n.key}" :title="n.label" :aria-label="n.label"
                    :aria-expanded="terminalOpen" aria-controls="terminal-menu" @click="terminalOpen = !terminalOpen">
              <el-icon aria-hidden="true"><component :is="n.icon" /></el-icon><span class="lbl">{{ n.label }}</span>
              <span class="badge" v-if="n.badge()">{{ n.badge() }}</span>
              <el-icon class="nav-chevron" :class="{expanded: terminalOpen}" aria-hidden="true"><ArrowRight /></el-icon>
            </button>
            <el-collapse-transition>
            <div v-show="terminalOpen" id="terminal-menu" class="nav-submenu" role="group" :aria-label="n.label">
              <button v-for="child in n.children" :key="child.key" type="button"
                      :class="{active: tab === n.key && terminalTab === child.key}"
                      :aria-current="tab === n.key && terminalTab === child.key ? 'page' : undefined"
                      :title="child.label" :aria-label="child.label" @click="openTerminal(child.key)">
                <el-icon aria-hidden="true"><component :is="child.icon" /></el-icon><span class="lbl">{{ child.label }}</span>
                <span class="badge" v-if="child.key === 'devices' && n.badge()">{{ n.badge() }}</span>
              </button>
            </div>
            </el-collapse-transition>
          </div>
          <button v-else type="button" :class="{active: navActive(n.key)}"
                  :aria-current="tab === n.key ? 'page' : navActive(n.key) ? 'true' : undefined" :title="n.label" :aria-label="n.label" @click="openNav(n.key)">
            <el-icon aria-hidden="true"><component :is="n.icon" /></el-icon><span class="lbl">{{ n.label }}</span>
            <span class="badge" v-if="n.badge()">{{ n.badge() }}</span>
          </button>
        </template>
      </nav>
      <div class="side-foot">
        <div class="row" :title="sseOn ? 'SSE 实时推送已连接' : 'SSE 未连接，每 5 秒轮询'">
          <span class="dot" :class="{on: sseOn}"></span><span class="lbl">{{ sseOn ? '实时推送中' : '轮询模式' }}</span>
        </div>
        <dl class="side-stats" aria-label="运行决策统计">
          <div><dt>拦截</dt><dd class="c-crit">{{ stats.denied }}</dd></div>
          <div><dt>待确认</dt><dd class="c-med">{{ stats.asked }}</dd></div>
          <div><dt>放行</dt><dd class="c-ok">{{ stats.allowed }}</dd></div>
        </dl>
        <div class="side-version mono">{{ policies.rules_version || '' }}</div>
        <button type="button" class="side-toggle" :aria-label="sideCollapsed ? '展开侧栏' : '收起侧栏'" :aria-expanded="!sideCollapsed" @click="sideCollapsed = !sideCollapsed">
          <el-icon aria-hidden="true"><Expand v-if="sideCollapsed" /><Fold v-else /></el-icon><span class="lbl">收起侧栏</span>
        </button>
      </div>
    </aside>

    <main v-console-motion="tab === 'terminals' ? `${tab}/${terminalTab}` : tab" class="main">
      <el-alert v-if="runtimeError" :title="runtimeError" type="error" show-icon class="global-error"
                @close="runtimeError = ''"></el-alert>
      <ThreatView />
      <EventsView />
      <ChainView />
      <MetricsView />
      <DeploymentView />
      <RulesView />
      <StaticView />
      <TerminalsView />
      <BaselineView />
      <JudgeView />
      <ModelConfigView />
    </main>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from "vue";
import { tab, terminalTab, TERMINAL_PAGES, sseOn, stats, policies, runtimeError, startRuntime, returnToAudit } from "./store/runtime";
import { Download, Expand, Fold } from "./icons";
import { staticStats } from "./store/static";
import { deviceData, startDevicePolling } from "./store/devices";
import { proposalPending, startProposalPolling } from "./store/judge";
import vConsoleMotion from "./directives/consoleMotion";
import ThreatView from "./views/ThreatView.vue";
import EventsView from "./views/EventsView.vue";
import ChainView from "./views/ChainView.vue";
import MetricsView from "./views/MetricsView.vue";
import DeploymentView from "./views/DeploymentView.vue";
import RulesView from "./views/RulesView.vue";
import StaticView from "./views/StaticView.vue";
import TerminalsView from "./views/TerminalsView.vue";
import BaselineView from "./views/BaselineView.vue";
import JudgeView from "./views/JudgeView.vue";
import ModelConfigView from "./views/ModelConfigView.vue";

const navItems = [
  { key: "threat", label: "威胁中心", icon: "Radar", badge: () => stats.value.denied },
  { key: "events", label: "运行审计", icon: "Activity", badge: () => 0 },
  { key: "metrics", label: "评测与指标", icon: "Gauge", badge: () => 0 },
  { key: "deployment", label: "部署架构", icon: "Connection", badge: () => 0 },
  { key: "rules", label: "规则库", icon: "Library", badge: () => 0 },
  { key: "static", label: "静态资产", icon: "Database", badge: () => staticStats.value.critical },
  { key: "terminals", label: "终端管控", icon: "Monitor", badge: () => deviceData.value.enrollments?.length || 0,
    children: TERMINAL_PAGES.map((page) => ({ ...page, icon: page.key === "deploy" ? Download : page.icon })) },
  { key: "baseline", label: "行为基线", icon: "TrendCharts", badge: () => 0 },
  { key: "judge", label: "大模型研判", icon: "Brain", badge: () => proposalPending.value },
  { key: "models", label: "模型管理", icon: "Boxes", badge: () => 0 },
];

const navActive = key => tab.value === key || (key === "events" && tab.value === "chain");
function openNav(key) {
  if (key === "events" && tab.value === "chain") returnToAudit();
  else tab.value = key;
}

let savedSidebar = false;
try { savedSidebar = localStorage.getItem('agentguard.sidebar.collapsed') === 'true'; } catch { /* 无法使用本地存储时使用默认布局。 */ }
const sideCollapsed = ref(savedSidebar);
watch(sideCollapsed, value => { try { localStorage.setItem('agentguard.sidebar.collapsed', String(value)); } catch { /* 界面偏好不影响导航。 */ } });
const terminalOpen = ref(false);
watch(tab, (page) => { if (page === "terminals") terminalOpen.value = true; }, { immediate: true });
function openTerminal(page) {
  terminalTab.value = page;
  tab.value = "terminals";
}

onMounted(() => { startRuntime(); startDevicePolling(); startProposalPolling(); });
</script>
