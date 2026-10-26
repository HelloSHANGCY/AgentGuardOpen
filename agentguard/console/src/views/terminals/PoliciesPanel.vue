<template>
  <div v-if="selected" class="policy-workspace compact-controls">
    <aside class="policy-picker" aria-label="Agent 选择">
      <div class="policy-picker-heading"><h3>Agent</h3><span>{{ deviceData.agents.length }} 种</span></div>
      <div class="policy-agent-list" role="group" aria-label="选择 Agent">
        <button v-for="agent in deviceData.agents" :key="agent.agent" type="button" class="policy-agent"
                :class="{selected: selected.agent === agent.agent}" :aria-pressed="selected.agent === agent.agent"
                :aria-label="'选择 ' + agentName(agent)" @click="selectedId = agent.agent">
          <AgentIcon :agent="agent.agent" :size="36" />
          <span class="policy-agent-copy">
            <span class="policy-agent-name">{{ agentName(agent) }}</span>
            <span class="policy-agent-meta">{{ agent.devices || 0 }} 台设备 · {{ statusOf(agent).label }}</span>
          </span>
          <span class="policy-status-dot" :class="statusOf(agent).kind" aria-hidden="true"></span>
        </button>
      </div>
    </aside>

    <article class="policy-detail" :aria-label="agentName(selected) + ' 防护策略'">
      <header class="policy-detail-header">
        <div class="policy-identity">
          <AgentIcon :agent="selected.agent" :size="48" />
          <div>
            <div class="policy-title-line">
              <h3>{{ agentName(selected) }}</h3>
              <el-tag size="small" :type="statusOf(selected).tag" effect="light">{{ statusOf(selected).label }}</el-tag>
            </div>
            <p class="policy-agent-meta">{{ selected.devices || 0 }} 台设备 · 最近上报 {{ selected.last_seen ? short(selected.last_seen) : '暂无上报' }}</p>
          </div>
        </div>
        <div class="policy-enable">
          <span>启用检测</span>
          <el-switch :model-value="selected.enabled" :loading="busy === selected.agent + ':enabled'" :disabled="!!busy"
                     :aria-label="'默认启用 ' + agentName(selected)" @change="(v) => changeDefault(selected, {enabled: v})" />
        </div>
      </header>

      <el-alert v-if="!selected.enabled" class="policy-mode-note" title="检测已停止"
                type="info" show-icon :closable="false" />
      <el-alert v-else-if="selected.enforce === false" class="policy-mode-note"
                title="当前为观察模式"
                type="warning" show-icon :closable="false" />

      <div class="policy-settings-grid">
        <section class="policy-section" aria-label="防护能力">
          <div class="policy-section-heading"><el-icon aria-hidden="true"><CircleCheck /></el-icon><h4>防护能力</h4></div>
          <div v-for="control in protectionControls" :key="control.key" class="policy-toggle-row">
            <div class="policy-control-copy">
              <div class="policy-control-title">
                <span>{{ control.label }}</span>
                <el-tooltip :content="itemOf(control.key).hint" :trigger="['hover', 'focus']" placement="top" :show-after="150"
                            :popper-style="{maxWidth: 'min(360px, calc(100vw - 24px))', boxSizing: 'border-box'}">
                  <button type="button" class="policy-help" :aria-label="control.label + '说明'">
                    <el-icon aria-hidden="true"><QuestionFilled /></el-icon>
                  </button>
                </el-tooltip>
              </div>

              <span v-if="control.key !== 'enforce' && selected.enforce === false" class="policy-inactive-note">观察模式下不生效</span>
            </div>
            <el-switch :model-value="selected[control.key] !== false" :loading="busy === selected.agent + ':' + control.key" :disabled="!!busy"
                       :aria-label="control.aria + agentName(selected)" @change="(v) => changeDefault(selected, {[control.key]: v})" />
          </div>
        </section>

        <section class="policy-section" aria-label="降级与上传">
          <div class="policy-section-heading"><el-icon aria-hidden="true"><Connection /></el-icon><h4>降级与上传</h4></div>
          <div class="policy-choice-row">
            <div class="policy-control-title"><span>服务不可达时</span></div>
            <el-segmented :model-value="controlValue('fail_mode')" :options="failModeOptions" class="control-segmented" :disabled="!!busy"
                          :aria-label="'默认服务不可达处理：' + agentName(selected)" @change="(v) => changeDefault(selected, {fail_mode: v})" />
          </div>
          <div class="policy-choice-row">
            <div class="policy-control-title"><span>工具返回上传</span></div>
            <el-segmented :model-value="controlValue('upload_mode')" :options="uploadModeOptions" class="control-segmented" :disabled="!!busy"
                          :aria-label="'默认工具返回上传方式：' + agentName(selected)" @change="(v) => changeDefault(selected, {upload_mode: v})" />
          </div>
        </section>
      </div>

      <section class="policy-timeouts" aria-label="超时参数">
        <div class="policy-section-heading"><el-icon aria-hidden="true"><Timer /></el-icon><h4>超时参数</h4></div>
        <div class="policy-timeout-grid">
          <div v-for="key in TIMEOUT_KEYS" :key="key" class="policy-timeout-field">
            <div class="policy-control-copy"><span>{{ itemOf(key).label }}</span></div>
            <div class="policy-timeout-input">
              <el-input-number size="small" :model-value="controlValue(key)" :min="0.3" :max="10" :step="0.5" :precision="1"
                               controls-position="right" :disabled="!!busy" :aria-label="itemOf(key).label + '：' + agentName(selected)"
                               @change="(v) => v != null && v !== selected[key] && changeDefault(selected, {[key]: v})" />
              <span>秒</span>
            </div>
          </div>
        </div>
      </section>

      <footer class="policy-detail-footer">
        <span v-if="busy || lastSaved === selected.agent" role="status" aria-live="polite"><el-icon aria-hidden="true"><CircleCheck /></el-icon>{{ busy ? '正在保存配置…' : '已保存' }}</span>
        <span v-if="selected.updated_at">更新于 {{ short(selected.updated_at) }}</span>
      </footer>
    </article>
  </div>
  <el-empty v-else description="暂无可配置的 Agent" />
</template>

<script setup>
import { computed, ref } from "vue";
import { CircleCheck, Connection, QuestionFilled, Timer } from "../../icons";
import { AGENT_NAMES } from "../../store/runtime";
import { deviceData, FAIL_MODE_TEXT, UPLOAD_MODE_TEXT, TIMEOUT_KEYS, updateDefaults } from "../../store/devices";
import AgentIcon from "../../components/AgentIcon.vue";
import { itemOf, short } from "./helpers";

const selectedId = ref("");
const selected = computed(() => deviceData.value.agents.find((agent) => agent.agent === selectedId.value) || deviceData.value.agents[0]);
const agentName = (agent) => AGENT_NAMES[agent.agent] || agent.agent;
const statusOf = (agent) => !agent.enabled ? {label: "已停止", kind: "off", tag: "info"}
  : agent.enforce === false ? {label: "仅观察", kind: "observe", tag: "warning"}
    : {label: "拦截模式", kind: "enforce", tag: "success"};
const protectionControls = [
  {key: "enforce", label: "行为拦截", aria: "默认拦截："},
  {key: "local_rules", label: "本地快速判定", aria: "默认本地快速判定："},
  {key: "result_guard", label: "返回内容拦截", aria: "默认返回内容拦截："},
];
const failModeOptions = computed(() => deviceData.value.fail_modes.map((value) => ({ label: FAIL_MODE_TEXT[value]?.label || value, value })));
const uploadModeOptions = Object.entries(UPLOAD_MODE_TEXT).map(([value, item]) => ({ label: item.label, value }));
const busy = ref("");
const lastSaved = ref("");
const pendingChange = ref(null);
const controlValue = (key) => pendingChange.value && pendingChange.value.agent === selected.value?.agent && key in pendingChange.value.values
  ? pendingChange.value.values[key] : selected.value?.[key];

async function changeDefault(agent, changes) {
  if (busy.value) return;
  lastSaved.value = "";
  pendingChange.value = { agent: agent.agent, values: changes };
  busy.value = agent.agent + ":" + Object.keys(changes)[0];
  try {
    if (await updateDefaults(agent.agent, changes)) lastSaved.value = agent.agent;
  } finally { pendingChange.value = null; busy.value = ""; }
}
</script>

<style scoped>
.policy-workspace { display: grid; grid-template-columns: 224px minmax(0, 1fr); gap: 18px; margin-top: 18px; align-items: start; }
.policy-picker { position: sticky; top: 20px; padding: 12px 8px; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
.policy-picker-heading { display: flex; justify-content: space-between; align-items: center; padding: 2px 10px 12px; }
.policy-picker-heading h3 { margin: 0; font-size: 13px; color: var(--title); }
.policy-picker-heading > span { font-size: 12px; color: var(--muted); }
.policy-agent-list { display: flex; flex-direction: column; gap: 5px; }
.policy-agent { display: flex; align-items: center; gap: 10px; width: 100%; padding: 11px 10px; border: 1px solid transparent; border-radius: 8px;
                background: transparent; color: var(--text); font: inherit; text-align: left; cursor: pointer; transition: background var(--motion-fast), border-color var(--motion-fast); }
.policy-agent:hover { background: var(--bg); }
.policy-agent.selected { background: var(--brand-bg); border-color: var(--brand); }
.policy-agent:focus-visible, .policy-help:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
.policy-agent-copy { flex: 1; min-width: 0; }
.policy-agent-name { display: block; font-size: 13px; font-weight: 600; color: var(--title); }
.policy-agent-meta { display: block; margin: 4px 0 0; font-size: 12px; color: var(--muted); line-height: 1.6; }
.policy-status-dot { flex: none; width: 6px; height: 6px; border-radius: 50%; background: var(--faint); }
.policy-status-dot.enforce { background: var(--ok); }
.policy-status-dot.observe { background: var(--med); }
.policy-detail { min-width: 0; padding: 18px; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
.policy-detail-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding-bottom: 16px; }
.policy-identity { display: flex; align-items: center; gap: 12px; min-width: 0; }
.policy-title-line { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.policy-title-line h3 { margin: 0; color: var(--title); font-size: 18px; font-weight: 600; }
.policy-enable { display: flex; flex: none; align-items: center; gap: 10px; font-size: 12px; color: var(--text); }
.policy-mode-note { margin-bottom: 18px; }
.policy-settings-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 18px; }
.policy-section { min-width: 0; }
.policy-section-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 7px; color: var(--brand); margin-bottom: 4px; }
.policy-section-heading h4 { margin: 0; font-size: 13px; font-weight: 600; color: var(--title); }
.policy-section-heading > span { margin-left: auto; font-size: 12px; color: var(--muted); }
.policy-toggle-row { display: flex; justify-content: space-between; align-items: center; gap: 14px; padding: 10px 0; border-bottom: 1px solid var(--line-2); }
.policy-toggle-row:last-child { border-bottom: 0; }
.policy-control-copy { min-width: 0; }
.policy-control-title { display: flex; align-items: center; gap: 6px; color: var(--text); font-size: 13px; font-weight: 500; }
.policy-help { display: inline-flex; align-items: center; justify-content: center; min-width: 24px; min-height: 24px; padding: 0; border: 0;
               background: transparent; color: var(--muted); cursor: help; border-radius: 4px; }
.policy-help:hover { color: var(--brand); background: var(--brand-bg); }
.policy-control-copy p { margin: 5px 0 0; color: var(--muted); font-size: 12px; line-height: 1.7; }
.policy-inactive-note { display: inline-block; margin-top: 5px; color: var(--med); font-size: 12px; }
.policy-choice-row { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px; padding:10px 0; }
.policy-choice-row + .policy-choice-row { border-top: 1px solid var(--line-2); }
.policy-enable .el-switch, .policy-toggle-row .el-switch { flex:none; }
.policy-timeouts { border-top: 1px solid var(--line); margin-top: 16px; padding-top: 14px; }
.policy-timeout-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 18px; margin-top: 12px; }
.policy-timeout-field { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; }
.policy-timeout-input { display: flex; align-items: center; gap: 7px; font-size: 12px; color: var(--muted); }
.policy-timeout-input .el-input-number { width: 100px; }
.policy-detail-footer { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 6px 16px; border-top: 1px solid var(--line-2);
                        margin-top: 16px; padding-top: 12px; color: var(--muted); font-size: 12px; }
.policy-detail-footer > span:first-child { display: flex; align-items: center; gap: 5px; }
.policy-detail-footer .el-icon { color: var(--ok); }
@media (max-width: 1180px) { .policy-settings-grid, .policy-timeout-grid { grid-template-columns: minmax(0, 1fr); gap: 16px; } }
@media (max-width: 1000px) {
  .policy-workspace { grid-template-columns: minmax(0, 1fr); gap: 14px; }
  .policy-picker { position: static; min-width: 0; padding: 10px; }
  .policy-picker-heading { padding: 0 2px 10px; }
  .policy-agent-list { flex-direction: row; overflow-x: auto; padding: 2px; scroll-snap-type: x proximity; }
  .policy-agent { flex: 0 0 188px; scroll-snap-align: start; }
}
@media (max-width: 600px) {
  .policy-detail { padding: 16px; }
  .policy-detail-header { align-items: flex-start; flex-wrap: wrap; gap: 12px; }
  .policy-enable { width: 100%; justify-content: space-between; border-top: 1px solid var(--line-2); padding-top: 10px; }
  .policy-title-line h3 { font-size: 16px; }
  .policy-section-heading > span { margin-left: 0; }
}
</style>
