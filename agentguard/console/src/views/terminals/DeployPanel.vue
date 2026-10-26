<template>
  <div class="deployment-page compact-controls" id="client-deploy">
    <div v-if="deviceData.deploy" class="deployment-layout">
      <section class="deployment-card deployment-settings" aria-labelledby="deploy-settings-title">
        <div class="deployment-card-header">
          <div class="deployment-heading"><span class="deployment-step" aria-hidden="true">1</span><h3 id="deploy-settings-title">部署配置</h3></div>
          <span class="deployment-save-state" :class="{dirty: deployDirty}">{{ deployDirty ? '未保存' : '已保存' }}</span>
        </div>

        <el-form label-position="top" size="small" class="deploy-form" :disabled="deploySaving" @submit.prevent="saveDeploy">
          <el-form-item label="服务端地址">
            <el-input v-model="deployForm.server_url" aria-label="服务端地址" :placeholder="'留空使用 ' + origin" clearable />
          </el-form-item>
          <el-form-item>
            <template #label><div class="deployment-agent-label"><span>接入的 Agent <small>已选 {{ deployForm.agents.length }} 项</small></span>
              <el-button link type="primary" size="small" @click="toggleAllAgents">{{ allAgentsSelected ? '清空' : '全选' }}</el-button></div></template>
            <el-checkbox-group v-model="deployForm.agents" class="deployment-agent-options" aria-label="接入的 Agent">
              <el-checkbox v-for="a in deviceData.agents" :key="a.agent" :value="a.agent" border>
                <AgentIcon :agent="a.agent" :size="24" /><span>{{ AGENT_NAMES[a.agent] || a.agent }}</span>
              </el-checkbox>
            </el-checkbox-group>

            <p v-if="!deployForm.agents.length" class="deployment-field-error" role="status">请至少选择一个 Agent。</p>
          </el-form-item>
          <el-form-item label="安装方式">
            <el-segmented v-model="deployForm.scope" :options="scopeOptions" class="control-segmented" aria-label="安装方式" />
          </el-form-item>
          <details class="deployment-advanced">
            <summary><span>更多安装选项</span><span class="deployment-summary-note">{{ waitText(deployForm.wait) }} · 自检{{ deployForm.self_test ? '开启' : '关闭' }}</span></summary>
            <div class="deployment-advanced-body">
              <el-form-item label="等待认证">
                <div class="deployment-wait"><el-input-number v-model="deployForm.wait" aria-label="等待认证秒数" :min="0" :max="3600" :step="60" :precision="0" controls-position="right" /><span>秒</span></div>
              </el-form-item>
              <div class="deployment-self-test"><div><label for="deployment-self-test">安装后自检</label></div>
                <el-switch id="deployment-self-test" v-model="deployForm.self_test" aria-label="安装后自检" /></div>
            </div>
          </details>
          <el-alert v-if="deployError" :title="deployError" type="error" :closable="false" show-icon class="deployment-form-error" />
          <div class="deployment-save-actions">
            <el-button type="primary" size="small" native-type="submit" :loading="deploySaving" :disabled="!deployForm.agents.length || !deployDirty">保存配置</el-button>
            <el-button size="small" :disabled="!deployDirty" @click="discardChanges">放弃修改</el-button>
            <span v-if="deploySuccess" class="deployment-saved-message" role="status">{{ deploySuccess }}</span>
          </div>
          <p class="deployment-updated">{{ deviceData.deploy.updated_at ? '更新于 ' + short(deviceData.deploy.updated_at) : '正在使用默认部署配置' }}</p>
        </el-form>
      </section>

      <div class="deployment-main">
        <section class="deployment-card deploy-commands" aria-labelledby="deploy-install-title">
          <div class="deployment-card-header"><div class="deployment-heading"><span class="deployment-step" aria-hidden="true">2</span><h3 id="deploy-install-title">安装客户端</h3></div></div>

          <el-segmented v-model="platform" :options="platformOptions" aria-label="终端操作系统" class="deployment-platforms control-segmented" />
          <div v-if="deployDirty" class="deployment-draft-note" role="status">部署配置未保存</div>
          <dl class="deployment-effective">
            <div><dt>连接地址</dt><dd class="mono">{{ effectiveUrl }}</dd></div>
            <div><dt>接入 Agent</dt><dd>{{ deployAgentsText }}</dd></div>
          </dl>
          <div class="deployment-effective-tags"><span>{{ deviceData.deploy.scope === 'machine' ? '系统级安装' : '当前用户安装' }}</span>
            <span>{{ waitText(deviceData.deploy.wait) }}</span><span>自检{{ deviceData.deploy.self_test ? '开启' : '关闭' }}</span></div>

          <el-alert v-if="!installAvailable" :title="deviceData.enroll?.enabled === false ? '自助接入已关闭' : '未发布 Windows 客户端包'"
                    type="warning" :closable="false" show-icon class="deployment-platform-note" />

          <pre class="hook-cmd deployment-install-command" tabindex="0" aria-label="一键安装命令">{{ oneClick.install }}</pre>
          <div class="deploy-actions deployment-install-actions">
            <el-button type="primary" size="small" :disabled="!installAvailable" @click="copyCommand(oneClick.install, '安装命令')"><el-icon class="btn-ic"><DocumentCopy /></el-icon>复制安装命令</el-button>
            <el-button v-if="platform === 'windows' && installAvailable" size="small" tag="a" href="/v1/agents/install.cmd"><el-icon class="btn-ic"><Download /></el-icon>下载安装脚本</el-button>
          </div>
        </section>

        <section class="deployment-approval" aria-labelledby="deploy-approval-title">
          <div class="deployment-heading"><span class="deployment-step" aria-hidden="true">3</span><h3 id="deploy-approval-title">认证设备</h3></div>

          <el-button size="small" @click="terminalTab = 'devices'">前往设备列表<span v-if="deviceData.enrollments?.length" class="deployment-pending">{{ deviceData.enrollments.length }} 台待认证</span><el-icon class="deployment-next"><ArrowRight /></el-icon></el-button>
        </section>

        <section class="deployment-card deployment-tools" aria-label="其他部署操作">
          <details class="deployment-tool">
            <summary><el-icon aria-hidden="true"><Download /></el-icon><span>手动下载安装包<small>{{ deviceData.clients?.length || 0 }} 个可用</small></span></summary>
            <div class="deployment-tool-body">

              <div v-for="client in deviceData.clients" :key="client.name" class="deployment-package">
                <div><strong>{{ packageLabel(client) }}</strong><span class="deployment-package-meta">{{ client.kind === 'script' ? '需要 ' + client.requires : '独立客户端' }} · {{ packageSize(client.size) }}{{ client.version ? ' · ' + client.version : '' }}</span>
                  <a :href="'/v1/agents/client/' + client.name" class="mono">{{ client.name }}</a></div>
                <a :href="'/v1/agents/client/' + client.name" class="deployment-package-download" :aria-label="'下载 ' + client.name"><el-icon aria-hidden="true"><Download /></el-icon>下载</a>
              </div>
              <p v-if="!deviceData.clients?.length" class="deployment-field-hint">当前服务尚未提供可下载的客户端包。</p>
            </div>
          </details>
          <details class="deployment-tool deployment-uninstall">
            <summary><el-icon aria-hidden="true"><SetUp /></el-icon><span>卸载客户端</span></summary>
            <div class="deployment-tool-body">

              <pre class="hook-cmd" tabindex="0" aria-label="一键卸载命令">{{ oneClick.uninstall }}</pre>
              <div class="deploy-actions"><el-button size="small" @click="copyCommand(oneClick.uninstall, '卸载命令')"><el-icon class="btn-ic"><DocumentCopy /></el-icon>复制卸载命令</el-button>
                <el-button v-if="platform === 'windows'" size="small" tag="a" href="/v1/agents/uninstall.cmd"><el-icon class="btn-ic"><Download /></el-icon>下载卸载脚本</el-button></div>
            </div>
          </details>
        </section>
      </div>
    </div>
    <el-empty v-else description="当前服务未提供客户端部署配置" />
  </div>
</template>

<script setup>
import { computed, reactive, ref, watch } from "vue";
import { DocumentCopy, Download } from "../../icons";
import AgentIcon from "../../components/AgentIcon.vue";
import { AGENT_NAMES, terminalTab } from "../../store/runtime";
import { deviceData, updateDeploy } from "../../store/devices";
import { short } from "./helpers";
import { useClientCommands } from "./useClientCommands";

const { platform, origin, oneClick, deployAgentsText, copyCommand } = useClientCommands();
const scopeOptions = [{ label: "当前用户", value: "user" }, { label: "系统级", value: "machine" }];
const platformOptions = [{ label: "Windows", value: "windows" }, { label: "Linux", value: "linux" }, { label: "macOS", value: "macos" }];
const deployForm = reactive({ server_url: "", agents: [], scope: "user", wait: 600, self_test: true });
const deploySaving = ref(false);
const deployError = ref("");
const deploySuccess = ref("");
const DEPLOY_KEYS = ["server_url", "agents", "scope", "wait", "self_test"];
function syncDeployForm(config) {
  DEPLOY_KEYS.forEach((key) => { deployForm[key] = Array.isArray(config[key]) ? [...config[key]] : config[key]; });
}
watch(() => deviceData.value.deploy, (config, previous) => {
  // 后台刷新与子菜单切换不覆盖尚未保存的编辑。
  const editing = previous && DEPLOY_KEYS.some((key) => JSON.stringify(deployForm[key]) !== JSON.stringify(previous[key]));
  if (config && !editing) syncDeployForm(config);
}, { immediate: true });
const deployDirty = computed(() => {
  const config = deviceData.value.deploy || {};
  return DEPLOY_KEYS.some((key) => JSON.stringify(deployForm[key] ?? "") !== JSON.stringify(config[key] ?? ""));
});
watch(deployDirty, (dirty) => { if (dirty) deploySuccess.value = ""; });
const allAgentsSelected = computed(() => deviceData.value.agents.length > 0 && deviceData.value.agents.every((item) => deployForm.agents.includes(item.agent)));
function toggleAllAgents() { deployForm.agents = allAgentsSelected.value ? [] : deviceData.value.agents.map((item) => item.agent); }
function discardChanges() { syncDeployForm(deviceData.value.deploy); deployError.value = ""; deploySuccess.value = ""; }
const effectiveUrl = computed(() => deviceData.value.deploy?.effective_url || origin);
const published = (name) => (deviceData.value.clients || []).some((client) => client.name === name);
const installAvailable = computed(() => deviceData.value.enroll?.enabled !== false && (platform.value !== "windows" || published("agentguard-endpoint-windows-x64.zip")));

const waitText = (seconds) => Number(seconds) === 0 ? "提交后不等待" : "等待认证 " + Number(seconds ?? 600) + " 秒";
const packageLabel = (client) => client.kind === "script" ? "通用脚本包" : ({"windows-x64": "Windows x64 客户端", "linux-x64": "Linux x64 客户端"}[client.platform] || client.platform + " 客户端");
const packageSize = (size) => (Number(size || 0) / 1048576).toFixed(size > 1048576 ? 1 : 2) + " MB";
async function saveDeploy() {
  if (deploySaving.value || !deployDirty.value || !deployForm.agents.length) return;
  deploySaving.value = true;
  deployError.value = "";
  deploySuccess.value = "";
  try {
    const config = await updateDeploy({ ...deployForm, agents: [...deployForm.agents], server_url: (deployForm.server_url || "").trim(), wait: Math.round(deployForm.wait || 0) });
    syncDeployForm(config);
    deploySuccess.value = "已保存，后续安装使用新配置";
  } catch (e) {
    deployError.value = e.message;
  } finally {
    deploySaving.value = false;
  }
}
</script>

<style scoped>
.deployment-page { --deployment-section-gap: 20px; min-width: 0; }
.deployment-layout { display: grid; grid-template-columns: minmax(320px, .85fr) minmax(0, 1.3fr); gap: 16px; align-items: start; }
.deployment-card { min-width: 0; padding: 18px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
.deployment-card-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: var(--deployment-section-gap); }
.deployment-heading { display: flex; align-items: center; gap: 9px; min-width: 0; }
.deployment-heading h3 { margin: 0; font-size: 14px; color: var(--title); }
.deployment-step { flex: none; width: 24px; height: 24px; border-radius: 7px; background: var(--brand-bg); color: var(--brand); font: 600 12px/24px var(--mono); text-align: center; }
.deployment-save-state { color: var(--muted); font-size: 12px; }
.deployment-save-state.dirty { color: var(--med); }
.deploy-form { min-width: 0; }
.deploy-form :deep(.el-form-item) { margin-bottom: 12px; }
.deploy-form :deep(.el-form-item__label) { display: block; width: 100%; margin-bottom: 6px; padding: 0; font-size: 12px; line-height: 20px; color: var(--text); }
.deployment-field-hint { flex-basis: 100%; margin: 6px 0 0; color: var(--muted); font-size: 12px; line-height: 1.6; }
.deployment-agent-label { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.deployment-agent-label small { margin-left: 6px; font-size: 12px; color: var(--muted); font-weight: 400; }
.deployment-agent-options { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; width: 100%; }
.deployment-agent-options :deep(.el-checkbox.is-bordered) { display: flex; align-items: center; min-width: 0; min-height: 44px; height: auto; margin: 0; padding: 7px 12px; border-radius: 7px; }
.deployment-agent-options :deep(.el-checkbox.is-bordered .el-checkbox__label) { display: inline-flex; align-items: center; gap: 8px; min-width: 0; padding-left: 8px; font-size: 14px; }
.deployment-agent-options :deep(.el-checkbox__label > span:last-child) { overflow-wrap: anywhere; white-space: normal; line-height: 1.4; }
.deployment-agent-options :deep(.is-checked) { background: var(--brand-bg); }
.deployment-agent-options :deep(.agent-icon) { padding: 2px; border-radius: 6px; }
.deployment-field-error { flex-basis: 100%; margin: 6px 0 0; color: var(--crit); font-size: 12px; line-height: 1.6; }
.deployment-advanced { border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.deployment-advanced summary { display: flex; flex-wrap: wrap; align-items: center; gap: 3px 10px; padding: 10px 0; color: var(--text); font-size: 12px; cursor: pointer; list-style: none; }
.deployment-advanced summary::before, .deployment-tool summary::after { content: '›'; color: var(--muted); font-size: 18px; line-height: 1; }
.deployment-advanced[open] summary::before, .deployment-tool[open] summary::after { transform: rotate(90deg); }
.deployment-summary-note { margin-left: auto; color: var(--muted); font-size: 12px; }
.deployment-advanced-body { padding: 0 0 12px; }
.deployment-wait { display: flex; align-items: center; gap: 8px; color: var(--muted); }
.deployment-wait .el-input-number { width: 136px; }
.deployment-self-test { display: flex; align-items: center; justify-content: space-between; gap: 16px; font-size: 12px; }
.deployment-self-test .deployment-field-hint { margin: 2px 0 0; }
.deployment-save-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 12px; }
.deployment-save-actions .el-button { margin: 0; }
.deployment-saved-message { flex-basis: 100%; color: var(--ok); font-size: 12px; }
.deployment-updated { margin: 8px 0 0; color: var(--muted); font-size: 12px; }
.deployment-form-error { margin-top: 14px; }
.deployment-main { display: flex; flex-direction: column; gap: 16px; min-width: 0; }
.deployment-platforms { margin-bottom: 14px; }
.deployment-draft-note { margin-bottom: 12px; padding: 8px 10px; border-radius: 7px; background: var(--med-bg); color: var(--med); font-size: 12px; }
.deployment-effective { display: flex; flex-direction: column; gap: 8px; margin: 0; padding: 12px 14px; border-radius: 8px; background: var(--bg); }
.deployment-effective > div { display: grid; grid-template-columns: 64px minmax(0, 1fr); gap: 10px; font-size: 12px; }
.deployment-effective dt { color: var(--muted); }
.deployment-effective dd { margin: 0; overflow-wrap: anywhere; }
.deployment-effective-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.deployment-effective-tags span { padding: 2px 7px; border: 1px solid var(--line); border-radius: 5px; color: var(--muted); font-size: 12px; }
.deployment-platform-note { margin-top: 12px; }
.deployment-install-command { margin-bottom: 10px; background: var(--brand-bg); border-color: var(--line); padding: 14px; }
.hook-cmd { overflow-wrap: anywhere; word-break: normal; }
.hook-cmd:focus-visible, summary:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; border-radius: 6px; }
.deployment-approval { padding: 16px 18px; border: 1px solid var(--line); border-radius: 10px; background: var(--brand-bg); }
.deployment-approval > .deployment-heading { margin-bottom: var(--deployment-section-gap); }
.deployment-approval p { margin: 8px 0 12px; color: var(--muted); font-size: 12px; }
.deployment-approval .deployment-step { background: var(--panel); }
.deployment-pending { margin-left: 8px; font-size: 12px; color: var(--med); }
.deployment-next { margin-left: 8px; }
.deployment-tools { padding: 0 18px; }
.deployment-tool + .deployment-tool { border-top: 1px solid var(--line); }
.deployment-tool summary { display: flex; align-items: center; gap: 8px; padding: 14px 0; cursor: pointer; list-style: none; }
.deployment-tool summary::after { margin-left: auto; flex: none; }
.deployment-tool summary > .el-icon { color: var(--muted); font-size: 15px; }
.deployment-tool summary > span { min-width: 0; font-size: 12px; }
.deployment-tool summary small { margin-left: 8px; color: var(--muted); font-size: 12px; }
summary::-webkit-details-marker { display: none; }
.deployment-tool-body { padding-bottom: 16px; }
.deployment-tool-body > .deployment-field-hint:first-child { margin-top: 0; }
.deployment-package { display: flex; align-items: center; gap: 14px; padding: 12px 0; border-bottom: 1px solid var(--line-2); }
.deployment-package:last-child { border-bottom: 0; padding-bottom: 0; }
.deployment-package > div { flex: 1; min-width: 0; }
.deployment-package strong { display: block; color: var(--title); font-size: 12px; font-weight: 500; }
.deployment-package-meta, .deployment-package .mono { display: block; margin-top: 3px; font-size: 12px; overflow-wrap: anywhere; }
.deployment-package-meta { color: var(--muted); }
.deployment-package a { color: var(--brand); text-decoration: none; }
.deployment-package a:hover { text-decoration: underline; }
.deployment-package-download { display: inline-flex; align-items: center; gap: 4px; flex: none; min-height: 28px; font-size: 12px; }
@media (max-width: 1100px) { .deployment-layout { grid-template-columns: minmax(0, 1fr); } }
@media (max-width: 600px) {
  .deployment-card { padding: 14px 12px; }
  .deployment-layout, .deployment-main { gap: 12px; }
  .deployment-agent-options { gap: 6px; }
  .deployment-agent-options :deep(.el-checkbox.is-bordered) { padding: 0 7px; min-height: 44px; height: auto; }
  .deployment-agent-options :deep(.el-checkbox__label) { gap: 4px; padding-left: 5px; }
  .deployment-agent-options :deep(.agent-icon) { width: 20px !important; height: 20px !important; }
  .deployment-summary-note { flex-basis: 100%; margin-left: 16px; }
  .deployment-effective { padding: 10px; }
  .deployment-effective > div { grid-template-columns: minmax(0, 1fr); gap: 2px; }
  .deployment-platforms { display: flex; }
  .deployment-approval { padding: 14px 12px; }
  .deployment-tools { padding: 0 12px; }
  .deployment-tool summary small { display: block; margin: 2px 0 0; }
}
</style>
