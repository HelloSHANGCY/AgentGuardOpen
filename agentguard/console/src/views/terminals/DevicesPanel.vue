<template>
  <div class="devices-page">
    <section v-if="deviceData.enrollments?.length" class="device-enrollments"><EnrollmentsPanel /></section>

    <section class="device-inventory" aria-label="已接入设备">
      <div class="inventory-header">
        <h3><el-icon aria-hidden="true"><Monitor /></el-icon>已接入设备 <span class="inventory-count">{{ devices.length }}</span></h3>
        <el-button size="small" type="primary" @click="openRegister"><el-icon class="btn-ic"><Plus /></el-icon>接入新设备</el-button>
      </div>
      <div class="inventory-toolbar">
        <div class="device-search-filters">
          <el-input v-model="search" clearable size="small" aria-label="搜索设备" placeholder="设备、用户、IP 或 MAC">
            <template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template>
          </el-input>
          <el-select v-model="agentFilter" clearable size="small" aria-label="筛选 Agent" placeholder="全部 Agent">
            <el-option v-for="agent in agentOptions" :key="agent" :value="agent" :label="AGENT_NAMES[agent] || agent" />
          </el-select>
        </div>
        <div class="device-status-filters" role="group" aria-label="设备上报状态">
          <button v-for="item in statusOptions" :key="item.key" type="button" :aria-pressed="statusFilter === item.key"
                  :class="{selected: statusFilter === item.key}" @click="statusFilter = item.key">
            {{ item.label }} <span>{{ item.count }}</span>
          </button>
        </div>
        <div class="device-view-switch" role="group" aria-label="设备显示方式">
          <button type="button" :aria-pressed="viewMode === 'cards'" :class="{selected: viewMode === 'cards'}" @click="viewMode = 'cards'">
            <el-icon aria-hidden="true"><Grid /></el-icon>卡片视图
          </button>
          <button type="button" :aria-pressed="viewMode === 'table'" :class="{selected: viewMode === 'table'}" @click="viewMode = 'table'">
            <el-icon aria-hidden="true"><Tickets /></el-icon>表格视图
          </button>
        </div>
      </div>

      <el-table v-if="viewMode === 'table'" :data="pagedDevices" row-key="device_id" stripe class="device-table" :empty-text="emptyText">
        <el-table-column label="设备 / 系统" min-width="210">
          <template #default="{row}">
            <button type="button" class="device-name device-name-link" :title="row.host?.hostname || row.device_id" :aria-label="'查看设备：' + row.device_id" @click="openDetails(row)">{{ row.host?.hostname || row.device_id }}</button>
            <div v-if="row.host?.hostname && row.host.hostname !== row.device_id" class="device-secondary mono">{{ row.device_id }}</div>
            <div class="device-secondary">{{ row.host?.os || '系统未上报' }}{{ row.host?.user ? ' · ' + row.host.user : '' }}</div>
            <el-tag v-if="row.purpose === 'evaluation'" size="small" type="info" effect="plain">评测</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="终端 IP" min-width="170">
          <template #default="{row}"><DeviceNetwork :host="row.host" :remote-ip="row.remote_ip" :name="row.device_id" /></template>
        </el-table-column>
        <el-table-column label="Agent" min-width="185">
          <template #default="{row}"><DeviceAgents :agents="row.agents" :name="row.device_id" @details="openDetails(row)" /></template>
        </el-table-column>
        <el-table-column label="策略 / 管控" min-width="150">
          <template #default="{row}">
            <div class="device-policy"><span>{{ row.profile }}</span><span class="device-mode" :class="modeOf(row).tone">{{ modeOf(row).label }}</span></div>
            <div class="device-secondary" :class="{'c-brand': overrideCount(row)}">{{ overrideCount(row) ? overrideCount(row) + ' 项设备覆盖' : '跟随全局默认' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="最近联系" min-width="135">
          <template #default="{row}">
            <div class="device-contact" :class="contactOf(row).tone">{{ contactOf(row).label }}</div>
            <div class="device-secondary" :title="row.uninstalled_at || row.last_seen">{{ row.uninstalled_at ? short(row.uninstalled_at) : row.last_seen ? short(row.last_seen) : '等待首次上报' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="142" fixed="right">
          <template #default="{row}"><DeviceActions :device="row" @details="openDetails(row)" @configure="openConfig(row)" /></template>
        </el-table-column>
      </el-table>

      <div v-else class="device-card-view" aria-label="设备卡片列表">
        <div v-if="pagedDevices.length" class="device-card-grid">
          <article v-for="row in pagedDevices" :key="row.device_id" class="device-card" :class="{'is-uninstalled': row.uninstalled_at}" :data-device-id="row.device_id">
            <div class="device-card-heading">
              <div class="device-card-icon"><el-icon aria-hidden="true"><Monitor /></el-icon></div>
              <div class="device-card-identity">
                <button type="button" class="device-name device-name-link" :title="row.host?.hostname || row.device_id" :aria-label="'查看设备：' + row.device_id" @click="openDetails(row)">{{ row.host?.hostname || row.device_id }}</button>
                <div class="device-card-status"><span class="device-contact" :class="contactOf(row).tone">{{ contactOf(row).label }}</span>
                  <el-tag v-if="row.purpose === 'evaluation'" size="small" type="info" effect="plain">评测</el-tag></div>
              </div>
              <el-tag class="device-profile-tag" :type="row.profile === 'strict' ? 'danger' : 'info'" size="small" effect="plain">{{ row.profile }}</el-tag>
            </div>
            <div v-if="row.host?.hostname && row.host.hostname !== row.device_id" class="device-card-id device-secondary mono">{{ row.device_id }}</div>
            <dl class="device-card-facts">
              <div class="device-card-system"><dt>操作系统</dt><dd>{{ row.host?.os || '未上报' }}</dd></div>
              <div><dt>终端 IP</dt><dd><DeviceNetwork :host="row.host" :remote-ip="row.remote_ip" :name="row.device_id" /></dd></div>
              <div><dt>登录用户</dt><dd>{{ row.host?.user || '未上报' }}</dd></div>
              <div class="device-card-client"><dt>客户端</dt><dd class="mono">{{ row.client || '未上报' }}</dd></div>
            </dl>
            <div class="device-card-agents"><span class="device-field-label">Agent <span class="mono">{{ row.agents?.length || 0 }}</span></span>
              <DeviceAgents :agents="row.agents" :name="row.device_id" @details="openDetails(row)" /></div>
            <div class="device-card-control"><span class="device-mode" :class="modeOf(row).tone">{{ modeOf(row).label }}</span>
              <span class="device-secondary">{{ overrideCount(row) ? overrideCount(row) + ' 项设备覆盖' : '跟随全局默认' }}</span></div>
            <div class="device-card-footer"><span class="device-secondary" :title="row.uninstalled_at || row.last_seen || ''">{{ row.uninstalled_at ? '卸载于 ' + short(row.uninstalled_at) : row.last_seen ? '最近联系 ' + short(row.last_seen) : '等待首次上报' }}</span>
              <DeviceActions :device="row" @details="openDetails(row)" @configure="openConfig(row)" /></div>
          </article>
        </div>
        <el-empty v-else :description="emptyText" :image-size="64" class="device-card-empty" />
      </div>
      <div v-if="devices.length" class="inventory-footer">
        <span class="device-secondary" role="status">{{ hasFilters ? '匹配 ' + filteredDevices.length + ' / ' : '共 ' }}{{ devices.length }} 台设备</span>
        <el-button v-if="hasFilters" link size="small" @click="clearFilters">清除筛选</el-button>
        <el-pagination v-if="filteredDevices.length > pageSize" v-model:current-page="page" :page-size="pageSize"
                       :total="filteredDevices.length" :pager-count="5" layout="prev, pager, next" size="small" />
      </div>
    </section>

    <el-drawer v-model="detailsOpen" title="设备详情" size="min(760px, 100vw)" class="device-details-drawer">
      <template v-if="selectedDevice">
        <div class="device-detail-heading"><div><h3>{{ selectedDevice.host?.hostname || selectedDevice.device_id }}</h3>
          <div class="mono device-secondary">{{ selectedDevice.device_id }}</div></div>
          <el-tag :type="selectedDevice.uninstalled_at ? 'info' : selectedDevice.last_seen ? 'success' : 'warning'" effect="light">{{ contactOf(selectedDevice).label }}</el-tag></div>
        <dl class="device-facts">
          <div><dt>操作系统</dt><dd>{{ selectedDevice.host?.os || '未上报' }}</dd></div>
          <div><dt>登录用户</dt><dd>{{ selectedDevice.host?.user || '未上报' }}</dd></div>
          <div><dt>归属用户</dt><dd>{{ selectedDevice.actor?.sub || '—' }}</dd></div>
          <div><dt>策略档案</dt><dd>{{ selectedDevice.profile }}</dd></div>
          <div><dt>终端 IP</dt><dd class="mono">{{ selectedDevice.host?.ip || '未上报' }}</dd></div>
          <div><dt>网卡 MAC</dt><dd class="mono">{{ selectedDevice.host?.mac || '未上报' }}</dd></div>
          <div><dt>连接来源</dt><dd class="mono">{{ selectedDevice.remote_ip || '未记录' }}</dd></div>
          <div><dt>客户端</dt><dd class="mono">{{ selectedDevice.client || '未上报' }}</dd></div>
          <div><dt>扫描通道</dt><dd><el-tag size="small" :type="scanChannelState(selectedDevice).type">{{ scanChannelState(selectedDevice).label }}</el-tag></dd></div>
          <div><dt>接入时间</dt><dd>{{ selectedDevice.created_at ? short(selectedDevice.created_at) : '—' }}</dd></div>
          <div><dt>最近联系</dt><dd>{{ selectedDevice.last_seen ? short(selectedDevice.last_seen) : '尚未上报' }}</dd></div>
          <div v-if="selectedDevice.uninstalled_at"><dt>卸载时间</dt><dd>{{ short(selectedDevice.uninstalled_at) }}</dd></div>
        </dl>

        <h4 class="device-detail-section">各 Agent 管控</h4>

        <section v-for="agent in selectedDevice.agents" :key="agent" class="device-agent-detail">
          <div class="device-agent-detail-header"><AgentIcon :agent="agent" :size="30" />
            <div><strong>{{ AGENT_NAMES[agent] || agent }}</strong>
              <div class="device-secondary">{{ selectedDevice.seen_agents?.[agent] ? '最近上报 ' + short(selectedDevice.seen_agents[agent]) : '尚未收到该 Agent 的 Hook 事件' }}</div></div>
            <el-button v-if="!selectedDevice.uninstalled_at && selectedDevice.purpose !== 'evaluation'" size="small" plain @click="scanAgent(selectedDevice, agent)">扫描资产</el-button>
          </div>
          <div class="device-control-details">
            <div v-for="item in controlDetails(selectedDevice, agent)" :key="item.key" :class="{overridden: item.overridden}">
              <span>{{ item.label }}</span><strong>{{ item.text }}</strong>
              <small>{{ item.overridden ? '设备覆盖 · 默认 ' + item.fallback : '跟随全局默认' }}</small>
            </div>
          </div>
        </section>
      </template>
      <el-empty v-else description="设备记录已移除" />
      <template #footer><el-button @click="detailsOpen = false">关闭</el-button>
        <el-button v-if="selectedDevice && !selectedDevice.uninstalled_at" type="primary" @click="configureSelected">配置设备</el-button></template>
    </el-drawer>

    <!-- 设备配置：策略档案、允许的 Agent、管控覆盖 -->
    <el-dialog v-model="configOpen" :title="'配置设备 ' + (editing?.device_id || '')" width="600px" class="detail-dialog device-config-dialog">
      <el-form v-if="editing" label-width="110px" size="small" class="device-config-form compact-controls" :disabled="saving" @submit.prevent>
        <el-form-item label="策略档案">
          <el-segmented v-model="edit.profile" :options="deviceData.profiles" class="device-config-options control-segmented" aria-label="策略档案" />
        </el-form-item>
        <el-form-item label="允许的 Agent">
          <el-checkbox-group v-model="edit.agents" class="device-config-agents" aria-label="允许的 Agent">
            <el-checkbox v-for="a in deviceData.agents" :key="a.agent" :value="a.agent">{{ AGENT_NAMES[a.agent] || a.agent }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item v-for="item in CONTROL_ITEMS" :key="item.key" :label="item.label">
          <div v-if="TIMEOUT_KEYS.includes(item.key)" class="device-timeout-controls">
            <el-segmented :model-value="edit.overrides[item.key] === FOLLOW ? FOLLOW : 'custom'"
                          :options="controlOptions(item)" class="device-config-options control-segmented" :aria-label="item.label"
                          @change="(v) => { edit.overrides[item.key] = v === FOLLOW ? FOLLOW : defaultNumber(item.key); }" />
            <template v-if="edit.overrides[item.key] !== FOLLOW">
              <el-input-number v-model="edit.overrides[item.key]" class="timeout-input" :aria-label="item.label + '秒数'"
                               :min="0.3" :max="10" :step="0.5" :precision="1" controls-position="right" />
              <span>秒</span>
            </template>
          </div>
          <el-segmented v-else v-model="edit.overrides[item.key]" :options="controlOptions(item)"
                        class="device-config-options control-segmented" :aria-label="item.label" />
        </el-form-item>
        <el-alert v-if="configError" :title="configError" type="error" :closable="false"></el-alert>
      </el-form>
      <template #footer>
        <el-button size="small" @click="configOpen = false">取消</el-button>
        <el-button size="small" type="primary" :loading="saving" :disabled="!edit.agents.length" @click="saveConfig">保存</el-button>
      </template>
    </el-dialog>

    <!-- 接入新设备：自助接入（推荐，安装命令不含令牌）或签发主机令牌 -->
    <el-dialog v-model="registerOpen" title="接入新设备" width="680px" class="detail-dialog" @closed="issued = null">
      <el-radio-group v-if="!issued" v-model="registerMode" size="small" class="mb-10">
        <el-radio-button value="enroll" :disabled="!deviceData.enroll?.enabled">自助接入</el-radio-button>
        <el-radio-button value="token">签发令牌</el-radio-button>
      </el-radio-group>
      <template v-if="!issued && registerMode === 'enroll'">

        <a href="#/terminals/deploy" @click.prevent="openDeploy">修改配置</a>
        <el-radio-group v-model="platform" size="small">
          <el-radio-button value="windows">Windows</el-radio-button>
          <el-radio-button value="linux">Linux</el-radio-button>
          <el-radio-button value="macos">macOS</el-radio-button>
        </el-radio-group>
        <el-alert v-if="oneClick.warning" :title="oneClick.warning" type="warning" :closable="false" class="mt-10"></el-alert>

        <pre class="hook-cmd">{{ oneClick.install }}</pre>
        <div class="deploy-actions">
          <el-button size="small" @click="copyCommand(oneClick.install)"><el-icon class="btn-ic"><DocumentCopy /></el-icon>复制命令</el-button>
          <el-button v-if="platform === 'windows'" size="small" tag="a" href="/v1/agents/install.cmd"
                     title="下载后双击运行"><el-icon class="btn-ic"><Download /></el-icon>下载 agentguard-install.cmd</el-button>
        </div>
      </template>
      <el-form v-else-if="!issued" label-width="90px" size="small" @submit.prevent>
        <el-form-item label="设备 ID"><el-input v-model="form.device_id" placeholder="设备 ID" maxlength="48"></el-input></el-form-item>
        <el-form-item label="用户"><el-input v-model="form.sub" placeholder="默认同设备 ID"></el-input></el-form-item>
        <el-form-item label="Agent">
          <el-checkbox-group v-model="form.agents">
            <el-checkbox v-for="a in deviceData.agents" :key="a.agent" :value="a.agent">{{ AGENT_NAMES[a.agent] || a.agent }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="策略档案">
          <el-radio-group v-model="form.profile">
            <el-radio-button v-for="p in deviceData.profiles" :key="p" :value="p">{{ p }}</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-alert v-if="registerError" :title="registerError" type="error" :closable="false"></el-alert>
      </el-form>
      <template v-else>
        <el-alert title="令牌只显示这一次，请立即在终端执行安装命令或妥善保存" type="warning" :closable="false" show-icon></el-alert>
        <div class="dd-callout-label mt-10">设备令牌</div>
        <CopyText :text="issued.token" />
        <el-radio-group v-model="platform" size="small" class="mt-10">
          <el-radio-button value="windows">Windows</el-radio-button>
          <el-radio-button value="linux">Linux</el-radio-button>
          <el-radio-button value="macos">macOS</el-radio-button>
        </el-radio-group>

        <pre class="hook-cmd">{{ installCommand }}</pre>
        <el-button size="small" @click="copyCommand(installCommand)"><el-icon class="btn-ic"><DocumentCopy /></el-icon>复制命令</el-button>
      </template>
      <template #footer>
        <el-button size="small" @click="registerOpen = false">{{ issued || registerMode === 'enroll' ? '完成' : '取消' }}</el-button>
        <el-button v-if="!issued && registerMode === 'token'" size="small" type="primary" :loading="registering"
                   :disabled="!form.device_id || !form.agents.length" @click="submitRegister">签发令牌</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, reactive, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { DocumentCopy, Download, Grid, Tickets } from "../../icons";
import { tab, terminalTab, AGENT_NAMES } from "../../store/runtime";
import { prepareDeviceStaticScan } from "../../store/static";
import { scanChannelState } from "../../utils/staticText";
import {
  deviceData, FAIL_MODE_TEXT, CONTROL_ITEMS, UPLOAD_MODE_TEXT, TIMEOUT_KEYS,
  updateDevice, registerDevice,
} from "../../store/devices";
import CopyText from "../../components/CopyText.vue";
import AgentIcon from "../../components/AgentIcon.vue";
import EnrollmentsPanel from "./EnrollmentsPanel.vue";
import DeviceNetwork from "./DeviceNetwork.vue";
import DeviceAgents from "./DeviceAgents.vue";
import DeviceActions from "./DeviceActions.vue";
import { itemOf, short } from "./helpers";
import { useClientCommands } from "./useClientCommands";

const FOLLOW = "__follow__";
function scanAgent(device, agent) {
  prepareDeviceStaticScan(device.device_id, agent);
  detailsOpen.value = false;
  tab.value = "static";
}
const search = ref("");
const agentFilter = ref("");
const statusFilter = ref("all");
const VIEW_KEY = "agentguard.devices.view";
let savedView = "cards";
try { const value = localStorage.getItem(VIEW_KEY); if (["cards", "table"].includes(value)) savedView = value; } catch { /* 本地偏好不可用时使用卡片视图。 */ }
const viewMode = ref(savedView);
watch(viewMode, (value) => { try { localStorage.setItem(VIEW_KEY, value); } catch { /* 显示偏好不影响设备操作。 */ } });
const page = ref(1);
const pageSize = 20;
const devices = computed(() => deviceData.value.devices || []);
const deviceStatus = (row) => row.uninstalled_at ? "uninstalled" : row.last_seen ? "reported" : "pending";
const contactOf = (row) => ({
  reported: { label: "已上报", tone: "reported" },
  pending: { label: "待首次上报", tone: "pending" },
  uninstalled: { label: "已卸载", tone: "uninstalled" },
})[deviceStatus(row)];
const statusOptions = computed(() => [
  { key: "all", label: "全部", count: devices.value.length },
  ...[{ key: "reported", label: "已上报" }, { key: "pending", label: "待上报" }, { key: "uninstalled", label: "已卸载" }]
    .map((item) => ({ ...item, count: devices.value.filter((row) => deviceStatus(row) === item.key).length })),
]);
const agentOptions = computed(() => [...new Set([
  ...deviceData.value.agents.map((item) => item.agent), ...devices.value.flatMap((row) => row.agents || []),
])]);
const hasFilters = computed(() => Boolean(search.value.trim() || agentFilter.value || statusFilter.value !== "all"));
const filteredDevices = computed(() => {
  const query = search.value.trim().toLocaleLowerCase();
  return devices.value.filter((row) => {
    if (statusFilter.value !== "all" && deviceStatus(row) !== statusFilter.value) return false;
    if (agentFilter.value && !row.agents?.includes(agentFilter.value)) return false;
    return !query || [row.device_id, row.host?.hostname, row.host?.os, row.host?.user, row.actor?.sub,
      row.host?.ip, row.host?.mac, row.remote_ip, row.profile, row.client, ...(row.agents || []).map((a) => AGENT_NAMES[a] || a)]
      .some((value) => String(value || "").toLocaleLowerCase().includes(query));
  });
});
const pagedDevices = computed(() => filteredDevices.value.slice((page.value - 1) * pageSize, page.value * pageSize));
const emptyText = computed(() => hasFilters.value ? "没有匹配的设备，请调整筛选条件" : "尚无已接入设备，点击「接入新设备」开始接入");
watch([search, agentFilter, statusFilter], () => { page.value = 1; });
watch(() => filteredDevices.value.length, (total) => { page.value = Math.min(page.value, Math.max(1, Math.ceil(total / pageSize))); });
function clearFilters() { search.value = ""; agentFilter.value = ""; statusFilter.value = "all"; }
const overrideCount = (row) => CONTROL_ITEMS.filter(({key}) => row.overrides?.[key] != null).length;
function modeOf(row) {
  if (row.uninstalled_at) return { label: "令牌已停用", tone: "muted" };
  const modes = [...new Set((row.agents || []).map((agent) => {
    const control = row.effective?.[agent];
    if (control?.enabled === false) return "stopped";
    if (control?.enabled === true && control.enforce === false) return "observe";
    return control?.enabled === true && control.enforce === true ? "enforce" : "unknown";
  }))];
  if (modes.length > 1) return { label: "按 Agent 生效", tone: "c-brand" };
  return { stopped: { label: "检测已停止", tone: "muted" }, observe: { label: "仅观察", tone: "c-med" },
    enforce: { label: "检测并拦截", tone: "c-ok" }, unknown: { label: "未取得策略", tone: "muted" } }[modes[0] || "unknown"];
}

const detailsOpen = ref(false);
const selectedDeviceId = ref("");
const selectedDevice = computed(() => devices.value.find((row) => row.device_id === selectedDeviceId.value));
function openDetails(row) { selectedDeviceId.value = row.device_id; detailsOpen.value = true; }
function configureSelected() { detailsOpen.value = false; openConfig(selectedDevice.value); }

const defaultsOf = (agent) => deviceData.value.agents.find((a) => a.agent === agent) || {};
const valueText = (key, value) => {
  if (value == null) return "—";
  if (key === "fail_mode") return FAIL_MODE_TEXT[value]?.label || value;
  if (key === "upload_mode") return UPLOAD_MODE_TEXT[value]?.label || value;
  if (TIMEOUT_KEYS.includes(key)) return value == null ? "—" : `${Number(value).toFixed(1)} 秒`;
  return value === false ? itemOf(key).off : itemOf(key).on;
};
// 自定义超时的初始值：设备上第一个 Agent 的默认值。
const defaultNumber = (key) => Number(defaultsOf((editing.value?.agents || [])[0])[key] ?? 1.5);
// 设备覆盖对其上所有 Agent 生效；默认值按 Agent 可能不同，列出各 Agent 的默认。
function defaultText(key) {
  const agents = editing.value?.agents || [];
  const values = [...new Set(agents.map((a) => valueText(key, defaultsOf(a)[key])))];
  return values.join(" / ") || "—";
}

function controlOptions(item) {
  const inherited = { label: `跟随默认（${defaultText(item.key)}）`, value: FOLLOW };
  if (TIMEOUT_KEYS.includes(item.key)) return [inherited, { label: "自定义", value: "custom" }];
  if (item.key === "fail_mode") return [inherited, ...deviceData.value.fail_modes.map((value) => ({ label: FAIL_MODE_TEXT[value]?.label || value, value }))];
  if (item.key === "upload_mode") return [inherited, ...Object.entries(UPLOAD_MODE_TEXT).map(([value, item]) => ({ label: item.label, value }))];
  return [inherited, { label: item.on, value: true }, { label: item.off, value: false }];
}

// 详情按 Agent 展示全部生效值，避免把第一个 Agent 的默认值误当成整台设备的配置。
function controlDetails(row, agent) {
  const eff = row.effective?.[agent] || {};
  return CONTROL_ITEMS.map((item) => {
    const value = eff[item.key];
    return { key: item.key, label: item.label, text: valueText(item.key, value), overridden: row.overrides?.[item.key] != null,
      fallback: valueText(item.key, defaultsOf(agent)[item.key]) };
  });
}

// ---- 设备配置 ----
const configOpen = ref(false);
const editing = ref(null);
const saving = ref(false);
const configError = ref("");
const edit = reactive({ profile: "developer", agents: [], overrides: {} });

function openConfig(row) {
  editing.value = row;
  configError.value = "";
  Object.assign(edit, {
    profile: row.profile, agents: [...row.agents],
    overrides: Object.fromEntries(CONTROL_ITEMS.map((item) => [item.key, item.key in (row.overrides || {}) ? row.overrides[item.key] : FOLLOW])),
  });
  configOpen.value = true;
}

async function saveConfig() {
  saving.value = true;
  configError.value = "";
  try {
    const overrides = Object.fromEntries(Object.entries(edit.overrides).map(([k, v]) => [k, v === FOLLOW ? null : v]));
    await updateDevice(editing.value.device_id, { profile: edit.profile, agents: edit.agents, overrides });
    configOpen.value = false;
    ElMessage.success("已保存，设备在下一次上报时取得新配置");
  } catch (e) {
    configError.value = e.message;
  } finally {
    saving.value = false;
  }
}

// ---- 接入新设备 ----
const registerMode = ref("enroll");
const registerOpen = ref(false);
const registering = ref(false);
const registerError = ref("");
const issued = ref(null);
const form = reactive({ device_id: "", sub: "", agents: [], profile: "developer" });

function openRegister() {
  registerMode.value = deviceData.value.enroll?.enabled === false ? "token" : "enroll";
  Object.assign(form, { device_id: "", sub: "", agents: deviceData.value.agents.map((a) => a.agent) });
  registerError.value = "";
  registerOpen.value = true;
}

async function submitRegister() {
  registering.value = true;
  registerError.value = "";
  try {
    issued.value = await registerDevice({
      device_id: form.device_id.trim(), agents: form.agents, profile: form.profile,
      actor: { sub: form.sub.trim() || form.device_id.trim() },
    });
  } catch (e) {
    registerError.value = e.message;
  } finally {
    registering.value = false;
  }
}

const { platform, installCommand, oneClick, copyCommand } = useClientCommands(issued);

function openDeploy() {
  registerOpen.value = false;
  terminalTab.value = "deploy";
}
</script>

<style scoped>
.devices-page { min-width: 0; }
.device-enrollments { padding: 0 16px 12px; margin-bottom: 16px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
.device-inventory { min-width: 0; }
.inventory-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 18px 18px 12px;
  border: 1px solid var(--line); border-bottom: 0; border-radius: 12px 12px 0 0; background: var(--panel); }
.inventory-header h3 { display: flex; align-items: center; gap: 8px; margin: 0; color: var(--title); font-size: 14px; }
.inventory-header h3 > .el-icon { font-size: 16px; }
.inventory-header > .el-button { flex: none; }
.inventory-count { min-width: 22px; padding: 0 6px; border-radius: 6px; background: var(--line-2); color: var(--muted); font: 12px/22px var(--mono); text-align: center; }
.inventory-toolbar { display: flex; align-items: center; flex-wrap: wrap; gap: var(--control-gap); padding: 0 18px 18px;
  border: 1px solid var(--line); border-top: 0; border-radius: 0 0 12px 12px; background: var(--panel); }
.device-status-filters { flex:none; }
.device-status-filters button span { margin-left: 3px; font-family: var(--mono); }
.device-search-filters { display: flex; gap: 8px; flex: 1 1 325px; min-width: 0; }
.device-search-filters .el-input { flex: 1; min-width: 175px; }
.device-search-filters .el-select { width: 140px; flex: none; }
.device-search-filters .el-input, .device-search-filters .el-select { height: var(--control-height); }
.device-search-filters :deep(.el-input__wrapper), .device-search-filters :deep(.el-select__wrapper) { box-sizing: border-box; height: var(--control-height); min-height: var(--control-height); }
.device-view-switch { flex:none; margin-left:auto; }
.device-view-switch button { gap:6px; }
.device-view-switch button .el-icon { font-size: 16px; }
.device-table { margin-top: 20px; border: 1px solid var(--line); border-radius: 12px; font-size: 12px; }
.device-table :deep(th.el-table__cell) { background: var(--bg); color: var(--muted); font-weight: 500; }
.device-table :deep(td.el-table__cell) { padding: 12px 0; vertical-align: top; }
.device-table :deep(.cell) { padding: 0 14px; }
.device-name { color: var(--title); font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
.device-name-link { min-height: 24px; padding: 0; border: 0; background: none; font-family: inherit; line-height: 1.5; text-align: left; cursor: pointer; }
.device-name-link:hover { text-decoration: underline; text-underline-offset: 3px; }
.device-name-link:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; border-radius: 3px; }
.device-secondary { margin-top: 3px; color: var(--muted); font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
.device-policy { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 8px; }
.device-mode { font-size: 12px; }
.device-contact { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; white-space: nowrap; }
.device-contact::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--faint); }
.device-contact.reported::before { background: var(--ok); }
.device-contact.pending::before { background: var(--med); }
.device-contact.uninstalled { color: var(--muted); }
.inventory-footer { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 14px 0; }
.inventory-footer .el-pagination { margin-left: auto; max-width: 100%; }
.device-card-view { margin-top: 20px; }
.device-card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 300px), 1fr)); gap: 16px; }
.device-card { display: flex; flex-direction: column; min-width: 0; gap: 14px; padding: 18px; border: 1px solid var(--line);
  border-radius: 12px; background: var(--panel); box-shadow: var(--shadow-panel); }
.device-card.is-uninstalled { background: var(--surface-soft); border-style: dashed; }
.device-card-heading { display: flex; align-items: flex-start; gap: 10px; }
.device-card-icon { display: grid; flex: none; place-items: center; width: 36px; height: 36px; border: 1px solid var(--line); border-radius: 9px; background: var(--surface-code); color: var(--brand); }
.device-card-icon .el-icon { font-size: 19px; }
.device-card-identity { flex: 1; min-width: 0; }
.device-card-identity .device-name { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; max-width: 100%; overflow: hidden; font-size: 14px; }
.device-card-status { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 3px; }
.device-profile-tag { flex: none; max-width: 100px; }
.device-card-id { margin-top: -5px; }
.device-card-facts { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); gap: 12px; margin: 0; }
.device-card-facts > div { min-width: 0; }
.device-card-facts dt, .device-field-label { color: var(--muted); font-size: 12px; }
.device-card-facts dd { margin: 4px 0 0; font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
.device-card-system, .device-card-client { grid-column: 1 / -1; }
.device-card-agents { display: grid; gap: 7px; }
.device-card-control { display: flex; align-items: center; flex-wrap: wrap; justify-content: space-between; gap: 4px 10px; padding: 10px 12px;
  border: 1px solid var(--line-2); border-radius: 8px; background: var(--surface-soft); }
.device-card-control .device-secondary { margin: 0; }
.device-card-footer { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 6px 10px;
  margin-top: auto; padding-top: 10px; border-top: 1px solid var(--line-2); }
.device-card-footer > .device-secondary { margin: 0; }
.device-card-empty { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); }
.device-detail-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px; }
.device-detail-heading h3 { margin: 0; color: var(--title); font-size: 17px; overflow-wrap: anywhere; }
.device-detail-heading > div { min-width: 0; }
.device-detail-heading > .el-tag { flex: none; }
.device-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px 20px; margin: 0; padding: 16px;
  border: 1px solid var(--line); border-radius: 10px; background: var(--bg); }
.device-facts dt { margin-bottom: 3px; font-size: 12px; color: var(--muted); }
.device-facts dd { margin: 0; font-size: 13px; overflow-wrap: anywhere; }
.device-detail-section { margin: 0; color: var(--title); font-size: 14px; }
.device-agent-detail { margin-top: 14px; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.device-agent-detail-header { display: flex; align-items: center; gap: 10px; padding: 12px 14px; border-bottom: 1px solid var(--line); }
.device-agent-detail-header strong { font-size: 13px; }
.device-control-details { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 20px; padding: 14px; }
.device-control-details > div { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 3px 10px; font-size: 12px; }
.device-control-details strong { color: var(--title); font-weight: 500; }
.device-control-details small { grid-column: 1 / -1; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.device-control-details .overridden small { color: var(--brand); }
.device-config-form :deep(.el-form-item) { margin-bottom:10px; }
.device-config-form :deep(.el-form-item__content) { min-width:0; }
.device-config-form :deep(.el-form-item__label) { padding-right:14px; }
.device-config-agents { display:flex; flex-wrap:wrap; gap:0 16px; }
.device-config-agents :deep(.el-checkbox) { margin-right:0; }
.device-timeout-controls { display:flex; align-items:center; flex-wrap:wrap; gap:8px; min-width:0; }
.device-timeout-controls .timeout-input { width:96px; }
@media (max-width: 760px) {
  .device-enrollments { padding: 0 12px 12px; }
  .inventory-header { align-items: flex-start; flex-wrap: wrap; padding: 14px 12px 10px; }
  .inventory-toolbar { padding: 0 12px 12px; gap: 10px; }
  .device-status-filters { max-width: 100%; }
  .device-status-filters button { flex: 1; padding: 0 6px; }
  .device-search-filters { flex-wrap: wrap; }
  .device-search-filters .el-input { width: 100%; max-width: none; flex-basis: 100%; }
  .device-search-filters .el-select { width: 100%; }
  .device-card-grid { grid-template-columns: minmax(0, 1fr); }
  .device-card { padding: 16px; }
  .device-facts { gap: 12px; padding: 12px; }
  .device-control-details { grid-template-columns: minmax(0, 1fr); }
}
</style>
