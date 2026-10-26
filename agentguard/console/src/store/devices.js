// 终端管控：设备清单、接入审批、防护策略与客户端部署共用的数据与管理接口。
// 管控 = 各 Agent 的全局默认（/v1/admin/hooks）+ 设备覆盖（/v1/admin/devices/{id} 的 overrides，null 表示跟随默认）。
// 接入：终端自助申请（/v1/admin/enrollments，管理员核对核对码后认证）或管理员手动签发令牌。
import { ref } from "vue";
import { requestJson } from "../api/client";

export const adminToken = ref("");          // 管理令牌，仅保存在当前页面
export const adminNeedsToken = ref(false);  // 服务端配置了 AG_AGENT_ADMIN_TOKEN 且未提供/不匹配
export const deviceError = ref("");
export const deviceLoaded = ref(false);
export const deviceData = ref({ agents: [], devices: [], fail_modes: [], profiles: [], enrollments: [],
  enroll: { enabled: true, key_required: false }, clients: [], deploy: null });

export const FAIL_MODE_TEXT = {
  open: { label: "直接放行" },
  failsafe: { label: "降级拦截" },
};

export const UPLOAD_MODE_TEXT = {
  full: { label: "原文" },
  digest: { label: "只传摘要" },
};

// 管控项：设备配置弹窗与默认卡片共用。kind：bool 开关 / choice 单选 / seconds 秒数。
export const CONTROL_ITEMS = [
  { key: "enabled", label: "检测", on: "检测中", off: "已停止" },
  { key: "enforce", label: "拦截", on: "拦截", off: "仅观察",
    hint: "关闭后为观察模式：照常检测并记录告警与行为基线数据，但不拦截、不弹确认，MCP 中转照常转发；本地快速判定与降级拦截同时停用，大模型危险审批不再复核" },
  { key: "local_rules", label: "本地快速判定", on: "开启", off: "关闭",
    hint: "终端按服务端签名下发的规则包，在本地直接拒绝凭证读取、恶意命令、改写 Agent 配置、直接外发敏感内容等高置信威胁；服务端不可达时同样生效" },
  { key: "result_guard", label: "返回内容拦截", on: "拦截", off: "仅标记",
    hint: "MCP 中转与网关检出工具返回含注入指令时，不把原文交给 Agent，替换为拦截说明并记录拒绝决策；原文进入证据库，可在运行审计与会话链路中溯源。关闭后只打污点、记录告警，返回原样交给 Agent；观察模式下不生效" },
  { key: "fail_mode", label: "服务不可达时" },
  { key: "upload_mode", label: "工具返回上传" },
  { key: "timeout_pre", label: "调用前超时", unit: "秒" },
  { key: "timeout", label: "其他事件超时", unit: "秒" },
];
export const TIMEOUT_KEYS = ["timeout_pre", "timeout"];

// 管理令牌同时用于行为基线等其他管理接口（store/baseline.js）。
export const adminJson = (path, options = {}) => requestJson("/v1/admin" + path, {
  ...options,
  headers: { "Content-Type": "application/json", ...(adminToken.value ? { "X-AG-Admin-Token": adminToken.value } : {}) },
}, "管理请求失败");

function handleError(e) {
  // 401：令牌缺失或错误；503：服务端既未开启本地测试模式也未配置管理令牌。
  if (e.status === 401) adminNeedsToken.value = true;
  deviceError.value = e.message;
}

export async function refreshDevices({ quiet = false } = {}) {
  try {
    deviceData.value = await adminJson("/hooks");
    deviceError.value = "";
    deviceLoaded.value = true;
  } catch (e) { if (!quiet) handleError(e); }
}

// 后台定期刷新（导航上的待认证数量、设备最近上报）；需要管理令牌而尚未提供时不请求。
let pollTimer = null;
export function startDevicePolling(intervalMs = 15000) {
  if (pollTimer) return;
  const tick = () => {
    if (document.visibilityState === "visible" && (!adminNeedsToken.value || adminToken.value)) refreshDevices({ quiet: true });
  };
  tick();
  pollTimer = setInterval(tick, intervalMs);
}

// spec: {device_id, profile, agents, actor: {sub}}；返回新设备行。
export async function approveEnrollment(enrollmentId, spec) {
  const row = await adminJson("/enrollments/" + encodeURIComponent(enrollmentId) + "/approve",
    { method: "POST", body: JSON.stringify(spec) });
  await refreshDevices();
  return row;
}

export async function rejectEnrollment(enrollmentId) {
  try {
    await adminJson("/enrollments/" + encodeURIComponent(enrollmentId), { method: "DELETE" });
    await refreshDevices();
  } catch (e) { handleError(e); }
}

// 修改某个 Agent 的全局默认；设备的实际生效值随之变化，刷新列表。
export async function updateDefaults(agent, changes) {
  try {
    await adminJson("/hooks/" + encodeURIComponent(agent), { method: "PUT", body: JSON.stringify(changes) });
    await refreshDevices();
    return true;
  } catch (e) { handleError(e); return false; }
}

// changes: {profile?, agents?, overrides?: {key: value | null}}
export async function updateDevice(deviceId, changes) {
  const row = await adminJson("/devices/" + encodeURIComponent(deviceId), { method: "PUT", body: JSON.stringify(changes) });
  deviceData.value.devices = deviceData.value.devices.map((d) => (d.device_id === deviceId ? row : d));
  await refreshDevices();
  return row;
}

// 返回 {device, token}；明文令牌只在签发时出现一次。
export async function registerDevice(spec) {
  const result = await adminJson("/devices", { method: "POST", body: JSON.stringify(spec) });
  await refreshDevices();
  return result;
}

// 客户端部署配置（一键安装参数）：{server_url, agents, scope, wait, self_test}。
export async function updateDeploy(changes) {
  const config = await adminJson("/deploy", { method: "PUT", body: JSON.stringify(changes) });
  deviceData.value = { ...deviceData.value, deploy: config };
  return config;
}

export async function revokeDevice(deviceId) {
  try {
    await adminJson("/devices/" + encodeURIComponent(deviceId), { method: "DELETE" });
    await refreshDevices();
  } catch (e) { handleError(e); }
}
