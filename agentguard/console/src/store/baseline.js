// 行为基线：真实会话数据、手动训练、启用与回滚（/v1/admin/baseline/*）。管理令牌与设备管理共用。
import { ref } from "vue";
import { adminJson, adminNeedsToken } from "./devices";

export const baselineData = ref({ active: "", models: [], data: { devices: [], sessions: 0, steps: 0 }, defaults: {} });
export const baselineLoaded = ref(false);
export const baselineError = ref("");
export const lastTrained = ref(null);

export async function compareBaselines(versions, signal) {
  try {
    return await adminJson('/baseline/compare', {method: 'POST', body: JSON.stringify({versions}), signal});
  } catch (error) {
    if (error.status === 401) adminNeedsToken.value = true;
    throw error;
  }
}

function fail(e) {
  if (e.status === 401) adminNeedsToken.value = true;
  baselineError.value = e.message;
}

export async function refreshBaseline() {
  try {
    baselineData.value = await adminJson("/baseline");
    baselineError.value = "";
    baselineLoaded.value = true;
  } catch (e) { fail(e); }
}

export async function trainBaseline(params) {
  lastTrained.value = null;
  try {
    lastTrained.value = await adminJson("/baseline/train", { method: "POST", body: JSON.stringify({ params }) });
    baselineError.value = "";
    await refreshBaseline();
    return lastTrained.value;
  } catch (e) { fail(e); return null; }
}

export async function activateBaseline(version) {
  try {
    await adminJson("/baseline/activate", { method: "POST", body: JSON.stringify({ version }) });
    await refreshBaseline();
    return true;
  } catch (e) { fail(e); return false; }
}

export async function deleteBaseline(version) {
  try {
    await adminJson("/baseline/models/" + encodeURIComponent(version), { method: "DELETE" });
    if (lastTrained.value?.version === version) lastTrained.value = null;
    await refreshBaseline();
  } catch (e) { fail(e); }
}

export async function clearRecords(device = "") {
  try {
    const query = device ? "?device=" + encodeURIComponent(device) : "";
    const result = await adminJson("/baseline/records" + query, { method: "DELETE" });
    await refreshBaseline();
    return result.removed;
  } catch (e) { fail(e); return null; }
}
