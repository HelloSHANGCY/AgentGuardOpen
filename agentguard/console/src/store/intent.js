// 意图识别的共享状态与功能开关；连接参数由模型管理维护。
import { ref } from "vue";
import { adminJson, adminNeedsToken } from "./devices";

export const intentStatus = ref(null);
export const intentError = ref("");

function fail(e) {
  if (e.status === 401) adminNeedsToken.value = true;
  intentError.value = e.message;
}

export async function refreshIntent() {
  try {
    intentStatus.value = await adminJson("/intent");
    intentError.value = "";
    return true;
  } catch (e) { fail(e); return false; }
}

export async function updateIntent(changes) {
  try {
    intentStatus.value = await adminJson("/intent", { method: "PUT", body: JSON.stringify(changes) });
    intentError.value = "";
    return true;
  } catch (e) { fail(e); return false; }
}
