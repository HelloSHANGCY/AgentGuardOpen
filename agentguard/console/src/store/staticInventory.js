import { ref, watch } from "vue";
import { staticJson } from "./static";

export const inventory = ref(null), inventoryLoading = ref(false), inventoryError = ref("");
export const inventoryAgent = ref(""), inventoryKind = ref(""), inventoryQuery = ref(""), inventoryRisk = ref("");
export const inventoryPage = ref(1), inventoryPageSize = ref(20);
let requestSequence = 0;

export async function loadInventory() {
  const sequence = ++requestSequence;
  inventoryLoading.value = true; inventoryError.value = "";
  const query = new URLSearchParams({view: "groups", limit: String(inventoryPageSize.value),
    offset: String((inventoryPage.value - 1) * inventoryPageSize.value)});
  for (const [key, value] of Object.entries({agent: inventoryAgent.value, kind: inventoryKind.value,
    q: inventoryQuery.value.trim(), risk: inventoryRisk.value})) if (value) query.set(key, value);
  try {
    const data = await staticJson("/v1/static/inventory?" + query);
    if (sequence !== requestSequence) return;
    const last = Math.max(1, Math.ceil(data.total / inventoryPageSize.value));
    if (inventoryPage.value > last) { inventoryPage.value = last; return loadInventory(); }
    inventory.value = data;
  } catch (error) {
    if (sequence === requestSequence) inventoryError.value = "加载资产总览失败：" + error.message;
  } finally { if (sequence === requestSequence) inventoryLoading.value = false; }
}

export function resetInventoryFilters() {
  inventoryAgent.value = ""; inventoryKind.value = ""; inventoryQuery.value = ""; inventoryRisk.value = "";
  inventoryPage.value = 1;
}

watch([inventoryAgent, inventoryKind, inventoryQuery, inventoryRisk, inventoryPageSize], () => { inventoryPage.value = 1; }, {flush: "sync"});
