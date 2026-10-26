import { ref } from "vue";
import { adminJson, adminNeedsToken } from "./devices";

export const modelData = ref({ models: [], bindings: {}, purposes: {}, presets: [] });
export const modelsLoaded = ref(false);
export const modelsError = ref("");
function fail(error) {
  if (error.status === 401) adminNeedsToken.value = true;
  modelsError.value = error.message;
}
export async function refreshModels() {
  try {
    modelData.value = await adminJson("/models");
    modelsLoaded.value = true;
    modelsError.value = "";
    return true;
  } catch (error) { fail(error); return false; }
}
export async function saveModel(modelId, config) {
  try {
    const model = await adminJson("/models" + (modelId ? "/" + encodeURIComponent(modelId) : ""),
      { method: modelId ? "PUT" : "POST", body: JSON.stringify(config) });
    await refreshModels();
    return model;
  } catch (error) { fail(error); return null; }
}
export async function deleteModel(modelId) {
  try {
    await adminJson("/models/" + encodeURIComponent(modelId), { method: "DELETE" });
    await refreshModels();
    return true;
  } catch (error) { fail(error); return false; }
}
export async function testModel(modelId, config) {
  try {
    return await adminJson("/models/test", { method: "POST", body: JSON.stringify({ config, ...(modelId ? { model_id: modelId } : {}) }) });
  } catch (error) { if (error.status === 401) adminNeedsToken.value = true; return { ok: false, error: error.message }; }
}
export async function discoverModels(config, modelId) {
  try {
    return await adminJson("/models/discover", { method: "POST", body: JSON.stringify({ config, ...(modelId ? { model_id: modelId } : {}) }) });
  } catch (error) {
    if (error.status === 401) adminNeedsToken.value = true;
    throw error;
  }
}
