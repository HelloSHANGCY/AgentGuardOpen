<template>
  <section v-show="active" class="models-page">
    <ConsolePageHeader title="模型管理" class="models-page-head">

      <div class="models-actions"><el-button size="small" :loading="operation === 'refresh'" :disabled="busy" @click="reload"><el-icon class="btn-ic"><Refresh /></el-icon>刷新</el-button><el-button size="small" type="primary" :disabled="busy || !modelsLoaded" @click="openModel()"><el-icon class="btn-ic"><Plus /></el-icon>新增模型</el-button></div>
    </ConsolePageHeader>
    <div v-if="adminNeedsToken" class="eval-controls">
      <label>管理令牌<el-input v-model="adminToken" size="small" type="password" show-password autocomplete="off" aria-label="管理令牌" placeholder="AG_AGENT_ADMIN_TOKEN，仅保存在当前页面" @keyup.enter="reload" /></label>
      <el-button size="small" type="primary" :disabled="!adminToken || busy" @click="reload">加载</el-button>
    </div>
    <el-alert v-if="modelsError && !visible" :title="modelsError" type="error" show-icon class="my-12" @close="modelsError = ''" />
    <section v-if="modelsLoaded" class="models-card" aria-label="模型接入列表">
      <div class="models-filters">
        <el-input v-model="query" size="small" clearable aria-label="搜索模型" placeholder="名称、供应商、模型或接口"><template #prefix><el-icon><Search /></el-icon></template></el-input>
        <el-select v-model="provider" size="small" clearable aria-label="筛选供应商" placeholder="全部供应商"><el-option v-for="name in providers" :key="name" :label="name" :value="name" /></el-select>
        <el-select v-model="purpose" size="small" clearable aria-label="筛选用途" placeholder="全部用途"><el-option label="未分配" value="unassigned" /><el-option v-for="(spec, key) in modelData.purposes" :key="key" :label="spec.label" :value="key" /></el-select>
        <span class="models-count">{{ filtered.length }} 条</span>
      </div>
      <el-table :data="pagedModels" row-key="model_id" size="small" @row-click="openModel" :empty-text="filtersActive ? '没有匹配的模型' : '暂无接入模型'">
        <el-table-column label="名称" min-width="145" show-overflow-tooltip><template #default="{row}"><strong class="models-name">{{ row.name }}</strong></template></el-table-column>
        <el-table-column label="供应商" min-width="90" prop="provider" show-overflow-tooltip />
        <el-table-column label="模型" min-width="125" show-overflow-tooltip><template #default="{row}"><span class="mono">{{ row.model }}</span></template></el-table-column>
        <el-table-column label="接口" min-width="140"><template #default="{row}"><span class="mono" :title="row.url">{{ endpointHost(row.url) }}</span></template></el-table-column>
        <el-table-column label="API Key" width="95"><template #default="{row}"><el-tag size="small" effect="plain" :type="row.key_set ? 'success' : 'info'">{{ row.key_set ? row.key_hint : '未配置' }}</el-tag></template></el-table-column>
        <el-table-column label="默认思考" width="85"><template #default="{row}">{{ EFFORT_TEXT[row.effort] }}</template></el-table-column>
        <el-table-column label="用途" min-width="150"><template #default="{row}"><div class="models-usages"><el-tag v-for="key in Object.keys(row.usages)" :key="key" size="small" effect="plain">{{ modelData.purposes[key]?.label || key }}</el-tag><span v-if="!Object.keys(row.usages).length" class="muted">未分配</span></div></template></el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{row}">
            <el-button size="small" link type="primary" :disabled="busy" @click.stop="openModel(row)">详情</el-button>
            <el-tooltip :content="deleteHint(row)" :disabled="!deleteHint(row)" :trigger="['hover', 'focus']" placement="top" :show-after="150" :popper-style="{maxWidth: '320px'}">
              <span class="models-delete" :tabindex="deleteHint(row) ? 0 : undefined" :aria-label="deleteHint(row) ? '删除模型：' + deleteHint(row) : undefined" @click.stop>
                <el-popconfirm :title="'删除模型「' + row.name + '」？'" confirm-button-text="删除" cancel-button-text="取消" :disabled="!!Object.keys(row.usages).length || busy" @confirm="remove(row)">
                  <template #reference><el-button size="small" link type="danger" :disabled="busy || !!Object.keys(row.usages).length" @click.stop>删除</el-button></template>
                </el-popconfirm>
              </span>
            </el-tooltip>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="filtered.length > 10" class="models-pager"><el-pagination v-model:current-page="page" v-model:page-size="pageSize" background size="small" :total="filtered.length" :page-sizes="[10, 20, 50]" layout="total, sizes, prev, pager, next" /></div>
    </section>
    <el-skeleton v-else-if="!adminNeedsToken && !modelsError" :rows="6" animated />

    <el-dialog v-model="visible" class="detail-dialog" :title="modelId ? '模型详情' : '新增模型'" width="min(680px, 94vw)" top="6vh" :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" append-to-body destroy-on-close :before-close="closeEditor" @closed="clearDraft">
      <el-form ref="formRef" :model="form" :rules="rules" size="small" label-position="top" :disabled="busy" novalidate @submit.prevent="save">
        <el-tabs v-model="detailTab" aria-label="模型详情配置">
          <el-tab-pane label="接入配置" name="connection">
            <div class="models-form-row"><el-form-item label="名称" prop="name"><el-input v-model="form.name" aria-label="模型名称" :maxlength="80" /></el-form-item><el-form-item label="供应商" prop="provider"><el-select v-model="form.provider" filterable allow-create default-first-option aria-label="模型供应商" @change="chooseProvider"><el-option v-for="name in providerOptions" :key="name" :label="name" :value="name" /></el-select></el-form-item></div>
            <el-form-item label="接口地址" prop="url"><el-input v-model="form.url" aria-label="模型接口地址" class="mono" placeholder="https://api.example.com/v1/chat/completions" /></el-form-item>
            <el-form-item label="API Key"><el-input v-model="form.key" aria-label="模型 API Key" :disabled="form.clear_key" type="password" show-password autocomplete="off" :placeholder="keySet ? `已设置（${keyHint}），留空不修改` : '输入 API Key'" /><el-checkbox v-if="keySet" v-model="form.clear_key">清除 API Key</el-checkbox></el-form-item>
            <div class="models-form-row"><el-form-item label="模型" prop="model"><el-select v-if="connectionPreset" v-model="form.model" filterable aria-label="模型标识" class="mono"><el-option v-for="model in connectionPreset.models" :key="model.id" :label="model.id" :value="model.id" /></el-select><el-input v-else v-model="form.model" aria-label="模型标识" class="mono" /></el-form-item><el-form-item label="默认思考等级"><el-select v-model="form.effort" aria-label="默认思考等级"><el-option v-for="key in effortOptions" :key="key" :label="EFFORT_TEXT[key]" :value="key" /></el-select></el-form-item></div>
          </el-tab-pane>
          <el-tab-pane label="用途配置" name="usages">
            <el-form-item label="用途（可选）"><el-select v-model="selectedUsages" multiple clearable aria-label="模型用途" placeholder="未分配"><el-option v-for="(spec, key) in modelData.purposes" :key="key" :label="purposeOption(key, spec)" :value="key" :disabled="key === 'intent' && !supportsIntent" /></el-select></el-form-item>
            <section v-for="key in selectedUsages" :key="key" class="models-purpose" :aria-label="modelData.purposes[key].label + '配置'">
              <h3>{{ modelData.purposes[key].label }}</h3>
              <div class="models-form-row"><el-form-item label="超时（秒）"><el-input-number v-model="usages[key].timeout" :min="modelData.purposes[key].min_timeout" :max="modelData.purposes[key].max_timeout" :step="0.5" controls-position="right" :aria-label="modelData.purposes[key].label + '超时秒数'" /></el-form-item>
                <el-form-item label="思考等级"><el-input v-if="key === 'intent'" model-value="关闭（固定）" aria-label="意图识别思考等级" readonly /><el-select v-else v-model="usages[key].effort" :aria-label="modelData.purposes[key].label + '思考等级'"><el-option label="继承模型设置" value="inherit" /><el-option v-for="value in effortOptions" :key="value" :label="EFFORT_TEXT[value]" :value="value" /></el-select></el-form-item></div>
            </section>
            <el-empty v-if="!selectedUsages.length" description="未分配用途" :image-size="60" />
          </el-tab-pane>
        </el-tabs>
        <el-alert v-if="testResult" :type="testResult.ok ? 'success' : 'error'" :title="testResult.ok ? `连接正常（${testResult.latency}s）` : `调用失败：${testResult.error}`" :closable="false" show-icon class="my-12" />
        <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon class="my-12" />
      </el-form>
      <template #footer><div class="models-dialog-actions"><span v-if="dirty" class="models-dirty" role="status">未保存</span><el-button size="small" :loading="operation === 'test'" :disabled="busy" @click="runTest">测试连接</el-button><el-button size="small" :disabled="busy" @click="closeEditor(() => visible = false)">取消</el-button><el-button size="small" type="primary" :loading="operation === 'save'" :disabled="busy" @click="save">保存</el-button></div></template>
    </el-dialog>
  </section>
</template>

<script setup>
import { computed, reactive, ref, watch, nextTick, onMounted, onBeforeUnmount } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { tab, registerPageLeaveGuard } from "../store/runtime";
import { adminToken, adminNeedsToken } from "../store/devices";
import { EFFORT_TEXT } from "../utils/format";
import { modelData, modelsLoaded, modelsError, refreshModels, saveModel, deleteModel, testModel } from "../store/models";

const endpointHost = url => { try { return new URL(url).host; } catch { return url; } };
const active = computed(() => tab.value === "models");
const operation = ref("");
const busy = computed(() => !!operation.value);
const query = ref(""), provider = ref(""), purpose = ref(""), page = ref(1), pageSize = ref(20);
const providers = computed(() => [...new Set(modelData.value.models.map(model => model.provider))].sort());
const filtersActive = computed(() => !!query.value.trim() || !!provider.value || !!purpose.value);
const filtered = computed(() => modelData.value.models.filter(model => {
  if (provider.value && model.provider !== provider.value) return false;
  if (purpose.value === "unassigned" && Object.keys(model.usages).length) return false;
  if (purpose.value && purpose.value !== "unassigned" && !model.usages[purpose.value]) return false;
  return [model.name, model.provider, model.model, model.url].join(" ").toLowerCase().includes(query.value.trim().toLowerCase());
}));
const pagedModels = computed(() => filtered.value.slice((page.value - 1) * pageSize.value, page.value * pageSize.value));
watch([query, provider, purpose, pageSize], () => { page.value = 1; });
watch(filtered, rows => { page.value = Math.min(page.value, Math.max(1, Math.ceil(rows.length / pageSize.value))); });
const visible = ref(false), detailTab = ref("connection"), modelId = ref(""), keySet = ref(false), keyHint = ref("");
const formRef = ref(null), form = reactive({ name: "", provider: "", url: "", model: "", effort: "off", key: "", clear_key: false });
const providerOptions = computed(() => [...new Set([...(modelData.value.presets || []).map(preset => preset.provider), ...providers.value])]);
const connectionPreset = computed(() => {
  const base = form.url.trim().replace(/\/+$/, '').replace(/\/chat\/completions$/, '');
  return (modelData.value.presets || []).find(preset => preset.base_urls.includes(base));
});
const modelProfile = computed(() => connectionPreset.value?.models.find(model => model.id === form.model));
const effortOptions = computed(() => modelProfile.value?.efforts || Object.keys(EFFORT_TEXT));
const supportsIntent = computed(() => effortOptions.value.includes('off'));
const selectedUsages = ref([]), usages = reactive({});
const testResult = ref(null), error = ref("");
const rules = Object.fromEntries([['name', '名称'], ['provider', '供应商'], ['url', '接口地址'], ['model', '模型']].map(([field, label]) => [field, [{required:true, message:'请输入' + label, trigger:'blur'}]]));
const initialDraft = ref(null);
function draftSnapshot() {
  const {key, ...fields} = form;
  return JSON.stringify({fields, usages:[...selectedUsages.value].sort().map(name => [name, {...usages[name]}])});
}
const dirty = computed(() => visible.value && initialDraft.value !== null && (!!form.key || draftSnapshot() !== initialDraft.value));
let confirmation;
function canLeaveEditor() {
  if (!visible.value) return true;
  if (busy.value) return false;
  if (!dirty.value) return true;
  if (!confirmation) {
    confirmation = ElMessageBox.confirm('有未保存的修改，是否放弃？', '未保存修改', {
      confirmButtonText:'放弃修改', cancelButtonText:'继续编辑', type:'warning', closeOnClickModal:false, closeOnHashChange:false,
    }).then(() => true, () => false).finally(() => { confirmation = null; });
  }
  return confirmation;
}
async function closeEditor(done) { if (await canLeaveEditor()) done(); }
const unregisterGuard = registerPageLeaveGuard(canLeaveEditor);
function protectUnload(event) {
  if (dirty.value) { event.preventDefault(); event.returnValue = ''; }
}
onMounted(() => window.addEventListener('beforeunload', protectUnload));
onBeforeUnmount(() => { unregisterGuard(); window.removeEventListener('beforeunload', protectUnload); });
function clearDraft() { initialDraft.value = null; form.key = ""; form.clear_key = false; testResult.value = null; error.value = ""; }
async function openModel(model) {
  if (busy.value) return;
  initialDraft.value = null;
  modelId.value = model?.model_id || "";
  keySet.value = !!model?.key_set; keyHint.value = model?.key_hint || "";
  Object.assign(form, {name:model?.name || "", provider:model?.provider || "", url:model?.url || "", model:model?.model || "", effort:model?.effort || "off", key:"", clear_key:false});
  selectedUsages.value = Object.keys(model?.usages || {});
  for (const [key, spec] of Object.entries(modelData.value.purposes)) usages[key] = {timeout:model?.usages[key]?.timeout ?? spec.timeout, effort:model?.usages[key]?.effort ?? "inherit"};
  detailTab.value = "connection"; error.value = ""; testResult.value = null; visible.value = true;
  await nextTick();
  initialDraft.value = draftSnapshot();
}
function chooseProvider(name) {
  const preset = (modelData.value.presets || []).find(item => item.provider === name);
  if (!preset) return;
  form.url = preset.url;
  if (!preset.models.some(model => model.id === form.model)) form.model = preset.models[0].id;
  form.effort = 'default';
  if (!form.name) form.name = `${name} · ${form.model}`;
}
watch(effortOptions, options => {
  if (!options.includes(form.effort)) form.effort = 'default';
  for (const [key, config] of Object.entries(usages)) {
    if (key !== 'intent' && config.effort !== 'inherit' && !options.includes(config.effort)) config.effort = 'inherit';
  }
});
function purposeOption(key, spec) {
  if (key === 'intent' && !supportsIntent.value) return spec.label + '（模型不支持关闭思考）';
  const ownerId = modelData.value.bindings[key]?.model_id;
  const owner = modelData.value.models.find(model => model.model_id === ownerId);
  return spec.label + (owner && ownerId !== modelId.value ? `（当前：${owner.name}）` : "");
}
function deleteHint(model) {
  const labels = Object.keys(model.usages).map(key => modelData.value.purposes[key]?.label || key);
  if (labels.length) return `已绑定用途：${labels.join('、')}。请进入「详情 → 用途配置」解除绑定后删除。`;
  return busy.value ? '操作进行中，请稍后删除' : '';
}
function connectionConfig() {
  const {key, clear_key, ...fields} = form;
  return {...fields, ...(key && !clear_key ? {key} : {}), ...(clear_key ? {clear_key:true} : {})};
}
async function save() {
  if (busy.value || !await formRef.value?.validate().catch(() => false)) { detailTab.value = "connection"; return; }
  if (selectedUsages.value.includes('intent') && !supportsIntent.value) {
    detailTab.value = 'usages'; error.value = '当前模型不支持关闭思考，请取消意图识别用途或更换模型'; return;
  }
  operation.value = "save"; error.value = "";
  try {
    const conflicts = selectedUsages.value.filter(key => modelData.value.bindings[key] && modelData.value.bindings[key].model_id !== modelId.value);
    if (conflicts.length) {
      try { await ElMessageBox.confirm(`将${conflicts.map(key => modelData.value.purposes[key].label).join('、')}切换到「${form.name}」？`, "切换用途绑定", {confirmButtonText:"切换", cancelButtonText:"取消", type:"warning"}); }
      catch { return; }
    }
    const config = {...connectionConfig(), usages:Object.fromEntries(selectedUsages.value.map(key => [key, {timeout:usages[key].timeout, ...(key === 'intent' ? {effort:'off'} : usages[key].effort !== 'inherit' ? {effort:usages[key].effort} : {})}])), ...(conflicts.length ? {replace_usages:true} : {})};
    if (await saveModel(modelId.value, config)) { initialDraft.value = null; visible.value = false; form.key = ""; ElMessage.success("模型配置已保存"); }
    else error.value = modelsError.value;
  } finally { operation.value = ""; }
}
async function runTest() {
  if (busy.value || !await formRef.value?.validate().catch(() => false)) { detailTab.value = "connection"; return; }
  operation.value = "test"; error.value = "";
  try { const result = await testModel(modelId.value, connectionConfig()); if (visible.value && active.value) testResult.value = result; }
  finally { operation.value = ""; }
}
async function remove(model) {
  if (busy.value) return;
  operation.value = "delete";
  try { if (await deleteModel(model.model_id)) ElMessage.success("模型已删除"); }
  finally { operation.value = ""; }
}
async function reload() {
  if (busy.value || visible.value) return;
  operation.value = "refresh";
  try { await refreshModels(); } finally { operation.value = ""; }
}
watch([form, selectedUsages, usages], () => { testResult.value = null; }, {deep:true});
watch(active, shown => { if (shown) reload(); else {visible.value = false; clearDraft();} }, {immediate:true});
</script>

<style scoped>
.models-page-head, .models-actions, .models-dialog-actions { display:flex; align-items:center; justify-content:space-between; gap:8px; }
.models-page-head { margin-bottom:16px; gap:16px; }
.models-actions .el-button + .el-button, .models-dialog-actions .el-button + .el-button { margin-left:0; }
.models-card { min-width:0; padding:var(--space-4); border:1px solid var(--line); border-radius:var(--radius-panel); background:var(--panel); }
.models-filters { display:flex; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:16px; }
.models-filters > .el-input { flex:1; min-width:180px; max-width:420px; }
.models-filters > .el-select { width:170px; }
.models-count { margin-left:auto; color:var(--muted); font-size:12px; }
.models-name { color:var(--title); font-weight:600; }
.models-usages { display:flex; flex-wrap:wrap; gap:4px; }
.models-delete { display:inline-flex; margin-left:12px; vertical-align:middle; }
.models-delete[tabindex] { cursor:not-allowed; }
.models-card :deep(.el-table__row) { cursor:pointer; }
.models-pager { display:flex; justify-content:flex-end; margin-top:16px; }
.models-form-row { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }
.models-form-row :deep(.el-select) { width:100%; }
.models-purpose { margin:14px 0 0; padding:14px; border:1px solid var(--line); border-radius:8px; }
.models-purpose h3 { margin:0 0 14px; color:var(--title); font-size:14px; font-weight:500; }
.models-purpose :deep(.el-form-item) { margin-bottom:0; }
.models-dialog-actions { justify-content:flex-end; flex-wrap:wrap; }
.models-dirty { margin-right:auto; color:var(--med); font-size:12px; }
@media (max-width:600px) {
  .models-page-head { align-items:flex-start; flex-wrap:wrap; }
  .models-card { padding:14px; }
  .models-form-row { grid-template-columns:minmax(0,1fr); gap:0; }
  .models-purpose :deep(.el-form-item) { margin-bottom:12px; }
}
</style>
