<template>
  <section v-show="tab === 'static'" class="sa-page">
    <ConsolePageHeader title="静态资产">      <el-button size="small" plain @click="refreshPage"><el-icon class="btn-ic"><Refresh /></el-icon>刷新</el-button>
      <el-button size="small" :type="newScanOpen ? 'default' : 'primary'" @click="newScanOpen = !newScanOpen">
        <el-icon class="btn-ic"><component :is="newScanOpen ? 'Close' : 'Plus'" /></el-icon>{{ newScanOpen ? '收起' : '新建扫描' }}
      </el-button>
    </ConsolePageHeader>

    <div class="sa-navigation">
      <el-radio-group v-model="staticPage" class="sa-page-switch" aria-label="静态资产页面">
        <el-radio-button value="overview"><el-icon aria-hidden="true"><Files /></el-icon>资产总览</el-radio-button>
        <el-radio-button value="risks"><el-icon aria-hidden="true"><Warning /></el-icon>风险详情</el-radio-button>
      </el-radio-group>
    </div>
    <div class="filters sa-scan-selector" v-if="staticPage === 'risks'">
      <el-select v-model="staticScanId" placeholder="选择扫描" size="small" class="w-360" @change="loadStaticDetail"
                 no-data-text="暂无扫描记录" popper-class="scan-select-popper">
        <el-option v-for="s in staticScans" :key="s.scan_id" :value="s.scan_id" :label="scanLabel(s)">
          <div class="scan-opt">
            <span class="scan-opt-main">{{ s.project_id || 'default' }} · <span class="mono">{{ scanTarget(s) }}</span></span>
            <span class="scan-opt-meta">{{ shortTime(s.created_at) }} · <span :class="'scan-st-' + s.status">{{ scanStatusName(s.status) }}</span></span>
          </div>
        </el-option>
      </el-select>
      <template v-if="staticScan">
        <el-tag size="small" effect="plain" :type="scanTagType(staticScan.status)">
          {{ staticPolling && staticScan.phase === 'WAITING_ENDPOINT' ? '等待终端' : staticPolling && staticScan.phase === 'COLLECTING' ? '终端采集中' : scanStatusName(staticScan.status) }}<template v-if="staticPolling && !['WAITING_ENDPOINT', 'COLLECTING'].includes(staticScan.phase)"> · {{ scanPhaseName(staticScan.phase) }} {{ staticScan.progress || 0 }}%</template>
        </el-tag>
        <el-tooltip v-if="staticPolling && staticScan.device_id" placement="top" :content="deviceScanHelp" :trigger="['hover', 'focus']" :popper-style="{maxWidth:'380px'}">
          <el-icon tabindex="0" aria-label="设备扫描执行方式"><QuestionFilled /></el-icon>
        </el-tooltip>
        <el-button v-if="staticPolling" size="small" :loading="staticBusy" @click="updateStaticTask('cancel')">取消扫描</el-button>
        <el-button v-else-if="['FAILED', 'CANCELLED', 'INTERRUPTED'].includes(staticScan.status)" size="small" :loading="staticBusy" @click="updateStaticTask('retry')">重试扫描</el-button>
      </template>

    </div>

    <div class="form-card static-scan-form" v-if="newScanOpen">
      <div class="form-card-title">新建扫描</div>
      <div class="form-row">
        <label>扫描来源
          <el-radio-group v-model="staticMode" size="small">
            <el-radio-button value="registered">授权目录</el-radio-button>
            <el-radio-button value="custom">指定路径</el-radio-button>
            <el-radio-button value="device">已接入设备</el-radio-button>
          </el-radio-group>
        </label>
        <label v-if="staticMode==='registered'">授权目录
          <el-select v-model="staticSource" placeholder="授权目录" size="small" class="w-200">
            <el-option v-for="s in staticSources" :key="s" :label="s" :value="s"></el-option>
          </el-select>
        </label>
        <label v-else-if="staticMode==='custom'">扫描路径
          <span class="inline-pair">
            <el-input v-model="staticPath" placeholder="授权根内的绝对路径" size="small" class="w-260"></el-input>
            <el-button size="small" plain @click="openStaticBrowse">浏览…</el-button>
          </span>
        </label>
        <template v-else>
          <label>设备
            <el-select v-model="staticDeviceId" placeholder="选择设备" size="small" class="w-260" filterable aria-label="扫描设备">
              <el-option v-for="device in staticDevices" :key="device.device_id" :value="device.device_id"
                         :label="(device.host?.hostname || device.device_id) + ' · ' + device.device_id" />
            </el-select>
          </label>
          <label>Agent
            <el-select v-model="staticAgent" placeholder="选择 Agent" size="small" class="w-150" aria-label="扫描 Agent">
              <el-option v-for="agent in selectedDevice?.agents || []" :key="agent" :value="agent" :label="AGENT_NAMES[agent] || agent" />
            </el-select>
          </label>
          <label>范围
            <el-select v-model="staticScope" size="small" class="w-180" aria-label="设备扫描范围">
              <el-option value="user" label="用户级 Agent 资产" />
              <el-option value="user_project" label="用户级与最近项目资产" />
            </el-select>
          </label>
          <label>单文件上限（KiB）
            <el-input-number v-model="staticFileLimitKiB" :min="256" :max="2048" :step="256" :precision="0"
                             size="small" controls-position="right" aria-label="单文件上限（KiB）" />
          </label>
          <el-tag v-if="selectedDevice" size="small" :type="scanChannelState(selectedDevice, staticAgent).type" aria-label="扫描通道状态">
            扫描通道{{ scanChannelState(selectedDevice, staticAgent).label }}
          </el-tag>
          <el-tooltip placement="top" :content="deviceScanHelp" :trigger="['hover', 'focus']" :popper-style="{maxWidth:'380px'}">
            <el-icon tabindex="0" aria-label="设备扫描范围与客户端要求"><QuestionFilled /></el-icon>
          </el-tooltip>
        </template>
        <label>项目 ID<el-input v-model="staticProject" placeholder="default" size="small" class="w-140"></el-input></label>
        <label>管理令牌<el-input v-model="staticToken" placeholder="如已配置" size="small" class="w-180" show-password></el-input></label>
        <el-button size="small" type="primary" :loading="staticBusy" @click="startScan">发起扫描</el-button>
      </div>
    </div>
    <StaticBrowseDialog />
    <el-alert v-if="staticError" :title="staticError" type="warning" show-icon class="mb-10" @close="staticError = ''"></el-alert>
    <StaticInventory v-if="tab === 'static' && staticPage === 'overview'" />
    <div v-if="staticPage === 'risks'" class="sa-risk-page" v-loading="staticLoading">
    <el-alert v-if="staticScan?.status === 'PARTIAL'" type="warning" show-icon :closable="false" class="mb-10">
      <template #title>
        {{ partialSummary }}
        <el-button link type="primary" size="small" @click="staticView = 'coverage'">查看覆盖详情</el-button>
      </template>
    </el-alert>
    <el-alert v-else-if="staticScan?.error" :title="'扫描出错：' + staticScan.error" type="error" show-icon :closable="false" class="mb-10"></el-alert>

    <StaticCoverageCards />

    <div class="filters static-toolbar" v-if="staticScanId">
      <el-radio-group v-model="staticView" size="small" class="static-view-switch" aria-label="静态资产视图">
        <el-radio-button value="findings">风险 <span class="rb-count">{{ staticStats.findings }}</span></el-radio-button>
        <el-radio-button value="assets">资产 <span class="rb-count">{{ staticAssets.length }}</span></el-radio-button>
        <el-radio-button value="graph">图谱</el-radio-button>
        <el-radio-button value="coverage">覆盖<span v-if="coverageWarn" class="rb-dot" title="存在限额命中、解析失败或未解析引用"></span></el-radio-button>
      </el-radio-group>

      <template v-if="staticView==='findings'">
        <el-select v-model="staticSeverity" placeholder="全部等级" clearable size="small" class="w-120">
          <el-option v-for="s in SEVERITIES" :key="s" :label="severityName(s) + ' · ' + s" :value="s"></el-option>
        </el-select>
        <el-input v-model="staticFindingQuery" placeholder="规则 / 标题 / 资产 / 路径" size="small" clearable class="w-220">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-tag v-if="staticAssetFilter" closable size="small" type="primary" effect="light" @close="staticAssetFilter = ''">
          资产：{{ staticAssetById.get(staticAssetFilter)?.name || staticAssetFilter }}
        </el-tag>
        <div class="grow"></div>
        <span class="muted fs-11">{{ staticFindings.length }} / {{ staticStats.findings }} 条</span>
        <el-radio-group v-model="staticRuleGrouped" size="small">
          <el-radio-button :value="true">按规则聚合</el-radio-button>
          <el-radio-button :value="false">逐条</el-radio-button>
        </el-radio-group>
      </template>

      <template v-else-if="staticView==='assets'">
        <el-select v-model="staticKind" placeholder="全部类型" clearable size="small" class="w-150">
          <el-option v-for="k in staticAssetKinds" :key="k" :label="kindName(k)" :value="k"></el-option>
        </el-select>
        <el-input v-model="staticAssetQuery" placeholder="名称 / 路径 / 版本" size="small" clearable class="w-200">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <div class="grow"></div>
        <span class="muted fs-11">{{ staticFilteredAssetCount }} / {{ staticAssets.length }} 个</span>
        <el-radio-group v-model="staticAssetGrouped" size="small">
          <el-radio-button :value="true">按类型聚合</el-radio-button>
          <el-radio-button :value="false">平铺</el-radio-button>
        </el-radio-group>
      </template>
    </div>
    <div v-if="staticScanId && truncated" class="muted fs-11 mb-6">
      仅加载了前 {{ staticAllFindings.length }} / {{ staticFindingTotal }} 条风险、{{ staticAssets.length }} / {{ staticAssetTotal }} 个资产。
    </div>

    <StaticFindingList v-if="staticView==='findings'" />
    <StaticAssetTable v-else-if="staticView==='assets'" />
    <StaticGraphPanel v-else-if="staticView==='graph'" />

    <div v-else-if="staticCoverage" class="coverage-grid">
      <div class="rule-item">
        <b>文件</b>
        <dl class="kv">
          <dt>索引</dt><dd>{{ staticCoverage.indexed_files }}</dd>
          <dt>解析成功</dt><dd>{{ staticCoverage.parsed_files }}</dd>
          <dt>解析失败</dt><dd :class="{ 'c-crit': staticCoverage.failed_files }">{{ staticCoverage.failed_files }}</dd>
          <dt>跳过</dt><dd>{{ staticCoverage.skipped_files ?? 0 }}</dd>
        </dl>
      </div>
      <div class="rule-item">
        <b>语言分布</b>
        <div class="tag-row">
          <el-tag v-for="[k, v] in languages" :key="k" size="small" effect="plain" class="mono">{{ k }} · {{ v }}</el-tag>
          <span v-if="!languages.length" class="muted">-</span>
        </div>
      </div>
      <div class="rule-item">
        <b>达到限额</b>
        <div class="tag-row mt-6 static-limit-hits">
          <el-tag v-for="(h, i) in staticCoverage.limit_hits || []" :key="i" size="small" type="warning" effect="plain"
                  :title="typeof h === 'string' ? h : JSON.stringify(h)">{{ limitHitText(h) }}</el-tag>
          <span v-if="!(staticCoverage.limit_hits || []).length" class="c-ok fs-12">未触达任何限额</span>
        </div>
      </div>
      <div class="rule-item">
        <b>漏洞库</b>
        <dl class="kv">
          <dt>状态</dt><dd :class="vuln.status === 'ok' ? 'c-ok' : 'c-crit'">{{ vuln.status === 'ok' ? '可用' : (vuln.status || '不可用') }}</dd>
          <dt>版本</dt><dd class="mono">{{ vuln.db_version || '-' }}</dd>
          <dt>生成时间</dt><dd class="mono">{{ fmt(vuln.generated_at) || '-' }}</dd>
          <dt>来源</dt><dd class="mono">{{ vuln.source || '-' }}</dd>
          <dt>条目数</dt><dd>{{ vuln.entry_count ?? '-' }}</dd>
        </dl>
      </div>
      <div class="rule-item" v-if="staticScan">
        <b>扫描信息</b>
        <dl class="kv">
          <dt>扫描 ID</dt><dd><CopyText :text="staticScan.scan_id" /></dd>
          <template v-if="staticScan.device_id">
            <dt>设备</dt><dd class="mono">{{ staticScan.device_id }}</dd>
            <dt>Agent</dt><dd>{{ AGENT_NAMES[staticScan.agent] || staticScan.agent }}</dd>
            <dt>采集范围</dt><dd>{{ staticScan.collection?.scope === 'user_project' ? '用户级与项目资产' : '用户级 Agent 资产' }}</dd>
            <dt>采集文件</dt><dd>{{ staticScan.collection?.files ?? '等待采集' }}</dd>
            <dt>单文件上限</dt><dd>{{ (staticScan.limits?.max_file_parse_bytes || 262144) / 1024 }} KiB</dd>
          </template>
          <dt>规则集</dt><dd class="mono">{{ staticScan.ruleset_version || '-' }}</dd>
          <dt>开始</dt><dd class="mono">{{ fmt(staticScan.created_at) || '-' }}</dd>
          <dt>完成</dt><dd class="mono">{{ fmt(staticScan.finished_at) || '-' }}</dd>
        </dl>
      </div>
      <div class="rule-item span-all" v-if="unresolved.length">
        <b>未解析引用</b> <span class="muted fs-11">共 {{ staticCoverage.unresolved_refs.length }} 条</span>
        <div v-for="[file, refs] in unresolved" :key="file" class="unresolved-file">
          <div class="mono fs-12">{{ file }} <span class="muted">· {{ refs.length }}</span></div>
          <div v-for="(r, i) in refs" :key="i" class="mono fs-11 muted unresolved-ref">{{ r }}</div>
        </div>
      </div>
      <div class="rule-item span-all" v-if="(staticCoverage.notes || []).length">
        <b>覆盖详情</b>
        <div class="d" v-for="(n, i) in staticCoverage.notes" :key="'n'+i">{{ coverageNoteText(n) }}</div>
      </div>
    </div>
    <el-empty v-if="!staticScanId" description="暂无扫描记录" />
    </div>
  </section>
</template>

<script setup>
import { computed, watch } from "vue";
import { QuestionFilled } from "../icons";
import { tab, AGENT_NAMES } from "../store/runtime";
import {
  staticSources, staticSource, staticProject, staticToken, staticScans, staticScanId,
  staticMode, staticPath, staticScan, staticCoverage, staticPolling, staticError, staticPage, staticLoading,
  staticBusy, staticKind, staticSeverity, staticView, staticAssetGrouped, staticAssetQuery, staticAssetKinds,
  staticFindingQuery, staticAssetFilter, staticRuleGrouped, staticAssetById, staticStats, staticFindings,
  staticAllFindings, staticAssets, staticFilteredAssetCount, staticFindingTotal, staticAssetTotal,
  loadStaticSources, loadStaticScans, createStaticScan, loadStaticDetail, refreshStatic, openStaticBrowse,
  staticDevices, staticDeviceId, staticAgent, staticScope, staticFileLimitKiB, staticNewScanOpen as newScanOpen,
  loadStaticDevices, updateStaticTask,
} from "../store/static";
import { fmt } from "../utils/format";
import { SEVERITIES, severityName, kindName, scanStatusName, scanPhaseName, limitHitText, coverageNoteText, scanChannelState } from "../utils/staticText";
import CopyText from "../components/CopyText.vue";
import StaticBrowseDialog from "./static/StaticBrowseDialog.vue";
import StaticCoverageCards from "./static/StaticCoverageCards.vue";
import StaticFindingList from "./static/StaticFindingList.vue";
import StaticAssetTable from "./static/StaticAssetTable.vue";
import StaticGraphPanel from "./static/StaticGraphPanel.vue";
import StaticInventory from "./static/StaticInventory.vue";
import { loadInventory } from "../store/staticInventory";
import "./static/static.css";

// 新建扫描表单默认收起；没有任何扫描记录时自动展开，引导首次使用。
const selectedDevice = computed(() => staticDevices.value.find(item => item.device_id === staticDeviceId.value));
const deviceScanHelp = computed(() => `终端客户端 0.16.0 起支持后台扫描通道${selectedDevice.value?.client ? '（所选设备最近上报：' + selectedDevice.value.client + '）' : ''}，可在「设备管理 → 客户端部署」升级。安装后后台等待任务，在线时无需 Agent 活动即可接收扫描，离线任务在重连后执行。单文件默认上限 256 KiB，可调至 2048 KiB；上调后需客户端 0.16.1，旧客户端不会领取超出其采集能力的任务。总文本上限仍为 4 MiB。只读取 Agent 配置、指令、Skill 与 MCP 资产；项目范围使用该 Agent 最近 24 小时上报的项目，无可用项目时记录跳过。手动执行 static-scan 时可用 --workspace 指定。`);
const scanTagType = (status) => ({ COMPLETED: "success", FAILED: "danger", RUNNING: "primary", QUEUED: "info", CANCELLED: "info" }[status] || "warning");
const shortTime = (ts) => fmt(ts).slice(5, 16);
const scanTarget = s => s.device_id ? s.device_id + ' / ' + (AGENT_NAMES[s.agent] || s.agent) : s.source_path || s.source_id;
const scanLabel = (s) => `${s.project_id || "default"} · ${scanTarget(s)} · ${shortTime(s.created_at)} · ${s.phase === 'WAITING_ENDPOINT' && s.status === 'QUEUED' ? '等待终端' : scanStatusName(s.status)}`;

const truncated = computed(() => staticAllFindings.value.length < staticFindingTotal.value
  || staticAssets.value.length < staticAssetTotal.value);

const vuln = computed(() => staticCoverage.value?.vulnerability_db || {});
const partialSummary = computed(() => {
  const c = staticCoverage.value || {};
  const gaps = [];
  if (c.failed_files) gaps.push(`${c.failed_files} 个文件解析或读取失败`);
  if (c.skipped_files) gaps.push(`${c.skipped_files} 个文件跳过`);
  return '扫描部分完成：' + (gaps.join('，') || '存在分析覆盖缺口');
});
const languages = computed(() => Object.entries(staticCoverage.value?.languages || {}).sort((a, b) => b[1] - a[1]));
// 未解析引用形如 "path/file.py:func:kind:detail"，按文件分组展示。
const unresolved = computed(() => {
  const groups = new Map();
  for (const ref of staticCoverage.value?.unresolved_refs || []) {
    const i = ref.indexOf(":");
    const file = i > 0 ? ref.slice(0, i) : "(未知文件)";
    if (!groups.has(file)) groups.set(file, []);
    groups.get(file).push(i > 0 ? ref.slice(i + 1) : ref);
  }
  return [...groups.entries()];
});
const coverageWarn = computed(() => {
  const c = staticCoverage.value;
  return !!c && (staticScan.value?.status === 'PARTIAL' || (c.limit_hits || []).length > 0 || c.failed_files > 0 || (c.unresolved_refs || []).length > 0);
});

async function startScan() {
  await createStaticScan();
  if (!staticError.value) { newScanOpen.value = false; staticPage.value = 'risks'; }
}

const refreshPage = () => staticPage.value === 'overview' ? loadInventory() : refreshStatic();
watch(staticPage, async page => {
  if (page !== 'risks') return;
  await loadStaticScans();
  if (!staticScanId.value && staticScans.value.length) staticScanId.value = staticScans.value[0].scan_id;
  if (staticScanId.value && !staticLoading.value && staticScan.value?.scan_id !== staticScanId.value) await loadStaticDetail();
});

watch(tab, async (t) => {
  if (t !== "static") return;
  await loadStaticSources();
  if (staticMode.value === "device") await loadStaticDevices();
  await loadStaticScans();
  if (!staticScans.value.length) newScanOpen.value = true;
  if (!staticScanId.value && staticScans.value.length) staticScanId.value = staticScans.value[0].scan_id;
  if (staticScanId.value && staticPage.value === 'risks') await loadStaticDetail();
});

watch(staticMode, mode => { if (mode === "device") loadStaticDevices(); });
watch(staticDeviceId, () => {
  const agents = selectedDevice.value?.agents || [];
  if (agents.length && !agents.includes(staticAgent.value)) staticAgent.value = agents[0];
});
</script>

<style scoped>
.static-scan-form :deep(.el-select__wrapper) { min-height: var(--control-height); }
.static-scan-form :deep(.el-radio-button__inner) {
  display: inline-flex; align-items: center; box-sizing: border-box; height: var(--control-height);
}
.static-limit-hits .el-tag { max-width: 100%; }
.static-limit-hits :deep(.el-tag__content) { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
</style>
