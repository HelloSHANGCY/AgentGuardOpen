// 静态资产扫描状态：授权目录/指定路径、扫描队列、资产/风险/图谱数据与轮询。
import { ref, computed, watch } from "vue";
import { requestJson } from "../api/client";
import { SEVERITIES, sevRank, kindRank, ruleTitle } from "../utils/staticText";

export const staticSources = ref([]), staticSource = ref(""), staticProject = ref("default");
export const staticMode = ref("registered"), staticPath = ref("");
export const staticDevices = ref([]), staticDeviceId = ref(""), staticAgent = ref(""), staticScope = ref("user");
export const staticFileLimitKiB = ref(256);
export const staticNewScanOpen = ref(false);
export const staticBrowseOpen = ref(false), staticBrowsePath = ref(""), staticBrowseParent = ref("");
export const staticBrowseRoots = ref([]), staticBrowseEntries = ref([]);
export const staticPolling = ref(false);
export const staticToken = ref(localStorage.getItem("ag_static_token") || "");
export const staticScans = ref([]), staticScanId = ref(""), staticScan = ref(null);
export const staticCoverage = ref(null), staticAssets = ref([]), staticAllFindings = ref([]);
export const staticAssetTotal = ref(0), staticFindingTotal = ref(0);
export const staticKind = ref(""), staticSeverity = ref(""), staticView = ref("findings");
export const staticPage = ref("overview"), staticLoading = ref(false);
export const staticAssetGrouped = ref(true), staticAssetQuery = ref("");
// 风险列表的客户端筛选：关键字、按资产过滤（从资产表/图谱跳转而来）、按规则聚合。
export const staticFindingQuery = ref(""), staticAssetFilter = ref(""), staticRuleGrouped = ref(true);
// 图谱中心节点；空表示全图。由图谱面板与“在图谱中查看”共同驱动。
export const staticGraphCenter = ref("");
export const staticError = ref(""), staticBusy = ref(false);

let pollTimer = null;
let detailRequest = 0;

export const staticJson = (p, opts = {}) => {
  const headers = Object.assign({}, opts.headers || {});
  if (staticToken.value) headers["X-AG-Admin"] = staticToken.value;
  return requestJson(p, Object.assign({}, opts, { headers }));
};

export async function loadStaticSources() {
  try {
    const data = await staticJson("/v1/static/sources");
    staticSources.value = data.sources || [];
    staticBrowseRoots.value = data.roots || [];
    if (!staticSource.value && staticSources.value.length) staticSource.value = staticSources.value[0];
  } catch (e) { staticError.value = "加载授权目录失败：" + e.message; }
}

export async function loadStaticDevices() {
  try {
    const data = await staticJson("/v1/static/devices");
    staticDevices.value = data.devices || [];
    const device = staticDevices.value.find(item => item.device_id === staticDeviceId.value);
    if (device && !device.agents.includes(staticAgent.value)) staticAgent.value = device.agents[0] || "";
  } catch (e) { staticError.value = "加载扫描设备失败：" + e.message; }
}

export function prepareDeviceStaticScan(deviceId, agent) {
  staticMode.value = "device";
  staticDeviceId.value = deviceId;
  staticAgent.value = agent;
  staticNewScanOpen.value = true;
}

export async function openStaticBrowse() {
  staticBrowseOpen.value = true;
  await staticBrowseTo(staticPath.value.trim());
}

export async function staticBrowseTo(path) {
  try {
    const query = path ? "?path=" + encodeURIComponent(path) : "";
    const data = await staticJson("/v1/static/browse" + query);
    staticBrowsePath.value = data.path || "";
    staticBrowseParent.value = data.parent || "";
    staticBrowseRoots.value = data.roots || staticBrowseRoots.value;
    staticBrowseEntries.value = data.entries || [];
  } catch (e) { staticError.value = "浏览目录失败：" + e.message; }
}

export function chooseStaticBrowse() {
  if (staticBrowsePath.value) staticPath.value = staticBrowsePath.value;
  staticBrowseOpen.value = false;
}

export async function loadStaticScans() {
  try {
    const data = await staticJson("/v1/static/scans?limit=50");
    staticScans.value = data.scans || [];
  } catch (e) { staticError.value = "加载扫描列表失败：" + e.message; }
}

const isStaticActive = (scan) => !!scan && (scan.status === "QUEUED" || scan.status === "RUNNING");

export function scheduleStaticPoll() {
  clearTimeout(pollTimer); pollTimer = null;
  staticPolling.value = isStaticActive(staticScan.value);
  if (!staticPolling.value) return;
  pollTimer = setTimeout(async () => {
    if (staticMode.value === 'device') await loadStaticDevices();
    await loadStaticScans();
    await loadStaticDetail();
  }, 2000);
}

export async function refreshStatic() {
  if (staticMode.value === "device") await loadStaticDevices();
  await loadStaticScans();
  if (!staticScanId.value && staticScans.value.length) staticScanId.value = staticScans.value[0].scan_id;
  await loadStaticDetail();
}

export async function createStaticScan() {
  if (staticMode.value === "registered" && !staticSource.value) { staticError.value = "请选择授权目录"; return; }
  if (staticMode.value === "custom" && !staticPath.value.trim()) { staticError.value = "请填写或选择扫描路径"; return; }
  if (staticMode.value === "device" && (!staticDeviceId.value || !staticAgent.value)) {
    staticError.value = "请选择设备与 Agent"; return;
  }
  if (staticMode.value === "device" && (!Number.isInteger(staticFileLimitKiB.value)
      || staticFileLimitKiB.value < 256 || staticFileLimitKiB.value > 2048)) {
    staticError.value = "单文件上限须为 256–2048 KiB 的整数"; return;
  }
  staticBusy.value = true; staticError.value = "";
  try {
    localStorage.setItem("ag_static_token", staticToken.value || "");
    const payload = staticMode.value === "device"
      ? { device_id: staticDeviceId.value, agent: staticAgent.value, scope: staticScope.value,
          limits: { max_file_parse_bytes: staticFileLimitKiB.value * 1024 }, project_id: staticProject.value || "default" }
      : staticMode.value === "custom"
      ? { path: staticPath.value.trim(), project_id: staticProject.value || "default" }
      : { source_id: staticSource.value, project_id: staticProject.value || "default" };
    const data = await staticJson("/v1/static/scans", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    staticScanId.value = data.scan_id;
    await loadStaticScans();
    await loadStaticDetail();
  } catch (e) { staticError.value = "发起扫描失败：" + e.message; }
  finally { staticBusy.value = false; }
}

export async function loadStaticDetail() {
  const scanId = staticScanId.value, request = ++detailRequest;
  clearTimeout(pollTimer);
  if (!scanId) return false;
  staticLoading.value = true;
  try {
    const base = "/v1/static/scans/" + encodeURIComponent(scanId);
    const loadItems = async (path) => {
      const first = await staticJson(`${base}/${path}?limit=${FETCH_LIMIT}`);
      const items = [...(first.items || [])], total = first.total ?? items.length;
      while (items.length < total) {
        if (request !== detailRequest || scanId !== staticScanId.value) throw new Error("扫描已切换");
        const next = await staticJson(`${base}/${path}?limit=${FETCH_LIMIT}&offset=${items.length}`);
        if (!next.items?.length) throw new Error("扫描结果已变化，请刷新重试");
        items.push(...next.items);
      }
      return {items, total};
    };
    const [data, assets, findings] = await Promise.all([
      staticJson(base), loadItems("assets"), loadItems("findings"),
    ]);
    if (request !== detailRequest || scanId !== staticScanId.value) return false;
    staticScan.value = data.scan; staticCoverage.value = data.coverage;
    if (!staticScans.value.some(scan => scan.scan_id === scanId)) staticScans.value.unshift(data.scan);
    staticAssets.value = assets.items || []; staticAssetTotal.value = assets.total ?? staticAssets.value.length;
    staticAllFindings.value = findings.items || []; staticFindingTotal.value = findings.total ?? staticAllFindings.value.length;
    staticError.value = "";
    scheduleStaticPoll();
    return true;
  } catch (e) {
    if (request === detailRequest && scanId === staticScanId.value) {
      staticError.value = "加载扫描详情失败：" + e.message;
      scheduleStaticPoll();
    }
    return false;
  } finally { if (request === detailRequest) staticLoading.value = false; }
}

export async function updateStaticTask(action) {
  if (!staticScanId.value || staticBusy.value) return;
  staticBusy.value = true; staticError.value = "";
  try {
    await staticJson(`/v1/static/scans/${encodeURIComponent(staticScanId.value)}/${action}`, { method: "POST" });
    await loadStaticScans();
    await loadStaticDetail();
  } catch (e) { staticError.value = "更新扫描任务失败：" + e.message; }
  finally { staticBusy.value = false; }
}

// 分批加载当前扫描的全部资产与风险，再一次性更新视图，避免大扫描尾部资产被误显示为零风险。
const FETCH_LIMIT = 2000;

export async function loadStaticFindingDetail(finding) {
  // 详情弹窗按需拉取证据明细，避免列表接口一次性返回全部证据。
  if (finding.evidence) return;
  try {
    const detail = await staticJson(`/v1/static/scans/${encodeURIComponent(staticScanId.value)}/findings/${encodeURIComponent(finding.finding_id)}`);
    finding.evidence = detail.evidence || [];
  } catch (e) { finding.evidence = []; }
}

export const staticAssetById = computed(() => new Map(staticAssets.value.map((a) => [a.asset_id, a])));

// 每个资产命中的风险数与最高等级，供资产表“风险”列与图谱着色使用。
export const staticRiskByAsset = computed(() => {
  const map = new Map();
  for (const f of staticAllFindings.value) {
    if (!f.asset_id) continue;
    const r = map.get(f.asset_id) || { count: 0, top: "INFO" };
    r.count += 1;
    if (sevRank(f.severity) < sevRank(r.top)) r.top = f.severity;
    map.set(f.asset_id, r);
  }
  return map;
});

export const staticStats = computed(() => {
  const severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const item of staticAllFindings.value) severity[item.severity] = (severity[item.severity] || 0) + 1;
  return { findings: staticAllFindings.value.length, critical: severity.CRITICAL || 0, severity };
});

const byRisk = (a, b) => sevRank(a.severity) - sevRank(b.severity) || (a.rule_id || "").localeCompare(b.rule_id || "");

export const staticFindings = computed(() => {
  const q = staticFindingQuery.value.trim().toLowerCase();
  const assets = staticAssetById.value;
  return staticAllFindings.value.filter((f) => {
    if (staticSeverity.value && f.severity !== staticSeverity.value) return false;
    if (staticAssetFilter.value && f.asset_id !== staticAssetFilter.value) return false;
    if (!q) return true;
    const a = assets.get(f.asset_id);
    return [f.title, f.rule_id, ruleTitle(f.rule_id), f.category, a?.name, a?.relative_path]
      .some((v) => (v || "").toLowerCase().includes(q));
  }).sort(byRisk);
});

// 按规则聚合：同一规则的多处命中合为一组，组按最高等级、再按命中数排序。
export const staticFindingGroups = computed(() => {
  const groups = new Map();
  for (const f of staticFindings.value) {
    let g = groups.get(f.rule_id);
    if (!g) { g = { rule_id: f.rule_id, title: ruleTitle(f.rule_id), items: [], top: f.severity, severity: {} }; groups.set(f.rule_id, g); }
    g.items.push(f);
    g.severity[f.severity] = (g.severity[f.severity] || 0) + 1;
    if (sevRank(f.severity) < sevRank(g.top)) g.top = f.severity;
  }
  return [...groups.values()].sort((a, b) => sevRank(a.top) - sevRank(b.top) || b.items.length - a.items.length);
});

export const staticAssetKinds = computed(() =>
  [...new Set(staticAssets.value.map((a) => a.kind))].sort((a, b) => kindRank(a) - kindRank(b)));

const filteredAssets = computed(() => {
  const q = staticAssetQuery.value.trim().toLowerCase();
  return staticAssets.value.filter((a) => (!staticKind.value || a.kind === staticKind.value)
    && (!q || [a.name, a.relative_path, a.version].some((v) => (v || "").toLowerCase().includes(q))));
});

export const staticAssetRows = computed(() => {
  const list = [...filteredAssets.value].sort((a, b) => kindRank(a.kind) - kindRank(b.kind) || (a.name || "").localeCompare(b.name || ""));
  if (!staticAssetGrouped.value) return list.map((a) => ({ ...a, row_key: a.asset_id }));
  const groups = new Map();
  for (const asset of list) {
    if (!groups.has(asset.kind)) groups.set(asset.kind, []);
    groups.get(asset.kind).push({ ...asset, row_key: asset.asset_id });
  }
  return [...groups.entries()].map(([kind, items]) => ({ row_key: "group-" + kind, kind, is_group: true, children: items }));
});

export const staticFilteredAssetCount = computed(() => filteredAssets.value.length);

// 从资产表/图谱跳到风险列表并只看该资产。
export function showAssetFindings(assetId) {
  staticPage.value = "risks";
  staticSeverity.value = ""; staticFindingQuery.value = "";
  staticAssetFilter.value = assetId;
  staticView.value = "findings";
}

export function showAssetInGraph(assetId) {
  staticPage.value = "risks";
  staticGraphCenter.value = assetId || "";
  staticView.value = "graph";
}

// 切换扫描时清掉只对上一次扫描有意义的筛选。
watch(staticScanId, () => {
  ++detailRequest; clearTimeout(pollTimer); staticPolling.value = false; staticLoading.value = false;
  staticAssetFilter.value = ""; staticGraphCenter.value = "";
  staticScan.value = null; staticCoverage.value = null;
  staticAssets.value = []; staticAllFindings.value = [];
  staticAssetTotal.value = 0; staticFindingTotal.value = 0;
}, { flush: "sync" });

export async function openStaticAssetContext(asset, view = "findings") {
  staticPage.value = "risks"; staticView.value = view;
  staticScanId.value = asset.scan_id;
  staticSeverity.value = ""; staticFindingQuery.value = "";
  staticAssetFilter.value = view === "findings" ? asset.asset_id : "";
  staticGraphCenter.value = view === "graph" ? asset.asset_id : "";
  return loadStaticDetail();
}
