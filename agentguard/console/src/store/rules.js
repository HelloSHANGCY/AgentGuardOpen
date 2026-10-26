// 特征规则库：YAML 规则包的启停、样本测试、上传与删除（/v1/admin/rules、/v1/admin/rule-packs）。
// 管理令牌与设备管理共用；停用规则会削弱检测，变更即时生效并改变运行时规则版本。
import { ref } from "vue";
import { adminJson, adminNeedsToken } from "./devices";

export const rulesData = ref({ packs: [], groups: [], strategies: [], errors: [], history: [], default: true, runtime_version: "",
  persistent: false, limits: {} });
export const rulesLoaded = ref(false);
export const rulesError = ref("");

export const SCOPE_TEXT = { runtime: "运行时", static: "静态扫描" };
export const SAMPLE_TEXT = { path: "路径", command: "命令", text: "文本", key: "配置键名", value: "取值" };
export const ACTION_TEXT = {
  enable_rule: "启用规则", disable_rule: "停用规则", enable_pack: "启用规则包", disable_pack: "停用规则包",
  add_pack: "上传规则包", replace_pack: "替换规则包", remove_pack: "删除规则包", reset: "恢复默认",
};

function fail(e) {
  if (e.status === 401) adminNeedsToken.value = true;
  rulesError.value = e.message;
}

export async function refreshRules() {
  try {
    rulesData.value = await adminJson("/rules");
    rulesError.value = "";
    rulesLoaded.value = true;
    return true;
  } catch (e) { fail(e); return false; }
}

// 启停后整体刷新：规则包的已启用计数、规则版本与变更记录都会变化。
async function mutate(path, options) {
  try {
    await adminJson(path, options);
    return await refreshRules();
  } catch (e) { fail(e); return false; }
}

export const setRule = (ruleId, enabled) =>
  mutate("/rules/" + encodeURIComponent(ruleId), { method: "PUT", body: JSON.stringify({ enabled }) });

export const setPack = (packId, enabled) =>
  mutate("/rule-packs/" + encodeURIComponent(packId), { method: "PUT", body: JSON.stringify({ enabled }) });

export const resetRules = () => mutate("/rules/reset", { method: "POST" });

export const deletePack = (packId) => mutate("/rule-packs/" + encodeURIComponent(packId), { method: "DELETE" });

// 上传失败（校验不通过）时把服务端的具体原因抛给调用方，在上传弹窗内展示。
export async function uploadPack(content) {
  const view = await adminJson("/rule-packs", { method: "POST", body: JSON.stringify({ content }) });
  await refreshRules();
  return view;
}

export async function testSample(sample, group) {
  return (await adminJson("/rules/test", { method: "POST", body: JSON.stringify({ sample, group }) })).hits;
}

export async function packSource(packId) {
  return (await adminJson("/rule-packs/" + encodeURIComponent(packId) + "/source")).content;
}

// 自定义规则包模板：列出全部特征组，示例规则可直接通过上传校验。
export function packTemplate(groups) {
  const lines = groups.map((g) => `#   ${g.group.padEnd(28)} ${g.kind === "regex" ? "patterns" : "keywords"}` +
    `  ${g.title}（${g.used_by}）`);
  return `# AgentGuard 自定义特征规则包
# 规则加入代码中已定义的特征组；正则用单引号书写，flags 可选 i / m / s。
# tests.match 中的样本必须命中、tests.nomatch 中的不得命中，上传时自检。
# 可用特征组：
${lines.join("\n")}
format: 1
pack: team-signatures          # 小写字母、数字、. _ -；不能以 builtin 开头
name: 团队补充特征
version: "1"
description: 示例：补充内部凭证目录与注入暗号
rules:
  - id: TEAM-CRED-001
    group: path.credential_store
    title: 内部凭证目录
    severity: CRITICAL
    patterns:
      - '(^|/)\\.corp-vault/'
    tests:
      match: ["~/.corp-vault/token"]
      nomatch: ["/srv/docs/corp-vault.md"]
  - id: TEAM-INJ-001
    group: content.injection_marker
    title: 内部注入暗号
    severity: HIGH
    keywords: ["sudo mode activated"]
`;
}
