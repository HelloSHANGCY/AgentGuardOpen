<template>
  <section v-show="tab === 'rules'" class="rules-page">
    <ConsolePageHeader title="规则库" class="rl-page-head">
      <div class="rl-actions">
        <el-button :loading="refreshing" :disabled="busy" @click="reload"><el-icon class="btn-ic" aria-hidden="true"><Refresh /></el-icon>刷新规则库</el-button>
        <el-button :loading="sourceLoading" :disabled="busy || !selectedPack" @click="exportSelectedPack"><el-icon class="btn-ic" aria-hidden="true"><Download /></el-icon>导出 YAML</el-button>
        <el-button type="primary" :disabled="busy || !rulesLoaded" @click="openUpload"><el-icon class="btn-ic" aria-hidden="true"><Upload /></el-icon>导入 YAML</el-button>
      </div>
    </ConsolePageHeader>
    <div class="eval-controls" v-if="adminNeedsToken">
      <label>管理令牌<el-input size="small" v-model="adminToken" type="password" show-password autocomplete="off" aria-label="管理令牌" placeholder="AG_AGENT_ADMIN_TOKEN，仅保存在当前页面" @keyup.enter="reload" /></label>
      <el-button size="small" type="primary" :disabled="!adminToken || busy" @click="reload">加载</el-button>
    </div>
    <el-alert v-if="rulesError" :title="rulesError" type="error" show-icon class="my-12" @close="rulesError = ''" />
    <template v-if="rulesLoaded">
      <el-alert v-for="err in rulesData.errors" :key="err" type="warning" show-icon :closable="false" class="my-12" :title="'规则包加载失败（已跳过）：' + err" />
      <el-alert v-if="!rulesData.persistent" type="info" show-icon :closable="false" class="my-12" title="规则变更未持久化" />
      <div class="rl-overview">
        <section class="rl-card rl-stat-card"><div><h3>规则总数</h3><div class="rl-number">{{ ruleCount }}</div></div><span class="rl-stat-icon rl-stat-brand"><el-icon aria-hidden="true"><Collection /></el-icon></span><p class="rl-note">生效 {{ enabledCount }} · 未生效 {{ ruleCount - enabledCount }}</p></section>
        <section class="rl-card rl-stat-card"><div><h3>已生效规则</h3><div class="rl-number">{{ enabledCount }}</div></div><span class="rl-stat-icon rl-stat-green"><el-icon aria-hidden="true"><CircleCheck /></el-icon></span><p class="rl-note">生效率 {{ ruleCount ? Math.round(enabledCount / ruleCount * 100) + '%' : '—' }}</p></section>
        <section class="rl-card rl-stat-card"><div><h3>规则包</h3><div class="rl-number">{{ rulesData.packs.length }}</div></div><span class="rl-stat-icon rl-stat-warning"><el-icon aria-hidden="true"><Files /></el-icon></span><p class="rl-note">内置 {{ builtinCount }} · 自定义 {{ rulesData.packs.length - builtinCount }}</p></section>
        <section class="rl-card rl-stat-card rl-version-card"><div><h3>运行时规则版本</h3><strong class="rl-version mono">{{ rulesData.runtime_version || '—' }}</strong></div><span class="rl-stat-icon rl-stat-neutral"><el-icon aria-hidden="true"><Refresh /></el-icon></span><div class="rl-card-foot"><el-tag size="small" effect="plain" :type="rulesData.default ? 'info' : 'warning'">{{ rulesData.default ? '默认' : '已调整' }}</el-tag><span class="rl-note">{{ rulesData.persistent ? '已持久化' : '仅内存生效' }}</span><el-popconfirm v-if="!rulesData.default" title="恢复默认启停状态？自定义规则包保留，其中的规则恢复各自默认状态。" confirm-button-text="恢复" cancel-button-text="取消" @confirm="change('reset', resetRules, '已恢复默认启停状态')"><template #reference><el-button link type="primary" size="small" :disabled="busy">恢复默认</el-button></template></el-popconfirm></div></section>
      </div>
      <el-tabs v-model="activeTab" class="rl-tabs" aria-label="规则库管理">
        <el-tab-pane label="特征规则" name="features">
          <section class="rl-card rl-filter-card" aria-label="规则筛选">
            <div class="rl-filters">
              <el-input id="rl-search" v-model="query" clearable class="rl-search" aria-label="搜索规则" placeholder="搜索规则名 / ID / 描述 / 特征"><template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template></el-input>
              <el-select id="rl-scope" v-model="scope" clearable class="rl-scope-filter" aria-label="筛选检测范围" placeholder="全部范围"><el-option v-for="(label,key) in SCOPE_TEXT" :key="key" :label="label" :value="key" /></el-select>
              <el-select id="rl-group" v-model="group" clearable filterable class="rl-group-filter" aria-label="筛选特征组" placeholder="全部特征组"><el-option v-for="g in filterGroups" :key="g.group" :value="g.group" :label="g.title" /></el-select>
              <el-select id="rl-status" v-model="status" clearable class="rl-status-filter" aria-label="筛选生效状态" placeholder="全部状态"><el-option label="已生效" value="enabled" /><el-option label="未生效" value="disabled" /></el-select>
              <el-radio-group v-model="severity" class="rl-severity-filter" aria-label="筛选严重度"><el-radio-button value="">全部</el-radio-button><el-radio-button v-for="s in severities" :key="s" :value="s">{{ severityText(s) }}</el-radio-button></el-radio-group>
            </div>
            <div v-if="filtering" class="rl-filter-summary"><span class="rl-note">匹配 {{ matchedCount }} / {{ ruleCount }} 条 · {{ visiblePacks.length }} 个规则包</span><el-button link type="primary" size="small" @click="clearFilters">清除筛选</el-button></div>
          </section>
          <section class="rl-card rl-library" aria-labelledby="rl-library-title">
            <div class="rl-card-head rl-library-heading"><div><h3 id="rl-library-title"><el-icon aria-hidden="true"><Collection /></el-icon>特征规则</h3><p class="rl-note">{{ matchedCount }} / {{ ruleCount }} 条 · 已生效 {{ enabledCount }}</p></div><span class="rl-library-count">{{ visiblePacks.length }} 个规则包</span></div>
            <div v-if="selectedPack" class="rl-workspace">
              <aside class="rl-pack-list" aria-label="选择规则包">
                <h4 class="rl-pack-list-label">选择规则包</h4>
                <button v-for="pack in visiblePacks" :key="pack.pack" type="button" class="rl-pack-option" :class="{selected: selectedPack.pack === pack.pack}" :aria-pressed="selectedPack.pack === pack.pack" @click="selectedId = pack.pack">
                  <span class="rl-pack-name">{{ pack.name }}<el-tag size="small" effect="plain" :type="pack.builtin ? 'info' : 'success'">{{ pack.builtin ? '内置' : '自定义' }}</el-tag></span>
                  <span class="rl-note mono rl-pack-id">{{ pack.pack }}</span>
                  <span class="rl-pack-count"><span>{{ pack.enabled ? `${pack.enabled_rules} / ${pack.rules} 已生效` : '规则包已停用' }}</span><b v-if="filtering">匹配 {{ pack.visible.length }}</b></span>
                </button>
              </aside>
              <section class="rl-pack-detail" aria-labelledby="rl-pack-title">
                <div class="rl-pack-heading"><div class="rl-pack-heading-text"><h3 id="rl-pack-title">{{ selectedPack.name }}</h3><p class="rl-note mono">{{ selectedPack.pack }}{{ selectedPack.version ? ' · v' + selectedPack.version : '' }}</p></div><div class="rl-actions"><span class="rl-note">规则包启用</span><el-switch :model-value="selectedPack.enabled" size="small" :loading="mutation === 'pack:' + selectedPack.pack" :disabled="busy" :aria-label="'启用规则包 ' + selectedPack.name" @change="v => togglePack(selectedPack, v)" /></div></div>
                <p class="rl-pack-description" v-if="selectedPack.description">{{ selectedPack.description }}</p>
                <div class="rl-pack-meta"><span class="rl-note">共 {{ selectedPack.rules }} 条 · {{ selectedPack.enabled_rules }} 条生效<span v-if="filtering"> · 当前匹配 {{ selectedPack.visible.length }} 条</span></span><div class="rl-actions"><el-button link type="primary" size="small" :loading="sourceLoading" :disabled="busy" @click="showSource(selectedPack)">查看原文</el-button><el-popconfirm v-if="!selectedPack.builtin" :title="'删除规则包 ' + selectedPack.name + '？其中的特征立即失效。'" confirm-button-text="删除" cancel-button-text="取消" @confirm="removePack(selectedPack)"><template #reference><el-button link type="danger" size="small" :disabled="busy">删除规则包</el-button></template></el-popconfirm></div></div>
                <el-alert v-if="!selectedPack.enabled" class="rl-pack-alert" type="info" show-icon :closable="false" title="规则包已停用" />
                <el-table :data="pagedRules" size="small" stripe row-key="rule_id" class="rl-rules">
                  <el-table-column label="规则 ID" min-width="148" show-overflow-tooltip><template #default="{row}"><span class="mono rl-rule-id rl-rule-link">{{ row.rule_id }}</span></template></el-table-column>
                  <el-table-column label="规则名" min-width="180"><template #default="{row}"><div class="rl-rule-name"><span class="rl-rule-title">{{ row.title }}</span><el-tag v-if="row.rule_enabled !== row.default_enabled" size="small" effect="plain" type="warning">已调整</el-tag></div></template></el-table-column>
                  <el-table-column label="类别" min-width="142"><template #default="{row}"><span class="rl-group-tag" :class="'rl-group-' + groupOf(row.group).scope">{{ groupOf(row.group).title }}</span><div class="rl-note">{{ SCOPE_TEXT[groupOf(row.group).scope] || '—' }} · {{ row.patterns.length ? '正则' : '关键词' }} {{ featureList(row).length }} 条</div></template></el-table-column>
                  <el-table-column label="严重度" width="82"><template #default="{row}"><span class="rl-severity-tag" :class="'rl-severity-' + row.severity"><i aria-hidden="true" />{{ severityText(row.severity) }}</span></template></el-table-column>
                  <el-table-column width="100" align="right"><template #header><el-tooltip :content="hitStatsHint" :trigger="['hover', 'focus']" placement="top"><span class="rl-hits-heading" tabindex="0">命中次数<el-icon aria-hidden="true"><QuestionFilled /></el-icon></span></el-tooltip></template><template #default="{row}"><span class="rl-hit-count" :class="{'rl-hit-active': row.hit_count > 0}">{{ row.hit_count == null ? '—' : row.hit_count.toLocaleString('zh-CN') }}</span></template></el-table-column>
                  <el-table-column label="启用" width="62" align="center"><template #default="{row}"><el-switch :model-value="row.rule_enabled" size="small" :loading="mutation === 'rule:' + row.rule_id" :disabled="busy || !selectedPack.enabled" :aria-label="'启用规则 ' + row.rule_id" @change="v => toggleRule(row, v)" /></template></el-table-column>
                  <el-table-column label="操作" width="82" fixed="right"><template #default="{row}"><el-button link type="primary" size="small" @click="openRule(row)">查看详情</el-button></template></el-table-column>
                </el-table>
                <div class="rl-pager" v-if="selectedPack.visible.length > 10"><el-pagination background size="small" layout="total, sizes, prev, pager, next" :pager-count="5" :page-sizes="[10,20,50]" :total="selectedPack.visible.length" v-model:current-page="page" v-model:page-size="pageSize" /></div>
              </section>
            </div>
            <el-empty v-else :description="filtering ? '没有符合筛选条件的规则' : '暂无可用规则包'" :image-size="72"><el-button v-if="filtering" size="small" @click="clearFilters">清除筛选</el-button></el-empty>
          </section>
        </el-tab-pane>
        <el-tab-pane label="内置策略" name="strategies">
          <section class="rl-card">
            <div class="rl-card-head"><h3>内置策略 <span class="rl-note">{{ filteredStrategies.length }} 条</span></h3><el-input v-model="strategyQuery" clearable class="rl-strategy-search" aria-label="搜索内置策略" placeholder="搜索策略名 / ID / 触发条件"><template #prefix><el-icon aria-hidden="true"><Search /></el-icon></template></el-input></div>
            <el-table :data="filteredStrategies" size="small" row-key="rule_id" empty-text="没有匹配的内置策略">
              <el-table-column prop="rule_id" label="策略 ID" width="180"><template #default="{row}"><span class="mono">{{ row.rule_id }}</span></template></el-table-column>
              <el-table-column prop="title" label="策略名" min-width="180" />
              <el-table-column prop="condition" label="触发条件" min-width="320" />
              <el-table-column label="操作" width="90"><template #default="{row}"><el-button link type="primary" size="small" @click="openStrategy(row.rule_id)">查看详情</el-button></template></el-table-column>
            </el-table>
          </section>
        </el-tab-pane>
        <el-tab-pane label="样本测试" name="test">
          <div class="rl-test-layout">
            <section class="rl-card"><div class="rl-card-head"><h3>测试输入</h3></div><el-form label-position="top" size="small" @submit.prevent="runTest">
              <el-form-item label="测试样本"><el-input v-model="sample" type="textarea" :rows="7" resize="vertical" :maxlength="4000" show-word-limit :disabled="testing" class="mono rl-editor" aria-label="测试样本" placeholder="输入路径、命令或文本，例如 ~/.aws/credentials" /></el-form-item>
              <el-form-item label="特征组"><el-select v-model="sampleGroup" size="small" clearable filterable :disabled="testing" placeholder="全部特征组" aria-label="测试特征组"><el-option-group v-for="s in ['runtime','static']" :key="s" :label="SCOPE_TEXT[s]"><el-option v-for="g in groupsOf(s)" :key="g.group" :value="g.group" :label="g.title" /></el-option-group></el-select></el-form-item>
              <div class="rl-actions"><el-button size="small" type="primary" native-type="submit" :loading="testing" :disabled="busy || !sample.trim()">测试样本</el-button><el-button size="small" :disabled="testing || !sample" @click="sample = ''">清空</el-button></div>
            </el-form><el-alert v-if="testError" :title="testError" type="error" :closable="false" show-icon class="my-12" /></section>
            <section class="rl-card rl-test-results" aria-live="polite"><div class="rl-card-head"><h3>命中结果</h3><span class="rl-note" v-if="testHits !== null">{{ testHits.length }} 条命中 · {{ testEnabledCount }} 条已生效</span></div><p class="rl-note mono rl-tested-version" v-if="testHits !== null">测试版本 {{ testedVersion }}</p>
              <el-table v-if="testHits !== null" :data="testHits" size="small" empty-text="没有规则命中这个样本">
                <el-table-column label="规则" min-width="190"><template #default="{row}"><div class="rl-rule-title">{{ row.title }}</div><div class="mono rl-rule-id">{{ row.rule_id }}</div><el-tag size="small" effect="plain" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '已生效' : '未生效' }}</el-tag></template></el-table-column>
                <el-table-column label="特征组 / 严重度" min-width="145"><template #default="{row}"><div>{{ groupOf(row.group).title }}</div><span :class="'sev-tag sev-' + row.severity">{{ row.severity }}</span></template></el-table-column>
                <el-table-column label="命中特征" min-width="200"><template #default="{row}"><div class="rl-pats"><code v-for="m in row.matched" :key="m" class="rl-pat">{{ m }}</code></div></template></el-table-column>
              </el-table><el-empty v-else description="暂无测试结果" :image-size="72" />
            </section>
          </div>
        </el-tab-pane>
        <el-tab-pane label="变更记录" name="history"><section class="rl-card"><div class="rl-card-head"><h3>最近变更</h3></div><el-table :data="pagedHistory" size="small" empty-text="暂无规则变更记录"><el-table-column label="时间" width="170"><template #default="{row}"><span class="mono">{{ fmt(row.at) }}</span></template></el-table-column><el-table-column label="操作" width="120"><template #default="{row}">{{ ACTION_TEXT[row.action] || row.action }}</template></el-table-column><el-table-column label="对象" min-width="240"><template #default="{row}"><span class="mono rl-wrap">{{ row.target || '—' }}</span></template></el-table-column><el-table-column label="变更内容" min-width="240"><template #default="{row}"><span class="rl-wrap">{{ row.detail || '—' }}</span></template></el-table-column></el-table><div class="rl-pager" v-if="rulesData.history.length > 10"><el-pagination background size="small" layout="total, prev, pager, next" :pager-count="5" :total="rulesData.history.length" :page-size="10" v-model:current-page="historyPage" /></div></section></el-tab-pane>
      </el-tabs>
    </template>
    <el-skeleton v-else-if="!adminNeedsToken" :rows="6" animated />

    <el-dialog v-model="ruleDialog" title="特征规则详情" class="detail-dialog rl-rule-dialog" width="min(760px, 94vw)" top="6vh" append-to-body>
      <template v-if="detailRule">
        <el-alert v-if="rulesRevision && rulesRevision !== detailRule.revision" title="当前规则与告警记录的特征版本不同；本页展示当前规则。" type="warning" :closable="false" show-icon class="my-12" />
        <div class="rl-detail-title"><h3>{{ detailRule.title }}</h3><span :class="'sev-tag sev-' + detailRule.severity">{{ detailRule.severity }}</span><el-tag size="small" effect="plain" :type="detailRule.enabled ? 'success' : 'info'">{{ detailRule.enabled ? '已生效' : '未生效' }}</el-tag></div>
        <p class="rl-note mono">{{ detailRule.rule_id }} · {{ detailRule.pack_version ? 'v' + detailRule.pack_version + ' · ' : '' }}{{ detailRule.revision }}</p><p v-if="detailRule.description" class="rl-wrap">{{ detailRule.description }}</p>
        <dl class="rl-detail-meta"><dt>所属规则包</dt><dd>{{ detailPack?.name }}<span class="rl-note mono">{{ detailRule.pack }}</span></dd><dt>特征组</dt><dd>{{ groupOf(detailRule.group).title }}<span class="rl-note mono">{{ detailRule.group }}</span></dd><dt>使用方</dt><dd>{{ groupOf(detailRule.group).used_by || '—' }}</dd><dt>规则标签</dt><dd class="mono">{{ detailRule.tag || '—' }}</dd><dt>默认状态</dt><dd>{{ detailRule.default_enabled ? '启用' : '停用' }}<span class="rl-note"> · {{ detailPack?.enabled ? '规则包已启用' : '规则包已停用' }}</span></dd></dl>
        <h4 class="rl-section-title">{{ detailRule.patterns.length ? '正则特征' : '关键词特征' }} · {{ featureList(detailRule).length }} 条</h4><div class="rl-detail-features"><div v-for="(p,i) in featureList(detailRule)" :key="i"><code>{{ p.text }}</code><span v-if="p.flags" class="rl-note mono">flags: {{ p.flags }}</span></div></div>
      </template><el-alert v-else :title="'当前规则库中没有特征规则 ' + detailId" type="warning" :closable="false" show-icon /><template #footer><el-button size="small" @click="ruleDialog = false">关闭</el-button></template>
    </el-dialog>
    <el-dialog v-model="strategyDialog" title="内置策略详情" class="detail-dialog" width="min(760px, 94vw)" top="6vh" append-to-body>
      <template v-if="detailStrategy">
        <div class="rl-detail-title"><h3>{{ detailStrategy.title }}</h3><el-tag size="small" effect="plain" type="info">内置</el-tag></div>
        <p class="mono">{{ detailStrategy.rule_id }}</p>
        <dl class="rl-detail-meta"><dt>触发条件</dt><dd>{{ detailStrategy.condition }}</dd><dt>特征组</dt><dd v-if="detailStrategy.groups.length" class="rl-strategy-groups"><el-button v-for="g in detailStrategy.groups" :key="g" link type="primary" @click="showStrategyGroup(g)">{{ groupOf(g).title }}</el-button></dd><dd v-else>无直接特征组依赖</dd><dt>运行时规则版本</dt><dd class="mono">{{ rulesData.runtime_version }}</dd></dl>
      </template>
      <el-alert v-else :title="'当前服务未提供策略 ' + rulesTarget + ' 的定义'" type="warning" :closable="false" show-icon />
      <template #footer><el-button size="small" @click="strategyDialog = false">关闭</el-button></template>
    </el-dialog>
    <el-dialog v-model="uploadDialog" title="上传自定义规则包" class="detail-dialog rl-upload-dialog" width="min(840px, 94vw)" top="6vh" append-to-body :close-on-click-modal="false" :close-on-press-escape="!uploading && !readingFile" :show-close="!uploading && !readingFile">

      <div class="rl-upload-bar"><el-button size="small" :loading="readingFile" :disabled="uploading || readingFile" @click="fileInput?.click()">选择文件</el-button><el-button size="small" :disabled="uploading || readingFile" @click="fillTemplate">填入模板</el-button><input ref="fileInput" type="file" accept=".yaml,.yml,text/yaml" class="rl-file" @change="readFile" /><span class="rl-note rl-wrap">{{ uploadName || '未选择文件' }}</span></div>
      <label for="rl-upload-content" class="rl-field-label">规则包内容</label><el-input id="rl-upload-content" v-model="uploadText" type="textarea" :rows="15" :disabled="uploading || readingFile" class="mono rl-editor" spellcheck="false" aria-label="规则包内容" placeholder="粘贴规则包 YAML，或选择文件 / 填入模板" /><p class="rl-note" :class="{'c-crit': uploadTooLarge}">{{ uploadKB }} / {{ rulesData.limits.pack_kb || 256 }} KB<span v-if="uploadTooLarge"> · 内容超过上传限制</span></p>
      <el-alert v-if="uploadError" :title="uploadError" type="error" show-icon :closable="false" class="my-12" /><template #footer><el-button size="small" :disabled="uploading || readingFile" @click="uploadDialog = false">取消</el-button><el-button size="small" type="primary" :loading="uploading" :disabled="busy || readingFile || !uploadText.trim() || uploadTooLarge" @click="submitUpload">校验并上传</el-button></template>
    </el-dialog>
    <el-dialog v-model="sourceDialog" :title="sourcePack?.name || '规则包原文'" class="detail-dialog rl-source-dialog" width="min(900px, 94vw)" top="6vh" append-to-body><p class="rl-note mono rl-wrap">{{ sourcePack?.pack }} · YAML 原文</p><pre class="rl-source mono">{{ sourceText }}</pre><template #footer><el-button size="small" @click="downloadSource">下载 YAML</el-button><el-button size="small" type="primary" @click="sourceDialog = false">关闭</el-button></template></el-dialog>
  </section>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { CircleCheck, Download } from "../icons";
import { tab, rulesTab as activeTab, rulesTarget, rulesRevision, openRuleTarget } from "../store/runtime";
import { adminNeedsToken, adminToken } from "../store/devices";
import { ACTION_TEXT, SCOPE_TEXT, deletePack, packSource, packTemplate, refreshRules, resetRules, rulesData, rulesError, rulesLoaded, setPack, setRule, testSample, uploadPack } from "../store/rules";
import { fmt } from "../utils/format";
import "./rules/rules.css";

const refreshing = ref(false), mutation = ref(""), sourceLoading = ref(false);
const testing = ref(false), uploading = ref(false), readingFile = ref(false);
const busy = computed(() => refreshing.value || Boolean(mutation.value) || testing.value || uploading.value || readingFile.value || sourceLoading.value);
async function reload() {
  if (busy.value) return;
  refreshing.value = true;
  try { await refreshRules(); } finally { refreshing.value = false; }
}
watch(tab, t => { if (t === "rules") reload(); }, { immediate: true });
async function change(key, action, message) {
  if (busy.value) return;
  mutation.value = key;
  try { if (await action()) ElMessage.success(message); }
  finally { mutation.value = ""; }
}
const togglePack = (pack, value) => change('pack:' + pack.pack, () => setPack(pack.pack, value), `规则包已${value ? '启用' : '停用'}`);
const toggleRule = (rule, value) => change('rule:' + rule.rule_id, () => setRule(rule.rule_id, value), `规则 ${rule.rule_id} 已${value ? '启用' : '停用'}`);
const removePack = pack => change('delete:' + pack.pack, () => deletePack(pack.pack), '已删除规则包 ' + pack.name);

const groupMap = computed(() => Object.fromEntries(rulesData.value.groups.map(g => [g.group, g])));
const groupOf = name => groupMap.value[name] || { title: name, used_by: "", scope: "" };
const groupsOf = scope => rulesData.value.groups.filter(g => g.scope === scope);
const builtinCount = computed(() => rulesData.value.packs.filter(p => p.builtin).length);
const ruleCount = computed(() => rulesData.value.packs.reduce((n,p) => n + p.rules, 0));
const enabledCount = computed(() => rulesData.value.packs.reduce((n,p) => n + p.enabled_rules, 0));
const hitStatsHint = computed(() => rulesData.value.hit_stats?.error
  ? '命中统计暂不可用：' + rulesData.value.hit_stats.error
  : '服务端检测与静态扫描中的特征匹配次数；同一操作多次检查可累计。规则自检与样本测试不计入。' + (rulesData.value.hit_stats?.since ? ' 统计起点：' + fmt(rulesData.value.hit_stats.since) : ''));
const featureList = row => row.patterns.length ? row.patterns.map(p => ({text:p.re, flags:p.flags})) : row.keywords.map(k => ({text:k, flags:""}));
const scope = ref(""), group = ref(""), severity = ref(""), status = ref(""), query = ref("");
const filterGroups = computed(() => rulesData.value.groups.filter(g => !scope.value || g.scope === scope.value));
const severities = computed(() => {
  const values = new Set(rulesData.value.packs.flatMap(p => p.items.map(r => r.severity)));
  return [...new Set(['CRITICAL','HIGH','MEDIUM','LOW','INFO', ...values])].filter(s => values.has(s));
});
const severityText = value => ({ CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '信息' }[value] || value);
const filtering = computed(() => Boolean(query.value.trim() || scope.value || group.value || severity.value || status.value));
const visiblePacks = computed(() => {
  const q = query.value.trim().toLowerCase();
  return rulesData.value.packs.map(pack => ({...pack, visible: pack.items.filter(r => {
    if (scope.value && groupOf(r.group).scope !== scope.value || group.value && r.group !== group.value) return false;
    if (severity.value && r.severity !== severity.value) return false;
    if (status.value === 'disabled' && r.enabled || status.value === 'enabled' && !r.enabled) return false;
    return !q || [r.rule_id, r.title, r.description, r.group, groupOf(r.group).title, r.tag, pack.name, pack.pack, ...featureList(r).map(f => f.text)].some(s => String(s || '').toLowerCase().includes(q));
  })})).filter(p => p.visible.length);
});
const matchedCount = computed(() => visiblePacks.value.reduce((n,p) => n + p.visible.length, 0));
const selectedId = ref("");
const selectedPack = computed(() => visiblePacks.value.find(p => p.pack === selectedId.value) || visiblePacks.value[0] || null);
watch(() => selectedPack.value?.pack, id => { if (id) selectedId.value = id; });
const page = ref(1), pageSize = ref(10), historyPage = ref(1);
const pagedRules = computed(() => selectedPack.value?.visible.slice((page.value-1)*pageSize.value, page.value*pageSize.value) || []);
const pagedHistory = computed(() => rulesData.value.history.slice((historyPage.value-1)*10, historyPage.value*10));
watch([query, scope, group, severity, status, selectedId, pageSize], () => { page.value = 1; });
watch(filterGroups, groups => { if (group.value && !groups.some(g => g.group === group.value)) group.value = ''; });
watch(() => selectedPack.value?.visible.length, count => { page.value = Math.min(page.value, Math.max(1, Math.ceil((count || 0)/pageSize.value))); });
watch(() => rulesData.value.history.length, count => { historyPage.value = Math.min(historyPage.value, Math.max(1, Math.ceil(count/10))); });
function clearFilters() { query.value = scope.value = group.value = severity.value = status.value = ''; }

const ruleDialog = ref(false), detailId = computed(() => rulesTarget.value);
const detailPack = computed(() => rulesData.value.packs.find(p => p.items.some(r => r.rule_id === detailId.value)));
const detailRule = computed(() => detailPack.value?.items.find(r => r.rule_id === detailId.value));
function openRule(rule) { openRuleTarget(rule.rule_id); }
const strategyQuery = ref(''), strategyDialog = ref(false);
const strategies = computed(() => rulesData.value.strategies || []);
const filteredStrategies = computed(() => {
  const q = strategyQuery.value.trim().toLowerCase();
  return strategies.value.filter(s => !q || [s.rule_id, s.title, s.condition].some(v => v.toLowerCase().includes(q)));
});
const detailStrategy = computed(() => strategies.value.find(s => s.rule_id === rulesTarget.value));
function openStrategy(id) { openRuleTarget(id, 'strategies'); }
function showStrategyGroup(g) {
  clearFilters();
  group.value = g;
  rulesTarget.value = rulesRevision.value = '';
  activeTab.value = 'features';
}
watch([tab, activeTab, rulesTarget, rulesLoaded], () => {
  const ready = tab.value === 'rules' && rulesLoaded.value && Boolean(rulesTarget.value);
  ruleDialog.value = ready && activeTab.value === 'features';
  strategyDialog.value = ready && activeTab.value === 'strategies';
}, {immediate:true});
watch([rulesTarget, detailRule], ([id, rule]) => {
  if (!id || !rule || activeTab.value !== 'features') return;
  clearFilters();
  selectedId.value = rule.pack;
  const index = detailPack.value.items.findIndex(r => r.rule_id === id);
  page.value = Math.floor(index / pageSize.value) + 1;
});
watch(ruleDialog, value => { if (!value && tab.value === 'rules' && activeTab.value === 'features') rulesTarget.value = rulesRevision.value = ''; });
watch(strategyDialog, value => { if (!value && tab.value === 'rules' && activeTab.value === 'strategies') rulesTarget.value = rulesRevision.value = ''; });
watch(activeTab, (value, previous) => {
  if (rulesTarget.value && ((value === 'features' && previous === 'strategies' && detailStrategy.value)
      || (value === 'strategies' && previous === 'features' && detailRule.value)
      || !['features', 'strategies'].includes(value))) rulesTarget.value = rulesRevision.value = '';
});

const sample = ref(""), sampleGroup = ref(""), testHits = ref(null), testError = ref(""), testedVersion = ref("");
const testEnabledCount = computed(() => testHits.value?.filter(h => h.enabled).length || 0);
watch([sample, sampleGroup, () => rulesData.value.runtime_version], () => { testHits.value = null; testError.value = ''; });
async function runTest() {
  if (busy.value || !sample.value.trim()) return;
  const snapshot = { sample:sample.value, group:sampleGroup.value, version:rulesData.value.runtime_version };
  testing.value = true; testHits.value = null; testError.value = '';
  try {
    const hits = await testSample(snapshot.sample, snapshot.group);
    if (snapshot.sample === sample.value && snapshot.group === sampleGroup.value && snapshot.version === rulesData.value.runtime_version) {
      testHits.value = hits; testedVersion.value = snapshot.version;
    }
  } catch (e) { if (e.status === 401) adminNeedsToken.value = true; testError.value = e.message; }
  finally { testing.value = false; }
}

const uploadDialog = ref(false), uploadText = ref(""), uploadName = ref(""), uploadError = ref(""), fileInput = ref(null);
const uploadBytes = computed(() => new TextEncoder().encode(uploadText.value).length);
const uploadKB = computed(() => (uploadBytes.value/1024).toFixed(1));
const uploadTooLarge = computed(() => uploadBytes.value > (rulesData.value.limits.pack_kb || 256)*1024);
function openUpload() { if (!busy.value) { uploadError.value = ''; uploadDialog.value = true; } }
function fillTemplate() { if (uploading.value || readingFile.value) return; uploadText.value = packTemplate(rulesData.value.groups); uploadName.value = ''; uploadError.value = ''; }
function readFile(event) {
  const file = event.target.files?.[0]; event.target.value = '';
  if (!file || uploading.value || readingFile.value) return;
  const limitKB = rulesData.value.limits.pack_kb || 256;
  if (file.size > limitKB*1024) { uploadError.value = `文件超过 ${limitKB} KB`; return; }
  readingFile.value = true;
  const reader = new FileReader();
  reader.onload = () => { uploadText.value = String(reader.result || ''); uploadName.value = file.name; uploadError.value = ''; };
  reader.onerror = () => { uploadError.value = '文件读取失败，请重试或粘贴 YAML 内容'; };
  reader.onloadend = () => { readingFile.value = false; };
  reader.readAsText(file, 'utf-8');
}
async function submitUpload() {
  if (busy.value || !uploadText.value.trim() || uploadTooLarge.value) return;
  uploading.value = true; uploadError.value = '';
  try {
    const view = await uploadPack(uploadText.value);
    ElMessage.success(`已加载规则包 ${view.name}：${view.enabled_rules} 条规则生效`);
    clearFilters(); selectedId.value = view.pack; activeTab.value = 'library';
    uploadDialog.value = false; uploadText.value = uploadName.value = '';
  } catch (e) { if (e.status === 401) adminNeedsToken.value = true; uploadError.value = e.message; }
  finally { uploading.value = false; }
}
const sourceDialog = ref(false), sourcePack = ref(null), sourceText = ref("");
async function showSource(pack) {
  if (busy.value) return;
  rulesError.value = '';
  sourceLoading.value = true;
  try { sourceText.value = await packSource(pack.pack); sourcePack.value = pack; sourceDialog.value = true; }
  catch (e) { if (e.status === 401) adminNeedsToken.value = true; rulesError.value = e.message; }
  finally { sourceLoading.value = false; }
}
async function exportSelectedPack() {
  const pack = selectedPack.value;
  if (!pack || busy.value) return;
  rulesError.value = ''; sourceLoading.value = true;
  try { downloadYaml(pack, await packSource(pack.pack)); }
  catch (e) { if (e.status === 401) adminNeedsToken.value = true; rulesError.value = e.message; }
  finally { sourceLoading.value = false; }
}
function downloadYaml(pack, content) {
  const url = URL.createObjectURL(new Blob([content], {type:'text/yaml;charset=utf-8'}));
  const link = Object.assign(document.createElement('a'), {href:url, download:pack.pack + '.yaml'});
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function downloadSource() { if (sourcePack.value) downloadYaml(sourcePack.value, sourceText.value); }
</script>
