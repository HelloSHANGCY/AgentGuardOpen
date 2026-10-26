<template>
  <div class="rule-proposals">
    <div class="filters">
      <el-radio-group v-model="fStatus" size="small" aria-label="建议状态">
        <el-radio-button value="pending">待审批 {{ counts.pending }}</el-radio-button>
        <el-radio-button value="approved">已批准 {{ counts.approved }}</el-radio-button>
        <el-radio-button value="rejected">已拒绝 {{ counts.rejected }}</el-radio-button>
      </el-radio-group>
      <el-button size="small" :disabled="!!busy" @click="refreshJudge"><el-icon class="btn-ic"><Refresh /></el-icon>刷新建议</el-button>
    </div>

    <el-table :data="rows" size="small" row-key="proposal_id" class="alert-table proposal-table" @row-click="open"
              :empty-text="fStatus === 'pending' ? '没有待审批的规则建议' : '暂无记录'">
      <el-table-column label="时间" width="150">
        <template #default="{ row }">
          <div class="mono">{{ fmtTime(row.decided_at || row.created_at) }}</div>
          <div class="muted fs-11 mono">{{ fmt(row.decided_at || row.created_at).slice(0, 10) }}</div>
        </template>
      </el-table-column>
      <el-table-column label="规则" min-width="240">
        <template #default="{ row }">
          <div class="al-title">{{ row.rule.title }}<span v-if="row.rule_id" class="code-hint">{{ row.rule_id }}</span></div>
          <div class="muted fs-11">{{ row.group_title }} · {{ row.rule.severity }}</div>
        </template>
      </el-table-column>
      <el-table-column label="特征" min-width="260">
        <template #default="{ row }">
          <div class="mono ellipsis" :title="features(row).join('\n')">{{ features(row).join('  ') }}</div>
          <div class="muted fs-11 ellipsis" :title="row.finding">{{ row.finding || '-' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="检查" width="170">
        <template #default="{ row }">
          <div :class="row.problems?.length ? 'c-med' : 'c-ok'">{{ row.problems?.length ? `${row.problems.length} 项问题` : '全部通过' }}
            <span class="muted fs-11">· {{ row.history?.length || 1 }} 轮</span></div>
          <div class="muted fs-11" v-if="row.checks.replay && !row.checks.replay.error && !row.checks.replay.skipped">
            回放误报 {{ row.checks.replay.benign_blocked }} · 新覆盖 {{ row.checks.replay.newly_detected?.length || 0 }}</div>
        </template>
      </el-table-column>
      <el-table-column label="来源会话" width="180">
        <template #default="{ row }">
          <el-button link type="primary" class="mono ellipsis al-trace" :title="'查看会话链路：' + row.trace_id"
                     @click.stop="openChain(row.trace_id)">{{ scenarioOf(row.trace_id) }}</el-button>
          <div class="muted fs-11">{{ row.round ? `第 ${row.round} 轮` : '整个会话' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="86" fixed="right"><template #default="{row}"><el-button link type="primary" size="small" @click.stop="open(row)">查看详情</el-button></template></el-table-column>
    </el-table>
    <div class="proposal-cards">
      <p v-if="!rows.length" class="proposal-empty">{{ fStatus === 'pending' ? '没有待审批的规则建议' : '暂无记录' }}</p>
      <article v-for="row in rows" :key="row.proposal_id" class="proposal-card">
        <div class="proposal-card-head"><strong>{{ row.rule.title }}</strong><el-tag size="small" effect="plain" :type="PROPOSAL_STATUS[row.status].tag">{{ PROPOSAL_STATUS[row.status].label }}</el-tag></div>
        <p class="proposal-intro">{{ row.group_title }} · {{ row.rule.severity }}{{ row.rule_id ? ' · ' + row.rule_id : '' }}</p>
        <p class="proposal-features mono">{{ features(row).join(' · ') }}</p><p v-if="row.finding" class="proposal-intro">{{ row.finding }}</p>
        <p class="proposal-intro" :class="row.problems?.length ? 'c-med' : 'c-ok'">{{ row.problems?.length ? `${row.problems.length} 项问题` : '检查全部通过' }} · {{ row.history?.length || 1 }} 轮</p>
        <div class="proposal-card-foot"><el-button link type="primary" size="small" class="mono" :title="row.trace_id" @click="openChain(row.trace_id)">{{ scenarioOf(row.trace_id) }}</el-button><el-button size="small" @click="open(row)">查看详情</el-button></div>
      </article>
    </div>

    <el-dialog v-model="visible" class="detail-dialog proposal-dialog" width="min(800px, 94vw)" top="5vh" :close-on-click-modal="!busy" :close-on-press-escape="!busy" :show-close="!busy" append-to-body destroy-on-close>
      <template #header="{titleId}">
        <div v-if="item" :id="titleId" class="dd-head">
          <div class="dd-title-row">
            <el-tag size="small" :type="PROPOSAL_STATUS[item.status].tag" effect="dark">{{ PROPOSAL_STATUS[item.status].label }}</el-tag>
            <span class="sev-tag" :class="'sev-' + item.rule.severity">{{ item.rule.severity }}</span>
            <span class="dd-title">{{ item.rule.title }}</span>
          </div>
          <div class="dd-subtitle">{{ item.group_title }} <span class="mono">{{ item.rule.group }}</span>
            · 来自 {{ scenarioOf(item.trace_id) }}{{ item.round ? ` 第 ${item.round} 轮` : '' }} · {{ fmt(item.created_at) }}</div>
        </div>
      </template>
      <div v-if="item" class="dd-body">
        <div class="dd-callout dd-callout-ASK">
          <div class="dd-callout-label">命中后</div><div class="dd-callout-text">{{ item.effect }}</div>
        </div>
        <div v-if="item.rationale" class="dd-callout">
          <div class="dd-callout-label">模型的理由<template v-if="item.finding"> · 针对「{{ item.finding }}」</template></div>
          <div class="dd-callout-text">{{ item.rationale }}</div>
        </div>
        <div v-if="item.status !== 'pending'" class="dd-callout" :class="item.status === 'approved' ? 'dd-callout-ALLOW' : ''">
          <div class="dd-callout-label">{{ PROPOSAL_STATUS[item.status].label }} · {{ fmt(item.decided_at) }}</div>
          <div class="dd-callout-text">
            <template v-if="item.rule_id">已写入规则库，编号 <span class="mono">{{ item.rule_id }}</span></template>
            {{ item.note }}</div>
        </div>

        <section class="dd-section" v-if="item.history?.length">
          <h4 class="dd-section-title">生成过程 <span class="dd-count">{{ item.history.length }} 轮</span></h4>
          <ul class="dd-list">
            <li v-for="h in item.history" :key="h.round" class="dd-rule">
              <div class="dd-rule-head">
                <el-tag size="small" effect="plain" :type="h.role === '主 agent' ? 'primary' : 'warning'">第 {{ h.round }} 轮 · {{ h.role }}</el-tag>
                <span :class="h.problems.length ? 'c-med' : 'c-ok'">{{ h.problems.length ? h.problems.join('；') : '检查通过' }}</span>
              </div>
              <div v-if="h.notes" class="fs-12 mt-6">{{ h.notes }}</div>
              <div v-if="h.accepted" class="fs-12 mt-6 c-med">子 agent 认可残留命中：{{ h.accepted }}</div>
              <details class="mt-6"><summary class="fs-11 muted">这一轮的规则</summary><pre class="dd-code">{{ h.yaml }}</pre></details>
            </li>
          </ul>
        </section>

        <ProposalChecks :checks="item.checks" :problems="item.problems || []"
                        :title="item.problems?.length ? '优化后仍有问题，请审慎审批' : '检查结果'" />

        <section class="dd-section">
          <h4 class="dd-section-title">规则{{ item.status === 'pending' ? '（可修改后批准）' : '' }}</h4>
          <el-input v-model="draft" type="textarea" :autosize="{ minRows: 8, maxRows: 22 }" class="mono"
                    :readonly="item.status !== 'pending' || !!busy" aria-label="规则 YAML"></el-input>

          <el-input v-if="item.status === 'pending'" v-model="note" :disabled="!!busy" size="small" placeholder="审批备注（可选）" class="mt-6"
                    aria-label="审批备注"></el-input>
          <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="mt-6"></el-alert>
        </section>
        <ProposalChecks v-if="recheck" :checks="recheck.checks" :problems="recheck.problems" title="修改后的检查结果" class="mt-10" />
      </div>
      <template #footer>
        <div class="proposal-dialog-actions"><el-button size="small" :disabled="!!busy" @click="visible = false">关闭</el-button>
        <template v-if="item?.status === 'pending'">
          <el-button size="small" :disabled="!!busy" :loading="busy === 'check'" @click="recheckDraft">重新检查</el-button>
          <el-button size="small" :disabled="!!busy" :loading="busy === 'reject'" @click="decide('reject')">拒绝</el-button>
          <el-button size="small" type="primary" :disabled="!!busy" :loading="busy === 'approve'" @click="decide('approve')">批准并启用</el-button>
        </template>
        <el-button v-else-if="item?.rule_id" size="small" type="primary" @click="goRules">到规则库查看</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
// 大模型规则建议的审批：列表、证据与误报试跑、可修改的规则 YAML、批准 / 拒绝。
import { ref, computed } from "vue";
import { ElMessage } from "element-plus";
import { tab, fmt, fmtTime, scenarioOf, openChain } from "../store/runtime";
import ProposalChecks from "./ProposalChecks.vue";
import { judgeProposals, PROPOSAL_STATUS, decideProposal, refreshJudge, checkProposal } from "../store/judge";

const fStatus = ref("pending");
const counts = computed(() => {
  const out = { pending: 0, approved: 0, rejected: 0 };
  for (const p of judgeProposals.value) out[p.status] = (out[p.status] || 0) + 1;
  return out;
});
const rows = computed(() => judgeProposals.value.filter((p) => p.status === fStatus.value));
const features = (row) => (row.rule.patterns || row.rule.keywords || []).map(String);

const goRules = () => { visible.value = false; tab.value = "rules"; };

const visible = ref(false), itemId = ref(""), draft = ref(""), note = ref(""), error = ref(""), busy = ref("");
const recheck = ref(null);
const item = computed(() => judgeProposals.value.find((p) => p.proposal_id === itemId.value) || null);
function open(row) {
  itemId.value = row.proposal_id;
  draft.value = row.yaml;
  note.value = "";
  error.value = "";
  recheck.value = null;
  visible.value = true;
}

// 修改 YAML 后重新跑证据、回放与样本检查（几秒），结果显示在编辑框下方。
async function recheckDraft() {
  if (busy.value || !item.value) return;
  busy.value = "check";
  error.value = "";
  try {
    recheck.value = await checkProposal(item.value.proposal_id, draft.value !== item.value.yaml ? draft.value : undefined);
  } catch (e) {
    error.value = e.message;
  } finally {
    busy.value = "";
  }
}

async function decide(action) {
  if (busy.value || !item.value) return;
  busy.value = action;
  error.value = "";
  try {
    const rule = action === "approve" && draft.value !== item.value.yaml ? draft.value : undefined;
    const result = await decideProposal(item.value.proposal_id, action, { rule, note: note.value });
    if (action === "approve") {
      draft.value = result.yaml;
      ElMessage.success(`已批准，规则 ${result.rule_id} 已生效`);
    } else {
      ElMessage.success("已拒绝");
      visible.value = false;
    }
  } catch (e) {
    error.value = e.message;
  } finally {
    busy.value = "";
  }
}
</script>

<style scoped>
.proposal-intro { margin: 8px 0 16px; color: var(--muted); font-size: 12px; line-height: 1.8; overflow-wrap: anywhere; }
.proposal-cards { display: none; }
.proposal-dialog-actions { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 8px; }
.proposal-dialog-actions .el-button + .el-button { margin-left: 0; }
@media (max-width: 600px) {
  .proposal-table { display: none; }
  .proposal-cards { display: grid; gap: 12px; }
  .proposal-card { min-width: 0; padding: 12px; border: 1px solid var(--line); border-radius: 10px; }
  .proposal-card-head, .proposal-card-foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .proposal-card-head { flex-wrap: wrap; }
  .proposal-card-head strong { color: var(--title); font-size: 13px; overflow-wrap: anywhere; }
  .proposal-card .proposal-intro { margin: 6px 0; }
  .proposal-features { margin: 10px 0; font-size: 12px; overflow-wrap: anywhere; }
  .proposal-card-foot { margin-top: 12px; }
  .proposal-card-foot > .el-button:first-child { flex: 1; min-width: 0; justify-content: flex-start; }
  .proposal-card-foot > .el-button:first-child :deep(span) { overflow: hidden; text-overflow: ellipsis; }
  .proposal-card-foot .el-button { min-height: 36px; }
  .proposal-empty { padding: 20px 8px; text-align: center; color: var(--muted); }
  .filters :deep(.el-radio-group) { display: flex; flex-wrap: wrap; gap: 4px 0; }
  .filters :deep(.el-radio-button__inner) { padding: 8px; }
}
</style>
