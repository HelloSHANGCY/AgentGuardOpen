<template>
  <div class="ev-detail">
    <div class="ev-head">
      <span class="ev-stage">{{ stageName(n) }}</span>
      <span class="ev-meta">{{ fmtTime(n.timestamp) }} · {{ n.source }}</span>
      <el-tag v-if="n.attribution" size="small" effect="plain"
              :type="n.attribution === 'unknown' ? 'warning' : 'info'"
              :title="'父子关联：' + attributionName(n.attribution)">{{ attributionName(n.attribution) }}</el-tag>
      <el-tag v-if="n.link_note" size="small" effect="plain" type="warning"
              title="缺失对应 Hook/网关事件，链路证据不完整">{{ linkNoteName(n.link_note) }}</el-tag>
      <template v-if="n.decision">
        <span class="dec-tag" :class="dispositionTag(n.decision)">{{ dispositionLabel(n.decision) }}</span>
        <span v-if="n.decision.severity" class="sev-tag" :class="'sev-'+n.decision.severity">{{ n.decision.severity }}</span>
        <span v-if="n.decision.reason_code" class="code-hint" :title="n.decision.reason_code">{{ threatText(n.decision.reason_code) }}</span>
      </template>
    </div>
    <pre v-if="n.redacted_preview" class="ev-preview">{{ n.redacted_preview }}</pre>
    <div v-if="(n.decision?.provenance || []).length" class="ev-provenance">
      <div class="dd-callout-label">指令来源</div>
      <ProvenanceList :items="n.decision.provenance" />
    </div>
    <div v-if="(n.decision?.flow || []).length" class="ev-provenance">
      <div class="dd-callout-label">数据流证据</div>
      <FlowList :items="n.decision.flow" />
    </div>
    <div v-if="n.decision?.anomaly" class="ev-provenance">
      <div class="dd-callout-label">行为基线</div>
      <AnomalyCard :a="n.decision.anomaly" />
    </div>
    <dl class="ev-kv">
      <template v-if="(n.stack||[]).length">
        <dt>调用栈</dt>
        <dd>
          <div v-for="(f, i) in n.stack" :key="i" class="stack-frame">
            <span class="stack-src" :data-src="frameSource(f)">{{ stackSourceName(frameSource(f)) }}</span>
            <span class="mono">{{ frameText(f) }}</span>
          </div>
        </dd>
      </template>
      <template v-if="(n.evidence||[]).length">
        <dt>证据</dt>
        <dd class="ev-chips">
          <span v-for="e in n.evidence" :key="e.evidence_id" class="evidence-item mono"
                :title="e.evidence_id + ' · ' + (e.origin_source || '') + ' · ' + e.digest
                        + ((e.snippets || []).length ? ' · ' + e.snippets.length + ' 个关键片段' : '')">
            {{ e.kind }}<template v-if="e.truncated">（截断）</template>
          </span>
        </dd>
      </template>
      <template v-if="(n.labels||[]).length">
        <dt>标签</dt>
        <dd class="ev-chips">
          <el-tag v-for="l in n.labels" :key="l" size="small" effect="plain" class="mono"
                  :title="l" :type="isRiskLabel(l) ? 'danger' : 'info'">{{ threatText(l) }}</el-tag>
        </dd>
      </template>
    </dl>
  </div>
</template>

<script setup>
// 攻击链中单个原始事件的完整明细：只在用户展开某一步时渲染，默认视图只展示归并后的摘要。
import {
  stageName, dispositionTag, dispositionLabel, threatText, isRiskLabel, attributionName, linkNoteName,
  stackSourceName, frameSource, frameText, fmtTime,
} from "../../utils/format";
import ProvenanceList from "../../components/ProvenanceList.vue";
import FlowList from "../../components/FlowList.vue";
import AnomalyCard from "../../components/AnomalyCard.vue";

defineProps({ n: { type: Object, required: true } });
</script>
