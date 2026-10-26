<template>
  <ul class="dd-list pv-list">
    <li v-for="(p, i) in items" :key="i" class="pv-item">
      <div class="pv-head">
        <span class="mono pv-token">{{ p.token }}</span>
        <span class="pv-risk">{{ RISK_TEXT[p.risk] || p.risk }}</span>
        <span class="pv-source" :class="'pv-' + sourceTone(p)" :title="p.event_id ? '来源事件 ' + p.event_id : undefined">{{ sourceText(p) }}</span>
        <span v-for="c in p.cues || []" :key="c" class="pv-cue">{{ CUE_TEXT[c] || c }}</span>
      </div>
      <pre v-if="p.snippet" class="dd-code pv-snippet"><template v-for="(seg, j) in segments(p.snippet, p.token)" :key="j"><mark v-if="seg.hit">{{ seg.text }}</mark><template v-else>{{ seg.text }}</template></template></pre>
    </li>
  </ul>
</template>

<script setup>
// 参数来源归因（创新检测实施方案 §3）：每个高危参数从哪里来——用户指令 / 某轮工具返回 / 无来源，
// 来自工具返回时展示上下文片段（高亮参数）与指令痕迹。
defineProps({ items: { type: Array, default: () => [] } });

const RISK_TEXT = {
  payload_egress: "携带数据外发", download_exec: "下载执行", reverse_shell: "反弹连接",
  persistence: "持久化写入", agent_config: "Agent 配置写入", sensitive_read: "敏感读取", plain_fetch: "访问链接",
};
const CUE_TEXT = {
  INJECTION_MARKER: "注入特征词", HIDDEN_MARKUP: "隐藏载体", AGENT_DIRECTIVE: "对 Agent 下指令",
  PROCEDURE_DIRECTIVE: "流程化指令",
};

const sourceText = (p) => {
  if (p.source === "USER") return "来自用户指令";
  if (p.source === "NONE") return "无来源（模型生成）";
  return `来自${p.round ? `第 ${p.round} 轮` : ""}工具返回 · ${p.tool || "未知工具"}${p.untrusted ? "（不可信）" : ""}`;
};
const sourceTone = (p) => (p.source === "USER" ? "user" : p.source === "NONE" ? "none" : (p.cues || []).length ? "bad" : "data");

// 片段按参数（不区分大小写）切分，命中部分高亮。
function segments(text, token) {
  if (!token) return [{ text, hit: false }];
  const out = [];
  const lower = text.toLowerCase();
  const needle = token.toLowerCase();
  let from = 0;
  for (let at = lower.indexOf(needle); at >= 0; at = lower.indexOf(needle, from)) {
    if (at > from) out.push({ text: text.slice(from, at), hit: false });
    out.push({ text: text.slice(at, at + needle.length), hit: true });
    from = at + needle.length;
  }
  if (from < text.length) out.push({ text: text.slice(from), hit: false });
  return out;
}
</script>
