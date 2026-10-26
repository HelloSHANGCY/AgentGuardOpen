<template>
  <ul class="dd-list pv-list">
    <li v-for="(h, i) in items" :key="i" class="pv-item">
      <div class="pv-head">
        <span class="pv-source pv-bad"
              :title="h.event_id ? (h.kind === 'fingerprint' ? '秘密读取事件 ' : '暂存事件 ') + h.event_id : undefined">{{ KIND_TEXT[h.kind] || h.kind }}</span>
        <span v-if="h.form" class="pv-cue">{{ FORM_TEXT[h.form] || h.form }}</span>
        <span v-if="h.path" class="mono pv-token">{{ h.path }}</span>
        <span v-if="h.preview" class="mono pv-risk" title="秘密值只展示前 4 位">{{ h.preview }}</span>
      </div>
      <div v-if="h.origin && h.origin !== 'content'" class="pv-meta">派生自 <span class="mono">{{ h.origin }}</span></div>
      <div v-if="h.trace_id" class="pv-meta">
        所在会话 <a class="mono clickable" @click="openChain(h.trace_id)">{{ h.trace_id }}</a>
      </div>
    </li>
  </ul>
</template>

<script setup>
// 数据流溯源证据（创新检测实施方案 §4）：本次外发携带了哪份秘密、以什么形态、经哪个暂存物。
import { openChain } from "../store/runtime";

defineProps({ items: { type: Array, default: () => [] } });

const KIND_TEXT = { fingerprint: "内容含秘密指纹", staged: "外发暂存物", direct: "直接外发秘密文件" };
const FORM_TEXT = { plain: "明文", urlencoded: "URL 编码", hex: "hex 编码", base64: "base64 编码" };
</script>
