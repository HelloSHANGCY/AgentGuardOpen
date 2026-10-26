<template>
  <details class="more-fields">
    <summary><el-icon class="more-chevron"><ArrowRight /></el-icon>{{ title }}</summary>
    <div class="more-fields-body"><slot /></div>
  </details>
</template>

<script setup>
// 标识符、耗时、版本等不参与研判的字段统一收在这里，默认折叠，需要排障或复制时再展开。
defineProps({ title: { type: String, default: "详细字段" } });
</script>
