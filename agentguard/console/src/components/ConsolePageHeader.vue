<template>
  <header class="console-page-head">
    <div class="console-page-heading">
      <h2 class="page-title">{{ title }}</h2>
      <slot name="title-extra" />
    </div>
    <div v-if="$slots.default" class="console-page-actions"><slot /></div>
  </header>
</template>

<script setup>
defineProps({ title: { type: String, required: true } });
</script>
