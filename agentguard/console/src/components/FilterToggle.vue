<template>
  <el-button size="small" :aria-expanded="modelValue" :aria-controls="controls"
             :type="modelValue || count ? 'primary' : 'default'" :plain="modelValue || count > 0"
             @click="$emit('update:modelValue', !modelValue)">
    <el-icon class="btn-ic" aria-hidden="true"><Filter /></el-icon>
    {{ modelValue ? '收起筛选' : '更多筛选' }}<span v-if="count" class="filter-count">{{ count }}</span>
  </el-button>
</template>

<script setup>
import { Filter } from '../icons';
defineProps({ modelValue: Boolean, count: { type: Number, default: 0 }, controls: { type: String, required: true } });
defineEmits(['update:modelValue']);
</script>
