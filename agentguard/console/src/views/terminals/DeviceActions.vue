<template>
  <div class="device-actions">
    <el-button link type="primary" size="small" :aria-label="'查看设备详情：' + device.device_id" @click="$emit('details')">详情</el-button>
    <el-button v-if="!device.uninstalled_at" link type="primary" size="small" :aria-label="'配置设备：' + device.device_id" @click="$emit('configure')">配置</el-button>
    <el-popconfirm :title="device.uninstalled_at ? '删除 ' + device.device_id + ' 的记录？'
                     : '吊销 ' + device.device_id + '？该设备上所有 Agent 的 Hook 将无法上报'"
                   :confirm-button-text="device.uninstalled_at ? '删除' : '吊销'" cancel-button-text="取消"
                   @confirm="revokeDevice(device.device_id)">
      <template #reference><el-button link type="danger" size="small" :aria-label="(device.uninstalled_at ? '删除设备：' : '吊销设备：') + device.device_id">{{ device.uninstalled_at ? '删除' : '吊销' }}</el-button></template>
    </el-popconfirm>
  </div>
</template>

<script setup>
import { revokeDevice } from "../../store/devices";
defineProps({ device: { type: Object, required: true } });
defineEmits(['details', 'configure']);
</script>

<style scoped>
.device-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.device-actions .el-button { margin: 0; min-height: var(--control-compact-height); }
@media (max-width: 760px) { .device-actions { gap: 20px; } .device-actions .el-button { min-height: var(--control-height); } }
</style>
