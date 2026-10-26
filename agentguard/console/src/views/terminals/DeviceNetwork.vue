<template>
  <div class="device-network">
    <div v-if="host.ip" class="mono network-ip">{{ host.ip }}</div>
    <template v-else-if="remoteIp || host.mac">
      <div class="muted">未上报终端 IP</div>
      <div v-if="remoteIp" class="network-source muted">连接来源 <span class="mono">{{ remoteIp }}</span></div>
    </template>
    <span v-else class="muted">未上报</span>
    <el-popover v-if="host.ip || host.mac || remoteIp" trigger="click" :width="280" placement="bottom-start">
      <template #reference>
        <button type="button" class="network-more" :aria-label="'查看网络详情：' + name">网络详情</button>
      </template>
      <dl class="network-facts">
        <div><dt>终端 IP</dt><dd class="mono">{{ host.ip || '未上报' }}</dd></div>
        <div><dt>网卡 MAC</dt><dd class="mono">{{ host.mac || '未上报' }}</dd></div>
        <div><dt>连接来源</dt><dd class="mono">{{ remoteIp || '未记录' }}</dd></div>
      </dl>
    </el-popover>
  </div>
</template>

<script setup>
defineProps({
  host: { type: Object, default: () => ({}) },
  remoteIp: { type: String, default: '' },
  name: { type: String, default: '设备' },
});
</script>

<style scoped>
.device-network { min-width: 0; font-size: 12px; line-height: 1.6; }
.network-ip, .network-source { overflow-wrap: anywhere; }
.network-source { font-size: 12px; }
.network-more { display: block; min-height: 24px; padding: 0; border: 0; background: none;
  color: var(--brand); font: inherit; font-size: 12px; cursor: pointer; }
.network-more:hover { text-decoration: underline; }
.network-more:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; border-radius: 2px; }
.network-facts { margin: 0; color: var(--text); font-size: 12px; }
.network-facts > div { display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 8px; margin: 6px 0; }
.network-facts dt { color: var(--muted); }
.network-facts dd { margin: 0; overflow-wrap: anywhere; }
</style>
