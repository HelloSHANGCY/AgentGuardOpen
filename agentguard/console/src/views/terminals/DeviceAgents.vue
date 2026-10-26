<template>
  <div class="device-agent-list">
    <span v-for="agent in agents.slice(0, 2)" :key="agent" class="device-agent-chip">
      <AgentIcon :agent="agent" :size="22" />{{ AGENT_NAMES[agent] || agent }}
    </span>
    <button v-if="agents.length > 2" type="button" class="device-agent-more"
            :aria-label="'查看全部 ' + agents.length + ' 个 Agent：' + name" @click="$emit('details')">+{{ agents.length - 2 }}</button>
    <span v-if="!agents.length" class="muted">未配置</span>
  </div>
</template>

<script setup>
import AgentIcon from "../../components/AgentIcon.vue";
import { AGENT_NAMES } from "../../store/runtime";
defineProps({ agents: { type: Array, default: () => [] }, name: { type: String, default: '设备' } });
defineEmits(['details']);
</script>

<style scoped>
.device-agent-list { display: flex; align-items: center; flex-wrap: wrap; gap: 5px 8px; font-size: 12px; }
.device-agent-chip { display: inline-flex; align-items: center; gap: 5px; min-width: 0; overflow-wrap: anywhere; }
.device-agent-chip :deep(.agent-icon) { padding: 2px; border-radius: 6px; }
.device-agent-more { min-width: 28px; min-height: 24px; padding: 1px 6px; border: 1px solid var(--line);
  border-radius: 6px; background: var(--line-2); color: var(--text); font: inherit; cursor: pointer; }
.device-agent-more:hover { color: var(--brand); border-color: var(--brand); }
.device-agent-more:focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
</style>
