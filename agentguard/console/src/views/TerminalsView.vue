<template>
  <section v-show="tab === 'terminals'">
    <div class="terminal-context">终端管控 <span aria-hidden="true">/</span> {{ currentPage.label }}</div>
    <ConsolePageHeader :title="currentPage.label" class="terminal-page-header">

      <el-button size="small" @click="refreshDevices"><el-icon class="btn-ic"><Refresh /></el-icon>刷新</el-button>
    </ConsolePageHeader>

    <div class="eval-controls" v-if="adminNeedsToken">
      <label>管理令牌<el-input size="small" v-model="adminToken" type="password" show-password autocomplete="off"
                aria-label="管理令牌" placeholder="AG_AGENT_ADMIN_TOKEN，仅保存在当前页面" @keyup.enter="refreshDevices"></el-input></label>
      <el-button size="small" type="primary" :disabled="!adminToken" @click="refreshDevices">加载</el-button>
    </div>
    <el-alert v-if="deviceError" :title="deviceError" type="error" show-icon class="my-12" @close="deviceError = ''"></el-alert>
    <el-skeleton v-if="!deviceLoaded && !deviceError && !adminNeedsToken" :rows="6" animated class="my-12" />

    <template v-if="deviceLoaded">
      <DevicesPanel v-show="terminalTab === 'devices'" />
      <PoliciesPanel v-show="terminalTab === 'policies'" />
      <DeployPanel v-show="terminalTab === 'deploy'" />
    </template>
  </section>
</template>

<script setup>
import { computed, watch } from "vue";
import { tab, terminalTab, TERMINAL_PAGES } from "../store/runtime";
import { adminToken, adminNeedsToken, deviceError, deviceLoaded, refreshDevices } from "../store/devices";
import DevicesPanel from "./terminals/DevicesPanel.vue";
import PoliciesPanel from "./terminals/PoliciesPanel.vue";
import DeployPanel from "./terminals/DeployPanel.vue";

const currentPage = computed(() => TERMINAL_PAGES.find((page) => page.key === terminalTab.value) || TERMINAL_PAGES[0]);
watch([tab, terminalTab], ([page]) => { if (page === "terminals") refreshDevices(); }, { immediate: true });
</script>
