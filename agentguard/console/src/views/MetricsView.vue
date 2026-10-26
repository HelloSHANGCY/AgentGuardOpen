<template>
  <section v-show="tab === 'metrics'" class="metrics-page">
    <ConsolePageHeader title="评测与指标" class="mt-page-head"></ConsolePageHeader>
    <el-tabs v-model="metricsTab" class="mt-main-tabs" aria-label="评测与指标页签">
      <el-tab-pane name="eval"><template #label><el-icon aria-hidden="true"><DataAnalysis /></el-icon><span>评测任务</span></template><EvalPanel /></el-tab-pane>
      <el-tab-pane name="runtime"><template #label><el-icon aria-hidden="true"><DataLine /></el-icon><span>运行指标</span></template><RuntimeMetrics v-if="tab === 'metrics' && metricsTab === 'runtime'" /></el-tab-pane>
    </el-tabs>
  </section>
</template>
<script setup>
import { tab, metricsTab } from "../store/runtime";
import EvalPanel from "./metrics/EvalPanel.vue";
import RuntimeMetrics from "./metrics/RuntimeMetrics.vue";
import "./metrics/metrics.css";
</script>
