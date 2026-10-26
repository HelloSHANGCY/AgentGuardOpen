<template>
  <span class="agent-icon" :style="{width: size + 'px', height: size + 'px'}" aria-hidden="true">
    <img v-if="source && !failed" :src="source" alt="" @error="failed = true" />
    <el-icon v-else><Monitor /></el-icon>
  </span>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import { Monitor } from "../icons";
import claude from "../assets/agents/claude.png";
import codex from "../assets/agents/codex.png";
import trae from "../assets/agents/trae.png";
import qoder from "../assets/agents/qoder.svg";
import zcode from "../assets/agents/zcode.png";
import workbuddy from "../assets/agents/workbuddy.svg";
import codebuddy from "../assets/agents/codebuddy.svg";

const props = defineProps({ agent: {type: String, required: true}, size: {type: Number, default: 36} });
const icons = { "claude-code": claude, codex, trae, qoder, zcode, workbuddy, codebuddy };
const source = computed(() => icons[props.agent]);
const failed = ref(false);
watch(() => props.agent, () => { failed.value = false; });
</script>

<style scoped>
.agent-icon { display: inline-flex; flex: none; align-items: center; justify-content: center; box-sizing: border-box;
              padding: 4px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); overflow: hidden; }
.agent-icon img { display: block; width: 100%; height: 100%; object-fit: contain; border-radius: 5px; }
.agent-icon .el-icon { font-size: 20px; color: var(--muted); }
</style>
