<template>
  <el-dialog v-model="staticBrowseOpen" title="选择扫描目录" width="560px">
    <div class="muted fs-12 mb-6">
      授权根：{{ staticBrowseRoots.join(' · ') || '未配置' }}
    </div>
    <div class="inline-pair mb-8">
      <el-button size="small" plain :disabled="!staticBrowseParent" @click="staticBrowseTo(staticBrowseParent)">上一级</el-button>
      <el-input v-model="staticBrowsePath" size="small" readonly placeholder="授权根列表"></el-input>
    </div>
    <div class="browse-list">
      <button v-for="e in staticBrowseEntries" :key="e.path" type="button" class="browse-entry" @click="staticBrowseTo(e.path)">
        <el-icon><Folder /></el-icon><span>{{ e.name }}</span>
      </button>
      <el-empty v-if="!staticBrowseEntries.length" description="没有可选的子目录" :image-size="60"></el-empty>
    </div>
    <template #footer>
      <el-button size="small" @click="staticBrowseOpen=false">取消</el-button>
      <el-button size="small" type="primary" :disabled="!staticBrowsePath" @click="chooseStaticBrowse">选择此目录</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import {
  staticBrowseOpen, staticBrowsePath, staticBrowseParent, staticBrowseRoots,
  staticBrowseEntries, staticBrowseTo, chooseStaticBrowse,
} from "../../store/static";
</script>
