<template>
  <div class="threat finding-row" :data-sev="f.severity" role="button" tabindex="0"
       :title="'查看详情：' + (f.title || f.rule_id)"
       @click="$emit('open', f)" @keydown.enter="$emit('open', f)" @keydown.space.prevent="$emit('open', f)">
    <div class="threat-head">
      <span class="sev-tag" :class="'sev-'+f.severity" :title="severityName(f.severity)">{{ f.severity }}</span>
      <div class="grow-min">
        <div class="reason">{{ f.title || ruleTitle(f.rule_id) }}</div>
        <div class="meta">
          <template v-if="asset">
            <span class="asset-ref"><span class="kind-dot" :style="{ background: kindColor(asset.kind) }"></span>{{ kindName(asset.kind) }} · {{ asset.name }}</span>
            <span class="mono path-ref" :title="asset.relative_path">{{ asset.relative_path }}</span>
          </template>
          <span v-else-if="f.asset_id" class="mono">{{ f.asset_id }}</span>
          <span>{{ categoryName(f.category) }} · 置信度{{ confidenceName(f.confidence) }}</span>
        </div>
      </div>
      <span v-if="showRule" class="lat" :title="ruleTitle(f.rule_id)">{{ f.rule_id }}</span>
      <el-icon class="row-chevron" aria-hidden="true"><ArrowRight /></el-icon>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";
import { staticAssetById } from "../../store/static";
import { ruleTitle, categoryName, confidenceName, kindName, kindColor, severityName } from "../../utils/staticText";

const props = defineProps({ f: { type: Object, required: true }, showRule: { type: Boolean, default: true } });
defineEmits(["open"]);
const asset = computed(() => staticAssetById.value.get(props.f.asset_id));
</script>
