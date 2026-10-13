<template>
  <el-table v-bind="$attrs" :data="rows" border stripe style="width: 100%" :max-height="height">
    <slot />
  </el-table>
</template>

<script setup>
defineOptions({ inheritAttrs: false });
defineProps({
  rows: { type: Array, default: () => [] },
  height: { type: [String, Number], default: 520 }
});
</script>
