<template>
  <el-card class="stat-card" shadow="never">
    <div class="stat-label">{{ label }}</div>
    <div class="stat-value">{{ value }}</div>
    <div class="stat-hint">{{ hint }}</div>
  </el-card>
</template>

<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [Number, String], default: 0 },
  hint: { type: String, default: "" }
});
</script>

<style scoped>
.stat-card {
  border-radius: 3px;
}

.stat-label {
  color: #9aa8b8;
  font-size: 11px;
}

.stat-value {
  margin-top: 4px;
  color: #e6edf7;
  font-family: "Fira Code", Consolas, monospace;
  font-size: 22px;
  font-weight: 600;
}

.stat-hint {
  margin-top: 4px;
  min-height: 18px;
  color: #718094;
  font-size: 10px;
}
</style>
