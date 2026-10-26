<template>
  <header class="page-head">
    <div class="ph-row">
      <div class="ph-copy">
        <h1>{{ title }}</h1>
      </div>
    </div>
    <div class="ph-row">
      <div class="ph-sub">
        <span v-if="subtitle" class="ph-en">{{ subtitle }}</span>
        <span v-if="subtitle && (description || $slots.meta)" class="ph-divider">|</span>
        <span v-if="description" class="ph-desc">{{ description }}</span>
        <span v-if="$slots.meta" class="ph-sep">·</span>
        <span v-if="$slots.meta" class="ph-meta"><slot name="meta" /></span>
      </div>
      <div v-if="$slots.actions" class="actions"><slot name="actions" /></div>
    </div>
  </header>
  <ConsoleRunPanel />
</template>

<script setup>
import ConsoleRunPanel from "./ConsoleRunPanel.vue";

defineProps({
  eyebrow: { type: String, default: "" },
  title: { type: String, required: true },
  subtitle: { type: String, default: "" },
  description: { type: String, default: "" }
});
</script>
