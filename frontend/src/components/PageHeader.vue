<template>
  <header class="page-head">
    <div>
      <span v-if="eyebrow" class="eyebrow"><i class="dot"></i>{{ eyebrow }}</span>
      <h1>{{ title }}</h1>
      <p v-if="description" class="sub">{{ description }}</p>
      <div v-if="$slots.meta" class="meta"><slot name="meta" /></div>
    </div>
    <div v-if="$slots.actions" class="actions"><slot name="actions" /></div>
  </header>
</template>

<script setup>
defineProps({
  eyebrow: { type: String, default: "" },
  title: { type: String, required: true },
  description: { type: String, default: "" }
});
</script>
