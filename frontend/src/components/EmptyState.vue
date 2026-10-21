<template>
  <div class="empty-state">
    <Icon :name="icon" :size="30" />
    <b>{{ title }}</b>
    <p v-if="description">{{ description }}</p>
    <slot />
  </div>
</template>

<script setup>
import Icon from "./Icon.vue";
defineProps({
  title: { type: String, default: "暂无记录" },
  description: { type: String, default: "" },
  icon: { type: String, default: "file" }
});
</script>
