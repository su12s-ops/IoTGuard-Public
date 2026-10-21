<template>
  <svg class="icon" :width="size" :height="size" aria-hidden="true">
    <use :href="`#i-${name}`" />
  </svg>
</template>

<script setup>
defineProps({
  name: { type: String, required: true },
  size: { type: [Number, String], default: 17 }
});
</script>
