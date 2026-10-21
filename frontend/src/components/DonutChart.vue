<template>
  <div class="donut-wrap" :style="{ width: size + 'px', height: size + 'px' }">
    <svg :width="size" :height="size" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--line-soft)" stroke-width="10" />
      <circle
        v-for="segment in segments"
        :key="segment.label"
        cx="50"
        cy="50"
        r="42"
        fill="none"
        :stroke="segment.color"
        stroke-width="10"
        :stroke-dasharray="`${segment.length} ${segment.circumference}`"
        :stroke-dashoffset="-segment.offset"
        transform="rotate(-90 50 50)"
      />
    </svg>
    <div class="donut-center">
      <b>{{ displayValue }}</b>
      <span>{{ centerLabel }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
  items: { type: Array, default: () => [] },
  size: { type: Number, default: 108 },
  centerLabel: { type: String, default: "" },
  centerValue: { type: [Number, String], default: null }
});

const circumference = 2 * Math.PI * 42;
const total = computed(() => props.items.reduce((sum, item) => sum + (Number(item.value) || 0), 0));
const displayValue = computed(() => (props.centerValue !== null && props.centerValue !== undefined ? props.centerValue : total.value || "—"));
const segments = computed(() => {
  if (!total.value) return [];
  let offset = 0;
  return props.items
    .filter((item) => Number(item.value) > 0)
    .map((item) => {
      const length = (Number(item.value) / total.value) * circumference;
      const segment = { ...item, length, circumference, offset };
      offset += length;
      return segment;
    });
});
</script>
