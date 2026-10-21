<template>
  <div class="donut-wrap" :style="{ width: size + 'px', height: size + 'px' }">
    <svg :width="size" :height="size" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="43" fill="none" stroke="#eef3fa" :stroke-width="stroke" />
      <circle
        v-for="segment in segments"
        :key="segment.label"
        cx="50"
        cy="50"
        r="43"
        fill="none"
        :stroke="segment.color"
        :stroke-width="stroke"
        :stroke-dasharray="`${segment.length} ${segment.circumference}`"
        :stroke-dashoffset="-segment.offset"
        stroke-linecap="butt"
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
  size: { type: Number, default: 132 },
  stroke: { type: Number, default: 13 },
  centerLabel: { type: String, default: "" },
  centerValue: { type: [Number, String], default: null }
});

const circumference = 2 * Math.PI * 43;
const total = computed(() => props.items.reduce((sum, item) => sum + (Number(item.value) || 0), 0));
const displayValue = computed(() => (props.centerValue !== null && props.centerValue !== undefined ? props.centerValue : total.value || "—"));
const segments = computed(() => {
  if (!total.value) return [];
  const visible = props.items.filter((item) => Number(item.value) > 0);
  const gap = visible.length > 1 ? 2.2 : 0;
  let offset = 0;
  return visible.map((item) => {
    const raw = (Number(item.value) / total.value) * circumference;
    const length = Math.max(0, raw - gap);
    const segment = { ...item, length, circumference, offset: offset + gap / 2 };
    offset += raw;
    return segment;
  });
});
</script>
