<template>
  <div class="gauge" :style="{ width: size + 'px', height: size + 'px' }">
    <svg :width="size" :height="size" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="44" fill="none" stroke="var(--line-soft)" :stroke-width="stroke" />
      <circle
        cx="50"
        cy="50"
        r="44"
        fill="none"
        :stroke="color"
        :stroke-width="stroke"
        stroke-linecap="round"
        :stroke-dasharray="`${dash} 276.46`"
      />
    </svg>
    <div class="gauge-center">
      <b>{{ display }}</b>
      <span v-if="label">{{ label }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
  value: { type: [Number, String], default: null },
  label: { type: String, default: "" },
  size: { type: Number, default: 84 },
  stroke: { type: Number, default: 7 },
  color: { type: String, default: "var(--accent)" }
});

const numeric = computed(() => {
  const n = Number(props.value);
  return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : null;
});
const dash = computed(() => ((numeric.value ?? 0) / 100) * 276.46);
const display = computed(() => (numeric.value === null ? "—" : `${Math.round(numeric.value)}%`));
</script>
