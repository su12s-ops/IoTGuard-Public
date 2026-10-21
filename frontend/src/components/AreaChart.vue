<template>
  <div class="area-chart" :style="{ height: `${height}px` }">
    <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient :id="`${uid}-fill`" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" :stop-color="series[0]?.color || '#2f6fed'" stop-opacity="0.28" />
          <stop offset="100%" :stop-color="series[0]?.color || '#2f6fed'" stop-opacity="0.02" />
        </linearGradient>
      </defs>

      <g class="axis">
        <line v-for="tick in yTicks" :key="tick.value" :x1="pad.l" :x2="W - pad.r" :y1="tick.y" :y2="tick.y" stroke="#edf3fa" stroke-width="1" />
        <text v-for="tick in yTicks" :key="`t-${tick.value}`" :x="pad.l - 8" :y="tick.y + 3.5" text-anchor="end" fill="#7b8ca6" font-size="10">{{ tick.label }}</text>
      </g>

      <path v-if="series[0]" :d="areaPath(series[0])" :fill="`url(#${uid}-fill)`" />
      <path
        v-for="item in series"
        :key="item.name"
        :d="linePath(item)"
        fill="none"
        :stroke="item.color"
        stroke-width="2.2"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
      <g v-if="series[0] && series[0].values.length">
        <circle :cx="lastPoint(series[0]).x" :cy="lastPoint(series[0]).y" r="4" fill="#fff" :stroke="series[0].color" stroke-width="2.4" />
      </g>

      <g v-if="labels.length">
        <text
          v-for="(label, index) in xLabels"
          :key="`${label}-${index}`"
          :x="xFor(index)"
          :y="H - 4"
          text-anchor="middle"
          fill="#7b8ca6"
          font-size="10"
        >{{ label }}</text>
      </g>
    </svg>
  </div>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
  series: { type: Array, default: () => [] },
  labels: { type: Array, default: () => [] },
  height: { type: Number, default: 168 }
});

const W = 1000;
const H = 220;
const pad = { l: 42, r: 12, t: 14, b: 24 };
const uid = `area-${Math.random().toString(36).slice(2, 8)}`;

const maxValue = computed(() => {
  const values = props.series.flatMap((item) => item.values || []).map((v) => Number(v) || 0);
  return niceMax(Math.max(...values, 1));
});

function niceMax(value) {
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

const yTicks = computed(() => {
  const max = maxValue.value;
  return [0, 0.25, 0.5, 0.75, 1].map((fraction) => {
    const value = max * fraction;
    return {
      value,
      label: value >= 1000 ? `${Math.round(value / 100) / 10}k` : String(Math.round(value)),
      y: pad.t + (1 - fraction) * (H - pad.t - pad.b)
    };
  });
});

function xFor(index) {
  const count = Math.max(props.labels.length, 2);
  return pad.l + (index / (count - 1)) * (W - pad.l - pad.r);
}

function pointFor(item, index) {
  const values = item.values || [];
  const count = Math.max(values.length, 2);
  return {
    x: pad.l + (index / (count - 1)) * (W - pad.l - pad.r),
    y: pad.t + (1 - (Number(values[index]) || 0) / maxValue.value) * (H - pad.t - pad.b)
  };
}

function linePath(item) {
  const points = (item.values || []).map((_, index) => pointFor(item, index));
  if (!points.length) return "";
  if (points.length === 1) return `M${points[0].x},${points[0].y}`;
  let d = `M${points[0].x},${points[0].y}`;
  for (let i = 0; i < points.length - 1; i += 1) {
    const p0 = points[i - 1] || points[i];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] || p2;
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C${c1x},${c1y} ${c2x},${c2y} ${p2.x},${p2.y}`;
  }
  return d;
}

function areaPath(item) {
  const points = (item.values || []).map((_, index) => pointFor(item, index));
  if (!points.length) return "";
  const base = H - pad.b;
  const line = linePath(item);
  return `${line} L${points[points.length - 1].x},${base} L${points[0].x},${base} Z`;
}

function lastPoint(item) {
  const values = item.values || [];
  return pointFor(item, Math.max(0, values.length - 1));
}

const xLabels = computed(() => {
  const labels = props.labels;
  if (labels.length <= 7) return labels.map((label, index) => ({ label, index })).map(({ label, index }) => label);
  const step = Math.ceil(labels.length / 6);
  return labels.map((label, index) => (index % step === 0 || index === labels.length - 1 ? label : ""));
});
</script>

<style scoped>
.area-chart { width: 100%; min-height: 120px; }
.area-chart svg { width: 100%; height: 100%; display: block; overflow: visible; }
</style>
