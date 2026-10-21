<template>
  <div ref="canvasRef" class="topology-canvas" :style="{ minHeight: `${height}px` }">
    <svg class="topology-svg" viewBox="0 0 900 420" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
      <defs>
        <radialGradient id="topo-bg" cx="50%" cy="42%" r="62%">
          <stop offset="0%" stop-color="#ffffff" />
          <stop offset="58%" stop-color="#f4f9ff" />
          <stop offset="100%" stop-color="#edf5ff" />
        </radialGradient>
        <radialGradient id="topo-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#5fa2ff" stop-opacity="0.32" />
          <stop offset="100%" stop-color="#5fa2ff" stop-opacity="0" />
        </radialGradient>
        <linearGradient id="topo-plat" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#f2f8ff" />
          <stop offset="100%" stop-color="#d9e8fa" />
        </linearGradient>
        <linearGradient id="topo-shield" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#6aa6ff" />
          <stop offset="52%" stop-color="#2f6fed" />
          <stop offset="100%" stop-color="#1546b8" />
        </linearGradient>
        <filter id="topo-shadow" x="-40%" y="-40%" width="180%" height="180%">
          <feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#2f6fed" flood-opacity="0.22" />
        </filter>
        <filter id="topo-soft" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="12" />
        </filter>
      </defs>

      <g stroke="#dfebf9" stroke-width="1" opacity="0.55">
        <line v-for="y in [80, 130, 180, 230, 280, 330, 380]" :key="`h-${y}`" x1="0" :y1="y" x2="900" :y2="y" />
        <line v-for="k in [-2, -1, 0, 1, 2, 3, 4, 5]" :key="`d-${k}`" :x1="k * 150" y1="420" :x2="k * 150 + 290" y2="0" />
      </g>

      <g opacity="0.5">
        <path
          v-for="(link, index) in links"
          :key="`l-${index}`"
          :d="link.d"
          fill="none"
          :stroke="link.color"
          stroke-width="1.6"
          stroke-dasharray="5 6"
          stroke-linecap="round"
        />
        <circle v-for="(link, index) in links" :key="`p-${index}`" r="3.2" :fill="link.color" opacity="0.85">
          <animateMotion :dur="`${5 + index}s`" repeatCount="indefinite" :path="link.d" />
        </circle>
      </g>

      <ellipse cx="450" cy="248" rx="230" ry="110" fill="url(#topo-glow)" />
      <circle cx="450" cy="228" r="152" fill="none" stroke="#cfe0f5" stroke-width="1.2" stroke-dasharray="2 9" opacity="0.9" />
      <circle cx="450" cy="228" r="112" fill="none" stroke="#dbe8fa" stroke-width="1" opacity="0.85" />

      <g>
        <path d="M450 320 L626 263 L450 206 L274 263 Z" fill="#e5eefb" opacity="0.9" />
        <path d="M450 306 L600 258 L450 210 L300 258 Z" fill="url(#topo-plat)" stroke="#c4dbf4" stroke-width="1.4" />
        <path d="M450 292 L574 254 L450 216 L326 254 Z" fill="#f7fbff" stroke="#d6e6f9" stroke-width="1" />
      </g>

      <g transform="translate(450 232)" filter="url(#topo-shadow)">
        <g transform="translate(-40 -44) scale(3.33)">
          <path d="M12 3 5 6v5.5c0 4.2 2.8 7.5 7 9 4.2-1.5 7-4.8 7-9V6l-7-3Z" fill="url(#topo-shield)" stroke="rgba(255,255,255,.6)" stroke-width="1" />
          <path d="m9 12 2 2 4-4" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
        </g>
        <text x="0" y="66" text-anchor="middle" font-family="Inter, 'Microsoft YaHei UI', sans-serif" font-size="19" font-weight="700" fill="#0d1b2e">IoTGuard</text>
      </g>

      <g v-for="(node, index) in nodes" :key="node.key">
        <ellipse :cx="node.x" :cy="node.y + 34" :rx="58" :ry="18" :fill="node.color" opacity="0.10" />
        <ellipse :cx="node.x" :cy="node.y + 6" :rx="56" :ry="40" :fill="node.color" opacity="0.08" filter="url(#topo-soft)" />
        <path :d="hexPath(node.x, node.y)" :fill="node.soft" :stroke="node.color" stroke-opacity="0.35" stroke-width="1.3" />
        <path :d="hexPath(node.x, node.y - 6)" fill="#ffffff" opacity="0.55" />
        <circle :cx="node.x" :cy="node.y - 4" r="3" :fill="node.color" opacity="0.9" />
      </g>
    </svg>

    <div
      v-for="node in placedNodes"
      :key="`pod-${node.key}`"
      class="device-pod"
      :style="{ left: `${node.left}px`, top: `${node.top}px`, '--pod-color': node.color, '--pod-soft': node.soft }"
    >
      <span class="pod-icon"><Icon :name="node.icon" :size="20" /></span>
      <div>
        <div class="pod-name">{{ node.name }}</div>
        <div class="pod-count">{{ node.count }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  height: { type: Number, default: 380 }
});

const slots = [
  { x: 196, y: 118 },
  { x: 706, y: 104 },
  { x: 208, y: 326 },
  { x: 700, y: 318 }
];

const canvasRef = ref(null);
const canvasSize = ref({ width: 900, height: 420 });
let observer = null;

onMounted(() => {
  if (!canvasRef.value) return;
  const update = () => {
    const rect = canvasRef.value.getBoundingClientRect();
    canvasSize.value = { width: rect.width || 900, height: rect.height || 420 };
  };
  update();
  observer = new ResizeObserver(update);
  observer.observe(canvasRef.value);
});

onUnmounted(() => {
  if (observer) observer.disconnect();
});

const nodes = computed(() => props.nodes.slice(0, 4).map((node, index) => ({ ...node, ...slots[index] })));

const placedNodes = computed(() => {
  const { width, height } = canvasSize.value;
  const scale = Math.min(width / 900, height / 420);
  const offsetX = (width - 900 * scale) / 2;
  const offsetY = (height - 420 * scale) / 2;
  return nodes.value.map((node) => ({
    ...node,
    left: offsetX + node.x * scale,
    top: offsetY + (node.y - 22) * scale
  }));
});

const links = computed(() =>
  nodes.value.map((node) => ({
    color: node.color,
    d: `M${node.x},${node.y + 8} C${node.x + (450 - node.x) * 0.35},${node.y + 20} ${node.x + (450 - node.x) * 0.62},${250} 450,250`
  }))
);

function hexPath(x, y) {
  const w = 54;
  const h = 31;
  return `M${x},${y - h} L${x + w},${y - h / 2} L${x + w},${y + h / 2} L${x},${y + h} L${x - w},${y + h / 2} L${x - w},${y - h / 2} Z`;
}
</script>

<style scoped>
.topology-canvas { position: relative; overflow: hidden; border-radius: 12px; }
.topology-svg { position: absolute; inset: 0; display: block; width: 100%; height: 100%; }
.device-pod {
  position: absolute;
  transform: translate(-50%, -50%);
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 13px 8px 9px;
  border: 1px solid #e3edf9;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.92);
  box-shadow: 0 14px 30px -20px rgba(16, 35, 70, 0.5);
  backdrop-filter: blur(6px);
  z-index: 2;
}
.device-pod .pod-icon {
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  border-radius: 10px;
  background: var(--pod-soft);
  color: var(--pod-color);
}
.device-pod .pod-name { color: #5b6b82; font-size: 11.5px; font-weight: 600; line-height: 1.2; white-space: nowrap; }
.device-pod .pod-count { color: #0d1b2e; font-family: var(--font-num); font-size: 20px; font-weight: 800; line-height: 1.1; letter-spacing: -0.02em; }
</style>
