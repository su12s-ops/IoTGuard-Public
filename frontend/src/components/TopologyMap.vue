<template>
  <div ref="canvasRef" class="topology-canvas" :class="{ 'is-static': !animating, 'has-timeline': events.length > 0 }" :style="{ minHeight: `${height}px` }">
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
        <!-- 减动效保护：SVG 的 animateMotion 不受 CSS prefers-reduced-motion 约束，
             必须用 JS 判断后决定是否渲染；开启"减少动态效果"时数据点静止显示。 -->
        <template v-if="!reducedMotion">
          <circle v-for="(link, index) in links" :key="`p-${index}`" r="3.2" :fill="link.color" opacity="0.85">
            <animateMotion :dur="`${5 + index}s`" repeatCount="indefinite" :path="link.d" />
          </circle>
        </template>
        <template v-else>
          <circle v-for="(link, index) in links" :key="`ps-${index}`" r="3.2" :fill="link.color" opacity="0.85" />
        </template>
      </g>

      <!-- 事件流：真实事件驱动的点，从各节点流向中心（方向 = 数据流方向） -->
      <g ref="flowRef" class="topo-flow"></g>

      <ellipse cx="450" cy="248" rx="230" ry="110" fill="url(#topo-glow)" />
      <circle cx="450" cy="228" r="152" fill="none" stroke="#cfe0f5" stroke-width="1.2" stroke-dasharray="2 9" opacity="0.9" />
      <circle cx="450" cy="228" r="112" fill="none" stroke="#dbe8fa" stroke-width="1" opacity="0.85" />

      <g>
        <path d="M450 320 L626 263 L450 206 L274 263 Z" fill="#e5eefb" opacity="0.9" />
        <path d="M450 306 L600 258 L450 210 L300 258 Z" fill="url(#topo-plat)" stroke="#c4dbf4" stroke-width="1.4" />
        <path d="M450 292 L574 254 L450 216 L326 254 Z" fill="#f7fbff" stroke="#d6e6f9" stroke-width="1" />
      </g>

      <g transform="translate(450 232)" filter="url(#topo-shadow)">
        <g class="topo-core" :class="{ beating: animating }" transform-origin="450px 232px">
          <g transform="translate(-40 -44) scale(3.33)">
            <path d="M12 3 5 6v5.5c0 4.2 2.8 7.5 7 9 4.2-1.5 7-4.8 7-9V6l-7-3Z" fill="url(#topo-shield)" stroke="rgba(255,255,255,.6)" stroke-width="1" />
            <path d="m9 12 2 2 4-4" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
          </g>
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
      :class="{ 'has-events': eventCount(node.key) > 0, 'is-active': highlightKey === node.key }"
      :style="{ left: `${node.left}px`, top: `${node.top}px`, '--pod-color': node.color, '--pod-soft': node.soft }"
      role="button"
      tabindex="0"
      :aria-label="`${node.name}，${node.count} 台设备，窗口内 ${eventCount(node.key)} 条事件`"
      @mouseenter="hoverKey = node.key"
      @mouseleave="hoverKey = ''"
      @focus="activeKey = node.key"
      @click="activeKey = activeKey === node.key ? '' : node.key"
      @keydown.enter.prevent="activeKey = activeKey === node.key ? '' : node.key"
      @keydown.space.prevent="activeKey = activeKey === node.key ? '' : node.key"
    >
      <span class="pod-icon"><Icon :name="node.icon" :size="20" /></span>
      <div>
        <div class="pod-name">{{ node.name }}</div>
        <div class="pod-count">{{ node.count }}</div>
      </div>
      <span v-if="eventCount(node.key) > 0" class="pod-ev">{{ eventCount(node.key) }}</span>
    </div>

    <!-- 右上角：数据来源 + 动态/静态开关 -->
    <div class="topo-controls">
      <span class="topo-mode" :class="'mode-' + mode">{{ modeLabel }}</span>
      <button
        class="topo-toggle"
        type="button"
        :aria-pressed="playing"
        @click="playing = !playing"
      >{{ playing ? "动态" : "静态" }}</button>
    </div>

    <!-- 节点检查器：悬停/聚焦/点击任一节点 -->
    <aside v-if="activeNode" class="topo-inspect" aria-live="polite">
      <header>
        <b>{{ activeNode.name }}</b>
        <span>{{ activeNode.count }} 台设备 · 窗口内 {{ eventCount(activeNode.key) }} 条事件</span>
      </header>
      <ul v-if="nodeEvents(activeNode.key).length">
        <li v-for="(ev, i) in nodeEvents(activeNode.key).slice(0, 4)" :key="i">
          <span class="t">{{ shortTime(ev.timestamp) }}</span>
          <span class="r">{{ ev.rule || ev.event_type || "事件" }}</span>
          <span class="p">{{ ev.process_name || ev.commandline || "—" }}</span>
        </li>
      </ul>
      <p v-else class="none">该节点在当前时间窗内没有运行时事件。</p>
      <p class="map-note">映射依据：主机名 → 生态（来自设备业务总览）；未识别主机归入「其他设备」。</p>
    </aside>

    <!-- 时间轴：只在有事件时可拖动 -->
    <div v-if="events.length" class="topo-timeline">
      <span class="tl-label">{{ windowLabel }}</span>
      <input
        v-model.number="cutoff"
        type="range"
        min="0"
        max="100"
        step="1"
        aria-label="事件回放时间轴"
        @input="applyCutoff"
      />
      <span class="tl-count">{{ activeEvents.length }} / {{ events.length }} 条</span>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  height: { type: Number, default: 380 },
  // 运行时事件（真实字段：timestamp / hostname / rule / event_type / process_name）
  events: { type: Array, default: () => [] },
  // live=实时事件 / replay=实采快照回放 / none=无事件
  mode: { type: String, default: "none" },
  modeLabel: { type: String, default: "无运行时事件" },
  // 主机名 → 生态节点 key 的映射，由父组件按设备清单算出
  nodesByHost: { type: Object, default: () => ({}) }
});

const slots = [
  { x: 196, y: 118 },
  { x: 706, y: 104 },
  { x: 208, y: 326 },
  { x: 700, y: 318 }
];

const canvasRef = ref(null);
const flowRef = ref(null);
const canvasSize = ref({ width: 900, height: 420 });
const playing = ref(true);
const activeKey = ref("");
const hoverKey = ref("");
const cutoff = ref(100);
const reducedMotion = ref(false);
let observer = null;
let motionQuery = null;
const onMotionChange = (event) => {
  reducedMotion.value = event.matches;
};

// 时间轴占用的底部高度；节点定位要用"可用高度"而不是画布全高，
// 否则底排节点会被时间轴压住（用户反馈的正是这个问题）。
const TIMELINE_H = 52;

const measure = () => {
  if (!canvasRef.value) return;
  const rect = canvasRef.value.getBoundingClientRect();
  const reserved = props.events.length ? TIMELINE_H : 0;
  canvasSize.value = {
    width: rect.width || 900,
    height: Math.max(160, (rect.height || 420) - reserved)
  };
};

onMounted(() => {
  if (typeof window !== "undefined" && window.matchMedia) {
    motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    reducedMotion.value = motionQuery.matches;
    motionQuery.addEventListener?.("change", onMotionChange);
  }
  if (!canvasRef.value) return;
  const update = measure;
  update();
  observer = new ResizeObserver(update);
  observer.observe(canvasRef.value);
  buildFlow();
  raf = requestAnimationFrame(tick);
});

onUnmounted(() => {
  if (observer) observer.disconnect();
  motionQuery?.removeEventListener?.("change", onMotionChange);
  if (raf) cancelAnimationFrame(raf);
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

/* ---------------- 事件 → 节点 ---------------- */

const eventTimes = computed(() =>
  props.events.map((e) => Date.parse(e.timestamp)).filter((n) => Number.isFinite(n))
);
const minTime = computed(() => (eventTimes.value.length ? Math.min(...eventTimes.value) : 0));
const maxTime = computed(() => (eventTimes.value.length ? Math.max(...eventTimes.value) : 0));

const activeEvents = computed(() => {
  if (!props.events.length) return [];
  if (cutoff.value >= 100) return props.events;
  const span = maxTime.value - minTime.value || 1;
  const end = minTime.value + (span * cutoff.value) / 100;
  return props.events.filter((e) => {
    const t = Date.parse(e.timestamp);
    return Number.isFinite(t) && t <= end;
  });
});

function keyOf(event) {
  return props.nodesByHost[event.hostname] || "other";
}

function eventCount(key) {
  return activeEvents.value.filter((e) => keyOf(e) === key).length;
}

function nodeEvents(key) {
  return activeEvents.value
    .filter((e) => keyOf(e) === key)
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
}

const highlightKey = computed(() => activeKey.value || hoverKey.value);
const activeNode = computed(() => nodes.value.find((n) => n.key === activeKey.value) || null);

function shortTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

const windowLabel = computed(() => {
  if (!props.events.length) return "无事件";
  if (cutoff.value >= 100) return `全窗口 ${props.events.length} 条`;
  const pct = cutoff.value;
  return `回放至 ${pct}%`;
});

function applyCutoff() {
  /* v-model 已更新，activeEvents 自动重算 */
}

/* ---------------- 数据流：沿连线朝中心流动 ---------------- */
let raf = null;
const flowDots = [];

function buildFlow() {
  const host = flowRef.value;
  if (!host) return;
  host.innerHTML = "";
  flowDots.length = 0;
  for (let i = 0; i < 16; i++) {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("r", "2.6");
    c.setAttribute("opacity", "0");
    host.appendChild(c);
    flowDots.push({
      el: c,
      key: "",
      t: Math.random(),
      speed: 0.00022 + Math.random() * 0.00026
    });
  }
}

const animating = computed(
  () => playing.value && !reducedMotion.value && props.events.length > 0 && props.mode !== "none"
);

function tick() {
  if (animating.value && flowDots.length && nodes.value.length) {
    const pathCache = new Map();
    for (const dot of flowDots) {
      if (!dot.key || !eventCount(dot.key)) {
        // 只给"窗口内有事件"的节点派点，避免无事件的生态也在动（那就是装饰了）
        const candidates = nodes.value.filter((n) => eventCount(n.key) > 0);
        if (!candidates.length) {
          dot.el.setAttribute("opacity", "0");
          continue;
        }
        dot.key = candidates[Math.floor(Math.random() * candidates.length)].key;
        dot.t = 0;
      }
      const node = nodes.value.find((n) => n.key === dot.key);
      if (!node) { dot.el.setAttribute("opacity", "0"); continue; }
      let path = pathCache.get(dot.key);
      if (!path) {
        path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute(
          "d",
          `M${node.x},${node.y + 8} C${node.x + (450 - node.x) * 0.35},${node.y + 20} ${node.x + (450 - node.x) * 0.62},250 450,250`
        );
        pathCache.set(dot.key, path);
      }
      const len = path.getTotalLength();
      dot.t += dot.speed * 16;
      if (dot.t > 1) {
        dot.t = 0;
        dot.key = "";
        continue;
      }
      const pt = path.getPointAtLength(dot.t * len);
      dot.el.setAttribute("cx", pt.x);
      dot.el.setAttribute("cy", pt.y);
      dot.el.setAttribute("fill", node.color);
      dot.el.setAttribute("opacity", "0.9");
    }
  } else if (flowDots.length) {
    for (const dot of flowDots) dot.el.setAttribute("opacity", "0");
  }
  raf = requestAnimationFrame(tick);
}

watch(() => props.events, () => {
  cutoff.value = 100;
  activeKey.value = "";
  // 事件到达/消失会切换时间轴的有无，可用高度随之变化，需要重新量一次
  measure();
}, { deep: false });
</script>

<style scoped>
.topology-canvas { position: relative; overflow: hidden; border-radius: 12px; }

/* 心跳：中心标识呼吸 = 后端在线；静态/减动效时停止 */
@keyframes topo-beat {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.045); }
}
.topo-core.beating { animation: topo-beat 3.2s ease-in-out infinite; }
.topology-canvas.is-static .topo-core.beating { animation: none; }

.topology-svg { position: absolute; inset: 0; display: block; width: 100%; height: 100%; }
/* 时间轴占用底部 52px：让 SVG 与节点定位都避开它，避免压住底排节点与中央字标 */
/* height:100% 会压过 bottom 偏移，必须显式改成 auto 才能真正让出底部空间 */
.topology-canvas.has-timeline .topology-svg { bottom: auto; height: calc(100% - 52px); }
.device-pod {
  position: absolute;
  transform: translate(-50%, -50%);
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px 8px 8px;
  border: 1px solid #e3edf9;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.92);
  box-shadow: 0 14px 30px -20px rgba(16, 35, 70, 0.5);
  backdrop-filter: blur(6px);
  z-index: 2;
  cursor: pointer;
}
.device-pod:focus-visible { outline: 2px solid var(--accent, #c95012); outline-offset: 2px; }
.device-pod.is-active { border-color: var(--pod-color); }
.device-pod.has-events::after {
  content: "";
  position: absolute;
  inset: -1px;
  border-radius: 12px;
  border: 1px solid var(--pod-color);
  opacity: 0.35;
  pointer-events: none;
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
.device-pod .pod-name { color: #5b6b82; font-size: 13.5px; font-weight: 600; line-height: 1.2; white-space: nowrap; }
.device-pod .pod-count { color: #0d1b2e; font-family: var(--font-num); font-size: 20px; font-weight: 800; line-height: 1.1; letter-spacing: -0.02em; }
.device-pod .pod-ev {
  margin-left: 2px;
  min-width: 20px;
  padding: 2px 4px;
  border-radius: 999px;
  background: var(--pod-color);
  color: #fff;
  font-size: 11.5px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

/* 右上角控制条 */
.topo-controls {
  position: absolute;
  top: 8px;
  right: 10px;
  display: flex;
  align-items: center;
  gap: 8px;
  z-index: 4;
}
.topo-mode {
  padding: 2px 8px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.92);
  border: 1px solid var(--line, #e0ddd7);
  font-size: 12px;
  font-weight: 600;
  color: var(--ink-3, #6b665f);
  white-space: nowrap;
}
.topo-mode.mode-live { color: var(--low, #1a6b45); border-color: var(--low-line, #c3ddcf); background: var(--low-soft, #e9f4ee); }
.topo-mode.mode-replay { color: var(--info, #1c5a86); border-color: #cbdce9; background: #eaf1f7; }
.topo-toggle {
  font: inherit;
  font-size: 12px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--line-strong, #cfcbc3);
  background: rgba(255, 255, 255, 0.92);
  color: var(--ink-2, #4d4843);
  cursor: pointer;
}
.topo-toggle:hover { background: #fff; border-color: var(--ink-3, #6b665f); }
.topo-toggle:focus-visible { outline: 2px solid var(--accent, #c95012); outline-offset: 2px; }

/* 节点检查器 */
.topo-inspect {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  bottom: 52px;
  width: 300px;
  max-height: 210px;
  overflow: auto;
  padding: 8px 12px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.96);
  border: 1px solid var(--line, #e0ddd7);
  box-shadow: 0 18px 40px -28px rgba(16, 35, 70, 0.55);
  z-index: 4;
}
.topo-inspect header { display: grid; gap: 2px; margin-bottom: 4px; }
.topo-inspect header b { font-size: 14px; color: var(--ink, #2a2723); }
.topo-inspect header span { font-size: 12px; color: var(--ink-3, #6b665f); }
.topo-inspect ul { margin: 0; padding: 0; list-style: none; }
.topo-inspect li {
  display: grid;
  grid-template-columns: auto auto 1fr;
  gap: 4px;
  align-items: baseline;
  padding: 4px 0;
  border-top: 1px dashed var(--line-soft, #eeece8);
  font-size: 12px;
}
.topo-inspect li .t { font-family: var(--font-mono, Consolas, monospace); color: var(--ink-3, #6b665f); }
.topo-inspect li .r { color: var(--ink, #2a2723); font-weight: 600; white-space: nowrap; }
.topo-inspect li .p { color: var(--ink-2, #4d4843); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.topo-inspect .none { margin: 4px 0 0; font-size: 12px; color: var(--ink-3, #6b665f); }
.topo-inspect .map-note { margin: 8px 0 0; font-size: 11.5px; line-height: 1.5; color: var(--muted, #7a746c); }

/* 时间轴 */
.topo-timeline {
  position: absolute;
  left: 10px;
  right: 10px;
  bottom: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.94);
  border: 1px solid var(--line, #e0ddd7);
  z-index: 4;
}
.topo-timeline .tl-label { font-size: 12.5px; color: var(--ink-2, #4d4843); white-space: nowrap; }
.topo-timeline .tl-count { font-size: 12.5px; color: var(--ink-3, #6b665f); white-space: nowrap; font-variant-numeric: tabular-nums; }
.topo-timeline input[type="range"] {
  flex: 1;
  appearance: none;
  height: 4px;
  border-radius: 999px;
  background: var(--line-strong, #cfcbc3);
  outline: none;
}
.topo-timeline input[type="range"]::-webkit-slider-thumb {
  appearance: none;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #fff;
  border: 2px solid var(--accent, #c95012);
  cursor: grab;
}
.topo-timeline input[type="range"]:focus-visible { outline: 2px solid var(--accent, #c95012); outline-offset: 4px; }
</style>
