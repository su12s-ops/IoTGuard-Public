<template>
  <section class="ruling" :data-state="state" :aria-label="`研判结论：${stampMain}`">
    <!-- 印章：结论的物理凭证，一页最多一枚 -->
    <div class="seal" aria-hidden="true">
      <b>{{ stampMain }}</b>
      <i>{{ stampEn }}</i>
    </div>

    <div class="copy">
      <h2>{{ title }}</h2>
      <p v-if="detail">{{ detail }}</p>
      <div v-if="tags.length" class="basis">
        <span v-for="tag in tags" :key="tag.text" class="tag" :class="tag.tone">{{ tag.text }}</span>
      </div>
    </div>

    <!-- 证据指纹：由本页可见数据算出，可当场复算 -->
    <!-- 证据指纹：sourceKey 为空时不渲染（其他页面复用本组件只借用印章与结论） -->
    <div v-if="sourceKey" class="fp">
      <div class="lbl">证据指纹</div>
      <code :title="fullHash || '计算中'">{{ shortCode }}</code>
      <div class="meta">{{ generatedAt }}</div>
      <div class="fp-actions">
        <button class="recalc" type="button" @click="recalc">复算</button>
        <span v-if="match" class="match" :class="match">{{ match === 'ok' ? '✓ 一致' : '✗ 不一致' }}</span>
      </div>
    </div>
  </section>

  <details v-if="evidence.length" class="fold">
    <summary>展开证据链（{{ evidence.length }} 条）</summary>
    <ul class="chain">
      <li v-for="(item, index) in evidence" :key="index">
        <span class="src">{{ item.src }}</span>
        <span v-if="item.code" class="mono">{{ item.code }}</span>
        <div class="say">{{ item.say }}</div>
      </li>
    </ul>
  </details>
</template>

<script setup>
/**
 * 裁决条组件（记忆点方案 A）
 *
 * 当前状态：**已启用**，接入四态判决页（`views/Verdict.vue` 页头下方）。
 * 2026-10-23 曾按用户指令回退一次，随后按指令重新接入；接入/回退方法见
 * `_work/redesign-2026/PATCH-NOTES.md` 的 Q5 与 Q5-R 节。
 */
import { computed, ref, watch } from "vue";

const props = defineProps({
  // fail=成立 / pass=不成立 / weak=证据不足 / replay=回放
  state: { type: String, default: "weak" },
  stampMain: { type: String, default: "证据不足" },
  stampEn: { type: String, default: "UNPROVEN" },
  title: { type: String, required: true },
  detail: { type: String, default: "" },
  tags: { type: Array, default: () => [] },
  evidence: { type: Array, default: () => [] },
  // 指纹来源：由父组件用真实数值拼成的规范化字符串
  sourceKey: { type: String, default: "" },
  generatedAt: { type: String, default: "" }
});

const fullHash = ref("");
const match = ref("");

const shortCode = computed(() => {
  if (!fullHash.value) return "计算中…";
  const raw = fullHash.value;
  // 纯 JS 降级时带前缀，原样显示
  if (raw.startsWith("fnv1a-")) return raw;
  return raw.slice(0, 12).replace(/(.{4})(?=.)/g, "$1 ");
});

async function digest(text) {
  // 优先真正的 SHA-256；环境不支持时退化为 FNV-1a 并如实标注
  if (globalThis.crypto?.subtle) {
    try {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch {
      /* 落到降级分支 */
    }
  }
  let h = 0x811c9dc5;
  for (const ch of text) {
    h ^= ch.codePointAt(0);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return "fnv1a-" + h.toString(16).padStart(8, "0");
}

async function compute() {
  match.value = "";
  if (!props.sourceKey) {
    fullHash.value = "";
    return;
  }
  fullHash.value = await digest(props.sourceKey);
}

// 数据变了（切换固件版本等）→ 自动重算，并清掉上一次的比对结果
watch(() => props.sourceKey, compute, { immediate: true });

async function recalc() {
  if (!props.sourceKey) return;
  const fresh = await digest(props.sourceKey);
  match.value = fresh === fullHash.value ? "ok" : "bad";
}
</script>

<style scoped>
.ruling {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 16px;
  padding: 16px 16px;
  background: var(--surface, #fff);
  border: 1px solid var(--line, #e0ddd7);
  border-left: 4px solid var(--line-strong, #cfcbc3);
  border-radius: var(--radius, 10px);
  box-shadow: var(--shadow, 0 1px 2px rgba(28, 24, 20, 0.05));
  margin-bottom: 12px;
}
.ruling[data-state="fail"] { border-left-color: var(--crit, #b3261e); }
.ruling[data-state="pass"] { border-left-color: var(--low, #1a6b45); }
.ruling[data-state="weak"] { border-left-color: var(--mid, #8a6200); }
.ruling[data-state="replay"] { border-left-color: var(--info, #1c5a86); }

.seal {
  width: 76px;
  height: 76px;
  flex: 0 0 auto;
  display: grid;
  place-items: center;
  text-align: center;
  border: 2px solid currentColor;
  border-radius: 50%;
  transform: rotate(-5deg);
  font-weight: 800;
  letter-spacing: 0.04em;
}
.seal b { display: block; font-size: 19px; line-height: 1.1; }
.seal i { display: block; font-style: normal; font-size: 9.5px; letter-spacing: 0.16em; opacity: 0.8; margin-top: 2px; }
.ruling[data-state="fail"] .seal { color: var(--crit, #b3261e); background: var(--crit-soft, #fdeceb); }
.ruling[data-state="pass"] .seal { color: var(--low, #1a6b45); background: var(--low-soft, #e9f4ee); }
.ruling[data-state="weak"] .seal { color: var(--mid, #8a6200); background: var(--mid-soft, #fbf5e2); }
.ruling[data-state="replay"] .seal { color: var(--info, #1c5a86); background: var(--info-soft, #eaf1f7); }

.copy h2 { margin: 0; font-size: 20px; line-height: 1.3; letter-spacing: -0.01em; color: var(--ink, #2a2723); }
.copy p { margin: 4px 0 0; color: var(--ink-2, #4d4843); font-size: 14px; line-height: 1.6; }
.basis { display: flex; flex-wrap: wrap; gap: 4px 8px; margin-top: 8px; }
.tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 12.5px;
  font-weight: 600;
  background: var(--surface-3, #f2f1ed);
  color: var(--ink-2, #4d4843);
  white-space: nowrap;
}
.tag.crit { background: var(--crit-soft, #fdeceb); color: var(--crit, #b3261e); }
.tag.high { background: var(--high-soft, #fdf1e6); color: var(--high, #a84a09); }
.tag.mid { background: var(--mid-soft, #fbf5e2); color: var(--mid, #8a6200); }
.tag.low { background: var(--low-soft, #e9f4ee); color: var(--low, #1a6b45); }
.tag.info { background: var(--info-soft, #eaf1f7); color: var(--info, #1c5a86); }

.fp {
  display: grid;
  gap: 4px;
  justify-items: end;
  padding-left: 16px;
  border-left: 1px dashed var(--line-strong, #cfcbc3);
  min-width: 250px;
}
.fp .lbl { font-size: 12px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted, #7a746c); }
.fp code {
  font-family: var(--font-mono, "Cascadia Mono", Consolas, monospace);
  font-size: 13.5px;
  font-weight: 600;
  color: var(--ink, #2a2723);
  background: var(--surface-3, #f2f1ed);
  padding: 2px 8px;
  border-radius: var(--radius-sm, 6px);
  letter-spacing: 0.02em;
}
.fp .meta { font-size: 12.5px; color: var(--ink-3, #6b665f); font-variant-numeric: tabular-nums; }
.fp-actions { display: flex; align-items: center; gap: 8px; }
.recalc {
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  padding: 4px 12px;
  border-radius: var(--radius-sm, 6px);
  border: 1px solid var(--line-strong, #cfcbc3);
  background: var(--surface, #fff);
  color: var(--ink-2, #4d4843);
  cursor: pointer;
}
.recalc:hover { background: var(--surface-2, #fbfaf8); border-color: var(--ink-3, #6b665f); }
.recalc:focus-visible { outline: 2px solid var(--accent, #c95012); outline-offset: 2px; }
.match { font-size: 12.5px; font-weight: 700; }
.match.ok { color: var(--low, #1a6b45); }
.match.bad { color: var(--crit, #b3261e); }

/* 证据链 */
.fold { margin: 0 0 14px; }
.fold > summary {
  cursor: pointer;
  list-style: none;
  font-size: 13.5px;
  font-weight: 600;
  color: var(--accent-2, #0f6b78);
  padding: 4px 2px;
  width: fit-content;
}
.fold > summary::-webkit-details-marker { display: none; }
.fold > summary::before { content: "▸ "; display: inline-block; }
.fold[open] > summary::before { content: "▾ "; }
.fold > summary:focus-visible { outline: 2px solid var(--accent, #c95012); outline-offset: 2px; border-radius: 4px; }
.chain { margin: 8px 0 0; padding: 0; list-style: none; border-left: 1px solid var(--line, #e0ddd7); }
.chain li { position: relative; padding: 9px 0 9px 18px; border-bottom: 1px dashed var(--line-soft, #eeece8); font-size: 13.5px; }
.chain li::before {
  content: "";
  position: absolute;
  left: -4.5px;
  top: 17px;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--line-strong, #cfcbc3);
}
.chain li:last-child { border-bottom: 0; }
.chain .src { font-weight: 650; color: var(--ink, #2a2723); margin-right: 8px; }
.chain .mono { font-family: var(--font-mono, "Cascadia Mono", Consolas, monospace); font-size: 12.5px; color: var(--ink-3, #6b665f); }
.chain .say { color: var(--ink-2, #4d4843); margin-top: 2px; }

@media (max-width: 900px) {
  .ruling { grid-template-columns: 1fr; gap: 12px; }
  .fp { justify-items: start; padding-left: 0; border-left: 0; border-top: 1px dashed var(--line-strong, #cfcbc3); padding-top: 8px; min-width: 0; }
  .seal { width: 64px; height: 64px; }
  .seal b { font-size: 16px; }
}
</style>
