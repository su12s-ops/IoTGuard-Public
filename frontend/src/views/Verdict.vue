<template>
  <PageHeader
    title="四态判决"
    subtitle="VERDICT CONSOLE"
    description="给定固件版本，九条 OpenWrt 官方公告各自的四态结论；浏览器复刻与服务端参照逐条对照，不一致会标红。"
  >
    <template #meta>
      <span class="mono v-meta">快照 {{ snapshotDate }} · {{ advisories.length }} 条公告 · fixture {{ shortHash(fixtureSha) }}</span>
    </template>
    <template #actions>
      <button class="btn v-kbd-btn" type="button" aria-keyshortcuts="Control+K" @click="openPalette">
        <kbd>Ctrl</kbd><kbd>K</kbd>命令
      </button>
      <button class="btn v-kbd-btn" type="button" :aria-expanded="helpOpen" @click="helpOpen = !helpOpen">
        <kbd>?</kbd>快捷键
      </button>
      <button class="btn" type="button" @click="printView">
        <Icon name="printer" :size="15" />打印
      </button>
    </template>
  </PageHeader>

  <VerdictRuling
    :state="ruling.state"
    :stamp-main="ruling.stampMain"
    :stamp-en="ruling.stampEn"
    :title="ruling.title"
    :detail="ruling.detail"
    :tags="ruling.tags"
    :evidence="ruling.evidence"
    :source-key="ruling.sourceKey"
    :generated-at="ruling.generatedAt"
  />

  <section class="card v-dial">
    <div class="card-head">
      <div>
        <h2 class="card-title">固件版本</h2>
        <div class="card-desc">仅接受三段版本号 X.Y.Z；两段会让判定退化成假的「超出范围」，这里直接拒绝。</div>
      </div>
      <span class="chip" :class="hasReference ? 'info' : 'mid'">
        {{ hasReference ? "服务端参照可用" : "无参照可校" }}
      </span>
    </div>
    <div class="card-body">
      <div class="v-hero">
        <label class="v-version">
          <span class="v-version-label">当前固件版本</span>
          <input
            v-model="versionInput"
            class="v-input mono"
            :class="{ invalid: invalid }"
            inputmode="numeric"
            spellcheck="false"
            maxlength="12"
            aria-label="固件版本（三段版本号）"
            @change="commitVersion"
            @keydown.enter.prevent="commitVersion"
            @keydown.up.prevent="step(1)"
            @keydown.down.prevent="step(-1)"
            @keydown.right.prevent="step(1)"
            @keydown.left.prevent="step(-1)"
          />
        </label>
        <p class="v-version-hint mono">仅接受 X.Y.Z · 输入或点下方刻度换档</p>
      </div>

      <div class="v-spectrum" :class="{ tick }" role="img" :aria-label="spectrumLabel">
        <span
          v-for="seg in spectrum.filter((item) => item.value > 0)"
          :key="'sp-' + seg.status"
          class="v-spectrum-seg"
          :class="'tone-' + seg.status"
          :style="{ flexGrow: seg.value }"
        >
          <b>{{ seg.value }}</b>
        </span>
      </div>
      <p class="v-spectrum-legend">
        <span v-for="seg in spectrum" :key="'sl-' + seg.status" class="v-spectrum-item">
          <i :class="'tone-' + seg.status" aria-hidden="true"></i>{{ seg.label }}
          <b>{{ seg.value }}</b>
        </span>
        <span class="v-spectrum-total">共 {{ advisories.length }} 条 · 互斥四态</span>
      </p>

      <div class="v-detents" role="group" aria-label="版本档位（服务端参照覆盖的 8 档）">
        <button
          v-for="item in grid"
          :key="item"
          type="button"
          class="v-detent"
          :class="{ active: item === version }"
          :aria-pressed="item === version"
          :title="tips[item]"
          @click="setVersion(item)"
        >{{ item }}</button>
      </div>

      <p class="v-asof mono">
        口径 · 官方公告快照 <b>{{ snapshotDate }}</b> · fixture <b>{{ shortHash(fixtureSha) }}</b>
        · 覆盖 <b>{{ advisories.length }}</b> 条 OpenWrt 官方 GHSA（Zephyr 快照不在本仓库，不在此复算）
        · 本页现算于 {{ computedAt }}
      </p>
    </div>
  </section>

  <section id="v-ledger-card" class="card v-ledger">
    <div class="card-head">
      <div>
        <h2 class="card-title">判决台账</h2>
        <div class="card-desc">点任一行展开依据、规范化记录与公告内容哈希；「对照」列对比基准版本。</div>
      </div>
      <div class="v-compare">
        <label class="v-compare-label" for="v-compare-select">对照基准</label>
        <select
          id="v-compare-select"
          v-model="compare"
          class="v-compare-select mono"
          aria-label="对照基准版本"
        >
          <option v-for="item in grid" :key="'c-' + item" :value="item">{{ item }}</option>
        </select>
        <span class="v-flips" :class="{ on: flips.length > 0 }">
          <template v-if="flips.length">翻转 <b>{{ flips.length }}</b> 条</template>
          <template v-else>无翻转</template>
        </span>
      </div>
    </div>
    <div class="table-wrap">
      <table class="v-table">
        <thead>
          <tr>
            <th class="c-no">序</th>
            <th class="c-cve">CVE</th>
            <th class="c-comp">组件</th>
            <th class="c-range">官方受影响范围</th>
            <th class="c-status">四态结论</th>
            <th class="c-cmp">对照 {{ compare }}</th>
            <th class="c-code">依据码</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="row in ledgerRows" :key="row.cve">
            <tr
              class="v-row"
              :class="{ open: openRow === row.cve, cursor: cursorIndex === row.index }"
              :data-cve="row.cve"
              @click="toggleRow(row.cve)"
            >
              <td class="c-no mono">{{ String(row.index + 1).padStart(2, "0") }}</td>
              <td class="c-cve mono">
                {{ row.cve }}
                <small>{{ row.severity }} · {{ row.cvss == null ? "无评分" : "CVSS " + row.cvss }}</small>
              </td>
              <td class="c-comp mono">{{ row.components.join(", ") || "—" }}</td>
              <td class="c-range mono">
                <div v-for="range in row.ranges" :key="range">{{ range }}</div>
              </td>
              <td class="c-status">
                <span class="chip" :class="chipTone(row.status)">{{ statusLabel[row.status] }}</span>
              </td>
              <td class="c-cmp">
                <template v-if="row.baseStatus">
                  <span v-if="row.baseStatus !== row.status" class="v-delta">
                    <span class="chip" :class="chipTone(row.baseStatus)">{{ statusLabel[row.baseStatus] }}</span> ≠
                  </span>
                  <span v-else class="v-same">同</span>
                </template>
                <span v-else class="v-same">无基准</span>
              </td>
              <td class="c-code mono">{{ row.code }}</td>
            </tr>
            <tr v-if="openRow === row.cve" :key="row.cve + '-d'" class="v-detail">
              <td colspan="7">
                <div class="v-detail-grid">
                  <div>
                    <span class="v-label">判定说明</span>
                    <p>{{ row.reason }}</p>
                  </div>
                  <div>
                    <span class="v-label">公告内容哈希</span>
                    <p class="mono v-break">{{ row.advisorySha }}</p>
                  </div>
                  <div>
                    <span class="v-label">规范化记录</span>
                    <p class="mono v-break">{{ row.records }}</p>
                  </div>
                  <div>
                    <span class="v-label">复算命令</span>
                    <p class="mono v-break">python showcase/server/verdict_engine.py --version {{ version }}</p>
                  </div>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
    <p v-if="flips.length" class="v-flip mono">
      与基准 {{ compare }} 相比：<b>{{ flips.length }} 条翻转</b> ·
      {{ flips.slice(0, 2).map((f) => f.cve + " " + statusLabel[f.from] + " → " + statusLabel[f.to]).join("；") }}
    </p>
    <p v-else class="v-flip mono">与基准 {{ compare }} 相比：无差异</p>
  </section>

  <section id="v-matrix-card" class="card v-matrix">
    <div class="card-head">
      <div>
        <h2 class="card-title">八档 × 九条判决矩阵</h2>
        <div class="card-desc">{{ matrixSummary }}</div>
      </div>
      <button class="btn" type="button" @click="matrixOpen = !matrixOpen">
        {{ matrixOpen ? "收起" : "展开" }}
      </button>
    </div>
    <div v-if="matrixOpen" class="card-body">
      <p class="v-matrix-legend mono">
        <span class="v-matrix-legend-item"><i class="tone-potentially_affected" aria-hidden="true"></i>候选受影响</span>
        <span class="v-matrix-legend-item"><i class="tone-insufficient_data" aria-hidden="true"></i>证据不足</span>
        <span class="v-matrix-legend-item"><i class="tone-not_in_reported_range" aria-hidden="true"></i>超出官方范围</span>
        <span class="v-matrix-legend-item"><i class="tone-affected" aria-hidden="true"></i>已确认受影响</span>
        <span class="v-matrix-legend-item"><i class="tone-diff" aria-hidden="true"></i>与基准不同</span>
        <span class="v-matrix-legend-row">行=固件档位 · 列=公告（与台账同序）· 点行换档</span>
      </p>
      <div class="v-matrix-wrap">
        <table class="v-matrix-table">
          <thead>
            <tr>
              <th class="v-matrix-corner">固件 ╲ 公告</th>
              <th v-for="(cell, index) in matrix[0].cells" :key="cell.cve" class="v-matrix-col">
                <span class="v-matrix-idx mono">{{ String(index + 1).padStart(2, "0") }}</span>
                <span class="v-matrix-tail mono">{{ cell.cve.replace(/^CVE-\d{4}-/, "") }}</span>
              </th>
              <th class="mono v-matrix-count-head">候选/不足/超范围</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in matrix"
              :key="'m-' + row.version"
              :class="{ current: row.version === version }"
              class="v-matrix-row"
              @click="setVersion(row.version)"
            >
              <td class="mono v-matrix-ver">{{ row.version }}</td>
              <td
                v-for="cell in row.cells"
                :key="row.version + cell.cve"
                class="v-matrix-cell"
                :class="['tone-' + cell.status, { diff: cell.diff }]"
                :title="cell.cve + ' · ' + statusLabel[cell.status]"
              ></td>
              <td class="mono v-matrix-counts">
                {{ row.counts.potentially_affected }}/{{ row.counts.insufficient_data }}/{{ row.counts.not_in_reported_range }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <section id="v-check-card" class="card v-check">
    <div class="card-head">
      <div>
        <h2 class="card-title">自检 · 设备端复刻 vs 服务端参照</h2>
        <div class="card-desc">
          {{ grid.length }} 个版本 × {{ advisories.length }} 条公告，逐条比对四态与依据码；不一致会在下方标红。
        </div>
      </div>
      <span class="chip" :class="selfcheck.ok ? 'low' : 'crit'">{{ selfcheck.matched }} / {{ selfcheck.total }}</span>
    </div>
    <div class="card-body">
      <div class="v-pins">
        <span
          v-for="pin in selfcheck.pins"
          :key="pin.version"
          class="v-pin mono"
          :class="{ bad: !pin.ok }"
        >{{ pin.version }} {{ pin.ok ? "✓" : "✗" }}</span>
      </div>
      <p class="v-asof mono">
        参照引擎 {{ engineModule }} · {{ engineStub }} · 当前 {{ version }} 与服务端参照
        {{ hasReference ? "逐条全等" : "无参照可校（只显示设备端单侧结论）" }}
      </p>
    </div>
  </section>

  <section id="v-bounds-card" class="card v-bounds">
    <div class="card-head">
      <div>
        <h2 class="card-title">边界：不成立的说法，逐条写在这里</h2>
        <div class="card-desc">{{ boundsSummary }}</div>
      </div>
    </div>
    <div class="card-body v-bounds-list">
      <article v-for="item in bounds" :key="item.claim" class="v-bound">
        <h3>{{ item.claim }}</h3>
        <p class="v-bound-detail">{{ item.detail }}</p>
        <dl class="v-bound-check">
          <div><dt>如果成立</dt><dd>{{ item.ifTrue }}</dd></div>
          <div><dt>实际看到</dt><dd>{{ item.actual }}</dd></div>
          <div><dt>结论</dt><dd><span class="chip" :class="item.verdict.tone">{{ item.verdict.text }}</span></dd></div>
        </dl>
        <p v-if="item.cite" class="v-cite mono" :title="`${item.cite.file}:${item.cite.line}`" @click="openLens(item.cite.id)">
          {{ item.cite.label }} · 第 {{ item.cite.line }} 行 · {{ shortHash(item.cite.sha) }}
        </p>
      </article>
    </div>
  </section>

  <transition name="lens">
    <aside v-if="lens" class="v-lens" role="dialog" aria-modal="false" aria-labelledby="v-lens-title">
      <header class="v-lens-head">
        <span class="chip info">{{ lens.state }}</span>
        <h2 id="v-lens-title">{{ lens.title }}</h2>
        <button class="btn" type="button" @click="lens = null">关闭</button>
      </header>
      <div class="v-lens-body">
        <p class="mono v-lens-value">{{ lens.value }}</p>
        <div class="v-lens-sec">
          <span class="v-label">来源文件</span>
          <p class="mono v-break">{{ fileLabel(lens.file) }}<template v-if="lens.line"> · 第 {{ lens.line }} 行</template></p>
          <!-- 分级披露：默认只给人话标签，内部路径折在下面，需要核验时再展开 -->
          <details class="v-src-detail">
            <summary>显示内部路径</summary>
            <p class="mono v-break">{{ lens.file }}</p>
          </details>
        </div>
        <div class="v-lens-sec">
          <span class="v-label">内容哈希 sha256</span>
          <p class="mono v-break">{{ lens.hash }}</p>
        </div>
        <div v-if="lens.note" class="v-lens-sec">
          <span class="v-label">口径说明</span>
          <p>{{ lens.note }}</p>
        </div>
        <div v-if="lens.quote" class="v-lens-sec">
          <span class="v-label">原文 / 片段</span>
          <p class="mono v-quote">{{ lens.quote }}</p>
        </div>
        <div v-if="lens.cmd" class="v-lens-sec">
          <span class="v-label">怎么复算</span>
          <p class="mono v-break">{{ lens.cmd }}</p>
        </div>
      </div>
    </aside>
  </transition>

  <div v-if="paletteOpen" class="v-overlay" @click.self="closePalette">
    <div class="v-palette" role="dialog" aria-modal="true" aria-label="命令面板">
      <div class="v-palette-input">
        <span class="v-palette-prefix" aria-hidden="true">›</span>
        <input
          ref="paletteInput"
          v-model="paletteQuery"
          class="mono"
          placeholder="输入版本号或命令…"
          aria-label="命令面板输入"
          @input="paletteIndex = 0"
          @keydown.down.prevent="movePalette(1)"
          @keydown.up.prevent="movePalette(-1)"
          @keydown.enter.prevent="runPalette(paletteIndex)"
          @keydown.esc.prevent="closePalette"
        />
      </div>
      <ul class="v-palette-list" role="listbox" aria-label="可用命令">
        <li
          v-for="(item, index) in filteredPalette"
          :key="item.id"
          role="option"
          :aria-selected="index === paletteIndex"
          class="v-palette-item"
          :class="{ active: index === paletteIndex }"
          @mouseenter="paletteIndex = index"
          @click="runPalette(index)"
        >
          <span class="v-palette-kind">{{ item.kind }}</span>
          <span class="v-palette-label">{{ item.label }}</span>
          <span class="v-palette-hint mono">{{ item.hint }}</span>
        </li>
        <li v-if="!filteredPalette.length" class="v-palette-empty">没有匹配的命令</li>
      </ul>
      <p class="v-palette-foot mono">
        <kbd>↑</kbd><kbd>↓</kbd> 选择　<kbd>Enter</kbd> 执行　<kbd>Esc</kbd> 关闭
        <span class="v-palette-count">{{ filteredPalette.length }} 项</span>
      </p>
    </div>
  </div>

  <div v-if="helpOpen" class="v-overlay" @click.self="helpOpen = false">
    <div class="v-help" role="dialog" aria-modal="true" aria-labelledby="v-help-title">
      <header class="v-help-head">
        <h2 id="v-help-title">快捷键与操作</h2>
        <button class="btn" type="button" @click="helpOpen = false">关闭 <kbd>Esc</kbd></button>
      </header>
      <dl class="v-help-list">
        <div><dt><kbd>Ctrl</kbd><kbd>K</kbd></dt><dd>命令面板：输入版本号或区块名，回车直达</dd></div>
        <div><dt><kbd>↑</kbd><kbd>↓</kbd></dt><dd>台账行光标（蓝色左边框）</dd></div>
        <div><dt><kbd>Enter</kbd></dt><dd>展开 / 收起光标所在行的依据</dd></div>
        <div><dt><kbd>?</kbd></dt><dd>打开 / 关闭本帮助</dd></div>
        <div><dt><kbd>Esc</kbd></dt><dd>依次关闭命令面板、帮助、出处透镜</dd></div>
        <div><dt>鼠标</dt><dd>点档位换版本；点台账行展开；点矩阵行换档；点虚线下划线数字看出处</dd></div>
      </dl>
      <p class="v-help-note">
        四态为互斥结论：候选受影响（版本域命中，仍需组件/配置/可达性证据）、证据不足（官方载荷无法确定）、
        超出官方范围（不是安全结论）、已确认受影响（本数据集 0 条）。
      </p>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import VerdictRuling from "../components/VerdictRuling.vue";
import data from "../data/verdict-data.json";
import { IGEngine as E } from "../lib/verdictEngine.js";

const statusLabel = E.STATUS_LABEL;
const grid = data.verdicts.meta.grid;
const advisories = data.advisories;
const verdictGrid = data.verdicts.grid;
const ledgerItems = data.ledger.items;
const meta = data.meta;

const version = ref(initialVersion());
const versionInput = ref(version.value);
const compare = ref("25.12.4");
const invalid = ref(false);
const openRow = ref("");
const matrixOpen = ref(false);
const lens = ref(null);
const computedAt = ref(new Date().toISOString().slice(11, 19) + "Z");

function initialVersion() {
  const match = /[#&]v=(\d+\.\d+\.\d+)/.exec(window.location.hash || "");
  return match && grid.includes(match[1]) ? match[1] : "25.12.4";
}

function shortHash(hash) {
  if (!hash) return "—";
  return hash.slice(0, 12) + "…" + hash.slice(-6);
}

/* 内部文件名 → 人话标签。
   证据台账的出处原本直接把仓库内 .md 文件名印在页面上，属于
   "机密路径上展示层"；这里改成默认显示人话标签，完整路径折进
   出处透镜的「显示内部路径」里，可追溯性不丢、台面保持干净。 */
const FILE_LABELS = {
  "IOTGUARD_VIRTUAL_IOT_FINAL_ACCEPTANCE_REPORT.md": "虚拟 IoT 最终验收报告",
  "docs/STATUS.md": "项目状态",
  "STATUS.md": "项目状态",
  "README.md": "项目说明",
  "TECHNICAL_ARCHITECTURE.md": "技术架构",
};

function fileLabel(file) {
  const raw = String(file || "").trim();
  if (!raw) return "内部文档";
  const base = raw.split("/").pop();
  return FILE_LABELS[raw] || FILE_LABELS[base] || "内部文档";
}

function statusMapOf(payload) {
  const map = {};
  (payload?.results || []).forEach((item) => { map[item.advisory_id] = item; });
  return map;
}

function chipTone(status) {
  if (status === "potentially_affected") return "high";
  if (status === "insufficient_data") return "mid";
  if (status === "not_in_reported_range") return "info";
  if (status === "affected") return "crit";
  return "low";
}

const payload = computed(() => E.classify(version.value, advisories));
const now = computed(() => statusMapOf(payload.value));
const base = computed(() => statusMapOf(verdictGrid[compare.value]));
const hasReference = computed(() => Boolean(verdictGrid[version.value]));

const composition = computed(() => [
  { status: "potentially_affected", label: "候选受影响", value: payload.value.counts.potentially_affected },
  { status: "insufficient_data", label: "证据不足", value: payload.value.counts.insufficient_data },
  { status: "not_in_reported_range", label: "超出官方范围", value: payload.value.counts.not_in_reported_range },
  {
    status: "affected",
    label: "已确认受影响",
    value: payload.value.results.filter((item) => item.status === "affected").length,
  },
]);
const spectrum = composition;
const spectrumLabel = computed(() => composition.value
  .map((seg) => seg.label + " " + seg.value)
  .join("，") + "，共 " + advisories.length + " 条");

/* —— 裁决条：把四态计数收敛成"一句话、一个印章、一个可复算的指纹" ——
   语义纪律：只有 affected 才叫「成立」；候选受影响与证据不足都归入「证据不足」，
   因为「不匹配」不等于「安全」，判不出来时绝不给绿色通过。 */
const ruling = computed(() => {
  const counts = payload.value.counts || {};
  const affected = composition.value.find((seg) => seg.status === "affected")?.value || 0;
  const candidate = Number(counts.potentially_affected || 0);
  const insufficient = Number(counts.insufficient_data || 0);
  const outOfRange = Number(counts.not_in_reported_range || 0);
  const total = advisories.length;
  const current = version.value;

  let state = "weak";
  let stampMain = "证据不足";
  let stampEn = "UNPROVEN";
  let title = "";
  let detail = "";

  if (affected > 0) {
    state = "fail";
    stampMain = "成立";
    stampEn = "CONFIRMED";
    title = `固件 ${current} 命中 ${affected} 条已确认受影响公告`;
    detail = `同一次研判中，${candidate} 条为候选受影响、${insufficient} 条证据不足、${outOfRange} 条超出官方受影响范围。`;
  } else if (candidate + insufficient > 0) {
    title = `固件 ${current} 目前无法判为安全`;
    detail = `${candidate} 条候选受影响、${insufficient} 条证据不足、${outOfRange} 条超出官方受影响范围。「未命中」不等于「安全」，因此这里不下通过结论。`;
  } else {
    state = "pass";
    stampMain = "不成立";
    stampEn = "REFUTED";
    title = `固件 ${current} 未落在任何一条公告的受影响范围内`;
    detail = `${total} 条公告全部判定为超出官方受影响范围；该结论的覆盖范围仅限这 ${total} 条公告。`;
  }

  const tags = [
    { text: `已确认受影响 ${affected}`, tone: "crit" },
    { text: `候选受影响 ${candidate}`, tone: "high" },
    { text: `证据不足 ${insufficient}`, tone: "mid" },
    { text: `超出官方范围 ${outOfRange}`, tone: "info" },
    { text: hasReference.value ? "服务端参照可用" : "无服务端参照可校", tone: "" }
  ];

  const engineSha = verdictGrid?.[current]?.engine?.engine_module_sha256 || "";
  const evidence = [
    {
      src: "官方公告快照",
      code: `fixture ${shortHash(fixtureSha.value)}`,
      say: `${total} 条 OpenWrt GHSA 公告，生成于 ${snapshotDate.value}；本页在浏览器内按版本区间重新复算，不是读取结论。`,
    },
    {
      src: "判定引擎",
      code: engineSha ? `openwrt_intel · ${engineSha.slice(0, 12)}` : "openwrt_intel",
      say: "输出四态判定（候选受影响 / 证据不足 / 超出范围 / 已确认受影响），不是二元的「安全 / 不安全」。",
    },
    {
      src: "输入",
      code: `版本 ${current} · 对照基准 ${compare.value}`,
      say: "仅接受三段版本号 X.Y.Z；两段版本会被直接拒绝，避免判定退化成假的「超出范围」。",
    },
    {
      src: "服务端参照",
      code: hasReference.value ? "已登记，可逐条对照" : "未登记",
      say: hasReference.value
        ? "该版本存在服务端参照结果，浏览器复算结果与其逐条对照，不一致会标红。"
        : "该版本没有服务端参照结果，结论仅来自浏览器复算，已标注为不可对校。",
    },
    {
      src: "口径边界",
      code: "不覆盖运行时利用证据",
      say: "四态结论只回答「该固件版本是否落在官方受影响范围内」，不代表设备是否已被实际利用。",
    },
  ];

  const sourceKey = JSON.stringify({
    version: current,
    total,
    affected,
    candidate,
    insufficient,
    outOfRange,
    fixture: fixtureSha.value || "",
    reference: hasReference.value,
  });

  const generatedRaw = String(data.verdicts.meta.generated_at_utc || snapshotDate.value || "");
  const generatedAt = `生成 ${generatedRaw.replace("T", " ").slice(0, 19)} · 证据 ${evidence.length} 条`;

  return { state, stampMain, stampEn, title, detail, tags, evidence, sourceKey, generatedAt };
});

const ledgerRows = computed(() => advisories.map((advisory, index) => {
  const result = now.value[advisory.ghsa_id];
  const baseResult = base.value[advisory.ghsa_id];
  return {
    index,
    cve: advisory.cve_id,
    severity: advisory.severity || "—",
    cvss: advisory.cvss_score,
    components: (result?.components || []),
    ranges: (advisory.ranges || []).map((range) => range.range),
    status: result?.status || "nodata",
    baseStatus: baseResult?.status || null,
    code: result?.code || "no_result",
    reason: result?.reason || "",
    advisorySha: advisory.advisory_sha256,
    records: (result?.normalized_records || [])
      .map((rec) => `${rec.package_name} · ${rec.release || "—"} · ${(rec.affected_versions || []).join("/")}`)
      .join("；") || "无",
  };
}));

const flips = computed(() => ledgerRows.value
  .filter((row) => row.baseStatus && row.baseStatus !== row.status)
  .map((row) => ({ cve: row.cve, from: row.baseStatus, to: row.status })));

const matrix = computed(() => grid.map((item) => {
  const gridPayload = verdictGrid[item];
  const map = statusMapOf(gridPayload);
  return {
    version: item,
    counts: gridPayload.counts,
    cells: advisories.map((advisory) => {
      const status = map[advisory.ghsa_id]?.status || "nodata";
      const baseStatus = base.value[advisory.ghsa_id]?.status || null;
      return {
        cve: advisory.cve_id,
        status,
        diff: baseStatus !== null && baseStatus !== status,
      };
    }),
  };
}));

const tips = computed(() => {
  const out = {};
  matrix.value.forEach((row) => {
    out[row.version] = row.version + " · 候选 " + row.counts.potentially_affected
      + " / 不足 " + row.counts.insufficient_data + " / 超范围 " + row.counts.not_in_reported_range;
  });
  return out;
});

const matrixSummary = computed(() => {
  const baseRow = matrix.value.find((row) => row.version === compare.value);
  let diff = 0;
  if (baseRow) {
    matrix.value.forEach((row) => {
      if (row.version === baseRow.version) return;
      row.cells.forEach((cell, index) => {
        if (baseRow.cells[index].status !== cell.status) diff += 1;
      });
    });
  }
  return grid.length + " 档 × " + advisories.length + " 条 · 当前 " + version.value
    + " · 与基准 " + compare.value + " 共 " + diff + " 格不同";
});

const selfcheck = computed(() => {
  let total = 0;
  let matched = 0;
  const pins = grid.map((item) => {
    const reference = verdictGrid[item];
    const mine = E.classify(item, advisories);
    const comparison = E.compareWithReference(mine, reference);
    total += comparison.checked;
    matched += comparison.checked - comparison.diffs.filter(
      (diff) => diff.field === "status" || diff.field === "code").length;
    return { version: item, ok: comparison.ok };
  });
  return { total, matched, pins, ok: total > 0 && matched === total };
});

const snapshotDate = computed(() => String(data.verdicts.meta.generated_at_utc || "").slice(0, 10));
const fixtureSha = computed(() => meta.fixture_sha256);
const engineModule = computed(() => meta.engine_module);
const engineStub = computed(() => data.verdicts.meta.engine_stub);

const bounds = [
  {
    claim: "「0 条确认受影响」不是安全结论",
    detail: "候选受影响 = 版本域命中但缺组件、配置、链接或可达性证据；证据不足 = 官方载荷本身无法确定；其余超出官方报告范围。",
    ifTrue: "9 条里至少 1 条能拿出组件 + 配置 + 可达性证据，判定为 affected",
    actual: "affected 0 条；2 条证据不足；6 条超出官方报告范围",
    verdict: { text: "不成立", tone: "crit" },
    cite: pickLedger("affected"),
  },
  {
    claim: "Zephyr 的 281 / 125 / 54 / 71 只能回放，不能在此复算",
    detail: "这四个数字的原始快照不在本仓库（位于 gitignored 的报告目录），本页只有 OpenWrt 9 条。",
    ifTrue: "仓库里存在 Zephyr 官方快照，且本页判定函数能吃它",
    actual: "仓库无该快照；本页只覆盖 OpenWrt 9 条官方公告",
    verdict: { text: "不可复算 · 只回放", tone: "mid" },
    cite: pickLedger("281"),
  },
  {
    claim: "599.84 秒不等于长期稳定",
    detail: "最长稳定健康窗口约十分钟、21/21 样本；另有失败样本与恢复窗口保留。",
    ifTrue: "存在 ≥ 24 小时连续健康窗口，且丢失计数可用",
    actual: "最长 599.84 秒；Falco 丢失计数为 unavailable",
    verdict: { text: "不成立", tone: "crit" },
    cite: pickLedger("599.84"),
  },
  {
    claim: "817 passed / 3 skipped 是历史 CI 运行",
    detail: "本机 Python 3.11 且无 SQLAlchemy，测试套件未在此环境执行；本页只声称引用了该次运行。",
    ifTrue: "本机能跑通测试套件并得出同样的 817 passed / 3 skipped",
    actual: "本机未跑测试套件（环境缺依赖）",
    verdict: { text: "不成立", tone: "crit" },
    cite: pickLedger("817"),
  },
  {
    claim: "服务端参照是真实函数跑出来的",
    detail: "verdict_engine 直接 import 仓库原文件，空 app.models 只屏蔽 ORM 声明，判定函数体未改一字。",
    ifTrue: "参照引擎绕开仓库函数、另写一套逻辑",
    actual: "导入 backend/app/services/openwrt_intel.py；stub 仅屏蔽 ORM",
    verdict: { text: "成立 · 可自检", tone: "low" },
    cite: null,
  },
  {
    claim: "两段版本号会被拒绝",
    detail: "仓库 version_in_range 只做严格三段解析；两段会退化成假的 not_affected，本页不让它上屏。",
    ifTrue: "输入 25.12 会被接受并给出某个四态结论",
    actual: "输入层直接拒绝并提示",
    verdict: { text: "成立 · 已断言", tone: "low" },
    cite: null,
  },
  {
    claim: "本页没有任何写入能力",
    detail: "页面只读冻结数据与判定函数，不调用任何修复、审批或写接口。",
    ifTrue: "页面存在 POST/PUT 请求或写端点",
    actual: "仅本地冻结数据 + 纯函数计算",
    verdict: { text: "成立 · 只读", tone: "low" },
    cite: null,
  },
];

function pickLedger(token) {
  const item = ledgerItems.find((entry) => entry.value_token.indexOf(token) !== -1);
  if (!item) return null;
  return {
    id: item.id,
    label: item.meaning,
    file: item.file,
    line: item.line,
    sha: item.file_sha256,
    quote: item.quote,
    token: item.value_token,
  };
}

const boundsSummary = computed(() => {
  const fail = bounds.filter((item) => item.verdict.tone === "crit").length;
  const pass = bounds.filter((item) => item.verdict.tone === "low").length;
  const na = bounds.filter((item) => item.verdict.tone === "mid").length;
  return bounds.length + " 条说法 · 成立 " + pass + " · 不成立 " + fail + " · 不可复算 " + na
    + " —— 每条都给「如果成立你会看到什么」与「实际看到什么」。";
});

const lensIndex = computed(() => {
  const items = {
    fixture: {
      state: "⟲ 冻结回放",
      title: "公告快照文件",
      value: meta.fixture,
      file: meta.fixture,
      hash: meta.fixture_sha256,
      note: "逐条内容哈希口径与仓库导入函数一致（规范化 JSON 后取 sha256）。",
      quote: "源：" + meta.fixture,
      cmd: "python _work/port_to_new_frontend.py",
    },
    engine: {
      state: "⟲ 冻结回放",
      title: "服务端参照引擎",
      value: meta.engine_module,
      file: meta.engine_module,
      hash: meta.engine_module_sha256,
      note: engineStub.value,
      quote: "python " + meta.python,
      cmd: "python showcase/server/verdict_engine.py --selftest",
    },
  };
  ledgerItems.forEach((item) => {
    items[item.id] = {
      state: "⟲ 冻结回放 · 文档数字",
      title: item.meaning,
      value: item.value_token,
      file: item.file,
      line: item.line,
      hash: item.file_sha256,
      note: "出处行在导出时被断言过：该行必须包含该标记，断言失败则导出中止。",
      quote: item.quote,
      cmd: "python _work/port_to_new_frontend.py",
    };
  });
  return items;
});

function openLens(key) {
  lens.value = lensIndex.value[key] || null;
}

function setVersion(next) {
  if (!E.isValidVersion(next)) return;
  const changed = next !== version.value;
  version.value = next;
  versionInput.value = next;
  invalid.value = false;
  openRow.value = "";
  computedAt.value = new Date().toISOString().slice(11, 19) + "Z";
  syncHash();
  if (changed) {
    tick.value = false;
    window.clearTimeout(tickTimer);
    window.requestAnimationFrame(() => { tick.value = true; });
    tickTimer = window.setTimeout(() => { tick.value = false; }, 520);
  }
}

function commitVersion() {
  const next = String(versionInput.value || "").trim().replace(/^v/i, "");
  if (!E.isValidVersion(next)) {
    invalid.value = true;
    versionInput.value = version.value;
    return;
  }
  setVersion(next);
}

function step(delta) {
  const index = grid.indexOf(version.value);
  if (index === -1) return;
  const next = Math.min(grid.length - 1, Math.max(0, index + delta));
  if (next !== index) setVersion(grid[next]);
}

function toggleRow(cve) {
  openRow.value = openRow.value === cve ? "" : cve;
}

function printView() {
  window.print();
}

function syncHash() {
  try {
    window.history.replaceState(null, "", "#v=" + version.value);
  } catch (error) {
    window.location.hash = "#v=" + version.value;
  }
}

watch(version, syncHash);

/* ── 操作层：命令面板 / 快捷键帮助 / 行光标 ─────────────────────────────── */

const paletteOpen = ref(false);
const paletteQuery = ref("");
const paletteIndex = ref(0);
const paletteInput = ref(null);
const helpOpen = ref(false);
const cursorIndex = ref(-1);
const tick = ref(false);
let tickTimer = null;

const paletteSource = computed(() => {
  const items = matrix.value.map((row) => ({
    id: "ver:" + row.version,
    kind: "版本",
    label: row.version,
    hint: "候选 " + row.counts.potentially_affected + " / 不足 " + row.counts.insufficient_data
      + " / 超范围 " + row.counts.not_in_reported_range,
    run: () => setVersion(row.version),
  }));
  [
    ["判决台账", "v-ledger-card"],
    ["判决矩阵", "v-matrix-card"],
    ["自检", "v-check-card"],
    ["边界判据", "v-bounds-card"],
  ].forEach(([label, id]) => {
    items.push({
      id: "sec:" + id,
      kind: "跳到",
      label,
      hint: "滚动到该区块",
      run: () => scrollToSection(id),
    });
  });
  items.push({
    id: "act:link",
    kind: "动作",
    label: "复制本页深链",
    hint: "带当前版本的地址",
    run: copyLink,
  });
  items.push({
    id: "act:print",
    kind: "动作",
    label: "打印视图",
    hint: "浏览器打印 / 另存 PDF",
    run: () => window.print(),
  });
  return items;
});

const filteredPalette = computed(() => {
  const query = paletteQuery.value.trim().toLowerCase();
  if (!query) return paletteSource.value;
  return paletteSource.value.filter((item) =>
    (item.kind + " " + item.label + " " + item.hint).toLowerCase().includes(query));
});

function openPalette() {
  paletteOpen.value = true;
  paletteQuery.value = "";
  paletteIndex.value = 0;
  nextTick(() => paletteInput.value?.focus());
}

function closePalette() {
  paletteOpen.value = false;
}

function movePalette(delta) {
  const total = filteredPalette.value.length;
  if (!total) return;
  paletteIndex.value = (paletteIndex.value + delta + total) % total;
}

function runPalette(index) {
  const item = filteredPalette.value[index];
  if (!item) return;
  closePalette();
  item.run();
}

function scrollToSection(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function copyLink() {
  const url = window.location.origin + window.location.pathname + "#v=" + version.value;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).catch(() => {});
  }
}

function moveCursor(delta) {
  const rows = ledgerRows.value;
  if (!rows.length) return;
  const base = cursorIndex.value < 0 ? (delta > 0 ? -1 : rows.length) : cursorIndex.value;
  cursorIndex.value = Math.max(0, Math.min(rows.length - 1, base + delta));
  nextTick(() => {
    const cve = rows[cursorIndex.value]?.cve;
    document.querySelector(`.v-row[data-cve="${cve}"]`)?.scrollIntoView({ block: "nearest" });
  });
}

function toggleCursorRow() {
  const row = ledgerRows.value[cursorIndex.value];
  if (row) toggleRow(row.cve);
}

function onGlobalKeydown(event) {
  const tag = String(event.target?.tagName || "").toLowerCase();
  const typing = tag === "input" || tag === "textarea";
  if ((event.ctrlKey || event.metaKey) && String(event.key).toLowerCase() === "k") {
    event.preventDefault();
    if (paletteOpen.value) closePalette(); else openPalette();
    return;
  }
  if (event.key === "Escape") {
    if (paletteOpen.value) { closePalette(); return; }
    if (helpOpen.value) { helpOpen.value = false; return; }
    if (lens.value) { lens.value = null; return; }
  }
  if (typing) return;
  if (event.key === "?") {
    event.preventDefault();
    helpOpen.value = !helpOpen.value;
    return;
  }
  if (paletteOpen.value || helpOpen.value) return;
  if (event.key === "ArrowDown") { event.preventDefault(); moveCursor(1); return; }
  if (event.key === "ArrowUp") { event.preventDefault(); moveCursor(-1); return; }
  if (event.key === "Enter") { event.preventDefault(); toggleCursorRow(); }
}

onMounted(() => {
  window.addEventListener("keydown", onGlobalKeydown);
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", onGlobalKeydown);
});


onMounted(() => {
  watchHash();
  window.addEventListener("hashchange", watchHash);
});

function watchHash() {
  const match = /[#&]v=(\d+\.\d+\.\d+)/.exec(window.location.hash || "");
  if (match && grid.includes(match[1]) && match[1] !== version.value) {
    version.value = match[1];
    versionInput.value = match[1];
  }
}
</script>

<style scoped>
.v-meta { color: var(--ink-3); font-size: 13.5px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 12px; }

.v-dial-row { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; }
.v-version { display: grid; gap: 4px; }
.sr-label { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
.v-input {
  width: 7.2ch;
  padding: 2px 4px 8px;
  font-size: 56px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--ink);
  background: transparent;
  border: 0;
  border-bottom: 2px solid var(--line-strong);
  outline: none;
}
.v-input:focus-visible { border-bottom-color: var(--accent-2); }
.v-input.invalid { color: var(--crit); border-bottom-color: var(--crit-line); }

.v-detents { display: grid; grid-template-columns: repeat(8, minmax(0, 1fr)); gap: 4px; flex: 1 1 560px; }
.v-detent {
  padding: 8px 4px;
  font-family: var(--font-num);
  font-size: 14px;
  color: var(--ink-3);
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: color 0.18s, border-color 0.18s, background 0.18s;
}
.v-detent:hover { color: var(--ink); border-color: var(--line-strong); }
.v-detent.active { color: #fff; background: var(--gradient-brand); border-color: transparent; }

.v-asof { margin: 10px 0 0; font-size: 13.5px; color: var(--ink-3); line-height: 1.6; }
.v-asof b { color: var(--ink-2); font-weight: 600; }

.v-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.v-table th {
  padding: 8px 12px;
  text-align: left;
  font-size: 13.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--ink-3);
  background: var(--surface-2);
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
.v-table td { padding: 8px 12px; border-bottom: 1px solid var(--line-soft); vertical-align: top; color: var(--ink-2); }
.v-row { cursor: pointer; }
.v-row:hover { background: var(--surface-2); }
.v-row.open { background: var(--surface-3); }
.c-no { width: 3.4em; color: var(--ink-3); }
.c-cve { white-space: nowrap; color: var(--ink); font-weight: 600; }
.c-cve small { display: block; margin-top: 2px; font-size: 12.5px; font-weight: 400; color: var(--ink-3); }
.c-comp { width: 9em; }
.c-range { min-width: 14em; }
.c-status { width: 8.5em; }
.c-cmp { width: 9.5em; }
.c-code { width: 18em; font-size: 12.5px; color: var(--ink-3); overflow-wrap: anywhere; }
.v-same { color: var(--ink-3); font-size: 13.5px; }
.v-delta { display: inline-flex; align-items: center; gap: 4px; color: var(--accent); font-weight: 600; }
.v-detail > td { background: var(--surface-2); }
.v-detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; padding: 4px 2px; }
.v-label { display: block; margin-bottom: 2px; font-size: 12.5px; letter-spacing: 0.06em; color: var(--ink-3); }
.v-detail-grid p { margin: 0; font-size: 14px; line-height: 1.6; color: var(--ink-2); }
.v-break { overflow-wrap: anywhere; }
.v-flip { margin: 0; padding: 8px 16px 12px; font-size: 13.5px; color: var(--ink-3); }
.v-flip b { color: var(--accent); }

.v-compare { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
.v-matrix-wrap { overflow-x: auto; }
.v-matrix-table { width: 100%; border-collapse: separate; border-spacing: 2px; font-size: 12.5px; }
.v-matrix-table th { color: var(--ink-3); font-weight: 500; text-align: left; white-space: nowrap; }
.v-matrix-row { cursor: pointer; }
.v-matrix-ver { color: var(--ink-2); white-space: nowrap; padding-right: 4px; }
.v-matrix-row.current .v-matrix-ver { color: var(--accent); font-weight: 700; }
.v-matrix-cell { height: 14px; border-radius: 3px; border: 1px solid var(--line); }
.v-matrix-cell.tone-potentially_affected { background: var(--high); border-color: transparent; }
.v-matrix-cell.tone-insufficient_data { background: var(--mid); border-color: transparent; }
.v-matrix-cell.tone-not_in_reported_range { background: var(--info-soft); border-color: var(--info-line); }
/* 与对照基准不同的格：橙色内描边，让"翻转"在矩阵里自己说话 */
.v-matrix-cell { position: relative; }
/* 翻转标记与填充正交：右上角墨色缺口，橙底/浅底上都成立 */
.v-matrix-cell.diff::after {
  content: "";
  position: absolute;
  top: 0;
  right: 0;
  width: 0;
  height: 0;
  border-top: 6px solid var(--ink);
  border-left: 6px solid transparent;
}
.v-matrix-counts { color: var(--ink-3); white-space: nowrap; padding-left: 8px; }

.v-pins { display: flex; flex-wrap: wrap; gap: 4px; }
.v-pin { padding: 2px 8px; font-size: 13.5px; color: var(--ink-2); background: var(--surface-2); border: 1px solid var(--line); border-radius: 6px; }
.v-pin.bad { color: var(--crit); background: var(--crit-soft); border-color: var(--crit-line); }

.v-bounds-list { display: grid; gap: 12px; }
.v-bound h3 { margin: 0 0 4px; font-size: 13.5px; color: var(--ink); }
.v-bound-detail { margin: 0 0 8px; font-size: 14px; line-height: 1.65; color: var(--ink-2); }
.v-bound-check { display: grid; gap: 4px; margin: 0 0 8px; padding: 10px 0; border-top: 1px solid var(--line-soft); border-bottom: 1px solid var(--line-soft); }
.v-bound-check > div { display: grid; grid-template-columns: 6.5em minmax(0, 1fr); gap: 8px; align-items: baseline; }
.v-bound-check dt { font-size: 13.5px; color: var(--ink-3); }
.v-bound-check dd { margin: 0; font-size: 14px; color: var(--ink-2); }
.v-cite { margin: 0; font-size: 13.5px; color: var(--accent-2); cursor: pointer; }
.v-cite:hover { text-decoration: underline; text-underline-offset: 3px; }

.v-lens {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(420px, 94vw);
  z-index: 60;
  display: flex;
  flex-direction: column;
  background: var(--surface);
  border-left: 1px solid var(--line-strong);
  box-shadow: var(--shadow-pop);
}
.v-lens-head { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--line); }
.v-lens-head h2 { margin: 0; margin-right: auto; font-size: 15px; color: var(--ink); }
.v-lens-body { padding: 16px; overflow: auto; display: grid; gap: 12px; }
.v-lens-value { margin: 0; font-size: 15px; color: var(--ink); overflow-wrap: anywhere; }
.v-lens-sec p { margin: 0; font-size: 14px; line-height: 1.6; color: var(--ink-2); }
/* 内部路径分级披露：默认收起，需要核验时再展开 */
.v-src-detail { margin-top: 4px; }
.v-src-detail summary {
  cursor: pointer;
  list-style: none;
  width: fit-content;
  font-size: 12.5px;
  color: var(--ink-3);
  padding: 2px 0;
}
.v-src-detail summary::-webkit-details-marker { display: none; }
.v-src-detail summary::before { content: "▸ "; }
.v-src-detail[open] summary::before { content: "▾ "; }
.v-src-detail summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
.v-src-detail p { margin-top: 4px; padding: 4px 8px; background: var(--surface-3); border-radius: 6px; font-size: 12.5px; word-break: break-all; }
.v-quote { padding-left: 8px; border-left: 2px solid var(--accent-2); color: var(--ink-3) !important; font-size: 13.5px !important; }

.lens-enter-active, .lens-leave-active { transition: transform 0.22s ease, opacity 0.22s ease; }
.lens-enter-from, .lens-leave-to { transform: translateX(16px); opacity: 0; }

@media (max-width: 1080px) {
.v-detents { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .v-input { font-size: 34px; }
  .c-code { display: none; }
  .v-table th, .v-table td { padding: 8px 8px; }
}

@media print {
  .v-lens, .v-compare, .v-detents { display: none !important; }
  .card { box-shadow: none; break-inside: avoid; }
  .v-table th { background: transparent; }
}

/* ── 动效：入场编排 + 数值变化闪动（REDUCED 下全灭） ───────────────────── */

@media (prefers-reduced-motion: no-preference) {
  @keyframes v-rise {
    from { opacity: 0; transform: translate3d(0, 8px, 0); }
    to { opacity: 1; transform: translate3d(0, 0, 0); }
  }
  @keyframes v-tick {
    0% { transform: scale(1); opacity: 1; }
    35% { transform: scale(0.965); opacity: 0.72; }
    100% { transform: scale(1); opacity: 1; }
  }
.v-dial { animation: v-rise 0.34s cubic-bezier(0.16, 1, 0.3, 1) 0.04s both; }
  .v-ledger { animation: v-rise 0.34s cubic-bezier(0.16, 1, 0.3, 1) 0.08s both; }
  .v-matrix { animation: v-rise 0.34s cubic-bezier(0.16, 1, 0.3, 1) 0.12s both; }
  .v-check { animation: v-rise 0.34s cubic-bezier(0.16, 1, 0.3, 1) 0.16s both; }
  .v-bounds { animation: v-rise 0.34s cubic-bezier(0.16, 1, 0.3, 1) 0.2s both; }
}

@media (prefers-reduced-motion: reduce) {
.v-spectrum.tick .v-spectrum-seg { animation: none !important; }
}

/* ── 操作层：kbd / 行光标 / 命令面板 / 帮助 ─────────────────────────────── */

.v-kbd-btn { display: inline-flex; align-items: center; gap: 4px; }
kbd {
  display: inline-block;
  min-width: 1.4em;
  padding: 2px 4px;
  font-family: var(--font-num);
  font-size: 12.5px;
  line-height: 1.5;
  text-align: center;
  color: var(--ink-3);
  background: var(--surface-2);
  border: 1px solid var(--line-strong);
  border-radius: 5px;
}

.v-row.cursor { background: var(--info-soft); box-shadow: inset 3px 0 0 0 var(--accent-2); }

.v-overlay {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: grid;
  place-items: start center;
  padding: 12vh 16px 16px;
  background: rgba(13, 27, 46, 0.42);
  backdrop-filter: blur(2px);
}
.v-palette {
  width: min(680px, 94vw);
  background: var(--surface);
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-pop);
  overflow: hidden;
}
.v-palette-input { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--line); }
.v-palette-prefix { color: var(--accent-2); font-size: 15px; }
.v-palette-input input {
  flex: 1;
  min-width: 0;
  border: 0;
  outline: none;
  background: transparent;
  font-size: 15px;
  color: var(--ink);
}
.v-palette-input input::placeholder { color: var(--ink-3); }
.v-palette-list { max-height: 46vh; overflow: auto; margin: 0; padding: 6px 0; list-style: none; }
.v-palette-item {
  display: grid;
  grid-template-columns: 3.6em minmax(0, 1fr) auto;
  gap: 12px;
  align-items: baseline;
  padding: 8px 16px;
  cursor: pointer;
  border-left: 2px solid transparent;
}
.v-palette-item.active { background: var(--surface-2); border-left-color: var(--accent-2); }
.v-palette-kind { font-size: 12.5px; letter-spacing: 0.06em; color: var(--ink-3); }
.v-palette-label { font-size: 13.5px; color: var(--ink); }
.v-palette-hint { font-size: 13.5px; color: var(--ink-3); text-align: right; }
.v-palette-empty { padding: 12px 16px; font-size: 14px; color: var(--ink-3); }
.v-palette-foot {
  display: flex;
  align-items: center;
  gap: 4px;
  margin: 0;
  padding: 8px 16px 8px;
  border-top: 1px solid var(--line);
  font-size: 13.5px;
  color: var(--ink-3);
}
.v-palette-count { margin-left: auto; color: var(--ink-3); }

.v-help {
  width: min(620px, 94vw);
  background: var(--surface);
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-pop);
  padding: 16px 16px;
  display: grid;
  gap: 12px;
}
.v-help-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.v-help-head h2 { margin: 0; font-size: 15px; color: var(--ink); }
.v-help-list { display: grid; gap: 8px; margin: 0; }
.v-help-list > div { display: grid; grid-template-columns: 8.5em minmax(0, 1fr); gap: 8px; align-items: baseline; }
.v-help-list dt { display: flex; gap: 2px; }
.v-help-list dd { margin: 0; font-size: 14px; color: var(--ink-2); }
.v-help-note {
  margin: 0;
  padding-top: 8px;
  border-top: 1px solid var(--line);
  font-size: 13.5px;
  line-height: 1.65;
  color: var(--ink-3);
}

@media (max-width: 1080px) {
  .v-kbd-btn kbd { display: none; }
  /* 触摸目标：窄屏一律抬到 ≥32px（审计实测原先档位 31、对照 chip 22） */
  .v-detent { min-height: 36px; }
  .v-row { min-height: 40px; }
}

/* ── 页内字阶/色阶收敛：把继承来的 9.5/11/12/13/14px 与多档灰蓝并到 6 档、3 档灰 ─────
   只作用于本页，不改全局 console.css（其余六页保持原样）。 */
:deep(.page-head h1) { font-size: 27px; letter-spacing: -0.014em; }
:deep(.ph-en),
:deep(.ph-desc),
:deep(.ph-meta),
:deep(.ph-sep),
:deep(.ph-divider) { font-size: 14px; color: var(--ink-3); }
:deep(.kbd) { font-size: 12.5px; }
:deep(.top-avatar) { font-size: 13.5px; }
.sr-label { font-size: 12.5px; }
:deep(.chip) { font-size: 12.5px; }
:deep(.card-title) { font-size: 15px; letter-spacing: 0; }
:deep(.card-desc) { font-size: 13.5px; color: var(--ink-3); }
:deep(.btn) { font-size: 13.5px; }
.mono { font-variant-numeric: tabular-nums; }

/* ── R16 重排：仪器化的读数与谱带（按独立评审的三条意见改） ─────────────── */

.v-hero { display: grid; gap: 2px; }
.v-version { display: grid; gap: 2px; }
.v-version-label {
  font-size: 13.5px;
  letter-spacing: 0.08em;
  color: var(--ink-3);
}
.v-version-hint { margin: 0; font-size: 13.5px; color: var(--ink-3); }

.v-spectrum {
  display: flex;
  gap: 2px;
  height: 28px;
  margin-top: 12px;
  border-radius: 6px;
  overflow: hidden;
  background: var(--surface-3);
}
.v-spectrum-seg {
  display: grid;
  place-items: center;
  min-width: 0;
  font-size: 13.5px;
  color: #fff;
  transition: flex-grow 0.34s cubic-bezier(0.16, 1, 0.3, 1);
}
.v-spectrum-seg b { font-weight: 700; }
.v-spectrum-seg.tone-potentially_affected { background: var(--high); }
.v-spectrum-seg.tone-insufficient_data { background: var(--mid); }
.v-spectrum-seg.tone-not_in_reported_range { background: var(--info); opacity: 0.55; }
.v-spectrum-seg.tone-affected { background: var(--crit); }
.v-spectrum-seg b { color: #fff; }
.v-spectrum-seg:empty { min-width: 2px; }
.v-spectrum-seg.tone-not_in_reported_range b { color: var(--ink); }
/* 0 条也画出来，但画成"空槽"：不给实色，避免读成"有 1 个" */


.v-spectrum-legend {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 12px;
  margin: 8px 0 0;
  font-size: 13.5px;
  color: var(--ink-3);
}
.v-spectrum-item { display: inline-flex; align-items: baseline; gap: 4px; }
.v-spectrum-item i { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
.v-spectrum-item i.tone-potentially_affected { background: var(--high); }
.v-spectrum-item i.tone-insufficient_data { background: var(--mid); }
.v-spectrum-item i.tone-not_in_reported_range { background: var(--info); opacity: 0.55; }
.v-spectrum-item i.tone-affected { background: var(--crit); }
.v-spectrum-item b { color: var(--ink); font-weight: 700; }
.v-spectrum-total { margin-left: auto; color: var(--ink-3); }

/* 版本刻度：选中态改用墨色描边，橙色只留给"候选"与"翻转" */
.v-detents { margin-top: 12px; }
.v-detent.active {
  color: var(--ink);
  background: var(--surface);
  border-color: var(--ink);
  box-shadow: inset 0 -2px 0 0 var(--ink);
}

/* 对照基准：一个原生 select + 翻转计数 */
.v-compare { display: inline-flex; align-items: center; gap: 8px; }
.v-compare-select {
  min-height: 32px;
  padding: 4px 8px;
  font-size: 13.5px;
  color: var(--ink);
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.v-compare-select:focus-visible { outline: 2px solid var(--accent-2); outline-offset: 1px; }
.v-flips {
  font-size: 13.5px;
  color: var(--ink-3);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 2px 8px;
}
.v-flips.on { color: var(--accent); border-color: var(--accent); background: var(--accent-soft); }
.v-flips b { font-weight: 700; }

/* 矩阵：两行列头 + 图例 + "超出范围"保留描边 */
.v-matrix-legend {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  margin: 0 0 10px;
  font-size: 13.5px;
  color: var(--ink-3);
}
.v-matrix-legend-item { display: inline-flex; align-items: center; gap: 4px; }
.v-matrix-legend-item i { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
.v-matrix-legend-item i.tone-potentially_affected { background: var(--high); }
.v-matrix-legend-item i.tone-insufficient_data { background: var(--mid); }
.v-matrix-legend-item i.tone-not_in_reported_range { background: var(--info-soft); border: 1px solid var(--info-line); }
.v-matrix-legend-item i.tone-affected { background: var(--crit); }
.v-matrix-legend-item i.tone-diff { background: var(--ink); border-radius: 0; clip-path: polygon(100% 0, 0 0, 100% 100%); }
.v-matrix-legend-row { margin-left: auto; color: var(--ink-3); }

.v-matrix-corner { color: var(--ink-3); font-weight: 500; }
.v-matrix-col { text-align: left; padding-right: 4px; }
.v-matrix-idx { display: block; color: var(--ink-3); font-size: 12.5px; }
.v-matrix-tail { display: block; color: var(--ink-2); }
.v-matrix-count-head { color: var(--ink-3); }
.v-matrix-row.current { box-shadow: inset 0 0 0 1px var(--ink); }
.v-matrix-cell.tone-affected { background: var(--crit); border-color: transparent; }
.v-matrix-cell.tone-not_in_reported_range {
  background: var(--info-soft);
  border: 1px solid var(--info-line);
}


/* 入场与闪动显式绑定到新主体（旧 .v-kpi 已移除） */
@media (prefers-reduced-motion: no-preference) {
  .v-spectrum { animation: v-rise 0.34s cubic-bezier(0.16, 1, 0.3, 1) both; }
  .v-spectrum.tick .v-spectrum-seg { animation: v-tick 0.5s cubic-bezier(0.16, 1, 0.3, 1) both; }
}
@media (prefers-reduced-motion: reduce) {
  .v-spectrum { animation: none !important; }
  .v-spectrum.tick .v-spectrum-seg { animation: none !important; }
}
</style>
