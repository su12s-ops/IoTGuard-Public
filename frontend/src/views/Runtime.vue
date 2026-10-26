<template>
  <div class="page">
    <PageHeader
      title="运行监控与审计"
      subtitle="Runtime Monitoring & Audit"
      description="节点、传感器与证据新鲜度分开判定"
    >
      <template #meta>
        <span>{{ num(summary.total) }} 条运行时事件</span><i class="sep" /><span>最近事件 {{ latestLabel }}</span><i class="sep" /><span>{{ healthySensors }}/{{ totalSensors }} 个传感器健康</span>
      </template>
      <template #actions>
        <span class="range-chip"><Icon name="calendar" :size="14" />最近 24 小时<Icon name="chev-down" :size="13" /></span>
        <span class="live-toggle" @click="live = !live">
          <span>实时模式</span>
          <i class="switch" :class="{ on: live }" />
        </span>
        <button class="btn" type="button" :disabled="uploading" @click="pickEvidence"><Icon name="download" :size="15" />{{ uploading ? "上传中…" : "上传证据" }}</button>
      </template>
    </PageHeader>

    <VerdictRuling
      :state="ruling.state"
      :stamp-main="ruling.stampMain"
      :stamp-en="ruling.stampEn"
      :title="ruling.title"
      :detail="ruling.detail"
      :tags="ruling.tags"
    />

    <input ref="evidenceInput" type="file" accept=".json,.jsonl,.log,.txt" hidden @change="uploadEvidence" />

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <div class="kpi-row">
      <KpiCard label="实时事件" :value="uncollected ? '—' : num(summary.total)" :unit="uncollected ? '' : '条'" icon="activity" tone="blue" :sub="uncollected ? '未采集，无法判断是否有事件' : `最近事件 ${latestLabel}`" />
      <KpiCard label="告警事件" :value="uncollected ? '—' : num(alertCount)" :unit="uncollected ? '' : '条'" icon="shield-alert" tone="red" :sub="uncollected ? '未采集 ≠ 无告警' : `${criticalCount} 条严重 · ${warningCount} 条警告`" />
      <KpiCard label="涉及主机" :value="num(hostCount)" unit="台" icon="server" tone="orange" :sub="`按事件设备名归并 · ${hostCount} 台`" />
      <KpiCard label="采集传感器" :value="num(totalSensors)" unit="个" icon="radio" tone="green" :sub="`${healthySensors} 个在线 · 证据${evidenceFresh ? '新鲜' : '过期'}`" />
    </div>

    <div class="runtime-charts">
      <section class="card">
        <div class="card-head">
          <div><div class="card-title">事件强度分布</div><div class="card-desc">按严重度分桶 · 最近 {{ filteredEvents.length }} 条样本</div></div>
          <div class="chart-legend">
            <span><i :style="{ background: SERIES[0] }" />全部事件</span>
            <span><i :style="{ background: SEVERITY.critical }" />高危事件</span>
          </div>
        </div>
        <div class="chart-body">
          <AreaChart :series="intensitySeries" :labels="intensityLabels" :height="168" />
        </div>
        <div class="chart-foot">
          <span>样本 <b>{{ events.length }}</b> 条</span>
          <span>高价值事件 <b>{{ num(summary.high_value_count) }}</b></span>
          <span>观测模式 <b>eBPF / logread</b></span>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div><div class="card-title">事件类型分布</div><div class="card-desc">按类别计数</div></div>
        </div>
        <div class="type-donut">
          <DonutChart :items="categoryItems" :size="118" center-label="总事件" :center-value="num(summary.total)" />
          <div class="legend-list">
            <span v-for="item in categoryItems" :key="item.label">
              <i class="dot" :style="{ background: item.color }" />{{ item.label }}
              <b>{{ num(item.value) }}</b><em>{{ categoryPct(item.value) }}</em>
            </span>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div><div class="card-title">主机事件分布</div><div class="card-desc">按主机计数</div></div>
          <span class="chip muted">{{ hostCount }} 台</span>
        </div>
        <div class="host-chart">
          <div v-for="host in hostBars" :key="host.name" class="host-row">
            <span class="host-name" :title="host.name">{{ host.name }}</span>
            <span class="host-track"><i :style="{ width: `${host.width}%`, background: host.color }" /></span>
            <b class="num">{{ num(host.count) }}</b>
          </div>
          <div v-if="!hostBars.length" class="empty-note">暂无主机事件。</div>
        </div>
        <div class="host-foot"><span>按事件量排序</span><span class="num">{{ hostCount }} 台</span></div>
      </section>
    </div>

    <section class="card">
      <div class="card-head">
        <div><div class="card-title">实时事件列表</div><div class="card-desc">最近 {{ filteredEvents.length }} 条 · 未观测不等于安全</div></div>
        <div class="row">
          <span class="chip" :class="evidenceFresh ? 'low' : 'high'"><i class="dot" />{{ evidenceFresh ? "证据新鲜" : "证据过期" }}</span>
          <button class="btn sm" type="button" :disabled="!filteredEvents.length" @click="exportCsv"><Icon name="download" :size="13" />导出 CSV</button>
        </div>
      </div>
      <div class="event-filters">
        <label class="search-inline"><Icon name="search" :size="14" /><input v-model="search" type="search" placeholder="搜索规则、进程或资产" /></label>
        <span class="chip" :class="{ accent: sourceFilter === 'all' }" @click="sourceFilter = 'all'">全部</span>
        <span class="chip" :class="{ accent: sourceFilter === 'syscall' }" @click="sourceFilter = 'syscall'">syscall</span>
        <span class="chip" :class="{ accent: sourceFilter === 'openwrt_logread' }" @click="sourceFilter = 'openwrt_logread'">logread</span>
        <span class="filters-count">{{ filteredEvents.length }} / {{ events.length }}</span>
      </div>
      <div v-if="loading" class="loading-line" style="padding: 26px 18px"><span class="spinner" />正在读取运行时事件…</div>
      <div v-else-if="!filteredEvents.length" class="empty-wrap" style="min-height: 240px">
        <EmptyState title="暂无运行时事件" description="没有事件不代表安全；请确认采集节点与传感器是否在线。" icon="activity" />
      </div>
      <div v-else class="table-wrap">
        <table class="event-table" style="table-layout: fixed">
          <colgroup><col style="width: 150px" /><col style="width: 170px" /><col style="width: 108px" /><col style="width: 250px" /><col style="width: 140px" /><col style="width: 104px" /><col style="width: 104px" /><col style="width: 50px" /></colgroup>
          <thead><tr><th>时间</th><th>设备</th><th>事件类型</th><th>违规 / 行为</th><th>进程 / 端口</th><th>目标</th><th>严重程度</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="event in filteredEvents.slice(0, 8)" :key="event.id || `${event.timestamp}-${event.rule}`" style="cursor: pointer" tabindex="0" role="button" @click="activeEvent = event" @keydown.enter="activeEvent = event">
              <td class="num" style="font-size: 13.5px; color: var(--muted)">{{ shortTime(event.timestamp) }}</td>
              <td class="name" :title="event.hostname">{{ event.hostname || "—" }}</td>
              <td><span class="chip" :class="eventTone(event.category)"><i class="dot" />{{ categoryLabel(event.category) }}</span></td>
              <td :title="event.rule">
                <span class="event-rule">{{ event.rule || event.event_type || "—" }}</span>
              </td>
              <td class="mono" style="font-size: 13.5px">{{ event.process_name || "—" }}{{ event.port ? ` · ${event.port}` : "" }}</td>
              <td class="mono" style="font-size: 13.5px">{{ event.destination || "—" }}</td>
              <td><span class="chip" :class="severityTone(event.severity_score)"><i class="dot" />{{ severityLabel(event.severity_score) }}</span></td>
              <td><button class="row-action" type="button" aria-label="查看事件" @click.stop="activeEvent = event"><Icon name="eye" :size="15" /></button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="card-foot"><span>事件保留 90 天；日志丢失不可知时不能记为零。</span><span class="num">{{ num(summary.total) }} 条事件</span></div>
    </section>

    <Modal :open="Boolean(activeEvent)" title="运行时事件详情" description="事件来自采集节点与传感器；未观测不等于无风险。" wide @close="activeEvent = null">
      <div v-if="activeEvent" class="event-detail">
        <div><span>时间</span><b class="mono">{{ dateTime(activeEvent.timestamp) }}</b></div>
        <div><span>设备</span><b>{{ activeEvent.hostname || "—" }}</b></div>
        <div><span>事件类型</span><b>{{ categoryLabel(activeEvent.category) }}</b></div>
        <div><span>严重程度</span><b>{{ severityLabel(activeEvent.severity_score) }} · {{ activeEvent.severity_score ?? "—" }}</b></div>
        <div><span>规则 / 行为</span><b>{{ activeEvent.rule || "—" }}</b></div>
        <div><span>进程 / 端口</span><b class="mono">{{ activeEvent.process_name || "—" }}{{ activeEvent.port ? ` · ${activeEvent.port}` : "" }}</b></div>
        <div><span>目标</span><b class="mono">{{ activeEvent.destination || "—" }}</b></div>
        <div><span>ATT&CK</span><b>{{ activeEvent.tactic || "—" }} {{ activeEvent.technique || "" }}</b></div>
        <div class="wide"><span>命令行</span><b class="cmd">{{ activeEvent.commandline || "未记录" }}</b></div>
        <div class="wide"><span>风险信号</span><b>{{ activeEvent.risk_signal || "—" }}</b></div>
      </div>
      <template #footer><button class="btn" type="button" @click="activeEvent = null">关闭</button></template>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import KpiCard from "../components/KpiCard.vue";
import DonutChart from "../components/DonutChart.vue";
import AreaChart from "../components/AreaChart.vue";
import Modal from "../components/Modal.vue";
import { fetchHealth } from "../api";
import VerdictRuling from "../components/VerdictRuling.vue";
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { dateTime, num, shortTime } from "../utils/format";

const health = ref(null);
const summary = ref({});
const events = ref([]);
const loading = ref(true);
const error = ref("");
const search = ref("");
const sourceFilter = ref("all");
const evidenceInput = ref(null);
const uploading = ref(false);
const activeEvent = ref(null);
const live = ref(true);
let timer = null;

const layers = computed(() => health.value?.layers || {});
const totalSensors = computed(() => Number(layers.value.sensors?.total || 0));
const healthySensors = computed(() => Number(layers.value.sensors?.healthy || 0));
const evidenceFresh = computed(() => Boolean(layers.value.runtime_evidence?.fresh));
const latestLabel = computed(() => {
  const age = layers.value.runtime_evidence?.latest_event_age_seconds;
  if (age === undefined || age === null) return "未知";
  const seconds = Number(age);
  if (!Number.isFinite(seconds)) return "未知";
  if (seconds < 60) return `${Math.round(seconds)} 秒前`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟前`;
  return `${Math.round(seconds / 3600)} 小时前`;
});

const highSeverity = computed(() => events.value.filter((event) => Number(event.severity_score) >= 80).length);
const alertCount = computed(() => {
  const counts = summary.value.severity_counts || {};
  return Number(counts.Critical || 0) + Number(counts.Warning || 0) + Number(counts.warning || 0);
});

/* 页面级状态印章：把"采集是否在进行、证据是否新鲜"收敛成一句结论 */
const uncollected = computed(() => Number(summary.value.total || 0) === 0);

const ruling = computed(() => {
  const total = Number(summary.value.total || 0);
  const alerts = Number(alertCount.value || 0);
  const sensors = totalSensors.value;
  const healthy = healthySensors.value;
  const fresh = evidenceFresh.value;
  const tags = [
    { text: `事件 ${total} 条`, tone: "" },
    { text: `传感器 ${healthy}/${sensors}`, tone: sensors > 0 && healthy === sensors ? "low" : "mid" },
    { text: `告警 ${alerts} 条`, tone: alerts > 0 ? "crit" : "" },
    { text: fresh ? "证据新鲜" : "证据过期", tone: fresh ? "low" : "mid" },
  ];
  if (total === 0) {
    return {
      state: "weak", stampMain: "未采集", stampEn: "NO DATA",
      title: "当前没有运行时事件",
      detail: "没有事件不代表安全：需要先确认采集节点与传感器是否在线，再判断设备行为是否正常。",
      tags,
    };
  }
  if (!fresh) {
    return {
      state: "weak", stampMain: "证据过期", stampEn: "STALE",
      title: "窗口内事件已超出新鲜度阈值",
      detail: `共 ${total} 条事件，但最近一条已超出新鲜度窗口；回放数据不能当作实时状态。`,
      tags,
    };
  }
  if (alerts > 0) {
    return {
      state: "fail", stampMain: "有告警", stampEn: "ALERTING",
      title: `窗口内出现 ${alerts} 条告警事件`,
      detail: "告警来自规则匹配，需要人工确认是否构成真实风险；告警本身不等于已被利用。",
      tags,
    };
  }
  return {
    state: "pass", stampMain: "实时", stampEn: "LIVE",
    title: `采集正常，窗口内 ${total} 条事件`,
    detail: "事件来自 eBPF 采集；该结论仅覆盖已接入的传感器与主机。",
    tags,
  };
});
const criticalCount = computed(() => Number(summary.value.severity_counts?.Critical || 0));
const warningCount = computed(() => Number(summary.value.severity_counts?.Warning || 0) + Number(summary.value.severity_counts?.warning || 0));

import { SERIES, SEVERITY } from "../lib/palette";

const categoryCatalog = {
  process_execution: { label: "进程执行", color: SERIES[0] },
  network_activity: { label: "网络活动", color: SERIES[1] },
  sensitive_file_access: { label: "敏感文件", color: SEVERITY.critical },
  privilege_activity: { label: "权限变更", color: SERIES[2] },
  package_or_service_change: { label: "服务变更", color: SERIES[3] },
  runtime_observation: { label: "运行时观测", color: SEVERITY.low }
};

const categoryItems = computed(() =>
  Object.entries(summary.value.category_counts || {}).map(([key, value]) => ({
    label: categoryCatalog[key]?.label || key,
    value: Number(value) || 0,
    color: categoryCatalog[key]?.color || SEVERITY.none
  })).sort((a, b) => b.value - a.value)
);

function categoryPct(value) {
  const total = categoryItems.value.reduce((sum, item) => sum + item.value, 0) || 1;
  const ratio = (Number(value) / total) * 100;
  return ratio > 0 && ratio < 1 ? "<1%" : `${Math.round(ratio)}%`;
}

const hostCount = computed(() => Object.keys(summary.value.host_counts || {}).length);
const hostBars = computed(() => {
  const entries = Object.entries(summary.value.host_counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const max = Math.max(...entries.map(([, value]) => Number(value)), 1);
  const palette = SERIES;
  return entries.map(([name, count], index) => ({
    name,
    count: Number(count),
    short: name.length > 12 ? `${name.slice(0, 12)}…` : name,
    width: Math.max(4, (Number(count) / max) * 100),
    height: Math.max(8, (Number(count) / max) * 100),
    color: palette[index % palette.length]
  }));
});

const intensityBins = [0, 20, 40, 60, 80];
const intensityLabels = ["0–20", "20–40", "40–60", "60–80", "80–100"];
const intensitySeries = computed(() => {
  const all = Array(5).fill(0);
  const high = Array(5).fill(0);
  for (const event of events.value) {
    const score = Number(event.severity_score) || 0;
    const bin = Math.min(4, Math.max(0, Math.floor(score / 20)));
    all[bin] += 1;
    if (score >= 60) high[bin] += 1;
  }
  return [
    { name: "全部事件", color: SERIES[0], values: all },
    { name: "高危事件", color: SEVERITY.critical, values: high }
  ];
});

const filteredEvents = computed(() => {
  const needle = search.value.trim().toLowerCase();
  return events.value.filter((event) => {
    if (sourceFilter.value !== "all" && event.source !== sourceFilter.value) return false;
    if (needle && ![event.rule, event.process_name, event.hostname, event.category, event.destination].some((value) => String(value || "").toLowerCase().includes(needle))) return false;
    return true;
  });
});

function categoryLabel(value) {
  return categoryCatalog[value]?.label || value || "事件";
}
function eventTone(value) {
  return { sensitive_file_access: "crit", privilege_activity: "mid", process_execution: "high", network_activity: "info", package_or_service_change: "high" }[value] || "muted";
}
function severityTone(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "muted";
  if (n >= 80) return "crit";
  if (n >= 60) return "high";
  if (n >= 40) return "mid";
  return "info";
}
function severityLabel(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "未知";
  if (n >= 80) return "高危";
  if (n >= 60) return "中危";
  if (n >= 40) return "关注";
  return "提示";
}

function exportCsv() {
  const rows = [["timestamp", "hostname", "category", "rule", "process", "severity", "destination"]];
  for (const event of filteredEvents.value) rows.push([event.timestamp, event.hostname, event.category, event.rule, event.process_name, event.severity_score, event.destination]);
  const csv = rows.map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "iotguard-runtime-events.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function pickEvidence() {
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    ui.tokenOpen = true;
    return;
  }
  evidenceInput.value?.click();
}

async function uploadEvidence(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  uploading.value = true;
  try {
    const form = new FormData();
    form.append("file", file);
    await api.post("/runtime/ebpf/upload", form, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 120000
    });
    notify(`已上传 ${file.name}`, "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "证据上传失败", "error");
  } finally {
    uploading.value = false;
    if (evidenceInput.value) evidenceInput.value.value = "";
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    health.value = await fetchHealth();
  } catch {
    health.value = null;
  }

  const [summaryResult, eventResult] = await Promise.allSettled([
    api.get("/runtime/ebpf/summary", { timeout: 20000 }),
    api.get("/runtime/ebpf/events", { params: { limit: 500 }, timeout: 20000 })
  ]);
  if (summaryResult.status === "fulfilled") summary.value = summaryResult.value.data || {};
  if (eventResult.status === "fulfilled") events.value = eventResult.value.data?.events || [];
  if (summaryResult.status === "rejected" && eventResult.status === "rejected") {
    error.value = "运行时接口暂时不可用；传感器状态仍来自健康接口。";
  }
  loading.value = false;
}

onMounted(() => {
  load();
  timer = window.setInterval(() => {
    if (live.value) load();
  }, 60000);
});

onUnmounted(() => {
  if (timer) window.clearInterval(timer);
});
</script>

<style scoped>
.range-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 0 12px;
  border: 1px solid #e2ebf7;
  border-radius: 9px;
  background: #fff;
  color: #5b6b82;
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
}
.live-toggle { display: inline-flex; align-items: center; gap: 8px; color: #5b6b82; font-size: 14px; font-weight: 500; white-space: nowrap; cursor: pointer; user-select: none; }
.switch { position: relative; width: 34px; height: 20px; border-radius: 999px; background: #dbe4f0; transition: background 160ms ease; }
.switch::after { content: ""; position: absolute; left: 2px; top: 2px; width: 16px; height: 16px; border-radius: 50%; background: #fff; box-shadow: 0 1px 3px rgba(16, 35, 70, 0.25); transition: transform 160ms ease; }
.switch.on { background: var(--accent); }
.switch.on::after { transform: translateX(14px); }

.runtime-charts { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr) minmax(0, 0.85fr); gap: 16px; }
.chart-body { padding: 4px 12px 4px; }
.chart-foot { display: flex; align-items: center; gap: 16px; margin-top: auto; padding: 8px 16px 12px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 12.5px; }
.chart-foot b { color: var(--ink-2); font-family: var(--font-num); font-size: 13.5px; }
.chart-legend { display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13.5px; }
.chart-legend span { display: inline-flex; align-items: center; gap: 4px; }
.chart-legend i { width: 7px; height: 7px; border-radius: 2px; }
.type-donut { display: flex; align-items: center; gap: 12px; padding: 12px 16px 16px; }
.type-donut .legend-list { flex: 1; min-width: 0; gap: 8px; }
.type-donut .legend-list span { font-size: 13.5px; }
.type-donut .legend-list em { width: 34px; }

.host-chart { display: grid; gap: 12px; padding: 16px 16px 12px; }
.host-row { display: grid; grid-template-columns: minmax(0, 1fr) 92px 42px; gap: 8px; align-items: center; }
.host-name { color: #5b6b82; font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.host-track { height: 8px; border-radius: 999px; background: #eef3fa; overflow: hidden; }
.host-track i { display: block; height: 8px; border-radius: 999px; }
.host-row b { text-align: right; color: var(--ink); font-size: 14px; font-weight: 700; }
.host-foot { display: flex; align-items: center; justify-content: space-between; margin-top: auto; padding: 8px 16px 12px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 12.5px; }

.event-table td { overflow: hidden; text-overflow: ellipsis; }
.event-table td.name { white-space: nowrap; }
.event-rule { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); font-size: 14px; }
.row-action { display: grid; place-items: center; width: 28px; height: 28px; border: 1px solid transparent; border-radius: 7px; background: transparent; color: #64748b; }
.row-action:hover { border-color: #e3ebf6; background: #f7fafd; color: var(--accent-2); }

.event-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 0 22px; }
.event-detail > div { padding: 10px 0; border-bottom: 1px solid var(--line-soft); min-width: 0; }
.event-detail span { display: block; color: var(--muted); font-size: 13.5px; }
.event-detail b { display: block; margin-top: 2px; color: var(--ink); font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
.event-detail .wide { grid-column: 1 / -1; }
.event-detail .cmd { font-size: 13.5px; line-height: 1.6; color: var(--ink-3); background: #f7fafd; padding: 8px 8px; border-radius: 7px; }

@media (max-width: 1280px) {
  .runtime-charts { grid-template-columns: minmax(0, 1fr); }
}
</style>
