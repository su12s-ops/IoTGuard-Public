<template>
  <div class="page">
    <PageHeader
      eyebrow="Runtime evidence & audit · live"
      title="运行与审计"
      description="节点、传感器与证据新鲜度分开判定；没有事件不等于没有风险。"
    >
      <template #meta>
        <span>{{ healthySensors }}/{{ totalSensors }} 个传感器健康</span><i class="sep" /><span>{{ num(summary.total) }} 条运行时事件</span><i class="sep" /><span>最近事件 {{ latestLabel }}</span><i class="sep" /><span>证据 {{ evidenceFresh ? "新鲜" : "部分过期" }}</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="14" />刷新</button>
        <button class="btn" type="button" :disabled="uploading" @click="pickEvidence"><Icon name="download" :size="14" />{{ uploading ? "上传中…" : "上传证据" }}</button>
        <router-link class="btn primary" to="/soc"><Icon name="activity" :size="14" />SOC 大屏</router-link>
      </template>
    </PageHeader>

    <input ref="evidenceInput" type="file" accept=".json,.jsonl,.log,.txt" hidden @change="uploadEvidence" />

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 154px minmax(0, 1fr) 118px">
      <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr))">
        <section v-for="sensor in sensorCards" :key="sensor.id" class="card sensor-card">
          <div class="sensor-top"><i class="dot" :class="sensor.state" /><span>{{ sensor.name }}</span><span class="chip" :class="sensor.tone" style="margin-left: auto; height: 18px; font-size: 8px">{{ sensor.label }}</span></div>
          <div class="sensor-body">
            <GaugeRing :value="sensor.freshness" :size="58" :stroke="6" :color="sensor.color" />
            <div>
              <div class="num sensor-count">{{ sensor.events }}</div>
              <div class="sensor-age">{{ sensor.age }}</div>
              <div class="sensor-mode">{{ sensor.mode }}</div>
            </div>
          </div>
        </section>

        <section class="card sensor-card">
          <div class="sensor-top"><span style="font-size: 10px; font-weight: 650">24 小时事件</span><span class="num" style="margin-left: auto; color: var(--muted); font-size: 8px">{{ num(summary.total) }}</span></div>
          <div class="histogram">
            <i v-for="(bar, index) in histogram" :key="index" :class="bar.tone" :style="{ height: `${bar.height}%` }" :title="`${bar.hour}:00 · ${bar.count} 条`" />
          </div>
          <div class="histogram-labels"><span>00</span><span>06</span><span>12</span><span>18</span><span>24</span></div>
        </section>
      </div>

      <div class="grid g-2-1">
        <section class="card">
          <div class="card-head">
            <div><div class="card-title">事件流</div><div class="card-desc">最近 200 条 · 未观测不等于安全</div></div>
            <span class="chip muted">实时</span>
          </div>
          <div class="event-filters">
            <label class="search-inline"><Icon name="search" :size="12" /><input v-model="search" type="search" placeholder="搜索规则、进程或资产" /></label>
            <span class="chip" :class="{ accent: sourceFilter === 'all' }" @click="sourceFilter = 'all'">全部</span>
            <span class="chip" :class="{ accent: sourceFilter === 'sensor' }" @click="sourceFilter = 'sensor'">传感器</span>
            <span class="chip" :class="{ accent: sourceFilter === 'probe' }" @click="sourceFilter = 'probe'">探针</span>
            <span class="filters-count">{{ filteredEvents.length }} / {{ events.length }}</span>
          </div>
          <div v-if="loading" class="loading-line"><span class="spinner" />正在读取运行时事件…</div>
          <div v-else-if="!filteredEvents.length" class="empty-wrap"><EmptyState title="暂无运行时事件" description="没有事件不代表安全；请确认采集节点与传感器是否在线。" icon="activity" /></div>
          <div v-else class="table-wrap">
            <table class="event-table" style="table-layout: fixed">
              <colgroup><col style="width: 74px" /><col style="width: 136px" /><col style="width: 82px" /><col style="width: 224px" /><col style="width: 132px" /><col style="width: 52px" /></colgroup>
              <thead><tr><th>时间</th><th>资产</th><th>类型</th><th>规则 / 目标</th><th>进程 / 端口</th><th>强度</th></tr></thead>
              <tbody>
                <tr v-for="event in filteredEvents.slice(0, 7)" :key="event.id || `${event.timestamp}-${event.rule}`">
                  <td class="num" style="font-size: 8.5px; color: var(--muted)">{{ shortTime(event.timestamp) }}</td>
                  <td class="name">{{ event.hostname || "—" }}</td>
                  <td><span class="chip" :class="eventTone(event.category)" style="height: 18px; font-size: 8px"><i class="dot" />{{ categoryLabel(event.category) }}</span></td>
                  <td style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="event.rule">{{ event.rule || event.destination || "—" }}</td>
                  <td class="mono" style="font-size: 9px">{{ event.process_name || "—" }}{{ event.port ? ` · ${event.port}` : "" }}</td>
                  <td><span class="num" :style="{ color: severityColor(event.severity_score), fontWeight: 700 }">{{ event.severity_score ?? "—" }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="card-foot"><span>事件保留 90 天；日志丢失不可知时不能记为零。</span><span class="num">{{ filteredEvents.length }} 条</span></div>
        </section>

        <section class="card">
          <div class="card-head">
            <div><div class="card-title">证据覆盖</div><div class="card-desc">按传感器与资产拆分</div></div>
            <span class="chip" :class="healthySensors === totalSensors ? 'low' : 'high'"><i class="dot" />{{ totalSensors - healthySensors }} 个异常</span>
          </div>
          <div class="card-body" style="padding-top: 8px">
            <div class="coverage-top">
              <GaugeRing :value="coverage" label="资产覆盖" :size="78" :stroke="7" />
              <div class="coverage-copy">{{ coverageCopy }}</div>
            </div>
            <div class="metric-list">
              <div><span>已关联资产</span><b>{{ status.matched_asset_count ?? "—" }}</b></div>
              <div><span>高价值证据</span><b>{{ summary.high_value_count ?? "—" }}</b></div>
              <div><span>内核传感器事件</span><b>{{ kernelCount }}</b></div>
            </div>
            <div class="gap-title">已知缺口</div>
            <div v-if="sensorCards.length" class="gap-list">
              <div v-for="sensor in sensorCards.filter((item) => item.state !== 'ok')" :key="sensor.id"><i class="dot" :class="sensor.state" />{{ sensor.name }} · {{ sensor.age }}</div>
              <div v-if="!sensorCards.some((item) => item.state !== 'ok')"><i class="dot ok" />暂无已登记缺口</div>
            </div>
            <div v-else class="gap-list"><div><i class="dot unknown" />传感器状态尚未读取</div></div>
          </div>
          <div class="card-foot"><span>传感器在线不等于证据新鲜。</span><span class="link" @click="load">重新读取 <Icon name="refresh" :size="11" /></span></div>
        </section>
      </div>

      <div class="grid g-3">
        <div class="card audit-card"><div class="audit-label">LAST EVENT</div><div class="audit-value mono">{{ latestLabel }}</div><div class="audit-note">{{ status.latest_event_at ? dateTime(status.latest_event_at) : "后端未返回最近事件时间" }}</div></div>
        <div class="card audit-card"><div class="audit-label">RETENTION</div><div class="audit-value">事件 90 天 · 审计 365 天</div><div class="audit-note">清理任务每日 02:00 执行</div></div>
        <div class="card audit-card audit-export"><div><div class="audit-label">EXPORT</div><div class="audit-value">导出当前事件</div></div><button class="btn sm" type="button" :disabled="!filteredEvents.length" @click="exportCsv"><Icon name="download" :size="12" />CSV</button></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import GaugeRing from "../components/GaugeRing.vue";
import { fetchHealth } from "../api";
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { dateTime, num, shortTime } from "../utils/format";

const health = ref(null);
const status = ref({});
const summary = ref({});
const events = ref([]);
const loading = ref(true);
const error = ref("");
const search = ref("");
const sourceFilter = ref("all");
const evidenceInput = ref(null);
const uploading = ref(false);

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
const kernelCount = computed(() => Number(summary.value.observation_mode_counts?.ebpf || 0) + Number(summary.value.observation_mode_counts?.sensor || 0));
const coverage = computed(() => {
  const value = Number(status.value.matched_asset_ratio);
  if (!Number.isFinite(value)) return null;
  return value <= 1 ? value * 100 : value;
});
const coverageCopy = computed(() => {
  if (coverage.value === null) return "后端未返回资产覆盖率。";
  return `${status.value.matched_asset_count ?? "—"} 个资产有运行时关联；${totalSensors.value - healthySensors.value} 个传感器异常。`;
});

const sensorCards = computed(() => {
  const list = layers.value.sensors?.sensors || [];
  return list.slice(0, 3).map((sensor) => {
    const age = Number(sensor.heartbeat_age_seconds);
    const freshness = Number.isFinite(age) ? Math.max(0, Math.min(100, 100 - (age / 900) * 100)) : 0;
    const ok = sensor.status === "running" || sensor.status === "ok";
    return {
      id: sensor.sensor_id,
      name: `${sensor.source || "sensor"} · ${sensor.asset_id ? `asset ${sensor.asset_id}` : "未绑定"}`,
      state: ok ? "ok" : sensor.status === "stale" || sensor.status === "degraded" ? "warn" : "bad",
      tone: ok ? "low" : "high",
      label: ok ? "新鲜" : sensor.status === "stale" ? "过期" : "异常",
      freshness,
      color: ok ? "var(--low)" : "var(--high)",
      events: sensor.status === "running" ? "在线" : "0",
      age: Number.isFinite(age) ? (age < 3600 ? `${Math.round(age / 60)} 分钟前` : `${Math.round(age / 3600)} 小时前`) : "未知",
      mode: sensor.source === "falco" ? "eBPF 内核事件" : "logread"
    };
  });
});

const filteredEvents = computed(() => {
  const needle = search.value.trim().toLowerCase();
  return events.value.filter((event) => {
    if (sourceFilter.value === "sensor" && event.source !== "sensor") return false;
    if (sourceFilter.value === "probe" && event.source !== "probe") return false;
    if (needle && ![event.rule, event.process_name, event.hostname, event.category].some((value) => String(value || "").toLowerCase().includes(needle))) return false;
    return true;
  });
});

const histogram = computed(() => {
  const buckets = Array.from({ length: 24 }, (_, hour) => ({ hour, count: 0, tone: "" }));
  for (const event of events.value) {
    const date = new Date(event.timestamp);
    if (Number.isNaN(date.getTime())) continue;
    buckets[date.getHours()].count += 1;
  }
  const max = Math.max(...buckets.map((bucket) => bucket.count), 1);
  return buckets.map((bucket) => ({ ...bucket, height: Math.max(4, (bucket.count / max) * 100), tone: bucket.count > max * 0.7 ? "crit" : bucket.count > max * 0.4 ? "high" : "" }));
});

function categoryLabel(value) {
  return { process_execution: "进程", network_activity: "网络", sensitive_file_access: "文件", privilege_activity: "权限", package_or_service_change: "服务", runtime_observation: "观测" }[value] || value || "事件";
}
function eventTone(value) {
  return { sensitive_file_access: "crit", privilege_activity: "high", process_execution: "high", network_activity: "info", package_or_service_change: "mid" }[value] || "muted";
}
function severityColor(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "var(--muted)";
  if (n >= 80) return "var(--crit)";
  if (n >= 60) return "var(--high)";
  return "var(--info)";
}

function exportCsv() {
  const rows = [["timestamp", "hostname", "category", "rule", "process", "severity"]];
  for (const event of filteredEvents.value) rows.push([event.timestamp, event.hostname, event.category, event.rule, event.process_name, event.severity_score]);
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

  const [statusResult, summaryResult, eventResult] = await Promise.allSettled([
    api.get("/runtime/ebpf/status", { timeout: 12000 }),
    api.get("/runtime/ebpf/summary", { timeout: 12000 }),
    api.get("/runtime/ebpf/events", { params: { limit: 80 }, timeout: 12000 })
  ]);
  if (statusResult.status === "fulfilled") status.value = statusResult.value.data || {};
  if (summaryResult.status === "fulfilled") summary.value = summaryResult.value.data || {};
  if (eventResult.status === "fulfilled") events.value = eventResult.value.data?.events || [];
  if (statusResult.status === "rejected" && summaryResult.status === "rejected" && eventResult.status === "rejected") {
    error.value = "运行时接口暂时不可用；传感器状态仍来自健康接口。";
  }
  loading.value = false;
}

onMounted(load);
</script>

<style scoped>
.sensor-card { padding: 12px 14px; }
.sensor-top { display: flex; align-items: center; gap: 7px; font-size: 10px; font-weight: 650; }
.sensor-top > span:first-of-type { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sensor-body { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
.sensor-count { font-size: 17px; font-weight: 700; }
.sensor-age { color: var(--muted); font-size: 8.5px; }
.sensor-mode { color: var(--muted); font-size: 8px; margin-top: 2px; }
.histogram { display: flex; align-items: flex-end; gap: 3px; height: 56px; margin-top: 12px; }
.histogram i { flex: 1; min-width: 0; height: 4%; background: var(--accent); opacity: .75; }
.histogram i.high { background: var(--high); }
.histogram i.crit { background: var(--crit); }
.histogram-labels { display: flex; justify-content: space-between; color: var(--muted); font: 8px var(--font-num); margin-top: 4px; }
.event-filters { display: flex; align-items: center; gap: 6px; padding: 9px 15px 0; flex-wrap: wrap; }
.event-filters .chip { cursor: pointer; height: 21px; font-size: 9px; }
.filters-count { margin-left: auto; color: var(--muted); font: 8.5px var(--font-num); }
.search-inline { display: flex; align-items: center; gap: 6px; width: 230px; height: 28px; padding: 0 9px; border: 1px solid var(--line); background: var(--surface-2); color: var(--muted); }
.search-inline input { flex: 1; min-width: 0; border: 0; outline: 0; background: transparent; font: inherit; font-size: 9.5px; color: var(--ink); }
.empty-wrap { display: grid; place-items: center; min-height: 250px; }
.coverage-top { display: flex; align-items: center; gap: 14px; }
.coverage-copy { min-width: 0; color: var(--muted); font-size: 9px; line-height: 1.55; }
.metric-list { display: grid; gap: 0; margin-top: 9px; }
.metric-list div { display: flex; justify-content: space-between; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--line-soft); font-size: 9.5px; color: var(--muted); }
.metric-list b { color: var(--ink); font: 700 10px var(--font-num); }
.gap-title { margin-top: 9px; color: var(--ink); font-size: 9px; font-weight: 650; }
.gap-list { display: grid; gap: 5px; margin-top: 5px; }
.gap-list div { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 8.5px; }
.audit-card { padding: 12px 14px; }
.audit-label { color: var(--muted); font: 700 8px var(--font-num); letter-spacing: .08em; }
.audit-value { margin-top: 5px; color: var(--ink); font-size: 10.5px; font-weight: 650; }
.audit-value.mono { font: 600 10.5px var(--font-num); }
.audit-note { margin-top: 3px; color: var(--muted); font-size: 8.5px; }
.audit-export { display: flex; align-items: center; gap: 12px; }
.audit-export > div { flex: 1; }
.event-table td { overflow: hidden; text-overflow: ellipsis; }
</style>
