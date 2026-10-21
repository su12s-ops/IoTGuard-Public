<template>
  <div class="soc-page">
    <div class="soc-top">
      <div>
        <div class="soc-kicker">Security operations center</div>
        <div class="soc-title">安全运营总览</div>
      </div>
      <span class="chip crit"><i class="dot" />LIVE</span>
      <span class="chip muted">LAB · {{ summary.asset_count ?? "—" }} 台资产</span>
      <div class="soc-clock">{{ clock }}</div>
      <button class="btn sm" type="button" @click="load"><Icon name="refresh" :size="12" />刷新</button>
    </div>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="soc-grid">
      <div class="soc-cell wide">
        <div class="soc-cell-head"><div><h3>风险分分布</h3><div>当前风险队列 · 按 10 分一档</div></div><div class="soc-chips"><span class="chip">当前快照</span><span class="chip crit">{{ highCount }} 高危</span></div></div>
        <div class="soc-kpis">
          <div class="soc-kpi"><b>{{ highCount }}</b><span>高风险 / 严重</span></div>
          <div class="soc-kpi"><b class="mid">{{ riskTotal }}</b><span>资产级风险</span></div>
          <div class="soc-kpi"><b class="small-num">{{ num(summary.total_vulnerabilities) }}</b><span>情报记录</span></div>
          <div class="soc-rate"><span>待处置</span><b>{{ summary.pending_remediation_tasks ?? "—" }}</b></div>
        </div>
        <div class="dist">
          <div v-for="bucket in distribution" :key="bucket.label" class="dist-col" :title="`${bucket.label} 分 · ${bucket.count} 条`">
            <div class="dist-stack"><i :class="bucket.tone" :style="{ height: bucket.height }" /></div>
            <span>{{ bucket.label }}</span>
          </div>
        </div>
        <div v-if="!ranking.length" class="soc-empty">风险队列暂无对象。</div>
      </div>

      <div class="soc-cell">
        <div class="soc-cell-head"><h3>严重度分布</h3><span class="chip muted">{{ riskTotal }}</span></div>
        <div class="soc-donut">
          <DonutChart :items="severityItems" :size="112" :center-value="highCount" center-label="高危 / 严重" />
          <div class="soc-legend">
            <span v-for="item in severityItems" :key="item.label"><i class="dot" :style="{ background: item.color }" />{{ item.label }}<b class="num">{{ item.value }}</b></span>
          </div>
        </div>
        <div class="soc-footnote">严重度来自风险引擎；候选与确认分开计数。</div>
        <div class="soc-mini-metrics">
          <div><span>CISA KEV</span><b>{{ summary.kev_vulnerabilities ?? "—" }}</b></div>
          <div><span>待审查</span><b>{{ pendingReview }}</b></div>
        </div>
      </div>

      <div class="soc-cell">
        <div class="soc-cell-head"><h3>资产风险 Top 4</h3><span class="chip muted">按分数</span></div>
        <div v-if="topAssets.length" class="soc-assets">
          <div v-for="asset in topAssets" :key="asset.asset_id || asset.hostname">
            <div class="soc-asset-row"><span>{{ asset.hostname || asset.asset_id }}</span><b class="num">{{ score(asset.score) }}</b></div>
            <div class="conf-bar"><i :style="{ width: `${Math.min(100, Number(asset.score) || 0)}%`, background: Number(asset.score) >= 80 ? 'var(--crit)' : 'var(--high)' }" /></div>
          </div>
        </div>
        <div v-else class="soc-empty">暂无资产风险。</div>
        <div class="soc-mini-grid">
          <div><span>资产</span><b>{{ summary.asset_count ?? "—" }}</b></div>
          <div><span>暴露服务</span><b>{{ exposedServices }}</b></div>
          <div><span>KEV</span><b>{{ summary.kev_vulnerabilities ?? 0 }}</b></div>
          <div><span>待审查</span><b>{{ pendingReview }}</b></div>
        </div>
      </div>

      <div class="soc-cell">
        <div class="soc-cell-head"><h3>实时事件</h3><span class="chip info"><i class="dot" />Falco / logread</span></div>
        <div v-if="events.length" class="soc-events">
          <div v-for="event in events.slice(0, 6)" :key="event.id || `${event.timestamp}-${event.rule}`">
            <span class="num">{{ shortTime(event.timestamp) }}</span>
            <i class="dot" :style="{ background: eventColor(event.severity_score) }" />
            <span>{{ event.rule || event.process_name || "运行时事件" }}</span>
            <em>{{ event.hostname || "—" }}</em>
          </div>
        </div>
        <div v-else class="soc-empty">暂无运行时事件；未观测不等于安全。</div>
        <div class="soc-event-foot">Falco {{ falcoCount }} · logread {{ logreadCount }}</div>
      </div>

      <div class="soc-cell">
        <div class="soc-cell-head"><h3>采集覆盖</h3><span class="chip" :class="healthySensors === totalSensors ? 'low' : 'high'"><i class="dot" />{{ totalSensors - healthySensors }} 个异常</span></div>
        <div class="soc-coverage">
          <GaugeRing :value="coverage" label="资产覆盖" :size="70" :stroke="6" />
          <div><div class="soc-copy">{{ coverageCopy }}</div><div class="soc-agent"><i class="dot ok" />Agent 运行中 · {{ pendingReview }} 条待审查</div></div>
        </div>
        <div class="soc-cover-rows">
          <div v-for="sensor in sensorRows" :key="sensor.id"><span>{{ sensor.name }}</span><span class="conf-bar"><i :style="{ width: sensor.width, background: sensor.color }" /></span><b class="num">{{ sensor.value }}</b></div>
          <div v-if="!sensorRows.length" class="soc-empty">暂无传感器。</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import Icon from "../components/Icon.vue";
import DonutChart from "../components/DonutChart.vue";
import GaugeRing from "../components/GaugeRing.vue";
import { api, fetchHealth } from "../api";
import { num, score, shortTime } from "../utils/format";

const summary = ref({});
const ranking = ref([]);
const health = ref(null);
const events = ref([]);
const loading = ref(true);
const error = ref("");
const clock = ref("");
let timer = null;

const highCount = computed(() => Number(summary.value.risk_level_distribution?.Critical || 0) + Number(summary.value.risk_level_distribution?.High || 0));
const riskTotal = computed(() => Object.values(summary.value.risk_level_distribution || {}).reduce((sum, value) => sum + Number(value || 0), 0));
const pendingReview = computed(() => ranking.value.filter((row) => row.human_review_required || row.review_status === "pending_human_review").length);
const topAssets = computed(() => (summary.value.top_assets || []).slice(0, 4));
const exposedServices = computed(() => ranking.value.reduce((sum, row) => sum + Number(row.exposed_service_count || 0), 0));
const layers = computed(() => health.value?.layers || {});
const totalSensors = computed(() => Number(layers.value.sensors?.total || 0));
const healthySensors = computed(() => Number(layers.value.sensors?.healthy || 0));
const coverage = computed(() => (totalSensors.value ? Math.round((healthySensors.value / totalSensors.value) * 100) : null));
const coverageCopy = computed(() => `${healthySensors.value}/${totalSensors.value} 个传感器健康；证据 ${layers.value.runtime_evidence?.fresh ? "新鲜" : "部分过期"}。`);

const severityItems = computed(() => {
  const distribution = summary.value.risk_level_distribution || {};
  return [
    { label: "严重", value: Number(distribution.Critical || 0), color: "var(--crit)" },
    { label: "高危", value: Number(distribution.High || 0), color: "var(--high)" },
    { label: "中危", value: Number(distribution.Medium || 0), color: "var(--mid)" },
    { label: "低危", value: Number(distribution.Low || 0), color: "var(--low)" }
  ];
});

const distribution = computed(() => {
  const buckets = Array.from({ length: 10 }, (_, index) => ({ label: `${index * 10}`, count: 0, tone: index >= 8 ? "crit" : index >= 6 ? "high" : "" }));
  for (const row of ranking.value) {
    const value = Number(row.preliminary_score ?? row.static_score ?? 0);
    const index = Math.max(0, Math.min(9, Math.floor(value / 10)));
    buckets[index].count += 1;
  }
  const max = Math.max(...buckets.map((bucket) => bucket.count), 1);
  return buckets.map((bucket) => ({ ...bucket, height: bucket.count ? `${Math.max(6, (bucket.count / max) * 100)}%` : "2px" }));
});

const sensorRows = computed(() => {
  const list = layers.value.sensors?.sensors || [];
  return list.slice(0, 3).map((sensor) => {
    const age = Number(sensor.heartbeat_age_seconds);
    const ok = sensor.status === "running" || sensor.status === "ok";
    return {
      id: sensor.sensor_id,
      name: `${sensor.source || "sensor"} · ${sensor.asset_id ? `asset ${sensor.asset_id}` : "—"}`,
      width: ok ? "94%" : age > 3600 ? "4%" : "40%",
      color: ok ? "var(--low)" : "var(--high)",
      value: ok ? "94%" : "0%"
    };
  });
});

const falcoCount = computed(() => events.value.filter((event) => String(event.source || "").includes("falco")).length);
const logreadCount = computed(() => events.value.filter((event) => String(event.source || "").includes("logread")).length);

function eventColor(value) {
  const n = Number(value);
  if (n >= 80) return "var(--crit)";
  if (n >= 60) return "var(--high)";
  return "var(--info)";
}

function tick() {
  clock.value = new Date().toLocaleString("zh-CN", { hour12: false });
}

async function load() {
  loading.value = true;
  error.value = "";
  const [summaryResult, rankingResult, healthResult, eventsResult] = await Promise.allSettled([
    api.get("/dashboard/summary", { timeout: 20000 }),
    api.get("/risk/ranking", { timeout: 20000 }),
    fetchHealth(),
    api.get("/runtime/ebpf/events", { params: { limit: 40 }, timeout: 12000 })
  ]);
  if (summaryResult.status === "fulfilled") summary.value = summaryResult.value.data || {};
  if (rankingResult.status === "fulfilled") ranking.value = rankingResult.value.data || [];
  if (healthResult.status === "fulfilled") health.value = healthResult.value;
  if (eventsResult.status === "fulfilled") events.value = eventsResult.value.data?.events || [];
  if (summaryResult.status === "rejected" && rankingResult.status === "rejected") error.value = "安全态势数据读取失败，请检查后端服务。";
  loading.value = false;
}

onMounted(() => {
  load();
  tick();
  timer = window.setInterval(tick, 1000);
});
onUnmounted(() => window.clearInterval(timer));
</script>

<style scoped>
.soc-page { display: flex; flex-direction: column; gap: 10px; }
.soc-top { display: flex; align-items: center; gap: 12px; flex: 0 0 auto; padding: 0 2px; }
.soc-kicker { color: var(--accent); font: 700 8px var(--font-num); letter-spacing: .16em; text-transform: uppercase; }
.soc-title { margin-top: 3px; color: var(--ink); font-family: var(--font-display); font-size: 21px; font-weight: 700; letter-spacing: -.02em; }
.soc-clock { margin-left: auto; color: var(--muted); font: 10px var(--font-num); }
.soc-grid { flex: 1; min-height: 0; display: grid; grid-template-columns: 1.5fr 1fr 1fr; grid-template-rows: 1fr 1.05fr; gap: 10px; }
.soc-cell { min-width: 0; min-height: 0; overflow: hidden; border: var(--card-border); background: var(--surface); padding: 13px 15px; display: flex; flex-direction: column; }
.soc-cell.wide { grid-column: span 2; }
.soc-cell-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.soc-cell-head h3 { margin: 0; color: var(--ink); font-size: 11px; font-weight: 700; }
.soc-cell-head div > div { margin-top: 2px; color: var(--muted); font-size: 8.5px; }
.soc-chips { display: flex; gap: 5px; }
.soc-kpis { display: flex; align-items: flex-end; gap: 22px; margin-top: 8px; }
.soc-kpi b { color: var(--ink); font: 700 34px/.9 var(--font-num); letter-spacing: -.06em; }
.soc-kpi b.mid { font-size: 25px; }
.soc-kpi b.small-num { font-size: 21px; }
.soc-kpi span { display: block; margin-top: 3px; color: var(--muted); font-size: 8.5px; }
.soc-rate { margin-left: auto; text-align: right; color: var(--muted); font-size: 8.5px; }
.soc-rate b { display: block; margin-top: 2px; color: var(--ink); font: 700 17px var(--font-num); }
.dist { flex: 1; display: flex; align-items: flex-end; gap: 7px; min-height: 60px; margin-top: 6px; }
.dist-col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; gap: 4px; height: 100%; }
.dist-stack { width: 100%; flex: 1; display: flex; align-items: flex-end; }
.dist-stack i { display: block; width: 100%; background: var(--accent); opacity: .78; }
.dist-stack i.high { background: var(--high); opacity: .85; }
.dist-stack i.crit { background: var(--crit); opacity: .9; }
.dist-col span { color: var(--muted); font: 7.5px var(--font-num); }
.soc-empty { display: grid; place-items: center; flex: 1; color: var(--muted); font-size: 9px; }
.soc-donut { display: flex; align-items: center; gap: 14px; margin-top: 10px; }
.soc-legend { display: grid; gap: 6px; flex: 1; color: var(--muted); font-size: 9px; }
.soc-legend span { display: flex; align-items: center; gap: 6px; }
.soc-legend b { margin-left: auto; color: var(--ink); font: 700 9px var(--font-num); }
.soc-footnote { margin-top: 9px; padding-top: 7px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 8px; line-height: 1.5; }
.soc-mini-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: auto; padding-top: 8px; border-top: 1px solid var(--line-soft); }
.soc-mini-metrics span, .soc-mini-grid span { display: block; color: var(--muted); font-size: 8px; }
.soc-mini-metrics b, .soc-mini-grid b { display: block; margin-top: 1px; color: var(--ink); font: 700 13px var(--font-num); }
.soc-assets { display: grid; gap: 10px; margin-top: 11px; }
.soc-asset-row { display: flex; justify-content: space-between; gap: 8px; color: var(--ink-2); font-size: 9px; }
.soc-asset-row b { color: var(--ink); font: 700 9px var(--font-num); }
.soc-mini-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: auto; padding-top: 8px; border-top: 1px solid var(--line-soft); }
.soc-events { display: grid; margin-top: 6px; }
.soc-events > div { display: grid; grid-template-columns: 54px 10px minmax(0, 1fr) 88px; gap: 7px; align-items: center; min-height: 30px; border-bottom: 1px solid var(--line-soft); font-size: 9px; }
.soc-events .num { color: var(--muted); font-size: 7.5px; }
.soc-events span:nth-child(3) { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); }
.soc-events em { color: var(--muted); font-size: 7.5px; font-style: normal; text-align: right; }
.soc-event-foot { margin-top: auto; padding-top: 7px; border-top: 1px solid var(--line-soft); color: var(--muted); font: 8px var(--font-num); }
.soc-coverage { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
.soc-copy { color: var(--muted); font-size: 8.5px; line-height: 1.5; }
.soc-agent { display: flex; align-items: center; gap: 5px; margin-top: 4px; color: var(--muted); font-size: 8px; }
.soc-cover-rows { display: grid; gap: 7px; margin-top: auto; padding-top: 8px; border-top: 1px solid var(--line-soft); }
.soc-cover-rows > div { display: grid; grid-template-columns: 92px 1fr 30px; gap: 7px; align-items: center; color: var(--muted); font-size: 8px; }
.soc-cover-rows .conf-bar { height: 4px; }
.soc-cover-rows b { text-align: right; font-size: 8px; }
</style>
