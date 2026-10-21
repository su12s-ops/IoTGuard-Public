<template>
  <div class="page">
    <PageHeader
      eyebrow="Security posture · Lab environment"
      title="安全态势"
      description="从情报命中到运行证据，先看需要动手的对象，再进入工作台处理。"
    >
      <template #meta>
        <span>数据读取于 {{ updated || "尚未成功读取" }}</span><i class="sep" /><span>{{ summary.asset_count ?? "—" }} 台资产</span><i class="sep" /><span>{{ num(summary.total_vulnerabilities) }} 条情报</span><i class="sep" /><span>口径：资产级风险</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="refresh"><Icon name="refresh" :size="14" />刷新</button>
        <button class="btn" type="button" @click="exportReport"><Icon name="download" :size="14" />导出周报</button>
        <router-link class="btn primary" to="/agents"><Icon name="play" :size="14" />发起研判</router-link>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 300px minmax(0, 1fr)">
      <div class="grid g-2-1">
        <section class="card feature hero-card">
          <div class="hero-top">
            <div>
              <div class="card-title">风险态势</div>
              <div class="card-desc">资产级风险 · 按当前批次</div>
            </div>
            <span class="chip muted">当前快照</span>
          </div>

          <div class="hero-flex">
            <div class="hero-left">
              <div class="big-row">
                <span class="big-number">{{ highCount }}</span>
                <span class="big-label">高风险<br />及严重</span>
              </div>
              <span class="chip" :class="delta === null ? 'muted' : 'crit'" style="margin-top: 8px">
                <Icon v-if="delta !== null" name="arrow-up" :size="10" />
                {{ delta === null ? "较上周 —" : `${delta >= 0 ? "+" : ""}${delta} 较上周` }}
              </span>

              <div class="stack" style="margin-top: 14px">
                <i :style="{ width: widthFor('Critical'), background: 'var(--crit)', minWidth: critical ? '3px' : '0' }" />
                <i :style="{ width: widthFor('High'), background: 'var(--high)' }" />
                <i :style="{ width: widthFor('Medium'), background: 'var(--mid)' }" />
                <i :style="{ width: widthFor('Low'), background: 'var(--low)' }" />
              </div>

              <div class="legend" style="margin-top: 12px; display: grid; grid-template-columns: 1fr 1fr; gap: 7px 10px">
                <span><i class="dot" style="background: var(--crit)" />严重<b>{{ critical }}</b></span>
                <span><i class="dot" style="background: var(--high)" />高危<b>{{ high }}</b></span>
                <span><i class="dot" style="background: var(--mid)" />中危<b>{{ medium }}</b></span>
                <span><i class="dot" style="background: var(--low)" />低危<b>{{ low }}</b></span>
              </div>

              <div class="hero-note">
                <span>待处置</span><b class="num">{{ summary.pending_remediation_tasks ?? "—" }}</b>
                <span class="mini-bar"><i :style="{ width: dispositionWidth }" /></span>
                <span>{{ riskTotal }} 条</span>
              </div>
            </div>

            <div class="hero-right">
              <div class="chart-meta"><span>情报来源分布</span><span><b>{{ num(summary.total_vulnerabilities) }}</b> 条</span></div>
              <div v-if="sources.length" class="source-bars">
                <div v-for="source in sources" :key="source.name" class="source-row">
                  <span class="source-name" :title="source.name">{{ source.name }}</span>
                  <span class="source-track"><i :style="{ width: source.width, background: source.color }" /></span>
                  <b class="num">{{ num(source.value) }}</b>
                </div>
              </div>
              <div v-else class="empty-inline-chart">暂无可展示的情报来源。</div>
              <div class="chart-source-note">来源按情报记录计数；数量不代表适用性已完成。</div>
            </div>
          </div>
        </section>

        <section class="card evidence-card">
          <div class="card-head">
            <div>
              <div class="card-title">运行证据</div>
              <div class="card-desc">节点、传感器与证据新鲜度</div>
            </div>
            <span class="chip" :class="evidenceTone"><i class="dot" />{{ evidenceLabel }}</span>
          </div>

          <div class="card-body evidence-body">
            <div class="gauge-row">
              <GaugeRing :value="sensorHealth" label="传感器健康" :size="84" :color="sensorHealth >= 100 ? 'var(--low)' : sensorHealth === 0 ? 'var(--crit)' : 'var(--high)'" />
              <div class="gauge-copy">
                <div class="t">{{ healthySensors }}/{{ totalSensors }} 个传感器健康</div>
                <div class="d">{{ evidenceCopy }}</div>
                <div class="warn" :style="{ color: evidenceTone === 'low' ? 'var(--low)' : 'var(--high)' }">{{ evidenceWarning }}</div>
              </div>
            </div>
          </div>

          <div class="sensor-list">
            <div v-for="sensor in sensors" :key="sensor.id" class="sensor">
              <i class="dot" :class="sensor.state" />
              <span class="name" :title="sensor.name">{{ sensor.name }}</span>
              <span class="num time">{{ sensor.age }}</span>
            </div>
            <div v-if="!sensors.length" class="sensor-empty">暂无传感器登记。</div>
          </div>

          <div class="card-foot"><span>传感器在线不等于证据新鲜。</span><router-link class="link" to="/runtime">查看运行时 <Icon name="chev-right" :size="12" /></router-link></div>
        </section>
      </div>

      <div class="grid g-2-1">
        <section class="card">
          <div class="card-head">
            <div><div class="card-title">优先处置</div><div class="card-desc">按当前风险分排序 · 前 6 条</div></div>
            <router-link class="link" to="/risks">全部风险 <Icon name="chev-right" :size="12" /></router-link>
          </div>
          <div v-if="loadingSummary" class="loading-line"><span class="spinner" />正在读取风险记录…</div>
          <div v-else-if="!priorityRows.length" class="empty-wrap"><EmptyState title="暂无风险对象" description="完成资产采集与风险评估后，这里会出现按风险分排序的对象。" icon="bug" /></div>
          <div v-else class="table-wrap">
            <table style="table-layout: fixed">
              <colgroup><col style="width: 36px" /><col style="width: 150px" /><col style="width: 150px" /><col style="width: 88px" /><col style="width: 82px" /><col style="width: 92px" /><col style="width: 66px" /><col style="width: 24px" /></colgroup>
              <thead><tr><th>#</th><th>CVE</th><th>资产</th><th>风险分</th><th>等级</th><th>状态</th><th>更新</th><th></th></tr></thead>
              <tbody>
                <tr v-for="(row, index) in priorityRows" :key="row.cve_id || index" style="cursor: pointer" @click="openRisk(row)">
                  <td class="num" style="color: var(--muted)">P{{ index + 1 }}</td>
                  <td class="mono">{{ row.cve_id }}</td>
                  <td class="name">{{ row.hostname || "—" }}</td>
                  <td><span class="score" :class="toneForLevel(row.risk_level)"><b>{{ score(row.score) }}</b><i><em :style="{ width: `${Math.min(100, Number(row.score) || 0)}%` }" /></i></span></td>
                  <td><span class="chip" :class="toneForLevel(row.risk_level)"><i class="dot" />{{ levelLabel(row.risk_level) }}</span></td>
                  <td><span class="chip" :class="row.active === false ? 'muted' : 'high'"><i class="dot" />{{ row.active === false ? "历史归档" : "待研判" }}</span></td>
                  <td class="num" style="font-size: 9px; color: var(--muted)">{{ row.updated_at ? timeAgo(row.updated_at) : "—" }}</td>
                  <td><Icon name="chev-right" :size="12" style="color: var(--line-strong)" /></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="card-foot"><span>风险分综合 CVSS、EPSS、暴露面与运行时证据；不代表已确认利用。</span><span class="num">{{ num(riskTotal) }} 条</span></div>
        </section>

        <section class="card agent-card">
          <div class="card-head">
            <div><div class="card-title">智能体运行</div><div class="card-desc">四智能体协作 · 共享证据</div></div>
            <span v-if="latestRun" class="chip" :class="statusTone(latestRun.status)"><i class="dot" />{{ statusLabel(latestRun.status) }}</span>
            <span v-else class="chip muted"><i class="dot" />暂无运行</span>
          </div>

          <div v-if="latestRun" class="card-body" style="padding-top: 10px">
            <div class="agent-flow" style="display: grid; gap: 0">
              <div v-for="(step, index) in agentSteps" :key="step.key" class="agent-row" :style="{ paddingBottom: index === agentSteps.length - 1 ? 0 : '15px' }">
                <span class="step-dot" :class="step.state" :style="{ width: '22px', height: '22px' }">
                  <Icon :name="step.state === 'done' ? 'check' : step.state === 'active' ? 'clock' : 'more'" :size="11" />
                </span>
                <div><div class="step-title">{{ step.label }}</div><div class="step-note">{{ step.note }}</div></div>
                <span class="num step-time">{{ step.time }}</span>
              </div>
            </div>
            <div class="agent-metrics">
              <div><span>目标</span><b :title="latestRun.target_ref">{{ short(latestRun.target_ref) }}</b></div>
              <div><span>模式</span><b>{{ latestRun.mode || "—" }}</b></div>
              <div><span>记录</span><b>{{ latestRun.run_id?.slice(-4) || "—" }}</b></div>
            </div>
            <div class="agent-callout">
              <Icon name="alert" :size="12" />
              <span>{{ summary.pending_remediation_tasks ? `${summary.pending_remediation_tasks} 条待处置` : "暂无待处置记录" }}</span>
              <router-link class="link" to="/agents">打开 AgentOps <Icon name="chev-right" :size="11" /></router-link>
            </div>
          </div>
          <div v-else class="card-body"><EmptyState title="暂无智能体运行" description="发起一次研判后，四个智能体的状态会出现在这里。" icon="cpu" /></div>

          <div class="card-foot"><span class="num">{{ latestRun?.run_id || "—" }}</span><router-link class="link" to="/agents">查看全部 <Icon name="chev-right" :size="12" /></router-link></div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import GaugeRing from "../components/GaugeRing.vue";
import { api, fetchHealth, fetchReportArchives, currentReportUrls } from "../api";
import { levelLabel, levelTone, num, score, shortTime, statusLabel, statusTone, timeAgo } from "../utils/format";

const router = useRouter();
const summary = ref({});
const health = ref(null);
const archives = ref([]);
const runs = ref([]);
const loadingSummary = ref(true);
const error = ref("");
const updated = ref("");

const critical = computed(() => Number(summary.value.risk_level_distribution?.Critical || 0));
const high = computed(() => Number(summary.value.risk_level_distribution?.High || 0));
const medium = computed(() => Number(summary.value.risk_level_distribution?.Medium || 0));
const low = computed(() => Number(summary.value.risk_level_distribution?.Low || 0));
const riskTotal = computed(() => critical.value + high.value + medium.value + low.value);
const highCount = computed(() => Number(summary.value.high_risk_vulnerabilities ?? critical.value + high.value));
const delta = computed(() => {
  if (archives.value.length < 2) return null;
  const latest = Number(archives.value[0]?.summary?.risks);
  const previous = Number(archives.value[1]?.summary?.risks);
  return Number.isFinite(latest) && Number.isFinite(previous) ? latest - previous : null;
});

const priorityRows = computed(() => (summary.value.top_vulnerabilities || []).slice(0, 6));
const latestRun = computed(() => runs.value[0] || null);

const sources = computed(() => {
  const entries = Object.entries(summary.value.source_distribution || {});
  const max = Math.max(...entries.map(([, value]) => Number(value) || 0), 1);
  const colors = ["var(--chart-2)", "var(--info)", "var(--chart-4)", "var(--muted)"];
  return entries
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, 4)
    .map(([name, value], index) => ({
      name,
      value: Number(value) || 0,
      width: `${((Number(value) || 0) / max) * 100}%`,
      color: colors[index % colors.length]
    }));
});

const layers = computed(() => health.value?.layers || {});
const sensors = computed(() => {
  const list = layers.value.sensors?.sensors || [];
  return list.map((sensor) => ({
    id: sensor.sensor_id,
    name: `${sensor.source || "sensor"} · ${sensor.asset_id ? `asset ${sensor.asset_id}` : "未绑定"}`,
    state: sensor.status === "ok" || sensor.status === "running" ? "ok" : sensor.status === "stale" || sensor.status === "degraded" ? "warn" : sensor.status === "failed" || sensor.status === "stopped" ? "bad" : "unknown",
    age: sensor.heartbeat_age_seconds !== undefined ? `${Math.round(Number(sensor.heartbeat_age_seconds) / 60)} 分钟前` : "未知"
  }));
});
const totalSensors = computed(() => Number(layers.value.sensors?.total || 0));
const healthySensors = computed(() => Number(layers.value.sensors?.healthy || 0));
const sensorHealth = computed(() => (totalSensors.value ? Math.round((healthySensors.value / totalSensors.value) * 100) : null));
const evidence = computed(() => layers.value.runtime_evidence || null);
const evidenceTone = computed(() => (!evidence.value ? "muted" : evidence.value.fresh ? "low" : "high"));
const evidenceLabel = computed(() => (!evidence.value ? "未知" : evidence.value.fresh ? "新鲜" : "部分过期"));
const evidenceCopy = computed(() => (evidence.value ? `最近事件 ${evidence.value.latest_event_age_seconds !== undefined ? `${Math.round(Number(evidence.value.latest_event_age_seconds) / 60)} 分钟前` : "未知"}` : "未读取到运行时证据。"));
const evidenceWarning = computed(() => (evidence.value ? (evidence.value.fresh ? "证据在新鲜度窗口内" : "部分证据过期 · 不能视为“无风险”") : "证据状态未知"));

const dispositionWidth = computed(() => {
  const pending = Number(summary.value.pending_remediation_tasks || 0);
  const total = Math.max(riskTotal.value, 1);
  return `${Math.max(0, Math.min(100, 100 - (pending / total) * 100))}%`;
});

const agentSteps = computed(() => {
  const status = latestRun.value?.status;
  const done = ["completed", "succeeded"].includes(status);
  const active = ["running", "queued_remote", "pending"].includes(status);
  return [
    { key: "asset", label: "资产调查", note: done ? "已完成" : active ? "已读取对象" : "等待运行", time: shortTime(latestRun.value?.created_at || ""), state: done || active ? "done" : "idle" },
    { key: "vuln", label: "漏洞分析", note: done ? "已完成" : active ? "正在补证" : "等待上游", time: "—", state: done ? "done" : active ? "active" : "idle" },
    { key: "runtime", label: "运行时分析", note: done ? "已完成" : active ? "正在补证" : "等待上游", time: "—", state: done ? "done" : active ? "active" : "idle" },
    { key: "decision", label: "决策规划", note: done ? "已完成 · 待人工审查" : "等待上游", time: "—", state: done ? "done" : "idle" }
  ];
});

function widthFor(level) {
  const value = { Critical: critical.value, High: high.value, Medium: medium.value, Low: low.value }[level];
  if (!riskTotal.value) return "0%";
  return `${(value / riskTotal.value) * 100}%`;
}

function toneForLevel(level) {
  return levelTone(level);
}

function openRisk(row) {
  if (row?.cve_id) router.push(`/risks/${encodeURIComponent(row.cve_id)}`);
}

function short(value) {
  const text = String(value || "");
  return text.length > 18 ? `${text.slice(0, 18)}…` : text || "—";
}

function exportReport() {
  window.open(currentReportUrls.markdown, "_blank", "noopener");
}

async function refresh() {
  loadingSummary.value = true;
  error.value = "";
  try {
    const result = await api.get("/dashboard/summary", { timeout: 20000 });
    summary.value = result.data || {};
    updated.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "安全态势加载失败，请检查后端服务。";
  } finally {
    loadingSummary.value = false;
  }

  fetchHealth()
    .then((value) => { health.value = value; })
    .catch(() => { health.value = null; });

  fetchReportArchives()
    .then((value) => { archives.value = value.archives || []; })
    .catch(() => { archives.value = []; });

  api
    .get("/unified/runs", { params: { limit: 1 }, timeout: 15000 })
    .then((value) => { runs.value = value.data?.runs || value.data || []; })
    .catch(() => { runs.value = []; });
}

onMounted(refresh);
</script>

<style scoped>
.hero-card { display: flex; flex-direction: column; }
.hero-flex { flex: 1; display: flex; gap: 20px; padding: 6px 17px 0; }
.hero-left { width: 232px; flex: 0 0 auto; border-right: 1px solid var(--line-soft); padding-right: 18px; }
.hero-right { flex: 1; min-width: 0; }
.big-label { padding-bottom: 4px; color: var(--ink-3); font-size: 10.5px; line-height: 1.4; }
.hero-note { display: flex; align-items: center; gap: 8px; margin-top: 14px; padding-top: 10px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 9.5px; }
.hero-note b { color: var(--ink); font: 700 10.5px var(--font-num); }
.hero-note .mini-bar { flex: 1; min-width: 54px; height: 4px; border-radius: 3px; background: var(--line-soft); overflow: hidden; }
.hero-note .mini-bar i { display: block; height: 4px; background: var(--accent); }
.source-bars { display: grid; gap: 15px; margin-top: 26px; }
.source-row { display: grid; grid-template-columns: 122px minmax(0, 1fr) 52px; gap: 10px; align-items: center; font-size: 9.5px; color: var(--ink-3); }
.source-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.source-track { height: 7px; background: var(--line-soft); overflow: hidden; }
.source-track i { display: block; height: 7px; }
.source-row b { text-align: right; color: var(--ink); font: 700 9.5px var(--font-num); }
.chart-source-note { margin-top: 22px; padding-top: 10px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 9px; line-height: 1.55; }
.empty-inline-chart { display: grid; place-items: center; height: 150px; color: var(--muted); font-size: 10px; }
.evidence-card { display: flex; flex-direction: column; }
.evidence-body { padding-top: 8px; }
.gauge-row { display: flex; align-items: center; gap: 14px; }
.gauge-copy { min-width: 0; }
.gauge-copy .t { font-size: 11.5px; font-weight: 650; }
.gauge-copy .d { margin-top: 3px; color: var(--muted); font-size: 9.5px; line-height: 1.5; }
.gauge-copy .warn { margin-top: 5px; font-size: 9px; font-weight: 600; line-height: 1.45; }
.sensor-list { border-top: 1px solid var(--line-soft); margin-top: 2px; }
.sensor { display: flex; align-items: center; gap: 7px; height: 31px; padding: 0 17px; border-top: 1px solid var(--line-soft); font-size: 10px; }
.sensor:first-child { border-top: 0; }
.sensor .name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sensor .time { color: var(--muted); font-size: 8.5px; }
.sensor-empty { padding: 10px 17px; color: var(--muted); font-size: 9px; }
.agent-card { display: flex; flex-direction: column; }
.agent-row { display: grid; grid-template-columns: 22px minmax(0, 1fr) auto; gap: 9px; position: relative; }
.agent-row::before { content: ""; position: absolute; left: 10px; top: 22px; bottom: 0; width: 1px; background: var(--line); }
.agent-row:last-child::before { display: none; }
.step-dot { display: grid; place-items: center; border: 1px solid var(--line); border-radius: 50%; background: var(--surface); color: var(--muted); font: 700 8.5px var(--font-num); z-index: 1; }
.step-dot.done { background: var(--low-soft); border-color: var(--low-line); color: var(--low); }
.step-dot.active { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); box-shadow: 0 0 0 4px var(--accent-soft); }
.step-title { color: var(--ink); font-size: 11px; font-weight: 650; }
.step-note { color: var(--muted); font-size: 9px; margin-top: 1px; }
.step-time { color: var(--muted); font-size: 8.5px; padding-top: 3px; }
.agent-metrics { display: grid; grid-template-columns: 1.6fr 0.8fr 0.8fr; gap: 8px; margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--line-soft); }
.agent-metrics span { display: block; color: var(--muted); font-size: 8px; }
.agent-metrics b { display: block; margin-top: 2px; color: var(--ink); font: 700 11px var(--font-num); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.agent-callout { display: flex; align-items: center; gap: 7px; margin-top: 11px; padding: 8px 9px; border: 1px solid var(--high-line); background: var(--high-soft); color: var(--high); font-size: 9px; font-weight: 600; }
.agent-callout .link { margin-left: auto; color: var(--high); font-size: 8.5px; }
.empty-wrap { flex: 1; display: grid; place-items: center; }
</style>
