<template>
  <div class="page">
    <PageHeader
      eyebrow="Reports & archive · immutable"
      title="报告与归档"
      description="报告是可复核的交付物：数据口径、证据引用与生成时间都随归档保存。"
    >
      <template #meta>
        <span>{{ archives.length }} 份归档</span><i class="sep" /><span>最近生成 {{ updated || "尚未读取" }}</span><i class="sep" /><span>保留 90 天</span><i class="sep" /><span>SHA-256 校验</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="14" />刷新</button>
        <button class="btn primary" type="button" @click="download('json')"><Icon name="download" :size="14" />导出最新</button>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 84px minmax(0, 1fr) 120px">
      <div class="grid g-4">
        <div v-for="format in formats" :key="format.key" class="card format-card">
          <div class="stat-icon" :style="{ width: '32px', height: '32px', background: format.soft, color: format.color }"><Icon :name="format.icon" /></div>
          <div style="min-width: 0; flex: 1"><div class="format-name">{{ format.label }}</div><div class="format-note">{{ format.note }}</div></div>
          <button class="link" type="button" @click="format.action">{{ format.actionLabel }}</button>
        </div>
      </div>

      <div class="grid" style="grid-template-columns: minmax(0, 0.72fr) minmax(0, 1.6fr)">
        <section class="card">
          <div class="card-head">
            <div><div class="card-title">归档列表</div><div class="card-desc">按生成时间倒序</div></div>
            <span class="chip muted" style="height: 18px; font-size: 8px">{{ archives.length }} 份</span>
          </div>
          <div v-if="loading" class="loading-line"><span class="spinner" />正在读取归档…</div>
          <div v-else-if="!archives.length" class="archive-empty"><EmptyState title="暂无归档报告" description="生成并归档第一份报告后，这里会出现可复核的快照。" icon="file" /></div>
          <div v-else class="archive-list">
            <button v-for="(archive, index) in archives.slice(0, 7)" :key="archive.name || archive.filename || index" class="archive-row" :class="{ active: index === activeArchive }" type="button" @click="activeArchive = index">
              <div><div class="archive-title">{{ archive.title || archive.name || archive.filename || "归档报告" }}</div><div class="archive-meta">{{ archive.created_at || archive.archived_at || "—" }}<span v-if="archive.formats"> · {{ archive.formats }}</span></div></div>
              <span class="chip low" style="height: 18px; font-size: 8px">已归档</span>
            </button>
          </div>
          <div class="card-foot"><span>归档不可修改；重新生成会创建新版本。</span><span class="num">{{ archives.length }} 份</span></div>
        </section>

        <section class="card paper-card">
          <div class="paper">
            <div class="paper-cover">
              <div class="paper-kicker">IoTGuard / Weekly risk report</div>
              <h2>风险周报 · 当前快照</h2>
              <div class="paper-sub">物联网实验室 · {{ overview.asset_count ?? "—" }} 台资产 · 数据截至 {{ updated || "尚未读取" }}</div>
              <div class="paper-meta"><span>生成 {{ updated || "—" }}</span><span>版本 v0.2.0</span><span>SHA-256 {{ checksum }}</span></div>
            </div>
            <div class="paper-metrics">
              <div><span>高风险 / 严重</span><b>{{ num(overview.high_risk_count) }}</b></div>
              <div><span>待人工审查</span><b>{{ num(overview.human_review_required_count) }}</b></div>
              <div><span>资产</span><b>{{ num(overview.asset_count) }}</b></div>
            </div>
            <h3>本期结论</h3>
            <p>{{ conclusion }}</p>
            <h3>优先处置</h3>
            <table v-if="topRisks.length">
              <thead><tr><th>#</th><th>CVE</th><th>资产</th><th>风险分</th><th>建议</th></tr></thead>
              <tbody><tr v-for="(risk, index) in topRisks.slice(0, 3)" :key="risk.cve_id"><td>P{{ index + 1 }}</td><td>{{ risk.cve_id }}</td><td>{{ risk.hostname }}</td><td>{{ score(risk.score) }}</td><td>{{ risk.risk_level === "Critical" ? "立即修复" : "排期修复" }}</td></tr></tbody>
            </table>
            <p v-else class="paper-empty">风险队列暂无对象；本报告只陈述已读取事实。</p>
            <div class="foot">机密 · 仅限授权环境 · 生成后不可修改 · 证据引用见附录 A</div>
          </div>
        </section>
      </div>

      <section class="card">
        <div class="card-head" style="padding-top: 11px"><div><div class="card-title">归档与保留</div><div class="card-desc">自动归档、保留周期与完整性校验</div></div><button class="btn sm" type="button" @click="download('json')"><Icon name="download" :size="12" />立即导出</button></div>
        <div class="retention-grid">
          <div><span>自动归档</span><b>每日 02:00</b><i>由后端任务执行</i></div>
          <div><span>保留周期</span><b>90 天</b><i>到期自动清理</i></div>
          <div><span>完整性</span><b>SHA-256</b><i>{{ checksum }}</i></div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import { api, currentReportUrls } from "../api";
import { num, score } from "../utils/format";

const archives = ref([]);
const summary = ref({});
const dashboard = ref({});
const loading = ref(true);
const error = ref("");
const updated = ref("");
const activeArchive = ref(0);

const overview = computed(() => summary.value.overview || {});
const checksum = computed(() => {
  const value = summary.value?.overview?.sha256 || summary.value?.review?.sha256;
  return value ? String(value).slice(0, 12) + "…" : "未记录";
});
const topRisks = computed(() => dashboard.value.top_vulnerabilities || []);
const conclusion = computed(() => {
  const high = overview.value.high_risk_count;
  const pending = overview.value.human_review_required_count;
  const assets = overview.value.asset_count;
  if (high === undefined) return "本期报告尚未读取到汇总数据。请检查后端报告接口。";
  return `共读取 ${num(overview.value.vulnerability_count)} 条漏洞情报，覆盖 ${num(assets)} 台资产；当前 ${num(high)} 条高风险，${num(pending)} 条待人工审查。风险分只用于排序，确认受影响仍需版本与证据链。`;
});

const formats = [
  { key: "markdown", label: "Markdown", note: "可 diff · 适合评审", icon: "file", color: "var(--info)", soft: "var(--info-soft)", actionLabel: "导出", action: () => download("markdown") },
  { key: "json", label: "JSON", note: "机器可读 · 完整字段", icon: "file", color: "var(--low)", soft: "var(--low-soft)", actionLabel: "导出", action: () => download("json") },
  { key: "csv", label: "CSV", note: "明细表 · 便于核对", icon: "file", color: "var(--high)", soft: "var(--high-soft)", actionLabel: "导出", action: () => download("csv") },
  { key: "print", label: "打印", note: "浏览器打印当前快照", icon: "printer", color: "var(--accent)", soft: "var(--accent-soft)", actionLabel: "打印", action: () => window.print() }
];

function download(kind) {
  window.open(currentReportUrls[kind] || currentReportUrls.json, "_blank", "noopener");
}

async function load() {
  loading.value = true;
  error.value = "";
  const [archiveResult, summaryResult, dashboardResult] = await Promise.allSettled([
    api.get("/reports/archives", { timeout: 20000 }),
    api.get("/reports/summary.json", { timeout: 20000 }),
    api.get("/dashboard/summary", { timeout: 20000 })
  ]);
  if (archiveResult.status === "fulfilled") archives.value = archiveResult.value.data?.archives || archiveResult.value.data || [];
  if (summaryResult.status === "fulfilled") summary.value = summaryResult.value.data || {};
  if (dashboardResult.status === "fulfilled") dashboard.value = dashboardResult.value.data || {};
  if (summaryResult.status === "rejected" && dashboardResult.status === "rejected") error.value = "报告数据读取失败，请检查后端服务。";
  updated.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  loading.value = false;
}

onMounted(load);
</script>

<style scoped>
.format-card { display: flex; align-items: center; gap: 10px; padding: 11px 13px; }
.format-name { color: var(--ink); font-size: 10.5px; font-weight: 700; }
.format-note { color: var(--muted); font-size: 8.5px; margin-top: 1px; }
.archive-list { padding: 6px 0 0; }
.archive-row { display: flex; align-items: center; gap: 9px; width: 100%; min-height: 56px; padding: 0 16px; border: 0; border-bottom: 1px solid var(--line-soft); background: transparent; text-align: left; cursor: pointer; }
.archive-row:hover { background: var(--surface-2); }
.archive-row.active { background: var(--accent-soft); border-left: 3px solid var(--accent); }
.archive-row > div { flex: 1; min-width: 0; }
.archive-title { color: var(--ink); font-size: 10.5px; font-weight: 650; }
.archive-meta { color: var(--muted); font-size: 8.5px; margin-top: 2px; }
.archive-empty { display: grid; place-items: center; min-height: 280px; }
.paper-card { padding: 13px; background: var(--surface-2); }
.retention-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; padding: 8px 17px 12px; }
.retention-grid span { display: block; color: var(--muted); font-size: 8.5px; }
.retention-grid b { display: block; margin-top: 3px; color: var(--ink); font-size: 10.5px; }
.retention-grid i { display: block; margin-top: 2px; color: var(--muted); font-size: 8.5px; font-style: normal; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
