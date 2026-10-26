<template>
  <div class="page">
    <PageHeader
      title="漏洞与风险"
      subtitle="Vulnerability & Risk"
      description="公告候选、版本适用性与运行时证据分开表达"
    >
      <template #meta>
        <span>{{ highCount }} 条高风险</span><i class="sep" /><span>{{ rows.length }} 条资产级风险</span><i class="sep" /><span>{{ pendingReview }} 条待人工审查</span><i class="sep" /><span>{{ matches.length }} 条候选匹配</span>
      </template>
      <template #actions>
        <button class="btn" type="button" :disabled="calculating" @click="calculate"><Icon name="refresh" :size="15" />{{ calculating ? "计算中…" : "重新计算" }}</button>
        <button class="btn primary" type="button" :disabled="!rows.length" @click="openFirst"><Icon name="shield" :size="15" />进入风险审查</button>
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

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <div class="kpi-row">
      <KpiCard label="高危漏洞" :value="num(highCount)" unit="条" icon="shield-alert" tone="red" :sub="`严重 ${counts.Critical || 0} · 高危 ${counts.High || 0}`" />
      <KpiCard label="中危漏洞" :value="num(counts.Medium || 0)" unit="条" icon="alert" tone="orange" :sub="`${share(counts.Medium)} 的资产级风险`" />
      <KpiCard label="低危漏洞" :value="num(counts.Low || 0)" unit="条" icon="shield" tone="low" :sub="`${share(counts.Low)} 的资产级风险`" />
      <KpiCard label="待审查" :value="num(pendingReview)" unit="条" icon="target" tone="purple" :sub="`${pendingReview} 条风险等待人工签收`" />
    </div>

    <div class="risk-layout">
      <div class="risk-left">
        <section class="card">
          <div class="card-head">
            <div><div class="card-title">风险分布</div><div class="card-desc">按当前风险等级</div></div>
            <span class="chip muted">{{ rows.length }} 条</span>
          </div>
          <div class="risk-donut">
            <DonutChart :items="riskItems" :size="132" center-label="总览" :center-value="num(rows.length)" />
          </div>
          <div class="legend-list" style="padding: 0 18px 16px">
            <span v-for="item in riskItems" :key="item.label">
              <i class="dot" :style="{ background: item.color }" />{{ item.label }}
              <b>{{ num(item.value) }}</b><em>{{ pctOf(item.value) }}</em>
            </span>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div><div class="card-title">受影响设备类型</div><div class="card-desc">按资产命中计数</div></div>
          </div>
          <div class="device-bars">
            <div v-for="item in affectedAssets" :key="item.name" class="device-bar-row">
              <span class="db-name" :title="item.name">{{ item.name }}</span>
              <span class="db-track"><i :style="{ width: item.width, background: item.color }" /></span>
              <b class="num">{{ item.count }}</b>
            </div>
            <div v-if="!affectedAssets.length" class="empty-note" style="padding: 8px 0">暂无资产命中记录。</div>
          </div>
          <div class="card-foot"><span>同一资产可命中多条风险。</span><span class="num">{{ affectedAssets.length }} 类</span></div>
        </section>

        <section class="card">
          <div class="card-head">
            <div><div class="card-title">风险矩阵</div><div class="card-desc">等级 × 风险分区间</div></div>
            <span class="chip crit"><i class="dot" />{{ counts.Critical || 0 }} 严重</span>
          </div>
          <div class="matrix-body">
            <div class="matrix">
              <template v-for="(row, y) in matrix" :key="y">
                <div class="axis y">{{ yLabels[y] }}</div>
                <div v-for="(cell, x) in row" :key="`${y}-${x}`" class="cell" :data-tone="cellTone(y, x)" :title="`${yLabels[y] || '未分级'} · 风险分 ${x * 20}–${x * 20 + 20}`">{{ cell || "" }}</div>
              </template>
              <div></div><div class="axis">低</div><div class="axis"></div><div class="axis">中</div><div class="axis"></div><div class="axis">高</div>
            </div>
          </div>
          <div class="card-foot"><span>右上角为优先处理区。</span><span class="num">0–100</span></div>
        </section>
      </div>

      <section class="card risk-list-card">
        <div class="card-head">
          <div><div class="card-title">风险列表</div><div class="card-desc">严重度、证据与研判状态分开显示</div></div>
          <span class="link" @click="clearFilters">清除筛选 <Icon name="filter" :size="13" /></span>
        </div>
        <div class="risk-toolbar">
          <div class="risk-tabs">
            <span class="chip" :class="{ accent: !severity && !reviewOnly }" @click="clearFilters">全部 {{ rows.length }}</span>
            <span v-for="level in levels" :key="level" class="chip" :class="{ accent: severity === level }" @click="severity = severity === level ? '' : level">{{ levelLabel(level) }} {{ counts[level] || 0 }}</span>
            <span class="chip" :class="{ accent: reviewOnly }" @click="reviewOnly = !reviewOnly">待审查 {{ pendingReview }}</span>
          </div>
          <label class="search-inline"><Icon name="search" :size="14" /><input v-model="search" type="search" placeholder="搜索 CVE、资产或组件" /></label>
        </div>
        <div v-if="loading" class="loading-line" style="padding: 30px 18px"><span class="spinner" />正在读取风险队列…</div>
        <div v-else-if="!filteredRows.length" class="empty-wrap" style="min-height: 320px">
          <EmptyState title="没有符合条件的风险" description="调整搜索或筛选条件；候选记录不会因为未命中而消失。" icon="bug" />
        </div>
        <div v-else class="table-wrap">
          <table class="risk-table">
            <thead><tr><th>风险等级</th><th>CVE 编号</th><th>影响组件</th><th>发现设备</th><th>风险分</th><th>研判状态</th><th>操作</th></tr></thead>
            <tbody>
              <tr v-for="row in filteredRows.slice(0, 9)" :key="row.key" style="cursor: pointer" tabindex="0" role="link" @click="openRisk(row)" @keydown.enter="openRisk(row)">
                <td><span class="chip" :class="levelTone(row.level)"><i class="dot" />{{ levelLabel(row.level) }}</span></td>
                <td class="mono">{{ row.cve_id }}<small>CVSS {{ cvss(row.cvss_score) }}</small></td>
                <td>{{ row.package_name || "—" }}<small>{{ row.runtime === 'verified' ? "运行时已验证" : "公告候选" }}</small></td>
                <td class="name" :title="row.hostname">{{ row.hostname }}<small>{{ row.active === false ? "历史归档" : "当前风险" }}</small></td>
                <td><span class="score" :class="levelTone(row.level)"><b>{{ score(row.score) }}</b><i><em :style="{ width: `${Math.min(100, Number(row.score) || 0)}%` }" /></i></span></td>
                <td><span class="chip" :class="reviewTone(row)"><i class="dot" />{{ reviewLabel(row) }}</span></td>
                <td><button class="row-action" type="button" aria-label="查看风险详情" @click.stop="openRisk(row)"><Icon name="more" :size="15" /></button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="card-foot">
          <span>风险分排序不代表确认受影响；候选记录必须保留“未评估”状态。</span>
          <span class="num">{{ filteredRows.length }} / {{ rows.length }} 显示</span>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import KpiCard from "../components/KpiCard.vue";
import DonutChart from "../components/DonutChart.vue";
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify } from "../stores/ui";
import { cvss, levelLabel, levelTone, num, score, statusLabel } from "../utils/format";
import VerdictRuling from "../components/VerdictRuling.vue";
import { SEVERITY, SERIES } from "../lib/palette";

const route = useRoute();
const router = useRouter();
const rows = ref([]);
const matches = ref([]);
const loading = ref(true);
const calculating = ref(false);
const error = ref("");
const search = ref(String(route.query.q || ""));
const severity = ref("");
const reviewOnly = ref(false);
const levels = ["Critical", "High", "Medium", "Low"];

const counts = computed(() => rows.value.reduce((map, row) => {
  map[row.level] = (map[row.level] || 0) + 1;
  return map;
}, { Critical: 0, High: 0, Medium: 0, Low: 0 }));

const highCount = computed(() => (counts.value.Critical || 0) + (counts.value.High || 0));
const pendingReview = computed(() => rows.value.filter((row) => row.humanReviewRequired || row.reviewStatus === "pending_human_review").length);

const riskItems = computed(() => [
  { label: "严重", value: counts.value.Critical || 0, color: SEVERITY.critical },
  { label: "高危", value: counts.value.High || 0, color: SEVERITY.high },
  { label: "中危", value: counts.value.Medium || 0, color: SEVERITY.medium },
  { label: "低危", value: counts.value.Low || 0, color: SEVERITY.low }
]);

const affectedAssets = computed(() => {
  const map = rows.value.reduce((acc, row) => {
    const name = row.hostname || "未知资产";
    acc[name] = (acc[name] || 0) + 1;
    return acc;
  }, {});
  const entries = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const max = Math.max(...entries.map(([, value]) => value), 1);
  const palette = SERIES;
  return entries.map(([name, count], index) => ({
    name,
    count,
    width: `${Math.max(6, (count / max) * 100)}%`,
    color: palette[index % palette.length]
  }));
});

const filteredRows = computed(() => {
  const needle = search.value.trim().toLowerCase();
  return rows.value.filter((row) => {
    if (severity.value && row.level !== severity.value) return false;
    if (reviewOnly.value && !(row.humanReviewRequired || row.reviewStatus === "pending_human_review")) return false;
    if (needle && ![row.cve_id, row.hostname, row.package_name].some((value) => String(value || "").toLowerCase().includes(needle))) return false;
    return true;
  });
});

const yLabels = ["严重", "高危", "中危", "低危", ""];
const matrix = computed(() => {
  const grid = Array.from({ length: 5 }, () => Array(5).fill(0));
  for (const row of rows.value) {
    const y = { Critical: 0, High: 1, Medium: 2, Low: 3 }[row.level] ?? 4;
    const x = Math.min(4, Math.max(0, Math.floor((Number(row.score) || 0) / 20)));
    grid[y][x] += 1;
  }
  return grid;
});

function cellTone(y, x) {
  if (y <= 1 && x >= 3) return "crit";
  if (y <= 1 || x >= 3) return "high";
  if (y === 2 || x === 2) return "mid";
  return "low";
}

function share(value) {
  if (!rows.value.length) return "0%";
  const ratio = (Number(value) / rows.value.length) * 100;
  return ratio > 0 && ratio < 1 ? "<1%" : `${Math.round(ratio)}%`;
}
function pctOf(value) {
  if (!rows.value.length) return "0%";
  const ratio = (Number(value) / rows.value.length) * 100;
  return ratio > 0 && ratio < 1 ? "<1%" : `${Math.round(ratio)}%`;
}

function reviewLabel(row) {
  if (row.active === false) return "历史归档";
  if (row.humanReviewRequired || row.reviewStatus === "pending_human_review") return "待审查";
  if (row.reviewStatus === "human_confirmed") return "已确认";
  return statusLabel(row.reviewStatus || "candidate");
}
function reviewTone(row) {
  if (row.active === false) return "muted";
  if (row.humanReviewRequired || row.reviewStatus === "pending_human_review") return "high";
  if (row.reviewStatus === "quarantined_mapping") return "high";
  if (row.reviewStatus === "human_confirmed") return "low";
  return "info";
}

function openRisk(row) {
  router.push(`/risks/${encodeURIComponent(row.risk_id || row.cve_id)}`);
}
function openFirst() {
  const row = filteredRows.value[0];
  if (row) openRisk(row);
}
function clearFilters() {
  search.value = "";
  severity.value = "";
  reviewOnly.value = false;
}

async function calculate() {
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    return;
  }
  calculating.value = true;
  try {
    await api.post("/risk/calculate", null, { headers: { "X-Control-Token": controlSession.token }, timeout: 120000 });
    notify("风险基线已重新计算", "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "风险计算失败", "error");
  } finally {
    calculating.value = false;
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const ranking = await api.get("/risk/ranking", { timeout: 25000 });
    rows.value = (ranking.data || []).map((row) => {
      const level = row.has_final_conclusion ? row.risk_level : row.preliminary_level;
      return {
        key: String(row.risk_id ?? row.id ?? row.cve_id),
        risk_id: row.risk_id ?? row.id,
        cve_id: row.cve_id,
        hostname: row.hostname || "—",
        package_name: row.package_name || "",
        score: Number(row.has_final_conclusion ? row.final_score : row.preliminary_score ?? row.static_score ?? 0),
        level: level || "Medium",
        runtime: row.runtime_status || "waiting",
        reviewStatus: row.review_status || (row.active === false ? "inactive" : "candidate"),
        humanReviewRequired: Boolean(row.human_review_required),
        active: row.active,
        cvss_score: row.cvss_score,
        updated_at: row.updated_at || row.created_at
      };
    });
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "风险队列读取失败，请检查后端服务。";
  } finally {
    loading.value = false;
  }
  api.get("/matching/results", { timeout: 25000 }).then((value) => { matches.value = value.data || []; }).catch(() => { matches.value = []; });
}


/* 页面级状态印章：与判决页共用同一套视觉语言 */
const ruling = computed(() => {
  const nCrit = Number(counts.value.Critical || 0);
  const nHigh = Number(counts.value.High || 0);
  const nMid = Number(counts.value.Medium || 0);
  const nLow = Number(counts.value.Low || 0);
  const pending = pendingReview.value;
  const total = rows.value.length;
  const tags = [
    { text: `严重 ${nCrit}`, tone: "crit" },
    { text: `高危 ${nHigh}`, tone: "high" },
    { text: `中危 ${nMid}`, tone: "mid" },
    { text: `低危 ${nLow}`, tone: "low" },
    { text: `待审 ${pending}`, tone: "" },
  ];
  if (total === 0) {
    return {
      state: "weak", stampMain: "无数据", stampEn: "NO DATA",
      title: "当前没有可研判的风险记录",
      detail: "无记录不等于安全：需要先完成资产采集与情报同步，风险条目才会产生。",
      tags,
    };
  }
  if (nCrit + nHigh > 0) {
    return {
      state: "fail", stampMain: "存在高危", stampEn: "AT RISK",
      title: `当前资产存在 ${nCrit + nHigh} 条高危及以上风险`,
      detail: `严重 ${nCrit} 条、高危 ${nHigh} 条；中危 ${nMid} 条、低危 ${nLow} 条。风险分综合 CVSS、EPSS、暴露面与运行时证据，不代表已确认利用。`,
      tags,
    };
  }
  return {
    state: "pass", stampMain: "无高危", stampEn: "NO HIGH",
    title: `共 ${total} 条风险，其中无高危及以上`,
    detail: `中危 ${nMid} 条、低危 ${nLow} 条。该结论仅覆盖已采集资产，不代表未采集部分安全。`,
    tags,
  };
});
onMounted(load);
</script>

<style scoped>
.risk-layout { display: grid; grid-template-columns: 312px minmax(0, 1fr); gap: 16px; align-items: start; }
.risk-left { display: grid; gap: 16px; }
.risk-donut { display: grid; place-items: center; padding: 16px 0 12px; }
.device-bars { display: grid; gap: 12px; padding: 12px 16px 12px; }
.device-bar-row { display: grid; grid-template-columns: 104px minmax(0, 1fr) 32px; gap: 8px; align-items: center; }
.db-name { color: #5b6b82; font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.db-track { height: 7px; border-radius: 999px; background: #eef3fa; overflow: hidden; }
.db-track i { display: block; height: 7px; border-radius: 999px; }
.device-bar-row b { text-align: right; color: var(--ink); font-size: 14px; font-weight: 700; }

.risk-list-card { min-width: 0; }
.risk-table { width: 100%; table-layout: fixed; }
.risk-table th:nth-child(1), .risk-table td:nth-child(1) { width: 92px; }
.risk-table th:nth-child(2), .risk-table td:nth-child(2) { width: 170px; }
.risk-table th:nth-child(3), .risk-table td:nth-child(3) { width: 170px; }
.risk-table th:nth-child(4), .risk-table td:nth-child(4) { width: 220px; }
.risk-table th:nth-child(5), .risk-table td:nth-child(5) { width: 150px; }
.risk-table th:nth-child(6), .risk-table td:nth-child(6) { width: 132px; }
.risk-table th:nth-child(7), .risk-table td:nth-child(7) { width: 52px; }
.risk-table .score i { width: 44px; }
.risk-table td.name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
@media (max-width: 1500px) {
  .risk-table th:nth-child(3), .risk-table td:nth-child(3) { display: none; }
  .risk-table th:nth-child(1), .risk-table td:nth-child(1) { width: 92px; }
  .risk-table th:nth-child(2), .risk-table td:nth-child(2) { width: 160px; }
  .risk-table th:nth-child(4), .risk-table td:nth-child(4) { width: 200px; }
  .risk-table th:nth-child(5), .risk-table td:nth-child(5) { width: 136px; }
  .risk-table th:nth-child(6), .risk-table td:nth-child(6) { width: 124px; }
  .risk-table th:nth-child(7), .risk-table td:nth-child(7) { width: 48px; }
  .risk-table .score i { width: 36px; }
}
.matrix-body { padding: 12px 16px 12px; }
.matrix-body .matrix { height: 168px; }
.risk-toolbar { display: flex; align-items: center; gap: 12px; padding: 12px 16px 12px; flex-wrap: wrap; }
.risk-tabs { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.risk-tabs .chip { cursor: pointer; height: 28px; border-radius: 8px; padding: 0 11px; }
.risk-toolbar .search-inline { margin-left: auto; width: 240px; height: 34px; }
.row-action {
  display: grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: #64748b;
}
.row-action:hover { border-color: #e3ebf6; background: #f7fafd; color: var(--accent-2); }

@media (max-width: 1280px) {
  .risk-layout { grid-template-columns: minmax(0, 1fr); }
}
</style>
