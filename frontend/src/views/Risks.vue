<template>
  <div class="page">
    <PageHeader
      eyebrow="Vulnerability & risk · triage"
      title="漏洞与风险"
      description="公告候选、版本适用性与运行时证据分开表达，风险分只是排序，不是结论。"
    >
      <template #meta>
        <span>{{ highCount }} 条高风险</span><i class="sep" /><span>{{ rows.length }} 条资产级风险</span><i class="sep" /><span>{{ pendingReview }} 条待人工审查</span><i class="sep" /><span>{{ matches.length }} 条候选匹配</span>
      </template>
      <template #actions>
        <button class="btn" type="button" :disabled="calculating" @click="calculate"><Icon name="refresh" :size="14" />{{ calculating ? "计算中…" : "重新计算" }}</button>
        <button class="btn primary" type="button" :disabled="!rows.length" @click="openFirst"><Icon name="play" :size="14" />进入风险审查</button>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 230px minmax(0, 1fr)">
      <div class="grid g-2-1">
        <section class="card feature">
          <div class="card-head">
            <div><div class="card-title">风险矩阵</div><div class="card-desc">风险分 × 等级 · 数字为当前对象数</div></div>
            <span class="chip crit"><i class="dot" />{{ counts.Critical || 0 }} 严重 · {{ counts.High || 0 }} 高危</span>
          </div>
          <div class="card-body matrix-body">
            <div class="matrix">
              <template v-for="(row, y) in matrix" :key="y">
                <div class="axis y">{{ yLabels[y] }}</div>
                <div v-for="(cell, x) in row" :key="`${y}-${x}`" class="cell" :data-tone="cellTone(y, x)" :title="`${yLabels[y] || '未分级'} · 风险分 ${x * 20}–${x * 20 + 20}`">
                  {{ cell || "" }}
                </div>
              </template>
              <div></div><div class="axis">低</div><div class="axis"></div><div class="axis">中</div><div class="axis"></div><div class="axis">高</div>
            </div>
            <div class="matrix-copy">
              <p>右上角是优先处理区：高等级、高风险分，且通常伴随运行时证据。</p>
              <div class="matrix-legend">
                <span><i class="dot" style="background: var(--low)" />低风险</span>
                <span><i class="dot" style="background: var(--high)" />中风险</span>
                <span><i class="dot" style="background: var(--crit)" />高风险</span>
              </div>
              <div class="matrix-note">矩阵只用于分诊；确认受影响仍需版本与证据链。</div>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div><div class="card-title">今日处置队列</div><div class="card-desc">{{ queue.length }} 条优先 · 按风险分</div></div>
            <span class="chip high"><i class="dot" />P1 优先</span>
          </div>
          <div class="card-body" style="padding-top: 6px">
            <div v-if="!queue.length" class="queue-empty">暂无待处置对象。</div>
            <div v-for="row in queue" :key="row.key" class="queue-row" @click="openRisk(row)">
              <span class="chip" :class="levelTone(row.level)" style="height: 18px; font-size: 8px">{{ levelLabel(row.level) }}</span>
              <div class="queue-copy"><div class="mono">{{ row.cve_id }}</div><div>{{ row.hostname }} · {{ row.package_name || "—" }}</div></div>
              <span class="num">{{ score(row.score) }}</span>
            </div>
            <div class="queue-actions">
              <button class="btn sm primary" type="button" @click="openFirst">逐条审查</button>
              <button class="btn sm" type="button" @click="clearFilters">重置筛选</button>
            </div>
          </div>
          <div class="card-foot"><span>分派只改变责任人，不改变风险结论。</span><span class="num">{{ pendingReview }} / {{ rows.length }}</span></div>
        </section>
      </div>

      <section class="card">
        <div class="card-head">
          <div><div class="card-title">风险队列</div><div class="card-desc">严重度、证据与研判状态分开显示</div></div>
          <span class="link" @click="clearFilters">清除筛选 <Icon name="filter" :size="12" /></span>
        </div>
        <div class="queue-filters">
          <label class="search-inline"><Icon name="search" :size="12" /><input v-model="search" type="search" placeholder="搜索 CVE、资产或软件包" /></label>
          <span v-for="level in levels" :key="level" class="chip" :class="{ accent: severity === level }" @click="severity = severity === level ? '' : level">{{ levelLabel(level) }} {{ counts[level] || 0 }}</span>
          <span class="chip" :class="{ accent: reviewOnly }" @click="reviewOnly = !reviewOnly">待审查 {{ pendingReview }}</span>
          <span class="filters-count">{{ filteredRows.length }} / {{ rows.length }}</span>
        </div>
        <div v-if="loading" class="loading-line"><span class="spinner" />正在读取风险队列…</div>
        <div v-else-if="!filteredRows.length" class="empty-wrap"><EmptyState title="没有符合条件的风险" description="调整搜索或筛选条件；候选记录不会因为未命中而消失。" icon="bug" /></div>
        <div v-else class="table-wrap">
          <table style="table-layout: fixed">
            <colgroup><col style="width: 64px" /><col style="width: 152px" /><col style="width: 138px" /><col style="width: 78px" /><col style="width: 98px" /><col style="width: 86px" /><col style="width: 72px" /><col style="width: 20px" /></colgroup>
            <thead><tr><th>等级</th><th>CVE</th><th>资产</th><th>风险分</th><th>证据</th><th>研判状态</th><th>更新</th><th></th></tr></thead>
            <tbody>
              <tr v-for="row in filteredRows.slice(0, 7)" :key="row.key" style="cursor: pointer" @click="openRisk(row)">
                <td><span class="chip" :class="levelTone(row.level)"><i class="dot" />{{ levelLabel(row.level) }}</span></td>
                <td class="mono">{{ row.cve_id }}<small>{{ row.package_name || "—" }} · CVSS {{ cvss(row.cvss_score) }}</small></td>
                <td class="name">{{ row.hostname }}<small>{{ row.active === false ? "历史归档" : "当前风险" }}</small></td>
                <td><span class="score" :class="levelTone(row.level)"><b>{{ score(row.score) }}</b><i><em :style="{ width: `${Math.min(100, Number(row.score) || 0)}%` }" /></i></span></td>
                <td><span class="chip" :class="runtimeTone(row.runtime)"><i class="dot" />{{ runtimeLabel(row.runtime) }}</span></td>
                <td><span class="chip" :class="reviewTone(row)"><i class="dot" />{{ reviewLabel(row) }}</span></td>
                <td class="num" style="font-size: 8.5px; color: var(--muted)">{{ row.updated_at ? timeAgo(row.updated_at) : "—" }}</td>
                <td><Icon name="chev-right" :size="12" style="color: var(--line-strong)" /></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="card-foot"><span>风险分排序不代表确认受影响；候选记录必须保留“未评估”状态。</span><span class="num">{{ filteredRows.length }} / {{ rows.length }} 显示</span></div>
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
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify } from "../stores/ui";
import { cvss, levelLabel, levelTone, score, statusLabel, timeAgo } from "../utils/format";

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

const filteredRows = computed(() => {
  const needle = search.value.trim().toLowerCase();
  return rows.value.filter((row) => {
    if (severity.value && row.level !== severity.value) return false;
    if (reviewOnly.value && !(row.humanReviewRequired || row.reviewStatus === "pending_human_review")) return false;
    if (needle && ![row.cve_id, row.hostname, row.package_name].some((value) => String(value || "").toLowerCase().includes(needle))) return false;
    return true;
  });
});

const queue = computed(() => [...rows.value].sort((a, b) => (b.humanReviewRequired ? 1 : 0) - (a.humanReviewRequired ? 1 : 0) || Number(b.score) - Number(a.score)).slice(0, 3));

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

function runtimeLabel(value) {
  return { verified: "已验证", contextual: "上下文关联", not_observed: "未观测", waiting: "等待证据" }[value] || value || "未知";
}
function runtimeTone(value) {
  return { verified: "low", contextual: "info", not_observed: "muted", waiting: "high" }[value] || "muted";
}
function reviewLabel(row) {
  if (row.active === false) return "历史归档";
  if (row.humanReviewRequired || row.reviewStatus === "pending_human_review") return "待审查";
  if (row.reviewStatus === "human_confirmed") return "已确认";
  return statusLabel(row.reviewStatus || "candidate");
}
function reviewTone(row) {
  if (row.humanReviewRequired || row.reviewStatus === "pending_human_review") return "high";
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

onMounted(load);
</script>

<style scoped>
.matrix-body { display: flex; gap: 18px; padding: 6px 17px 10px; }
.matrix-body .matrix { flex: 1; min-width: 0; }
.matrix-copy { width: 190px; flex: 0 0 auto; color: var(--muted); font-size: 9.5px; line-height: 1.55; padding-top: 2px; }
.matrix-copy p { margin: 0; }
.matrix-legend { display: grid; gap: 6px; margin-top: 10px; }
.matrix-legend span { display: flex; align-items: center; gap: 6px; }
.matrix-note { margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--line-soft); font-size: 9px; }
.queue-row { display: flex; align-items: center; gap: 9px; min-height: 42px; border-bottom: 1px solid var(--line-soft); cursor: pointer; }
.queue-row:last-of-type { border-bottom: 0; }
.queue-copy { min-width: 0; flex: 1; }
.queue-copy div:first-child { font-size: 10.5px; color: var(--ink); }
.queue-copy div:last-child { color: var(--muted); font-size: 8.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.queue-row > .num { color: var(--ink); font: 700 11px var(--font-num); }
.queue-empty { padding: 20px 0; color: var(--muted); font-size: 10px; }
.queue-actions { display: flex; gap: 6px; margin-top: 8px; }
.queue-actions .btn { flex: 1; height: 28px; font-size: 10px; }
.queue-filters { display: flex; align-items: center; gap: 6px; padding: 9px 15px 0; flex-wrap: wrap; }
.queue-filters .chip { cursor: pointer; height: 21px; font-size: 9px; }
.search-inline { display: flex; align-items: center; gap: 6px; width: 210px; height: 28px; padding: 0 9px; border: 1px solid var(--line); background: var(--surface-2); color: var(--muted); }
.search-inline input { flex: 1; min-width: 0; border: 0; outline: 0; background: transparent; font: inherit; font-size: 9.5px; color: var(--ink); }
.filters-count { margin-left: auto; color: var(--muted); font: 8.5px var(--font-num); }
.empty-wrap { display: grid; place-items: center; min-height: 260px; }
</style>
