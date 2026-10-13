<template>
  <section class="page risk-center-page" v-loading="loading">
    <header class="page-header">
      <div><span class="section-kicker">RISK OPERATIONS</span><h1>风险中心</h1><p>统一管理漏洞命中、风险队列和单对象风险解释。</p></div>
      <div class="header-actions">
        <el-button v-if="activeTab === 'hits'" :icon="Connection" :disabled="!controlSession.token" @click="runMatch">重新执行命中分析</el-button>
        <el-button v-else type="primary" :icon="TrendCharts" @click="calculate">重新计算风险基线</el-button>
      </div>
    </header>

    <DeviceControlToken />

    <el-alert v-if="loadError" type="error" :closable="false" show-icon><template #title>风险数据加载失败</template><template #default>{{ loadError }}<el-button text type="primary" @click="load">重试</el-button></template></el-alert>

    <section class="metric-strip compact-metrics">
      <article><span>风险对象</span><strong>{{ rows.length }}</strong></article>
      <article class="metric-danger"><span>严重</span><strong>{{ count('Critical') }}</strong></article>
      <article class="metric-warning"><span>高危</span><strong>{{ count('High') }}</strong></article>
      <article><span>候选匹配</span><strong>{{ affectedMatches.length }}</strong></article>
      <article><span>待人工审核</span><strong>{{ auditCount }}</strong></article>
    </section>

    <section class="operation-section risk-workspace">
      <el-tabs v-model="activeTab" class="workspace-tabs" @tab-change="syncTab">
        <el-tab-pane label="风险队列" name="queue">
          <div class="filter-bar">
            <el-input v-model="search" clearable placeholder="搜索 CVE、资产或软件包" aria-label="搜索风险" />
            <el-select v-model="severity" clearable placeholder="风险等级"><el-option v-for="level in ['Critical','High','Medium','Low']" :key="level" :label="riskLevelText(level)" :value="level" /></el-select>
            <el-select v-model="runtimeFilter" clearable placeholder="运行状态"><el-option label="已验证" value="verified" /><el-option label="上下文关联" value="contextual" /><el-option label="未观察到" value="not_observed" /><el-option label="等待证据" value="waiting" /></el-select>
            <el-select v-model="auditFilter" clearable placeholder="研判状态"><el-option label="待人工审核" value="pending" /><el-option label="已形成结论" value="completed" /><el-option label="候选待研判" value="candidate" /></el-select>
            <span class="filter-result">显示 {{ filteredRows.length }} / {{ rows.length }} 条</span>
          </div>
          <DataTable :rows="filteredRows" :height="620" row-key="object_id" :default-sort="{ prop: 'display_score', order: 'descending' }" @row-dblclick="openRiskDetail">
            <el-table-column prop="cve_id" label="CVE" min-width="205" sortable><template #default="{ row }"><strong class="mono cve-link">{{ row.cve_id }}</strong><small class="cell-sub">{{ row.package_name }}</small></template></el-table-column>
            <el-table-column prop="hostname" label="资产" min-width="170" sortable />
            <el-table-column prop="display_level" label="风险等级" width="96" sortable><template #default="{ row }"><span class="status-label" :class="'is-' + lvlClass(row.display_level)">{{ riskLevelText(row.display_level) }}</span></template></el-table-column>
            <el-table-column prop="cvss_score" label="CVSS" width="82" sortable><template #default="{ row }"><span class="mono">{{ cvssText(row.cvss_score) }}</span></template></el-table-column>
            <el-table-column prop="epss_probability" label="EPSS" width="86" sortable><template #default="{ row }">{{ probabilityText(row.epss_probability) }}</template></el-table-column>
            <el-table-column prop="kev_score" label="KEV" width="68"><template #default="{ row }"><span :class="row.kev_score > 0 ? 'text-danger' : 'muted'">{{ row.kev_score > 0 ? '是' : '否' }}</span></template></el-table-column>
            <el-table-column label="Ubuntu 状态" min-width="118"><template #default="{ row }">{{ affectedStatusText(row.affected_status) }}</template></el-table-column>
            <el-table-column prop="runtime_status" label="运行状态" min-width="112"><template #default="{ row }">{{ runtimeStatusText(row.runtime_status) }}</template></el-table-column>
            <el-table-column label="研判状态" min-width="130"><template #default="{ row }"><span class="status-label" :class="auditClass(row)">{{ auditLabel(row) }}</span></template></el-table-column>
            <el-table-column label="操作" width="118" fixed="right"><template #default="{ row }"><el-button text type="primary" @click="openRiskDetail(row)">风险详情</el-button></template></el-table-column>
          </DataTable>
        </el-tab-pane>

        <el-tab-pane label="漏洞命中" name="hits">
          <div class="filter-bar"><el-input v-model="hitSearch" clearable placeholder="搜索 CVE、资产或软件包" /><el-switch v-model="affectedOnly" active-text="仅真实命中" inactive-text="全部结果" /><span class="filter-result">显示 {{ filteredMatches.length }} / {{ matches.length }} 条</span></div>
          <DataTable :rows="filteredMatches" :height="620" row-key="id">
            <el-table-column prop="cve_id" label="CVE" min-width="210"><template #default="{ row }"><strong class="mono">{{ row.cve_id }}</strong></template></el-table-column>
            <el-table-column prop="hostname" label="资产" min-width="170" />
            <el-table-column label="Ubuntu release" width="125"><template #default="{ row }">{{ releaseOf(row.cve_id) }}</template></el-table-column>
            <el-table-column prop="package_name" label="软件包" width="120" />
            <el-table-column prop="installed_version" label="Installed version" min-width="190"><template #default="{ row }"><span class="mono">{{ row.installed_version || '-' }}</span></template></el-table-column>
            <el-table-column prop="fixed_version" label="Fixed version" min-width="190"><template #default="{ row }"><span class="mono">{{ row.fixed_version || '未发布' }}</span></template></el-table-column>
            <el-table-column label="Canonical 状态" min-width="150"><template #default="{ row }">{{ canonicalStatus(row) }}</template></el-table-column>
            <el-table-column label="资产命中" width="105"><template #default="{ row }"><span class="status-label" :class="row.affected ? 'is-h' : 'is-l'">{{ row.affected ? '真实命中' : '未命中' }}</span></template></el-table-column>
            <el-table-column prop="confidence" label="置信度" width="90"><template #default="{ row }">{{ probabilityText(row.confidence) }}</template></el-table-column>
          </DataTable>
        </el-tab-pane>

        <el-tab-pane label="风险详情" name="detail">
          <template v-if="selectedRisk">
            <div class="risk-detail-head"><div><span class="section-kicker">RISK EXPLANATION</span><h2>{{ selectedRisk.cve_id }}</h2><p>{{ selectedRisk.hostname }} · {{ selectedRisk.package_name }}</p></div><div class="header-actions"><el-button @click="openFullEvidence(selectedRisk)">查看完整证据链</el-button><el-button type="primary" @click="openReview(selectedRisk)">进入风险研判</el-button></div></div>
            <div class="risk-decision-band"><div><span>最终风险</span><strong>{{ riskLevelText(selectedRisk.has_final_conclusion ? selectedRisk.risk_level : selectedRisk.preliminary_level) }}</strong></div><div><span>风险分</span><strong class="mono">{{ formatScore(selectedRisk.has_final_conclusion ? selectedRisk.final_score : selectedRisk.preliminary_score) }}</strong></div><div><span>置信度</span><strong>{{ probabilityText(selectedRisk.review_confidence || selectedRisk.decision_confidence) }}</strong></div><div><span>处置方向</span><strong>{{ decisionLabel(selectedRisk.recommended_action || selectedRisk.preliminary_decision) }}</strong></div></div>
            <div class="risk-detail-grid">
              <article class="risk-driver-panel"><header><h3>风险来源分解</h3><p>风险结果由技术严重度、适用性、暴露面和运行状态共同形成。</p></header><table class="data-table"><thead><tr><th>风险维度</th><th>当前状态</th><th>量化值</th><th>解释</th></tr></thead><tbody><tr v-for="driver in riskDrivers" :key="driver.label"><td><strong>{{ driver.label }}</strong></td><td>{{ driver.status }}</td><td class="mono">{{ driver.value }}</td><td>{{ driver.explanation }}</td></tr></tbody></table></article>
              <aside class="risk-evidence-panel"><h3>裁决摘要</h3><dl class="status-list"><div><dt>Ubuntu 适用性</dt><dd>{{ affectedStatusText(selectedRisk.affected_status) }}</dd></div><div><dt>服务可达性</dt><dd>{{ reachableStatusText(selectedRisk.reachable_status) }}</dd></div><div><dt>运行时验证</dt><dd>{{ runtimeStatusText(selectedRisk.runtime_status) }}</dd></div><div><dt>审计状态</dt><dd>{{ auditLabel(selectedRisk) }}</dd></div></dl><p>{{ selectedRisk.review_reason || selectedRisk.preliminary_reason || selectedRisk.decision_reason || '暂无裁决说明。' }}</p></aside>
            </div>
          </template>
          <div v-else class="empty-panel">请从“风险队列”选择一条风险记录进入详情。</div>
        </el-tab-pane>
      </el-tabs>
    </section>
  </section>
</template>

<script setup>
import { Connection, TrendCharts } from "@element-plus/icons-vue";
import { ElMessage } from "element-plus";
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import DataTable from "../components/DataTable.vue";
import { calculateRisk, fetchBehaviorChains, fetchMatches, fetchRiskRanking, runMatching } from "../api";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import { controlSession, errorMessage } from "../api/deviceOperations";

const route = useRoute();
const router = useRouter();
const loading = ref(false);
const loadError = ref("");
const rows = ref([]);
const matches = ref([]);
const chains = ref([]);
const activeTab = ref(["queue", "hits", "detail"].includes(String(route.query.tab)) ? String(route.query.tab) : "queue");
const selectedRiskId = ref(Number(route.query.risk_id) || null);
const search = ref("");
const severity = ref("");
const runtimeFilter = ref("");
const auditFilter = ref("");
const hitSearch = ref("");
const affectedOnly = ref(true);

const selectedRisk = computed(() => rows.value.find((row) => Number(row.risk_id || row.id) === Number(selectedRiskId.value)) || null);
const filteredRows = computed(() => rows.value.filter((row) => {
  const needle = search.value.trim().toLowerCase();
  const textMatch = !needle || [row.cve_id, row.hostname, row.package_name].some((value) => String(value || "").toLowerCase().includes(needle));
  const levelMatch = !severity.value || row.display_level === severity.value;
  const runtimeMatch = !runtimeFilter.value || row.runtime_status === runtimeFilter.value;
  const group = row.human_review_required || row.review_status === "pending_human_review" ? "pending" : row.has_final_conclusion ? "completed" : "candidate";
  return textMatch && levelMatch && runtimeMatch && (!auditFilter.value || group === auditFilter.value);
}));
const affectedMatches = computed(() => matches.value.filter((row) => row.affected));
const filteredMatches = computed(() => matches.value.filter((row) => {
  const needle = hitSearch.value.trim().toLowerCase();
  const textMatch = !needle || [row.cve_id, row.hostname, row.package_name].some((value) => String(value || "").toLowerCase().includes(needle));
  return textMatch && (!affectedOnly.value || row.affected);
}));
const auditCount = computed(() => rows.value.filter((row) => row.human_review_required || row.review_status === "pending_human_review").length);
const riskDrivers = computed(() => {
  const row = selectedRisk.value;
  if (!row) return [];
  return [
    { label: "技术严重度", status: `CVSS ${cvssText(row.cvss_score)}`, value: score100(row.cvss_score), explanation: "来自 NVD/Canonical 的漏洞技术影响，不代表资产一定受影响。" },
    { label: "利用可能性", status: `EPSS ${probabilityText(row.epss_probability)}`, value: (Number(row.epss_probability || 0) * 100).toFixed(1), explanation: "FIRST 对未来利用概率的估计。" },
    { label: "已知在野利用", status: Number(row.kev_score || 0) > 0 ? "CISA KEV 命中" : "未列入 KEV", value: Number(row.kev_score || 0).toFixed(0), explanation: "CISA 已知在野利用目录信号。" },
    { label: "Ubuntu 资产适用性", status: affectedStatusText(row.affected_status), value: scoreText(row.patch_score), explanation: "Canonical 状态与当前安装版本的适用性判断。" },
    { label: "服务暴露", status: reachableStatusText(row.reachable_status), value: scoreText(row.exposure_score), explanation: `${row.exposed_service_count || 0} 个关联暴露服务，${row.path_count || 0} 条可达路径。` },
    { label: "运行状态", status: runtimeStatusText(row.runtime_status), value: scoreText(row.runtime_score), explanation: "来自 eBPF/Falco 或运行时探针的上下文证据。" },
    { label: "资产重要度", status: row.business_score >= 80 ? "核心资产" : "一般资产", value: scoreText(row.business_score), explanation: "资产业务重要度对处置优先级的影响。" },
    { label: "最终风险", status: riskLevelText(row.has_final_conclusion ? row.risk_level : row.preliminary_level), value: formatScore(row.has_final_conclusion ? row.final_score : row.preliminary_score), explanation: "确定性风险引擎、专业研判与审计门禁的综合结果。" }
  ];
});

async function load() {
  loading.value = true; loadError.value = "";
  try {
    const [riskData, matchData, chainData] = await Promise.all([fetchRiskRanking(), fetchMatches(), fetchBehaviorChains().catch(() => [])]);
    rows.value = (riskData || []).map((row) => ({
      ...row,
      display_level: row.has_final_conclusion ? row.risk_level : row.preliminary_level,
      display_score: row.has_final_conclusion ? row.final_score : row.preliminary_score,
      epss_probability: Number(row.risk_factors?.exploit_likelihood?.probability ?? (Number(row.epss_score || 0) / 100))
    }));
    matches.value = matchData || [];
    chains.value = chainData || [];
    if (!selectedRiskId.value && activeTab.value === "detail") selectedRiskId.value = rows.value[0]?.risk_id || rows.value[0]?.id || null;
  }
  catch (error) { loadError.value = error?.response?.data?.detail || error?.message || "无法加载风险数据"; }
  finally { loading.value = false; }
}
async function calculate() { const result = await calculateRisk(); ElMessage.success(`风险计算完成：${result.count} 条`); await load(); }
async function runMatch() { try { const result = await runMatching(); ElMessage.success(`候选分析完成：${result.count} 条；不代表漏洞确认`); await load(); } catch (error) { loadError.value = errorMessage(error); } }
function syncTab(name) { router.replace({ path: "/risk", query: { ...(selectedRiskId.value ? { risk_id: selectedRiskId.value } : {}), tab: name } }); }
function openRiskDetail(row) { selectedRiskId.value = row.risk_id || row.id; activeTab.value = "detail"; syncTab("detail"); }
function openReview(row) { router.push({ path: "/workflow", query: { risk_id: row.risk_id || row.id } }); }
function openFullEvidence(row) { const chain = chains.value.find((item) => item.intelligence?.cve_id === row.cve_id && item.asset?.hostname === row.hostname); if (chain) router.push({ path: "/behavior-chain/detail", query: { chain_id: chain.chain_id } }); else ElMessage.warning("当前风险对象尚未形成完整行为链"); }

const count = (level) => rows.value.filter((row) => row.display_level === level).length;
const lvlClass = (level) => ({ Critical: "c", High: "h", Medium: "m", Low: "l" }[level] || "l");
const riskLevelText = (level) => ({ Critical: "严重", High: "高危", Medium: "中危", Low: "低危" }[level] || level || "未知");
const cvssText = (value) => { const n = Number(value || 0); return (n > 10 ? n / 10 : n).toFixed(1); };
const score100 = (value) => { const n = Number(value || 0); return (n <= 10 ? n * 10 : n).toFixed(0); };
const scoreText = (value) => Number.isFinite(Number(value)) ? Number(value).toFixed(0) : "-";
const probabilityText = (value) => `${(Number(value || 0) * (Number(value || 0) <= 1 ? 100 : 1)).toFixed(1)}%`;
const formatScore = (value) => Number.isFinite(Number(value)) ? Number(value).toFixed(2) : "待计算";
const affectedStatusText = (status) => ({ potentially_affected: "版本命中", version_match: "版本命中", insufficient_data: "证据不足", unknown: "待补证", fixed: "已修复", not_affected: "未受影响" }[status] || status || "未知");
const runtimeStatusText = (status) => ({ verified: "已验证", contextual: "上下文关联", not_observed: "未观察到", waiting: "等待证据" }[status] || status || "未知");
const reachableStatusText = (status) => ({ internet_exposed: "公网可达", internal_reachable: "内部可达", linked: "内部可达", local_only: "仅本机", none: "仅包级命中", unreachable: "不可达" }[status] || status || "未知");
const auditLabel = (row) => row.human_review_required || row.review_status === "pending_human_review" ? "待人工审核" : row.has_final_conclusion ? "已形成结论" : "候选待研判";
const auditClass = (row) => row.human_review_required || row.review_status === "pending_human_review" ? "is-h" : row.has_final_conclusion ? "is-l" : "is-info";
const decisionLabel = (value) => ({ immediate_fix: "立即修复", scheduled_fix: "排期修复", collect_more_evidence: "继续补证", monitor: "持续观察", defer: "暂缓处理" }[value] || value || "待裁决");
const releaseOf = (cveId) => (cveId || "").split(":")[1] || "-";
const canonicalStatus = (row) => ({ installed_version_below_fixed: "已发布修复版本", canonical_under_investigation: "Canonical 调查中", canonical_not_affected: "未受影响" }[row.reason_code] || row.match_status || "未知");

watch(() => route.query.risk_id, (value) => { if (value) selectedRiskId.value = Number(value); });
onMounted(load);
</script>

<style scoped>
.risk-workspace { padding-top: 5px; }.workspace-tabs :deep(.el-tabs__header) { margin: 0 0 14px; }.workspace-tabs :deep(.el-tabs__nav-wrap::after) { height: 1px; background: var(--soc-border-soft); }.workspace-tabs :deep(.el-tabs__item) { height: 42px; color: var(--soc-text-secondary); }.workspace-tabs :deep(.el-tabs__item.is-active) { color: #dfe9f5; }
.risk-detail-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; padding: 4px 0 14px; border-bottom: 1px solid var(--soc-border); }.risk-detail-head h2 { margin: 4px 0; color: #edf2f7; font: 650 20px Consolas, monospace; }.risk-detail-head p { margin: 0; color: var(--soc-text-muted); }
.risk-decision-band { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 14px 0; border: 1px solid var(--soc-border-soft); }.risk-decision-band > div { padding: 11px 13px; border-right: 1px solid var(--soc-border-soft); }.risk-decision-band > div:last-child { border-right: 0; }.risk-decision-band span { display: block; color: var(--soc-text-muted); font-size: 10px; }.risk-decision-band strong { display: block; margin-top: 4px; color: #e4eaf1; }
.risk-detail-grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(300px, .65fr); gap: 16px; }.risk-driver-panel, .risk-evidence-panel { border: 1px solid var(--soc-border-soft); background: var(--soc-surface-muted); }.risk-driver-panel header, .risk-evidence-panel { padding: 14px; }.risk-driver-panel header h3, .risk-evidence-panel h3 { margin: 0; color: #e7edf4; font-size: 14px; }.risk-driver-panel header p, .risk-evidence-panel p { margin: 4px 0 0; color: var(--soc-text-muted); font-size: 11px; line-height: 1.6; }.risk-evidence-panel p { padding-top: 12px; border-top: 1px solid var(--soc-border-soft); color: var(--soc-text-secondary); }
@media (max-width: 1180px) { .risk-detail-grid { grid-template-columns: 1fr; } }
@media (max-width: 800px) { .risk-decision-band { grid-template-columns: repeat(2, 1fr); }.risk-detail-head { align-items: stretch; flex-direction: column; } }
</style>
