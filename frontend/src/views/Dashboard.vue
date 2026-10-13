<template>
  <section class="dashboard-page" v-loading="loading">
    <header class="page-header">
      <div>
        <span class="section-kicker">SECURITY OVERVIEW</span>
        <h1>Linux 漏洞风险态势</h1>
        <p>聚焦当前风险、待办事项和真实任务状态；详细证据进入对应工作台处理。</p>
      </div>
      <div class="header-actions">
        <el-button :icon="Setting" :disabled="!controlSession.token" @click="openTargetDialog">接入配置</el-button>
        <el-button type="primary" :icon="VideoPlay" :loading="collecting" :disabled="!controlSession.token" @click="demoStart">执行全流程任务</el-button>
      </div>
    </header>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon>
      <template #title>安全态势加载失败</template>
      <template #default><span>{{ loadError }}</span><el-button text type="primary" @click="loadDashboard">重试</el-button></template>
    </el-alert>

    <section class="metric-strip" aria-label="关键安全指标">
      <article><span>纳管资产</span><strong>{{ summary.asset_count ?? 0 }}</strong><small>{{ targetSummary }}</small></article>
      <article><span>有效漏洞</span><strong>{{ summary.total_vulnerabilities ?? 0 }}</strong><small>已入库漏洞情报</small></article>
      <article class="metric-danger"><span>高风险</span><strong>{{ summary.high_risk_vulnerabilities ?? 0 }}</strong><small>严重与高危对象</small></article>
      <article class="metric-warning"><span>CISA KEV</span><strong>{{ summary.kev_vulnerabilities ?? 0 }}</strong><small>已知在野利用</small></article>
      <article><span>待研判</span><strong>{{ pendingReviewCount }}</strong><small>候选与人工审核</small></article>
      <article><span>待处置</span><strong>{{ summary.pending_remediation_tasks ?? 0 }}</strong><small>{{ summary.blocked_remediation_tasks ?? 0 }} 条受阻</small></article>
    </section>

    <section class="overview-grid">
      <article class="operation-section priority-section">
        <div class="section-head">
          <div><h2>优先处置风险</h2><p>当前风险队列 Top {{ topRisks.length }}</p></div>
          <el-button text type="primary" @click="router.push('/risk')">进入风险中心</el-button>
        </div>
        <div class="table-scroll">
          <table class="data-table top-table">
            <thead><tr><th>优先级</th><th>CVE</th><th>资产</th><th>软件包</th><th>风险分</th><th>研判状态</th></tr></thead>
            <tbody>
              <tr v-for="(row, index) in topRisks" :key="row.object_id || row.cve_id + index" @click="openRisk(row)">
                <td class="mono">P{{ index + 1 }}</td>
                <td><strong class="mono cve-link">{{ row.cve_id }}</strong></td>
                <td>{{ row.hostname || '-' }}</td>
                <td>{{ row.package_name || packageNameOf(row.cve_id) }}</td>
                <td class="mono">{{ formatScore(row.has_final_conclusion ? row.final_score : row.preliminary_score ?? row.score) }}</td>
                <td><span class="status-label" :class="auditClass(row)">{{ auditLabel(row) }}</span></td>
              </tr>
              <tr v-if="!topRisks.length"><td colspan="6" class="empty-cell">暂无风险对象，请先完成资产采集和风险评估。</td></tr>
            </tbody>
          </table>
        </div>
      </article>

      <aside class="overview-side">
        <article class="operation-section chart-section">
          <div class="section-head"><div><h2>风险等级分布</h2><p>{{ totalRiskCount }} 条资产级风险</p></div></div>
          <div v-if="totalRiskCount" class="chart-row"><div ref="riskEl" class="ring-chart"></div><div class="legend-list"><div v-for="item in riskRows" :key="item.name" class="legend-row"><span class="legend-name"><i :style="{ background: item.color }"></i>{{ riskLevelText(item.name) }}</span><b>{{ item.value }}</b></div></div></div>
          <div v-else class="empty-inline">暂无风险分布数据。</div>
        </article>

        <article class="operation-section task-section">
          <div class="section-head"><div><h2>当前研判任务</h2><p>真实批次状态与人工审计门禁</p></div><el-button text type="primary" @click="router.push('/workflow')">查看任务</el-button></div>
          <template v-if="collecting">
            <div class="task-progress"><span>全流程任务</span><b>{{ progressPct }}%</b></div>
            <div class="progress-bar"><i :style="{ width: progressPct + '%' }"></i></div>
            <p class="task-message">{{ demoState.currentStep || '正在启动任务' }}</p>
          </template>
          <dl v-else class="status-list">
            <div><dt>批次状态</dt><dd>{{ statusText(analysis?.status) }}</dd></div>
            <div><dt>当前对象</dt><dd class="mono">{{ analysis?.current_object_id || '-' }}</dd></div>
            <div><dt>处理进度</dt><dd>{{ analysis?.processed_object_count || 0 }} / {{ analysis?.selected_object_count || 0 }}</dd></div>
            <div><dt>人工审核</dt><dd :class="pendingReviewCount ? 'text-danger' : 'text-ok'">{{ pendingReviewCount }} 条</dd></div>
          </dl>
        </article>
      </aside>
    </section>

    <section class="secondary-grid dashboard-secondary">
      <article class="operation-section trend-section">
        <div class="section-head"><div><h2>风险对象趋势</h2><p>基于真实实验归档快照，不补造历史数据</p></div><span class="muted">最近 {{ trendRows.length }} 个归档批次</span></div>
        <div v-if="trendRows.length" ref="trendEl" class="trend-chart"></div>
        <div v-else class="empty-inline">暂无可用于趋势分析的历史归档。</div>
      </article>

      <article class="operation-section event-section">
        <div class="section-head"><div><h2>最近系统事件</h2><p>运行时证据流中的最新记录</p></div><el-button text type="primary" @click="router.push('/runtime')">查看全部</el-button></div>
        <div class="event-list">
          <article v-for="event in recentEvents" :key="event.id || event.timestamp + event.rule">
            <time>{{ formatTime(event.timestamp) }}</time>
            <div><strong>{{ event.rule || categoryLabel(event.category) }}</strong><small>{{ event.hostname || '-' }} · {{ event.process_name || event.source || '-' }}</small></div>
            <span class="status-label" :class="Number(event.severity_score || 0) >= 70 ? 'is-h' : 'is-info'">{{ event.severity || event.severity_score || '信息' }}</span>
          </article>
          <div v-if="!recentEvents.length" class="empty-inline">暂无运行时系统事件。</div>
        </div>
      </article>
    </section>

    <DeviceControlToken />
    <el-dialog v-model="targetDialogVisible" title="配置接入目标" width="min(980px, 92vw)">
      <div class="dialog-toolbar">
        <div><strong>采集与验证目标</strong><p>支持 SSH Linux 主机和本地 Docker 容器。</p></div>
        <div class="dialog-actions"><el-button :icon="Plus" @click="addSshTarget">新增 SSH 目标</el-button><el-button :icon="Box" @click="addContainerTarget">新增容器目标</el-button></div>
      </div>
      <div class="target-list">
        <div v-for="(target, index) in editableTargets" :key="index" class="target-card">
          <div class="target-card-head"><div class="target-card-title"><el-input v-model="target.label" placeholder="目标名称" /><el-tag size="small" effect="plain">{{ target.target_type === 'ssh' ? 'SSH 主机' : 'Docker 容器' }}</el-tag></div><div class="target-card-actions"><el-switch v-model="target.enabled" /><el-button text type="danger" :icon="Delete" @click="removeTarget(index)">删除</el-button></div></div>
          <div class="target-grid">
            <template v-if="target.target_type === 'ssh'">
              <el-input v-model="target.host" placeholder="连接地址"><template #prepend>Host</template></el-input>
              <el-input-number v-model="target.ssh_port" :min="1" :max="65535" controls-position="right" />
              <el-input v-model="target.username" placeholder="SSH 用户名"><template #prepend>User</template></el-input>
              <el-input v-model="target.password" type="password" show-password :placeholder="target.password_configured ? '已配置；留空保留，输入则替换' : 'SSH 或 sudo 密码'"><template #prepend>Password</template></el-input>
              <el-input v-model="target.asset_hostname" placeholder="可选：资产主机名覆盖值"><template #prepend>Asset</template></el-input>
              <label class="checkbox-row"><input v-model="target.install_falco_if_missing" type="checkbox" /><span>缺少 Falco 时自动安装</span></label>
            </template>
            <template v-else>
              <el-input v-model="target.container_name" placeholder="本机 Docker 容器名"><template #prepend>Container</template></el-input>
              <el-input v-model="target.asset_hostname" placeholder="可选：资产主机名覆盖值"><template #prepend>Asset</template></el-input>
            </template>
          </div>
          <div class="target-options"><label class="checkbox-row"><input v-model="target.collect_asset" type="checkbox" /><span>采集资产</span></label><label class="checkbox-row"><input v-model="target.collect_runtime" type="checkbox" /><span>采集运行时证据</span></label></div>
          <el-input v-model="target.notes" type="textarea" :rows="2" placeholder="业务用途、网络条件等备注" />
        </div>
      </div>
      <template #footer><el-button @click="targetDialogVisible = false">取消</el-button><el-button type="primary" :loading="savingTargets" @click="saveTargets">保存目标配置</el-button></template>
    </el-dialog>
  </section>
</template>

<script setup>
import * as echarts from "echarts";
import { Box, Delete, Plus, Setting, VideoPlay } from "@element-plus/icons-vue";
import { ElMessage } from "element-plus";
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import { controlSession } from "../api/controlSession";
import { fetchDemoTargets, fetchEbpfEvents, fetchLatestAnalysis, fetchReportArchives, fetchRiskRanking, fetchSummary, updateDemoTargets } from "../api";
import { demoState, onComplete, progressPct, startCollection } from "../stores/demoProgress";

const router = useRouter();
const loading = ref(false);
const loadError = ref("");
const summary = ref({});
const ranking = ref([]);
const analysis = ref(null);
const recentEvents = ref([]);
const archives = ref([]);
const targets = ref([]);
const editableTargets = ref([]);
const targetDialogVisible = ref(false);
const savingTargets = ref(false);
const riskEl = ref(null);
const trendEl = ref(null);
let riskChart = null;
let trendChart = null;
let offComplete = null;

const RISK_COLOR = { Critical: "#e05252", High: "#d5843f", Medium: "#d5ad45", Low: "#4da878" };
const RISK_ORDER = ["Critical", "High", "Medium", "Low"];
const collecting = computed(() => demoState.running);
const enabledTargets = computed(() => targets.value.filter((target) => target.enabled));
const targetSummary = computed(() => enabledTargets.value.length ? `${enabledTargets.value.length} 个启用目标` : "尚未配置目标");
const pendingReviewCount = computed(() => ranking.value.filter((row) => row.human_review_required || ["candidate", "pending_human_review", "human_review"].includes(row.review_status)).length);
const topRisks = computed(() => (ranking.value.length ? ranking.value : (summary.value.top_vulnerabilities || [])).slice(0, 8));
const totalRiskCount = computed(() => Object.values(summary.value.risk_level_distribution || {}).reduce((sum, value) => sum + Number(value || 0), 0));
const riskRows = computed(() => RISK_ORDER.map((name) => ({ name, value: Number(summary.value.risk_level_distribution?.[name] || 0), color: RISK_COLOR[name] })).filter((row) => row.value));
const trendRows = computed(() => archives.value.filter((item) => Number.isFinite(Number(item.summary?.risks))).slice(0, 10).reverse().map((item) => ({ time: formatShortTime(item.archived_at), value: Number(item.summary?.risks || 0) })));

const packageNameOf = (cveId) => (cveId || "").split(":").at(-1) || "-";
const riskLevelText = (level) => ({ Critical: "严重", High: "高危", Medium: "中危", Low: "低危" }[level] || level);
const formatScore = (value) => Number.isFinite(Number(value)) ? Number(value).toFixed(2) : "-";
const formatTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "未知";
const formatShortTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "未知";
const categoryLabel = (name) => ({ process_execution: "进程执行", network_activity: "网络活动", sensitive_file_access: "敏感文件访问", privilege_activity: "权限活动", package_or_service_change: "软件包/服务变更" }[name] || name || "运行时事件");
const auditLabel = (row) => row.human_review_required || row.review_status === "pending_human_review" ? "待人工审核" : row.has_final_conclusion ? "已形成结论" : "待研判";
const auditClass = (row) => row.human_review_required || row.review_status === "pending_human_review" ? "is-h" : row.has_final_conclusion ? "is-l" : "is-info";
const statusText = (status) => ({ completed: "已完成", partial: "部分完成", running: "执行中", human_review: "待人工审核", failed: "执行失败", no_candidates: "无候选对象" }[status] || status || "未执行");
const openRisk = (row) => router.push({ path: "/risk", query: { risk_id: row.risk_id || row.id, tab: "detail" } });

function cloneTarget(target) { return { ...JSON.parse(JSON.stringify(target)), password: "" }; }
function defaultTarget(type) { return { label: type === "ssh" ? "新建 SSH 目标" : "新建容器目标", target_type: type, enabled: true, host: "", ssh_port: 22, username: "", password: "", asset_hostname: "", container_name: "", install_falco_if_missing: false, collect_asset: true, collect_runtime: true, notes: "" }; }
async function loadTargets() { const response = await fetchDemoTargets(); targets.value = response.targets || []; }
async function openTargetDialog() { try { await loadTargets(); editableTargets.value = targets.value.map(cloneTarget); if (!editableTargets.value.length) editableTargets.value = [defaultTarget("ssh")]; targetDialogVisible.value = true; } catch (error) { ElMessage.error(error?.response?.data?.detail || "无法读取历史目标配置"); } }
function addSshTarget() { editableTargets.value.push(defaultTarget("ssh")); }
function addContainerTarget() { editableTargets.value.push(defaultTarget("container")); }
function removeTarget(index) { editableTargets.value.splice(index, 1); }
async function saveTargets() {
  savingTargets.value = true;
  try {
    const payload = editableTargets.value.map((target) => { const item = { ...target }; delete item.password_configured; return item; });
    const response = await updateDemoTargets(payload);
    targets.value = response.targets || [];
    targetDialogVisible.value = false;
    ElMessage.success("接入目标已保存");
  } catch (error) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "接入目标保存失败");
  } finally { savingTargets.value = false; }
}

async function demoStart() {
  try { await loadTargets(); if (!enabledTargets.value.length) { ElMessage.warning("请先配置至少一个启用中的接入目标"); await openTargetDialog(); return; } await startCollection(); } catch (error) { ElMessage.error(error?.response?.data?.detail || error?.message || "启动全流程任务失败"); }
}

async function loadDashboard() {
  loading.value = true;
  loadError.value = "";
  try {
    const [summaryData, riskData, analysisData, eventData, archiveData] = await Promise.all([
      fetchSummary(), fetchRiskRanking().catch(() => []), fetchLatestAnalysis().catch(() => null), fetchEbpfEvents({ limit: 6 }).catch(() => ({ events: [] })), fetchReportArchives().catch(() => ({ archives: [] }))
    ]);
    summary.value = summaryData || {};
    ranking.value = riskData || [];
    analysis.value = analysisData?.status === "none" ? null : analysisData;
    recentEvents.value = eventData.events || [];
    archives.value = archiveData.archives || [];
    await nextTick();
    renderCharts();
  } catch (error) {
    loadError.value = error?.response?.data?.detail || error?.message || "无法连接后端服务";
  } finally { loading.value = false; }
}

function renderCharts() {
  if (riskEl.value) {
    riskChart ||= echarts.init(riskEl.value);
    riskChart.setOption({ tooltip: { trigger: "item" }, series: [{ type: "pie", radius: ["58%", "82%"], center: ["50%", "50%"], label: { show: false }, data: riskRows.value.map((row) => ({ name: riskLevelText(row.name), value: row.value, itemStyle: { color: row.color } })) }] }, true);
  }
  if (trendEl.value && trendRows.value.length) {
    trendChart ||= echarts.init(trendEl.value);
    trendChart.setOption({ grid: { left: 34, right: 16, top: 16, bottom: 34 }, tooltip: { trigger: "axis" }, xAxis: { type: "category", data: trendRows.value.map((row) => row.time), axisLabel: { color: "#718094", fontSize: 10 }, axisLine: { lineStyle: { color: "#283544" } } }, yAxis: { type: "value", minInterval: 1, axisLabel: { color: "#718094" }, splitLine: { lineStyle: { color: "#202b38" } } }, series: [{ type: "line", data: trendRows.value.map((row) => row.value), symbol: "circle", symbolSize: 6, lineStyle: { color: "#4f8fe8", width: 2 }, itemStyle: { color: "#8ab4ea" }, areaStyle: { color: "rgba(79,143,232,.08)" } }] }, true);
  }
}
function onResize() { riskChart?.resize(); trendChart?.resize(); }
async function handleComplete() { await loadDashboard(); ElMessage.success("全流程任务已结束，安全态势已刷新"); }

onMounted(async () => { window.addEventListener("resize", onResize); offComplete = onComplete(handleComplete); await loadDashboard(); });
onBeforeUnmount(() => { window.removeEventListener("resize", onResize); riskChart?.dispose(); trendChart?.dispose(); offComplete?.(); });
</script>

<style scoped>
.dashboard-page { display: grid; gap: 16px; }
.priority-section tbody tr { cursor: pointer; }
.dashboard-secondary { grid-template-columns: minmax(0, 1.15fr) minmax(420px, .85fr); }
.trend-chart { width: 100%; height: 250px; }
.task-progress { display: flex; align-items: center; justify-content: space-between; color: var(--soc-text-secondary); }.task-progress b { color: var(--soc-text); font: 600 18px Consolas, monospace; }
.progress-bar { height: 6px; margin: 10px 0; overflow: hidden; border-radius: 2px; background: var(--soc-border-soft); }.progress-bar i { display: block; height: 100%; background: var(--soc-info); }
.task-message { margin: 0; color: var(--soc-text-secondary); font-size: 12px; }
.event-list { display: grid; }.event-list > article { display: grid; grid-template-columns: 108px minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--soc-border-soft); }.event-list time { color: var(--soc-text-muted); font: 10px Consolas, monospace; }.event-list strong, .event-list small { display: block; }.event-list strong { color: #dce4ed; font-size: 12px; }.event-list small { margin-top: 3px; color: var(--soc-text-muted); font-size: 10px; }
.dialog-toolbar, .target-card-head, .target-card-title, .target-card-actions, .target-options, .dialog-actions { display: flex; align-items: center; gap: 10px; }.dialog-toolbar, .target-card-head { justify-content: space-between; }.dialog-toolbar { align-items: flex-start; margin-bottom: 14px; }.dialog-toolbar p { margin: 4px 0 0; color: var(--soc-text-muted); }.target-list { display: grid; gap: 12px; max-height: 62vh; overflow: auto; }.target-card { padding: 14px; border: 1px solid var(--soc-border); border-radius: 3px; background: var(--soc-surface-muted); }.target-card-title { min-width: 0; flex: 1; }.target-card-title .el-input { max-width: 340px; }.target-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 12px 0; }.checkbox-row { display: inline-flex; align-items: center; gap: 7px; color: var(--soc-text-secondary); }
@media (max-width: 1180px) { .dashboard-secondary { grid-template-columns: 1fr; } }
@media (max-width: 760px) { .target-grid { grid-template-columns: 1fr; }.dialog-toolbar, .target-card-head { align-items: stretch; flex-direction: column; } }
</style>
