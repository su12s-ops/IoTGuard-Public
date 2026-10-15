<template>
  <section class="page review-page" v-loading="loading">
    <header class="page-header">
      <div><span class="eyebrow">RISK ADJUDICATION</span><h1>风险研判</h1><p>基于统一证据包完成专业分析、冲突复议、最终裁决与审计检查。</p></div>
      <div class="header-actions"><el-button :icon="Refresh" @click="load">刷新</el-button><el-button type="primary" :icon="VideoPlay" :loading="running" :disabled="!canStart" @click="startReview">{{ runButtonText }}</el-button></div>
    </header>

    <el-alert v-if="loadError" :title="loadError" type="error" show-icon :closable="false" />
    <el-alert v-else-if="!events.length" title="当前没有可研判的风险对象" description="请先完成资产采集、情报同步、漏洞命中与风险计算。" type="info" show-icon :closable="false" />
    <DeviceControlToken />

    <section class="operation-section">
      <div class="section-head">
        <div><h2>研判阶段</h2><p>显示后端真实 progress_percent、current_object_id 与 progress_message。</p></div>
        <el-select v-if="events.length" v-model="activeRiskId" aria-label="选择风险对象" class="object-select">
          <el-option v-for="row in events" :key="row.risk_id" :value="row.risk_id" :label="`${row.hostname} / ${row.cve_id} / ${row.package_name}`" />
        </el-select>
      </div>
      <div class="stage-track six-stage" aria-label="研判阶段进度">
        <div v-for="(step, index) in steps" :key="step.key" class="stage-node" :class="{ active: index === stageIndex, done: index < stageIndex }">
          <span>{{ index + 1 }}</span><strong>{{ step.label }}</strong><small>{{ index < stageIndex ? "已完成" : index === stageIndex ? (running ? "执行中" : "当前") : "待执行" }}</small>
        </div>
      </div>
      <div class="current-stage">
        <div><span>当前对象</span><strong class="mono">{{ currentObject }}</strong><p>{{ progressMessage }}</p></div>
        <div class="stage-meta"><b>{{ progressPercent }}%</b><small>{{ reviewStatusLabel(review?.status) }}</small></div>
      </div>
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>专业分析</h2><p>运营名称用于阅读，技术名称保留用于审计与故障定位。</p></div><span class="connection-state" :class="status.configured ? 'online' : 'offline'"><i></i>{{ status.configured ? `${status.model || "模型"} 已连接` : "研判服务未配置" }}</span></div>
      <div class="table-scroll"><table class="data-table analyst-table"><thead><tr><th>分析角色</th><th>状态</th><th>核心结论</th><th>置信度</th><th>时间</th></tr></thead><tbody>
        <tr v-for="row in analystRows" :key="row.id"><td><strong>{{ row.role }}</strong><small class="cell-sub mono">{{ row.id }}</small></td><td><span class="status-label" :class="row.statusClass">{{ row.status }}</span></td><td class="conclusion-cell">{{ row.conclusion }}</td><td class="mono">{{ row.confidence }}</td><td class="mono cell-time">{{ row.time }}</td></tr>
        <tr v-if="!analystRows.length"><td colspan="5" class="empty-cell">尚未产生专业分析记录</td></tr>
      </tbody></table></div>
    </section>

    <section class="adjudication-grid">
      <article class="operation-section"><div class="section-head"><div><h2>冲突复议</h2><p>仅展示真实冲突和缺失证据。</p></div><span class="status-label" :class="conflicts.length ? 'is-high' : 'approved'">{{ conflicts.length ? `${conflicts.length} 项待处理` : "无冲突" }}</span></div>
        <div class="timeline-list"><article v-for="(item, index) in conflicts" :key="index"><time>复议 {{ index + 1 }}</time><p>{{ item }}</p></article><div v-if="!conflicts.length" class="empty-inline">当前对象没有冲突或证据缺口记录。</div></div>
      </article>
      <article class="operation-section"><div class="section-head"><div><h2>最终裁决</h2><p>Coordinator 输出与确定性结果。</p></div></div>
        <dl class="decision-list"><div><dt>研判状态</dt><dd>{{ reviewStatusLabel(activeEvent?.review_status || review?.status) }}</dd></div><div><dt>风险方向</dt><dd>{{ activeEvent?.risk_direction || activeEvent?.review_verdict || "待裁决" }}</dd></div><div><dt>最终风险</dt><dd>{{ activeEvent?.has_final_conclusion ? `${activeEvent.risk_level} / ${activeEvent.final_score}` : "待审计确认" }}</dd></div><div><dt>处置建议</dt><dd>{{ activeEvent?.recommended_action || activeEvent?.preliminary_decision || "待生成" }}</dd></div></dl>
        <p class="decision-reason">{{ activeEvent?.review_reason || review?.answer || review?.error || "暂无最终裁决。" }}</p>
      </article>
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>审计检查</h2><p>Audit Policy 与人工审核共同构成处置门禁。</p></div><span class="status-label" :class="activeEvent?.human_review_required ? 'is-high' : 'approved'">{{ activeEvent?.human_review_required ? "需人工审核" : "策略已检查" }}</span></div>
      <ul class="audit-list"><li v-for="reason in activeEvent?.audit_policy_reasons || []" :key="reason"><span>策略命中</span><code>{{ reason }}</code></li><li v-if="!(activeEvent?.audit_policy_reasons || []).length"><span>检查结果</span><code>未返回策略命中记录</code></li></ul>
      <div v-if="activeEvent?.review_status === 'pending_human_review'" class="human-review-actions"><span>该对象需由人工逐条确认，专业分析结论不构成修复授权。</span><el-button type="success" :loading="humanReviewLoading" @click="submitHuman('confirm')">人工确认</el-button><el-button type="danger" plain :loading="humanReviewLoading" @click="submitHuman('reject')">驳回</el-button></div>
    </section>
  </section>
</template>

<script setup>
import { Refresh, VideoPlay } from "@element-plus/icons-vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute } from "vue-router";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import { createReviewRun, fetchAnalysisStatus, fetchLatestAnalysis, fetchPreflight, fetchReviewRun, fetchRiskRanking, fetchWorkflowOverview, reviewRiskEvent } from "../api";

const route = useRoute();
const loading = ref(false); const running = ref(false); const humanReviewLoading = ref(false); const loadError = ref("");
const status = ref({ configured: false }); const review = ref(null); const overview = ref({ agents: [] }); const events = ref([]); const activeRiskId = ref(null); const preflight = ref({});
let pollTimer = null;
const terminalStatuses = new Set(["completed", "partial", "human_review", "failed", "skipped", "interrupted", "legacy_failed", "no_candidates"]);
const steps = [
  { key: "evidence", label: "证据准备" }, { key: "analysis", label: "专业分析" }, { key: "conflict", label: "冲突复议" },
  { key: "decision", label: "最终裁决" }, { key: "audit", label: "审计检查" }, { key: "done", label: "完成" }
];
const stageMap = { candidate_preflight: 0, evidence_preparing: 0, prepare: 0, agent_reviewing: 1, investigate_asset: 1, analyze_vulnerability: 1, analyze_runtime: 1, evidence_audit_agent: 1, impact_assessment_agent: 1, exposure_runtime_agent: 1, conflict_review: 2, directed_rereview: 2, coordinator_review: 3, decide: 3, execute_follow_ups: 3, decision_coordinator_agent: 3, audit_policy: 4, finalize: 4, completed: 5 };
const roleNames = { evidence_audit_agent: "数据质量分析", impact_assessment_agent: "漏洞影响分析", exposure_runtime_agent: "运行时归因", decision_coordinator_agent: "最终裁决", asset_investigator: "资产与证据调查", vulnerability_analyst: "漏洞适用性分析", runtime_analyst: "运行时行为分析", decision_planner: "综合研判与处置规划" };
const activeEvent = computed(() => events.value.find((row) => Number(row.risk_id) === Number(activeRiskId.value)) || events.value[0] || null);
const stageIndex = computed(() => {
  if (running.value) return stageMap[review.value?.current_stage] ?? 0;
  const s = activeEvent.value?.review_status || review.value?.status;
  if (["auto_confirmed", "human_confirmed", "remediation_ready", "resolved", "completed"].includes(s)) return 5;
  if (["pending_human_review", "human_review", "human_reviewing"].includes(s)) return 4;
  if (activeEvent.value?.agent_results?.decision_coordinator_agent) return 4;
  return 0;
});
const progressPercent = computed(() => running.value ? Math.round(Number(review.value?.progress_percent || 0)) : Math.round((stageIndex.value / (steps.length - 1)) * 100));
const currentObject = computed(() => review.value?.current_object_id || activeEvent.value?.object_id || activeEvent.value?.cve_id || "未选择");
const progressMessage = computed(() => review.value?.progress_message || (activeEvent.value ? `${activeEvent.value.hostname} · ${activeEvent.value.cve_id} · ${activeEvent.value.package_name}` : "等待风险对象"));
const canStart = computed(() => status.value.configured && !running.value && Number(preflight.value.selected_object_count || events.value.length) > 0);
const runButtonText = computed(() => running.value ? "研判进行中" : ["failed", "partial", "interrupted"].includes(review.value?.status) ? "重试未完成对象" : "启动风险研判");
const conflicts = computed(() => [...(activeEvent.value?.review_conflicts || []), ...(activeEvent.value?.review_missing_evidence || []).map((x) => `证据缺口：${x}`)]);
const resultFor = (id) => activeEvent.value?.agent_results?.[id] || review.value?.agent_executions?.[id] || {};
const analystRows = computed(() => {
  const source = overview.value.agents?.length ? overview.value.agents : Object.keys(roleNames).map((id) => ({ id }));
  return source.map((agent) => {
    const result = resultFor(agent.id); const rawStatus = result.status || agent.status || "pending";
    return { id: agent.id, role: roleNames[agent.id] || agent.name || agent.id, status: ({ completed: "已完成", complete: "已完成", partial: "部分完成", running: "执行中", failed: "失败", pending: "待执行" }[rawStatus] || rawStatus), statusClass: ["completed", "complete"].includes(rawStatus) ? "approved" : rawStatus === "partial" ? "is-medium" : rawStatus === "failed" ? "is-high" : "is-info", conclusion: result.output || result.conclusion || result.reason || agent.output || "尚未产生意见", confidence: result.confidence !== undefined ? `${Math.round(Number(result.confidence) <= 1 ? Number(result.confidence) * 100 : Number(result.confidence))}%` : (agent.confidence ? `${agent.confidence}%` : "—"), time: formatTime(result.completed_at || result.updated_at || result.timestamp) };
  });
});
const formatTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
const reviewStatusLabel = (value) => ({ running: "执行中", completed: "已完成", partial: "部分完成", human_review: "待人工审核", pending_human_review: "待人工审核", failed: "失败", no_candidates: "无候选对象", candidate: "待研判", auto_confirmed: "自动确认", human_confirmed: "人工确认" }[value] || value || "未执行");

const load = async () => {
  loading.value = true; loadError.value = "";
  try {
    const [statusData, latestData, riskRows, overviewData, preflightData] = await Promise.all([fetchAnalysisStatus().catch(() => ({ configured: false })), fetchLatestAnalysis().catch(() => null), fetchRiskRanking(), fetchWorkflowOverview().catch(() => ({ agents: [] })), fetchPreflight().catch(() => ({}))]);
    status.value = statusData || {}; review.value = latestData?.status === "none" ? null : latestData; overview.value = overviewData || { agents: [] }; preflight.value = preflightData || {};
    events.value = (riskRows || []).filter((row) => !["inactive", "resolved"].includes(row.review_status)).map((row) => ({ ...row, risk_id: row.risk_id || row.id, object_id: row.object_id || `risk-${row.risk_id || row.id}` }));
    const requested = Number(Array.isArray(route.query.risk_id) ? route.query.risk_id[0] : route.query.risk_id);
    if (!events.value.some((row) => Number(row.risk_id) === Number(activeRiskId.value))) activeRiskId.value = events.value.find((row) => Number(row.risk_id) === requested)?.risk_id || events.value[0]?.risk_id || null;
    const runId = latestData?.review_run_id || latestData?.run_id;
    if (latestData?.status === "running" && runId) poll(runId, false);
  } catch (error) { loadError.value = error?.response?.data?.detail || error?.message || "研判数据加载失败"; }
  finally { loading.value = false; }
};
const poll = async (runId, announce = true) => {
  running.value = true; clearTimeout(pollTimer);
  try {
    const data = await fetchReviewRun(runId); review.value = data;
    if (terminalStatuses.has(data.status)) { running.value = false; if (announce) ElMessage.success(`研判任务已结束：${reviewStatusLabel(data.status)}`); await load(); return; }
    pollTimer = setTimeout(() => poll(runId, announce), 1500);
  } catch (error) { running.value = false; ElMessage.error(error?.response?.data?.detail || error?.message || "研判进度读取失败"); }
};
const startReview = async () => {
  try { const retry = ["failed", "partial", "interrupted"].includes(review.value?.status); const accepted = await createReviewRun(retry); const runId = accepted.review_run_id || accepted.run_id || accepted.id; review.value = accepted; if (!runId) throw new Error("任务未返回 run_id"); poll(runId); }
  catch (error) { running.value = false; ElMessage.error(error?.response?.data?.detail || error?.message || "风险研判启动失败"); }
};
const submitHuman = async (decision) => {
  if (!activeEvent.value) return;
  try { const reason = await ElMessageBox.prompt(decision === "confirm" ? "请输入人工确认依据" : "请输入驳回原因", decision === "confirm" ? "人工确认" : "人工驳回", { inputType: "textarea", confirmButtonText: "提交", cancelButtonText: "取消" }); humanReviewLoading.value = true; await reviewRiskEvent(activeEvent.value.risk_id, decision, reason.value); ElMessage.success("人工审核结果已记录"); await load(); }
  catch (error) { if (error !== "cancel" && error !== "close") ElMessage.error(error?.response?.data?.detail || error?.message || "人工审核提交失败"); }
  finally { humanReviewLoading.value = false; }
};
onMounted(load); onUnmounted(() => clearTimeout(pollTimer));
</script>

<style scoped>
.object-select { width: min(460px, 48vw); }.six-stage { grid-template-columns: repeat(6, minmax(0, 1fr)); }.cell-time { color: var(--soc-text-muted); font-size: 10px; }.empty-inline { padding: 18px 0; color: var(--soc-text-muted); }.human-review-actions { display: flex; align-items: center; gap: 10px; margin-top: 14px; padding: 12px; border: 1px solid #654b31; background: #241d16; }.human-review-actions span { flex: 1; color: #d8bd9c; font-size: 11px; }
@media (max-width: 1180px) { .six-stage { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 760px) { .object-select { width: 100%; }.six-stage { grid-template-columns: 1fr; } }
</style>
