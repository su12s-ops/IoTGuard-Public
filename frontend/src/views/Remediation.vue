<template>
  <section class="page remediation-page" v-loading="loading">
    <header class="page-header"><div><span class="eyebrow">REMEDIATION OPERATIONS</span><h1>修复处置</h1><p>以可执行任务管理风险对象、修复方案、执行状态与验证结果。</p></div><div class="header-actions"><el-button @click="goReview">前往人工审核<span v-if="pendingReviewCount">（{{ pendingReviewCount }}）</span></el-button><el-button type="primary" :icon="Tools" :loading="generating" :disabled="!eligibleCount" @click="generate">{{ rows.length ? '刷新处置方案' : '生成处置方案' }}</el-button></div></header>
    <el-alert v-if="loadError" :title="loadError" type="error" show-icon :closable="false" />
    <section class="metric-strip compact-metrics"><article><span>建议执行</span><strong>{{ suggestedCount }}</strong></article><article class="metric-warning"><span>前置受阻</span><strong>{{ count("blocked") }}</strong></article><article><span>执行中</span><strong>{{ count("in_progress") }}</strong></article><article><span>已执行待验证</span><strong>{{ count("fixed") }}</strong></article><article><span>已验证</span><strong>{{ count("verified") }}</strong></article></section>

    <section class="operation-section">
      <div class="section-head"><div><h2>处置任务</h2><p>“建议执行”只表示方案已生成；仅 fixed / verified 表示资产侧已经执行。</p></div><span class="status-note"><i></i>状态变更将写回任务记录</span></div>
      <DataTable v-if="rows.length" :rows="rows" row-key="id" class="remediation-table">
        <el-table-column type="expand"><template #default="{ row }"><div class="remediation-detail">
          <dl class="decision-list"><div><dt>修复方式</dt><dd>{{ fixType(row) }}</dd></div><div><dt>影响范围</dt><dd>{{ row.hostname }} / {{ row.package_name }}</dd></div><div><dt>当前版本</dt><dd class="mono">{{ row.current_version || "待复采确认" }}</dd></div><div><dt>目标版本</dt><dd class="mono">{{ row.target_version || "暂无厂商修复版本" }}</dd></div><div><dt>修复前风险</dt><dd>{{ beforeRisk(row) }}</dd></div><div><dt>预计风险变化</dt><dd>{{ expectedChange(row) }}</dd></div><div><dt>验证结果</dt><dd>{{ verificationResult(row) }}</dd></div><div><dt>前置条件</dt><dd>{{ row.mitigation || "无额外前置条件" }}</dd></div></dl>
          <div class="command-block"><header><span>修复命令</span><el-button text :icon="CopyDocument" @click="copy(row.remediation_command)">复制</el-button></header><pre>$ {{ row.remediation_command || fallbackCommand(row) }}</pre></div>
          <div class="command-block verify-command"><header><span>验证命令</span><el-button text :icon="CopyDocument" @click="copy(row.verification_command || verifyCommand(row))">复制</el-button></header><pre>$ {{ row.verification_command || verifyCommand(row) }}</pre></div>
        </div></template></el-table-column>
        <el-table-column label="风险对象" min-width="220" fixed="left"><template #default="{ row }"><strong class="mono">{{ row.cve_id }}</strong><small class="cell-sub">{{ row.hostname }}</small></template></el-table-column>
        <el-table-column label="风险" width="88"><template #default="{ row }"><span class="status-label" :class="riskClass(row.risk_level)">{{ row.risk_level || "—" }}</span></template></el-table-column>
        <el-table-column prop="package_name" label="软件包" min-width="135" /><el-table-column label="修复类型" width="120"><template #default="{ row }">{{ fixType(row) }}</template></el-table-column>
        <el-table-column label="目标版本" min-width="185"><template #default="{ row }"><span class="mono">{{ row.target_version || "暂无固定版本" }}</span></template></el-table-column>
        <el-table-column label="执行判定" width="125"><template #default="{ row }"><strong :class="['execution-state', isExecuted(row) ? 'executed' : 'suggested']">{{ isExecuted(row) ? "已经执行" : "建议执行" }}</strong></template></el-table-column>
        <el-table-column label="验证结果" min-width="145"><template #default="{ row }">{{ verificationResult(row) }}</template></el-table-column>
        <el-table-column label="当前状态" min-width="190" fixed="right"><template #default="{ row }"><span class="cell-status">{{ statusText(row.status) }}</span><el-button v-if="row.distribution === 'openwrt'" size="small" @click="router.push({ path: '/device-tasks', query: { asset: row.asset_id, risk: row.risk_id } })">前往设备任务</el-button><el-select v-else v-model="row.status" size="small" :loading="updatingId === row.id" :disabled="updatingId === row.id" @change="(value) => update(row, value)"><el-option label="待执行" value="pending" /><el-option label="受阻" value="blocked" /><el-option label="执行中" value="in_progress" /><el-option label="已执行待验证" value="fixed" /><el-option label="已验证" value="verified" /></el-select></template></el-table-column>
      </DataTable>
      <div v-if="!loading && !rows.length" class="remediation-empty">
        <h3>尚未生成处置任务</h3>
        <p>这不代表漏洞已经修复。风险对象必须先完成人工审核或通过审计门禁，随后才能生成可执行方案。</p>
        <dl><div><dt>待人工审核</dt><dd>{{ pendingReviewCount }} 条</dd></div><div><dt>当前可生成</dt><dd>{{ eligibleCount }} 条</dd></div><div><dt>已验证修复</dt><dd>0 条</dd></div></dl>
        <div class="empty-actions"><el-button @click="goReview">查看待审核对象</el-button><el-button type="primary" :loading="generating" :disabled="!eligibleCount" @click="generate">生成 {{ eligibleCount }} 条处置方案</el-button></div>
      </div>
    </section>
  </section>
</template>

<script setup>
import { ElMessage } from "element-plus";
import { CopyDocument, Tools } from "@element-plus/icons-vue";
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import DataTable from "../components/DataTable.vue";
import { fetchRemediationTasks, fetchRiskRanking, generateRemediation, updateTaskStatus } from "../api";

const router = useRouter();
const rows = ref([]); const risks = ref([]); const loading = ref(false); const generating = ref(false); const updatingId = ref(null); const loadError = ref("");
const authorizedStates = new Set(["completed", "auto_confirmed", "human_confirmed", "remediation_ready", "remediation_in_progress", "verification"]);
const versionCommands = { openssl: "openssl version", "openssh-server": "sshd -V", nginx: "nginx -v", bash: "bash --version", sudo: "sudo -V", curl: "curl --version", "redis-server": "redis-server --version", apache2: "apache2 -v", systemd: "systemctl --version" };
const count = (status) => rows.value.filter((row) => row.status === status).length;
const suggestedCount = computed(() => rows.value.filter((row) => !["fixed", "verified"].includes(row.status)).length);
const pendingReviewCount = computed(() => risks.value.filter((row) => row.human_review_required || ["candidate", "pending_human_review", "human_review", "human_reviewing"].includes(row.review_status)).length);
const eligibleCount = computed(() => risks.value.filter((row) => authorizedStates.has(row.review_status) && !row.human_review_required && !(row.review_status === "auto_confirmed" && ["High", "Critical"].includes(row.risk_level))).length);
const isExecuted = (row) => ["fixed", "verified"].includes(row.status);
const fixType = (row) => row.target_version ? "Root-Fixed" : "Surface-Fixed";
const riskFor = (row) => risks.value.find((risk) => (risk.cve_id === row.cve_id || String(risk.cve_id || "").startsWith(String(row.cve_id || "").split(":")[0])) && risk.hostname === row.hostname);
const beforeRisk = (row) => { const risk = riskFor(row); return risk ? `${risk.risk_level || risk.preliminary_level || "—"} / ${risk.final_score ?? risk.preliminary_score ?? "—"}` : (row.risk_level || "待复评"); };
const expectedChange = (row) => row.target_version ? "升级并复采验证后重新计算风险" : "先降低暴露面，根因风险仍需后续修复";
const verificationResult = (row) => row.status === "verified" ? "验证通过" : row.status === "fixed" ? "待复采验证" : "尚未执行";
const verifyCommand = (row) => row.distribution === "openwrt" ? "通过设备任务执行版本、漏洞回归和业务检查" : versionCommands[row.package_name] || `dpkg-query -W ${row.package_name}`;
const fallbackCommand = (row) => row.distribution === "openwrt" ? "通过设备任务安装已审批的适配软件包" : row.target_version ? `sudo apt update && sudo apt install ${row.package_name}=${row.target_version}` : `# 暂无固定版本，请执行缓解措施并持续跟踪 ${row.package_name}`;
const statusText = (value) => ({ pending: "待执行", blocked: "前置条件未满足", in_progress: "执行中", fixed: "已执行，待验证", verified: "已验证" }[value] || "待确认");
const riskClass = (value) => ({ Critical: "is-critical", High: "is-high", Medium: "is-medium", Low: "is-low" }[value] || "is-muted");
const load = async () => { loading.value = true; loadError.value = ""; try { const [taskRows, riskRows] = await Promise.all([fetchRemediationTasks(), fetchRiskRanking().catch(() => [])]); rows.value = taskRows || []; risks.value = riskRows || []; } catch (error) { loadError.value = error?.response?.data?.detail || error?.message || "处置任务加载失败"; } finally { loading.value = false; } };
const goReview = () => router.push({ path: "/workflow", query: { focus: "human_review" } });
const generate = async () => {
  generating.value = true;
  try {
    const result = await generateRemediation();
    const generated = Number(result.count || 0);
    if (generated) ElMessage.success(`已生成或更新 ${generated} 条处置任务`);
    else ElMessage.warning("当前没有通过审计门禁且可生成方案的风险对象");
    await load();
  } catch (error) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "处置方案生成失败");
  } finally { generating.value = false; }
};
const update = async (row, status) => {
  updatingId.value = row.id;
  try { await updateTaskStatus(row.id, status); ElMessage.success("任务状态已更新"); await load(); }
  catch (error) { ElMessage.error(error?.response?.data?.detail || error?.message || "状态更新失败，已恢复原状态"); await load(); }
  finally { updatingId.value = null; }
};
const copy = async (text) => { if (!text) return; try { await navigator.clipboard.writeText(text); ElMessage.success("命令已复制"); } catch { ElMessage.warning("复制失败，请手动选择"); } };
onMounted(load);
</script>

<style scoped>
.remediation-table :deep(.el-table__expanded-cell) { padding: 0 !important; }.execution-state { font-size: 11px; }.execution-state.suggested { color: #e1ad74; }.execution-state.executed { color: #79c39b; }.cell-status { display: block; margin-bottom: 5px; color: #cbd5df; font-size: 10px; }
.remediation-empty { display: grid; justify-items: center; gap: 10px; padding: 42px 20px; color: var(--soc-text-secondary); text-align: center; }.remediation-empty h3 { margin: 0; color: #e6ebf1; font-size: 16px; }.remediation-empty p { max-width: 720px; margin: 0; line-height: 1.7; }.remediation-empty dl { display: grid; grid-template-columns: repeat(3, minmax(120px, 1fr)); width: min(620px, 100%); margin: 6px 0 0; border: 1px solid var(--soc-border-soft); }.remediation-empty dl div { padding: 10px; border-right: 1px solid var(--soc-border-soft); }.remediation-empty dl div:last-child { border-right: 0; }.remediation-empty dt { font-size: 11px; }.remediation-empty dd { margin-top: 3px; color: #e1e7ee; font: 600 16px Consolas, monospace; }.empty-actions { display: flex; gap: 8px; margin-top: 4px; }
@media (max-width: 760px) { .remediation-empty dl { grid-template-columns: 1fr; }.remediation-empty dl div { border-right: 0; border-bottom: 1px solid var(--soc-border-soft); }.empty-actions { align-items: stretch; flex-direction: column; width: 100%; } }
</style>
