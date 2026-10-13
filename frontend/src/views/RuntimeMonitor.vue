<template>
  <section class="page runtime-page" v-loading="loading">
    <header class="page-header"><div><span class="eyebrow">RUNTIME VERIFICATION</span><h1>运行时验证</h1><p>验证静态漏洞命中后，相关服务、进程与端口在当前资产上的实际运行状态。</p></div><div class="header-actions"><el-button :icon="Refresh" @click="load">刷新</el-button></div></header>
    <el-alert v-if="loadError" :title="loadError" type="error" show-icon :closable="false" />
    <DeviceControlToken />

    <section class="metric-strip compact-metrics">
      <article><span>运行时事件</span><strong>{{ summary.total || 0 }}</strong></article><article class="metric-danger"><span>高价值证据</span><strong>{{ summary.high_value_count || 0 }}</strong></article><article><span>关联资产</span><strong>{{ status.matched_asset_count || 0 }}</strong></article><article><span>内核传感器事件</span><strong>{{ (summary.observation_mode_counts?.ebpf || 0) + (summary.observation_mode_counts?.sensor || 0) }}</strong></article><article><span>资产覆盖率</span><strong>{{ status.matched_asset_ratio || 0 }}%</strong></article>
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>资产验证结果</h2><p>资产、进程、服务、端口与证据强度的汇总视图。</p></div><span class="mono">最新事件 {{ formatTime(status.latest_event_at) }}</span></div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>资产</th><th>IP / OS</th><th>事件</th><th>采集模式</th><th>进程 / 软件包</th><th>服务 / 端口</th><th>证据强度</th></tr></thead><tbody>
        <tr v-for="row in correlations" :key="row.asset.id"><td><strong>{{ row.asset.hostname }}</strong></td><td class="mono">{{ row.asset.ip_address }}<small class="cell-sub">{{ row.asset.os }}</small></td><td class="mono">{{ row.event_count }}</td><td>{{ modeSummary(row) }}</td><td>{{ row.matched_packages?.slice(0, 4).join(" / ") || "—" }}</td><td>{{ row.matched_services?.slice(0, 4).join(" / ") || "—" }}</td><td><span class="status-label" :class="row.evidence_score >= 60 ? 'approved' : 'is-info'">{{ row.evidence_score }}</span></td></tr>
        <tr v-if="!correlations.length"><td colspan="7" class="empty-cell">暂无资产运行时关联</td></tr>
      </tbody></table></div>
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>CVE 行为链与风险影响</h2><p>运行时证据只调整风险判断，不等同于漏洞已被利用。</p></div><span>{{ verifiedCount }} 已验证 · {{ waitingCount }} 待补证</span></div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>CVE</th><th>资产</th><th>软件包</th><th>运行状态</th><th>证据强度</th><th>风险影响</th><th>验证结论</th></tr></thead><tbody>
        <tr v-for="chain in behaviorChains" :key="chain.chain_id"><td class="mono cve-cell">{{ chain.intelligence?.cve_id }}</td><td>{{ chain.asset?.hostname }}</td><td>{{ chain.package?.name }}<small class="cell-sub mono">{{ chain.package?.installed_version }}</small></td><td><span class="status-label" :class="runtimeClass(chain.runtime_verification?.status)">{{ runtimeLabel(chain.runtime_verification?.status) }}</span></td><td class="mono">{{ chain.runtime_verification?.strength ?? "—" }}</td><td>{{ riskImpact(chain) }}</td><td>{{ chain.runtime_verification?.conclusion || "尚未形成运行时结论" }}</td></tr>
        <tr v-if="!behaviorChains.length"><td colspan="7" class="empty-cell">暂无可关联的 CVE 行为链</td></tr>
      </tbody></table></div>
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>证据明细</h2><p>可按资产、类别、采集模式与强度筛选原始事件。</p></div><span class="filter-result">{{ events.length }} 条</span></div>
      <div class="filter-bar"><el-select v-model="filters.hostname" placeholder="资产" clearable><el-option v-for="host in status.available_hosts || []" :key="host" :label="host" :value="host" /></el-select><el-select v-model="filters.category" placeholder="证据类别" clearable><el-option v-for="category in status.available_categories || []" :key="category" :label="categoryLabel(category)" :value="category" /></el-select><el-select v-model="filters.mode" placeholder="采集模式" clearable><el-option label="Tetragon 来源" value="ebpf" /><el-option label="Falco 来源（驱动待核验）" value="sensor" /><el-option label="运行探针" value="probe" /></el-select><el-input-number v-model="filters.severityMin" :min="0" :max="100" controls-position="right" /><el-button type="primary" @click="load">应用筛选</el-button></div>
      <DataTable :rows="events" max-height="480" @row-click="selectEvent">
        <el-table-column label="时间" min-width="180"><template #default="{ row }"><span class="mono cell-time">{{ formatTime(row.timestamp) }}</span></template></el-table-column>
        <el-table-column prop="hostname" label="资产" min-width="160" /><el-table-column label="模式" width="105"><template #default="{ row }"><span class="status-label is-info">{{ observationLabel(row.source) }}</span></template></el-table-column>
        <el-table-column label="类别" min-width="130"><template #default="{ row }">{{ categoryLabel(row.category) }}</template></el-table-column><el-table-column prop="rule" label="规则" min-width="200" show-overflow-tooltip />
        <el-table-column label="进程 / 端口" min-width="170"><template #default="{ row }"><strong>{{ row.process_name || "—" }}</strong><small class="cell-sub">{{ row.port ? `${row.destination || ""}:${row.port}` : row.parent_process }}</small></template></el-table-column>
        <el-table-column label="命令 / 目标" min-width="300" show-overflow-tooltip><template #default="{ row }"><code>{{ row.commandline || row.destination || row.file_path || "—" }}</code></template></el-table-column>
        <el-table-column prop="severity_score" label="强度" width="80" align="right" />
      </DataTable>
      <el-empty v-if="!loading && !events.length" description="当前筛选条件下没有运行时证据" />
    </section>

    <section class="runtime-bottom-grid">
      <article class="operation-section"><div class="section-head"><div><h2>原始证据</h2><p>保留事件原始字段与命令输出。</p></div></div><pre class="evidence-terminal">{{ rawEvidence }}</pre></article>
      <article class="operation-section"><div class="section-head"><div><h2>采集控制</h2><p>上传真实 Falco/Tetragon 事件，或生成明确标注的测试证据。</p></div></div>
        <input ref="fileInput" class="hidden-input" type="file" accept=".json,.jsonl,.log,.txt" @change="onFileSelected" />
        <div class="toolbar"><el-button :icon="UploadFilled" @click="fileInput?.click()">选择事件文件</el-button><el-button type="primary" :disabled="!selectedFile" :loading="actionLoading.upload" @click="uploadSelected">上传证据</el-button><el-button :icon="MagicStick" :loading="actionLoading.demo" @click="generateTestEvidence">生成测试证据</el-button><el-button type="danger" plain :icon="Delete" :loading="actionLoading.clear" @click="clearAll">清空事件</el-button></div>
        <p class="file-note">{{ selectedFile ? `已选择：${selectedFile.name}` : "测试证据会以 probe 模式入库，不会标记为真实 eBPF。" }}</p><pre class="collector-command">{{ status.collector_command || collectorCommand }}</pre><ul class="diagnostic-list"><li v-for="item in status.recommendations || []" :key="item">{{ item }}</li></ul>
      </article>
    </section>
    <RuntimeEvidencePanel />
  </section>
</template>

<script setup>
import { ElMessage, ElMessageBox } from "element-plus";
import { Delete, MagicStick, Refresh, UploadFilled } from "@element-plus/icons-vue";
import { computed, onMounted, reactive, ref } from "vue";
import DataTable from "../components/DataTable.vue";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import RuntimeEvidencePanel from "../components/RuntimeEvidencePanel.vue";
import { API_BASE, clearEbpfEvents, fetchBehaviorChains, fetchEbpfCorrelations, fetchEbpfEvents, fetchEbpfStatus, fetchEbpfSummary, generateEbpfDemo, uploadEbpfEvents } from "../api";

const loading = ref(false); const loadError = ref(""); const summary = ref({}); const status = ref({}); const events = ref([]); const correlations = ref([]); const behaviorChains = ref([]); const selectedEvent = ref(null); const selectedFile = ref(null); const fileInput = ref(null);
const actionLoading = reactive({ upload: false, demo: false, clear: false }); const filters = reactive({ hostname: "", category: "", mode: "", severityMin: 0, limit: 100 });
const categoryMap = { sensitive_file_access: "敏感文件访问", privilege_activity: "权限活动", network_activity: "网络连接", process_execution: "进程执行", package_or_service_change: "服务或软件包变更", runtime_observation: "运行时观测" };
const collectorCommand = `chmod +x collector/run_falco_capture.sh\n./collector/run_falco_capture.sh ${API_BASE} 60`;
const verifiedCount = computed(() => behaviorChains.value.filter((x) => x.runtime_verification?.status === "verified").length);
const waitingCount = computed(() => behaviorChains.value.filter((x) => ["waiting", "not_observed"].includes(x.runtime_verification?.status)).length);
const rawEvidence = computed(() => selectedEvent.value ? JSON.stringify(selectedEvent.value, null, 2) : events.value.length ? events.value.slice(0, 8).map((event) => JSON.stringify(event, null, 2)).join("\n\n") : "# 暂无原始运行时证据\n# 请上传 Falco / Tetragon 事件或执行采集任务。" );
const formatTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
const categoryLabel = (name) => categoryMap[name] || name || "未知";
const observationLabel = (source) => { const value = String(source || "").toLowerCase(); if (value.includes("falco") || value.includes("tetragon") || value === "syscall") return "真实 eBPF"; if (value.startsWith("runtime_probe_")) return "运行探针"; return "运行时"; };
const runtimeLabel = (value) => ({ verified: "组件活动已关联", contextual: "上下文关联", waiting: "等待证据", not_observed: "未观测" }[value] || "未知");
const runtimeClass = (value) => value === "verified" ? "approved" : value === "contextual" ? "is-info" : "is-muted";
const riskImpact = (chain) => { const delta = Number(chain.risk?.adjustment?.runtime || 0); return delta ? `风险调整 +${delta}` : "未调整风险"; };
const modeSummary = (row) => { const ebpf = Number((row.observation_modes?.ebpf || 0) + (row.observation_modes?.sensor || 0)); const probe = Number(row.observation_modes?.probe || 0); return `${ebpf ? `传感器 ${ebpf}` : "无内核传感器事件"}${probe ? ` / 探针 ${probe}` : ""}`; };
const selectEvent = (row) => { selectedEvent.value = row; };
const load = async () => { loading.value = true; loadError.value = ""; try { const params = { limit: filters.limit, hostname: filters.hostname || undefined, category: filters.category || undefined, mode: filters.mode || undefined, severity_min: filters.severityMin || undefined }; const [s, m, e, c, b] = await Promise.all([fetchEbpfStatus(), fetchEbpfSummary(), fetchEbpfEvents(params), fetchEbpfCorrelations(), fetchBehaviorChains().catch(() => [])]); status.value = s || {}; summary.value = m || {}; events.value = e.events || []; correlations.value = c || []; behaviorChains.value = b || []; selectedEvent.value = null; } catch (error) { loadError.value = error?.response?.data?.detail || error?.message || "运行时数据加载失败"; } finally { loading.value = false; } };
const onFileSelected = (event) => { selectedFile.value = event.target.files?.[0] || null; };
const uploadSelected = async () => { if (!selectedFile.value) return; actionLoading.upload = true; try { const result = await uploadEbpfEvents(selectedFile.value); ElMessage.success(`已入库 ${result.count || 0} 条运行时事件`); selectedFile.value = null; if (fileInput.value) fileInput.value.value = ""; await load(); } catch (error) { ElMessage.error(error?.response?.data?.detail || error?.message || "事件上传失败"); } finally { actionLoading.upload = false; } };
const generateTestEvidence = async () => { actionLoading.demo = true; try { const result = await generateEbpfDemo({ per_asset: 4 }); ElMessage.success(`已生成 ${result.count || 0} 条测试证据`); await load(); } catch (error) { ElMessage.error(error?.response?.data?.detail || error?.message || "测试证据生成失败"); } finally { actionLoading.demo = false; } };
const clearAll = async () => { try { await ElMessageBox.confirm("确认清空当前运行时事件吗？此操作会删除已入库证据。", "清空事件", { type: "warning" }); actionLoading.clear = true; const result = await clearEbpfEvents(); ElMessage.success(`已清空 ${result.count || 0} 条事件`); await load(); } catch (error) { if (error !== "cancel" && error !== "close") ElMessage.error(error?.response?.data?.detail || error?.message || "清空失败"); } finally { actionLoading.clear = false; } };
onMounted(load);
</script>

<style scoped>
.cell-time { color: var(--soc-text-muted); font-size: 10px; }.hidden-input { display: none; }.file-note { margin: 10px 0; color: var(--soc-text-muted); font-size: 11px; }.evidence-terminal { min-height: 360px; }.collector-command { max-height: 160px; overflow: auto; }.runtime-page code { color: #b6c8dc; font-family: Consolas, monospace; }
</style>
