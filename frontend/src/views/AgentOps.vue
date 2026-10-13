<template>
  <section class="page upgrade-page" v-loading="loading">
    <header class="page-header">
      <div>
        <span class="eyebrow">AGENT OPERATIONS</span>
        <h1>智能体分析与修复工作流</h1>
        <p>四智能体按 DEVICE→VULNERABILITY→RUNTIME→RISK→REMEDIATION→VERIFY 编排分析；修复工作流记录真实的 Before / Action / After / Verification。</p>
      </div>
      <div class="header-actions"><el-button @click="load">刷新</el-button></div>
    </header>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" role="alert" />
    <DeviceControlToken />
    <el-tabs v-model="tab">
      <el-tab-pane label="四智能体分析" name="agents">
        <section class="operation-section">
          <div class="section-head">
            <div>
              <h2>发起编排分析</h2>
              <p class="operation-help">四个智能体各用专属工具读取真实数据（设备画像 / CVE·KEV·EPSS / eBPF 证据 / 白名单修复方案）；RISK 与 VERIFY 由程序确定性完成。</p>
            </div>
          </div>
          <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="startAnalysis">
            <el-form-item label="目标（二选一）">
              <el-select v-model="analysisForm.target" filterable allow-create placeholder="选择设备或输入主机名" style="width: 100%">
                <el-option v-for="d in devices" :key="d.device_id" :value="d.device_id" :label="`${d.device_name}（${d.device_id}）`" />
              </el-select>
            </el-form-item>
            <el-form-item label="目标类型">
              <el-radio-group v-model="analysisForm.targetType">
                <el-radio value="device">智能设备</el-radio>
                <el-radio value="host">Linux 主机</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="执行">
              <el-button type="primary" native-type="submit" :disabled="!canOperate || !analysisForm.target" :loading="starting">开始分析</el-button>
            </el-form-item>
          </el-form>
        </section>

        <section class="operation-section" v-if="agentRun">
          <div class="section-head">
            <div><h2>运行 {{ agentRun.run_id }}</h2><p>目标 {{ agentRun.target_ref }} · 状态 <el-tag size="small" :type="statusTag(agentRun.status)">{{ agentRun.status }}</el-tag></p></div>
            <el-button size="small" :loading="polling" @click="refreshAgentRun">轮询刷新</el-button>
          </div>
          <el-steps :active="stageActive" finish-status="success" align-center style="margin: 8px 0 14px">
            <el-step v-for="stage in stageOrder" :key="stage" :title="stage" :status="stepStatus(agentRun.stages[stage])" />
          </el-steps>
          <el-row :gutter="12">
            <el-col :span="12"><el-descriptions title="风险结论（程序聚合）" :column="1" border size="small">
              <el-descriptions-item label="优先级">{{ agentRun.risk.priority || '—' }}（{{ agentRun.risk.risk_score ?? '—' }} 分）</el-descriptions-item>
              <el-descriptions-item label="运行时等级">{{ agentRun.risk.runtime_level || '—' }}</el-descriptions-item>
              <el-descriptions-item label="依据">{{ agentRun.risk.rationale || '—' }}</el-descriptions-item>
            </el-descriptions></el-col>
            <el-col :span="12"><el-descriptions title="修复方案（白名单动作）" :column="1" border size="small">
              <el-descriptions-item v-for="(action, i) in agentRun.remediation.actions || []" :key="i" :label="action.action">
                {{ action.target }} — {{ action.rationale }}
              </el-descriptions-item>
              <el-descriptions-item v-if="!(agentRun.remediation.actions || []).length" label="动作">无</el-descriptions-item>
            </el-descriptions></el-col>
          </el-row>
          <h3 class="drawer-section-title">智能体执行明细（各自专属工具）</h3>
          <DataTable :rows="agentRows">
            <el-table-column prop="name" label="智能体" min-width="220" />
            <el-table-column label="状态" width="100"><template #default="{ row }">{{ row.status }}</template></el-table-column>
            <el-table-column label="工具调用" min-width="260"><template #default="{ row }">{{ (row.tool_calls || []).map(c => c.name).join('、') || '—' }}</template></el-table-column>
            <el-table-column prop="latency_ms" label="耗时(ms)" width="100" />
            <el-table-column label="错误" min-width="180"><template #default="{ row }">{{ row.error || '—' }}</template></el-table-column>
          </DataTable>
        </section>

        <section class="operation-section">
          <div class="section-head"><div><h2>历史运行</h2></div></div>
          <DataTable :rows="agentHistory">
            <el-table-column prop="run_id" label="运行" min-width="200" />
            <el-table-column prop="target_ref" label="目标" min-width="150" />
            <el-table-column label="状态" width="110"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
            <el-table-column prop="created_at" label="创建时间" min-width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
            <el-table-column label="操作" width="110"><template #default="{ row }"><el-button size="small" @click="viewAgentRun(row.run_id)">查看</el-button></template></el-table-column>
          </DataTable>
        </section>
      </el-tab-pane>

      <el-tab-pane label="修复工作流" name="workflow">
        <section class="operation-section">
          <div class="section-head">
            <div>
              <h2>MQTT 匿名接入修复</h2>
              <p class="operation-help">真实探测 MQTT 是否允许匿名连接；修复动作（备份/改配置/重启）由设备侧白名单执行器完成，平台复核后判定 RESOLVED / ROLLBACK。</p>
            </div>
          </div>
          <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="startWorkflow">
            <el-form-item label="MQTT 地址"><el-input v-model="workflowForm.host" aria-label="MQTT 地址" placeholder="目标 IP（须在后端允许网段内）" /></el-form-item>
            <el-form-item label="端口"><el-input-number v-model="workflowForm.port" :min="1" :max="65535" /></el-form-item>
            <el-form-item label="执行"><el-button type="primary" native-type="submit" :disabled="!canOperate" :loading="startingWorkflow">检测并创建</el-button></el-form-item>
          </el-form>
        </section>

        <section class="operation-section" v-if="workflow">
          <div class="section-head">
            <div><h2>工作流 {{ workflow.run_id }}</h2><p>目标 {{ workflow.target }} · 状态 <el-tag size="small" :type="statusTag(workflow.status)">{{ workflow.status }}</el-tag></p></div>
            <el-button size="small" @click="refreshWorkflow">刷新</el-button>
          </div>
          <el-timeline style="margin-top: 10px">
            <el-timeline-item timestamp="Before" type="warning">
              匿名连接：<strong>{{ workflow.before.anonymous_allowed ? '允许（漏洞存在，CONNACK rc=0）' : '已拒绝' }}</strong>
              <div class="cell-sub">证据 {{ workflow.evidence_id }}</div>
            </el-timeline-item>
            <el-timeline-item timestamp="Action" type="primary">
              <div v-for="(action, i) in workflow.actions" :key="i">{{ action.action }} → {{ action.result || action.target }}</div>
              <div v-if="!workflow.actions.length" class="cell-sub">未上报</div>
            </el-timeline-item>
            <el-timeline-item timestamp="After" type="info">
              <template v-if="workflow.verification.platform_recheck">
                匿名 rc={{ workflow.verification.platform_recheck.recheck?.anonymous?.return_code ?? '—' }}，
                认证 rc={{ workflow.verification.platform_recheck.recheck?.authenticated?.return_code ?? '—' }}
              </template>
              <span v-else class="cell-sub">等待上报</span>
            </el-timeline-item>
            <el-timeline-item timestamp="Verification" :type="workflow.status === 'RESOLVED' ? 'success' : workflow.status === 'ROLLBACK' ? 'warning' : 'info'">
              {{ workflow.status }}<div class="cell-sub" v-if="workflow.rollback.reason">回滚原因：{{ workflow.rollback.reason }}（恢复验证 {{ workflow.rollback.restored_ok }}）</div>
            </el-timeline-item>
          </el-timeline>
          <h3 class="drawer-section-title">实际执行命令</h3>
          <el-input type="textarea" :rows="Math.min(8, (workflow.commands || []).length || 1)" :model-value="(workflow.commands || []).join('\n')" readonly />
        </section>

        <section class="operation-section">
          <div class="section-head"><div><h2>历史工作流</h2></div></div>
          <DataTable :rows="workflowHistory">
            <el-table-column prop="run_id" label="工作流" min-width="200" />
            <el-table-column prop="target" label="目标" min-width="150" />
            <el-table-column label="状态" width="130"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
            <el-table-column prop="created_at" label="创建时间" min-width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
            <el-table-column label="操作" width="110"><template #default="{ row }"><el-button size="small" @click="viewWorkflow(row.run_id)">查看</el-button></template></el-table-column>
          </DataTable>
        </section>
      </el-tab-pane>
    </el-tabs>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import DataTable from "../components/DataTable.vue";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import {
  controlSession, errorMessage, fetchDevices,
  startAgentAnalysis, fetchAgentRuns, fetchAgentRun,
  startMqttWorkflow, fetchWorkflowRuns, fetchWorkflowRun
} from "../api/deviceOperations";

const tab = ref("agents");
const loading = ref(false);
const error = ref("");
const devices = ref([]);
const agentHistory = ref([]);
const workflowHistory = ref([]);
const agentRun = ref(null);
const workflow = ref(null);
const starting = ref(false);
const startingWorkflow = ref(false);
const polling = ref(false);
let timer = null;
const analysisForm = reactive({ target: "", targetType: "device" });
const workflowForm = reactive({ host: "", port: 1883 });
const canOperate = computed(() => Boolean(controlSession.token));
const stageOrder = ["DEVICE", "VULNERABILITY", "RUNTIME", "RISK", "REMEDIATION", "VERIFY"];
const agentRows = computed(() => Object.entries(agentRun.value?.agents || {}).map(([name, log]) => ({ name, ...log })));
const stageActive = computed(() => {
  const stages = agentRun.value?.stages || {};
  const done = stageOrder.filter(s => ["succeeded", "failed"].includes(stages[s]?.status)).length;
  return agentRun.value?.status === "completed" || agentRun.value?.status === "failed" ? stageOrder.length : done;
});

const statusTag = value => ({ completed: "success", RESOLVED: "success", succeeded: "success", failed: "danger", FAILED: "danger", ROLLBACK: "warning", running: "primary", REMEDIATING: "primary", VERIFYING: "primary", DETECTED: "info" }[value] || "info");
const stepStatus = entry => ({ succeeded: "success", failed: "error", running: "process", pending: "wait" }[entry?.status] || "wait");
const formatTime = value => value ? new Date(value).toLocaleString("zh-CN") : "—";

async function load() {
  loading.value = true; error.value = "";
  try {
    [devices.value, agentHistory.value, workflowHistory.value] = await Promise.all([fetchDevices(), fetchAgentRuns(), fetchWorkflowRuns()]);
  } catch (e) { error.value = errorMessage(e); } finally { loading.value = false; }
}

async function startAnalysis() {
  starting.value = true; error.value = "";
  try {
    const payload = analysisForm.targetType === "device"
      ? { device_id: analysisForm.target } : { hostname: analysisForm.target };
    const result = await startAgentAnalysis(payload);
    ElMessage.success("编排已启动：" + result.run_id);
    await viewAgentRun(result.run_id);
  } catch (e) { error.value = errorMessage(e); } finally { starting.value = false; }
}

async function viewAgentRun(runId) {
  agentRun.value = await fetchAgentRun(runId);
  if (agentRun.value.status === "running") startPolling();
}

function startPolling() {
  stopPolling();
  timer = window.setInterval(async () => {
    polling.value = true;
    try {
      agentRun.value = await fetchAgentRun(agentRun.value.run_id);
      if (agentRun.value.status !== "running") { stopPolling(); await load(); }
    } catch { stopPolling(); }
    polling.value = false;
  }, 3000);
}
function stopPolling() { if (timer) { window.clearInterval(timer); timer = null; } }
async function refreshAgentRun() { if (agentRun.value) agentRun.value = await fetchAgentRun(agentRun.value.run_id); }

async function startWorkflow() {
  startingWorkflow.value = true; error.value = "";
  try {
    const result = await startMqttWorkflow({ host: workflowForm.host.trim(), port: workflowForm.port });
    if (result.status === "not_vulnerable") {
      ElMessage.success("检测完成：MQTT 不允许匿名连接，无需修复");
    } else {
      ElMessage.success(`检测到匿名接入（${result.run_id}），修复方案 ${result.plan.actions.length} 个动作已生成；请执行设备侧白名单执行器 run_mqtt_remediation_demo.sh`);
      workflow.value = await fetchWorkflowRun(result.run_id);
    }
    await load();
  } catch (e) { error.value = errorMessage(e); } finally { startingWorkflow.value = false; }
}
async function viewWorkflow(runId) { workflow.value = await fetchWorkflowRun(runId); }
async function refreshWorkflow() { if (workflow.value) workflow.value = await fetchWorkflowRun(workflow.value.run_id); }

onMounted(load);
onUnmounted(stopPolling);
</script>

<style scoped>
.drawer-section-title { margin: 18px 0 10px; font-size: 14px; font-weight: 600; }
</style>
