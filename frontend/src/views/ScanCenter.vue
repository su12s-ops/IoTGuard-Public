<template>
  <section class="page upgrade-page" v-loading="loading">
    <header class="page-header">
      <div>
        <span class="eyebrow">INTERNET TARGET SCANNING</span>
        <h1>互联网扫描</h1>
        <p>对自有或书面授权的互联网主机做主动端口扫描、服务指纹与组件版本识别，结果直接进入 CVE 匹配与风险研判链路；只做指纹识别，不做漏洞利用验证。</p>
      </div>
      <div class="header-actions"><el-button @click="load">刷新</el-button></div>
    </header>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" role="alert" />
    <el-alert v-if="!capabilities.control_configured" title="主动扫描尚未启用：请先在后端配置 LINUXGUARD_CONTROL_TOKEN，并把授权主机的网段加入 LINUXGUARD_DISCOVERY_CIDRS。" type="info" :closable="false" show-icon />

    <section class="metric-strip compact-metrics" aria-label="互联网扫描概况">
      <article><span>授权目标</span><strong>{{ targets.length }}</strong></article>
      <article><span>启用目标</span><strong>{{ targets.filter(t => t.enabled).length }}</strong></article>
      <article><span>扫描运行</span><strong>{{ runs.length }}</strong></article>
      <article><span>最近命中 CVE</span><strong>{{ totalHits }}</strong></article>
    </section>
    <DeviceControlToken />

    <section class="operation-section">
      <div class="section-head">
        <div>
          <h2>登记授权目标</h2>
          <p class="operation-help">双重授权：目标 IP 必须位于后端允许网段（LINUXGUARD_DISCOVERY_CIDRS）内，且在此显式填写授权依据（自有资产或书面授权说明）。仅接受 IP，不接受域名。</p>
        </div>
      </div>
      <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="registerTarget">
        <el-form-item label="目标名称" required>
          <el-input v-model="targetForm.name" aria-label="目标名称" placeholder="例如：阿里云演示 VPS" />
        </el-form-item>
        <el-form-item label="目标 IP" required>
          <el-input v-model="targetForm.ip" aria-label="目标 IP" placeholder="例如 203.0.113.10（须在允许网段内）" />
        </el-form-item>
        <el-form-item label="授权依据" required>
          <el-input v-model="targetForm.authorization_basis" aria-label="授权依据" type="textarea" :rows="2" placeholder="例如：本人租用的云服务器（订单号 xxx），授权全权扫描" />
        </el-form-item>
        <el-form-item label="端口画像（可选，逗号分隔）">
          <el-input v-model="targetForm.ports" aria-label="端口画像" placeholder="留空使用默认画像（22/80/443/3306/6379 等 19 个端口）" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="targetForm.notes" aria-label="备注" placeholder="可选" />
        </el-form-item>
        <el-form-item label="执行">
          <el-button type="primary" native-type="submit" :disabled="!canOperate" :loading="registering">登记目标</el-button>
        </el-form-item>
      </el-form>
    </section>

    <section class="operation-section">
      <div class="section-head">
        <div><h2>发起扫描</h2><p>选择已登记目标执行后台扫描；端口留空使用目标画像。扫描完成后自动执行设备级 CVE 匹配。</p></div>
      </div>
      <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="scan">
        <el-form-item label="选择目标" required>
          <el-select v-model="scanForm.target_id" aria-label="选择目标" placeholder="选择授权目标" style="width: 100%">
            <el-option v-for="target in enabledTargets" :key="target.id" :label="`${target.name}（${target.ip}）`" :value="target.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="端口覆盖（可选，逗号分隔）">
          <el-input v-model="scanForm.ports" aria-label="端口覆盖" placeholder="留空使用目标画像" />
        </el-form-item>
        <el-form-item label="执行">
          <el-button type="primary" native-type="submit" :disabled="!canOperate || !scanForm.target_id" :loading="scanning">开始扫描</el-button>
        </el-form-item>
      </el-form>
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>授权目标清单</h2><p>目标、授权依据与最近扫描结果一览。</p></div></div>
      <DataTable :rows="targets">
        <el-table-column label="名称" min-width="140"><template #default="{ row }">{{ row.name }}</template></el-table-column>
        <el-table-column prop="ip" label="IP" min-width="120" />
        <el-table-column label="授权依据" min-width="200"><template #default="{ row }">{{ row.authorization_basis }}</template></el-table-column>
        <el-table-column label="端口画像" min-width="110"><template #default="{ row }">{{ row.ports.length ? row.ports.join(', ') : '默认画像' }}</template></el-table-column>
        <el-table-column label="状态" min-width="80"><template #default="{ row }">{{ row.enabled ? '启用' : '停用' }}</template></el-table-column>
        <el-table-column label="最近扫描" min-width="200">
          <template #default="{ row }">
            <template v-if="row.last_run">
              {{ runStatusText(row.last_run.status) }}<small class="cell-sub">开放 {{ row.last_run.open_ports_count }} · 识别 {{ row.last_run.identified_count }} · 命中 {{ row.last_run.vulnerability_hits }}</small>
            </template>
            <template v-else>—</template>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" :disabled="!canOperate || !row.enabled" :loading="scanning" @click="scanRow(row)">扫描</el-button>
            <el-button size="small" :disabled="!canOperate" @click="toggleTarget(row)">{{ row.enabled ? '停用' : '启用' }}</el-button>
            <el-button size="small" :disabled="!canOperate" @click="removeTarget(row)">删除</el-button>
          </template>
        </el-table-column>
      </DataTable>
      <el-empty v-if="!targets.length" description="尚无授权目标；在上方登记第一个目标" />
    </section>

    <section class="operation-section">
      <div class="section-head"><div><h2>运行历史</h2><p>每次扫描的完整审计记录：端口、识别结论与 CVE 命中；运行中条目自动轮询刷新。</p></div></div>
      <DataTable :rows="runs">
        <el-table-column label="运行" min-width="170"><template #default="{ row }">{{ row.run_id }}<small class="cell-sub">{{ formatTime(row.created_at) }}</small></template></el-table-column>
        <el-table-column prop="target_ip" label="目标 IP" min-width="120" />
        <el-table-column label="状态" min-width="90"><template #default="{ row }">{{ runStatusText(row.status) }}</template></el-table-column>
        <el-table-column prop="ports_scanned_count" label="扫描端口" width="90" />
        <el-table-column prop="open_ports_count" label="开放" width="70" />
        <el-table-column prop="identified_count" label="识别服务" width="90" />
        <el-table-column prop="vulnerability_hits" label="命中 CVE" width="90" />
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="openRun(row.run_id)" :disabled="row.status === 'running'">详情</el-button>
          </template>
        </el-table-column>
      </DataTable>
      <el-empty v-if="!runs.length" description="尚无扫描运行" />
    </section>

    <el-drawer v-model="runDrawer" :title="runDetail?.run_id || '扫描详情'" size="min(760px, 96vw)">
      <div v-if="runDetail">
        <el-descriptions title="运行信息" :column="2" border size="small">
          <el-descriptions-item label="目标 IP">{{ runDetail.target_ip }}</el-descriptions-item>
          <el-descriptions-item label="状态">{{ runStatusText(runDetail.status) }}</el-descriptions-item>
          <el-descriptions-item label="扫描端口">{{ runDetail.ports_scanned.join(', ') }}</el-descriptions-item>
          <el-descriptions-item label="开放端口">{{ runDetail.open_ports.join(', ') || '—' }}</el-descriptions-item>
          <el-descriptions-item label="命中 CVE">{{ runDetail.vulnerability_hits }}</el-descriptions-item>
          <el-descriptions-item label="关联设备">{{ runDetail.device_id || '—' }}</el-descriptions-item>
        </el-descriptions>
        <el-alert v-if="runDetail.error" :title="runDetail.error" type="error" show-icon :closable="false" />

        <h3 class="drawer-section-title">识别出的服务</h3>
        <DataTable :rows="runDetail.identified_services">
          <el-table-column prop="port" label="端口" width="80" />
          <el-table-column prop="service_type" label="协议" width="90" />
          <el-table-column prop="product" label="产品" min-width="200" />
          <el-table-column prop="version" label="版本" width="100"><template #default="{ row }">{{ row.version || '—' }}</template></el-table-column>
          <el-table-column label="认证状态" width="120"><template #default="{ row }">{{ authText(row.auth_state) }}</template></el-table-column>
        </DataTable>

        <h3 v-if="runDetail.unmatched_ports.length" class="drawer-section-title">开放但未识别协议的端口（仅横幅证据）</h3>
        <DataTable v-if="runDetail.unmatched_ports.length" :rows="runDetail.unmatched_ports">
          <el-table-column prop="port" label="端口" width="80" />
          <el-table-column prop="banner" label="原始横幅" min-width="300" />
        </DataTable>

        <h3 class="drawer-section-title">结论边界</h3>
        <ul class="boundary-list">
          <li v-for="(item, index) in boundaries" :key="index">{{ item }}</li>
        </ul>
        <p class="operation-help">CVE 命中详情可在「智能设备中心」按设备标识 {{ runDetail.device_id || '—' }} 查看，并进入四智能体研判。</p>
      </div>
    </el-drawer>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import DataTable from "../components/DataTable.vue";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import {
  controlSession, errorMessage, fetchScanCapabilities, fetchScanTargets,
  createScanTarget, updateScanTarget, deleteScanTarget, startScan,
  fetchScanRuns, fetchScanRun,
} from "../api/scanOperations";

const loading = ref(false);
const error = ref("");
const capabilities = ref({});
const targets = ref([]);
const runs = ref([]);
const registering = ref(false);
const scanning = ref(false);
const runDrawer = ref(false);
const runDetail = ref(null);
const targetForm = reactive({ name: "", ip: "", authorization_basis: "", ports: "", notes: "" });
const scanForm = reactive({ target_id: null, ports: "" });
const canOperate = computed(() => Boolean(controlSession.token && capabilities.value.control_configured));
const enabledTargets = computed(() => targets.value.filter(target => target.enabled));
const totalHits = computed(() => targets.value.reduce((sum, target) => sum + (target.last_run?.vulnerability_hits || 0), 0));
const boundaries = computed(() => runDetail.value?.findings?.boundaries || []);
let pollTimer = null;

const runStatusText = value => ({ running: "扫描中", completed: "完成", failed: "失败" }[value] || value);
const authText = value => ({ anonymous_accepted: "匿名可接入", auth_required: "需要认证", unknown: "未知" }[value] || value);
const formatTime = value => value ? new Date(value).toLocaleString("zh-CN") : "—";
const parsePorts = text => text.split(/[,，]/).map(x => Number(x.trim())).filter(x => x > 0);

async function load() {
  loading.value = true;
  error.value = "";
  try {
    [capabilities.value, targets.value, runs.value] = await Promise.all([
      fetchScanCapabilities(), fetchScanTargets(), fetchScanRuns(),
    ]);
    schedulePoll();
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    loading.value = false;
  }
}

async function registerTarget() {
  registering.value = true;
  error.value = "";
  try {
    await createScanTarget({
      name: targetForm.name.trim(),
      ip: targetForm.ip.trim(),
      authorization_basis: targetForm.authorization_basis.trim(),
      ports: parsePorts(targetForm.ports),
      notes: targetForm.notes.trim(),
    });
    ElMessage.success("授权目标已登记");
    targetForm.name = ""; targetForm.ip = ""; targetForm.authorization_basis = "";
    targetForm.ports = ""; targetForm.notes = "";
    targets.value = await fetchScanTargets();
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    registering.value = false;
  }
}

async function scan() {
  await runScan({ target_id: scanForm.target_id, ports: parsePorts(scanForm.ports) });
}

async function scanRow(row) {
  await runScan({ target_id: row.id });
}

async function runScan(payload) {
  scanning.value = true;
  error.value = "";
  try {
    const started = await startScan(payload);
    ElMessage.success(`扫描已启动（${started.run_id}），完成后自动更新结果`);
    runs.value = await fetchScanRuns();
    schedulePoll();
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    scanning.value = false;
  }
}

function schedulePoll() {
  if (pollTimer) clearInterval(pollTimer);
  if (!runs.value.some(run => run.status === "running")) return;
  pollTimer = setInterval(async () => {
    try {
      const previous = runs.value;
      const [freshRuns, freshTargets] = await Promise.all([fetchScanRuns(), fetchScanTargets()]);
      runs.value = freshRuns;
      targets.value = freshTargets;
      previous.filter(run => run.status === "running"
        && freshRuns.find(item => item.run_id === run.run_id)?.status === "completed")
        .forEach(run => {
          const done = freshRuns.find(item => item.run_id === run.run_id);
          ElMessage.success(`扫描完成：${run.target_ip} 识别 ${done.identified_count} 个服务，命中 ${done.vulnerability_hits} 个受影响 CVE`);
        });
      if (!runs.value.some(run => run.status === "running")) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    } catch {
      // 轮询失败不打断页面，下个周期重试
    }
  }, 2500);
}

async function toggleTarget(row) {
  error.value = "";
  try {
    await updateScanTarget(row.id, { enabled: !row.enabled });
    targets.value = await fetchScanTargets();
  } catch (e) {
    error.value = errorMessage(e);
  }
}

async function removeTarget(row) {
  try {
    await ElMessageBox.confirm(`删除授权目标 ${row.name}（${row.ip}）？运行历史将保留。`, "删除目标", { type: "warning" });
  } catch {
    return;
  }
  error.value = "";
  try {
    await deleteScanTarget(row.id);
    targets.value = await fetchScanTargets();
    ElMessage.success("目标已删除");
  } catch (e) {
    error.value = errorMessage(e);
  }
}

async function openRun(runId) {
  runDrawer.value = true;
  try {
    runDetail.value = await fetchScanRun(runId);
  } catch (e) {
    error.value = errorMessage(e);
  }
}

onMounted(load);
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer); });
</script>

<style scoped>
.drawer-section-title {
  margin: 18px 0 10px;
  font-size: 14px;
  font-weight: 600;
}

.boundary-list {
  margin: 0;
  padding-left: 18px;
  color: var(--el-text-color-secondary, #909399);
  font-size: 13px;
  line-height: 1.8;
}
</style>
