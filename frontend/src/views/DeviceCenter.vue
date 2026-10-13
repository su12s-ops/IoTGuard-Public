<template>
  <section class="page upgrade-page" v-loading="loading">
    <header class="page-header">
      <div>
        <span class="eyebrow">SMART DEVICE INVENTORY</span>
        <h1>智能设备中心</h1>
        <p>对授权目标执行在线发现与服务识别，建立设备 → 服务 → 组件清单；设备数据全部来自后端真实探测结果。</p>
      </div>
      <div class="header-actions"><el-button @click="load">刷新</el-button></div>
    </header>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" role="alert" />
    <el-alert v-if="!capabilities.control_configured" title="设备发现尚未启用：请先在后端配置 LINUXGUARD_CONTROL_TOKEN 与允许网段，并输入操作令牌。" type="info" :closable="false" show-icon />
    <section class="metric-strip compact-metrics" aria-label="设备清单概况">
      <article><span>设备总数</span><strong>{{ devices.length }}</strong></article>
      <article><span>在线设备</span><strong>{{ devices.filter(d => d.status === 'online').length }}</strong></article>
      <article><span>识别服务</span><strong>{{ devices.reduce((sum, d) => sum + d.service_count, 0) }}</strong></article>
      <article><span>软件组件</span><strong>{{ devices.reduce((sum, d) => sum + d.component_count, 0) }}</strong></article>
    </section>
    <DeviceControlToken />

    <section class="operation-section">
      <div class="section-head">
        <div>
          <h2>发现智能设备</h2>
          <p class="operation-help">输入授权网段内的目标 IP，后端将逐端口做协议级探测（SSH 横幅 / HTTP / RTSP OPTIONS / MQTT CONNACK），再由设备自身信息与横幅推导身份。</p>
        </div>
      </div>
      <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="discover">
        <el-form-item label="目标 IP" required>
          <el-input v-model="discoverForm.host" aria-label="目标 IP" placeholder="例如 127.0.0.1（须在后端允许网段内）" />
        </el-form-item>
        <el-form-item label="探测端口（可选，逗号分隔）">
          <el-input v-model="discoverForm.ports" aria-label="探测端口" placeholder="留空使用默认端口集（22/80/554/1883 等）" />
        </el-form-item>
        <el-form-item label="执行">
          <el-button type="primary" native-type="submit" :disabled="!canOperate" :loading="discovering">开始发现与识别</el-button>
        </el-form-item>
      </el-form>
    </section>

    <section class="operation-section">
      <div class="section-head">
        <div><h2>设备清单</h2><p>设备信息、端口、服务与组件均来自后端在线识别结果。</p></div>
      </div>
      <DataTable :rows="devices">
        <el-table-column label="设备名称" min-width="150"><template #default="{ row }">{{ row.device_name }}<small class="cell-sub">{{ row.device_id }}</small></template></el-table-column>
        <el-table-column label="类型" min-width="110"><template #default="{ row }">{{ typeText(row.device_type) }}</template></el-table-column>
        <el-table-column label="厂商 / 型号" min-width="170"><template #default="{ row }">{{ row.vendor || '—' }}<small class="cell-sub">{{ row.model || '—' }}</small></template></el-table-column>
        <el-table-column prop="firmware_version" label="固件版本" min-width="100"><template #default="{ row }">{{ row.firmware_version || '—' }}</template></el-table-column>
        <el-table-column prop="ip" label="IP" min-width="120" />
        <el-table-column label="状态" min-width="90"><template #default="{ row }">{{ statusText(row.status) }}</template></el-table-column>
        <el-table-column label="开放端口" min-width="170"><template #default="{ row }">{{ row.open_ports.join(', ') || '—' }}<small class="cell-sub">{{ row.service_count }} 个服务 · {{ row.component_count }} 个组件</small></template></el-table-column>
        <el-table-column label="风险基线" min-width="110"><template #default="{ row }">{{ row.risk_score_basis === 'service_exposure_baseline' ? row.risk_score + ' / 40（暴露基线）' : '—' }}</template></el-table-column>
        <el-table-column label="漏洞数" min-width="90"><template #default="{ row }">{{ row.vulnerability_count }}</template></el-table-column>
        <el-table-column label="安全状态" min-width="120"><template #default="{ row }">{{ securityText(row.security_status) }}</template></el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="openDetail(row.device_id)">详情</el-button>
            <el-button size="small" :disabled="!canOperate" :loading="refreshing === row.device_id" @click="refresh(row)">重新探测</el-button>
          </template>
        </el-table-column>
      </DataTable>
      <el-empty v-if="!devices.length" description="尚无设备；在上方输入授权目标 IP 开始发现" />
    </section>

    <el-drawer v-model="detailDrawer" :title="detail?.device_name || '设备详情'" size="min(720px, 96vw)">
      <div v-if="detail" v-loading="detailLoading">
        <el-descriptions title="设备信息" :column="2" border size="small">
          <el-descriptions-item label="设备标识">{{ detail.device_id }}</el-descriptions-item>
          <el-descriptions-item label="设备名称">{{ detail.device_name }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ typeText(detail.device_type) }}</el-descriptions-item>
          <el-descriptions-item label="厂商">{{ detail.vendor || '—' }}</el-descriptions-item>
          <el-descriptions-item label="型号">{{ detail.model || '—' }}</el-descriptions-item>
          <el-descriptions-item label="固件版本">{{ detail.firmware_version || '—' }}</el-descriptions-item>
          <el-descriptions-item label="操作系统">{{ detail.os || '—' }}</el-descriptions-item>
          <el-descriptions-item label="IP">{{ detail.ip }}</el-descriptions-item>
          <el-descriptions-item label="状态">{{ statusText(detail.status) }}</el-descriptions-item>
          <el-descriptions-item label="身份来源">{{ identityText(detail.identity_source) }}（置信度 {{ (detail.identity_confidence * 100).toFixed(0) }}%）</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ formatTime(detail.first_seen_at) }}</el-descriptions-item>
          <el-descriptions-item label="最近探测">{{ formatTime(detail.last_seen_at) }}</el-descriptions-item>
        </el-descriptions>

        <h3 class="drawer-section-title">开放端口与服务</h3>
        <DataTable :rows="detail.services">
          <el-table-column prop="port" label="端口" width="80" />
          <el-table-column prop="service_type" label="服务" width="90" />
          <el-table-column prop="product" label="产品" min-width="180" />
          <el-table-column prop="version" label="版本" width="100"><template #default="{ row }">{{ row.version || '—' }}</template></el-table-column>
          <el-table-column label="认证状态" width="130"><template #default="{ row }">{{ authText(row.auth_state) }}</template></el-table-column>
          <el-table-column prop="status" label="当前状态" width="90" />
        </DataTable>

        <h3 class="drawer-section-title">软件组件</h3>
        <DataTable :rows="detail.components">
          <el-table-column prop="component_name" label="组件" min-width="190" />
          <el-table-column label="类型" width="90"><template #default="{ row }">{{ row.component_type === 'firmware' ? '固件' : '软件' }}</template></el-table-column>
          <el-table-column prop="version" label="版本" width="100"><template #default="{ row }">{{ row.version || '—' }}</template></el-table-column>
          <el-table-column prop="cpe" label="CPE" min-width="230"><template #default="{ row }">{{ row.cpe || '—' }}</template></el-table-column>
          <el-table-column label="来源" width="130"><template #default="{ row }">{{ row.source === 'device_identity' ? '设备身份接口' : '服务横幅' }}</template></el-table-column>
        </DataTable>

        <h3 class="drawer-section-title">漏洞与安全状态</h3>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="漏洞数量">{{ detail.vulnerability_count }}</el-descriptions-item>
          <el-descriptions-item label="安全状态">{{ securityText(detail.security_status) }}</el-descriptions-item>
          <el-descriptions-item label="暴露基线分" :span="2">
            {{ detail.risk_score_basis === 'service_exposure_baseline' ? `${detail.risk_score} / 40（依据已识别开放服务计算）` : '暂无' }}
          </el-descriptions-item>
        </el-descriptions>
        <p class="operation-help">设备级 CVE 匹配将在下一阶段接入现有匹配与四智能体研判流程；当前漏洞数量为真实计数的 0，不使用占位数据。</p>
      </div>
    </el-drawer>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import DataTable from "../components/DataTable.vue";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import {
  controlSession, errorMessage, fetchDeviceCapabilities,
  fetchDevices, fetchDeviceDetail, discoverDevice, refreshDevice
} from "../api/deviceOperations";

const loading = ref(false);
const error = ref("");
const capabilities = ref({});
const devices = ref([]);
const discovering = ref(false);
const refreshing = ref(null);
const detailDrawer = ref(false);
const detailLoading = ref(false);
const detail = ref(null);
const discoverForm = reactive({ host: "", ports: "" });
const canOperate = computed(() => Boolean(controlSession.token && capabilities.value.control_configured));

const typeText = value => ({ ip_camera: "智能摄像头", video_device: "视频设备", gateway: "网关设备", unknown: "未知类型" }[value] || value);
const statusText = value => ({ online: "在线", offline: "离线", unknown: "未知" }[value] || value);
const securityText = value => ({ unassessed: "待漏洞评估", offline: "离线" }[value] || value);
const authText = value => ({ anonymous_accepted: "匿名可接入", auth_required: "需要认证", unknown: "未知" }[value] || value);
const identityText = value => ({ device_identity_endpoint: "设备身份接口", banner_heuristic: "横幅推断" }[value] || value);
const formatTime = value => value ? new Date(value).toLocaleString("zh-CN") : "—";

async function load() {
  loading.value = true;
  error.value = "";
  try {
    [capabilities.value, devices.value] = await Promise.all([fetchDeviceCapabilities(), fetchDevices()]);
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    loading.value = false;
  }
}

async function discover() {
  discovering.value = true;
  error.value = "";
  try {
    const ports = discoverForm.ports.split(/[,，]/).map(x => Number(x.trim())).filter(x => x > 0);
    const result = await discoverDevice({ host: discoverForm.host.trim(), ports });
    const identified = Object.values(result.discovery_report?.identified || {});
    ElMessage.success(`发现设备 ${result.device_name}（${result.device_type}），识别 ${identified.length} 个服务`);
    await load();
    openDetail(result.device_id);
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    discovering.value = false;
  }
}

async function openDetail(deviceId) {
  detailDrawer.value = true;
  detailLoading.value = true;
  try {
    detail.value = await fetchDeviceDetail(deviceId);
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    detailLoading.value = false;
  }
}

async function refresh(row) {
  refreshing.value = row.device_id;
  error.value = "";
  try {
    const result = await refreshDevice(row.device_id);
    if (result.status === "offline") {
      ElMessage.warning("设备无响应，已标记为离线");
    } else {
      ElMessage.success("重新探测完成，清单已更新");
    }
    await load();
    if (detailDrawer.value && detail.value?.device_id === row.device_id) detail.value = await fetchDeviceDetail(row.device_id);
  } catch (e) {
    error.value = errorMessage(e);
  } finally {
    refreshing.value = null;
  }
}

onMounted(load);
</script>

<style scoped>
.drawer-section-title {
  margin: 18px 0 10px;
  font-size: 14px;
  font-weight: 600;
}
</style>
