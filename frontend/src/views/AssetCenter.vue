<template>
  <section class="page asset-page" v-loading="loading">
    <header class="page-header">
      <div>
        <span class="eyebrow">PROTECTED ASSETS</span>
        <h1>资产管理</h1>
        <p>维护 Linux 与 OpenWrt 资产、组件清单和服务暴露基线。</p>
      </div>
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="handleUpload" :disabled="!controlSession.token" accept=".txt,.json">
        <el-button type="primary" :icon="Upload" :disabled="!controlSession.token">导入采集文件</el-button>
      </el-upload>
    </header>

    <el-alert v-if="loadError" :title="loadError" type="error" show-icon :closable="false" />
    <DeviceControlToken />

    <section class="metric-strip" aria-label="资产概况">
      <article><span>资产总数</span><strong>{{ rows.length }}</strong></article>
      <article><span>Ubuntu 资产</span><strong>{{ ubuntuCount }}</strong></article>
      <article><span>麒麟资产</span><strong>{{ kylinCount }}</strong></article>
      <article><span>核心资产</span><strong>{{ coreCount }}</strong></article>
      <article><span>暴露服务</span><strong>{{ exposedServiceCount }}</strong></article>
      <article><span>漏洞命中</span><strong>{{ affectedMatches.length }}</strong></article>
    </section>

    <section class="section-block">
      <div class="section-heading">
        <div>
          <h2>资产清单</h2>
          <p>软件包、服务与风险数量来自当前资产快照及既有分析结果。</p>
        </div>
        <el-input v-model="keyword" clearable placeholder="搜索资产、IP 或版本" aria-label="搜索资产" style="width: 280px" />
      </div>
      <DataTable v-if="filteredRows.length" :rows="filteredRows" @row-dblclick="openDetail">
        <el-table-column label="资产名称" min-width="170" fixed="left">
          <template #default="{ row }">
            <button class="table-link" @click="openDetail(row)">{{ row.hostname }}</button>
          </template>
        </el-table-column>
        <el-table-column prop="ip_address" label="IP" width="138" />
        <el-table-column label="设备类型" width="130"><template #default="{ row }">{{ row.device_type === 'iot_gateway' ? '物联网网关' : 'Linux 主机' }}</template></el-table-column>
        <el-table-column label="OS / 发行版" min-width="165">
          <template #default="{ row }">
            <span>{{ row.os_name || row.distribution || "—" }}</span>
            <small class="cell-sub">{{ row.os_version || "版本未知" }}</small>
          </template>
        </el-table-column>
        <el-table-column label="重要度" width="105">
          <template #default="{ row }"><span class="status-label" :class="businessClass(row.business_level)">{{ businessStatus(row.business_level) }}</span></template>
        </el-table-column>
        <el-table-column prop="package_count" label="软件包" width="90" align="right" />
        <el-table-column prop="service_count" label="暴露服务" width="100" align="right" />
        <el-table-column prop="risk_count" label="风险数量" width="100" align="right" />
        <el-table-column label="采集状态" width="120">
          <template #default="{ row }"><span class="status-label" :class="row.detail_loaded ? 'approved' : 'is-muted'">{{ row.detail_loaded ? '已采集' : '不完整' }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="80" fixed="right">
          <template #default="{ row }"><el-button link type="primary" @click="openDetail(row)">详情</el-button></template>
        </el-table-column>
      </DataTable>
      <el-empty v-if="!loading && !filteredRows.length" description="没有符合条件的资产" />
    </section>

    <el-drawer v-model="drawer" size="min(980px, 94vw)" destroy-on-close>
      <template #header>
        <div class="drawer-title">
          <span class="eyebrow">ASSET RECORD</span>
          <h2>{{ detail.hostname || "资产详情" }}</h2>
          <p>{{ detail.ip_address || "IP 未记录" }} · {{ detail.os_name }} {{ detail.os_version }}</p>
        </div>
      </template>
      <el-tabs v-model="detailTab" class="workspace-tabs">
        <el-tab-pane label="基本信息" name="base">
          <dl class="description-grid">
            <div><dt>资产名称</dt><dd>{{ detail.hostname || "—" }}</dd></div>
            <div><dt>IP 地址</dt><dd>{{ detail.ip_address || "—" }}</dd></div>
            <div><dt>操作系统</dt><dd>{{ detail.os_name || "—" }} {{ detail.os_version || "" }}</dd></div>
            <div><dt>架构</dt><dd>{{ detail.architecture || "—" }}</dd></div>
            <div><dt>设备型号</dt><dd>{{ detail.device_model || "—" }}</dd></div>
            <div><dt>固件版本</dt><dd>{{ detail.firmware_version || "—" }}</dd></div>
            <div><dt>身份依据</dt><dd>{{ detail.identity_source || "未记录" }}</dd></div>
            <div><dt>清单完整性</dt><dd>{{ detail.inventory_complete ? "完整采集" : "需补采确认" }}</dd></div>
            <div><dt>重要度</dt><dd>{{ businessLabel(detail.business_level) }}</dd></div>
            <div><dt>暴露等级</dt><dd>{{ exposureLabel(detail.exposure_level) }}</dd></div>
            <div class="wide"><dt>内核版本</dt><dd>{{ detail.kernel_version || "—" }}</dd></div>
            <div class="wide"><dt>资产说明</dt><dd>{{ detail.description || "暂无说明" }}</dd></div>
          </dl>
        </el-tab-pane>
        <el-tab-pane :label="`软件包 ${detail.packages?.length || 0}`" name="packages">
          <DataTable :rows="detail.packages || []" height="540">
            <el-table-column prop="package_name" label="软件包" min-width="220" />
            <el-table-column prop="package_version" label="已安装版本" min-width="260" />
            <el-table-column prop="package_manager" label="包管理器" width="110" />
            <el-table-column prop="architecture" label="架构" width="100" />
          </DataTable>
        </el-tab-pane>
        <el-tab-pane :label="`服务与端口 ${detail.services?.length || 0}`" name="services">
          <DataTable v-if="detail.services?.length" :rows="detail.services || []" height="500">
            <el-table-column prop="service_name" label="服务" min-width="180" />
            <el-table-column prop="port" label="端口" width="90" />
            <el-table-column prop="protocol" label="协议" width="90" />
            <el-table-column prop="listen_address" label="监听地址" min-width="180" />
            <el-table-column prop="process_name" label="进程" min-width="160" />
          </DataTable>
          <el-empty v-if="!detail.services?.length" description="当前资产快照未发现监听服务" />
        </el-tab-pane>
        <el-tab-pane :label="`漏洞命中 ${detailMatches.length}`" name="matches">
          <DataTable v-if="detailMatches.length" :rows="detailMatches" height="500">
            <el-table-column prop="cve_id" label="CVE" min-width="180" />
            <el-table-column prop="package_name" label="软件包" min-width="150" />
            <el-table-column prop="installed_version" label="已安装版本" min-width="190" />
            <el-table-column prop="fixed_version" label="修复版本" min-width="190" />
            <el-table-column label="命中结论" width="110">
              <template #default="{ row }"><span class="status-label" :class="row.affected ? 'is-high' : 'is-muted'">{{ ({ affected: '官方确认受影响', potentially_affected: '候选待核验', under_investigation: '官方调查中', unknown: '依据不足', fixed: '已修复', not_affected: '不受影响', not_applicable: '不适用' })[row.match_status] || row.match_status }}</span></template>
            </el-table-column>
          </DataTable>
          <el-empty v-if="!detailMatches.length" description="当前资产没有漏洞命中记录" />
        </el-tab-pane>
        <el-tab-pane :label="`运行状态 ${detailEvents.length}`" name="runtime">
          <DataTable v-if="detailEvents.length" :rows="detailEvents" height="500">
            <el-table-column prop="timestamp" label="时间" min-width="180" />
            <el-table-column prop="event_type" label="事件" min-width="150" />
            <el-table-column prop="process_name" label="进程" min-width="150" />
            <el-table-column prop="details" label="证据摘要" min-width="280" show-overflow-tooltip />
          </DataTable>
          <el-empty v-if="!detailEvents.length" description="暂无与该资产关联的运行时事件" />
        </el-tab-pane>
        <el-tab-pane label="历史采集" name="history">
          <div class="state-note">
            <strong>当前资产快照</strong>
            <span>当前原始证据：{{ detail.inventory_metadata?.inventory_evidence_id || "历史上传清单（无本轮采集证据）" }}</span><span>采集时间：{{ detail.inventory_collected_at || "未记录" }}；执行节点：{{ detail.inventory_metadata?.execution_node || "未记录" }}</span><span>SHA256：{{ detail.inventory_sha256 || "未记录" }}</span><span>身份来源：{{ detail.identity_source }}；历史批次通过「物联网接入 → 采集记录」查询。</span>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-drawer>
  </section>
</template>

<script setup>
import { ElMessage } from "element-plus";
import { Upload } from "@element-plus/icons-vue";
import { computed, onMounted, ref } from "vue";
import DataTable from "../components/DataTable.vue";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import { controlSession } from "../api/controlSession";
import { fetchAsset, fetchAssets, fetchEbpfEvents, fetchMatches, fetchRiskRanking, uploadAsset } from "../api";

const rows = ref([]);
const matches = ref([]);
const risks = ref([]);
const events = ref([]);
const drawer = ref(false);
const detail = ref({});
const detailTab = ref("base");
const keyword = ref("");
const loading = ref(false);
const loadError = ref("");

const filteredRows = computed(() => {
  const term = keyword.value.trim().toLowerCase();
  if (!term) return rows.value;
  return rows.value.filter((row) => [row.hostname, row.ip_address, row.os_name, row.os_version].some((v) => String(v || "").toLowerCase().includes(term)));
});
const ubuntuCount = computed(() => rows.value.filter((row) => String(row.os_name || row.distribution).toLowerCase().includes("ubuntu")).length);
const kylinCount = computed(() => rows.value.filter((row) => ["kylin", "openkylin"].includes(String(row.distribution || "").toLowerCase()) || String(row.os_name || "").toLowerCase().includes("kylin")).length);
const coreCount = computed(() => rows.value.filter((row) => ["core", "critical", "high"].includes(String(row.business_level).toLowerCase())).length);
const exposedServiceCount = computed(() => rows.value.reduce((sum, row) => sum + Number(row.service_count || 0), 0));
const affectedMatches = computed(() => matches.value.filter((item) => item.affected));
const detailMatches = computed(() => affectedMatches.value.filter((item) => Number(item.asset_id) === Number(detail.value.id) || item.hostname === detail.value.hostname));
const detailEvents = computed(() => events.value.filter((item) => item.asset_id === detail.value.id || item.hostname === detail.value.hostname));

const businessLabel = (value) => ({ core: "核心", high: "重要", medium: "一般", low: "低" }[String(value || "").toLowerCase()] || value || "未标注");
const businessStatus = (value) => ["core", "critical", "high"].includes(String(value || "").toLowerCase()) ? "高" : businessLabel(value);
const businessClass = (value) => ["core", "critical", "high"].includes(String(value || "").toLowerCase()) ? "is-high" : "is-info";
const exposureLabel = (value) => ({ public: "公网暴露", external: "外部暴露", internal: "内部", private: "内部" }[String(value || "").toLowerCase()] || value || "未知");

const load = async () => {
  loading.value = true;
  loadError.value = "";
  try {
    const [assetRows, matchRows, riskRows, eventRows] = await Promise.all([
      fetchAssets(), fetchMatches(), fetchRiskRanking(), fetchEbpfEvents({ limit: 500 })
    ]);
    matches.value = matchRows || [];
    risks.value = riskRows || [];
    events.value = Array.isArray(eventRows) ? eventRows : (eventRows?.events || []);
    rows.value = await Promise.all((assetRows || []).map(async (asset) => {
      try {
        const full = await fetchAsset(asset.id);
        return {
          ...asset,
          ...full,
          package_count: full.packages?.length || 0,
          service_count: full.services?.length || 0,
          risk_count: risks.value.filter((risk) => Number(risk.asset_id) === Number(asset.id) || risk.hostname === asset.hostname).length,
          detail_loaded: true
        };
      } catch {
        return { ...asset, package_count: 0, service_count: 0, risk_count: 0, detail_loaded: false };
      }
    }));
  } catch (error) {
    loadError.value = error?.response?.data?.detail || error?.message || "资产数据加载失败";
  } finally {
    loading.value = false;
  }
};

const openDetail = async (row) => {
  try {
    detailTab.value = "base";
    detail.value = row?.packages ? row : await fetchAsset(row.id);
    drawer.value = true;
  } catch (error) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "资产详情加载失败");
  }
};
const handleUpload = async (uploadFile) => {
  try {
    await uploadAsset(uploadFile.raw);
    ElMessage.success("资产采集文件已解析入库");
    await load();
  } catch (error) {
    ElMessage.error(error?.response?.data?.detail || error?.message || "资产文件导入失败");
  }
};

onMounted(load);
</script>

<style scoped>
.asset-page { min-width: 0; }
.drawer-title h2, .drawer-title p { margin: 4px 0 0; }
.drawer-title p, .section-heading p { color: var(--soc-text-muted, #8c99a8); }
.cell-sub { display: block; margin-top: 3px; color: var(--soc-text-muted, #8c99a8); }
.table-link { padding: 0; border: 0; background: none; color: var(--el-color-primary); cursor: pointer; font: inherit; font-weight: 600; }
.description-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 0; border-top: 1px solid var(--soc-border, #293441); border-left: 1px solid var(--soc-border, #293441); }
.description-grid > div { min-height: 76px; padding: 14px 16px; border-right: 1px solid var(--soc-border, #293441); border-bottom: 1px solid var(--soc-border, #293441); }
.description-grid .wide { grid-column: 1 / -1; }
.description-grid dt { color: var(--soc-text-muted, #8c99a8); font-size: 12px; }
.description-grid dd { margin: 7px 0 0; color: var(--soc-text, #e6edf5); overflow-wrap: anywhere; }
.state-note { display: flex; flex-direction: column; gap: 8px; padding: 18px; border-left: 3px solid var(--el-color-primary); background: var(--soc-surface-raised, #111923); }
.state-note span { color: var(--soc-text-muted, #8c99a8); }
@media (max-width: 760px) { .description-grid { grid-template-columns: 1fr; } .description-grid .wide { grid-column: auto; } }
</style>
