<template>
  <div class="page">
    <PageHeader
      eyebrow="Asset discovery & inventory · Lab"
      title="资产与发现"
      description="设备身份、组件清单与原始观测分开记录，每个发现都能回到来源。"
    >
      <template #meta>
        <span>{{ devices.length }} 台设备</span><i class="sep" /><span>{{ num(componentCount) }} 个组件</span><i class="sep" /><span>{{ trustedCount }}/{{ devices.length }} 身份可信</span><i class="sep" /><span>{{ incompleteCount }} 份清单待补</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="14" />刷新</button>
        <button class="btn" type="button" :disabled="uploading" @click="pickImport"><Icon name="download" :size="14" />{{ uploading ? "导入中…" : "导入清单" }}</button>
        <button class="btn primary" type="button" @click="openDiscovery"><Icon name="search" :size="14" />发起发现</button>
      </template>
    </PageHeader>

    <input ref="fileInput" type="file" accept=".json,.txt,.csv,.md" hidden @change="importAsset" />

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 84px minmax(0, 1fr) 152px">
      <div class="stats">
        <div class="stat">
          <div class="stat-icon"><Icon name="server" /></div>
          <div class="stat-copy"><div class="stat-label">登记设备</div><div class="stat-value">{{ devices.length }}<small>台</small></div></div>
          <div class="stat-delta">{{ devices.length ? "台账" : "暂无" }}</div>
        </div>
        <div class="stat">
          <div class="stat-icon" style="background: var(--info-soft); color: var(--info)"><Icon name="layers" /></div>
          <div class="stat-copy"><div class="stat-label">组件记录</div><div class="stat-value">{{ num(componentCount) }}<small>条</small></div></div>
          <div class="stat-delta" style="color: var(--info)">{{ ecosystemCount }} 个生态</div>
        </div>
        <div class="stat">
          <div class="stat-icon" style="background: var(--low-soft); color: var(--low)"><Icon name="shield" /></div>
          <div class="stat-copy"><div class="stat-label">身份可信</div><div class="stat-value">{{ trustedCount }}<small>/ {{ devices.length }}</small></div></div>
          <div class="stat-delta">{{ devices.length ? Math.round((trustedCount / devices.length) * 100) : 0 }}%</div>
        </div>
        <div class="stat">
          <div class="stat-icon" style="background: var(--high-soft); color: var(--high)"><Icon name="alert" /></div>
          <div class="stat-copy"><div class="stat-label">清单待补</div><div class="stat-value">{{ incompleteCount }}<small>台</small></div></div>
          <div class="stat-delta down">{{ incompleteCount ? "需补清单" : "已齐" }}</div>
        </div>
      </div>

      <div class="grid g-2-1">
        <section class="card">
          <div class="card-head">
            <div><div class="card-title">资产台账</div><div class="card-desc">设备身份与组件清单分开计数，不按 IP 自动合并</div></div>
            <div style="display: flex; gap: 10px"><span class="link" @click="exportCsv">导出 CSV</span><span class="link" @click="load">重新读取 <Icon name="refresh" :size="12" /></span></div>
          </div>
          <div class="filters">
            <span v-for="item in ecosystemFilters" :key="item.value" class="chip" :class="{ accent: eco === item.value }" @click="eco = item.value">{{ item.label }} {{ item.count }}</span>
            <span class="filters-note">按身份可信度排序</span>
          </div>
          <div v-if="loading" class="loading-line"><span class="spinner" />正在读取资产台账…</div>
          <div v-else-if="!filteredDevices.length" class="empty-wrap"><EmptyState title="暂无设备记录" description="接入设备或完成一次发现后，台账会出现在这里。" icon="server" /></div>
          <div v-else class="table-wrap">
            <table class="tall asset-table" style="table-layout: fixed">
              <colgroup><col style="width: 185px" /><col style="width: 68px" /><col style="width: 108px" /><col style="width: 46px" /><col style="width: 108px" /><col style="width: 86px" /><col style="width: 86px" /><col style="width: 18px" /></colgroup>
              <thead><tr><th>设备 / 身份</th><th>生态</th><th>系统 / 固件</th><th>组件</th><th>漏洞命中</th><th>运行时</th><th>修复能力</th><th></th></tr></thead>
              <tbody>
                <tr v-for="device in filteredDevices" :key="device.key" style="cursor: pointer" @click="selected = device">
                  <td class="name">{{ device.name || device.key }}<small>{{ device.key }} · {{ ratioPct(device.identity_confidence, 0) }}</small></td>
                  <td><span class="chip" :class="ecoClass(device.ecosystem)"><i class="dot" />{{ ecosystemLabel(device.ecosystem) }}</span></td>
                  <td><span class="mono">{{ device.version || "未识别" }}</span><small>{{ device.inventory_complete === false ? "清单待补" : "清单完整" }}</small></td>
                  <td class="num">{{ device.component_count ?? "—" }}</td>
                  <td><span class="chip" :class="device.matches?.confirmed ? 'crit' : device.matches?.pending ? 'high' : 'muted'"><i class="dot" />{{ device.matches?.confirmed ?? 0 }} 确认 · {{ device.matches?.pending ?? 0 }} 待核</span></td>
                  <td><span class="chip" :class="runtimeTone(device.runtime)"><i class="dot" />{{ runtimeLabel(device.runtime) }}</span></td>
                  <td style="color: var(--muted); font-size: 9.5px">{{ remediationLabel(device.remediation) }}</td>
                  <td><Icon name="chev-right" :size="12" style="color: var(--line-strong)" /></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="card-foot"><span>身份可信度来自 SSH 清单、HTTP 身份端点与 banner 指纹；三者不等价。</span><span class="num">{{ devices.length }} 台 · 最多 5 条</span></div>
        </section>

        <div class="grid" style="grid-template-rows: 1fr 1fr">
          <section class="card">
            <div class="card-head">
              <div><div class="card-title">生态分布</div><div class="card-desc">按设备台账计数</div></div>
              <span class="chip muted" style="height: 18px; font-size: 8px">{{ ecosystemCount }} 个生态</span>
            </div>
            <div class="card-body eco-body">
              <DonutChart :items="ecosystemItems" :size="104" center-label="台设备" />
              <div class="eco-legend">
                <span v-for="item in ecosystemItems" :key="item.label"><i class="dot" :style="{ background: item.color }" />{{ item.label }}<b class="num">{{ item.value }}</b></span>
              </div>
            </div>
            <div class="card-foot"><span>OpenWrt / Zephyr 按 IoT 设备管理；Ubuntu 单列基础设施。</span></div>
          </section>

          <section class="card">
            <div class="card-head">
              <div><div class="card-title">身份可信分布</div><div class="card-desc">每条记录保留原始观测方式</div></div>
            </div>
            <div class="card-body" style="padding-top: 9px">
              <div v-for="bucket in confidenceBuckets" :key="bucket.label" class="cover-row" style="grid-template-columns: 88px 1fr 30px; margin-top: 9px">
                <span>{{ bucket.label }}</span><span class="cover-bar"><i :style="{ width: bucket.width, background: bucket.color }" /></span><span class="cover-val">{{ bucket.count }}</span>
              </div>
              <div v-if="!devices.length" class="empty-note">暂无身份记录。</div>
            </div>
            <div class="card-foot"><span>没有响应不等于设备不存在；只代表当前探测未命中。</span><span class="link" @click="load">重新发现 <Icon name="chev-right" :size="12" /></span></div>
          </section>
        </div>
      </div>

      <section class="card">
        <div class="card-head">
          <div><div class="card-title">采集覆盖</div><div class="card-desc">身份、清单与评估是三条独立链路</div></div>
          <span class="chip muted" style="height: 18px; font-size: 8px">最近同步 {{ updated || "尚未读取" }}</span>
        </div>
        <div v-if="!coverageDevices.length" class="empty-note" style="padding: 18px">暂无覆盖记录。</div>
        <div v-else class="cover-grid">
          <div v-for="device in coverageDevices" :key="device.key" class="cover">
            <div class="cover-name"><i class="dot" :style="{ background: ecoColor(device.ecosystem) }" />{{ device.name || device.key }}</div>
            <div class="cover-row"><span>身份</span><span class="cover-bar"><i :class="pctClass(device.identity_confidence)" :style="{ width: ratioPct(device.identity_confidence) }" /></span><span class="cover-val">{{ ratioPct(device.identity_confidence, 0) }}</span></div>
            <div class="cover-row"><span>清单</span><span class="cover-bar"><i :class="device.inventory_complete === false ? 'warn' : 'low'" :style="{ width: device.inventory_complete === false ? '40%' : device.inventory_complete ? '100%' : '0%' }" /></span><span class="cover-val">{{ device.inventory_complete === false ? "40%" : device.inventory_complete ? "100%" : "—" }}</span></div>
            <div class="cover-row"><span>评估</span><span class="cover-bar"><i :class="assessmentClass(device.matches?.assessment)" :style="{ width: assessmentWidth(device.matches?.assessment) }" /></span><span class="cover-val">{{ assessmentLabel(device.matches?.assessment) }}</span></div>
          </div>
        </div>
      </section>
    </div>

    <Modal :open="Boolean(selected)" :title="selected?.name || '设备详情'" description="台账字段来自后端观测；未知字段不推测。" wide @close="selected = null">
      <div v-if="selected" class="detail-grid">
        <div><span>台账键</span><b class="mono">{{ selected.key }}</b></div>
        <div><span>生态</span><b>{{ ecosystemLabel(selected.ecosystem) }}</b></div>
        <div><span>版本</span><b class="mono">{{ selected.version || "未识别" }}</b></div>
        <div><span>组件</span><b>{{ selected.component_count ?? "—" }}</b></div>
        <div><span>身份可信度</span><b>{{ ratioPct(selected.identity_confidence, 0) }}</b></div>
        <div><span>清单状态</span><b>{{ selected.inventory_complete === false ? "待补" : selected.inventory_complete ? "完整" : "未知" }}</b></div>
        <div><span>漏洞命中</span><b>{{ selected.matches?.count ?? "—" }} 条</b></div>
        <div><span>运行时</span><b>{{ runtimeLabel(selected.runtime) }}</b></div>
        <div class="wide"><span>修复能力</span><b>{{ remediationLabel(selected.remediation) }}</b></div>
        <div class="wide"><span>下一步</span><b>{{ selected.next_action || "—" }}</b></div>
      </div>
      <template #footer><button class="btn" type="button" @click="selected = null">关闭</button></template>
    </Modal>

    <Modal :open="discoveryOpen" title="发起授权发现" description="只扫描显式授权网段；没有响应不等于设备不存在。" @close="discoveryOpen = false">
      <label class="field-label" for="discovery-cidr">授权网段（CIDR）</label>
      <input id="discovery-cidr" v-model="cidr" class="input" placeholder="例如 192.168.100.0/24" />
      <label class="field-label" for="discovery-ports">TCP 端口（逗号分隔）</label>
      <input id="discovery-ports" v-model="ports" class="input" placeholder="22, 80, 443" />
      <label class="checkbox-row"><input v-model="enroll" type="checkbox" /> 发现后自动入档（写入设备台账）</label>
      <p class="field-hint">发现过程可能持续数十秒；接口需要操作令牌。仅对授权目标使用。</p>
      <template #footer>
        <button class="btn" type="button" @click="discoveryOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="discovering || !cidr.trim()" @click="submitDiscovery">{{ discovering ? "发现中…" : "开始发现" }}</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import DonutChart from "../components/DonutChart.vue";
import Modal from "../components/Modal.vue";
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { ecosystemLabel, num, ratioPct } from "../utils/format";

const devices = ref([]);
const loading = ref(true);
const error = ref("");
const updated = ref("");
const eco = ref("all");
const selected = ref(null);
const fileInput = ref(null);
const discoveryOpen = ref(false);
const cidr = ref("192.168.100.0/24");
const ports = ref("22, 80, 443");
const enroll = ref(true);
const discovering = ref(false);
const uploading = ref(false);

const ecosystemCount = computed(() => new Set(devices.value.map((d) => d.ecosystem).filter(Boolean)).size);
const componentCount = computed(() => devices.value.reduce((sum, d) => sum + Number(d.component_count || 0), 0));
const trustedCount = computed(() => devices.value.filter((d) => Number(d.identity_confidence) >= 0.9).length);
const incompleteCount = computed(() => devices.value.filter((d) => d.inventory_complete === false).length);
const coverageDevices = computed(() => devices.value.slice(0, 4));

const filteredDevices = computed(() => {
  const list = eco.value === "all" ? devices.value : devices.value.filter((d) => (d.ecosystem || "other_iot") === eco.value);
  return list.slice(0, 5);
});

const ecosystemFilters = computed(() => {
  const counts = devices.value.reduce((map, d) => {
    const key = d.ecosystem || "other_iot";
    map[key] = (map[key] || 0) + 1;
    return map;
  }, {});
  const base = [{ value: "all", label: "全部", count: devices.value.length }];
  for (const [key, count] of Object.entries(counts)) base.push({ value: key, label: ecosystemLabel(key), count });
  return base;
});

const ecoColors = ["var(--accent)", "var(--chart-2)", "var(--chart-4)", "var(--chart-3)", "var(--high)"];
const ecosystemItems = computed(() => {
  const counts = devices.value.reduce((map, d) => {
    const key = d.ecosystem || "other_iot";
    map[key] = (map[key] || 0) + 1;
    return map;
  }, {});
  return Object.entries(counts).map(([key, value], index) => ({ label: ecosystemLabel(key), value, color: ecoColors[index % ecoColors.length] }));
});

const confidenceBuckets = computed(() => {
  const trusted = devices.value.filter((d) => Number(d.identity_confidence) >= 0.9).length;
  const partial = devices.value.filter((d) => Number(d.identity_confidence) >= 0.35 && Number(d.identity_confidence) < 0.9).length;
  const low = devices.value.length - trusted - partial;
  const max = Math.max(devices.value.length, 1);
  return [
    { label: "可信 ≥ 90%", count: trusted, width: `${(trusted / max) * 100}%`, color: "var(--low)" },
    { label: "部分 35–90%", count: partial, width: `${(partial / max) * 100}%`, color: "var(--info)" },
    { label: "低 / 未知", count: low, width: `${(low / max) * 100}%`, color: "var(--high)" }
  ];
});

const ecoClassMap = { openwrt: "accent", zephyr: "info", ubuntu: "low" };
const ecoClass = (value) => ecoClassMap[value] || "muted";
const ecoColor = (value) => ({ openwrt: "var(--accent)", zephyr: "var(--chart-2)", ubuntu: "var(--chart-4)" }[value] || "var(--muted)");

function runtimeLabel(value) {
  return { requires_sensor_evidence: "需传感器证据", ebpf_not_applicable: "RTOS 不支持 eBPF", requires_runtime_evidence: "需运行时证据" }[value] || value || "未记录";
}
function runtimeTone(value) {
  if (value === "ebpf_not_applicable") return "muted";
  return value ? "info" : "muted";
}
function remediationLabel(value) {
  return { requires_device_specific_plan: "需设备专用方案", firmware_update_not_automated: "固件更新未接通" }[value] || value || "—";
}
function assessmentLabel(value) {
  return { partial: "部分评估", unassessed: "未评估", complete: "已评估", evaluated: "已评估" }[value] || value || "未记录";
}
function assessmentClass(value) {
  if (value === "complete" || value === "evaluated") return "low";
  if (value === "partial") return "warn";
  return "";
}
function assessmentWidth(value) {
  return { partial: "66%", complete: "100%", evaluated: "100%", unassessed: "0%" }[value] || "0%";
}
function pctClass(value) {
  const n = Number(value);
  return n >= 0.9 ? "low" : n >= 0.35 ? "warn" : "";
}

function exportCsv() {
  const rows = [["key", "name", "ecosystem", "version", "component_count", "identity_confidence", "inventory_complete"]];
  for (const d of devices.value) rows.push([d.key, d.name, d.ecosystem, d.version, d.component_count, d.identity_confidence, d.inventory_complete]);
  const csv = rows.map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "iotguard-assets.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function requireToken() {
  if (controlSession.token) return true;
  notify("请先在顶栏设置操作令牌", "error");
  ui.tokenOpen = true;
  return false;
}

function pickImport() {
  if (!requireToken()) return;
  fileInput.value?.click();
}

async function importAsset(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  uploading.value = true;
  try {
    const form = new FormData();
    form.append("file", file);
    await api.post("/assets/upload", form, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 120000
    });
    notify(`已导入 ${file.name}`, "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "清单导入失败", "error");
  } finally {
    uploading.value = false;
    if (fileInput.value) fileInput.value.value = "";
  }
}

function openDiscovery() {
  if (!requireToken()) return;
  discoveryOpen.value = true;
}

async function submitDiscovery() {
  discovering.value = true;
  try {
    const portList = ports.value.split(",").map((value) => Number(value.trim())).filter((value) => Number.isInteger(value) && value > 0 && value < 65536);
    const result = await api.post(
      "/iot/discovery",
      { cidr: cidr.value.trim(), ports: portList, enroll: enroll.value },
      { headers: { "X-Control-Token": controlSession.token }, timeout: 180000 }
    );
    const count = Array.isArray(result.data) ? result.data.length : result.data?.count;
    notify(`发现请求已完成${count !== undefined ? ` · ${count} 条观测` : ""}`, "success");
    discoveryOpen.value = false;
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "发现失败", "error");
  } finally {
    discovering.value = false;
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const result = await api.get("/devices/business/overview", { timeout: 25000 });
    devices.value = result.data?.devices || [];
    updated.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "资产台账读取失败，请检查后端服务。";
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.filters { display: flex; align-items: center; gap: 6px; padding: 9px 15px 0; flex-wrap: wrap; }
.filters .chip { cursor: pointer; height: 21px; font-size: 9px; }
.filters-note { margin-left: auto; color: var(--muted); font-size: 9px; }
.empty-wrap { display: grid; place-items: center; min-height: 260px; }
.eco-body { display: flex; align-items: center; gap: 16px; padding-top: 4px; }
.eco-legend { display: grid; gap: 8px; font-size: 9.5px; color: var(--muted); flex: 1; }
.eco-legend span { display: flex; align-items: center; gap: 6px; }
.eco-legend b { margin-left: auto; color: var(--ink); font: 700 9.5px var(--font-num); }
.empty-note { color: var(--muted); font-size: 9.5px; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0; border-top: 1px solid var(--line); }
.detail-grid > div { padding: 9px 0; border-bottom: 1px solid var(--line-soft); }
.detail-grid > div:nth-child(odd) { padding-right: 14px; }
.detail-grid span { display: block; color: var(--muted); font-size: 9px; }
.detail-grid b { display: block; margin-top: 3px; color: var(--ink); font-size: 11px; }
.detail-grid .wide { grid-column: 1 / -1; }
.asset-table td { overflow: hidden; text-overflow: ellipsis; }
</style>

