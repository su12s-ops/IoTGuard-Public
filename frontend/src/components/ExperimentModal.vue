<template>
  <Modal
    :open="open"
    title="本轮实验与存档"
    description="设备与采集配置保留；运行结果先存档，再清理衍生数据。"
    wide
    @close="$emit('close')"
  >
    <div v-if="loading" class="exp-loading"><span class="spinner" />正在读取本轮数据…</div>
    <div v-else-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <template v-else-if="state">
      <div v-if="activeText" class="exp-warning"><Icon name="clock" :size="14" />{{ activeText }}</div>

      <div class="exp-overview">
        <div class="exp-stat"><span>保留资产</span><b>{{ summary.assets ?? "—" }}</b></div>
        <div class="exp-stat"><span>智能设备</span><b>{{ summary.iot_devices ?? "—" }}</b></div>
        <div class="exp-stat"><span>风险对象</span><b>{{ summary.risks ?? "—" }}</b></div>
        <div class="exp-stat"><span>高危 / 严重</span><b class="hot">{{ summary.high_risks ?? "—" }}</b></div>
        <div class="exp-stat"><span>运行事件</span><b>{{ formatNumber(summary.runtime_events) }}</b></div>
      </div>

      <div class="exp-columns">
        <section class="exp-block keep">
          <header><Icon name="shield" :size="15" />保留 · 设备与配置<span>{{ formatNumber(keepTotal) }}</span></header>
          <div class="exp-rows">
            <div v-for="row in keepRows" :key="row.key"><span>{{ row.label }}</span><b>{{ formatNumber(row.value) }}</b></div>
            <div v-if="!keepRows.length" class="exp-empty">暂无设备配置计数。</div>
          </div>
          <p>接入设备、组件、连接、传感器与采集配置不会被删除；另有 {{ formatNumber(cacheCount) }} 条全局 CVE 情报缓存保留，用于加速下一轮复查。</p>
        </section>

        <section class="exp-block clear">
          <header><Icon name="archive-down" :size="15" />归档并清理 · 运行产物<span>{{ formatNumber(derivedTotal) }}</span></header>
          <div class="exp-rows">
            <div v-for="row in clearRows" :key="row.key"><span>{{ row.label }}</span><b>{{ formatNumber(row.value) }}</b></div>
            <div v-if="!clearRows.length" class="exp-empty">还没有衍生数据，当前已是干净状态。</div>
          </div>
          <p>漏洞、匹配、风险、研判、修复与追踪记录会先写入存档；原始事件只保留汇总。</p>
        </section>
      </div>

      <label class="field-label" for="experiment-label">存档备注（可选）</label>
      <input id="experiment-label" v-model="label" class="input" maxlength="80" placeholder="例如：第一轮回归 / 演示前快照" />

      <div v-if="!tokenReady" class="exp-token-box">
        <div class="exp-token-title"><Icon name="lock" :size="14" />需要操作令牌</div>
        <div class="exp-token-row">
          <input
            ref="tokenInput"
            v-model="tokenDraft"
            class="input"
            type="password"
            autocomplete="off"
            placeholder="粘贴 backend/.env 中的 LINUXGUARD_CONTROL_TOKEN（48 位，不带引号）"
            @keyup.enter="saveInlineToken"
          />
          <button class="btn primary" type="button" :disabled="!tokenDraft.trim()" @click="saveInlineToken">保存并继续</button>
        </div>
        <p class="exp-token-hint">令牌只保存在当前页面内存；保存后会自动继续刚才的操作。</p>
      </div>
      <div v-else class="exp-token ok">
        <i class="dot" />
        <span>操作令牌已设置</span>
        <button class="link" type="button" @click="clearInlineToken">清除</button>
      </div>

      <div class="exp-archives">
        <div class="exp-archives-head"><b>最近存档</b><span>{{ archives.length }} 份</span></div>
        <div v-if="!archives.length" class="exp-empty" style="padding: 10px 0">还没有存档；点击“仅归档结果”生成第一份。</div>
        <div v-for="item in archives" :key="item.filename" class="archive-item">
          <span class="ai-icon"><Icon name="archive" :size="15" /></span>
          <div class="ai-copy">
            <b>{{ item.label || "未命名存档" }}</b>
            <small>{{ formatTime(item.archived_at) }} · {{ formatBytes(item.size_bytes) }}</small>
          </div>
          <span class="ai-counts">风险 {{ item.summary?.risks ?? "—" }} · 高危 {{ item.summary?.high_risks ?? "—" }}</span>
          <button class="link" type="button" @click="downloadArchive(item)">下载</button>
        </div>
      </div>

      <p class="exp-note">
        <Icon name="help" :size="13" />
        页面刷新不会自动清空，避免误删；如希望后端每次启动时先存档再清理，请配置
        <span class="mono">LINUXGUARD_ARCHIVE_ON_STARTUP=1</span>。
      </p>

      <div v-if="confirmReset" class="exp-confirm">
        <b>确认开始新一轮？</b>
        <p>当前 {{ formatNumber(derivedTotal) }} 条衍生数据会先写入存档，再被删除；设备保留。删除后不能从界面恢复。</p>
      </div>
    </template>

    <template #footer>
      <button class="btn" type="button" @click="$emit('close')">关闭</button>
      <button class="btn" type="button" :disabled="busy || loading || !state" @click="archiveOnly">{{ busy && !confirmReset ? "处理中…" : "仅归档结果" }}</button>
      <button v-if="!confirmReset" class="btn primary" type="button" :disabled="busy || loading || !state || Boolean(activeText)" @click="requestReset"><Icon name="archive-down" :size="15" />{{ activeText ? "有任务运行中" : "归档并开始新一轮" }}</button>
      <button v-else class="btn danger" type="button" :disabled="busy" @click="resetNow">{{ busy ? "清理中…" : "确认清理并开始" }}</button>
    </template>
  </Modal>
</template>

<script setup>
import { computed, nextTick, ref, watch } from "vue";
import Modal from "./Modal.vue";
import Icon from "./Icon.vue";
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify } from "../stores/ui";

const props = defineProps({ open: { type: Boolean, default: false } });
const emit = defineEmits(["close"]);

const state = ref(null);
const loading = ref(false);
const busy = ref(false);
const error = ref("");
const label = ref("");
const confirmReset = ref(false);
const pendingAction = ref("");
const tokenDraft = ref("");
const tokenInput = ref(null);

const tokenReady = computed(() => Boolean(controlSession.token));
const summary = computed(() => state.value?.summary || {});
const archives = computed(() => state.value?.archives || []);
const activeText = computed(() => {
  const active = state.value?.active_runs || {};
  const total = Number(active.unified || 0) + Number(active.harness || 0) + Number(active.orchestration || 0);
  return total ? `仍有 ${total} 个运行中的任务，结束后才能开始新一轮。` : "";
});

const keepLabels = {
  linux_asset: "资产",
  asset_package: "组件",
  asset_service: "服务",
  device_connection: "设备连接",
  device_observation: "发现记录",
  runtime_sensor: "采集传感器",
  iot_device: "智能设备",
  iot_device_service: "设备服务",
  iot_device_component: "设备组件",
  scan_target: "扫描目标",
  lsm_policy: "LSM 策略",
  demo_target: "演示目标",
  openwrt_advisory: "OpenWrt 公告",
  iot_official_advisory: "官方公告",
  iot_device_advisory: "厂商公告"
};

const derivedLabels = {
  vulnerability_info: "漏洞情报",
  vulnerability_match: "匹配记录",
  risk_assessment: "风险对象",
  runtime_event: "运行时事件",
  trace_event: "追踪事件",
  trace_run: "追踪任务",
  unified_analysis_run: "研判运行",
  agent_orchestration_run: "编排运行",
  harness_run: "修复任务",
  harness_tool_call: "工具调用",
  analysis_report: "研判报告",
  agent_audit_record: "智能体审计",
  remediation_task: "处置任务",
  scan_run: "扫描记录",
  remediation_workflow_run: "修复工作流",
  risk_governance_event: "治理事件",
  applicability_correction: "适用性修正",
  security_evidence: "安全证据",
  collection_evidence: "采集证据",
  official_cve_record: "官方记录",
  investigation_request: "调查请求",
  device_vulnerability_match: "设备漏洞",
  runtime_evidence_job: "证据任务",
  threat_intel_source: "情报源"
};

const keepRows = computed(() =>
  Object.entries(state.value?.kept || {})
    .filter(([, value]) => Number(value) > 0)
    .map(([key, value]) => ({ key, label: keepLabels[key] || key, value: Number(value) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 9)
);
const keepTotal = computed(() => Object.values(state.value?.kept || {}).reduce((sum, value) => sum + Number(value || 0), 0));
const cacheCount = computed(() => Number(state.value?.cache?.vulnerability_intelligence_source || 0));
const derivedTotal = computed(() => Object.values(state.value?.derived || {}).reduce((sum, value) => sum + Number(value || 0), 0));
const clearRows = computed(() =>
  Object.entries(state.value?.derived || {})
    .filter(([, value]) => Number(value) > 0)
    .map(([key, value]) => ({ key, label: derivedLabels[key] || key, value: Number(value) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 9)
);

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const result = await api.get("/experiment/state", { timeout: 30000 });
    state.value = result.data || null;
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "本轮数据读取失败，请检查后端服务。";
  } finally {
    loading.value = false;
  }
  if (controlSession.token) {
    try {
      await api.get("/experiment/archives", {
        headers: { "X-Control-Token": controlSession.token },
        timeout: 10000
      });
    } catch (cause) {
      if (cause?.response?.status === 401) {
        controlSession.token = "";
        notify("操作令牌已失效，请重新输入", "error");
      }
    }
  }
}

function focusTokenInput() {
  nextTick(() => {
    tokenInput.value?.scrollIntoView({ block: "center", behavior: "smooth" });
    tokenInput.value?.focus({ preventScroll: true });
  });
}

function ensureToken(action = "") {
  if (controlSession.token) return true;
  pendingAction.value = action;
  notify("请先在面板里输入操作令牌，保存后会自动继续", "error");
  focusTokenInput();
  return false;
}

function saveInlineToken() {
  const value = tokenDraft.value.trim();
  if (!value) return;
  controlSession.token = value;
  tokenDraft.value = "";
  notify("操作令牌已保存，正在继续当前操作…", "success");
}

function clearInlineToken() {
  controlSession.token = "";
  pendingAction.value = "";
  notify("操作令牌已清除");
}

function scrollBodyTop() {
  window.requestAnimationFrame(() => {
    document.querySelector(".modal-body")?.scrollTo({ top: 0, behavior: "smooth" });
  });
}

function handleAuthError(cause, action) {
  if (cause?.response?.status !== 401) return false;
  controlSession.token = "";
  pendingAction.value = action;
  error.value = "";
  notify("操作令牌无效，请重新输入；保存后会自动继续", "error");
  focusTokenInput();
  return true;
}

async function archiveOnly() {
  if (!ensureToken("archive")) return;
  busy.value = true;
  error.value = "";
  notify("正在生成本轮结果存档，请稍候…", "info");
  try {
    await api.post("/experiment/archive", { label: label.value.trim() }, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 120000
    });
    notify("本轮结果已存档", "success");
    confirmReset.value = false;
    await load();
  } catch (cause) {
    if (handleAuthError(cause, "archive")) return;
    error.value = cause?.response?.data?.detail || "存档失败";
    notify(error.value, "error");
    scrollBodyTop();
  } finally {
    busy.value = false;
  }
}

function requestReset() {
  if (!ensureToken("reset")) return;
  confirmReset.value = true;
}

async function resetNow() {
  if (!ensureToken("reset")) return;
  busy.value = true;
  error.value = "";
  notify("正在归档本轮结果并清理衍生数据，请稍候…", "info");
  try {
    const result = await api.post("/experiment/reset", { label: label.value.trim(), archive: true }, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 180000
    });
    const cleared = result.data?.cleared || {};
    const total = Object.values(cleared).reduce((sum, value) => sum + Number(value || 0), 0);
    notify(`本轮结果已存档，已清理 ${formatNumber(total)} 条衍生数据；设备已保留`, "success");
    emit("close");
    window.setTimeout(() => { window.location.assign("/"); }, 600);
  } catch (cause) {
    if (handleAuthError(cause, "reset")) {
      confirmReset.value = false;
      return;
    }
    error.value = cause?.response?.data?.detail || "清理失败，未删除任何数据";
    notify(error.value, "error");
    confirmReset.value = false;
    scrollBodyTop();
  } finally {
    busy.value = false;
  }
}

async function downloadArchive(item) {
  if (!ensureToken()) return;
  try {
    const response = await api.get(`/experiment/archives/${encodeURIComponent(item.filename)}`, {
      responseType: "blob",
      headers: { "X-Control-Token": controlSession.token },
      timeout: 120000
    });
    const url = URL.createObjectURL(new Blob([response.data], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = item.filename;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (cause) {
    notify(cause?.response?.data?.detail || "存档下载失败", "error");
  }
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString("zh-CN") : "—";
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("zh-CN", { hour12: false });
}

watch(() => props.open, (open) => {
  if (!open) {
    pendingAction.value = "";
    return;
  }
  confirmReset.value = false;
  error.value = "";
  load();
}, { immediate: true });

watch(() => controlSession.token, (token) => {
  if (!token || !pendingAction.value) return;
  const action = pendingAction.value;
  pendingAction.value = "";
  if (action === "archive") archiveOnly();
  else if (action === "reset") requestReset();
});
</script>

<style scoped>
.exp-loading { display: flex; align-items: center; gap: 9px; padding: 22px 0; color: var(--muted); font-size: 12px; }
.exp-overview { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }
.exp-stat { padding: 11px 12px; border: 1px solid var(--line-soft); border-radius: 10px; background: #f9fbfe; }
.exp-stat span { display: block; color: var(--muted); font-size: 10.5px; }
.exp-stat b { display: block; margin-top: 2px; color: var(--ink); font-family: var(--font-num); font-size: 20px; font-weight: 800; letter-spacing: -0.02em; }
.exp-stat b.hot { color: var(--crit); }

.exp-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.exp-block { padding: 12px 14px; border: 1px solid var(--line-soft); border-radius: 11px; }
.exp-block.keep { background: linear-gradient(160deg, #f3fbf7, #fff); border-color: #d7f0e2; }
.exp-block.clear { background: linear-gradient(160deg, #fff7ef, #fff); border-color: #f8ddc2; }
.exp-block header { display: flex; align-items: center; gap: 6px; color: var(--ink); font-size: 12.5px; font-weight: 700; }
.exp-block header .icon { color: var(--low); }
.exp-block.clear header .icon { color: var(--high); }
.exp-block header span { margin-left: auto; color: var(--muted); font-family: var(--font-num); font-size: 11px; font-weight: 600; }
.exp-rows { display: grid; gap: 0; margin-top: 7px; }
.exp-rows > div { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 5px 0; border-bottom: 1px dashed rgba(100, 116, 139, 0.14); color: #5b6b82; font-size: 11.5px; }
.exp-rows > div:last-child { border-bottom: 0; }
.exp-rows b { color: var(--ink); font-family: var(--font-num); font-size: 11.5px; }
.exp-block p { margin: 8px 0 0; color: var(--muted); font-size: 10.5px; line-height: 1.5; }
.exp-empty { color: var(--muted); font-size: 11px; }

.exp-warning { display: flex; align-items: center; gap: 7px; margin-top: 12px; padding: 8px 10px; border: 1px solid var(--high-line); border-radius: 8px; background: var(--high-soft); color: #c2410c; font-size: 11.5px; font-weight: 600; }
.exp-token-box { padding: 10px 12px; border: 1px solid var(--high-line); border-radius: 10px; background: var(--high-soft); }
.exp-token-title { display: flex; align-items: center; gap: 6px; color: #c2410c; font-size: 12px; font-weight: 700; }
.exp-token-row { display: flex; gap: 8px; margin-top: 8px; }
.exp-token-row .input { flex: 1; height: 36px; background: #fff; }
.exp-token-row .btn { height: 36px; flex: 0 0 auto; }
.exp-token-hint { margin: 6px 0 0; color: #b45309; font-size: 10.5px; line-height: 1.5; }
.exp-token { display: flex; align-items: center; gap: 7px; margin: 8px 0 12px; color: var(--muted); font-size: 11px; }
.exp-token .dot { background: var(--high); }
.exp-token.ok .dot { background: var(--low); }
.exp-token .link { font-size: 11px; }

.exp-archives { min-height: max-content; border: 1px solid var(--line-soft); border-radius: 11px; overflow: hidden; }
.exp-archives-head { display: flex; align-items: center; justify-content: space-between; padding: 9px 13px; background: #f9fbfe; border-bottom: 1px solid var(--line-soft); }
.exp-archives-head b { color: var(--ink); font-size: 12px; }
.exp-archives-head span { color: var(--muted); font-size: 10.5px; }
.archive-item { display: flex; align-items: center; gap: 9px; padding: 9px 13px; border-bottom: 1px solid var(--line-soft); }
.archive-item:last-child { border-bottom: 0; }
.ai-icon { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 8px; background: var(--info-soft); color: var(--info); flex: 0 0 auto; }
.ai-copy { min-width: 0; flex: 1; display: grid; gap: 1px; }
.ai-copy b { color: var(--ink); font-size: 11.5px; font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ai-copy small { color: var(--muted); font-size: 10px; }
.ai-counts { color: var(--muted); font-size: 10.5px; white-space: nowrap; }
.archive-item .link { font-size: 11px; }

.exp-note { display: flex; align-items: flex-start; gap: 6px; margin: 0; color: var(--muted); font-size: 10.5px; line-height: 1.55; }
.exp-note .icon { margin-top: 1px; flex: 0 0 auto; }
.exp-note .mono { color: var(--ink-3); font-size: 10px; }
.exp-confirm { padding: 10px 12px; border: 1px solid var(--crit-line); border-radius: 9px; background: var(--crit-soft); }
.exp-confirm b { color: #b42318; font-size: 12.5px; }
.exp-confirm p { margin: 3px 0 0; color: #b42318; font-size: 11px; line-height: 1.55; }

@media (max-width: 900px) {
  .exp-overview { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .exp-columns { grid-template-columns: 1fr; }
}
</style>
