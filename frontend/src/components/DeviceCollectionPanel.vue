<template>
  <section class="collect-panel" data-testid="collection-panel">
    <div v-if="!supported" class="warn-note">
      <Icon name="alert" :size="15" />
      <span>当前采集接口只支持已登记的 OpenWrt / Ubuntu 主机资产；该设备不是主机资产，不能在此发起连接或清单采集。</span>
    </div>

    <template v-else>
      <div class="collect-top">
        <div class="collect-identity">
          <b>{{ asset?.name || asset?.hostname || "未命名资产" }}</b>
          <span class="mono">{{ asset?.ip_address || "地址未记录" }}</span>
          <span class="chip" :class="inventory.valid ? 'low' : 'warn'" data-testid="inventory-state">
            <i class="dot" />{{ inventory.valid ? "有效软件清单" : "尚无有效清单" }}
          </span>
        </div>
        <button class="btn" type="button" :disabled="busy" @click="loadAll">
          <Icon name="refresh" :size="14" />{{ loading ? "读取中…" : "刷新状态" }}
        </button>
      </div>

      <div v-if="!hasToken" class="warn-note">
        <Icon name="lock" :size="15" />
        <span>连接配置、预检与采集都需要操作令牌。令牌只保存在当前页面内存中。</span>
        <button class="link" type="button" @click="ui.tokenOpen = true">设置操作令牌</button>
      </div>
      <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

      <div class="state-grid">
        <div class="state-card">
          <span>发现状态</span>
          <b>{{ asset ? "设备已登记" : "未登记" }}</b>
          <small>身份来源：{{ identitySourceLabel }} · 可信度 {{ ratioPct(identityConfidence, 0) }}</small>
        </div>
        <div class="state-card">
          <span>有效软件清单</span>
          <b :class="{ ok: inventory.valid }">{{ inventory.valid ? "已取得" : "未取得" }}</b>
          <small>{{ inventory.detail }}</small>
        </div>
        <div class="state-card">
          <span>最近成功采集</span>
          <b data-testid="last-success">{{ lastSuccessAt }}</b>
          <small>{{ lastSuccessHint }}</small>
        </div>
        <div class="state-card">
          <span>最近失败</span>
          <b :class="{ bad: Boolean(summary.lastFailure) }">{{ lastFailureAt }}</b>
          <small>{{ lastFailureHint }}</small>
        </div>
      </div>

      <div class="block">
        <div class="block-head">
          <div>
            <b>设备连接</b>
            <small>连接必须绑定当前选中资产；后端只保存认证环境变量名，不接收明文密码或私钥。</small>
          </div>
          <div class="row">
            <span v-if="connection" class="chip" :class="connection.enabled ? 'low' : 'muted'">{{ connection.enabled ? "已启用" : "已禁用" }}</span>
            <span v-if="connection" class="chip" :class="connection.identity_verified ? 'low' : 'warn'">{{ connection.identity_verified ? "身份已核验" : "身份待核验" }}</span>
            <button v-if="connection && !formOpen" class="btn" type="button" @click="startEdit">编辑连接</button>
            <button v-if="!connection && !formOpen" class="btn" type="button" @click="startCreate">配置连接</button>
          </div>
        </div>

        <div v-if="loading" class="empty-note">正在读取连接与采集记录…</div>

        <div v-else-if="connection && !formOpen" class="conn-grid" data-testid="connection-summary">
          <div><span>连接</span><b>{{ connection.label || `#${connection.id}` }}</b></div>
          <div><span>地址</span><b class="mono">{{ connection.host }}:{{ connection.port }}</b></div>
          <div><span>用户</span><b class="mono">{{ connection.username }}</b></div>
          <div><span>认证</span><b>{{ authLabel }}</b></div>
          <div><span>认证引用</span><b class="mono">{{ authReference || "未配置" }}</b></div>
          <div><span>主机指纹</span><b class="mono wrap">{{ connection.host_key_sha256 }}</b></div>
          <div class="wide"><span>资产绑定</span><b>{{ connection.asset_id === assetId ? `当前资产 #${assetId}` : "未绑定当前资产" }}</b></div>
        </div>

        <form v-if="!loading && (formOpen || !connection)" class="conn-form" @submit.prevent="saveConnectionForm">
          <div class="form-grid">
            <label>
              <span class="field-label">连接名称</span>
              <input v-model.trim="form.label" class="input" maxlength="128" placeholder="例如 OpenWrt-Lab 采集连接" />
            </label>
            <label>
              <span class="field-label">设备地址</span>
              <input v-model.trim="form.host" class="input mono" maxlength="64" placeholder="资产已登记的 IP 地址" />
              <small class="field-hint">必须与当前资产登记地址一致（{{ registeredAddress || "该资产未登记 IP" }}），防止把连接绑到其他设备。</small>
            </label>
            <label>
              <span class="field-label">SSH 端口</span>
              <input v-model.number="form.port" class="input mono" type="number" min="1" max="65535" />
            </label>
            <label>
              <span class="field-label">SSH 用户</span>
              <input v-model.trim="form.username" class="input mono" maxlength="64" placeholder="root" />
            </label>
            <label>
              <span class="field-label">认证方式</span>
              <select v-model="form.auth_type" class="select" @change="onAuthTypeChange">
                <option value="ssh_key">SSH 密钥（环境变量引用）</option>
                <option value="password">密码（环境变量引用）</option>
              </select>
            </label>
            <label v-if="form.auth_type === 'ssh_key'">
              <span class="field-label">私钥路径环境变量名</span>
              <input v-model.trim="form.key_path_env" class="input mono" maxlength="96" placeholder="LINUXGUARD_DEVICE_OPENWRT_LAB_KEY" />
              <small class="field-hint">只填写变量名；变量值（路径）由采集节点自身解析，前端与 API 都不接收私钥内容。</small>
            </label>
            <label v-else>
              <span class="field-label">密码环境变量名</span>
              <input v-model.trim="form.credential_env" class="input mono" maxlength="96" placeholder="LINUXGUARD_DEVICE_EXAMPLE_PASSWORD" />
              <small class="field-hint">只填写变量名；不要把密码本身输入页面、URL 或日志。</small>
            </label>
            <label v-if="form.auth_type === 'ssh_key'">
              <span class="field-label">密钥口令环境变量名（可选）</span>
              <input v-model.trim="form.key_passphrase_env" class="input mono" maxlength="96" placeholder="留空表示密钥无口令" />
            </label>
            <label class="wide">
              <span class="field-label">SSH 主机公钥指纹（SHA256）</span>
              <input v-model.trim="form.host_key_sha256" class="input mono" maxlength="80" placeholder="SHA256:..." />
              <small class="field-hint">这是公开的主机公钥指纹，不是私钥。必须与设备实际指纹一致；不匹配时后端会阻止连接。</small>
            </label>
            <label class="checkbox-row wide">
              <input v-model="form.enabled" type="checkbox" /> 启用此连接
            </label>
          </div>
          <div class="form-actions">
            <span class="field-hint">绑定资产：#{{ assetId }} · {{ asset?.name || asset?.hostname }}</span>
            <div class="row">
              <button v-if="connection" class="btn" type="button" :disabled="saving" @click="cancelEdit">取消</button>
              <button class="btn primary" type="submit" :disabled="saving" data-testid="save-connection">{{ saving ? "保存中…" : connection ? "保存修改" : "创建连接" }}</button>
            </div>
          </div>
        </form>
      </div>

      <div v-if="connection && !formOpen" class="block">
        <div class="block-head">
          <div>
            <b>预检与软件清单采集</b>
            <small>预检只核对后端元数据，不打开网络连接；实际连通性与清单有效性以采集任务终态为准。</small>
          </div>
        </div>
        <div class="action-row">
          <button class="btn" type="button" :disabled="busy || activeRun" @click="runPreflight" data-testid="preflight">
            <Icon name="shield" :size="14" />{{ checking ? "预检中…" : "连接预检" }}
          </button>
          <button class="btn primary" type="button" :disabled="busy || activeRun || !preflight?.ready" @click="startCollection" data-testid="start-collection">
            <Icon name="download" :size="14" />{{ submitting ? "提交中…" : "发起软件清单采集" }}
          </button>
          <button v-if="currentRun && currentRun.status === 'pending' && !submitting" class="btn" type="button" @click="retryExecute">重试执行</button>
          <span v-if="activeRun" class="chip accent"><i class="dot" />任务进行中</span>
          <span v-else-if="preflight && !preflight.ready" class="chip warn">预检未通过</span>
        </div>
        <p class="field-hint">
          采集任务由后端固定只读 Collector 执行；重复点击不会重复创建同一请求。任务在服务端继续执行，离开页面会停止前端轮询，不会停止任务。
        </p>

        <div v-if="preflight" class="preflight" data-testid="preflight-result">
          <div class="preflight-head">
            <span class="chip" :class="preflight.ready ? 'low' : 'crit'">{{ preflight.ready ? "预检通过（仅元数据）" : "预检未通过" }}</span>
            <span>network_attempted={{ preflight.network_attempted ? "true" : "false" }}</span>
            <span>key_loaded={{ preflight.key_loaded ? "true" : "false" }}</span>
            <span>SSH 指纹：{{ preflight.ssh_host_identity || "not_attempted" }}</span>
          </div>
          <ul class="check-list">
            <li v-for="check in checks" :key="check.key">
              <span class="dot" :class="check.ok ? 'ok' : 'warn'" />
              <span>{{ check.label }}</span>
              <b :class="{ bad: !check.ok }">{{ check.ok ? "通过" : "不满足" }}</b>
              <small>{{ check.note }}</small>
            </li>
          </ul>
        </div>
      </div>

      <div v-if="currentRun" ref="runBlockRef" class="block run-block" data-testid="current-run">
        <div class="block-head">
          <div>
            <b>本次采集任务</b>
            <small class="mono" data-testid="run-id">{{ currentRun.id }}</small>
          </div>
          <span class="chip" :class="collectionStatusTone(currentRun.status)" data-testid="run-status">{{ collectionStatusText(currentRun.status) }}</span>
        </div>
        <div class="progress-track"><i :style="{ width: progressWidth }" :class="collectionStatusTone(currentRun.status)" /></div>
        <div class="run-grid">
          <div><span>状态</span><b>{{ collectionStatusText(currentRun.status) }}</b></div>
          <div><span>开始</span><b>{{ formatBackendTime(currentRun.started_at || currentRun.created_at) }}</b></div>
          <div><span>完成</span><b>{{ formatBackendTime(currentRun.completed_at, "尚未完成") }}</b></div>
          <div><span>耗时</span><b>{{ runDuration(currentRun) }}</b></div>
          <div><span>组件</span><b data-testid="run-package-count">{{ currentRun.result?.package_count ?? "—" }}</b></div>
          <div><span>执行节点</span><b class="mono">{{ currentRun.result?.execution_node || currentRun.node?.id || "—" }}</b></div>
          <div><span>SSH 指纹</span><b>{{ currentRun.result?.ssh_host_identity || "未记录" }}</b></div>
          <div><span>SSH 认证</span><b>{{ currentRun.result?.ssh_authentication || "未记录" }}</b></div>
        </div>
        <div v-if="currentRun.status === 'queued_remote'" class="warn-note">
          <Icon name="alert" :size="15" />
          <span>任务已转交 Linux 采集节点，正在等待节点领取。节点离线时任务会保持排队，不会用旧清单冒充本轮结果。</span>
        </div>
        <div v-if="currentRunError" class="error-banner" role="alert">
          <Icon name="alert" :size="15" />
          <span><b>{{ currentRunError.code || "采集失败" }}</b> · {{ currentRunError.message }}</span>
        </div>
        <div v-if="pollError" class="field-hint">状态查询暂时失败：{{ pollError }}；前端会继续重试。</div>
        <div v-if="currentRun.tool_calls?.length" class="tool-list">
          <div v-for="call in currentRun.tool_calls" :key="call.id" class="tool-row">
            <span class="mono">{{ call.tool || "collect_inventory" }}</span>
            <span class="chip" :class="collectionStatusTone(call.status)">{{ call.status || "未知" }}</span>
            <span>{{ formatBackendTime(call.started_at) }}</span>
            <span>{{ call.duration_ms != null ? `${call.duration_ms} ms` : "—" }}</span>
          </div>
        </div>
      </div>

      <div class="block">
        <div class="block-head">
          <div>
            <b>最近采集记录</b>
            <small>仅列出软件清单任务；运行时日志采集不计入“最近成功清单”。</small>
          </div>
          <span class="chip muted">{{ recentRuns.length }} 条</span>
        </div>
        <div v-if="!recentRuns.length" class="empty-note">尚无软件清单采集记录。</div>
        <div v-else class="table-wrap" data-testid="recent-runs">
          <table>
            <thead><tr><th>创建时间</th><th>状态</th><th>结果</th><th>耗时</th><th>失败原因</th></tr></thead>
            <tbody>
              <tr v-for="run in recentRuns" :key="run.id" :data-run-id="run.id">
                <td class="nowrap">{{ formatBackendTime(run.created_at) }}</td>
                <td><span class="chip" :class="collectionStatusTone(run.status)">{{ collectionStatusText(run.status) }}</span></td>
                <td>{{ runResultLabel(run) }}</td>
                <td class="nowrap">{{ runDuration(run) }}</td>
                <td class="wrap">
                  <template v-if="runError(run)">
                    <b class="mono">{{ runError(run).code || "失败" }}</b>
                    <small>{{ runError(run).message }}</small>
                  </template>
                  <span v-else class="dim">—</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </section>
</template>

<script setup>
import { computed, nextTick, onUnmounted, ref, watch } from "vue";
import Icon from "./Icon.vue";
import { fetchAsset } from "../api";
import { controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { ratioPct } from "../utils/format";
import {
  connectionForAsset,
  collectionStatusText,
  collectionStatusTone,
  createRequestId,
  formatBackendTime,
  inventoryRuns,
  inventoryState,
  isActiveRun,
  isTerminalRun,
  parseBackendTime,
  preflightChecks,
  runDuration,
  runResultLabel,
  runError,
  summarizeRuns,
  timeAgoText
} from "../utils/deviceCollection";
import {
  createCollectionRun,
  errorMessage,
  executeCollectionRun,
  fetchCollectionRun,
  fetchCollectionRuns,
  fetchConnections,
  preflightConnection,
  saveConnection
} from "../api/deviceOperations";

const props = defineProps({
  asset: { type: Object, default: null },
  open: { type: Boolean, default: true }
});
const emit = defineEmits(["updated"]);

const connections = ref([]);
const connection = ref(null);
const assetDetail = ref(null);
const runs = ref([]);
const loading = ref(false);
const saving = ref(false);
const checking = ref(false);
const submitting = ref(false);
const formOpen = ref(false);
const error = ref("");
const pollError = ref("");
const preflight = ref(null);
const currentRun = ref(null);
const runBlockRef = ref(null);
const pollTimer = ref(null);
const terminalHandled = ref("");

const form = ref(blankForm());

const assetId = computed(() => Number(props.asset?.asset_id || props.asset?.id || 0));
const supported = computed(() => {
  const distribution = props.asset?.distribution || (props.asset?.ecosystem === "openwrt" ? "openwrt" : "");
  return Number.isFinite(assetId.value) && assetId.value > 0 && ["openwrt", "ubuntu"].includes(distribution);
});
const hasToken = computed(() => Boolean(controlSession.token));
const busy = computed(() => loading.value || saving.value || checking.value || submitting.value);
const activeRun = computed(() => isActiveRun(currentRun.value));
const checks = computed(() => preflightChecks(preflight.value));
const summary = computed(() => summarizeRuns(runs.value));
const recentRuns = computed(() => inventoryRuns(runs.value).slice().sort((left, right) => {
  const a = parseBackendTime(left.created_at)?.getTime() || 0;
  const b = parseBackendTime(right.created_at)?.getTime() || 0;
  return b - a;
}).slice(0, 8));
const packageCount = computed(() => {
  const detail = assetDetail.value;
  if (detail && Array.isArray(detail.packages)) return detail.packages.length;
  return Number(props.asset?.component_count || 0);
});
const inventory = computed(() => inventoryState(assetDetail.value || props.asset, packageCount.value));
const currentRunError = computed(() => runError(currentRun.value));
const progressWidth = computed(() => {
  if (!currentRun.value) return "0%";
  if (isTerminalRun(currentRun.value.status)) return "100%";
  if (currentRun.value.status === "running") return "66%";
  if (currentRun.value.status === "queued_remote") return "45%";
  return "22%";
});
const authLabel = computed(() => connection.value?.auth_type === "ssh_key" ? "SSH 密钥（环境变量引用）" : "密码（环境变量引用）");
const authReference = computed(() => connection.value?.auth_type === "ssh_key" ? connection.value?.key_path_env : connection.value?.credential_env);
const identityConfidence = computed(() => assetDetail.value?.identity_confidence ?? props.asset?.identity_confidence ?? null);
const registeredAddress = computed(() => String(props.asset?.ip_address || assetDetail.value?.ip_address || "").trim());
const identitySourceLabel = computed(() => {
  const source = assetDetail.value?.identity_source || props.asset?.identity_source || "";
  return {
    pinned_ssh_inventory: "固定 SSH 清单",
    authenticated_collection_node: "认证采集节点",
    uploaded_inventory: "人工导入清单",
    http_identity: "HTTP 身份端点",
    banner_fingerprint: "Banner 指纹"
  }[source] || source || "未记录";
});
const lastSuccessAt = computed(() => {
  const run = summary.value.lastSuccess;
  if (run) return formatBackendTime(run.completed_at || run.created_at);
  const fallback = assetDetail.value?.inventory_collected_at || props.asset?.inventory_collected_at;
  return fallback ? `${formatBackendTime(fallback)}（台账）` : "尚无成功记录";
});
const lastSuccessHint = computed(() => {
  const run = summary.value.lastSuccess;
  if (run) return `任务 ${run.id.slice(0, 10)}… · ${timeAgoText(run.completed_at || run.created_at)}`;
  const fallback = assetDetail.value?.inventory_collected_at || props.asset?.inventory_collected_at;
  return fallback ? "来自台账清单时间；该资产暂无本系统清单任务记录" : "尚无成功采集记录";
});
const lastFailureAt = computed(() => {
  const run = summary.value.lastFailure;
  return run ? formatBackendTime(run.created_at) : "无失败记录";
});
const lastFailureHint = computed(() => {
  const run = summary.value.lastFailure;
  if (!run) return "最近软件清单任务没有失败记录";
  const failure = runError(run);
  return [failure?.code, failure?.message].filter(Boolean).join(" · ") || "失败原因未记录";
});

function blankForm() {
  return {
    label: "",
    host: "",
    port: 22,
    username: "root",
    auth_type: "ssh_key",
    credential_env: "",
    key_path_env: "",
    key_passphrase_env: "",
    host_key_sha256: "",
    enabled: true
  };
}

function resetForm() {
  const row = connection.value;
  form.value = {
    label: row?.label || (props.asset?.name ? `${props.asset.name} 采集连接` : "设备采集连接"),
    host: row?.host || props.asset?.ip_address || "",
    port: row?.port || 22,
    username: row?.username || "root",
    auth_type: row?.auth_type || "ssh_key",
    credential_env: row?.credential_env || "",
    key_path_env: row?.key_path_env || "",
    key_passphrase_env: row?.key_passphrase_env || "",
    host_key_sha256: row?.host_key_sha256 || "",
    enabled: row?.enabled !== false
  };
}

function startCreate() {
  connection.value = null;
  resetForm();
  formOpen.value = true;
  error.value = "";
}

function startEdit() {
  resetForm();
  formOpen.value = true;
  error.value = "";
}

function cancelEdit() {
  if (!connection.value) return;
  formOpen.value = false;
  resetForm();
  error.value = "";
}

function onAuthTypeChange() {
  if (form.value.auth_type === "ssh_key") form.value.credential_env = "";
  else {
    form.value.key_path_env = "";
    form.value.key_passphrase_env = "";
  }
}

function requireToken() {
  if (controlSession.token) return true;
  notify("请先设置操作令牌", "error");
  ui.tokenOpen = true;
  return false;
}

async function loadAll() {
  if (!supported.value) return;
  stopPolling();
  currentRun.value = null;
  terminalHandled.value = "";
  loading.value = true;
  error.value = "";
  pollError.value = "";
  preflight.value = null;
  try {
    const [rows, detail] = await Promise.all([
      fetchConnections(),
      fetchAsset(assetId.value).catch(() => null)
    ]);
    connections.value = Array.isArray(rows) ? rows : [];
    connection.value = connectionForAsset(connections.value, assetId.value);
    assetDetail.value = detail;
    if (connection.value) {
      formOpen.value = false;
      form.value = { ...blankForm(), ...form.value };
      runs.value = (await fetchCollectionRuns(connection.value.id)) || [];
      const active = inventoryRuns(runs.value).find((row) => isActiveRun(row));
      if (active) {
        currentRun.value = active;
        startPolling();
      }
      resetForm();
    } else {
      runs.value = [];
      formOpen.value = true;
      resetForm();
    }
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    loading.value = false;
  }
}

function validateForm() {
  const value = form.value;
  if (!value.host.trim()) return "请填写设备地址";
  if (value.host.trim().length > 64) return "设备地址不能超过 64 个字符";
  if (registeredAddress.value && value.host.trim() !== registeredAddress.value) {
    return `设备地址必须与当前资产登记地址 ${registeredAddress.value} 一致，不能用当前资产操作其他设备`;
  }
  if (!Number.isInteger(Number(value.port)) || Number(value.port) < 1 || Number(value.port) > 65535) return "SSH 端口必须在 1–65535 之间";
  if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(value.username.trim())) return "SSH 用户只允许字母、数字、下划线、点和短横线";
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(value.host_key_sha256.trim())) return "请输入完整的 SHA256 主机公钥指纹（SHA256: 加 43 位 Base64 字符）";
  if (value.auth_type === "ssh_key") {
    if (!/^LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}$/.test(value.key_path_env.trim())) return "私钥路径环境变量名必须形如 LINUXGUARD_DEVICE_OPENWRT_LAB_KEY";
    if (value.key_passphrase_env.trim() && !/^LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}$/.test(value.key_passphrase_env.trim())) return "密钥口令环境变量名格式无效";
  } else if (!/^LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}$/.test(value.credential_env.trim())) {
    return "密码环境变量名必须形如 LINUXGUARD_DEVICE_EXAMPLE_PASSWORD";
  }
  return "";
}

async function saveConnectionForm() {
  if (!requireToken()) return;
  const problem = validateForm();
  if (problem) {
    error.value = problem;
    notify(problem, "error");
    return;
  }
  saving.value = true;
  error.value = "";
  try {
    const value = form.value;
    const payload = {
      asset_id: assetId.value,
      label: value.label.trim(),
      host: value.host.trim(),
      port: Number(value.port),
      username: value.username.trim(),
      auth_type: value.auth_type,
      credential_env: value.auth_type === "password" ? value.credential_env.trim() : "",
      key_path_env: value.auth_type === "ssh_key" ? value.key_path_env.trim() : "",
      key_passphrase_env: value.auth_type === "ssh_key" ? value.key_passphrase_env.trim() : "",
      host_key_sha256: value.host_key_sha256.trim(),
      enabled: Boolean(value.enabled)
    };
    const saved = await saveConnection(payload, connection.value?.id);
    if (Number(saved?.asset_id) !== assetId.value) {
      throw new Error("后端返回的连接未绑定当前资产，已拒绝继续");
    }
    connection.value = saved;
    formOpen.value = false;
    preflight.value = null;
    resetForm();
    await refreshRuns();
    notify("设备连接已保存", "success");
  } catch (cause) {
    error.value = errorMessage(cause);
    notify(error.value, "error");
  } finally {
    saving.value = false;
  }
}

function connectionMatchesAsset() {
  if (!connection.value) return false;
  if (Number(connection.value.asset_id) !== assetId.value) {
    error.value = "该连接未绑定当前选中资产，已拒绝操作";
    notify(error.value, "error");
    return false;
  }
  return true;
}

async function runPreflight() {
  if (!connection.value || checking.value) return;
  if (!connectionMatchesAsset()) return;
  if (!requireToken()) return;
  checking.value = true;
  preflight.value = null;
  error.value = "";
  try {
    const result = await preflightConnection(connection.value.id);
    if (Number(result?.asset_id) !== assetId.value) throw new Error("预检结果未绑定当前资产，已拒绝展示");
    preflight.value = result;
    notify(result?.ready ? "连接预检通过（仅元数据）" : "连接预检未通过，请查看检查项", result?.ready ? "success" : "error");
  } catch (cause) {
    error.value = errorMessage(cause);
    notify(error.value, "error");
  } finally {
    checking.value = false;
  }
}

async function startCollection() {
  if (!connection.value || submitting.value || activeRun.value) return;
  if (!connectionMatchesAsset()) return;
  if (!requireToken()) return;
  if (!preflight.value?.ready) {
    notify("请先完成并通过连接预检", "error");
    return;
  }
  submitting.value = true;
  error.value = "";
  pollError.value = "";
  terminalHandled.value = "";
  try {
    const requestId = createRequestId(assetId.value);
    const created = await createCollectionRun(connection.value.id, requestId);
    if (Number(created?.asset_id) !== assetId.value || Number(created?.connection_id) !== Number(connection.value.id)) {
      throw new Error("后端返回的采集任务未绑定当前资产/连接，已拒绝执行");
    }
    currentRun.value = created;
    await nextTick();
    runBlockRef.value?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    startPolling();
    const executed = await executeCollectionRun(created.id);
    applyRun(executed);
  } catch (cause) {
    error.value = errorMessage(cause);
    notify(error.value, "error");
    if (currentRun.value) startPolling();
  } finally {
    submitting.value = false;
    await refreshRunsQuiet();
  }
}

function applyRun(run) {
  if (!run) return;
  if (currentRun.value && currentRun.value.id !== run.id) return;
  currentRun.value = run;
  if (isTerminalRun(run.status)) {
    stopPolling();
    handleTerminal(run);
  }
}

async function handleTerminal(run) {
  if (!run || terminalHandled.value === run.id) return;
  terminalHandled.value = run.id;
  stopPolling();
  if (run.status === "completed") {
    notify(`软件清单采集完成 · ${run.result?.package_count ?? 0} 个组件`, "success");
  } else {
    const failure = runError(run);
    notify(`软件清单采集失败：${failure?.message || run.status}`, "error");
  }
  await refreshRunsQuiet();
  try {
    const detail = await fetchAsset(assetId.value);
    if (detail) assetDetail.value = detail;
  } catch {
    /* keep the last known detail; the run history carries the outcome */
  }
  emit("updated", assetDetail.value);
}

async function retryExecute() {
  if (!currentRun.value || submitting.value) return;
  if (!requireToken()) return;
  submitting.value = true;
  error.value = "";
  try {
    const executed = await executeCollectionRun(currentRun.value.id);
    applyRun(executed);
  } catch (cause) {
    error.value = errorMessage(cause);
    notify(error.value, "error");
    startPolling();
  } finally {
    submitting.value = false;
    await refreshRunsQuiet();
  }
}

function startPolling() {
  stopPolling();
  if (!currentRun.value) return;
  pollTimer.value = window.setInterval(pollOnce, 1800);
  pollOnce();
}

function stopPolling() {
  if (pollTimer.value != null) {
    window.clearInterval(pollTimer.value);
    pollTimer.value = null;
  }
}

async function pollOnce() {
  const id = currentRun.value?.id;
  if (!id) return;
  try {
    const latest = await fetchCollectionRun(id);
    if (currentRun.value?.id !== id) return;
    pollError.value = "";
    applyRun(latest);
  } catch (cause) {
    pollError.value = errorMessage(cause);
  }
}

async function refreshRuns() {
  if (!connection.value) {
    runs.value = [];
    return;
  }
  runs.value = (await fetchCollectionRuns(connection.value.id)) || [];
}

async function refreshRunsQuiet() {
  try {
    await refreshRuns();
  } catch {
    /* history refresh is best effort; the current run state is already shown */
  }
}

watch(() => props.open, (open) => {
  if (open) loadAll();
  else stopPolling();
}, { immediate: true });

watch(() => props.asset?.id || props.asset?.asset_id, () => {
  if (props.open) loadAll();
});

watch(() => form.value.auth_type, () => onAuthTypeChange());

onUnmounted(stopPolling);
</script>

<style scoped>
.collect-panel { display: grid; gap: 12px; }
.collect-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.collect-identity { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
.collect-identity b { color: var(--ink); font-size: 14px; }
.collect-identity .mono { color: var(--muted); font-size: 13.5px; }
.state-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
.state-card { display: grid; gap: 4px; padding: 8px 12px; border: 1px solid var(--line-soft); border-radius: 10px; background: #f9fbfe; min-width: 0; }
.state-card > span { color: var(--muted); font-size: 12.5px; }
.state-card b { color: var(--ink); font-size: 14px; word-break: break-word; }
.state-card b.ok { color: #067647; }
.state-card b.bad { color: #d92d20; }
.state-card small { color: #64748b; font-size: 12.5px; line-height: 1.5; }
.block { display: grid; gap: 8px; padding: 12px 0 0; border-top: 1px solid var(--line-soft); }
.block-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.block-head > div:first-child { display: grid; gap: 2px; min-width: 0; }
.block-head b { color: var(--ink); font-size: 14px; }
.block-head small { color: #64748b; font-size: 12.5px; line-height: 1.5; }
.block-head .row { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; justify-content: flex-end; }
.conn-grid, .run-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0; border-top: 1px solid var(--line-soft); }
.conn-grid > div, .run-grid > div { padding: 8px 0; border-bottom: 1px solid var(--line-soft); min-width: 0; }
.conn-grid > div:nth-child(odd), .run-grid > div:nth-child(odd) { padding-right: 12px; }
.conn-grid span, .run-grid span { display: block; color: var(--muted); font-size: 12.5px; }
.conn-grid b, .run-grid b { display: block; margin-top: 2px; color: var(--ink); font-size: 13.5px; word-break: break-all; }
.conn-grid .wide { grid-column: 1 / -1; }
.conn-form { display: grid; gap: 8px; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 12px; }
.form-grid label { display: grid; gap: 4px; min-width: 0; }
.form-grid .wide { grid-column: 1 / -1; }
.form-actions { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.form-actions .row { display: flex; gap: 8px; }
.action-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.preflight { display: grid; gap: 8px; padding: 8px 12px; border: 1px solid var(--line-soft); border-radius: 10px; background: #f9fbfe; }
.preflight-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; color: var(--muted); font-size: 12.5px; }
.check-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 4px 12px; margin: 0; padding: 0; list-style: none; }
.check-list li { display: grid; grid-template-columns: 8px 1fr auto; gap: 4px; align-items: center; min-width: 0; }
.check-list li small { grid-column: 2 / -1; color: #64748b; font-size: 12.5px; line-height: 1.4; }
.check-list b { color: #067647; font-size: 12.5px; }
.check-list b.bad { color: #d92d20; }
.progress-track { height: 6px; border-radius: 999px; background: #eef3fa; overflow: hidden; }
.progress-track i { display: block; height: 100%; border-radius: 999px; background: #2f6fed; transition: width 220ms ease; }
.progress-track i.low { background: var(--low); }
.progress-track i.crit { background: #ef4444; }
.progress-track i.accent { background: #2f6fed; }
.tool-list { display: grid; gap: 4px; }
.tool-row { display: grid; grid-template-columns: 1.2fr auto auto auto; gap: 8px; align-items: center; color: #64748b; font-size: 12.5px; }
.warn-note { display: flex; align-items: flex-start; gap: 8px; padding: 8px 12px; border-radius: 9px; background: var(--high-soft); color: #9a3412; font-size: 13.5px; line-height: 1.55; }
.warn-note .link { color: #9a3412; text-decoration: underline; }
.empty-note { color: var(--muted); font-size: 13.5px; }
.wrap { overflow-wrap: anywhere; }
@media (max-width: 720px) {
  .state-grid, .form-grid, .check-list, .conn-grid, .run-grid { grid-template-columns: 1fr; }
  .conn-grid .wide, .form-grid .wide { grid-column: auto; }
}
</style>
