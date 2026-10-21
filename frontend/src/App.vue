<template>
  <AppSprite />
  <div class="shell" :class="{ 'shell--bare': bare }">
    <aside v-if="!bare" class="rail">
      <div class="brand">
        <span class="brand-mark">IG</span>
        <div><div class="brand-name">IoTGuard</div><div class="brand-sub">Security Console</div></div>
      </div>

      <div class="ws">
        <span class="ws-env">LAB</span>
        <div><div class="ws-name">物联网实验室</div><div class="ws-sub">{{ workspaceSub }}</div></div>
        <Icon name="chev-down" :size="12" />
      </div>

      <nav class="nav" aria-label="IoTGuard 导航">
        <template v-for="group in navigation" :key="group.label">
          <p class="nav-label">{{ group.label }}</p>
          <router-link
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            :class="{ active: isActive(item) }"
            :aria-current="isActive(item) ? 'page' : undefined"
          >
            <Icon :name="item.icon" />
            <span>{{ item.text }}</span>
            <span v-if="countFor(item)" class="nav-count" :class="{ hot: item.to === '/risks' }">{{ countFor(item) }}</span>
          </router-link>
        </template>
      </nav>

      <div class="rail-foot">
        <div class="user">
          <span class="avatar">WY</span>
          <div><div class="user-name">王工</div><div class="user-role">安全工程师</div></div>
          <Icon name="chev-right" :size="13" />
        </div>
        <div class="rail-meta"><span>v0.2.0</span><span>{{ buildLabel }}</span></div>
      </div>
    </aside>

    <div class="frame">
      <header class="topbar">
        <div v-if="bare" class="top-brand">
          <span class="brand-mark">IG</span><b>IoTGuard</b>
        </div>
        <div class="crumbs">
          <span>{{ rootLabel }}</span>
          <Icon name="chev-right" :size="12" />
          <b>{{ pageTitle }}</b>
        </div>

        <form v-if="!bare" class="search" role="search" @submit.prevent="submitSearch">
          <Icon name="search" :size="14" />
          <input ref="searchInput" v-model="search" type="search" placeholder="搜索 CVE、资产或任务" aria-label="全局搜索" />
          <span class="kbd">Ctrl K</span>
        </form>
        <router-link v-else class="link" to="/" style="font-size: 11px">返回工作台 <Icon name="chev-right" :size="12" /></router-link>

        <div class="top-right">
          <div class="health" :title="healthHint">
            <span v-for="segment in healthSegments" :key="segment.key" class="seg">
              <i class="dot" :class="segment.state" />
              <b v-if="segment.label">{{ segment.label }}</b>
              <span v-if="segment.value">{{ segment.value }}</span>
            </span>
          </div>
          <button class="icon-btn" type="button" aria-label="操作令牌" title="操作令牌" @click="ui.tokenOpen = true">
            <Icon name="lock" :size="15" />
          </button>
          <button class="icon-btn" type="button" aria-label="运行审计" title="运行审计" @click="router.push('/runtime')">
            <Icon name="bell" :size="15" />
            <i v-if="attention > 0" class="ping" />
          </button>
          <span class="top-avatar">WY</span>
        </div>
      </header>

      <main class="main" :class="{ 'main--bare': bare }">
        <router-view />
      </main>
    </div>
  </div>

  <Modal :open="ui.tokenOpen" title="操作令牌" description="令牌只保存在当前页面内存中，刷新即清除；不会写入本地存储。" @close="ui.tokenOpen = false">
    <label class="field-label" for="control-token">LINUXGUARD_CONTROL_TOKEN</label>
    <input id="control-token" v-model="tokenDraft" class="input" type="password" autocomplete="off" placeholder="粘贴后端控制令牌" @keyup.enter="saveToken" />
    <p class="field-hint">设备写、审批与部分审计查询需要令牌；只读页面不需要。</p>
    <template #footer>
      <button v-if="hasToken" class="btn" type="button" @click="clearToken">清除</button>
      <button class="btn" type="button" @click="ui.tokenOpen = false">取消</button>
      <button class="btn primary" type="button" :disabled="!tokenDraft.trim()" @click="saveToken">保存</button>
    </template>
  </Modal>

  <ToastHost />
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import AppSprite from "./components/AppSprite.vue";
import Icon from "./components/Icon.vue";
import Modal from "./components/Modal.vue";
import ToastHost from "./components/ToastHost.vue";
import { api, fetchHealth } from "./api";
import { controlSession } from "./api/controlSession";
import { notify, ui } from "./stores/ui";

const route = useRoute();
const router = useRouter();
const search = ref("");
const searchInput = ref(null);
const tokenDraft = ref("");
const health = ref(null);
const healthState = ref("checking");
const summary = ref({});
const buildLabel = ref("working-tree");
const now = ref(new Date());
let timer = null;
let clock = null;

const navigation = [
  {
    label: "工作台",
    items: [
      { to: "/", icon: "grid", text: "安全态势" },
      { to: "/assets", icon: "server", text: "资产与发现" },
      { to: "/risks", icon: "bug", text: "漏洞与风险" },
      { to: "/agents", icon: "cpu", text: "智能研判" },
      { to: "/repairs", icon: "wrench", text: "修复与验证" },
      { to: "/runtime", icon: "activity", text: "运行与审计" }
    ]
  },
  {
    label: "运营",
    items: [
      { to: "/reports", icon: "file", text: "报告与归档" },
      { to: "/soc", icon: "monitor", text: "SOC 态势大屏" }
    ]
  }
];

const bare = computed(() => Boolean(route.meta.bare));
const pageTitle = computed(() => route.meta.title || "安全态势");
const rootLabel = computed(() => route.meta.root || "安全工作台");
const hasToken = computed(() => Boolean(controlSession.token));

function isActive(item) {
  if (item.to === "/") return route.path === "/";
  return route.path === item.to || route.path.startsWith(`${item.to}/`);
}

function countFor(item) {
  if (item.to === "/risks") return summary.value.high_risk_vulnerabilities ? num(summary.value.high_risk_vulnerabilities) : "";
  if (item.to === "/repairs") return summary.value.pending_remediation_tasks ? num(summary.value.pending_remediation_tasks) : "";
  return "";
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString("zh-CN") : "";
}

const workspaceSub = computed(() => {
  const assets = Number(summary.value.asset_count);
  const nodes = health.value?.layers?.collection_node?.registered?.length;
  return `${Number.isFinite(assets) ? assets : "—"} 台资产${nodes ? ` · ${nodes} 个采集节点` : ""}`;
});

const attention = computed(() => Number(summary.value.pending_remediation_tasks || 0) + Number(summary.value.pending_human_review || 0));

const healthSegments = computed(() => {
  if (healthState.value === "checking") {
    return [
      { key: "service", label: "服务", state: "unknown", value: "检查中" },
      { key: "node", label: "节点", state: "unknown" },
      { key: "sensor", label: "传感器", state: "unknown" },
      { key: "evidence", label: "证据", state: "unknown" }
    ];
  }
  if (healthState.value !== "online") {
    return [
      { key: "service", label: "服务", state: "bad", value: "离线" },
      { key: "node", label: "节点", state: "unknown" },
      { key: "sensor", label: "传感器", state: "unknown" },
      { key: "evidence", label: "证据", state: "unknown" }
    ];
  }
  const node = health.value?.layers?.collection_node;
  const sensors = health.value?.layers?.sensors;
  const evidence = health.value?.layers?.runtime_evidence;
  const healthy = Number(sensors?.healthy || 0);
  const total = Number(sensors?.total || 0);
  return [
    { key: "service", label: "服务", state: "ok" },
    { key: "node", label: "节点", state: node?.configured === false ? "unknown" : node?.online === false ? "warn" : "ok", value: node?.registered?.length ? `${node.online_ids?.length || 0}/${node.registered.length}` : "" },
    { key: "sensor", label: "传感器", state: total === 0 ? "unknown" : healthy === total ? "ok" : healthy === 0 ? "bad" : "warn", value: total ? `${healthy}/${total}` : "" },
    { key: "evidence", label: "证据", state: evidence ? (evidence.fresh ? "ok" : "warn") : "unknown", value: evidence ? (evidence.fresh ? "新鲜" : "过期") : "" }
  ];
});

const healthHint = computed(() => {
  if (healthState.value === "checking") return "正在检查后端与采集链路";
  if (healthState.value !== "online") return "后端服务不可达：页面可浏览已有内容，写操作不可用";
  const node = health.value?.layers?.collection_node;
  const sensors = health.value?.layers?.sensors;
  const evidence = health.value?.layers?.runtime_evidence;
  return [
    "后端在线",
    node?.configured ? `采集节点 ${node.online_ids?.length || 0}/${node.registered?.length || 0} 在线` : "未配置采集节点",
    sensors ? `传感器 ${sensors.healthy}/${sensors.total} 健康` : "传感器状态未知",
    evidence ? (evidence.fresh ? "运行时证据新鲜" : "运行时证据已过期") : "运行时证据未知"
  ].join(" · ");
});

async function loadShellData() {
  try {
    const result = await fetchHealth();
    health.value = result;
    healthState.value = result?.status === "ok" ? "online" : "offline";
    if (result?.build?.revision) buildLabel.value = String(result.build.revision).slice(0, 12);
  } catch {
    healthState.value = "offline";
    health.value = null;
  }
  try {
    summary.value = (await api.get("/dashboard/summary", { timeout: 20000 })).data || {};
  } catch {
    /* the dashboard renders its own error state */
  }
}

function saveToken() {
  const value = tokenDraft.value.trim();
  if (!value) return;
  controlSession.token = value;
  tokenDraft.value = "";
  ui.tokenOpen = false;
  notify("操作令牌已保存到当前页面内存", "success");
}

function clearToken() {
  controlSession.token = "";
  tokenDraft.value = "";
  ui.tokenOpen = false;
  notify("操作令牌已清除");
}

function submitSearch() {
  const value = search.value.trim();
  if (!value) return;
  router.push({ path: "/risks", query: { q: value } });
}

function onKey(event) {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    searchInput.value?.focus();
  }
}

onMounted(() => {
  loadShellData();
  timer = window.setInterval(loadShellData, 30000);
  clock = window.setInterval(() => { now.value = new Date(); }, 10000);
  window.addEventListener("keydown", onKey);
});

onUnmounted(() => {
  window.clearInterval(timer);
  window.clearInterval(clock);
  window.removeEventListener("keydown", onKey);
});
</script>
