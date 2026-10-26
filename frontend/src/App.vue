<template>
  <AppSprite />
  <div class="shell">
    <aside class="rail" aria-label="IoTGuard 主导航">
      <router-link class="brand" to="/">
        <span class="brand-mark"><Icon name="shield" :size="21" /></span>
        <div>
          <div class="brand-name">IoTGuard</div>
          <div class="brand-sub">Security Console</div>
        </div>
      </router-link>

      <div class="ws" :title="workspaceSub">
        <span class="ws-env">LAB</span>
        <div>
          <div class="ws-name">物联网实验室</div>
          <div class="ws-sub">{{ workspaceSub }}</div>
        </div>
      </div>

      <nav class="nav">
        <router-link
          v-for="item in navigation"
          :key="item.to"
          :to="item.to"
          :class="{ active: isActive(item) }"
          :aria-current="isActive(item) ? 'page' : undefined"
        >
          <Icon :name="item.icon" :size="18" />
          <span>{{ item.text }}</span>
          <span v-if="countFor(item)" class="nav-count" :class="{ hot: item.to === '/risks' }">{{ countFor(item) }}</span>
        </router-link>
      </nav>

      <button class="rl-btn" style="margin: auto 12px 16px; width: calc(100% - 24px)" type="button" :disabled="refreshingRound || consoleState.starting || consoleState.workflow?.status === 'running'" @click="refreshRound">
        <Icon name="refresh" :size="14" />{{ refreshingRound ? "清理中…" : "刷新本轮" }}
      </button>

      <div class="rail-foot">
        <div class="user">
          <span class="avatar">AD</span>
          <div>
            <div class="user-name">admin</div>
            <div class="user-role">安全管理员</div>
          </div>
        </div>
        <div class="rail-meta"><span>v0.2.0</span><span>{{ buildLabel }}</span></div>
      </div>
    </aside>

    <div class="frame">
      <main class="main">
        <div v-if="controlSession.error" class="error-banner" role="alert">{{ controlSession.error }}</div>
        <router-view />
      </main>
    </div>
  </div>


  <Modal :open="ui.tokenOpen && !controlSession.managed" title="操作令牌" description="令牌只保存在当前页面内存中，刷新即清除；不会写入本地存储。" @close="ui.tokenOpen = false">
    <label class="field-label" for="control-token">LINUXGUARD_CONTROL_TOKEN</label>
    <input id="control-token" v-model="tokenDraft" class="input" type="password" autocomplete="off" placeholder="粘贴后端控制令牌" @keyup.enter="saveToken" />
    <p class="field-hint">设备写、审批、存档与清理需要令牌；令牌值见后端 <span class="mono">backend/.env</span> 的 <span class="mono">LINUXGUARD_CONTROL_TOKEN</span>。只读页面不需要。</p>
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
import { useRoute } from "vue-router";
import AppSprite from "./components/AppSprite.vue";
import Icon from "./components/Icon.vue";
import Modal from "./components/Modal.vue";
import ToastHost from "./components/ToastHost.vue";
import { api } from "./api";
import { controlSession } from "./api/controlSession";
import { notify, ui } from "./stores/ui";
import { consoleState, pollWorkflow } from "./stores/consoleWorkflow";

const route = useRoute();
const refreshingRound = ref(false);
let stopWorkflowPolling = null;

async function refreshRound() {
  if (refreshingRound.value) return;
  refreshingRound.value = true;
  consoleState.resetting = true;
  try {
    await api.post("/experiment/refresh", null, {
      headers: { "X-Experiment-Action": "refresh" }, timeout: 180000
    });
    window.location.assign("/");
  } catch (cause) {
    notify(cause?.response?.data?.detail || "清理失败，请稍后重试", "error");
  } finally {
    refreshingRound.value = false;
    consoleState.resetting = false;
  }
}
const tokenDraft = ref("");
const summary = ref({});
const buildLabel = ref("working-tree");
let timer = null;

const navigation = [
  { to: "/", icon: "home", text: "安全总览" },
  { to: "/assets", icon: "shield", text: "资产与发现" },
  { to: "/risks", icon: "bug", text: "漏洞与风险" },
  { to: "/agents", icon: "cpu", text: "智能研判中心" },
  { to: "/repairs", icon: "wrench", text: "修复与验证" },
  { to: "/runtime", icon: "activity", text: "运行监控与审计" }
];

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
  return `${Number.isFinite(assets) ? assets : "—"} 台资产 · 3 个节点`;
});

async function loadSummary() {
  try {
    summary.value = (await api.get("/dashboard/summary", { timeout: 20000 })).data || {};
  } catch {
    /* pages render their own error state */
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

onMounted(() => {
  stopWorkflowPolling = pollWorkflow();
  loadSummary();
  timer = window.setInterval(loadSummary, 30000);
});

onUnmounted(() => {
  stopWorkflowPolling?.();
  window.clearInterval(timer);
});
</script>
