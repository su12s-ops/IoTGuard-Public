<template>
  <div v-if="ui.routeLoading" class="route-progress" role="status" aria-label="页面加载中"></div>
  <AppSprite />
  <div class="shell">
    <aside class="rail" aria-label="IoTGuard 主导航">
      <router-link class="brand" to="/">
        <span class="brand-mark"><Icon name="shield" :size="21" /></span>
        <div>
          <div class="brand-name">IoTGuard</div>
          <div class="brand-sub">Security Console</div>
        </div>
        <Icon name="menu" :size="17" style="margin-left: auto; color: #6f83a0" />
      </router-link>

      <div class="ws" :title="workspaceSub">
        <span class="ws-env">LAB</span>
        <div>
          <div class="ws-name">物联网实验室</div>
          <div class="ws-sub">{{ workspaceSub }}</div>
        </div>
        <Icon name="chev-down" :size="13" />
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

      <div class="rail-lifecycle" role="button" tabindex="0" @click="ui.experimentOpen = true" @keydown.enter="ui.experimentOpen = true" @keydown.space.prevent="ui.experimentOpen = true">
        <div class="rl-head"><Icon name="archive" :size="14" />本轮实验</div>
        <p class="rl-note">设备保留 · 结果可归档<br />清理后可开始新一轮</p>
        <button class="rl-btn" type="button" @click.stop="ui.experimentOpen = true">
          <Icon name="sliders" :size="13" />管理与新一轮
        </button>
      </div>

      <div class="rail-foot">
        <div class="user">
          <span class="avatar">AD</span>
          <div>
            <div class="user-name">admin</div>
            <div class="user-role">安全管理员</div>
          </div>
          <Icon name="chev-right" :size="13" />
        </div>
        <div class="rail-meta"><span>v0.2.0</span><span>{{ buildLabel }}</span></div>
      </div>
    </aside>

    <div class="frame">
      <main class="main">
        <router-view />
      </main>
    </div>
  </div>

  <ExperimentModal :open="ui.experimentOpen" @close="ui.experimentOpen = false" />

  <Modal :open="ui.tokenOpen" title="操作令牌" description="令牌只保存在当前页面内存中，刷新即清除；不会写入本地存储。" @close="ui.tokenOpen = false">
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
import ExperimentModal from "./components/ExperimentModal.vue";
import ToastHost from "./components/ToastHost.vue";
import { api } from "./api";
import { controlSession } from "./api/controlSession";
import { notify, ui } from "./stores/ui";

const route = useRoute();
const tokenDraft = ref("");
const summary = ref({});
// 构建标识：本仓库不是 git 仓库，后端只会返回 working-tree / unknown 这类内部状态字符串。
// 这类值不该出现在展示层（投影上看着像没打包），统一归一成「本地构建」；
// 将来接入真实构建号时，只要给 buildRaw 赋值即可原样显示。
const buildRaw = ref("working-tree");
const buildLabel = computed(() => {
  const raw = String(buildRaw.value || "").trim();
  if (!raw || /^(working-tree|unknown|dev|none|null|undefined)$/i.test(raw)) return "本地构建";
  return raw;
});
let timer = null;

const navigation = [
  { to: "/", icon: "home", text: "安全总览" },
  { to: "/assets", icon: "shield", text: "资产与发现" },
  { to: "/devices", icon: "camera", text: "设备接入" },
  { to: "/hosts", icon: "server", text: "主机资产" },
  { to: "/risks", icon: "bug", text: "漏洞与风险" },
  { to: "/verdict", icon: "target", text: "四态判决" },
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
  // 原实现写死「3 个节点」，那是没有数据支撑的假数字；现在只报后端真实台账：
  // 主机线（LinuxAsset）+ 设备线（IotDevice）。
  const hosts = Number(summary.value.linux_asset_count ?? summary.value.asset_count);
  const devices = Number(summary.value.iot_device_count);
  if (!Number.isFinite(hosts) && !Number.isFinite(devices)) return "台账未就绪";
  const total = (Number.isFinite(hosts) ? hosts : 0) + (Number.isFinite(devices) ? devices : 0);
  return `${total} 台资产 · ${Number.isFinite(hosts) ? hosts : 0} 主机 / ${Number.isFinite(devices) ? devices : 0} 设备`;
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
  loadSummary();
  timer = window.setInterval(loadSummary, 30000);
});

onUnmounted(() => {
  window.clearInterval(timer);
});
</script>
