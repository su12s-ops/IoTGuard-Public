<template>
  <div class="top-actions">
    <form class="search" role="search" @submit.prevent="submit">
      <Icon name="search" :size="16" />
      <input ref="input" v-model="q" type="search" placeholder="搜索资产、CVE、组件…" aria-label="全局搜索" />
      <span class="kbd">Ctrl K</span>
    </form>

    <div class="health" :title="hint">
      <span v-for="segment in segments" :key="segment.key" class="seg">
        <i class="dot" :class="segment.state" />
        <b>{{ segment.label }}</b>
        <span v-if="segment.value">{{ segment.value }}</span>
      </span>
    </div>

    <button v-if="!controlSession.managed" class="icon-btn" type="button" aria-label="操作令牌" title="操作令牌" @click="ui.tokenOpen = true">
      <Icon name="lock" :size="17" />
    </button>
    <button class="icon-btn" type="button" aria-label="运行审计" title="运行审计" @click="router.push('/runtime')">
      <Icon name="bell" :size="17" />
      <i v-if="alerting" class="ping" />
    </button>

    <div class="top-user">
      <span class="top-avatar">AD</span>
      <span>admin</span>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRouter } from "vue-router";
import Icon from "./Icon.vue";
import { fetchHealth } from "../api";
import { ui } from "../stores/ui";
import { controlSession } from "../api/controlSession";

const router = useRouter();
const q = ref("");
const input = ref(null);
const health = ref(null);
const state = ref("checking");
let timer = null;

const segments = computed(() => {
  if (state.value !== "online") {
    return [
      { key: "service", label: "服务", state: state.value === "checking" ? "unknown" : "bad", value: state.value === "checking" ? "…" : "离线" },
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
    {
      key: "node",
      label: "节点",
      state: node?.configured === false ? "unknown" : node?.online === false ? "warn" : "ok",
      value: node?.registered?.length ? `${node.online_ids?.length || 0}/${node.registered.length}` : ""
    },
    {
      key: "sensor",
      label: "传感器",
      state: total === 0 ? "unknown" : healthy === total ? "ok" : healthy === 0 ? "bad" : "warn",
      value: total ? `${healthy}/${total}` : ""
    },
    { key: "evidence", label: "证据", state: evidence ? (evidence.fresh ? "ok" : "warn") : "unknown", value: evidence ? (evidence.fresh ? "新鲜" : "过期") : "" }
  ];
});

const alerting = computed(() => segments.value.some((item) => item.state === "bad" || item.state === "warn"));

const hint = computed(() => {
  if (state.value === "checking") return "正在检查后端与采集链路";
  if (state.value !== "online") return "后端服务不可达：页面可浏览，写操作不可用";
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

async function load() {
  try {
    const result = await fetchHealth();
    health.value = result;
    state.value = result?.status === "ok" ? "online" : "offline";
  } catch {
    health.value = null;
    state.value = "offline";
  }
}

function submit() {
  const value = q.value.trim();
  if (!value) return;
  router.push({ path: "/risks", query: { q: value } });
}

function onKey(event) {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    input.value?.focus();
  }
}

onMounted(() => {
  load();
  timer = window.setInterval(load, 30000);
  window.addEventListener("keydown", onKey);
});

onUnmounted(() => {
  window.clearInterval(timer);
  window.removeEventListener("keydown", onKey);
});
</script>
