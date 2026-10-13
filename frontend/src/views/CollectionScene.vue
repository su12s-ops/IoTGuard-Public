<template>
  <section class="page collection-page">
    <div class="collection-hero">
      <div>
        <span class="eyebrow">Live Collection</span>
        <h3>虚拟机资产采集现场</h3>
        <p>展示 Ubuntu / 麒麟 OS 虚拟机中执行采集脚本、生成资产文件、回传平台并进入分析队列的全过程。</p>
      </div>
      <el-button type="primary" :icon="VideoPlay" @click="replay">重新播放采集过程</el-button>
    </div>

    <div class="grid stats-grid">
      <StatCard label="目标虚拟机" :value="assets.length" hint="Ubuntu 22.04 / 24.04 / 麒麟 V10" />
      <StatCard label="采集脚本" value="1" hint="collect_linux_asset.sh" />
      <StatCard label="资产文件" :value="assets.length" hint="已回传 txt" />
      <StatCard label="采集阶段" :value="currentStepLabel" hint="终端日志回放" />
      <StatCard label="联网状态" value="OK" hint="SSH / SCP 可达" />
      <StatCard label="入库状态" value="完成" hint="资产中心可见" />
    </div>

    <div class="scan-layout">
      <el-card class="panel" shadow="never">
        <div class="panel-title">
          <h3>虚拟机清单</h3>
          <span class="muted">来自资产中心</span>
        </div>
        <div class="vm-list">
          <button
            v-for="asset in assets"
            :key="asset.id"
            class="vm-row"
            :class="{ active: selectedAsset?.id === asset.id }"
            type="button"
            @click="selectedId = asset.id"
          >
            <span class="vm-icon"><Monitor /></span>
            <span class="vm-main">
              <strong>{{ asset.os_name }} {{ asset.os_version }}</strong>
              <small>{{ asset.hostname }}</small>
            </span>
            <span class="vm-meta">{{ asset.ip_address }}</span>
          </button>
        </div>
      </el-card>

      <el-card class="panel terminal-panel" shadow="never">
        <div class="terminal-header">
          <div>
            <span class="dot red"></span>
            <span class="dot yellow"></span>
            <span class="dot green"></span>
          </div>
          <span>{{ selectedAsset?.hostname || "collector" }}:~/</span>
        </div>
        <pre class="terminal-body">{{ terminalText }}</pre>
      </el-card>
    </div>

    <el-card class="panel" shadow="never">
      <div class="panel-title">
        <h3>采集链路</h3>
        <span class="muted">脚本执行到平台入库</span>
      </div>
      <div class="timeline-grid">
        <div v-for="(step, index) in steps" :key="step.title" class="flow-step" :class="{ done: index <= currentStep }">
          <span class="step-icon"><component :is="step.icon" /></span>
          <strong>{{ step.title }}</strong>
          <small>{{ step.desc }}</small>
        </div>
      </div>
    </el-card>
  </section>
</template>

<script setup>
import { computed, markRaw, onMounted, onUnmounted, ref, watch } from "vue";
import { CircleCheck, Connection, DocumentCopy, Monitor, UploadFilled, VideoPlay } from "@element-plus/icons-vue";
import StatCard from "../components/StatCard.vue";
import { fetchAssets } from "../api";

const assets = ref([]);
const selectedId = ref(null);
const currentStep = ref(0);
let timer = null;

const steps = [
  { title: "连接 VM", desc: "确认 SSH 与 IP 可达", icon: markRaw(Connection) },
  { title: "执行采集", desc: "读取系统、内核、软件包和服务", icon: markRaw(Monitor) },
  { title: "生成文件", desc: "输出 ubuntu*/kylin*_asset.txt", icon: markRaw(DocumentCopy) },
  { title: "回传主机", desc: "通过 scp 复制到项目目录", icon: markRaw(UploadFilled) },
  { title: "平台入库", desc: "资产中心解析并保存", icon: markRaw(CircleCheck) }
];

const selectedAsset = computed(() => assets.value.find((asset) => asset.id === selectedId.value) || assets.value[0]);
const currentStepLabel = computed(() => `${Math.min(currentStep.value + 1, steps.length)}/${steps.length}`);

const assetFileName = computed(() => {
  const dist = String(selectedAsset.value?.distribution || "").toLowerCase();
  if (dist === "kylin" || dist === "openkylin") return "kylin_asset.txt";
  const version = String(selectedAsset.value?.os_version || "").replace(".", "");
  return version.includes("2404") ? "ubuntu24_asset.txt" : "ubuntu22_asset.txt";
});

const terminalLines = computed(() => {
  const asset = assets.value[0];
  if (!asset) {
    return ["$ 等待上传资产文件...", "$ 打开资产中心并上传 ubuntu22_asset.txt / ubuntu24_asset.txt / kylin_asset.txt"];
  }
  return [
    `$ hostname -I`,
    `${asset.ip_address}`,
    `$ chmod +x collect_linux_asset.sh`,
    `$ ./collect_linux_asset.sh ${assetFileName.value}`,
    `hostname: ${asset.hostname}`,
    `ip_address: ${asset.ip_address}`,
    `os_release: ${asset.os_name} ${asset.os_version}`,
    `kernel: ${asset.kernel_version}`,
    `dpkg packages: collected`,
    `open ports and running services: collected`,
    `Asset inventory written to ${assetFileName.value}`,
    `$ scp ${assetFileName.value} Windows:<PROJECT_ROOT>\\`,
    `upload complete: LinuxGuard Asset Center`
  ];
});

const terminalText = computed(() => terminalLines.value.slice(0, Math.min(terminalLines.value.length, 4 + currentStep.value * 2)).join("\n"));

const replay = () => {
  currentStep.value = 0;
  clearInterval(timer);
  timer = setInterval(() => {
    currentStep.value = currentStep.value >= steps.length - 1 ? steps.length - 1 : currentStep.value + 1;
    if (currentStep.value === steps.length - 1) {
      clearInterval(timer);
    }
  }, 900);
};

const load = async () => {
  assets.value = await fetchAssets();
  selectedId.value = assets.value[0]?.id || null;
};

watch(selectedId, replay);

onMounted(async () => {
  await load();
  replay();
});

onUnmounted(() => clearInterval(timer));
</script>
