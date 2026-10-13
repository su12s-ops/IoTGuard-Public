<template>
  <el-container class="app-shell">
    <el-aside class="sidebar" width="224px">
      <div class="brand">
        <div class="brand-mark">LG</div>
        <div>
          <h1>LinuxGuard</h1>
          <p>漏洞安全运营平台</p>
        </div>
      </div>
      <el-menu router :default-active="activeMenu" class="nav-menu">
        <el-menu-item index="/">
          <el-icon><DataBoard /></el-icon>
          <span>安全总览</span>
        </el-menu-item>
        <el-menu-item index="/assets">
          <el-icon><Monitor /></el-icon>
          <span>资产管理</span>
        </el-menu-item>
        <el-menu-item index="/vulnerabilities">
          <el-icon><Search /></el-icon>
          <span>漏洞情报</span>
        </el-menu-item>
        <el-menu-item index="/iot"><el-icon><Connection /></el-icon><span>物联网接入</span></el-menu-item>
        <el-menu-item index="/devices"><el-icon><Camera /></el-icon><span>智能设备中心</span></el-menu-item>
        <el-menu-item index="/scans"><el-icon><Aim /></el-icon><span>互联网扫描</span></el-menu-item>
        <el-menu-item index="/agent-ops"><el-icon><Cpu /></el-icon><span>智能体与修复</span></el-menu-item>
        <el-menu-item index="/risk">
          <el-icon><DataAnalysis /></el-icon>
          <span>风险中心</span>
        </el-menu-item>
        <el-menu-item index="/workflow">
          <el-icon><Connection /></el-icon>
          <span>风险研判</span>
        </el-menu-item>
        <el-menu-item index="/runtime">
          <el-icon><Aim /></el-icon>
          <span>运行时验证</span>
        </el-menu-item>
        <el-menu-item index="/remediation">
          <el-icon><Finished /></el-icon>
          <span>修复处置</span>
        </el-menu-item>
        <el-menu-item index="/device-tasks"><el-icon><Finished /></el-icon><span>智能体设备任务</span></el-menu-item>
        <el-menu-item index="/reports">
          <el-icon><Document /></el-icon>
          <span>报告与归档</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="topbar">
        <div class="topbar-title">
          <span class="topbar-context">Linux / IoT 漏洞安全运营</span>
          <h2>{{ $route.meta.title }}</h2>
        </div>
        <div v-if="demoState.running" class="global-collect">
          <div class="global-collect-bar">
            <div class="global-collect-fill" :style="{ width: progressPct + '%' }"></div>
          </div>
          <span class="global-collect-text">{{ progressPct }}% · {{ demoState.currentStep || "采集中" }}</span>
        </div>
        <div v-else class="system-online" :class="{ offline: healthState !== 'online' }">
          <i></i><span>{{ healthText }}</span>
        </div>
      </el-header>
      <el-main :class="['main', { 'main-dashboard': route.path === '/' }]">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from "vue";
import { Aim, Camera, Connection, Cpu, DataAnalysis, DataBoard, Document, Finished, Monitor, Search } from "@element-plus/icons-vue";
import { useRoute } from "vue-router";
import { fetchHealth } from "./api";
import { demoState, progressPct } from "./stores/demoProgress";

const route = useRoute();
const healthState = ref("checking");
let healthTimer = null;
const healthText = computed(() => ({ online: "系统在线", offline: "后端服务异常", checking: "状态检查中" }[healthState.value]));
const activeMenu = computed(() => {
  if (route.path.startsWith("/behavior-chain") || route.path === "/matching") {
    return "/risk";
  }
  return route.path;
});

async function checkHealth() {
  try {
    const result = await fetchHealth();
    healthState.value = result?.status === "ok" ? "online" : "offline";
  } catch {
    healthState.value = "offline";
  }
}

onMounted(() => {
  checkHealth();
  healthTimer = window.setInterval(checkHealth, 30000);
});
onUnmounted(() => window.clearInterval(healthTimer));
</script>
