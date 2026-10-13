<template>
  <section class="page">
    <div class="workflow-hero workflow-hero-tight">
      <div class="hero-copy">
        <h3>CVE 处置主线</h3>
      </div>
      <div class="hero-actions">
        <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">刷新列表</el-button>
        <el-button :icon="DataLine" plain @click="openRuntime">深度诊断</el-button>
      </div>
    </div>

    <div class="grid stats-grid">
      <StatCard label="工作流总数" :value="chains.length" hint="已形成闭环判断的 CVE" />
      <StatCard label="已验证" :value="runtimeCount('verified')" hint="已有直接运行时证据" />
      <StatCard label="上下文关联" :value="runtimeCount('contextual')" hint="已有服务或调用链佐证" />
      <StatCard label="待补证据" :value="waitingCount" hint="尚未补到运行时链路" />
      <StatCard label="高价值事件" :value="runtimeSummary.high_value_count || 0" hint="最近采集到的关键运行事件" />
      <StatCard label="最新事件时间" :value="runtimeStatus.latest_event_at || '-'" hint="最近一次运行时采集时间" />
    </div>

    <el-card class="panel cve-main-panel" shadow="never">
      <div class="panel-title">
        <div>
          <h3>CVE 列表（{{ chains.length }}）</h3>
        </div>
      </div>

      <div v-if="chains.length" class="cve-list scroll-panel cve-scroll-panel">
        <button
          v-for="chain in chains"
          :key="chain.chain_id"
          class="cve-list-row cve-list-row-strong"
          type="button"
          @click="openDetail(chain)"
        >
          <div class="cve-row-rank">#{{ chain.priority_rank }}</div>

          <div class="cve-row-main">
            <div class="cve-title-line">
              <strong>{{ chain.intelligence.cve_id }}</strong>
              <span>{{ chain.package.name }}</span>
            </div>

            <div class="cve-row-meta">
              {{ chain.asset.hostname }} / {{ chain.asset.ip_address }} / {{ chain.asset.os }}
            </div>

            <div class="cve-status-line">
              <span>情报完成</span>
              <span>{{ chain.matching.affected ? "资产命中" : "未命中" }}</span>
              <span>{{ graphText(chain) }}</span>
              <span>{{ runtimeText(chain.runtime_verification.status) }}</span>
              <span>{{ decisionText(chain.risk.decision) }}</span>
              <span>{{ chain.remediation.command ? "已生成修复命令" : "待生成修复命令" }}</span>
            </div>
          </div>

          <div class="cve-row-risk">
            <span class="score">{{ chain.risk.dynamic_score }}</span>
            <el-tag :type="riskTag(chain.risk.dynamic_level)" effect="light">
              {{ riskLevelText(chain.risk.dynamic_level) }}
            </el-tag>
          </div>

          <span class="cve-row-action">查看详情</span>
        </button>
      </div>

      <div v-else class="empty-panel">
        暂无可展示的 CVE 工作流。请先完成资产采集、情报同步、命中分析和风险计算。
      </div>
    </el-card>

    <div class="grid two-col">
      <el-card class="panel" shadow="never">
        <div class="panel-title">
          <div>
            <h3>运行时验证概览</h3>
          </div>
        </div>

        <div class="runtime-overview">
          <article class="runtime-metric">
            <span>入库事件</span>
            <strong>{{ runtimeStatus.db_event_count || 0 }}</strong>
          </article>
          <article class="runtime-metric">
            <span>资产覆盖率</span>
            <strong>{{ runtimeStatus.matched_asset_ratio || 0 }}%</strong>
          </article>
          <article class="runtime-metric">
            <span>真实 eBPF</span>
            <strong>{{ runtimeSummary.observation_mode_counts?.ebpf || 0 }}</strong>
          </article>
          <article class="runtime-metric">
            <span>演示探针</span>
            <strong>{{ runtimeSummary.observation_mode_counts?.probe || 0 }}</strong>
          </article>
        </div>

        <div class="runtime-status-list">
          <div class="runtime-status-row ok">
            <span class="runtime-status-label">已验证</span>
            <strong>{{ runtimeCount('verified') }}</strong>
          </div>
          <div class="runtime-status-row info">
            <span class="runtime-status-label">上下文关联</span>
            <strong>{{ runtimeCount('contextual') }}</strong>
          </div>
          <div class="runtime-status-row idle">
            <span class="runtime-status-label">待补证据</span>
            <strong>{{ waitingCount }}</strong>
          </div>
        </div>
      </el-card>

      <el-card class="panel" shadow="never">
        <div class="panel-title">
          <div>
            <h3>证据作用到哪些 CVE</h3>
          </div>
        </div>

        <div class="verify-list">
          <div class="vc-row verified" v-for="item in verifiedChains" :key="`verified-${item.chain_id}`">
            <span class="vc-badge ok">已验证</span>
            <strong>{{ item.intelligence.cve_id }}</strong>
            <small>{{ item.asset.hostname }} / {{ item.package.name }}</small>
            <span class="vc-impact">+{{ item.risk.adjustment.runtime }}</span>
          </div>

          <div class="vc-row contextual" v-for="item in contextualChains" :key="`context-${item.chain_id}`">
            <span class="vc-badge ctx">上下文关联</span>
            <strong>{{ item.intelligence.cve_id }}</strong>
            <small>{{ item.asset.hostname }} / {{ item.package.name }}</small>
            <span class="vc-impact">+{{ item.risk.adjustment.runtime }}</span>
          </div>

          <div class="vc-row notobs" v-for="item in waitingChainsList" :key="`waiting-${item.chain_id}`">
            <span class="vc-badge idle">{{ runtimeText(item.runtime_verification.status) }}</span>
            <strong>{{ item.intelligence.cve_id }}</strong>
            <small>{{ item.asset.hostname }} / {{ item.package.name }}</small>
            <span class="vc-impact">+0</span>
          </div>

          <div v-if="!verifiedChains.length && !contextualChains.length && !waitingChainsList.length" class="empty-inline">
            暂无可用于处置链路展示的运行时证据。
          </div>
        </div>
      </el-card>
    </div>

    <el-card class="panel" shadow="never">
      <div class="panel-title">
        <div>
          <h3>最新运行时事件</h3>
        </div>
      </div>

      <div v-if="recentEvents.length" class="event-list">
        <article v-for="event in recentEvents" :key="event.id || `${event.timestamp}-${event.rule}`" class="event-card">
          <div class="event-head">
            <strong>{{ categoryLabel(event.category) }}</strong>
            <el-tag size="small" effect="light">{{ observationModeLabel(event.source) }}</el-tag>
          </div>
          <div class="event-meta">
            <span>{{ event.hostname || "未知主机" }}</span>
            <span>{{ event.process_name || "未知进程" }}</span>
            <span>{{ event.timestamp || "-" }}</span>
          </div>
          <code>{{ event.commandline || event.destination || event.file_path || event.rule || "-" }}</code>
        </article>
      </div>

      <div v-else class="empty-panel">
        暂无运行时事件。你可以先完成扫描，或者进入“深度诊断”页上传 Falco / Tetragon 事件。
      </div>
    </el-card>
  </section>
</template>

<script setup>
import { DataLine, Refresh } from "@element-plus/icons-vue";
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import StatCard from "../components/StatCard.vue";
import { fetchBehaviorChains, fetchEbpfEvents, fetchEbpfStatus, fetchEbpfSummary } from "../api";

const router = useRouter();
const loading = ref(false);
const chains = ref([]);
const runtimeSummary = ref({});
const runtimeStatus = ref({});
const recentEvents = ref([]);

const categoryMap = {
  sensitive_file_access: "敏感文件访问",
  privilege_activity: "权限提升行为",
  network_activity: "网络连接行为",
  process_execution: "进程执行行为",
  package_or_service_change: "服务或软件包变更",
  runtime_observation: "运行时观察"
};

const verifiedChains = computed(() => chains.value.filter((item) => item.runtime_verification?.status === "verified"));
const contextualChains = computed(() => chains.value.filter((item) => item.runtime_verification?.status === "contextual"));
const waitingChainsList = computed(() =>
  chains.value.filter((item) => ["not_observed", "waiting"].includes(item.runtime_verification?.status))
);
const waitingCount = computed(() => waitingChainsList.value.length);

const load = async () => {
  loading.value = true;
  try {
    const [chainData, summaryData, statusData, eventData] = await Promise.all([
      fetchBehaviorChains(),
      fetchEbpfSummary().catch(() => ({})),
      fetchEbpfStatus().catch(() => ({})),
      fetchEbpfEvents({ limit: 10 }).catch(() => ({ events: [] }))
    ]);
    chains.value = chainData || [];
    runtimeSummary.value = summaryData || {};
    runtimeStatus.value = statusData || {};
    recentEvents.value = eventData.events || [];
  } finally {
    loading.value = false;
  }
};

const openDetail = (chain) => {
  router.push({
    path: "/behavior-chain/detail",
    query: { chain_id: chain.chain_id }
  });
};

const openRuntime = () => {
  router.push("/runtime");
};

const runtimeCount = (status) =>
  chains.value.filter((chain) => chain.runtime_verification?.status === status).length;

const runtimeText = (status) => {
  if (status === "verified") return "运行时已验证";
  if (status === "contextual") return "运行时上下文关联";
  if (status === "not_observed") return "尚未观察到";
  return "等待运行时证据";
};

const graphText = (chain) =>
  (
    {
      internet_exposed: "公网路径可达",
      linked: "依赖链已关联",
      none: "包级命中"
    }[chain.dependency_graph?.status] || "包级命中"
  );

const decisionText = (decision) =>
  (
    {
      immediate_fix: "立即修复",
      scheduled_fix: "排期修复",
      monitor: "持续观察",
      defer: "暂缓处理"
    }[decision] || decision || "待决策"
  );

const riskLevelText = (level) =>
  (
    {
      Critical: "严重",
      High: "高危",
      Medium: "中危",
      Low: "低危"
    }[level] || "未知"
  );

const riskTag = (level) => {
  if (level === "Critical" || level === "High") return "danger";
  if (level === "Medium") return "warning";
  return "success";
};

const categoryLabel = (name) => categoryMap[name] || name || "未知";

const observationModeLabel = (source) => {
  const value = (source || "").toLowerCase();
  if (value.includes("falco") || value.includes("tetragon") || value === "syscall") return "真实 eBPF";
  if (value.startsWith("runtime_probe_")) return "演示探针";
  return "运行时";
};

onMounted(load);
</script>

<style scoped>
.workflow-hero-tight {
  align-items: center;
  min-height: auto;
}

.hero-copy h3 {
  margin: 0;
}

.hero-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.cve-main-panel {
  display: grid;
}

.cve-scroll-panel {
  min-height: 620px;
  max-height: 72vh;
  overflow-y: auto;
  padding-right: 8px;
}

.cve-scroll-panel::-webkit-scrollbar {
  width: 8px;
}

.cve-scroll-panel::-webkit-scrollbar-thumb {
  border-radius: 999px;
  background: rgba(96, 165, 250, 0.45);
}

.cve-scroll-panel::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.3);
}

.cve-list-row-strong {
  width: 100%;
  min-height: 136px;
  padding: 20px;
  border-radius: 18px;
  border: 1px solid rgba(91, 163, 255, 0.32);
  background:
    linear-gradient(135deg, rgba(27, 47, 78, 0.78), rgba(16, 26, 48, 0.96)),
    rgba(15, 23, 42, 0.9);
  box-shadow: inset 0 1px 0 rgba(148, 163, 184, 0.1);
  transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
}

.cve-list-row-strong:hover {
  transform: translateY(-2px);
  border-color: rgba(96, 165, 250, 0.58);
  box-shadow:
    0 12px 28px rgba(15, 23, 42, 0.28),
    inset 0 1px 0 rgba(148, 163, 184, 0.12);
}

.cve-row-risk {
  display: grid;
  justify-items: end;
  gap: 12px;
}

.cve-row-risk .score {
  color: #dbeafe;
  font-size: 32px;
  font-weight: 700;
  line-height: 1;
  font-family: Consolas, monospace;
}

.cve-row-action {
  display: inline-flex;
  align-items: center;
  justify-content: flex-end;
  min-width: 88px;
  color: #e6edf7;
  font-size: 20px;
  font-weight: 600;
}

.scroll-panel {
  overflow: auto;
}

.runtime-overview {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.runtime-metric {
  padding: 14px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(148, 163, 184, 0.14);
}

.runtime-metric span {
  display: block;
  color: #8ea0c5;
  font-size: 12px;
}

.runtime-metric strong {
  display: block;
  margin-top: 8px;
  color: #e6edf7;
  font-family: Consolas, monospace;
  font-size: 22px;
}

.runtime-status-list,
.verify-list,
.event-list {
  display: grid;
  gap: 10px;
}

.runtime-status-list {
  margin-top: 16px;
}

.runtime-status-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 14px 16px;
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.14);
}

.runtime-status-row strong {
  color: #e6edf7;
  font-family: Consolas, monospace;
  font-size: 24px;
}

.runtime-status-row.ok {
  background: rgba(52, 211, 153, 0.08);
  border-color: rgba(52, 211, 153, 0.25);
}

.runtime-status-row.info {
  background: rgba(59, 130, 246, 0.08);
  border-color: rgba(59, 130, 246, 0.25);
}

.runtime-status-row.idle {
  background: rgba(148, 163, 184, 0.08);
}

.runtime-status-label {
  color: #dbe6ff;
  font-weight: 600;
}

.vc-row {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid;
}

.vc-row.verified {
  background: rgba(52, 211, 153, 0.08);
  border-color: rgba(52, 211, 153, 0.3);
}

.vc-row.contextual {
  background: rgba(59, 130, 246, 0.08);
  border-color: rgba(59, 130, 246, 0.28);
}

.vc-row.notobs {
  background: rgba(120, 150, 200, 0.05);
  border-color: rgba(120, 150, 200, 0.15);
}

.vc-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-family: Consolas, monospace;
  font-size: 11px;
  text-align: center;
}

.vc-badge.ok {
  background: rgba(52, 211, 153, 0.2);
  color: #6ee7b7;
}

.vc-badge.ctx {
  background: rgba(59, 130, 246, 0.16);
  color: #93c5fd;
}

.vc-badge.idle {
  background: rgba(120, 150, 200, 0.15);
  color: #a8b8d8;
}

.vc-row strong,
.event-card strong {
  color: #e6edf7;
  font-family: Consolas, monospace;
  font-size: 13px;
}

.vc-row small {
  color: #8896ad;
  font-size: 12px;
}

.vc-impact {
  color: #34d399;
  font-family: Consolas, monospace;
  font-size: 12px;
  font-weight: 700;
}

.event-card {
  display: grid;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(148, 163, 184, 0.14);
}

.event-head,
.event-meta {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.event-meta {
  color: #8ea0c5;
  font-size: 12px;
}

.event-card code {
  color: #dbeafe;
  font-family: Consolas, monospace;
  white-space: pre-wrap;
  word-break: break-all;
}

.empty-inline {
  color: #8ea0c5;
  line-height: 1.7;
}

@media (max-width: 1100px) {
  .cve-list-row-strong {
    grid-template-columns: 88px minmax(0, 1fr);
  }

  .cve-row-risk,
  .cve-row-action {
    justify-items: start;
    justify-content: flex-start;
  }
}

@media (max-width: 900px) {
  .runtime-overview,
  .vc-row,
  .runtime-status-row,
  .cve-list-row-strong {
    grid-template-columns: 1fr;
  }

  .hero-actions {
    width: 100%;
  }

  .cve-scroll-panel {
    min-height: 520px;
    max-height: none;
  }
}
</style>
