<template>
  <div class="page">
    <PageHeader
      title="安全总览"
      subtitle="Security Overview"
      description="多智能体协同的物联网安全运营平台"
    >
      <template #meta>
        <span>数据读取于 {{ updated || "尚未读取" }}</span><i class="sep" /><span>{{ num(totalAssets) }} 台资产</span><i class="sep" /><span>{{ num(summary.total_vulnerabilities) }} 条情报</span>
      </template>
      <template #actions>
        <span class="range-chip"><Icon name="calendar" :size="14" />{{ today }} · 最近 7 天<Icon name="chev-down" :size="13" /></span>
        <button class="btn" type="button" @click="refresh"><Icon name="refresh" :size="15" />刷新</button>
        <router-link class="btn primary" to="/agents"><Icon name="rocket" :size="15" />发起研判</router-link>
      </template>
    </PageHeader>

  <VerdictRuling
    :state="ruling.state"
    :stamp-main="ruling.stampMain"
    :stamp-en="ruling.stampEn"
    :title="ruling.title"
    :detail="ruling.detail"
    :tags="ruling.tags"
  />

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <div class="kpi-row">
      <KpiCard label="接入资产" :value="num(totalAssets)" unit="台" icon="server" tone="blue" :sub="`${num(summary.linux_asset_count)} 台 Linux 主机 · ${num(summary.iot_device_count)} 台 IoT 设备`" />
      <KpiCard label="高危风险" :value="num(highCount)" unit="条" icon="shield-alert" tone="red" :delta="riskDelta" :delta-tone="riskDeltaTone" :sub="`严重 ${critical} · 高危 ${high}`" />
      <KpiCard label="运行任务" :value="num(runs.length)" unit="个" icon="cpu" tone="green" :sub="`${completedCount} 个已完成 · ${runningCount} 个执行中`" />
      <KpiCard label="待审事项" :value="num(pendingReview)" unit="项" icon="shield" tone="purple" :sub="`${num(candidateRisk)} 条待研判 · ${num(summary.pending_remediation_tasks)} 条待修复`" />
    </div>

    <div class="overview-main">
      <section class="card topology-card">
        <div class="card-head topology-head">
          <div>
            <div class="card-title">安全态势拓扑</div>
            <div class="card-desc">资产、漏洞与运行时证据在同一张图上关联</div>
          </div>
          <div class="row">
            <span class="live-dot" :class="{ warn: !evidenceFresh }" /><span class="live-text" :class="{ warn: !evidenceFresh }">{{ evidenceFresh ? "实时监测" : hasEvidence ? "监测受限" : "未采集运行时证据" }}</span>
            <span class="chip" :class="healthySensors === totalSensors && totalSensors ? 'low' : 'high'" style="margin-left: 6px"><i class="dot" />{{ healthySensors }}/{{ totalSensors }} 传感器健康</span>
          </div>
        </div>
        <TopologyMap
          :nodes="topologyNodes"
          :height="368"
          :events="runtimeEvents"
          :mode="runtimeMode"
          :mode-label="runtimeModeLabel"
          :nodes-by-host="nodesByHost"
        />
        <div class="hero-metrics">
          <div class="hero-metric"><span>风险对象</span><b>{{ num(riskTotal) }}</b></div>
          <div class="hero-metric"><span>待处置</span><b>{{ num(summary.pending_remediation_tasks) }}</b></div>
          <div class="hero-metric"><span>运行时证据</span><b class="evidence" :style="{ color: evidenceFresh ? 'var(--low)' : hasEvidence ? 'var(--high)' : 'var(--ink-3)' }">{{ evidenceLabel }}</b></div>
          <div class="hero-metric"><span>情报来源</span><b>{{ sourceCount }}</b></div>
          <router-link class="link" to="/runtime" style="margin-left: auto">运行监控 <Icon name="chev-right" :size="13" /></router-link>
        </div>
      </section>

      <section class="card risk-dist">
        <div class="card-head">
          <div>
            <div class="card-title">风险等级分布</div>
            <div class="card-desc">资产级风险 · 共 {{ num(riskTotal) }} 条</div>
          </div>
          <router-link class="link" to="/risks">查看全部 <Icon name="chev-right" :size="13" /></router-link>
        </div>
        <div class="risk-donut">
          <DonutChart :items="riskItems" :size="126" center-label="总风险" :center-value="num(riskTotal)" />
          <div class="legend-list">
            <span v-for="item in riskItems" :key="item.label">
              <i class="dot" :style="{ background: item.color }" />{{ item.label }}
              <b>{{ num(item.value) }}</b>
              <em>{{ pctOf(item.value) }}</em>
            </span>
          </div>
        </div>
        <div class="trend-block">
          <div class="trend-title"><b>重点资产风险</b><span>综合风险分 / 100</span></div>
          <div v-if="topAssets.length" class="asset-risk-list">
            <div v-for="asset in topAssets" :key="asset.asset_id || asset.hostname" class="asset-risk-row">
              <span class="ar-name" :title="asset.hostname">{{ truncate(asset.hostname, 18) }}</span>
              <span class="ar-track"><i :style="{ width: `${Math.min(100, Number(asset.score) || 0)}%`, background: scoreColor(asset.score) }" /></span>
              <b class="num">{{ score(asset.score, 1) }}</b>
            </div>
          </div>
          <div v-else class="empty-note" style="padding: 10px 0">暂无资产风险分数据。</div>
        </div>
      </section>
    </div>

    <div class="overview-bottom">
      <section class="card">
        <div class="card-head">
          <div><div class="card-title">优先处置</div><div class="card-desc">按综合风险分排序 · 前 5 条</div></div>
          <router-link class="link" to="/risks">全部风险 <Icon name="chev-right" :size="13" /></router-link>
        </div>
        <div v-if="loadingSummary" class="loading-line" style="padding: 26px 18px"><span class="spinner" />正在读取风险记录…</div>
        <div v-else-if="!priorityRows.length" class="empty-wrap" style="min-height: 200px">
          <EmptyState title="暂无风险对象" description="完成资产采集与风险评估后，这里会出现按风险分排序的对象。" icon="bug" />
        </div>
        <div v-else class="table-wrap">
          <table class="ov-table">
            <thead><tr><th>#</th><th>CVE 编号</th><th>资产</th><th>风险分</th><th>等级</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="(row, index) in priorityRows" :key="row.cve_id || index" style="cursor: pointer" tabindex="0" role="link" @click="openRisk(row)" @keydown.enter="openRisk(row)">
                <td><span class="rank" :class="{ top: index < 2 }">P{{ index + 1 }}</span></td>
                <td class="mono cve-cell"><span class="cve-id">{{ row.cveOnly }}</span><small v-if="row.cveContext">{{ row.cveContext }}</small></td>
                <td class="name" :title="row.hostname">{{ row.hostname || "—" }}</td>
                <td><span class="score" :class="toneForLevel(row.risk_level)"><b>{{ score(row.score) }}</b><i><em :style="{ width: `${Math.min(100, Number(row.score) || 0)}%` }" /></i></span></td>
                <td><span class="chip" :class="toneForLevel(row.risk_level)"><i class="dot" />{{ levelLabel(row.risk_level) }}</span></td>
                <td><span class="chip" :class="row.active === false ? 'muted' : 'high'"><i class="dot" />{{ row.active === false ? "历史归档" : "待研判" }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="card-foot"><span>风险分综合 CVSS、EPSS、暴露面与运行时证据；不代表已确认利用。</span><span class="num">{{ num(riskTotal) }} 条 · {{ num(candidateRisk) }} 条待研判 · {{ num(pendingReview) }} 条待审</span></div>
      </section>

      <section class="card agent-card">
        <div class="card-head">
          <div><div class="card-title">智能体运行</div><div class="card-desc">四智能体协作 · 共享知识库</div></div>
          <span v-if="latestRun" class="chip" :class="statusTone(latestRun.status)"><i class="dot" />{{ statusLabel(latestRun.status) }}</span>
          <span v-else class="chip muted"><i class="dot" />暂无运行</span>
        </div>

        <div v-if="latestRun" class="agent-body">
          <div class="agent-flow">
            <div v-for="(step, index) in agentSteps" :key="step.key" class="agent-row">
              <span class="step-dot" :class="step.state">
                <Icon :name="step.state === 'done' ? 'check' : step.state === 'active' ? 'clock' : 'more'" :size="12" />
              </span>
              <div class="agent-row-copy">
                <div class="step-title">{{ step.label }}</div>
                <div class="step-note">{{ step.note }}</div>
              </div>
              <span class="step-time">{{ step.time }}</span>
            </div>
          </div>
          <div class="agent-meta">
            <div><span>目标</span><b :title="latestRun.target_ref">{{ short(latestRun.target_ref) }}</b></div>
            <div><span>模式</span><b>{{ latestRun.mode || "—" }}</b></div>
            <div><span>记录</span><b>{{ latestRun.run_id?.slice(-4) || "—" }}</b></div>
          </div>
          <div class="agent-callout">
            <Icon name="alert" :size="14" />
            <span>{{ pendingReview ? `${pendingReview} 条记录待人工审查` : "暂无待处理记录" }}</span>
            <router-link class="link" to="/agents">进入 <Icon name="chev-right" :size="12" /></router-link>
          </div>
        </div>
        <div v-else class="empty-wrap" style="min-height: 210px">
          <EmptyState title="暂无智能体运行" description="发起一次研判后，四个智能体的状态会出现在这里。" icon="cpu" />
        </div>
        <div class="card-foot"><span>流程结束不代表风险已获审批。</span><router-link class="link" to="/agents">AgentOps <Icon name="chev-right" :size="12" /></router-link></div>
      </section>
    </div>

    <WorkflowStrip />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import KpiCard from "../components/KpiCard.vue";
import TopologyMap from "../components/TopologyMap.vue";
import VerdictRuling from "../components/VerdictRuling.vue";
import DonutChart from "../components/DonutChart.vue";
import WorkflowStrip from "../components/WorkflowStrip.vue";
import { api, fetchHealth, fetchReportArchives } from "../api";
import { ecosystemLabel, levelLabel, levelTone, num, score, shortTime, statusLabel, statusTone, truncate } from "../utils/format";

const router = useRouter();
const summary = ref({});
const health = ref(null);
const archives = ref([]);
const runs = ref([]);
const devices = ref([]);
const loadingSummary = ref(true);
const error = ref("");
const updated = ref("");
const now = ref(new Date());

const critical = computed(() => Number(summary.value.risk_level_distribution?.Critical || 0));
const high = computed(() => Number(summary.value.risk_level_distribution?.High || 0));
const medium = computed(() => Number(summary.value.risk_level_distribution?.Medium || 0));
const low = computed(() => Number(summary.value.risk_level_distribution?.Low || 0));
const riskTotal = computed(() => critical.value + high.value + medium.value + low.value);
const highCount = computed(() => Number(summary.value.high_risk_vulnerabilities ?? critical.value + high.value));
const pendingReview = computed(() => Number(summary.value.pending_human_review || 0) + Number(summary.value.pending_remediation_tasks || 0));
const candidateRisk = computed(() => Number(summary.value.candidate_risk_count || 0));
// 接入总数 = 主机线（LinuxAsset） + 设备线（IotDevice）。两条台账本来就是不同对象，
// 只报一个数字会让"资产 1 台"和拓扑上的设备计数对不上。
const linuxAssetCount = computed(() => Number(summary.value.linux_asset_count ?? summary.value.asset_count ?? 0));
const totalAssets = computed(() => linuxAssetCount.value + Number(summary.value.iot_device_count || 0));
const completedCount = computed(() => runs.value.filter((run) => ["completed", "succeeded"].includes(run.status)).length);
const runningCount = computed(() => runs.value.filter((run) => ["running", "queued_remote"].includes(run.status)).length);

const riskDelta = computed(() => {
  if (archives.value.length < 2) return "";
  const latest = Number(archives.value[0]?.summary?.risks);
  const previous = Number(archives.value[1]?.summary?.risks);
  if (!Number.isFinite(latest) || !Number.isFinite(previous)) return "";
  const value = latest - previous;
  return `${value >= 0 ? "+" : ""}${value}`;
});
const riskDeltaTone = computed(() => (riskDelta.value.startsWith("-") ? "up" : "down"));

import { SEVERITY, ECOSYSTEM } from "../lib/palette";

const riskItems = computed(() => [
  { label: "严重", value: critical.value, color: SEVERITY.critical },
  { label: "高危", value: high.value, color: SEVERITY.high },
  { label: "中危", value: medium.value, color: SEVERITY.medium },
  { label: "低危", value: low.value, color: SEVERITY.low }
]);

function pctOf(value) {
  if (!riskTotal.value) return "0%";
  const ratio = (Number(value) / riskTotal.value) * 100;
  return ratio > 0 && ratio < 1 ? "<1%" : `${Math.round(ratio)}%`;
}

function scoreColor(value) {
  const n = Number(value) || 0;
  if (n >= 75) return SEVERITY.critical;
  if (n >= 60) return SEVERITY.high;
  return SEVERITY.low;
}

// 风险记录的 cve_id 实际是复合键，形如 "CVE-2026-84782:noble:openssl"。
// 直接整串塞进表格会在连字符/冒号处折断，因此拆成"主标识 + 上下文"两级显示。
const priorityRows = computed(() =>
  (summary.value.top_vulnerabilities || []).slice(0, 5).map((row) => {
    const parts = String(row.cve_id || "").split(":");
    return {
      ...row,
      cveOnly: parts[0] || row.cve_id || "—",
      cveContext: parts.slice(1).filter(Boolean).join(" · ")
    };
  })
);
const topAssets = computed(() => (summary.value.top_assets || []).slice(0, 4));
const latestRun = computed(() => runs.value[0] || null);

const layers = computed(() => health.value?.layers || {});
const totalSensors = computed(() => Number(layers.value.sensors?.total || 0));
const healthySensors = computed(() => Number(layers.value.sensors?.healthy || 0));
const evidenceFresh = computed(() => Boolean(layers.value.runtime_evidence?.fresh));
// 从没采过运行时证据时，latest_event_age_seconds 是 null——这时说"过期"是假话，
// 只能说"未采集"。
const hasEvidence = computed(() => {
  const age = layers.value.runtime_evidence?.latest_event_age_seconds;
  return age !== null && age !== undefined;
});
const evidenceLabel = computed(() => {
  if (evidenceFresh.value) return "新鲜";
  return hasEvidence.value ? "部分过期" : "未采集";
});
const sourceCount = computed(() => Object.keys(summary.value.source_distribution || {}).length);

const topologyNodes = computed(() => {
  const counts = devices.value.reduce((map, device) => {
    const key = device.ecosystem || "other_iot";
    map[key] = (map[key] || 0) + 1;
    return map;
  }, {});
  // 主机线单独报数：LinuxAsset 除去已经是"设备"的 OpenWrt，剩下的就是基础设施主机。
  // 后端把两个计数分开给出，前端不做减法猜测。
  const linuxHosts = Math.max(0, linuxAssetCount.value - Number(summary.value.openwrt_asset_count || 0))
    + Number(counts.ubuntu || 0);
  return [
    { key: "openwrt", name: ecosystemLabel("openwrt"), count: counts.openwrt || 0, icon: "router", color: ECOSYSTEM.openwrt.color, soft: ECOSYSTEM.openwrt.soft },
    { key: "zephyr", name: ecosystemLabel("zephyr"), count: counts.zephyr || 0, icon: "cpu", color: ECOSYSTEM.zephyr.color, soft: ECOSYSTEM.zephyr.soft },
    { key: "ubuntu", name: "Linux 主机", count: linuxHosts, icon: "server", color: ECOSYSTEM.ubuntu.color, soft: ECOSYSTEM.ubuntu.soft },
    { key: "other", name: "其他设备", count: counts.other_iot || 0, icon: "box", color: ECOSYSTEM.other.color, soft: ECOSYSTEM.other.soft }
  ];
});

const agentSteps = computed(() => {
  const status = latestRun.value?.status;
  const done = ["completed", "succeeded"].includes(status);
  const active = ["running", "queued_remote", "pending"].includes(status);
  return [
    { key: "asset", label: "资产建模", note: done ? "设备识别 / 拓扑建模" : active ? "已读取对象" : "等待运行", time: shortTime(latestRun.value?.created_at || ""), state: done || active ? "done" : "idle" },
    { key: "vuln", label: "漏洞分析", note: done ? "CVE 分析 / 漏洞挖掘" : active ? "正在补证" : "等待上游", time: "—", state: done ? "done" : active ? "active" : "idle" },
    { key: "runtime", label: "运行时分析", note: done ? "行为建模 / 证据聚合" : active ? "正在采集证据" : "等待上游", time: "—", state: done ? "done" : active ? "active" : "idle" },
    { key: "decision", label: "决策规划", note: done ? "风险评级 / 处置建议" : "等待上游", time: "—", state: done ? "done" : "idle" }
  ];
});

const today = computed(() =>
  now.value.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })
);

function toneForLevel(level) {
  return levelTone(level);
}

function openRisk(row) {
  if (row?.cve_id) router.push(`/risks/${encodeURIComponent(row.cve_id)}`);
}

function short(value) {
  const text = String(value || "");
  return text.length > 20 ? `${text.slice(0, 20)}…` : text || "—";
}

async function refresh() {
  loadingSummary.value = true;
  error.value = "";
  try {
    const result = await api.get("/dashboard/summary", { timeout: 20000 });
    summary.value = result.data || {};
    updated.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "安全态势加载失败，请检查后端服务。";
  } finally {
    loadingSummary.value = false;
  }

  fetchHealth().then((value) => { health.value = value; }).catch(() => { health.value = null; });
  fetchReportArchives().then((value) => { archives.value = value.archives || []; }).catch(() => { archives.value = []; });
  api.get("/unified/runs", { params: { limit: 20 }, timeout: 15000 }).then((value) => { runs.value = value.data?.runs || value.data || []; }).catch(() => { runs.value = []; });
  api.get("/devices/business/overview", { timeout: 20000 }).then((value) => { devices.value = value.data?.devices || []; }).catch(() => { devices.value = []; });
  loadRuntimeEvents();
}

/* —— 拓扑活性数据源（B 方案）——
   1) 优先用真实实时事件 /runtime/ebpf/events；
   2) 若采集未开（当前运行时证据为"未采集"，接口返回 0 条），
      退到仓库内的**实采快照** verdict-data.json#capture（真实录制的 40 条 eBPF 事件），
      并在界面上显式标注「回放」+ 采集时间，绝不伪装成实时；
   3) 两者都没有则显示"运行证据未采集"，拓扑保持静态。 */
const runtimeEvents = ref([]);
const runtimeMode = ref("none");
const runtimeModeLabel = ref("运行证据未采集");

async function loadRuntimeEvents() {
  try {
    const res = await api.get("/runtime/ebpf/events", { params: { limit: 500 }, timeout: 20000 });
    const list = res.data?.events || [];
    if (list.length) {
      runtimeEvents.value = list;
      runtimeMode.value = "live";
      runtimeModeLabel.value = `实时 · ${list.length} 条`;
      return;
    }
  } catch {
    /* 落到回放分支 */
  }
  try {
    const mod = await import("../data/verdict-data.json");
    const capture = mod.default?.capture;
    const list = capture?.events || [];
    if (list.length) {
      runtimeEvents.value = list;
      runtimeMode.value = "replay";
      const first = capture?.meta?.derived?.first_timestamp;
      // 统一用本地时间：事件行按本地时区显示，标签若用原始 UTC 串会出现
      // "标签 12:05 / 事件 20:05" 的自相矛盾（UTC+8 环境）。
      const when = first ? new Date(first) : null;
      const stamp = when && !Number.isNaN(when.getTime())
        ? `${when.getFullYear()}-${String(when.getMonth() + 1).padStart(2, "0")}-${String(when.getDate()).padStart(2, "0")} ${String(when.getHours()).padStart(2, "0")}:${String(when.getMinutes()).padStart(2, "0")}`
        : "";
      runtimeModeLabel.value = stamp ? `回放 · 实采 ${list.length} 条 · ${stamp}` : `回放 · 实采 ${list.length} 条`;
      return;
    }
  } catch {
    /* 保持 none */
  }
  runtimeMode.value = "none";
  runtimeModeLabel.value = "运行证据未采集";
}

/* 主机名 → 生态节点 key：来自设备业务总览；未识别主机归入"其他设备" */
const nodesByHost = computed(() => {
  const map = {};
  for (const device of devices.value) {
    const host = device.hostname || device.host || device.device_name || device.name;
    const eco = device.ecosystem || device.ecosystem_key;
    if (!host || !eco) continue;
    map[host] = eco === "other_iot" ? "other" : eco;
  }
  // 实采快照来自 Ubuntu 实验室主机，归入 Linux（ubuntu）节点
  map["lab-ebpf-host"] = "ubuntu";
  return map;
});
/* 页面级状态印章：总览页回答"整体安全姿态是什么" */
const ruling = computed(() => {
  const crit = critical.value;
  const danger = high.value;
  const mid = medium.value;
  const mild = low.value;
  const total = riskTotal.value;
  const assets = Number(summary.value.asset_count ?? 0);
  const tags = [
    { text: `严重 ${crit}`, tone: "crit" },
    { text: `高危 ${danger}`, tone: "high" },
    { text: `中危 ${mid}`, tone: "mid" },
    { text: `低危 ${mild}`, tone: "low" },
    { text: `资产 ${assets} 台`, tone: "" },
  ];
  if (total === 0) {
    return {
      state: "weak", stampMain: "无数据", stampEn: "NO DATA",
      title: "当前没有可研判的风险",
      detail: "没有风险条目不代表安全：需要先完成资产采集与情报同步，风险才会被计算出来。",
      tags,
    };
  }
  if (crit + danger > 0) {
    return {
      state: "fail", stampMain: "存在高危", stampEn: "AT RISK",
      title: `当前 ${assets} 台资产上有 ${crit + danger} 条高危及以上风险`,
      detail: "风险分综合 CVSS、EPSS、暴露面与运行时证据；命中不等于已被利用。",
      tags,
    };
  }
  return {
    state: "pass", stampMain: "无高危", stampEn: "NO HIGH",
    title: `共 ${total} 条风险，其中无高危及以上`,
    detail: `中危 ${mid} 条、低危 ${mild} 条；结论仅覆盖已采集资产。`,
    tags,
  };
});


onMounted(refresh);
</script>

<style scoped>
.range-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 0 12px;
  border: 1px solid #e2ebf7;
  border-radius: 9px;
  background: #fff;
  color: #5b6b82;
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
  box-shadow: 0 1px 2px rgba(16, 35, 70, 0.03);
}
.overview-main { display: grid; grid-template-columns: minmax(0, 2.05fr) minmax(0, 1fr); gap: 16px; }
.overview-bottom { display: grid; grid-template-columns: minmax(0, 2.05fr) minmax(0, 1fr); gap: 16px; }
.topology-head { position: relative; z-index: 2; }
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--low); box-shadow: 0 0 0 4px rgba(18, 183, 106, 0.12); }
.live-dot.warn { background: var(--high); box-shadow: 0 0 0 4px rgba(249, 115, 22, 0.12); }
.live-text { color: var(--low); font-size: 13.5px; font-weight: 600; }
.live-text.warn { color: var(--high); }

.risk-dist { display: flex; flex-direction: column; }
.risk-donut { display: flex; align-items: center; gap: 16px; padding: 12px 16px 8px; }
.risk-donut .legend-list { flex: 1; min-width: 0; }
.trend-block { margin-top: auto; padding: 12px 16px 12px; border-top: 1px solid var(--line-soft); }
.trend-title { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 8px; }
.trend-title b { color: var(--ink); font-size: 14px; font-weight: 700; }
.trend-title span { color: var(--muted); font-size: 12.5px; }
.asset-risk-list { display: grid; gap: 8px; }
.asset-risk-row { display: grid; grid-template-columns: minmax(0, 1fr) 92px 38px; gap: 8px; align-items: center; }
.ar-name { color: #5b6b82; font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ar-track { height: 6px; border-radius: 999px; background: #eef3fa; overflow: hidden; }
.ar-track i { display: block; height: 6px; border-radius: 999px; }
.asset-risk-row b { text-align: right; color: var(--ink); font-size: 14px; font-weight: 700; }

.rank {
  display: inline-grid;
  place-items: center;
  min-width: 30px;
  height: 22px;
  padding: 0 6px;
  border-radius: 6px;
  background: #f3f7fc;
  color: #7b8ca6;
  font-family: var(--font-num);
  font-size: 13.5px;
  font-weight: 700;
}
.rank.top { background: var(--accent-soft); color: #c2410c; }
.ov-table { table-layout: fixed; width: 100%; }
.ov-table th:nth-child(1), .ov-table td:nth-child(1) { width: 42px; }
.ov-table th:nth-child(2), .ov-table td:nth-child(2) { width: 156px; }
.ov-table th:nth-child(3), .ov-table td:nth-child(3) { width: 240px; }
.ov-table th:nth-child(4), .ov-table td:nth-child(4) { width: 132px; }
.ov-table th:nth-child(5), .ov-table td:nth-child(5) { width: 82px; }
.ov-table th:nth-child(6), .ov-table td:nth-child(6) { width: 104px; }
.ov-table td.name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* CVE 复合键拆两级：主标识一行不折，生态/组件作次要信息 */
.ov-table .cve-id { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ov-table .cve-cell small {
  display: block;
  margin-top: 2px;
  font-size: 12.5px;
  font-weight: 400;
  color: var(--ink-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
@media (max-width: 1500px) {
  .ov-table th:nth-child(2), .ov-table td:nth-child(2) { width: 140px; }
  .ov-table th:nth-child(3), .ov-table td:nth-child(3) { width: 190px; }
  .ov-table th:nth-child(4), .ov-table td:nth-child(4) { width: 120px; }
  .ov-table th:nth-child(5), .ov-table td:nth-child(5) { width: 76px; }
  .ov-table th:nth-child(6), .ov-table td:nth-child(6) { width: 92px; }
  .ov-table .score i { width: 42px; }
}

.agent-card { display: flex; flex-direction: column; }
.agent-body { padding: 12px 16px 8px; flex: 1; }
.agent-flow { display: grid; gap: 0; }
.agent-row { display: grid; grid-template-columns: 26px minmax(0, 1fr) auto; gap: 8px; position: relative; padding-bottom: 12px; }
.agent-row::before { content: ""; position: absolute; left: 12px; top: 24px; bottom: 0; width: 1px; background: #e8f0f9; }
.agent-row:last-child { padding-bottom: 0; }
.agent-row:last-child::before { display: none; }
.agent-row .step-dot { width: 25px; height: 25px; }
.agent-row-copy { padding-top: 2px; }
.agent-row .step-title { font-size: 14px; }
.agent-row .step-note { font-size: 12.5px; }
.agent-row .step-time { color: var(--muted); font-size: 12.5px; padding-top: 4px; }
.agent-meta { display: grid; grid-template-columns: 1.7fr 0.9fr 0.7fr; gap: 8px; margin-top: 12px; padding-top: 8px; border-top: 1px solid var(--line-soft); }
.agent-meta span { display: block; color: var(--muted); font-size: 12.5px; }
.agent-meta b { display: block; margin-top: 2px; color: var(--ink); font: 700 11.5px var(--font-num); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.agent-callout { display: flex; align-items: center; gap: 8px; margin-top: 8px; padding: 8px 8px; border: 1px solid var(--high-line); border-radius: 8px; background: var(--high-soft); color: #c2410c; font-size: 13.5px; font-weight: 600; }
.agent-callout .link { margin-left: auto; color: #c2410c; font-size: 13.5px; }

@media (max-width: 1280px) {
  .overview-main, .overview-bottom { grid-template-columns: minmax(0, 1fr); }
}
</style>
