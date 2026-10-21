<template>
  <div class="page">
    <PageHeader
      eyebrow="Multi-agent analysis · unified runtime"
      title="智能研判"
      description="四个智能体共享证据、按确定性流程协作；流程结束不等于风险已获审批。"
    >
      <template #meta>
        <span>{{ runs.length }} 条运行</span><i class="sep" /><span>{{ completedCount }} 条已完成</span><i class="sep" /><span>{{ selectedRun?.target_ref || "未选择运行" }}</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="14" />刷新</button>
        <router-link class="btn" to="/risks"><Icon name="bug" :size="14" />风险队列</router-link>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 152px minmax(0, 1fr) 128px">
      <section class="card" style="padding: 0 13px; justify-content: center">
        <div class="pipeline" style="height: 118px">
          <div v-for="(agent, index) in agents" :key="agent.key" class="pipe-card" :class="agent.state" style="height: 118px">
            <div class="pipe-top">
              <span class="pipe-no">0{{ index + 1 }} / {{ agent.code }}</span>
              <span class="chip" :class="agent.tone" style="height: 18px; font-size: 8px; margin-left: auto"><i class="dot" />{{ agent.statusLabel }}</span>
            </div>
            <div class="pipe-role">{{ agent.label }}</div>
            <div class="pipe-state">{{ agent.note }}</div>
            <div class="pipe-meta"><span>{{ agent.output }}</span><span>{{ agent.time }}</span></div>
            <div class="conf-bar" style="margin-top: 6px"><i :style="{ width: agent.progress, background: agent.barColor }" /></div>
          </div>
        </div>
      </section>

      <div class="grid g-2-1">
        <section class="card">
          <div class="card-head">
            <div><div class="card-title">运行轨迹</div><div class="card-desc">目标、状态与智能体交接；详情读取失败时只展示已返回字段</div></div>
            <span class="chip muted num" style="height: 18px; font-size: 8px">{{ selectedRun?.run_id || "—" }}</span>
          </div>
          <div v-if="loading" class="loading-line"><span class="spinner" />正在读取运行详情…</div>
          <div v-else-if="!selectedRun" class="empty-wrap"><EmptyState title="暂无智能体运行" description="发起一次研判后，四个智能体的执行轨迹会出现在这里。" icon="cpu" /></div>
          <div v-else class="card-body" style="padding-top: 8px">
            <div class="trace-list">
              <div v-for="(event, index) in timeline" :key="index" class="trace-row">
                <span class="trace-time num">{{ event.time }}</span>
                <i class="dot" :class="event.tone" />
                <span class="trace-copy"><b>{{ event.actor }}</b> {{ event.action }}</span>
                <span class="chip" :class="event.tone" style="height: 18px; font-size: 8px">{{ event.status }}</span>
              </div>
            </div>
            <div v-if="detailError" class="field-hint" style="margin-top: 8px">详情接口未返回：{{ detailError }}</div>
          </div>
          <div class="card-foot"><span>共享证据与确定性协调；流程结束不代表风险已获审批。</span><span class="num">{{ selectedRun?.mode || "—" }}</span></div>
        </section>

        <section class="card">
          <div class="card-head">
            <div><div class="card-title">决策门禁</div><div class="card-desc">机器结论必须通过的四道检查</div></div>
            <span class="chip" :class="reviewCount ? 'high' : 'muted'"><i class="dot" />{{ reviewCount ? "待人工审查" : "无待审" }}</span>
          </div>
          <div class="card-body" style="padding-top: 8px">
            <div class="gate-check" v-for="check in gateChecks" :key="check.label">
              <i class="dot" :class="check.tone" /><span>{{ check.label }}</span><b>{{ check.value }}</b>
            </div>
            <div class="gate-callout">
              <Icon name="alert" :size="12" />
              <span>{{ reviewCount ? `${reviewCount} 条记录待人工审查` : "暂无待人工审查记录" }}</span>
            </div>
            <router-link class="btn primary" to="/risks" style="width: 100%; height: 30px; font-size: 10.5px">进入人工审查</router-link>
            <p class="field-hint" style="margin-top: 7px">门禁结果会写入审计，不会自动执行修复。</p>
          </div>
          <div class="card-foot"><span>{{ selectedRun?.trace_id || "Trace 未记录" }}</span><router-link class="link" to="/runtime">运行审计 <Icon name="chev-right" :size="11" /></router-link></div>
        </section>
      </div>

      <section class="card">
        <div class="card-head" style="padding-top: 11px">
          <div><div class="card-title">最近运行</div><div class="card-desc">点击一行读取该次运行详情</div></div>
          <span class="link" @click="load">刷新 <Icon name="refresh" :size="11" /></span>
        </div>
        <div v-if="!runs.length" class="empty-note" style="padding: 14px 17px">暂无运行记录。</div>
        <div v-else class="table-wrap">
          <table style="table-layout: fixed">
            <colgroup><col style="width: 222px" /><col style="width: 250px" /><col style="width: 92px" /><col style="width: 100px" /><col style="width: 112px" /><col style="width: 20px" /></colgroup>
            <thead><tr><th>运行</th><th>目标</th><th>模式</th><th>状态</th><th>创建时间</th><th></th></tr></thead>
            <tbody>
              <tr v-for="run in runs.slice(0, 3)" :key="run.run_id" style="cursor: pointer" :style="{ background: run.run_id === selectedRun?.run_id ? 'var(--accent-soft)' : '' }" @click="select(run)">
                <td class="mono">{{ run.run_id }}</td>
                <td class="name">{{ run.target_ref || "—" }}</td>
                <td><span class="chip muted" style="height: 18px; font-size: 8px">{{ run.mode || "—" }}</span></td>
                <td><span class="chip" :class="statusTone(run.status)" style="height: 18px; font-size: 8px"><i class="dot" />{{ statusLabel(run.status) }}</span></td>
                <td class="num" style="font-size: 8.5px; color: var(--muted)">{{ shortTime(run.created_at) }}</td>
                <td><Icon name="chev-right" :size="11" style="color: var(--line-strong)" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import { api } from "../api";
import { shortTime, statusLabel, statusTone } from "../utils/format";

const runs = ref([]);
const selectedRun = ref(null);
const detail = ref(null);
const detailError = ref("");
const loading = ref(true);
const error = ref("");

const completedCount = computed(() => runs.value.filter((run) => ["completed", "succeeded"].includes(run.status)).length);

const agents = computed(() => {
  const status = selectedRun.value?.status;
  const detailAgents = detail.value?.agents || null;
  const definitions = [
    { key: "asset_investigator", code: "ASSET", label: "资产调查", note: "读取身份、清单与对象", output: "证据对象", progress: "100%", barColor: "var(--low)" },
    { key: "vulnerability_analyst", code: "VULN", label: "漏洞分析", note: "公告适用性与版本比对", output: "候选与命中", progress: "100%", barColor: "var(--low)" },
    { key: "runtime_analyst", code: "RUNTIME", label: "运行时分析", note: "Falco / logread 证据", output: "上下文关联", progress: "66%", barColor: "var(--accent)" },
    { key: "decision_planner", code: "DECISION", label: "决策规划", note: "策略门禁与人工审查", output: "决策建议", progress: "0%", barColor: "var(--line-strong)" }
  ];
  return definitions.map((agent, index) => {
    const rawStatus = detailAgents?.[agent.key]?.status || (status === "completed" ? "completed" : status === "running" ? (index < 2 ? "completed" : index === 2 ? "running" : "pending") : "pending");
    const mapped = rawStatus === "completed" || rawStatus === "succeeded" ? "done" : rawStatus === "running" ? "active" : "idle";
    const tone = rawStatus === "completed" || rawStatus === "succeeded" ? "low" : rawStatus === "running" ? "accent" : "muted";
    return {
      ...agent,
      state: mapped,
      tone,
      statusLabel: statusLabel(rawStatus),
      progress: mapped === "done" ? "100%" : mapped === "active" ? "66%" : "0%",
      barColor: mapped === "done" ? "var(--low)" : mapped === "active" ? "var(--accent)" : "var(--line-strong)",
      time: rawStatus === "completed" || rawStatus === "running" ? "已记录" : "—"
    };
  });
});

const timeline = computed(() => {
  if (!selectedRun.value) return [];
  const events = detail.value?.events || [];
  if (Array.isArray(events) && events.length) {
    return events.slice(0, 7).map((event) => ({
      time: shortTime(event.created_at || event.timestamp),
      actor: event.actor || event.agent || "系统",
      action: event.action || event.event_type || event.message || "事件",
      status: statusLabel(event.status || "completed"),
      tone: statusTone(event.status || "completed")
    }));
  }
  const run = selectedRun.value;
  const rows = [
    { time: shortTime(run.created_at), actor: "编排器", action: `创建 ${run.mode || "统一"} 运行`, status: statusLabel(run.status), tone: statusTone(run.status) },
    { time: "—", actor: "资产调查", action: `目标 ${run.target_ref || "未记录"}`, status: statusLabel(run.status === "completed" ? "completed" : "running"), tone: statusTone(run.status === "completed" ? "completed" : "running") },
    { time: "—", actor: "漏洞分析", action: "公告适用性与版本比对", status: statusLabel(run.status === "completed" ? "completed" : "running"), tone: statusTone(run.status === "completed" ? "completed" : "running") },
    { time: "—", actor: "运行时分析", action: "读取运行时证据与上下文", status: statusLabel(run.status === "completed" ? "completed" : "waiting"), tone: statusTone(run.status === "completed" ? "completed" : "waiting") },
    { time: shortTime(run.completed_at), actor: "决策规划", action: "门禁结果与人工审查", status: statusLabel(run.status), tone: statusTone(run.status) }
  ];
  return rows;
});

const policy = computed(() => detail.value?.final?.policy || null);
const policyLabel = computed(() => policy.value?.status ? statusLabel(policy.value.status) : "待详情");
const policyTone = computed(() => (policy.value?.status ? statusTone(policy.value.status) : "muted"));
const reviewCount = computed(() => (detail.value?.harness_checks || []).filter((item) => item.status === "awaiting_approval").length);
const gateChecks = computed(() => {
  const checks = detail.value?.harness_checks || [];
  return [
    { label: "证据引用", value: `${checks.length || 0} 项检查`, tone: checks.length ? "ok" : "muted" },
    { label: "对象级人工审查", value: reviewCount.value ? "待签收" : "无待签", tone: reviewCount.value ? "warn" : "ok" },
    { label: "策略版本", value: policy.value?.policy_version || "未记录", tone: policy.value ? "ok" : "muted" },
    { label: "执行授权", value: policy.value?.status === "auto_confirmed" ? "自动" : "需人工", tone: policy.value?.status === "auto_confirmed" ? "ok" : "warn" }
  ];
});

async function select(run) {
  selectedRun.value = run;
  detail.value = null;
  detailError.value = "";
  try {
    const result = await api.get(`/unified/runs/${encodeURIComponent(run.run_id)}`, { timeout: 20000 });
    detail.value = result.data || null;
  } catch (cause) {
    detailError.value = cause?.response?.data?.detail || "详情接口未返回";
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const result = await api.get("/unified/runs", { params: { limit: 30 }, timeout: 25000 });
    runs.value = result.data?.runs || result.data || [];
    if (runs.value.length) await select(selectedRun.value && runs.value.find((run) => run.run_id === selectedRun.value.run_id) || runs.value[0]);
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "智能体运行读取失败。";
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.pipe-card.idle { opacity: .7; }
.trace-list { display: grid; }
.trace-row { display: grid; grid-template-columns: 66px 12px minmax(0, 1fr) 66px; gap: 8px; align-items: center; min-height: 44px; border-bottom: 1px solid var(--line-soft); }
.trace-row:last-child { border-bottom: 0; }
.trace-time { color: var(--muted); font-size: 8.5px; }
.trace-copy { color: var(--ink-2); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trace-copy b { color: var(--ink); font-weight: 650; }
.gate-check { display: flex; align-items: center; gap: 7px; height: 36px; border-bottom: 1px solid var(--line-soft); font-size: 10px; color: var(--ink-2); }
.gate-check b { margin-left: auto; color: var(--muted); font: 600 9px var(--font-num); }
.gate-callout { display: flex; align-items: center; gap: 7px; margin: 9px 0; padding: 8px 9px; border: 1px solid var(--high-line); background: var(--high-soft); color: var(--high); font-size: 9px; font-weight: 600; }
.empty-wrap { display: grid; place-items: center; min-height: 250px; }
.empty-note { color: var(--muted); font-size: 9.5px; }
</style>
