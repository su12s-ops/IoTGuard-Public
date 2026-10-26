<template>
  <div class="page">
    <PageHeader
      title="智能研判中心"
      subtitle="Analysis Rounds"
      description="自动运行：情报获取 → 版本匹配 → 风险计算 → 四智能体研判 → 审核"
    >
      <template #meta>
        <span>本轮 {{ runs.length }} 条运行</span><i class="sep" /><span>候选 {{ round?.active?.candidates ?? "—" }} 项</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="refreshAll"><Icon name="refresh" :size="15" />刷新</button>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>
    <div v-if="pipelineNote" class="error-banner soft" role="status"><Icon name="alert" :size="15" />{{ pipelineNote }}</div>
    <div v-if="reviewRunId" class="card" role="status" aria-live="polite">
      <div class="card-head">
        <div><div class="card-title">正式研判任务 <span class="mono">{{ reviewRunId }}</span></div><div class="card-desc">{{ reviewRun?.progress_message || reviewRun?.current_stage || "等待任务进度记录" }}</div></div>
        <span class="chip" :class="statusTone(reviewRun?.status)">{{ reviewRun ? statusLabel(reviewRun.status) : "状态未读取" }}</span>
      </div>
      <div class="card-foot"><span>{{ reviewError || reviewRun?.error || reviewRun?.termination_reason || "任务完成仅表示流程结束，不代表自动研判成功；修复仍需人工审批。" }}</span><span>已处理 {{ reviewRun?.processed_object_count ?? "—" }} / {{ reviewRun?.selected_object_count ?? "—" }} · 待人工 {{ reviewRun?.human_review_object_count ?? "—" }}</span></div>
    </div>

    <details class="card recover-card">
      <summary class="card-head">维护工具：中断恢复</summary>
      <div class="card-head">
        <div>
          <div class="card-title">中断恢复（维护操作）</div>
          <div class="card-desc">宿主停机等基础设施中断可能把风险留在「研判中」并阻塞新批次；本操作只回收无存活报告引用的遗留对象</div>
        </div>
        <button class="btn" type="button" :disabled="recoverBusy || runningActive" @click="openRecover"><Icon name="refresh" :size="15" />{{ recoverBusy ? "执行中…" : "检查并恢复中断遗留" }}</button>
      </div>
      <div v-if="recoverResult" class="recover-body">
        <div class="recover-stats">
          <span><i class="dot ok" />已重置回待分析 <b>{{ recoverResult.recovered }}</b></span>
          <span><i class="dot warn" />存活任务跳过 <b>{{ recoverResult.skipped?.length || 0 }}</b></span>
          <span><i class="dot crit" />子运行标记中断 <b>{{ recoverResult.interrupted_run_ids?.length || 0 }}</b></span>
        </div>
        <div v-if="recoverResult.skipped?.length" class="recover-note">
          以下对象被存活 running 报告引用，未重置（对仍存活任务禁止恢复）：
          <span v-for="item in recoverResult.skipped" :key="item.object_id" class="chip muted mono-chip">{{ item.object_id }} · {{ item.reason }}</span>
        </div>
        <div v-else class="recover-note ok">没有存活报告引用的中断对象；被重置的对象已回到「待重新分析」，可在风险队列或资产面板重新发起。</div>
      </div>
    </details>

    <Modal :open="recoverOpen" title="恢复中断遗留对象" description="维护操作：把未被存活报告引用的「研判中」风险重置回「待重新分析」，并把孤儿子运行标记为中断。" @close="recoverOpen = false">
      <ul class="recover-facts">
        <li>被存活 running 报告引用的对象会被跳过（对仍存活任务禁止恢复）。</li>
        <li>原报告、治理事件与失败原因全部保留；重置只追加恢复标记。</li>
        <li>该操作不产生新的模型调用，也不代签任何人工裁定。</li>
      </ul>
      <template #footer>
        <button class="btn" type="button" @click="recoverOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="recoverBusy" @click="doRecover">{{ recoverBusy ? "执行中…" : "执行恢复" }}</button>
      </template>
    </Modal>

    <section v-if="!hasActiveResults" class="card round-start">
      <div class="card-head">
        <div>
          <div class="card-title">开始新一轮分析</div>
          <div class="card-desc">选择本轮分析范围，然后点击上方“开始”；无需手动同步情报。</div>
        </div>
        <span class="chip info"><i class="dot" />等待开始</span>
      </div>
      <div v-if="!devices.length" style="padding: 8px 16px 4px">
        <EmptyState title="暂无接入设备" description="先在「资产与发现」完成设备接入或清单上传，再开始新一轮分析。" icon="server" />
      </div>
      <template v-else>
        <div class="device-grid">
          <button type="button" class="device-card all" :class="{ selected: selectedAssetId === 0 }" @click="selectedAssetId = 0">
            <span class="dc-icon"><Icon name="layers" :size="17" /></span>
            <b>全部设备</b>
            <span class="dc-meta">{{ devices.length }} 台 · 不限范围</span>
          </button>
          <button v-for="device in devices" :key="device.asset_id" type="button" class="device-card"
            :class="{ selected: selectedAssetId === device.asset_id }" @click="selectedAssetId = device.asset_id">
            <span class="dc-icon"><Icon :name="device.distribution === 'openwrt' ? 'router' : 'server'" :size="17" /></span>
            <b>{{ device.hostname }}</b>
            <span class="dc-meta">{{ device.distribution || "linux" }} {{ device.os_version || "" }} · {{ device.package_count }} 包</span>
            <span class="dc-flags">
              <span v-if="device.ip" class="mono">{{ device.ip }}</span>
              <span class="chip muted">匹配 {{ device.active_matches }}</span>
              <span class="chip muted">风险 {{ device.active_risks }}</span>
            </span>
          </button>
        </div>
        <div class="card-foot">
          <span>情报准备、匹配和研判由后端按顺序执行，当前阶段显示在上方进度条。</span>
        </div>
      </template>
    </section>

    <div v-if="hasActiveResults" class="agent-grid">
      <section class="card flow-card">
        <div class="card-head">
          <div><div class="card-title">任务流程</div><div class="card-desc">确定性编排 · 每步留痕</div></div>
          <span v-if="selectedRun" class="chip" :class="statusTone(selectedRun.status)"><i class="dot" />{{ statusLabel(selectedRun.status) }}</span>
        </div>
        <div v-if="loading" class="loading-line" style="padding: 24px 18px"><span class="spinner" />正在读取运行详情…</div>
        <div v-else-if="!selectedRun" class="empty-wrap" style="min-height: 320px">
          <EmptyState title="本轮暂无运行" description="点击「开始执行」发起一次研判后，执行轨迹会出现在这里。" icon="cpu" />
        </div>
        <template v-else>
          <div class="flow-steps">
            <div v-for="(step, index) in agentSteps" :key="step.key" class="flow-step-row" :class="step.state">
              <span class="fs-no">{{ index + 1 }}</span>
              <div class="fs-copy">
                <div class="fs-title">{{ step.label }}</div>
                <div class="fs-note">{{ step.note }}</div>
              </div>
              <span class="fs-state">
                <Icon v-if="step.state === 'done'" name="check-circle" :size="17" />
                <span v-else class="chip" :class="step.state === 'active' ? 'info' : 'muted'">{{ step.statusLabel }}</span>
              </span>
            </div>
          </div>
          <div class="run-facts">
            <div><span>目标</span><b :title="selectedRun.target_ref">{{ selectedRun.target_ref || "—" }}</b></div>
            <div><span>模式</span><b>{{ selectedRun.mode || "—" }}</b></div>
            <div><span>创建</span><b class="mono">{{ shortTime(selectedRun.created_at) }}</b></div>
            <div><span>运行</span><b class="mono">{{ selectedRun.run_id?.slice(0, 12) }}</b></div>
          </div>
          <div class="gate-mini">
            <div v-for="check in gateChecks" :key="check.label">
              <i class="dot" :class="check.tone" /><span>{{ check.label }}</span><b>{{ check.value }}</b>
            </div>
          </div>
        </template>
        <div class="card-foot"><span>流程结束不代表风险已获审批。</span><span class="num">{{ selectedRun?.mode || "—" }}</span></div>
      </section>

      <section class="card map-panel">
        <div class="card-head">
          <div><div class="card-title">四智能体协作</div><div class="card-desc">共享知识库 · 证据一次采集多方复用</div></div>
          <span class="chip info"><i class="dot" />{{ runningActive ? "协同运行中" : "协同待命" }}</span>
        </div>
        <div class="agent-map">
          <svg class="agent-links" viewBox="0 0 600 430" preserveAspectRatio="none" aria-hidden="true">
            <defs>
              <marker id="agent-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#b9d2f2" />
              </marker>
            </defs>
            <circle cx="300" cy="215" r="126" fill="none" stroke="#dbe9fb" stroke-width="1.2" stroke-dasharray="3 8" />
            <circle cx="300" cy="215" r="86" fill="none" stroke="#e6f0fb" stroke-width="1" />
            <path d="M300 96 C300 130 300 145 300 158" fill="none" stroke="#c7dcf6" stroke-width="1.4" stroke-dasharray="4 5" marker-end="url(#agent-arrow)" />
            <path d="M118 215 C160 215 178 215 196 215" fill="none" stroke="#c7dcf6" stroke-width="1.4" stroke-dasharray="4 5" marker-end="url(#agent-arrow)" />
            <path d="M482 215 C440 215 422 215 404 215" fill="none" stroke="#c7dcf6" stroke-width="1.4" stroke-dasharray="4 5" marker-end="url(#agent-arrow)" />
            <path d="M300 334 C300 300 300 285 300 272" fill="none" stroke="#c7dcf6" stroke-width="1.4" stroke-dasharray="4 5" marker-end="url(#agent-arrow)" />
          </svg>

          <div class="agent-core">
            <span class="core-ic"><Icon name="database" :size="26" /></span>
            <b>共享知识库</b>
            <span>统一证据链</span>
          </div>

          <div
            v-for="(agent, index) in agents"
            :key="agent.key"
            class="agent-node"
            :class="[`n${index + 1}`, agent.state]"
            :style="{ '--an-color': agent.color, '--an-soft': agent.soft }"
          >
            <div class="an-head">
              <span class="an-icon"><Icon :name="agent.icon" :size="17" /></span>
              <b>{{ agent.label }} Agent</b>
              <span class="an-state"><i class="dot" :class="agent.tone" /></span>
            </div>
            <p>{{ agent.note }}</p>
            <div class="an-foot"><span>{{ agent.output }}</span><em>{{ agent.statusLabel }}</em></div>
          </div>
        </div>
        <div v-if="detail?.activity?.roles?.length" style="padding: 0 18px 12px" aria-live="polite">
          <p v-if="detail.activity.totals?.observed">{{ detail.activity.totals.partial ? '近期记录：' : '' }}模型请求 {{ detail.activity.totals.model_requests }} 次，已返回 {{ detail.activity.totals.model_responses }} 次
            · 累计排队 {{ detail.activity.totals.queue_seconds }} 秒 · 模型等待 {{ detail.activity.totals.model_seconds }} 秒（并行时间可重叠）</p>
          <p v-for="role in detail.activity.roles" :key="role.role">
            <b>{{ activityRoleLabels[role.role] || role.role }}</b>：{{ role.error || activityPhaseLabels[role.phase] || statusLabel(role.status) }}
            <span v-if="role.elapsed_seconds != null"> · 当前步骤 {{ role.elapsed_seconds }} 秒</span>
          </p>
        </div>
        <div class="card-foot"><span>共享证据与确定性协调；每步结论都可回溯。</span><span class="num">{{ selectedRun?.trace_id?.slice(-12) || "Trace 未记录" }}</span></div>
      </section>

      <section class="card message-card">
        <div class="card-head">
          <div><div class="card-title">实时消息流</div><div class="card-desc">智能体交接与证据引用</div></div>
          <span class="chip muted">全部</span>
        </div>
        <div class="messages">
          <div v-for="(event, index) in timeline" :key="index" class="message-row">
            <span class="msg-icon" :class="event.tone"><Icon :name="event.icon" :size="15" /></span>
            <div class="msg-copy">
              <div class="msg-head"><b>{{ event.actor }}</b><time>{{ event.time }}</time></div>
              <p>{{ event.action }}</p>
            </div>
          </div>
          <div v-if="!timeline.length" class="empty-note" style="padding: 26px 18px">{{ detailError ? `详情读取失败：${detailError}` : selectedRun ? "该运行未记录消息日志；不能据此确认角色执行或结论成功。" : "暂无运行消息，选择一条运行后读取。" }}</div>
        </div>
        <div class="card-foot"><span>消息只读；写操作需人工审批。</span><span class="link" @click="refreshAll">刷新 <Icon name="refresh" :size="12" /></span></div>
      </section>
    </div>

    <section v-if="hasActiveResults" class="card">
      <div class="card-head">
        <div><div class="card-title">本轮运行</div><div class="card-desc">点击一行读取该次运行详情</div></div>
        <span class="num" style="color: var(--muted); font-size: 11.5px">{{ runs.length }} 条记录</span>
      </div>
      <div v-if="!runs.length" class="empty-note" style="padding: 18px">暂无运行记录。</div>
      <div v-else class="table-wrap">
        <table style="table-layout: fixed">
          <colgroup><col style="width: 210px" /><col style="width: 260px" /><col style="width: 100px" /><col style="width: 110px" /><col style="width: 140px" /><col style="width: 36px" /></colgroup>
          <thead><tr><th>运行</th><th>目标</th><th>模式</th><th>状态</th><th>创建时间</th><th></th></tr></thead>
          <tbody>
            <tr v-for="run in runs.slice(0, 8)" :key="run.run_id" style="cursor: pointer" :class="{ selected: run.run_id === selectedRun?.run_id }" tabindex="0" role="link" @click="select(run)" @keydown.enter="select(run)">
              <td class="mono">{{ run.run_id }}</td>
              <td class="name">{{ run.target_ref || "—" }}</td>
              <td><span class="chip muted">{{ run.mode || "—" }}</span></td>
              <td><span class="chip" :class="statusTone(run.status)"><i class="dot" />{{ statusLabel(run.status) }}</span></td>
              <td class="num" style="color: var(--muted); font-size: 11.5px">{{ shortTime(run.created_at) }}</td>
              <td><Icon name="chev-right" :size="13" style="color: #c3d1e3" /></td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>


  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import Modal from "../components/Modal.vue";
import { api, recoverInterrupted } from "../api";
import { controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { shortTime, statusLabel, statusTone } from "../utils/format";
import { consoleState } from "../stores/consoleWorkflow";

const runs = ref([]);
const selectedRun = ref(null);
const detail = ref(null);
const detailError = ref("");
const loading = ref(true);
const error = ref("");
const round = ref(null);
const devices = ref([]);
const selectedAssetId = ref(0);
watch(selectedAssetId, (value) => {
  consoleState.selectedAssetId = value;
  consoleState.selectedAssetLabel = devices.value.find(item => item.asset_id === value)?.hostname || "全部接入设备";
});

const reviewRunId = ref("");
const reviewRun = ref(null);
const reviewError = ref("");
const recoverOpen = ref(false);
const recoverBusy = ref(false);
const recoverResult = ref(null);

function openRecover() {
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    ui.tokenOpen = true;
    return;
  }
  recoverOpen.value = true;
}

async function doRecover() {
  recoverBusy.value = true;
  try {
    const result = await recoverInterrupted();
    recoverResult.value = result;
    recoverOpen.value = false;
    notify(`恢复完成：重置 ${result.recovered} 项，跳过存活引用 ${result.skipped?.length || 0} 项`, result.recovered ? "success" : "info");
    await refreshAll();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "恢复操作失败", "error");
  } finally {
    recoverBusy.value = false;
  }
}
const terminalReviewStatuses = new Set(["completed", "succeeded", "partial", "human_review", "pending_human_review", "failed", "interrupted", "cancelled", "skipped", "no_candidates", "blocked"]);
let pollTimer = null;
let refreshing = false;
let disposed = false;

const reviewPending = computed(() => Boolean(reviewRunId.value) && !terminalReviewStatuses.has(reviewRun.value?.status));
const runningActive = computed(() => reviewPending.value || Boolean(round.value?.active?.running) || consoleState.workflow?.status === "running");
const hasActiveResults = computed(() => runs.value.length > 0 || runningActive.value);

const pipelineNote = computed(() => {
  if (!round.value) return "";
  const intelCount = round.value.intel?.vulnerability_count;
  if (Number(intelCount) === 0) {
    return "本轮尚无漏洞情报，点击上方“开始”后自动获取。";
  }
  const pipeline = round.value.pipeline || {};
  if (pipeline.mode !== "on") {
    return "统一编排器未启用（LINUXGUARD_UNIFIED_PIPELINE ≠ on）：开始执行会完成匹配与风险计算，四智能体研判不会启动。";
  }
  if (!pipeline.model_configured) {
    return "未配置模型接口密钥：研判将降级为“证据不足”结论并要求人工复核，不会伪造分析结果。";
  }
  return "";
});

const agents = computed(() => {
  const detailAgents = detail.value?.agents || null;
  const definitions = [
    { key: "asset_investigator", code: "ASSET", label: "资产建模", note: "设备识别 / 拓扑建模", output: "身份与清单", icon: "user", color: "#0e9fbf", soft: "#e9faff" },
    { key: "vulnerability_analyst", code: "VULN", label: "漏洞分析", note: "CVE 分析 / 漏洞挖掘", output: "候选与命中", icon: "bug", color: "#f4622a", soft: "#fff1e8" },
    { key: "runtime_analyst", code: "RUNTIME", label: "运行时分析", note: "行为建模 / 证据聚合", output: "上下文关联", icon: "activity", color: "#2f6fed", soft: "#eef4ff" },
    { key: "decision_planner", code: "DECISION", label: "决策规划", note: "风险评级 / 处置建议", output: "决策建议", icon: "target", color: "#7c3aed", soft: "#f3eeff" }
  ];
  return definitions.map((agent) => {
    const rawStatus = detailAgents?.[agent.key]?.status;
    const mapped = ["completed", "succeeded"].includes(rawStatus) ? "done" : rawStatus === "running" ? "active" : "idle";
    return { ...agent, state: mapped, tone: rawStatus ? statusTone(rawStatus) : "muted", statusLabel: rawStatus ? statusLabel(rawStatus) : "未记录" };
  });
});

const agentSteps = computed(() => agents.value);
const activityRoleLabels = { asset_investigator: '资产调查', vulnerability_analyst: '漏洞分析', runtime_analyst: '运行时分析', decision_planner: '决策规划' };
const activityPhaseLabels = { shared_report: '等待同设备共享报告（不会重复调用模型）', queue: '等待模型槽位（最多 2 个并发请求）', model: '等待模型生成并返回', tool: '正在查询原始证据', validating: '响应已返回，正在处理与校验', failed: '请求失败' };
const activityEventLabels = { task_waiting: '等待同设备共享报告', model_waiting: '进入模型请求队列', model_started: '模型请求已发出', model_finished: '模型响应已返回', model_failed: '模型请求失败', tool_started: '开始查询证据', tool_finished: '证据查询结束' };

const timeline = computed(() => {
  if (!selectedRun.value) return [];
  const activity = detail.value?.activity?.timeline;
  if (activity?.length) return [...activity].reverse().map(event => ({
    time: shortTime(event.at), actor: activityRoleLabels[event.role] || event.role,
    action: activityEventLabels[event.event] || event.event, tone: event.event === 'model_failed' ? 'warn' : 'muted', icon: iconFor(activityRoleLabels[event.role])
  }));
  const events = detail.value?.events || [];
  if (Array.isArray(events) && events.length) {
    return events.slice(0, 6).map((event) => ({
      time: shortTime(event.created_at || event.timestamp),
      actor: event.actor || event.agent || "系统",
      action: event.action || event.event_type || event.message || "事件",
      status: event.status ? statusLabel(event.status) : "未记录",
      tone: event.status ? statusTone(event.status) : "muted",
      icon: iconFor(event.actor || event.agent)
    }));
  }
  return [];
});

const policy = computed(() => detail.value?.final?.policy || null);
const reviewCount = computed(() => (detail.value?.harness_checks || []).filter((item) => item.status === "awaiting_approval").length);
const gateChecks = computed(() => {
  const checks = detail.value?.harness_checks || [];
  return [
    { label: "证据引用", value: Array.isArray(detail.value?.harness_checks) ? `${checks.length} 项检查` : "未记录", tone: checks.length ? "ok" : "muted" },
    { label: "对象级人工审查", value: reviewCount.value ? "待签收" : "未记录待签信息", tone: reviewCount.value ? "warn" : "muted" },
    { label: "策略版本", value: policy.value?.policy_version || "未记录", tone: policy.value ? "ok" : "muted" },
    { label: "研判策略", value: policy.value?.status === "auto_confirmed" ? "研判自动确认" : policy.value?.status ? statusLabel(policy.value.status) : "未记录", tone: "muted" },
    { label: "修复执行授权", value: "仍需人工审批", tone: "warn" }
  ];
});

function iconFor(actor) {
  const text = String(actor || "");
  if (text.includes("资产")) return "user";
  if (text.includes("漏洞")) return "bug";
  if (text.includes("运行时")) return "activity";
  if (text.includes("决策")) return "target";
  if (text.includes("编排")) return "layers";
  return "bot";
}

async function select(run) {
  selectedRun.value = run;
  detail.value = null;
  detailError.value = "";
  try {
    const result = await api.get(`/unified/runs/${encodeURIComponent(run.run_id)}`, { timeout: 20000 });
    if (selectedRun.value?.run_id === run.run_id) detail.value = result.data || null;
  } catch (cause) {
    if (selectedRun.value?.run_id === run.run_id) detailError.value = cause?.response?.data?.detail || "详情接口未返回";
  }
}

async function loadRound() {
  try {
    const result = await api.get("/rounds/current", { timeout: 20000 });
    round.value = result.data || null;
    devices.value = round.value?.devices || [];
    const review = consoleState.workflow?.round?.review_run;
    if (review?.run_id && reviewRunId.value !== review.run_id) {
      reviewRunId.value = review.run_id;
      reviewRun.value = review;
    }
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "轮次状态读取失败。";
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const result = await api.get("/unified/runs", { params: { limit: 30, mode: "formal" }, timeout: 25000 });
    runs.value = result.data?.runs || result.data || [];
    if (runs.value.length) await select((selectedRun.value && runs.value.find((run) => run.run_id === selectedRun.value.run_id)) || runs.value[0]);
    else selectedRun.value = null;
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "智能体运行读取失败。";
  } finally {
    loading.value = false;
  }
}


async function loadReview() {
  if (!reviewRunId.value || (reviewRun.value && !reviewPending.value)) return;
  const runId = reviewRunId.value;
  try {
    const result = await api.get(`/analysis/runs/${encodeURIComponent(runId)}`, { timeout: 20000 });
    if (reviewRunId.value === runId) {
      reviewRun.value = result.data || null;
      reviewError.value = "";
    }
  } catch (cause) {
    if (reviewRunId.value === runId) reviewError.value = `任务状态读取失败，将继续重试：${cause?.response?.data?.detail || cause.message || "未知错误"}`;
  }
}

async function refreshAll() {
  if (refreshing) return;
  refreshing = true;
  try {
    await Promise.all([loadRound(), load(), loadReview()]);
  } finally {
    refreshing = false;
    if (!disposed) syncPolling();
  }
}

function syncPolling() {
  const shouldPoll = runningActive.value;
  if (shouldPoll && !pollTimer) {
    pollTimer = window.setInterval(() => { refreshAll(); }, 15000);
  } else if (!shouldPoll && pollTimer) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
}

onMounted(async () => {
  await refreshAll();
  syncPolling();
});
watch(runningActive, syncPolling);
watch(() => `${consoleState.workflow?.status}:${consoleState.workflow?.progress_percent}:${consoleState.workflow?.round?.review_run_id}`, refreshAll);
onUnmounted(() => {
  disposed = true;
  if (pollTimer) window.clearInterval(pollTimer);
});
</script>

<style scoped>
.recover-card .card-head { align-items: flex-start; }
.recover-body { display: grid; gap: 8px; padding: 4px 16px 12px; }
.recover-stats { display: flex; flex-wrap: wrap; gap: 14px; color: var(--muted); font-size: 11.5px; }
.recover-stats span { display: inline-flex; align-items: center; gap: 6px; }
.recover-stats b { color: var(--ink); font-family: var(--font-num); font-size: 12.5px; }
.recover-note { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; color: var(--ink-2); font-size: 11.5px; line-height: 1.6; }
.recover-note.ok { color: #067647; }
.mono-chip { font-size: 10px; height: 20px; font-family: var(--font-num); }
.recover-facts { margin: 0 0 6px; padding-left: 18px; display: grid; gap: 6px; color: var(--ink-2); font-size: 12px; line-height: 1.6; }
.round-start .card-foot { justify-content: space-between; }
.device-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(228px, 1fr));
  gap: 12px;
  padding: 6px 16px 12px;
}
.device-card {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
  padding: 14px;
  border: 1px solid #e4edf9;
  border-radius: 12px;
  background: #fff;
  cursor: pointer;
  text-align: left;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.device-card:hover { border-color: #b9d2f2; }
.device-card.selected {
  border-color: var(--accent-2, #2f6fed);
  box-shadow: 0 0 0 3px rgba(47, 111, 237, 0.12);
}
.device-card b { color: var(--ink); font-size: 12.5px; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
.dc-icon { display: grid; place-items: center; width: 32px; height: 32px; border-radius: 9px; background: #eef4ff; color: #2f6fed; }
.device-card.selected .dc-icon { background: var(--gradient-blue); color: #fff; }
.dc-meta { color: var(--muted); font-size: 10.5px; }
.dc-flags { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.dc-flags .mono { color: #64748b; font-family: var(--font-num); font-size: 10px; }
.error-banner.soft { background: #fff8ec; border-color: #f3dfb6; color: #92400e; }

.agent-grid { display: grid; grid-template-columns: 292px minmax(0, 1fr) 330px; gap: 16px; align-items: stretch; }
.flow-card, .message-card { display: flex; flex-direction: column; }
.flow-steps { padding: 8px 16px 2px; }
.flow-step-row {
  display: grid;
  grid-template-columns: 30px minmax(0, 1fr) auto;
  gap: 11px;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid var(--line-soft);
}
.flow-step-row:last-child { border-bottom: 0; }
.fs-no {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: #eef4ff;
  color: #2f6fed;
  font-family: var(--font-num);
  font-size: 12px;
  font-weight: 700;
}
.flow-step-row.done .fs-no { background: var(--low-soft); color: #067647; }
.flow-step-row.active .fs-no { background: var(--gradient-blue); color: #fff; box-shadow: 0 0 0 4px rgba(47, 111, 237, 0.12); }
.fs-title { color: var(--ink); font-size: 12.5px; font-weight: 650; }
.fs-note { color: var(--muted); font-size: 10.5px; margin-top: 2px; }
.fs-state { display: flex; align-items: center; color: var(--low); }
.fs-state .chip { height: 20px; font-size: 10px; }
.run-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0 14px; padding: 8px 16px 10px; border-top: 1px solid var(--line-soft); }
.run-facts > div { display: grid; gap: 1px; padding: 6px 0; border-bottom: 1px dashed #eef3fa; min-width: 0; }
.run-facts > div:first-child { grid-column: 1 / -1; }
.run-facts span { color: var(--muted); font-size: 9.5px; white-space: nowrap; }
.run-facts b { color: var(--ink-2); font-size: 10.5px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.gate-mini { margin-top: auto; padding: 10px 16px; border-top: 1px solid var(--line-soft); display: grid; gap: 0; }
.gate-mini div { display: flex; align-items: center; gap: 7px; height: 30px; border-bottom: 1px dashed #eef3fa; color: #5b6b82; font-size: 11px; }
.gate-mini div:last-child { border-bottom: 0; }
.gate-mini b { margin-left: auto; color: var(--muted); font: 600 10.5px var(--font-num); }

.map-panel { display: flex; flex-direction: column; }
.agent-map { position: relative; flex: 1; min-height: 440px; margin: 6px 12px 10px; }
.agent-links { position: absolute; inset: 0; width: 100%; height: 100%; }
.agent-core {
  position: absolute;
  left: 50%;
  top: 50%;
  transform: translate(-50%, -50%);
  width: 154px;
  height: 154px;
  display: grid;
  place-content: center;
  justify-items: center;
  gap: 3px;
  border-radius: 50%;
  background: radial-gradient(circle at 38% 30%, #f4f9ff, #e4efff 60%, #d5e6ff);
  box-shadow: 0 0 0 12px rgba(47, 111, 237, 0.045), inset 0 1px 0 #fff, 0 18px 30px -24px rgba(47, 111, 237, 0.6);
  z-index: 2;
}
.core-ic { display: grid; place-items: center; width: 46px; height: 46px; border-radius: 50%; background: #fff; color: #2f6fed; box-shadow: 0 8px 18px -10px rgba(47, 111, 237, 0.55); }
.agent-core b { color: var(--ink); font-size: 12.5px; font-weight: 700; margin-top: 3px; }
.agent-core span { color: var(--muted); font-size: 10px; }
.agent-node {
  position: absolute;
  width: 186px;
  padding: 10px 12px;
  border: 1px solid #e4edf9;
  border-radius: 12px;
  background: #fff;
  box-shadow: 0 16px 32px -24px rgba(16, 35, 70, 0.5);
  z-index: 3;
}
.agent-node.n1 { left: 50%; top: 4%; bottom: auto; transform: translateX(-50%); }
.agent-node.n2 { left: 0; right: auto; top: 50%; bottom: auto; transform: translateY(-50%); }
.agent-node.n3 { right: 0; left: auto; top: 50%; bottom: auto; transform: translateY(-50%); }
.agent-node.n4 { left: 50%; top: auto; bottom: 3%; transform: translateX(-50%); }
.agent-node.idle { opacity: 0.72; }
.an-head { display: flex; align-items: center; gap: 7px; }
.an-icon { display: grid; place-items: center; width: 30px; height: 30px; border-radius: 9px; background: var(--an-soft); color: var(--an-color); }
.an-head b { color: var(--ink); font-size: 11.5px; font-weight: 700; white-space: nowrap; }
.an-state { margin-left: auto; }
.agent-node p { margin: 7px 0 0; color: var(--muted); font-size: 10.5px; line-height: 1.45; }
.an-foot { display: flex; align-items: center; justify-content: space-between; margin-top: 7px; color: #64748b; font-size: 10px; }
.an-foot em { font-style: normal; color: var(--an-color); font-weight: 600; }

.messages { flex: 1; padding: 8px 14px; }
.message-row { display: flex; gap: 11px; padding: 11px 4px; border-bottom: 1px solid var(--line-soft); }
.message-row:last-child { border-bottom: 0; }
.msg-icon { display: grid; place-items: center; width: 30px; height: 30px; border-radius: 9px; background: #eef4ff; color: #2f6fed; flex: 0 0 auto; }
.msg-icon.low { background: var(--low-soft); color: #067647; }
.msg-icon.high { background: var(--high-soft); color: #c2410c; }
.msg-icon.crit { background: var(--crit-soft); color: #d92d20; }
.msg-icon.muted { background: #f3f7fc; color: #7b8ca6; }
.msg-copy { min-width: 0; flex: 1; }
.msg-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.msg-head b { color: var(--ink); font-size: 11.5px; font-weight: 650; }
.msg-head time { color: #64748b; font-family: var(--font-num); font-size: 10px; white-space: nowrap; }
.msg-copy p { margin: 3px 0 0; color: var(--muted); font-size: 10.5px; line-height: 1.5; }

@media (max-width: 1440px) {
  .agent-grid { grid-template-columns: 272px minmax(0, 1fr) 300px; }
}
@media (max-width: 1280px) {
  .agent-grid { grid-template-columns: minmax(0, 1fr); }
  .agent-map { min-height: 420px; }
}
</style>
