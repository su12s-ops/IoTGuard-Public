<template>
  <div class="page">
    <PageHeader
      title="修复与验证"
      subtitle="Harness Remediation"
      description="每个计划都有哈希、授权范围与独立复验"
    >
      <template #meta>
        <span>{{ runs.length }} 条任务</span><i class="sep" /><span>{{ stats.pending }} 条待审批</span><i class="sep" /><span>{{ stats.running }} 条执行中</span><i class="sep" /><span>设备写：{{ controlSession.token ? "需审批" : "只读" }}</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="15" />刷新</button>
        <router-link class="btn" to="/risks"><Icon name="plus" :size="15" />从风险创建</router-link>
        <button class="btn primary" type="button" :disabled="!selected || !primaryEnabled" @click="primaryAction">{{ primaryLabel }}</button>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <section class="card step-card">
      <div class="step-card-head">
        <div class="step-target">
          <router-link class="back-link" to="/risks"><Icon name="chev-left" :size="13" />返回风险队列</router-link>
          <b>{{ selected?.id?.slice(0, 12) || "未选择任务" }}</b>
          <span v-if="selected" class="chip crit"><i class="dot" />{{ goalLabel(selected.plan?.goal) }}</span>
          <span v-if="selected" class="chip info">asset {{ selected.asset_id }}</span>
          <span v-if="selected" class="chip" :class="statusTone(selected.status)"><i class="dot" />{{ statusLabel(selected.status) }}</span>
        </div>
        <div class="step-stats">
          <span><i class="dot" style="background: #f5b301" />待审批 <b>{{ stats.pending }}</b></span>
          <span><i class="dot" style="background: #2f6fed" />执行中 <b>{{ stats.running }}</b></span>
          <span><i class="dot" style="background: #12b76a" />复验通过 <b>{{ stats.verified }}</b></span>
        </div>
      </div>
      <div class="step-track">
        <template v-for="(step, index) in pipelineSteps" :key="step.key">
          <div class="track-step" :class="step.state">
            <span class="track-no">{{ step.state === "done" ? "✓" : step.state === "skip" ? "—" : index + 1 }}</span>
            <span class="track-label">{{ step.label }}</span>
          </div>
          <span v-if="index < pipelineSteps.length - 1" class="track-line" />
        </template>
      </div>
    </section>

    <div v-if="loading" class="card loading-line" style="padding: 30px 20px"><span class="spinner" />正在读取 Harness 任务…</div>
    <div v-else-if="!selected" class="card">
      <EmptyState title="暂无 Harness 任务" description="从风险对象创建计划后，审批、执行与复验记录会出现在这里。" icon="wrench" />
    </div>
    <div v-else class="plan-grid">
      <section class="plan-panel">
        <div class="pp-head"><Icon name="file" :size="16" />修复方案</div>
        <div class="plan-rows">
          <div class="plan-row"><span>方案描述</span><b>{{ goalCopy }}</b></div>
          <div class="plan-row"><span>影响范围</span><b>asset {{ selected.asset_id }} · {{ selected.plan?.plan?.adapter || selected.plan?.collector_type || "标准采集器" }}</b></div>
          <div class="plan-row"><span>执行策略</span><b>{{ executionCopy }}</b></div>
          <div class="plan-row"><span>回滚策略</span><b>{{ rollbackCopy }}</b></div>
          <div class="plan-row"><span>策略版本</span><b class="mono">{{ selected.plan?.policy_version || selected.plan?.plan?.policy_version || "—" }}</b></div>
        </div>
        <div class="plan-hash" :title="selected.plan_hash">
          <span>计划哈希</span>
          <b class="mono">{{ selected.plan_hash ? `${selected.plan_hash.slice(0, 24)}…` : "缺失" }}</b>
        </div>
      </section>

      <section class="plan-panel">
        <div class="pp-head"><Icon name="shield" :size="16" />审批信息</div>
        <div class="plan-rows">
          <div class="plan-row"><span>审批状态</span><b><span class="chip" :class="statusTone(selected.status)"><i class="dot" />{{ statusLabel(selected.status) }}</span></b></div>
          <div class="plan-row"><span>申请人</span><b>{{ selected.approved_by || "尚未提交" }}</b></div>
          <div class="plan-row"><span>申请时间</span><b class="mono">{{ dateTime(selected.created_at) }}</b></div>
          <div class="plan-row"><span>审批说明</span><b>{{ selected.approval_reason || "批准后会锁定计划哈希；执行前再次校验资产身份。" }}</b></div>
        </div>
        <div class="approve-actions">
          <button class="btn danger-line" type="button" :disabled="!canCancel" @click="cancelRun">取消任务</button>
          <button class="btn primary" type="button" :disabled="!primaryEnabled" @click="primaryAction">{{ primaryLabel }}</button>
        </div>
        <div class="approval-note"><Icon name="lock" :size="12" />批准与执行都会写入审计，不会自动改写设备。</div>
      </section>

      <section class="plan-panel">
        <div class="pp-head"><Icon name="check-circle" :size="16" />执行验证</div>
        <div class="verify-list">
          <div v-for="check in verificationChecks" :key="check.label" class="verify-row">
            <span class="ok-ic" :class="{ pending: !check.ok }">
              <Icon :name="check.ok ? 'check' : 'clock'" :size="12" />
            </span>
            <span>{{ check.label }}</span>
            <span class="chip" :class="check.ok ? 'low' : 'high'">{{ check.value }}</span>
          </div>
        </div>
        <div class="verify-foot">
          <span>机器复验与人工签收分开记录</span>
          <span class="num">{{ selected.attempts ?? 0 }} 次尝试</span>
        </div>
      </section>
    </div>

    <section class="card">
      <div class="card-head">
        <div><div class="card-title">最近任务</div><div class="card-desc">包含调查、采集与修复；机器复验与人工签收分开记录</div></div>
        <span class="num" style="color: var(--muted); font-size: 11.5px">{{ runs.length }} 条记录</span>
      </div>
      <div v-if="!runs.length" class="empty-note" style="padding: 18px">暂无任务记录。</div>
      <div v-else class="table-wrap">
        <table style="table-layout: fixed">
          <colgroup><col style="width: 140px" /><col style="width: 110px" /><col style="width: 130px" /><col style="width: 130px" /><col style="width: 180px" /><col style="width: 130px" /><col style="width: 44px" /></colgroup>
          <thead><tr><th>任务</th><th>资产</th><th>目标</th><th>状态</th><th>当前步骤</th><th>更新</th><th></th></tr></thead>
          <tbody>
            <tr v-for="run in runs.slice(0, 5)" :key="run.id" style="cursor: pointer" :class="{ selected: run.id === selected?.id }" tabindex="0" role="link" @click="select(run)" @keydown.enter="select(run)">
              <td class="mono">{{ run.id.slice(0, 12) }}</td>
              <td class="name">asset {{ run.asset_id }}</td>
              <td>{{ goalLabel(run.plan?.goal) }}</td>
              <td><span class="chip" :class="statusTone(run.status)"><i class="dot" />{{ statusLabel(run.status) }}</span></td>
              <td class="mono" style="font-size: 11.5px">{{ toolLabel(run.current_step) }}</td>
              <td class="num" style="color: var(--muted); font-size: 11.5px">{{ shortTime(run.updated_at) }}</td>
              <td><Icon name="chev-right" :size="13" style="color: #c3d1e3" /></td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <Modal :open="approvalOpen" title="批准修复计划" description="批准会锁定计划哈希并写入审计；批准本身不会执行设备写。" @close="approvalOpen = false">
      <label class="field-label" for="approver">批准人</label>
      <input id="approver" v-model="actor" class="input" placeholder="例如：wang.gong" autocomplete="off" />
      <label class="field-label" for="approval-reason">审批理由</label>
      <textarea id="approval-reason" v-model="reason" class="textarea" placeholder="确认资产、作用域与回滚准备。"></textarea>
      <p class="field-hint">计划哈希：<span class="mono">{{ selected?.plan_hash || "—" }}</span></p>
      <template #footer>
        <button class="btn" type="button" @click="approvalOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="busy || !actor.trim() || !reason.trim()" @click="approve">{{ busy ? "提交中…" : "批准计划" }}</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import Modal from "../components/Modal.vue";
import { api } from "../api";
import { controlSession } from "../api/controlSession";
import { notify } from "../stores/ui";
import { dateTime, shortTime, statusLabel, statusTone } from "../utils/format";

const runs = ref([]);
const selected = ref(null);
const loading = ref(true);
const error = ref("");
const busy = ref(false);
const approvalOpen = ref(false);
const actor = ref("");
const reason = ref("");

const stats = computed(() => ({
  pending: runs.value.filter((run) => run.status === "awaiting_approval").length,
  running: runs.value.filter((run) => ["running", "queued_remote"].includes(run.status)).length,
  verified: runs.value.filter((run) => run.status === "verified").length,
  rolledBack: runs.value.filter((run) => run.status === "rolled_back").length
}));

const pipelineSteps = computed(() => {
  const run = selected.value;
  if (!run) {
    return [
      { key: "plan", label: "修复计划" },
      { key: "preflight", label: "执行前检查" },
      { key: "approval", label: "人工审批" },
      { key: "execute", label: "执行修复" },
      { key: "verify", label: "效果验证" }
    ].map((step) => ({ ...step, state: "idle" }));
  }
  const status = run.status;
  const approved = ["approved", "running", "queued_remote", "completed", "verified", "rolled_back", "failed"].includes(status);
  const approvalNotRequired = run.plan?.goal === "collect";
  return [
    { key: "plan", label: "修复计划", state: "done" },
    { key: "preflight", label: "执行前检查", state: run.plan_hash && run.asset_id ? "done" : "active" },
    { key: "approval", label: "人工审批", state: approvalNotRequired && !run.approved_by ? "skip" : approved ? "done" : status === "awaiting_approval" ? "active" : "idle" },
    { key: "execute", label: "执行修复", state: ["completed", "verified"].includes(status) ? "done" : ["running", "queued_remote"].includes(status) ? "active" : "idle" },
    { key: "verify", label: "效果验证", state: status === "verified" ? "done" : "idle" }
  ];
});

const primaryLabel = computed(() => {
  if (!selected.value) return "提交审批";
  const status = selected.value.status;
  if (status === "awaiting_approval") return "提交审批";
  if (status === "approved") return "执行计划";
  if (["running", "queued_remote"].includes(status)) return "执行中…";
  if (status === "verified") return "复验通过";
  return statusLabel(status);
});
const primaryEnabled = computed(() => {
  if (!selected.value) return false;
  const status = selected.value.status;
  if (status === "awaiting_approval") return Boolean(controlSession.token);
  if (status === "approved") return Boolean(controlSession.token) && !busy.value;
  return false;
});
const canCancel = computed(() => selected.value && ["awaiting_approval", "approved", "running", "queued_remote"].includes(selected.value.status) && Boolean(controlSession.token));

const goalCopy = computed(() => {
  const goal = selected.value?.plan?.goal;
  return { collect: "只读采集：读取清单与运行时日志，不修改设备", repair: "受控修复：安装已登记修复产物并回归验证", investigate: "调查任务：汇总证据并生成研判" }[goal] || "—";
});
const executionCopy = computed(() => {
  const steps = selected.value?.plan?.steps;
  if (Array.isArray(steps) && steps.length) return steps.map((step) => toolLabel(step)).join(" → ");
  return toolLabel(selected.value?.current_step) || "—";
});
const rollbackCopy = computed(() => {
  const goal = selected.value?.plan?.goal;
  return goal === "collect" ? "只读采集不修改设备；无需回滚" : "执行失败自动回滚，并开启监控告警";
});

const verificationChecks = computed(() => {
  const run = selected.value;
  if (!run) return [];
  return [
    { label: "计划哈希锁定", ok: Boolean(run.plan_hash), value: run.plan_hash ? "已锁定" : "缺失" },
    { label: "资产作用域", ok: Boolean(run.asset_id), value: run.asset_id ? `asset ${run.asset_id}` : "未记录" },
    { label: "操作令牌", ok: Boolean(controlSession.token), value: controlSession.token ? "已设置" : "未设置" },
    { label: "人工签收", ok: Boolean(run.approved_by), value: run.approved_by || "待审批" },
    { label: "机器复验", ok: run.status === "verified", value: run.status === "verified" ? "通过" : "待执行" }
  ];
});

function goalLabel(value) {
  return { collect: "只读采集", repair: "受控修复", investigate: "调查任务" }[value] || value || "—";
}
function toolLabel(value) {
  return {
    collect_inventory: "采集资产清单",
    install_fix: "安装修复产物",
    regression_check: "漏洞回归检查",
    business_check: "业务检查",
    collect_logs: "采集运行时日志"
  }[value] || value || "—";
}

async function primaryAction() {
  if (!selected.value) return;
  if (selected.value.status === "awaiting_approval") {
    openApproval();
    return;
  }
  if (selected.value.status === "approved") {
    await execute();
  }
}

async function select(run) {
  selected.value = run;
  try {
    const result = await api.get(`/harness/runs/${encodeURIComponent(run.id)}`, { timeout: 20000 });
    selected.value = result.data || run;
  } catch {
    /* list record is enough for display */
  }
}

function openApproval() {
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    return;
  }
  approvalOpen.value = true;
}

async function approve() {
  if (!selected.value) return;
  busy.value = true;
  try {
    const result = await api.post(
      `/harness/runs/${encodeURIComponent(selected.value.id)}/approve`,
      { plan_hash: selected.value.plan_hash, actor: actor.value.trim(), reason: reason.value.trim() },
      { headers: { "X-Control-Token": controlSession.token }, timeout: 30000 }
    );
    selected.value = result.data || selected.value;
    approvalOpen.value = false;
    actor.value = "";
    reason.value = "";
    notify("计划已批准；执行前会再次校验", "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "批准失败", "error");
  } finally {
    busy.value = false;
  }
}

async function execute() {
  if (!selected.value) return;
  busy.value = true;
  try {
    const result = await api.post(`/harness/runs/${encodeURIComponent(selected.value.id)}/execute`, null, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 120000
    });
    selected.value = result.data || selected.value;
    notify("执行请求已提交", "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "执行失败", "error");
  } finally {
    busy.value = false;
  }
}

async function cancelRun() {
  if (!selected.value) return;
  busy.value = true;
  try {
    await api.post(`/harness/runs/${encodeURIComponent(selected.value.id)}/cancel`, null, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 30000
    });
    notify("任务已取消", "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "取消失败", "error");
  } finally {
    busy.value = false;
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const result = await api.get("/harness/runs", { timeout: 30000 });
    runs.value = result.data?.runs || result.data || [];
    if (runs.value.length) {
      const keep = selected.value && runs.value.find((run) => run.id === selected.value.id);
      await select(keep || runs.value[0]);
    } else {
      selected.value = null;
    }
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "Harness 任务读取失败。";
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.step-card { padding: 14px 18px 12px; }
.step-card-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--line-soft); flex-wrap: wrap; }
.step-target { display: flex; align-items: center; gap: 9px; min-width: 0; flex-wrap: wrap; }
.step-target .back-link { margin-right: 4px; }
.step-target b { color: var(--ink); font-family: var(--font-num); font-size: 14px; font-weight: 700; }
.step-stats { display: flex; align-items: center; gap: 16px; color: var(--muted); font-size: 11.5px; }
.step-stats span { display: inline-flex; align-items: center; gap: 6px; }
.step-stats b { color: var(--ink); font-family: var(--font-num); font-size: 12.5px; }
.step-track { padding: 18px 10px 6px; }
.step-track .track-step.skip .track-no { background: #f6f9fd; color: #9aa9c0; border-style: dashed; }
.step-track .track-step.skip .track-label { color: #8b9bb1; }

.plan-grid { display: grid; grid-template-columns: minmax(0, 1.08fr) minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
.plan-panel { display: flex; flex-direction: column; border: 1px solid #e6eef8; border-radius: 12px; background: #fff; overflow: hidden; box-shadow: 0 1px 2px rgba(16, 35, 70, 0.03); }
.pp-head { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--line-soft); background: #f9fbfe; color: var(--ink); font-size: 13px; font-weight: 700; }
.pp-head .icon { color: var(--accent-2); }
.plan-rows { display: grid; }
.plan-row { display: grid; grid-template-columns: 74px minmax(0, 1fr); gap: 12px; padding: 10px 16px; border-bottom: 1px solid var(--line-soft); font-size: 12px; }
.plan-row:last-child { border-bottom: 0; }
.plan-row > span { color: var(--muted); }
.plan-row b { color: var(--ink-2); font-weight: 600; line-height: 1.5; }
.plan-row b .chip { height: 22px; font-size: 11px; }
.plan-hash { margin-top: auto; padding: 11px 16px; border-top: 1px solid var(--line-soft); background: #fbfdff; display: grid; gap: 3px; }
.plan-hash span { color: var(--muted); font-size: 10.5px; }
.plan-hash b { color: var(--ink-3); font-size: 10.5px; font-weight: 600; }
.approve-actions { display: flex; gap: 8px; padding: 12px 16px 8px; margin-top: auto; }
.approve-actions .btn { flex: 1; height: 36px; }
.approval-note { display: flex; align-items: center; gap: 6px; padding: 0 16px 12px; color: #64748b; font-size: 10.5px; }
.verify-list { display: grid; }
.verify-row { display: flex; align-items: center; gap: 9px; padding: 10px 16px; border-bottom: 1px solid var(--line-soft); color: var(--ink-2); font-size: 12px; }
.verify-row:last-child { border-bottom: 0; }
.ok-ic { display: grid; place-items: center; width: 20px; height: 20px; border-radius: 50%; background: var(--low-soft); color: #067647; }
.ok-ic.pending { background: var(--high-soft); color: #c2410c; }
.verify-row .chip { margin-left: auto; height: 22px; font-size: 11px; }
.verify-foot { margin-top: auto; display: flex; align-items: center; justify-content: space-between; padding: 11px 16px; border-top: 1px solid var(--line-soft); background: #fbfdff; color: var(--muted); font-size: 10.5px; }

@media (max-width: 1280px) {
  .plan-grid { grid-template-columns: minmax(0, 1fr); }
}
</style>
