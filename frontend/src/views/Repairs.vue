<template>
  <div class="page">
    <PageHeader
      eyebrow="Harness remediation · controlled"
      title="修复与验证"
      description="每个计划都有哈希、授权范围与独立复验；设备写默认关闭。"
    >
      <template #meta>
        <span>{{ runs.length }} 条任务</span><i class="sep" /><span>{{ stats.pending }} 条待审批</span><i class="sep" /><span>{{ stats.running }} 条执行中</span><i class="sep" /><span>设备写：{{ controlSession.token ? "需审批" : "只读" }}</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="14" />刷新</button>
        <router-link class="btn primary" to="/risks"><Icon name="plus" :size="14" />从风险创建</router-link>
      </template>
    </PageHeader>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div class="content" style="grid-template-rows: 80px minmax(0, 1fr) 220px">
      <div class="stats">
        <div class="stat"><div class="stat-icon" style="background: var(--high-soft); color: var(--high)"><Icon name="clock" /></div><div class="stat-copy"><div class="stat-label">待审批</div><div class="stat-value">{{ stats.pending }}<small>条</small></div></div><div class="stat-delta down">需签收</div></div>
        <div class="stat"><div class="stat-icon"><Icon name="play" /></div><div class="stat-copy"><div class="stat-label">执行中</div><div class="stat-value">{{ stats.running }}<small>条</small></div></div><div class="stat-delta">{{ stats.tools }}</div></div>
        <div class="stat"><div class="stat-icon" style="background: var(--low-soft); color: var(--low)"><Icon name="check" /></div><div class="stat-copy"><div class="stat-label">机器复验通过</div><div class="stat-value">{{ stats.verified }}<small>条</small></div></div><div class="stat-delta">已记录</div></div>
        <div class="stat"><div class="stat-icon" style="background: var(--crit-soft); color: var(--crit)"><Icon name="refresh" /></div><div class="stat-copy"><div class="stat-label">已回退</div><div class="stat-value">{{ stats.rolledBack }}<small>条</small></div></div><div class="stat-delta" style="color: var(--muted)">近 30 天</div></div>
      </div>

      <div class="grid g-2-1">
        <section class="card feature">
          <div class="card-head">
            <div><div class="card-title">计划 {{ selected?.id ? selected.id.slice(0, 12) : "—" }}</div><div class="card-desc">{{ selected ? `${goalLabel(selected.plan?.goal)} · ${selected.plan?.adapter || "未指定适配器"}` : "选择一条任务读取计划" }}</div></div>
            <span v-if="selected" class="chip" :class="statusTone(selected.status)"><i class="dot" />{{ statusLabel(selected.status) }}</span>
          </div>

          <div v-if="loading" class="loading-line"><span class="spinner" />正在读取 Harness 任务…</div>
          <div v-else-if="!selected" class="empty-wrap"><EmptyState title="暂无 Harness 任务" description="从风险对象创建计划后，审批、执行与复验记录会出现在这里。" icon="wrench" /></div>
          <div v-else class="card-body plan-body">
            <div>
              <div class="stepper">
                <div v-for="(step, index) in steps" :key="step.key" class="step" :class="step.state">
                  <span class="step-dot">{{ step.state === "done" ? "✓" : String(index + 1).padStart(2, "0") }}</span>
                  <div><div class="step-title">{{ step.label }}</div><div class="step-note">{{ step.note }}</div></div>
                  <time>{{ step.time }}</time>
                </div>
              </div>
              <div v-if="steps.length === 1" class="single-step">该计划只有只读采集步骤；修复计划通常包含采集、安装、回归与业务检查。</div>
            </div>
            <div class="plan-facts">
              <div><span>目标资产</span><b>{{ selected.asset_id ?? "—" }}</b></div>
              <div><span>目标</span><b>{{ goalLabel(selected.plan?.goal) }}</b></div>
              <div><span>尝试次数</span><b>{{ selected.attempts ?? 0 }}</b></div>
              <div><span>批准人</span><b>{{ selected.approved_by || "尚未审批" }}</b></div>
              <div class="wide"><span>计划哈希</span><b class="mono">{{ selected.plan_hash || "—" }}</b></div>
              <div v-if="selected.plan?.artifact" class="wide"><span>修复产物</span><b>{{ selected.plan.artifact.package_name }} → {{ selected.plan.artifact.version }}</b></div>
            </div>
          </div>
          <div class="card-foot"><span>计划哈希在审批时锁定；执行前再次校验资产身份与哈希。</span><span class="num">{{ selected?.plan?.policy_version || "—" }}</span></div>
        </section>

        <section class="card">
          <div class="card-head">
            <div><div class="card-title">审批与执行</div><div class="card-desc">批准不等于执行；执行前重新校验</div></div>
            <span v-if="selected" class="chip" :class="statusTone(selected.status)"><i class="dot" />{{ statusLabel(selected.status) }}</span>
          </div>
          <div v-if="selected" class="card-body" style="padding-top: 10px">
            <div class="approval-band" :class="approvalTone">
              <span class="ic"><Icon name="alert" :size="15" /></span>
              <div><div class="t">{{ approvalTitle }}</div><div class="d">{{ approvalCopy }}</div></div>
            </div>
            <div class="checklist">
              <div><i class="dot" :class="controlSession.token ? 'ok' : 'warn'" />操作令牌 <span>{{ controlSession.token ? "已设置" : "未设置" }}</span></div>
              <div><i class="dot" :class="selected.plan_hash ? 'ok' : 'warn'" />计划哈希 <span>{{ selected.plan_hash ? "已锁定" : "缺失" }}</span></div>
              <div><i class="dot" :class="selected.asset_id ? 'ok' : 'warn'" />资产作用域 <span>{{ selected.asset_id ? `asset ${selected.asset_id}` : "未记录" }}</span></div>
              <div><i class="dot" :class="selected.approved_by ? 'ok' : 'warn'" />人工签收 <span>{{ selected.approved_by || "待审批" }}</span></div>
            </div>
            <div class="approval-actions">
              <button v-if="selected.status === 'awaiting_approval'" class="btn primary" type="button" :disabled="!controlSession.token" @click="openApproval">批准计划</button>
              <button v-else-if="selected.status === 'approved'" class="btn primary" type="button" :disabled="!controlSession.token || busy" @click="execute">{{ busy ? "执行中…" : "执行计划" }}</button>
              <button v-else-if="selected.status === 'verified'" class="btn" type="button" disabled>复验通过</button>
              <button v-else class="btn" type="button" disabled>{{ statusLabel(selected.status) }}</button>
              <router-link class="btn" to="/runtime">查看审计</router-link>
            </div>
            <p class="field-hint" style="margin-top: 8px">批准动作写入审计；执行失败会先复读状态，不会自动重写设备。</p>
          </div>
          <div class="card-foot"><span>{{ selected?.approved_by || "无批准人记录" }}</span><span>{{ selected?.approval_reason || "无审批理由" }}</span></div>
        </section>
      </div>

      <section class="card">
        <div class="card-head" style="padding-top: 11px"><div><div class="card-title">最近任务</div><div class="card-desc">包含调查、采集与修复；机器复验与人工签收分开记录</div></div><span class="link" @click="load">刷新 <Icon name="refresh" :size="11" /></span></div>
        <div v-if="!runs.length" class="empty-note" style="padding: 14px 17px">暂无任务记录。</div>
        <div v-else class="table-wrap">
          <table style="table-layout: fixed">
            <colgroup><col style="width: 138px" /><col style="width: 160px" /><col style="width: 110px" /><col style="width: 116px" /><col style="width: 140px" /><col style="width: 100px" /><col style="width: 20px" /></colgroup>
            <thead><tr><th>任务</th><th>资产</th><th>目标</th><th>状态</th><th>当前步骤</th><th>更新</th><th></th></tr></thead>
            <tbody>
              <tr v-for="run in runs.slice(0, 3)" :key="run.id" style="cursor: pointer" :style="{ background: run.id === selected?.id ? 'var(--accent-soft)' : '' }" @click="select(run)">
                <td class="mono">{{ run.id.slice(0, 12) }}</td>
                <td class="name">asset {{ run.asset_id }}</td>
                <td>{{ goalLabel(run.plan?.goal) }}</td>
                <td><span class="chip" :class="statusTone(run.status)" style="height: 18px; font-size: 8px"><i class="dot" />{{ statusLabel(run.status) }}</span></td>
                <td class="mono" style="font-size: 9px">{{ run.current_step || "—" }}</td>
                <td class="num" style="font-size: 8.5px; color: var(--muted)">{{ shortTime(run.updated_at) }}</td>
                <td><Icon name="chev-right" :size="11" style="color: var(--line-strong)" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

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
import { shortTime, statusLabel, statusTone } from "../utils/format";

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
  rolledBack: runs.value.filter((run) => run.status === "rolled_back").length,
  tools: runs.value.length ? `${runs.value.length} 条记录` : "无记录"
}));

const steps = computed(() => {
  const run = selected.value;
  if (!run) return [];
  const planSteps = run.plan?.steps?.length ? run.plan.steps : ["collect_inventory", "install_fix", "regression_check", "business_check"];
  const current = Math.max(0, planSteps.indexOf(run.current_step));
  const finished = ["completed", "verified", "succeeded"].includes(run.status);
  return planSteps.slice(0, 4).map((step, index) => {
    const state = finished || index < current ? "done" : index === current && ["running", "approved", "queued_remote"].includes(run.status) ? "active" : "idle";
    return {
      key: step,
      label: toolLabel(step),
      note: stepNote(step, run),
      time: state === "done" ? "已记录" : state === "active" ? "进行中" : "—",
      state
    };
  });
});

const approvalTone = computed(() => (selected.value?.status === "awaiting_approval" ? "high" : selected.value?.status === "approved" ? "ok" : "muted"));
const approvalTitle = computed(() => {
  if (!selected.value) return "";
  if (selected.value.status === "awaiting_approval") return "需要人工签收";
  if (selected.value.status === "approved") return "已批准 · 等待执行";
  if (selected.value.status === "running") return "执行中";
  if (selected.value.status === "verified") return "复验通过";
  return statusLabel(selected.value.status);
});
const approvalCopy = computed(() => {
  if (!selected.value) return "";
  if (selected.value.status === "awaiting_approval") return "批准人签收后会进入执行队列；执行前会再次校验身份与哈希。";
  if (selected.value.status === "approved") return "计划已锁定；执行会调用已登记修复产物。";
  return selected.value.error || "当前状态不需要额外动作。";
});

function goalLabel(value) {
  return { collect: "只读采集", repair: "受控修复", investigate: "调查任务" }[value] || value || "—";
}
function toolLabel(value) {
  return { collect_inventory: "采集资产清单", install_fix: "安装已登记修复产物", regression_check: "漏洞回归检查", business_check: "业务检查", collect_logs: "采集日志" }[value] || value || "—";
}
function stepNote(step, run) {
  if (step === "collect_inventory") return run.asset_id ? `asset ${run.asset_id} · 清单` : "等待资产";
  if (step === "install_fix") return run.plan?.artifact ? `${run.plan.artifact.package_name} ${run.plan.artifact.version}` : "等待已登记产物";
  if (step === "regression_check") return "复跑公告适用性";
  if (step === "business_check") return "HTTP 身份端点 / 业务探针";
  return "—";
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
.plan-body { display: grid; grid-template-columns: 1fr 232px; gap: 20px; padding-top: 8px; }
.plan-facts { border-left: 1px solid var(--line-soft); padding-left: 16px; display: grid; align-content: start; gap: 7px; }
.plan-facts div { display: flex; justify-content: space-between; gap: 8px; font-size: 9px; }
.plan-facts span { color: var(--muted); }
.plan-facts b { color: var(--ink-2); font-weight: 600; text-align: right; }
.plan-facts .wide { display: block; padding-top: 7px; border-top: 1px solid var(--line-soft); }
.plan-facts .wide b { display: block; margin-top: 3px; text-align: left; word-break: break-all; font: 600 8.5px var(--font-num); color: var(--ink-3); }
.approval-band { display: flex; align-items: center; gap: 9px; padding: 9px 10px; border: 1px solid var(--line); background: var(--surface-2); }
.approval-band.high { border-color: var(--high-line); background: var(--high-soft); }
.approval-band.ok { border-color: var(--low-line); background: var(--low-soft); }
.approval-band .ic { display: grid; place-items: center; width: 27px; height: 27px; background: var(--surface); color: var(--high); flex: 0 0 auto; }
.approval-band.ok .ic { color: var(--low); }
.approval-band .t { font-size: 10px; font-weight: 700; color: var(--ink); }
.approval-band .d { font-size: 8.5px; color: var(--muted); margin-top: 2px; line-height: 1.45; }
.checklist { display: grid; gap: 0; margin-top: 8px; }
.checklist div { display: flex; align-items: center; gap: 7px; height: 31px; border-bottom: 1px solid var(--line-soft); font-size: 9.5px; }
.checklist div:last-child { border-bottom: 0; }
.checklist span { margin-left: auto; color: var(--muted); font: 8.5px var(--font-num); }
.approval-actions { display: flex; gap: 6px; margin-top: 9px; }
.approval-actions .btn { flex: 1; height: 31px; font-size: 10px; }
.single-step { margin: 8px 0 0; padding: 8px 9px; border: 1px solid var(--line-soft); background: var(--surface-2); color: var(--muted); font-size: 8.5px; line-height: 1.5; }
.empty-wrap { display: grid; place-items: center; min-height: 300px; }
.empty-note { color: var(--muted); font-size: 9.5px; }
</style>
