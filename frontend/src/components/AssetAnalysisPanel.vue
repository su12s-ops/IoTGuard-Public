<template>
  <div class="analysis-panel">
    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <div class="analysis-head">
      <div class="analysis-title">
        <b>{{ assetName }}</b>
        <small>
          资产 <span class="mono">#{{ asset?.asset_id || "—" }}</span>
          · 分析任务 <span class="mono">{{ round?.round_id || "尚未创建" }}</span>
        </small>
      </div>
      <div class="analysis-state">
        <span class="chip muted">{{ stageText }}</span>
        <span class="chip" :class="roundTone">{{ roundStatusText }}</span>
      </div>
    </div>

    <div v-if="blockedReason" class="error-banner soft" role="status">
      <Icon name="alert" :size="15" />阻断原因：{{ blockedReason }}
    </div>

    <div class="kpi-grid">
      <div class="kpi"><span>候选数</span><b>{{ count("candidates") }}</b><small>可进入研判 {{ count("eligible") }}</small></div>
      <div class="kpi"><span>本轮选择</span><b>{{ count("selected") }}</b><small>上限 {{ round?.batch_cap || 20 }}</small></div>
      <div class="kpi"><span>已处理</span><b>{{ count("processed") }}</b><small>{{ progressText }}</small></div>
      <div class="kpi"><span>剩余未处理</span><b :class="{ warn: count('remaining') > 0 }">{{ count("remaining") }}</b><small>含未进入本批的候选</small></div>
      <div class="kpi"><span>失败</span><b :class="{ bad: count('failed') > 0 }">{{ count("failed") }}</b><small>角色降级 {{ count("degraded") }} 条</small></div>
      <div class="kpi"><span>结论去向</span><b class="small-b">{{ outcomeText }}</b><small>自动确认 {{ count("auto_confirmed") }} · 待人工 {{ count("human_review") }}</small></div>
    </div>

    <div class="basis-grid">
      <div><span>清单采集时间</span><b class="mono">{{ round?.inventory?.collected_at ? formatBackendTime(round.inventory.collected_at) : "未记录" }}</b></div>
      <div><span>清单 SHA-256</span><b class="mono" :title="round?.inventory?.sha256 || ''">{{ shortHash(round?.inventory?.sha256) }}</b></div>
      <div><span>清单证据</span><b class="mono">{{ round?.inventory?.evidence_id || "未记录" }}</b></div>
      <div><span>情报更新时间</span><b class="mono">{{ round?.intel?.updated_at ? formatBackendTime(round.intel.updated_at) : "未记录" }}</b></div>
      <div><span>运行时证据</span><b :class="{ warn: runtimeStale }">{{ runtimeText }}</b></div>
      <div><span>统一研判</span><b>{{ pipelineText }}</b></div>
    </div>

    <div class="analysis-actions">
      <button class="btn primary" type="button" :disabled="starting || running" @click="startAnalysis">
        <Icon name="play" :size="14" />{{ starting ? "启动中…" : running ? "本轮执行中" : "开始分析" }}
      </button>
      <button class="btn" type="button" :disabled="loading" @click="loadRound"><Icon name="refresh" :size="14" />刷新状态</button>
      <router-link v-if="reviewRunId" class="link" :to="'/agents'">查看研判任务 <Icon name="chev-right" :size="12" /></router-link>
      <span class="hint">一次点击连续执行：漏洞匹配 → 风险计算 → 对符合条件的风险发起四智能体研判。</span>
    </div>

    <div v-if="notice" class="notice-line" role="status">{{ notice }}</div>

    <div v-if="loading && !round" class="loading-line"><span class="spinner" />正在读取该资产的分析轮次…</div>

    <div v-else-if="round && round.status === 'no_candidates'" class="empty-analysis">
      <EmptyState
        title="本轮零候选"
        description="匹配与风险计算已完成，但该资产在本轮没有可进入正式研判的风险对象。本页不会伪造风险或模型结论。"
        icon="shield"
      />
    </div>

    <template v-if="round">
      <div class="section-head">
        <div><b>本轮风险与研判结果</b><small>每行对应一个具体 risk_id；未进入本轮的对象单独列出。</small></div>
        <span class="chip muted">{{ round.objects?.length || 0 }} 条</span>
      </div>
      <div v-if="round.objects?.length" class="table-wrap">
        <table style="table-layout: fixed">
          <colgroup><col style="width: 70px" /><col style="width: 150px" /><col style="width: 130px" /><col style="width: 110px" /><col style="width: 120px" /><col style="width: 110px" /><col style="width: 70px" /></colgroup>
          <thead><tr><th>risk</th><th>CVE</th><th>组件</th><th>研判状态</th><th>结论去向</th><th>分数 / 等级</th><th>证据</th></tr></thead>
          <tbody>
            <tr v-for="item in round.objects" :key="item.risk_id">
              <td><router-link class="mono link" :to="`/risks/${item.risk_id}`">#{{ item.risk_id }}</router-link></td>
              <td class="name">{{ item.cve_id }}</td>
              <td class="mono">{{ item.package_name || "—" }}</td>
              <td><span class="chip" :class="statusTone(item.review_status)"><i class="dot" />{{ statusLabel(item.review_status) }}</span></td>
              <td><span class="chip" :class="dispositionTone(item.disposition)"><i class="dot" />{{ dispositionLabel(item.disposition) }}</span></td>
              <td class="num">
                <span v-if="item.final_score !== null && item.final_score !== undefined">{{ score(item.final_score) }} · {{ levelLabel(item.risk_level) }}</span>
                <span v-else class="muted-text">基线 {{ score(item.preliminary_score) }} · {{ levelLabel(item.preliminary_level) }}</span>
              </td>
              <td class="num">{{ item.review_evidence_ids?.length || 0 }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-note" style="padding: 16px">本轮尚无已选中的风险对象。</div>

      <div v-if="round.skipped_objects?.length" class="skipped-block">
        <div class="section-head"><div><b>未进入本批的对象</b><small>原因如实展示；这些对象未调用模型。</small></div><span class="chip high">{{ round.skipped_objects.length }} 条</span></div>
        <div class="skip-list">
          <div v-for="item in round.skipped_objects" :key="item.object_id" class="skip-row">
            <span class="mono">{{ item.object_id }}</span>
            <span>{{ item.cve_id || "对象未在当前资产范围内" }}{{ item.package_name ? ` · ${item.package_name}` : "" }}</span>
            <span class="chip muted">{{ reasonLabel(item.reason) }}</span>
          </div>
        </div>
      </div>

      <div v-if="round.history_objects?.length" class="skipped-block">
        <div class="section-head"><div><b>该资产的历史风险（不在本轮）</b><small>已有历史风险只有在事实变化、重新进入可研判状态或被正式要求再研判时才参与本轮。</small></div><span class="chip muted">{{ round.history_objects.length }} 条</span></div>
        <div class="skip-list">
          <div v-for="item in round.history_objects.slice(0, 12)" :key="item.risk_id" class="skip-row">
            <router-link class="mono link" :to="`/risks/${item.risk_id}`">#{{ item.risk_id }}</router-link>
            <span>{{ item.cve_id }} · {{ item.package_name || "—" }}</span>
            <span class="chip muted">{{ statusLabel(item.review_status) }}</span>
            <span class="chip muted">{{ reasonLabel(item.reason) }}</span>
          </div>
        </div>
      </div>

      <div class="round-foot">
        <span>轮次完成只表示本批对象已处理，不等于风险自动确认或修复授权。</span>
        <span>开始 {{ round.started_at ? formatBackendTime(round.started_at) : "—" }} · 更新 {{ round.updated_at ? formatBackendTime(round.updated_at) : "—" }}</span>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import Icon from "./Icon.vue";
import EmptyState from "./EmptyState.vue";
import { api } from "../api";
import { controlRequest, controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { levelLabel, score, statusLabel, statusTone } from "../utils/format";
import { formatBackendTime } from "../utils/deviceCollection";

const props = defineProps({
  asset: { type: Object, default: null },
  refreshKey: { type: Number, default: 0 }
});
const emit = defineEmits(["started"]);

const round = ref(null);
const loading = ref(false);
const starting = ref(false);
const error = ref("");
const notice = ref("");
let timer = null;
let disposed = false;

const assetId = computed(() => Number(props.asset?.asset_id) || 0);
const assetName = computed(() => props.asset?.name || props.asset?.hostname || `资产 #${assetId.value || "—"}`);
const running = computed(() => round.value?.status === "running");
const reviewRunId = computed(() => round.value?.review_run_id || round.value?.review_run?.run_id || "");
const blockedReason = computed(() => {
  if (!round.value) return "";
  if (round.value.status === "blocked" || round.value.status === "failed" || round.value.status === "interrupted") return round.value.blocked_reason || round.value.error || "";
  if (round.value.blocked_reason && round.value.status === "partial") return round.value.blocked_reason;
  return "";
});
const runtimeStale = computed(() => {
  const fresh = round.value?.runtime_evidence?.fresh;
  return fresh === false;
});
const runtimeText = computed(() => {
  const runtime = round.value?.runtime_evidence;
  if (!runtime) return "未读取";
  if (runtime.fresh === true) return `新鲜 · 最近事件 ${runtime.latest_event_age_seconds ?? "—"} 秒前`;
  if (runtime.fresh === false) return `已过期 · 最近事件 ${runtime.latest_event_age_seconds ?? "—"} 秒前，不能当作当前行为证据`;
  return "无可用运行时证据";
});
const pipelineText = computed(() => {
  const pipeline = round.value?.pipeline;
  if (!pipeline) return "未读取";
  return `${pipeline.mode === "on" ? "已启用" : pipeline.mode || "未启用"} · ${pipeline.model || "模型未记录"} · ${pipeline.api_protocol || "协议未记录"}`;
});
const stageText = computed(() => ({
  matching: "漏洞匹配",
  risk_calculation: "风险计算",
  candidate_selection: "候选选择",
  reviewing: "四智能体研判",
  completed: "本轮结束",
  blocked: "已阻断",
  failed: "失败"
}[round.value?.stage] || (round.value ? "状态未记录" : "尚未开始")));
const roundStatusText = computed(() => ({
  running: "执行中",
  completed: "已结束",
  partial: "部分完成",
  failed: "失败",
  blocked: "已阻断",
  no_candidates: "零候选",
  interrupted: "已中断"
}[round.value?.status] || "尚未开始"));
const roundTone = computed(() => ({
  running: "accent",
  completed: "low",
  partial: "high",
  failed: "crit",
  blocked: "crit",
  no_candidates: "muted",
  interrupted: "crit"
}[round.value?.status] || "muted"));
const progressText = computed(() => {
  const counts = round.value?.counts;
  if (!counts) return "未开始";
  return `${counts.processed}/${counts.selected} 已处理`;
});
const outcomeText = computed(() => ({
  auto_confirmed: "自动确认",
  human_review: "待人工复核",
  mixed: "自动 + 人工",
  partial: "部分失败",
  failed: "失败",
  no_result: "无结论",
  no_candidates: "零候选"
}[round.value?.outcome] || "未记录"));

function count(key) {
  return round.value?.counts?.[key] ?? 0;
}

function shortHash(value) {
  if (!value) return "未记录";
  return value.length > 20 ? `${value.slice(0, 16)}…` : value;
}

function dispositionLabel(value) {
  return ({
    auto_confirmed: "自动确认",
    human_review: "待人工复核",
    failed: "失败",
    processing: "处理中",
    eligible_not_processed: "本轮未处理"
  }[value] || value || "未记录");
}
function dispositionTone(value) {
  return ({ auto_confirmed: "low", human_review: "high", failed: "crit", processing: "accent" }[value] || "muted");
}
function reasonLabel(value) {
  return ({
    bounded_queue: "超出本轮批次上限",
    single_risk_scope: "仅分析指定单条风险",
    status_not_reviewable: "状态不可研判",
    inactive: "已失效",
    nvd_package_mapping_quarantined: "NVD 包名映射隔离",
    exact_match_missing: "缺少精确匹配",
    exact_match_ambiguous: "精确匹配不唯一",
    match_not_found: "匹配记录缺失",
    not_selected_in_this_round: "不在本轮范围",
    not_selected: "未选中"
  }[value] || value || "未说明");
}

async function loadRound() {
  if (!assetId.value) {
    round.value = null;
    return;
  }
  loading.value = true;
  error.value = "";
  try {
    const result = await api.get("/rounds/current", { params: { asset_id: assetId.value }, timeout: 25000 });
    round.value = result.data?.round || null;
    syncPolling();
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "分析轮次读取失败。";
  } finally {
    loading.value = false;
  }
}

async function refreshRound() {
  if (!round.value?.round_id) return loadRound();
  try {
    const result = await api.get(`/rounds/${encodeURIComponent(round.value.round_id)}`, { timeout: 25000 });
    round.value = result.data || round.value;
    syncPolling();
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "分析轮次状态读取失败，将继续重试。";
  }
}

async function startAnalysis() {
  if (!assetId.value) {
    notify("该设备没有可分析的登记资产 ID。", "error");
    return;
  }
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    ui.tokenOpen = true;
    return;
  }
  starting.value = true;
  error.value = "";
  notice.value = "";
  try {
    const result = await api.post("/rounds/start", {
      asset_id: assetId.value,
      risk_id: 0,
      batch_size: 0,
      investigation_goal: ""
    }, { ...controlRequest(), timeout: 180000 });
    const body = result.data || {};
    round.value = body.round || round.value;
    const counts = round.value?.counts || {};
    if (body.reused) {
      notice.value = `已恢复运行中的轮次 ${round.value?.round_id || ""}，未创建重复任务。`;
    } else if (round.value?.status === "no_candidates") {
      notice.value = `本轮完成匹配 ${counts.matches ?? 0} 项、风险计算 ${counts.risks_calculated ?? 0} 项；零候选，未调用模型。`;
    } else if (round.value?.status === "blocked") {
      notice.value = `匹配与风险计算已完成，但研判未启动：${round.value.blocked_reason || "原因未记录"}`;
    } else {
      notice.value = `已启动分析轮次 ${round.value?.round_id || ""}：候选 ${counts.candidates ?? 0} 条，本轮选择 ${counts.selected ?? 0} 条。`;
    }
    emit("started", round.value);
    syncPolling();
  } catch (cause) {
    const detail = cause?.response?.data?.detail;
    error.value = typeof detail === "string" ? detail : (cause?.response?.data?.detail?.error || "分析启动失败。");
    if (cause?.response?.status === 401) {
      ui.tokenOpen = true;
    }
  } finally {
    starting.value = false;
  }
}

function syncPolling() {
  const shouldPoll = running.value;
  if (shouldPoll && !timer && !disposed) {
    timer = window.setInterval(refreshRound, 5000);
  } else if (!shouldPoll && timer) {
    window.clearInterval(timer);
    timer = null;
  }
}

watch(() => props.asset?.asset_id, () => {
  stopPolling();
  round.value = null;
  notice.value = "";
  error.value = "";
  loadRound();
});
watch(() => props.refreshKey, () => loadRound());

onMounted(loadRound);
onUnmounted(stopPolling);

function stopPolling() {
  disposed = false;
  if (timer) {
    window.clearInterval(timer);
    timer = null;
  }
}
</script>

<style scoped>
.analysis-panel { display: grid; gap: 14px; }
.analysis-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 2px 2px 0; }
.analysis-title { display: grid; gap: 4px; }
.analysis-title b { color: var(--ink); font-size: 14px; }
.analysis-title small { color: var(--muted); font-size: 11px; }
.analysis-state { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; }
.kpi { display: grid; gap: 3px; padding: 12px 14px; border: 1px solid #e4edf9; border-radius: 12px; background: #fff; }
.kpi span { color: var(--muted); font-size: 11px; }
.kpi b { color: var(--ink); font-size: 21px; line-height: 1.1; }
.kpi b.small-b { font-size: 14px; }
.kpi b.warn { color: #b45309; }
.kpi b.bad { color: #b42318; }
.kpi small { color: var(--muted); font-size: 10px; }
.basis-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px 18px; padding: 12px 14px; border: 1px solid var(--line-soft); border-radius: 12px; background: #fbfdff; }
.basis-grid div { display: flex; justify-content: space-between; gap: 12px; font-size: 11px; }
.basis-grid span { color: var(--muted); }
.basis-grid b { color: var(--ink-2); font-weight: 600; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.basis-grid b.warn { color: #b45309; }
.analysis-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.analysis-actions .hint { color: var(--muted); font-size: 11px; }
.notice-line { padding: 9px 12px; border-radius: 9px; background: #f2f8ff; color: #245b9e; font-size: 11.5px; }
.empty-analysis { padding: 4px 0; }
.section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 4px 2px; }
.section-head b { color: var(--ink); font-size: 12.5px; }
.section-head small { display: block; color: var(--muted); font-size: 10.5px; margin-top: 2px; }
.skipped-block { display: grid; gap: 6px; }
.skip-list { display: grid; gap: 4px; }
.skip-row { display: grid; grid-template-columns: 90px minmax(0, 1fr) auto auto; gap: 10px; align-items: center; padding: 7px 10px; border-radius: 8px; background: #f8fafc; font-size: 11px; color: var(--ink-2); }
.round-foot { display: flex; justify-content: space-between; gap: 12px; padding: 10px 2px 0; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 10.5px; }
.muted-text { color: var(--muted); }
.link { color: var(--accent-2, #2f6fed); text-decoration: none; }
</style>
