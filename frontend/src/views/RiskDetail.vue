<template>
  <div class="page">
    <header class="page-head risk-head">
      <div class="ph-row">
        <div class="ph-copy">
          <router-link class="back-link" to="/risks"><Icon name="chev-left" :size="13" />返回风险队列</router-link>
          <div class="risk-title">
            <h1>{{ row?.cve_id || id }}</h1>
            <span v-if="row" class="sev"><i class="dot" style="width: 5px; height: 5px; background: currentColor" />{{ levelLabel(level) }} · CVSS {{ cvss(row.cvss_score) }}</span>
            <span v-if="row" class="chip muted">{{ row.active === false ? "历史归档" : "当前风险" }}</span>
          </div>
        </div>
        <TopActions />
      </div>
      <div class="ph-row">
        <div class="ph-sub">
          <span v-if="row" class="pkg">{{ row.package_name || "—" }}</span><i class="sep" />
          <span v-if="row">{{ row.hostname }}</span><i class="sep" />
          <span>{{ row?.updated_at ? `更新于 ${dateTime(row.updated_at)}` : "更新时间未记录" }}</span><i class="sep" />
          <span>risk_id {{ row?.risk_id ?? "—" }}</span>
        </div>
        <div class="actions">
          <button class="btn" type="button" @click="openDecision('reject')"><Icon name="flag" :size="15" />标记误报</button>
          <button class="btn" type="button" :disabled="roundBusy" @click="openRound"><Icon name="play" :size="15" />{{ roundBusy ? "启动中…" : "分析本风险" }}</button>
          <button class="btn primary" type="button" @click="openRepair"><Icon name="wrench" :size="15" />创建修复任务</button>
        </div>
      </div>
    </header>

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="13" />{{ error }}</div>

    <div v-if="loading" class="loading-line"><span class="spinner" />正在读取风险对象…</div>
    <div v-else-if="!row" class="card"><EmptyState title="未找到该风险对象" description="它可能已被归档、合并，或不在当前风险队列中。" icon="bug" /></div>

    <template v-else>
      <div class="content">
        <section class="card summary">
          <div class="cell"><div class="label">风险分</div><div class="value">{{ score(riskScore) }}</div><div class="hint">{{ levelLabel(level) }} · {{ decisionLabel }}</div></div>
          <div class="cell"><div class="label">CVSS</div><div class="value">{{ cvss(row.cvss_score) }}</div><div class="hint">{{ row.preliminary_level || "—" }}</div></div>
          <div class="cell"><div class="label">EPSS</div><div class="value">{{ row.epss_score !== undefined ? `${row.epss_score}%` : "—" }}</div><div class="hint">未来 30 天</div></div>
          <div class="cell"><div class="label">CISA KEV</div><div class="value">{{ Number(row.kev_score) > 0 ? "是" : "否" }}</div><div class="hint">{{ Number(row.kev_score) > 0 ? "已知在野利用" : "未列入" }}</div></div>
          <div class="cell"><div class="label">运行时证据</div><div class="value text" :style="{ color: runtimeTone(rt) === 'low' ? 'var(--low)' : runtimeTone(rt) === 'high' ? 'var(--high)' : 'var(--ink)' }">{{ runtimeLabel(rt) }}</div><div class="hint">Falco / logread</div></div>
          <div class="cell"><div class="label">处置建议</div><div class="value text" :style="{ color: decisionTone }">{{ decisionLabel }}</div><div class="hint">需人工确认</div></div>
        </section>

        <div class="grid risk-grid" style="grid-template-columns: minmax(0, 1.9fr) minmax(0, 1fr)">
          <div class="grid" style="grid-template-rows: auto auto; align-content: start">
            <section class="card feature">
              <div class="card-head">
                <div><div class="card-title">判定依据</div><div class="card-desc">四步独立判定；任一步缺失都会降级为“证据不足”。</div></div>
                <span class="link" @click="openEvidence">查看原始证据 <Icon name="chev-right" :size="12" /></span>
              </div>
              <div class="flow">
                <div class="flow-step">
                  <div class="no">01 · ADVISORY</div><div class="t">公告适用性</div>
                  <div class="m">{{ row.cve_id }}<br />NVD / Canonical</div>
                  <div class="s"><span class="chip" :class="affectedTone"><i class="dot" />{{ affectedLabel }}</span></div>
                </div>
                <div class="flow-step">
                  <div class="no">02 · VERSION</div><div class="t">版本比对</div>
                  <div class="m">CVSS {{ cvss(row.cvss_score) }} · {{ statusLabel(row.affected_status || "unknown") }}<br />{{ row.package_name || "组件未记录" }}</div>
                  <div class="s"><span class="chip" :class="Number(row.patch_score) > 0 ? 'low' : 'muted'"><i class="dot" />{{ Number(row.patch_score) > 0 ? "已比对" : "待补证" }}</span></div>
                </div>
                <div class="flow-step">
                  <div class="no">03 · EXPOSURE</div><div class="t">服务暴露</div>
                  <div class="m">{{ routeText(row.reachable_status) }}<br />reachable_status</div>
                  <div class="s"><span class="chip" :class="reachableTone"><i class="dot" />{{ reachableLabel }}</span></div>
                </div>
                <div class="flow-step">
                  <div class="no">04 · RUNTIME</div><div class="t">运行时证据</div>
                  <div class="m">{{ evidenceCount }} 条关联事件<br />{{ row.runtime_reason || "未观察到利用链" }}</div>
                  <div class="s"><span class="chip" :class="runtimeTone(rt)"><i class="dot" />{{ runtimeLabel(rt) }}</span></div>
                </div>
              </div>

              <div class="factor-wrap">
                <div class="factor-head"><span class="h">风险分解</span><span class="n">综合 {{ score(riskScore) }} / 100</span></div>
                <div v-for="factor in factors" :key="factor.label" class="factor">
                  <span>{{ factor.label }}</span><span class="track"><i class="fill" :style="{ width: `${Math.min(100, factor.value)}%`, background: factor.tone }" /></span><span class="val">{{ Math.round(factor.value) }}</span>
                </div>
              </div>

              <div class="card-foot"><span>{{ flowSummary }}</span><span class="num">policy v3</span></div>
            </section>

            <section class="terminal">
              <div class="term-head"><span>Evidence / runtime</span><span class="right"><i class="dot" />{{ evidenceTime }}</span></div>
              <pre>{{ terminalText }}</pre>
              <div class="term-foot"><span>{{ evidenceCount }} 条事件 · {{ row.cve_id }}</span><span class="link" style="color: #7fd6c8" @click="openEvidence">打开证据 <Icon name="chev-right" :size="11" /></span></div>
            </section>
          </div>

          <div class="grid" style="grid-template-rows: auto auto; align-content: start">
            <section class="card">
              <div class="card-head">
                <div><div class="card-title">人工裁决</div><div class="card-desc">机器结论只作为输入，不替代责任签收。</div></div>
                <span class="chip" :class="reviewTone"><i class="dot" />{{ reviewLabel }}</span>
              </div>
              <div class="card-body decision" style="padding-top: 10px">
                <div class="recommend">
                  <span class="ic"><Icon name="alert" :size="14" /></span>
                  <div><div class="t">{{ decisionLabel }}</div><div class="d">{{ recommendation }}</div></div>
                </div>
                <div class="verdict-grid">
                  <div class="verdict-cell">
                    <span class="v-label">机器结论</span>
                    <b class="v-value">{{ verdictLabel }}</b>
                    <span class="v-hint">置信 {{ pct(Number(row.review_confidence ?? row.decision_confidence ?? 0) * 100) }}{{ row.review_adjustment ? ` · 修正 +${row.review_adjustment}` : "" }}</span>
                  </div>
                  <div class="verdict-cell">
                    <span class="v-label">降级角色</span>
                    <b class="v-value">{{ row.review_failed_agents?.length ? row.review_failed_agents.join("、") : "无（四角色完整）" }}</b>
                    <span class="v-hint">{{ row.review_failed_agents?.length ? "预算/证据边界导致降级" : "本轮无角色降级" }}</span>
                  </div>
                </div>
                <div v-if="missingEvidence.length" class="gap-block">
                  <div class="g-head"><Icon name="search" :size="12" />证据缺口（{{ missingEvidence.length }}）<span class="link" @click="gapsOpen = !gapsOpen">{{ gapsOpen ? "收起" : "展开全部" }}</span></div>
                  <ul class="g-list">
                    <li v-for="gap in visibleGaps" :key="gap">{{ gap }}</li>
                  </ul>
                </div>
                <div v-if="conflictNotes.length" class="gap-block">
                  <div class="g-head"><Icon name="branch" :size="12" />未消解冲突（{{ conflictNotes.length }}）</div>
                  <ul class="g-list">
                    <li v-for="note in conflictNotes" :key="note">{{ note }}</li>
                  </ul>
                </div>
                <div v-if="auditReasons.length" class="gap-block">
                  <div class="g-head"><Icon name="shield" :size="12" />进入人工复核的策略原因</div>
                  <div class="audit-chips">
                    <span v-for="reason in auditReasons" :key="reason" class="chip muted mono-chip">{{ reason }}</span>
                  </div>
                </div>
                <div>
                  <div class="conf-top"><span>模型置信度</span><b>{{ pct(row.decision_confidence ? Number(row.decision_confidence) * 100 : 0) }}</b></div>
                  <div class="conf-bar"><i :style="{ width: `${Math.min(100, Number(row.decision_confidence || 0) * 100)}%` }" /></div>
                </div>
                <div class="field">
                  <label>裁决理由</label>
                  <div class="textarea">{{ row.decision_reason || row.preliminary_reason || "尚无裁决理由；人工签收后会写入审计。" }}</div>
                </div>
                <div class="gate-list">
                  <div><i class="dot" :class="row.cve_id ? 'ok' : 'warn'" />证据引用 <span>{{ evidenceCount }}/{{ evidenceCount }}</span></div>
                  <div><i class="dot" :class="row.human_review_required ? 'warn' : 'ok'" />对象级人工审查 <span>{{ row.human_review_required ? "待签收" : "已记录" }}</span></div>
                  <div><i class="dot ok" />资产锁与工具预算 <span>{{ controlSession.token ? "令牌已设置" : "只读" }}</span></div>
                </div>
                <div class="actions-row">
                  <button class="btn primary" type="button" @click="openDecision('confirm')">确认受影响</button>
                  <button class="btn" type="button" @click="openDecision('reject')">判为不受影响</button>
                  <button class="btn" type="button" @click="openDecision('accept_risk')">接受风险</button>
                  <button class="btn" type="button" @click="openDecision('request_reanalysis')">要求重新分析</button>
                </div>
                <div class="decision-note">裁定由操作员提交并写入审计；确认/接受风险前必须已有四智能体当期结论。不代签、不自动确认。</div>
              </div>
              <div class="card-foot"><span class="num">AUD-{{ row.risk_id || "—" }}</span><span>{{ row.reviewed_by ? `签收人 ${row.reviewed_by}` : "等待签收" }}</span></div>
            </section>

            <section class="card">
              <div class="card-head" style="padding-top: 12px"><div class="card-title" style="font-size: 12px">关联记录</div><span class="link" @click="router.push('/risks')">全部 <Icon name="chev-right" :size="11" /></span></div>
              <div class="rel"><span class="ic"><Icon name="branch" :size="11" /></span><span class="name">匹配记录</span><span class="id">#{{ row.match_id ?? "—" }}</span><span class="chip" :class="affectedTone"><i class="dot" />{{ affectedLabel }}</span><span class="chev"><Icon name="chev-right" :size="11" /></span></div>
              <div class="rel"><span class="ic"><Icon name="shield" :size="11" /></span><span class="name">风险事件</span><span class="id">R-{{ row.risk_id ?? "—" }}</span><span class="chip" :class="reviewTone"><i class="dot" />{{ reviewLabel }}</span><span class="chev"><Icon name="chev-right" :size="11" /></span></div>
              <div class="rel" @click="router.push('/agents')"><span class="ic"><Icon name="cpu" :size="11" /></span><span class="name">Agent 运行</span><span class="id">—</span><span class="chip info"><i class="dot" />查看</span><span class="chev"><Icon name="chev-right" :size="11" /></span></div>
              <div class="rel" @click="router.push('/repairs')"><span class="ic"><Icon name="wrench" :size="11" /></span><span class="name">Harness 计划</span><span class="id">—</span><span class="chip muted"><i class="dot" />未创建</span><span class="chev"><Icon name="chev-right" :size="11" /></span></div>
            </section>
          </div>
        </div>
      </div>
    </template>

    <Modal :open="decisionOpen" :title="decisionMeta[decision]?.title || '人工裁决'" :description="decisionMeta[decision]?.hint || ''" @close="decisionOpen = false">
      <label class="field-label" for="actor">操作员标识</label>
      <input id="actor" v-model="actor" class="input" placeholder="例如：wang.gong" autocomplete="off" />
      <label class="field-label" for="reason">裁决理由</label>
      <textarea id="reason" v-model="reason" class="textarea" placeholder="写下依据、证据缺口或后续动作。"></textarea>
      <p class="field-hint">当前对象：{{ row?.cve_id }} · expected_status {{ expectedStatus }}<br />{{ decisionMeta[decision]?.note }}</p>
      <template #footer>
        <button class="btn" type="button" @click="decisionOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="submitting || !actor.trim() || !reason.trim()" @click="submitDecision">{{ submitting ? "提交中…" : "提交裁决" }}</button>
      </template>
    </Modal>

    <Modal :open="roundOpen" title="发起单风险分析轮次" description="对该风险所属资产执行：漏洞匹配 → 风险计算 → 仅本风险进入研判选择。其余候选如实标注不进入本批。" @close="roundOpen = false">
      <div class="plan-rows-mini">
        <div><span>资产</span><b>asset {{ row?.asset_id }} · {{ row?.hostname }}</b></div>
        <div><span>风险</span><b>risk-{{ row?.risk_id }} · {{ row?.cve_id }}</b></div>
        <div><span>当前审核状态</span><b>{{ expectedStatus }}</b></div>
      </div>
      <p class="field-hint">有当期结论（待人工复核/已确认等）的风险不满足再研判条件时，轮次会在匹配与风险计算后如实阻断，不会重跑模型。</p>
      <template #footer>
        <button class="btn" type="button" @click="roundOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="roundBusy" @click="submitRound">{{ roundBusy ? "启动中…" : "开始分析" }}</button>
      </template>
    </Modal>

    <Modal :open="Boolean(roundResult)" :title="roundResultTitle" :description="''" @close="roundResult = null">
      <div v-if="roundResult" class="plan-rows-mini">
        <div><span>轮次</span><b class="mono">{{ roundResult.round_id }}</b></div>
        <div><span>状态</span><b>{{ roundResult.status }}</b></div>
        <div><span>匹配 / 风险计算</span><b>{{ roundResult.counts?.matches ?? "—" }} / {{ roundResult.counts?.risks_calculated ?? "—" }}</b></div>
        <div v-if="roundResult.counts?.candidates !== undefined"><span>候选 / 选择</span><b>{{ roundResult.counts.candidates }} / {{ roundResult.counts.selected }}</b></div>
      </div>
      <div v-if="roundResult?.blocked_reason" class="blocked-box">
        <b>阻断原因</b>
        <p class="mono">{{ roundResult.blocked_reason }}</p>
      </div>
      <p class="field-hint">轮次只驱动流程；风险状态以风险事件为准，结论仍须人工复核，不自动确认。</p>
    </Modal>

    <Modal :open="repairOpen" title="创建 Harness 修复任务" description="同一资产、同一风险创建修复计划；无适用修复方案时会被策略阻断，不会伪造成功。" @close="repairOpen = false">
      <div class="plan-rows-mini">
        <div><span>资产</span><b>asset {{ row?.asset_id }} · {{ row?.hostname }}</b></div>
        <div><span>风险</span><b>risk-{{ row?.risk_id }} · {{ row?.cve_id }}</b></div>
        <div><span>当前审核状态</span><b>{{ expectedStatus }}</b></div>
      </div>
      <label class="field-label" for="artifact">修复产物（已登记清单）</label>
      <select id="artifact" v-model="artifactId" class="input">
        <option value="">不指定（后端将校验并如实阻断）</option>
        <option v-for="item in artifacts" :key="item.id" :value="item.id">{{ item.id }} · {{ item.package_name }} {{ item.version }}</option>
      </select>
      <p class="field-hint">审批与执行前检查保持不变：计划哈希锁定、人工审批、执行前资产与清单复核。</p>
      <template #footer>
        <button class="btn" type="button" @click="repairOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="repairBusy" @click="submitRepairRun">{{ repairBusy ? "创建中…" : "创建修复任务" }}</button>
      </template>
    </Modal>

    <Modal :open="Boolean(repairResult)" :title="repairResult?.status === 'blocked' ? '修复计划被策略阻断' : '修复任务已创建'" :description="''" @close="repairResult = null">
      <div v-if="repairResult" class="plan-rows-mini">
        <div><span>任务</span><b class="mono">{{ repairResult.id?.slice(0, 16) }}</b></div>
        <div><span>状态</span><b>{{ repairResult.status }}</b></div>
        <div><span>资产 / 风险</span><b>asset {{ repairResult.asset_id }} · risk-{{ repairResult.risk_id }}</b></div>
      </div>
      <div v-if="repairBlockedReasons.length" class="blocked-box">
        <div class="g-head"><Icon name="shield" :size="12" />阻断原因（如实展示，不伪造成功）</div>
        <ul class="g-list">
          <li v-for="cause in repairBlockedReasons" :key="cause">{{ cause }}</li>
        </ul>
      </div>
      <p v-else class="field-hint">计划进入待审批；请到「修复与验证」完成人工审批与执行前检查。</p>
      <template #footer>
        <button class="btn" type="button" @click="repairResult = null">关闭</button>
        <router-link v-if="repairResult && repairResult.status !== 'blocked'" class="btn primary" to="/repairs">前往修复与验证</router-link>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import Icon from "../components/Icon.vue";
import EmptyState from "../components/EmptyState.vue";
import Modal from "../components/Modal.vue";
import TopActions from "../components/TopActions.vue";
import { api, fetchBehaviorChains, fetchCveRuntimeEvidence, reviewRiskEvent, startAssetRound } from "../api";
import { createHarnessRun } from "../api/deviceOperations";
import { controlSession } from "../api/controlSession";
import { ui, notify } from "../stores/ui";
import { cvss, dateTime, levelLabel, pct, score, statusLabel } from "../utils/format";

const route = useRoute();
const router = useRouter();
const id = computed(() => String(route.params.id || ""));
const row = ref(null);
const chain = ref(null);
const evidence = ref(null);
const loading = ref(true);
const error = ref("");
const decisionOpen = ref(false);
const decision = ref("confirm");
const actor = ref("");
const reason = ref("");
const submitting = ref(false);
const gapsOpen = ref(false);
const repairOpen = ref(false);
const repairBusy = ref(false);
const repairResult = ref(null);
const artifacts = ref([]);
const artifactId = ref("");
const roundOpen = ref(false);
const roundBusy = ref(false);
const roundResult = ref(null);

const roundResultTitle = computed(() => {
  const item = roundResult.value;
  if (!item) return "分析轮次";
  if (item.status === "blocked") return "轮次被阻断（匹配与风险计算已完成）";
  if (item.status === "no_candidates") return "本轮零候选（未调用模型）";
  return `分析轮次 ${item.round_id || ""}`;
});

async function openRound() {
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    ui.tokenOpen = true;
    return;
  }
  roundResult.value = null;
  roundOpen.value = true;
}

async function submitRound() {
  if (!row.value) return;
  roundBusy.value = true;
  try {
    const result = await startAssetRound(Number(row.value.asset_id), {
      riskId: Number(row.value.risk_id ?? row.value.id)
    });
    roundResult.value = result?.round || result;
    roundOpen.value = false;
  } catch (cause) {
    const detail = cause?.response?.data?.detail;
    notify(typeof detail === "string" ? detail : (detail?.error || "分析轮次启动失败。"), "error");
    if (cause?.response?.status === 401) {
      ui.tokenOpen = true;
    }
  } finally {
    roundBusy.value = false;
  }
}

const DECISION_META = {
  confirm: {
    title: "确认受影响",
    hint: "最终裁定：确认风险真实受影响，进入处置与修复候选。",
    note: "需要四智能体当期结论（native assessment）存在；否则会被拒绝。"
  },
  accept_risk: {
    title: "接受风险",
    hint: "最终裁定：受影响但暂不修复，记录风险接受。",
    note: "与确认一样需要当期结论；接受后不再进入修复授权。"
  },
  reject: {
    title: "判为不受影响",
    hint: "最终裁定：证据表明该风险不适用于本资产。",
    note: "请在理由中写明反证或证据缺口。"
  },
  request_reanalysis: {
    title: "要求重新分析",
    hint: "退回重新分析：不形成最终裁定。",
    note: "适用于证据过期、结论存疑或清单更新后需要复评。"
  }
};

const level = computed(() => (row.value?.has_final_conclusion ? row.value?.risk_level : row.value?.preliminary_level) || "unknown");
const riskScore = computed(() => row.value?.has_final_conclusion ? row.value?.final_score : row.value?.preliminary_score ?? row.value?.static_score);
const rt = computed(() => row.value?.runtime_status || "waiting");
const expectedStatus = computed(() => row.value?.review_status || "pending_human_review");
const evidenceCount = computed(() => {
  const events = chain.value?.events || evidence.value?.events || [];
  return Array.isArray(events) ? events.length : 0;
});
const evidenceTime = computed(() => (row.value?.updated_at ? "最近更新" : "未记录"));
const decisionLabel = computed(() => {
  const value = row.value?.recommended_action || row.value?.preliminary_decision || row.value?.decision;
  return { immediate_fix: "立即修复", scheduled_fix: "排期修复", collect_more_evidence: "继续补证", monitor: "持续观察", defer: "暂缓处理" }[value] || "需人工确认";
});
const decisionTone = computed(() => (["immediate_fix"].includes(row.value?.recommended_action || row.value?.preliminary_decision) ? "var(--crit)" : "var(--ink)"));
const affectedLabel = computed(() => ({ potentially_affected: "可能受影响", version_match: "版本命中", confirmed_affected: "确认受影响", not_affected: "不受影响", fixed: "已修复", insufficient_data: "证据不足" }[row.value?.affected_status] || statusLabel(row.value?.affected_status)));
const affectedTone = computed(() => ({ potentially_affected: "high", version_match: "high", confirmed_affected: "crit", not_affected: "low", fixed: "low", insufficient_data: "muted" }[row.value?.affected_status] || "muted"));
const reachableLabel = computed(() => ({ internet_exposed: "公网可达", internal_reachable: "内部可达", linked: "内部可达", local_only: "仅本机", none: "仅包级命中", unreachable: "不可达" }[row.value?.reachable_status] || "未记录"));
const reachableTone = computed(() => ({ internet_exposed: "crit", internal_reachable: "high", linked: "high", local_only: "muted", none: "muted", unreachable: "low" }[row.value?.reachable_status] || "muted"));
const reviewLabel = computed(() => {
  if (row.value?.active === false) return "历史归档";
  if (row.value?.human_review_required || row.value?.review_status === "pending_human_review") return "待人工审查";
  if (row.value?.review_status === "human_confirmed") return "已确认";
  return statusLabel(row.value?.review_status || "candidate");
});
const reviewTone = computed(() => (row.value?.human_review_required || row.value?.review_status === "pending_human_review" || row.value?.review_status === "quarantined_mapping" ? "high" : row.value?.review_status === "human_confirmed" ? "low" : "info"));
const recommendation = computed(() => row.value?.review_status_reason || row.value?.review_reason || row.value?.preliminary_reason || "版本适用性与暴露面需要人工签收；机器结论只作为输入。");
const decisionMeta = DECISION_META;
const verdictLabel = computed(() => ({
  confirmed_affected: "确认受影响", potentially_affected: "可能受影响", not_affected: "不受影响", insufficient_data: "证据不足"
}[row.value?.review_verdict] || row.value?.review_verdict || "无当期结论"));
const missingEvidence = computed(() => (Array.isArray(row.value?.review_missing_evidence) ? row.value.review_missing_evidence : []));
const visibleGaps = computed(() => (gapsOpen.value ? missingEvidence.value : missingEvidence.value.slice(0, 3)));
const conflictNotes = computed(() => (Array.isArray(row.value?.review_conflicts) ? row.value.review_conflicts : []));
const auditReasons = computed(() => (Array.isArray(row.value?.audit_policy_reasons) ? row.value.audit_policy_reasons : []));
const repairBlockedReasons = computed(() => {
  const plan = repairResult.value?.plan || {};
  return Array.isArray(plan.blocked_reasons) ? plan.blocked_reasons : [];
});

const factors = computed(() => {
  const source = row.value || {};
  const normalize = (value) => {
    const n = Number(value);
    if (!Number.isFinite(n)) return 0;
    return n <= 10 && n > 0 ? n * 10 : Math.min(100, n);
  };
  return [
    { label: "静态风险", value: normalize(source.static_score), tone: "var(--crit)" },
    { label: "服务暴露", value: normalize(source.exposure_score), tone: "var(--high)" },
    { label: "运行时", value: normalize(source.runtime_score), tone: "var(--accent)" },
    { label: "业务重要度", value: normalize(source.business_score), tone: "var(--accent)" },
    { label: "可操作性", value: normalize(source.actionability_score), tone: "var(--mid)" }
  ];
});

const flowSummary = computed(() => {
  const hits = [row.value?.affected_status, row.value?.patch_score, row.value?.reachable_status].filter(Boolean).length;
  return `${hits} 步有记录；运行时证据 ${runtimeLabel(rt.value)}。机器结论不替代人工签收。`;
});

const terminalText = computed(() => {
  if (!row.value) return "";
  const lines = [
    `# risk_id ${row.value.risk_id ?? "—"} · ${row.value.cve_id}`,
    `affected_status = ${row.value.affected_status || "—"}`,
    `reachable_status = ${row.value.reachable_status || "—"}`,
    `runtime_status  = ${row.value.runtime_status || "—"}`,
    `score = ${score(riskScore.value)} · level = ${level.value}`,
    "# 原始运行时事件请在“运行与审计”中查看；未观察到事件不等于安全。"
  ];
  return lines.join("\n");
});

function runtimeLabel(value) {
  return { verified: "已验证", contextual: "上下文关联", not_observed: "未观测", waiting: "等待证据" }[value] || value || "未知";
}
function runtimeTone(value) {
  return { verified: "low", contextual: "high", not_observed: "muted", waiting: "high" }[value] || "muted";
}
function routeText(value) {
  return { internet_exposed: "公网可达", internal_reachable: "内部可达", linked: "内部可达", local_only: "仅本机", none: "仅包级命中", unreachable: "不可达" }[value] || "未记录";
}

function openDecision(kind) {
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    ui.tokenOpen = true;
    return;
  }
  decision.value = kind;
  decisionOpen.value = true;
}

function openEvidence() {
  router.push("/runtime");
}

async function openRepair() {
  if (!row.value) return;
  if (!controlSession.token) {
    notify("请先在顶栏设置操作令牌", "error");
    ui.tokenOpen = true;
    return;
  }
  repairResult.value = null;
  artifactId.value = "";
  try {
    const result = await api.get("/harness/artifacts", { timeout: 20000 });
    artifacts.value = Array.isArray(result.data) ? result.data : [];
  } catch {
    artifacts.value = [];
  }
  repairOpen.value = true;
}

async function submitRepairRun() {
  if (!row.value) return;
  repairBusy.value = true;
  try {
    const result = await createHarnessRun({
      asset_id: Number(row.value.asset_id),
      risk_id: Number(row.value.risk_id ?? row.value.id),
      goal: "repair",
      artifact_id: artifactId.value
    });
    repairResult.value = result;
    repairOpen.value = false;
    notify(result.status === "blocked" ? "修复计划被策略阻断（原因已展示）" : "修复任务已创建", result.status === "blocked" ? "error" : "success");
  } catch (cause) {
    notify(cause?.response?.data?.detail || "修复任务创建失败", "error");
  } finally {
    repairBusy.value = false;
  }
}

async function submitDecision() {
  if (!row.value || !actor.value.trim() || !reason.value.trim()) return;
  submitting.value = true;
  try {
    await reviewRiskEvent(row.value.risk_id ?? row.value.id, decision.value, reason.value.trim(), actor.value.trim(), expectedStatus.value);
    notify("人工裁决已记录", "success");
    decisionOpen.value = false;
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "裁决提交失败", "error");
  } finally {
    submitting.value = false;
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const ranking = await api.get("/risk/ranking", { timeout: 30000 });
    const list = ranking.data || [];
    row.value = list.find((item) => String(item.risk_id ?? item.id) === id.value || String(item.cve_id) === id.value) || null;
    if (!row.value) error.value = "当前风险队列中未找到该对象。";
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "风险对象读取失败。";
  } finally {
    loading.value = false;
  }
  if (!row.value) return;
  fetchBehaviorChains()
    .then((value) => {
      const list = Array.isArray(value) ? value : value?.chains || [];
      chain.value = list.find((item) => item.intelligence?.cve_id === row.value.cve_id && item.asset?.hostname === row.value.hostname) || null;
    })
    .catch(() => { chain.value = null; });
  if (row.value.active !== false) {
    fetchCveRuntimeEvidence(row.value.cve_id, row.value.asset_id)
      .then((value) => { evidence.value = value || null; })
      .catch(() => { evidence.value = null; });
  }
}

onMounted(load);
</script>

<style scoped>
.risk-head .ph-copy { display: grid; gap: 4px; justify-items: start; }
.back-link { margin-bottom: 2px; }
.risk-title { margin-top: 0; }
.risk-sub { display: flex; align-items: center; gap: 9px; color: var(--ink-3); font-size: 12.5px; }
.risk-sub .pkg { color: var(--ink-2); font-family: var(--font-num); font-size: 12px; }
.gate-list { display: grid; gap: 5px; padding: 9px 10px; border: 1px solid var(--line-soft); border-radius: 8px; background: #f9fbfe; }
.gate-list div { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--ink-2); }
.gate-list span { margin-left: auto; color: var(--muted); font-family: var(--font-num); font-size: 10.5px; }
.terminal { min-height: 258px; }
.risk-grid { height: auto; }
.verdict-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.verdict-cell { display: grid; gap: 3px; padding: 9px 10px; border: 1px solid var(--line-soft); border-radius: 8px; background: #fbfdff; }
.v-label { color: var(--muted); font-size: 10.5px; }
.v-value { color: var(--ink); font-size: 12.5px; font-weight: 700; line-height: 1.45; word-break: break-all; }
.v-hint { color: var(--muted); font-size: 10.5px; }
.gap-block { display: grid; gap: 6px; padding: 9px 10px; border: 1px solid var(--line-soft); border-radius: 8px; background: #fffdf7; }
.g-head { display: flex; align-items: center; gap: 6px; color: var(--ink-2); font-size: 11px; font-weight: 700; }
.g-head .link { margin-left: auto; font-weight: 400; }
.g-list { margin: 0; padding-left: 16px; display: grid; gap: 4px; color: var(--ink-2); font-size: 11px; line-height: 1.5; }
.audit-chips { display: flex; flex-wrap: wrap; gap: 4px; }
.mono-chip { font-size: 10px; height: 20px; }
.plan-rows-mini { display: grid; gap: 8px; margin-bottom: 10px; }
.plan-rows-mini div { display: grid; grid-template-columns: 88px minmax(0, 1fr); gap: 10px; font-size: 12px; align-items: baseline; }
.plan-rows-mini span { color: var(--muted); }
.plan-rows-mini b { color: var(--ink-2); font-weight: 600; word-break: break-all; }
.blocked-box { display: grid; gap: 6px; padding: 10px; border: 1px solid #f3c6c6; border-radius: 8px; background: #fdf6f6; }
.blocked-box .g-head { color: #b42318; }
.actions-row { display: flex; flex-wrap: wrap; gap: 8px; }
.actions-row .btn { flex: 1 1 auto; min-width: 120px; }
@media (max-width: 1280px) {
  .risk-grid { grid-template-columns: minmax(0, 1fr) !important; }
}
</style>
