<template>
  <section class="page cve-detail-page" v-if="chain">
    <header class="cve-header"><el-button :icon="ArrowLeft" @click="back">返回风险列表</el-button><div class="cve-identity"><span class="section-kicker">VULNERABILITY RECORD</span><h1>{{ chain.intelligence.cve_id }}</h1><p>{{ vulnerabilityDetail.title || chain.intelligence.title || "Linux 软件包漏洞研判记录" }}</p></div><span class="severity-block" :class="lvlClass(displayLevel)">{{ riskLevelText(displayLevel) }}</span></header>
    <section class="cve-metrics"><div><span>风险分</span><strong>{{ displayScore }}</strong></div><div><span>CVSS</span><strong>{{ Number(vulnerabilityDetail.cvss_score || chain.intelligence.cvss_score || 0).toFixed(1) }}</strong></div><div><span>EPSS</span><strong>{{ epssDisplay }}</strong></div><div><span>KEV</span><strong>{{ vulnerabilityDetail.is_kev || chain.intelligence.is_kev ? "是" : "否" }}</strong></div><div><span>受影响资产</span><strong>1</strong></div><div><span>Ubuntu 状态</span><strong>{{ chain.matching.affected ? "受影响" : "未命中" }}</strong></div></section>

    <section class="detail-section"><header><span>01</span><div><h2>漏洞概况</h2><p>基础情报与漏洞适用性摘要</p></div></header><dl class="detail-dl"><div><dt>CVE</dt><dd class="mono">{{ chain.intelligence.cve_id }}</dd></div><div><dt>风险等级</dt><dd>{{ riskLevelText(displayLevel) }}</dd></div><div><dt>攻击场景</dt><dd>{{ chain.attack_scenario.name }}</dd></div><div><dt>情报来源</dt><dd>{{ chain.intelligence.source || "Canonical Ubuntu" }}</dd></div><div class="wide"><dt>漏洞描述</dt><dd>{{ vulnerabilityDetail.description || chain.intelligence.description || chain.risk.decision_reason }}</dd></div></dl></section>

    <section class="detail-section"><header><span>02</span><div><h2>资产影响</h2><p>资产、软件包、版本和暴露状态</p></div></header><table class="data-table"><thead><tr><th>资产</th><th>IP / 系统</th><th>软件包</th><th>当前版本</th><th>修复版本</th><th>适用性</th><th>置信度</th></tr></thead><tbody><tr><td>{{ chain.asset.hostname }}</td><td class="mono">{{ chain.asset.ip_address }} / {{ chain.asset.os }}</td><td>{{ chain.package.name }}</td><td class="mono">{{ chain.package.installed_version }}</td><td class="mono">{{ chain.package.fixed_version || "待确认" }}</td><td><span class="status-label" :class="chain.matching.affected ? 'is-h' : 'is-l'">{{ chain.matching.affected ? "真实命中" : "未命中" }}</span></td><td>{{ pct(chain.matching.confidence) }}</td></tr></tbody></table><p class="section-note">{{ chain.matching.reason }}</p></section>

    <section class="detail-section"><header><span>03</span><div><h2>多源漏洞情报</h2><p>Canonical、NVD、CISA KEV 与 FIRST EPSS</p></div></header><table class="data-table"><thead><tr><th>来源</th><th>职责</th><th>状态</th><th>关键证据</th><th>更新时间</th></tr></thead><tbody><tr v-for="source in intelligenceRows" :key="source.name"><td><strong>{{ source.label }}</strong></td><td>{{ source.role }}</td><td><span class="status-label" :class="source.status === '可用' ? 'is-l' : 'is-h'">{{ source.status }}</span></td><td>{{ source.summary }}</td><td>{{ source.updated }}</td></tr><tr v-if="!intelligenceRows.length"><td colspan="5" class="empty-cell">暂无多源情报记录。</td></tr></tbody></table></section>

    <section class="detail-section"><header><span>04</span><div><h2>证据链</h2><p>资产 → 服务 → 软件包 → CVE 的可达路径</p></div></header><dl class="detail-dl compact"><div><dt>可达性</dt><dd>{{ depText(chain.dependency_graph.status) }}</dd></div><div><dt>路径数</dt><dd>{{ chain.dependency_graph.path_count || 0 }}</dd></div><div><dt>暴露服务</dt><dd>{{ chain.dependency_graph.exposed_service_count || 0 }}</dd></div><div><dt>置信度</dt><dd>{{ pct(chain.dependency_graph.confidence) }}</dd></div></dl><div class="evidence-path" v-for="(path,i) in paths" :key="i"><span v-for="(node,j) in path" :key="j"><code>{{ node }}</code><b v-if="j < path.length - 1">→</b></span></div><div class="service-table" v-if="services.length"><table class="data-table"><thead><tr><th>服务</th><th>端口</th><th>协议</th><th>监听地址</th><th>公网暴露</th></tr></thead><tbody><tr v-for="(service,index) in services" :key="index"><td>{{ service.service_name }}</td><td>{{ service.port }}</td><td>{{ service.protocol }}</td><td class="mono">{{ service.listen_address }}</td><td>{{ service.is_public_exposed ? "是" : "否" }}</td></tr></tbody></table></div></section>

    <section class="detail-section"><header><span>05</span><div><h2>运行时验证</h2><p>验证结论与原始运行时证据</p></div><span class="status-label" :class="chain.runtime_verification.status === 'verified' ? 'is-l' : 'is-info'">{{ rtText(chain.runtime_verification.status) }}</span></header><p class="section-note">{{ chain.runtime_verification.conclusion }}</p><dl class="detail-dl compact"><div><dt>证据强度</dt><dd>{{ chain.runtime_verification.strength || 0 }}</dd></div><div><dt>置信度</dt><dd>{{ pct(chain.runtime_verification.confidence) }}</dd></div><div><dt>直接命中</dt><dd>{{ chain.runtime_verification.signals?.direct_count || 0 }}</dd></div><div><dt>上下文命中</dt><dd>{{ chain.runtime_verification.signals?.contextual_count || 0 }}</dd></div></dl><div class="runtime-rows"><article v-for="(event,index) in chain.runtime_verification.matched_events || []" :key="index"><header><strong>{{ event.rule || event.category }}</strong><span>{{ matchTypeText(event.match_type) }} / {{ freshnessText(event.freshness) }} / 权重 {{ event.evidence_weight }}</span></header><pre>{{ [event.process_name,event.commandline,event.file_path].filter(Boolean).join(" / ") }}</pre></article><div v-if="!(chain.runtime_verification.matched_events || []).length" class="empty-inline">未记录匹配的原始运行时事件。</div></div></section>

    <section class="detail-section"><header><span>06</span><div><h2>风险研判</h2><p>专业分析、冲突复议与最终裁决</p></div></header><table class="data-table"><thead><tr><th>研判角色</th><th>核心结论</th><th>置信度 / 方向</th><th>证据引用</th></tr></thead><tbody><tr v-for="row in agentRows" :key="row.id"><td><strong>{{ row.label }}</strong><small class="cell-sub mono">{{ row.id }}</small></td><td>{{ row.reason }}</td><td>{{ row.meta }}</td><td class="mono">{{ row.evidence || "-" }}</td></tr><tr v-if="!agentRows.length"><td colspan="4" class="empty-cell">暂无专业分析记录。</td></tr></tbody></table><div class="final-decision"><div><span>当前风险</span><strong>{{ displayScore }} / {{ riskLevelText(displayLevel) }}</strong></div><div><span>风险裁决</span><strong>{{ riskRecord.review_verdict || decisionText(chain.risk.decision) }}</strong></div><div><span>处置建议</span><strong>{{ riskRecord.recommended_action || decisionText(chain.risk.decision) }}</strong></div><p>{{ riskRecord.review_reason || chain.risk.decision_reason }}</p></div></section>

    <section class="detail-section"><header><span>07</span><div><h2>修复建议</h2><p>建议执行不代表已经执行</p></div><span class="status-label" :class="['fixed','verified'].includes(chain.remediation.status) ? 'is-l' : 'is-h'">{{ ['fixed','verified'].includes(chain.remediation.status) ? "已经执行" : "建议执行" }}</span></header><dl class="detail-dl compact"><div><dt>修复状态</dt><dd>{{ fixStatus(chain.remediation.status) }}</dd></div><div><dt>目标版本</dt><dd>{{ chain.package.fixed_version || "待确认" }}</dd></div></dl><div class="command-grid"><div><header><span>修复命令</span><el-button text :icon="CopyDocument" @click="copy(chain.remediation.command)">复制</el-button></header><pre>{{ chain.remediation.command || "暂无修复命令" }}</pre></div><div><header><span>验证命令</span></header><pre>{{ chain.remediation.verification || "升级后重新采集资产并核对软件包版本。" }}</pre></div></div></section>

    <section class="detail-section"><header><span>08</span><div><h2>审计记录</h2><p>Audit Policy、人工审核和证据缺口</p></div></header><table class="data-table"><thead><tr><th>审计项</th><th>结果</th><th>说明</th></tr></thead><tbody><tr><td>自动审计策略</td><td>{{ riskRecord.human_review_required ? "转人工审核" : "通过" }}</td><td>{{ (riskRecord.audit_policy_reasons || []).join("；") || "无阻断策略" }}</td></tr><tr><td>冲突复议</td><td>{{ riskRecord.review_conflicts?.length ? "存在冲突" : "无冲突" }}</td><td>{{ (riskRecord.review_conflicts || []).join("；") || "-" }}</td></tr><tr><td>证据完整性</td><td>{{ riskRecord.review_missing_evidence?.length ? "存在缺口" : "完整" }}</td><td>{{ (riskRecord.review_missing_evidence || []).join("；") || "-" }}</td></tr><tr><td>人工审计</td><td>{{ riskRecord.review_status || "待研判" }}</td><td>{{ riskRecord.human_review_required ? "必须由人工逐条确认" : "未触发人工门禁" }}</td></tr></tbody></table></section>
  </section>

  <section v-else class="page">
    <el-card class="panel"><div class="empty">请从「CVE 工作流」列表点击某条 CVE 进入。</div></el-card>
  </section>
</template>

<script setup>
import { ArrowLeft, CopyDocument } from "@element-plus/icons-vue";
import { ElMessage } from "element-plus";
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { fetchBehaviorChains, fetchRiskRanking, fetchVulnerability } from "../api";

const route = useRoute();
const router = useRouter();
const chains = ref([]);
const vulnerabilityDetail = ref({});
const riskRows = ref([]);

const chainId = computed(() => (Array.isArray(route.query.chain_id) ? route.query.chain_id[0] : route.query.chain_id));
const chain = computed(() => chains.value.find((c) => c.chain_id === chainId.value));
const paths = computed(() => chain.value?.dependency_graph?.paths || []);
const services = computed(() => (chain.value?.service_context || []).slice(0, 8));
const riskRecord = computed(() => riskRows.value.find((row) => row.cve_id === chain.value?.intelligence?.cve_id && row.hostname === chain.value?.asset?.hostname) || {});
const displayScore = computed(() => riskRecord.value.has_final_conclusion ? riskRecord.value.final_score : (riskRecord.value.preliminary_score ?? chain.value?.risk?.dynamic_score ?? "-"));
const displayLevel = computed(() => riskRecord.value.has_final_conclusion ? riskRecord.value.risk_level : (riskRecord.value.preliminary_level || chain.value?.risk?.dynamic_level));
const epssDisplay = computed(() => {
  const sourceScore = vulnerabilityDetail.value.intelligence_sources?.epss?.value?.score;
  return pct(sourceScore ?? chain.value?.intelligence?.epss_score);
});
const intelligenceRows = computed(() => {
  const sources = vulnerabilityDetail.value.intelligence_sources || riskRecord.value.intelligence_sources || {};
  const definitions = {
    canonical: ["Canonical Ubuntu", "Ubuntu 软件包适用性"], nvd: ["NVD", "漏洞技术严重度"],
    cisa_kev: ["CISA KEV", "已知在野利用"], epss: ["FIRST EPSS", "未来利用概率"]
  };
  return Object.entries(sources).map(([name, source]) => {
    const value = source.value || {};
    const summary = name === "canonical" ? `${value.package || chain.value?.package?.name || "-"} / ${value.release || "-"} / ${value.status || "-"} / 修复 ${value.fixed_version || "未发布"}`
      : name === "nvd" ? `CVSS ${value.cvss?.score ?? chain.value?.intelligence?.cvss_score ?? "-"} / ${(value.cwe || []).join(", ") || "CWE 未提供"}`
      : name === "cisa_kev" ? (value.is_kev ? `已列入 KEV，加入时间 ${value.date_added || "未知"}` : "未列入 KEV")
      : `利用概率 ${pct(value.score ?? chain.value?.intelligence?.epss_score)} / 百分位 ${pct(value.percentile)}`;
    return { name, label: definitions[name]?.[0] || name, role: definitions[name]?.[1] || "补充情报", status: ({ available: "可用", cached: "缓存", rate_limited: "限流", timeout: "超时", unavailable: "不可用" }[source.status] || source.status || "未获取"), summary, updated: source.source_updated_at || source.fetched_at ? new Date(source.source_updated_at || source.fetched_at).toLocaleString("zh-CN", { hour12: false }) : "未知" };
  });
});
const agentRows = computed(() => Object.entries(riskRecord.value.agent_results || {}).map(([id, result]) => ({
  id,
  label: ({ evidence_audit_agent: "证据质量分析", data_quality_agent: "证据质量分析", impact_assessment_agent: "漏洞适用性分析", exposure_runtime_agent: "暴露与运行时分析", runtime_attribution_agent: "运行时归因分析", decision_coordinator_agent: "最终裁决" }[id] || "专业分析"),
  reason: result.reason || "已完成分析",
  meta: `${result.evidence_quality || result.impact_status || result.risk_direction || [result.exposure_status, result.runtime_status].filter(Boolean).join(" / ") || "已完成"}${result.confidence == null ? "" : ` / ${pct(result.confidence)}`}`,
  evidence: [...new Set([...(result.valid_evidence_ids || []), ...(result.supporting_evidence_ids || []), ...(result.counter_evidence_ids || []), ...(result.conflicting_evidence_ids || [])])].slice(0, 8).join("、")
})));

const lvlClass = (l) => ({ Critical: "c", High: "h", Medium: "m", Low: "l" }[l] || "l");
const riskLevelText = (level) => ({ Critical: "严重", High: "高危", Medium: "中危", Low: "低危" }[level] || "未知");
const rtText = (s) => ({ verified: "eBPF 已验证", contextual: "上下文关联", not_observed: "未观察到", waiting: "等待证据" }[s] || s);
const rtClass = (s) => ({ verified: "done", contextual: "partial", not_observed: "idle", waiting: "idle" }[s] || "idle");
const depText = (s) => ({ internet_exposed: "公网可达", linked: "已形成路径", none: "包级命中" }[s] || s);
const depClass = (s) => ({ internet_exposed: "done", linked: "done", none: "partial" }[s] || "partial");
const decisionText = (decision) =>
  ({ immediate_fix: "立即修复", scheduled_fix: "排期修复", monitor: "持续观察", defer: "暂缓处理" }[decision] || "待决策");
const affectedStatusText = (status) => ({ version_match: "版本命中", not_affected: "未受影响" }[status] || "未知");
const reachableStatusText = (status) => ({ internet_exposed: "公网可达", linked: "内部可达", none: "仅包级命中" }[status] || "未知");
const exploitabilityText = (status) => ({ active: "活跃可利用", likely: "较可能利用", plausible: "存在可能", unlikely: "暂不明显" }[status] || "未知");
const matchTypeText = (type) => ({ direct: "直接命中", contextual: "上下文命中" }[type] || "未知");
const freshnessText = (freshness) => ({ last_hour: "最近一小时", last_day: "最近一天", last_week: "最近一周", stale: "较早事件", unknown: "时间未知" }[freshness] || "时间未知");
const nodeType = (j) => ["host", "svc", "pkg", "cve"][j] || "cve";
const barW = (v) => Math.max(3, Math.min(100, Number(v || 0))) + "%";
const adjSum = (a) => Number(a?.scenario || 0) + Number(a?.dependency_graph || 0) + Number(a?.exposure || 0) + Number(a?.runtime || 0);
const adjBar = (a) => Math.max(3, Math.min(100, adjSum(a) + 20)) + "%";
const signed = (v) => (Number(v) > 0 ? `+${v}` : `${v}`);
const pct = (v) => `${Math.round(Number(v || 0) * 100)}%`;
const fixStatus = (s) => ({ pending: "待修复", in_progress: "进行中", fixed: "已修复", verified: "已验证" }[s] || "待修复");
const back = () => router.push("/risk");

const copy = async (text) => {
  if (!text) return;
  try { await navigator.clipboard.writeText(text); ElMessage.success("修复命令已复制"); }
  catch { ElMessage.warning("复制失败"); }
};

onMounted(async () => {
  const [chainData, rankingData] = await Promise.all([fetchBehaviorChains(), fetchRiskRanking().catch(() => [])]);
  chains.value = chainData || [];
  riskRows.value = rankingData || [];
  if (chain.value?.intelligence?.cve_id) {
    vulnerabilityDetail.value = await fetchVulnerability(chain.value.intelligence.cve_id).catch(() => ({}));
  }
});
</script>

<style scoped>
.ev-hero {
  padding: 20px 22px;
  border: 1px solid rgba(56, 189, 248, 0.18);
  border-radius: 12px;
  background: rgba(14, 22, 42, 0.72);
  display: grid;
  gap: 14px;
  margin-bottom: 16px;
}
.hero-main { display: flex; justify-content: space-between; gap: 20px; align-items: center; }
.hero-left h3 { margin: 4px 0 8px; font-size: 22px; color: #e6edf7; font-family: Consolas, monospace; }
.pkg-line { margin: 0; color: #cfe0f5; }
.pkg-line b { color: #22d3ee; }
.host-line { margin: 4px 0 0; color: #8896ad; font-size: 13px; font-family: Consolas, monospace; }
.hero-right { text-align: right; display: grid; gap: 12px; }
.dyn-score { display: flex; align-items: baseline; gap: 10px; justify-content: flex-end; }
.ds-num { font-family: Consolas, monospace; font-size: 44px; font-weight: 700; line-height: 1; }
.num-c { color: #ff6b6b; text-shadow: 0 0 18px rgba(239, 68, 68, 0.45); }
.num-h { color: #fb923c; text-shadow: 0 0 18px rgba(251, 146, 60, 0.45); }
.num-m { color: #facc15; text-shadow: 0 0 18px rgba(250, 204, 21, 0.4); }
.num-l { color: #34d399; text-shadow: 0 0 18px rgba(52, 211, 153, 0.4); }
.ds-lvl { font-family: Consolas, monospace; font-size: 13px; padding: 3px 10px; border-radius: 5px; color: #fff; }
.badge-c { background: #ef4444; }
.badge-h { background: #fb923c; }
.badge-m { background: #facc15; color: #1a2332; }
.badge-l { background: #34d399; color: #04121b; }
.badges { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.badge { font-size: 12px; padding: 3px 10px; border-radius: 5px; border: 1px solid rgba(255, 255, 255, 0.12); }
.b-kev { background: rgba(239, 68, 68, 0.18); color: #ff8585; border-color: rgba(239, 68, 68, 0.4); }
.b-scene { background: rgba(167, 139, 250, 0.15); color: #c4b5fd; border-color: rgba(167, 139, 250, 0.4); }
.b-plain { background: rgba(255, 255, 255, 0.05); color: #a8b8d8; }

/* 纵向流水线 */
.pipeline {
  border: 1px solid rgba(56, 189, 248, 0.15);
  border-radius: 12px;
  background: rgba(14, 22, 42, 0.6);
  padding: 20px 22px;
}
.stage {
  display: grid;
  grid-template-columns: 32px 1fr;
  gap: 14px;
}
.rail {
  position: relative;
  display: flex;
  justify-content: center;
}
.num {
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  font-family: Consolas, monospace;
  font-weight: 700;
  font-size: 14px;
  z-index: 2;
  background: rgba(120, 150, 200, 0.15);
  color: #8896ad;
  border: 1px solid rgba(120, 150, 200, 0.3);
}
.num.done { background: #22d3ee; color: #04121b; box-shadow: 0 0 12px rgba(34, 211, 238, 0.5); border-color: #22d3ee; }
.num.partial { background: rgba(251, 146, 60, 0.2); color: #ffc285; border-color: rgba(251, 146, 60, 0.5); }
.num.idle { background: rgba(120, 150, 200, 0.12); color: #8896ad; }
.line {
  position: absolute;
  top: 30px;
  bottom: -16px;
  left: 50%;
  width: 2px;
  background: linear-gradient(rgba(56, 189, 248, 0.3), rgba(56, 189, 248, 0.08));
  z-index: 1;
}
.stage.last .line { display: none; }

.body {
  padding-bottom: 22px;
}
.head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}
.head h3 {
  margin: 0;
  font-size: 15px;
  color: #e6edf7;
}
.st {
  font-size: 11px;
  padding: 2px 9px;
  border-radius: 4px;
  font-family: Consolas, monospace;
}
.st.done { background: rgba(34, 211, 238, 0.15); color: #22d3ee; }
.st.partial { background: rgba(251, 146, 60, 0.15); color: #ffc285; }
.st.idle { background: rgba(120, 150, 200, 0.12); color: #a8b8d8; }
.copy-btn { margin-left: auto; }

.facts {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
}
.facts span {
  font-size: 12.5px;
  color: #a8b8d8;
}
.facts label {
  color: #64748b;
  margin-right: 5px;
}
.mono { font-family: Consolas, monospace; color: #cfe0f5; }
.reason {
  margin: 8px 0 0;
  font-size: 12.5px;
  color: #8896ad;
  line-height: 1.6;
}

.svc-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
}
.svc-label { font-size: 12px; color: #64748b; }
.svc-chip {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11.5px;
  font-family: Consolas, monospace;
  background: rgba(59, 130, 246, 0.12);
  color: #93c5fd;
  border: 1px solid rgba(59, 130, 246, 0.3);
}
.svc-chip.exposed { background: rgba(239, 68, 68, 0.12); color: #ff8585; border-color: rgba(239, 68, 68, 0.4); }

.path-line {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 6px;
}
.pn {
  padding: 3px 9px;
  border-radius: 5px;
  font-size: 11.5px;
  font-family: Consolas, monospace;
  border: 1px solid;
}
.pn-host { background: rgba(34, 211, 238, 0.12); color: #7dd3fc; border-color: rgba(34, 211, 238, 0.4); }
.pn-svc { background: rgba(59, 130, 246, 0.12); color: #93c5fd; border-color: rgba(59, 130, 246, 0.4); }
.pn-pkg { background: rgba(167, 139, 250, 0.12); color: #c4b5fd; border-color: rgba(167, 139, 250, 0.4); }
.pn-cve { background: rgba(239, 68, 68, 0.15); color: #ff8585; border-color: rgba(239, 68, 68, 0.4); }
.arr { color: #475569; font-size: 12px; }

.evt {
  margin-top: 8px;
  padding: 8px 10px;
  background: rgba(52, 211, 153, 0.06);
  border-left: 3px solid #34d399;
  border-radius: 5px;
}
.evt strong { display: block; color: #6ee7b7; font-size: 12.5px; margin-bottom: 3px; }
.evt-meta { margin-bottom: 3px; color: #8fd8c0; font-size: 11px; font-family: Consolas, monospace; }
.evt code { font-size: 11.5px; color: #cfe0f5; word-break: break-all; }

.adjust { display: grid; gap: 8px; max-width: 460px; }
.adj { display: grid; grid-template-columns: 150px 1fr auto; align-items: center; gap: 10px; font-size: 12.5px; color: #a8b8d8; }
.adj.total { color: #e6edf7; font-weight: 600; border-top: 1px solid rgba(56, 189, 248, 0.15); padding-top: 8px; margin-top: 4px; }
.bar { height: 8px; border-radius: 5px; background: rgba(255, 255, 255, 0.06); overflow: hidden; }
.bar i { display: block; height: 100%; border-radius: 5px; }
.adj b { font-family: Consolas, monospace; color: #cfe0f5; }

.cmd {
  margin: 8px 0 0;
  padding: 12px 14px;
  background: #0a1120;
  color: #7dd3fc;
  border-radius: 8px;
  font-family: Consolas, monospace;
  font-size: 12.5px;
  line-height: 1.7;
  white-space: pre-wrap;
  border: 1px solid rgba(56, 189, 248, 0.15);
}
.cmd.verify { color: #6ee7b7; border-color: rgba(52, 211, 153, 0.2); }
.empty { padding: 30px; text-align: center; color: #8896ad; }

/* Structured vulnerability record */
.cve-detail-page { max-width: 1600px; margin: 0 auto; }
.cve-header { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: start; gap: 18px; padding-bottom: 14px; border-bottom: 1px solid var(--soc-border); }
.cve-identity h1 { margin: 3px 0; color: #edf2f7; font: 650 23px/1.25 Consolas, monospace; }.cve-identity p { margin: 0; color: var(--soc-text-secondary); font-size: 12px; line-height: 1.6; }
.severity-block { min-width: 88px; padding: 8px 12px; border: 1px solid var(--soc-border); color: #cbd5df; font-size: 12px; font-weight: 700; text-align: center; }.severity-block.c { color: #ef9292; border-color: #713b3e; }.severity-block.h { color: #e5a06b; border-color: #70472e; }.severity-block.m { color: #dfc36b; border-color: #625631; }.severity-block.l { color: #7bc49c; border-color: #315f49; }
.cve-metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); border: 1px solid var(--soc-border); background: var(--soc-surface); }.cve-metrics > div { padding: 11px 14px; border-right: 1px solid var(--soc-border-soft); }.cve-metrics > div:last-child { border-right: 0; }.cve-metrics span { display: block; color: var(--soc-text-muted); font-size: 10px; }.cve-metrics strong { display: block; margin-top: 3px; color: #e8edf3; font: 600 17px Consolas, "Microsoft YaHei", sans-serif; }
.detail-section { padding: 16px; border: 1px solid var(--soc-border); border-radius: 3px; background: var(--soc-surface); }.detail-section > header { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 13px; }.detail-section > header > span:first-child { color: #6f8399; font: 600 10px Consolas, monospace; }.detail-section > header > div { flex: 1; }.detail-section h2 { margin: 0; color: #edf1f6; font-size: 14px; }.detail-section header p { margin: 2px 0 0; color: var(--soc-text-muted); font-size: 10px; }
.detail-dl { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); margin: 0; border: 1px solid var(--soc-border-soft); }.detail-dl > div { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 12px; padding: 8px 10px; border-right: 1px solid var(--soc-border-soft); border-bottom: 1px solid var(--soc-border-soft); }.detail-dl > div:nth-child(even) { border-right: 0; }.detail-dl .wide { grid-column: 1 / -1; border-right: 0; }.detail-dl dt { color: var(--soc-text-muted); }.detail-dl dd { margin: 0; color: #ccd5df; line-height: 1.6; }.detail-dl.compact { grid-template-columns: repeat(4, minmax(0, 1fr)); }.detail-dl.compact > div { grid-template-columns: 1fr; gap: 3px; border-right: 1px solid var(--soc-border-soft); }.detail-dl.compact > div:last-child { border-right: 0; }
.section-note { margin: 10px 0 0; color: var(--soc-text-secondary); font-size: 11px; line-height: 1.65; }
.evidence-path { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin: 12px 0; }.evidence-path span { display: contents; }.evidence-path code { padding: 4px 7px; border: 1px solid #33475b; border-radius: 2px; background: #0d161f; color: #adc4df; }.evidence-path b { color: #5d6c7c; }.service-table { margin-top: 12px; }
.runtime-rows { display: grid; gap: 8px; margin-top: 12px; }.runtime-rows article { border: 1px solid var(--soc-border-soft); background: #0d151e; }.runtime-rows article > header { display: flex; justify-content: space-between; gap: 14px; padding: 8px 10px; border-bottom: 1px solid var(--soc-border-soft); }.runtime-rows article header strong { color: #cad4df; }.runtime-rows article header span { color: var(--soc-text-muted); font-size: 10px; }.runtime-rows pre { margin: 0; padding: 10px; color: #aebdcb; font: 11px/1.6 Consolas, monospace; white-space: pre-wrap; }
.final-decision { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0; margin-top: 12px; border: 1px solid var(--soc-border-soft); }.final-decision > div { padding: 10px; border-right: 1px solid var(--soc-border-soft); }.final-decision span { display: block; color: var(--soc-text-muted); font-size: 10px; }.final-decision strong { display: block; margin-top: 3px; }.final-decision p { grid-column: 1 / -1; margin: 0; padding: 10px; border-top: 1px solid var(--soc-border-soft); color: var(--soc-text-secondary); line-height: 1.6; }
.command-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 12px; }.command-grid > div { border: 1px solid #29394a; background: #090f16; }.command-grid header { display: flex; justify-content: space-between; align-items: center; min-height: 36px; padding: 0 10px; border-bottom: 1px solid #29394a; color: #8fa0b2; }.command-grid pre { margin: 0; padding: 12px; overflow: auto; color: #adbed0; font: 11px/1.65 Consolas, monospace; white-space: pre-wrap; }
@media (max-width: 900px) { .cve-header { grid-template-columns: 1fr; }.cve-metrics, .detail-dl, .detail-dl.compact, .final-decision, .command-grid { grid-template-columns: 1fr; }.detail-dl .wide { grid-column: auto; }.detail-dl > div { border-right: 0; } }
</style>
