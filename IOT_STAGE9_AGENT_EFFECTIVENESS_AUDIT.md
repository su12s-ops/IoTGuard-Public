# IoTGuard 四智能体有效性专项审计（第九阶段前置专项，eBPF 2.0 后；Stage 9B 未启动）

> 审计基线：bfa7ec2（eBPF 2.0 P2-2）。审计日期：2026-10-15。
> 审计方式：真实源码逐行追踪 + 受控 Fixture 上的真实 LLM 消融/反事实实验（deepseek-v4-flash，与生产同模型同温度；无任何 mock 结论、无硬编码测试预期）。
> 实验产物：`backend/scripts/stage9_agent_effectiveness_audit.py`（可复跑）、`backend/scripts/stage9_recompute_metrics.py`；原始输出仅存本地 `backend/reports/stage9-agent-audit/`（.gitignore 排除，不入库）。

---

## 0. 审计结论（TL;DR）

**"四智能体摆设化"的怀疑部分成立，但成立的位置与直觉不同。** 本仓库实际存在**两套都被称为"四智能体"的体系**，它们的有效性截然相反：

| | System A：设备编排四智能体 | System B：逐风险专家评审四智能体 |
|---|---|---|
| 位置 | `backend/app/services/agents/`（device_intelligence / vulnerability_intelligence / runtime_behavior / remediation_verification） | `backend/app/services/event_review_pipeline.py`（evidence_audit / impact_assessment / exposure_runtime / decision_coordinator） |
| 形态 | 真工具循环（14 个专属只读工具，8 轮上限） | 单次 LLM 调用 × 类型化 JSON 输出（无工具，读确定性证据包） |
| 输出去向 | `AgentOrchestrationRun.risk_json` → **仅前端展示（AgentOps.vue）**，风险研判主链路不消费；唯一写回路径是创建修复任务 | 写入 `RiskAssessment` 的 review/final 字段 → **风险排序、人工复核队列、修复授权、Harness 补采全部真实消费** |
| 消融敏感度 | runtime 智能体被屏蔽：风险分 62→54，优先级 high→medium（真实变化） | 任一智能体被屏蔽：全部处置建议退化为 `collect_more_evidence` 兜底（人工门禁不受影响） |
| 实测增量 | 对 eBPF 证据的真实读取与行为链推理（ACTIVE 判定引用真实 evidence_id） | **在规则误报案例上纠正了确定性引擎**（详见 §5 CF7） |

**对用户六大疑点的直接回答**（证据全部在正文）：

1. **"四个 Agent 分别总结现成报告？"** — System A 不是（真实工具循环，实测 vuln 智能体 13 次工具调用、runtime 智能体逐条 evidence_id 推理）；System B 的三个专家**确实是**"读一个确定性代码拼装的证据包后给类型化意见"，没有独立取证能力——但其意见经过了真值对照检验并被证明有增量（§6）。
2. **"输出生成后无人消费？"** — System A 的 `risk_json/stages_json` **确认死端**（除 AgentOps 展示和一条修复任务写回路径外无任何消费者，grep 全仓验证）；System B 输出全链路消费。
3. **"预设结论/写死风险等级？"** — 未发现。两套体系的最终分数/等级都是确定性公式计算（`aggregate_risk` / `apply_audit_policy`），LLM 只能在有界范围内影响（±10/±20 调整、行为等级、处置建议）；审计策略门禁全部为代码而非提示词。
4. **"是否真正消费 eBPF 2.0 动态证据与数据质量？"** — 是。System B 证据包包含 SecurityEvidence 三类证据、进程树、`service_shell_chains`、传感器心跳覆盖（`build_evidence_packet` L530-581）；System A runtime 智能体实测调用了 `query_runtime_data_quality`（P2-3 工具）。但**证据新鲜度不参与运行时状态判定**（stale 证据仍计为 verified/contextual，只降低权重）——见缺陷 F6。
5. **"不管前序 Agent 输出什么，最终结果都基本一致？"** — 不成立，但弱于预期。System B：运行时证据只改变 3/7 案例的处置建议（且 1 例变差）；System A：runtime 智能体屏蔽使风险分变化 8 分、优先级降一级；屏蔽任一 System B 智能体则建议全部坍缩到兜底值。
6. **"证据不足/矛盾/过期/unsupported 处理？"** — 矛盾处理实测优秀（E3/E4 冲突检测→定向复议→人工复核）；unsupported 平台（Zephyr）能力标注进 Trace 但 **runtime 智能体两次输出均被 schema 拒绝、阶段失败**（缺陷 F3）；过期证据被 evidence_audit 智能体在缺失清单中点名但**不改变运行时状态语义**（F6）。

**成本口径**（真实计量）：System B 逐事件评审 ≈ 4.4 次 LLM 调用 / 2.2 万~2.5 万 token / 11 秒；System A 全编排 ≈ 14 次调用 / 3.7 万 token / 42 秒。

---

## 1. 审计范围与方法

- **静态审计**：`agents/agents.py`、`agents/base.py`、`agents/orchestrator.py`、`agents/tools.py`、`event_review_pipeline.py`、`agent_group_chat.py`、`agent_intelligence.py`、`risk_engine.py`、`remediation_engine.py`、`agent_harness.py`、`security_evidence.py`、`runtime_evidence.py`、`runtime_telemetry.py`、`report_service.py`、`routers/{agents,analysis,risk,workflow,traces}.py`、前端 `AgentOps.vue`/`AgentWorkflow.vue`/`RiskRanking.vue` 消费点；全仓 grep 消费方。
- **动态实验**：受控 Fixture（独立临时 SQLite，4 资产 / 5 合成 CVE / 7 风险事件，见 §4.1），真实 DeepSeek API，共 11 组运行、约 160 次 LLM 调用。**Fixture 一律使用合成 CVE 编号（CVE-2026-81xxx）与 TEST-NET 地址**，目的是强制模型只依据证据包推理、隔离参数知识干扰，同时保证不外泄任何真实环境信息。
- **禁止项遵守**：全程未修改任何生产代码；未使用"4/4 调用成功/Trace 全记录/测试全绿"作为有效性证据；实验 Harness 自身的两处统计缺陷（§7 方法注记）如实留档并离线修正。

---

## 2. 四智能体真实调用架构

### 2.1 实际存在两套"四智能体"（职责重叠、品牌混用）

```
                        ┌─────────────────────────── System A：设备编排 ───────────────────────────┐
 POST /api/agents/analyze                                                           （前端 AgentOps.vue 触发）
   orchestrator.start_analysis → trace_id（唯一）→ capability_marks（Zephyr 等）
   DEVICE(LLM+3工具) → VULNERABILITY(LLM+3工具) → RUNTIME(LLM+5工具,含数据质量)
        │ device_type/firmware 摘要传入 VULN 上下文                     ↓ validate_runtime_report
        │                                              evidence_id 存在性校验→失败带反馈重试1次→仍败则按 NORMAL 降级
        ▼
   RISK（纯程序 aggregate_risk）→ REMEDIATION(LLM+3工具) → VERIFY（纯程序）
   落库：AgentOrchestrationRun.stages/agents/risk/remediation/verify_json
   消费：GET /api/agents/runs/* → AgentOps.vue 展示；execute_remediation_plan 可对已授权风险创建 RemediationTask
   ✗ 不写入 RiskAssessment；不进 report_service；不影响修复授权

                        ┌─────────────────────────── System B：逐风险评审 ─────────────────────────┐
 POST /api/analysis/runs                                                             （前端 AgentWorkflow.vue 触发）
   calculate_risk（确定性候选，preliminary_*）
   → build_evidence_packet（纯代码：match/NVD/Canonical/KEV/EPSS/可达性/心跳覆盖/
     OpenWrt 公告/SecurityEvidence 三类+进程树+RuntimeEvent 匹配事件+数据质量+baseline）
   → 3 专家并行（各 1 次 LLM 调用，类型化 JSON；impact 不含 baseline 防锚定）
   → detect_conflicts（确定性 3 规则）→ 命中则定向复议 1 次
   → decision_coordinator（读 baseline+三专家+冲突）→ risk_direction/建议/优先级
   → apply_audit_policy（确定性门禁）→ auto_confirmed 罕见 / pending_human_review 常态
   落库：RiskAssessment.review_*/final_score/decision/recommended_*/agent_results_json + AgentAuditRecord（逐调用审计）
   消费：/risk/ranking → RiskRanking.vue；人工复核 API → apply_human_review；
        _authorized()（remediation_engine）→ generate_remediation_tasks → Harness 修复；
        Harness inspect/expert_review 会重建证据包、执行 coordinator.requested_tools 补采并复评（agent_harness.py:466-483）
```

**架构级发现 A1（必须整改）**：两套体系都自称"四智能体"，但职责互不映射、数据互不流通。总览大屏（`build_four_agent_workflow`，`agent_intelligence.py:418`）向用户展示的是 System B 的四个智能体；而"智能体分析与修复工作流"页展示 System A。System A 对同一设备得出的风险结论（`risk_json`）与 System B 对同一主机的逐 CVE 结论之间**没有任何引用、对账或合并**。

### 2.2 逐智能体数据流追踪（实际输入 → 输出 → 下游）

**System A（`agents/agents.py`，工具数 3+3+5+3）**

| 智能体 | 实际输入 | 工具（实测调用次数） | 输出消费点 | 对最终决策的影响 |
|---|---|---|---|---|
| device_intelligence | `host` 字符串 | query_device_profile(2)/query_network_surface(2)/list_devices(1) | `stages_json`；**仅** device_type+firmware 两字段注入 VULN 上下文（orchestrator.py:241-243） | services 计数进 `aggregate_risk` 暴露面项（≤10 分） |
| vulnerability_intelligence | host + 设备画像摘要 | query_matched_vulnerabilities(2)/query_cve_intelligence(8)/query_version_impact(2) | max_severity+KEV 进 RISK（基线分 0-40+10） | `VulnerabilityFinding.version_impact` **不被 RISK 消费**（F5）；`data_gaps` 无消费者 |
| runtime_behavior | host（无前序摘要） | process/network/file/process_tree/**runtime_data_quality** 各 1 | behavior_level 进 RISK（0/4/8/10 分）；evidence_id 经 `validate_runtime_report` 对照库校验 | 实测屏蔽后 risk 62→54、priority high→medium |
| remediation_verification | **仅 host（无 RISK 输出、无 CVE 列表）** | targets/status/options 各 1 | `execute_remediation_plan`：仅当 `plan.risk_ref` 命中**已授权** RiskAssessment 时建任务 | 实测输出 `risk_ref=""`、`actions=[]`（空方案，§4.4） |

**System B（`event_review_pipeline.py`）**

| 智能体 | 实际输入 | 工具 | 输出消费点 |
|---|---|---|---|
| evidence_audit | 完整证据包（含 baseline） | **无**（单次 JSON 调用） | evidence_quality 进审计策略门禁；冲突检测输入 |
| impact_assessment | 证据包**剔除 baseline**（防锚定，L786-790） | 无 | impact_status 进冲突检测（`deterministic_match_vs_not_affected` 规则） |
| exposure_runtime | 完整证据包 | 无 | exposure/runtime_status 进冲突检测；不直接改分 |
| decision_coordinator | baseline + 三专家结构化结果 + 冲突结果 | 无（但 `requested_tools` 由 Harness 真实执行） | risk_direction → ±10/±20（DIRECTION_ADJUSTMENTS）；recommended_action → `risk.decision`；置信度进门禁 |

### 2.3 Trace 与 Harness 关联（核验通过）

- 两套体系均接统一 Trace：System A 每次 `start_analysis` 生成唯一 trace_id，`agent_started/finished` 携带真实 LLM 调用数、模型、token 用量与工具调用表（orchestrator.py:298-314）；Zephyr 目标额外发射 `capability_marks`（unsupported 语义）——实测 CF6 中三个 unsupported 项全部入 Trace。
- Harness 与 System B 是**真实双向消费**：`_expert_review`（agent_harness.py:351-366）重建证据包跑完整评审；coordinator 的 `requested_tools` 中的 `collect_inventory/inspect_runtime/inspect_evidence` 会触发真实补采后自动复评一轮（L466-483）。这是全仓"智能体输出驱动程序行动"的最强实例。
- 修复授权链为纯代码闭环：System B `auto_confirmed`/`human_confirmed` → `_authorized()`（High/Critical 的 auto_confirmed 一律拒绝授权）→ `generate_remediation_tasks` → Harness 产物哈希绑定执行。

---

## 3. 每个智能体的实际不可替代贡献（静态+动态证据）

### System A

- **runtime_behavior（最有价值）**：实测（sysA 运行）对 fixture 中 nginx→sh→wget→读 /etc/shadow 链给出 ACTIVE 判定，逐条引用 6 个真实 evidence_id 并给出"正常 nginx worker 不应派生交互式 shell"级别的推理；`aggregate_risk` 因此 +8 分并升级优先级。屏蔽实验证明该输出**可测量地**改变结论。这是四智能体中唯一同时满足"真实输入（eBPF 证据）、真实推理、真实消费（风险聚合）、可测增量"四条的智能体。
- **vulnerability_intelligence（部分可替代）**：实测 13 次工具调用、给出逐 CVE 的 version_impact 与诚实 data_gaps（发现并上报了 fixture 中 edge-01 openssl 版本缺失的不一致，而非编造）。但其结论与确定性匹配引擎/风险引擎高度同源（同样的库、同样的版本比较函数 `is_version_less`），`version_impact` 又不被聚合消费——**独立增量集中在 data_gaps 情报一致性检查，而非结论本身**。
- **device_intelligence（低增量）**：输出真实（2 服务、诚实缺口），但消费端只用了 services 计数（≤10 分）和两个字段透传。其"暴露面分析"与 `query_network_surface`/risk_engine 的 exposure 评分重复。
- **remediation_verification（当前接近失效）**：实测对 edge-01（KEV+Critical+ACTIVE）输出**空方案**（risk_ref=""、actions=[]）。根因是结构性的：①上下文不含本 run 的 RISK 结果与 CVE 列表（orchestrator.py:246-247）；②可执行路径要求 RiskAssessment 已授权，而授权只能来自 System B 的复核——**即 System A 的修复智能体在 System B 未运行时结构性地无事可做**。

### System B

- **impact_assessment（最有价值）**：CF7 实测其**纠正了确定性规则的假阳性**——E3 误匹配候选（NVD 明示受影响分支为 3.1.x，装机为 3.0.x，规则按"低于修复版本"判 High 69.05/scheduled_fix）被其判为 not_affected（置信 0.88），理由逐条引用证据（"版本规则命中为假阳性…NVD cpe_status=affected 为通用 CPE 匹配，不构成反证"）。规则系统自身无法做到这一点（它不做语义阅读）。
- **evidence_audit（门禁价值）**：E1 案例产出 7 条结构化缺失清单（exploitation_confirmed=false、无 PCAP/WAF、wget 落地未验证等）；E5 案例正确点名"新鲜的运行时/传感器覆盖数据"缺失。是 audit_policy 中 `evidence_*` 门禁的直接供给者。
- **exposure_runtime（语义澄清价值）**：E1 实测在确定性层给出 runtime_status=verified（进程名直接匹配）的情况下，智能体判 contextual 并说明理由（wget/shadow 行为与 HTTP/2 走私路径无关联）——**纠正了确定性匹配把"包活动"当"漏洞利用关联"的过宽语义**（与 F6 相关）。
- **decision_coordinator（集成价值+兜底）**：给出有理由的离散裁定（E1 upgrade_minor 的理由是"修复仅为同一主线补丁号递增"）；E3 冲突未消解时明确"不采纳任何一方确定性结论"。屏蔽后全部坍缩（§4.3）。

---

## 4. 消融实验（第二部分）

### 4.1 统一评测集

4 资产（edge-01 Ubuntu22.04 公网/core、edge-02/03 Ubuntu 内网、wrt-node OpenWrt23.05.3 DMZ）× 5 合成 CVE → **7 个风险事件**（E3/E4 因两台资产均装 openssl 而各产生 2 个实例，语义等同，记为 E3a/b、E4a/b）。每事件附真值表（期望影响判定/允许方向/允许处置/是否必须人工），真值独立于实现预先定义。

### 4.2 A/B/C 三组对照（同一模型、同一案例、同一评价标准）

**组 A（传统 CVE+确定性规则：run_matching+calculate_risk）**

| 案例 | 规则结论 | 对照真值判定 |
|---|---|---|
| E1 nginx+KEV+直接证据 | 100.0 Critical / immediate_fix | ✅ 处置正确 |
| E2 curl 无相关证据 | 61.05 High / monitor | ✅ 处置正确 |
| **E3a/b 误匹配候选** | **69.05 High / scheduled_fix** | ❌ **假阳性**（真值：不受影响） |
| **E4a/b 矛盾情报** | **85.25 Critical / scheduled_fix** | ❌ **无视 under_investigation 冲突** |
| **E5 OpenWrt 过期监控** | **83.83 Critical / immediate_fix** | ❌ **忽视 72h 采集过期+丢失未知** |

规则处置正确率 **2/7**。注意 E1 分数有/无运行时证据完全相同（100 封顶），运行时证据只改变 `runtime_status` 字段不改变决策。

**组 B/C（四智能体，无/有运行时证据，真实 LLM）**

| 指标 | B（无运行时） | C（有运行时） |
|---|---|---|
| 影响判定正确（对照真值） | 7/7 | 7/7 |
| 处置建议适当 | 6/7 | 6/7 |
| 风险方向适当 | 6/7 | 5/7 |
| 人工复核路由正确 | 3/3 | 3/3 |
| 与证据包事实的确定性矛盾 | **0** | **0** |
| 包外证据引用（幻觉） | **0/48 条** | **0/66 条** |
| auto_confirmed | 0/7 | 0/7 |
| Token 合计（7 事件） | 159,897 | 177,159 |
| 墙钟（7 事件） | 75.1s | 77.1s |

**C−B 逐案例净变化（运行时证据的真实效应，M6）**：7 案例中 3 个改变——E5 建议 `collect_more_evidence→scheduled_fix`（证据更充分后建议更明确，仍被人工门禁拦截）、E4a `scheduled_fix→collect_more_evidence`（更谨慎，方向正确）、**E3b 方向 `maintain→upgrade_minor`（变差：运行时证据把一个误匹配候选向升级方向推）**。结论：运行时证据对 System B 结论的边际效应真实存在但有限且不单调；置信度普遍上升（E1 0.75→0.82、E5 0.5→0.70）。

### 4.3 组 D：逐一屏蔽单个智能体（System B，E1+E4a/E4b）

屏蔽方式：实验 Harness 将该智能体的工作产物替换为失败（管线视为 agent 失败，走既有 fail-safe 路径）。

| 屏蔽对象 | E1 建议（完整管线为 immediate_fix/upgrade/high） | E4 建议（完整管线为 collect_more_evidence） | 人工门禁 |
|---|---|---|---|
| evidence_audit | collect_more_evidence / maintain / 无优先级 | collect_more_evidence / maintain | 保持 pending_human_review ✅ |
| impact_assessment | 同上（坍缩） | 同上（坍缩） | 保持 ✅ |
| exposure_runtime | 同上（坍缩） | 同上（坍缩） | 保持 ✅ |
| decision_coordinator | 同上（坍缩，verdict 兜底 insufficient_evidence） | 同上（坍缩） | 保持 ✅ |

结论：**四个智能体中任何一个失能都会摧毁全部处置建议价值（无冗余、无优雅降级），但审计门禁在四种屏蔽下全部正确转入人工复核**——安全性设计成立，可用性设计单薄（且兜底输出完全同质，仅在 `review_failed_agents`/`audit_policy_reasons` 中记录了死因）。

### 4.4 System A 屏蔽实验 + 真实编排

- 完整编排（edge-01）：14 次调用 / 36,710 token / 41.7s，风险 62/high，RUNTIME=ACTIVE（6 个真实 evidence_id）。
- 屏蔽 runtime 智能体：11 次 / 26,628 token，风险 **54/medium**——runtime 智能体的输出可测量地贡献 8 分与一级优先级（RUNTIME_LEVEL_WEIGHT 机制的直接验证）。
- 修复智能体两个运行均输出空方案（§3 根因），`execute_remediation_plan` 得以空转——"输出未进决策"在 System A 内部的又一个实例。

---

## 5. 反事实证据实验（第三部分）

全部为受控 Fixture 条件（与任何真实运行严格区分），观察智能体是否**识别证据变化**并**合理调整研判**：

| # | 反事实条件 | 实测结果 | 判定 |
|---|---|---|---|
| CF1 | 只有静态 CVE 候选（B 组） | 影响判定 7/7 正确；E1 仍 immediate_fix（版本+KEV+公网足以支撑）；运行时智能体如实报 not_observed、evidence_audit 列出覆盖缺口；0 矛盾 | ✅ |
| CF2 | 加入真实形态运行时证据（C 组） | runtime 智能体改报 contextual/verified 语义辨析（E1 拒绝把"包活动"升级为"利用证据"）；E5/E4a 建议改变（§4.2） | ✅（幅度有限） |
| CF3 | 移除运行时证据（C→B 对照） | 3/7 案例建议回退（E5 scheduled_fix→collect_more_evidence 等）；置信度回落 | ✅ 敏感 |
| CF4 | 矛盾厂商公告/情报（E4：Canonical under_investigation vs NVD affected vs CISA KEV） | evidence_audit 判 conflicting 并给出冲突对（EV-4-PKG vs EV-4-SRC-*）；coordinator 判 insufficient_evidence→collect_more_evidence；`major_baseline_contradiction`/`unresolved_major_conflict` 门禁触发→人工复核。规则引擎对同一案例给 85.25 Critical/scheduled_fix | ✅ **显著优于规则** |
| CF5 | 监控数据过期+丢失未知（E5：72h 前证据、心跳 stale、dropped=unavailable） | evidence_audit 把"新鲜的运行时/传感器覆盖数据"列入缺失；置信度 0.68/0.5；建议 collect_more_evidence/scheduled_fix（未 immediate_fix）；`confidence_below_0.70` 门禁触发 | ✅ 但见 F6：**runtime_status 仍为 contextual（未因过期降为 waiting 语义）** |
| CF6 | Zephyr 不支持 Linux eBPF | capability_marks（ssh/package/ebpf 三项 unsupported）入 Trace ✅；DEVICE/VULN/REMEDIATION 智能体产出高质量诚实 data_gaps（"13 条命中全部属于其他主机，未纳入 findings"——零编造）✅；**但 RUNTIME 智能体两次输出均因多余字段 `note` 被 `extra="forbid"` 拒绝，阶段失败**，最终按 NORMAL 降级（无风险虚增，安全方向正确） | ⚠️ 缺陷 F3 |
| CF7 | CVE 误匹配候选（E3） | impact 智能体在定向复议后判 not_affected 并明确"版本规则命中为假阳性"；冲突规则 `deterministic_match_vs_not_affected` 命中→复议→`major_baseline_contradiction`→人工复核；coordinator 拒绝依未经权威源核实的 fixed_version 触发升级。**规则引擎同案例输出 High 69.05/scheduled_fix** | ✅ **本次审计最强正例** |

**CF 总结**：七项反事实中六项表现合格或显著优于规则，一项（CF6）暴露 System A 输出 schema 脆弱性。没有任何案例出现"为了预期效果而硬编码"的空间——判定全部由管线真实产出，Harness 的真值表在实验前独立写定（`TRUTH` 常量，见脚本）。

---

## 6. 摆设化问题的明确结论

1. **System A 整体不是摆设，但处于"半接入"状态**：它有真实的工具循环与证据消费（ACTIVE 判定、数据质量工具调用、诚实 data_gaps 均为实证），且 runtime 智能体输出对风险分有可测影响；但其主产出 `risk_json` 不进风险研判主链路、修复智能体结构性空转、跨阶段交接断裂（RISK→REMEDIATION 无上下文传递）。**结论：真实运行、局部摆设（remediation 环节）+ 输出死端（风险结论）。**
2. **System B 不是摆设**：输出被排序/复核/授权/Harness 全链消费；在规则误报（E3）、矛盾情报（E4）、过期监控（E5）三类案例上产生了规则系统给不出的正确行为；证据引用零幻觉（114 条引用全部可回溯，0 包外）。
3. **但 System B 的"专家"是单次读取器而非自主智能体**：三专家无工具、无独立取证，全部事实来自确定性代码拼装的证据包——它更像"四个带类型化输出与门禁的 LLM 评审员"。这一定位本身成立（证据包质量高、防锚定设计到位），但竞赛材料中不应表述为"自主取证智能体"。
4. **auto_confirmed 路径在真实数据质量下几乎不可达**：14 个事件 0 auto_confirm。门禁直方图（B+C）：`high_or_critical_final_score` 14/14、`confidence_below_0.70` 12/14、`evidence_partial` 10/14、`high_or_critical_priority` 8/14。即 LLM±20 分调整实际从不落地——**智能体对"分数"的影响是理论性的，对"建议+路由+补采"的影响是实在的**。这必须如实表述。

---

## 7. 必须整改的问题清单

| # | 级别 | 问题 | 源码定位 | 运行证据 |
|---|---|---|---|---|
| F1 | P0（功能损坏） | 存在 v3 研判报告后 Markdown 报告生成必然崩溃：`opinions.items()` 作用于 list | `report_service.py:143-152`（v3 管线把 event_results 列表存入 `opinions_json`） | 最小复现：`AttributeError: 'list' object has no attribute 'items'`（已复现） |
| F2 | P0（架构） | 双"四智能体"体系无对账：System A risk_json 与 System B 逐 CVE 结论互不引用；System A 主输出死端 | `routers/agents.py`（仅展示 API）；全仓 grep 无其他消费者 | §2.1 |
| F3 | P1 | System A 结构化输出重试**无错误反馈**：`model_validate` 失败直接抛出走整体重试，模型不知道错在哪；叠加 `extra="forbid"` 导致 Zephyr 场景 2/2 次全败 | `agents/base.py:188-215`（对照：System B 有 `retry_instruction` 反馈，event_review_pipeline.py:424-427） | CF6：`ValidationError: note — Extra inputs are not permitted`，RUNTIME 阶段 failed |
| F4 | P1 | REMEDIATION 智能体上下文饥饿：无 RISK 结果、无 CVE 列表；可执行路径依赖 System B 已授权 → 结构性空转 | `orchestrator.py:246-247,369-370` | 实测 risk_ref=""、actions=[] |
| F5 | P1 | `aggregate_risk` 不消费 `version_impact`：已修复/不受影响的 finding 仍按 CVSS 计基线分（是否低估取决于模型自觉调低 max_severity） | `orchestrator.py:120-145`；`VulnerabilityReport.severity_consistent` 只防夸大不防"已修复仍高分" | 静态证据 |
| F6 | P1 | 证据新鲜度不参与运行时状态：stale 证据（72h）仍计 verified/contextual，只降 strength 权重；风险引擎 `_decision` 的 runtime_status 语义随之过宽 | `runtime_evidence.py:202-233`（status 判定无新鲜度条件）；`risk_engine.py` | CF5 |
| F7 | P2 | System B 无优雅降级：任一专家失败→coordinator 跳过→全部建议坍缩为同质兜底（丢失"哪路意见缺失"的区分度，仅审计字段留痕） | `event_review_pipeline.py:819-839` | §4.3 四种屏蔽输出完全同质 |
| F8 | P2 | 竞赛口径风险：`build_four_agent_workflow` 大屏把 System B 展示为"协同智能体"，与 System A 的"工具循环智能体"混用同一品牌，易被评委追问 | `agent_intelligence.py:418-496` | §2.1 |
| F9 | P2 | System B 每事件 ≈2.2-2.5 万 token、重试后 4.4 次调用/事件；batch 内 15 路并发下 evidence_audit 单事件最高 16.2s——规模化成本需预算 | `event_review_pipeline.py`（BATCH_SIZE=5、MAX_RETRIES=1） | §4.2 计量 |
| F10 | P3 | 实验方法学：本审计 Harness 首版统计器存在键碰撞/未包裹 packet 两处伪报（首报"50 条无依据断言"），离线修正后为 0——统计口径必须与修正脚本同行入库 | `stage9_recompute_metrics.py` | §8 注记 |

---

## 8. 评价指标实测汇总（第四部分）

| 指标 | 实测值 | 口径 |
|---|---|---|
| 风险判断正确性（影响判定） | System B：B 组 7/7、C 组 7/7；规则组处置正确 2/7、智能体组 6/7 | 对照预先定义真值表 |
| 证据引用准确性 | 114 条引用（B 48/C 66）全部命中证据包内 ID，0 幻觉；承重证据占比 89%/85%（其余为 coverage 类） | 逐 ID 对照重建证据包 |
| 无依据断言（确定性矛盾） | **0**/14 事件（运行时状态、暴露状态、影响状态 vs 证据包事实三维检查） | 修正后统计器 |
| 不确定性处理 | 人工路由 3/3 正确（必须人工的案例全部进入人工）；12/14 案例模型置信度<0.7 如实自报并被门禁采纳 | 门禁记录 |
| 单智能体增量（D 组） | 屏蔽任一 System B 智能体：建议 100% 坍缩至兜底；System A 屏蔽 runtime：62→54 分、high→medium | §4.3/§4.4 |
| 运行时证据引入的判断变化 | 7 案例中 3 例建议改变、置信度整体上升；1 例方向变差 | C−B 逐字段对比 |
| 总耗时/Token 成本 | System B：~23-25k token/事件、4.4 调用/事件、77s/7 事件；System A：36.7k token/次编排、42s；D 组屏蔽运行 8-25s | 客户端真实 usage 计量（14+14+4 次运行全部上报 usage，无估算） |
| 对前序输出的依赖 | coordinator 结论与三专家一致率高（14/14 事件采纳其结构化输入并引用其证据 ID）；屏蔽实验证明其为必要集成点而非橡皮图章 | §4.3 |

**对"规则已足够"假设的如实回答**：在本评测集的三个困难案例上，规则系统给出 5 个处置级错误（E3a/b 假阳性、E4a/b 无视冲突、E5 忽视过期），智能体层纠正其中 4 个并全部保守路由——**规则+智能体优于纯规则**。但在简单案例（E1/E2）上两者结论一致，智能体层每事件 2 万+ token 的成本只为困难案例买单；若资产面大量简单候选，应先用规则做廉价分层，只把困难候选送入智能体评审（见 §9 R1）。

---

## 9. 针对性升级方案（第五部分）

原则：**不新增智能体数量、不更换更大模型**；优先修复工作流与证据消费缺陷；不破坏 Harness 安全机制（所有方案保持 fail-closed 门禁与人工复核语义）。

**保留/重设计判断**

| 组件 | 判断 |
|---|---|
| System A runtime_behavior | **保留**（唯一具备"动态证据→行为判定→风险聚合"闭环的智能体） |
| System A vulnerability_intelligence | 保留但瘦身：结论与匹配引擎同源，价值在 data_gaps 交叉核验；`version_impact` 必须接入聚合（F5 修复后） |
| System A device_intelligence | 降级为 RISK 的暴露面输入提供者即可，或并入 runtime 智能体上下文 |
| System A remediation_verification | **重设计**（F4）：直接接收本 run 的 RISK 输出与 CVE 列表；授权前允许产出"待审批计划"而非空方案 |
| System B 四角色 | **保留**：四角色门禁供给关系经消融证明成立；不合并、不新增 |

**修复优先级（供评审后立项）**

- **R1（对应 F2+F8，高收益低成本）双体系对账与口径统一**：System A 完成编排后，将其 risk_json 的 runtime_level/evidence_ids 写入同主机 RiskAssessment 的补充字段（只读附加，不改变 System B 门禁）；总览大屏明确标注两套体系名称与分工。这是"删除摆设"的最短路径：让 System A 的动态证据结论真正进入主链路，而不是新建第五个智能体。
- **R2（F1）**修复 report_service 的 list/dict 兼容（一行级修复，随下轮提交）。
- **R3（F3）**System A 输出校验失败时把 ValidationError 摘要注入重试上下文（复用 System B 的 retry_instruction 模式）；`RuntimeBehaviorReport` 可选放宽为"未知键进 data_gaps"或加 note 字段。
- **R4（F4）**REMEDIATION 上下文注入 `risk.risk_ref/priority/runtime_evidence_ids`；允许对未授权风险产出 `requires_approval=true` 的计划（现有 validator 已强制回滚计划），授权仍由 `_authorized` 把守——不改变任何安全语义。
- **R5（F5）**`aggregate_risk` 消费 `version_impact`：`fixed/not_affected` 的 finding 不计入基线分（或在 rationale 中显式扣减）。
- **R6（F6）**运行时状态语义升级：`evaluate_runtime_evidence` 增加 stale 维度——全部命中事件超过新鲜度阈值时 status 降为 `stale_verified`（或 waiting），风险引擎 `_decision` 与证据包同步该语义；`tool_query_runtime_data_quality` 已具备全部所需数据。
- **R7（F7）**System B 部分失败时允许"3/4 降级评审"：三专家中任一失败时 coordinator 仍可产出建议但必须带 `degraded=true` 与缺失角色名，audit_policy 对 degraded 结论强制人工复核（比当前全兜底保留更多信息，不放松门禁）。
- **R8（F9）**成本分层：`confidence_below_0.70` 与 `evidence_partial` 占比高说明证据包天生不全；在进入 LLM 评审前用规则预分层（E1/E2 类简单候选直接维持 monitor 基线，跳过 4 次调用），预计节省 50%+ 评审成本，困难案例（E3/E4/E5 类）全量送审。

**明确不做**：不加第五个智能体；不用更大模型（deepseek-v4-flash 在本评测集上行为合格）；不让 LLM 直接写 final_score（保持 DIRECTION_ADJUSTMENTS 有界映射）。

---

## 10. 可直接用于竞赛论文的实验数据

**实验设置**：模型 deepseek-v4-flash（temperature 0.1，生产同配置）；7 风险事件 × {A, B, C} 全量 + 4 组单智能体屏蔽 + 3 次 System A 编排；共 ~160 次真实 LLM 调用；合成 CVE/TEST-NET Fixture（防参数知识污染与信息外泄）；真值表先于实验独立定义。

**表 1 处置建议正确率（对照真值，处置级）**

| 配置 | 正确/总数 | 错误案例 |
|---|---|---|
| A 纯规则 | 2/7 (28.6%) | E3a, E3b（假阳性升级）；E4a, E4b（无视冲突）；E5（忽视过期） |
| B 规则+四智能体（无运行时） | 6/7 (85.7%) | E4b 建议 scheduled_fix（应为 monitor/collect） |
| C 规则+四智能体+运行时 | 6/7 (85.7%) | 同 B |

**表 2 影响判定/引用完整性（智能体层）**

| 指标 | B | C |
|---|---|---|
| 影响判定正确 | 7/7 | 7/7 |
| 证据引用总数 / 幻觉数 | 48 / 0 | 66 / 0 |
| 与证据包事实矛盾数 | 0 | 0 |
| auto_confirmed | 0/7 | 0/7 |

**表 3 成本（真实 usage 计量）**

| 运行 | LLM 调用 | prompt tokens | completion tokens | 墙钟 |
|---|---|---|---|---|
| B（7 事件评审） | 33 | 116,331 | 43,566 | 75.1s |
| C（7 事件评审） | 31 | 127,703 | 49,456 | 77.1s |
| System A 单次编排 | 14 | 30,613 | 6,097 | 41.7s |
| System A 屏蔽 runtime | 11 | 22,358 | 4,270 | — |

**表 4 单智能体屏蔽（D 组，E1+E4×2）**：四种屏蔽均 → 建议 collect_more_evidence/兜底、优先级空、方向 maintain；人工复核路由 100% 保持。

**表 5 System A 风险聚合敏感性**：完整 62/high（RUNTIME=ACTIVE，6 evidence_id）vs 屏蔽 54/medium（NORMAL）——动态证据对最终优先级的净贡献 +8 分/一级。

---

## 11. 方法学与诚实性声明

1. 本轮**未修改任何生产代码**；两份实验脚本入库（不含密钥；`.env` 不入库）；原始运行产物（含 LLM 原文）仅存本地 `backend/reports/stage9-agent-audit/`（gitignore）。
2. 实验统计器首版存在两处缺陷导致"无依据断言 50 条"的**伪报**（case 键碰撞覆盖 + packet 未按结构传入）；已由 `stage9_recompute_metrics.py` 按 object_id 对齐证据包离线修正为 0。伪报与修正过程全部留档。
3. Fixture 使用合成 CVE 编号：这是为隔离模型参数知识的有意设计，代价是无法考察模型对真实知名 CVE 的先验；该边界已在报告多处标注，不作为智能体能力的普适性证明。
4. 单次运行、temperature=0.1：E3b 方向在 C 组变差（maintain→upgrade_minor）提示存在运行间方差；结论中所有"变化/未变化"均基于本运行实测，未做多次重复平滑——如需论文级稳定性数据，建议下轮对 E1/E3/E5 各做 3 次重复。
5. 真实密钥、真实数据库、未脱敏日志均未入库；本报告中的 IP 均为 TEST-NET 文档地址。

## 12. 后续

- 本报告仅完成审计、消融、反事实与升级方案；**未启动任何整改**（Stage 9B 待评审指令）。
- 建议评审顺序：R2（崩溃修复）→ R1（双体系对账）→ R3/R4（System A 可用性）→ R6（新鲜度语义）→ R7/R8。
