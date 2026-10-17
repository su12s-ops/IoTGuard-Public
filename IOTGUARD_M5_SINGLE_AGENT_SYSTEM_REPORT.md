# IoTGuard M5 交付报告：统一四智能体唯一化与旧 LLM 系统退役

**日期**：2026-10-17
**基线**：origin/main `58fd221`（M4.7 交付 + GLM-5.3-Flash 切换），工作区干净。
**本轮结论（先读）**：

> **正式切换 `LINUXGUARD_UNIFIED_PIPELINE=on` 依约停在 Q1–Q8 人工裁定门禁，等待真实授权操作员签署。**
> M4.7 迁移契约（`IOTGUARD_UNIFIED_AGENT_MIGRATION_ACCEPTANCE.md` §77）明确「授权操作员完成复核材料 Q1–Q8 裁定」为正式切换前置人工事项。经逐项核查：两份材料（风险 126 / 历史 12）裁定栏全部留空，数据库零人工裁定痕迹（`human_confirmed`/`rejected`/`[human_review]` 标记均为 0），风险 126 现值 `reanalysis_required`、风险 12 `inactive`——与交付时状态一致，签署确实未发生。按 M5 指令第 4 条「模型不得代签；如契约要求先完成签署，则停在该人工环节」，本轮**不切 on、不重启进 on、不删除旧系统产品代码**；门禁之外的全部准备工作已一次性完成并验证（中立迁移、一致性备份、排空、回滚演练 44/44、Mimosa 0 findings）。旧系统的互斥护栏（`system_b_formal_writer_disabled`）经演练确认在 on 侧全部有效，不存在绕过路径。

---

## 1. 最终唯一 LLM 架构（目标态与当前态）

**目标态（M5 完成后）**——全项目唯一正式 LLM 研判体系：

```
真实资产/风险（RiskAssessment, reanalysis_required|candidate）
  → /api/analysis 正式入口（routers/analysis.py）
  → unified.adapter.generate_and_save_report_unified（唯一适配层）
  → LangGraph 统一四智能体（services/unified/graph.py）
      asset_investigator → vulnerability_analyst ∥ runtime_analyst → decision_planner
      （全部只读工具 = services/agent_tools.py；LLM 客户端 = services/agent_infra.py）
  → 确定性安全校验（unified/audit_policy.py 审计门禁 + conflicts + plan_guard）
  → 人工复核（必要时，POST /api/analysis/risks/{id}/human-review，控制令牌保护）
  → 正式 RiskAssessment（formal_sink 唯一写入器）
  → Harness 候选处置计划（agent_harness，审批独立，模型无执行权）
```

异常路径唯一合法行为：**fail-closed**（`unified_orchestrator_failed:*` → `pending_human_review` + 人工标记 + 清空自动确认字段），不允许回退旧系统。

**当前态**：代码结构已就位——正式入口适配层已唯一接至统一编排器（on 模式下）；旧 System A/B 代码仍在仓库中（off 模式下的现行正式链路），其四个写入入口在 on 模式下被护栏拒绝（演练 D3 实证）。物理删除按 §6 计划待门禁放行后执行。

## 2. 实际删除或迁移的旧系统文件

### 2.1 本轮已完成的中立迁移（新系统依赖的通用确定性组件移出旧文件）

| 旧位置（System A/B 内） | 新中立位置 | 内容 | 回归 |
| --- | --- | --- | --- |
| `services/agents/base.py` | `services/agent_infra.py` | AgentTool/AgentSpec/ChatClient 协议、DeepSeekChatClient、AnthropicProtocolChatClient、build_llm_client、parse_structured_output | 统一 75 测试通过 |
| `services/agents/tools.py`（全文） | `services/agent_tools.py` | 四组只读查询工具（设备画像/CVE 情报/eBPF 证据/修复目标）+ `_evidence_keys` | 同上 |
| `services/agents/agents.py`（部分） | `services/unified/schemas.py`（内联） | RemediationActionPlan、VerificationStep（白名单动作 Schema，唯一消费方为统一编排器） | 同上 |
| `services/event_review_pipeline.py`（部分） | `services/review_common/`（新包） | evidence_packet.py：EvidenceItem/EvidencePacket/build_evidence_packet；selection.py：select_candidates/explain_candidate_selection/preflight_check/REVIEWABLE_STATUSES；human_review.py：apply_human_review/DIRECTION_ADJUSTMENTS | 203 测试通过 |
| `services/event_review_pipeline.py`（部分） | `services/review_common/` | latest_analysis 式报告读模型（analysis.py /latest 沿用，随切换改造接入） | — |

统一编排器六个模块（agent_base/graph/agents_def/evidence_prep/routing/schemas/adapter）已全部改为只依赖中立模块，**与旧 System A/B 无任何 import 关系**（adapter 对候选选择的依赖已切至 `review_common.select_candidates`）。

### 2.2 待门禁放行后的物理删除清单（已审计定位，执行属机械操作）

| 删除对象 | 性质 | 现调用方（切换后归零） |
| --- | --- | --- |
| `services/agents/`（__init__/agents/base/orchestrator/tools） | 旧 System A 独立编排 + 已迁出基础件 | routers/agents.py（删除）、mqtt_security_workflow.agent_plan（改确定性）、历史脚本（归档） |
| `services/event_review_pipeline.py` | 旧 System B 独立 LLM 审查编排 | analysis.py off 分支（删除）、demo.py（改统一适配层）、agent_harness._expert_review（删除）、历史脚本（归档） |
| `services/agent_group_chat.py` | System B 兼容门面（246 行 re-export） | analysis.py、demo.py、历史脚本、测试 |
| `routers/agents.py`（/api/agents/*） | 旧 System A 独立接口 | main.py 注册（移除）；前端 AgentOps 改接 /api/unified/* |
| `models.AgentOrchestrationRun` | 旧 System A 运行表映射 | 仅 routers/agents 与 orchestrator 引用；既有表保留为历史审计证据，不迁移不回填（TraceRun 注释既有约定） |
| `agent_harness._expert_review` + `model_review` LLM 分支 | Harness 内嵌的第二套 System B LLM 评审 | `model_review=true` 改为显式拒绝（fail-closed），`inspect_evidence` 确定性能力经 review_common 保留 |
| `mqtt_security_workflow.agent_plan` 的 System A LLM 调用 | 辅助 LLM 方案生成 | 改为纯确定性白名单方案（现 fallback_plan 内容），人工审批与设备执行器语义不变 |
| `routers/demo.py` 的 `generate_and_save_report` 调用 | 演示链直调 System B | 改调 `generate_and_save_report_unified` |
| `analysis.py` 的 off→System B 分支 | off 回退分支 | `_review_entrypoint` 统一唯一；mode!=on → 503 fail-closed（无回退） |
| 历史脚本 14 个（diag_group_chat、smoke_*、stage9*、m46_production_readiness、m47_continuous_shadow、m47_migration_drill 旧引用、verify_*） | 仅驱动旧系统的操作员工具 | 移出 main 分支（local-archive 私有留存）；m47_migration_drill 已先行改造为退役感知（D3 双态断言），作为未来切换的契约校验器保留 |
| 测试 6 个（test_agent_refactor、test_review_workflow、test_four_agent_pipeline、test_delivery_refactor、test_json_extraction、test_trace_system 的 System A/B 部分） | 旧系统专项测试 | 删除或改写为中立模块/统一编排器等价测试；新增退役守卫测试（旧模块不可导入、/api/agents 404、mode!=on 时正式入口 503） |
| 前端 `deviceOperations.js` 4 个函数 + AgentOps.vue 四智能体页签 | 旧 System A 前端入口 | 改接 /api/unified/specs|runs|analyze（device_surface shadow） |

**不删**（通用业务能力，与旧编排器解耦后保留）：`review_common` 全部、`agent_tools` 全部、`agent_infra` 全部、Harness 确定性采集/审批/执行、风险规则计算器、CVE 匹配、情报服务、trace、数据库、控制令牌门禁、`models.AgentAuditRecord`（统一适配层同表写入）。

## 3. 完整调用关系核查结果

### 3.1 旧 System A（services/agents/orchestrator+agents+base+tools）

| 调用方 | 调用内容 | 处置 |
| --- | --- | --- |
| `routers/agents.py`（/api/agents/specs、/analyze、/runs） | `orchestrator.start_analysis`、`specs_summary` | 删除路由；前端改接 unified |
| `services/mqtt_security_workflow.py:agent_plan` | `ToolLoopAgent(REMEDIATION_VERIFICATION_SPEC)` 真实 LLM + 确定性兜底 | 改纯确定性白名单方案 |
| `services/unified/*`（6 处 import） | 仅基础件/工具/Schema（非编排） | 已全部切至中立模块（本轮完成） |
| `scripts/smoke_device_analysis.py`、`smoke_real_agents.py`、`stage9_agent_effectiveness_audit.py` | run_orchestration | 随退役归档 |
| `tests/test_agent_refactor.py`、`test_trace_system.py`、`test_ebpf_p23_agent_data_quality.py`（specs_summary 部分） | orchestrator/ToolLoopAgent | 删除/改写 |
| `tests/test_device_cve_matching.py`、`test_ebpf_p0/p13/p22`、`test_llm_protocol_clients.py`、`test_unified_investigation.py` | 仅 tools/base 基础件 | 随中立迁移改 import（本轮已完成映射更新路径） |

### 3.2 旧 System B（event_review_pipeline + agent_group_chat 门面）

| 调用方 | 调用内容 | 处置 |
| --- | --- | --- |
| `routers/analysis.py` | `_review_entrypoint` off 分支 → `generate_and_save_report`；status/preflight/latest/human-review（确定性） | 入口唯一化（统一）；确定性部分经 review_common |
| `routers/demo.py:761` | `generate_and_save_report`（演示 E2E 直调） | 改统一适配层 |
| `services/agent_harness.py:367,485` | `_expert_review`（System B LLM）；`build_evidence_packet`（确定性） | 前者删除（fail-closed 拒绝），后者已切 review_common（本轮完成） |
| `services/unified/adapter.py:206,283` | `_selection` | 已切 `review_common.select_candidates`（本轮完成） |
| `scripts/` 12 个 + 根目录 `scripts/verify_*` | 流水线直调 | 随退役归档 |
| `tests/` 8 个 | 流水线/校验器 | 删除/改写 |

### 3.3 确认为通用能力、不属旧 LLM 的模块（保留不动）

`risk_engine`、`matching_engine`、`vulnerability_intelligence/*`、`real_intel_collector`、`reachability`、`runtime_evidence`、`runtime_telemetry`、`security_evidence`、`ebpf_*`、`device_vulnerability`、`remediation_engine`、`ubuntu_repair`、`device_access`、`collection_tasks`、`trace_service`、`report_service`、`experiment_lifecycle`、`agent_intelligence`（确定性读模型，读 AnalysisReport 不调 LLM）、`routers/workflow.py`（读模型）。

## 4. 正式运行的 flag 与进程状态

| 项 | 状态 |
| --- | --- |
| `LINUXGUARD_UNIFIED_PIPELINE`（backend/.env） | **未设置（等效 off）——按门禁要求保持**；未做「只改 .env 宣布成功」的半切换 |
| 运行中后端进程 | `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`（PID 16528，2026-10-16 23:21:56 启动）——**早于 58fd221 提交，进程内为旧代码+旧环境**；切换重启时一并收敛 |
| 进程内实测模式 | `GET /api/unified/specs → mode=off`（与 .env 一致，无暗中 on） |
| 双设备修复写开关 | `LINUXGUARD_ENABLE_DEVICE_REPAIR`、`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR` 均未设置（默认 0=关）；演练 H3 实证关态拒绝入队 |
| 控制令牌 | .env 为 M4.7 轮换后令牌；实测运行中进程对轮换令牌返回 401（进程持有更早环境）——**轮换令牌将在切换重启时生效**，已列入恢复清单第 4 步 |

## 5. 四智能体真实核心功能验收

本轮在**隔离数据库副本**上以 M4.7 同一契约校验器（m47_migration_drill，确定性演练客户端，明确标注非真实 LLM、不复制任何历史影子结论）重跑，**44/44 通过**：

| 验收项 | 结果 | 证据 |
| --- | --- | --- |
| A. 正式业务请求进入唯一 LangGraph 四智能体 | ✅（隔离 on 态） | E1/E2 正式入口 17 键契约齐备；E7 统一运行行 mode=formal；D4 /api/unified/analyze 拒绝第二正式入口（409） |
| B. 四角色调用真实工具、消费真实资产/漏洞情报/动态证据 | ✅（隔离 on 态） | E6 四角色审计入库（asset_investigator/vulnerability_analyst/runtime_analyst/decision_planner）；E4 全量路径写入处置与方向；E5 设备上下文对账回写；工具集即 §2.1 中立 agent_tools（真实库查询） |
| C. 调查申请→独立只读授权→补证→再研判 | ✅（机制；真实采集已于 M4.6/M4.7 实证） | G1–G5 令牌保护/状态机/409 边界；F2 无晋升端点；resume 仅在已授权采集完成后派发（routers/unified.py） |
| D. 风险↔证据↔Trace↔人工门禁↔Harness 候选计划关联 | ✅（隔离 on 态） | E4/E5 落库关联；G4 人工确认落 human_confirmed（77.4 分）；H1–H3 Harness 未审批/错哈希拒绝、修复开关关态拒绝 |
| fail-closed（未来唯一异常路径） | ✅ | E9a/E9b/E9c 模型故障 → pending_human_review + 报告如实落 human_review；D3 on 侧 System B 四写入器全部拒绝 |
| 禁止影子晋升 | ✅ | B3 快照声明 shadow_promotion_allowed=False；F1 历史 shadow 行经 formal_sink 被拒；F2 静态扫描无 promote 端点 |
| 回滚 | ✅ | I1 仅切 flag 不还原已写正式字段；I2–I7 manifest 校验→全字段恢复→差异 0→副本完整 |

**Live 正式 on 态验收（A–D 生产面）**：待门禁放行、重启进 on 后按恢复清单第 6–7 步执行（POST /api/analysis/runs 真实候选 → pipeline_version=unified-four-agent-v1+analysis-compat、UnifiedAnalysisRun/AgentAuditRecord/TraceRun 关联核验）。

## 6. 数据库、证据、人工复核及 Harness 状态

| 项 | 状态 |
| --- | --- |
| 一致性备份 | `local-archive/m5-switch/linuxguard-preM5-20261017T020005Z.db`（397,836,288 B，sha256 `33283418…e513f`，PRAGMA integrity_check=ok，126 风险行），manifest 同目录 |
| 排空 | busy risks=0、running AnalysisReport=0、running UnifiedAnalysisRun=0 |
| 候选 | 111 条活跃风险全部 `reanalysis_required`（M4.7 隔离演练后的待重研状态），切换后由统一链**重新研判**产生正式结论——不存在影子结论晋升 |
| Q1–Q8 人工裁定 | **未签署**（门禁停点）：材料裁定人/时间/Q1–Q4/签名栏全空；DB `human_review` 标记 0；风险 126=`reanalysis_required`、风险 12=`inactive` 与交付时一致；`POST /api/analysis/risks/{id}/human-review` 仅接受 `pending_human_review/human_reviewing` 状态——126/12 当前状态不可被 API 代签，须操作员按材料途径落库 |
| 隔离演练写入 | 全部发生在 `reports/m47-work/migration-drill/isolated.db` 副本并已全字段回滚（I3 差异 0）；真实库本轮零写入（仅只读快照与备份） |
| Harness | 52 条历史 HarnessRun 为证据留存；无进行中任务；修复写开关关；候选计划链路（shadow_candidate 授权=none）在 M4.7 验收过，本轮未触碰 |
| Trace/证据 | AgentAuditRecord 0 条新写入；UnifiedAnalysisRun 39 条历史影子行原样保留 |

## 7. 最终测试、安全检查及 Git Commit

| 项 | 结果 |
| --- | --- |
| 统一系统回归 | tests/test_unified_pipeline + test_unified_adapter + test_unified_investigation：75/75 |
| 中立迁移波及面回归 | test_evidence_prep + test_quality_deepening + test_agent_harness_upgrade + test_multi_source_vulnerability_intelligence：128/128 |
| 迁移契约演练（隔离副本） | 44/44（含退役感知改造后的 D3 双态断言、E9 修复验证） |
| 全量回归 | **742 passed / 0 failed**（主干 `python -m pytest tests/ -q` 701 通过/533s + `test_ebpf_p21_perf` 41 通过；与 GLM 切换里程碑 742 基线完全对齐，零增减） |
| Mimosa 深度安全扫描（迁移后代码） | 过程扫 `scan-2026-10-17T01-59-32.762Z-90ab750eaf44` 0 findings；**交付终扫（含演练修复后最终代码）`scan-2026-10-17T02-18-21.318Z-f6346022fd88`，findingCount=0**，封印 `sha256:580103b6b4803026e59fc0e16020c9e3da6bb980310f9dc2ddaeda24e6544f4b`，123 依赖包，离线通告库可用——迁移前置「完成 Mimosa 安全验收」对当前代码成立 |
| SQL/凭据约束 | 新增代码全部参数绑定/ORM 查询；无凭据字面量；Mimosa 0 findings |
| Git Commit | 本报告随实现提交并推送 IoTGuard-Public main（commit 号见 CHANGELOG）；不修改公开历史 |

## 8. 是否已不存在旧系统的运行入口及自动兜底

**如实回答：尚未完全消失（门禁停点的如实状态）。**

- 旧系统**产品运行入口**在当前 off 态下仍是现行正式链路（设计使然：切换与删除必须以「新正式入口实测可用」为前提，而该验证被 Q1–Q8 门禁阻断）；
- 但旧系统**不存在任何自动兜底/暗中第二写入器**：on 态下 System B 的全部四个写入入口（`run_review_analysis`、`generate_and_save_report`、`_persist_event_result`、`_apply_object_verdicts`）被 `system_b_formal_writer_disabled` 护栏拒绝（演练 D3 实证）；统一编排器故障时唯一行为是 fail-closed 落人工（E9 实证）；不存在新旧双模型对照、隐藏预判或影子晋升路径（F1/F2 实证）；
- 「旧系统物理删除 + 入口消失」将在操作员完成 Q1–Q8 落库后的恢复流程中一次性执行（§7 恢复清单），届时本报告 §2.2 清单逐项落地并以退役守卫测试锁定。

## 9. 恢复清单（操作员完成 Q1–Q8 后的既定流程）

1. **操作员裁定**：按 `IOTGUARD_M47_HUMAN_REVIEW_PACKETS.md` A4/B4 材料完成 Q1–Q4 ×2 决定并落库（`POST /api/analysis/risks/126/human-review`、`/12` 需 X-Control-Token；模型不代签）。注：两风险当前状态（reanalysis_required/inactive）不可径直裁定，按材料口径执行——材料 Q1 的选项本身包含「维持 reanalysis_required」；
2. **执行 M5 第二阶段**：按本报告 §2.2 清单物理删除旧系统、analysis.py 唯一化（mode!=on → 503 fail-closed）、config 默认 on、前端改接、测试退役守卫、历史脚本归档；
3. **切换**：`backend/.env` 追加 `LINUXGUARD_UNIFIED_PIPELINE=on` → 重启唯一 uvicorn → `GET /api/unified/specs` 应返回 `mode=on, formal_writer=unified` → 确认单 worker；
4. **令牌生效核验**：轮换令牌（现 .env 值）对 human-review 端点错误令牌 401/正确令牌按状态 401/409/200；
5. **Live 验收 A–D**：真实候选走 POST /api/analysis/runs → 核验 UnifiedAnalysisRun(mode=formal)/AgentAuditRecord/TraceRun/formal_sink 落库链与 Harness 候选计划关联；
6. **回归**：全量测试 + 退役守卫测试 + Mimosa 终扫（对删除后代码）；
7. **交付**：更新本报告与协作文档，commit+push。回滚仅依赖：本报告 §6 备份 + 明确版本 + 授权恢复程序（不依赖任何第二套在线研判器）。

## 10. 边界声明

本轮：未切 on、未重启服务、未删除任何产品代码、未执行任何真实软件包修复、两个设备修复写开关保持关闭、未将任何影子结论晋升为正式结论、未签署或代填任何人工裁定、未修改公开 Git 历史。所有演练写入均发生在隔离副本并已验证回滚至差异 0。
