# IoTGuard 统一四智能体代码迁移说明（Stage 9B）

> 基线：b1d4014（审计）→ f6bd0ef（M0 设计）→ 9185144（M1–M3 实现）。
> 设计契约：`IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md`。
> 本文面向后续维护者：新代码在哪里、每个模块从旧体系继承了什么、如何开关、如何最终退役旧代码。

---

## 1. 新包结构（唯一正式编排器）

```
backend/app/services/unified/
├── schemas.py       四个 Agent 的输出 Schema + 编排层结构（冲突/门禁记录）
├── agent_base.py    执行基座：工具循环 + 结构化校验 + F3 反馈重试 + 空输出拒绝
│                    + 字段预分拣（CF6 修复）+ UsageMeter 预算计量
├── agents_def.py    四个 Agent 定义（职责/只读工具/输出模型，唯一命名）
│                    + 新增只读工具 query_intelligence_sources
├── state.py         LangGraph 有状态工作流 State（含并行分支 reducer）
├── routing.py       任务分类与成本分层路由（R8：simple 层 0 次 LLM）
├── conflicts.py     确定性冲突检测（System B 3 规则 + 4 条跨 Agent 交叉新规则）
├── audit_policy.py  确定性审计门禁（继承 System B 全部门禁 + 降级/过期语义）
├── aggregator.py    设备级确定性聚合（F5：fixed/not_affected 不计基线分）
├── graph.py         LangGraph StateGraph：9 节点 + 条件路由 + A2∥A3 并行
├── runner.py        运行生命周期：建行/后台线程/逐节点快照/Trace 收尾/simple 直通
└── adapter.py       兼容适配层：flag=on 时把 /api/analysis 接到统一编排器
                    （formal_sink 正式落库，语义与 System B _persist_event_result 一致）
```

配套变更：
- `models.py`：新增 `UnifiedAnalysisRun` 表（影子/正式运行记录）；
  `RiskAssessment.device_context_json` 新列（F2/R1 设备级结论对账写回，只读附加）。
- `database.py`：`RISK_ASSESSMENT_COLUMN_MIGRATIONS` 增加 `device_context_json`（旧库增量幂等）。
- `trace_service.py`：`TASK_TYPES` 注册 `unified_four_agent`。
- `routers/unified.py`：`/api/unified/{specs,analyze,runs,...}` 影子/正式运行 API 与对照查询。
- `config.py`：`LINUXGUARD_UNIFIED_PIPELINE = off | shadow | on`（默认 off = 零行为变化）。
- `requirements.txt`：新增 `langgraph>=1.2`（Python 3.14 实测 1.2.15 可用）。

## 2. 能力来源映射（不复制旧代码，逐项复用）

| 统一模块 | 来源 | 复用方式 |
|---|---|---|
| `agent_base.DeepSeekChatClient` / `ChatClient` / `parse_structured_output` | System A `agents/base.py` | 直接 import |
| 14 个只读调查工具 | System A `agents/tools.py` | 直接 import（零改动） |
| `AgentSpec` / `AgentTool` | System A `agents/base.py` | 直接 import |
| `RemediationActionPlan` / `VerificationStep`（白名单动作 + 禁 shell 参数校验） | System A `agents/agents.py` | 直接 import 嵌入统一 ResponsePlan |
| `severity_consistent`（防夸大） | System A `VulnerabilityReport` | 语义继承进统一 VulnerabilityAnalysisReport |
| 证据存在性校验 + 反馈重试 | System A `validate_runtime_report` + RUNTIME 阶段 | 泛化进 `_run_specialist` + 各 validator |
| `build_evidence_packet` | System B `event_review_pipeline.py` | 原地共享（风险事件证据底座；packet 证据 ID 供防幻觉校验） |
| 防锚定（impact 输入剔除 baseline） | System B `IMPACT_PROMPT` 设计 | 统一 VulnerabilityTask 不含规则分数 |
| 3 条冲突规则 | System B `detect_conflicts` | 语义继承 + 扩展 4 条跨 Agent 规则 |
| `apply_audit_policy` 全部门禁 + fail-safe 兜底 | System B | 语义继承进统一 audit_policy（新增降级/过期理由） |
| `DIRECTION_ADJUSTMENTS` 有界方向映射 | System B | 原样保留 |
| 逐事件进度持久化/批量模式 | System B `_RunProgressTracker` | 模式继承进 runner/adapter |
| 补采请求语义（requested_tools → Harness 补采复评） | System B coordinator | `follow_up_requests` + Harness 链路保留 |
| 品牌与版本 | F8 整改 | 单一 `unified-four-agent-v1`；历史运行保留原版本标识 |

**明确废弃**：System B 的 autogen 模型客户端（统一走 ChatClient 协议）；System A 的 6 阶段硬编码串行流程与 `aggregate_risk`（被图与 F5 聚合器取代）。

## 3. 缺陷修复落点

| 缺陷 | 修复位置 | 回归锁定 |
|---|---|---|
| F1 (P0) markdown 崩溃 | `report_service.py` list/dict 双形态渲染 | `test_unified_pipeline.py::TestReportF1Fix` |
| F2 (P0) 双体系死端 | 唯一编排器 + `formal_sink.device_context_json` 对账写回 | `test_unified_adapter.py::TestFormalSink` |
| F3 (P1) 校验失败无反馈 | `agent_base._validate_with_feedback`（错误摘要注入重试上下文） | `TestAgentBase::test_retry_with_validation_feedback` |
| F5 (P1) version_impact 不被消费 | `aggregator.aggregate_device_risk` + 冲突规则 5 | `TestAggregator` + `TestConflicts` |
| F6 (P1) 新鲜度不参与状态 | `RuntimeAnalysisReport` schema 强制（verified⇒fresh / stale_verified）+ 门禁 `stale_runtime_evidence` | `TestSchemas` + `TestAuditPolicy` |
| F7 (P2) 部分失败全丢 | 逐 Agent 独立落库 + `degraded_roles` + 门禁 `agent_degraded:*` | `TestGraphTopology::test_agent_failure_degrades_without_losing_others` |
| F8 (P2) 品牌混乱 | 单一命名/版本 + 前端映射统一 | `test_unified_pipeline.py::TestUnifiedApi::test_specs_endpoint` |
| F9 (P2) 成本无分层 | `routing.decide_routing` simple 层 0 次 LLM | `TestRouting` + `TestRunner::test_simple_tier_zero_llm` |
| CF6 根因 | `triage_extra_fields`（顶层未知键→notes）+ 空对象拒绝 | `TestSchemas::test_field_triage_*` |
| 空输出伪成功 | `agent_base._validate_with_feedback` 拒绝 `{}` | 降级路径各测试 |
| §7-7 动态证据错误升级 | 冲突规则 4（告警 vs 不受影响/已修复）+ 有界方向 + 语义边界声明 | `TestConflicts::test_runtime_alert_vs_not_affected_cross_conflict` |

## 4. 开关与灰度

```bash
# off（默认）：/api/analysis 走 System B 原链路，统一 API 仅可查 specs（analyze 返回 503）
# shadow：正式链路照旧；/api/unified/analyze 可发起影子运行（只写 unified_analysis_run）
# on：/api/analysis 正式入口切换到统一编排器（响应契约兼容）；/api/unified 同步可用
LINUXGUARD_UNIFIED_PIPELINE=shadow
```

- 回滚：任何阶段把开关拨回 `off` 即恢复原链路（适配层是唯一接缝）。
- 影子隔离由测试锁定：影子运行后 `RiskAssessment` 全部正式字段与运行前逐项一致
  （`TestRunner::test_shadow_run_persists_and_never_touches_formal_fields`）。

## 5. 旧体系退役清单（M5 后执行，须逐项核验）

正式入口切换并稳定后，下列项满足条件方可退役（先摘除引用，文件删除须用户批准）：

1. `routers/analysis.py` 的 `_review_entrypoint` 分支删除（唯一入口=统一编排器）；
2. `services/agents/orchestrator.py`（System A 编排）从 `routers/agents.py` 摘除，
   AgentOps 页改读 `/api/unified/runs`；
3. `services/event_review_pipeline.py` 的评审执行路径保留最小兼容面
   （`build_evidence_packet`/`_selection`/`apply_human_review` 仍被统一链与 Harness 复用）；
4. `services/agent_group_chat.py` 兼容 facade 收缩为纯 re-export；
5. `pyautogen` / `autogen-ext` 依赖移除（确认无其他消费方后）；
6. 前端 AgentOps/AgentWorkflow 数据源统一指向 `/api/unified`；
7. 全仓 `grep` 核验：不存在第二个可作为正式入口的四智能体执行路径。

**硬性不变式**：`agent_harness.py` 安全语义（审批哈希/资产锁/工具预算/回滚/写操作总开关）在任何阶段零改动。

## 6. 新增测试索引

- `backend/tests/test_unified_pipeline.py`（46 项）：Schema 语义 / F3 重试 / 预算 / 路由分层 /
  冲突 7 规则 / 门禁 / F5 聚合 / 图拓扑（并行、复议≤1、补查≤1、伪造证据降级、
  部分失败保留）/ 影子隔离 / simple 直通 / 统一 API / F1 修复。
- `backend/tests/test_unified_adapter.py`（4 项）：formal_sink fail-closed 落库 /
  auto_confirmed 可达路径 + 规则直通 / 批量适配契约 / 入口按开关切换。
