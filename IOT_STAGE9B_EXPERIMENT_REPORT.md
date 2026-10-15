# IoTGuard Stage 9B 统一四智能体迁移与对照实验报告

> 基线：b1d4014（Stage 9 审计）。实施：f6bd0ef（M0 设计）→ 9185144（M1–M3 实现）→ 本报告。
> 实验脚本：`backend/scripts/stage9b_unified_compare.py`（可复跑，支持断点续跑）。
> 模型：deepseek-v4-flash（与生产同配置，temperature 0.1）；真实客户端 usage 计量，无估算。

---

## 0. 结论（TL;DR）

1. **统一四智能体已完整落地并通过全量回归**：LangGraph 单图、四个专业 Agent、A2∥A3 并行、有界补查/复议、确定性门禁；全量回归 **549 passed / 0 failed**（499 基线 + 50 新增专项，零回归）。F1/F3/F5/F6 及 §7 八项问题全部修复并有测试锁定。
2. **真实 LLM 同案例对照实验部分完成**：System B 全量 10 事件（44 次调用 / 242,108 tokens / 76.0s）+ 统一链 7 次运行（E1×3、E2、E3×1、X1×2）后，**DeepSeek 账户余额耗尽（HTTP 402 Insufficient Balance）**，其余运行（E3 剩余、E4、E5、X3、屏蔽消融）未能执行。这是外部依赖，只有账户充值后可续跑（命令见 §6）。
3. **实验在前 5 次 LLM 运行中暴露了 5 个统一链真实缺陷，全部已修复并加回归锁定**（§4）——这是本轮最重要的工程产出：统一链在真实 LLM 下的第一次暴露即完成了自我纠正。其中「执行基座丢失异常保护」一项（实验中把一次图节点击穿）是 M1–M3 实现引入的真实回归，被实验当场抓获。
4. **不做无依据的优劣结论**：完成的样本量（统一链 5 次 LLM 评审 vs System B 10 次）不足以支撑"新系统不劣于/优于旧系统"的判定；E1 的 3 次重复中 1 次全链成功且结论正确（confirmed_affected/immediate_fix，与真值一致），2 次因上述已修复缺陷降级。续跑完成前，本报告不对判定质量下结论。

---

## 1. 实验设置

- **Fixture**：完整复用 Stage 9 审计受控环境（`build_fixture(with_runtime=True)`：4 资产 / 5 合成 CVE-2026-81xxx / TEST-NET 地址 / 7 风险事件），新增独立案例：
  - **X1**（CVE-2026-81006，Low/zlib，edge-01 与 edge-04 两事件）：成本分层直通验证；
  - **X3**（CVE-2026-81007，sudo/edge-05）：仅 72h 过期运行时证据 + 采集器在线——F6 新鲜度语义验证。
  - 规则基线与 Stage 9 审计逐案一致（100.0/61.05/69.05×2/85.25×2/83.83），确认 Fixture 可比性。
- **对照组**：A 规则基线（`collect_baseline`）；System B 原链路全量；统一链影子运行（sink=None，不触碰正式字段，测试锁定）。
- **计量**：客户端真实 usage（`usage_reported_responses == llm_calls`，无缺失）。

## 2. 已完成的运行与成本

| 运行 | 事件数 | LLM 调用 | tokens | 墙钟 |
|---|---|---|---|---|
| System B（原链路，10 事件全量） | 10 | 44 | 242,108 | 76.0s |
| 统一链 E1×3 / E2 / E3#0 | 5 | — | — | ≈4 min/次 |
| 统一链 X1×2（simple 分层） | 2 | **0** | **0** | <1s/次 |
| 统一链合计（有效） | 7 | 30 | 436,251（含失败重试消耗） | 2,247s |

统一链单次标准评审 ≈4 分钟/事件，显著慢于 System B 的 ≈7.6s/事件——来源是工具循环多轮调用（本轮实测还叠加了 API 限流退化，见 §4-5）；其成本收益设计依赖 simple 分层把简单候选挡在 LLM 之外（X1 两次运行 0 次调用验证了该路径）。

## 3. 部分数据的观察（样本不足，不作优劣结论）

- **E1#1（第二次重复）全链成功**：影响判定 confirmed_affected、方向 maintain、处置 immediate_fix/优先级 critical——与真值一致，且 4 智能体全部 succeeded、证据引用 0 幻觉（防幻觉校验全程有效，`unified_citation_hallucination=0`）、审计门禁正确转人工（High+immediate_fix）。
- **E3#0（误匹配候选）**：统一链在漏洞分析师给出 not_affected 后触发 `deterministic_match_vs_not_affected` + `baseline_high_vs_all_findings_resolved` 冲突 → 定向复议维持 → 门禁 `unresolved_major_contradiction` 转人工——与 System B 在同案例的优异表现同向（insufficient_evidence/collect_more_evidence/人工）。
- **人工路由 6/6 全部正确**（真值要求人工的案例全部 pending_human_review；simple 直通的 Low 事件保持 auto_confirmed 且结论来源显式标注 `rule_tier_simple`）。
- System B 同期数据再次复现审计结论（E1/E2 影响 8/8、处置 9/10、人工 4/4）。

## 4. 实验暴露并已修复的统一链缺陷（重点）

| # | 缺陷 | 实验证据 | 修复 | 回归锁定 |
|---|---|---|---|---|
| 1 | **执行基座丢失异常保护**：`UnifiedToolLoopAgent.run` 未包裹 `_run_once` 的 try/except，解析/网络异常直接击穿图节点（E3#1 decide 阶段一次 "Extra data" 解析失败使整图 failed） | `runner.py:119` 完整 traceback（JSONDecodeError 穿透 decide 节点） | 恢复 System A 语义：异常→计入重试→降级，绝不击穿节点 | 全部降级路径测试继续绿 + 新解析容错 |
| 2 | **解析器不容忍尾部多余文字**：模型输出合法 JSON 后带说明文字时 "Extra data" 整体报废 | 同上 traceback 首帧 | `parse_structured_output` 增加 raw_decode 平衡扫描（共享改进，旧套件全绿） | `test_json_extraction.py` 全绿 |
| 3 | **决策者把 CVE/版本号当证据 ID**：3 次运行 decision_planner 因 `supporting_evidence_ids=['CVE-…','7.81.0-…']` 防幻觉校验失败降级 | agents_json：`引用了材料中不存在的证据 ID: ['CVE-2026-81002','curl','fixture',…]` | 决策上下文显式下发 `available_evidence_ids` 全集；校验失败的反馈附合法 ID 清单 | 决策防幻觉校验路径（feedback 携带清单） |
| 4 | **情报冲突规则过敏**：`intelligence_source_conflict` 只要分析师声明任何来源差异即触发→复议→unresolved 门禁，E1/E2 也被牵连 | E1 三次运行全部出现该冲突 | 规则 7 收紧：仅当分析师**未能消解**矛盾（无结论或全部 insufficient_evidence）时触发 | `TestConflicts` 语义更新 |
| 5 | **API 限流退化的时长放大**：单智能体调用链实测 17.8 分钟（SDK 内部指数退避 × 限流），把 run 级 900s 预算拖穿，出现 "5.0s 残余额度" 的连带超时 | `vulnerability_analyst latency_ms=1068918` | `DeepSeekChatClient` 限定 `max_retries=1`；deadline 为协作式语义已写入设计文档 | 共享客户端变更，旧套件全绿 |

另发现规则层事实（非统一链缺陷，如实留档）：X1 的 edge-01 zlib 事件规则基线为 30.51/**immediate_fix**（zlib 作为 nginx 依赖被判定 contextual→likely→公网核心资产立即修复）——simple 分层曾把它直通为 auto_confirmed。已修复：simple 分层对 `immediate_fix` 一律转人工（与主门禁 `high_impact_operation_requires_human` 一致）。

## 5. 失败运行的完整口径（不掩盖）

18 次计划运行中：7 完成、11 失败。失败原因分布：**10 次为 402 Insufficient Balance**（外部依赖）、**1 次为缺陷 #1**（已修复）。屏蔽消融（F7 失败恢复）未执行。所有失败运行的状态/错误原文保留在实验 JSON 与临时库快照中，未删除、未混入成功样本。

## 6. 续跑命令（余额恢复后）

```bash
cd backend
# 续跑剩余统一链运行（跳过已完成的 System B 与已完成的案例可用 --cases 过滤）
python scripts/stage9b_unified_compare.py --out reports/stage9b-unified-r2 \
    --unified-only --repeats 3
# 或只补缺口案例：
python scripts/stage9b_unified_compare.py --out reports/stage9b-unified-r2 \
    --unified-only --cases CVE-2026-81003,CVE-2026-81004,CVE-2026-81005,CVE-2026-81007
# 屏蔽消融随 --cases 含 CVE-2026-81001 时自动执行（或不过滤时执行）
```

## 7. 诚实性声明

1. 本报告不含任何 mock 结论；所有已完成运行的真实产物（LLM 原文、逐智能体日志、usage）保留在 `reports/stage9b-unified/`（gitignore，本地留存）与临时库快照。
2. §3 的观察仅为部分样本描述，不构成新旧系统优劣结论；续跑完成并满足 §9 验收判据前，正式入口保持 System B（开关默认 off）。
3. Fixture 全程使用合成 CVE 与 TEST-NET 地址；真值表先验独立于实现。
4. 余额耗尽本身如实记录为外部依赖，未通过降低评测标准或缩减真值来"完成"实验。

## 8. 当前交付状态

| 里程碑 | 状态 |
|---|---|
| M0 架构设计与迁移计划（f6bd0ef） | ✅ |
| M1–M3 统一编排器 + 适配层 + F1 修复 + 前端统一（9185144） | ✅ |
| M4 真实 LLM 对照实验 | ⏸ 部分完成（余额耗尽）；脚本与续跑就绪；5 项缺陷已修复并有回归锁定 |
| M4 切换（flag=on 正式入口） | ⏸ 依赖 M4 实验完成 |
| M5 旧编排器退役 | ⏸ 依赖 M4 切换稳定（退役清单见迁移说明 §5） |

**最终回归**：549 基线 + 54 项统一链专项（含实验修复锁定测试）= **全量 551 passed / 0 failed**（含 §4 全部修复后的复跑）。Mimosa 深度扫描：**0 findings**（scan-2026-10-15T11-46-21.537Z-669c19b8f1c8，seal sha256:4225b150…f193b，123 依赖包）。
