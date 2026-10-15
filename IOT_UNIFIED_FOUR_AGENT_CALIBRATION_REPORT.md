# IoTGuard 统一四智能体研判校准与成本治理报告（Stage 9B M4.1）

> 生成：2026-10-15。正式依据：`IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md`（M4 验收，结论"未达切换门槛"）、
> `IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md`、`IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md`。
> 本轮 = 针对性整改（统计口径修正 / 五类决策缺陷修复 / Evidence Preparation / 稳定性治理 / 分阶段验收）。
> 离线核查脚本（零 LLM）：`backend/scripts/stage9b_calibration_stats.py`；真实 LLM 复测脚本：
> `backend/scripts/stage9b_unified_compare.py`（沿用原 Fixture / 真值表 / 计量，真值先验未动）。
> 原始产物（LLM 原文/逐智能体日志/真实 usage/归档）本地留存于 `backend/reports/`（gitignore），不入库。

---

## 0. 结论（TL;DR）

1. **统计口径修正完成（第一部分，零 LLM）**：M4 的 20 次运行重建为严格五类口径——
   全链 LLM 14 / 程序兜底 3（**E3a×2+E3b×1，验收报告误记为"E3a 三次"**）/ 屏蔽消融 1 / simple 直通 2。
   不得混合计算的口径分离后：M4 的 LLM-only 影响判定为 **12/14（85.7%）**（混合口径 88.2%）、
   处置 **8/14（57.1%）**（混合口径 64.7%）——旧报告把 3 次程序兜底混入了 LLM 准确率。
   旧 System B 耗时口径澄清：**7.6s/事件是 76.0s/10 事件的全量运行口径**，104.1s/11 事件的合并口径应为
   **9.46s/事件**；调用数 258 为 runner 计量表口径（237 评审 + 21 消融），客户端计数口径为 246。
2. **五类决策缺陷按通用安全语义修复（第二部分，无任何 case_id/合成 CVE 硬编码）**，
   全部以「确定性事实 + 程序校验 + fail-closed 门禁」三层实现，并新增 35 项回归锁定。
3. **Evidence Preparation 确定性节点落地（第三部分）**：LangGraph 单图新增 `prepare_evidence`
   程序节点（非第五个 Agent，无 LLM），复用既有只读工具/多源情报包/SecurityEvidence 结构，
   运行内只读复用、新鲜度按当前时间重算。逐 Agent 前后对照见 §5。
4. **真实 LLM 复测（第五部分 B-D）**：固定 Fixture/真值表，统一链 **20 次矩阵运行 + 2 次 E4 缺陷修复补充运行
   全部 completed**（0 失败 / 0 兜底 / 0 预算触界）；旧 System B 沿用已核查代码条件的留档结果（零新增支出）。
   **质量与稳定性显著改善：影响判定（配对）9/9 vs 旧 7/7 持平满分；X2「已修复」语义完美生效；
   X3 回到真值；E5 处置 3/3 一致收敛；E4 冲突约束修复后 5/5 全对。处置建议（配对）8/9 vs 旧 8/8，
   仍差 1 例（E2）。**
5. **成本未达"实质改善"门槛**：按全链评审运行为分母 **-4.8%**（93.0k→88.5k tokens/全链运行），
   按评审运行分母 +15.6%；墙钟 **-7.8%**；资产调查员工具调用 -15.6%、专家延迟 -17%~-27%，
   但漏洞/运行时分析员工具调用反增、决策输出变长——成本门槛如实判 ✗。
6. **维持 `LINUXGUARD_UNIFIED_PIPELINE=off`**，不切换正式入口、不删除旧编排器、不绕过 Harness（§9）。
7. 本轮实验再次暴露并修复 **1 项真实缺陷**（E4 厂商冲突漏检：release 作用域 value 为单记录形态），
   带回归锁定；受影响案例已用修复后版本真实复测。全量回归 **589 passed / 0 failed**。

---

## 1. 实验统计口径修正（第一部分）

核查对象：`reports/stage9b-unified-final/`（M4 最终验收）全部 20 次运行的
run JSON（case_id / 代码版本 / 状态 / 耗时 / 真实用量 / 真值评分逐条核对）+
`acceptance_data.json` + 上一轮 `stage9b-unified/` 原始 JSON。核查过程零付费调用；
原始存档与真值标签未做任何改动，修正只作用于汇总。

### 1.1 五类口径分类（M4 全部 20 次运行）

| 类别 | 次数 | 运行 |
|---|---|---|
| 全链四智能体（LLM 评审） | 14 | E1×3、E2、E3a×1、E3b×2、E4a、E4b、E5×3、X2、X3 |
| 独立重复实验 | —（与上行重叠） | E1×3、E3a×3、E3b×3、E5×3 中非首次者 |
| API 连接失败→程序兜底 | 3 | **E3a×2（risk#3 #0/#2）+ E3b×1（risk#5 #0）**；判定全部落真值内 |
| 单智能体屏蔽消融 | 1 | uni-mask-runtime-e1（F7 验证） |
| simple 直通（0 次 LLM） | 2 | X1 两事件（risk#8/#9） |

**纠正**：M4 验收报告 §2.1 将 3 次兜底记为"E3a 三次"；逐运行 `degraded_roles` 核查实为
**E3a×2 + E3b×1**。兜底裁定的 impact 全部为 insufficient_evidence，按 E3 真值
{not_affected, insufficient_evidence} 判"落在真值内"成立——但这是 **fail-safe 程序语义**，
不是 LLM 研判质量。

### 1.2 混合口径 vs LLM-only 口径（M4 数据重算）

| 指标 | 混合口径（原报告，17 次评审运行） | **LLM-only（14 次全链）** | 差异来源 |
|---|---|---|---|
| 影响判定 | 15/17（88.2%） | **12/14（85.7%）** | 3 次兜底判 insufficient_evidence 落真值，抬高了混合口径 |
| 风险方向 | 13/17（76.5%） | **10/14（71.4%）** | 同上 |
| 处置建议 | 11/17（64.7%） | **8/14（57.1%）** | 3 次兜底 action=collect_more_evidence 全部在允许集 |
| 人工路由 | 6/6（100%） | 6/6（100%） | 无差异 |

结论：M4 报告的质量数字系统性偏乐观约 3~7 个百分点；本报告后续所有统一链准确率一律使用
LLM-only 口径（M4.1 运行无兜底，两类口径自然重合）。

### 1.3 成本分母与耗时口径统一

| 项 | 口径 A（原报告混用） | 口径 B（修正） |
|---|---|---|
| 统一链调用数 | 258 次/20 运行 | **meter 口径 258 = 237 评审 + 21 消融**（runner 级预算计量，含 F3 反馈重试占位）；客户端计数口径 246（237+9）。两个口径均如实呈现，来源：逐运行 `usage`（meter）与 `usage_delta_vs_counter`（client） |
| 统一链 Token | 1,357,234（含消融 55,270） | 核对无误：1,301,964（19 次评审运行）+ 55,270（消融） |
| System B 耗时 | "104.1s/11 事件（≈7.6s/事件）" | **7.6s = 76.0s/10 事件（上一轮全量运行口径）**；104.1s = 76.0+28.1（X2 补充，冷启动单事件），合并口径 9.46s/事件。两组运行条件不同，分母不得混用；配对比较使用全量运行口径 |
| System B Token/事件 | ≈24.1k | 全量口径 24,211（242,108/10）；合并口径 24,114（265,250/11）——两者接近，配对比较使用全量口径 |
| 统一链 Token/运行 | "≈76.6k" | 1,301,964/17 次耗用运行 = 76.6k ✓（其中含 3 次兜底运行；纯全链口径 93.0k/14） |

### 1.4 严格配对对照表（M4 数据，同案例首次成功 LLM 评审 vs System B）

由 `stage9b_calibration_stats.py` 重建（逐事件取首次 impact 正确的全链 LLM 运行；
X1 两事件为 simple 直通，不进入 LLM 配对）：

| 案例 | System B（留档） | 统一链 M4（首次成功 LLM） | 真值命中对比 |
|---|---|---|---|
| E1 | confirmed/immediate/upgrade_minor | confirmed/immediate/upgrade_major | 双方全对 |
| E2 | confirmed/scheduled/upgrade_minor | confirmed/scheduled/upgrade_minor | 双方 impact/处置对，方向均超集 |
| E3a | insufficient/collect/maintain | not_affected/monitor/downgrade_major | 双方在真值内 |
| E3b | insufficient/collect/maintain | potentially/scheduled/maintain | **统一链接受误匹配（✗）**，旧系统保守正确 |
| E4a/E4b | potentially/collect(maintain) | confirmed/scheduled+immediate | 双方 impact 在真值；处置均超集 |
| E5 | confirmed/scheduled | confirmed/immediate | 双方 impact 对；统一链处置超集 |
| X2 | insufficient/collect | insufficient/scheduled | 双方未因 KEV 虚判（核心验收达标） |
| X3 | confirmed/scheduled | insufficient/scheduled | 统一链 impact 偏保守（✗） |

---

## 2. 五类核心决策缺陷的根因与修复（第二部分）

全部修复为**通用安全语义规则**（以结构化事实的存在形态触发，不存在任何
case_id / CVE 编号 / 主机名的条件分支），三层防线：①确定性事实进上下文；
②决策输出程序校验（不合规→带语义反馈重试一次）；③审计门禁 fail-closed
（重试后仍矛盾→强制人工，绝不自动采纳任一侧）。

### 2.1 E3（NVD-only 误匹配候选被接受）
- **根因**：分支排除声明只存在于公告文本，未被结构化；模型在最稀薄实例上凭通用候选匹配翻案。
- **修复**：`evidence_prep.check_branch_applicability()`——从多源情报包文本中**确定性提取**
  「不受影响分支声明」（`not affected/unaffected/...` + 与装机分支前缀匹配的版本记号）与
  「受影响区间声明」（`X before Y` + affected 语义），与装机版本做确定性比对，产出
  `branch_check: branch_excluded / in_stated_affected_range / undetermined` 进漏洞分析师与决策上下文。
  决策校验：`branch_excluded` 时 impact=confirmed_affected → 语义反馈重试；门禁新增
  `branch_exclusion_contradiction`（fail-closed）。
- **实测**：E3 六跑 branch_check 全部=branch_excluded；5/6 落真值（E3b 三跑全部识破，**此前接受误匹配的
  实例本轮三跑全部正确**）；唯一失败为 E3a#1（potentially_affected+scheduled_fix，门禁强制人工）。

### 2.2 E4（未消解的厂商公告冲突被"装机+KEV"压过）
- **根因**：「确认组件已安装」与「确认 CVE 适用」混同；厂商 under_investigation 冲突未主导处置。
- **修复**：`evidence_prep.detect_vendor_conflict()` 结构化预检（厂商调查中 vs 其他源 affected →
  `vendor_conflict.unresolved`）。决策校验：冲突未消解时 impact=confirmed_affected 与
  scheduled_fix/immediate_fix 均禁止（只允许 monitor/collect_more_evidence/mitigate/defer）；
  门禁新增 `vendor_conflict_unresolved_disposal`。
- **实测**：首轮矩阵中该约束**未触发**（见 §7 缺陷）；修复后 E4a/E4b 补充复测
  **两跑完全一致：potentially_affected + mitigate + 人工 + 引用干净，5/5 真值全中**
  （M4 时为 scheduled_fix/immediate_fix 超集）。"组件已安装≠CVE 适用已确认"语义落地。

### 2.3 E5（过期运行时证据与处置紧迫度混同）
- **根因**：适用性、运行时证据有效性、处置紧迫度三类判断共用字段，stale 信号与静态证据互相污染。
- **修复**：`VerdictItem` 新增 `runtime_evidence_validity`（fresh_verified/stale_verified/unavailable/
  not_observed）与 `urgency_basis`（fresh_runtime_evidence/static_evidence_only/no_urgency_evidence）
  两个独立字段。校验：`immediate_fix` 必须显式声明 urgency_basis；宣称 fresh 但证据不新鲜 → 反馈重试；
  **静态证据独立支撑的紧急建议不被一刀切禁止**，但必须显式声明 `static_evidence_only` 并说明依据，
  门禁加 `static_evidence_urgency_requires_human` 强制人工。运行时证据新鲜时缺省由程序归一为
  fresh_runtime_evidence（不替模型做裁量）。门禁另新增 `urgency_claim_without_fresh_runtime`、
  `urgency_basis_undeclared`。
- **实测**：E5 三跑处置全部 scheduled_fix（**与上轮 immediate_fix×2 超集相比方差收敛且全部落真值**）；
  E4 补充复测的 static_evidence_only 路径正确走人工。

### 2.4 X2（确定性已修复判定被模型误解版本顺序推翻）
- **根因**：装机 2.9.13-2ubuntu0.4 ≥ 修复 2.9.13-2ubuntu0.3（正常已修复形态）被模型判为"语义反常"。
- **修复**：预取包逐候选携带确定性 `version_compare`（复用 `is_version_less`）。决策校验：
  `version_compare=fixed` 时 impact=confirmed/potentially → 反馈重试（"KEV 收录/厂商历史受影响状态
  不改变已修复事实"）；门禁新增 `deterministic_fixed_overridden`。
- **实测**：X2 本轮 **not_affected + monitor + 不升级方向，全部落真值且无超集**
  （M4 为 insufficient_evidence + scheduled_fix 超集）。核心验收（不因 KEV 虚判）两轮均保持。

### 2.5 X3（运行时证据过期被推导为适用性不足）
- **根因**：applicability 与 runtime_status 混同——静态版本证据确定适用时，规划师仍因"证据过期"拒绝研判。
- **修复**：决策校验：impact=insufficient_evidence 且 version_compare=affected 且 freshness=stale →
  反馈重试（要求区分 applicability/runtime_status/exploitation/urgency 四个字段）；
  门禁新增 `applicability_conflated_with_stale_runtime`。
- **实测**：X3 本轮 **potentially_affected + scheduled_fix + stale_verified 门禁 + 人工，全部落真值**
  （M4 为 insufficient_evidence + downgrade_major 双超集）。

### 2.6 防回归

以上全部约束共 35 项新测试锁定（`tests/test_evidence_prep.py`）：声明提取/分支前缀语义/
冲突判定（含 release 作用域单记录回归）/预取包构建/节点失败降级/上下文携带/六类决策约束的
反馈重试/门禁矛盾理由/程序兜底显式标记。真值表、Fixture、评分语义均未改动。

---

## 3. Evidence Preparation 设计与调用链（第三部分）

### 3.1 定位与调用链

```
START → prepare → [prepare_evidence（新，确定性，无 LLM）] → investigate_asset
      → {analyze_vulnerability ∥ analyze_runtime} → detect_conflicts
      → [directed_rereview?] → decide → [execute_follow_ups?] → finalize → END
```

- **不是第五个 Agent**：无 LLM、无裁量、无独立输出 Schema 参与研判；它只做
  「可一次性完成的确定性事实查询前置」，结果以 `EvidencePrepPacket` 存入 state
  供四个专业 Agent 与决策规划师引用；全部专属工具保留，有界补查与定向复议能力不变，
  未取消任何安全复核。
- **复用**：`agents/tools.py` 只读工具（画像/暴露面/数据质量）、`get_source_bundle`
  多源情报包（含操作员登记 OpenWrt 公告）、`is_version_less` 版本比较、SecurityEvidence
  证据清单——零新增情报能力。
- **有界**：组件≤60、证据 ID≤30、源记录≤12、候选≤60；超限记截断标记。
- **缓存语义**：本次运行内只读复用（state 作用域）；**运行时新鲜度在节点内按当前时间重算**
  （sensor 心跳/证据时间分桶不复用任何陈旧结论）；每条事实带 `as_of` 与来源。
- **失败语义**：预取失败 → 置空 + stage=failed + 退回各角色自主工具查询（预取是优化不是安全依赖），
  有回归测试锁定。

### 3.2 分发给四个角色的切片

| 消费者 | 收到的预取切片 | 保留的深查工具 |
|---|---|---|
| asset_investigator | 画像/服务暴露面/组件清单/运行时数据质量 | 全部 4 个（缺口/歧义时） |
| vulnerability_analyst | version_compare/branch_check/vendor_conflict/情报摘要/有界源状态包 | 全部 4 个（复核/深查时） |
| runtime_analyst | 覆盖/心跳/新鲜度（按当前时间重算）/证据 ID 清单 | 全部 5 个（行为证据深查必须） |
| decision_planner | `deterministic_facts`（上述事实的约束视图）+ 分离字段语义要求 | 无（综合者定位不变） |

---

## 4. 真实 LLM 复测：运行构成与条件（第五部分 B）

- **代码版本**：本轮整改代码（含 §2/§3/§7 全部修复）；E4 两跑使用 §7 缺陷修复后的最终代码，其余 18 轮
  矩阵运行使用其前一版本（差异仅 §7 的冲突检测单记录形态——该缺陷只影响 E4 约束触发，
  对其余案例无行为差异，逐运行 `vendor_conflict_unresolved` 字段可核）。
- **Fixture/真值表/评分脚本**：与 M4 完全相同的固定版本（`stage9_agent_effectiveness_audit.py`
  的 E1-E5 + `stage9b_unified_compare.py` 的 X1/X2/X3；真值先验零改动）。
- **模型**：deepseek-v4-flash，temperature=0.1（与生产及 M4 一致）；实验前最小连通性验证通过。
- **运行构成（22 次真实 LLM 运行，全部 completed）**：

| 类别 | 次数 | 明细 |
|---|---|---|
| 全链四智能体（LLM 评审） | 17 | E1×3、E2、E3a×3、E3b×3、E4a、E4b、E5×3、X2、X3 |
| 缺陷修复补充运行（E4，最终代码） | 2 | E4a、E4b（替换矩阵中约束未触发的同案例结果） |
| simple 直通（0 次 LLM） | 2 | X1 两事件（edge-04 monitor→auto_confirmed；edge-01 immediate_fix→强制人工，行为与 M4 一致） |
| 屏蔽消融 | 1 | E1 屏蔽 runtime_analyst：降级留痕+三角色结论保留+门禁人工（F7 三项期望全中） |
| 程序兜底 | **0** | M4 为 3 次（API 连接错误）；本轮退避重试下零外部故障、零兜底 |

- **预算**：`--max-total-tokens 1500000` 未触界；断点续跑/去重机制在位（本轮未触发续跑）。
- 旧 System B 对照：**零新增调用**，沿用 M4 核查过的留档（10 事件全量 + X2 补充，代码条件
  `event_review_pipeline.py` 自 d14f354 未变）。

---

## 5. 修改前后逐 Agent 成本对照（第三部分交付）

统一链 19 次评审运行（矩阵，不含消融）逐 Agent 汇总（真实 usage 计量；修改前的运行未记录
逐 Agent token，如实标 unavailable）：

| Agent | 工具调用 前→后 | 延迟合计 前→后 | LLM 调用 后（前） | Token 后（前） |
|---|---|---|---|---|
| asset_investigator | 90 → **76（-15.6%）** | 276.6s → **208.9s（-24.5%）** | 39（unavailable） | 146,006（unavailable） |
| vulnerability_analyst | 72 → 81（+12.5%） | 407.2s → **298.3s（-26.7%）** | 38（unavailable） | 190,694（unavailable） |
| runtime_analyst | 77 → 93（+20.8%） | 285.8s → **236.3s（-17.3%）** | 35（unavailable） | 149,236（unavailable） |
| decision_planner | 0 → 0 | 877.2s → 908.5s（+3.6%） | 21（unavailable） | 353,606（unavailable） |

运行级（19 次评审运行；M4 含 3 次兜底运行，M4.1 含 17 次全链 + 2 次 simple）：

| 指标 | M4（修改前） | M4.1（修改后） | 变化 |
|---|---|---|---|
| Token/耗用评审运行 | 76.6k（1,301,964/17） | 88.5k（1,505,184/17） | **+15.6%** |
| Token/全链评审运行 | 93.0k（1,301,964/14） | 88.5k（1,505,184/17） | **-4.8%** |
| LLM 调用/评审运行 | 12.5（meter 237/19） | 12.6（240/19） | 持平 |
| 墙钟/评审运行 | 173.8s（3,303.1/19） | **160.3s（3,045.7/19）** | **-7.8%** |
| 本轮真实总支出 | — | 矩阵 1,505,184 + E4 补充 144,966 + 消融 59,037 = **1,709,187 tokens**（含缺陷修复复测成本） | — |

**如实结论**：成本门槛（"实质改善"）**未达到**。预取包降低了资产调查员的重复查询（工具数 -16%）
与全部专家的墙钟（-17%~-27%），但 ①预取上下文本身增加 prompt token；②漏洞/运行时分析员对预取事实
做了**更多**主动复核（工具数 +12%/+21%——质量正向、成本负向）；③决策规划师在约束语义下产出更长的
论证（completion 显著变长）。按"每产出一个完整全链决策"的口径成本 -4.8%，属于改善但非"实质改善"。
后续降本方向见 §9。

---

## 6. 严格配对比较（第五部分 C/D）

配对口径：逐案例取统一链**首次成功（impact 正确）的全链 LLM 评审** vs System B 同案例留档结果；
X1（simple 直通，0 次 LLM）不进入 LLM 配对；E4 采用缺陷修复后的补充运行（最终代码态）。

### 6.1 案例级配对表（最终代码态）

| 案例 | 统一链 M4.1 | System B（留档） | 真值命中 |
|---|---|---|---|
| E1 | confirmed_affected + immediate_fix + 人工（×3 重复 impact/action/人工完全一致；#0 方向 upgrade_major✓，#1/#2 maintain 超集） | confirmed + immediate | impact/处置/人工 双方全对 |
| E2 | confirmed + immediate_fix（direction/action 超集；见 §6.3） | confirmed + scheduled | impact 对；统一链处置超集（**退化点**） |
| E3a | not_affected+monitor ✓ / potentially+scheduled ✗ / not_affected+monitor ✓ | insufficient + collect | 2/3（M4 LLM-only 为 1/1——本轮恢复独立重复暴露方差） |
| E3b | insufficient+collect ✓ / monitor ✓ / not_affected+monitor ✓（三跑全部识破误匹配） | insufficient + collect | **3/3（M4 同实例 1/2，曾接受误匹配）** |
| E4a/E4b | potentially_affected + mitigate + 人工 ×2（完全一致） | potentially + collect | **5/5 全对（M4 为 confirmed+scheduled/immediate 超集）** |
| E5 | potentially/confirmed/potentially + scheduled_fix×3 + 人工 ×3 | confirmed + scheduled | impact 3/3、**处置 3/3 全对且零方差**（M4 处置 immediate×2 超集） |
| X2 | **not_affected + monitor + 不升级**（无超集） | insufficient + collect | 完美（M4 为 insufficient+scheduled 超集） |
| X3 | potentially_affected + scheduled_fix + stale 门禁 + 人工 | confirmed + scheduled | **全对（M4 为 insufficient+downgrade_major 双超集）** |

### 6.2 汇总率（LLM-only 口径）

| 指标 | 统一链 M4.1（矩阵 17 跑） | 统一链 M4.1（E4=补充运行） | 统一链 M4（LLM-only 修正口径） | System B | 门禁要求 |
|---|---|---|---|---|---|
| 影响判定 | 16/17（94.1%） | 16/17（94.1%） | 12/14（85.7%） | 7/7（100%） | 不劣于旧系统 |
| 处置建议 | 13/17（76.5%） | **15/17（88.2%）** | 8/14（57.1%） | 8/8（100%） | 不劣于旧系统 |
| 风险方向 | 11/17（64.7%） | 11/17（64.7%） | 10/14（71.4%） | 6/8（75%） | —（保守方向为主） |
| 人工路由 | 6/6（100%） | 6/6（100%） | 6/6 | 3/3（100%） | 保持 |
| 引用幻觉 | 0 真实（2 例评分器假阳性，§6.4） | 0 | 0/20 | 不可比（无逐条校验器） | 0 |
| 无依据升级 | 0（E1 upgrade_major 有 KEV+新鲜运行时证据） | 0 | 0 | 0 | 0 |

配对视图（9 个 LLM 案例）：统一链 impact **9/9** vs System B 7/7；action **8/9** vs 8/8；
direction 7/9 vs 6/8；human 4/4 vs 3/3。

### 6.3 退化点（不掩盖）

1. **E2（唯一处置配对失败案例）**：High 客户端包（curl）、无运行时证据。模型在
   `urgency_basis=static_evidence_only` 路径下选了 immediate_fix（静态证据：厂商 affected + CVSS 8.1 +
   装机受影响），超出真值允许集 {scheduled_fix, monitor}。该路径是 §2.3 设计使然
   （不一刀切禁止静态紧迫性），但**在无 KEV、无暴露面公网证据的组合上应更保守**——
   遗留整改项：为 static_evidence_only 增加"KEV/公网暴露等urgency 放大因子存在"的确定性前提校验。
   人工门禁保持（evidence_partial + 高优先级理由），无越权。
2. **E1 方向**（×2 maintain，真值要求 upgrade）：基线已 100/Critical，模型明示"评分上限附近不宜再上调"
   ——保守方向偏差，人工路由保持，无安全影响；记方差不记退化。
3. **E5 方向**（×3 downgrade_minor 超集）：F6 新鲜度语义下模型对"证据过期"的保守下修；
   影响判定与处置均正确。评分口径本身偏宽（M4 已如实标注）。
4. **E3a#1**（potentially+scheduled）：低证据实例的单次方差依旧存在（branch_excluded 事实在包内但模型
   未遵从）；门禁强制人工，无越权。E3b 同类实例三跑全部正确。

### 6.4 引用完整性

矩阵 2 例 citation 标记（E2、消融）经逐条核查均为**评分器假阳性**：模型引用的 SE-* 为
预取证据清单中的真实 ID（图内防幻觉校验实时放行；离线评分器此前未读 `evidence_prep.runtime_facts.evidence_ids`，
已对齐）。**真实引用幻觉 0/20**。评分器已修复（运行记录新增 `runtime_evidence_ids` 字段），
原始存档未改动。

---

## 7. 稳定性治理与失败恢复（第四部分）

| 检查项 | 状态 | 证据 |
|---|---|---|
| E3 低证据条件下的判断波动 | **改善未消除**：E3b（无背景事件实例）3/3 识破（M4 曾 1/2 接受误匹配）；E3a 3 跑中 1 跑偏离 | branch_excluded 确定性事实在包内；残余方差记入遗留项 |
| API 连接错误的重试与限流 | 改善：异常重试间新增 1s 固定退避；OpenAI 客户端 max_retries=1 + Agent 级 llm_retries=1 + run 级预算与时限不变 | 本轮 0 次 API 故障/0 兜底（M4 为 3 次故障 3 兜底）；外部网络条件亦有差异，如实标注 |
| LangGraph 并行节点错误合并 | 保持（M4 已修复） | state.error/degraded_roles/stage_status 三键 Annotated reducer 在位性测试 |
| 部分 Agent 降级 | 保持（F7） | 消融运行：runtime 降级留痕、其余三角色结论保留、门禁强制人工，期望三项全中 |
| 决策输出完整性 | 保持 + 增强 | 空 verdicts 完备性反馈重试（M4 修复）+ 本轮语义约束校验共用同一 combined_validator |
| 统一 run 预算 | 保持 | run 级 40 次调用/150s Agent/900s run 时限全程未触界；逐 Agent 计量新增（llm_calls/llm_usage 入 agents_log） |
| 人工门禁 fail-closed | **增强**：新增 7 类确定性矛盾理由（branch_exclusion_contradiction / deterministic_fixed_overridden / vendor_conflict_unresolved_disposal / urgency_claim_without_fresh_runtime / urgency_basis_undeclared / static_evidence_urgency_requires_human / applicability_conflated_with_stale_runtime） | 与 decide 校验同语义兜底；重试后仍矛盾→强制人工，绝不自动采纳；程序兜底裁定显式 `program_fallback` 标记（统计口径与 LLM 判定分离） |
| 方差治理方式 | 按任务书要求：结构化事实+程序校验+路由，未增加盲目重复推理 | 复议/补查轮数上限未变（各 ≤1）；E5 处置方差收敛至 0 证明路径有效 |

### 本轮实验暴露并修复的缺陷（1 项，回归锁定）

| 缺陷 | 根因 | 修复与复测 |
|---|---|---|
| E4 厂商冲突漏检（`vendor_conflict_unresolved=False`，约束未触发，矩阵中 E4a/E4b 处置超集） | `get_source_bundle` 在 release 作用域下 canonical 的 `value` 是**单条选中记录**而非 `records` 列表；`detect_vendor_conflict` 只读 records 形态 | 兼容两种形态（单记录回退）；新增单记录回归测试；**受影响案例用修复后版本真实复测：E4a/E4b 两跑 5/5 全对且完全一致** |

---

## 8. 完整回归与安全扫描（第五部分 A + 第六部分）

| 项 | 结果 |
|---|---|
| 全量回归 | **589 passed / 0 failed**（554 M4 基线 + 35 项校准专项，零回归；缺陷修复后再跑一次确认） |
| 统一链专项 | test_unified_pipeline(50) + test_unified_adapter + test_json_extraction + test_four_agent_pipeline + **test_evidence_prep(35，新增)** |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-15T17-10-38.086Z-25c64eb52112，seal sha256:edb186b2…529f1b，123 依赖包，focus=本轮全部改动文件） |
| 敏感信息 | 全部改动扫描：无凭据字面量（API Key 仅环境变量引用）；Fixture 全程 TEST-NET/RFC5737；无用户路径 |
| shadow 隔离 | 实验全程 shadow（sink=None）；正式 RiskAssessment/修复授权/设备状态零变化（专项测试锁定）；`LINUXGUARD_UNIFIED_PIPELINE` 保持默认 off |

---

## 9. 是否达到正式切换门槛：**未达到（维持 flag=off）**

| 切换门槛 | M4 实测（修正口径） | **M4.1 实测** | 判定 |
|---|---|---|---|
| 影响判定不劣于旧系统 | 85.7%（LLM-only） | 配对 **9/9 = 100%**（矩阵口径 94.1%） | **✓（首次达标）** |
| 处置建议不劣于旧系统 | 57.1%（LLM-only） | 配对 8/9（88.9%） vs 旧 100%；汇总 88.2% vs 100% | **✗（差 1 例 E2）** |
| 重复结果稳定性 | E3/E5 二至三值分布 | E1 impact/action/human ×3 全一致；E5 处置 ×3 全一致；E3 5/6；无兜底 | **✓（达标）** |
| LLM 成本实质改善 | —（基线） | 全链口径 -4.8%；评审运行口径 +15.6%；墙钟 -7.8% | **✗（改善不实质）** |
| 安全门禁不可绕过 | ✓ | ✓（人工路由 100%、幻觉 0、无依据升级 0、fail-closed 扩展 7 类） | **✓** |
| Harness/旧编排器不动 | ✓ | ✓（shadow 全程、flag=off） | **✓** |

**判定：质量与稳定性已达标或大幅接近，成本与处置各差一步 → 不切换。**
本轮结束后停止，等待下一轮指令。剩余整改清单（按优先级）：

1. **E2/静态紧迫性校准**：`static_evidence_only` 增加确定性放大因子前提（KEV 或公网暴露或预认证），
   否则回退 scheduled_fix——预期直接补齐处置配对差距；
2. **E3a 残余方差**：branch_excluded 与 impact 矛盾时把「维持 potentially 以上」也纳入
   强制人工理由（当前仅禁 confirmed），或按 R8 升级 focused 层；
3. **方向口径**：E1"基线满分不上调"、E5"过期下修"的保守方向偏差，与真值允许集对齐
   （修评分口径或注入方向约束，二者择一，需先约定）；
4. **降本**：预取切片按角色瘦身（决策上下文去重专家报告与 deterministic_facts 的重叠字段）、
   漏洞/运行时分析员对预取事实的复核改为"仅在质疑时"的提示收敛、决策 completion 长度上限引导；
   目标：评审运行口径 token 降至 ≤60k/运行（当前 88.5k）。

## 10. 切换与回滚（不变，重申）

- 切换仍需：上述遗留项整改 → 同 Fixture/真值表复测达标 → **人工确认**后置
  `LINUXGUARD_UNIFIED_PIPELINE=on`（影子观察 ≥1 周语义不变）。
- 回滚：环境变量置回 `off` 即恢复 System B 原路径；统一链产物在独立表，正式字段零迁移；
  旧编排器在 M5 退役审批前始终完整在位。

## 11. 交付物清单（本轮）

| 交付物 | 位置 |
|---|---|
| 统计口径核查与配对统计脚本（离线，零 LLM） | `backend/scripts/stage9b_calibration_stats.py` |
| 确定性证据预取节点 | `backend/app/services/unified/evidence_prep.py` + `graph.py` 接入 |
| 决策语义约束与 fail-closed 门禁扩展 | `graph.py`（decide）/`audit_policy.py`/`schemas.py` |
| 校准专项回归（35 项） | `backend/tests/test_evidence_prep.py` |
| 实验脚本增强（五类分类/逐 Agent 计量/预取留痕/兜底标记/评分器对齐） | `backend/scripts/stage9b_unified_compare.py` |
| 真实 LLM 复测原始产物（本地留存） | `backend/reports/stage9b-unified-calibration{,-supplement}/`（gitignore） |
| 聚合统计（含修正前后对照与配对表） | `backend/reports/stage9b-unified-calibration/calibration_stats.json`（本地留存） |
| 协作文档更新 | `ai_collaboration/` 五份 |

## 12. 诚实性声明

1. 全部 22 次真实 LLM 运行的原始产物（LLM 原文、逐智能体日志、真实 usage、Trace）本地留存；
   真值表与 Fixture 先验零改动；两处评分器对齐（M4 引用全集、本轮预取 ID）均只作用于汇总并如实标注。
2. M4 报告的三处口径错误（兜底归属、7.6s 标注、混合准确率）在本报告 §1 如实修正，未回写原报告。
3. 成本未达标、处置差 1 例、E3a 残余方差均如实计入并给出根因；E4 补充运行与矩阵运行的代码版本
   差异（仅冲突检测单记录形态修复）已显式标注。
4. System B 对照零新增调用，完全复用 M4 已核查代码条件的留档数据。
5. 本报告不预设新系统更优——四项门槛两项 ✓ 两项 ✗，结论为"不切换"，与数据一致。
