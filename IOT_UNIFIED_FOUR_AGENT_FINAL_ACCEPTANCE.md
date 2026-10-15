# IoTGuard 统一四智能体最终验收报告（Stage 9B M4）

> 生成：2026-10-15。实验脚本：`backend/scripts/stage9b_unified_compare.py`（断点续跑/去重/预算上限）＋
> `backend/scripts/stage9b_final_acceptance_report.py`（离线汇总，零 LLM）。
> 原始产物（LLM 原文/逐智能体日志/usage/归档）本地留存于 `backend/reports/`（gitignore），不入库。

---

## 0. 结论（TL;DR）

1. **全部 10 个风险事件（E1/E2/E3a/E3b/E4a/E4b/E5/X1/X2/X3）的统一链真实 LLM 实验已完成**：
   20 次运行（14 次全链四智能体 + 3 次决策降级程序兜底 + 1 次屏蔽消融 + 2 次 simple 直通），
   全部 completed，1,357,234 tokens / 258 次调用 / 58 分钟墙钟。
2. **确定性安全防线 100% 保持**：人工路由 6/6、证据引用幻觉 0/20、无一次无依据风险升级、
   3 次 API 连接错误全部被 fail-safe 兜底且兜底判定全部落在真值内、屏蔽消融验证 F7 部分失败恢复。
3. **质量与成本未达到正式替换旧 System B 的门槛**（§8 逐项）：影响判定 88%（旧 100%）、
   处置适当 65%（旧 91%）、单事件成本 ≈3.2×、单事件墙钟 ≈27×；退化点已逐案例定位根因（§6）。
   **维持 `LINUXGUARD_UNIFIED_PIPELINE=off`**，待 §9 整改项完成后复测。
4. 本轮实验暴露并修复 **5 项真实缺陷**（2 项实验脚手架保真度 + 3 项生产代码，§5），
   全部带回归锁定；全量回归 **554 passed / 0 failed**（551 基线 + 3 新增）；Mimosa 深度扫描 **0 findings**。

---

## 1. 实验使用的准确 Commit 与代码条件

- **基线 Commit**：`fce2f42`（上一轮最新提交），工作区于实验开始时干净、与 origin/main 一致。
- **运行时代码**：`fce2f42` + 本轮 5 项修复（§5，随本报告同一提交入库）。
  修复前/中的运行已全部归档为调试证据，不计入验收（§2.3）。
- **模型**：deepseek-v4-flash，temperature=0.1（与生产 `DeepSeekChatClient` 及上一轮实验完全一致）；
  充值后最小连通性调用验证：真实 usage 67 tokens，无 HTTP 402。
- **对照有效性核查**：`event_review_pipeline.py`（System B）自 `d14f354` 后未再改动，
  上一轮 System B 全量运行（10 事件 / 44 调用 / 242,108 tokens / 76.0s）的代码条件与当前完全一致，
  **保留为对照**；其缺口案例 X2 由本轮以同配置补充运行（4 调用 / 23,142 tokens / 28.1s）。
  Fixture、真值表、评价脚本沿用上一轮固定版本（真值先验未因结果修改）。

## 2. 全部案例的实际运行状态

### 2.1 运行构成（20 次）

| 类别 | 次数 | 说明 |
|---|---|---|
| 全链四智能体（决策规划师成功） | 14 | E1×3、E2、E3×3、E4×2、E5×3、X2、X3 |
| 决策降级→程序兜底 | 3 | E3a 三次：间歇性 API 连接错误（重试 2 次仍失败），兜底判定全部落在真值内 |
| 屏蔽消融（mask runtime_analyst） | 1 | F7 失败恢复验证 |
| simple 直通（0 次 LLM） | 2 | X1 两事件（成本分层） |

### 2.2 案例级结果与真值对照（全链 14 次的口径）

| 案例 | 基线（规则） | 统一链结果（impact/action/人工） | 真值命中 |
|---|---|---|---|
| E1×3 | 100.0 Critical/immediate_fix | confirmed_affected + immediate_fix + upgrade_major + 人工 ×3（三次完全一致） | impact/方向/处置/人工 全对 |
| E2 | 61.05 High/monitor | confirmed_affected + scheduled_fix + 人工（version_impact=affected 经确定性版本工具证实） | impact/处置对；方向 upgrade_minor 超出真值允许集（maintain/downgrade） |
| E3（6 次含 E3a/E3b） | 69.05 High/scheduled_fix ×2 | 5/6 判 insufficient_evidence 或 not_affected + monitor/collect_more（识破 3.1.x/3.0.x 误匹配）；**1 次**（E3b#1）判 potentially_affected+scheduled_fix 接受了误匹配；全部转人工 | impact 5/6、处置 5/6 |
| E4a/E4b | 85.25 Critical/scheduled_fix ×2 | confirmed_affected / potentially_affected + scheduled_fix + 人工 ×2（E4a 经 follow_up 定向补查确认装机后判定） | impact 2/2、人工 2/2；处置 scheduled_fix 超出真值允许集（monitor/collect_more/mitigate） |
| E5×3 | 83.83 Critical/immediate_fix | confirmed×2/potentially×1 + immediate_fix×2/scheduled_fix×1 + 人工 ×3；runtime 明确 stale_verified、规划师明示"运行时支点已过期 72.5h 被削弱" | impact 3/3、freshness 3/3；处置 immediate_fix×2 超出真值允许集 |
| X1×2 | 21.85 Low/monitor | simple 直通：edge-04 monitor→auto_confirmed；edge-01 规则 immediate_fix→强制人工 | 无依据升级 0；immediate_fix 直通强制人工（上轮修复行为保持） |
| X2 | 76.48 High/monitor | insufficient_evidence + scheduled_fix + 人工；**未因 KEV 判 confirmed_affected**；确定性工具给出 version_impact=fixed（装机 0.4 ≥ 修复 0.3），LLM 复议后对"已修复"语义保守化为 insufficient_evidence | 核心验收达标（无 KEV 虚判）；处置超出真值允许集 |
| X3 | 81.4 Critical/scheduled_fix | insufficient_evidence + scheduled_fix + 人工；runtime=stale_verified/stale、门禁 stale_runtime_evidence | 处置/人工/freshness 对；impact 偏保守（真值允许 confirmed/potentially） |
| 消融（E1 屏蔽 runtime） | — | runtime 降级留痕、其余三角色照常产出 confirmed_affected+immediate_fix、门禁强制人工 | F7：部分失败不全丢 ✓ |

### 2.3 归档的调试运行（不计入验收）

| 归档目录 | 内容 | 处置 |
|---|---|---|
| `reports/stage9b-unified-archive-targetref-defect/` | 7 次运行：实验脚手架以 `"fixture"` 充当 target_ref（生产语义为资产 hostname），决策规划师如实判"资产身份未核实"而保守降级 | 脚手架修复后全部重跑 |
| `reports/stage9b-unified-archive-heartbeat-race/` | 3 次运行：传感器心跳 120s 覆盖阈值被 Fixture 一次性写入打破（E1#1 心跳 196s→stale→freshness mixed） | 脚手架修复（每次运行前刷新在线心跳）后全部重跑 |
| `reports/stage9b-unified-archive-network-outage/` | 4 次运行：3 次 API 连接错误致全智能体降级（tokens=0）+ 1 次 error-key 崩溃 | 网络恢复 + state.py 修复后续跑重跑 |

## 3. 新旧系统对照（整改后完整数据）

对照口径：System B = 上一轮全量 10 事件（代码条件已核查一致）+ 本轮 X2 补充 = 11 事件；
统一链 = 本轮 17 次 LLM 评审运行（14 全链 + 3 兜底 + 消融；simple 直通不计 LLM 评审）。

| 指标 | 统一四智能体 | System B（旧） | 差异说明 |
|---|---|---|---|
| 影响判定正确 | **15/17（88.2%）**；全链口径 12/14（85.7%） | **9/9（100%）** | 旧系统占优；新系统偏离 2 例（E3b#1 接受误匹配、X3 偏保守），根因见 §6 |
| 风险方向适当 | 13/17（76.5%）；全链 10/14（71.4%） | 8/11（72.7%） | 大体相当；新系统偏离均为保守方向（stale→downgrade）或 confirmed 下的 minor upgrade，**无一次无依据 upgrade_major**（唯一的 upgrade_major 在 E1，证据充分且真值允许） |
| 处置建议适当 | 11/17（64.7%）；全链 9/14（64.3%） | **10/11（90.9%）** | 旧系统显著占优；新系统在"确认装机+KEV/高危"组合下倾向更激进处置（scheduled_fix/immediate_fix），但全部被人工门禁截住 |
| 人工复核路由 | **6/6（100%）**（真值要求人工的案例全部转人工；E3/E5/X2/X3 的门禁额外兜底） | **4/4（100%）** | 持平 |
| 证据引用幻觉 | **0/20**（修正后评分器，全集与 runner known_evidence_ids 对齐；运行时防幻觉校验全程有效） | 不可比（System B 无逐条引用校验器；审计结论：证据包确定性下发，幻觉面更小） | 如实标注不可比 |
| 无依据断言/确定性矛盾 | 0（E1 upgrade_major 有 KEV+直接运行时证据支撑） | 0 | 持平 |
| LLM 调用 | 258 次 / 20 运行（≈12.9 次/评审运行；simple 直通 0 次） | 48 次 / 11 事件（4.4 次/事件） | 新系统 ≈2.9× 调用 |
| Token | 1,357,234（含消融 55,270） | 265,250（242,108 + 23,142） | 单事件 ≈76.6k vs ≈24.1k（**≈3.2×**） |
| 墙钟 | 3,460s/20 运行（≈3.4 min/评审运行） | 104.1s/11 事件（≈7.6s/事件，X2 补充 28.1s） | 新系统 ≈27× 慢（工具循环多轮 + 并行受 API 限速约束） |
| 失败恢复 | 3 次 API 连接错误→角色降级→程序兜底（判定全部在真值内）+ 门禁转人工；1 次屏蔽消融→F7 降级保留→转人工；预算/超时/异常全程未绕过门禁 | 0 失败（本轮）；无内建降级语义 | 新系统具备旧系统没有的降级保留语义（F7），代价是兜底判定的"质量分"依赖真值宽容度 |
| 断点续跑/去重 | 已实装并在本轮真实使用（4 次归档后续跑重跑，已完成运行去重跳过；Token 硬预算 2.5M 上限） | 脚本同款机制（全量运行一次完成） | — |

## 4. 重复实验结果

| 案例 | 重复口径 | 结果 |
|---|---|---|
| E1 ×3 | 同事件独立重复 | **完全一致**：confirmed_affected + immediate_fix + 人工 ×3，真值全对（67k–83k tokens，无方差） |
| E3 ×6 | **每个事件实例独立重复 3 次**（E3a=edge-02 有良性背景事件、E3b=edge-03 无任何运行时证据），既测运行间方差也测实例间一致性 | impact 三值分布：insufficient_evidence×3 / not_affected×2 / potentially_affected×1；5/6 在真值内。实例差异可见：E3a（有背景事件）3 次全部保守正确；E3b（无背景事件）1 次接受误匹配。方向/处置同趋势 |
| E5 ×3 | 同事件独立重复 | impact 全部在真值内（confirmed×2/potentially×1）；处置 1/3（immediate_fix×2 超集）——方差集中于处置激进度而非影响判定 |
| 屏蔽消融 ×1 | E1 屏蔽 runtime_analyst | 降级留痕、三角色结论保留、门禁强制人工（F7 期望三项全中） |

上一轮 System B 为每事件单次运行，无重复数据可对照——运行间方差是统一链的诚实短板之一（§9 整改项 3）。

## 5. 本轮实验暴露并已修复的缺陷（5 项，全部带回归锁定）

| # | 层面 | 缺陷 | 实验证据 | 修复与锁定 |
|---|---|---|---|---|
| 1 | 实验脚手架 | `target_ref="fixture"` 违背生产语义（adapter 以资产 hostname 为 target_ref）；决策规划师如实判"资产身份未核实"保守降级 | 归档 targetref-defect：E1#1/#2、E2 判 insufficient_evidence，漏洞分析师本输出 confirmed_affected | 脚手架改为 `target_ref=资产 hostname`；归档重跑 |
| 2 | 实验脚手架 | 传感器覆盖 stale 阈值 120s vs Fixture 一次性心跳：连跑中后段运行必然"心跳过期" | 归档 heartbeat-race：E1#1 心跳 196s→stale_verified（设计应为 verified） | 每次运行前刷新"设计在线"传感器心跳（wrt-node 保持过期语义）；归档重跑 |
| 3 | 生产（graph.py） | 决策规划师输出**空 verdicts** 仍通过结构化校验（伪成功），只能靠门禁 `structured_result_incomplete` 兜底 | E1#1（heartbeat-race 归档中）verdicts=[] 但 status=succeeded | decide 节点组合完备性校验：空 verdicts 视为校验失败进 F3 反馈重试，仍失败→程序兜底裁定；2 项新测试（重试成功/持续失败兜底） |
| 4 | 生产（runner.py） | simple 直通路径不落 `routing_json`/`decision_json`（与 LLM 路径字段不对齐，消费方无法从行级字段识别分层） | 首轮 X1 验证运行 tier=None | 对齐落库；测试断言扩展锁定 |
| 5 | 生产（state.py） | `error` 字段被定义两次，普通注解覆盖 Annotated reducer；并行节点（A2∥A3）并发写错误时 LangGraph `InvalidUpdateError` 整图崩溃 | E3a#1 崩溃 traceback + 网络中断窗口复现 | 删除重复定义；新增 reducer 在位性测试 |

另修正实验评分器 1 处：引用完整性全集此前仅对照 runtime 证据集，产生 2 例假阳性
（E1#0 引用情报源名与事件包 EV-ID 均为合法引用）；已对齐 runner `known_evidence_ids` 语义后复评，
**真实引用幻觉为 0**。原始存档 graded 字段未改写，修正仅作用于汇总。

## 6. 退化根因分析（逐案例，不掩盖）

1. **E3b#1 接受误匹配（potentially_affected + scheduled_fix）**：该实例（edge-03）无任何运行时/背景事件，
   漏洞分析师对"纯 NVD 候选"的版本分支核对出现一次未识破；同案例 E3a（有背景事件）三次全部识破，
   E3b 另两次亦识破。根因：LLM 在证据最稀薄实例上的单次方差，非上下文饥饿（版本事实在包内）。
   整改方向见 §9-2。
2. **E4a/E4b 处置 scheduled_fix 超集**：规划师在"确定性版本比较 affected + follow_up 确认装机 + KEV"
   三重证据下选择排期修复；厂商 under_investigation 冲突未主导处置。人工路由保持（2/2）。
   根因：处置校准未给"情报冲突未消解"足够的权重。
3. **E5#0/#1 处置 immediate_fix 超集**：DMZ 网关 + dropbear 预认证 + 厂商精确公告 → 保守安全立场压过
   "运行时证据已过期"的新鲜度信号（freshness 语义本身工作正常：runtime=stale_verified、规划师明示削弱）。
4. **X2 处置 scheduled_fix 超集 + insufficient_evidence 保守化**：确定性工具正确给出 version_impact=fixed，
   LLM 复议后把"修复版本低于装机版本"（正常已修复形态）判为语义反常而保守化。核心验收
   （不因 KEV 虚判受影响）达标；"已修复"语义的置信标定是整改项。
5. **X3 impact 偏保守（insufficient_evidence）**：仅过期证据 + 新鲜传感器场景下，规划师拒绝在无新鲜
   证据时确认/倾向受影响。这是 F6 新鲜度语义的正确副作用，真值允许集偏宽是评分口径问题（如实保留）。
6. **3 次决策降级（E3a）**：间歇性 API 连接错误（外部依赖），重试 2 次仍失败 → 程序兜底 + 人工。
   兜底判定全部在真值内，fail-safe 语义正确；不记为管线质量退化。

## 7. 四智能体实际增量贡献（真实调用/工具/消费链，17 次 LLM 评审运行）

| 智能体 | 实际调用与工具（全部成功） | 输出消费者 | 增量贡献实证 |
|---|---|---|---|
| asset_investigator | 17 运行 / 90 次工具调用 / 100% ok：query_device_profile×29、query_network_surface×28、query_runtime_data_quality×17、list_devices×16 | 漏洞/运行时/决策上下文 | target_ref 修复后资产身份可解析；盘点驱动 data_quality 语义（E1 freshness 判定输入） |
| vulnerability_analyst | 17 运行 / 72 次工具调用 / 100% ok：query_version_impact×18（确定性版本比较）、query_intelligence_sources×19、query_cve_intelligence×17、query_matched_vulnerabilities×18 | 冲突检测器、决策规划师 | E3 识破误匹配（not_affected/0.9 引用分支范围）；E2/X2 version_impact 确定性输出；多源情报包真实消费（canonical/NVD/KEV/EPSS） |
| runtime_analyst | 13 运行 / 77 次工具调用 / 100% ok：process/network/file 证据×16/15/15、process_tree×15、data_quality×16 | 冲突检测器、决策规划师、门禁 | F6 新鲜度语义落地：E1 verified/fresh、E5/X3 stale_verified/stale 并进门禁理由；行为链 findings 引用真实 SE-* ID |
| decision_planner | 17 运行 / 0 次工具调用（综合者定位，正确）；消费三角色结构化输出 + 冲突结果 + 合法证据 ID 清单 | 审计门禁、待审批计划、Trace | follow_up_requests 触发 17 次真实只读补查（34 个结果，14 次确认回灌再决策；E4a 据补查确认装机后改判）；兜底路径 3 次全部保真值 |
| 确定性门禁 | 19 次评审：auto_confirmed 仅 1（X1 edge-04 Low/monitor），18 次转人工；理由直方图：high_or_critical_final_score×15、confidence_below_0.70×14、evidence_partial×8、high_impact_operation_requires_human×6、unresolved_major_conflict×7、agent_degraded×3+1 | 正式链路（flag=on 时）/影子留痕 | LLM 全程无法绕过：预算耗尽/超时/解析失败/屏蔽均落兜底+人工；shadow 模式 sink=None 零触碰正式字段（专项测试锁定）；工具面只读白名单，无写操作可调用 |

## 8. Harness 安全回归与全量验收

| 项 | 结果 |
|---|---|
| 全量回归 | **554 passed / 0 failed**（551 基线 + 3 新增专项；零回归） |
| 统一链专项 | test_unified_pipeline + test_unified_adapter + test_json_extraction 共 61 项全过（含本轮 5 项修复锁定） |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-15T14-43-14.902Z-512f1a628440，seal sha256:448f342c…2394，123 依赖包） |
| 敏感信息检查 | 本轮全部改动扫描：无凭据字面量、无私网地址（Fixture 全程 TEST-NET/RFC5737）、无用户路径；API Key 仅环境变量引用，未打印未入库 |
| shadow 无副作用 | 实验全程 shadow（sink=None）；正式 RiskAssessment/修复授权/设备状态零变化（专项测试 + 影子隔离测试锁定；`LINUXGUARD_UNIFIED_PIPELINE` 保持默认 off） |
| 预算/失败/超时门禁 | run 级 40 次调用预算、Agent 150s/run 900s 时限、异常保护、屏蔽降级——全部路径终点是人工门禁，无绕过（消融与 3 次真实 API 故障实证） |

## 9. 是否达到统一架构正式切换门槛：**未达到**（维持 flag=off）

| 切换门槛（架构 §9） | 实测 | 判定 |
|---|---|---|
| 影响判定不劣于旧系统 | 88% vs 100%（全链 85.7%） | ✗ |
| 处置建议不劣于旧系统 | 64.7% vs 90.9% | ✗ |
| 人工路由/引用完整性/无依据升级 | 全部 100% / 0 幻觉 / 0 次 | ✓ |
| 成本可控 | ≈3.2× token、≈27× 墙钟（simple 分层可挡 2/19 事件，实证有效但占比低） | ✗ |
| 运行间稳定性 | E3/E5 重复呈 2–3 值分布 | ✗ |
| 安全门禁不可绕过 | 全路径实证 ✓ | ✓ |

**安全面全部达标，质量/成本/稳定性三项未达标。** 建议：不切换，按以下整改后再以同一 Fixture/真值表/脚本复测：
1. 处置校准：决策规划师 prompt/规则中加入"情报冲突未消解→不得跳过 collect_more_evidence"与
   "运行时证据 stale→不得 immediate_fix"的确定性处置约束（与门禁同语义，程序可校验）；
2. E3 类纯 NVD 候选的最小证据核对清单（分支范围比对）进决策上下文，压缩单次方差；
3. 方差治理：对 impact 判定引入低置信二次复议（复议预算已有），或按 R8 成本分层把 E3 类候选
   升级 focused 层；
4. "已修复"语义标定（X2）：装机 ≥ 修复版本 → not_affected 的确定性捷径进决策约束；
5. 成本：E1 类富证据候选的工具轮次收敛（当前 12–18 次/事件）与结论缓存复用。

## 10. 切换与回滚方案（待整改复测通过后执行）

- **切换（M4，人工确认后）**：`LINUXGUARD_UNIFIED_PIPELINE=on` → `/api/analysis` 经兼容适配层
  （`adapter.py`）以既有契约写正式链路（审计门禁→RiskAssessment）；影子模式先行观察 ≥1 周
  （`shadow` 模式下逐字段快照对比已有测试锁定）。
- **回滚**：环境变量置回 `off` 即恢复 System B 原路径——统一链全部产物在独立表
  （UnifiedAnalysisRun/Trace），正式字段零迁移、零残留；旧编排器代码在 M5 退役前始终完整在位。
- **退役（M5，独立审批）**：切换稳定后按迁移说明 §5 清单摘除 event_review_pipeline，
  历史数据只读保留。

## 11. 诚实性声明

1. 全部 20 次验收运行的真实产物（LLM 原文、逐智能体日志、真实 usage、Trace）本地留存；
   3 次归档目录中的失败/缺陷运行**未删除、未混入**验收样本。
2. 真值表先验未因结果修改；E3b#1、E4/E5 处置、X3 impact 的"失败"如实计入并给出根因。
3. 3 次 API 连接错误为外部依赖，其兜底运行如实标注为"程序兜底"口径，不冒充 LLM 决策质量。
4. 上一轮 System B 全量对照经代码版本核查后保留；修复前的统一链运行仅作调试证据。
5. 本报告不预设新系统更优——结论（未达切换门槛）即当前数据下的诚实判断。
