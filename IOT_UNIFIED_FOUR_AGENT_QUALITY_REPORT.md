# IoTGuard 统一四智能体安全研判能力深化质量报告（Stage 9B M4.2）

> 生成：2026-10-16。正式依据：`IOT_UNIFIED_FOUR_AGENT_CALIBRATION_REPORT.md`（M4.1）、
> `IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md`（M4）、`IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md`。
> 本轮 = 研判质量/专业推理/协作价值/泛化能力深化专项（Token 成本降为次要任务，
> 取消 ≤60k 硬指标；不新增 Agent、不改 LangGraph、维持 `LINUXGUARD_UNIFIED_PIPELINE=off`）。
> 实现与先验真值表提交：**`42fe3b1`（先于任何实验数据入库——真值先验可核验）**。
> 实验脚本：`backend/scripts/stage9b_quality_experiment.py`（断点续跑/去重/Token 硬预算）；
> Y 案例集与真值：`backend/scripts/stage9b_quality_cases.py`。原始产物（LLM 原文/逐智能体
> 日志/真实 usage）本地留存 `backend/reports/stage9b-quality*/`（gitignore），不入库。

---

## 0. 结论（TL;DR）

1. **研判质量在有效口径下达到全对**：主矩阵 25 次统一链运行中 **19 次全链 LLM 评审——
   影响判定 19/19（100%）、处置建议 19/19（100%）、人工路由 5/5、证据引用幻觉 0**。
   方向 14/19（73.7%，偏差全部为保守方向或既有评分口径问题，见 §7）。
   M4.1 的两项未达标（处置 88.2%、差 1 例 E2）在本轮补齐。
2. **十类新增独立案例 Y1–Y10 首次全部通过**（10/10 案例的 impact/action 全部落真值，
   含厂商 backport、NVD 候选 vs 厂商 not_affected、触发条件不满足、无关可疑事件、
   监控缺失、静态紧迫性、情报冲突、OpenWrt 能力边界、无关动态证据、已缓解未修复）。
3. **M4.1 遗留整改全部落地并有实验证据**：E2（静态紧迫性确定性放大因子）、
   E3a（分支排除矛盾扩展拦截 potentially + 复议规则）、E1（方向语义与分数封顶分离）。
   E3 六跑（两实例×重复）**全部 not_affected+monitor 零方差**（M4.1 为 5/6）。
4. **语义消融证明角色独立贡献真实存在**：隐藏漏洞分析师报告后 Y1（backport）决策
   降级为空裁定兜底、E3 仍靠确定性事实正确；隐藏运行时分析师后 E1/Y9 结论保持正确
   （静态证据足够），证明「哪些案例纯规则/静态事实已足够、哪些真正依赖智能体协作」
   可以被区分度量（§6）。
5. **诚实记录两项中断**：①实验脚本首轮遗漏 X 扩展 Fixture，X2/X3 复验未进入本轮矩阵
   （脚本已修复，X2/X3 的 M4.1 锁定回归测试 35 项仍在位）；②实验末段 API 余额耗尽
   （HTTP 402，外部依赖），E4 复验（2 实例首跑为连接错误兜底）、反事实运行、2 项
   asset 消融未完成——已留断点续跑路径（§12），不影响已完成的 19+3 有效运行结论。
6. 全量回归 **637 passed / 0 failed**（589 基线 + 48 新增，零回归）；Mimosa 深度扫描
   见 §11。维持 flag=off，不删旧编排器。
7. **结论：研判质量门槛已达标，具备进入真实设备 Shadow 验证的候选条件**；
   建议补完 §12 中断项后再启动（人工决策，不自动切换）。

---

## 1. 研判机制修改前后的设计

### 1.1 四 Agent 专业分工深化（任务书第二部分）

| Agent | 修改前 | 修改后（本轮） |
|---|---|---|
| asset_investigator | 单一 `evidence_quality` 评级 | 输出强制三级证据分级：`verified_facts`（工具真实返回+来源）/`unverified_observations`（来源不明/单一来源/stale，注明 reason）/`conflicting_facts`（矛盾事实+双方来源）；「清单里没有≠不存在」，清单不完整必须声明 |
| vulnerability_analyst | version_impact + applicability 两维 | 新增四专业维度：`version_range_relation`（装机与受影响**区间**的关系，独立于 fixed_version 单点比较，含低于下界）/`branch_relation`（发行分支）/`patch_semantics`（**厂商补丁及 backport**：发行版回移植后「装机<上游修复版本」≠受影响）/`advisory_specificity`（厂商精确公告 vs NVD 通用候选）；「保守起见当受影响」被明确为非法结论 |
| runtime_analyst | behavior_level + freshness | 逐条证据 `relation` 七态（组件存在/服务活跃/攻击前置条件/可疑行为/CVE 相关/已确认利用/无关）+ `observed_at`（真实时间）+ `source_quality`；报告级 `exploitation_relation` 九态总结（含 suspicious_unlinked/monitoring_missing/monitoring_unavailable）；**schema 校验强制：confirmed_exploitation 必须由直接关联证据条目支撑**（防跳级） |
| decision_planner | 单一 verdict + urgency_basis | 四维分层（见 1.2）+ `resolved/unresolved_conflicts` 显式声明 + `unsatisfied_conditions` + follow-up `expected_effect` 前置声明 |

### 1.2 分层安全研判模型（任务书第三部分，维度非 Agent）

`VerdictItem` 新增三个 `DimensionAssessment`（status: established/partial/absent/
insufficient_evidence/unknown + conclusion + confidence + supporting_evidence_ids + gaps）：

1. **applicability_dimension**（漏洞适用性——静态版本/情报证据）；
2. **runtime_dimension**（运行时证据及其关联——组件存在…已确认利用；证据过期/监控缺失如实标注）；
3. **exposure_dimension**（暴露面与利用条件——公网/内网/仅本地/已缓解/证据不足）；
4. 处置维度由 action/priority/urgency_basis 承载。

程序侧配套：维度支撑引用纳入防幻觉校验（`_decision_evidence_validator`）；
两条铁律写入 decide 约束（运行时异常≠已利用；缺运行时事件≠漏洞不存在）。
**实验证据：19 次有效运行四维字段填充率 19/19/19/19（100%）**，各维度独立表达
证据不足（如 Y5：applicability=established 而 runtime=monitoring_missing 并存）。

### 1.3 确定性事实层扩展（evidence_prep，全部通用规则无案例硬编码）

- `detect_vendor_patch_semantics`：厂商精确公告 release 作用域立场 + **backport 语义词检测**；
  上游口径版本比较与厂商口径相左时给 `caveat`（两口径都如实保留）；
- `compute_urgency_amplifiers`：**静态紧迫性确定性放大因子** = KEV 收录 ∨
  （受影响组件自身公网监听 ∧ CVSS≥9.0）——组件公网匹配为保守规则（服务名/进程名与
  包名一致才算；客户端库如 curl 不算暴露）；
- `check_branch_applicability` 新增 `below_stated_affected_range`（装机低于受影响区间
  下界同样不受影响）；
- `collect_stances`/`detect_vendor_conflict` 扩展：可信源之间「肯定 vs 否定」立场并存
  （affected vs not_affected）同样标记未消解冲突（Y7 语义；Y1/Y2 的厂商优先级消解由
  决策约束完成，程序不静默替任何一方裁量）；
- 预取包新增 `public_services`（目标公网监听服务事实）。

### 1.4 决策约束与门禁（M4.1 七类矛盾理由 + 本轮四类）

decide 反馈重试约束（`_decision_semantic_errors`）与审计门禁 fail-closed 理由
（`_deterministic_contradiction_reasons`）同语义新增：

| 约束 | 触发（确定性事实） | 语义 |
|---|---|---|
| `static_urgency_without_amplifier`（E2 整改） | immediate_fix + static_evidence_only + impact∈{confirmed,potentially} + 无放大因子 | 厂商 affected+高 CVSS+装机受影响的静态组合只支撑 scheduled_fix |
| branch 排除扩展（E3a 整改） | branch_excluded/below_range + impact∈{confirmed,**potentially**} | 不再只拦 confirmed；维持矛盾→强制人工 |
| `fixed_disposal_contradiction`（X2 加固） | version_compare=fixed + action∈{immediate,scheduled} | 已修复不得给修复类处置 |
| `vendor_not_affected_overridden` | 厂商精确公告 not_affected（含 backport）+ impact∈{confirmed,potentially} | 厂商精确公告优先于 NVD 通用候选 |

冲突检测新增**规则 8**：预取确定性事实与漏洞分析师结论矛盾 → 触发被牵连专家定向
复议（≤1 次）——「与已核实事实相矛盾的结论」不再直接进入决策。
路由层（R8 成本分层的反向修正）：**装机版本未知/匹配状态不可靠、或源立场矛盾的
候选禁止 simple 直通**（证据质量不满足 simple 层前提；Y1/Y2/Y4/Y7 因此进入全量评审）。

### 1.5 协作与补查深化（任务书第五部分）

- follow_up_requests 新增 `expected_effect`（补查消除哪个缺口、结果如何改变研判）；
- 补查执行侧纪律：只查证所问事实，无关信息不展开，工具无法回答时如实 data_gaps；
- 决策侧纪律：**补查结果先过相关性评估——答非所问不计入证据；返回更多信息本身
  不构成提高置信度的依据**；只有实质性改变关键事实才调整结论/置信度并说明改变点；
- 冲突消解状态显式化：`resolved_conflicts`/`unresolved_conflicts`（18/18 次运行使用）。

---

## 2. 各 Agent 的真实专业贡献（本轮实验证据）

**逐 Agent 计量（31 次统一链运行，含消融/兜底）：**

| Agent | LLM 调用 | 工具调用 | tokens | 延迟合计 |
|---|---|---|---|---|
| asset_investigator | 79 | 187 | 442,375 | 831.5s |
| vulnerability_analyst | 62 | 125 | 366,974 | 866.5s |
| runtime_analyst | 58 | 121 | 290,263 | 753.3s |
| decision_planner | 31 | 0（综合者定位） | 799,453 | 3,567.7s |

**专业输出的真实消费证据（非兜底路径）：**

- **漏洞分析师**：Y1 冒烟运行中主动发起定向补查「以厂商分支修复版本复核确定性比较」，
  识破规则命中为「跨发行分支单点比较口径错配」（decision reason 原文留档）；
  E3 两实例六跑全部输出 not_affected 并引用分支范围证据。
- **运行时分析师**：`exploitation_relation` 语义被正确使用——`suspicious_unlinked`×3
  （Y4/Y9：可疑事件明确标注与候选 CVE 无关）、`monitoring_missing/unavailable`×2
  （Y5/Y6/Y8：能力边界如实标注而非「无异常」）、`service_active_only`×2（Y9/Y10）、
  `cve_related_evidence`×2（E1）——**「组件存在/服务活跃/可疑/利用」的混同在本轮
  被结构化消除**。
- **资产调查员**：Y4（清单不完整）上「包未列出」未被当作「不存在」，决策正确落
  insufficient_evidence；Y10 的回环绑定（缓解）进入 exposure_dimension 结论。
- **决策规划师**：四维分层 19/19 填充；补查请求-执行-回灌再决策 19 次运行全程
  「请求→执行→再决策」闭环无死循环（预算 ≤1 轮未触界）。

**程序兜底与真实贡献的区分**（任务书第五部分要求）：6 次兜底全部带
`program_fallback` 标记并与 LLM 口径分离统计——5 次为外部 API 故障（4 次连接错误
+ 2 次 402 余额耗尽，其一被计为 simple 类别系 llm_calls=0 的分类兼容路径），
1 次（Y1 首跑）为**语义 fail-closed**：模型在分支排除事实上坚持 potentially，
反馈重试后仍矛盾 → 按设计强制人工，不自动采纳任何一侧。

---

## 3. M4.1 遗留缺陷的根因与解决结果

### 3.1 E2（静态证据条件下产生 immediate_fix）——已解决

- **根因**（M4.1 §6.3-1）：`static_evidence_only` 路径对「厂商 affected + CVSS 8.1 +
  装机受影响」的静态组合过度授权 immediate_fix，而该组合无 KEV、无组件公网暴露，
  缺乏确定性紧迫依据。
- **修复**：`compute_urgency_amplifiers` + decide 约束 + 门禁三层（§1.3/1.4）。
- **实验结果**：`q-CVE-2026-81002-1`：**confirmed_affected + scheduled_fix**
  （真值 {scheduled_fix, monitor} 内）——决策 reason 明示「适用性维度独立成立…置信度
  与证据质量对齐下调」；对照 Y6（KEV+公网 Critical）immediate_fix + static_evidence_only
  **合法通过**（放大因子齐备）。E2↔Y6 构成放大因子机制的正反对照。
- E2 首跑为 API 连接错误兜底（已按口径分离；兜底判定 insufficient+collect 未计入
  LLM 准确率）。

### 3.2 E3a（分支排除证据可信度与复议）——已解决

- **修复**：①branch 排除扩展拦截 potentially（反馈重试）；②冲突规则 8 触发定向复议；
  ③审计门禁对 maintained 矛盾强制人工。
- **实验结果**：E3 两实例（E3a/E3b）×重复共 **6 跑全部 not_affected + monitor，
  零方差**（M4.1 为 5/6，E3a 曾出现 potentially 偏差）。Y1（backport 陷阱）矩阵运行
  not_affected + 冒烟运行 not_affected+downgrade_major + 重复运行 not_affected——
  3/3 有效 LLM 运行全对。

### 3.3 E1（风险方向建议与分数封顶语义混同）——改善但未完全消除

- **修复**：decide 约束第 6 条明示「最终分数由程序有界映射并封顶，与方向建议无关；
  不得因『分数已高不能再升』而给 maintain」。
- **实验结果**：E1 两跑 impact/action 全对；方向 #0=upgrade_minor ✓（M4.1 两跑
  maintain 的偏差消失），#1=maintain（残余单次方差）。3/3→2/2 的改善方向正确，
  如实记为「改善未根除」。

### 3.4 E5/X2/X3/E4 锁定状态

- E5：potentially_affected + scheduled_fix（处置正确，M4.1 修复保持）；方向
  downgrade_minor 超集（M4.1 已知保守方差，见 §7）。
- X2/X3：本轮矩阵因脚本遗漏未复跑（§5.3、§12）；M4.1 的 35 项锁定回归（含
  version_compare=fixed 语义、stale≠不适用）全部在位且通过（全量 637 passed）。
- E4：两实例首跑均为 API 连接错误兜底（兜底判定 insufficient+collect 落真值），
  LLM 复验被 402 中断——厂商冲突约束的单元回归（含 release 单记录形态）在位。

---

## 4. 新增独立案例 Y1–Y10 设计与结果（任务书第六部分）

**真值表先验固定**：`stage9b_quality_cases.py` 的 `Y_TRUTH` 于 `42fe3b1` 提交，
**先于任何模型运行入库**（git 历史可核验）；评价标准为允许集语义，与 E/X 同一纪律。
每案例独占包名（一案例一事件，无交叉匹配）；Y1/Y2 的厂商 not_affected 公告在
run_matching **之后**登记（考察「规则候选已命中后，研判层能否识别厂商精确事实」）。

| 案例 | 场景 | 统一链结果（impact/action/direction） | 真值命中 |
|---|---|---|---|
| Y1 | 厂商补丁 backport（上游 affected） | not_affected / monitor / downgrade_major ✓ | 全对 |
| Y2 | NVD 候选命中但厂商明确不受影响（低于区间下界） | not_affected / monitor / downgrade_major ✓ | 全对 |
| Y3 | 组件安装但触发条件不满足（无监听） | confirmed_affected / scheduled_fix / maintain ✓ | 全对（不得 immediate 达成） |
| Y4 | 组件未确认 + 无关可疑运行时事件 | insufficient_evidence / monitor / downgrade_minor ✓ | 全对（异常未被解释为利用） |
| Y5 | 严重漏洞但动态监控缺失 | potentially_affected / scheduled_fix / maintain ✓ | 全对（缺失≠不存在） |
| Y6 | 可信静态证据需及时处置（KEV+公网 Critical） | confirmed_affected / immediate_fix / maintain ✓（#1: potentially/scheduled 亦在真值内） | 全对（static 路径合法生效） |
| Y7 | 厂商公告与第三方情报冲突 | potentially_affected / mitigate / upgrade_minor ✓ | 全对（冲突显式化+人工） |
| Y8 | OpenWrt 采集能力限制 | confirmed_affected / scheduled_fix / maintain ✓ | 全对（能力受限≠不受影响） |
| Y9 | 动态证据充足但与 CVE 无直接关联 | confirmed_affected / scheduled_fix / downgrade_minor ✓ | 全对（活跃未被当紧迫依据） |
| Y10 | 已缓解但补丁未安装（回环绑定） | confirmed_affected / scheduled_fix / downgrade_major（方向超集） | impact/action 对 |

**System B 同案例对照**（同库同真值，10 事件 47 调用 252,512 tokens）：impact/action
亦全对（10/10）；方向 3 例偏差（Y3/Y9/Y10 upgrade_minor 超集）——统一链方向 1 例偏差
（Y10）。两系统在本测试集质量相当；差异体现在：Y8 上 System B 判 insufficient+collect
（对 OpenWrt 证据形态保守），统一链判 confirmed+scheduled（静态适用性照常成立）；
Y7 上 System B 直接 confirmed+scheduled_fix（冲突未主导处置），统一链 potentially+mitigate
（冲突语义主导）——统一链的分层语义在边界案例上更稳定，但**不预设整体更优**（§5 配对）。

---

## 5. 严格配对结果（任务书第七部分：三方对照，全运行口径）

**统计纪律**：全运行口径（25 次主矩阵运行全部计入，不挑选首次正确；LLM 准确率
仅统计 llm_full_chain 19 次；程序兜底/simple 单列）。

| 指标 | 确定性规则（A） | System B（Y 案例） | 统一四智能体（本轮） |
|---|---|---|---|
| 影响判定 | 不适用（规则不产生 impact 研判） | 10/10 | **19/19（100%）**（含 E+Y） |
| 处置建议 | 见下（决策语义粗） | 10/10 | **19/19（100%）** |
| 方向 | 不适用 | 7/10 | 14/19（73.7%，偏差全为保守/口径项） |
| 人工路由 | N/A | — | 5/5（真值要求者全部转人工） |
| 引用幻觉 | N/A | 不可比（无逐条校验器） | 0/19 |

**「哪些案例纯规则已足够 vs 需要四智能体协作」**（任务书第七部分额外要求）：

- **规则已足够（动作碰巧/语义简单）**：Y2/Y5 的规则 monitor 落在允许集——但规则无法
  给出 impact 结论与理由（误报候选将永远挂起），且 Y10 规则 immediate_fix 过度紧迫、
  Y6 规则 immediate_fix 恰好正确但无依据说明——**规则可作动作兜底，不能作研判**。
- **四智能体真正改善**：Y1/Y2（误报候选被证据链关闭并 downgrade）、Y3（适用性成立
  但紧迫度正确降级）、Y4（无关异常与候选 CVE 解耦）、Y7（冲突主导处置）、
  Y8（能力边界不影响适用性）、Y10（缓解≠修复的分层表达）。
- **静态事实已足够、智能体边际小**：消融显示（§6）隐藏漏洞分析师后 E3 仍正确
  （确定性分支事实驱动）——对这类案例，预取事实层+决策约束已承载主要研判，
  智能体的价值在证据稀薄/冲突形态（Y1 消融后即崩）上不可替代。

---

## 6. 语义消融与反事实测试

### 6.1 语义消融（graph `ablation_mask`：隐藏角色报告于决策输入；角色照常执行；
非失败路径，与 fail-safe 兜底口径分离）

| 消融 | 案例 | 结果 | 与完整运行对照 | 解读 |
|---|---|---|---|---|
| 隐藏 vulnerability_analyst | Y1（backport） | **决策空裁定 → 程序兜底** | 完整运行 not_affected 全对 | 漏洞分析师在 backport 语义上是承重角色：无其报告，决策无法自行消解上游/厂商口径冲突 |
| 隐藏 vulnerability_analyst | E3 | not_affected/monitor ✓（正确） | 完整运行同 | 确定性分支事实 + 决策约束已足够——该案例「纯规则+约束已足够」的实证 |
| 隐藏 runtime_analyst | E1 | confirmed/immediate ✓ | 完整运行同 | 静态证据（KEV+厂商+版本）足够支撑；运行时证据是冗余确认 |
| 隐藏 runtime_analyst | Y9 | confirmed/scheduled ✓ | 完整运行同 | 无关动态证据本就不应影响结论——消融后结论不变恰证明其无关性 |
| 隐藏 asset_investigator | Y4 / Y10 | 402 余额中断（未完成） | — | 待续跑（§12） |

### 6.2 反事实测试（Y6 去除 KEV）

- **设计**：同构 Fixture 去除 Y6 的 KEV（`--counterfactual` 独立库），预期
  immediate_fix 不再合法（放大因子消失 → scheduled_fix 上限）——直接验证
  urgency_amplifiers 机制驱动决策而非偶然。
- **状态**：被 402 余额耗尽中断，**未执行**（§12 续跑路径在位；单元测试已锁定
  反事实构造正确性：kev=False 且 critical_public 保持）。
- **替代证据**：E2（无 KEV、无组件公网暴露）↔ Y6（KEV+公网 Critical）构成本轮
  已完成的天然后事实对照——同为 static_evidence_only 路径，前者 scheduled、
  后者 immediate，处置差异与放大因子存在性一一对应。

---

## 7. 稳定性与不确定性分析

| 案例 | 重复口径 | 结果 |
|---|---|---|
| E1 ×2 | 独立重复 | impact/action 完全一致（confirmed/immediate ×2）；方向 #0 upgrade_minor ✓ / #1 maintain（残余方差） |
| E3 ×6（两实例×3） | 实例×重复 | **not_affected + monitor 六跑零方差**（M4.1 为 5/6 且实例间分化） |
| Y1 ×2（另加冒烟×1） | 独立重复 | 3 次有效 LLM 运行全部 not_affected（#0 矩阵首跑为语义 fail-closed 兜底，已分离口径） |
| Y6 ×2 | 独立重复 | impact 两值（confirmed/potentially 均在真值）；action immediate/scheduled 均在真值——方差存在但**未出真值**，紧迫度接近阈值时的两值分布如实记录 |

方向偏差 5 例明细（全部保守或既有口径项）：E1#1 maintain、E2 upgrade_minor
（M4.1 已知评分口径偏宽）、E5 downgrade_minor（过期证据保守下修，M4.1 已知）、
Y6#1 downgrade_minor、Y10 downgrade_major（缓解场景过度下调）。**无一起是
「无依据升级」**；方向维度仍为最弱项，建议下轮与真值口径约定对齐（M4.1 §9-3 遗留）。

不确定性表达：四维 DimensionAssessment 使「维度级证据不足」可机读——Y5 同时
applicability=established 与 runtime=monitoring_missing；Y4 runtime=suspicious_unlinked
与 impact=insufficient 并存且互不污染。

---

## 8. Token / 工具 / 运行时间记录（如实，不追求压缩）

| 项 | 数值 |
|---|---|
| 统一链总支出（31 运行：25 主矩阵 + 6 消融） | 432 调用 / **3,394,004 tokens** / 9,948s 墙钟 |
| 有效 LLM 全链运行均值 | 22 次 / **133,660 tokens/运行** / 377s 墙钟 |
| System B（Y 案例 10 事件） | 47 调用 / 252,512 tokens |
| 冒烟（Y1） | 12 调用 / 108,821 tokens |
| **本轮真实总支出** | **≈3.76M tokens**（任务书允许：成本次要，不为数值压缩专业深度） |
| 逐 Agent | 见 §2 表（决策规划师 token 占比最高——更长论证是分层语义的直接代价，如实记录） |

预算/时限：run 级 40 调用、150s/Agent、900s/run、补查≤1 轮、复议≤1 次全程未触界；
断点续跑/去重机制在位。本轮**未做任何影响研判质量的成本优化**（预取包复用等
M4.1 已有机制保持原样）。

---

## 9. 本轮实验暴露的问题（全部如实记录）

| # | 问题 | 处置 |
|---|---|---|
| 1 | 实验脚本首轮未调用 `extend_fixture_for_x_cases`——X2/X3 未进本轮复验矩阵 | 脚本已修复入库；X2/X3 语义由 M4.1 35 项回归继续锁定；续跑即补 |
| 2 | API 余额耗尽（HTTP 402，外部依赖）：中断 E4 的 LLM 复验、反事实运行、2 项 asset 消融 | 6 次兜底全部 `program_fallback` 标记分离口径；续跑路径见 §12 |
| 3 | 4 次 API 连接错误窗口（E2/E3a/E3b/E4 首跑） | 兜底判定全部落真值（fail-safe 语义正确）；有效重复运行已补齐 E2/E3 的 LLM 口径 |
| 4 | Y1 首跑模型坚持 potentially 与分支排除事实矛盾 | 按设计 fail-closed 强制人工——E3a 整改目标的正向验证，不计为缺陷 |

---

## 10. 全量回归

| 项 | 结果 |
|---|---|
| 全量回归 | **637 passed / 0 failed**（589 M4.1 基线 + 48 项 M4.2 专项 `test_quality_deepening.py`，零回归） |
| 专项覆盖 | Schema 深化（12）/ evidence_prep 新事实（11）/ 决策约束+门禁（11）/ 冲突规则 8（2）/ 路由（3）/ 消融钩子（2）/ 决策提示与维度校验（2）/ Y 集真值不变量+隔离性+关键事实+反事实构造（8）——含 1 项 M4.1 语义演进适配（静态紧迫性无放大因子→降级 scheduled） |
| shadow 隔离 | 实验全程 shadow（sink=None）；正式 RiskAssessment/修复授权/设备状态零变化；`LINUXGUARD_UNIFIED_PIPELINE` 保持 off |

---

## 11. Mimosa 深度扫描与敏感信息

- **Mimosa 深度扫描（交付态）**：scan-2026-10-16T02-26-27.410Z-4d6db1efbac3，
  **0 findings**，123 依赖包（离线公告：1 包 2 条匹配——依赖面与本仓使用方式
  经复核无受影响路径），seal **sha256:28f82cedb9daf20b30415a73a26f3989d43ba8d9d4b496d686e1b700d9589f4d**。
  扫描对象为本轮全部改动文件（focus 列表）与项目深度复核；扫描时工作区内容与
  最终提交内容一致（提交 hash 见 §14 补记）。
- 敏感信息：全部改动扫描——API Key 仅环境变量引用（.env 不入库）；Fixture 全程
  TEST-NET/RFC5737 合成地址与合成 CVE；无用户路径；无凭据字面量。
- git pre-commit 钩子快速检查因 python_ast 工具不可用未出完整结论（如实留痕，
  与 M4.1 同情况）；以上完整深度扫描为权威记录。

---

## 12. 中断项与续跑路径（402 余额恢复后）

```bash
# ① 主矩阵续跑（自动去重已完成运行，仅补 E4 两实例的 LLM 运行与 X2/X3 复验；
#    旧的 API 失败兜底运行文件需先删除以强制重跑）：
#    del backend/reports/stage9b-quality/runs/run-q-CVE-2026-81002-0-2.json 等 4 个兜底文件
python scripts/stage9b_quality_experiment.py --out reports/stage9b-quality
# ② 反事实（独立库，仅 Y6）：
python scripts/stage9b_quality_experiment.py --counterfactual --out reports/stage9b-quality-cf
```

预期工作量：E4×2 + X2 + X3 + 删除兜底重跑（E2/E3a/E3b 首跑）+ asset 消融×2 +
反事实×1 ≈ 9 次运行 ≈ 1.2M tokens。续跑完成后按 §0 口径更新汇总（脚本已输出
全运行口径统计，无需改标签——真值表先验不变）。

---

## 13. 是否具备进入真实设备 Shadow 验证的条件：**候选具备，建议补完中断项后启动**

| 条件 | 状态 |
|---|---|
| 研判质量（影响/处置）不劣于旧系统 | **✓（本轮 19/19；M4.1 配对 9/9 影响达标基础上处置补齐）** |
| 新场景泛化（十类独立案例） | **✓（10/10 案例全对，含 backport/冲突/能力边界/缓解等真实世界形态）** |
| 安全防线（人工路由/防幻觉/无依据升级/fail-closed） | **✓（5/5、0 幻觉、0 无依据升级、语义矛盾 fail-closed 实证）** |
| 稳定性 | **✓（E3 六跑零方差；Y6 两值但均真值内）/ 方向维度仍最弱（§7）** |
| 中断项（E4 复验/X2/X3 复验/反事实/2 消融） | **待补（402 外部中断，续跑路径在位）** |
| 成本 | 不作为本轮门槛（任务书明确降级；均值 133.7k tokens/运行如实记录） |

**本轮到此停止**：不切换 `LINUXGUARD_UNIFIED_PIPELINE=on`、不删除旧编排器、
不自动启动真实设备 Shadow——等待正式迁移指令。回滚语义不变（flag=off 即恢复
System B 原路径；统一链产物独立表，正式字段零迁移）。

## 14. 交付物清单

| 交付物 | 位置 |
|---|---|
| 实现提交（含先验真值表） | **`42fe3b1`**（基线 ff7e3c8） |
| 本报告 + 实验脚本 X 扩展修复 + Mimosa 补记 | 最终提交（见 §11 补记的 commit hash） |
| Y 案例集与先验真值表 | `backend/scripts/stage9b_quality_cases.py` |
| 实验脚本（三方对照/消融/反事实/全运行口径/断点续跑） | `backend/scripts/stage9b_quality_experiment.py` |
| M4.2 专项回归（48 项） | `backend/tests/test_quality_deepening.py` |
| 真实 LLM 实验原始产物（本地留存） | `backend/reports/stage9b-quality{,-smoke}/`（gitignore） |
| 汇总统计 JSON（本地留存） | `backend/reports/stage9b-quality/stage9b_quality_experiment.json` |

## 15. 诚实性声明

1. 全部 31 次统一链运行 + 10 次 System B 运行 + 1 次冒烟的真实产物本地留存；
   Y 真值表先验于 `42fe3b1` 入库、先于任何模型运行（git 时序可核验），
   未因结果调整任何标签；E/X 真值零改动。
2. 6 次程序兜底、2 次 402 中断、脚本 X 扩展遗漏全部如实记录（§9），兜底判定
   未混入 LLM 准确率；消融/兜底/主矩阵三口径分离统计。
3. 方向维度 5 例偏差、E1 残余单次方差、Y6 两值分布均如实计入并给出根因，
   未以「保守方向无害」为由豁免。
4. 反事实运行未执行（402），以 E2↔Y6 天然对照作替代证据并明确标注局限；
   不宣称反事实假设已被直接检验。
5. 本报告不预设新系统优于旧系统：System B 在 Y 集上 impact/action 同为 10/10；
   统一链的优势集中在分层语义、边界案例稳定性与可解释性（§4/§5），
   代价是 ≈10 倍 token（133.7k vs ≈25k/事件）与更长墙钟——全部如实呈现。
