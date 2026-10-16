# IoTGuard 统一四智能体质量闭环收尾报告（Stage 9B M4.2 Closure）

> 生成：2026-10-16。正式依据：`IOT_UNIFIED_FOUR_AGENT_QUALITY_REPORT.md`（M4.2 主报告）。
> 本轮 = M4.2 收尾验收：**研判质量闭环**（完整反事实与语义消融检验），非 Token 优化。
> 不新增智能体、不替换 LangGraph、`LINUXGUARD_UNIFIED_PIPELINE=off` 保持。
> 先验设计提交：**`9f9e2e6`**（Y6 2×2 与 RT 真值表，先于任何收尾 LLM 实验）；
> 脚手架修复提交：**`d306622`**（证据层时间戳缺陷 + RT 心跳竞态，先于 rt2- 重跑）；
> 退化输出检测提交：**`5ab79e1`**。原始 M4.2 产物（`backend/reports/stage9b-quality/`）
> **零改动**——所有收尾运行写入 `backend/reports/stage9b-closure/`（gitignore，本地留存），
> 重试一律新 run_id 新文件，被取代的失败运行全部保留。
> 可复现统计：`python scripts/stage9b_closure_stats.py`（零 LLM 离线重建本报告全部数字）。

---

## 0. 结论（TL;DR）

1. **M4.2 遗留实验全部补齐且落真值**：E4a/E4b 真实 LLM 复验两跑一致
   （potentially_affected + mitigate + 人工，厂商冲突语义在 LLM 层生效）；X2/X3 在
   M4.2 最终代码状态复验全对（X2：KEV 未推翻已修复事实；X3：过期证据不驱动
   immediate）；Y4/Y10 资产调查员语义消融完成（判定不承重、**校准承重**——隐藏后
   置信度膨胀 0.62→0.70 / 0.4→0.65）。
2. **Y6 反事实设计修正后机制得到完整验证**：原单因素设计（仅去 KEV）被
   kev0_pub1 格**证伪**——公网×CVSS9.8 通道下放大因子仍成立、immediate_fix 保持
   合法；新 2×2 四格确定性断言 **4/4 PASS**，LLM 处置与放大因子存在性**一一对应**
   （三格 immediate、无放大因子格 scheduled 被确定性门禁拦下）。
3. **Runtime Agent 正向贡献被区分度量**：完整管线 RT 四条件 impact/action **4/4 全对**
   （方向 3/4）；隐藏运行时分析师后 **RT-D（无监控）决策崩为 insufficient_evidence**
   （impact 出真值）——运行时分析师在「监控缺失≠漏洞不存在」语义上是承重角色；
   RT-B/RT-C 不承重（确定性程序事实已足够）；RT-A 上分析师的真实贡献是**新鲜度
   核实**（verified/fresh），关联语义偏保守（suspicious_unlinked vs 设计预期
   cve_related）如实记录。
4. **诚实记录两项新发现的脚手架缺陷（本轮暴露、已修复、回归锁定）**：①Y Fixture
   事件缺 `timestamp` 键 → 主矩阵全部 Y 案例证据层时间戳为空（无任何已记录真值
   依赖 freshness，**19+3 有效结论不受影响**）；②RT 传感器心跳 120s 竞态（E/X/Y 的
   同类竞态 M4 已修，新 Fixture 未继承）。被污染的 rt- 前缀 8 运行全部留档，修复后
   以 rt2- 前缀重跑作为最终样本。
5. **方向维度四层区分完成**（§5）：方向偏差全部为保守或口径项；「分数已封顶」与
   「模型应提升级方向」的分离在 E1 上双向实证；「监控过期」驱动 E5 downgrade 的
   混同被确认为方向通道最弱项。
6. 最终回归 **650 passed / 0 failed**（637 基线 + 13 项收尾专项，零回归，终态复跑）；
   Mimosa 深度扫描见 §8。**维持 flag=off**：不切换、不退役旧编排器、不启动真实设备
   Shadow——等待正式迁移指令。
7. **切换准备状态：候选具备、建议启动真实设备 Shadow 验证**（与 M4.2 主报告判定
   一致；本轮补齐了其全部前置中断项并修正了反事实设计）。

---

## 1. 离线核查：M4.2 实验完整性（任务书第一部分）

对 `backend/reports/stage9b-quality/` 全部原始产物独立重建统计（零 LLM），
**与主报告申报数字逐项对账一致**：

**分母与分类（25 主矩阵 + 6 消融 = 31 运行文件，控制台日志单次 invocation 可核）：**

| 类别 | 数量 | 运行 |
|---|---|---|
| llm_full_chain | 19 | E1×2(r1)、E2×1、E3a×2、E3b×2、E5×1、Y1×1、Y2–Y5 各 1、Y6×2、Y7–Y10 各 1 |
| program_fallback | 5 | E2 首跑(8 调用后连接错误)、E3a/E3b 首跑、E4a 首跑（外部故障）+ Y1 首跑（**语义 fail-closed**：分析师全部成功、仅 decide 失败，错误为确定性矛盾反馈文本） |
| simple_passthrough | 1 | E4b 首跑（0 调用外部故障，llm_calls=0 分类兼容路径） |
| 消融（abl-*） | 6 | vulnerability×2、runtime×2、asset×2（Y4/Y10 两项均为 402 外部故障兜底，无语义结论——与主报告申报一致） |

**19 次全链准确率复现**：impact 19/19、action 19/19、方向 14/19、人工路由 5/5
（E1×2/Y6×2/Y7——真值要求者全部转人工）、引用幻觉 0/19。

**计量关系（三口径分离，全部对账闭合）**：

| 口径 | 数值 | 说明 |
|---|---|---|
| run 级 meter（`usage.llm_calls`） | **432 调用 / 3,394,004 tokens** | register_call 计每一笔调用，**含零 token 失败调用**（如 402/连接错误重试）。主矩阵 348/2,806,308 + 消融 84/587,696 |
| client 级 counter（`usage_this_invocation`） | 338 / 2,806,308 | CountedChatClient 只计**成功响应**；与 meter 的差 10 次 = 零 token 失败调用（与 4 个 API 故障窗口吻合）；token 完全一致（失败调用无 token） |
| 逐 Agent 表（主报告 §2） | 230 调用 / 1,899,065 tokens | **agents_log 每角色只保留每运行末次调用**——定向复议/补查再执行同角色时覆盖同名条目。与 meter 差 202 调用/1.49M tokens = 被覆盖的早期调用 + 失败调用 |

> **对主报告的两处口径修正**（不影响结论，收尾轮如实更正）：
> ① 主报告 §3.2/§7 「E3 六跑全部 not_affected+monitor 零方差」表述不精确——实为
> **4 次 LLM 全链运行全部 not_affected+monitor 零方差**；2 次兜底运行为
> insufficient+collect（在真值允许集内但非同一判定）。准确表述：**6/6 落真值，
> LLM 口径 4/4 零方差**。
> ② 主报告 §2 逐 Agent 表应标注计量范围为「每运行每角色末次调用合计」，
> 非全量归属（全量归属 = meter 口径）。

**其他核查**：冒烟 12 调用/108,821 tokens ✓；System B 47 调用/252,512 tokens ✓；
本轮总支出 432+47+12=491 调用 / ≈3.76M tokens 与主报告 §8 一致 ✓；
原始 31 文件全部在位、无删除/替换痕迹 ✓。

---

## 2. 遗留实验补齐（任务书第二部分）

收尾矩阵 33 个运行文件（最终样本 26 次 LLM 全链 + 7 次被取代的外部/退化首跑，
全部留档）。API 修复前 M4.2 的 E2/E3a/E3b 首跑兜底**不重跑**：三案例均已有
att1/att2 有效 LLM 终样本（重跑仅增加重复，不改分母；原始文件不得删除）。

| 遗留项 | 收尾结果 | 真值判定 |
|---|---|---|
| **E4a**（qc-…-1-4） | potentially_affected + mitigate + 人工；方向 downgrade_minor（偏差） | impact ✓ action ✓ 方向 ✗ |
| **E4b**（qc-…-1-6） | **与 E4a 完全一致**（potentially + mitigate + 人工 + 同方向偏差） | impact ✓ action ✓ 方向 ✗ |
| **X2**（KEV+已修复） | not_affected + monitor + downgrade_major | **全对**（KEV 未虚判——核心验收） |
| **X3**（仅过期证据） | potentially_affected + scheduled_fix + downgrade_minor | **全对**（stale 不驱动 immediate） |
| **Y4 资产消融**（abl2-asset-81013） | 隐藏后 insufficient + monitor + maintain | 全对（与完整运行判定同级） |
| **Y10 资产消融**（abl2-asset-81019） | 隐藏后 confirmed + scheduled + downgrade_major | impact ✓ action ✓ 方向 ✗（与完整运行同偏差） |

E4a/E4b 的两跑一致 + mitigate（冲突未消解不得进入修复处置的厂商冲突约束）
在真实 LLM 层得到复验，补上了 M4.2 只能靠单元回归锁定的缺口。
E4 方向 downgrade_minor 双跑一致偏差：冲突情报场景模型选择保守下修方向
（真值允许 {maintain, upgrade_minor, upgrade_major}）——计入方向偏差口径。

**语义消融对照（asset_investigator）**：

| 案例 | 完整运行 | 隐藏资产调查员 | 解读 |
|---|---|---|---|
| Y10 | confirmed/scheduled/downgrade_major，置信度 0.62，暴露面置信 0.4 | 判定完全相同，置信度 **0.70**，暴露面置信 **0.65** | **判定不承重、校准承重**：资产调查员的 verified/unverified 分级纪律约束着决策置信度——隐藏后决策对「单一来源画像」更自信（置信度膨胀），缓解绑定的暴露面证据不再被降权。真实但隐性的贡献形态 |
| Y4 | insufficient/monitor/downgrade_minor，暴露面=insufficient_evidence | insufficient/monitor/**maintain**，暴露面=**partial** | 判定不承重：未确认组件候选的 insufficient 由程序事实（inventory_incomplete）承载；隐藏后决策把单来源设备画像采信为 partial（更少保留），missing_evidence 列表更短 |

与主矩阵消融合并的四角色承重图谱见 §4。

---

## 3. Y6 反事实修正（任务书第三部分）

**修正原因**：原设计只去除 KEV，而确定性放大因子规则为
`KEV ∨（受影响组件公网监听 ∧ CVSS≥9.0）`——Y6 的 caddy 0.0.0.0:443 × CVSS 9.8
在 kev=False 下放大因子仍成立，「去 KEV 必降 scheduled」的预期不成立
（M4.2 既有测试 `test_counterfactual_build_removes_kev` 已实证该事实）。
原设计保留于 `stage9b_quality_cases.py` 并标注 SUPERSEDED（不静默覆盖）。

**新设计**（`9f9e2e6` 先于实验提交）：完整 2×2（KEV 有/无 × 受影响组件公网高危
有/无），四格共用相同静态适用性事实，每格先验固定确定性预期与处置允许集；
并明确区分「**存在放大因子**（immediate 的确定性必要依据）」与「**必然执行
immediate**（非必然——是否选择仍由模型综合裁量）」。

**结果**（四格独立库；先确定性断言、后 LLM 运行）：

| 格 | 放大因子断言（程序事实） | LLM 处置 | 判定 |
|---|---|---|---|
| kev1_pub1（Y6 原样锚点） | kev=T pub=T any=T → **PASS** | confirmed / **immediate** / maintain | 全对 |
| **kev0_pub1（去 KEV、公网×9.8 在）** | kev=F pub=T any=T → **PASS** | potentially / **immediate 保持** / downgrade_minor(偏) | impact✓ action✓ 方向✗ ——**原单因素设计预期被证伪** |
| kev1_pub0（KEV 在、组件转仅本地） | kev=T pub=F any=T → **PASS** | confirmed / **immediate** / maintain | 全对（KEV 单通道足够） |
| **kev0_pub0（双通道皆除）** | kev=F pub=F any=F → **PASS** | confirmed / **scheduled（immediate 被拦）** / downgrade_minor | 全对——`static_urgency_without_amplifier` 确定性门禁端到端生效 |

**三点结论**：①放大因子检测是纯程序事实，四格断言 4/4 与规则定义逐项一致；
②LLM 处置与放大因子存在性**一一对应**（3 格 immediate、1 格 scheduled）——
机制真实驱动决策而非偶然；③「存在放大因子 ≠ 必然 immediate」亦有实证：
主矩阵 Y6#1（放大因子在场）模型选择 scheduled_fix 且在真值内——紧迫度接近
阈值时的两值分布与 M4.2 主报告 §7 记录一致。

---

## 4. Runtime Agent 正向贡献实验（任务书第四部分）

**设计**（`9f9e2e6` 先验固定）：四条件 RT-A/B/C/D 共用**相同设备身份**（edge-rt/
192.0.2.50）、**相同 CVE**（CVE-2026-81021，vsftpd 独占包）、**相同静态版本与厂商
事实**（affected、CVSS 8.5、无 KEV、无公网监听——静态放大因子关闭，运行时证据
是紧迫度唯一变量）；仅运行时层不同：A=新鲜直接相关利用模式链（vsftpd 拉起 shell
拉取载荷，T-5min）；B=新鲜无关可疑链（sshd 会话下载器）+vsftpd 常规活动；
C=过期相关证据（T-45d，传感器心跳同步过期）；D=完全无监控。每条件运行完整
管线 + 隐藏 runtime_analyst 消融对照。证据时间偏移先验固定、证据 ID 由
persist_evidence 确定性生成可追溯（run 文件 evidence_prep.runtime_evidence_ids）。

**脚手架缺陷与处置（诚实记录）**：rt- 前缀首跑集暴露两项缺陷（§0-4）：Y Fixture
证据层时间戳为空（预存）+ RT 心跳 120s 竞态（本轮特有）。rt- 集 8 运行全部留档；
修复后（`d306622`）以 **rt2- 前缀重跑全部四条件**作为最终样本。rt- 集并非全然
浪费：它构成一次自然实验——新鲜事件+过期传感器覆盖时，分析师把证据整体降级
stale_verified 并拒绝升级行为等级（F6/X3 语义的正确保守融合）。

**最终样本（rt2 集，8 运行）**：

| 条件 | 完整管线 | 隐藏 runtime_analyst | 真值命中 | 语义发现 |
|---|---|---|---|---|
| **RT-A** 新鲜相关 | confirmed/scheduled/**downgrade_minor(偏)**；分析师 findings=2、**verified/fresh ✓**、关联 suspicious_unlinked（保守于设计预期 cve_related） | confirmed/scheduled/maintain；被遮蔽分析师仍运行且给出 **cve_related_evidence**×2（关联正确但新鲜度 stale_verified——运行中段传感器再老化的残留脚手架敏感性） | full I✓A✓D✗ / abl 全对 | 分析师真实贡献=**新鲜度核实**（无报告时决策层 validity 只能保守标注）；关联语义偏保守为模型行为方差，如实记录 |
| **RT-B** 新鲜无关 | confirmed/scheduled/**maintain** ✓✓✓；exploitation_relation=**suspicious_unlinked** ✓ | confirmed/scheduled/downgrade_minor ✓✓✓ | **全对×2** | 无关可疑事件未被解释为本 CVE 利用、未抬紧迫度（Y 语义泛化到新构造案例） |
| **RT-C** 过期相关 | confirmed/scheduled/downgrade_minor ✓✓✓；**stale_verified** ✓ 无 immediate ✓ | confirmed/scheduled/maintain ✓✓✓；分析师条目含 cve_related_evidence（过期但相关——被正确降级使用） | **全对×2** | 过期证据不得作为当前利用依据——决策与分析师双层一致 |
| **RT-D** 无监控 | **potentially/scheduled/maintain ✓✓✓**；runtime_dimension 如实标注证据完全缺失、validity=unavailable | **insufficient_evidence + collect（impact 出真值 ✗）** | full 全对 / **abl impact ✗** | **承重实证**：无分析师的诚实「监控缺失」报告，决策自行坍缩为「证据不足」，偏离「缺失≠漏洞不存在」铁律；保守方向但为可度量的准确率损失 |

**四智能体语义贡献图谱（合并主矩阵消融 + 本轮 RT/Y 消融）**：

| 角色 | 承重场景（隐藏后决策退化） | 不承重场景（确定性程序事实已足够） | 贡献形态 |
|---|---|---|---|
| vulnerability_analyst | Y1 backport（主矩阵：隐藏后决策空裁定→兜底） | E3 分支排除（主矩阵：隐藏后仍正确） | 上游/厂商口径冲突的语义消解 |
| runtime_analyst | **RT-D 无监控（本轮：隐藏后 insufficient 崩）** | RT-B/RT-C（本轮：隐藏后判定不变——freshness 分桶与覆盖状态是程序事实） | 「监控缺失≠不存在」「异常≠利用」铁律的载体；新鲜度核实 |
| asset_investigator | （判定级不承重）Y4/Y10 隐藏后判定不变 | — | **校准承重**：证据分级纪律约束决策置信度（Y10 隐藏后 0.62→0.70 膨胀）；单来源画像降权 |
| decision_planner | 分层研判/约束执行（程序侧 Validator+门禁兜底，无消融设计——其为确定性语义层） | — | 四维分层 + 冲突显式化 |

**确定性程序已能完成 vs 智能体语义贡献的边界**（任务书第四部分要求）：
分支排除、版本比较、KEV/公网放大因子、freshness 分桶、覆盖状态——全部为
evidence_prep 确定性事实，消融实验反复证明它们足以承载多数判定（B/C/Y4/Y10/E3）；
智能体的不可替代贡献集中在**证据语义关系**（backport 消解、无关性辨析、
监控缺失的诚实表达）与其对决策**置信度校准**的约束。这一边界正是
「哪些案例纯规则已足够」可区分度量的结构基础。

---

## 5. 风险方向维度检查（任务书第五部分）

四层区分：原始规则基线 → 模型提出的方向 → 确定性程序封顶后的分数 → 处置
紧迫度。分数通道为程序独占（`DIRECTION_ADJUSTMENTS` 有界映射 + [0,100] 封顶），
模型方向仅选择 adjustment——以下封顶分数为该确定性公式的计算值（shadow 运行
final_score 落库为 null，非模型输出）。

| 案例 | 规则基线 | 模型方向 | 封顶后分数 | 处置（紧迫度） |
|---|---|---|---|---|
| E1#0 | 100.0/Critical, immediate_fix | upgrade_minor(+10) | **100.0（已封顶，+10 无位移）** | immediate_fix/critical ✓ |
| E1#1 | 同上 | maintain(0)（方向偏差） | 100.0 | immediate_fix/critical ✓ |
| E2 | 61.05/High, monitor | upgrade_minor(+10)（偏差，真值 {maintain,downgrade_minor}） | 71.05 | scheduled_fix/high ✓ |
| E5 | 83.83/Critical, immediate_fix | downgrade_minor(−10)（偏差） | 73.83 | scheduled_fix/high ✓ |
| Y6#0 | 100.0/Critical, immediate_fix | maintain ✓ | 100.0 | immediate_fix/critical ✓ |
| Y6#1 | 同上 | downgrade_minor(−10)（偏差） | 90.0 | scheduled_fix/high ✓（真值内） |
| Y10 | 92.27/Critical, immediate_fix | downgrade_major(−20)（超集偏差） | 72.27 | scheduled_fix/high ✓（规则 immediate 被正确降级） |

三个任务书要求的区分，逐条对应：

1. **「不能把最终分数已封顶直接解释为模型不需要提出升级方向」**——E1 双跑实证：
   基线已 100，#0 仍按约束第 6 条给出 upgrade_minor（方向语义正确，尽管封顶后
   分数与 maintain 无差异）；#1 的 maintain 是「分数已高不能再升」残余偏差
   （M4.2 已知单次方差），其对分数的影响为 0、对语义的影响是少传递了证据强度
   信号。两层的正确解耦：方向=证据强度语义，分数=程序有界映射。
2. **「不能将监控过期直接解释为漏洞本身风险下降」**——E5 是本条的反面教材
   （如实承认）：其 downgrade_minor 由 stale 监控驱动（门禁 reasons 含
   stale_runtime_evidence）而静态适用性未变——方向通道把「运行时证据质量」
   混同进了「漏洞风险水平」。处置层正确（scheduled_fix，未随方向升级为激进
   或降级为 monitor），但方向口径混同为本轮确认的方向维度最弱项，与
   M4.1 §9-3 遗留一致。**如需改进评分规范必须另建版本**——本轮不动原始
   实验与其评分结果，仅在此明确记录改进方向（方向真值允许集与
   runtime_evidence_validity 的语义对齐）。
3. **处置紧迫度独立于方向**：全部 7 次运行的处置均落真值（含 E1#1/Y6#1/Y10 的
   方向偏差运行）——方向偏差未污染处置；Y10 反向例证：方向 downgrade_major
   过度下调的同时处置恰好从规则过紧的 immediate 修正为 scheduled（缓解≠修复
   的分层表达）。

收尾新增方向数据点：E4a/E4b 双跑一致 downgrade_minor（冲突情报下保守下修，
超集偏差）；Y6 2×2 中 kev0_pub1/kev0_pub0 两格 downgrade_minor（无 KEV 格
降方向可辩护；kev0_pub1 格在放大因子在场下降方向为偏差）。**全部收尾+主矩阵
方向偏差继续保持「无一起无依据升级」的记录**。

---

## 6. 完整实验分母与真实成本（任务书第六部分·报告要件）

**全部分母（不挑选、不删除、不覆盖）**：

| 集 | 运行文件 | 有效 LLM 全链 | 程序兜底/退化 | 说明 |
|---|---|---|---|---|
| M4.2 主矩阵（原始） | 25 | 19 | 5+1 simple | 原始产物零改动 |
| M4.2 消融（原始） | 6 | 4 有效（vuln×2/runtime×2） | 2（asset×2 外部故障） | asset 两项由收尾 abl2-* 补齐 |
| 收尾 matrix-retry（qc-* + abl2-*） | 6 | 6 | 0 | E4a/E4b + X2/X3 + Y4/Y10 资产消融 |
| 收尾 y6-matrix（cf2-*） | 4 | 4 | 0 | Y6 2×2 四格（放大因子断言另 4/4 程序断言） |
| 收尾 rt-（污染留档集） | 13 文件 | 8（链末端口径，不作验收样本） | 3 外部兜底 + 2 退化输出（被取代） | 脚手架缺陷集，仅作自然实验记录 |
| 收尾 rt2-（最终 RT 样本） | 10 文件 | 8 | 2 退化输出（被取代） | 权威 RT 样本 |
| System B / 冒烟（原始） | — | 10 / 1 | — | 零改动 |

精确数字以 `python scripts/stage9b_closure_stats.py` 输出为准（收尾合计 33 个运行
文件：最终样本 26 次 LLM 全链 + 7 次被取代首跑——5 次外部故障 + 2 次模型退化
输出；链式重试的中间运行亦全部在盘）。

**真实成本（meter 口径，含失败调用）**：

| 段 | 调用 | tokens |
|---|---|---|
| M4.2 原始 31 运行 | 432 | 3,394,004 |
| M4.2 System B + 冒烟 | 59 | 361,333 |
| 收尾 33 运行文件 | 514 | 3,754,203 |
| **累计** | **1,005** | **≈7.51M** |

收尾段均值 ≈144k tokens/全链运行（含退避重试与被取代首跑）；外部故障重试 7 次
约占收尾 token 的 19%（718,366）——故障成本如实计入。预算纪律：全程
--max-total-tokens 硬预算、逐运行落盘、断点续跑链末端续接，未发生失控调用。

---

## 7. 回归、扫描与隔离（任务书第六部分）

| 项 | 结果 |
|---|---|
| 收尾专项测试 | `tests/test_closure_counterfactuals.py` **13 项**：Y6 2×2 四格放大因子断言（走 build_evidence_prep_packet 真实路径）、四格静态事实一致性、真值不变量、旧设计 SUPERSEDED 留档、RT 四条件同构性/干预点/证据时间戳回归锁（含 Y 案例同缺陷锁） |
| 全量回归 | **650 passed / 0 failed**（8m16s；637 M4.2 基线 + 13 项收尾专项，零回归；终态 HEAD=5ab79e1 复跑确认） |
| Mimosa 深度扫描 | 见 §8（交付态封印） |
| 敏感信息 | 全仓扫描：无 API Key/私钥/口令字面量；仅 .env.example 入库且凭据为空值占位；收尾脚本凭据仅经 app.config 环境变量读取；Fixture 全程 TEST-NET/RFC5737 合成地址与合成 CVE |
| shadow 隔离 | 收尾全部运行经 run_case（mode="shadow"、sink=None）；正式 RiskAssessment/修复授权/设备状态零变化；`LINUXGUARD_UNIFIED_PIPELINE` 环境未设置 → **off**（config 默认值验证） |
| pre-commit 钩子 | python_ast 工具不可用未出完整结论（如实留痕，与 M4.1/M4.2 同情况）；完整深度扫描为权威记录 |

## 8. Mimosa 深度扫描（交付态）

扫描于最终代码态（HEAD=5ab79e1，工作区仅另有未入库的本报告文档）执行，
focus 覆盖本轮全部改动代码文件（closure_cases / closure_experiment /
closure_stats / quality_cases / quality_experiment / test_closure_counterfactuals）：

- scanId：**scan-2026-10-16T06-22-58.264Z-997fe0409b11**（单次 attempt 即封印，
  无中断无 resume）；seal：**sha256:9d3c421e3bf6c9536ba42c1052c313c87fbd4116de6dc426b423f400d7de2d0a**；
- findings：**0**；依赖包：123（离线公告：1 包 2 条匹配——与 M4.2 交付态扫描
  同一条目，依赖面与本仓使用方式经复核无受影响路径）。

## 9. 诚实性声明

1. **原始产物零改动**：`backend/reports/stage9b-quality/` 的 31 个运行文件、汇总
   JSON、控制台日志全部保持提交时状态；收尾全部产物独立目录；重试一律新 run_id；
   被取代的外部故障/退化运行 7 个文件全部在盘可查（stats 脚本 superseded 列表）。
2. **真值先验**：Y6 2×2 与 RT 真值表随 `9f9e2e6` 入库，先于任何收尾 LLM 运行
   （git 时序可核验）；E/X/Y 原始真值零改动；实验结果未反向调整任何标签——
   RT-A 的关联语义设计预期（cve_related）未达（模型判 suspicious_unlinked），
   如实记录为发现而非改表。
3. **两类新缺陷如实归因**：Y 案例证据层时间戳为空是**预存脚手架缺陷**
   （M4.2 已记录运行的判定无真值依赖 freshness，19+3 结论不受影响——但若
   未来有依赖 freshness 的 Y 语义测试则必须以修复后 Fixture 重跑）；RT 心跳
   竞态是本轮新 Fixture 未继承 M4 已有修复所致。两者均修复+回归锁定+受影响
   运行重跑，污染集留档。
4. **模型退化输出如实计入**：rt2-RT-A 首跑两次 Schema 回显退化（deepseek-v4-flash
   随机失效模式）以新检测捕获并以 -r1 重试；退化运行 2 文件留档，最终样本为
   重试后运行——该检测已入库（`5ab79e1`）防复发。
5. **RT-A 语义结论的局限**：分析师新鲜度核实（verified/fresh）在其报告中成立，
   但决策层 validity 仍标 stale_verified（传感器 120s 阈值在运行中段再次触发的
   残留脚手架敏感性）；关联语义设计预期未达。RT-A 的「新鲜证据→紧迫度提升」
   通路因此**未被完整正向验证**——如实记录，不在报告中宣称已验证。
6. **成本与口径**：全部成本为 meter 口径真实计量（含失败与重试）；三口径差异
   （meter/client/逐 Agent）已在 §1 给出机制解释；主报告两处口径表述修正已
   在 §1 注明，不改写主报告原文（其全文保留，本报告为更正记录）。
7. **本轮到此停止**：不设置 `LINUXGUARD_UNIFIED_PIPELINE=on`、不删除旧编排器、
   不未经批准启动真实设备 Shadow。

## 10. 最终切换准备状态

| 条件 | 状态 |
|---|---|
| 研判质量（影响/处置）不劣于旧系统 | **✓**（M4.2 19/19 + 收尾 E4/X2/X3/RT 全部落真值；唯一 impact 出真值 = RT-D 消融态，恰证明角色承重） |
| 反事实机制验证 | **✓**（Y6 2×2 修正设计四格全过：放大因子断言 4/4、处置与因子存在性一一对应、无因子格确定性门禁拦下 immediate） |
| 语义消融完整性 | **✓**（六消融组合全数据：角色承重图谱可区分「纯规则已足够」与「智能体不可替代」） |
| 安全面 | **✓**（人工路由全对、引用幻觉 0、无依据升级 0、fail-closed 语义与门禁多次正向触发） |
| 方向维度 | **最弱项（已知）**：保守/口径偏差约 25%；E5「过期→降风险」混同确认；改进需另建评分规范版本，不在本轮 |
| 成本 | 不作门槛（任务书降级）；≈144k tokens/运行如实记录 |
| 稳定性 | E4a/E4b 一致；Y6 2×2 确定性断言零方差；LLM 层随机退化输出（Schema 回显）已具检测与重试机制 |

**建议**：具备启动真实设备 Shadow 验证的条件（人工决策）。启动前建议顺带处理：
①传感器 stale 阈值（120s）对慢管线的残留敏感性——生产环境传感器心跳连续，
该阈值行为与 Fixture 时序的交互建议在 Shadow 观测确认；②方向评分规范另建
版本提案（E5 混同整改）。

---

## 附：交付物与提交链

| 交付物 | 位置/哈希 |
|---|---|
| 先验设计（真值表先于实验） | `9f9e2e6` |
| 脚手架缺陷修复（时间戳+心跳+rt2 机制） | `d306622` |
| 退化输出检测 | `5ab79e1` |
| 本报告 + ai_collaboration 更新 + Mimosa 封印补录 | 本轮收尾提交（git log 可见） |
| 收尾实验案例与真值 | `backend/scripts/stage9b_closure_cases.py` |
| 收尾实验脚本（三模式+链末端续接+退化检测） | `backend/scripts/stage9b_closure_experiment.py` |
| 可复现统计（零 LLM） | `backend/scripts/stage9b_closure_stats.py` |
| 收尾专项回归（13 项） | `backend/tests/test_closure_counterfactuals.py` |
| 原始产物（本地留存，零改动） | `backend/reports/stage9b-quality/`、`backend/reports/stage9b-closure/`（均 gitignore） |
