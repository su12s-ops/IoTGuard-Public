# 当前任务

> 每完成一个任务更新本文件。最后更新：2026-10-16

## 最近完成

**Stage 9B M4.2 收尾：统一四智能体质量闭环验收（研判质量闭环而非 Token 优化；遗留实验全部补齐、Y6 反事实 2×2 修正、Runtime Agent 正向贡献度量；650 回归零失败；维持 flag=off）**（2026-10-16，报告 IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md）
- [x] 第一部分（零 LLM 离线核查）：M4.2 主矩阵 25+6 运行完整性独立重建与对账（19 全链+5 兜底+1 simple+6 消融；432 调用/3,394,004 tokens meter 闭合；三口径差异机制解释：meter 含零 token 失败调用、逐 Agent 表=每角色末次调用）；更正主报告两处口径（E3 零方差表述、逐 Agent 计量范围）；原始产物零改动核验
- [x] 第二部分（遗留补齐，真实 LLM，全部落真值）：E4a/E4b 两跑一致（potentially+mitigate+人工）；X2 全对（KEV 未推翻已修复）；X3 全对（stale 不驱动 immediate）；Y4/Y10 资产消融（判定不承重、校准承重——Y10 隐藏后置信度 0.62→0.70 膨胀）
- [x] 第三部分（Y6 反事实修正）：原单因素设计 SUPERSEDED 留档；新 2×2 四格先验真值先于实验提交（9f9e2e6）；确定性放大因子断言 4/4 PASS；LLM 处置与因子存在性一一对应（kev0_pub1 证伪原预期、kev0_pub0 门禁拦下 immediate）
- [x] 第四部分（RT-A/B/C/D 正向贡献）：最终样本完整管线 impact/action 4/4（方向 3/4）；RT-D 隐藏运行时分析师后崩为 insufficient（承重实证）；RT-B/RT-C 程序事实已足够；RT-A 贡献=新鲜度核实、关联偏保守如实记录
- [x] 缺陷修复（2 项脚手架+1 项检测，回归锁定、污染集留档、受影响运行 rt2- 重跑）：Y Fixture 证据层时间戳为空（预存；已记录 Y 运行结论不受影响）/ RT 心跳 120s 竞态 / 运行时分析师 Schema 回显退化检测
- [x] 回归与安全：全量 **650 passed / 0 failed**（637+13 终态复跑零回归）；Mimosa **0 findings**（scan-…-997fe0409b11，seal sha256:9d3c421e…de2d0a）；敏感信息干净；shadow 零触碰；**flag=off 保持**
- [x] 方向维度四层检查：E1 封顶/方向分离双向实证、E5「过期→降风险」混同确认（方向最弱项，改进需另建评分规范版本）；全部偏差无一起无依据升级
- [x] **本轮结束即停止**：不设 flag=on、不退役旧编排器、不未经批准启动真实设备 Shadow；切换准备状态=候选具备，建议人工决策启动 Shadow

## 最近完成

**Stage 9B M4.2 主轮（补记归档）：统一四智能体研判质量深化**（2026-10-16 交付提交 42fe3b1/22045b8，报告 IOT_UNIFIED_FOUR_AGENT_QUALITY_REPORT.md）
- [x] 四 Agent 专业分工 Schema 深化 + 四维分层研判 + E2/E3a/E1/X2 整改 + Y1–Y10 独立案例 10/10；主矩阵 19 全链 impact/action 19/19、人工路由 5/5、幻觉 0、方向 14/19；全量 637 passed；真值先验 42fe3b1 先于实验数据入库；维持 flag=off（遗留中断项由收尾轮补齐）

## 最近完成

**Stage 9B M4.1：统一四智能体研判校准与成本治理（口径修正+五类缺陷修复+证据预取；复测后影响判定首次达标，成本/处置仍差一步，维持 flag=off）**（2026-10-15，报告 IOT_UNIFIED_FOUR_AGENT_CALIBRATION_REPORT.md）
- [x] 第一部分（零 LLM 离线核查，`stage9b_calibration_stats.py`）：M4 的 20 次运行重建为严格五类口径——全链 LLM 14 / 程序兜底 3（**实为 E3a×2+E3b×1，原报告误记"E3a 三次"**）/ 消融 1 / simple 2；混合口径 vs LLM-only 修正（影响 88.2%→85.7%、处置 64.7%→57.1%——原报告把兜底混入 LLM 准确率）；耗时口径澄清（7.6s=76.0s/10 事件全量口径，104.1s 合并口径应为 9.46s/事件）；调用数双口径如实呈现（meter 258 = 237 评审+21 消融；client 246）；原始存档与真值零改动
- [x] 第二部分（通用安全语义，零 case_id 硬编码，三层防线=确定性事实+程序校验+fail-closed 门禁）：E3 分支排除声明确定性提取与比对（branch_excluded 不得被通用匹配推翻）/ E4 厂商冲突预检（装机≠适用确认，冲突未消解禁 confirmed 与修复处置）/ E5 VerdictItem 新增 runtime_evidence_validity+urgency_basis 分离字段（stale_verified 不是活跃利用充分依据；静态证据独立支撑的紧急建议不一刀切禁止但强制人工）/ X2 确定性 fixed 语义（KEV 不改变已修复事实）/ X3 过期证据不得推导适用性不足；门禁新增 7 类确定性矛盾理由
- [x] 第三部分：`prepare_evidence` 确定性节点落地（LangGraph 单图，非第五个 Agent，无 LLM）：复用只读工具/多源情报包/SecurityEvidence，运行内只读复用、新鲜度按当前时间重算、有界（组件≤60/证据≤30/记录≤12）、失败退回自主查询；逐 Agent 前后对照：资产工具 90→76（-15.6%）、专家延迟 -17%~-27%、墙钟/评审运行 -7.8%、全链口径 token -4.8%（93.0k→88.5k）——**成本"实质改善"未达（评审运行口径 +15.6%），如实判定 ✗**
- [x] 第四部分：异常重试 1s 退避；程序兜底裁定显式 program_fallback 标记（统计口径分离）；人工门禁 fail-closed 扩展；预算/超时/降级路径全保持（消融复验 F7 三项全中）；本轮 0 次 API 故障/0 兜底
- [x] 第五部分 B-D（真实 LLM 复测，Fixture/真值表零改动）：22 次运行全部 completed（矩阵 17 全链+2 simple+1 消融 + E4 补充 2）；0 失败 0 兜底 0 预算触界；**影响判定（配对）9/9 vs 旧 7/7 首次达标；X2 完美（not_affected+monitor 零超集）；X3 回到真值；E5 处置 3/3 零方差；E4 修复后 5/5 全对**；处置（配对）8/9 vs 旧 8/8 仍差 1 例（E2 静态紧迫性超集）；E3b 三跑全部识破误匹配、E3a 残余 1/6 方差；引用幻觉 0/20（2 例评分器假阳性已对齐）
- [x] 实验暴露并修复 1 项真实缺陷（E4 冲突漏检：release 作用域 canonical value 为单记录形态，detect_vendor_conflict 只读 records 漏检）→ 回归锁定 + 受影响案例修复后真实复测 5/5 全对
- [x] 回归与安全：全量 **589 passed / 0 failed**（554 基线 + 35 项校准专项 test_evidence_prep.py）；Mimosa 深度扫描 **0 findings**（scan-…-25c64eb52112，123 依赖包）；shadow 全程零触碰正式字段
- [x] **维持 LINUXGUARD_UNIFIED_PIPELINE=off**；不切换正式入口、不删旧编排器、不绕过 Harness；本轮结束即停止
- [ ] 待办（下轮指令）：①static_evidence_only 加确定性放大因子前提（KEV/公网暴露/预认证，预期补齐处置差距）②branch_excluded 下 potentially 以上强制人工或升 focused 层（E3a 残余方差）③方向口径与真值允许集对齐（E1/E5 保守偏差）④预取切片按角色瘦身+决策 completion 引导（目标 ≤60k tokens/评审运行）

## 最近完成

**Stage 9B M4：统一四智能体最终验收实验（全部 10 事件真实 LLM 完成；未达切换门槛，维持 flag=off）**（2026-10-15，报告 IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md）
- [x] 充值验证：最小真实调用通过（deepseek-v4-flash / temperature 0.1 与上轮一致 / 真实 usage 67 tokens / 无 402）；System B 上一轮全量对照经代码版本核查保留（event_review_pipeline 自 d14f354 未改），X2 由本轮同配置补充
- [x] 补齐 X2 案例（架构 §9 定义，此前未落地）：KEV + 厂商 affected 但装机已高于修复版本（CVE-2026-81008 / libxml2 / edge-06）进 Fixture 与真值表；10 事件 = E1×1 + E2×1 + E3×2 + E4×2 + E5×1 + X1×2 + X2×1 + X3×1
- [x] 全部 20 次运行 completed：14 全链四智能体 + 3 次 API 连接错误程序兜底（判定全部落真值）+ 1 屏蔽消融（F7 通过）+ 2 simple 直通；1,357,234 tokens / 258 调用 / 58min；E1×3 / E3×6（每实例独立重复 3 次）/ E5×3
- [x] 安全面全达标：人工路由 6/6、引用幻觉 0/20、无依据升级 0、E1 重复完全一致、X2 未因 KEV 虚判（核心验收）、X3 stale_verified 语义与门禁正确
- [x] 未达切换门槛（如实）：影响判定 88% vs 旧 100%、处置适当 65% vs 91%、成本 ≈3.2×/事件、墙钟 ≈27×、E3/E5 重复方差；退化逐案例根因 + 整改清单（验收报告 §9）；**不切换生产入口，等待用户确认**
- [x] 实验暴露并修复 5 项真实缺陷（全部回归锁定）：脚手架 target_ref 保真度 / 脚手架传感器心跳 120s 竞态 / 生产·决策空 verdicts 伪成功（完备性反馈重试）/ 生产·simple 路径 routing_json 缺失 / 生产·state.error 重复定义致并行 reducer 丢失（InvalidUpdateError 崩溃）
- [x] 实验基建：逐案例保存/断点续跑/已完成去重/Token 硬预算 2.5M；3 个归档目录留存缺陷期运行不混入验收
- [x] 回归与安全：全量 **554 passed / 0 failed**（551+3）；Mimosa 深度扫描 0 findings；敏感信息干净；shadow 零副作用
- [x] 待办（已于同日完成）：整改复测（M4.1 校准，见顶部最新完成）

## 最近完成

**Stage 9B：统一四智能体架构重建（唯一编排器落地 + 真实 LLM 对照实验部分完成）**（2026-10-15，设计 IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md、迁移说明 IOT_STAGE9B_MIGRATION_NOTES.md、实验报告 IOT_STAGE9B_EXPERIMENT_REPORT.md）
- [x] 技术选型（实测论证）：**LangGraph 1.2.15**（Python 3.14 实装冒烟通过）为唯一编排器底座——有状态图/条件路由/并行/任务恢复语义与本项目"程序门禁+LLM 分析"形态直译；不选 OpenAI Agents SDK（自由 handoff 与固定管线+程序门禁形态相反）；不选 MS Agent Framework（与 LangGraph 重叠且本仓对 AutoGen 仅有单次 JSON 调用面，无可继承资产）
- [x] 唯一四智能体落地（`backend/app/services/unified/`，11 模块）：asset_investigator（资产与证据调查）/ vulnerability_analyst（漏洞分析，新增只读多源情报包工具含 OpenWrt 公告）/ runtime_analyst（运行时，F6 新鲜度语义）/ decision_planner（研判与处置规划，F4 全上下文+有界补查+白名单待审批计划）；A2∥A3 并行、冲突定向复议≤1、补查≤1、run 级 40 次调用预算、真实 usage 计量、统一 Trace
- [x] 缺陷修复：F1（P0 报告崩溃，list/dict 双形态）、F3（校验失败带错误反馈重试+字段预分拣修 CF6）、F5（fixed/not_affected 不计聚合基线分）、F6（freshness 参与 runtime_status：verified⇒fresh、stale_verified 新状态+门禁）、F7（逐 Agent 独立落库+degraded 保留意见+门禁转人工）、F2/R1（device_context_json 对账写回）、F9（simple 分层 0 次 LLM 直通，immediate_fix 仍强制人工）、§7-7（运行时告警 vs 不受影响交叉冲突强制人工）
- [x] 影子模式与兼容适配层：`LINUXGUARD_UNIFIED_PIPELINE=off|shadow|on`（默认 off 零行为变化）；影子运行零触碰正式字段（逐字段快照对比测试锁定）；flag=on 时 /api/analysis 经 adapter 以兼容契约接统一编排器
- [x] 测试：新增 52 项专项（schema 语义/重试反馈/预算/路由分层/冲突 7 规则/门禁/图拓扑/降级/影子隔离/适配层）；全量回归 **549 passed / 0 failed**（499 基线，零回归）
- [x] 真实 LLM 对照实验（deepseek-v4-flash）：System B 全量 10 事件 44 调用 242,108 tokens 76.0s 完成；统一链 7 次运行（E1×3/E2/E3#0/X1×2）后**账户余额耗尽（402）**，其余运行待充值续跑（脚本已支持 --unified-only/--cases 断点续跑）；人工路由 6/6、引用幻觉 0、E1#1 全链成功且与真值一致
- [x] 实验暴露并修复 5 个统一链真实缺陷（执行基座异常保护回归/解析器 Extra data 容错/决策者误用 CVE 作证据 ID（上下文下发合法 ID 清单）/情报冲突规则过敏收紧/API 限流退化 max_retries=1），全部加回归锁定
- [x] 待办（已于同日完成）：充值后续跑完整对照实验 → 最终验收未达切换门槛，flag=off 维持（见顶部最新完成）

## 最近完成

**第九阶段前置专项：四智能体有效性深度审计（真实代码追踪 + 真实 LLM 消融/反事实实验）**（2026-10-15，报告 IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md；Stage 9B 未启动，等待审阅）
- [x] 静态审计：查明仓库存在**两套"四智能体"体系**——System A 设备编排（services/agents/，真工具循环 14 工具）与 System B 逐风险评审（event_review_pipeline.py，单次类型化 LLM+确定性证据包/门禁），职责互不映射、数据互不流通
- [x] 消费链路核验：System B 输出全链真实消费（风险排序/人工复核/修复授权/Harness 补采复评）；System A 主输出 risk_json 确认为**死端**（仅 AgentOps 展示+一条修复任务写回），其修复智能体实测结构性空转（risk_ref=""、actions=[]）
- [x] 真实实验（deepseek-v4-flash，约 160 次真实调用；合成 CVE/TEST-NET Fixture 隔离参数知识；真值表先于实验独立定义）：A 纯规则处置正确 **2/7**（E3 假阳性 scheduled_fix / E4 无视 under_investigation 冲突 / E5 忽视 72h 过期），B/C 四智能体 **6/7** 且影响判定 7/7、114 条证据引用 **0 幻觉**、0 确定性矛盾；D 组屏蔽任一智能体→建议全部坍缩兜底（人工门禁 100% 保持）；System A 屏蔽 runtime→风险分 62→54、优先级 high→medium
- [x] 反事实 CF1-CF7：矛盾公告（E4）/误匹配候选（E3，impact 智能体定向复议后明确"版本规则命中为假阳性"）/过期监控（E5）三类案例智能体显著优于规则；Zephyr 能力标注入 Trace、其余智能体产出高质量诚实 data_gaps，但 RUNTIME 智能体因 schema extra="forbid" 两次全败（fail-safe 降级无风险虚增）
- [x] 成本与可达性量化：System B ≈2.2-2.5 万 token/事件（4.4 次调用/事件）；System A ≈3.7 万 token/次编排（14 调用/42s）；auto_confirmed 14 事件 0 触发（门禁直方图：high_or_critical_final_score 14/14、confidence_below_0.70 12/14）——LLM 对分数的影响理论性、对建议/路由/补采的影响实在
- [x] 发现 10 项问题（F1 P0：存在 v3 报告后 markdown_report 必崩 AttributeError 已最小复现；F2 双体系死端；F3 System A 重试无反馈；F5 aggregate_risk 不消费 version_impact；F6 证据新鲜度不参与运行时状态等），升级方案 R1-R8（双体系对账/崩溃修复/重试反馈/新鲜度语义/3/4 降级评审/成本分层）；不新增智能体、不换大模型、不动 Harness 门禁
- [x] 零生产代码改动；全量回归 **499 passed / 0 failed** 与基线一致；实验脚本两份入库（backend/scripts/stage9_agent_effectiveness_audit.py、stage9_recompute_metrics.py，无密钥）；原始实验产物（含 LLM 原文）本地 reports/ 留存不入库
- [x] 实验统计器首版 2 处伪报（case 键碰撞+packet 未包裹，首报"50 条无依据断言"）如实留档并离线修正为 0

## 最近完成

**eBPF 2.0 P2-2：OpenWrt 轻量化降级采集（logread 只读）**（2026-10-15，报告 IOT_EBPF2_P22_REPORT.md，证据 reports/ebpf-p22-20261015-111451/ 本地留存）
- [x] 真实链路 21/21 验收：OpenWrt 25.12.5 经既有 DeviceConnection（指纹钉扎+凭据环境变量）只读拉取 logread → 1237 条真实事件全链入库（source=openwrt_logread、观察模式=syslog、资产绑定 1237/1237、SecurityEvidence 1:1）
- [x] 时间/身份语义（不猜测）：设备本地时间按采集偏移换算 UTC（实测 +0000）；缺年份/不可解析行跳过计数不虚构；boot_id 参与指纹（跨重启不误合并，专项锁定）；ring 覆盖丢失 unavailable；窗口元数据留档
- [x] 复用 P0 管线零新表：append_events 既有幂等/绑定/证据链；重复采集全量对账（duplicates+stored_new=窗口行数，会话自身新日志如实说明）
- [x] 智能体数据质量：OpenWrt 缺 logread 采集显式 data_gap；已有则声明"拉取式降级采集、非 eBPF、ring 窗口外不可知"；证据工具实测读取
- [x] CVE/Trace 联调：真实 syslog 证据直接匹配 dropbear（direct_count=57、runtime_status=verified）；统一 Trace runtime_log_collection completed 可查
- [x] 对设备零改动（只读脚本内容哈希入审计）；Zephyr 语义零触碰
- [x] 采集过程发现并修复 2 项真实缺陷：raw 传输标记含 "ssh" 子串致全量误分类敏感文件访问（改名并固化命名约束）；"立即重复"语义修正（SSH 会话自身产生新日志，改为全量对账断言）
- [x] 测试：新增专项 23 项；全量 **499 passed / 0 failed**（476 基线 + 23 新增，零回归）

## 最近完成

**eBPF 2.0 P2-1：性能评测落地**（2026-10-15，报告 IOT_EBPF2_P21_REPORT.md，证据 reports/ebpf-p21-final/ 本地留存）
- [x] 五种评测形态全部真实执行并统一汇总（吞吐/CPU/内存/延迟 P50/P95/P99/事件计数/丢失/重复/spool；0 与 unavailable 严格区分）：synthetic×2（后端摄取）、replay（断网 21.6s 中断恢复+幂等）、real-wsl×2（WSL2 bpftrace 真实内核，4.1 万事件/次，两次独立运行归因对账 0 丢失）、real-vm-falco（VM 常驻 Falco journalctl 拉取，14910 事件，0.021% 丢失如实记录）、bounded-spool（容量不变量+数据保全）
- [x] 实测发现并修复 SQLite 判重全表扫描缺陷（P0 部分唯一索引不被查询计划蕴含推理）：全量索引+旧库幂等补建；EXPLAIN 前后证据 SCAN→COVERING INDEX；后端摄取 115→379 EPS、批 RTT P50 4.3s→1.3s（synthetic 口径，明确不表述为内核采集提升）
- [x] 评测过程暴露并修复 8 项缺陷（含生产脚本缺陷）：wsl 内联转义 EOF、资产登记非幂等、伪造 boot_id 被身份防线正确拒绝、探针健康文件 grep -c 双 0/set -e 中止（collector/ebpf_trace_capture.sh）、falco 消息本地时区（+8h）伪零延迟、对账口径错配、固定 sensor_id 跨运行污染；三次失败尝试完整留档不删除
- [x] bpftrace 成为受支持采集源（心跳 Literal/转发器 choices/观察模式归类 ebpf，真实内核采集不误标 runtime）
- [x] 测试：新增专项 41 项；相关域发现 init_db 幂等契约回归 1 处→根因修复；全量 **476 passed / 0 failed**（435 基线 + 41 新增，零回归）
- [x] VM 连接参数改环境变量注入（私网地址/用户名不写入跟踪文件）
- [x] Mimosa 深度扫描首次成功运行：首轮 4 项高危（SSRF×2/路径穿越/SQL 注入临时文件）→ 全部修复（环回白名单/穿越分量拒绝+输出等价验证/删除遗留临时文件）→ 复扫 0 findings（封印 sha256:430b93f2…ed9c）

## 最近完成

**eBPF 2.0 final C6：回归钩子根因修复 + demo SSH 安全加固**（2026-10-14，提交 de9f1f9）
- [x] conftest 审计钩子环回放行（127.0.0.0/8、::1、localhost、数字 IP getaddrinfo；主机名与非环回连接仍阻断）——根因修复原 19 个既有失败（钩子误杀环回测试桩）
- [x] test_scan_runs 本地 lab 套发现白名单（与同类 execute_scan 测试一致）
- [x] demo SSH 加固：主机指纹钉扎（VM_HOSTKEY_SHA256，fail-closed，替换 AutoAddPolicy）+ sudo 口令仅经 stdin（sudo -S）不进命令行 + 上传脚本 0700；补齐缺失导入（本轮审查发现）
- [x] .env.example 补 VM_HOSTKEY_SHA256 文档
- [x] 全量回归 **435 passed / 0 failed**（原基线 385/19，19 既有失败清零、零新增回归）；修复后 435 收集无导入错误 + 23 项快测复验
- [x] 推送前安全检查通过后推送

## 最近完成

**单一仓库制落地：Public 成为唯一正式开发仓库**（2026-10-14）
- [x] 决策确认：E:\IoTGuard-Public 为唯一正式开发仓库，此后全部开发/测试/Commit/Push 在此进行；双仓同步机制取消（scripts/sync_public.py 已 git rm）
- [x] 完整性核对：Private 跟踪文件清单为本仓库真子集（逐一 comm 比对，零缺失）——代码/文档/测试无需回迁
- [x] Private 独有本地数据归档：local-archive/private-backup-20261014/（历史实验证据 reports/×11、backend/data 数据库、backend/.env、asset_inventory.json，共 59M；.gitignore 排除永不入库）
- [x] backend/.env 就位于本仓库本地，具备独立运行条件
- [x] C1–C5（未推送提交）安全检查通过（无私网 IP/用户名/硬编码密钥/二进制/大文件）后推送 GitHub；本地与远端差 0
- [x] 独立构建/运行/重新 Clone 验证（见下方回归与 Clone 记录）
- [x] 已知事项更新：原 Private 初始提交 a05f3c8 的整改前环境标识问题随双仓取消自然终结（该仓库降级为本地备份，待批准后删除）

## 最近完成

**eBPF 2.0 P1 三轮 + final C1–C5 补记**（2026-10-14 晚，提交 f8b9f80…5a9244b，均已推送）
- [x] P1 准备轮（f8b9f80）：探针增强（execve argv / process start_time / 会话键）+ Falco 部署包（collector/deploy/falco/）
- [x] P1 部署验收（8cfd519）：Ubuntu VM Falco 0.44.1 真实常驻部署全链路（>10 分钟）；2418 真实事件=2418 SecurityEvidence（1:1）；8 规则命中（sshd→bash / bash→curl / sudo→sh→cat shadow 全链自然触发）；drops 真实指标闭环
- [x] P1 稳定性收尾（1368fae）：弃用临时 SSH 反向隧道改 VMnet8 直连；spool 续传对账 34/34 精确入库、双表 1:1（6071=6071）、全库重复 0；开机自启 + kill -9/SIGTERM 自动恢复（数据缺口<2s）+ SIGINT 干净停止；32 分钟连续运行 2619 条真实事件；修复 3 处真实缺陷（前台阻塞吞 SIGTERM/停止摘要竞态/falco 摘要污染 rejected）；回归 385/19 与基线零差异×2
- [x] final C1（a0b5ac3）：write-ahead spool（事件先持久化后发送，服务端确认后移除；SIGKILL 仅丢管道尾部，重放由服务端幂等去重）+ 有界 spool（条数/字节/磁盘三重上限背压）+ 运行中自愈；专项 12 项含真实 SIGKILL 硬杀恢复对账
- [x] final C2（fa0886d）：connect retval==0 守卫（立即失败连接不再产生网络事件）；WSL2 6.6.87.2 真实内核双模式验证（黑洞路由 ENETUNREACH→0 事件）；已知边界如实记录（回环异步 RST 不可过滤）；验证脚本 collector/ebpf_p24_verify.sh
- [x] final C3（aeae6df）：SecurityEvidence 增 process_exec_id/parent_exec_id（列迁移幂等，evidence_hash 基不变零漂移）；evidence_sessions() 按进程会话键聚合，PID 复用不合并，legacy 行如实标注不足身份
- [x] final C4（c24f410）：package_match_reasons() 抽取为 CVE×运行时匹配单一语义源；cve_runtime_evidence() 下钻 + GET /runtime/cve-evidence 端点 + 行为链详情页下钻块；exploitation_confirmed 恒 False 诚实边界
- [x] final C5（5a9244b）：query_runtime_data_quality 智能体工具（覆盖/心跳/真实 dropped（0 与 unavailable 严格区分）/证据新鲜度/显式 data_gaps）；未知名 found=False 不编造报告

## 最近完成

**Git 完整托管与自动同步机制建设**（2026-10-13，历史记录；该机制已于 2026-10-14 取消）
- [x] 整改提交 6f4724b 推送 Private
- [x] ai_collaboration/ 协作文件、GitHub 模板（Issue/PR）、CI 工作流
- [x] scripts/sync_public.py 自动同步脚本（流式导出+敏感扫描+增量推送，幂等）
- [x] Public 仓库建立（PUBLIC、独立历史）并完成首次同步（223 文件，来源哈希可追踪）

## 最近完成

**第六阶段：OpenWrt 异构终端真实接入**（2026-10-13，证据 reports/openwrt-live-*，本地留存）
- [x] 环境：复用运行中的 OpenWrt 25.12.5 VM（VMnet2 实验段），TCP 22/80/443/53 全通
- [x] 主机指纹：SSH 握手取证与历史受信记录完全一致（ed25519）
- [x] 自动发现：真实 API 双 /25 扫描 → 观察证据 → 协议指纹（dropbear/http/https）→ IotDevice 建档（16/16 验收点）
- [x] CVE 分级诚实呈现：dropbear 横幅无版本 token → 组件无版本证据 → 按规则延迟匹配（非伪造零命中）
- [x] 复扫幂等、未授权网段 400、零修复/Harness 副作用
- [x] 回归：后端 81 项 + SmartCam 真实闭环 16/16，无新增回归
- [x] **阻塞已解除（同日）**：根因为 id_ed25519_vms 非默认身份名且 agent 停用（历史 BatchMode 从未真正提供该钥匙）；显式 `-i` 认证即成功，Ubuntu 零改动
- [x] 主机线补全：SSH 隧道 → 既有 collection_only 节点 → 复用采集任务 2 次真实采集（host identity verified / 密钥认证 succeeded / 182 包 / collector exit 0）
- [x] 幂等：同 request_id 复用同任务不重放 SSH；新 request_id 二采不重复建档（assets=1/connections=1）
- [x] 身份链闭合：采集 MAC 与 VMware .vmx 网卡地址逐字一致；主机指纹与受信记录一致
- [x] 新旧对比：181/182 一致 + 1 处真实包变化（kmod-nls-iso8859 → kmod-nls-iso8859-1）
- [x] CVE 分级消费：本轮快照入引擎（幂等 0 伪造结论；全部落在"无充分证据"层——未登记公告/情报）

## 最近完成

**第七阶段：Zephyr RTOS 终端接入**（2026-10-13，部分完成）
- [x] Zephyr v4.4.2 + SDK v1.0.1（模块化免 root 部署，Ubuntu 用户空间）
- [x] Zephyr-Sensor-01 固件：真实 Zephyr 应用（TCP 服务线程 + DHCP + 模拟传感 + /api/system 身份 JSON），qemu_x86_64 构建成功（5.7MB ELF + 28KB locore）
- [x] 后端适配：capabilities OS 能力画像（增量字段）+ discovery_pipeline Zephyr 能力边界标注（ssh/package/eBPF = unsupported）
- [x] device_inventory 增强固件扩展元数据（board/soc/arch/build_id/telemetry→metadata）
- [x] Mock 测试 5 项 + 回归 26 项全过（发现→Zephyr 身份→建档→版本化组件→CVE 三层→双实例不合并→幂等→能力画像）
- [x] **West Workspace 补充轮（同日）**：手动创建 .west 工作区（绕过 git 依赖）→ hello_world 以 west build + 正确 QEMU 参数启动 ✅；根因更正：CONFIG_NETWORKING=y 隐式启用 e1000 驱动导致 x86_64 内核崩溃（非体积阈值）
- [ ] ~~最终阻塞：QEMU 网络连接（xilinx-aarch64 FDT 机器不接受命令行 netdev 挂载）~~ → **已于 2026-10-14 解除**（系统 qemu-system-arm + xilinx-zynq-a9 + `-nic model=cadence_gem`，见下方完成记录）；勘误：该轮"qemu_cortex_a9 构建成功"无产物支撑（半成品），2026-10-14 重建才真正完成

## 最近完成

**第七阶段完成：Zephyr RTOS 真实端到端联调**（2026-10-14，证据 reports/zephyr-live-20261014-085507/，本地留存）
- [x] 阻塞解除：Ubuntu 24.04 VM 安装 qemu-system-arm 8.2.2 / gcc / build-essential（用户执行）；SSH 重连（显式 id_ed25519_vms）
- [x] qemu_cortex_a9 固件真实构建：arm-zephyr-eabi + 完整网络栈（eth_xlnx_gem + DHCPv4 + TCP Sockets）；修正 CMSIS 模块布局（对齐 west 清单路径）+ .west 工作区 + stage7-cmsis-wiring 接线模块（源码包部署环境缺口，非上游组件）
- [x] Zephyr 树补丁 patches/0001：soc.c 在 GEM 启用时映射 SLCR（上游缺口：驱动初始化写 GEM 时钟分频寄存器 0xf8000140，未映射 → 裸启翻译错误）
- [x] 固件真实缺陷修复：/api/system JSON "port" 键重复（真实探测暴露，mock 不可见）；arch 改为编译期如实上报（arm）
- [x] QEMU 启动：系统 qemu-system-arm xilinx-zynq-a9 + `-nic user,model=cadence_gem`（SoC 内建网卡挂载）+ SLIRP hostfwd 8080→:80；串口证据：Booting Zephyr OS 4.4.2 → dhcp ok → http on :80
- [x] 真实网络：Windows 后端 → VMnet2 → Ubuntu 宿主（VMnet2 地址:8080）→ QEMU 固件（跨主机真实 TCP/HTTP，遥测值实时变化）
- [x] 自动发现→建档：/25 真实扫描（≤128 地址）→ identity_source=device_identity_endpoint、置信 0.9、os=Zephyr RTOS 4.4.2、固件元数据（board/arch/build_id/telemetry simulated）、版本化组件×2、能力三项 unsupported 如实标注
- [x] CVE 分级：清洁库诚实零命中（无证据≠无漏洞）+ TEST-FIXTURE 三层（厂商精确 affected/0.95、NVD 候选 potentially_affected、无关不出现；夹具仅存一次性临时库）
- [x] 幂等：复扫 enrolled_new=0、设备唯一、组件无重复（复扫自动重跑设备匹配）
- [x] 边界：未授权网段 400、harness/remediation 零副作用、NAT 拓扑与宿主服务混入如实记录于证据（具体地址见本地证据）
- [x] 验收 20/20 ALL PASS（backend/scripts/stage7_zephyr_live.py）+ 回归 26/26 复跑通过
- [x] 勘误：上一轮"qemu_cortex_a9 构建成功"无产物支撑（build-arm 为 Kconfig 阶段失败的半成品），本轮为首次真实完成

## 最近完成

**第八阶段：统一任务 Trace 与可观测性系统**（2026-10-14，证据 reports/stage8-trace-20261014-094539/ 本地留存）
- [x] 统一 Trace 数据结构：trace_run（trace_id/任务类型/资产标识/运行标识/Harness 关联/起止/状态/汇总）+ trace_event（seq 顺序/actor/is_llm_step/payload/证据引用/耗时）；旧表（AgentAuditRecord/AgentOrchestrationRun/HarnessRun）不动，仅增量 trace_id 列（SQLite ALTER 兼容），旧记录不回填不伪造
- [x] 四智能体追踪：start_analysis 生成唯一 trace_id；agent_started/finished/failed + 阶段/交接事件；LLM 调用真实统计（DeepSeekChatClient 透出真实 usage；无依据 unavailable）；程序步骤 is_llm_step=false 不伪装；失败/超时/证据校验错误如实入 Trace
- [x] Harness 关联：create_run 可选 trace_id（空=旧路径零影响）；计划生成/审批通过与拒绝（policy_blocked）/工具调用（开始/结束/失败）/预算拦截/执行收口/回滚/超时恢复全部事件化；安全行为（计划哈希审批绑定/资产锁/预算/写开关/不重放写操作）零变更
- [x] 设备管线 Trace：discovery_enrollment / device_refresh / device_cve_match 三类任务；Zephyr 能力 unsupported（ssh/package/eBPF）如实 capability_marks 入 Trace
- [x] Trace API（/api/traces*，7 端点）：列表分页+过滤/详情/时间线/智能体事件/Harness 关联（not_requested/not_applicable 诚实语义）/证据解析（unresolved 如实）/汇总统计；payload 写入端脱敏（敏感键分词匹配）+16KB 限长；索引齐备
- [x] AgentOps 前端四区域：任务总览（真实统计）/智能体时间线（28 事件含 LLM 标记与真实模型耗时）/Harness 安全监控（关联状态+工具调用+策略拦截）/证据关联（SE-/CVE 解析+资产跳转）；loading/empty/error 状态；无静态演示数据
- [x] 真实只读安全评估演示：真实发现入档 Zephyr 设备 → 真实 DeepSeek 四智能体分析（4/4 真实 token 用量）→ Trace 全链路验收 ALL PASS；浏览器实测前端展示（截图本地留存）
- [x] 测试：专项 test_trace_system 15/15；全量回归 356 passed（19 失败均为既有已知冲突文件，改动前基线 33 失败——无新增回归）；前端构建通过
- [x] 诚实性修复：成功路径 LLM 统计回填补齐（真实 model/tokens 不再显示 unavailable）

## 最近完成

**eBPF 2.0 审计轮：源码审计、真实验证与升级设计**（2026-10-14，报告 IOT_EBPF2_AUDIT_REPORT.md，证据 reports/ebpf-audit-20261014/ 本地留存）
- [x] 十项逐一审计（真实源码/挂载点、真实vs模拟、Falco 现状、信息面、存储绑定、丢失重复缺失、CVE 消费、Runtime Agent、前端数据源、三端能力）——每项含路径/函数/调用链/验证结果
- [x] 真实验证：40 条真实内核事件全链回放；WSL root 全新探针采集；风险引擎正/负例消费（verified/not_observed）；发现 D1 幂等破坏等 9 项缺陷
- [x] 对标矩阵（Tetragon/Falco/Tracee/Hubble，官方文档依据）+ 差距四级分级
- [x] P0/P1/P2 升级设计（复用 Falco 为主、新增探针仅 2 处、默认只读）+ 每项验收方法 + 性能评测方案 + 兼容性分析
- [x] 零功能代码改动（仅报告与文档）；阶段七/八功能无回归面

## 最近完成

**eBPF 2.0 P0：运行时证据可靠性升级**（2026-10-14，报告 IOT_EBPF2_P0_REPORT.md，证据 reports/ebpf-p0-20261014/ 本地留存）
- [x] D1 修复：三层身份分离 + 双表回绑 + 并发兜底；真实复现 40→80 → 修复后四次重放 40/40/0
- [x] 迁移 v2：指纹重算/精确去重（绑定无歧义传递）/证据精确回绑/标记幂等（旧库专项测试覆盖）
- [x] 转发器 2.0：批量+退避重试+spool 续传+ack 确认（"已发出"≠"已确认"）；断网真实场景验证
- [x] 可靠性指标：心跳计数+bpftrace 丢失解析+可靠性端点；0 与 unavailable 严格区分（实测两态）
- [x] 清空语义：作用范围明确（仅事件流）；证据审计引用保留（测试覆盖 Trace/复核不破坏）
- [x] 测试：专项 18/18 + 契约 5/5 + 相关 92/92 + 全量 374/19 与基线一致（零新增回归）
- [x] 旧 API/旧心跳/旧转发器路径全部兼容

## 下一步（等待审阅，不自动开始）

- **Stage 9B M4 后续（等待用户指令）**：按 IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md §9 五项整改 → 以同一 Fixture/真值表/脚本复测 → 达标后经用户确认 flag=on 正式切换 → M5 按退役清单摘除旧编排器；**当前 flag=off，旧链路（System B）仍为正式入口**
- Private 仓库删除申请：本仓库独立 Clone/构建/运行验证与归档核验已通过，可向用户提交删除申请
- P2-1 遗留（低优先）：后端摄取上限 ~380 EPS（SQLite 单进程）扩展评估；falco 引擎级 drops/CPU 采样待 sudo 授权窗口；bounded-spool 告警触发路径的真实触界复现（当前由单元测试覆盖）
- P2-2 遗留（低优先）：logread 拉取式采集无常驻增量（设备只读不留状态，设计边界）；真实设备重启演练未执行（避免干预，语义由专项测试锁定）

## 已知事项

- ~~后端 4 个真实套接字测试文件与 conftest 审计钩子冲突~~ → **已根因修复**（de9f1f9 环回放行；全量 435/0）
- 已推送的 P1 部署/稳定性报告（f8b9f80…1368fae）含实验室 VMnet8 私网地址与 VM 用户名（具体值见那些报告，此处不再复写）——RFC1918 实验网段、不可公网路由，已如实告知用户；后续报告遵循"具体地址仅存本地证据"惯例，不再写入跟踪文件
- Mimosa 完整项目扫描仍不可用（python_ast_unavailable）；本轮推送以人工多维敏感扫描（凭据/私网标识/密钥材料/二进制/大文件）为闸门，如实记录，不宣称全局安全审计已完成
- 竞赛章程对公开时点的要求待用户确认
