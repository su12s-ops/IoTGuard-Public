# 变更日志

> 重要版本变化，新条目置顶。格式：日期 / Commit / 变更。

## 2026-10-16 — Stage 9B M4.3：核心业务主链集中建设（真实设备检测、四智能体研判与安全修复闭环；OpenWrt+Ubuntu 双真实链路打通；655 回归零失败；flag=off 维持）

- **P0 OpenWrt 真实链路**：授权网段发现入档 → 操作员 SSH 只读采集（ED25519 指纹钉扎 + 固定 Collector stdin 下发，27KB 真实清单）→ 官方上传 API 建档（LinuxAsset id=2，182 真实包）→ CVE 匹配真实零命中（OpenWrt 主机线仅认 openwrt.org 公告，不可达且不合成）→ logread 证据入库（1304 行，幂等）→ 统一四智能体影子研判消费真实 logread 证据（runtime 分析师 5 工具 6 发现全挂真实证据 ID）
- **P1/P2 Ubuntu 真实链路**：dpkg 采集（1790 包）→ 真实情报（本地存档 588 行 + NVD/KEV/EPSS 线上同步 349 条）→ 377 匹配/125 真实风险 → 影子 risk_review 多轮全链成功（CVE-2026-63073 openssl：potentially_affected 不虚判 / stale_verified 诚实降级 / static_evidence_only → scheduled_fix / 门禁 pending_human_review / 待审批计划 requires_approval 程序强制）；溯源链资产→CVE→证据 ID→四 Agent→门禁→结论→计划全程可核（43 引用证据全真实、Trace 22/22）
- **P3 Harness 闭环（零设备写）**：调查任务只读执行+证据包挂接 / 修复前置门禁 blocked+执行 409 / 伪造审批哈希 409 / 调查计划拒绝修复式授权 / Windows 采集节点策略边界如实演示
- **前端**：AgentOps 新增「统一编排（影子）」页签 + 风险详情「09 统一四智能体影子研判」区块（只读；`GET /api/unified/runs` 增加 risk_id/target_ref 过滤）；浏览器实测渲染通过
- **E2E 暴露并修复 3 项真实缺陷（回归锁定）**：情报同步重复行崩溃（autoflush=False 同轮重复建行 → 二次同步 one_or_none 抛错；first()+flush）/ 设备身份降级（弱探测轮覆盖已识别身份；upsert 防降级）/ 设备线↔主机线证据键失配（logread 锚定设备自报主机名，经同 IP 资产+指纹钉扎 DeviceConnection 双向传递证据键）
- **回归与安全**：全量 **655 passed / 0 failed**（650+5 新增）；E2E 38 项检查全通过；Mimosa 0 findings（scan-…-b7c5bff9c409，seal sha256:52fbd4fb…e18a7）；敏感信息干净；影子零触碰正式字段；交付 IOTGUARD_CORE_E2E_REPORT.md + backend/scripts/m43_core_e2e.py；本轮结束即停止

## 2026-10-16 — Stage 9B M4.2 主轮+收尾闭环：统一四智能体研判质量深化与质量闭环验收（遗留实验全部补齐；Y6 反事实修正 2×2；Runtime Agent 正向贡献度量；650 回归零失败，维持 flag=off）

- **主轮（42fe3b1 实现/真值先验 + 22045b8 报告/脚本修复，补记归档）**：四 Agent 专业分工 Schema（资产三级证据分级、漏洞四专业维度含 backport、运行时逐条 relation 九态、决策四维 DimensionAssessment）+ 确定性事实层扩展（紧迫性放大因子 KEV∨公网×CVSS≥9.0、below_range、源立场冲突、public_services 预取）+ 四类决策约束/门禁 + 冲突规则 8 + 路由反向修正 + Y1–Y10 独立案例（真值表先验 42fe3b1 先于任何模型运行）；主矩阵 19 全链 impact/action 19/19、人工 5/5、幻觉 0、方向 14/19；全量 637 passed；Mimosa 0 findings
- **收尾（9f9e2e6 先验设计 → d306622 脚手架修复 → 5ab79e1 退化检测 → 收尾提交）**：
  - 离线核查：31 运行/432 调用/3,394,004 tokens 全对账；三口径差异机制解释（meter 含零 token 失败调用 10 次；逐 Agent 表=每角色末次调用，差 202 次为覆盖语义）；更正主报告两处口径（E3 零方差=LLM 4/4；逐 Agent 表范围）
  - 遗留补齐（真实 LLM 全落真值）：E4a/E4b 两跑一致 potentially+mitigate+人工；X2 全对（KEV 未虚判）；X3 全对（stale 不驱动 immediate）；Y4/Y10 资产消融=判定不承重、校准承重（Y10 隐藏后置信度 0.62→0.70 膨胀）
  - Y6 反事实修正：原单因素设计 SUPERSEDED 留档；新 2×2 四格先验真值先于实验；确定性放大因子断言 4/4 PASS；LLM 处置与因子存在性一一对应（kev0_pub1 证伪「去 KEV 必降」；kev0_pub0 确定性门禁拦下 immediate）
  - Runtime Agent 正向贡献（RT-A/B/C/D 同构反事实，rt2- 最终样本）：完整管线 impact/action 4/4（方向 3/4）；RT-D 隐藏运行时分析师后崩为 insufficient=承重实证；RT-B/RT-C 程序事实已足够；RT-A 贡献=新鲜度核实、关联偏保守如实记录
  - 方向四层分析：E1 封顶/方向分离双向实证；E5「监控过期→降风险」混同确认（方向最弱项，改进需另建评分规范）；全部偏差无一起无依据升级
  - 缺陷（全部回归锁定+污染集留档+受影响运行重跑）：Y Fixture 证据层时间戳为空（预存，已记录 Y 结论不受影响）/ RT 心跳 120s 竞态 / 运行时分析师 Schema 回显退化检测
- **回归与安全**：全量 **650 passed / 0 failed**（637+13 终态复跑）；Mimosa 深度扫描 **0 findings**（scan-2026-10-16T06-22-58.264Z-997fe0409b11，seal sha256:9d3c421e…de2d0a，123 依赖包）；敏感信息干净；shadow 零触碰；累计真实成本 ≈7.51M tokens（meter，含重试）
- **边界**：`LINUXGUARD_UNIFIED_PIPELINE=off` 保持；不删旧编排器；不启动真实设备 Shadow；切换准备状态=候选具备（人工决策）；交付 IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md + stage9b_closure_{cases,experiment,stats}.py + test_closure_counterfactuals.py（13 项）；本轮结束即停止

## 2026-10-15 — Stage 9B M4.1：统一四智能体研判校准与成本治理（影响判定首次达标；成本/处置差一步，维持 flag=off）

- **第一部分 统计口径修正（离线零 LLM，新脚本 backend/scripts/stage9b_calibration_stats.py）**：M4 全部 20 次运行重建五类口径——全链 LLM 14 / 程序兜底 3（**实为 E3a×2+E3b×1，修正 M4 报告"E3a 三次"误记**）/ 消融 1 / simple 2；LLM-only 修正口径：影响 85.7%（原混合 88.2%）、处置 57.1%（原 64.7%）——兜底判定不得混入 LLM 准确率；耗时口径澄清（7.6s=76.0s/10 事件全量口径；104.1s 合并口径=9.46s/事件）；调用双口径如实（meter 258=237 评审+21 消融；client 246）；原始存档与真值零改动
- **第二部分 五类决策缺陷通用语义修复（零 case_id 硬编码；确定性事实+程序校验+fail-closed 门禁三层）**：E3 分支排除声明确定性提取比对（branch_excluded 不得被通用 NVD 匹配推翻）/ E4 厂商冲突预检（装机≠适用确认；冲突未消解禁 confirmed 与修复处置）/ E5 verdict 新增 runtime_evidence_validity+urgency_basis 分离字段（stale_verified 不作活跃利用依据；静态证据独立支撑的紧急建议不一刀切禁止但强制人工）/ X2 确定性 fixed 语义（KEV 不改变已修复）/ X3 过期证据≠适用性不足；门禁新增 7 类确定性矛盾理由；程序兜底裁定显式 program_fallback 标记
- **第三部分 Evidence Preparation（非第五个 Agent）**：LangGraph 新增 prepare_evidence 确定性节点（backend/app/services/unified/evidence_prep.py）——复用只读工具/多源情报包（get_source_bundle 含 OpenWrt 公告）/SecurityEvidence/版本比较；运行内只读复用、新鲜度按当前时间重算、有界（组件≤60/证据 ID≤30/记录≤12）、失败退回自主查询；逐 Agent 前后对照：资产工具 90→76（-15.6%）、专家延迟 -17%~-27%、墙钟/评审运行 -7.8%、全链口径 token 93.0k→88.5k（-4.8%）——评审运行口径 +15.6%，成本"实质改善"未达（✗ 如实判定）
- **第四部分 稳定性**：异常重试 1s 退避；人工门禁 fail-closed 扩展；预算/时限/降级/消融路径全保持；本轮 0 次 API 故障、0 兜底
- **第五部分 真实 LLM 复测（Fixture/真值零改动，22 次运行全 completed，0 失败 0 触界）**：矩阵 17 全链+2 simple+1 消融 + E4 缺陷修复补充 2；**影响判定（配对）9/9 vs System B 7/7 首次达标**；X2 not_affected+monitor 零超集、X3 回到真值、E5 处置 3/3 零方差、E4 修复后 5/5 全对、E3b 三跑全部识破误匹配；处置（配对）8/9 仍差 1 例（E2 静态紧迫性超集）；引用幻觉 0/20（2 例评分器假阳性已对齐）；稳定性达标（E1×3/E5×3 全一致、0 兜底）
- **本轮暴露并修复 1 项真实缺陷（回归锁定+真实复测）**：E4 厂商冲突漏检——get_source_bundle release 作用域 canonical value 为单记录形态，detect_vendor_conflict 只读 records 漏检；兼容两种形态后 E4a/E4b 真实复测 5/5 全对且两跑一致
- 回归与扫描：全量 **589 passed / 0 failed**（554 基线 + 35 项校准专项 tests/test_evidence_prep.py）；Mimosa 深度扫描 0 findings（seal sha256:edb186b2…529f1b）；shadow 零副作用
- 门槛判定：影响 ✓ / 稳定性 ✓ / 安全面 ✓ / 处置 ✗（差 1 例）/ 成本 ✗（非实质）→ **维持 LINUXGUARD_UNIFIED_PIPELINE=off**；遗留四项（static_evidence_only 放大因子前提 / E3a 残余方差 / 方向口径对齐 / 预取切片瘦身 ≤60k/评审运行）见校准报告 §9
- 交付 IOT_UNIFIED_FOUR_AGENT_CALIBRATION_REPORT.md（12 章校准 + 诚实性声明）；System B 对照零新增调用（复用 M4 已核查留档）；本轮结束即停止

## 2026-10-15 — Stage 9B M4：统一四智能体最终验收实验完成（全部 10 事件；未达切换门槛，维持 flag=off）

- 充值恢复后完成全部真实 LLM 对照实验：10 事件（E1/E2/E3a/E3b/E4a/E4b/E5/X1/X2/X3）20 次运行全 completed（14 全链 + 3 次 API 故障程序兜底 + 1 屏蔽消融 + 2 simple 直通），1,357,234 tokens / 258 调用 / 58min；X2 案例（KEV+装机已修复）为本轮按架构 §9 补齐的 Fixture
- 安全面全部达标：人工路由 6/6、引用幻觉 0/20（评分器对齐 runner known_evidence_ids 后复评）、无依据升级 0、E1 重复 3/3 完全一致且真值全对、F7 屏蔽消融通过、fail-safe 兜底 3/3 落真值
- 质量/成本/稳定性未达切换门槛：影响判定 88%（System B 100%）、处置适当 65%（91%）、单事件 token ≈3.2×、墙钟 ≈27×、E3/E5 重复呈 2–3 值方差；退化逐案例定位根因（处置校准/纯 NVD 单次方差/已修复语义保守化），整改清单见验收报告 §9；**LINUXGUARD_UNIFIED_PIPELINE 保持 off，等待用户确认后再议迁移**
- 实验暴露并修复 5 项真实缺陷（全部回归锁定）：脚手架 target_ref 保真度（"fixture"→资产 hostname）、脚手架传感器心跳 120s 竞态、生产·决策空 verdicts 伪成功（完备性反馈重试，2 测试）、生产·simple 路由不落 routing_json/decision_json（对齐+测试）、生产·state.error 重复定义致并行错误合并 reducer 丢失（InvalidUpdateError 崩溃，测试锁定）
- 实验基建：断点续跑/已完成去重/Token 硬预算（2.5M 上限，本轮未触界）/逐运行落盘；3 个归档目录留存缺陷期运行（targetref-defect / heartbeat-race / network-outage），不混入验收样本
- 回归与扫描：全量 **554 passed / 0 failed**（551 + 3 新增）；Mimosa 深度扫描 0 findings（seal sha256:448f342c…2394）；敏感信息扫描干净；shadow 零副作用测试锁定
- 交付 IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md（10 章验收 + 切换/回滚方案 + 诚实性声明）；System B 上一轮全量对照经代码版本核查保留，X2 由本轮同配置补充（23,142 tokens）

## 2026-10-15 — Stage 9B：统一四智能体架构重建（M0-M4 部分，LangGraph 唯一编排器）

- M0（f6bd0ef）：IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md——LangGraph 选型实测论证（Python 3.14 + 1.2.15 冒烟）、四 Agent Schema/路由/预算/影子-切换-退役/验收设计；对比否决 OpenAI Agents SDK 与 MS Agent Framework
- M1-M3（9185144）：`backend/app/services/unified/` 唯一编排器（LangGraph 单图 9 节点、asset_investigator/vulnerability_analyst/runtime_analyst/decision_planner 四角色、A2∥A3 并行、有界复议/补查、UsageMeter 预算、统一 Trace）；F1/F3/F5/F6/F7/F9 与 §7 八问题修复；`UnifiedAnalysisRun` 影子表 + `LINUXGUARD_UNIFIED_PIPELINE=off|shadow|on` 开关 + /api/analysis 兼容适配层 + F2/R1 device_context_json 对账列；前端角色映射与品牌统一；新增 52 项专项测试，全量 **549 passed / 0 failed**（499 基线零回归）
- M4 部分：真实 LLM 对照实验（backend/scripts/stage9b_unified_compare.py，可复跑+断点续跑）——System B 全量 10 事件 44 调用 242k tokens 完成；统一链 7 次运行后 DeepSeek 账户余额耗尽（402），剩余运行待充值；部分数据显示人工路由 6/6、引用幻觉 0、E1#1 全链成功与真值一致；实验暴露并修复统一链 5 项真实缺陷（图节点异常保护回归/解析容错/决策证据 ID 清单下发/情报冲突规则收紧/限流 max_retries=1）；IOT_STAGE9B_EXPERIMENT_REPORT.md 如实留档，不含未完成部分的结论
- 诚实性：样本量不足以判定新旧优劣，正式入口保持 System B（开关默认 off）；所有失败运行原文留档未删除

## 2026-10-15 — 第九阶段前置专项：四智能体有效性深度审计（零生产代码改动，Stage 9B 未启动）

- 交付 IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md：双"四智能体"体系架构核验（System A 设备编排=真工具循环、System B 逐风险评审=单次类型化 LLM+确定性证据包/门禁）、逐智能体输入→工具→输出→消费追踪、摆设化明确结论
- 真实实验（deepseek-v4-flash，约 160 次真实调用；合成 CVE/TEST-NET Fixture；真值表先于实验定义）：消融 A/B/C/D + 反事实 CF1-CF7 + System A 屏蔽。核心数字：规则处置正确 2/7 vs 智能体 6/7（影响判定 7/7）；114 条证据引用 0 幻觉、0 确定性矛盾；屏蔽任一 System B 智能体建议全坍缩（人工门禁保持）；System A runtime 屏蔽 62→54 分；auto_confirmed 0/14（门禁直方图留档）；成本 System B ≈2.2-2.5 万 token/事件、System A ≈3.7 万 token/编排
- 关键发现：E3 误匹配候选上智能体纠正规则假阳性（定向复议后"版本规则命中为假阳性"）；E4 矛盾情报/E5 过期监控均被保守路由而规则无视；F1 P0 缺陷（存在 v3 报告后 markdown_report 必崩 AttributeError，最小复现）；System A risk_json 死端、remediation 智能体结构性空转、Zephyr 场景 RUNTIME 智能体 schema 两次全败；证据新鲜度不参与运行时状态语义
- 新增（非生产代码）：backend/scripts/stage9_agent_effectiveness_audit.py（可复跑实验 Harness：Fixture/消融/反事实/Token 计量）、backend/scripts/stage9_recompute_metrics.py（证据包离线对齐的修正统计）；原始实验产物本地 reports/ 留存不入库
- 诚实性：实验统计器首版 2 处伪报（首报"50 条无依据断言"）如实留档并离线修正为 0；单次运行方差（E3b 方向 1 例变差）如实标注
- 回归：全量 **499 passed / 0 failed** 与基线一致（零改动生产代码）

## 2026-10-15 — eBPF 2.0 P2-2：OpenWrt 轻量化降级采集（logread 只读，21/21 真实验收）

- 真实链路：OpenWrt 25.12.5 经既有 DeviceConnection（SSH 指纹钉扎+凭据环境变量）只读拉取 logread → P0 统一事件管线（零新表零新库）；1237 条真实事件入库、资产绑定 1237/1237、SecurityEvidence 1:1；对设备零改动、零 eBPF、零软件包（报告 IOT_EBPF2_P22_REPORT.md，证据本地留存）
- 时间/身份诚实语义：设备本地时间按采集偏移换算 UTC；缺年份/不可解析行跳过计数不虚构；boot_id 参与指纹（跨重启不误合并）；ring 覆盖丢失 unavailable；source=openwrt_logread/观察模式 syslog，绝不伪装 eBPF
- 集成：智能体数据质量（缺采集显式 gap；已有声明降级边界非 eBPF）；CVE 下钻真实 syslog 证据直接匹配 dropbear（direct_count=57 verified）；统一 Trace runtime_log_collection；coverage/reliability 含 logread 心跳语义
- 修复 2 项真实验收发现缺陷：raw 传输标记含 "ssh" 子串致全量误分类敏感文件访问（1246 条→修正，命名约束固化）；立即重复采集的全量对账语义修正（SSH 会话自身新日志如实计数）
- 测试：新增专项 23 项；全量 499 passed / 0 failed（476 基线 + 23 新增，零回归）；设备重启语义由专项锁定（真实重启未执行，避免设备干预）

## 2026-10-15 — eBPF 2.0 P2-1：性能评测落地（五形态实测 + 判重索引缺陷修复）

- 五种评测形态全部真实执行（synthetic×2 / replay 断网恢复 / real-wsl×2 真实内核 / real-vm-falco / bounded-spool），统一汇总吞吐/CPU/内存/延迟/丢失/重复/spool，0 与 unavailable 严格区分；synthetic 优化明确不表述为内核采集提升（报告 IOT_EBPF2_P21_REPORT.md，证据 reports/ebpf-p21-final/ 本地留存）
- 修复实测发现的 SQLite 判重全表扫描：P0 部分唯一索引不被查询计划蕴含推理 → 补全量索引（models index=True + 旧库幂等补建，EXPLAIN SCAN→COVERING INDEX 回归锁定）；后端摄取 115→379 EPS、批 RTT P50 4.3s→1.3s
- 修复 8 项评测链缺陷（3 次失败尝试留档）：wsl 内联转义、资产非幂等、伪造 boot_id 注入（身份防线正确拒绝）、ebpf_trace_capture.sh 健康文件 grep -c 双 0 + set -e 中止（生产脚本）、falco 消息本地时区 +8h 伪零延迟、对账口径错配、固定 sensor_id 污染；bpftrace 采集源标识补全（心跳/转发器/观察模式）
- VM 连接参数改环境变量（LINUXGUARD_PERF_VM_HOST/USER/API），私网地址与用户名不再写入跟踪文件
- 测试：新增专项 41 项；全量 476 passed / 0 failed（435 基线 + 41 新增，零回归；期间发现并根因修复 init_db 幂等契约回归 1 处）

## 2026-10-14 — 单一仓库制落地（Public 为唯一正式开发仓库）

- 决策：所有开发/测试/Commit/Push 在本仓库进行；双仓同步机制取消，`scripts/sync_public.py` 删除
- 完整性核对：原 Private（IoTGuard-Project）跟踪文件清单为本仓库真子集（逐一比对零缺失）；其独有本地数据（历史证据 reports/×11、backend/data、backend/.env、asset_inventory.json，共 59M）归档至 `local-archive/private-backup-20261014/`（.gitignore 排除，永不入库）
- C1–C5 补推：安全检查通过（无私网 IP/用户名/硬编码密钥/二进制/大文件）后推送 1368fae..5a9244b，本地与远端差 0；P1 部署/稳定性报告（已推送）含实验室 VMnet8 私网地址与 VM 用户名，如实告知，后续报告具体地址仅存本地证据
- 原 Private 降级为临时本地备份（E:\IoTGuard-Project，内容冻结不动）；删除须待本仓库独立构建/运行/重新 Clone 验证与归档核验通过，并经用户逐项批准

## 2026-10-14 — eBPF 2.0 P1 + final C1–C5（提交 f8b9f80…5a9244b，均已推送）

- P1 准备/部署/稳定性三轮：探针增强（execve argv/start_time/会话键）；Ubuntu VM Falco 0.44.1 真实常驻（2418 事件=2418 证据 1:1，8 规则命中全链）；VMnet8 直连 + 开机自启 + kill -9/SIGTERM 自愈（缺口<2s）+ 32 分钟连续运行 2619 真实事件；修复 3 处真实缺陷；回归 385/19 零差异×2（报告 IOT_EBPF2_P1_PREP/DEPLOY/STABILITY_REPORT.md）
- final C1 write-ahead spool：先持久化后发送（逐事件 fsync），SIGKILL 仅丢管道尾部、服务端幂等去重重放；有界 spool 三重上限背压；真实 SIGKILL 硬杀恢复对账（专项 12 项）
- final C2 connect retval 守卫：失败连接（ENETUNREACH）不再产生网络证据，WSL2 真实内核双模式验证；回环异步 RST 边界如实记录
- final C3 证据会话身份：SecurityEvidence 增 process_exec_id/parent_exec_id（evidence_hash 基不变零漂移）；evidence_sessions() 聚合，PID 复用不合并
- final C4 CVE 证据下钻：package_match_reasons() 单一语义源 + GET /runtime/cve-evidence + 前端行为链下钻块；exploitation_confirmed 恒 False
- final C5 数据质量工具：query_runtime_data_quality（coverage/dropped 0 与 unavailable 严格区分/证据新鲜度/显式 data_gaps；未知名 found=False）

## 2026-10-14 — eBPF 2.0 P0：运行时证据可靠性升级（D1 修复 + 转发器 2.0 + 可靠性指标 + 清空语义）

- 新幂等：原始事件身份（anchor+boot_id+raw 去传输键，递归剔除归一化 artifact）/采集来源/资产归属三层分离；判重路径双表回绑（先绑定不改写）；并发=进程锁+部分唯一索引+SAVEPOINT
- 迁移 v2：历史指纹确定性重算、精确去重（绑定无歧义传递）、证据精确匹配回绑、标记幂等可重跑
- 转发器 2.0：批量确认协议（POST /runtime/ebpf/events/batch，逐条拒绝）+有界重试指数退避+spool 断点续传（未确认≠丢失）+ack 确认语义+非零退出状态；--legacy-single 兼容
- 可靠性指标：转发器真实计数随心跳上报；bpftrace stderr 丢失计数解析→supervisor 健康文件；GET /runtime/ebpf/reliability 自报×服务端观测（0 与 unavailable 严格区分）
- 清空语义：仅清 RuntimeEvent+镜像文件；SecurityEvidence 为只追加审计层（风险复核/Trace 引用）一律保留并上报
- 验证：专项 18/18；转发器契约 5/5（boot_id 不注入/degraded-stopped 心跳意图保留）；相关回归 92/92；真实 E2E（断网→续传→四次重放零重复：40/40/0）；全量回归 374 passed/19 failed 与基线完全一致（零新增）
- 边界：未动内核/Falco 服务/LSM enforce/设备写；P1 前置=VM sudo 授权窗口

## 2026-10-14 — eBPF 2.0 审计轮：源码审计 + 真实验证 + 升级设计（零功能代码改动）

- 交付 IOT_EBPF2_AUDIT_REPORT.md：现有架构图、十项逐一审计（路径/函数/调用链/验证结果）、Tetragon/Falco/Tracee/Hubble 对比矩阵、D1-D9 缺陷清单、P0/P1/P2 升级设计与验收方法、性能评测方案、四智能体/Harness/Trace 兼容性分析
- 真实运行验证：阶段二 40 条真实内核事件全链回放（上传→双表幂等→证据→API→进程树→风险消费 mosquitto=verified）；WSL root 用项目脚本原样全新采集（execve/openat 真实事件）；智能体工具/心跳/demo 标注实测
- 重要发现：D1 资产绑定态变化破坏幂等（重传 40→80 重复、证据不回绑）等 9 项缺陷如实入册；VM falco 0.44.1+bpftrace 已装但自定义规则未部署、LSM 无 bpf、sudo 阻塞（环境限制如实记录）
- 边界：本轮零功能代码改动；升级方案默认只读，不引入 Tetragon/Tracee 级重型依赖；新增探针仅 execve argv/session-id 与 connect 返回值两处
- 证据 reports/ebpf-audit-20261014/（本地留存）

## 2026-10-14 — 第八阶段：统一任务 Trace 与可观测性系统

- 统一追踪：新增 trace_run / trace_event（seq 顺序、is_llm_step 如实标注、证据引用、payload 服务端脱敏+限长）；旧表增量 trace_id 列（SQLite ALTER），旧记录不回填
- 四智能体：编排全程事件化（agent/stage/handoff/task 生命周期 + LLM 真实统计）；DeepSeekChatClient 透出真实 usage（无依据 unavailable 不编造）
- Harness：计划/审批（通过与拒绝）/工具调用/预算拦截/回滚/超时恢复事件关联 trace_id，安全行为零变更；只读分析显示 not_requested 不伪造修复状态
- 设备管线：discovery_enrollment / device_refresh / device_cve_match 三类任务 Trace；Zephyr 能力 unsupported 如实入 Trace
- Trace API：/api/traces* 7 端点（分页/详情/时间线/智能体/Harness/证据/统计），索引与脱敏齐备
- AgentOps 前端：统一追踪标签四区域（总览/时间线/Harness 监控/证据关联），真实数据 + loading/empty/error 状态
- 真实演示：真实 DeepSeek 只读分析 ALL PASS（4/4 真实 token 用量），浏览器实测四区域展示
- 测试：专项 15/15；全量回归无新增失败（19 失败为既有已知冲突文件，基线对照 33）；前端构建通过

## 2026-10-14 — 第七阶段完成：Zephyr 真实端到端联调（QEMU 阻塞解除）

- 阻塞解除：Ubuntu 24.04 VM 安装 qemu-system-arm 8.2.2 / gcc / build-essential（用户执行）；SSH 重连验证（Ubuntu 用户 + VMnet8 管理地址，显式 id_ed25519_vms；具体标识见本地证据）
- 板级切换落地：qemu_cortex_a9 构建成功（arm-zephyr-eabi，含完整网络栈 eth_xlnx_gem+DHCP+TCP）
- 三处真实修复：①CMSIS 模块路径与 west 清单对齐 + .west 工作区 + stage7-cmsis-wiring 接线模块（源码包部署环境缺口）；②Zephyr 树补丁 patches/0001（soc 未映射 SLCR → GEM 初始化翻译错误，8 行）；③固件 /api/system JSON 拼接缺陷（"port"键重复 → 非法 JSON，真实探测发现，mock 不可暴露）
- QEMU 运行打通：xilinx-zynq-a9 + `-nic user,model=cadence_gem`（SoC 内建网卡标准挂载）+ SLIRP hostfwd 8080→:80；DHCP ok、http on :80
- 真实网络链路：Windows 后端 → VMnet2 → Ubuntu 宿主（VMnet2 地址:8080）→ QEMU 固件（跨主机真实 TCP/HTTP）
- 真实联调验收：stage7_zephyr_live.py 20/20 ALL PASS（发现→身份接口建档 0.9→固件元数据→版本化组件→能力 unsupported→CVE 清洁库诚实零+TEST-FIXTURE 三层→复扫幂等→未授权 400→零修复副作用）；证据 reports/zephyr-live-20261014-085507/
- 回归：26/26 复跑通过（zephyr+discovery+identity_edge+api_smoke）
- 诚实记录：Ubuntu 宿主 VMnet2 地址为 SLIRP 入口（NAT 拓扑边界写入证据）；上轮"ARM 构建成功"无产物支撑（build-arm 为失败半成品），本轮重建才真正完成

## 2026-10-13 — 第七阶段：Zephyr RTOS 终端接入（固件+后端+测试就绪，QEMU 阻塞）

- 固件：Zephyr-Sensor-01（真实 Zephyr v4.4.2 应用，TCP+DHCP+传感+/api/system 身份）构建成功
- 后端：OS 能力画像 + Zephyr unsupported 标注 + 固件扩展元数据（增量适配）
- 测试：5 项 Mock + 26 项回归全过
- 阻塞：QEMU v10.0.2 locore 启动链不兼容（需系统 QEMU 或 GCC，待 sudo）

## 2026-10-13 — 第六阶段收尾：主机线端到端闭环

- SSH 阻塞根因定位（非默认身份名 + agent 停用）并解除；Ubuntu 侧零改动
- 主机线真实采集 2 次全过（指纹钉扎 verified、密钥认证、182 包、幂等、无重复建档）
- 采集身份与 VMware .vmx MAC 闭合；与基线 diff 捕获 1 处真实包演进
- 本轮快照 CVE 分级消费：诚实三层呈现（无证据 → 拒绝下结论）

## 2026-10-13 — 第六阶段：OpenWrt 真实接入（设备线）

- 新增 stage6_openwrt_live.py：OpenWrt VM 真实发现联调入口（指纹比对/发现/建档/幂等/边界 16 项）
- 真实成果：授权段内自动发现 OpenWrt 并以真实协议横幅建档；主机指纹与受信记录一致
- 已知阻塞：Ubuntu 采集节点 SSH 凭据失效 → 主机线采集与精确 CVE 匹配待恢复（未绕过、未伪造）

## 2026-10-13 — 托管机制落地（Private 0a679e9 / Public d14f354）

- 双仓体系投入运行：Private（完整历史）与 Public（独立干净历史，PUBLIC 可见）
- sync_public.py 首次同步 223 文件；commit message 携带 Source-Commit 溯源；幂等复跑验证通过
- gh 令牌补齐 workflow scope（CI 文件推送所需）

## 2026-10-13 — Commit 6f4724b（Private）+ Public 首次发布

### 安全
- 公开前整改：删除含用户名截图、旧工程路径占位符化、夹具主机名合成化、样本全合成化、用户目录脱敏（详见 EXECUTION_REPORT）

### 机制
- 建立 Private（su12s-ops/IoTGuard-Project，完整历史）+ Public（su12s-ops/IoTGuard-Public，独立干净历史）双仓体系
- 新增 `scripts/sync_public.py` 自动同步（导出→扫描→增量提交→推送，来源 hash 可追踪）
- 新增 `ai_collaboration/` 协作文件、GitHub Issue/PR 模板、CI 工作流

## 2026-10-13 — Commit a05f3c8（初始基线，Private）

- IoTGuard 工程基线：backend（FastAPI，30+ 表，341 项测试）/ frontend（Vue3，16 视图）/ collector（eBPF+采集器）/ simulator（SmartCam-X1）/ 技术文档
- 初始提交含整改前环境标识（后续 6f4724b 已在工作区修复；历史按授权保留）
