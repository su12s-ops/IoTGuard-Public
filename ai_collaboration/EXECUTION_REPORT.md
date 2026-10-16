# 最近一次开发结果

> 本仓库（IoTGuard-Public）为唯一正式开发仓库；每完成一个任务在此归档摘要并提交。最后更新：2026-10-16（Stage 9B M4.2 收尾：质量闭环验收——研判质量闭环而非 Token 优化）

## 2026-10-16（Stage 9B M4.2 收尾）：统一四智能体质量闭环验收（遗留实验全部补齐 + Y6 反事实 2×2 修正 + Runtime Agent 正向贡献度量；650 回归零失败；flag=off 维持）

- **交付**：IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md（十节收尾报告：离线核查/遗留补齐/Y6 修正/RT 正向贡献/方向四层分析/完整分母/回归扫描隔离/诚实性声明/切换准备状态）+ backend/scripts/stage9b_closure_{cases,experiment,stats}.py + backend/tests/test_closure_counterfactuals.py（13 项）；实验脚本与真值先验提交 9f9e2e6（先于任何收尾 LLM 运行）、脚手架修复 d306622、退化输出检测 5ab79e1
- **第一部分（离线核查，零 LLM）**：M4.2 主矩阵完整性独立重建——25 主矩阵+6 消融全部对账（19 全链+5 兜底+1 simple+6 消融）；432 调用/3,394,004 tokens meter 口径闭合（client 级 338 差 10=零 token 失败调用；逐 Agent 230 差 202=agents_log 每角色末次调用语义，定向复议/补查覆盖同名条目）；**更正主报告两处口径**（E3「六跑全 not_affected+monitor 零方差」实为 LLM 4/4 零方差+2 兜底落真值；逐 Agent 表计量范围需标注）；原始 31 文件零改动核验
- **第二部分（遗留补齐，真实 LLM，全部落真值）**：E4a/E4b 复验两跑完全一致（potentially_affected+mitigate+人工——厂商冲突语义在 LLM 层生效；方向 downgrade_minor 双跑一致保守偏差）；X2 复验 not_affected+monitor 全对（KEV 未推翻已修复事实）；X3 复验 potentially+scheduled 全对（过期证据不驱动 immediate）；Y4/Y10 资产调查员消融完成——**判定不承重、校准承重**（Y10 隐藏后置信度 0.62→0.70、暴露面 0.4→0.65 膨胀，证据分级纪律约束决策置信度）
- **第三部分（Y6 反事实修正）**：原单因素设计（仅去 KEV）标注 SUPERSEDED 保留——caddy 公网×CVSS9.8 通道下去 KEV 放大因子仍成立；新 2×2（KEV×公网高危）四格先验真值：确定性放大因子断言 **4/4 PASS**，LLM 处置与因子存在性**一一对应**（kev0_pub1 格 immediate 保持=原设计预期被证伪；kev0_pub0 格 immediate 被确定性门禁拦下=端到端正-反对照）
- **第四部分（Runtime Agent 正向贡献，RT-A/B/C/D 同构反事实）**：四条件共用相同设备/CVE/静态事实、仅运行时层不同；最终样本（rt2-）完整管线 impact/action **4/4 全对**（方向 3/4）；**RT-D（无监控）隐藏运行时分析师后决策崩为 insufficient（承重实证）**；RT-B/RT-C 不承重（freshness 分桶与覆盖状态为程序事实）；RT-A 分析师贡献=新鲜度核实（verified/fresh）、关联语义偏保守（suspicious_unlinked vs 设计预期 cve_related）如实记录
- **本轮暴露并修复 2 项脚手架缺陷（回归锁定+受影响运行重跑，污染集留档）**：①Y Fixture 事件缺 timestamp 键→主矩阵全部 Y 案例证据层时间戳为空（RuntimeEvent.occurred_at 一直正确；已记录 Y 运行无真值依赖 freshness，19+3 结论不受影响）；②RT 传感器心跳 120s 竞态（M4 已修的同类 E/X/Y 竞态未继承到新 Fixture）。另增运行时分析师 Schema 回显退化输出检测（rt2-RT-A 两次命中的随机失效模式）
- **回归与安全**：全量 **650 passed / 0 failed**（637 基线+13 收尾专项，终态复跑零回归）；Mimosa 深度扫描 **0 findings**（scan-2026-10-16T06-22-58.264Z-997fe0409b11，seal sha256:9d3c421e…de2d0a，123 依赖包）；敏感信息干净（无凭据字面量，.env 不入库）；shadow 全程零触碰（收尾运行全部 shadow/sink=None）；**flag=off 保持**
- **诚实记录**：收尾 33 运行文件=26 有效全链+7 被取代首跑（5 外部故障+2 模型退化），全部留盘不删除；累计真实成本 meter 口径 ≈7.51M tokens/1005 调用（含重试与故障成本）；E5「监控过期→方向下调」混同确认为方向通道最弱项（改进需另建评分规范版本，本轮不动原始实验）
- **切换准备状态：候选具备，建议启动真实设备 Shadow 验证（人工决策）**；本轮不设 flag=on、不删旧编排器、不启动 Shadow，到此停止

## 2026-10-16（Stage 9B M4.2 主轮，补记）：统一四智能体研判质量深化（上轮交付，报告 IOT_UNIFIED_FOUR_AGENT_QUALITY_REPORT.md；其 ai_collaboration 归档在本轮补记）

- 四 Agent 专业分工 Schema 深化 + 四维分层研判 + E2/E3a/E1/X2 整改 + Y1–Y10 独立案例 10/10 全对；主矩阵 25 运行中 19 全链 LLM 评审 impact/action 19/19、人工路由 5/5、引用幻觉 0、方向 14/19（偏差全保守/口径项）；System B 同库 Y 案例 10/10 同对（统一链优势集中在分层语义/边界案例/可解释性，代价 ≈10× token 如实呈现）；实现与先验真值表提交 42fe3b1 先于实验数据入库；全量 637 passed；Mimosa 深度扫描 0 findings（scan-2026-10-16T02-26-27.410Z-4d6db1efbac3）；维持 flag=off。遗留中断项（E4 复验/X2/X3 复验/反事实/2 项 asset 消融）全部由本轮收尾补齐

## 2026-10-15（Stage 9B M4.1）：统一四智能体研判校准与成本治理（口径修正+五类缺陷修复+证据预取；影响判定首次达标，成本/处置差一步，flag=off 维持）

- **交付**：IOT_UNIFIED_FOUR_AGENT_CALIBRATION_REPORT.md（十项：口径修正/五类根因与修改/证据预取设计/逐 Agent 前后成本/严格配对/稳定性/回归/扫描/Commit/迁移判定）+ backend/scripts/stage9b_calibration_stats.py（离线核查，零 LLM）
- **第一部分（零付费离线核查）**：M4 的 20 次运行重建五类口径——全链 LLM 14 / 程序兜底 3（**实为 E3a×2+E3b×1，原报告误记"E3a 三次"**）/ 消融 1 / simple 2；LLM-only 修正口径：影响 85.7%、处置 57.1%（原混合口径 88.2%/64.7% 把兜底混入）；7.6s=76.0s/10 事件全量口径（104.1s 合并应为 9.46s/事件）；调用双口径（meter 258=237+21，client 246）；原始存档/真值零改动
- **第二部分（通用安全语义，零案例硬编码；事实+校验+门禁三层）**：E3 分支排除确定性提取（branch_excluded 不得被通用匹配推翻）/ E4 厂商冲突预检（冲突未消解禁 confirmed 与修复处置）/ E5 verdict 新增 runtime_evidence_validity+urgency_basis 分离字段（static_evidence_only 不一刀切禁止但强制人工）/ X2 确定性 fixed 语义（KEV 不改变已修复）/ X3 过期证据≠适用性不足；门禁新增 7 类确定性矛盾理由；35 项新测试锁定
- **第三部分（Evidence Preparation，非第五个 Agent）**：LangGraph 新增 prepare_evidence 确定性节点（复用只读工具/多源情报包/SecurityEvidence；运行内只读复用；新鲜度按当前时间重算；有界；失败退回自主查询）。逐 Agent 前后：资产工具 90→76（-15.6%）、专家延迟 -17%~-27%、墙钟/评审运行 173.8s→160.3s（-7.8%）、全链口径 token 93.0k→88.5k（-4.8%）——评审运行口径 +15.6%，**成本"实质改善"未达，如实判 ✗**
- **第五部分 B-D（真实 LLM 复测，Fixture/真值零改动，22 次全 completed，0 失败 0 兜底 0 触界）**：矩阵 17 全链+2 simple+1 消融 + E4 补充 2（缺陷修复后）。**影响判定（配对）9/9 vs System B 7/7——首次达标**；处置（配对）8/9 vs 8/8（差 1 例 E2 静态紧迫性超集）；X2 not_affected+monitor 完美（上轮 insufficient+scheduled 超集）；X3 回到真值（上轮双超集）；E5 处置 3/3 零方差（上轮 immediate×2 超集）；E4 修复后 5/5 全对两跑一致；E3b 三跑全部识破误匹配（上轮同实例曾接受）、E3a 残余 1/6 方差；引用幻觉 0/20（2 例评分器假阳性已对齐，原始存档未改）；消融 F7 三项全中
- **本轮暴露并修复 1 项真实缺陷（回归锁定+真实复测）**：E4 厂商冲突漏检——get_source_bundle release 作用域 canonical value 为单记录形态，detect_vendor_conflict 只读 records 漏检 → 兼容两种形态 + 单记录回归测试 + E4a/E4b 修复后真实复测 5/5 全对
- **回归与安全**：全量 **589 passed / 0 failed**（554 基线 + 35 项校准专项，缺陷修复后复跑确认）；Mimosa 深度扫描 **0 findings**（scan-2026-10-15T17-10-38.086Z-25c64eb52112，seal sha256:edb186b2…529f1b，123 依赖包）；敏感信息干净；shadow 零副作用
- **门槛判定**：影响 ✓（首次）/ 稳定性 ✓（E1×3、E5×3 全一致，0 兜底）/ 安全面 ✓（人工路由 100%、幻觉 0、fail-closed 扩展）/ 处置 ✗（差 1 例）/ 成本 ✗（-4.8% 非实质）→ **维持 LINUXGUARD_UNIFIED_PIPELINE=off**；遗留清单：static_evidence_only 放大因子前提 / E3a 残余方差强制人工 / 方向口径对齐 / 预取切片瘦身（目标 ≤60k/评审运行）
- **边界**：未切换生产入口；未删除旧编排器；未绕过 Harness；System B 对照零新增调用（复用 M4 已核查留档）；原始产物本地 reports/ 留存不入库；本轮结束即停止

## 2026-10-15（Stage 9B M4）：统一四智能体最终验收实验完成（全部 10 事件；未达切换门槛，flag=off 维持）

- **交付**：IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md（准确 Commit/20 次运行状态/新旧对照/重复实验/智能体增量贡献/Harness 安全回归/成本/测试扫描/切换门槛判定/切换回滚方案 + 诚实性声明）
- **实验完成度**：充值最小调用验证通过（deepseek-v4-flash/0.1/真实 usage/无 402）后，全部 10 事件（含按架构 §9 补齐的 X2：KEV+装机已修复）20 次运行全 completed——14 全链四智能体、3 次 API 连接错误程序兜底（判定全部落真值）、1 屏蔽消融（F7 通过）、2 simple 直通（0 LLM）；1,357,234 tokens / 258 调用 / 58min；E1×3、E3×6（双实例各 3 次）、E5×3 重复
- **安全面全达标**：人工路由 6/6；引用幻觉 0/20（评分器对齐 runner known_evidence_ids 复评，原 2 例假阳性修正）；无依据升级 0；E1 重复 3/3 完全一致且真值全对；X2 未因 KEV 虚判 confirmed_affected（确定性工具 version_impact=fixed 正确）；X3 stale_verified 语义+门禁正确；预算/超时/异常/屏蔽全程未绕过门禁
- **未达切换门槛（诚实结论）**：影响判定 88% vs System B 100%、处置适当 65% vs 91%、单事件 token ≈3.2×、墙钟 ≈27×、E3/E5 重复 2–3 值方差；退化逐案例根因（E3b#1 纯 NVD 单次方差接受误匹配 / E4·E5 处置激进但人工截住 / X2 已修复语义保守化 / X3 保守副作用）；**LINUXGUARD_UNIFIED_PIPELINE 保持 off，整改清单 §9 五项，等待用户确认后再议**
- **5 项真实缺陷修复（全部回归锁定）**：脚手架 target_ref 保真度（"fixture"→资产 hostname，生产 adapter 同语义）；脚手架传感器心跳 120s 竞态（运行前刷新在线心跳）；生产·决策规划师空 verdicts 伪成功→完备性反馈重试+兜底（2 测试）；生产·simple 直通路径 routing_json/decision_json 不落库→对齐（测试扩展）；生产·state.error 重复定义覆盖并行 reducer→InvalidUpdateError 崩溃→删除重复定义（reducer 在位性测试）
- **实验基建**：逐运行 JSON 落盘/断点续跑/已完成去重/Token 硬预算 2.5M（本轮真实使用：4 次归档后续跑重跑全部去重完成）；3 个归档目录（targetref-defect / heartbeat-race / network-outage）缺陷期运行完整留档不混入验收
- **对照有效性**：System B 上一轮全量（10 事件/44 调用/242,108 tokens）经 event_review_pipeline 代码版本核查（d14f354 后未改）保留；X2 由本轮同配置补充（4 调用/23,142 tokens，同为非受影响判定）
- **回归与安全**：全量 **554 passed / 0 failed**（551 基线 + 3 新增专项，零回归）；Mimosa 深度扫描 **0 findings**（seal sha256:448f342c…2394）；敏感信息扫描干净（无凭据字面量/私网地址/用户路径）；shadow 零副作用测试锁定；API Key 未打印未入库
- **边界**：未切换生产入口；未删除旧编排器；原始实验产物（LLM 原文/逐智能体日志/usage/Trace/归档）本地 reports/ 留存不入库

## 2026-10-15（第九阶段前置专项）：四智能体有效性深度审计（真实代码追踪 + 真实 LLM 消融/反事实；零生产代码改动）

- **交付**：IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md（12 节：架构/逐智能体贡献/消融/反事实/摆设化结论/整改清单 F1-F10/升级方案 R1-R8/竞赛数据表/方法学声明）；实验脚本 backend/scripts/stage9_agent_effectiveness_audit.py + stage9_recompute_metrics.py（可复跑、无密钥入库）
- **静态审计核心结论**：仓库存在两套"四智能体"——System A（services/agents/，真工具循环 14 专属工具）与 System B（event_review_pipeline.py，单次类型化 LLM + 确定性证据包 + 确定性门禁）。System B 输出全链真实消费（RiskAssessment.final/decision → 排序/人工复核/修复授权/Harness 补采复评）；System A 主输出 risk_json 为死端（仅 AgentOps 展示），其 remediation 智能体因上下文饥饿+授权依赖结构性空转（实测 risk_ref=""、actions=[]）
- **真实实验**（deepseek-v4-flash 与生产同配置，约 160 次调用，合成 CVE/TEST-NET Fixture，真值表先于实验独立定义）：A 纯规则处置正确 2/7（E3 假阳性/E4 无视冲突/E5 忽视过期全部命中）；B/C 四智能体 6/7、影响判定 7/7、114 条证据引用 0 幻觉、0 确定性矛盾；D 屏蔽任一智能体→建议全坍缩兜底、人工门禁 4/4 保持；System A runtime 屏蔽 62→54 分/high→medium；CF6 Zephyr：能力标注入 Trace 但 RUNTIME 智能体 schema 两次全败（fail-safe 降级）
- **正面实证**：E3 误匹配候选被 impact 智能体识破（定向复议后明确"版本规则命中为假阳性"并引用分支范围证据），coordinator 拒绝依未核实 fixed_version 触发升级——规则引擎同案例给 High 69.05/scheduled_fix。E4 矛盾情报全部转人工复核。结论：规则+智能体优于纯规则；但简单案例（E1/E2）两者一致，成本只应花在困难候选（R8 分层方案）
- **量化边界**：auto_confirmed 0/14（high_or_critical_final_score 14/14、confidence_below_0.70 12/14 门禁）——LLM 对分数影响理论性、对建议/路由/补采影响实在；成本 System B ≈2.2-2.5 万 token/事件、System A ≈3.7 万 token/编排
- **缺陷清单**（未整改，待评审）：F1 P0 report_service opinions list 崩溃（已复现）/F2 双体系死端/F3 System A 重试无反馈/F4 remediation 上下文饥饿/F5 aggregate_risk 不消费 version_impact/F6 新鲜度不参与运行时状态/F7 无优雅降级/F8 竞赛口径双体系混名/F9 评审成本/F10 统计器伪报已修正
- **诚实性**：统计器首版 2 处伪报（首报 50 条无依据断言）留档并离线修正为 0；单次运行方差如实标注；合成 CVE 的能力边界如实声明；密钥/真实库/原始日志未入库
- **回归**：全量 **499 passed / 0 failed**（零生产代码改动，与基线一致）

## 2026-10-15（eBPF 2.0 P2-2）：OpenWrt logread 只读降级采集（真实链路 21/21 + 全量 499/0）

- **真实采集**：OpenWrt 25.12.5（VMnet2 实验段）经既有 DeviceConnection（指纹钉扎与 2026-10-13 受信记录一致 + 设备私钥环境变量引用）执行固定只读脚本：身份段（hostname/boot_id/UTC 纪元/本地偏移）+ logread 全量环形缓冲；1237 条真实事件（窗口 00:13:30→03:01:55 UTC，tz=+0000）全链入库
- **P0 复用**：append_events 既有管线（指纹幂等/资产绑定 1237:1237/证据 1:1/清空语义），零新表零新库；重复采集全量对账（duplicates 1268 + stored_new 3 = built 1271，3 条=采集会话自身 SSH 登录的真实新日志，如实说明）
- **诚实语义**：source=openwrt_logread、观察模式=syslog（新增第五模式）、智能体声明"拉取式降级采集非 eBPF"；缺年份/不可解析行跳过计数（46 条防御路径如实入元数据）；ring 覆盖丢失 unavailable；boot_id 参与指纹（跨重启零误合并，专项锁定）；窗口变化三采新行入库/旧行判重/dropbear 57 条真实行可见
- **联调**：CVE 下钻真实 syslog 证据直接匹配（direct_count=57、runtime_status=verified、exploitation_confirmed 恒 False）；统一 Trace runtime_log_collection completed；coverage/reliability 端点 logread 传感器可见
- **修复 2 项真实验收发现缺陷**：raw 传输标记 "logread_ssh_pull" 含 "ssh" 关键词子串致 1246 条全量误分类敏感文件访问（改名 logread_remote_pull + 命名约束注释）；"立即重复=0 新增"断言不成立（会话自身产日志）改全量对账
- **边界**：对设备零改动（只读、零配置、零软件包）；真实重启未执行（避免干预，语义专项锁定）；Zephyr 零触碰；未进入第九阶段
- **回归**：新增专项 23/23；相关域 306/0（实现期中检）；全量 **499 passed / 0 failed**（476 基线 + 23 新增，零回归）

## 2026-10-15（eBPF 2.0 P2-1）：五形态性能评测完成（真实内核采集 0 丢失 + 判重索引缺陷修复 115→379 EPS）

- **五形态实测**：synthetic 后端摄取 379 EPS（修复后）/批 RTT P50 1.3s；replay 断网 21.6s→5 次重试全成功/spool 清零/幂等收敛 40 唯一；real-wsl 真实 bpftrace 内核两次独立运行 41446/41322 事件、归因对账 0 丢失、探针 CPU ≈2% 单核；real-vm-falco 常驻 Falco journalctl 拉取 14910 事件、0.021% 丢失（1 条如实记录）；bounded-spool 容量不变量与数据保全成立（告警路径未触发，如实记录）
- **判重索引缺陷（实测发现→修复→回归锁定）**：P0 部分唯一索引 WHERE != '' 不被 SQLite 查询计划蕴含推理，判重全表扫描（7500 行批 RTT P50 4.3s）→ 全量索引+幂等补建 → EXPLAIN SCAN→COVERING INDEX；后端摄取 115→379 EPS（synthetic 口径，不表述为内核采集提升）
- **8 项评测链缺陷修复**（3 次失败尝试留档 reports/ebpf-p21-final/*attempt*.json）：wsl 内联转义 EOF / 资产登记非幂等 / 伪造 boot_id 被身份防线正确拒绝（去注入改真实身份）/ ebpf_trace_capture.sh 健康文件 grep -c 双 0+set -e 中止（生产脚本缺陷）/ falco 消息本地时区 +8h 伪零延迟（journal UTC 基准+tz_mismatch 计数）/ 对账口径错配虚报 25% / 固定 sensor_id 跨运行污染
- **诚实边界**：不可测项全部 unavailable（bpftrace 丢失计数未报告→null、falco 引擎 drops/CPU 无 sudo、replay 延迟无实时语义）；/etc/passwd 读取噪声不进丢失结论；VM 文件写项 no_perm 如实降级
- **回归**：新增专项 41 项；相关域发现 init_db 幂等契约回归（_ensure_query_indexes 首版二次运行仍报告变更）→ 根因修复（只在真创建时报告）；全量 **476 passed / 0 failed**（435 基线 + 41 新增，零新增回归）
- **安全**：VM 连接参数改环境变量注入，私网地址/用户名不写入跟踪文件；reports/ 证据本地留存不入库
- **边界**：未进入 P2-2 与第九阶段；未删改任何既有测试；对 VM/WSL 零持久化改动

## 2026-10-14（eBPF 2.0 P1 稳定性收尾轮）：常驻化与可靠性验收（直连方案 + spool 精确对账 + 32 分钟连续运行 + 3 处真实缺陷修复）

- **稳定后端连接**：弃用临时反向隧道，实测直连 `http://192.168.183.1:8000/api`（VMnet8，复用既有防火墙放行规则，零防火墙改动）；配置备份后更新
- **spool 续传对账**：启动前基线（1 批 34 条 / 34 唯一指纹 / 库 2418）→ 重启后 34 条精确入库（时间窗 34/34 唯一）、双表 1:1、全库零重复、spool 经确认清空（非删除）
- **常驻**：enable 开机自启；kill -9 与 SIGTERM 均自动恢复（NRestarts=1，数据缺口 <2s）；SIGINT 干净停止（stopped 心跳 + drops 真实零 + 在途 spool 保全）
- **32 分钟连续运行**：2619 条真实事件、4 规则持续命中、自报/服务端对账一致、spool 全程 0、dropped 运行中 unavailable/停止后真实零
- **修复 3 处真实缺陷**（全部真实验证）：① bash 前台阻塞吞外部 SIGTERM（后台+wait+显式 trap，143 失败语义）；② 停止摘要竞态 ×2（on_int 先 wait 后 cleanup；tee 免疫 INT）；③ falco 退出摘要块污染 rejected（状态机过滤，6~9→0）
- **回归**：全量 385/19 与基线零差异×2；falco-modern-bpf 恢复原状；证据 reports/ebpf-p1-deploy-20261014/stability-*（本地留存）
- **边界**：零防火墙/sudoers/SSH 改动；未删 spool；未伪造指标；未进 P1-3/P1-4/P2
## 2026-10-14（eBPF 2.0 P1 部署验收轮）：Ubuntu VM 真实常驻部署全链路打通（2418 真实事件 / 8 规则命中 / 10 分钟窗口 / 回归零差异）

- **部署**：Ubuntu 24.04 VM（内核 7.0.0，falco 0.44.1）按 §10 流序完成 --check→规则部署（备份先行）→systemd 单元→常驻启动；SSH 反向隧道接入 Windows 后端（零防火墙改动）；资产登记绑定 asset_id=1
- **常驻验收**：19:39:52→19:50:41 连续 >10 分钟；转发器自报 983/983/982、零拒绝零重试零 spool；服务端 2418 RuntimeEvent = 2418 SecurityEvidence（1:1）、零无归属
- **链式规则（全部真实自然触发）**：sshd→bash（sftp）Service Spawned Shell、bash→curl Shell Run Downloader、sudo→sh→cat /etc/shadow 全链含 Shadow Access(CRITICAL) 多规则同事件命中
- **drops 真实指标**：运行中=unavailable（0.44.1 无周期 stats，实测确认）；SIGINT 退出摘要 event drop detected: 0 occurrences → 健康文件 dropped_events=0（真实零）
- **VM 增强探针**：内核 7.0.0 实测 17 条，argv/start_time/会话键全通过（与 Falco 路线 boot_id 交叉一致）
- **部署中发现并修复 8 个真实问题**（详见 IOT_EBPF2_P1_DEPLOY_REPORT.md §3）：0.44 规则兼容 ×2、rule_matching=first 遮蔽 CRITICAL、主机名大小写、KillMode SIGKILL、SIGINT 在途批次丢失路径、单元态语义、drops 来源确认——全部同步仓库源码
- **回归**：相关 48/48、全量 385/19 与基线失败集合零差异（零新增）；falco-modern-bpf 已恢复原状；密码仅经 PTY stdin 一次，未落任何文件/命令行/输出
- **边界**：未改 sudoers/SSH/防火墙/LSM enforce；未动 P1-3/P1-4/P2
## 2026-10-14（eBPF 2.0 P1 准备轮）：探针增强真实内核验证 + Falco 部署包（专项 11/11 + 回归 385/19 与基线零差异）

- **P1 前置审计**：动手前全量回归重测锁定基线 374/19（失败集合与 P0 逐项一致）；P0 专项 18/18 复验通过；WSL 探针环境可用（6.6.87.2/bpftrace 0.20.2/root/BTF），VM 无 sudo 窗口维持阻塞记录，Mimosa 命令不在 PATH（不可用复现）
- **P1-1 探针增强（完成并真实内核验证）**：execve argv（4×48B，NULL 守卫防 envp 泄漏——真实复现该风险并修复）、三类事件 start_time、合成会话键 lg-{boot8}-{pid}-{start_time}、后处理独立模块（新旧格式兼容）、normalize_event argv 有界透传；WSL 实测同一 curl 进程 exec→openat→connect 共享会话键；legacy 模式对照逐字段一致；DB 零迁移、转发器/P0 语义零改动
- **P1-2 Falco 部署准备（未执行部署）**：collector/deploy/falco/ 四件套（README 八项 runbook、deploy_falco.sh --check 非特权体检已在 WSL 实测、常驻管线 falco→转发器、systemd 单元）；--apply/--install-service/--rollback 需 root+确认+备份，本轮一律未执行
- **验证**：P1 专项 11/11、P0 专项 18/18、相关套件 111/111、全量 385/19（Compare-Object 失败集合零差异，零新增回归）；3 个 shell 脚本 bash -n 通过
- **边界**：未动内核/Falco 服务/LSM enforce/设备写；报告 IOT_EBPF2_P1_PREP_REPORT.md；证据 reports/ebpf-p1-20261014/ 本地留存
## 2026-10-14（eBPF 2.0 P0）：运行时证据可靠性升级完成（专项 18/18 + 真实 E2E 零重复 + 回归与基线一致）

- **D1 修复（双层根因）**：旧指纹基含当前 asset_id 且传输键（asset_id/sensor_id）经归一化嵌进 raw（含嵌套链）——三层身份分离后，anchor+boot_id+去传输键 raw 构成原始事件身份；真实复现 40→80 → 修复后同批 4 次上传（断网 spool→恢复→重放×2）对账 **40 行/40 证据/0 重复**
- **回绑**：RuntimeEvent 与 SecurityEvidence 在判重路径补绑（先绑定不改写、冲突显式拒绝）；旧库迁移确定性重算+精确去重（绑定无歧义传递，歧义保守置空）+证据精确匹配回绑，标记 ebpf_p0_stable_fingerprint_v2 幂等
- **转发器 2.0**：批量确认端点（逐条拒绝、ack=已持久化）+ 有界重试/指数退避/安全随机抖动 + spool 断点续传（未确认≠丢失、已确认行不写回）+ 明确非零退出状态；--legacy-single 兼容路径保留；两处旧契约测试按安全意图等价改写（boot_id 不注入、degraded/stopped、失败退出码）
- **可靠性指标**：转发器九项真实计数随心跳；ebpf_trace_capture.sh 解析 bpftrace stderr 丢失计数→supervisor 健康文件（解析不到=null→unavailable，绝不虚构为零）；GET /runtime/ebpf/reliability 自报×服务端观测交叉（E2E 实测 dropped=unavailable 与 received=40 并存、按 sensor 归属 stored=40）
- **清空语义**：仅 RuntimeEvent+镜像文件；SecurityEvidence 只追加审计层（review_evidence_ids/Trace evidence_refs 引用）保留并上报，禁止全表清空替代重复处理
- **验证分级**：真实运行（E2E 全链+四重放对账）/ 集成测试（并发线程、批量端点、迁移旧库）/ 单元（退避、spool、身份基）；全量回归 374/19 与基线逐集合相同（19=既有已知冲突文件）
- **边界**：未动内核/Falco 服务/LSM enforce/设备写；Mimosa 完整扫描仍不可用，如实报告

## 2026-10-14（eBPF 2.0 审计轮）：源码审计 + 真实验证 + 升级设计（零功能改动交付）

- **审计范围**：collector 全部 eBPF/Falco/LSM 脚本与转发器、后端 ebpf_event_collector/security_evidence/runtime_telemetry/runtime 路由、智能体证据工具、风险引擎消费链、前端 RuntimeMonitor——十项逐一给出文件路径、函数、调用链与**真实运行验证结果**（IOT_EBPF2_AUDIT_REPORT.md）
- **真实验证**：① 阶段二 40 条真实内核事件全链回放（normalize→RuntimeEvent 指纹幂等→SecurityEvidence SE- 幂等→三类证据 API→真实 bash→sh→wget 进程树→二次上传幂等）；② WSL root 以项目脚本原样运行 12-14s 全新采集（真实 execve/openat 事件，含 pid/ppid/uid→root）；③ 风险引擎消费正负例（mosquitto 真实进程/连接证据→runtime_status=verified、reachable=linked；openssl→not_observed 语义正确）；④ 智能体工具返回真实 SE- 记录；⑤ 心跳/coverage、demo probe 标注实测
- **重要发现（D1-D9）**：D1 资产绑定态变化破坏幂等（重传 40→80、证据不回绑，已复现）；D2 丢失不可度量（bpftrace lost/Falco drops 未采集）；D3 转发器无批量/重试；D5 无 argv/exec 会话键；D6 Falco 自定义规则未部署；D7 无性能指标；D8 connect 不校验返回值；D9 清空事件不清证据层；D10 OpenWrt/Zephyr 运行时盲区（如实 unsupported）
- **环境事实**：Ubuntu VM falco 0.44.1 + bpftrace 已装、内核 LSM 无 bpf（LSM 钩子不可用）、自定义规则未部署、sudo 密码阻塞探针执行；WSL bpftrace v0.20.2 可用（本轮真实采集即在此完成）
- **升级设计**：P0 可靠性（D1/D2/D3/D9，含验收方法与复现基线）→ P1 进程关联与 CVE 联动（execve argv+session-id 探针、Falco 规则部署常驻、证据链×Trace）→ P2 性能评测/异构降级/Agent 工具增强；默认只读，不引入重型依赖，新增探针仅 2 处；四智能体/Harness/Trace 全兼容（分析见报告 §8）
- **边界**：本轮零功能代码改动（仅报告+文档），阶段七/八已验收功能零回归面；Mimosa 完整扫描仍不可用，不声称完成全局安全审计

## 2026-10-14（第八阶段）：统一任务 Trace 与可观测性系统（专项 15/15 + 真实 LLM 演示 ALL PASS）

- **统一 Trace**：trace_run（唯一 trace_id、任务类型、资产标识、运行标识、Harness 关联、起止与状态）+ trace_event（trace 内 seq 单调保持顺序、actor、is_llm_step、脱敏 payload、证据引用、耗时）；既有审计表零改动，仅 SQLite ALTER 增量 trace_id 列，旧记录保持原样可读（不回填不伪造）
- **四智能体追踪**：start_analysis 建唯一 trace_id；agent_started/finished/failed、stage/handoff、task_finished 全事件化；LLM 统计仅记录响应真实携带的 usage（本次真实演示 4/4 智能体带真实 deepseek-v4-flash token 用量；剧本/无密钥场景如实 unavailable）；程序步骤 is_llm_step=false；失败/超时/证据校验错误如实入 Trace
- **Harness 关联**：create_run 可选 trace_id（默认空=既有调用零影响）；计划生成、审批通过与拒绝（harness_policy_blocked）、工具调用开始/结束/失败、预算拦截、执行收口、回滚、租约超时恢复全部事件化；计划哈希审批绑定/资产互斥锁/工具预算/设备写开关/不重放写操作等安全行为零变更
- **设备管线**：发现入档/设备刷新/CVE 匹配三类任务生成 Trace；Zephyr 设备能力边界（ssh/package/eBPF unsupported）capability_marks 事件如实记录
- **Trace API**（/api/traces*）：列表分页过滤、详情、时间线、智能体事件、Harness 关联（linked/not_requested/not_applicable 诚实语义）、证据解析（unresolved 如实）、汇总统计；查询走索引；payload 写入端脱敏（敏感键分词匹配、api_key/apiKey 覆盖、16KB 限长）
- **AgentOps 前端**：新增“统一追踪 (Trace)”标签四区域——任务总览（真实统计卡片）、智能体运行时间线（28 事件：能力标注→四智能体 LLM 步骤→阶段交接→收口）、Harness 安全监控（关联状态/审批/工具调用表/策略拦截）、证据关联（SE-/CVE 解析+资产跳转）；支持 loading/empty/error；分析完成后自动跳转对应 Trace
- **真实只读演示**（stage8_trace_demo.py，ALL PASS）：真实发现入档 QEMU Zephyr 设备 → 真实 DeepSeek 四智能体只读分析（真实 token 用量）→ 事件顺序/能力标注/LLM 诚实性/Harness not_requested/统计聚合全部验收通过；另以浏览器实测前端展示（vite preview 构建产物 + 真实后端，截图本地留存）
- **测试**：test_trace_system 15/15；全量回归 356 passed、19 failed 全部为既有已知冲突文件（基线对照 33 failed，无新增回归）；前端构建通过；agent_refactor 15/15、agent_harness_upgrade 30/30 复跑确认
- **诚实性修正**：修复成功路径 LLM 统计未回填问题（此前真实调用显示 unavailable）；token_usage 键更名 llm_tokens 避免与凭据脱敏语义冲突

## 2026-10-14（第七阶段完成）：Zephyr RTOS 真实端到端联调（QEMU 阻塞解除，20/20 ALL PASS）

- **阻塞解除**：用户在 Ubuntu 24.04 VM 安装 qemu-system-arm 8.2.2 / gcc 13.3 / build-essential；SSH 重连验证（显式 id_ed25519_vms 密钥，Ubuntu 用户；VMnet8 管理地址与 VMnet2 实验地址见本地证据）
- **板级构建真正完成**：qemu_cortex_a9（arm-zephyr-eabi）+ 完整网络栈（eth_xlnx_gem + DHCPv4 + TCP Sockets，RAM 964KB）。勘误：上轮"ARM 构建成功"无产物支撑（Kconfig 阶段失败半成品）；本轮排查出三处环境/上游缺口并修复：
  1. CMSIS 模块布局与 west 清单对齐（modules/hal/cmsis{,_6} 放真实仓库、树内 modules/cmsis{,_6} 兼容层复位）+ .west 工作区重建 + 固件侧 stage7-cmsis-wiring 接线模块（源码包非 git 部署导致 west 模块发现不可用的环境补偿，非上游组件）
  2. Zephyr 树补丁 patches/0001：soc.c 在 GEM 启用时映射 SLCR（eth_xlnx_gem 初始化写 GEM 时钟分频寄存器 0xf8000140，上游未映射 → 裸启 1 级翻译错误；8 行补丁，VM 应用并随库存档）
  3. 固件 /api/system JSON 拼接缺陷（"port" 键重复 → 非法 JSON）：真实探测暴露（mock 测试无法发现），修复后端可正常走 identity_endpoint 路径
- **QEMU 运行打通**：系统 qemu-system-arm + machine xilinx-zynq-a9 + `-nic user,model=cadence_gem`（SoC 内建网卡标准挂载；此前 xilinx-aarch64 FDT 机器不接受的正是这一点）+ SLIRP hostfwd 8080→固件:80。串口证据：`*** Booting Zephyr OS build 4.4.2 ***` → `dhcp ok` → `http on :80`
- **真实网络链路**（跨主机，无模拟跳变）：Windows 后端 → VMnet2 → Ubuntu 宿主（VMnet2 地址:8080，SLIRP hostfwd）→ QEMU 固件 :80；遥测值实时变化（25.1→25.4℃）
- **验收（backend/scripts/stage7_zephyr_live.py，20/20 ALL PASS，证据 reports/zephyr-live-20261014-085507/）**：
  - 自动发现：/25 真实扫描（≤128 地址上限）端口 [22,80,443,8080] → Zephyr 设备上线
  - 身份建档：identity_source=device_identity_endpoint、置信 0.9、os/device_type/firmware_version 全部来自固件自报；固件元数据（board=qemu_cortex_a9、arch=arm、build_id、MAC、telemetry simulated=true）入档
  - 版本化组件：Zephyr-Sensor-01 firmware + zephyr-sensor-httpd（均 0.1.0-stage7）；能力边界 ssh/package/eBPF = unsupported 如实标注；os_capability_profiles 端点含 Zephyr/Linux 画像
  - CVE 分级：清洁库诚实零命中（无证据≠无漏洞）；TEST-FIXTURE 三层验证（厂商精确 affected/0.95/vendor_advisory、NVD 候选 potentially_affected/nvd_generic、无关 CVE 不出现；夹具仅存一次性临时库）
  - 幂等：复扫 enrolled_new=0、设备唯一、组件无重复（复扫自动重跑设备匹配）
  - 边界：未授权网段 400；harness/remediation 零副作用；NAT 拓扑（宿主 VMnet2 地址为 SLIRP 入口，:22/:80 属宿主服务、OpenSSH 组件来自宿主）如实写入证据
- **回归**：26/26 复跑通过（zephyr 5 + discovery_pipeline 9 + identity_edge_cases 5 + api_smoke 7）；未触碰 OpenWrt/SmartCam 既有口径

## 2026-10-13（第七阶段）：Zephyr RTOS 终端接入（固件就绪，QEMU 运行阻塞）

- **环境**：Zephyr v4.4.2（官方最新稳定版）+ sdk-ng v1.0.1 模块化布局（免 root 部署于 ~/zephyr-stage7/）
- **固件**：Zephyr-Sensor-01（4 个源文件）——真实 Zephyr 应用：TCP 服务 + DHCP + 模拟传感（标记 simulated）+ /api/system JSON 身份（board/soc/firmware_version/MAC/build_id/OS 版本全部来自编译配置与运行时状态）
- **构建成功**：qemu_x86_64 目标，x86_64-zephyr-elf 交叉编译（SDK v1.0.1 GNU 工具链），5.7MB ELF + 28KB 32 位 locore 引导
- **后端适配**（增量，零重构）：capabilities 端点新增 os_capability_profiles；discovery_pipeline 为 Zephyr 设备标注 unsupported 能力（SSH/包管理/eBPF）；device_inventory 保留固件扩展元数据
- **Mock 测试**（5 项全过）：真实 Zephyr 身份 JSON 结构模拟 → HTTP 探测 → 身份识别（confidence=0.9）→ IotDevice 建档 → 版本化组件（固件+httpd）→ CVE 三层分级（厂商公告→确认 / NVD→候选 / 无证据→延迟）→ 双实例同固件不合并 → 重复扫描幂等 → 能力画像端点
- **根因诊断（补充轮）**：CONFIG_NETWORKING=y 使内核从 ~200KB 增至 ~490KB → qemu_x86_64 locore 引导崩溃。逐步排除法确认：hello_world（~200KB）✅ / 诊断版（无网络）✅ / 仅加 CONFIG_NETWORKING=y ❌。非 QEMU 版本问题，是 Zephyr 树外裸 cmake 构建不生成完整 locore 元数据所致。Zephyr 树内符号链接构建可启动诊断版（已验证），完整版仍受限于 locore 机制
- **回归**：Zephyr 专项 5 + 发现闭环 9+5 + API smoke = 26 项全过；SmartCam/OpenWrt 不受影响

## 2026-10-13（晚）：第六阶段主机线补全——SSH 凭据阻塞解除，端到端闭环

- 阻塞根因（非凭据失效）：专用密钥文件名不是 OpenSSH 默认身份名且 agent 停用，历史 BatchMode 探测从未真正提供该钥匙；显式 `-i` 指定后认证成功。全程未改 Ubuntu/密钥/防火墙，known_hosts 既有记录未动
- 真实采集：SSH 本地隧道 → 既有 collection_only 节点（仍在运行）→ preflight 全绿 → 复用采集任务管线执行 2 次（新 request_id）；host identity verified、密钥认证 succeeded、182 包、collector SHA256 审计、退出码 0
- 幂等与一致性：同 request_id 返回同任务且不重放 SSH；二采后 assets=1/connections=1/packages=182 无重复；采集 MAC 与 .vmx 网卡地址一致（VM↔资产身份链闭合）
- 真实变化：与 10-12 基线对比 181/182 一致，kmod-nls-iso8859 → kmod-nls-iso8859-1（设备真实演进）
- CVE：本轮快照消费于匹配引擎（隔离内存库），幂等、零伪造；无公告/情报 → 全部 182 包落在"无充分证据"层（精确/通用两层为空系无证据，非无漏洞）
- 回归：76 项通过；证据包本地留存 reports/openwrt-hostline-*

## 2026-10-13：第六阶段 OpenWrt 真实接入（设备线全通，主机线受阻待凭据）

- 真实环境：复用 VMnet2 实验段中运行中的 OpenWrt 25.12.5 x86/64 VM；TCP 22/80/443/53 全部可达
- 主机指纹：仅握手（不认证）取证 SSH ed25519 指纹，与第四阶段首次采集的受信记录完全一致
- 发现闭环：标准模式后端（一次性临时库，白名单=授权实验段）经真实 HTTP API 双 /25 扫描；
  OpenWrt 以横幅证据建档（dropbear/http/https 真实指纹，identity=banner_heuristic，无伪造身份）；
  同段另发现 Ubuntu 第二网卡 ssh 服务（属授权段内真实事实）
- CVE 分级：dropbear 横幅不含版本 token → 无版本组件证据 → 按规则延迟匹配；
  未登记公告 → 零命中=无证据（非无漏洞）；全程未提升候选为确认
- 幂等/边界：复扫 enrolled_new=0；未授权网段 400；harness/remediation 全零
- 阻塞：Windows→Ubuntu SSH publickey 仍被拒 → 主机线 SSH 只读采集与 match_openwrt 精确匹配待凭据恢复；
  按项目策略不从 Windows 执行设备采集（stage6 脚本不含任何私钥加载）
- 新增：backend/scripts/stage6_openwrt_live.py（可重复的真实联调入口，16 个验收点）
- 回归：后端 6 套件 81 项 + SmartCam 真实闭环 16/16 全过

## 2026-10-13：公开前安全整改 + 托管机制建设

### 安全整改（Private Commit 6f4724b，已推送）

- 删除无引用截图 `frontend/public/fix-nginx.png`（含真实用户名提示符）
- 5 个文件旧竞赛工程绝对路径 → 中性占位符/根目录推导（`collector/run_real_capture_once.sh` 改为脚本位置推导 PROJECT_ROOT）
- eBPF 采集夹具真实主机名 → `lab-ebpf-host`（40 行，语义不变）
- 两个资产样本文件（根目录 sample + tests/fixtures structure sample）替换为全合成数据，经真实导入器 `parse_asset_document` 验证兼容
- 3 个阶段文档中 `C:\Users\<user>` 占位符化（6 处）
- 回归：后端受影响 6 套件 108 项全过；前端构建通过；业务零变更

### 托管机制（本轮新增）

- `ai_collaboration/` 5 份协作文件
- `.github/`：Issue×2 / PR 模板 + CI 工作流（后端 pytest 交付口径 + 前端构建）
- `scripts/sync_public.py`：Private→Public 单向同步（导出跟踪树 → 敏感扫描 → 增量提交 → 推送，来源 hash 写入 commit message）
- Public 仓库 `su12s-ops/IoTGuard-Public` 建立独立历史并完成首次同步

### 历史安全基线

Private 初始提交 a05f3c8 含整改前标识（真实主机名×40 等）——按授权保持不重写；**Public 不含该历史**。当前 HEAD 工作区经多维扫描：凭据 0、真实环境标识 0、二进制文件 0。
