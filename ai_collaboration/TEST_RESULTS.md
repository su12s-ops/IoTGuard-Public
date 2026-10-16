# 测试结果

> 记录最近测试口径与结果，与 CI 保持一致。最后更新：2026-10-16

## Stage 9B M4.3 核心主链轮（2026-10-16；E2E 证据 reports/m43-core-e2e-*/ 本地留存不入库）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **655 passed / 0 failed**（650 基线 + 5 新增：test_unified_pipeline runs 过滤 1 / test_multi_source 情报重复行容错 1 / test_discovery_pipeline 身份防降级 1 / test_ebpf_p23 证据键跨线 2；终态代码两轮独立复跑零回归） |
| 实机 E2E（backend/scripts/m43_core_e2e.py） | 五阶段 38 项检查全通过：A OpenWrt 12/12（发现/指纹钉扎采集/上传建档/连接预检边界/匹配诚实零命中/logread 幂等/风险计算）+ B Ubuntu 7/7（采集/情报导入/线上同步 349 条/377 匹配/125 风险/risk 12 就绪）+ C/D/E 19/19（flag=off 核验/OpenWrt 设备面影子研判/Ubuntu 风险影子研判/影子隔离快照/引用反幻觉/待审批计划/Harness×6 门禁/链内一致×2/Trace 贯穿/正式结论零写入/引用独立复验） |
| 影子研判质量（真实 LLM，14 次运行全部 completed） | risk_review 多轮全链成功：CVE-2026-63073 openssl → potentially_affected + scheduled_fix + pending_human_review（confidence<0.70/evidence_partial/stale_runtime_evidence/high_critical 四理由）；runtime_evidence_validity=stale_verified（Falco 45.8h 如实降级）、urgency_basis=static_evidence_only；canonical unavailable 不虚判 confirmed；计划 update_package openssl + backup/restart，验证+回滚齐备，requires_approval 程序强制 |
| 溯源核验 | E2：影子链引用证据 43 条全部真实存在于 SecurityEvidence；E3：统一 Trace 22/22 贯穿（unified_four_agent + harness_*）；E4：正式 RiskAssessment 零触碰（无最终分/裁决，review_status 保持候选侧）；C2b：影子前后正式字段快照一致 |
| 本轮缺陷修复（3 项，回归锁定） | ①情报同步二次运行崩溃（autoflush=False 重复建行）②设备身份降级（弱探测轮覆盖已识别身份）③设备线↔主机线证据键失配（修复后 OpenWrt 设备面 runtime 分析师真实入链，6 发现+6 引用全真实） |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-16T11-54-28.320Z-b7c5bff9c409，seal sha256:52fbd4fb…e18a7，123 依赖包） |
| 敏感信息/边界 | diff 与新增脚本无凭据字面量；设备密钥/口令仅环境变量引用；影子零触碰；flag=off 保持；零设备写操作 |

## Stage 9B M4.2 收尾闭环轮（2026-10-16；实验证据 backend/reports/stage9b-closure/ 本地留存，stage9b-quality/ 原始产物零改动）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **650 passed / 0 failed**（8m16s；637 M4.2 基线 + 13 项收尾专项 tests/test_closure_counterfactuals.py：Y6 2×2 四格放大因子断言走 build_evidence_prep_packet 真实路径/四格静态事实一致/真值不变量/旧设计 SUPERSEDED 留档/RT 四条件同构性与干预点/证据层时间戳回归锁（RT 新鲜≤1h、Y 非空）；终态 HEAD=5ab79e1 复跑零回归） |
| 离线核查（stage9b_closure_stats.py，零 LLM） | M4.2 主矩阵 25+6 全部对账（19 全链+5 兜底+1 simple+6 消融）；三口径对账闭合：meter 432 调用/3,394,004 tokens（主矩阵 348+消融 84）、client 级 338（差 10=零 token 失败调用）、逐 Agent 230（差 202=agents_log 每角色末次调用语义）；更正主报告两处口径（E3 零方差=LLM 4/4；逐 Agent 表计量范围） |
| 遗留补齐（真实 LLM，收尾 qc-*/abl2-*，全部落真值） | E4a/E4b 两跑完全一致 potentially_affected+mitigate+人工（方向 downgrade_minor 双跑一致保守偏差）；X2 not_affected+monitor 全对（KEV 未虚判）；X3 potentially+scheduled 全对；Y4/Y10 资产消融全对且暴露校准承重（Y10 隐藏后置信度 0.62→0.70、暴露面 0.4→0.65） |
| Y6 反事实 2×2（cf2-*，四格独立库） | 确定性放大因子断言 **4/4 PASS**；LLM 处置与因子存在性一一对应：kev1_pub1/kev1_pub0/kev0_pub1（原单因素设计证伪格）→ immediate_fix，kev0_pub0 → scheduled_fix（确定性门禁端到端拦下）；方向仅 kev0_pub1 一例偏差 |
| RT 正向贡献（rt2-* 最终样本，rt- 污染集留档） | 完整管线 impact/action **4/4 全对**（方向 3/4，RT-A downgrade_minor 偏差）；隐藏 runtime_analyst：RT-B/RT-C 不变（程序事实已足够）、**RT-D 崩为 insufficient+collect（impact 出真值）=承重实证**；RT-A 分析师新鲜度核实 verified/fresh 成立、关联语义偏保守（suspicious_unlinked vs 设计预期 cve_related）如实记录 |
| 收尾成本（meter 口径） | 33 运行文件 514 调用 / 3,754,203 tokens（26 有效全链 + 7 被取代首跑=5 外部故障+2 模型 Schema 回显退化，全部留盘）；含 M4.2 原始累计 ≈7.51M tokens / 1005 调用 |
| 缺陷修复（本轮暴露） | ①Y Fixture 证据层时间戳为空（预存；已记录 Y 运行无真值依赖 freshness，结论不受影响）②RT 传感器心跳 120s 竞态 ③运行时分析师 Schema 回显退化输出检测——均回归锁定；污染集 rt- 留档，rt2- 重跑为最终样本 |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-16T06-22-58.264Z-997fe0409b11，seal sha256:9d3c421e…de2d0a，123 依赖包，离线公告 1 包 2 条同 M4.2 交付态） |
| 敏感信息/shadow 隔离 | 无凭据字面量；.env 不入库（仅空值占位 example）；收尾运行全部 shadow/sink=None；**flag=off 保持** |

## Stage 9B M4.2 主轮（2026-10-16 交付，补记归档；实验证据 backend/reports/stage9b-quality{,-smoke}/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **637 passed / 0 failed**（589 M4.1 基线 + 48 项 M4.2 专项 test_quality_deepening.py，零回归） |
| 主矩阵（真实 LLM） | 25 运行：19 全链（impact 19/19、action 19/19、方向 14/19、人工 5/5、幻觉 0）+ 5 兜底 + 1 simple；Y1–Y10 10/10 案例全对；E3 LLM 4/4 零方差（收尾轮口径更正：另有 2 兜底落真值）；收尾轮补记逐 Agent 表=每角色末次调用口径 |
| 收尾轮口径更正 | 主报告 §3.2/§7「E3 六跑全部 not_affected+monitor」应读作「6/6 落真值；LLM 口径 4/4 零方差 not_affected+monitor；2 兜底 insufficient+collect」 |

## Stage 9B M4.1 校准轮（2026-10-15；实验证据 backend/reports/stage9b-unified-calibration{,-supplement}/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **589 passed / 0 failed**（7m03s；554 M4 基线 + 35 项新增校准专项 tests/test_evidence_prep.py：分支声明提取/版本分支前缀/冲突判定含 release 作用域单记录回归/预取包构建/节点失败降级/上下文携带/六类决策约束反馈重试/门禁 7 类矛盾理由/program_fallback 标记；缺陷修复后复跑确认，零回归） |
| 离线口径核查（backend/scripts/stage9b_calibration_stats.py，零 LLM） | M4 全部 20 运行五类分类：全链 14 / 兜底 3（E3a×2+E3b×1，修正原报告"E3a 三次"误记）/ 消融 1 / simple 2；LLM-only vs 混合口径：影响 85.7% vs 88.2%、处置 57.1% vs 64.7%；耗时口径修正（7.6s=76.0s/10 全量口径；104.1s 合并=9.46s/事件）；调用双口径（meter 258=237+21；client 246） |
| 真实 LLM 复测矩阵（stage9b_unified_compare.py --unified-only，deepseek-v4-flash/0.1，Fixture/真值零改动） | 20 运行全 completed：17 全链 + 2 simple + 1 屏蔽消融；**0 失败 / 0 程序兜底 / 0 预算触界**；1,505,184 tokens（评审）/ 240 调用 / 3,045.7s；evidence_prep 17/17 可用 |
| E4 缺陷修复补充运行（最终代码） | 2 运行全 completed：potentially_affected+mitigate+人工 ×2 完全一致，5/5 真值全中，144,966 tokens |
| 统一链 vs System B（严格配对，9 个 LLM 案例；System B 复用 M4 已核查留档，零新增调用） | **影响 9/9 vs 7/7（首次达标）**；处置 8/9（88.9%，差 1 例 E2）vs 8/8；方向 7/9 vs 6/8；人工路由 4/4 vs 3/3；引用幻觉 0（2 例评分器假阳性已对齐，真实幻觉 0/20） |
| 案例级改善（vs M4 LLM-only） | X2 not_affected+monitor 零超集（上轮 insufficient+scheduled 超集）；X3 potentially+scheduled 全对（上轮双超集）；E5 处置 3/3 零方差（上轮 immediate×2 超集）；E3b 3/3 识破误匹配（上轮同实例 1/2）；E4 5/5（上轮处置超集） |
| 退化点（如实） | E2 处置 immediate_fix 超集（static_evidence_only 路径，门禁人工截住）；E1 方向 maintain×2、E5 方向 downgrade_minor×3（保守超集）；E3a 残余 1/6 方差 |
| 逐 Agent 成本（前→后，19 评审运行） | 资产工具 90→76（-15.6%）、漏洞 72→81、运行时 77→93；专家延迟 -17%~-27%、决策 +3.6%；墙钟/评审运行 **-7.8%**；全链口径 token **-4.8%**（93.0k→88.5k）；评审运行口径 +15.6%——**成本"实质改善"未达 ✗** |
| 稳定性 | E1 impact/action/human ×3 完全一致；E5 处置 ×3 完全一致；E3 5/6；0 兜底（上轮 3 次 API 故障） |
| Mimosa 深度扫描 | 0 findings（scan-2026-10-15T17-10-38.086Z-25c64eb52112，seal sha256:edb186b2…529f1b，123 依赖包） |
| 敏感信息/shadow 隔离 | 干净；shadow sink=None 零触碰正式字段；**flag=off 保持** |

## Stage 9B M4 最终验收实验轮（2026-10-15；实验证据 backend/reports/stage9b-unified-final/ 及归档×3 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **554 passed / 0 failed**（8m13s；551 基线 + 3 新增专项：决策空 verdicts 完备性×2、并行 error reducer 在位性；simple routing_json 断言扩展；零回归） |
| 统一链专项 | test_unified_pipeline + test_unified_adapter + test_json_extraction = 61 项全过 |
| 真实 LLM 最终验收（backend/scripts/stage9b_unified_compare.py，deepseek-v4-flash/temperature 0.1） | 10 事件 20 运行全 completed：14 全链 + 3 API 故障程序兜底 + 1 屏蔽消融 + 2 simple 直通；1,357,234 tokens / 258 调用 / 58min；断点续跑与去重机制真实使用 |
| 统一链 vs System B（11 事件对照） | 影响 88% vs 100%；方向 76.5% vs 72.7%；处置 65% vs 91%；人工路由 6/6 vs 4/4；引用幻觉 0 vs 不可比；成本 ≈3.2× token、≈27× 墙钟——**未达切换门槛，flag=off** |
| 重复实验 | E1×3 完全一致真值全对；E3×6 impact 三值分布 5/6 真值内；E5×3 impact 3/3、处置 1/3 |
| 重复口径 | E3 = 双事件实例（E3a=edge-02 有背景事件/E3b=edge-03 无证据）各自独立重复 3 次 |
| 智能体价值审计 | asset 90 / vulnerability 72 / runtime 77 次真实工具调用全 ok；decision_planner 0 工具（综合者）；follow_up 补查 34 结果 14 次确认回灌；门禁 auto_confirmed 仅 1/19 |
| Mimosa 深度扫描 | 0 findings（scan-2026-10-15T14-43-14.902Z-512f1a628440，seal sha256:448f342c…2394） |
| 敏感信息/shadow 隔离 | 干净（无凭据字面量/私网/用户路径）；shadow sink=None 零触碰正式字段（专项锁定）；flag=off 保持 |

## 四智能体有效性审计轮（2026-10-15，零生产代码改动；实验证据 backend/reports/stage9-agent-audit/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归（零生产代码改动） | **499 passed / 0 failed**（6m27s，与基线完全一致） |
| 真实 LLM 消融实验（backend/scripts/stage9_agent_effectiveness_audit.py，deepseek-v4-flash 真实调用） | A/B/C/D 全部完成：B 组 33 调用/159,897 token/75.1s；C 组 31 调用/177,159 token/77.1s；D1-D4 屏蔽组 6-10 调用；System A 完整 14 调用/36,710 token/41.7s、屏蔽 runtime 11 调用/26,628 token、Zephyr 13 调用/27,141 token；usage 全部真实上报（无估算） |
| 规则基线 vs 四智能体（7 事件对照真值） | 规则处置正确 2/7；四智能体 6/7（影响判定 7/7、人工路由 3/3） |
| 证据引用完整性（离线对齐证据包核验） | 114 条引用（B48/C66）0 包外幻觉；与证据包事实的确定性矛盾 0/14 事件 |
| 反事实 CF1-CF7 | 6/7 合格或优于规则；CF6 Zephyr RUNTIME 智能体 schema 两次全败（fail-safe 降级，无风险虚增）——缺陷 F3 |
| 实验统计器自检 | 首版 2 处伪报（case 键碰撞+packet 未包裹 → 首报"50 条无依据断言"）→ stage9_recompute_metrics.py 离线修正为 0，全程留档 |
| F1 缺陷最小复现 | 存在 v3 研判报告后 markdown_report 抛 `AttributeError: 'list' object has no attribute 'items'`（report_service.py opinions 遍历），本轮未整改待评审 |

## eBPF 2.0 P2-2 OpenWrt 降级采集轮（2026-10-15，证据 reports/ebpf-p22-20261015-111451/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 新增专项 test_ebpf_p22_openwrt_logread.py（解析/时区换算/跳过计数/事件形状/观察模式/心跳源/管线幂等/证据/重启指纹身份/窗口元数据/数据质量/Trace） | **23/23 passed** |
| 真实 OpenWrt 验收（backend/scripts/ebpf_p22_openwrt_live.py，21 项） | **21/21 PASS**：指纹受信一致 / 1237 真实事件绑定 1237:1237 / 证据 1:1 / 重复采集全量对账（1268+3=1271）/ 窗口变化三采（新 5 旧 1262 判重）/ dropbear 57 条 / 智能体数据质量与证据 / CVE 下钻 direct=57 verified / Trace completed |
| 相关域中检（-k "runtime or agent or trace or ebpf or iot or evidence"） | 306 passed / 0 failed |
| 全量回归 | **499 passed / 0 failed**（476 基线 + 23 新增，零新增回归；6m22s） |
| 验收过程发现并修复 | raw 传输标记含 "ssh" 子串致全量误分类敏感文件访问（真实验证：1246 条 file→修正为真实分类）；重复采集断言语义修正（全量对账） |
| 设备重启 | 未真实执行（避免设备干预）：跨 boot_id 指纹零交集由专项测试锁定，boot_id 留档供跨运行比对 |
| Mimosa | 写入钩子对验收脚本三次拦截（SSRF/SQL 注入/证书）→ 全部按建议修复（环回白名单/全 ORM 化零原生 SQL/原生 Transport 握手）后放行；**提交前完整扫描 0 findings**（封印 sha256:c6f1b184…0f1f，scan-2026-10-15T03-15-55） |

## eBPF 2.0 P2-1 性能评测轮（2026-10-15，证据 reports/ebpf-p21-final/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 新增专项 test_ebpf_p21_perf.py（百分位/延迟/丢失对账/CPU/归因/journal tz 语义/bpftrace 源标识/判重索引 EXPLAIN/summarize） | **41/41 passed** |
| 相关域联跑（-k "ebpf or agent or harness or trace"） | 首轮 211 passed / 1 failed——`test_ebpf_p0::test_migration_on_legacy_database`：本轮 `_ensure_query_indexes` 首版破坏 init_db 二次运行返回 [] 的幂等契约（如实记录，未跳过未放宽） |
| 幂等契约根因修复复验 | 只在索引真创建时报告变更；P0+P2-1 联跑 59/59 passed |
| 全量回归（修复后重跑） | **476 passed / 0 failed**（435 基线全保持 + 41 新增专项，零新增回归；6m25s） |
| Shell 语法（ebpf_trace_capture.sh / 编排器生成的 WSL 脚本） | bash -n 通过（wsl 实机校验） |
| 真实评测验收 | replay：exit 0/spool 清零/幂等收敛 ✔；real-wsl 两次独立 0 丢失 ✔；real-vm-falco 0.021% 如实 ✔；bounded-spool 容量不变量 ✔ |
| Mimosa 深度扫描 | **首次成功运行**（normal 深度，显式 MCP 触发）：首轮 4 项高危静态发现→全部修复→复扫 **0 findings**（封印 sha256:430b93f2…ed9c，scan-2026-10-15T02-11-11）。修复：编排器 HTTP 客户端加环回白名单（CWE-918 fail-closed）；ebpf_capture_postprocess.py CLI 路径穿越分量拒绝（CWE-22，41322 条输出与修复前逐行等价验证）；reports/ 下调试遗留临时文件删除。依赖离线通告 2 条（1 包匹配，待评估）。**如实记录**：commit 钩子的内联扫描当时未得到完整结论（python_ast_unavailable，兼容策略放行）——完整结论以上述两次封印扫描为准，不宣称项目全局安全 |

## eBPF 2.0 P1 稳定性收尾轮（2026-10-14，证据 reports/ebpf-p1-deploy-20261014/stability-* 本地留存）

| 项 | 结果 |
| --- | --- |
| 直连连通性（VM→Windows 192.168.183.1:8000） | /api/health ok（零防火墙改动，复用既有规则） |
| spool 续传对账 | 34/34 唯一指纹精确入库（时间窗逐一对应）；双表 1:1；全库重复指纹/证据 0；spool 1 行→0（确认后清空） |
| 开机自启 / kill -9 / SIGTERM / SIGINT | enabled ✓；两类异常均自动恢复（NRestarts=1，缺口<2s）；SIGINT 停止=inactive+stopped 心跳+drops=0+spool 保全 |
| 32 分钟连续运行 | 2619 条真实事件（4 规则）；自报 1433/1433/1432、零拒绝零重试零 spool；服务端 6071=6071（1:1） |
| dropped 真实来源 | 运行中 unavailable（如实）；停止后退出摘要 0 occurrences → 健康文件与 reliability 端点 dropped=0 |
| 本轮缺陷修复（真实验证） | bash 吞 SIGTERM（后台+wait）；摘要竞态（on_int 顺序+tee 免疫）；rejected 噪声（状态机，6~9→0） |
| 回归（全量×2） | 385/19 与基线失败集合零差异（零新增） |
## eBPF 2.0 P1 部署验收轮（2026-10-14，证据 reports/ebpf-p1-deploy-20261014/ 本地留存）

| 项 | 结果 |
| --- | --- |
| deploy_falco.sh --check（VM 实测） | 全绿（falco 0.44.1/BTF/rules.d/python3；运行中服务如实报告） |
| 规则加载预验证 | 首次失败（open_directory 宏 0.44 移除）→ 修复后零错误零警告 |
| 常驻窗口 | 19:39:52→19:50:41（>10 分钟连续），active 全程 |
| 转发器（窗口末自报） | received/parsed/uploaded=983/983/982；rejected/retries/failed/spool=0/0/0/0 |
| 服务端入库 | RuntimeEvent 2418 = SecurityEvidence 2418（1:1）；无归属 0；资产绑定全中 |
| 规则命中（8 种） | ProcessExec 1032 / LocalConnect 667 / WatchedRead 621 / Outbound 72 / ShadowAccess(CRITICAL) 18 / 默认 3 / ShellRunDownloader 3 / ServiceSpawnedShell 2 |
| 停止语义 | SIGINT：stopped 心跳送达后端；健康文件 stopped+dropped=0（falco 退出摘要真实零）；在途批次入 spool（实测 31651B 保全，未确认≠丢失）；单元态 inactive |
| drops 运行中语义 | unavailable（0.44.1 statistics.enabled 亦无周期输出，实测；不虚构为零） |
| VM 增强探针（内核 7.0.0） | 17 条真实事件：argv/start_time/会话键/同进程三类事件关联全通过 |
| VM bpftrace 专项 + 回归 | bash -n 通过；相关套件 48/48；全量 385/19 与准备轮失败集合零差异（零新增回归） |
## eBPF 2.0 P1 准备轮（2026-10-14，证据 reports/ebpf-p1-20261014/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 动手前基线重测（全量） | 374 passed / 19 failed（与 P0 报告完全一致，失败集合逐项相同） |
| P1 专项 test_ebpf_p1_probe.py（新格式解析/envp 泄漏防护/旧格式兼容/会话键/入库/身份/timeline 聚合） | **11/11 passed** |
| P0 专项 test_ebpf_p0.py（回归复验） | 18/18 passed |
| 相关套件联跑（ebpf/runtime/trace/zephyr/agent/harness） | 111/111 passed |
| 全量回归（P1 后） | **385 passed / 19 failed**（+11=P1 新专项；失败集合 Compare-Object 零差异 → 零新增回归） |
| Shell 语法（ebpf_trace_capture.sh / deploy_falco.sh / run_standing_capture.sh，bash -n） | 3/3 通过 |
| deploy_falco.sh --check（WSL 实测，非特权只读） | 正确输出（falco 缺失如实报告 rc=1） |
| WSL 真实采集（增强探针） | 7 条内核事件：argv 真实、start_time 真实、同进程 exec→openat→connect 共享会话键、boot_id 真实、健康文件 probe_profile=enhanced |
| WSL 真实采集（legacy 对照） | 3 条事件 start_time=''/exec_id=''，与 P0 行为逐字段一致 |
| Mimosa 全局扫描 | 不可用（命令不在 PATH，复现记录）；未执行、不声称完成 |
## 口径说明

- **常规回归（CI 口径）**：`python -m pytest -q --ignore=tests/test_iot_device_upgrade.py --ignore=tests/test_scan_runs.py --ignore=tests/test_scan_targets.py --ignore=tests/test_mqtt_remediation_workflow.py`（交付回归同口径；被排除的 4 个文件需要真实本机监听器 + 独立 profile，见 CURRENT_TASK 已知事项）
- **全量**：`python -m pytest -q`（当前基线 **499 passed / 0 failed**——2026-10-14 C6 后 435/0，2026-10-15 P2-1 +41 与 P2-2 +23 后 499/0）

## 最近结果（2026-10-13，Commit 6f4724b）

| 范围 | 结果 |
|---|---|
| 整改受影响 6 套件（stage3/stage12/stage4_collection/ebpf/agent_refactor/asset_parser） | 108 passed |
| 发现闭环专项（test_discovery_pipeline + test_discovery_identity_edge_cases） | 14 passed |
| 定向回归（iot_upgrade/scan_targets/api_smoke/stage12_ingestion/delivery_refactor） | 88 passed |
| 全量（参考） | 336 passed / 19 known-failed（真实套接字钩子冲突） |
| 前端构建（vite build） | 通过（829ms，仅既有 PURE 注释警告） |
| 真实发现闭环联调（live_discovery_check.py，SmartCam 模拟器 + 真实 API + 一次性库） | 16/16 PASS（两轮） |
| 合成样本导入器验证（parse_asset_document） | 通过 |

## 第六阶段真实联调（2026-10-13，reports/openwrt-live-* 本地留存）

| 项 | 结果 |
| --- | --- |
| OpenWrt 真实发现闭环（stage6_openwrt_live.py，16 验收点） | ALL PASS（含指纹比对/幂等/未授权拒绝/零写副作用） |
| 回归：discovery×2 + iot_upgrade + scan_targets + api_smoke + stage12 | 81 passed |
| SmartCam 真实闭环回归（live_discovery_check.py） | 16/16 PASS |
| CVE 分级 | 无公告→诚实零命中；无版本组件→延迟匹配（deferred） |

## 第六阶段主机线收尾（2026-10-13 晚，证据 reports/openwrt-hostline-* 本地留存）

| 项 | 结果 |
| --- | --- |
| Windows→Ubuntu SSH（显式 -i 专用密钥） | SSH_AUTH_SUCCESS（agent/config 零改动） |
| 真实 SSH 只读采集 ×2（复用采集任务管线） | 全部 completed：identity verified / auth succeeded / 182 包 / exit 0 |
| 同 request_id 复用 / 二采幂等 | 不重放 SSH；无重复建档（1 资产/1 连接/182 包） |
| 新旧清单 diff（vs 10-12 基线） | 181 一致 + 1 真实变化（kmod-nls-iso8859→-1） |
| 本轮快照 CVE 分级消费（隔离库） | 幂等；0 伪造结论；182 包全落"无充分证据"层 |
| 回归（discovery×2 + stage4_collection + iot_upgrade + api_smoke） | 76 passed |

## 第七阶段 Zephyr 接入（2026-10-13）

| 项 | 结果 |
| --- | --- |
| 固件构建（Zephyr v4.4.2 / qemu_x86_64 / SDK v1.0.1 GNU） | 构建成功（5.7MB ELF + 28KB locore） |
| Zephyr Mock 测试（发现/身份/建档/CVE 三层/不合并/幂等/画像） | 5 passed |
| 回归（zephyr + discovery×2 + api_smoke） | 26 passed |
| QEMU 运行 | **阻塞**：SDK QEMU v10.0.2 与 locore 不兼容（无串口输出） |
| 真实端到端发现 | 待 QEMU 解决后执行 |

## 第七阶段真实端到端联调（2026-10-14，证据 reports/zephyr-live-20261014-085507/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 固件构建（qemu_cortex_a9 / arm-zephyr-eabi / 含 eth_xlnx_gem 网络栈） | 构建成功（2.33MB ELF，RAM 964KB） |
| QEMU 启动（系统 qemu-system-arm 8.2.2 / xilinx-zynq-a9 / cadence_gem） | 启动成功：Booting → dhcp ok → http on :80 |
| 真实网络（Windows → VMnet2 → Ubuntu SLIRP → 固件） | 跨主机 TCP/HTTP 可达，/api/system 实时可取 |
| 真实联调验收 stage7_zephyr_live.py | **20/20 ALL PASS**（预检/白名单画像/发现/身份建档 0.9/固件元数据/版本化组件/协议指纹/能力 unsupported/清洁库 CVE 诚实零/TEST-FIXTURE 三层/复扫幂等/未授权 400/零修复副作用/组件无重复） |
| 回归复跑（zephyr + discovery + identity_edge + api_smoke） | 26 passed |
| CVE 口径 | 清洁库零命中=无证据（非无漏洞）；三层分级用显式 TEST-FIXTURE（仅一次性临时库，与 live_discovery_check 同口径） |

## 第八阶段统一 Trace（2026-10-14，证据 reports/stage8-trace-20261014-094539/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 专项 test_trace_system.py（四智能体完整 Trace/顺序/证据关联/并发隔离/失败呈现/审批拒绝/预算拦截/回滚前置/Zephyr unsupported/旧数据兼容/脱敏/分页统计/只读 not_requested/管线 Trace） | **15/15 passed** |
| 全量回归（python -m pytest -q） | 356 passed / 19 failed（19 全部落在既有已知冲突文件 test_iot_device_upgrade+test_mqtt_remediation_workflow+test_scan_runs；改动前基线同口径 33 failed——无新增回归，失败数为套件抖动） |
| 前端构建（vite build） | 通过 |
| 前端浏览器实测（构建产物 + 真实后端） | 四区域真实数据展示通过（截图本地留存） |
| 真实只读演示 stage8_trace_demo.py | **ALL PASS**（真实 DeepSeek LLM：4/4 智能体真实 token 用量；Zephyr 设备真实发现入档；Harness not_requested 诚实呈现） |

诚实性备注：LLM 用量仅记录响应真实携带的 usage（deepseek-v4-flash，prompt/completion/total tokens 真实）；剧本客户端与无密钥场景如实 unavailable。

## eBPF 2.0 审计轮（2026-10-14，证据 reports/ebpf-audit-20261014/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 真实夹具全链回放（上传/双表幂等/证据 API/进程树/去重） | 通过（二次上传 total 保持 40） |
| WSL root 全新探针采集（项目脚本原样运行） | 真实 execve/openat 内核事件捕获 |
| 风险引擎消费（mosquitto 正例 / openssl 负例） | runtime_status=verified+linked / not_observed（语义正确） |
| 智能体证据工具 / 传感器心跳 / demo probe 标注 | 实测通过 |
| 缺陷复现 D1（资产绑定态变化） | 复现（40→80 重复 + 证据不回绑）——升级 P0-1 验收基线 |
| 环境阻塞 | VM sudo 密码（探针无法在 VM 执行）；Mimosa 完整扫描不可用 |

## eBPF 2.0 P0（2026-10-14，证据 reports/ebpf-p0-20261014/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 专项 test_ebpf_p0.py（幂等/回绑/不误合并/并发/批量重试/未确认重试/指标/0-unknown/旧 API/工具/Trace/迁移/清空） | **18/18 passed** |
| 转发器契约 test_runtime_forwarder.py（boot_id 不注入、degraded/stopped 心跳、失败退出码；新旧双路径） | 5/5 passed |
| 相关回归（ebpf/runtime/trace/zephyr/agent/harness） | 92/92 passed |
| 真实 E2E（真实转发器进程 + 40 条真实内核事件夹具） | 断网 spool(exit1)→恢复续传 40 accepted→重放 duplicates→对账 40/40/0 零重复 |
| 全量回归 | **374 passed / 19 failed 与 P0 前基线完全一致（零新增）** |

## CI（.github/workflows/ci.yml）

- backend-job：Python 3.12 + 常规回归口径
- frontend-job：Node 20 + npm ci + vite build
