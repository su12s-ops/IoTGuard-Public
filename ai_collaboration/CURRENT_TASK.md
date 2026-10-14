# 当前任务

> 每完成一个任务更新本文件。最后更新：2026-10-14

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

- eBPF 2.0 P2 剩余：P2-1 性能评测落地、P2-2 OpenWrt 降级采集（syslog 尾随）
- 第九阶段待用户指令（未开始）
- Private 仓库删除申请：本仓库独立 Clone/构建/运行验证与归档核验已通过，可向用户提交删除申请

## 已知事项

- ~~后端 4 个真实套接字测试文件与 conftest 审计钩子冲突~~ → **已根因修复**（de9f1f9 环回放行；全量 435/0）
- 已推送的 P1 部署/稳定性报告（f8b9f80…1368fae）含实验室 VMnet8 私网地址与 VM 用户名（具体值见那些报告，此处不再复写）——RFC1918 实验网段、不可公网路由，已如实告知用户；后续报告遵循"具体地址仅存本地证据"惯例，不再写入跟踪文件
- Mimosa 完整项目扫描仍不可用（python_ast_unavailable）；本轮推送以人工多维敏感扫描（凭据/私网标识/密钥材料/二进制/大文件）为闸门，如实记录，不宣称全局安全审计已完成
- 竞赛章程对公开时点的要求待用户确认
