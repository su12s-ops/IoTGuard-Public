# 当前任务

> 每完成一个任务更新本文件。最后更新：2026-10-14

## 最近完成

**Git 完整托管与自动同步机制建设**（2026-10-13）
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

## 下一步（等待审阅，不自动开始）

- eBPF 2.0 正式实施：P0（D1 修复/丢失闭环/转发器 2.0/清空语义）→ P1（argv+session-id 探针、Falco 规则部署与常驻、证据链×Trace）→ P2（性能评测、OpenWrt 降级采集、Agent 工具增强）
- 实施需 VM sudo 授权窗口（Falco 常驻与规则部署）
- 第九阶段待用户指令（未开始）

## 已知事项

- 后端 4 个真实套接字测试文件（test_iot_device_upgrade / test_mqtt_remediation_workflow / test_scan_runs 部分）与 conftest 审计钩子冲突，常规回归显式排除（与交付回归口径一致），待加独立 profile 开关
- Private 初始提交 a05f3c8 历史含整改前环境标识——Private 保持历史不重写；Public 不继承该历史（独立初始化）
- 竞赛章程对公开时点的要求待用户确认（Public 仓库内容已脱敏）
