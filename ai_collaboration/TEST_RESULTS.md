# 测试结果

> 记录最近测试口径与结果，与 CI 保持一致。最后更新：2026-10-15

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
- **全量**：`python -m pytest -q`（当前基线 **476 passed / 0 failed**——2026-10-14 C6 环回放行修复后 435/0，2026-10-15 P2-1 新增专项 41 项后 476/0）

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
