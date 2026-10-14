# 最近一次开发结果

> 本仓库（IoTGuard-Public）为唯一正式开发仓库；每完成一个任务在此归档摘要并提交。最后更新：2026-10-14（单一仓库制落地，双仓同步取消）

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
