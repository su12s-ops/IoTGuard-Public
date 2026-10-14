# IoTGuard eBPF 2.0：源码审计与升级设计报告

日期：2026-10-14。工作副本：`E:\IoTGuard-Project`（审计基线 Private commit `597097a`）。
本轮为**审计与设计**交付：全部结论以实际源码 + 真实运行验证为依据；未实施的升级能力一律标注为"计划"，不描述为已实现。

---

## 1. 现有 eBPF 真实架构图

```
┌─ 采集端（Linux，需 root）──────────────────────────────────────────────┐
│ 路线 A：bpftrace 自研探针（collector/ebpf_trace_capture.sh）             │
│   tracepoint:syscalls:sys_enter_execve    → 进程（pid/ppid/uid/comm/文件名/父进程名）
│   kprobe+kretprobe:tcp_v4/v6_connect      → 网络（进程 → 目的 IP:port）
│   tracepoint:syscalls:sys_enter_openat    → 文件（受控路径前缀过滤，读/写判定）
│   后处理（python3）：uid→用户名、纳秒→ISO（/proc/stat btime）→ 统一 JSONL   │
│ 路线 B：Falco 现代探针（collector/run_falco_capture.sh / capture_ebpf.sh）│
│   falco -o json_output=true（standalone，暂停 falco-modern-bpf 服务）     │
│   自定义规则 collector/linuxguard_iot_rules.yaml（进程/链式/网络/文件）    │
│ 路线 C：BPF-LSM 实验（collector/ebpf_lsm_monitor.py，observe-only）       │
│   能力探测（/sys/kernel/security/lsm 含 bpf？BTF？bpftrace -l lsm:*）     │
│   lsm:file_open observe（enforce 被显式拒绝，exit 4——不假装阻断）         │
│ 传输：collector/ebpf_event_collector.py（JSONL→HTTP 转发器）             │
│   stdin/文件 → POST /runtime/ebpf/events（逐条）；心跳 → /runtime/sensors/heartbeat
└──────────────────────────────────────────────────────────────────────┘
                              │ multipart 上传（capture 脚本）或逐条 POST
┌─ 后端（FastAPI）───────────────────────────────────────────────────────┐
│ routers/runtime.py（/runtime/ebpf/*、/runtime/evidence/*、/runtime/lsm/*、│
│                    /runtime/sensors/heartbeat、/runtime/assets/{id}/…）  │
│ services/ebpf_event_collector.py                                        │
│   parse_event_lines → normalize_event（Falco/Tetragon/通用三格式归一）    │
│   → classify_event（类别/战术/技术/风险信号）                            │
│   → _asset_for_event（hostname/asset_id 绑定，冲突拒绝）                 │
│   → RuntimeEvent（event_fingerprint 幂等）+ events.jsonl 双写            │
│   → services/security_evidence.py persist_evidence                      │
│     → SecurityEvidence（SE-<hash16>，evidence_hash 幂等；process/       │
│       network/file 三类；受控路径/严重度定级；进程树 build_process_tree）  │
│ 消费方：                                                                 │
│   ① 智能体工具 tools.py query_process/network/file_evidence + process_tree │
│      （编排器 validate_runtime_report 强校验 evidence_id 真实存在）       │
│   ② risk_engine.calculate_risk → evaluate_runtime_evidence             │
│      （runtime_status/reachable_status/adjustment → risk_factors_json）  │
│   ③ event_review_pipeline（复核证据包）                                  │
│   ④ 前端 RuntimeMonitor.vue / RuntimeEvidencePanel（真实 API，历史数据） │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. 审计十项逐一结论（源码 + 调用链 + 真实验证）

### 2.1 真实存在的 eBPF 源码、加载器与挂载点

| 组件 | 路径 | 挂载点（真实） | 加载器 |
|---|---|---|---|
| 综合探针脚本 | `collector/ebpf_trace_capture.sh` | tracepoint `syscalls:sys_enter_execve`；kprobe+kretprobe `tcp_v4_connect`/`tcp_v6_connect`；tracepoint `syscalls:sys_enter_openat`（5 个受控路径前缀过滤） | bpftrace |
| LSM 实验监控 | `collector/ebpf_lsm_monitor.py`（`OBSERVE_PROBE`） | LSM `file_open`（仅 observe；`enforce` 分支显式拒绝，返回码 4） | bpftrace |
| Falco 采集 | `collector/run_falco_capture.sh`、`collector/capture_ebpf.sh` | Falco 现代探针（falco 自带，syscall 级） | falco（CO-RE modern probe） |
| JSONL 转发器 | `collector/ebpf_event_collector.py` | —（用户态转发，`post_event`→`/runtime/ebpf/events`） | — |
| 自定义规则 | `collector/linuxguard_iot_rules.yaml`（进程 exec、服务→shell、shell→下载器链、对外/本地连接、受控文件） | — | — |

**无自研 C/libbpf/CO-RE 程序**；Tetragon 仅作为 `normalize_event` 的兼容输入格式与 `--source tetragon` 选项存在（`ebpf_event_collector.py:162`），本项目未部署 Tetragon。

**真实验证**：在 WSL2（内核 6.6.87.2-microsoft-standard-WSL2，bpftrace v0.20.2）以 root 运行 `ebpf_trace_capture.sh`，真实挂载三类探针并捕获全新内核事件（示例：`execve cat（pid 1546/ppid 1518/uid 0→root）`、`openat /etc/shadow read`，纳秒时间戳换算为 ISO）。Ubuntu VM 侧 bpftrace/falco 均已安装但 sudo 需密码，本轮无法在 VM 上直接执行（如实记录，见 §2.10）。

### 2.2 真实内核事件与模拟事件的区别

- **真实**：`source=ebpf_bpftrace`（bpftrace 路线）与 `source=falco*`（Falco 路线）；`_observation_mode()`（`ebpf_event_collector.py:336`）分别标注 `ebpf`/`sensor` 模式。
- **模拟**：`source=runtime_probe_*`，仅由 `POST /runtime/ebpf/demo` 生成（routers/runtime.py:128），标注 `probe` 模式。
- **夹具**：`backend/tests/fixtures/ebpf_real_capture.jsonl` 为阶段二 WSL 真实采集的 40 条内核事件（主机名已合成化 `lab-ebpf-host`），测试与本次审计回放共用。
- **真实验证**：demo 接口生成 4 条事件，入库 `source=runtime_probe_exec/network/privilege/patch`，与真实来源严格分离；前端 `observationLabel()` 按 source 显示"真实 eBPF / 运行探针"。

### 2.3 Falco 的安装、启动、规则与事件接收

- **安装**：Ubuntu VM 实测 `falco 0.44.1（Libs 0.25.4）`，`/etc/falco/` 含 `falco.yaml`、`falco_rules.yaml`、`falco_rules.local.yaml`、`rules.d/`；systemd 单元 `falco-custom`、`falco-kmod-inject` 存在但均为 inactive。
- **启动方式**：采集脚本采用 standalone 短时运行（`sudo timeout Ns falco -o json_output=true -o stdout_output.enabled=true > out.jsonl`），运行前停 `falco-modern-bpf` 服务、结束后恢复。
- **规则**：项目自定义规则 `linuxguard_iot_rules.yaml`（进程/链式/网络/文件四类）**未部署**到 VM `/etc/falco/`（grep `LinuxGuard` 无命中）——实际采集使用 Falco 默认规则集。
- **接收**：文件级 multipart 上传 `POST /runtime/ebpf/upload`（解析在 `parse_event_lines`）或常驻转发 `ebpf_event_collector.py`（stdin→逐条 POST，需控制令牌）。当前无常驻采集部署在运行（采集为按需脚本驱动）。

### 2.4 可获取的进程/网络/文件/权限信息

| 维度 | 现有字段 | 缺失 |
|---|---|---|
| 进程 | pid/ppid/uid→用户名/comm/可执行文件名/父进程名（bpftrace）；Falco 路线另有 proc.cmdline/exepath（规则输出） | bpftrace 路线 execve **无完整 argv**（仅 filename）；无 exec_id/进程唯一生命周期键；无容器上下文（`container_id` 字段存在但该路线无来源） |
| 网络 | 进程→目的 IP:port（v4/v6） | kretprobe **不校验返回值**→失败连接也成事件；无 DNS、无 L7、无发送/接收字节 |
| 文件 | 受控路径（/etc/mosquitto、/etc/iotguard、/etc/passwd、/etc/shadow、/opt/firmware）读/写判定、进程、时间 | 仅 5 个硬编码前缀；无通用路径策略化配置 |
| 权限 | uid/用户名；LSM 路线 observe `file_open`（passwd/shadow/mosquitto/iotguard） | 无 capability 变更、无 setuid 监控；LSM enforce 明确不做（正确边界） |

### 2.5 事件存储与资产绑定

- 存储：`runtime_event` 表（`event_fingerprint` 幂等、`asset_id` 可空 FK、hostname）+ `security_evidence` 表（`SE-<hash16>`、`evidence_hash` 唯一、`device_id=hostname`、`asset_id`）+ `LINUXGUARD_EVENT_FILE` JSONL 双写（`append_events`）。
- 查询主源是 DB（`load_runtime_events(db=...)`）；`clear_events` 同时清 DB 与文件，但**不清 SecurityEvidence**（前端"清空事件"后证据层仍保留——双存储语义不一致，见 D9）。
- 绑定链：`_asset_for_event`（asset_id 精确或 hostname→LinuxAsset 匹配，冲突拒绝）→ `RuntimeEvent.asset_id` → `persist_evidence` 透传。
- **真实验证（发现缺陷 D1）**：资产注册前上传 40 条 → `asset_id=NULL`（device_id 兜底，查询/工具可用）；注册资产后**重传同一采集** → RuntimeEvent 指纹基含 `asset_id`（`_persist_events:356`）→ 指纹变化 → **不去重，产生 40+80 双份**；SecurityEvidence 因 hash 命中旧记录而**保持未绑定**（旧 hash 的记录 asset_id=NULL 一直返回）。

### 2.6 事件丢失、重复、字段缺失

- **重复**：双层幂等（RuntimeEvent 指纹 + evidence_hash）实测有效（同文件二次上传 total 仍 40）；但 D1 场景（资产绑定态变化）会破坏幂等。
- **丢失**：① 转发器 `pending` 队列 maxsize=256（读线程阻塞背压，进程崩溃即丢）；② 每事件单次 HTTP POST，`OSError` 即退出（`main` 返回 1），**无重试/无断点续传**；③ bpftrace 丢事件提示（stderr `N events lost`）写入 `.err` 文件但**未解析**进遥测；④ Falco drops 统计未采集；⑤ 传感器 `dropped_events` 仅接受 supervisor health 文件（默认 `unavailable`）——采集可靠性当前**不可度量**。
- **字段缺失**：见 §2.4；另 `identity_fields`（exec_id/sensor_id/boot_id/executable 等）模型已备，bpftrace 路线大部分为空。

### 2.7 CVE 引擎是否消费 eBPF 证据

- `matching_engine.run_matching`：**不消费**运行时证据（纯版本/公告/指纹路线，设计上证据不影响受影响判定）。
- 消费发生在风险层：`risk_engine.calculate_risk` → `load_runtime_events(db, limit=5000)` → `evaluate_runtime_evidence(asset, package, services, events)` → `runtime_status/reachable_status/adjustment` 写入 `risk_factors_json.environment`。
- **真实验证**：审计库中真实夹具事件（mosquitto 进程+1883 连接）+ mosquitto 包/服务 → `runtime_status=verified`、`reachable_status=linked`；openssl 包（无相关进程）→ `not_observed`（语义正确，"未观测≠安全"）。复核线 `event_review_pipeline` 证据包同样引用运行时事件。

### 2.8 Runtime Agent 是否直接使用真实动态证据

是。`agents/tools.py:218-260`：`tool_query_process_evidence / query_network_evidence / query_file_evidence / query_process_tree` 直查 `SecurityEvidence`（`query_evidence`/`build_process_tree`），返回真实 `SE-*` 记录（实测 3 条进程证据含真实 pid/ppid）。编排器 `validate_runtime_report` 强校验 `evidence_id` 必须存在于库——伪造证据的智能体输出会被拒并降级（阶段三测试覆盖，本轮实测工具路径）。第八阶段真实 DeepSeek 演示中 runtime agent 即用该工具链。

### 2.9 前端展示的是实时/历史/测试数据

- `RuntimeMonitor.vue` 全部数据来自真实 API（`/runtime/ebpf/status|summary|events|correlations` + 行为链接口）——展示**入库历史数据**（手动刷新，无 WebSocket/SSE 实时推送）。
- 数据是混合来源：真实 eBPF/传感器 + probe 测试事件，凭 `observation_mode`/source 标注区分（"真实 eBPF / 运行探针"）；demo 生成明确提示"以 probe 模式入库，不会标记为真实 eBPF"（实测符合）。

### 2.10 Ubuntu / OpenWrt / Zephyr 各自真实采集能力

| 终端 | 内核采集 | 实际验证状态 |
|---|---|---|
| Ubuntu VM（内核 7.0.0-28-generic） | bpftrace ✅ 已装；falco 0.44.1 ✅ 已装；**LSM 列表无 bpf**（lockdown,capability,landlock,yama,apparmor,ima,evm）→ BPF-LSM 钩子不可用 | 安装状态实测；探针执行被 sudo 密码阻塞（环境限制，如实记录） |
| WSL2（6.6.87.2） | bpftrace v0.20.2 ✅（root 可用）；falco 未装 | **本轮已实测真实探针采集**（路线 A 全链路） |
| OpenWrt VM | **无 eBPF 能力**（无 bpftrace/BPF 加载条件）；采集=SSH 包清单（阶段六已验证） | 阶段六实测；运行时证据层 unsupported |
| Zephyr QEMU 终端 | ebpf_runtime/ssh_inventory/package_inventory 全部 unsupported（阶段七/八 capability_marks 实测） | 已实测标注 |

---

## 3. 成熟项目对比矩阵

对标依据：[Tetragon 官方文档（Execution Monitoring / Tracing Policy / K8s Filtering）](https://tetragon.io/docs/getting-started/execution)、[Falco Kernel Events](https://falco.org/docs/concepts/event-sources/kernel)与[Modern eBPF probe](https://falco.org/blog/falco-modern-bpf-0-35-0)、[Tracee Architecture](https://aquasecurity.github.io/tracee/v0.8.3/architecture)与[Performance Deep Dive](https://aquasecurity.github.io/tracee/v0.8.1/deep-dive/performance)、[Hubble](https://github.com/cilium/hubble)与[Cilium Flow Logs](https://cilium.io/use-cases/network-flow-logs)。

| 能力 | Tetragon | Falco | Tracee | Hubble | IoTGuard 现状 | 差距分级 |
|---|---|---|---|---|---|---|
| 事件采集 | 专用传感器（process_exec/kprobe/tracepoint/exit）+ 策略过滤在内核态 | 现代 CO-RE 探针（随二进制分发）+ 插件多源 | eBPF 程序内核态过滤 → perf/ring buffer → libbpfgo | eBPF 网络流（L3/L4/DNS/L7，身份感知） | bpftrace 3 类探针 + Falco 默认规则（脚本驱动） | 部分实现 |
| 事件关联 | exec_id/父链标签、K8s 元数据自动映射 | proc.pname/字段 | 进程血统enrichment | Cilium 身份标签（工作负载级） | pid/ppid 进程树（实测）+ Falco 链式规则（未部署） | 部分实现 |
| 检测规则 | TracingPolicy（k8s 命名空间/标签过滤） | YAML 规则引擎（成熟生态） | signatures（GO 插件） | 网络策略可观测 | 自定义 YAML 规则已写**未部署**；后端 classify_event 关键词分类 | 部分实现 |
| 进程上下文 | 完整（exec_id/argv/容器/K8s） | 完整（proc.* 字段族） | 完整（含 ancestry） | N/A（网络域） | pid/ppid/uid/comm（bpftrace 路线无 argv/exec_id） | 部分实现 |
| 性能指标 | gRPC 导出+指标 | syscall drops 统计、缓冲区可调 | **events_lost Prometheus 计数**、9.34MB/s@2CPU 基线 | Prometheus 指标+上下文选项 | **无任何丢失/速率/开销度量** | 尚未实现 |
| 运行时证据输出 | JSON/gRPC 流 | JSON（stdout/file/webhook） | JSON/回放管道 | Flow API/CLI/UI | SecurityEvidence 统一证据层+DB+API（**本项目优势**：证据直接进智能体/风险研判/Trace） | 已实现且有真实证据 |
| 阻断能力 | 有（enforce，策略级） | 有（可选） | 有（可选） | 策略执行 | **明确不做**（observe-only，LSM enforce 被拒绝执行）——项目边界 | 不适用（有意） |

结论：IoTGuard 的差异化在**证据层与研判消费链**（SecurityEvidence → 智能体强校验 → 风险因子 → 统一 Trace），不在采集器本身；升级应以"补可靠性度量与关联键"为主，**不引入 Tetragon/Tracee 级重型依赖**。

## 4. 当前缺陷与技术债

| # | 级别 | 缺陷 | 证据 |
|---|---|---|---|
| D1 | P0 | 资产绑定态变化破坏幂等：指纹含 asset_id → 重传产生重复 RuntimeEvent；SecurityEvidence 不回绑（永久 asset_id=NULL） | §2.5 实测 40→80 |
| D2 | P0 | 采集可靠性不可度量：bpftrace lost events / Falco drops 未采集；dropped_events 默认 unavailable | §2.6 |
| D3 | P0 | 转发器逐事件单 HTTP、无重试、无本地 spool；崩溃即丢 | ebpf_event_collector.py:176-231 |
| D4 | P1 | 无常驻采集部署：全部脚本按需驱动；心跳机制存在但无部署物 | §2.3 |
| D5 | P1 | 进程关联键弱：无 argv、无 exec_id/进程会话键（pid 复用可致树错连） | §2.4 |
| D6 | P1 | Falco 自定义规则未部署（采集实际用默认规则集） | §2.3 实测 |
| D7 | P1 | 无性能指标（事件速率/丢失率/缓冲/探针 CPU 开销） | §2.6 |
| D8 | P2 | connect 不校验返回值，失败连接计入证据 | §2.4 |
| D9 | P2 | "清空事件"仅清 RuntimeEvent+文件，SecurityEvidence 残留 → 双存储语义不一致 | clear_events:718 |
| D10 | P2 | OpenWrt/Zephyr 运行时盲区（如实 unsupported，但无降级采集如 syslog/网络镜像） | §2.10 |
| 边界 | — | LSM enforce 拒绝执行、demo 标注 probe、验证脚本诚实（非缺陷，记录为设计边界） | §2.1/2.2 |

## 5. eBPF 2.0 目标架构（兼容性增量）

原则：**只读监控不变**（不启用内核阻断/设备写）；复用 Falco（0.44.1 已装）与 bpftrace；新增探针仅 2 处；其余为后端关联逻辑。

```
采集端（常驻化）
  bpftrace 2.0 探针（execve+argv+start_time / connect+retval / openat 策略路径）
  Falco 常驻（部署 linuxguard_iot_rules.yaml + json 输出）
  采集器 supervisor：解析 lost-events/drops → 真实 health 文件 → 心跳
  转发器 2.0：批量 + 本地 spool + 重试 + 断点续传
后端
  RuntimeEvidence 统一层（修复 D1/D9：指纹不含 asset_id、绑定回填、清空语义对齐）
  进程会话键（boot_id+pid+start_time 合成 exec-session-id）→ 证据关联链
  性能遥测：events/s、lost、buffer、probe CPU → /runtime/metrics + 心跳
  CVE×运行时：risk_factors 已有 → 增加证据引用进第八阶段 Trace（evidence_refs 已支持）
异构终端
  Ubuntu/WSL：全量探针；OpenWrt：syslog/conntrack 降级采集（可选）；Zephyr：保持 unsupported 如实标注
Runtime Agent
  新增 coverage/lost 查询工具 + 证据新鲜度因子（数据不足时 confidence 降级而非编造）
```

## 6. 分优先级实施计划（含验收方法）

### P0：统一 RuntimeEvidence 及采集可靠性

| 项 | 内容 | 复用/新增 | 验收方法 |
|---|---|---|---|
| P0-1 | 修复 D1：指纹基去除 asset_id；资产注册后证据回绑（重传或后台任务） | 后端逻辑 | 重放 §2.5 审计场景：建资产→重传→行数仍 40、evidence.asset_id 全部绑定（新增回归测试） |
| P0-2 | 丢失计数闭环：supervisor 解析 bpftrace stderr lost 行与 Falco stats → heartbeat.dropped_events 真实值 | 新增采集端小脚本 | 人为缩小 ring 缓冲制造丢失→心跳展示 dropped>0→coverage=degraded（真实环境复演） |
| P0-3 | 转发器 2.0：批量 POST（复用现有 events 接口加批量入口或分块）、本地 spool、指数重试 | 新增（collector 内） | 断网 30s 期间持续喂事件→恢复后全部入库无缺（计数对账测试） |
| P0-4 | 清空语义对齐（D9） | 后端逻辑 | 清空后 evidence summary=0（或接口显式声明 evidence 保留语义并文档化） |

### P1：进程行为关联、动态证据与 CVE 关联

| 项 | 内容 | 复用/新增 | 验收方法 |
|---|---|---|---|
| P1-1 | 探针增强：execve 补 argv 与 process start_time；合成 session-id | **新增 eBPF 探针参数**（bpftrace 内） | 真实采集中 exec 事件含 argv；pid 复用场景 session-id 区分 |
| P1-2 | 部署 Falco 自定义规则 + 常驻（falco -o json_output → forwarder --heartbeat） | **复用 Falco** | VM 上常驻采集 10 分钟，服务→shell→下载器链规则产生真实告警（需 sudo 授权窗口） |
| P1-3 | 证据链关联：进程树/网络/文件证据挂 session-id；风险因子与 Trace evidence_refs 打通 | 后端逻辑 | 第八阶段 Trace /evidence 端点可解析真实 SE-（已有），新增按 session-id 聚合视图 |
| P1-4 | CVE 关联视图：行为链页展示"该 CVE 相关进程证据"（runtime_status 已有 → 前端下钻） | 后端+前端 | 行为链点击→证据明细（真实数据） |

### P2：性能指标、异构兼容与 Runtime Agent 深度接入

| 项 | 内容 | 复用/新增 | 验收方法 |
|---|---|---|---|
| P2-1 | 性能评测方案落地（§7） | 新增脚本 | 产出真实评测报告（速率/丢失/CPU） |
| P2-2 | 异构降级采集：OpenWrt syslog/热连接观测（logread 尾随，标注 source=openwrt_syslog） | 新增（非 eBPF） | OpenWrt 端真实产生日志→入证据层→观察模式标注降级来源 |
| P2-3 | Runtime Agent 工具增强：coverage/dropped/新鲜度查询；证据窗口不足→输出 data_gaps（不编造） | 后端逻辑 | 智能体测试：无证据设备分析→coverage 工具返回 degraded，结论不升级 |
| P2-4 | connect 返回值过滤（D8） | 探针小改 | 失败连接（127.0.0.1:1）不再产生网络证据 |

## 7. 性能评测方案（P2-1 细化）

1. **事件速率**：以固定行为负载（ebpf_selftest.sh 扩展：循环 exec/connect/open）在 60s 窗口采集，统计 events/s（后端入库计数 - 前端生成计数 = 传输损耗）。
2. **丢失率**：bpftrace stderr lost 计数 / supervisor drops / 转发器 spool 对账三方交叉；人为缩缓冲复现（验收 P0-2 同法）。
3. **端到端延迟**：探针时间戳（纳秒→ISO）与后端 `created_at` 差值分布（P50/P95）。
4. **探针开销**：采集开/关两态 `pidstat` 对比 bpftrace 与 falco 进程 CPU%；参考 Tracee 公开基线（2 CPU ~9.34MB/s 吞吐）作数量级对照，不做同条件竞品宣称。
5. **入库性能**：`_persist_events` 批量 40/400/4000 条的耗时（SQLite 事务粒度影响）。
6. 所有指标以真实运行产出报告入 `reports/`，无数据时如实标注 unavailable。

## 8. 对四智能体、Harness、Trace 的兼容性分析

- **四智能体**：P0/P1 全部向后兼容——SecurityEvidence 结构不变（新增字段为增量列），`validate_runtime_report` 校验语义不变；P2-3 仅新增工具与降级标注，不改既有四个 Spec。
- **Harness**：零影响。运行时证据只影响风险层（`environment.runtime_status` 已是既有因子）；采集端升级不触碰设备写路径、审批绑定与回滚语义；`compare_windows`（修复前后证据窗口对比）反而因时间戳/绑定修复而更可靠（D1 修复消除假重复窗口污染）。
- **第八阶段 Trace**：证据引用链路（`evidence_refs_json` → `/traces/{id}/evidence`）已就绪；P1-3 的 session-id 与 P2 指标可作为事件 payload 增量字段，不破坏旧 Trace 可读性（旧记录不回填）。
- **阶段七/八已验收功能**：本轮审计**零代码改动**（除本报告与文档），不存在回归面；后续实施按上表验收方法逐项回归（SmartCam/OpenWrt/Zephyr 既有测试套件全量复跑为准）。

---

## 9. 审计验证记录（本轮真实执行摘要）

| 验证 | 结果 |
|---|---|
| 阶段二真实夹具 40 条全链回放（上传→双表→证据→API→进程树→去重） | 通过；发现 D1 |
| WSL root 全新 bpftrace 探针采集（项目脚本原样运行） | 捕获真实 execve/openat 内核事件 |
| 智能体工具查询真实证据（process/network/tree） | 返回真实 SE- 记录 |
| 风险引擎消费（mosquitto 正例 / openssl 负例） | verified+linked / not_observed（语义正确） |
| 传感器心跳→RuntimeSensor→coverage | 通过 |
| demo 测试事件标注（probe 模式隔离） | 通过 |
| Ubuntu VM falco 0.44.1/bpftrace 安装、LSM 无 bpf、规则未部署、sudo 阻塞 | 实测记录 |
| 环境限制 | VM sudo 密码（无法 VM 内执行探针）；Mimosa 完整扫描仍不可用（不声称完成全局审计） |
