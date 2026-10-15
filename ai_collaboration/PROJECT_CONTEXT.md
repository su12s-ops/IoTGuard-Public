# IoTGuard 项目长期背景与系统架构

> 本文件由开发过程持续维护，必须与实际代码保持一致。最后核对：2026-10-15（第九阶段前置专项：四智能体有效性审计）。

## 项目定位

IoTGuard（内部代号 LinuxGuard）是面向物联网与 Linux 资产的**安全检测与修复平台**：授权网段资产自动发现 → 协议级设备指纹 → 多源 CVE 情报匹配 → 智能体协同研判 → eBPF 运行时取证 → 带审批与回滚的 Agent Harness 修复。所有探测/修复能力均内置授权边界，默认不启用任何设备写操作。

## 系统架构（与代码对应）

```
frontend/  Vue3+ElementPlus+ECharts，16 个业务视图，Playwright e2e
    │ HTTP
backend/   FastAPI + SQLAlchemy + SQLite（30+ 表）
    ├─ routers/       17 个路由模块（assets/iot/devices/scans/harness/agents/…）
    ├─ services/
    │   ├─ discovery_pipeline.py   发现闭环（扫描→观察→识别→建档→CVE）
    │   ├─ device_inventory.py     协议指纹（SSH/HTTP(S)/RTSP/MQTT 真实报文）
    │   ├─ matching_engine.py      主机线 CVE 匹配（发行版适用性优先）
    │   ├─ device_vulnerability.py 设备线 CVE 匹配（厂商公告精确版本优先）
    │   ├─ agents/                 System A：设备编排四智能体（真工具循环 14 工具；
    │   │                          DEVICE→VULN→RUNTIME→RISK(程序)→REMEDIATION→VERIFY(程序)）
    │   ├─ event_review_pipeline.py System B：主机逐风险四智能体研判（单次类型化 LLM
    │   │                          + 确定性证据包/冲突检测/审计门禁；输出驱动排序/复核/授权）
    │   ├─ agent_harness.py        修复 Harness（审批哈希/锁/预算/回滚；执行 coordinator
    │   │                          requested_tools 真实补采并复评）
    │   └─ ebpf_event_collector.py eBPF/Falco 证据层
    └─ tests/ 499 项 pytest（全量绿：499 passed / 0 failed，2026-10-15）
collector/  bpftrace 探针、OpenWrt/Linux 只读采集器、Falco 规则、性能评测负载发生器、logread 降级采集
simulator/  SmartCam-X1 摄像头模拟器（真实监听 SSH/MQTT/HTTP/RTSP）
```

### 两套"四智能体"体系（2026-10-15 审计核实，详见 IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md）

- **System A（services/agents/，AgentOps 页展示）**：device_intelligence / vulnerability_intelligence / runtime_behavior / remediation_verification，真工具循环。runtime 智能体对 eBPF 证据的消费与风险聚合有实测增量（屏蔽实验 62→54 分）；但主输出 risk_json 不进风险研判主链路（死端），remediation 智能体因上下文饥饿+授权依赖结构性空转——整改方案 R1-R8 待评审。
- **System B（event_review_pipeline.py，风险研判页/总览大屏展示）**：evidence_audit / impact_assessment / exposure_runtime / decision_coordinator，单次类型化 LLM + 确定性证据包 + 门禁。输出全链真实消费；真实 LLM 消融实验证明其在规则误报/矛盾情报/过期监控案例上优于纯规则（规则处置正确 2/7 vs 智能体 6/7，影响判定 7/7，0 证据幻觉）。
- 两体系职责互不映射、数据互不引用（F2，待整改）；竞赛表述不得混用"自主取证智能体"口径。

## 关键安全边界（不可回退）

- 设备凭据仅经 `LINUXGUARD_DEVICE_*` 环境变量引用；SSH 主机指纹 SHA256 钉扎
- 扫描仅限 `LINUXGUARD_DISCOVERY_CIDRS` 白名单，≤128 地址/次
- 设备写操作总开关 `LINUXGUARD_ENABLE_DEVICE_REPAIR=0`（默认关闭）
- 发现闭环绝不触发修复/Harness；NVD 通用匹配保持候选语义
- 真实凭据只存在于本地 `backend/.env`（已 .gitignore，永不入库）

## 仓库拓扑（2026-10-14 起单一仓库制）

**唯一正式开发仓库：本仓库（su12s-ops/IoTGuard-Public）。** 所有开发、测试、Commit、Push 均在此进行；双仓同步机制已取消（`scripts/sync_public.py` 已删除）。

- 原 Private 仓库（su12s-ops/IoTGuard-Project，本地 `E:\IoTGuard-Project`）降级为**临时本地备份**：其跟踪内容已全部被本仓库包含（跟踪文件清单逐一核对为真子集），独有本地数据（历史实验证据 reports/、backend 数据库、backend/.env、asset_inventory.json）已归档至 `local-archive/private-backup-20261014/`（.gitignore 排除，永不入库）。其删除须满足：本仓库可独立构建/运行/重新 Clone 且数据归档核验通过，并经用户逐项批准。

## 当前阶段路线

1. ✅ 阶段一~四：设备清单/采集/四智能体/Harness（已完成并有联调证据）
2. ✅ 阶段五：资产发现闭环（discovery_pipeline，9+5 项专项测试，SmartCam 真实联调 16/16）
3. ✅ 阶段六：OpenWrt 异构终端接入——设备线（自动发现/指纹/建档/幂等）与主机线（SSH 只读采集×2/身份链闭合/新旧 diff/CVE 分级消费）均已真实闭环；精确版本匹配层待登记真实官方公告后激活
4. ✅ 阶段七：Zephyr RTOS 终端接入——qemu_cortex_a9 固件真实构建运行（QEMU 网络打通），真实端到端联调 20/20 ALL PASS（发现/身份建档 0.9/固件元数据/版本化组件/CVE 分级/幂等/边界）；证据 reports/zephyr-live-20261014-085507/
5. ✅ 阶段八：统一任务 Trace 与可观测性——trace_run/trace_event 统一追踪（四智能体/Harness/设备管线共用），Trace API 7 端点，AgentOps 四区域（总览/时间线/Harness 监控/证据关联）；真实 LLM 只读演示 ALL PASS；专项 15 + 回归无新增失败
6. ✅ eBPF 2.0 全部完成：审计 → P0 运行时证据可靠性 → P1 探针增强+Falco 真实常驻部署与稳定性收尾 → final C1–C6（write-ahead spool、connect 返回值守卫、证据 session 身份、CVE 证据下钻、智能体数据质量工具、回归钩子根因修复）→ P2-1 性能评测落地（五形态实测+判重索引修复，476/0）→ P2-2 OpenWrt 降级采集（logread 只读 21/21 真实验证，499/0，IOT_EBPF2_P22_REPORT.md）
7. ✅ 第九阶段前置专项（2026-10-15）：四智能体有效性深度审计——真实代码追踪 + 真实 LLM 消融（A/B/C/D）+ 反事实（CF1-CF7）+ 量化指标；结论与整改清单见 IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md（F1-F10 / R1-R8）；零生产代码改动，499/0
8. ⏳ Stage 9B：按审计整改清单评审后启动（双体系对账 R1 / 崩溃修复 R2 / 重试反馈 R3 / remediation 上下文 R4 / version_impact 消费 R5 / 新鲜度语义 R6 / 降级评审 R7 / 成本分层 R8）；双台账统一并入后续规划
