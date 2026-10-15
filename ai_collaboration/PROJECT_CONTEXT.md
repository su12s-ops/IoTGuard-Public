# IoTGuard 项目长期背景与系统架构

> 本文件由开发过程持续维护，必须与实际代码保持一致。最后核对：2026-10-15（eBPF 2.0 P2-1 性能评测落地）。

## 项目定位

IoTGuard（内部代号 LinuxGuard）是面向物联网与 Linux 资产的**安全检测与修复平台**：授权网段资产自动发现 → 协议级设备指纹 → 多源 CVE 情报匹配 → 四智能体协同研判 → eBPF 运行时取证 → 带审批与回滚的 Agent Harness 修复。所有探测/修复能力均内置授权边界，默认不启用任何设备写操作。

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
    │   ├─ agents/                 设备编排四智能体（DEVICE→…→VERIFY）
    │   ├─ event_review_pipeline.py 主机逐风险四智能体研判
    │   ├─ agent_harness.py        修复 Harness（审批哈希/锁/预算/回滚）
    │   └─ ebpf_event_collector.py eBPF/Falco 证据层
    └─ tests/ 476 项 pytest（全量绿：476 passed / 0 failed，2026-10-15）
collector/  bpftrace 探针、OpenWrt/Linux 只读采集器、Falco 规则、性能评测负载发生器
simulator/  SmartCam-X1 摄像头模拟器（真实监听 SSH/MQTT/HTTP/RTSP）
```

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
6. ✅ eBPF 2.0：审计（IOT_EBPF2_AUDIT_REPORT.md）→ P0 运行时证据可靠性（IOT_EBPF2_P0_REPORT.md）→ P1 探针增强+Falco 真实常驻部署与稳定性收尾（IOT_EBPF2_P1_PREP/DEPLOY/STABILITY_REPORT.md）→ final C1–C5（write-ahead spool、connect 返回值守卫+真实内核验证、证据 session 身份+聚合视图、CVE 证据下钻、智能体数据质量工具）→ C6 回归钩子根因修复 + demo SSH 加固（de9f1f9，全量 435/0）→ P2-1 性能评测落地（IOT_EBPF2_P21_REPORT.md，五形态实测+判重索引修复 115→379 EPS，全量 476/0）；P2-2 OpenWrt 降级采集仍未实施
7. ⏳ 后续：双台账统一（第九阶段未开始，待指令）
