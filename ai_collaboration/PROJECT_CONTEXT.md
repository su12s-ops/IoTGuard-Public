# IoTGuard 项目长期背景与系统架构

> 本文件由开发过程持续维护，必须与实际代码保持一致。最后核对：2026-10-13（Commit 6f4724b 之后）。

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
    └─ tests/ 341 项 pytest（4 个真实套接字文件需独立 profile）
collector/  bpftrace 探针、OpenWrt/Linux 只读采集器、Falco 规则
simulator/  SmartCam-X1 摄像头模拟器（真实监听 SSH/MQTT/HTTP/RTSP）
```

## 关键安全边界（不可回退）

- 设备凭据仅经 `LINUXGUARD_DEVICE_*` 环境变量引用；SSH 主机指纹 SHA256 钉扎
- 扫描仅限 `LINUXGUARD_DISCOVERY_CIDRS` 白名单，≤128 地址/次
- 设备写操作总开关 `LINUXGUARD_ENABLE_DEVICE_REPAIR=0`（默认关闭）
- 发现闭环绝不触发修复/Harness；NVD 通用匹配保持候选语义
- 真实凭据只存在于本地 `backend/.env`（已 .gitignore，永不入库）

## 仓库拓扑

| 仓库 | 用途 | 地址 |
|---|---|---|
| Private 主开发库 | 日常开发、完整历史 | https://github.com/su12s-ops/IoTGuard-Project |
| Public 公开库 | 脱敏镜像、独立干净历史 | https://github.com/su12s-ops/IoTGuard-Public |

同步机制：`scripts/sync_public.py`（Private HEAD → 导出跟踪树 → 敏感扫描 → Public 增量提交推送，commit message 携带来源 hash）。

## 当前阶段路线

1. ✅ 阶段一~四：设备清单/采集/四智能体/Harness（已完成并有联调证据）
2. ✅ 阶段五：资产发现闭环（discovery_pipeline，9+5 项专项测试，SmartCam 真实联调 16/16）
3. ✅ 阶段六：OpenWrt 异构终端接入——设备线（自动发现/指纹/建档/幂等）与主机线（SSH 只读采集×2/身份链闭合/新旧 diff/CVE 分级消费）均已真实闭环；精确版本匹配层待登记真实官方公告后激活
4. 🔄 阶段七：Zephyr RTOS 终端接入——固件+后端+Mock 测试就绪；QEMU 运行阻塞（SDK QEMU v10.0.2 兼容性）
5. ⏳ 后续：trace_id 智能体运行监控、双台账统一
