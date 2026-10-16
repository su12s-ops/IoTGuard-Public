# IoTGuard 项目长期背景与系统架构

> 本文件由开发过程持续维护，必须与实际代码保持一致。最后核对：2026-10-16（Stage 9B M4.3 核心主链）。

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
    │   ├─ unified/                统一编排器（Stage 9B）：LangGraph 单图四智能体
    │   │                          + evidence_prep 确定性证据预取节点（M4.1，非 Agent）
    │   ├─ agent_harness.py        修复 Harness（审批哈希/锁/预算/回滚；执行 coordinator
    │   │                          requested_tools 真实补采并复评）
    │   └─ ebpf_event_collector.py eBPF/Falco 证据层
    ├─ scripts/ m43_core_e2e.py 核心主链 E2E 编排器（真实设备发现/采集/匹配/logread/影子研判/Harness 闭环/一致性核验）
    └─ tests/ 655 项 pytest（全量绿：655 passed / 0 failed，2026-10-16）
collector/  bpftrace 探针、OpenWrt/Linux 只读采集器、Falco 规则、性能评测负载发生器、logread 降级采集
simulator/  SmartCam-X1 摄像头模拟器（真实监听 SSH/MQTT/HTTP/RTSP）
```

### 统一四智能体（Stage 9B 起，2026-10-15 落地；演进自 Stage 9 审计的双体系）

- **统一编排器（services/unified/，唯一正式架构，pipeline_version=unified-four-agent-v1）**：LangGraph 1.2 单图——prepare(路由分层)→**prepare_evidence(确定性证据预取，M4.1：无 LLM、复用只读工具/多源情报包/SecurityEvidence、运行内只读复用、新鲜度按当前时间重算、失败退回自主查询)**→asset_investigator→(vulnerability_analyst ∥ runtime_analyst)→detect_conflicts(7 确定性规则)→[定向复议≤1]→decision_planner([补查≤1])→finalize(审计门禁/F5 聚合/强制待审批计划)。能力来源：System A 的 14 只读工具与工具循环基座 + System B 的证据包/冲突/门禁/有界方向映射；F1/F3/F5/F6/F7/F9、§7 八问题与 M4.1 五类决策语义约束（分支排除/厂商冲突/紧迫度分离字段 runtime_evidence_validity+urgency_basis/已修复确定性/过期≠不适用）已修复并有测试锁定；门禁 fail-closed 新增 7 类确定性矛盾理由；程序兜底裁定带 program_fallback 显式标记（统计口径与 LLM 判定分离）。M4.2 增：紧迫性放大因子（KEV ∨ 受影响组件公网监听×CVSS≥9.0）、branch_excluded/below_stated_affected_range 扩展拦截、fixed_disposal_contradiction、vendor_not_affected_overridden（含 backport）、冲突规则 8（确定性事实 vs 分析师结论→定向复议）、四维 DimensionAssessment 分层 Schema、消融钩子 ablation_mask。
- **开关**：`LINUXGUARD_UNIFIED_PIPELINE=off|shadow|on`（默认 off=System B 原链路零变化；shadow=影子对照只写 unified_analysis_run；on=/api/analysis 经 adapter 切换统一编排器）。影子隔离由逐字段快照测试锁定。
- **旧体系现状（能力来源与历史兼容，非正式入口）**：System A（services/agents/）与 System B（event_review_pipeline.py）在开关 off 时仍是正式链路（System B）；on 切换稳定后按 IOT_STAGE9B_MIGRATION_NOTES.md §5 清单退役。
- **核心主链 E2E（M4.3，2026-10-16）**：backend/scripts/m43_core_e2e.py 把真实设备业务闭环固化为可重入编排：发现入档→操作员 SSH 只读采集（指纹钉扎+固定 Collector）→官方上传建档→CVE 匹配→logread/运行时证据→统一四智能体影子研判（隔离入口，flag=off 不变）→Harness 只读闭环与门禁→一致性核验（影子隔离/引用反幻觉/Trace 贯穿）。证据键跨线语义：设备线（IotDevice DEV-*）与主机线（LinuxAsset 自报主机名）经同 IP 资产或指纹钉扎 DeviceConnection 双向传递（agents/tools._evidence_keys）；设备身份防降级（device_inventory.upsert_device）；影子运行可经 `GET /api/unified/runs?risk_id=` 关联风险详情展示。
- **实验基建（backend/scripts/，本地 reports/ 留存不入库）**：stage9_agent_effectiveness_audit.py（E 案例与基座）→ stage9b_unified_compare.py（X 案例/三方对照）→ stage9b_quality_{cases,experiment}.py（M4.2：Y1–Y10 先验真值、消融/反事实、断点续跑）→ stage9b_closure_{cases,experiment,stats}.py（M4.2 收尾：Y6 2×2 修正反事实、RT-A/B/C/D 正向贡献、链末端续接重试、退化输出检测、零 LLM 可复现统计）。**真值先验纪律**：cases 真值表提交先于任何真实 LLM 运行（git 时序可核验）；原始产物零改动，重试新 run_id。
- **M4 最终验收（2026-10-15，IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md）**：全部 10 事件 20 次运行完成（1.357M tokens）；安全面全达标；质量/成本/稳定性未达切换门槛，flag=off；其统计口径由 M4.1 离线核查修正（兜底归属 E3a×2+E3b×1、混合口径高估 3~7pp、7.6s 为全量运行口径）。
- **M4.1 校准复测（2026-10-15，IOT_UNIFIED_FOUR_AGENT_CALIBRATION_REPORT.md）**：22 次真实 LLM 运行全 completed（0 兜底）；**影响判定（配对）9/9 vs 旧 7/7 首次达标、稳定性达标（E1×3/E5×3 全一致）、安全面保持**；处置（配对）8/9 差 1 例（E2 静态紧迫性超集）、成本 -4.8%（全链口径）非实质改善 → **维持 flag=off**；遗留：static_evidence_only 放大因子前提 / E3a 残余方差 / 方向口径对齐 / 预取切片瘦身（目标 ≤60k/评审运行）。

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
7. ✅ Stage 9 前置审计 + Stage 9B M0-M5 主体（2026-10-15）：架构重建/影子适配层/最终验收实验（flag=off 维持）
8. ✅ Stage 9B M4.1 校准（2026-10-15）：统计口径修正 + 五类决策缺陷通用语义修复 + evidence_prep 确定性预取 + 稳定性治理 + 真实 LLM 复测（影响判定/稳定性首次达标；处置差 1 例、成本非实质改善，flag=off 维持）；遗留四项见校准报告 §9
9. ✅ Stage 9B M4.2 深化 + 收尾闭环（2026-10-16）：四 Agent 分工 Schema/四维分层/E2-E3a-E1-X2 整改/Y1–Y10 独立案例（主轮 637 passed）→ 收尾补齐全部遗留实验（E4a/E4b/X2/X3/资产消融）+ Y6 反事实修正 2×2（放大因子断言 4/4、处置与因子一一对应）+ RT-A/B/C/D 正向贡献（RT-D 承重实证）+ 方向四层分析；650 passed / 0 failed；Mimosa 0 findings；**flag=off 维持**，切换准备状态=候选具备（报告 IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md）
10. ⏳ 后续（需指令）：真实设备 Shadow 验证启动（人工决策）→ 达标后经用户确认 flag=on（影子观察 ≥1 周）→ M5 退役清单；方向评分规范另建版本提案（E5 混同整改）
