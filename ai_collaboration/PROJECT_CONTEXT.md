<!-- M5_FINAL_STATUS_START -->
## 2026-10-17 M5 完成稿：唯一统一四智能体核心实测全链通过，人工裁定仍开放

- 封印实现提交 `788a826`（前置草稿 `129dd21` 交付回归修复后修订并入），基线 `969a4fa`。迁移契约 `IOTGUARD_M5_MIGRATION_CONTRACT_V2.md`；正式 on / formal_writer=unified，两个设备修复写开关 0。
- 节点恢复完成并实测通过：原 m45-linux-node Pull Runner 未停止，预检失败根因是后端重启+令牌轮换后未加载节点配置；按 M4.4/M4.5 成功回执核对两条登记连接后恢复配置并重启后端（PID 46128）。两条连接预检 ready=true、节点认证 200；恢复后真实只读补采 Ubuntu 1790 包（INV-ae45e3e8944567a19d3502f1c3ca3919）与 OpenWrt 182 包（INV-7631d63227b003339d316e92dfaa29f8）均 completed。未新建采集体系、未扩大范围、未读取设备敏感文件。
- 核心实测：formal 风险126 再研判 `UA-5daea17fd7e14273ab3d814e` completed（10阶段全成功，29次LLM调用441,460 tokens，置信0.7，消费恢复采集证据后 confirmed_affected / upgrade_minor，与首个 formal 运行 UA-fe6e8559fb28-126 同结论互证）；historical 风险12 归档建议稿 `UA-20261017031216-2888ac` completed（10阶段全成功、0降级）。126轮漏洞分析师一次轮次超限降级已如实记录，冲突2项保留 unresolved 待人工，未代签；补证申请一律 awaiting_authorization 无越权。
- 最终一致性备份 `local-archive/m5-final-switch/20261017T040749Z/production.db`（sha256 `0d5d3f34…9a900`，integrity ok，busy 全0，隔离恢复差异0，零设备写）。最终 PID：后端 46128、Runner 隧道 46424。
- 回归：交付版全量 667/0（496.82s）+ 前端 21/0；Mimosa 封印代码扫 0 findings / coverage=partial（seal `4a93c6dc…245e4`），封印后应用代码零变更。历史建议稿：历史 Critical 基线保留为待纠正基线，界面/报告标注历史错误基线并展示官方"不受影响"与归档裁定状态；风险12 维持 inactive。
- 人工仍待：Q1–Q8 与风险126 对象级裁定、风险12 归档确认、补证申请 IR-a0c04a79 授权；模型未代签。

本段为 M5 机器可执行验收完成稿；人工裁定关闭前不宣称风险结论定案。完整数据见 `IOTGUARD_M5_FINAL_UNIFIED_PRODUCTION_REPORT.md` 与 `reports/m5-final/`。
<!-- M5_FINAL_STATUS_END -->

# IoTGuard 项目长期背景与系统架构

## Stage 9B M5 当前边界（2026-10-17）

当前报告：`IOTGUARD_M5_SINGLE_AGENT_SYSTEM_REPORT.md`；基线`58fd221`。目标：全项目唯一正式 LLM 研判体系（LangGraph 统一四智能体，正式入口 /api/analysis），彻底退役 System A（services/agents/）与 System B（event_review_pipeline+agent_group_chat）。

已完成：完整调用关系审计与旧/新边界划定；中立迁移（`services/agent_infra.py`、`services/agent_tools.py`、`services/review_common/`——统一编排器与旧系统零 import，通用确定性组件不随旧文件删除）；一致性备份（`local-archive/m5-switch/`，sha256 `33283418…e513f`）；排空核验；迁移演练隔离副本 44/0（演练已改造为退役感知，保留为切换契约校验器）；Mimosa 0 findings；全量回归 742/0。

**门禁（当前停点）**：正式切换前置的 Q1–Q8 人工裁定未签署（`IOTGUARD_M47_HUMAN_REVIEW_PACKETS.md` 裁定栏全空，DB 零人工裁定痕迹）。按 M5 指令与 M4.7 契约 §77：模型不得代签，停在该人工环节等待真实授权操作员；不得将影子结论晋升为正式结论（111 条 reanalysis_required 候选切换后由统一链重新研判，非晋升）。

门禁后既定流程（M5 报告 §9）：操作员裁定落库 → 物理删除旧系统（报告 §2.2 逐文件清单：services/agents/ 全包、event_review_pipeline、agent_group_chat、routers/agents、AgentOrchestrationRun 映射、agent_harness._expert_review、mqtt agent_plan LLM 分支、demo 直调、analysis off 回退分支、历史脚本归档、前端 AgentOps 改接 unified）→ `.env` flag=on → 重启唯一 uvicorn → 进程内核验 mode=on/formal_writer=unified 与轮换令牌生效 → live 验收 A–D → 终扫封印。回滚仅依赖明确版本+备份+授权恢复程序，不依赖第二套在线研判器。

边界维持：flag=off、`LINUXGUARD_ENABLE_DEVICE_REPAIR=0`、`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=0`；旧系统 on 态互斥护栏（`system_b_formal_writer_disabled` 四写入器）经演练实证；统一链异常唯一合法路径为 fail-closed 落人工。下方 M4.7 及更早内容为历史。

## Stage 9B M4.7 当前边界（2026-10-17）

当前报告：`IOTGUARD_UNIFIED_AGENT_MIGRATION_ACCEPTANCE.md`；基线`fa3b474`。四角色与LangGraph原体系未动；正式入口仍System B，`LINUXGUARD_UNIFIED_PIPELINE=off`，双修复写开关0，旧编排器保留。

接管阻断项处置：控制令牌已轮换（演示脚本改环境变量强制读取；新值仅存`backend/.env`，指纹`9f06…58ffe`，操作员须重启后端生效）；风险126/12人工复核材料已备（`IOTGUARD_M47_HUMAN_REVIEW_PACKETS.md`，Q1–Q8待授权操作员裁定，落库走`POST /api/analysis/risks/{id}/human-review`）；Mimosa恢复可用，交付以最终重扫封印为准。

新增能力面（均为验收工具，不改变业务语义）：`backend/scripts/m47_migration_drill.py`（隔离副本迁移/回滚演练，确定性客户端）、`backend/scripts/m47_continuous_shadow.py`（受批准连续shadow窗口）；`unified/adapter.py`修复正式批处理对编排器failed运行的fail-closed缺口（与System B `_fail_selected`同语义，回归锁定）。

W47连续shadow实证：9/9运行、36/36角色、同事实置信无上行、申请未授权不执行、正式字段零触碰；curl 126存在同事实impact/方向方差（动作稳定），openssl 12全稳，OpenWrt零候选诚实；新旧分歧模式与M4.6一致且均可解释。技术侧具备接管条件；正式切换前置：操作员完成Q1–Q8裁定 + 用户切换批准 + M4.6 §5排空/备份/单worker程序。不得将shadow结论复制为正式结果；回滚须恢复快照而非仅切flag。

未关闭（人工事项）：复核材料裁定；curl方差口径确认；采集授权流程执行；正式迁移审批与部署排空。本轮结束即停止；下方M4.6及更早内容为历史。

## Stage 9B M4.6 当前边界（2026-10-16—17）

当前报告：`IOTGUARD_UNIFIED_AGENT_PRODUCTION_READINESS.md`；起点origin/main=`10be6f0`。四角色和LangGraph保持原体系；正式入口System B，flag=off，两个修复写开关均0。

新增InvestigationRequest保存问题/预期效果/能力范围/事实快照/摘要、授权、collection_tasks关联、父子运行及角色前后报告。Agent只能提出inventory申请，操作员持控制令牌与精确摘要授权；固定节点Collector不刷新索引、不补运行时、不执行修复。resume校验同资产原文/摘要与采集任务、原子领取、四角色再研判；同事实限制最终置信。

`POST /api/unified/shadow`为受控隔离入口；调查authorize/resume及AgentOps复用现有业务。未来正式输出仍只走`/api/analysis`：on拒绝旧写入器，formal_sink拒绝非formal/off来源，shadow拒绝sink。不能混跑不同模式的正式worker。

迁移工具只生成正式全字段快照和回滚差异计划；不能将shadow直接提升为正式结论/审批。回滚须排空worker、另行批准恢复正式字段并保留审计，再恢复off；只改flag不能还原结果。真实正式字段与M4.5快照一致，历史19条统一运行未改变。

未关闭：Mimosa无入口、正式人工分歧复核、Ubuntu过期运行时覆盖、OpenWrt覆盖范围、修复包可用性与隔离修复实验、正式迁移审批。本轮结束停止；旧文档为历史，不代表已切换。

最终功能回归729/0（711+18）、前端21/0与构建、52引用及原文摘要核验通过；不是完整安全验收。当前本地控制令牌匹配历史演示默认值，需迁移前轮换；M4.6暂存26文件没有新增敏感匹配。临时验收服务/节点已停止。

## Stage 9B M4.5（2026-10-16）

当前交付基线：最新 origin/main `cbce1293b93e02d23093263c6bedcc0d8fee0992`，开发前工作区干净。唯一项目 IoTGuard-Public；System B 正式入口；LINUXGUARD_UNIFIED_PIPELINE=off；设备修复与 Ubuntu 隔离写开关均为 0。当前依据为 `IOTGUARD_REAL_REMEDIATION_E2E_REPORT.md`，下方 M4.4 及更早内容作为历史保留。

Ubuntu 适配是 agent_harness 的发行版工具分支，复用原 HarnessRun、精确审批、资产锁、16次主工具预算、尝试上限和Trace，以及原认证节点传输。当前仅支持明确绑定的节点本机 Ubuntu24.04/noble；源包 curl 按官方 USN 映射实际二进制包。OpenWrt 授权和登记产物回退规则保持。

状态链：awaiting_preflight → 只读预演 → 观察进入新计划哈希 → awaiting_approval（预演通过才开放）→ 独立审批 + 原风险授权 + 双写开关 + 克隆许可 → 节点重核 → 精确白名单归档维护 → 新采集/官方重取/原匹配器纯评估 → 风险更新建议。许可绑定资产、machine-id、计划、快照恢复证明、操作员和有效期，后端和节点分别核验。中断不重放，Ubuntu 回滚需虚拟化快照另行批准。

旧 RiskAssessment、VulnerabilityMatch、UnifiedAnalysisRun 只读；新证据与结果写 Harness，满足版本也只建议 fixed_pending_human_acceptance，业务回归待隔离实验。本机当前索引无 .16，不能据此推断官方仓库全局不存在修复包。本轮 Mimosa 不可运行，安全验收未全部满足。

---

> M4.4 实现提交：`c7ca5a3e2a558b52799c4b113643e25ab3ac44c7`（已推送）；最终报告提交以本文件最新 Git 记录为准。

## Stage 9B M4.4 当前产品边界

Ubuntu 适用性按 Canonical 的实际发行版及源包记录判定；USN 的 CVE/release/source-package 必须精确匹配。NVD 上游版本范围只用于候选，不能替代发行版回移植/分支结论。新增 OfficialCveRecord、ApplicabilityCorrection、CollectionEvidence，原始 JSON/stdout、失败来源状态、内容摘要、历史纠正都可追溯。

Windows 仍不执行产品设备 SSH；Linux 节点通过独立节点令牌原子领取固定任务，保留 SSH 指纹钉扎、资产白名单和凭据环境变量引用。Ubuntu 节点本机采集身份为 authenticated_collection_node，SSH 状态不适用；OpenWrt 为节点核验的 pinned SSH。节点声明与产品直接执行核验分开记录。临时开发会话部署不是持久 systemd 服务。

唯一 LangGraph 四角色仍经隔离 shadow runner 接入真实风险。计划增加原始依据、源包/发行版版本核验与动作分类；Harness 只接收影子计划溯源关联，不接收修复授权。正式入口 System B，flag=off，设备写关闭。CVE-2026-63073/noble/openssl 的旧 M4.3 判断已纠正为 not-affected，替代可信案例为 CVE-2026-94266/noble/curl。

> 本文件由开发过程持续维护，必须与实际代码保持一致。最后核对：2026-10-16（Stage 9B M4.4 真实漏洞闭环）。

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
