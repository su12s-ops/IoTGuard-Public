<!-- FINAL_CLOSURE_20261018 -->
## 最终收口（2026-10-18，优先于下方全部历史状态）

最终依据：[最终产品验收报告](../IOTGUARD_FINAL_PRODUCT_ACCEPTANCE_REPORT.md)。用户委托代理判断；裁定actor明确为代理，未冒充用户亲签。此段替代历史待人工状态，历史记录仅为过程留存。

- 克隆三包.15→.16保留；一次正式修复后复评`UA-7eb1c1d131d5-127`完成，四角色成功、零降级、14调用、28分26.5秒；原始策略pending_human_review因evidence_partial保留。模型公告号误写与历史清单误推已独立纠正，正确USN-8932-1。
- 代理完成Q1–Q8裁定、风险12正式归档确认、风险126保持open/unfixed、克隆有限范围版本/包数据库/curl/HTTP接受。源风险不关闭；克隆无完整运行时/全业务覆盖。生产修复写双0。
- Falco真实持续上报；OpenWrt既有Collector/Pull Runner/Harness启用60秒只读周期，真实新事件与重复去重均验证；身份后缀误判已修复，失败历史保留。SSH监督进程断线退避重连；未安装宿主开机服务。
- 正式nginx入口http://127.0.0.1:18080，API18000；独立验证库不共享宿主写入，非root、最小权限、最终HEAD镜像标签。容器不注入真实节点/设备私钥，快照心跳过期如实显示。
- 后端全量716/0（最后补丁前），身份专项9/0、相关回归85/0，最终身份/运行时查询/请求内复用专项52/0（47.75秒）、扩展运行时39/0（44.46秒）；前端24/0（20.8秒）、生产构建通过（1.24秒）。npm/pip已知漏洞0；Bandit高0/中28/低81；Mimosa仍partial/inconclusive，不能宣称全覆盖安全通过。
- 修复后真实快照回滚未执行，保留已修复克隆；[回滚方案](../IOTGUARD_FINAL_ROLLBACK_PLAN.md)、[部署](../DEPLOYMENT.md)、[架构](../TECHNICAL_ARCHITECTURE.md)、[演示](../IOTGUARD_FINAL_DEMO_GUIDE.md)已交付。按用户要求收口，不再扩展阶段或反复索取人工判断。

<!-- STAGE10_COMPLETION_STATUS_START -->
## Stage 10 第五轮（2026-10-18）：克隆真实修复与复采通过，Falco持续上报恢复

本段优先于下方历史状态；完整报告：[第五轮完成记录](../IOTGUARD_STAGE10_COMPLETION_REPORT.md)。

- 隔离克隆 root 真实执行已完成：运行 `ddc385a143ed4a50bb6ef109041155fc` 为 `verified`；三个 curl 同源包 .15→.16，完整复采与新获取官方原文匹配均 fixed。独立 dpkg/audit/curl/HTTP 检查通过；源 Ubuntu 三包仍 .15。
- 首次下载因 VMware NAT 故障失败，正式复验版本未变；用户重启 NAT 服务后生成新计划成功，失败证据保留。成功后撤销两端许可，生产/实验后端写开关均双0。
- Falco 后端监听、失效令牌、systemd自动恢复问题已修复；源机19:26:08→19:37:01持续运行超过10分钟，未再重启，真实标记行为4条事件入库；内核丢失数仍 unavailable。
- 前后端恢复，源/克隆节点在线；Ubuntu/克隆各1790包、OpenWrt182包正式复采完成。OpenWrt经既有跳板只读补采1260条新日志；仍是pull，心跳可stale，Windows直接日志路由尚不可达，不宣称全部传感器健康。
- 角色截止时间覆盖HTTP等待与反馈/事实重试，SDK按剩余预算限时；迟到结果丢弃。同步工具与底层网络取消仍有边界，未重跑真实LLM耗时基准。
- 本轮回归：后端705/0（530.01s、5个既有警告），前端23/0（30.9s），生产构建通过。两库完整性ok、Harness资产锁0；实验复制库保留一条历史running研判快照，不是活跃工作进程。
- 未代签风险126、Q1–Q8、风险12归档或补证申请；克隆建议 fixed_pending_human_acceptance，业务接受仍待人工。未开启生产修复写，不能据此宣称整个项目生产验收结束。
<!-- STAGE10_COMPLETION_STATUS_END -->

<!-- STAGE10_CONTINUATION_STATUS_START -->
## Stage 10 第四轮（2026-10-17）：风险127人工确认、独立实验环境与root权限门禁

本段优先于下方第三轮及更早状态；完整报告：`IOTGUARD_STAGE10_CONTINUATION_REPORT.md`。

- 用户本次明确答复“可以的”后，经正式API将风险127置为 `human_confirmed`；审计注明来自当前对话，未编造实名签署。旧计划 `1edbaaf5…` 已取消，保留全部历史记录。
- 独立实验后端 `127.0.0.1:18001`、独立数据库/控制令牌/节点令牌、clone-only `/32` 地址与资产3作用域、隧道18447均已建立；生产与实验后端写开关均保持双0。跨环境控制令牌实测均401。
- 修复“预检全绿但执行节点无root权限”的缺口：预演分开记录 `package_ready` 与真实UID；后端接收/排队/领取及节点执行均拒绝缺失或非root权限证据；前端分层展示，取消计划明确显示已取消。
- 真实克隆实验预演 `c35b28cf…` 与部署后的生产只读预演 `936214b3…` 均证明：软件包检查通过、UID=1000、唯一问题 `root_execution_node_required`；状态 `preflight_failed`，无软件包写入。实验审批/执行API均409。
- 用户明确暂时无法操作克隆控制台；root节点脚本已发布、尚未启动，无执行许可。源Ubuntu Falco仍inactive/dead，用户表示会自行启动，尚无完成通知。
- OpenWrt只读补采98条新事件/1093去重；事件实际时间仍过期，未伪装健康。风险126正式重研判 `UA-ada3c8644aab-126` 已completed，四角色有效、零降级、42m30s/21调用/356370 tokens，结论 `confirmed_affected / pending_human_review`。未代签126或Q1–Q8；本轮暴露协作超时未严格约束HTTP等待的问题，已记入报告。
- 回归：专项54/0、后端全量698/0（486.82s，5个既有弃用警告）、前端23/0及生产构建通过。
- 排空并一致性备份后已部署新代码，生产PID=38076，双节点在线、统一on、生产双写开关0。一次归档读取输出曾含克隆节点令牌，已删除清单明文字段并轮换，旧令牌401，新令牌真实预演验证成功；.env与备份ACL收紧。零.deb下载、零dpkg写、无回滚。
<!-- STAGE10_CONTINUATION_STATUS_END -->

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
<!-- STAGE10_GATE_STATUS_START -->
## Stage 10 第三轮（2026-10-17）：授权 A+B 执行——隔离克隆全链建成，停在授权二门禁

基线 `f60c102`。统一报告：`IOTGUARD_STAGE10_ISOLATED_CLONE_PREFLIGHT_REPORT.md`（十问直答格式）。生产双写开关全程 0；dpkg 写/.deb 下载/安装升级全部为零。

- **克隆实建与隔离**：vmrun full clone（20GB）→ vmware-vdiskmanager flat 化（80GiB）→ WSL2 离线 root 完成八维身份隔离（hostname/machine-id/MAC/UUID/SSH 主机密钥/authorized_keys/netplan .110/cloud-init 冻结），全部逐项实测；源机密钥登录克隆实测被拒。源 VM 批准窗口软关机-回开，全项恢复（含 m45 runner 重启，节点回在线）。
- **快照与恢复验证**：`stage10-baseline-20261017T115000Z`；客户机内标记协议（快照后 r3 标记 → revert → r3 消失 + 身份/版本/候选不变）→ restore_verified=true。首次"离线直写标记"协议因关机态快照无 delta 而无效，已作废重做并全文披露。r2 机制观察（关机态快照记录最近干净关机状态）如实记录。
- **登记与采集**：asset 3（1790 包）+ 连接 3（指纹钉扎，preflight ready）+ stage10-clone-node（独立令牌/隧道 18446/开关双 0/无 OpenWrt 密钥）→ 首次认证采集 `INV-3bef62a8…`（execution_node=stage10-clone-node，authenticated，output_sha256 `caaa5083…`）。
- **官方索引与预演**：chroot 仅官方源刷新（deb822 双源签名验证，Falco 第三方源排除，零 .deb）；三包 Candidate `.16` 全部来自 security.ubuntu.com noble-security；`apt-get --simulate` 3 upgraded/0 newly/0 remove；dpkg audit 干净、无 hold。
- **克隆独立研判**：官方核验管线建立风险 127（自有匹配 2177）→ 正式入口四智能体 `UA-b522f38df422-127` completed：四角色全 valid（113/89/111/278s），零冲突零降级，11 项缺口如实（runtime 零证据=monitoring_missing），pending_human_review / confirmed_affected / scheduled_fix / upgrade_minor，模型未代签。
- **Harness dry-run 本 CVE 历史首次全绿**：run `1edbaaf5…99e1e7e`，preflight ready=true、issues=[]（资产 1 历史五次全败于 official_candidate_unavailable——索引刷新消除该失败类）；**最终计划 SHA256 `352208827415d3c9…4848cf`（dry-run 证据合入后终值），awaiting_approval、approved_by 空**；approve/execute 零调用。
- **授权 A 受阻（如实）**：falco 启动无可用口令通道（sudo 需密码/无 NOPASSWD/env 与 .env 均无凭据/root SSH 拒绝/VM 重启路径被授权 A 排除），服务保持 inactive；四态分层如实（backend_online=T、collection_node_online=T、sensor_healthy=F、runtime_evidence_fresh=F），未改库未伪造。解锁两路径已写入报告。
- **偏差与运维披露**：①官方核验端点按契约将风险 126 置 reanalysis_required（新证据 ADV-a74d8ba6 导入触发；governance events 全保留，126 重裁定回操作员）；②后端为多节点 .env 重启一次（预备份，重启后全项核验）；③生产库一致性备份 `local-archive/stage10-work/db-backups/linuxguard-consistent-20261017T105247Z.db`（sha256 `d9f75be1…fb641`）。
- 代码变更面：仅新增 `backend/scripts/start_clone_node.py`（ops 启动器，凭据仅经 env/SSH 引用）；后端应用代码零变更，既有回归基线维持，本轮以生产后端真实验收链（health/preflight/认证采集/正式研判/预演）为验证依据。
- 仍待用户：授权二（实验写开关/计划 `35220882…` 审批/dpkg 写/回滚授权）、Falco 凭据或控制台自执行、风险 126 重裁定、Q1–Q8。
<!-- STAGE10_GATE_STATUS_END -->


# 最近一次开发结果

## Stage 9B M5 第一阶段：唯一化准备（2026-10-17）——停在 Q1–Q8 人工门禁

基线`58fd221`、工作区干净；唯一仓库IoTGuard-Public。依据`IOTGUARD_M5_SINGLE_AGENT_SYSTEM_REPORT.md`。用户已授权正式切换与旧系统删除；执行中核查发现 Q1–Q8 未签署（材料裁定栏全空；DB `human_confirmed`/`rejected`/`[human_review]` 标记均为 0；风险126=`reanalysis_required`、12=`inactive` 与 M4.7 交付时一致），按 M5 指令第 4 条与 M4.7 契约 §77 停在人工环节，等待真实授权操作员；模型未签署、未代填。

审计：System A 调用方=routers/agents、mqtt_security_workflow.agent_plan、统一系统基础件 import（6处）、历史脚本3、测试9；System B 调用方=analysis.py off 分支、demo.py、agent_harness._expert_review、统一 adapter._selection、历史脚本12、测试8；通用能力（规则/匹配/情报/证据/trace/门禁/Harness 确定性采集审批）逐一确认保留。

中立迁移：`agent_infra.py`+`agent_tools.py`+`review_common/`（evidence_packet/selection/human_review）自旧文件迁出；统一 7 模块改依赖中立模块（与旧 System A/B 零 import）；`RemediationActionPlan`/`VerificationStep` 内联 unified/schemas；agent_harness inspect_evidence 切 review_common；m47 演练补丁移至 `review_common.select_candidates`（E9 首跑 2 失败=演练补丁失效非生产回归，副本写入范围曾扩大至 111 候选、已全字段回滚差异 0）、D3 退役感知。

切换前检查：一致性备份 sha256 `33283418…e513f`（integrity ok）；排空 busy=0/running=0；演练 **44/0**；Mimosa `scan-2026-10-17T01-59-32.762Z-90ab750eaf44` **0 findings**（seal `5b8402d7…a0ef`）；令牌探针证实运行中进程（10-16 23:21 启动，早于 58fd221）持有旧环境——轮换令牌随切换重启生效；修复写开关双 0。

回归：全量 **742/0**（701+41 perf，与 GLM 切换里程碑基线对齐）；统一专项 75/0；波及面 128/0。维持 flag=off、双写开关 0；未切 on、未重启、未删产品代码、无设备写、无影子晋升、未代签。恢复清单（操作员裁定后七步）见 M5 报告 §9。本轮结束即停止，等待 Q1–Q8 落库。

## Stage 9B M4.7（2026-10-17）

基线`fa3b474`、工作区含上轮遗留的两处演示令牌改动与验收草稿；唯一仓库IoTGuard-Public。依据`IOTGUARD_UNIFIED_AGENT_MIGRATION_ACCEPTANCE.md`。

P0执行：确认两处演示默认值与`backend/.env`现用令牌一致且已入公开Git历史→脚本改环境变量强制读取→现用令牌轮换为48位urlsafe（SHA256指纹`9f061621…58ffe`，全程未输出原文），归档烧毁值清除；`IOTGUARD_M47_HUMAN_REVIEW_PACKETS.md`建风险126/12独立复核材料（两侧真实输出+官方SHA256+Q1–Q8待裁问题，裁定栏留空）；Mimosa恢复，深扫`scan-2026-10-16T16-37-49.880Z-c218fa2fda10` 0 findings（seal `730ff98c…a504`，123包）。

P1执行：W47窗口经用户会话内批准（"批准 W47（推荐）"）后运行01:00–02:58三轮无重叠。统一链9/9 completed、每轮每对象4/4角色、零降级；curl126三轮`confirmed→potentially→potentially`/`maintain→downgrade_minor→maintain`（action恒scheduled_fix、置信0.65/0.60/0.62无上行）；openssl12三轮恒`not_affected/downgrade_major/monitor`；OpenWrt零候选诚实（R2/R3显式insufficient_evidence）。新申请IR-ee08ce1a/IR-f2feb101具体绑定只读范围，均awaiting_authorization未执行。窗口6次SystemB对照推理已跑但脚本提取缺陷（Pydantic CoordinatorResult .get）未捕获，全留失败样本；修复后补充对照：126`confirmed/upgrade_minor/0.62`、12`not_affected/maintain/0.72`，分歧模式与M4.6一致。正式字段每轮快照一致；真实库risk/harness零更新；3,299,064 tokens。

P2执行：`m47_migration_drill.py`隔离副本44/0；发现真实缺陷——runner吞编排异常后正式批处理把风险留在`agent_reviewing`（System B由`_fail_selected`落人工）→`adapter.run_review_analysis_unified`对failed运行逐风险fail-closed（`unified_orchestrator_failed:`原因），回归`test_orchestrator_failure_fail_closes_risk_not_stuck`锁定。演练含：off/on互斥9项、契约17键、简单/全量双分层、fail-closed、人审令牌401/409、Harness未审批与错哈希拒绝、仅切flag不还原、全字段恢复差异0、审计保留。演练副本曾误触发一次只读历史调查（side_effect=0、无SSH/LLM），留档并修正。

回归：全量730/0（527.88s，5既有警告）；前端21/0+构建；敏感扫描329跟踪文件0命中。最终Mimosa重扫与交付哈希见验收报告§9补录。维持flag=off、双写开关0；结束即停止，等待人工裁定与切换审批。

## Stage 9B M4.6（2026-10-16—17）

核验干净工作区与实际origin/main=`10be6f0`、M4.5 711/0交付；仅操作IoTGuard-Public。

真实首链：curl126 → `m46-real-482fde0e7bdb` → Agent申请 `IR-a57ce5d5436d5f8fc55c2f1c062d7383` → 授权固定Collector任务 `669e3d59963bdded5f49a3d0506ffd63` → 新INV → `UA-a300a7f502c746df9ef3d526`。1790包、版本仍.15，四角色成功，实质更新false，决策置信.64→.64。运行时、索引刷新问题没有被清单解决；未执行修复。

修正LinuxAsset网络工具、发行版CVE后缀查找、当前/历史版本区分、清单完整性及嵌套Trace引用；真实复验与首轮分开保存。SystemB风险126首轮结构失败与复验upgrade_minor语义偏差均保留，不作为真值；OpenSSL仍not_affected，OpenWrt不造CVE。

单一正式输出路径完成互斥与shadow隔离检查；126条风险迁移快照及只读回滚规划差异0。正式风险及原有19条统一运行与M4.5快照一致。精确摘要/控制令牌拒绝和Harness未授权执行拒绝实际验证。

最终全量729/0（842.87秒，5个既有警告），新增专项18/0、前端21/0和构建；4运行52引用真实解析并复算原文摘要。暂存26文件敏感匹配0；全量当前扫描发现2处既有演示默认值与本地控制令牌匹配，已列迁移前轮换事项。

完整结果、最终运行ID、回归与扫描见`IOTGUARD_UNIFIED_AGENT_PRODUCTION_READINESS.md`验收补录；本地原始证据在gitignored `reports/m46-work/`。Mimosa仍未运行，人工分歧复核仍待办。M4.6临时后端/节点已停止；维持flag=off、双写开关0，交付即停止等待迁移审批。

## Stage 9B M4.5（2026-10-16）

当前交付基线：最新 origin/main `cbce1293b93e02d23093263c6bedcc0d8fee0992`，开发前工作区干净。唯一项目 IoTGuard-Public；System B 正式入口；LINUXGUARD_UNIFIED_PIPELINE=off；设备修复与 Ubuntu 隔离写开关均为 0。当前依据为 `IOTGUARD_REAL_REMEDIATION_E2E_REPORT.md`，下方 M4.4 及更早内容作为历史保留。

真实链：资产1/风险126/M4.4四智能体 m44-real-841d76e9aa → 新采集0de447c11463b484871b2f8ce6504289（1790包）→ ADV-c73bcf3856244a5abc668abe17c6e95e（USN-8932-1/noble/curl .16）→ Harness4ef1f86fcdfc45eb9dcec9b584b3c6b5 / TR-20261016152210-0e5f95 → PRE-8f1b5602022b4afe901cba4bfafa9236。

curl、libcurl4t64:amd64、libcurl3t64-gnutls:amd64 安装与候选均 .15；目标 .16 缺候选/摘要/元数据，apt 模拟版本未找到，preflight_failed。dpkg audit为空、无hold、快照恢复未验证。错误哈希409、预演失败正确哈希409、未审批执行409、无控制令牌401。真实计划无成功审批/side_effect；原风险全字段与历史统一研判全文摘要前后一致。

成功审批、精确归档维护与写后复采/复匹配仅在测试桩；真实环境只读采集及预演。早期任务保留，最终任务以上述为准；时间戳兼容问题已修正并真实复跑。浏览器已核对真实包表、USN、失败原因、审批关闭、保持风险与待快照状态。

验收专项64/0、前端全套21/0、最终全量 711 passed / 0 failed（679.88秒，5个既有弃用警告）；敏感检查 当前322文件与暂存23文件已知凭据/私钥材料模式比对无匹配；未覆盖Git历史和未知格式。Mimosa 本轮未运行，安全验收未全部满足。当前 VM 和隔离副本的包写入、Falco重启、日志备份、实际回滚均未执行；交付后停止等待隔离实验授权。

---

> M4.4 实现提交：`c7ca5a3e2a558b52799c4b113643e25ab3ac44c7`（已推送）；最终报告提交以本文件最新 Git 记录为准。

## 2026-10-16 — Stage 9B M4.4 实际交付

真实链路：节点采集资产 1/2 → 官方 Canonical 原文 → CVE-2026-94266:noble:curl / risk 126 → INV/ADV/SE → `m44-real-841d76e9aa` / `TR-20261016135101-38986d` → confirmed_affected、scheduled_fix、stale_verified、pending_human_review → 只读 Harness `2dc572f6d9ad41b9abd0168063d37ba2`（needs_evidence）和修复门禁 `8e4241c90c4c4687840647046c33bf41`（blocked）。11/11 一致性，39 原始依据真实存在，16 条历史影子不变，126 条正式风险字段影子前后不变。

CVE-2026-63073 的错误为跨发行分支比较；noble/openssl 官方 not-affected，纠正 #9 关联旧风险 12 及 8 个历史影子，不再把旧升级建议作为可执行依据。curl 的 CVE 表 needed 与 USN 已发布 .16 的差异原样保留，以同 CVE/发行版/源包 USN 作为修复版本依据。

产品内采集通过常驻 Linux runner，无手工清单上传；OpenWrt 182 包、Ubuntu 1790 包，原文/执行节点/身份/Trace 入库。前端实测了纠正查询、采集任务、风险详情、角色实际输出与证据引用、计划动作分类及 Harness 状态。

正常产品按钮追加验收：Ubuntu 任务 `58ff0db47893fdf35428161426d330c5` 自动 completed（1790 包），INV/Trace 与页面一致，无手工 SSH/上传。

没有恢复 Falco/转发器、没有修改软件包、没有真实审批/修复/回滚、没有更改 Harness 授权规则。Falco 服务只读检查 active，但心跳约 48.7h 过期；恢复建议仍是待核验计划，不等于进程已停。75 个候选未取回可用官方证据，保留缺口。

最终测试/封印及提交以 TEST_RESULTS 和 `IOTGUARD_REAL_CVE_CLOSURE_REPORT.md` 为准；真实原文、数据库快照、截图与日志留在 gitignored `reports/m44-work/`。

> 本仓库（IoTGuard-Public）为唯一正式开发仓库；每完成一个任务在此归档摘要并提交。最后更新：2026-10-16（Stage 9B M4.2 收尾：质量闭环验收——研判质量闭环而非 Token 优化）

## 2026-10-16（Stage 9B M4.3）：核心业务主链集中建设——真实设备检测、四智能体研判与安全修复闭环（OpenWrt+Ubuntu 双真实链路打通；655 回归零失败；flag=off 维持）

- **交付**：IOTGUARD_CORE_E2E_REPORT.md + backend/scripts/m43_core_e2e.py（五阶段 E2E 编排器：A OpenWrt 发现/采集/匹配/logread、B Ubuntu 采集/情报/风险、C 影子研判、D Harness 闭环、E 一致性核验；幂等可重入，38 项检查全通过，证据 reports/m43-core-e2e-*/ 本地留存）+ `GET /api/unified/runs` risk_id/target_ref 只读过滤 + AgentOps「统一编排（影子）」页签 + 风险详情「09 统一四智能体影子研判」区块
- **真实链路 1（OpenWrt 25.12.5 @192.168.100.1）**：发现入档（DEV-59CCB87534B7）→ 操作员 SSH 只读采集（指纹钉扎 SHA256:+CaFHIb60… 与受信记录一致，固定 Collector stdin 下发）→ 上传建档（182 真实包）→ CVE 匹配真实零命中（主机线仅认 openwrt.org 公告，不合成）→ logread 证据 1304 行入库 → 影子 device_surface：**runtime 分析师以 5 工具消费真实 logread 证据**（6 发现全挂真实证据 ID，决策引用 6 真实 SE）
- **真实链路 2（Ubuntu 24.04 @192.168.183.129）**：dpkg 采集 1790 包 → 真实情报（本地存档 588 行 + 线上 NVD/KEV/EPSS 同步 349 条）→ 377 匹配/125 真实风险 → 影子 risk_review 多轮全链成功（risk 12 = CVE-2026-63073 openssl：potentially_affected / stale_verified / static_evidence_only → scheduled_fix，门禁 pending_human_review，待审批计划 requires_approval 强制）→ Harness 调查任务 15 条证据包挂接 + 修复门禁 blocked 演示
- **E2E 暴露并修复 3 项真实缺陷（回归锁定）**：①情报同步二次运行崩溃（autoflush=False 下同轮重复建行，二次同步 one_or_none 抛 MultipleResultsFound；改 first()+flush 并清理存量 6 行）②设备身份降级（upsert_device 弱探测轮无条件覆盖已识别身份；置信度更低时不覆盖身份字段）③设备线↔主机线证据键失配（_evidence_keys 经同 IP 资产与指纹钉扎 DeviceConnection 双向传递；修复后 C1 runtime 真实入链）
- **回归与安全**：全量 **655 passed / 0 failed**；Mimosa 0 findings（scan-…-b7c5bff9c409）；敏感信息干净；影子零触碰正式字段（前后快照一致）；**flag=off 保持**；零设备写操作（无产物登记/无修复审批）
- **边界（如实）**：产品内设备 SSH 采集需 Linux 采集节点（Windows 被策略拒绝，已演示边界）；OpenWrt 主机线零命中为诚实结果；Ubuntu Falco 常驻需 sudo 密码交接（stale 语义按设计工作）；本轮结束即停止

## 2026-10-16（Stage 9B M4.2 收尾）：统一四智能体质量闭环验收（遗留实验全部补齐 + Y6 反事实 2×2 修正 + Runtime Agent 正向贡献度量；650 回归零失败；flag=off 维持）

- **交付**：IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md（十节收尾报告：离线核查/遗留补齐/Y6 修正/RT 正向贡献/方向四层分析/完整分母/回归扫描隔离/诚实性声明/切换准备状态）+ backend/scripts/stage9b_closure_{cases,experiment,stats}.py + backend/tests/test_closure_counterfactuals.py（13 项）；实验脚本与真值先验提交 9f9e2e6（先于任何收尾 LLM 运行）、脚手架修复 d306622、退化输出检测 5ab79e1
- **第一部分（离线核查，零 LLM）**：M4.2 主矩阵完整性独立重建——25 主矩阵+6 消融全部对账（19 全链+5 兜底+1 simple+6 消融）；432 调用/3,394,004 tokens meter 口径闭合（client 级 338 差 10=零 token 失败调用；逐 Agent 230 差 202=agents_log 每角色末次调用语义，定向复议/补查覆盖同名条目）；**更正主报告两处口径**（E3「六跑全 not_affected+monitor 零方差」实为 LLM 4/4 零方差+2 兜底落真值；逐 Agent 表计量范围需标注）；原始 31 文件零改动核验
- **第二部分（遗留补齐，真实 LLM，全部落真值）**：E4a/E4b 复验两跑完全一致（potentially_affected+mitigate+人工——厂商冲突语义在 LLM 层生效；方向 downgrade_minor 双跑一致保守偏差）；X2 复验 not_affected+monitor 全对（KEV 未推翻已修复事实）；X3 复验 potentially+scheduled 全对（过期证据不驱动 immediate）；Y4/Y10 资产调查员消融完成——**判定不承重、校准承重**（Y10 隐藏后置信度 0.62→0.70、暴露面 0.4→0.65 膨胀，证据分级纪律约束决策置信度）
- **第三部分（Y6 反事实修正）**：原单因素设计（仅去 KEV）标注 SUPERSEDED 保留——caddy 公网×CVSS9.8 通道下去 KEV 放大因子仍成立；新 2×2（KEV×公网高危）四格先验真值：确定性放大因子断言 **4/4 PASS**，LLM 处置与因子存在性**一一对应**（kev0_pub1 格 immediate 保持=原设计预期被证伪；kev0_pub0 格 immediate 被确定性门禁拦下=端到端正-反对照）
- **第四部分（Runtime Agent 正向贡献，RT-A/B/C/D 同构反事实）**：四条件共用相同设备/CVE/静态事实、仅运行时层不同；最终样本（rt2-）完整管线 impact/action **4/4 全对**（方向 3/4）；**RT-D（无监控）隐藏运行时分析师后决策崩为 insufficient（承重实证）**；RT-B/RT-C 不承重（freshness 分桶与覆盖状态为程序事实）；RT-A 分析师贡献=新鲜度核实（verified/fresh）、关联语义偏保守（suspicious_unlinked vs 设计预期 cve_related）如实记录
- **本轮暴露并修复 2 项脚手架缺陷（回归锁定+受影响运行重跑，污染集留档）**：①Y Fixture 事件缺 timestamp 键→主矩阵全部 Y 案例证据层时间戳为空（RuntimeEvent.occurred_at 一直正确；已记录 Y 运行无真值依赖 freshness，19+3 结论不受影响）；②RT 传感器心跳 120s 竞态（M4 已修的同类 E/X/Y 竞态未继承到新 Fixture）。另增运行时分析师 Schema 回显退化输出检测（rt2-RT-A 两次命中的随机失效模式）
- **回归与安全**：全量 **650 passed / 0 failed**（637 基线+13 收尾专项，终态复跑零回归）；Mimosa 深度扫描 **0 findings**（scan-2026-10-16T06-22-58.264Z-997fe0409b11，seal sha256:9d3c421e…de2d0a，123 依赖包）；敏感信息干净（无凭据字面量，.env 不入库）；shadow 全程零触碰（收尾运行全部 shadow/sink=None）；**flag=off 保持**
- **诚实记录**：收尾 33 运行文件=26 有效全链+7 被取代首跑（5 外部故障+2 模型退化），全部留盘不删除；累计真实成本 meter 口径 ≈7.51M tokens/1005 调用（含重试与故障成本）；E5「监控过期→方向下调」混同确认为方向通道最弱项（改进需另建评分规范版本，本轮不动原始实验）
- **切换准备状态：候选具备，建议启动真实设备 Shadow 验证（人工决策）**；本轮不设 flag=on、不删旧编排器、不启动 Shadow，到此停止

## 2026-10-16（Stage 9B M4.2 主轮，补记）：统一四智能体研判质量深化（上轮交付，报告 IOT_UNIFIED_FOUR_AGENT_QUALITY_REPORT.md；其 ai_collaboration 归档在本轮补记）

- 四 Agent 专业分工 Schema 深化 + 四维分层研判 + E2/E3a/E1/X2 整改 + Y1–Y10 独立案例 10/10 全对；主矩阵 25 运行中 19 全链 LLM 评审 impact/action 19/19、人工路由 5/5、引用幻觉 0、方向 14/19（偏差全保守/口径项）；System B 同库 Y 案例 10/10 同对（统一链优势集中在分层语义/边界案例/可解释性，代价 ≈10× token 如实呈现）；实现与先验真值表提交 42fe3b1 先于实验数据入库；全量 637 passed；Mimosa 深度扫描 0 findings（scan-2026-10-16T02-26-27.410Z-4d6db1efbac3）；维持 flag=off。遗留中断项（E4 复验/X2/X3 复验/反事实/2 项 asset 消融）全部由本轮收尾补齐

## 2026-10-15（Stage 9B M4.1）：统一四智能体研判校准与成本治理（口径修正+五类缺陷修复+证据预取；影响判定首次达标，成本/处置差一步，flag=off 维持）

- **交付**：IOT_UNIFIED_FOUR_AGENT_CALIBRATION_REPORT.md（十项：口径修正/五类根因与修改/证据预取设计/逐 Agent 前后成本/严格配对/稳定性/回归/扫描/Commit/迁移判定）+ backend/scripts/stage9b_calibration_stats.py（离线核查，零 LLM）
- **第一部分（零付费离线核查）**：M4 的 20 次运行重建五类口径——全链 LLM 14 / 程序兜底 3（**实为 E3a×2+E3b×1，原报告误记"E3a 三次"**）/ 消融 1 / simple 2；LLM-only 修正口径：影响 85.7%、处置 57.1%（原混合口径 88.2%/64.7% 把兜底混入）；7.6s=76.0s/10 事件全量口径（104.1s 合并应为 9.46s/事件）；调用双口径（meter 258=237+21，client 246）；原始存档/真值零改动
- **第二部分（通用安全语义，零案例硬编码；事实+校验+门禁三层）**：E3 分支排除确定性提取（branch_excluded 不得被通用匹配推翻）/ E4 厂商冲突预检（冲突未消解禁 confirmed 与修复处置）/ E5 verdict 新增 runtime_evidence_validity+urgency_basis 分离字段（static_evidence_only 不一刀切禁止但强制人工）/ X2 确定性 fixed 语义（KEV 不改变已修复）/ X3 过期证据≠适用性不足；门禁新增 7 类确定性矛盾理由；35 项新测试锁定
- **第三部分（Evidence Preparation，非第五个 Agent）**：LangGraph 新增 prepare_evidence 确定性节点（复用只读工具/多源情报包/SecurityEvidence；运行内只读复用；新鲜度按当前时间重算；有界；失败退回自主查询）。逐 Agent 前后：资产工具 90→76（-15.6%）、专家延迟 -17%~-27%、墙钟/评审运行 173.8s→160.3s（-7.8%）、全链口径 token 93.0k→88.5k（-4.8%）——评审运行口径 +15.6%，**成本"实质改善"未达，如实判 ✗**
- **第五部分 B-D（真实 LLM 复测，Fixture/真值零改动，22 次全 completed，0 失败 0 兜底 0 触界）**：矩阵 17 全链+2 simple+1 消融 + E4 补充 2（缺陷修复后）。**影响判定（配对）9/9 vs System B 7/7——首次达标**；处置（配对）8/9 vs 8/8（差 1 例 E2 静态紧迫性超集）；X2 not_affected+monitor 完美（上轮 insufficient+scheduled 超集）；X3 回到真值（上轮双超集）；E5 处置 3/3 零方差（上轮 immediate×2 超集）；E4 修复后 5/5 全对两跑一致；E3b 三跑全部识破误匹配（上轮同实例曾接受）、E3a 残余 1/6 方差；引用幻觉 0/20（2 例评分器假阳性已对齐，原始存档未改）；消融 F7 三项全中
- **本轮暴露并修复 1 项真实缺陷（回归锁定+真实复测）**：E4 厂商冲突漏检——get_source_bundle release 作用域 canonical value 为单记录形态，detect_vendor_conflict 只读 records 漏检 → 兼容两种形态 + 单记录回归测试 + E4a/E4b 修复后真实复测 5/5 全对
- **回归与安全**：全量 **589 passed / 0 failed**（554 基线 + 35 项校准专项，缺陷修复后复跑确认）；Mimosa 深度扫描 **0 findings**（scan-2026-10-15T17-10-38.086Z-25c64eb52112，seal sha256:edb186b2…529f1b，123 依赖包）；敏感信息干净；shadow 零副作用
- **门槛判定**：影响 ✓（首次）/ 稳定性 ✓（E1×3、E5×3 全一致，0 兜底）/ 安全面 ✓（人工路由 100%、幻觉 0、fail-closed 扩展）/ 处置 ✗（差 1 例）/ 成本 ✗（-4.8% 非实质）→ **维持 LINUXGUARD_UNIFIED_PIPELINE=off**；遗留清单：static_evidence_only 放大因子前提 / E3a 残余方差强制人工 / 方向口径对齐 / 预取切片瘦身（目标 ≤60k/评审运行）
- **边界**：未切换生产入口；未删除旧编排器；未绕过 Harness；System B 对照零新增调用（复用 M4 已核查留档）；原始产物本地 reports/ 留存不入库；本轮结束即停止

## 2026-10-15（Stage 9B M4）：统一四智能体最终验收实验完成（全部 10 事件；未达切换门槛，flag=off 维持）

- **交付**：IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md（准确 Commit/20 次运行状态/新旧对照/重复实验/智能体增量贡献/Harness 安全回归/成本/测试扫描/切换门槛判定/切换回滚方案 + 诚实性声明）
- **实验完成度**：充值最小调用验证通过（deepseek-v4-flash/0.1/真实 usage/无 402）后，全部 10 事件（含按架构 §9 补齐的 X2：KEV+装机已修复）20 次运行全 completed——14 全链四智能体、3 次 API 连接错误程序兜底（判定全部落真值）、1 屏蔽消融（F7 通过）、2 simple 直通（0 LLM）；1,357,234 tokens / 258 调用 / 58min；E1×3、E3×6（双实例各 3 次）、E5×3 重复
- **安全面全达标**：人工路由 6/6；引用幻觉 0/20（评分器对齐 runner known_evidence_ids 复评，原 2 例假阳性修正）；无依据升级 0；E1 重复 3/3 完全一致且真值全对；X2 未因 KEV 虚判 confirmed_affected（确定性工具 version_impact=fixed 正确）；X3 stale_verified 语义+门禁正确；预算/超时/异常/屏蔽全程未绕过门禁
- **未达切换门槛（诚实结论）**：影响判定 88% vs System B 100%、处置适当 65% vs 91%、单事件 token ≈3.2×、墙钟 ≈27×、E3/E5 重复 2–3 值方差；退化逐案例根因（E3b#1 纯 NVD 单次方差接受误匹配 / E4·E5 处置激进但人工截住 / X2 已修复语义保守化 / X3 保守副作用）；**LINUXGUARD_UNIFIED_PIPELINE 保持 off，整改清单 §9 五项，等待用户确认后再议**
- **5 项真实缺陷修复（全部回归锁定）**：脚手架 target_ref 保真度（"fixture"→资产 hostname，生产 adapter 同语义）；脚手架传感器心跳 120s 竞态（运行前刷新在线心跳）；生产·决策规划师空 verdicts 伪成功→完备性反馈重试+兜底（2 测试）；生产·simple 直通路径 routing_json/decision_json 不落库→对齐（测试扩展）；生产·state.error 重复定义覆盖并行 reducer→InvalidUpdateError 崩溃→删除重复定义（reducer 在位性测试）
- **实验基建**：逐运行 JSON 落盘/断点续跑/已完成去重/Token 硬预算 2.5M（本轮真实使用：4 次归档后续跑重跑全部去重完成）；3 个归档目录（targetref-defect / heartbeat-race / network-outage）缺陷期运行完整留档不混入验收
- **对照有效性**：System B 上一轮全量（10 事件/44 调用/242,108 tokens）经 event_review_pipeline 代码版本核查（d14f354 后未改）保留；X2 由本轮同配置补充（4 调用/23,142 tokens，同为非受影响判定）
- **回归与安全**：全量 **554 passed / 0 failed**（551 基线 + 3 新增专项，零回归）；Mimosa 深度扫描 **0 findings**（seal sha256:448f342c…2394）；敏感信息扫描干净（无凭据字面量/私网地址/用户路径）；shadow 零副作用测试锁定；API Key 未打印未入库
- **边界**：未切换生产入口；未删除旧编排器；原始实验产物（LLM 原文/逐智能体日志/usage/Trace/归档）本地 reports/ 留存不入库

## 2026-10-15（第九阶段前置专项）：四智能体有效性深度审计（真实代码追踪 + 真实 LLM 消融/反事实；零生产代码改动）

- **交付**：IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md（12 节：架构/逐智能体贡献/消融/反事实/摆设化结论/整改清单 F1-F10/升级方案 R1-R8/竞赛数据表/方法学声明）；实验脚本 backend/scripts/stage9_agent_effectiveness_audit.py + stage9_recompute_metrics.py（可复跑、无密钥入库）
- **静态审计核心结论**：仓库存在两套"四智能体"——System A（services/agents/，真工具循环 14 专属工具）与 System B（event_review_pipeline.py，单次类型化 LLM + 确定性证据包 + 确定性门禁）。System B 输出全链真实消费（RiskAssessment.final/decision → 排序/人工复核/修复授权/Harness 补采复评）；System A 主输出 risk_json 为死端（仅 AgentOps 展示），其 remediation 智能体因上下文饥饿+授权依赖结构性空转（实测 risk_ref=""、actions=[]）
- **真实实验**（deepseek-v4-flash 与生产同配置，约 160 次调用，合成 CVE/TEST-NET Fixture，真值表先于实验独立定义）：A 纯规则处置正确 2/7（E3 假阳性/E4 无视冲突/E5 忽视过期全部命中）；B/C 四智能体 6/7、影响判定 7/7、114 条证据引用 0 幻觉、0 确定性矛盾；D 屏蔽任一智能体→建议全坍缩兜底、人工门禁 4/4 保持；System A runtime 屏蔽 62→54 分/high→medium；CF6 Zephyr：能力标注入 Trace 但 RUNTIME 智能体 schema 两次全败（fail-safe 降级）
- **正面实证**：E3 误匹配候选被 impact 智能体识破（定向复议后明确"版本规则命中为假阳性"并引用分支范围证据），coordinator 拒绝依未核实 fixed_version 触发升级——规则引擎同案例给 High 69.05/scheduled_fix。E4 矛盾情报全部转人工复核。结论：规则+智能体优于纯规则；但简单案例（E1/E2）两者一致，成本只应花在困难候选（R8 分层方案）
- **量化边界**：auto_confirmed 0/14（high_or_critical_final_score 14/14、confidence_below_0.70 12/14 门禁）——LLM 对分数影响理论性、对建议/路由/补采影响实在；成本 System B ≈2.2-2.5 万 token/事件、System A ≈3.7 万 token/编排
- **缺陷清单**（未整改，待评审）：F1 P0 report_service opinions list 崩溃（已复现）/F2 双体系死端/F3 System A 重试无反馈/F4 remediation 上下文饥饿/F5 aggregate_risk 不消费 version_impact/F6 新鲜度不参与运行时状态/F7 无优雅降级/F8 竞赛口径双体系混名/F9 评审成本/F10 统计器伪报已修正
- **诚实性**：统计器首版 2 处伪报（首报 50 条无依据断言）留档并离线修正为 0；单次运行方差如实标注；合成 CVE 的能力边界如实声明；密钥/真实库/原始日志未入库
- **回归**：全量 **499 passed / 0 failed**（零生产代码改动，与基线一致）

## 2026-10-15（eBPF 2.0 P2-2）：OpenWrt logread 只读降级采集（真实链路 21/21 + 全量 499/0）

- **真实采集**：OpenWrt 25.12.5（VMnet2 实验段）经既有 DeviceConnection（指纹钉扎与 2026-10-13 受信记录一致 + 设备私钥环境变量引用）执行固定只读脚本：身份段（hostname/boot_id/UTC 纪元/本地偏移）+ logread 全量环形缓冲；1237 条真实事件（窗口 00:13:30→03:01:55 UTC，tz=+0000）全链入库
- **P0 复用**：append_events 既有管线（指纹幂等/资产绑定 1237:1237/证据 1:1/清空语义），零新表零新库；重复采集全量对账（duplicates 1268 + stored_new 3 = built 1271，3 条=采集会话自身 SSH 登录的真实新日志，如实说明）
- **诚实语义**：source=openwrt_logread、观察模式=syslog（新增第五模式）、智能体声明"拉取式降级采集非 eBPF"；缺年份/不可解析行跳过计数（46 条防御路径如实入元数据）；ring 覆盖丢失 unavailable；boot_id 参与指纹（跨重启零误合并，专项锁定）；窗口变化三采新行入库/旧行判重/dropbear 57 条真实行可见
- **联调**：CVE 下钻真实 syslog 证据直接匹配（direct_count=57、runtime_status=verified、exploitation_confirmed 恒 False）；统一 Trace runtime_log_collection completed；coverage/reliability 端点 logread 传感器可见
- **修复 2 项真实验收发现缺陷**：raw 传输标记 "logread_ssh_pull" 含 "ssh" 关键词子串致 1246 条全量误分类敏感文件访问（改名 logread_remote_pull + 命名约束注释）；"立即重复=0 新增"断言不成立（会话自身产日志）改全量对账
- **边界**：对设备零改动（只读、零配置、零软件包）；真实重启未执行（避免干预，语义专项锁定）；Zephyr 零触碰；未进入第九阶段
- **回归**：新增专项 23/23；相关域 306/0（实现期中检）；全量 **499 passed / 0 failed**（476 基线 + 23 新增，零回归）

## 2026-10-15（eBPF 2.0 P2-1）：五形态性能评测完成（真实内核采集 0 丢失 + 判重索引缺陷修复 115→379 EPS）

- **五形态实测**：synthetic 后端摄取 379 EPS（修复后）/批 RTT P50 1.3s；replay 断网 21.6s→5 次重试全成功/spool 清零/幂等收敛 40 唯一；real-wsl 真实 bpftrace 内核两次独立运行 41446/41322 事件、归因对账 0 丢失、探针 CPU ≈2% 单核；real-vm-falco 常驻 Falco journalctl 拉取 14910 事件、0.021% 丢失（1 条如实记录）；bounded-spool 容量不变量与数据保全成立（告警路径未触发，如实记录）
- **判重索引缺陷（实测发现→修复→回归锁定）**：P0 部分唯一索引 WHERE != '' 不被 SQLite 查询计划蕴含推理，判重全表扫描（7500 行批 RTT P50 4.3s）→ 全量索引+幂等补建 → EXPLAIN SCAN→COVERING INDEX；后端摄取 115→379 EPS（synthetic 口径，不表述为内核采集提升）
- **8 项评测链缺陷修复**（3 次失败尝试留档 reports/ebpf-p21-final/*attempt*.json）：wsl 内联转义 EOF / 资产登记非幂等 / 伪造 boot_id 被身份防线正确拒绝（去注入改真实身份）/ ebpf_trace_capture.sh 健康文件 grep -c 双 0+set -e 中止（生产脚本缺陷）/ falco 消息本地时区 +8h 伪零延迟（journal UTC 基准+tz_mismatch 计数）/ 对账口径错配虚报 25% / 固定 sensor_id 跨运行污染
- **诚实边界**：不可测项全部 unavailable（bpftrace 丢失计数未报告→null、falco 引擎 drops/CPU 无 sudo、replay 延迟无实时语义）；/etc/passwd 读取噪声不进丢失结论；VM 文件写项 no_perm 如实降级
- **回归**：新增专项 41 项；相关域发现 init_db 幂等契约回归（_ensure_query_indexes 首版二次运行仍报告变更）→ 根因修复（只在真创建时报告）；全量 **476 passed / 0 failed**（435 基线 + 41 新增，零新增回归）
- **安全**：VM 连接参数改环境变量注入，私网地址/用户名不写入跟踪文件；reports/ 证据本地留存不入库
- **边界**：未进入 P2-2 与第九阶段；未删改任何既有测试；对 VM/WSL 零持久化改动

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

## Final closure execution

The delegated operator actor is recorded as `codex:operator-authorized-current-chat-20261018`. The three package upgrade and its authorization hashes are historical lab evidence; no user personal signature is inferred. Current changes add bounded read-only runtime log scheduling, post-repair admission guards, and reproducible Docker metadata.
