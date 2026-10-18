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
## Stage 10 第三轮（2026-10-17）：隔离克隆全链真实验证记录——停在授权二门禁

基线 `f60c102`。统一报告：`IOTGUARD_STAGE10_ISOLATED_CLONE_PREFLIGHT_REPORT.md`。本轮**后端应用代码零变更**（唯一新文件为 ops 启动器 `backend/scripts/start_clone_node.py`），既有回归基线（交付版全量 667/0 + 前端 21/0，见第二轮记录）继续有效；本轮验证为生产后端真实执行链：

- **身份隔离八项逐一实测**：hostname/machine-id（双口径哈希同源一致）/MAC/UUID/SSH 主机密钥（新指纹 `SHA256:JIvwH3Q…`）/authorized_keys（克隆密钥唯一，源密钥登录实测 `Permission denied`）/netplan .110/cloud-init 冻结——全部读盘+联网双重复核。
- **恢复验证（关键负样本如实）**：第一次"离线直写标记+关机态快照"协议无效（无 delta，标记未消失）——作废并披露；重做为客户机内标记协议：快照后 r3 标记经 revert 后实测消失，身份/安装版本 .15/候选 .16 全部不变，回滚后可正常引导 → restore_verified=true。
- **采集与研判真实验证**：连接 3 preflight ready=true；首次认证采集 INV-3bef62a8…（execution_node=stage10-clone-node，authenticated，1790 包，output_sha256 `caaa5083…`）；四智能体 `UA-b522f38df422-127` completed（四角色全 valid：113/89/111/278 秒，零冲突零降级，11 项缺口如实保留，pending_human_review/confirmed_affected，模型未代签）。
- **Harness dry-run 首次全绿**：preflight ready=true、issues=[]（对比资产 1 历史五次全败于 official_candidate_unavailable）；`apt-get --simulate` 3 upgraded/0 newly/0 remove；dpkg audit 干净、无 hold；最终计划 SHA256 `352208827415d3c9…4848cf` awaiting_approval、approved_by 空。
- **生产防护复核**：双写开关全程 0；dpkg 写零；approve/execute/rollback 端点零调用；资产 1 两条连接原样；风险 126 状态变化（reanalysis_required）为官方核验契约行为且治理历史完整保留（偏差披露见报告 §五）。
- **健康四态（交付时刻，如实）**：backend_online=true、collection_node_online=true（双节点）、sensor_healthy=false（falco inactive——sudo 凭据门禁；logread stale）、runtime_evidence_fresh=false。
<!-- STAGE10_GATE_STATUS_END -->


# 测试结果

## Stage 9B M5：唯一化准备与门禁验证（2026-10-17，切换停在 Q1–Q8 人工门禁）

基线`58fd221`；中立迁移后回归。

| 验证 | 已确认结果 |
| --- | --- |
| 最终全量 | **742 passed / 0 failed**（主干 701/533.01s + test_ebpf_p21_perf 41/0.24s；与 GLM 切换里程碑 742 基线完全对齐，零增减——旧系统既有测试全部在套件内并通过） |
| 统一系统专项 | unified pipeline+adapter+investigation **75/0**（中立迁移后） |
| 迁移波及面 | evidence_prep + quality_deepening + agent_harness_upgrade + multi_source_intelligence **128/0** |
| 迁移契约演练 | 隔离副本 **44/0**：中立迁移代码重验 M4.7 全部契约；E9 首跑 2 失败定位为演练脚本对旧 `_selection` 的补丁失效（非生产回归，仅副本写入范围扩大且已全字段回滚差异 0），演练改补丁至 `review_common.select_candidates` 后 44/0；D3 改造为退役感知双态断言（旧模块在→验护栏，退役后→验不可导入） |
| Mimosa 深扫（迁移后代码） | 过程扫 `scan-2026-10-17T01-59-32.762Z-90ab750eaf44` 0 findings（seal `5b8402d7…a0ef`）；**交付终扫 `scan-2026-10-17T02-18-21.318Z-f6346022fd88` findingCount=0**，seal `sha256:580103b6…f4b`，123 依赖包，离线通告库可用（1 包 2 通告命中） |
| 一致性备份 | `local-archive/m5-switch/linuxguard-preM5-20261017T020005Z.db`，397,836,288 B，sha256 `33283418…e513f`，integrity_check=ok |
| 令牌探针（live） | 运行中进程：错误令牌 401、轮换令牌 401（进程环境早于轮换）——令牌生效验证列入切换重启步骤；risk-126 复核确认未被探针改写 |
| 修复写开关 | `LINUXGUARD_ENABLE_DEVICE_REPAIR`/`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR` 未设置（默认 0）；演练 H3 实证关态拒绝 |
| 边界 | 未切 on、未重启、未删产品代码；live on 态验收 A–D 待门禁放行后执行 |

## 模型切换 GLM-5.3-Flash（2026-10-17，M4.7 后续）

| 验证 | 已确认结果 |
| --- | --- |
| 最终全量 | **742 passed / 0 failed**（580.98秒，5既有警告；M4.7 基线 730 + 12 项协议专项） |
| 协议专项 | `test_llm_protocol_clients.py` 12/12：消息转换（system 提取/tool_use/tool_result 合并/交替）、thinking 块处理、usage 映射、协议分发、System B 双分支 |
| 统一链专项 | unified pipeline+adapter+protocol 87/0；smoke 前置 63/0 |
| 连通性（真实调用） | 统一链：纯文本 JSON ✓（8.2s）、工具调用 ✓（check_host 正确参数）、工具结果往返 ✓；System B 生产形态 UserMessage+json_output ✓（2.7s，干净 JSON+真实 usage） |
| 真实四智能体 smoke | 风险12 shadow `m47-glm-smoke4`：**4/4 角色 succeeded**、19 调用/325,405 tokens/2506s（护栏内，预算未触界）、判定 `not_affected/downgrade_major/monitor/0.85`（与 DeepSeek 基线同对象结论一致）、正式字段零触碰 |
| 护栏校准依据 | 长输出实测：完整报告单调用 120-165s（133k prompt 仅 19.5s，瓶颈为生成而非上下文；thinking=off 实测更慢 164s vs 120s，保留模型默认）→ HTTP 400s/单智能体 900s/全程 3600s |
| 迭代留档 | smoke1/2/3 为护栏校准过程样本（60s 超时全降级→150s 局部→480s 局部），全部保留于 `reports/m47-work/glm-smoke/`，未筛选删除 |
| 边界 | 密钥仅存 gitignored `backend/.env`；tracked 文件敏感扫描 0 命中；flag=off、双修复写开关 0 维持 |

## Stage 9B M4.7（2026-10-17）

基线`fa3b474`；M4.6参考729/0。本轮围绕P0阻断项、W47连续shadow、隔离副本迁移演练与必要回归。

| 验证 | 已确认结果 |
| --- | --- |
| 最终全量 | **730 passed / 0 failed**，527.88秒，5个既有utcnow弃用警告；729基线+1项新增fail-closed回归 |
| 新增回归 | `test_orchestrator_failure_fail_closes_risk_not_stuck`（编排器异常→正式批处理fail-closed，不停留agent_reviewing）；适配层专项6/6 |
| 前端 | 全套Playwright **21 passed / 0 failed**（18.4s）；生产构建通过 |
| P2迁移演练 | 隔离副本 **44 passed / 0 failed**：快照哈希/排空/off-on互斥9项/契约17键/简单与全量分层/fail-closed/影子禁晋升/人审401·409/Harness未审批与错哈希拒绝/仅切flag不还原/全字段恢复差异0/审计保留/完整性ok |
| W47连续Shadow | 9/9统一链completed、36/36角色成功、零降级；正式字段每轮快照一致；真实库risk/harness零更新；3,299,064 tokens（40次/运行预算未触界） |
| W47申请纪律 | IR-ee08ce1a/IR-f2feb101 awaiting_authorization未执行；窗口6次SystemB对照提取缺陷失败样本保留+2次补充捕获（分歧模式与M4.6一致） |
| 令牌 | 现用令牌轮换后旧字面量失效（防呆比对通过）；329跟踪文件新旧令牌/私钥0命中 |
| Mimosa | 恢复可用；深扫`scan-2026-10-16T16-37-49.880Z-c218fa2fda10` 0 findings/123包（seal`730ff98c…a504`）；最终重扫见验收报告§9 |
| 边界 | flag=off、双修复写开关0全程维持；演练/影子零设备写、零正式结论写入、零shadow晋升 |

## Stage 9B M4.6（2026-10-16—17）

基线origin/main=`10be6f0`；M4.5参考711 passed / 0 failed。本轮测试仅围绕真实调查、采集授权、迁移契约及既有回归。

| 验证 | 已确认结果 |
| --- | --- |
| 最终全量 | **729 passed / 0 failed**，842.87秒，5个既有utcnow弃用警告；711基线+18必要专项 |
| 新增专项终态 | 18 passed / 0 failed，24.11秒 |
| 既有相关专项 | 初验78/0；真实问题修正后的统一/适配/调查专项72/0 |
| 前端 | 全套Playwright21/0；构建通过，AgentOps保留影子标识与人工授权 |
| 真实只读采集再研判 | 1790包新原文入库；四角色实际重跑；同事实置信不增长；缺控制令牌401、错申请哈希409 |
| Harness | 新影子计划仍awaiting_preflight；错误修复审批哈希409、未审批执行409，没有成功修复审批 |
| 隔离 | 正式风险全字段与M4.5一致；历史19条统一运行不变；迁移只读规划0差异 |
| Mimosa | 命令/工具无入口、插件查询plugins=[]；本轮未扫描，验收未关闭 |
| 补充Bandit | 相关文件保留1项既有B104（监听地址字面量数据比较），不能替代Mimosa/完整扫描 |
| 引用与敏感检查 | 4运行52引用均解析，INV/ADV摘要复算通过；暂存26文件匹配0；全329文件中2处既有演示默认值匹配当前本地控制令牌，需迁移前轮换，不宣称全无发现 |

最终全量结果、新增专项终态、逐引用原文核验和敏感检查详见本轮报告验收补录及本地`reports/m46-work/`。中间失败/被替代运行均保留，不计为最终通过。

## Stage 9B M4.5（2026-10-16）

当前交付基线：最新 origin/main `cbce1293b93e02d23093263c6bedcc0d8fee0992`，开发前工作区干净。唯一项目 IoTGuard-Public；System B 正式入口；LINUXGUARD_UNIFIED_PIPELINE=off；设备修复与 Ubuntu 隔离写开关均为 0。当前依据为 `IOTGUARD_REAL_REMEDIATION_E2E_REPORT.md`，下方 M4.4 及更早内容作为历史保留。

| 检查 | 实际结果 |
| --- | --- |
| M4.4参考基线 | 677 passed / 0 failed；origin/main cbce129 |
| Ubuntu + OpenWrt专项 | 64 passed / 0 failed（Ubuntu新增34，OpenWrt原30）；扩大含Trace/M4.4专项101 passed / 0 failed |
| 最终全量回归 | 711 passed / 0 failed（679.88秒，5个既有弃用警告） |
| 前端 | build通过；全套Playwright21/0；真实Harness/风险/AgentOps核验 |
| 真实dry-run | preflight_failed，三包实际.15、候选.15、USN.16不在本机索引；无索引刷新/包写 |
| 真实门禁 | 错哈希409、预演失败正确哈希409、未审批执行409、无控制令牌401 |
| 复检测试桩 | 缺新证据不fixed；未变/部分更新/官方不可达/中断/额外归档/摘要或身份错均停止或保持风险；审批/双许可/锁/预算验证 |
| 不可变历史 | 全部正式风险字段和历史统一研判前后摘要相同，未重跑四智能体 |
| Bandit1.9.4 | 新四文件无中高项；扩展9文件2574行，既有中危B108 1项（OpenWrt远端/tmp随机UUID路径）；16低危项保留，不作全局证明 |
| Mimosa | 本轮无工具/本机入口，插件查询空；未运行，不复用M4.4封印 |
| 敏感检查 | 当前322文件与暂存23文件已知凭据/私钥材料模式比对无匹配；未覆盖Git历史和未知格式 |

最终真实任务4ef1f86fcdfc45eb9dcec9b584b3c6b5，Trace TR-20261016152210-0e5f95，PRE-8f1b5602022b4afe901cba4bfafa9236。原始证据、真实库、地址、日志和截图均不提交；本地 reports/m45-work/ 保存 full-regression-delivery.txt、frontend-all-accepted.txt、bandit-accepted.json。Mimosa缺口使安全验收未全部完成，不能宣称全局安全。

---

> M4.4 实现提交：`c7ca5a3e2a558b52799c4b113643e25ab3ac44c7`（已推送）；最终报告提交以本文件最新 Git 记录为准。

## Stage 9B M4.4（2026-10-16）

| 检查 | 实际结果 |
| --- | --- |
| 全量回归 | 677 passed / 0 failed（655 基线 + 22 项主链必要回归）；交付代码最终复跑 487.00 秒，5 个既有 utcnow 弃用警告 |
| M4.4 必要专项 | 22 passed：发行分支/官方原文/纠正保留、精确 USN、节点认证/领取/失败/摘要/身份、单记录 ADV 引用与伪造拒绝、Schema 回显拒绝、计划源包版本/Harness 不授予权限 |
| 采集/Harness 相关专项 | 86 passed / 0 failed |
| 前端 | npm run build 通过；浏览器实际核对纠正 #9、两类真实采集、risk 126 同链、四角色原始输出及引用、分类计划、Harness needs_evidence/blocked |
| 实际一致性 | m44_real_cve_closure.py validate：11/11；39 个原始 ID 可解析；Trace 中引用均可解析；16 条历史影子全文不变；126 条正式风险全字段影子前后不变 |
| 真实运行 | m44-real-841d76e9aa，四角色 succeeded，runtime 7 真实证据/7 发现；confirmed_affected / scheduled_fix / stale_verified / pending_human_review；未确认利用 |
| 旧风险纠正 | correction #9 / risk 12 → noble openssl not_affected；保留 8 次关联历史影子。总 126 CVE 官方回查，51 可用、75 缺可用官方记录；15 条纠正 |
| Harness | 只读调查 needs_evidence；修复 blocked；错误哈希、无审批资格及 blocked 执行均 409；设备写 0、修复授权 0 |
| Mimosa | 0 findings；覆盖 partial / inconclusive，不能声称全局安全证明。SSRF 静态发现已改为固定回环、无重定向客户端后复扫 |
| 敏感检查 | 本轮改动对本地凭据值比对、私钥材料扫描无发现；Mimosa git-secrets 40 个历史提交无发现（含实现提交 c7ca5a3）；原始库/地址/日志/截图均不提交 |

最终 Mimosa 封印：`scan-2026-10-16T14-09-21.519Z-da2ab63a6201` / `sha256:f1a18ebd1b11ee95b113717e1d714bd1499946a0e4bcf867a58b2177f6f1f954`；223 个文件解析无失败；coverage 为 partial / inconclusive，威胁建模与发现阶段覆盖不完整。

失败/非验收运行同样保留：m44-real-0f50c24861（官方证据结构误拒后中止修复）；m44-real-33395231a5（Schema 回显伪空报告，经修复后重跑）。不把这两条结果混入最终验收。

> 记录最近测试口径与结果，与 CI 保持一致。最后更新：2026-10-16

## Stage 9B M4.3 核心主链轮（2026-10-16；E2E 证据 reports/m43-core-e2e-*/ 本地留存不入库）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **655 passed / 0 failed**（650 基线 + 5 新增：test_unified_pipeline runs 过滤 1 / test_multi_source 情报重复行容错 1 / test_discovery_pipeline 身份防降级 1 / test_ebpf_p23 证据键跨线 2；终态代码两轮独立复跑零回归） |
| 实机 E2E（backend/scripts/m43_core_e2e.py） | 五阶段 38 项检查全通过：A OpenWrt 12/12（发现/指纹钉扎采集/上传建档/连接预检边界/匹配诚实零命中/logread 幂等/风险计算）+ B Ubuntu 7/7（采集/情报导入/线上同步 349 条/377 匹配/125 风险/risk 12 就绪）+ C/D/E 19/19（flag=off 核验/OpenWrt 设备面影子研判/Ubuntu 风险影子研判/影子隔离快照/引用反幻觉/待审批计划/Harness×6 门禁/链内一致×2/Trace 贯穿/正式结论零写入/引用独立复验） |
| 影子研判质量（真实 LLM，14 次运行全部 completed） | risk_review 多轮全链成功：CVE-2026-63073 openssl → potentially_affected + scheduled_fix + pending_human_review（confidence<0.70/evidence_partial/stale_runtime_evidence/high_critical 四理由）；runtime_evidence_validity=stale_verified（Falco 45.8h 如实降级）、urgency_basis=static_evidence_only；canonical unavailable 不虚判 confirmed；计划 update_package openssl + backup/restart，验证+回滚齐备，requires_approval 程序强制 |
| 溯源核验 | E2：影子链引用证据 43 条全部真实存在于 SecurityEvidence；E3：统一 Trace 22/22 贯穿（unified_four_agent + harness_*）；E4：正式 RiskAssessment 零触碰（无最终分/裁决，review_status 保持候选侧）；C2b：影子前后正式字段快照一致 |
| 本轮缺陷修复（3 项，回归锁定） | ①情报同步二次运行崩溃（autoflush=False 重复建行）②设备身份降级（弱探测轮覆盖已识别身份）③设备线↔主机线证据键失配（修复后 OpenWrt 设备面 runtime 分析师真实入链，6 发现+6 引用全真实） |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-16T11-54-28.320Z-b7c5bff9c409，seal sha256:52fbd4fb…e18a7，123 依赖包） |
| 敏感信息/边界 | diff 与新增脚本无凭据字面量；设备密钥/口令仅环境变量引用；影子零触碰；flag=off 保持；零设备写操作 |

## Stage 9B M4.2 收尾闭环轮（2026-10-16；实验证据 backend/reports/stage9b-closure/ 本地留存，stage9b-quality/ 原始产物零改动）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **650 passed / 0 failed**（8m16s；637 M4.2 基线 + 13 项收尾专项 tests/test_closure_counterfactuals.py：Y6 2×2 四格放大因子断言走 build_evidence_prep_packet 真实路径/四格静态事实一致/真值不变量/旧设计 SUPERSEDED 留档/RT 四条件同构性与干预点/证据层时间戳回归锁（RT 新鲜≤1h、Y 非空）；终态 HEAD=5ab79e1 复跑零回归） |
| 离线核查（stage9b_closure_stats.py，零 LLM） | M4.2 主矩阵 25+6 全部对账（19 全链+5 兜底+1 simple+6 消融）；三口径对账闭合：meter 432 调用/3,394,004 tokens（主矩阵 348+消融 84）、client 级 338（差 10=零 token 失败调用）、逐 Agent 230（差 202=agents_log 每角色末次调用语义）；更正主报告两处口径（E3 零方差=LLM 4/4；逐 Agent 表计量范围） |
| 遗留补齐（真实 LLM，收尾 qc-*/abl2-*，全部落真值） | E4a/E4b 两跑完全一致 potentially_affected+mitigate+人工（方向 downgrade_minor 双跑一致保守偏差）；X2 not_affected+monitor 全对（KEV 未虚判）；X3 potentially+scheduled 全对；Y4/Y10 资产消融全对且暴露校准承重（Y10 隐藏后置信度 0.62→0.70、暴露面 0.4→0.65） |
| Y6 反事实 2×2（cf2-*，四格独立库） | 确定性放大因子断言 **4/4 PASS**；LLM 处置与因子存在性一一对应：kev1_pub1/kev1_pub0/kev0_pub1（原单因素设计证伪格）→ immediate_fix，kev0_pub0 → scheduled_fix（确定性门禁端到端拦下）；方向仅 kev0_pub1 一例偏差 |
| RT 正向贡献（rt2-* 最终样本，rt- 污染集留档） | 完整管线 impact/action **4/4 全对**（方向 3/4，RT-A downgrade_minor 偏差）；隐藏 runtime_analyst：RT-B/RT-C 不变（程序事实已足够）、**RT-D 崩为 insufficient+collect（impact 出真值）=承重实证**；RT-A 分析师新鲜度核实 verified/fresh 成立、关联语义偏保守（suspicious_unlinked vs 设计预期 cve_related）如实记录 |
| 收尾成本（meter 口径） | 33 运行文件 514 调用 / 3,754,203 tokens（26 有效全链 + 7 被取代首跑=5 外部故障+2 模型 Schema 回显退化，全部留盘）；含 M4.2 原始累计 ≈7.51M tokens / 1005 调用 |
| 缺陷修复（本轮暴露） | ①Y Fixture 证据层时间戳为空（预存；已记录 Y 运行无真值依赖 freshness，结论不受影响）②RT 传感器心跳 120s 竞态 ③运行时分析师 Schema 回显退化输出检测——均回归锁定；污染集 rt- 留档，rt2- 重跑为最终样本 |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-16T06-22-58.264Z-997fe0409b11，seal sha256:9d3c421e…de2d0a，123 依赖包，离线公告 1 包 2 条同 M4.2 交付态） |
| 敏感信息/shadow 隔离 | 无凭据字面量；.env 不入库（仅空值占位 example）；收尾运行全部 shadow/sink=None；**flag=off 保持** |

## Stage 9B M4.2 主轮（2026-10-16 交付，补记归档；实验证据 backend/reports/stage9b-quality{,-smoke}/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **637 passed / 0 failed**（589 M4.1 基线 + 48 项 M4.2 专项 test_quality_deepening.py，零回归） |
| 主矩阵（真实 LLM） | 25 运行：19 全链（impact 19/19、action 19/19、方向 14/19、人工 5/5、幻觉 0）+ 5 兜底 + 1 simple；Y1–Y10 10/10 案例全对；E3 LLM 4/4 零方差（收尾轮口径更正：另有 2 兜底落真值）；收尾轮补记逐 Agent 表=每角色末次调用口径 |
| 收尾轮口径更正 | 主报告 §3.2/§7「E3 六跑全部 not_affected+monitor」应读作「6/6 落真值；LLM 口径 4/4 零方差 not_affected+monitor；2 兜底 insufficient+collect」 |

## Stage 9B M4.1 校准轮（2026-10-15；实验证据 backend/reports/stage9b-unified-calibration{,-supplement}/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **589 passed / 0 failed**（7m03s；554 M4 基线 + 35 项新增校准专项 tests/test_evidence_prep.py：分支声明提取/版本分支前缀/冲突判定含 release 作用域单记录回归/预取包构建/节点失败降级/上下文携带/六类决策约束反馈重试/门禁 7 类矛盾理由/program_fallback 标记；缺陷修复后复跑确认，零回归） |
| 离线口径核查（backend/scripts/stage9b_calibration_stats.py，零 LLM） | M4 全部 20 运行五类分类：全链 14 / 兜底 3（E3a×2+E3b×1，修正原报告"E3a 三次"误记）/ 消融 1 / simple 2；LLM-only vs 混合口径：影响 85.7% vs 88.2%、处置 57.1% vs 64.7%；耗时口径修正（7.6s=76.0s/10 全量口径；104.1s 合并=9.46s/事件）；调用双口径（meter 258=237+21；client 246） |
| 真实 LLM 复测矩阵（stage9b_unified_compare.py --unified-only，deepseek-v4-flash/0.1，Fixture/真值零改动） | 20 运行全 completed：17 全链 + 2 simple + 1 屏蔽消融；**0 失败 / 0 程序兜底 / 0 预算触界**；1,505,184 tokens（评审）/ 240 调用 / 3,045.7s；evidence_prep 17/17 可用 |
| E4 缺陷修复补充运行（最终代码） | 2 运行全 completed：potentially_affected+mitigate+人工 ×2 完全一致，5/5 真值全中，144,966 tokens |
| 统一链 vs System B（严格配对，9 个 LLM 案例；System B 复用 M4 已核查留档，零新增调用） | **影响 9/9 vs 7/7（首次达标）**；处置 8/9（88.9%，差 1 例 E2）vs 8/8；方向 7/9 vs 6/8；人工路由 4/4 vs 3/3；引用幻觉 0（2 例评分器假阳性已对齐，真实幻觉 0/20） |
| 案例级改善（vs M4 LLM-only） | X2 not_affected+monitor 零超集（上轮 insufficient+scheduled 超集）；X3 potentially+scheduled 全对（上轮双超集）；E5 处置 3/3 零方差（上轮 immediate×2 超集）；E3b 3/3 识破误匹配（上轮同实例 1/2）；E4 5/5（上轮处置超集） |
| 退化点（如实） | E2 处置 immediate_fix 超集（static_evidence_only 路径，门禁人工截住）；E1 方向 maintain×2、E5 方向 downgrade_minor×3（保守超集）；E3a 残余 1/6 方差 |
| 逐 Agent 成本（前→后，19 评审运行） | 资产工具 90→76（-15.6%）、漏洞 72→81、运行时 77→93；专家延迟 -17%~-27%、决策 +3.6%；墙钟/评审运行 **-7.8%**；全链口径 token **-4.8%**（93.0k→88.5k）；评审运行口径 +15.6%——**成本"实质改善"未达 ✗** |
| 稳定性 | E1 impact/action/human ×3 完全一致；E5 处置 ×3 完全一致；E3 5/6；0 兜底（上轮 3 次 API 故障） |
| Mimosa 深度扫描 | 0 findings（scan-2026-10-15T17-10-38.086Z-25c64eb52112，seal sha256:edb186b2…529f1b，123 依赖包） |
| 敏感信息/shadow 隔离 | 干净；shadow sink=None 零触碰正式字段；**flag=off 保持** |

## Stage 9B M4 最终验收实验轮（2026-10-15；实验证据 backend/reports/stage9b-unified-final/ 及归档×3 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归 | **554 passed / 0 failed**（8m13s；551 基线 + 3 新增专项：决策空 verdicts 完备性×2、并行 error reducer 在位性；simple routing_json 断言扩展；零回归） |
| 统一链专项 | test_unified_pipeline + test_unified_adapter + test_json_extraction = 61 项全过 |
| 真实 LLM 最终验收（backend/scripts/stage9b_unified_compare.py，deepseek-v4-flash/temperature 0.1） | 10 事件 20 运行全 completed：14 全链 + 3 API 故障程序兜底 + 1 屏蔽消融 + 2 simple 直通；1,357,234 tokens / 258 调用 / 58min；断点续跑与去重机制真实使用 |
| 统一链 vs System B（11 事件对照） | 影响 88% vs 100%；方向 76.5% vs 72.7%；处置 65% vs 91%；人工路由 6/6 vs 4/4；引用幻觉 0 vs 不可比；成本 ≈3.2× token、≈27× 墙钟——**未达切换门槛，flag=off** |
| 重复实验 | E1×3 完全一致真值全对；E3×6 impact 三值分布 5/6 真值内；E5×3 impact 3/3、处置 1/3 |
| 重复口径 | E3 = 双事件实例（E3a=edge-02 有背景事件/E3b=edge-03 无证据）各自独立重复 3 次 |
| 智能体价值审计 | asset 90 / vulnerability 72 / runtime 77 次真实工具调用全 ok；decision_planner 0 工具（综合者）；follow_up 补查 34 结果 14 次确认回灌；门禁 auto_confirmed 仅 1/19 |
| Mimosa 深度扫描 | 0 findings（scan-2026-10-15T14-43-14.902Z-512f1a628440，seal sha256:448f342c…2394） |
| 敏感信息/shadow 隔离 | 干净（无凭据字面量/私网/用户路径）；shadow sink=None 零触碰正式字段（专项锁定）；flag=off 保持 |

## 四智能体有效性审计轮（2026-10-15，零生产代码改动；实验证据 backend/reports/stage9-agent-audit/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 全量回归（零生产代码改动） | **499 passed / 0 failed**（6m27s，与基线完全一致） |
| 真实 LLM 消融实验（backend/scripts/stage9_agent_effectiveness_audit.py，deepseek-v4-flash 真实调用） | A/B/C/D 全部完成：B 组 33 调用/159,897 token/75.1s；C 组 31 调用/177,159 token/77.1s；D1-D4 屏蔽组 6-10 调用；System A 完整 14 调用/36,710 token/41.7s、屏蔽 runtime 11 调用/26,628 token、Zephyr 13 调用/27,141 token；usage 全部真实上报（无估算） |
| 规则基线 vs 四智能体（7 事件对照真值） | 规则处置正确 2/7；四智能体 6/7（影响判定 7/7、人工路由 3/3） |
| 证据引用完整性（离线对齐证据包核验） | 114 条引用（B48/C66）0 包外幻觉；与证据包事实的确定性矛盾 0/14 事件 |
| 反事实 CF1-CF7 | 6/7 合格或优于规则；CF6 Zephyr RUNTIME 智能体 schema 两次全败（fail-safe 降级，无风险虚增）——缺陷 F3 |
| 实验统计器自检 | 首版 2 处伪报（case 键碰撞+packet 未包裹 → 首报"50 条无依据断言"）→ stage9_recompute_metrics.py 离线修正为 0，全程留档 |
| F1 缺陷最小复现 | 存在 v3 研判报告后 markdown_report 抛 `AttributeError: 'list' object has no attribute 'items'`（report_service.py opinions 遍历），本轮未整改待评审 |

## eBPF 2.0 P2-2 OpenWrt 降级采集轮（2026-10-15，证据 reports/ebpf-p22-20261015-111451/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 新增专项 test_ebpf_p22_openwrt_logread.py（解析/时区换算/跳过计数/事件形状/观察模式/心跳源/管线幂等/证据/重启指纹身份/窗口元数据/数据质量/Trace） | **23/23 passed** |
| 真实 OpenWrt 验收（backend/scripts/ebpf_p22_openwrt_live.py，21 项） | **21/21 PASS**：指纹受信一致 / 1237 真实事件绑定 1237:1237 / 证据 1:1 / 重复采集全量对账（1268+3=1271）/ 窗口变化三采（新 5 旧 1262 判重）/ dropbear 57 条 / 智能体数据质量与证据 / CVE 下钻 direct=57 verified / Trace completed |
| 相关域中检（-k "runtime or agent or trace or ebpf or iot or evidence"） | 306 passed / 0 failed |
| 全量回归 | **499 passed / 0 failed**（476 基线 + 23 新增，零新增回归；6m22s） |
| 验收过程发现并修复 | raw 传输标记含 "ssh" 子串致全量误分类敏感文件访问（真实验证：1246 条 file→修正为真实分类）；重复采集断言语义修正（全量对账） |
| 设备重启 | 未真实执行（避免设备干预）：跨 boot_id 指纹零交集由专项测试锁定，boot_id 留档供跨运行比对 |
| Mimosa | 写入钩子对验收脚本三次拦截（SSRF/SQL 注入/证书）→ 全部按建议修复（环回白名单/全 ORM 化零原生 SQL/原生 Transport 握手）后放行；**提交前完整扫描 0 findings**（封印 sha256:c6f1b184…0f1f，scan-2026-10-15T03-15-55） |

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
- **全量**：`python -m pytest -q`（当前基线 **499 passed / 0 failed**——2026-10-14 C6 后 435/0，2026-10-15 P2-1 +41 与 P2-2 +23 后 499/0）

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
