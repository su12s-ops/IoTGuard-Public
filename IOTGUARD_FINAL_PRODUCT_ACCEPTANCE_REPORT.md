# IoTGuard 最终产品验收报告

2026-10-18；唯一项目 `E:\IoTGuard-Public`。本报告优先于历史 Stage10 状态段。用户在本轮明确委托代理自行完成判断；涉及最终裁定的记录均标明代理身份，不冒充用户本人亲签。生产两个设备修复写开关始终为0。

| 验收领域 | 最终实际结果 |
|---|---|
| 唯一四智能体 | 正式 ON；asset_investigator → vulnerability_analyst ∥ runtime_analyst → decision_planner；未新增Agent或恢复旧系统 |
| 真实漏洞修复 | 独立克隆资产3三包 `.15→.16`；成功执行与认证复采可追溯；源资产1仍 `.15`，风险126未修复 |
| 修复后四智能体复评 | `UA-7eb1c1d131d5-127`；结果见下方正式运行回执 |
| 业务接受 | 代理受委托裁定，限版本与实际冒烟；不宣称所有业务回归或克隆运行时覆盖通过 |
| Falco | 真实systemd服务running、新心跳/事件/入库/工具读取已验证；内核丢失计数unavailable |
| OpenWrt | 既有logread Collector / Pull Runner / Harness 定期只读采集；实际周期回执见下方 |
| Docker | nginx生产入口 `http://127.0.0.1:18080`，API18000；独立数据库、非root、回环绑定；版本标签对应最终提交 |
| 安全扫描 | npm/pip已知漏洞0；Bandit高0/中28/低81；Mimosa仍inconclusive/partial，不宣称全覆盖安全通过 |
| 回滚 | 方案与只读准备完成，保留已修复克隆；历史基准恢复已验证，修复后实际恢复未执行 |

## 1. 基线、授权与真实修复链

起点 main/origin 为 `9f392cd92f76323e23f9e00c3a15ef200e24fdce`，核对其前序 `da336783904010a3a7f0436c612de86390bd557e`。没有扩大设备修复范围。

克隆资产3/连接3/`iotguard-stage10-clone`。machine-id去除结尾换行后的SHA256为 `0691eeb5df31a579f71cfd893abf592149ba891f86b2ab50b71739b07100e574`；原文件包含换行时的sha256sum是 `0e76c274fd5cba8f1b5a879eedade208fefc6411a98ee69ac11a337482a31a9b`，两者口径不同，不是身份变更。

成功修复 Harness `ddc385a143ed4a50bb6ef109041155fc`，Trace `TR-20261018112611-7758c7`，精确计划及审批hash `3684566174c9e815324f8191116f0b4cb1c947b7413dfe5b8e017752f293bf56`，actor `codex:operator-authorized-current-chat-20261018`。原始用户后续“可以的”上下文是克隆三个curl同源包的明确升级许可；精确哈希由代理执行审批，非用户亲签。执行时clone-only许可有效，rc0后许可撤销，生产与实验写开关均0。失败的首次NAT下载计划仍保留，未被覆盖。

实际升级：`curl`、`libcurl3t64-gnutls:amd64`、`libcurl4t64:amd64`，均 `8.5.0-2ubuntu10.15 → 8.5.0-2ubuntu10.16`。修复后原始实验INV `INV-f82d1efa67e74f1e8f4b5a6e59d24c50`，SHA256 `d3d89baca1d51f640ea8fb039ea36bee3a412cf961f2d4e130ef0b7a676e5f5f`。旧克隆INV `INV-3bef62a8eb2a912606f16643299b54e9`、生产复采INV `INV-ce6ef85e4765550a80ac39052f9bb576` 与本轮新INV分别保留。

官方依据为 [Canonical CVE JSON](https://ubuntu.com/security/cves/CVE-2026-94266.json)，原文SHA256 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`；精确tuple为 **CVE-2026-94266 / noble / curl / USN-8932-1 / 8.5.0-2ubuntu10.16**。状态表needed与公告released原文同时保留，不混入resolute的USN-8927-1。

## 2. 一次正式修复后完整复评

从正式控制令牌保护入口发起 `POST /api/analysis/runs?risk_id=127&post_repair=true`。新增入口只允许已有resolved、inactive、原始清单摘要完整且无官方不适用纠正的修复对象；记录原始风险快照和当前INV，写独立复评事件，不重激活旧风险或修改旧审批。

批次 `7eb1c1d131d5`，统一运行 `UA-7eb1c1d131d5-127`，Trace `TR-20261018121350-4878af`，2026-10-18T12:13:50Z启动，正式模式。当前INV `INV-c5e5ae6965b7b7233701c481a9fa5d37` 来自1790包完整认证复采。

正式复评于12:42:16.877Z完成，耗时28分26.5秒；四角色全部succeeded、零降级、14次真实调用；prompt195529 / completion101873 / total297402 tokens。最终原始建议not_affected、monitor、low、fixed_pending_human_acceptance；策略保留pending_human_review，原因evidence_partial、adjustment -10，未给出最终score/level。一次有界补证与重规划均在同一运行内，没有重跑整套模型。

复核发现最终planner把公告误写为USN-8923-1，且asset工具未查到旧克隆历史而误推旧.15仅属源资产；原始模型输出保留，独立代理审计以官方原文USN-8932-1、旧克隆INV和真实执行回执纠正。模型提出的dpkg status备份不等于真实软件包/VM回滚，文件监视也不证明进程加载库；相关配置、重启、暴露面变更建议均未执行。

模型原始输出、工具结果与策略门禁全部保留。任何模型对旧清单归属、公告独立核验或运行时配置的推测，必须结合原始证据解释；模型建议不作为新的设备变更授权。克隆运行时三类证据缺失是实际覆盖缺口，源资产Falco在线不能填补克隆覆盖。

## 3. 委托裁定、Q1–Q8与业务接受

本轮 actor `codex:delegated-operator-20261018-final-closure`。当前用户直接授权代理判断，故不继续留下“等人工决定”的研发阻塞；但没有把代理操作记为用户实名人审，也没有因委托而绕过证据/写门禁。

| 事项 | 代理最终裁定与保留边界 |
|---|---|
| Q1 证据层次 | 静态适用、触发条件、运行时观察、实际利用分别解释；无事件不等于不受影响 |
| Q2 风险方向 | 风险相对基线变化与包升级方向分开；`.15→.16`是package upgrade，风险降低不叫包降级 |
| Q3 优先级 | 厂商精确发行版修复、实际暴露/触发证据优先；端口0.0.0.0不自动等于CVE公网入口 |
| Q4 补证 | 当前完整INV及来源摘要可追溯；克隆无运行时覆盖如实保留，不用源事件跨资产补齐 |
| Q5 历史风险12 | 官方精确不受影响；代理通过正式API确认归档，保持inactive |
| Q6 旧计划 | OpenSSL旧修复路径失效，不恢复旧审批或重建错误候选 |
| Q7 原始记录 | 纠正、原始匹配、原审批、失败执行、成功修复和本轮裁定均分别保留 |
| Q8 置信度 | 静态适用、运行时质量、官方覆盖、模型方差分维说明；同事实重跑不构成新证据 |
| 源风险126 | 代理裁定retain_open_unfixed；源三包仍 .15。新官方刷新使其reanalysis_required；不强行用旧模型结果重新签confirm，更不因克隆修复关闭源风险 |
| 克隆127 | 版本已修复；代理有限范围业务接受，只依据下列真实检查，不签署“所有业务通过” |

本轮克隆只读检查：三包installed/.16、dpkg --audit空输出、curl --version正常、官方Ubuntu archive HTTP200、既有实验API隧道HTTP200。Canonical HTTPS一次20秒超时（rc28）原样保留，不能宣称所有外网HTTPS可用。此前成功冒烟、瞬时空响应和本轮超时记录均在本地归档。无长期业务工作负载清单与克隆运行时覆盖，故接受范围只含版本/包数据库/curl及上述HTTP连通性。

## 4. 持续监控与恢复边界

Falco：既有 `linuxguard-falco.service` active/running、Restart=always，观察时NRestarts=14（历史累计，非本轮零重启声明）。实际RuntimeEvent源是`syscall`，sensor为`wyh-vmware-virtual-platform:falco`，归属资产1。事件18745发生于2026-10-18T12:34:36.621621769Z，入库12:34:38.902671；后续持续有新事件。Runtime Analyst的实际quality/process/network/file工具读取均可获得新证据；一次回执为received/parsed/uploaded=9559、rejected=0、retries=1、failed_batches=0、spool_pending=0。内核dropped_events为null/unavailable，非0。

OpenWrt复用既有固定只读logread脚本、连接1/资产2、Linux Pull Runner与collection_tasks；host fingerprint、连接签名、Collector hash及hostname/boot_id均验证。宿主启用60秒周期，空配置默认禁用；每周期最多2次尝试、共用资产锁、900秒超时只释放自己的日志任务锁，不重放设备写操作。源Runner已有SSH监督进程，断线5–60秒退避重连，令牌不轮换。

真实周期验收：`46a536c1df508effc5b96d8b1a87cb48`（12:52:23Z完成）新增1245/去重16，`21b74b662a19500a1bf5ef49b69977d4`（12:52:28Z完成）新增5/去重1254，`fbd8e82411a46e1e4524538af8db1af7`（12:53:12.809509Z完成）新增6/去重1253；每条任务都有对应`LOG-<run_id>`原文和SHA256回执。前两条分别来自此前排队窗口和当前窗口，后续按60秒窗口继续采集，非重复导入制造增长。

初次周期任务`f4c9e12fd6362045d9c3004288addcea`及后续失败记录保留。根因为资产名采用OpenWrt-MAC后缀，设备自报OpenWrt；修复为精确重建已有MAC/钉扎key后缀规则，保留boot_id/SSH指纹/连接签名，回归覆盖合法后缀与外部主机名拒绝。未变更设备配置。

logread是syslog降级采集，不是eBPF。原始LOG完整保留；重复窗口以实际时间/boot_id/指纹判重，重启后读原缓冲，不伪造游标或实时增长。日志环覆盖的历史丢失不可知；事件与raw可能先于Harness最终回执提交，崩溃重试依赖幂等，不能称跨表原子事务。宿主关机后后端及监督进程仍需重新启动，不宣称已安装Windows开机服务。

健康页分别展示backend_online、collection_node_online、sensor_healthy、runtime_evidence_fresh。全局fresh可以只由Falco满足，必须再看OpenWrt及克隆各自数据；HTTP200不能代表监控全绿。

## 5. 最终Docker与产品访问

前端nginx非root、监听8080，宿主仅回环18080；后端appuser UID10001、仅回环18000。均cap_drop ALL、no-new-privileges、无privileged。镜像含应用、迁移、固定Collector及非密模板，排除.env、私钥、数据库、日志、归档。前端构建采用Node24与npm ci；npm锁文件已更新修复依赖漏洞。

实际镜像/容器启动及非root运行已核验。9个关键写入口（正式复评、人审、归档、统一研判、Harness创建/审批/执行、采集创建/执行）逐一测试无令牌/错令牌共18次均401；正确令牌读取新INV、正式统一运行、治理记录和health共4次均200。真实nginx浏览器完整加载总览、AgentOps指定复评、运行时、风险列表及克隆风险详情共5页，全部HTTP200、无JavaScript异常、无失败请求；运行时等待5个API全部成功且表格出现后验收，未将页面外壳视为加载完成。

独立验证库一致性备份来自本轮完整正式复评及代理治理之后。复制到已有卷后发现属主为root，容器迁移报readonly；停止容器后只修正该数据库文件为10001:10001，恢复健康。没有让应用以root运行，也未修改宿主正式库权限。

验证库使用独立命名卷和SQLite一致性备份，未并发写宿主生产库；未注入设备私钥、真实模型key或生产节点token。验证容器不自动采集设备，历史心跳会过期。宿主8000继续接收真实设备上报；5173仅保留为开发入口，非最终产品入口。

## 6. 安全扫描与实际覆盖

Mimosa工具在本轮运行环境不可调用。可读取的最新task-review `sess_bfadd0eb-9754-40d7-80b6-cfae61c71a14` / 20261017T124257178Z：inconclusive、coverage partial、扫描10文件、model_calls0，9个基线文件本地缺失；两个medium候选来自同一离线克隆脚本的LF/CRLF版本，均line86。历史deep scan `scan-2026-10-17T09-08-58.996Z-4dc68ad6cebb` seal `53c54180ef65df31cf37704572b2bfe31f23998c9a8d37bd871c59795f3a8822`，threatModel识别0入口，伴随enobufs。

现有材料只能证实扫描入口枚举/环境执行不完整；底层enobufs日志不可用，不能确证其资源原因或宣称已修复。没有重命名危险代码、删检查或压制发现来制造零结果。离线脚本line86为带引号的固定MNT目录清理，MNT在文件开头固定为`/mnt/clone-root`，不来自HTTP/模型输入；仅在独立离线克隆实验、gitignored、不进入镜像。两条候选应保留为本地离线脚本审查记录，不能扩展成正式API可利用命令注入结论；本轮未重执行这些设备写脚本。

| 实际面 | 本轮独立验证 | Mimosa边界 |
|---|---|---|
| FastAPI/写API/人审 | 全量pytest、控制令牌失败先于副作用、Docker实际无令牌/错令牌拒绝 | 未获得重新完整入口扫描 |
| 节点认证/Linux Runner | 节点专属令牌域、主机指纹、签名/脚本摘要、实际采集回执 | 同上 |
| Harness/独立Ubuntu实验 | 计划哈希、作用域、有效许可、root前置、两端开关0、跨库边界 | 同上 |
| Docker/密钥注入 | 非root、cap_drop、回环端口、镜像文件检查、独立数据库 | 同上 |
| 前端/API | 24条E2E、实际nginx页面/API、依赖审计 | 同上 |

Bandit1.9.4扫描backend/app与backend/scripts，27435行、未跳过测试、nosec0；高0、中28、低81。修复了perf辅助shell=True（改参数数组shell=False），以及OpenWrt辅助脚本隐式AutoAddPolicy（改为无认证握手读取指纹，后续连接仍固定钉扎）。

中项逐类保留：B608两处SQL结构（内部固定predicate、校验标识符及参数化值）；B601四处SSH exec（固定脚本或CLI内经shlex转义）；B108九处远程/tmp路径；B104八处监听/观测常量（实际Docker仅回环）；B310五处CLI URL读取（与正式控制入口/目标范围分开）。这些是人工式代码复核后的残余提示，**不是Bandit零发现**，也不是Mimosa全覆盖替代。

`pip-audit -r backend/requirements.txt`解析依赖未发现已知漏洞；npm audit最终info/low/moderate/high/critical均0。ECharts从5升级至6.1修复GHSA-fgmj-fm8m-jvvx，Vue/axios更新至修复版本并重跑前端构建/E2E。审计反映执行时的公告库，不保证未来无漏洞。

## 7. 回归、交付与停止边界

后端全量716 passed / 0 failed（545.96秒，5个既有datetime.utcnow弃用警告）；前端24 passed / 0 failed（20.8秒），生产构建通过（1.24秒）。新增测试覆盖post-repair完整编排保留历史、归档/损坏清单拒绝、周期禁用、身份错误有界重试、跨会话去重、仅超时自身锁及控制令牌。

身份修复专项回归9/9；相关采集、OpenWrt及运行时回归85/85（101.62秒）。最终身份、请求内复用与事件查询修复后的专项回归52/52（47.75秒）；扩展运行时/CVE证据/数据质量回归39/39（44.46秒，5个既有弃用警告）。前述716全量是这些最后补丁之前的完整结果，不将新增测试计入该数字。CI前端Node版本同步24，与正式镜像一致。

风险详情新增独立的修复后复评与委托接受区，原始研判明确标为历史；inactive对象不再请求仅支持活跃风险的证据接口。AgentOps长文本与计划布局已适配。行为链只在同一请求、同一资产/包/场景内复用运行时计算，跨请求不缓存；实测127条链从8.385秒降至1.873秒。运行时事件总数改为数据库计数，筛选先于分页，避免重复反序列化完整历史及稀疏模式漏项；有专门回归覆盖。

最终脱敏代码和报告提交main并推送origin/main；最终镜像用交付HEAD重新构建，OCI revision/build date及health metadata可追溯。按DEPLOYMENT.md的`git rev-parse HEAD`与`docker image inspect`核对当前确切哈希，避免报告自引用其自身提交哈希。敏感值逐一比对、tracked私钥/数据库检查及镜像文件检查均保留本地审计回执。

关联：[部署](DEPLOYMENT.md)、[技术架构](TECHNICAL_ARCHITECTURE.md)、[演示操作](IOTGUARD_FINAL_DEMO_GUIDE.md)、[回滚准备](IOTGUARD_FINAL_ROLLBACK_PLAN.md)、[上一轮真实执行证明](IOTGUARD_STAGE10_COMPLETION_REPORT.md)。原始数据库、控制/节点令牌、私钥、原始日志和实验材料均gitignored。

任务到此收口，不自动发起新阶段、不扩大修复范围。保留的事实边界为：源资产未修复、克隆无完整运行时/业务覆盖、Mimosa partial、修复后真实快照回滚未执行，以及宿主开机自动恢复未安装。上述边界不再作为反复请求人工判断的事项，也不包装为已通过。
