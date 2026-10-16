# IoTGuard Stage 9B M4.6：统一四智能体业务化与主动调查

日期：2026-10-16—17（Asia/Shanghai）。唯一仓库：`E:\IoTGuard-Public`。

本轮交付真实业务 shadow、受授权的主动补证与四角色再研判，以及正式入口迁移准备。**正式业务仍为 System B；`LINUXGUARD_UNIFIED_PIPELINE=off`；设备修复与 Ubuntu 隔离修复开关均为 `0`；没有软件包修复或正式迁移。**

## 1. 基线与可追溯范围

开发前工作区干净；成功 fetch 后 HEAD/origin/main 均为 `10be6f082ebf9779265bf8c6dbca7504173b95cd`。核对 M4.5 交付报告、五份协作文档及本地验收日志：基线 **711 passed / 0 failed**，Mimosa 未完成。没有以历史扫描封印替代本轮扫描。

本轮沿用唯一 LangGraph 与四个既有 Agent，没有新增 Agent、替换编排框架、删除旧编排器或扩展包执行能力。真实数据来自现有 Ubuntu 资产 1、OpenWrt 资产 2、风险 126、历史风险 12、已入库官方原文及运行时证据。本轮官方结论使用已保留的原文快照，未把模型文本当作新公告。

本地 `reports/m46-work/` 保存全部原始模型输出、System B 两次对照、采集原文关联、节点日志、前后快照、Trace 校验和测试结果；业务库、地址、主机标识、令牌、私钥、截图及原文不推送。失败、首轮偏差和未授权申请均保留，不删掉不利结果。

## 2. 三类真实对象

| 对象 | 输入与官方依据 | 统一四智能体的真实结果 |
| --- | --- | --- |
| Ubuntu curl / 风险 126 | noble；curl 及同源 libcurl 实装 `8.5.0-2ubuntu10.15`；Canonical CVE-2026-94266 / USN-8932-1 的 noble/curl 修复目标 `.16` | `potentially_affected / maintain / scheduled_fix`；正式人工门禁未通过；新采集仍为 `.15`，没有证据证明已修复或已被利用 |
| OpenSSL / 历史风险 12 | 已失活历史对象；实装 `3.0.13-0ubuntu3.16`；Canonical 对 noble/openssl 标注 `not-affected` | `not_affected / downgrade_major / monitor`；历史跨分支 Critical 基线与官方记录的冲突保留待人工复核，不重新激活风险、不执行旧升级建议 |
| OpenWrt / 资产 2 | 完整真实清单 182 包、现有官方公告匹配范围零命中、已有只读 logread/遥测覆盖信息 | 不虚构 CVE finding；零命中只适用于现有匹配范围，不宣称全局安全；运行时和公告覆盖缺口单独呈现 |

curl 官方来源：[Canonical CVE JSON](https://ubuntu.com/security/cves/CVE-2026-94266.json)、[USN-8932-1](https://ubuntu.com/security/notices/USN-8932-1)。OpenSSL 纠正来源：[Canonical CVE-2026-63073 JSON](https://ubuntu.com/security/cves/CVE-2026-63073.json)。引用的是库中保留原文，不声称本轮刷新了所有外部情报。

curl 复验运行：`m46-real-0ac56292c4d1` / `TR-20261016160102-a5c039`；OpenSSL：`m46-real-511217aaabfa`；OpenWrt 最终运行：`m46-real-7aa54b65f790` / `TR-20261016160625-3d9755`。三类对象均显式执行完整四角色，不因 simple 分层跳过模型。OpenWrt 最终运行实际消费 16 个历史 SE 引用，标注 stale_verified；聚合分 10 仅来自暴露面，CVE findings_counted=0，不代表新发现漏洞。

### 四角色的实际贡献

| Agent | 本轮业务贡献 | 保留的边界 |
| --- | --- | --- |
| asset_investigator | 消费实际资产身份、清单来源、安装包、服务与质量信息；提出当前实装版本需新清单核实的具体缺口；复核新增 INV | 画像分页/截断与原始清单完整性分开，不能将未展示的包当作不存在 |
| vulnerability_analyst | 对 curl 使用 noble/curl 精确官方版本与当前清单；对历史 OpenSSL 排除上游跨分支误判；OpenWrt 无候选时保留零 finding | 缺少某情报源不等于低风险；USN 修复目标不等于本机仓库已经可提供安装包 |
| runtime_analyst | 实际查询进程、网络、文件、进程树、心跳与覆盖质量；区分监控栈自身行为和 CVE 特异证据 | Ubuntu 心跳/进程/网络证据仍旧；未观察到利用不能证明没有利用；inventory 不补齐运行时 |
| decision_planner | 综合前三角色、官方证据、确定性门禁与补查结果；提出明确调查申请；生成待审批计划；新证据后说明保持/改变判断的理由 | 不直接写分、不授予修复权限、不生成可执行 SSH；相同事实不能通过模型重跑增加置信度 |

首轮真实运行暴露并修复了：LinuxAsset 网络暴露工具漏回查；裸 CVE 漏掉发行版/源包后缀的匹配；历史匹配版本被当作当前版本；画像截断与原始清单不完整混淆；决策嵌套证据未完整进入 Trace。修复后的工具保留发行版限定、当前/历史版本、真实完整性标志及监听事实的覆盖边界。OpenWrt 分析师同时获得已调查组件版本和原文来源，避免把零候选误述为没有清单。

## 3. 真实主动补证闭环

真实首条链路：

`m46-real-482fde0e7bdb` → Agent 申请 `IR-a57ce5d5436d5f8fc55c2f1c062d7383` → 确定性能力检查 → 控制令牌与申请哈希授权 → `collection_tasks` 任务 `669e3d59963bdded5f49a3d0506ffd63` → 已认证 Linux pull 节点 → `INV-669e3d59963bdded5f49a3d0506ffd63` → 四角色再研判 `UA-a300a7f502c746df9ef3d526`。

采集 Trace：`TR-20261016155613-0b5f7e`；再研判 Trace：`TR-20261016155624-c90fa1`。四角色均真实成功；没有用旧模型结论冒充重跑。首链和修正后的复验链均保留。

具体问题：确认本次调查时点的 curl/libcurl 安装版本、发行版身份和完整清单，核对修复候选是否可获得。固定 Collector 返回新的 1790 包清单、Ubuntu 身份与本地 apt 缓存信息；版本仍为 `.15`。它解决了“本次采集时点的实装版本”问题，**没有解决运行时覆盖、利用路径及刷新官方包索引后 `.16` 是否可获得的问题**。申请中超出能力的问题保留为缺口，未执行 apt update。

首链实质事实比较为 `false`；影子结论保持 `potentially_affected / scheduled_fix`，置信度 `.64 → .64`。新 INV/接收时间本身不计实质更新。各角色原始前后报告完整入库，区别“输出措辞变化”与“判断字段变化”；不能把文字变化描述成新证据导致的判断提升。

修正后完整复验链：`m46-real-0ac56292c4d1` → `IR-08f2f2ca43e507358215f8ebf7aa2121` → `35036f20a2ffe98440f99c718301de4b` → `INV-35036f20a2ffe98440f99c718301de4b` → `UA-e8b946663c534e46a6c8a9ef`。采集 Trace `TR-20261016160820-182f4e`；再研判 Trace `TR-20261016160831-59b845`。四角色全部成功；新原文仍1790包、curl仍.15，substantive_update=false，结论仍 `potentially_affected / maintain / scheduled_fix`，裁定置信 `.60 → .60`，adjustment=0，门禁 pending_human_review。

复验前后：资产顶层置信 `.72→.65`、漏洞 `.55→.55`、运行时 `.55→.50`、决策顶层 `.50→.50`。资产/漏洞/决策的关键判断保持；运行时逐 finding 的组织与描述发生模型差异，但总等级 NORMAL、状态 stale_verified、monitoring_missing 均保持，未出现新运行时证据，不将该差异归功于补采。它属于保留给人工复核的模型方差。新增证据对本次时点版本作了重新确认，没有让任何 Agent 获得无依据的升级或更高置信。

实现记录以下内容：

- 申请的来源运行、角色、具体问题、expected_effect、能力范围、申请摘要和采集前事实快照。
- 操作员身份/授权依据、绑定连接、固定 Collector 计划摘要、执行节点、原文摘要、INV 和采集 Trace。
- 新证据解决的清单事实、未解决的问题、是否出现版本/身份/官方内容/运行时事实实质更新。
- 父/子运行、各角色完整前后输出、判断字段差异、最终处置及保持/变化理由。

授权依据来自用户本轮明确的只读真实链路验收指令，由验收客户端持控制令牌提交精确申请哈希，审计 actor 为 `codex:m46-user-readonly-request`；这不冒充业务人工复核已经完成。模型工具不能调用授权接口。每源运行最多两个固定采集申请；重试幂等，重复 resume 用数据库原子领取避免并发重跑。中断留痕，不能静默重放。

同事实置信约束同时作用于数据库补查后的专家/决策报告，以及外部新采集后的四角色最终报告；先限制置信再计算门禁，避免门禁和展示结论不一致。旧快照缺少后来新增的指纹字段时，不把 Schema 扩展当作证据更新。

## 4. System B 与统一系统真实对照

System B 保持正式入口。本轮使用原 `build_evidence_packet → _process_event` 对同一实际风险进行只读对照推理，**不调用正式结果落库器**；历史失活风险 12 不被重新激活。正式存量快照与本轮对照推理分开保存。

| 对象 | System B 本轮对照 | 统一链 | 复核要求 |
| --- | --- | --- | --- |
| 风险 126 | 复验 `confirmed_affected / upgrade_minor / scheduled_fix`，confidence=.70；门禁仍 pending_human_review | `potentially_affected / maintain / scheduled_fix`；门禁 pending_human_review | 不将旧链当真值。System B 在理由中把 upgrade_minor 解释成“包升级方向”，与“证据对风险基线的修正方向”口径混淆；须人工核对，不能据此升级正式风险 |
| 历史风险 12 | `not_affected / maintain / monitor`，confidence=.74；门禁 pending_human_review | `not_affected / downgrade_major / monitor`；门禁 pending_human_review | 适用性一致；方向反映历史错误基线的处理口径不同。以 Canonical noble/openssl not-affected 原文核对，旧 Critical 基线不恢复为有效结论 |
| OpenWrt | 事件管线 no_candidates，没有可供事件评审的正式 CVE 对象 | 完整四角色设备面调查，零 CVE finding，并保留证据不足 | 这是入口对象能力差异，不能把无候选算成旧模型正确率，也不能造一条风险凑对照 |

首轮 System B 风险 126 的协调角色结构失败、无最终裁定，已保留；复验结果与首轮分开保存，不隐藏随机失败。复验还修正了验收脚本对 Pydantic 原始对象的序列化，使对照引用可逐一映射到真实 EV 证据包。

重要分歧建立 `pending_human_review` 记录，保存两侧实际输出、官方 ADV/原文摘要和 Trace。**human_reviewer=null，尚未完成人工复核**；本报告不冒签人工批准或把模型互相同意当真值。

## 5. 正式入口迁移与回滚准备

| 业务契约 | 本轮核查与准备 |
| --- | --- |
| 风险详情 / RiskAssessment | 全部正式字段前后摘要相同；shadow 单独标识、列表可按风险关联；当前安装版本与历史匹配值同时保留 |
| 正式输出路径 | `/api/analysis` 是唯一正式切换点。off/shadow 仍调 System B；未来 on 才调统一兼容适配器；`/api/unified/analyze` 在 on 拒绝成为第二正式入口 |
| 写入互斥 | System B 正式入口/落库器/遗留兼容写入器在 on 拒绝；统一 formal_sink 要求 on 且 row/state 均为 formal；shadow 禁止 sink |
| 人工复核 | 沿用正式风险的人审契约；影子 pending_human_review 是独立建议，不能替代正式人工复核 |
| 证据与 Trace | 真实 INV/ADV/SE 可解析；增加嵌套决策引用入 Trace；父子调查、授权、采集和复议可关联 |
| 待审批计划 / Harness | 保留原计划契约与 requires_approval；shadow 候选仅提供依据，不能授予原风险资格、精确计划审批或设备执行权限 |

新增只读迁移快照/回滚差异计划工具 `unified/migration.py`。真实快照含 **126 条 RiskAssessment 全字段**，本地快照哈希 `0f0e4ad154dcd30476ddd1a17d2b18bf09e1cfeb7e8fc3e966e7326af3a80bf9`；当前回滚差异 0。Schema 或摘要变化会拒绝规划。隔离测试验证字段漂移会被列出、快照篡改被拒绝，规划不写库，审计/影子记录保持。

正式迁移须另行批准后执行：暂停接收正式任务，排空/停止旧 worker；保存一致性数据库备份、正式字段快照、审批与在途任务清单；只启动一种模式的正式 worker；用实际业务契约核对后再恢复入口。**禁止混跑 off/on 进程操作同一正式库**，进程内开关检查不能代替部署排空。

迁移不把已有 shadow 结论批量复制成正式结论，也不自动继承影子审批。回滚须停止统一正式 worker、审核字段差异并另行批准恢复正式快照；保留新旧模型输出、AgentAudit、Trace、调查及执行审计，然后以 off 恢复 System B。**仅切 flag 不会还原已经写入的结论。** 本轮只生成计划和隔离验证，未实际切 on、迁移或恢复正式数据。

## 6. Harness 安全边界

- 复用 M4.4 `collection_tasks`、HarnessRun/资产锁、固定脚本摘要、已认证 Linux pull 节点和原文入库；未建第二套采集或 SSH 执行框架。
- Agent 只能提出 inventory 需求。程序映射固定能力；运行时采集、索引刷新、shell、扩白名单、读私钥和软件包修复均不在授权范围。
- authorize 受控制令牌保护，验证申请哈希、资产与已登记连接、白名单、Collector 和节点前置条件；resume 要求授权记录、已完成采集、同资产、同任务原文、SHA256 正确且未被后续清单替代。
- 真实缺控制令牌 401、错误申请哈希 409。正式修复候选 `f34fa6425562411cafc93787460c2eb0` 为 awaiting_preflight；错误修复审批哈希及未审批执行均 409，没有成功修复审批或 side_effect 调用。
- `.15` 仍低于 USN `.16`；没有宣称 fixed。运行时心跳未恢复，未执行 Falco 重启、`.netrc` 读取、包安装/下载/索引更新、设备配置修改、快照恢复或包降级。

## 7. 回归、安全与未关闭事项

最终全量回归 **729 passed / 0 failed（842.87秒，5个既有utcnow弃用警告）**，即711基线加18项必要安全/调查回归。相关专项72/0、新增专项终态18/0、前端全套21/0及最终构建通过；中间回归因真实链路发现并修正业务问题而被替代，不计作最终通过。闭环和引用终态见验收补录。

Mimosa 本机命令仍不可用；可调用工具目录无 Mimosa；plugin-management 查询 `Mimosa` 返回 plugins=[]。**本轮没有完成 Mimosa 扫描，安全验收仍未关闭**。不复用 M4.4 封印，不把 Bandit 当成 Mimosa 或完整威胁模型/依赖扫描。

补充 Bandit 在相关代码中报告 1 项既有中危 B104：`event_review_pipeline.py` 检查 `listen_address in {"0.0.0.0", "::"}` 的数据比较，并非新建全接口监听；完整低危及中危结果在本地保留。没有凭此宣称全仓零风险。

敏感检查覆盖当前329个受跟踪/非忽略文件，与3项本地已知凭据及常见私钥/访问令牌材料模式比对。发现2处**既有演示代码与当前本地控制令牌的字符串匹配**（stage8演示脚本及MQTT演示默认参数），M4.6新增/修改内容没有新增凭据材料。本轮没有输出该令牌，也不把现有默认值复用说成“完全无敏感发现”；正式迁移前应由操作员轮换控制令牌并清理演示默认值复用。本扫描不覆盖Git历史、未知凭据格式或所有泄露方式。

最终暂存26个交付文件再检查，已知凭据/私钥材料匹配0；2处既有演示匹配均不在本轮暂存文件。Git直连收尾曾重置/超时；使用现有本机代理成功重新fetch，origin/main仍为10be6f0，没有改动远端URL或持久Git网络配置。

尚未关闭：Mimosa；新旧方向口径与模型失败的人工复核；Ubuntu 运行时过期心跳、缺少当前 curl 特异利用路径；OpenWrt 公告/运行时覆盖范围限制；修复目标 `.16` 的刷新索引后可用性；隔离副本真实修复/回滚实验；正式迁移审批及生产部署排空。上述事项不能由模型置信度或影子计划替代。

## 8. 交付定位与停止条件

主要实现：`backend/app/services/unified/investigation.py`、`migration.py`、现有 graph/runner/adapter、统一 API、AgentOps、三份 M4.6 真实验收脚本及必要安全回归。五份 `ai_collaboration` 文档同步更新。

本报告、功能代码与协作文档所属最终交付 Commit 可用 `git log -1 --format=%H -- IOTGUARD_UNIFIED_AGENT_PRODUCTION_READINESS.md` 精确定位，最终回复同时提供实际提交哈希。仅提交并推送 IoTGuard-Public；原始证据保持 gitignored。

**本轮交付后停止，等待正式迁移审批。flag 保持 off，两个设备写开关保持关闭，旧编排器保留。**

## 9. 交付验收补录

| 最终真实运行 | 四角色状态 | 引用校验 |
| --- | --- | --- |
| curl `m46-real-0ac56292c4d1` | 4/4 succeeded | 11个实际引用全部解析 |
| OpenSSL `m46-real-511217aaabfa` | 4/4 succeeded | 10个实际引用全部解析 |
| OpenWrt `m46-real-7aa54b65f790` | 4/4 succeeded | 17个实际引用全部解析 |
| 再研判 `UA-e8b946663c534e46a6c8a9ef` | 4/4 succeeded | 14个实际引用全部解析 |

共52个引用（按运行计数），INV/ADV原文SHA256复算一致，SE均真实存在；SystemB两个真实EV包各11个模型引用均在相应实际证据包中。对早于嵌套Trace修正的M4.6运行，仅追加明确标记的确定性引用校验事件，没有改写原模型输出；正式分歧复核事件为pending_human_review，human_review_completed=false。

全量 `python -m pytest -q` 最终 **729 passed / 0 failed（842.87秒）**；新增必要调查/权限/回滚专项 **18 passed / 0 failed（24.11秒）**；前端全套 **21 passed / 0 failed**；最终前端构建通过。M4.6临时后端和Linux runner已停止，既有正式会话未动；没有宣称已部署持久生产服务。

最终边界：正式126条风险与M4.5全字段快照一致；原有19条统一运行不变；迁移快照逐字段差异0；新修复候选side_effect调用0；全局off、两个修复写开关0。Mimosa及本报告列出的人工复核/覆盖/令牌轮换事项仍未关闭，不能宣布正式迁移获批或完整安全验收通过。
