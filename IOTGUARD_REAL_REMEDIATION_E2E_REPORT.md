# IoTGuard Stage 9B M4.5 真实修复与复检交付

日期：2026-10-16（Asia/Shanghai）。唯一项目：IoTGuard-Public。
开发前工作区干净；成功 fetch 后 HEAD / origin/main 均为 `cbce1293b93e02d23093263c6bedcc0d8fee0992`，已核验 M4.4 实现 `c7ca5a3` 与最终交付 `cbce129`。M4.4 参考基线 677 passed / 0 failed。

**设备软件包写操作 0；LINUXGUARD_UNIFIED_PIPELINE=off；设备修复与 Ubuntu 隔离修复双开关均为 0。**

## 实际完成

- Ubuntu 专属适配器接入现有 `agent_harness.py`，复用 HarnessRun、精确审批哈希、资产锁、16 次主调用预算、尝试上限、授权策略、Trace 和已认证 Linux pull 节点。未新增执行框架或智能体；OpenWrt 继续使用原登记产物与回退语义。
- 绑定资产 ID、发行版、主机名、节点 ID、连接摘要与 machine-id 摘要；当前 Ubuntu 适配只允许明确登记的节点本机 Ubuntu 24.04，其他发行版或远程 SSH 修复被拒绝。
- 由 Canonical 原始记录内同 CVE / noble / curl 源包的 USN 决定目标版本，映射实际安装的同源二进制包。CVE 状态表仍为 needed，USN 提供修复版，两种原始状态同时保留。
- 只读预演重新执行 dpkg-query、apt-cache policy/show、apt-get --simulate、dpkg --audit、apt-mark showhold 与磁盘检查；检查候选来源、版本、摘要和依赖变化。没有 apt update、下载或包写入。
- 预演结果进入计划并改变审批哈希；预演失败不能审批。通过预演也仍须独立计划审批、原风险授权、未过期的执行前证据及隔离副本专属许可。模型/影子计划不能授予设备权限。
- 已准备固定白名单执行路径：节点再次检查身份、版本、候选元数据、依赖预演和计划绑定；未来经双开关及独立许可批准后，由 apt 认证下载、核验精确 `.deb` 集合及 SHA256，再只向 dpkg 传入批准包的固定路径。新增依赖、移除、换源、摘要变化、降级、hold 或未完成事务均停止。**此路径仅在测试桩验证，未在设备执行。**
- 执行结果自动触发新 Collector、同源包复核、官方记录重新获取及原匹配器纯评估函数。执行中断只允许 verify，不重放写操作；失败证据保留。Ubuntu 回退以隔离 VM 快照为依据，拒绝调用 OpenWrt 降级命令；回退仍先经过原通用审批完整性检查。
- 复用风险详情、AgentOps、设备任务/Harness 页面展示官方依据、原四智能体研判、包目标、预演、审批、执行、前后版本、复检及回滚状态；未新建业务页面。

## 真实当前证据

只读复采：`0de447c11463b484871b2f8ce6504289`；原文 `INV-0de447c11463b484871b2f8ce6504289`；1790 个包，认证 Linux 节点本机采集。

| 源包 / 已安装二进制 | 新读取的安装版本 | 本机仓库索引候选 | USN 修复目标 |
| --- | --- | --- | --- |
| curl / curl | 8.5.0-2ubuntu10.15 | 8.5.0-2ubuntu10.15 | 8.5.0-2ubuntu10.16 |
| curl / libcurl4t64:amd64 | 8.5.0-2ubuntu10.15 | 8.5.0-2ubuntu10.15 | 8.5.0-2ubuntu10.16 |
| curl / libcurl3t64-gnutls:amd64 | 8.5.0-2ubuntu10.15 | 8.5.0-2ubuntu10.15 | 8.5.0-2ubuntu10.16 |

官方依据：[Canonical CVE 原文](https://ubuntu.com/security/cves/CVE-2026-94266.json)、[USN-8932-1](https://ubuntu.com/security/notices/USN-8932-1)。本轮重新获取的 `ADV-c73bcf3856244a5abc668abe17c6e95e`，原文摘要 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`。

真实候选计划 `4ef1f86fcdfc45eb9dcec9b584b3c6b5` / Trace `TR-20261016152210-0e5f95`；预演证据 `PRE-8f1b5602022b4afe901cba4bfafa9236`；计划 SHA256 `7d93061f0fe909126d7a2924587f38f412fe1d9c115b5bb282b8a93cff04fc48`。

**实际结果是 preflight_failed。** 本地索引没有 `.16` 的可用包/摘要，apt 模拟明确返回目标版本未找到；changes=[]、removals=[]。dpkg audit 为空、目标包无 hold。未刷新索引，因此不能把“本机索引不可用”说成“官方仓库全局不存在修复包”；仓库策略也不等于已独立验证包签名。

错误审批哈希 409、预演失败时正确哈希审批 409、未授权执行 409、缺控制令牌的 dry-run 401。真实计划没有任何成功审批或 side_effect 工具调用。

风险 126 关联 M4.4 四智能体 `m44-real-841d76e9aa`，沿用原始输出及证据，本轮没有重跑或伪造模型结论。全部正式风险字段与全部历史统一研判记录的前后摘要一致；原始风险 126 仍为 active / reanalysis_required，human_review_required=false，recommended_action 为空；影子计划的 pending_human_review 不冒充正式风险授权，不标 fixed。

本地原始证据、真实库、节点日志及截图仅保存在 gitignored `reports/m45-work/` 与既有数据目录，不推送。后端与节点仍是本地开发会话进程，未部署为持久 systemd 服务。早期多次 dry-run 均保留，最终任务为上述任务；官方证据时间戳的 naive/aware 兼容问题已修正并复跑真实链路。

## 修复后闭环与失败口径

修复前原始 INV/版本 → 带 USN、节点与包范围的计划 → 独立审批哈希 → 执行前复核及隔离许可 → 实际执行状态 → 新原始采集 → 新官方依据 → 同一匹配器评估 → 风险更新建议及 Trace 前后对照。Trace 可解析 PRE 预演原文及 ADV 公告引用；实机核对原文 SHA256。

| 观察 | 结果 |
| --- | --- |
| 官方修复候选缺失、依赖预演失败 | preflight_failed；审批关闭，保持风险 |
| 命令成功但没有有效新采集 | verification_required；不建议 fixed |
| 版本完全未变 | version_unchanged；保持风险 |
| 部分同源包仍旧版 | partial_update；保持风险 |
| 软件包命令非零 | package_operation_failed；保留实际退出与证据，复检仍不得仅凭退出推断修复 |
| 节点超时、执行中断或结果未知 | verification_required / interrupted；不重试写入，仅独立复采复检 |
| 新官方记录不可达、身份或源包映射不符 | 明确失败原因，保持风险 |
| 所有实际新采集版本满足新官方依据 | fixed_version_verified；仅建议 fixed_pending_human_acceptance，原风险、旧匹配及旧研判不修改 |

业务验证仍须隔离实验验收；软件包版本复核不冒充业务稳定性或利用路径验证。Falco 健康恢复、日志备份与快照回滚分别处理，本轮没有将重启 Falco 作为 curl 修复，也没有执行这些辅助写操作。

## 隔离实验方案（仅准备，尚未执行）

1. 用户另行批准后，克隆 Ubuntu VM 或从快照创建隔离副本；原资产 1 不作为实验写目标。为副本登记新资产 ID、唯一主机名、确认 machine-id 摘要、隔离网段、独立节点身份及令牌，重新建立风险和连接绑定。
2. 在虚拟化平台创建基准快照，保存快照 ID、磁盘/内存范围；先实际恢复并启动副本，复核主机身份、`.15` 包版本、基础业务和隔离网络，保存恢复记录。尚未验证恢复时，restore_verified 不得设 true。
3. 仅在获批副本中检查/刷新官方 apt 索引，使用适配器固定源白名单（archive.ubuntu.com、security.ubuntu.com、ports.ubuntu.com）；获取 noble 官方签名索引与目标包来源/摘要。无法提供精确 USN 目标则停止，不换第三方源或上游包凑版本。
4. 运行正常采集和 dry-run，审核实际安装的全部 curl 同源包、旧版、新版、依赖图、磁盘/hold/dpkg 状态及影响范围。预期只维护批准的同源包；curl CLI、依赖 libcurl 的程序可能受影响，需预留停机窗口与业务回归。
5. 人工确认克隆风险授权，再独立审批当前精确计划。操作员在后端与节点分别登记私有许可文件，包含 asset_id、machine_id_sha256、plan_hash、snapshot_id、isolated_clone=true、restore_verified=true、approved_by、expires_at；保留对应外部恢复证明。
6. **仍须用户单独批准实际修复**，才可在该副本的后端/执行节点打开两个写开关。许可不能用于原 VM、其他资产或其他计划，不能由模型生成授权。
7. 执行前再次检查；候选或包/目标/计划变化、缺签名包、任何额外依赖/移除、授权失效、空间不足、事务/hold 异常均停止。执行失败或断连后不重放命令，先 verify。
8. 自动收集新版本及原文，重新获取官方公告并匹配；检查全部同源包和副本业务。版本未变/部分更新/缺证据一律保持风险；满足版本依据也仅产出待人工接受建议。
9. 回滚必须另行批准，通过虚拟化平台恢复已验证快照，再重新采集、匹配和检查业务。恢复旧版本会恢复漏洞风险；不自动 apt 降级，不把日志备份当可恢复证明。
10. 实验结束关闭双开关、撤销许可，保存前后证据与审批记录。当前没有创建克隆、快照、许可或设备修复授权。

## 验证与交付结论

| 验收 | 最终实际结果 |
| --- | --- |
| 全量 `python -m pytest -q` | **711 passed / 0 failed**；679.88 秒；5 个既有 utcnow 弃用警告（677 基线 + 34 新增） |
| Ubuntu / OpenWrt 必要专项 | 64 passed / 0 failed（34 + 30） |
| 扩大 Harness / Trace / M4.4 专项 | 101 passed / 0 failed |
| 前端 | build 通过；全套 Playwright **21 passed / 0 failed**；真实风险详情、AgentOps、Harness 浏览器核对 |
| 真实安全门禁 | 原文摘要可验证、Trace PRE/ADV 可解析；错误审批/未授权执行被拒；旧风险及研判不变 |

Mimosa：本轮没有可调用的工具或本机入口；插件目录查询 Mimosa 返回空结果，**未完成本轮 Mimosa 扫描**。M4.4 的封印只作为历史，不复用为本轮结论。

Bandit 1.9.4：新适配/维护/验收/节点四文件中高严重度结果 0；扩展检查 9 个相关 Python 文件，2574 行，保留 1 个既有中危 B108（OpenWrt 远端 `/tmp/linuxguard-<uuid>` 路径；原逻辑使用随机 UUID 和 umask 077，本轮未修改）。低危项及完整本地 JSON 保留。该检查不覆盖全仓、依赖链或完整威胁模型。

敏感检查：当前全部 322 个受跟踪/非忽略文件及 23 个暂存文件，与本地已知凭据值和私钥/GitHub/AWS/OpenAI 凭据材料模式比对，未发现匹配；不覆盖 Git 历史、未知凭据格式或所有泄露方式。原始数据/凭据没有加入暂存。

功能与只读实机验收已按实际结果交付：支持候选计划、安全门禁及自动复检接口；真实预演因 `.16` 不在本机索引而失败，正确停止。**Mimosa 仍是未完成的安全验收项，不能宣称全部验收通过或“0 findings 证明全局安全”。** 本轮未执行当前 VM 或隔离副本的 apt update/download/install/upgrade、dpkg 写操作、Falco 重启、日志备份或快照恢复。

仅向 IoTGuard-Public 提交并推送；完成本次交付后停止，等待正式隔离修复实验的单独授权。
