# IoTGuard M5 最终统一四智能体生产报告（完成稿）

日期：2026-10-17（Asia/Shanghai）。仓库：IoTGuard-Public。封印实现提交：`788a826`（前置草稿 `129dd21` 于交付回归后修订并入），基线 `969a4fa`。

**本报告完成 M5 机器可执行验收：唯一统一四智能体生产实测全链通过。** 人工裁定（Q1–Q8、风险126 对象级、风险12 归档确认）仍然开放，模型未代签；在人工裁定关闭前不宣称任何风险结论定案。

## 已完成的迁移

迁移契约 `m5-native-review-v2` 见 `IOTGUARD_M5_MIGRATION_CONTRACT_V2.md`。M4.7 原契约、空白人工签署栏和历史运行保留。Q1–Q8 从两系统对照转为统一系统原生能力。用户批准切换和退役不代表签署具体风险结论，也不代表设备修复授权。

产品 LLM 编排只保留 LangGraph 的 asset_investigator → vulnerability_analyst ∥ runtime_analyst → decision_planner。正式入口 `/api/analysis`，写入器 `unified.adapter.formal_sink`，非on拒绝正式请求，没有旧系统自动fallback。历史建议稿另行追加治理事件，不改历史风险、不等于操作员归档确认。

System A/B 编排、旧路由和依赖脚本已退役；公共工具、协议客户端、确定性规则、Trace、数据库表与原始审计保留。MQTT使用确定性白名单计划，Harness拒绝内嵌LLM，演示接统一适配层，前端AgentOps沿用统一运行记录。

## Linux 采集节点恢复（完成，实测通过）

**根因**：原 m45-linux-node Pull Runner 在 Ubuntu 侧并未停止（隔离诊断 `reports/m5-final/node-diagnostics.json`：SSH rc=0，远端 runner 进程在位）。预检失败根因是 M4.5 临时环境中的节点身份、独立认证及授权范围未持久化——后端重启与控制令牌轮换后，正式后端未加载 `LINUXGUARD_COLLECTION_NODE_*` 配置（预检呈现 node=backend-local/Windows、remote_node_configured 空）。

**恢复过程**：按 M4.4/M4.5 成功采集回执（`reports/m44-work/collection-results.json`、`reports/m45-work/fresh-collection.json`）与数据库计划摘要逐一核对两条登记连接（connection 1=OpenWrt/asset 2、connection 2=Ubuntu/asset 1，回执哈希与连接签名全部匹配）后，用 `backend/scripts/restore_collection_node.py` 恢复节点配置（令牌单一来源 `backend/.env`）并复用既有 Pull Runner 与反向隧道；随后重启正式后端（PID 46128）加载配置。

**实测结果**：
- 两条登记连接预检 `ready=true`（`node_platform=false` 为 Windows 本机预期项，由登记的远程 Linux 节点承接执行；其余检查全部通过）。
- 节点认证一致：轮换后令牌下 claim 轮询持续 HTTP 200；控制令牌核验维持当前值200/历史旧值401/错误值401。
- 恢复后真实只读补采双通道成功：Ubuntu 1790 包（run `ae45e3e8944567a19d3502f1c3ca3919`，`INV-ae45e3e8944567a19d3502f1c3ca3919`，execution_node=m45-linux-node，node_identity=authenticated，output_sha256 `e57e04bd…caac`）与 OpenWrt 182 包（run `7631d63227b003339d316e92dfaa29f8`，`INV-7631d63227b003339d316e92dfaa29f8`）均 completed。

边界：未新建采集体系，未扩大已批准范围，未读取设备敏感文件，两个修复写开关始终 0。

## M5 四智能体核心功能实测（完成）

**正式风险126 再研判** `UA-5daea17fd7e14273ab3d814e`（Trace `TR-20261017031335-1de33f`，formal）：completed @12:02:19，10 阶段全部 succeeded，29 次 LLM 调用 / 441,460 tokens（上限40，未超预算），综合置信 0.7。
- 消费恢复采集证据 `INV-ae45e3e8944567a19d3502f1c3ca3919`（认证节点、inventory_complete=true、1790 包），直证 curl/libcurl4t64/libcurl3t64-gnutls 三包精确版本 8.5.0-2ubuntu10.15 与 apt 源分支，静态适用性由 potential 升级为 confirmed_affected；无紧迫度放大因子（kev=false、CVE 公网入口未绑定、无新鲜利用证据），方向 upgrade_minor（基线 18.54/Low）。
- 与首个 formal 运行 `UA-fe6e8559fb28-126`（completed @11:08:15，0 降级，置信 0.7，同结论 confirmed_affected/upgrade_minor）相互印证。
- 处置规划仅建议 update_package → 8.5.0-2ubuntu10.16，前置条件"主机侧可得性直证"未满足（当前候选 10.15 为未刷新索引快照）；未执行、无 side_effect。风险126 库内状态 `pending_human_review`，模型未代签。

**如实记录的降级与冲突**：vulnerability_analyst 在126轮中触发"工具调用轮次超过上限 8"降级（attempts=2，透明记录，无静默重试编造）；决策按维度分离采纳其静态结论（锚定厂商精确公告 `ADV-e97cb19bd2594e9b8ca9b37de38fe6a6` + 认证完整清单 + 确定性版本比较），冲突 `evidence_quality_vs_impact_confidence` 经 1 次定向再研判后保留 unresolved=true，留人工裁定。

**补证纪律**：本轮新提申请 `IR-a0c04a79a7633d8ac92045a209548fcd` 状态 awaiting_authorization、resolved=false，未计入证据、未提高置信度；全部未授权调查申请保持 awaiting_authorization，无越权。

**历史风险12 归档建议稿** `UA-20261017031216-2888ac`（Trace `TR-20261017031216-e7058e`，historical）：completed @11:46:23，10 阶段全部 succeeded、0 降级。裁定性质为归档建议稿：历史 Critical / 80.47 基线保留为"待纠正基线"——保留原记录、不删除、不重新激活、不代替操作员确认、不授予修复资格（noble 无本 CVE 专属修复版本、apt 无 3.4.7 候选、厂商精确判定 not-affected）；采集器健康恢复 restart_service（falco）明确标注非 CVE 修复动作。冲突 `baseline_high_vs_all_findings_resolved` 保留 unresolved，界面和报告已标为历史错误基线，另行展示当前官方"不受影响"及实际归档裁定状态。风险12 库内维持 inactive。

**隔离版本恢复验证**：基线 `969a4fa` 隔离副本启动健康 200，126 行风险快照哈希一致（`970042db…b99dc`），LLM 密钥禁用、无网络监听（`reports/m5-final/isolated-code-recovery.txt`）。

## 最终核验数据

- 最终一致性备份：`local-archive/m5-final-switch/20261017T040749Z/production.db`，sha256 `0d5d3f345bdddb2b241c87fc8e75e28420d08bf78be074b736c450435079a900`，461,910,016 bytes，PRAGMA integrity_check=ok，任务排空（busy 全 0），snapshot_hash `785de7b2…6cf85`（126 行），隔离字段恢复差异 0，零设备写。
- 最终进程 PID：正式后端 46128（127.0.0.1:8000，2026-10-17 11:16 启动，已加载 m45-linux-node 配置）；Pull Runner SSH 隧道 46424（10:53 启动）。
- 回归：交付版全量 667 passed / 0 failed（496.82s）+ 前端 21 passed / 0 failed；切换前全量 665/0 与针对性 204/0 保留为过程记录。
- Mimosa：封印代码扫 0 findings、coverage=partial（`scan-2026-10-17T03-26-57Z`，seal `4a93c6dc…245e4`）；封印后应用代码零变更（工作区仅协作文档与本报告），不能声称全局安全证明。

## 人工仍待（模型不代签）

1. Q1–Q8 治理裁定与风险126 对象级人审（库内 `pending_human_review`）。
2. 风险12 归档建议稿的操作员确认（库内维持 inactive）。
3. 补证申请 `IR-a0c04a79…` 及其他 awaiting_authorization 申请的授权决定。
4. 处置规划中若 operators 选择执行的修复动作，须另行审批（当前无任何修复授权，双写开关 0）。

## 官方来源

[Canonical CVE-2026-94266](https://ubuntu.com/security/CVE-2026-94266) 与 [Canonical CVE-2026-63073](https://ubuntu.com/security/CVE-2026-63073)。原始官方记录及SHA-256保存在数据库，不把模型结论当成官方原文。
