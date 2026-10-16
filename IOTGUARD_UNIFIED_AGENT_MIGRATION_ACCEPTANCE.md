# IoTGuard Stage 9B M4.7 统一四智能体正式业务接管验收

日期：2026-10-17（Asia/Shanghai）。唯一仓库 IoTGuard-Public；开发基线 `fa3b47447196d5e1993882343da1da56249e7f2f`。本轮不重建架构、不新增 Agent、不做 Token 专项优化、不扩展 Harness 能力；只验证现有统一四智能体的持续真实运行能力并关闭接管前阻断项。

**结论先行：四智能体已具备接管 System B 的技术条件——连续真实运行 9/9 成功、四角色全勤、正式字段零触碰、模型故障 fail-closed（本轮修复一处缺口后经演练与回归锁定）、人工与 Harness 审批独立、迁移与回滚机制在隔离副本上验证通过。但正式切换本身仍未获批准，且存在两件只能由人工完成的前置事项：风险 126/12 的授权操作员裁定（材料已备、裁定栏留空），以及 curl 对象同事实结论方差（confirmed_affected ↔ potentially_affected）的人工口径确认。`LINUXGUARD_UNIFIED_PIPELINE=off`、双修复写开关 `0` 维持不变。**

## 1. P0-1 控制令牌清理与轮换（已关闭）

- 核查结果：两处演示代码（`backend/scripts/stage8_trace_demo.py`、`collector/run_mqtt_remediation_demo.sh`）原内嵌硬编码默认令牌字面量，与 `backend/.env` 现用控制令牌**完全一致**，且该字面量已进入公开 Git 历史（e9cff7e、d14f354 等；具体字面量值不复写，可于历史提交中核对），属真实暴露。
- 清理：两脚本改为强制从 `LINUXGUARD_CONTROL_TOKEN` 环境变量读取，缺失即退出；全仓 329 个跟踪文件复查，旧字面量、私钥材料零残留。
- 轮换（本轮完成，未输出令牌原文）：`backend/.env` 中令牌已替换为 48 位 urlsafe 随机值，新值 SHA256 指纹 `9f0616217c0aed9784352ea8a11299e6dc14796e4cdc22b2390a3a959c758ffe`（供操作员核对，不可反推原文）；`local-archive/private-backup-20261014/backend-env` 中已烧毁值同步清除并标注轮换。旧值自此失效。
- 操作员待办：重启后端进程使新令牌生效；运行两演示脚本前先 export `LINUXGUARD_CONTROL_TOKEN`。`backend/.env.example` 原有空占位符合要求，未改动。
- 边界：Git 历史中的旧字面量不再具效力，本报告不重写历史。

## 2. P0-2 人工复核材料（已建，未裁定）

`IOTGUARD_M47_HUMAN_REVIEW_PACKETS.md`（跟踪文件）为风险 126（curl / CVE-2026-94266 / USN-8932-1）与历史风险 12（OpenSSL / CVE-2026-63073 / USN-8678-1）各建一份独立材料：对象事实、两侧系统历次真实输出（统一链 M4.4/M4.6/W47 与 System B 只读对照）、官方原文 SHA256、待裁定问题（126 四项、12 四项）、理由摘录与完整原文指引。**两份材料的裁定记录栏全部留空，模型未签署、未代填**；正式裁定须经授权操作员以 `POST /api/analysis/risks/{id}/human-review`（控制令牌保护）落库。材料源数据提取件与对照原始件 SHA256 均在文内留档。

## 3. P0-3 Mimosa 可用性（已恢复）

Mimosa 本机入口恢复可用。深度扫描 `scan-2026-10-16T16-37-49.880Z-c218fa2fda10`：**0 findings**，封印 `sha256:730ff98cf47b3dfd87291cd394a9b878e1d4a63629d8091160455fe93820a504`，123 个依赖包，离线通告库可用（1 包 2 通告命中）。该扫描先于本轮 P2 代码改动，**不作为最终验收封印**；交付前以最终代码重扫（结果见 §9 补录）。M4.6 遗留的"安全验收未关闭"缺口就此关闭（以最终重扫为准）。开发过程中 Mimosa 预写钩子三次拦截本验收脚本候选（SQL 拼接模式误报面），经改写为参数化/Python 侧过滤后放行——拦截与改写过程本身即工具恢复可用的实证。

## 4. P1 W47 连续真实 Shadow（用户批准后执行，已完成）

窗口经用户明确批准（批准记录：会话内 AskUserQuestion 选择"批准 W47（推荐）"，2026-10-17）。T0=01:00:29，三轮实际执行 01:00–01:22、01:52–02:09、02:39–02:58（上轮结束+30 分钟顺延，无重叠）。每轮对真实 curl 风险 126、历史 OpenSSL 风险 12、OpenWrt 资产各执行一次完整四角色统一链（`force_full_review`，真实 LLM），共 **9 次全部 completed、每轮每对象 4/4 角色成功、零降级、零编排异常**；Trace 9/9 建链。统一链真实用量合计 **3,299,064 tokens**（逐运行留档于 usage_json，run 级 40 次调用预算未触界）。

| 观察点 | 结果 |
| --- | --- |
| 四角色持续真实执行 | 9/9 运行、36/36 角色调用成功；agents_json 逐角色真实延迟与尝试次数留档 |
| 调查申请具体/有效/合规 | 新产生 2 份申请（IR-ee08ce1a…/风险126、IR-f2feb101…/OpenWrt），均绑定资产、只读 inventory 范围、expected_effect 给出可证伪的双向预期；**未经操作员授权，均停留 awaiting_authorization，未执行任何采集** |
| 新证据是否解决原始问题 | 无新采集（申请 pending）；各运行如实把"16:08 清单无法证明此后无版本漂移"保留为 data_gap，未虚构解决 |
| 事实变化时研判是否随之变化 | 无自然事实变化，结论未发生有依据之外的变化；记录"未观察到实质事实变化" |
| 同事实无依据置信度提升 | curl 0.65→0.60→0.62、OpenSSL 0.82→0.78→0.74——**无上行膨胀**（呈下降/噪声） |
| 新旧系统分歧可解释 | 分歧模式与 M4.6 完全一致，指向已知口径问题（复核材料 Q1/Q2） |
| 模型故障 fail-closed | 窗口内零故障；该性质由 P2 演练 E9 以真实入口验证（见 §5） |
| 正式风险与设备写隔离 | 每轮前后正式字段快照哈希一致；全窗口真实库 risk_assessment/harness_run 零更新；双修复写开关恒 0 |

逐对象跨轮结论（原始输出全部保留于 gitignored `reports/m47-work/shadow/`，未筛选）：

- **curl 风险 126**：impact `confirmed_affected → potentially_affected → potentially_affected`，direction `maintain → downgrade_minor → maintain`，action 三轮稳定 `scheduled_fix`、priority low，置信 0.65/0.60/0.62。同事实下的 impact/方向方差真实存在且无新事实支撑，动作与优先级稳定；该方差与 System B 的分歧（见下）同源于"装机版本时点证据充分性"与 direction 字段语义，已列入复核材料 Q1/Q2，**须人工裁定口径后方可切换**。
- **历史 OpenSSL 风险 12**：三轮完全一致 `not_affected / downgrade_major / monitor`，与官方 not-affected 记录相容；置信缓降无膨胀。
- **OpenWrt 资产**：R1 以聚合结论输出（risk_score 10/low、CVE 零命中、pending 申请不计入置信），R2/R3 显式 `insufficient_evidence / collect_more_evidence`——零候选对象保持诚实不虚构，三次均未宣称全局安全。

System B 只读对照：窗口内 6 次对照的**真实推理已执行**，但验收脚本对 Pydantic `CoordinatorResult` 的提取存在缺陷（`.get` 调用）致输出未被捕获——6 次全部保留为失败样本不删；提取缺陷修复后另行执行 2 次补充对照（明确标注非窗口内产物）：风险126 `confirmed_affected / upgrade_minor / scheduled_fix / low / 0.62`、风险12 `not_affected / maintain / monitor / low / 0.72`，正式字段快照不变。**新旧分歧与 M4.6 同模式**：126 的 impact 口径与 direction 语义（upgrade_minor=包升级方向 vs 统一链 risk_direction=证据修正方向）、12 的 direction（maintain vs downgrade_major 对历史错误基线的处理口径）——均可解释、均已入复核材料，未发生无法解释的新分歧。

## 5. P2 正式迁移演练（隔离副本，44/0 通过）

`backend/scripts/m47_migration_drill.py` 在 `reports/m47-work/migration-drill/isolated.db`（真实库 sqlite backup 一致性副本）上执行，**44 项检查全部通过**：数据库指向防呆、126 行 RiskAssessment 全字段快照与哈希自洽、副本无在途正式任务、off 时 formal_sink/统一入口拒绝（formal_source_required/503）、on 时 System B 四个写入入口全部拒绝（system_b_formal_writer_disabled）且 `/api/unified/analyze` 拒绝成为第二正式入口（409）、shadow 行禁 sink、正式契约 17 键齐备、简单分层 0-LLM 直通与来源标注、全量路径写入处置/方向/设备上下文、四角色审计入库、**模型故障 fail-closed 落 pending_human_review**、历史 shadow 行无法经 formal_sink 晋升、统一 API 无晋升端点、人工裁定缺/错令牌 401 且非 pending 状态 409、未审批 Harness 执行拒绝且错误哈希审批不改变审批字段、**仅切 flag 不还原已写正式字段**、全字段恢复后差异 0、统一运行与审计记录保留、副本完整性 ok。演练使用确定性演练客户端（明确标注非真实 LLM、不复制任何历史 shadow 结论）；真实 LLM 的正式行为由 W47 影子与既有回归覆盖。

**演练发现并修复一处真实接管阻断缺陷**：`run_unified_sync` 捕获编排级异常后标记运行 failed 但不抛出、不调用 sink；正式批处理入口 `run_review_analysis_unified` 此前不处理该状态，风险会停留在 `agent_reviewing`（System B 对应场景经 `_fail_selected` 落 pending_human_review）。修复：`adapter.run_review_analysis_unified` 对 failed 运行逐风险 fail-closed（pending_human_review + human_review_required + `unified_orchestrator_failed:` 原因 + 清空自动确认字段），新增回归 `test_orchestrator_failure_fail_closes_risk_not_stuck` 锁定。演练首轮还曾因脚本自身选择器误触发一次历史调查任务在**副本上**的只读执行（inspect_inventory/inspect_runtime，side_effect=0，无 SSH/LLM/真实库影响），已按实情留档并修正选择逻辑。

演练中的隔离副本执行了持令牌人工 confirm 一次（仅副本、恢复阶段已回滚），用于验证操作员路径机制，**不构成对风险 107 的真实裁定**。

## 6. 回归与安全

- 后端全量 **730 passed / 0 failed**（527.88s，5 个既有 utcnow 弃用警告；M4.6 基线 729 + 1 项新增 fail-closed 回归）。
- 前端 Playwright **21 passed / 0 failed**（18.4s）；生产构建通过。
- 敏感扫描：329 个跟踪文件对新旧控制令牌、烧毁字面量、私钥材料零命中。
- 最终 Mimosa 重扫：见 §9 交付封印补录。

## 7. 接管条件评定

| 条件 | 状态 | 依据 |
| --- | --- | --- |
| 持续真实运行 | 达标 | W47 9/9、36/36 角色、零降级零故障 |
| 申请纪律与授权隔离 | 达标 | 2 份具体只读申请全部 pending，未越权采集 |
| 置信纪律 | 达标 | 同事实无上行膨胀 |
| fail-closed | 达标（修复后） | 演练 E9 + 回归锁定 |
| 写入互斥/单入口 | 达标 | 演练 D 系列 9 项 |
| 备份/恢复/回滚 | 达标 | 演练 B/I 系列；仅切 flag 不还原已实证 |
| 审批独立性 | 达标 | 人工裁定令牌保护；Harness 未审批/错哈希拒绝 |
| 影子不晋升 | 达标 | 演练 F 系列 + 无晋升端点 |
| 同事实结论稳定性 | **部分达标** | openssl 完全稳定；curl impact/方向存在无新事实支撑的方差，动作/优先级稳定 |
| 新旧分歧处置 | **待人工** | 分歧可解释且模式稳定，但口径裁定属授权操作员 |
| 安全验收 | 达标（以最终重扫为准） | Mimosa 恢复，首次深扫 0 findings |

**综合评定：技术侧具备接管条件；正式切换前置两件人工事项——①授权操作员完成复核材料 Q1–Q8 裁定（特别是 curl impact 口径与 direction 字段语义），②用户另行下达切换批准并按 M4.6 §5 排空/备份/单 worker 程序执行。本报告不构成切换许可。**

## 8. 交付与边界

交付物：本报告、`IOTGUARD_M47_HUMAN_REVIEW_PACKETS.md`、`backend/scripts/m47_migration_drill.py`、`backend/scripts/m47_continuous_shadow.py`、fail-closed 修复（`unified/adapter.py`）及回归测试、两处演示脚本令牌环境变量化、五份 `ai_collaboration` 文档更新。原始证据（W47 全部输出、演练副本与报告、回归日志）存 gitignored `reports/m47-work/`，不推送；推送仅含脱敏摘要。

全程维持：`LINUXGUARD_UNIFIED_PIPELINE=off`；`LINUXGUARD_ENABLE_DEVICE_REPAIR=0`；`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=0`；未删除旧编排器；未执行任何真实设备修复；未把任何 shadow 结论写入正式结果。本轮结束后停止，等待人工裁定与切换审批。

## 9. 交付验收补录

- 最终 Mimosa 深度重扫（交付前对最终代码与文档执行）：scanId `scan-2026-10-16T19-09-12.953Z-dd3deb9bdb53`，**findingCount=0**，123 个依赖包，封印 `sha256:922e9fddb926cd4de7d048e4b6aa5cfbc2ee3bdc2397425139abe7dc7505fad5`，离线通告库可用（1 包 2 通告命中）。
- 最终暂存敏感复查：新旧控制令牌、烧毁字面量、私钥材料 0 命中（329+ 跟踪文件）。
- 交付提交哈希：`git log -1 --format=%H -- IOTGUARD_UNIFIED_AGENT_MIGRATION_ACCEPTANCE.md`（最终回复同时提供实际提交哈希）。
