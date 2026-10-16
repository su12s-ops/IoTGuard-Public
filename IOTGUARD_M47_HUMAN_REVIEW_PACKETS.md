# IoTGuard Stage 9B M4.7 人工复核材料（独立版）

本材料服务于统一四智能体正式接管前的必要人工裁定。**它只汇编事实与两侧系统真实输出，不构成任何裁定。正式裁定必须由授权操作员本人作出并签署；模型（含本轮验收代理）不得代签、不得代填裁定栏、不得以模型之间相互一致冒充人工结论。**

数据来源与完整性：

- 开发基线 `fa3b47447196d5e1993882343da1da56249e7f2f`；材料提取时间 2026-10-17（Asia/Shanghai）。
- 统一链输出取自业务库 `unified_analysis_run` 真实行；System B 对照取自 M4.6 只读对照产物（未落正式库）。
- 源数据摘要（SHA256）：统一链+官方记录提取件 `8e4dfa0592fc5d149744a5c6183b8d1d2cf692bd0871bd9a899dc299a0a36959`；System B 对照 `a2d138fb02a709179a5ed16ed25c5637db5f94d55621cd59b0d59f986dbfebc8`；curl 侧统一原始 `a3e2507561e0ebccf27d4358efb91be4486d4538e8e33f8fa1652fc34909dc8e`；OpenSSL 侧统一原始 `44a7041f3782a0cf6e720d944ea1c645202a8f0216604b945e8b4e88e4f262dd`。原始件存于 gitignored `reports/m47-work/`、`reports/m46-work/`。
- 当前正式入口仍为 System B；`LINUXGUARD_UNIFIED_PIPELINE=off`。下表所有统一链记录均为 shadow 模式，未写任何正式字段。

---

## 材料A：真实 curl 风险 126（CVE-2026-94266 / USN-8932-1）

### A1 对象事实（两侧共用输入）

| 项 | 值 |
| --- | --- |
| 风险对象 | risk_assessment id=126，active=1，asset 1（Ubuntu noble 24.04） |
| 组件与装机版本 | curl / libcurl4t64 / libcurl3t64-gnutls 均为 `8.5.0-2ubuntu10.15`（2026-10-16 16:08 授权固定清单 INV-35036f20a2ffe98440f99c718301de4b，1790 包，inventory_complete=true） |
| 官方适用性 | Canonical noble/curl **受影响**，USN-8932-1 修复版本 `8.5.0-2ubuntu10.16`；确定性比较 `.15 < .16 = True` |
| 官方原文 | `https://ubuntu.com/security/cves/CVE-2026-94266.json`，内容 SHA256 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`（库内 7 条记录同哈希，evidence_status=available；证据 ID 示例 ADV-c73bcf3856244a5abc668abe17c6e95e） |
| 官方定性 | Canonical CVSS3=null、Ubuntu 优先级 low；漏洞为 libcurl `CURLINFO_EFFECTIVE_URL` 凭据泄漏（需本地 `.netrc` 等前提参与） |
| 正式行现状 | review_status=`reanalysis_required`；preliminary=18.54/Low/scheduled_fix；runtime_status=contextual；exposure public 但 exposed_service_count=0；NVD/EPSS/KEV 均 unavailable |

### A2 两侧系统历次真实输出（全部为真实运行，无一删改）

| 运行 | 系统与模式 | impact | direction | action | priority | 置信 | Trace |
| --- | --- | --- | --- | --- | --- | --- | --- |
| m44-real-841d76e9aa | 统一四智能体 shadow（M4.4） | confirmed_affected | maintain | scheduled_fix | medium | 0.6 | TR-20261016135101-38986d |
| m46-real-0ac56292c4d1 | 统一四智能体 shadow（补证复验） | potentially_affected | maintain | scheduled_fix | low | 0.6（run 0.5） | TR-20261016160102-a5c039 |
| UA-e8b946663c534e46a6c8a9ef | 统一四智能体 shadow（新 INV 再研判） | potentially_affected | maintain | scheduled_fix | low | 0.6（run 0.5） | TR-20261016160831-59b845 |
| M4.6 对照 | System B 只读推理（未落库） | confirmed_affected | **upgrade_minor** | scheduled_fix | low | 0.7 | 无（对照产物） |

两侧门禁终态均为 `pending_human_review`（System B 理由 `confidence_below_0.70, evidence_partial`；统一链门禁理由见各 run decision_json）。

### A3 需要授权操作员裁定的问题

- **Q1 impact 口径**：System B 与 M4.4 统一链判 `confirmed_affected`；M4.6 两轮统一链在引入"装机版本身份须以决策时点授权清单确认"的业务约束后改判 `potentially_affected`（其论证：静态确定性比较成立、厂商公告作用域一致，但 branch_check=undetermined，且运行时维度 insufficient_evidence）。请裁定正式记录应采信 `confirmed_affected` 还是 `potentially_affected`，或维持 `reanalysis_required`。
- **Q2 direction 字段语义冲突**：System B 输出 `upgrade_minor`，其理由原文把该词解释为"同一上游小版本内的补丁级升级"（即**包升级方向**）；统一链输出 `maintain`，其 `risk_direction` 语义为"证据相对风险基线的修正方向"。两者同名不同义。请裁定正式口径以哪种语义为准（该裁定影响迁移后历史数据可比性）。
- **Q3 优先级**：medium（M4.4）vs low（M4.6 两轮、System B）。结合 Ubuntu 官方 low 优先级、exposure public 但无监听服务、KEV/EPSS 不可用，请裁定正式建议优先级。
- **Q4 缺口处置**：两侧共同缺口——运行时覆盖 stale（file/process 证据约 50.8h 且新鲜度标签自相矛盾）、`.netrc`/CURLINFO_EFFECTIVE_URL 利用路径未观测、apt 索引刷新后 `.16` 可获得性未验证。请裁定是否需要新一轮采集/复核，或接受缺口按 scheduled_fix 排期。

### A4 操作员裁定记录（留空，由授权操作员填写）

| 项 | 内容 |
| --- | --- |
| 裁定人（姓名/角色） | 　 |
| 裁定时间 | 　 |
| Q1 决定 | 　 |
| Q2 决定 | 　 |
| Q3 决定 | 　 |
| Q4 决定 | 　 |
| 理由（可另附页） | 　 |
| 操作员签名/凭证标识 | 　 |

落库途径：`POST /api/analysis/risks/126/human-review`（需 `X-Control-Token`，即已轮换的 `LINUXGUARD_CONTROL_TOKEN`；模型工具无该接口权限）。裁定前该风险维持 `reanalysis_required`，不得被任何自动路径改写。

---

## 材料B：历史 OpenSSL 风险 12（CVE-2026-63073 / USN-8678-1）

### B1 对象事实

| 项 | 值 |
| --- | --- |
| 风险对象 | risk_assessment id=12，**active=0（已失活历史对象）**，asset 1 |
| 组件与装机版本 | openssl `3.0.13-0ubuntu3.16` |
| 官方适用性 | Canonical 对 noble/openssl 标注 **not-affected**（USN-8678-1，该分支内交付修复版本 `3.0.13-0ubuntu3.15`，装机 `.16` 已不低于修复版本） |
| 官方原文 | `https://ubuntu.com/security/cves/CVE-2026-63073.json`，内容 SHA256 `b4891e8f30cbdc5d957c5541dda945237a7bc70f045c62ff5dd2422ed9f7ecaa`（库内 2 条记录同哈希；证据 ID ADV-0b33fdceb43944dc9477e451f365e557） |
| 历史基线 | preliminary=80.47/Critical/immediate_fix（源自 NVD CVSS3 9.8 与 2026-10-16 误匹配窗口；当日已被发行分支核验纠正，M4.4 提交 c7ca5a3 留档） |
| 正式行现状 | review_status=`inactive`，review_reason=本轮精确匹配不再命中；历史风险保留 |

### B2 两侧系统真实输出

| 运行 | 系统与模式 | impact | direction | action | priority | 置信 | Trace |
| --- | --- | --- | --- | --- | --- | --- | --- |
| m46-real-511217aaabfa | 统一四智能体 shadow | not_affected | **downgrade_major** | monitor | low | 0.85（run 0.8） | TR-20261016155618-b7a3f3 |
| M4.6 对照 | System B 只读推理（未落库） | not_affected | **maintain** | monitor | low | 0.74 | 无（对照产物） |

两侧 impact 完全一致（not_affected/monitor/low）。分歧仅在 direction 与置信度。门禁终态两侧均 `pending_human_review`（System B 理由 `evidence_conflicting, high_or_critical_final_score`——后者来自历史 Critical 基线）。

### B3 需要授权操作员裁定的问题

- **Q1 direction**：统一链判 `downgrade_major`（语义：相对历史 Critical 基线，证据要求大幅下调）；System B 判 `maintain`（语义：无需版本变更）。请裁定正式 direction 口径——特别是历史误匹配基线（80.47/Critical）应记为"已由官方记录推翻"还是"维持历史原值不回写"。
- **Q2 历史对象处置**：风险 12 已失活。请裁定其终态：保持 inactive 留档 / 关闭（human_confirmed） / 重新激活（须有新事实，当前无）。
- **Q3 旧升级建议**：M4.3 期间基于误匹配产生的 openssl 升级建议已撤回适用性依据。请确认该建议作废，不得再被任何计划/修复路径引用。
- **Q4 置信度差异**：0.85 vs 0.74。两者均基于同一官方 not-affected 记录与同一装机版本事实；差异来自对 NVD 元数据残余不确定性的处理。请裁定是否需要在正式记录中注明该差异来源。

### B4 操作员裁定记录（留空，由授权操作员填写）

| 项 | 内容 |
| --- | --- |
| 裁定人（姓名/角色） | 　 |
| 裁定时间 | 　 |
| Q1 决定 | 　 |
| Q2 决定 | 　 |
| Q3 决定 | 　 |
| Q4 决定 | 　 |
| 理由（可另附页） | 　 |
| 操作员签名/凭证标识 | 　 |

落库途径：`POST /api/analysis/risks/12/human-review`（约束同上）。裁定前该风险维持 inactive，不重新激活、不执行任何升级。

---

## 附：两侧理由原文摘录（核对用，不代替全文明细）

- System B 风险126（conf 0.7）关键句：「资产为 Ubuntu noble(24.04)，已安装 curl 8.5.0-2ubuntu10.15，低于 Canonical/USN-8932-1 对 noble 发布的修复版本 8.5.0-2ubuntu10.16……故影响面判定为 confirmed_affected，对应修复方向为同一上游小版本内的补丁级升级（upgrade_minor）……curl 为客户端库/工具而非监听服务……定级为 low、scheduled_fix……本结论不构成自动确认或修复授权。」
- 统一链风险126 最终轮（run conf 0.5）关键句：「确定性版本比较 .15 < .16 = True；厂商精确公告作用域 release=noble、release_status=released……决策时点授权固定清单 INV-35036f20……确认三者均为 8.5.0-2ubuntu10.15……『历史清单不能证明调查时点版本』缺口已消解，结论维持受影响、不转 not_affected。但确定性 branch_check=undetermined……」未消解冲突包括运行时 file 证据新鲜度标签自相矛盾、多源（NVD/KEV/EPSS/Kylin）unavailable 无法交叉验证。
- System B 风险12（conf 0.74）关键句：「Canonical 对 noble 的 openssl 在 USN-8678-1 中为 not-affected，修复版本 3.0.13-0ubuntu3.15，本机安装 3.0.13-0ubuntu3.16 已不低于修复版本……判定为不受影响、无需版本变更（maintain）……是否关闭该事件须由人工复核确认。」
- 统一链风险12（conf 0.85）关键句：「两条相互独立的证据链同时成立：(a) 厂商精确公告……status=not_affected；(b) 该分支内交付修复版本 3.0.13-0ubuntu3.15，装机 3.0.13-0ubuntu3.16 已达/超该版本……」未消解冲突含 file 证据新鲜度矛盾、端口 18460 来源冲突、按 device_id 查画像 found=false 的可查性冲突。

完整原文：统一链见 `unified_analysis_run.decision_json/agents_json`（run_id 如上）；System B 见 `reports/m46-work/system-b.json`（SHA256 见上文）。
