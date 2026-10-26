# IoTGuard OpenWrt 通用漏洞情报接入与设备级 CVE 匹配报告

> 历史记录：保留当时的结果、失败与限制，不代表当前部署状态。当前入口见 [项目状态](../status.md)。

- 日期：2026-10-19（UTC 01:23–02:15 实测窗口）
- 代码基线：main `1ff170a` + 本轮工作区变更（运行实例 revision=`working-tree`，http://127.0.0.1:8000）
- 对象：生产 OpenWrt 资产 asset 2 / connection 1（`OpenWrt-000c2915a8c8` @ 192.168.100.1，25.12.6 / x86/64 / 内核 6.12.112）
- 方法：代码走读 + 在线官方 API 实时抓取 + 产品 API 端到端实测（同步 → 只读采集 → 匹配 → 覆盖 → 风险）。
  **未插入任何单条人工 CVE 记录，未写任何 CVE 专用匹配规则；未对设备做任何写操作。**
- 原始证据目录：`reports/openwrt-intel-20261019/`（本文所有数字均出自该目录 JSON）

## 0. 结论速览

| 检查对象 | 本轮前 | 本轮后 | 依据 |
|---|---|---|---|
| OpenWrt 官方情报接入 | 9 条 GHSA 原始快照躺库，全部 `insufficient_data`，操作员公告表 0 行 | 在线同步 9 快照 → **13 条规范化公告记录**（12 条确定性范围 + 1 条显式未确定），带内容哈希溯源，可持续更新 | `intel-sync.json`、`advisories-normalized.json` |
| 覆盖评估 API | 9/9 `insufficient_data` | 9 条全部分域归类：7 条 `not_in_reported_range`、2 条 `insufficient_data`（分支/commit 域，仅凭版本不可判） | `official-coverage.json` |
| 真实匹配器 | `POST /matching/run?asset_id=2` → **count=0**（结构性恒零） | 同一设备（182 包实测重采）→ **5 候选 5 判定**：affected 2 / fixed 1 / not_affected 2，absent 组件 5 条独立统计 | `matching-run.json`、`matching-results.json` |
| 通用 CVE 库关联 | 12849 条 Ubuntu/NVD 命名体系与 182 个 OpenWrt 包 **0 命中** | 官方 GHSA 规范化后按组件名+别名关联，候选 5；通用库同名兜底保留 | §3.3 |
| 活跃风险 | 无（匹配恒零 → 风险层对 OpenWrt 永远无输入） | **1 个 CVE（CVE-2026-62948）具有官方依据的活跃判定**，2 条 candidate 风险进入四智能体正式研判（分层，不自动定案） | §5.5 |
| 回归 | — | 后端全量回归 **756 passed / 0 failed**（含新增 18 项 OpenWrt 情报专项测试） | §6 |

**核心命题验证**：检测器对"新增公告"的处理能力是结构性的——本轮会话内 `openwrt_advisory` 表从 0 行变为 13 行（时间戳 01:42:35Z），未改任何 CVE 专用代码，随后 01:46 的匹配立即产出 5 条四态判定。通用性由规则驱动（版本域解析 + 组件名规范化 + 别名表），不由任何 CVE 特例驱动。

## 1. 根因定位（修复前实测）

按"逐层输入/输出/候选数量"记录（数据库 `backend/data/linuxguard.db`，2026-10-19 01:23 快照）：

### 1.1 GHSA 抓取与写入流程
- 抓取/导入链路存在且有效：`iot_official.py:18-49 import_snapshot` 全量校验（GHSA id 格式、官方 URL 钉扎 `github.com/openwrt/openwrt/security/advisories/<id>`、批量原子性）后写入 `iot_official_advisory`（ecosology='openwrt' 9 条，含 content_sha256）。
- **断点 1（转换层缺失）**：原始快照从未被转换为匹配器消费的 `OpenWrtAdvisory` 表——该表 0 行。匹配器 `iot_devices.py:195` 只读这张空表。

### 1.2 九条公告全部 insufficient_data 的直接原因
`iot_official.py:82-86`（修复前）：`assess_snapshot` 对 openwrt 生态**刻意不计算任何范围**（三元表达式对 openwrt 恒返回 `[]`），注释理由是"包版本与 release 版本是不同域"。于是 9/9 全部落入默认 `insufficient_data`。这是保守正确但能力为零的实现：官方载荷里其实存在可确定性解析的范围（见 §2.2），问题在"不同域"从未被显式建模。

### 1.3 通用 CVE 库无法关联 182 个包
`vulnerability_info` 12849 条（Ubuntu Security API / NVD / 操作员），`affected_package` 命名体系为 Ubuntu（`linux-kernel`/`openssl`/`curl`…）。与 asset 2 的 182 个 OpenWrt apk 包名做精确连接：**0 命中**（实测 SQL）。这不是 bug 而是结构性事实：OpenWrt 组件情报必须来自 OpenWrt 官方域，通用库只能做元数据补充。

### 1.4 官方载荷的四类数据格式问题（规范化的真实工作量）
9 条官方 GHSA 逐条过筛（`ghsa-live-fetch.json`）：

| 问题 | 实例 | 处理 |
|---|---|---|
| 组件名是仓库级占位 | `OpenWrt`（procd/ubusd/mdnsd/jsonpath/ltq-ptm 5 条）、`openwrt`（ead） | 组件名取自官方 summary 前缀（`procd: …`）/首词（`EAD …`），出处记录进 notes |
| 组件名带装饰/多组件 | `cgi-io (OpenWrt)`、`odhcpd/luci` | 去装饰；斜杠拆分为 odhcpd + luci 两个组件 |
| 范围表达式非标准 | `<= 25.12.4 (cgi-io HEAD 658b14b)`、`≤ commit 8e724fc`、`main`、`< 24.10.6` | 按版本域解析：release 域（含括号注记）、branch 域、commit 域、unknown |
| `first_patched_version` 全部为空 | 9/9 | 修复版本仅从 `< X` 边界蕴含或 description 官方声明提取，并区分两种依据 |

## 2. 通用情报接入实现（复用现有模型，无第二套系统）

新增 `backend/app/services/openwrt_intel.py`（约 470 行）+ 3 处消费方接线 + 1 个 API 端点 + 1 个脚本；`OpenWrtAdvisory`/`VulnerabilityInfo`/四智能体/Harness 数据模型与流程全部复用。

### 2.1 数据流
```
api.github.com（钉扎 https + host 精确校验 + 解析 IP 拒绝内网/环回/保留 + 禁重定向）
  → iot_official_advisory（原始快照 + content_sha256，复用既有校验导入）
  → normalize_advisory()（确定性规范化，纯函数）
  → openwrt_advisory（13 行：cve/package/release/scope/范围表达式/修复依据/溯源 notes）
  → vulnerability_info（source=openwrt_official_ghsa，供风险引擎与四智能体按 cve 检索）
```

### 2.2 版本域模型（"不同域"问题的显式建模）
- **release 域**：`< X.Y.Z`、`<= X.Y.Z (annotation)`。判定按全局版本序（`< 24.10.6` 即"低于 24.10.6 的任何版本"）。修复依据分两级：`< X` 边界蕴含（notes 标注"公告未显式给出修复版本号"）；description 官方原句 `This is fixed in OpenWrt X and later`（原文+版本存档）。
- **branch 域**：`main`。无上界、无登记修复时，安装包版本串含源码 commit 锚点（OpenWrt apk 版本格式 `YYYY.MM.DD~<commit>`）即落在官方范围内；无锚点则 insufficient。
- **commit 域**：`≤ commit 8e724fc`。release 设备无法确定性映射 → **显式未确定**（sync 摘要 `undetermined` 列表可见），绝不猜成 release 事实。
- 组件名非仓库级且范围是裸数字（无法证明属于 release 域）→ unknown 域 → 未确定（保持原测试语义）。

### 2.3 不确定态与防覆盖
- 每条记录 notes 携带 `provenance/ghsa_id/content_sha256/official_range/scope/component_source/fix_statement`，证据指纹含公告摘要 SHA。
- 操作员人工登记的 `OpenWrtAdvisory` 行（无 normalized 溯源标记）**永不自动覆盖**；操作员精确记录语义（release=固件版本、列表=包版本串精确枚举）与官方规范化记录语义在评估器中严格分型（回归 `test_wrong_firmware_and_incomplete_inventory_never_confirm_fixed` 守住该边界）。
- LLM 不参与规范化；所有派生事实可回溯到官方原文。

### 2.4 可持续更新入口
- API：`POST /api/matching/openwrt-intel/sync`（control token 保护；默认在线抓取，可提交离线快照）。
- 脚本：`backend/scripts/sync_openwrt_intel.py`（`--snapshot`/`--output`）。
- 重复同步幂等（回归验证）；同步只写公告与情报行，不触发匹配/风险（分层）。

## 3. 真实匹配器打通（`match_openwrt` 重写）

### 3.1 分层
1. **候选发现**：公告记录按组件名（+可审计别名表：`odhcpd→odhcpd-ipv6only`、`luci→luci/luci-base/luci-mod-status`）命中 182 包之一；通用库同名命中保留为无厂商依据候选。组件未安装 → 只进 `absent_components` 统计，**不产生匹配行也不解读为安全**。
2. **匹配执行**：`evaluate_candidate`（纯函数）按 操作员精确记录 > 官方 release 域 > 分支域 > 官方 fix-later 声明 > 未确定 的优先级输出 `affected / fixed / not_affected / insufficient_data` + reason_code + 置信度 + 中文理由（引用 GHSA id 与官方 URL）。
3. **风险创建**：独立层。`calculate_risk` 仅对 `affected=True` 的匹配建 candidate 风险，四智能体正式研判 + 人审才可定案——本轮实测沿用该分层（§5.5）。

### 3.2 设备侧输入（本轮实测）
2026-10-19T01:42:45Z 发起在线只读采集（connection 1，collector SHA 钉扎 `1d11e75…`）：成功，**182 包**（166 x86_64 + 16 noarch），`inventory_complete=true`，`os_version=25.12.6`，输出哈希 `aec77209…` 与 10-18 基线一致（设备未变）。`DISTRIB_TARGET=x86/64` 经 ubus board JSON 存于 `inventory_metadata_json.device_board.release.target`，随资产进入匹配上下文。

## 4. 多组件验收（在线设备真实重跑）

### 4.1 情报接入量
- 在线接入官方快照 **9** 条（2026-10-19T01:42:35Z，实时 api.github.com，当前仓库全部公告）。
- 规范化 **13** 条公告记录 / **9** 个组件（cgi-io、odhcpd、luci、ead、procd、jsonpath、mdnsd、ubusd、ltq-ptm）。
- 确定性范围 **12** 条（release 域 10 + branch 域 2），**显式未确定 1** 条（ead，commit 域，列入 sync 摘要 `undetermined`）。
- 通用情报行 9 条（`openwrt_official_ghsa`）。

### 4.2 候选关联
13 条记录 × 182 包 → **5 候选**（5 判定），**absent 5 项**（ead/jsonpath/ltq-ptm/mdnsd×2——组件未安装，如实统计）。

### 4.3 四态判定结果（`matching-results.json`，全部含官方依据）

| CVE | 组件（安装版本） | 判定 | 依据（摘要） |
|---|---|---|---|
| CVE-2026-62948 | odhcpd-ipv6only `2026.06.29~5d7be43f-r1` | **affected** (0.75) | 官方范围 `main` 且至今无登记修复（GHSA-hhmc-92hw-535f，CVSS 9.6）；设备包为主干源码快照（~5d7be43f，源码日期=公告发布日）落在范围内 |
| CVE-2026-62948 | luci `26.288.56989~75a306d` | **affected** (0.75) | 同上（公告双组件：注入点 odhcpd + 渲染点 LuCI；设备 luci 主干快照 ~75a306d） |
| CVE-2025-62526 | ubusd `2026.06.28~24864e78-r2` | **fixed** (0.85) | 官方原句 "This is fixed in OpenWrt 24.10.4 and later, including snapshots builds since October 18th 2025."（GHSA-cp32-65v4-cp73） |
| CVE-2026-30874 | procd `2026.03.13~58eb263d-r1` | **not_affected** (0.85) | 官方范围 `< 24.10.6` 不含 25.12.6（GHSA-jw28-hxcm-j934）；公告未给该版本修复声明——如实归 not_affected 而非 fixed |
| CVE-2026-62947 | cgi-io `2026.07.21~31cb3c89-r1` | **not_affected** (0.85) | 官方范围 `<= 25.12.4 (cgi-io HEAD 658b14b)` 不含 25.12.6；设备包源码位 31cb3c89 ≠ 受影响注记位 658b14b（GHSA-jw5r-xhf5-2xcq） |

设备级 `insufficient_data` 本轮为 0 行（无"在装但证据不足"组件）；该状态在覆盖层由 2 条公告实际展示（62948 分支域、55490 commit 域仅凭版本不可判），在单测中覆盖全部 insufficient 分支（`test_evaluate_four_states_on_real_records`）。absent 组件不冒充 insufficient 也不冒充安全。

### 4.4 覆盖评估 API（修复 insufficient 根因后的对照）
`GET /api/devices/official-coverage/openwrt?version=25.12.6` → 9 条全部分域：`not_in_reported_range` ×7、`insufficient_data` ×2（分支/commit 域），无一条再是"无理由的 insufficient"。同一 API 输入 `25.12.0` 时 CVE-2026-30873（`< 25.12.1`）正确翻转为 `potentially_affected`（回归断言）。

### 4.5 风险层（分层验证）
`POST /api/risk/calculate` → 仅 2 条 affected 匹配生成 candidate 风险（id 128/129，review_status=candidate，未定案）；fixed/not_affected 匹配不进风险层。四智能体正式研判已对风险 128 启动（run `686a4411f47c`，唯一正式入口 `/api/analysis`），结果见 §5.5。

## 5. 任务清单逐项回答

| 任务要求 | 实测回答 |
|---|---|
| 实际接入的情报数量 | 官方 GHSA 快照 9（当前仓库全量）；规范化记录 13；组件 9；情报行 9 |
| 成功规范化 / 证据不足数量 | 12 / 1（ead commit 域显式未确定；另 2 条公告在"仅版本"覆盖层因分支/commit 域不可判） |
| 实际关联到安装组件的候选数量 | 5（absent 5 项独立统计，不冒充安全） |
| 已修复 / 受影响 / 不适用 / 无法确定 | fixed 1（ubusd）；affected 2（odhcpd-ipv6only、luci，同一 CVE 62948）；not_affected 2（cgi-io、procd）；设备级 insufficient 0（状态机在覆盖层与测试中实际运行） |
| 本次情报覆盖范围及缺失项 | 覆盖：openwrt/openwrt 官方 GHSA 全量。缺失：NVD/KEV/EPSS 对这批 CVE **无记录**（多源刷新任务 89b764b3 已跑，0 命中，如实披露）；OpenWrt 论坛/feeds 级公告、组件上游仓库（cgi-io/odhcpd 自身 advisory）、24.10 之前的旧系列公告未接入 |
| 检测器能否处理新增公告 | 能，且已实证：公告表 0→13 行后匹配即时产出 5 判定，零 CVE 专用代码；规则全部是版本域/组件名/别名级别的通用逻辑 |
| 当前设备是否存在充分依据的活跃风险 | **存在 1 项**：CVE-2026-62948（odhcpd 注入 + LuCI 存储型 XSS 链，CVSS 9.6），依据=官方分支范围 + 设备源码锚点；置信 0.75，candidate 风险 128/129 待四智能体 + 人审定案 |

### 5.5 四智能体正式研判（risk 128，CVE-2026-62948/luci）
- 入口 `POST /api/analysis/runs?risk_id=128`（run `686a4411f47c`，正式模式，2026-10-19 01:45:52Z–02:08:49Z）。
- 证据包已注入新 OPENWRT 证据源：官方范围原文、scope、GHSA id、content_sha256、fix_statement（`evidence_packet.py` 升级）；Agent 2 专属工具同源（`agents_def.py`）。
- 四角色执行：asset_investigator ✅（153s）、vulnerability_analyst ✅（417s）、runtime_analyst ❌（APIConnectionError，2 次尝试，如实入档 review_failed_agents）、decision_planner ✅（343s）。

| 项 | 结果 |
|---|---|
| run 终态 | `human_review`（`four-agent-run128.json`） |
| 风险 128 终态 | `pending_human_review`，结论 `potentially_affected`，置信 0.55，**未自动定案** |
| 研判理由（节选） | "官方公告佐证 luci 受影响但范围仅分支域、无修复版本、分支映射不可证，维持 potentially_affected"——智能体正确理解并采信了新 OPENWRT 证据源的分支域语义，同时保持保守 |
| 风险 129 | 保持 candidate（同 CVE 的 odhcpd-ipv6only 侧，按批处理节奏另行研判） |

该闭环证明：官方情报 → 设备匹配 → candidate 风险 → 四智能体（含新证据源）→ 人审门，各层真实运转且互不越权。

## 6. 质量与边界

- 回归：后端全量 **756 passed / 0 failed**（含新增 `test_openwrt_intel.py` 18 项：范围解析、组件规范化、同步幂等与操作员防覆盖、四态判定、端到端匹配、覆盖 API、同步端点）。
- 安全边界遵守：本轮仅情报接入、代码修复、数据库业务更新、授权范围内只读采集（collector 脚本哈希钉扎、SSH 主机指纹核验、输出哈希留档）。未创建虚拟机、未安装/降级任何软件包、未执行修复、未动写开关（`LINUXGUARD_ENABLE_DEVICE_REPAIR=0` 保持）、设备零变更（采集输出哈希与基线一致）。
- 出网安全：GitHub 抓取实施 host 钉扎 + 解析后 IP 边界校验（拒绝环回/私网/保留/链路本地）+ 禁止重定向（Mimosa SSRF 约束落地）。

## 7. 后续建议（独立于本轮验收）

1. **隔离修复实验选型**：本轮实测为"充分依据的活跃风险"只支撑 CVE-2026-62948（官方分支范围 + 无修复版本）。但该 CVE **尚无官方修复版本**，不适合作修复实验对象（无可执行 fixed 目标）。若需可修复案例，建议等官方发布 odhcpd 修复后的下一个 25.12.x，或以 CVE-2025-62526 类（官方 fix-later 声明、修复版本明确）在受影响旧固件克隆上复现——需另行评估，本轮未做任何准备动作。
2. 情报面扩展（按需）：OpenWrt 论坛安全公告页、feeds 组件上游 advisory、NVD 对 2026 系列 CVE 的滞后收录轮询。
3. 分支域"affected"判定的复核机制保持：置信 0.75 + 四智能体 + 人审三层，官方发布修复后重同步即自动复评（`openwrt_branch_range_no_fix` 理由中已声明）。
