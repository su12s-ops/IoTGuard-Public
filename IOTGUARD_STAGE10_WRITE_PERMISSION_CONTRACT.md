# IoTGuard Stage 10 写操作权限契约（唯一正式版本）

日期：2026-10-17。状态：**生效**。本契约统一此前散布在 M4.5 设计、Stage 10 实验设计与实现代码之间对修复写开关的不一致描述；任何文档与本契约冲突时，以本契约为准。

## 1. 两个互斥的权限域（令牌层面）

| 域 | 令牌 | 传输 | 可执行的操作 | 明确不可执行 |
| --- | --- | --- | --- | --- |
| 控制平面（操作员） | `LINUXGUARD_CONTROL_TOKEN`，请求头 `X-Control-Token` | 常量时间比较（`hmac.compare_digest`） | 一切改变产品业务状态的 API：资产登记、连接管理、采集任务、调查授权、风险人工复核、Harness 计划审批/执行/回滚、修复任务状态、情报同步、配置与演示入口 | — |
| 节点平面（采集/执行节点） | 每节点独立令牌：主节点 `LINUXGUARD_COLLECTION_NODE_TOKEN`，附加节点 `LINUXGUARD_COLLECTION_NODE_TOKEN_<SUFFIX>`，请求头 `X-Collection-Node-Token` | 常量时间比较，令牌→节点身份绑定（`request.state.collection_node_ids`） | 仅限：`GET /api/iot/collection-node/claim`、`POST /api/iot/collection-node/results/{run_id}`，且令牌所属节点必须等于声称节点 | 风险审批、系统配置、修复计划审批、任何控制平面写操作 |

采集节点令牌**永远不能**取得风险审批、配置或修复执行权限；它只能领取后端已批准/已排队的任务并回传结果。修复的实际执行授权由第 3 节的独立机制约束，与节点令牌正交。

## 2. 两个互斥的写开关（设备域 vs 隔离实验室域）

| 开关 | 作用域 | 语义 | 生产要求 |
| --- | --- | --- | --- |
| `LINUXGUARD_ENABLE_DEVICE_REPAIR` | **仅 OpenWrt 设备写**（opkg/apk 修复产物安装，`agent_harness.install_registered_package`） | 设备写总开关；Ubuntu 隔离克隆路径**不读取**此开关 | 恒为 `0` |
| `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR` | **仅隔离 Ubuntu 克隆实验室写**（`ubuntu-apt-v1` 适配器的 dpkg 安装） | 必要非充分条件；须叠加第 3 节全部确定性校验 | 恒为 `0` |

两个域**互不授权**：打开其中任何一个都不能解锁另一个域的写操作。此为 Stage 10 修正项——此前实现错误地要求 Ubuntu 实验写同时满足两个开关，导致（a）实验必须打开生产设备写开关（违反隔离原则），或（b）文档承诺的"实验只开实验室开关"在代码上不可能成立。现实现已修正为下述契约。

## 3. 隔离 Ubuntu 实验写的完整充分条件（全部满足才可能执行）

对一次具体的 `ubuntu-apt-v1` execute，后端 `queue()` 与节点 `claim()` 两处独立复核：

1. `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=1`（且 `LINUXGUARD_ENABLE_DEVICE_REPAIR` 不参与判断）；
2. 目标资产 id 已在后端 `LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE`（逗号分隔白名单）中显式声明；**空作用域 = fail-closed**，即使开关被误开也无法执行任何实验写；
3. 风险对象通过既有治理（人工复核/裁定完成，模型不可代签，`assert_execution_allowed`）；
4. `run.approval_hash == run.plan_hash`，且计划哈希覆盖：克隆资产身份、实测安装版本、最新官方原文（24h 内、SHA256 完整性校验）、精确目标包集合、节点身份、连接签名、清单哈希、预演结果（15 分钟时效）；
5. 官方原文 SHA256 与计划生成时一致（变化即审批失效）；
6. 节点侧 `LINUXGUARD_UBUNTU_LAB_PERMIT` 许可文件独立成立：`asset_id`、`machine_id_sha256`、`plan_hash`、`isolated_clone=true`、`restore_verified=true`、`snapshot_id`、`approved_by`、`expires_at` 全部精确匹配且未过期；
7. 预演（dry-run）证据与计划逐字段一致。

实验环境作用域由**隔离数据库、独立节点、独立资产、独立配置、独立许可**共同定义；绝不允许通过在生产后端打开全局开关来"实现"实验。

## 4. 全部状态变更 API 的认证要求（本轮审计结论）

以下端点本轮已补齐 `require_control`（此前无认证，属真实写入口缺口）：

- `POST /api/risk/calculate`（重算风险，写 RiskAssessment）
- `POST /api/remediation/generate`（生成修复任务，写 RemediationTask）
- `POST /api/vulnerabilities/sync-real`、`/sync-ubuntu-assets`、`/sync-kylin-assets`（写情报库并触发联动分析，消耗外部配额）
- `POST /api/unified/analyze`（shadow 入口，消耗真实 LLM Token；on 模式下本就 409 fail-closed）

其余全部写端点（assets/upload、iot/connections*、collection-runs*、discovery、advisories、harness/runs 及 approve/execute/verify/dry-run/cancel/rollback/recover、matching/run、devices/*、scans/targets*、runtime/ebpf/*、runtime/lsm/*、runtime/sensors/heartbeat、analysis/runs 与 human-review、unified/shadow、unified/investigations/*、remediation/tasks/{id}、demo/start、demo/targets、vulnerabilities/official/verify、remediation_workflow/*）均已带 `require_control`；采集节点端点（claim/results）带 `require_collection_node` + 节点身份绑定。GET 入口中 `_bootstrap_targets` 仅在演示表为空时从环境变量播种，且调用点 `POST /demo/start` 已受令牌保护；`GET /demo/targets` 亦已受令牌保护。

前端已通过全局 axios 拦截器在控制会话解锁后自动附带 `X-Control-Token`，上述加固不改变前端交互；未解锁时请求按 401/503 明确拒绝。

## 5. 拒绝行为与审计

- 令牌缺失：`503`（后端未配置令牌）或 `401`（令牌不匹配），均不泄露期望值。
- 令牌错误/越权（节点令牌访问控制平面、控制令牌冒充节点）：`401`。
- 跨资产/跨节点/跨计划引用：`409`/`422`，业务语义拒绝。
- 所有 Harness 修复动作与节点领取/回传均落 `trace_event` 审计（含 side_effect 标记、工具调用预算、计划哈希）。

## 6. 违反本契约的已知历史问题（本轮已修复）

1. 文档承诺"实验仅开 `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR`"，代码却要求双开关同时为 1 → 已改为单开关+资产作用域。
2. `POST /risk/calculate`、`POST /remediation/generate`、`POST /api/vulnerabilities/sync-*`、`POST /api/unified/analyze` 无认证 → 已补 `require_control`。
3. `LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE` 为新增变量（默认空 = fail-closed），`.env.example` 已记录。
