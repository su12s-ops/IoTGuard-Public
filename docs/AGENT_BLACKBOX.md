# 智能体 + Harness 黑盒闭环检测

本页说明“黑盒检测机制”：它用什么边界观察智能体、Harness 在整条链路中处于什么位置、
真环境怎么跑、以及通过/不通过分别代表什么。检测器只走公开 HTTP 契约，不导入后端模块、
不直连数据库，因此不会因为内部重构而“自证正确”。

## 1. 三层检测

| 层 | 问题 | 判定依据（外部可见） |
|---|---|---|
| 契约 | 服务、四角色规格、模式与写开关是否与声明一致 | `/api/health`、`/api/unified/specs`、`/api/analysis/status`、`/api/analysis/preflight`、`/api/harness/artifacts` |
| 内嵌 | Harness 是否真的长在四智能体链路里，而不是旁路 | 一次研判运行详情里的 `final.harness_feedback`、`final.candidate_intents`、`final.plan_execution_mode`、`plan.requires_approval` |
| 闭环 | 研判 → 计划 → 审批边界 → 执行 → 结果 → Trace 是否首尾相接 | `/api/unified/runs/*`、`/api/harness/runs/*`、`/api/traces/*` |

三层判定与检查项分开（`verdicts.contract / closure / analysis`，总判定 `pass | degraded | fail`）：

- `contract`：health / specs / analysis status / preflight / artifacts / 授权边界 / 目标解析；
- `closure`：Harness 闭环、修复面 fail-closed、Trace 链；
- `analysis`：四智能体真实研判产出——**运行 `completed` 不等于研判成功**；
  `degraded_roles` 非空、无 `candidate_intents` 且无 `verdicts`、或阶段 `failed`
  都记为 `degraded`，并在报告里单列「研判面降级」小节；
- 退出码：`0`=pass、`3`=degraded（契约过但研判没产出）、`1`=fail、`2`=缺令牌。

失败面（全部只读、不触发设备写）：

- 无令牌/错令牌 → 401；计划哈希不匹配 → 409；重复/越权状态迁移 → 409；
- 写开关关闭时修复计划必须 `blocked` 且原因可核验，且 `blocked` 任务不可审批/执行；
- 只读调查任务没有审批前置，审批入口必须拒绝（不允许“假审批”路径）；
- 任何一次运行中出现 `side_effect=True` 的工具调用即判失败（检测器本身永不发写）。

## 2. 两种驱动，一套契约

| 驱动 | 位置 | 适用 | 模型 |
|---|---|---|---|
| 真环境检测器 | `scripts/agent_blackbox.py` | 对运行中的 API（默认 `http://127.0.0.1:8000`）做端到端检查，产出 JSON + Markdown 报告 | 可选：`--scope agent` 会真实调用一次四角色研判 |
| 隔离回归 | `backend/tests/test_whole_agent_blackbox.py` | CI / 本地回归，隔离 SQLite + 假模型客户端，不触网 | 假客户端（可复现） |

两边断言的是同一组契约，因此“隔离回归通过、真环境失败”本身就是一个有价值的结果
（本次真环境检测就据此发现了下面的 500 缺陷）。

## 3. 真环境怎么跑

```powershell
# 只做契约 + Harness 闭环（不调用模型，约 10 秒，不写设备）
python -X utf8 scripts/agent_blackbox.py --scope contract,authz,target,harness,repair,trace --asset-id 1

# 追加一次真实四智能体影子研判（只读、不写正式风险字段；耗时取决于模型）
python -X utf8 scripts/agent_blackbox.py --scope agent,embedding,trace --asset-id 1 --risk-id 28 --timeout 5400

# 复用已完成的运行，只做内嵌与 Trace 核验
python -X utf8 scripts/agent_blackbox.py --scope embedding,trace --run-id UA-xxxxxxxx
```

- 令牌：`--token` > `--token-env` 指定的环境变量 > `LINUXGUARD_CONTROL_TOKEN` > `backend/.env(.local)`；
- 报告默认写入 `reports/agent-blackbox/`，文件名带 UTC 时间戳；
- 退出码：`0` = 全部通过，`1` = 有失败项，`2` = 缺少令牌，`3` = 契约通过但研判面降级
  （`degraded`：角色降级或无可用结论）。CI 里请把 `3` 与 `1` 分开处理，
  更不能把 `3` 记成通过。

## 4. 隔离回归覆盖

`backend/tests/test_whole_agent_blackbox.py`

1. `test_pipeline_harness_precheck_gates_plan`：四角色图跑完后 `harness_precheck` 必须是
   真实阶段；候选意图绑定确定性资产/风险身份、`execution_authorized=False`、
   `requires_approval=True`；计划执行方式为 `pending_approval`；**编排期不得创建任何
   HarnessRun**（证明“预检 ≠ 派发”）。
2. `test_write_switch_off_blocks_plan_terminally`：写开关关闭 → 预检终止
   （`policy_denied`）→ 计划 `blocked`，且不消耗计划反馈轮次。
3. `test_harness_task_links_shadow_candidate_and_closes`：影子研判 → Harness 计划绑定该候选
   （`authorization="none"`）→ 执行闭环 → 反向链接出现在运行详情与 Trace；只读任务
   走审批入口必须 409。
4. `test_blocked_ubuntu_plan_execute_is_contract_error`：已阻断/残缺的 Ubuntu 计划执行必须
   是 `ValueError`（→ 409），不能 `KeyError`（→ 500）——本缺陷由真环境检测首次暴露。

## 5. 2026-10-20/21 真环境实测

宿主 API `http://127.0.0.1:8000`，`LINUXGUARD_UNIFIED_PIPELINE=on`，三个写开关全部关闭。
报告文件在 `reports/agent-blackbox/`（每次运行一份 JSON + 一份 Markdown）。

| 检测 | 对象 | 结果 |
|---|---|---|
| 契约 + 授权边界 | health / unified specs / analysis status / preflight / harness artifacts | 通过；四角色齐备，`mode=on`，`device_repair_enabled=false` |
| Harness 只读闭环 | asset 1 / risk 28 | `needs_evidence`（缺新鲜采集心跳）；工具 `inspect_inventory`/`inspect_runtime`/`inspect_evidence` 全无副作用；续跑计 `attempts=2` 后可收口为 `cancelled` |
| 修复面 fail-closed | asset 1 / risk 28 | 计划 `blocked`（`需要当前资产的有效 curl 风险`）；不可审批、不可执行 |
| 影子候选绑定 | `UA-20261020153207-617da0` → Harness `6a031973…` | `shadow_candidate.authorization="none"`；反向链接在运行详情与 Trace 均可见 |
| Trace 链 | `TR-20261020154845-117f8a` | `harness_plan` / `harness_execute_started` / `harness_finished` / `harness_policy_blocked`（拒绝审批留痕）齐全 |
| 四智能体（asset 1 / risk 28） | `UA-20261020153207-617da0`，977s | 运行 completed，但 `runtime/vulnerability/decision` 三角色降级：模型侧 `APIConnectionError`，以及 `[1261][prompt is too long]` |
| 四智能体（asset 4 / risk 146） | `UA-20261020232421-f0bbef`，549s | 运行 completed，同样三角色降级：run 级 token 预算击穿（7 次调用累计 266,072 tokens > 上限 200,000） |

诊断要点：

- 两次真环境研判都**没有**产出可用的模型计划，`final.candidate_intents` 为空、`harness_feedback.status=no_action`，
  所以“模型计划 → 候选意图 → 待审批计划”这条语义链在真环境仍是**缺口**，目前只有隔离回归
  （合规假模型）给出正面样本。检测器如实记录，不以“运行 completed”冒充通过。
- 缺口不是 Harness 造成的：`harness_precheck` 阶段每次都真实执行并写入
  `harness_feedback`（契约、只读、无执行权），是上游模型输出不可用导致没有意图可检。
- 两个上游容量问题（**待处理，不属于本次改动范围**）：
  1. `[1261][prompt is too long]`：Ubuntu 宿主（3944 包）与 OpenWrt-Lab 的证据预取上下文使单次
     prompt 过大，模型侧直接 400。
  2. run 级 token 上限 200,000 被累计调用击穿后，后续角色一律“预算已用尽”降级——单角色重试会
     把预算前移到第一个角色，而不是按角色分配。

> 边界：检测通过不代表设备已修复、业务已签收或安全验收完成。真环境 Harness 只读到
> “证据不足”，这本身就是结论——缺新鲜心跳时不得记为健康或已修复。

## 6. 已知限制

- 只读端点（`GET /api/harness/runs`、`/api/unified/runs`、`/api/traces`）不要求控制令牌，
  与非控制类只读端点口径一致；检测器把它记为观察项，不判失败。
- 检测器不验证设备侧真实写入（写开关在本轮全部关闭，且设备写不属于黑盒只读面）。
- 模型调用结果受模型方差影响：同事实重跑差异只算方差，不算新证据。

## 7. 2026-10-21：分层判定与提示词膨胀修复

两个真环境运行（`UA-20261020153207-617da0`、`UA-20261020232421-f0bbef`）都曾被
记成整体 PASS，但三角色降级的实际原因是可定位的：

1. `UA-20261020153207-617da0`：漏洞分析师与决策规划师的单次请求被渲染成
   **7,233,731 / 7,153,666 字符**。根因是证据注册表（284,748 条）的**全部 ID**
   被 `json.dumps(sorted(...))` 塞进提示词 → 模型侧 400 `[1261][prompt is too long]`，
   两个角色各浪费两次重试后降级；
2. `UA-20261020232421-f0bbef`：资产角色 5 次调用累计 266,072 tokens 吃穿 run 级
   200,000 上限，其余三个角色 0 次调用直接降级。

修复（见 [四智能体执行与评估改进](FOUR_AGENT_IMPROVEMENTS.md)）：

- 可引用证据 ID 改为有界渲染（样例 + 总数 + 截断标记），全集只在服务端校验；
- 每个角色有独立 token 配额，单角色不能先到先得吃光 run 预算；
- 请求前按角色做上下文预算（估算 token），超限**显式降级**
  （`context_budget_exceeded: role=… estimated_tokens=… limit=…`），
  不再把百万字符提示词发给模型换回 400；
- 预算耗尽的原因区分「调用次数」与「token」，并记录用尽角色。

因此本检测器的报告不再只有一个 PASS/FAIL：研判面 `degraded` 与契约面 `pass`
会同时出现在结论里，退出码也不同。
- 真环境研判的“模型计划”正面样本依赖模型可用性与上下文容量；检测器不替模型兜底，
  降级即如实标降级。
