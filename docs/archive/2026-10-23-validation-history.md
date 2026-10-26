# 历史构建与验证记录

> 历史记录：保留旧窗口通过数与失败，不代表当前提交。当前命令见 [验证方法](../validation/testing.md)。

## 本地命令

```powershell
# 根目录
python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
python -m pytest -q
cd frontend
npm ci
npm run build
npm run test:e2e
```

Playwright 默认 Chromium，需先安装 `npx playwright install chromium`；Windows 使用已安装 Edge 时设置 `$env:PLAYWRIGHT_CHANNEL='msedge'`。测试夹具、模拟器与隔离数据库不是实体设备证据。

## CI 与联调范围

当前工作区 GitHub Actions 使用 Python 3.12、Node.js 24，在 Windows/Linux 执行完整后端回归，并执行前端构建与隔离 Chromium 浏览器回归。含套接字场景使用本机回环测试服务，非回环连接及真实 SSH 被测试钩子阻断。CI 与隔离夹具随本轮交付；本地工作区通过不等于远端 CI 已通过。

`python backend/scripts/live_discovery_check.py` 启动 SmartCam 本机服务和一次性测试库。现场设备验证需另行核对授权、配置、节点与服务。

## 验证边界

2026-10-19 整理前：前端构建成功；官方公告、IoT 业务与 Zephyr 管线专项共 21 项通过。依赖存在不阻塞构建的 PURE 注释警告。此结果不作为新提交的全量回归证明。

VMX 工具仅创建虚拟机配置，不创建磁盘、安装系统或启动虚拟机。Ubuntu / Zephyr 脚本提供重建入口，新宿主上的下载安装和完整构建仍需独立验证，不继承旧实例验收结论。

## 本次整理检查

- Ubuntu / OpenWrt 两种 VMX 参数均可生成，重复生成拒绝覆盖，非法网络名拒绝，测试磁盘内容保持不变。
- 两个新 Bash 脚本通过语法检查；所有当前 Markdown 本地链接有效。
- SLCR 补丁原先存在无效 hunk 计数和上下文格式，本次仅修正补丁格式；已对官方 v4.4.2 `soc.c` 通过 `git apply --check`。
- 尚未执行新主机 apt 安装、完整 west / SDK 构建或 VMware 导入启动。

## 2026-10-19 OpenWrt 闭环轮

- 后端全量回归 **761 passed / 0 failed**（含 OpenWrt 实验作用域写契约 5 项新测试：未配置拒绝、资产未声明拒绝、声明资产放行、生产开关不越权授实验、范围外资产 fail-closed）。
- 前端 `npm run build` 通过（PURE 注释警告不阻塞）；`docker compose config` 校验通过。
- 变更文件敏感扫描（令牌/私钥/控制令牌模式）0 命中；密钥、镜像、apk 与修复清单仅存于 gitignored `local-archive/`。
- 真实设备验证（只读）：OpenWrt-01 基线封存与 S0-Lab 匹配一致性实测，见 `docs/archive/2026-10-19-openwrt-security-closure.md`。

## 2026-10-19 完善程度检查及设备收尾

- 本轮代码修订前：宿主 Python 3.14.4 全量 **783 passed，5 warnings，786.37 秒**；前端 Edge **26 passed**，生产构建和 Compose 配置通过。5 条警告来自测试夹具的 `datetime.utcnow()`。
- 修正资产列表当前风险汇总后：资产风险、API 冒烟和 IoT 业务专项 **15 passed**，含新增 4 项回归；未将专项结果记为再次全量通过。
- 当前风险仅聚合 active 且未 resolved/inactive 的记录；无当前评估时返回 null 与 unassessed，不把历史 Critical 或空记录当作当前风险。
- 标准 Compose 显式关闭生产、Ubuntu 实验和 OpenWrt 实验三个修复开关，并清空 OpenWrt 实验作用域；未重建正在运行的 Docker 快照库。
- 真实只读设备验收及剩余项见 [设备验收](../validation/device-acceptance.md)。本轮不重复历史软件包安装或快照恢复。
- 新正式复评约50分18秒后以 human_review 结束：三角色完成、漏洞角色证据引用校验未通过并降级；该真实结果不计为四角色全通过。接口重载后4个资产风险汇总核对、无令牌变更401及历史记录连续性检查通过；3/3传感器健康，证据新鲜。

## 2026-10-20 五项修复交付

具体代码、锁定依赖、安全扫描、真实 QEMU 及模型复评结果见 [本轮交付](../archive/2026-10-20-delivery.md)。Python 3.12 首轮全量 810 passed / 1 teardown error 的失败留存；修复测试线程方法名冲突后，最终代码 `4dfc91d` 的 Linux CI 为 817 passed / 3 skipped；Windows 托管回归已完成并通过。前端生产构建、26 项浏览器回归通过。

真实隔离模型标准预算复评耗时 1805.28 秒，四角色全部 succeeded、无 degraded；最终因部分证据与快照时效保持 pending_human_review，不代签业务接受。相关端口重启及 WAL 跨平台修复在本地 Windows/Linux 各 18 项通过。


最终虚拟设备验收报告：[`docs/archive/2026-10-20-virtual-iot-acceptance.md`](../archive/2026-10-20-virtual-iot-acceptance.md)。当前提交对应 GitHub Actions Run `39299728933`：Windows/Linux 各 817 passed、3 skipped，前端 26 项通过。

## 2026-10-20 智能体 + Harness 黑盒闭环检测

新增黑盒检测机制（只经公开 HTTP 契约观察，不导入后端模块、不直连数据库）：

- 真环境检测器 `scripts/agent_blackbox.py`：契约 → 内嵌 → Harness 闭环 → 修复面
  fail-closed → Trace 链，产出 `reports/agent-blackbox/*.json|.md`。
- 隔离回归 `backend/tests/test_whole_agent_blackbox.py`：四角色图内嵌预检、写开关终止、
  影子候选绑定闭环、阻断计划契约错误 4 项，`4 passed`。
- 真环境（宿主 API :8000，asset 1 / risk 28，写开关全关）：契约与授权边界通过；
  Harness 只读闭环以 `needs_evidence`（缺新鲜采集心跳）收口，全部工具调用无副作用；
  修复计划 `blocked` → 不可审批、不可执行。
- 检测发现真实缺陷：已阻断的 Ubuntu 修复计划执行返回 **500（KeyError）** 而非 409。
  已在 `ubuntu_repair.validate/queue` 修复（缺字段按"绑定已变化"失败、阻断计划前置拒绝），
  重启宿主 API 后真环境复测为 409，并加回归用例锁定。

细节与命令见 [智能体 + Harness 黑盒闭环检测](../validation/agent-blackbox.md)。检测通过不代表设备已修复
或业务已签收；真环境只读结论为“证据不足”，不得记为健康。

本轮回归：`python -m pytest -q` 为 **949 passed / 7 failed / 5 warnings**（1060s）。
7 项失败全部落在工作树中**本次改动之前就已修改**的文件（`unified/graph.py`、`unified/conflicts.py`、
`unified/adapter.py`、`unified/investigation.py` 的未提交改动，均与冲突复议/正式落库相关），
不涉及本轮修改的 `ubuntu_repair.py`；新增的 4 项黑盒回归与 `test_ubuntu_harness.py` 全部通过。
本轮修复的 500 缺陷对应 1 项新回归（`test_blocked_ubuntu_plan_execute_is_contract_error`）。

## 2026-10-21 质量收敛（不新增角色）

本轮只收敛质量：提示词预算、角色预算、判定口径、7 项回归与固定案例基准。

### 1. 上下文与角色预算（真实故障根因修复）

两个真环境运行曾把「契约通过」误当成「研判成功」，根因可定位到两处：

- `UA-20261020153207-617da0`：漏洞/决策角色的单次请求被渲染成 **7,233,731 / 7,153,666 字符**。
  根因不是证据多，而是把证据注册表（284,748 条）的**全部 ID** 序列化进提示词，
  模型侧返回 400 `[1261][prompt is too long]`，两个角色各浪费两次重试后降级。
- `UA-20261020232421-f0bbef`：资产角色 5 次调用累计 266,072 tokens 吃穿 run 级 200,000 上限，
  其余三个角色 0 次调用直接降级。

修复与实测口径：

- 可引用证据 ID 改为**有界渲染**（样例 80 条 + 全集条数 + 截断标记），全集仍在服务端校验；
- 新增 `unified/context_budget.py`：请求前按角色估算 token（3 字符/token 保守下界，
  依据同批真实调用的 3.57–7.04 字符/token），超额度显式降级
  `context_budget_exceeded: role=… estimated_tokens=… limit=…`，不再发百万字符提示词；
- `BudgetState.role_token_limits` 给四个角色独立配额（60k/55k/40k/60k），
  `UsageMeter` 按角色计量并区分「调用预算」与「token 预算」，记录 `budget_exhausted_role`；
- `agent_logs` 每角色新增 `prompt_estimated_tokens / prompt_chars`，`usage_json` 新增 `role_usage`。

### 2. 「契约通过」与「研判成功」分离

黑盒检测器 `scripts/agent_blackbox.py` 判定改为三层（`verdicts.contract/closure/analysis`）：

- 研判面在 `degraded_roles` 非空、无可用 `candidate_intents`/`verdicts`、阶段 `failed` 时记为
  `degraded`，报告单列「研判面降级（契约通过 ≠ 研判成功）」；
- 总判定 `pass|degraded|fail`，退出码 `0/3/1`（`2` 为缺令牌），degraded 不再冒充通过。

### 3. 7 项回归修正

全部 7 项都已定位并修正，且都是「新语义已实现、用例仍按旧语义断言」的错位：

| 失败用例 | 根因 | 处置 |
|---|---|---|
| `test_happy_path_parallel_and_followup` | 补查只新增 `data_gaps` 时被判「报告未变」而跳过二次决策 | `judgment()` 纳入 `data_gaps/missing_evidence`（新缺口是决策输入） |
| `test_conflict_triggers_single_directed_rereview` | `node_prepare` 用空基线覆盖调用方已有基线（risk=None 时 `match_status` 被清空），确定性冲突检测失效 | `_baseline_snapshot` 改为「程序事实优先、已有基线不回填为空」 |
| `test_rereview_inherits_full_context_and_failure_keeps_original` | 同上（无重大冲突 → 不触发定向复议） | 同上 |
| `test_runtime_alert_vs_not_affected_cross_conflict` | 用例仍按旧规则：泛化运行时告警即重大冲突 | 按 M4.2 规格更新：泛化告警=维度差异；只有新鲜且 CVE 特异的证据才是重大冲突（`test_unified_conflict_classification.py` 为规格） |
| `test_same_facts_preserves_raw_confidence_and_formal` | 用例仍期待「事实未变也重跑模型」 | 按 M4.9 契约更新：未变化 → `no_new_evidence`、返回原运行、不重跑 |
| `test_formal_resume_keeps_formal_trace_and_publishes_current_report` | 夹具的复采没有实质事实变化，走不到子运行路径 | 夹具制造真实清单变化（包版本），走回正式再研判与 Trace |
| `test_auto_confirmed_reachable` | 用例断言 30 分 = Medium、处置 = scheduled_fix | 分级阈值是 40/60/80；改用 45 分，并断言模型给出的 `monitor` |

### 4. 固定案例重复验证与对照实验脚手架

- `backend/examples/agent_quality_cases.jsonl`：固定案例（2 个来自人工复核的标注 + 1 个未标注）；
- `backend/scripts/agent_quality_record.py`：`--live` 现场执行或 `--from-run` 导入，观测按行追加；
- `backend/scripts/evaluate_agent_comparison.py`：新增 `observations`（成功率、p50/p95、稳定性）
  与 `conclusion_stability`；未标注观测只计成功率、不进准确率；
- `single_agent` 策略（只调用决策角色、共用同一预取事实）用于同事实对照。

已记录的真实数据（案例 `C-272-openwrt-cgi-io`，`four_agents` 4 次重复，历史运行导入）：
成功率 **0.50**、与标注一致 **0.25**、耗时 p50 **2541.88s** / p95 **2977.32s**、
`conclusion_stability` **0.00**。样本量 1 案例 × 4 次，只能说明方差，**不能**说明四智能体优于规则或单智能体。

现场执行补充（2026-10-21，数据库副本 `reports/agent-quality/bench-copy.db`）：

- `rules`：0.01s、0 tokens，两案例均 `not_affected/monitor`（与标注不符）；
- `single_agent`：**1192.23s、98,937 tokens**，`not_affected/monitor/0.72`（与标注不符）。
  该次运行随后申请了 4 次漏洞角色补查，因此**不是严格的单角色基线**；
- 成对统计 `paired_cases=1`（仅 repeat 1），三策略在该重复下都不对。

这次现场执行还暴露并修复了一个门禁缺陷：该 `not_affected` 裁定曾被 **auto_confirmed 且无理由**，
而 `risk 272` 的人工复核结论是 `confirmed_affected`（理由正是"不能仅凭版本变化关闭风险"）。
`_baseline_snapshot` 现携带 `review_status/review_verdict`，`audit_policy` 新增
`contradicts_resolved_review:*`：与已签收方向相反的裁定一律转人工。

仍未完成（不得当作已完成）：`single_agent` 需关补查后重跑；`four_agents` 需同日现场重复
（现有 4 次为历史导入）；已标注案例只有 2 个；`human_review_minutes` 未测量。
协议见[智能体质量基准](../validation/agent-quality-bench.md)。

### 5. 本轮回归结果

`python -m pytest -q`：**979 passed / 0 failed / 5 warnings**（732.58s）。
基线为 949 passed / 7 failed；本轮新增 23 项回归用例（上下文预算 10 项、分层判定 6 项、
固定案例统计 7 项），并把 7 项失败全部修到通过。5 条 warning 均为既有
`datetime.utcnow()` 弃用提示，与本轮改动无关。

