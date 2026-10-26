# 智能体质量基准：固定案例×重复×策略对照

2026-10-21。本页只讲「怎么测、测到了什么、还缺什么」，不新增智能体能力，
也不改变正式入口、风险真值、审批或设备写权限。

## 1. 为什么单列一页

此前交付里的结论有两种不同的「通过」，混在一起会高估系统：

| 说法 | 实际含义 | 由谁判定 |
|---|---|---|
| 契约通过 | 服务存活、四角色规格齐备、授权边界与写开关符合声明 | 黑盒检测器 `contract/authz/target` 层 |
| 研判成功 | 四个角色都产出通过校验的结构化结论，且决策有可用裁定/计划 | `analysis` 层（`degraded_roles` 为空 + 有可用输出） |

2026-10-20 的两个真环境运行都是「契约通过、运行 completed」，但
`runtime/vulnerability/decision` 三角色降级、`candidate_intents` 为空。
把这种状态记成「通过」会直接导致错误结论，所以现在报告分三层判定，
`degraded` 与 `fail` 分开（退出码 3 vs 1）。

## 2. 三个策略共用同一份事实

| 策略 | 模型调用 | 事实来源 | 用途 |
|---|---|---|---|
| `rules` | 0 | 规则基线（`match_status` → `impact_status`，`preliminary_decision` → 处置动作） | 成本下界与兜底对照 |
| `single_agent` | 1 个角色（决策） | 同一确定性预取包 | 单模型对照 |
| `four_agents` | 4 个角色 | 同一确定性预取包 | 正式链路 |

`single_agent` 只把 `routing.include_asset/vulnerability/runtime` 置 False，
预取节点、证据快照、校验器与门禁全部不变——差异只在「有没有专家角色」，
因此对照的是角色分工，而不是数据或提示词质量。

## 3. 固定案例与命令

案例文件：`backend/examples/agent_quality_cases.jsonl`

- `C-272-openwrt-cgi-io`：OpenWrt Lab / risk 272，标注来自人工复核记录
  （`confirmed_affected` + `scheduled_fix`，2026-10-19 复核完成）；
- `C-127-ubuntu-curl`：Ubuntu 克隆 / risk 127，同上（2026-10-17 复核完成）；
- `C-271-ubuntu-systemd`：**未标注**，只计成功率与耗时，不进入准确率。

记录一次观测（追加写，永不覆盖历史实验）：

```powershell
# 导入历史运行（不调用模型）
python backend/scripts/agent_quality_record.py --cases backend/examples/agent_quality_cases.jsonl \
    --case C-272-openwrt-cgi-io --strategy four_agents \
    --from-run UA-408054b8322d-272 --repeat 1 --out reports/agent-quality/obs.jsonl

# 现场执行（真实调用模型，需要副本库；单次四智能体约 20–50 分钟）
python backend/scripts/agent_quality_record.py --cases backend/examples/agent_quality_cases.jsonl \
    --case C-272-openwrt-cgi-io --strategy single_agent --repeat 1 --live \
    --database-url "sqlite:///E:/tmp/bench-copy.db" --out reports/agent-quality/obs.jsonl
```

统计（离线，不调用模型，拒绝覆盖已有结果文件）：

```powershell
python backend/scripts/evaluate_agent_comparison.py reports/agent-quality/obs.jsonl \
    --output reports/agent-quality/comparison.json
```

## 4. 统计口径

- `success_rate`：`status == succeeded` 的占比；`degraded`/`failed`/`timeout` 都算失败；
- `accuracy_including_failures`：失败计入分母，只对**已标注**案例计算；
- `latency_seconds_p50/p95` 与 `min/max`：墙钟耗时，含模型排队与重试；
- `conclusion_stability`：同一案例多次重复时，结论字段完全一致的占比；
  `null` 表示尚未重复，不能当成稳定；
- `paired_cases`：只有三策略齐备的案例才进成对准确率比较；未成对的单独计数。

## 5. 已记录的真实观测（2026-10-19，同一案例 4 次重复）

案例 `C-272-openwrt-cgi-io`，策略 `four_agents`，数据来源为历史运行导入
（`model_mode=recorded`），共 4 次：

| 重复 | 运行 | 状态 | 耗时(s) |
|---|---|---|---|
| 1 | `UA-97bee574d759-272` | degraded（决策 `verdicts` 为空） | 2336.29 |
| 2 | `UA-96f4103e371b-272` | succeeded | 2747.47 |
| 3 | `UA-b4c0526f5045-272` | succeeded | 1303.33 |
| 4 | `UA-408054b8322d-272` | degraded（漏洞角色防幻觉校验失败） | 3017.88 |

统计结果：

- 成功率 **0.50**（2/4），降级或失败 2 次；
- 与人工标注一致 **0.25**（1/4，失败计入分母）；
- 耗时 p50 **2541.88s**、p95 **2977.32s**、min 1303.33s、max 3017.88s；
- `conclusion_stability` **0.00**——同一案例、同一事实快照，四次结论互不相同。

这组数字本身就是结论：在这一个案例上，四智能体目前**既不快也不稳**，
「四智能体优于规则/单智能体」仍无证据。样本量 1 个案例 × 4 次，只能说明方差，
不能说明优劣。

## 6. 现场执行（2026-10-21，同一案例 C-272，数据库副本）

`rules` 与 `single_agent` 已现场执行（`obs-live.jsonl`）：

| 策略 | 耗时(s) | tokens | 结论 | 判定 |
|---|---|---|---|---|
| `rules` | 0.01 | 0 | `not_affected` / `monitor` | 与标注不符 |
| `single_agent` | **1192.23** | 98,937 | `not_affected` / `monitor` / 0.72 | 与标注不符，但 `auto_confirmed` |
| `four_agents`（历史 4 次） | p50 2541.88 | 172,106（1 次） | 1 次 `confirmed_affected` / 3 次 `not_affected` | 4 次中 1 次与标注一致 |

成对统计（`comparison-all.json`）：`paired_cases=1`（仅 repeat 1），该重复下三策略**都不对**。

必须披露的两个度量口径问题：

1. `single_agent` **不是严格的单角色**：决策角色通过 `follow_up_requests` 拉了漏洞分析师
   4 次（共 7 次调用，`role_usage` = decision 64,441 / vulnerability 34,496）。
   要得到干净的「单模型基线」，需要在对照实验里关掉补查（`follow_up_rounds=0`）；
2. `four_agents` 的 4 次是**历史运行导入**（`model_mode=recorded`，2026-10-19），
   与今天跑的两条不是同一时间窗，`facts_sha256` 相同但事实快照可能已变。

## 7. 这次现场执行暴露的门禁缺陷（已修）

`single_agent` 给出 `not_affected` + 0.72 置信，门禁 **auto_confirmed 且 0 条理由**；
而 `risk 272` 的人工复核结论是 `confirmed_affected`，复核理由正是
「不能仅凭版本变化关闭风险」。

根因：`match_status=fixed` 被当作确定性排除，且 `audit_policy` **没有**
「与已复核结论冲突」这条门禁——已签收的裁定可以被后续自动改判。

修复：`_baseline_snapshot` 携带 `review_status/review_verdict`，
`apply_unified_audit_policy` 增加 `contradicts_resolved_review:<reviewed>-><verdict>`，
与已签收方向相反的裁定一律 `pending_human_review`（回归见
`test_unified_pipeline.py::TestAuditPolicy::test_resolved_human_review_cannot_be_auto_reversed`）。

## 8. 离线审查后的最小收敛（2026-10-23）

本轮只做离线代码验证，未执行模型调用或设备操作，没有新增真实研判结果。

- 记录器导入历史运行前校验 risk/target/task 身份和角色路由，拒绝错案例或错策略。
- 新观测从运行自身保存的 `baseline/candidate_context/capability_marks/evidence_prep`
  计算事实哈希；缺少预取快照时拒绝，不再拿当前风险包替代历史输入。
  哈希保留时间与新鲜度，跨时间窗可能不配对；旧观测文件不能因新代码而视为已验证。
- `rules` 同样执行确定性预取；`single_agent` 的实验调用显式设置
  `follow_up_rounds=0`，不改变生产默认预算。路由角色数不是 LLM 调用次数，重试/工具循环仍可能多次调用。
- 未标注观测也检查重复 `(case_id, facts_sha256, repeat, strategy)`，但仍不进成对准确率。

当前环境先运行：

```powershell
python -m pytest backend/tests/test_agent_quality_bench.py backend/tests/test_agent_comparison.py -q
```

再按以下顺序收敛，不把 fixture/mock 的测试通过当作模型质量证据：

1. 固定一个可复核数据库副本、代码版本、模型配置与事实观察时间；保存不可变预取事实。
   当前预取会重新计算时间/新鲜度，只有数据库副本还不足以证明三策略完全同事实；
   在实现固定快照回放前，不强行合并不同哈希。
2. 先为 2 个已标注案例补独立评审及标注来源凭证；第 3 个仍只测运行指标。
3. 有真实模型配置及授权后，同一事实快照下按三策略各重复至少 3 次；
   核对单智能体实际 usage/agent logs 未调用专家，保留失败与降级。
4. 新建观测和统计文件，不覆盖旧实验；人审分钟数未经计时继续为 null。
   只有完整配对数据才能讨论准确率差异，样本小不能宣称显著优越。

## 9. 还缺什么（未完成，不得当作已完成）

1. `single_agent` 需要关掉补查后重跑，才是真正的单模型基线；
2. `four_agents` 需要**同日现场**重复（而非历史导入），才与另两条同时间窗；
3. 已标注案例只有 2 个（来自历史人工复核），需要独立评审补齐到 ≥5 个；
4. `human_review_minutes` 没有被测量，人审成本只能留空（不填 0 冒充已测）。

在补齐以上四项之前，任何「四智能体优于规则/单智能体」的表述都只能是假设。
现有的 1 案例数据只能说明：这个案例上三个策略都没给出与人工复核一致的结论，
四智能体多花 40 倍时间仍只有 1/4 概率命中。

## 10. 质量发布门槛与标签治理

标签不能由模型输出、同一运行的第二个角色或规则基线生成。每个计分案例必须保留：

- 不可变案例 ID、事实快照 SHA256、风险/资产身份和事实观察时间；
- 官方公告/版本/配置/可达性等原始证据引用及内容哈希；
- 两名独立审核者的裁定、理由、时间和分歧解决记录；
- 预先登记的期望字段；结果揭盲后不得改标签来贴合模型输出。

发布比较至少使用 5 个独立且双人复核的案例，每个已标注案例三策略各重复 3 次，
同一重复必须共享完全相同的 `facts_sha256`、代码版本和模型配置。报告需同时列出
全部失败/降级、准确率（失败计入分母）、配对差值和 95% bootstrap 区间；样本未达到
门槛或区间跨过零时只报告描述性结果，不宣称胜出。性能结论另需预先指定主度量、
纳入排队与重试耗时，并报告 p50/p95。不可标注的案例仅进入可靠性/耗时统计。

一次完成只能证明该次执行成功，不是质量发布门禁。基准命令应在隔离数据库副本上
运行；记录文件使用新的、只追加路径，严禁覆盖历史证据。正式风险路由仍由现有
配置决定，基准结果不自动改变生产模式。

比较脚本的 `quality_gate.ready` 仅表示采样完整性，要求每案例跨重复事实哈希一致；
同案例跨重复真值变化将直接拒绝。bootstrap 以独立案例聚类，避免把重复运行当成
独立样本。`statistical_separation_observed` 只描述记录的区间；由于脚本不能证明外部
独立标签审阅、冻结事实回放和代码/模型配置来源，`claims_allowed` 始终为 false，
必须另行完成独立验收才能作质量发布结论。
