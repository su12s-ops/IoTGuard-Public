# IoTGuard OpenWrt 真实安全闭环报告

更新：2026-10-19。唯一实验对象为 OpenWrt-Lab（asset 4），原始 OpenWrt-01（asset 2）保持不变。本轮未新增智能体、匹配器或 Ubuntu 实验。

## 实际结论

首次真实软件包修复、获批只读验证恢复、正式四角色复评及独立授权 C 的 S2→S1→S2 真实快照验收均已执行。最终设备在 S2-FIXED，cgi-io 为 `2026.07.21~31cb3c89-r1`，新采集经通用匹配器得出 `fixed / openwrt_exact_fixed_version`。机器验证通过不代表人工业务接受；四角色复评最终门禁为 `human_review / evidence_partial`，人工接受仍未完成。

## 第一次真实修复和脚本失败

此前已完成官方 25.12.4 受影响态部署、真实检测、四角色 confirmed_affected 研判及对象级人工审核。原 Harness Run 为 `75bbd6883ec2422c84bcc55deb129b36`，原计划 SHA256 为 `9c50fa58655625884358bd76fba61d73b97edbfa93de4c3eef3f9f083fcd0973`。修复产物 SHA256 为 `fd323f5eabdc0ff60ab53fd4f580bda73eb50ef3beb28b08efef3680ae608440`。首次设备安装成功回执及官方产物溯源保留在本地证据目录。

第一次验证因 `DEFECT-20261019-regression-freshness-tz` 的 SQLite naive UTC 与 aware UTC 比较 TypeError 停在 verification_required。原失败记录未覆盖、未删除。v1/v2/v3 脚本及完整 SHA256 保留在本地材料和哈希索引中。

## 获批只读续验

现有 Harness 增加最小 fail-closed verification-only resume，绑定原 Run、原安装回执、设备连接和产物摘要。新尝试追加审计；API 不接受任意脚本路径；重复批准幂等；身份、授权、计划完整性或设备状态不符即拒绝。

操作员明确批准补充计划 SHA256 `c2dc680ad95e0028ab0f3228fef60b4988aba0c49a6a28fe30bdf1c6f44544d3`；v3 脚本 SHA256 `028c8802f1dfe218b26695cdf5b931b56f00a9237a72e5515ab38a706231fc0f`。未沿用安装审批冒充新脚本授权。

实际执行包括新 Inventory、版本与包范围、LuCI HTTP 200、DNS TCP/53、只读 logread 与时钟检查。新 Inventory 后端接收时间晚于首次安装回执及续验开始。最新 120 行日志无严重模式匹配，保留 odhcpd 无默认路由告警。Harness 正式状态机将原 Run 推进为 verified，attempts=2，但软件包安装次数仍为 1。未直接改数据库状态。

新鲜度实现统一 naive UTC、带时区 UTC 和跨时区同一时刻；缺失、非法、过期、未来及修复前证据 fail-closed。设备时钟不作为后端收据时间。测试覆盖上述语义、时钟偏差和修复后新采集，未以捕获异常后返回 true 代替验证。全量回归为 **783 passed, 5 warnings**；测试结果不替代实际设备验证。

## 风险 272 与正式四角色复评

风险 272 在 Harness 机器验证后为 active=0 / review_status=resolved。现有 post-repair 入口允许对 resolved 风险进行带治理记录的复评，因而不需要伪造 closed 状态打破循环依赖。复评 sink 保留原风险生命周期，追加 post_repair_assessment，并明确 business_accepted=false。

正式入口 run `b4c0526f5045`（内部 `UA-b4c0526f5045-272`）的 asset_investigator、vulnerability_analyst、runtime_analyst、decision_planner 全部真实完成，各一次尝试，无降级；不是复用修复前输出。最终静态适用性 not_affected，package_change=none，建议 monitor/low；门禁 pending_human_review，原因为 evidence_partial。

运行时结论为 insufficient_evidence：logread 拉取能力有限、传感器状态 stopped、coverage unknown、丢失计数不可用，缺少 HTTP 请求和 execve 覆盖；网络时间戳存在未来值，鉴权状态未知，部分外部情报源不可用。未观察到攻击不等于不存在运行时安全风险。模型提出的重启采集器、配置备份及鉴权加固属于未执行建议，不构成本轮授权。odhcpd 告警保留，周期 SSH 会话不可直接推定为攻击。

## 独立授权 C 与真实快照回滚

操作员在本会话明确批准计划 SHA256 `d240601ccb0305af7a495338a3208daad4a11990bfe41d71d965bc37d5b6caf5`。仅操作 Lab VM，S1-AFFECTED uid 2、S2-FIXED uid 3；恢复后重新验证 SSH 钉扎、连接凭据、MAC、IP、主机身份和资产绑定。VMware 实际执行了 revertToSnapshot 和启动，没有安装软件包。

| 阶段 | 新采集 Run | 实际 cgi-io | 通用匹配结果 |
|---|---|---|---|
| 恢复 S1-AFFECTED | `2288ff54fc9d417440e266046357986f` | `2025.12.11~658b14bd-r1` | affected / openwrt_exact_affected_version |
| 恢复 S2-FIXED | `c80ff2ae49a86f1fb6e9b654b0804e7f` | `2026.07.21~31cb3c89-r1` | fixed / openwrt_exact_fixed_version |

两轮均为现有认证采集节点的真实 SSH Inventory，182 包、身份 verified，各生成独立 INV 证据。没有复制旧 Inventory，没有恢复外部数据库，没有手工改风险。原治理事件 369–372、501–502、原 Harness verified/attempts=2 及两份新证据均连续保留。匹配只限 asset 4。最终风险 272 仍为 resolved。

快照同时恢复了设备旧时钟；该偏差如实记录，使用后端接收时间证明本轮新采集，不将设备旧时间当作证据新鲜度。原始 OpenWrt-01 的身份、版本、MAC、182 包及 inventory_collected_at 与回滚前参考逐项一致；没有对原机执行快照或写操作。

## 交付、权限与未完成边界

原始执行证据保留于 gitignored `reports/openwrt-closure-20261019/round2/`；脚本、产物、私钥和清单位于 gitignored 本地材料目录。公开提交仅包含脱敏代码、测试及本报告。生产设备修复开关关闭，实验临时修复写许可关闭；授权 C 已执行完毕，不作为后续操作许可。

完整机器修复/验证/回滚实验已完成；人工业务接受仍未发生，四角色留下的运行时、鉴权和情报覆盖边界仍开放。不能将此报告解释为所有 CVE 均已修复或运行时无风险。没有执行第二次修复，也没有执行模型附加的服务/配置变更。
