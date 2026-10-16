# IoTGuard Stage 9B M4.4 真实漏洞闭环验收

日期：2026-10-16（Asia/Shanghai）。基线：`dfb9b60`。本轮仅在 IoTGuard-Public 开发与交付。
**正式入口仍为 System B；LINUXGUARD_UNIFIED_PIPELINE=off；设备修复写开关关闭。**

## 1. 实际结果

| 验收项 | 真实结果 |
| --- | --- |
| CVE-2026-63073 纠正 | Ubuntu noble / openssl 为官方 not-affected；历史风险 12 退为非活跃，纠正记录 #9 保留前后依据和 8 次旧影子运行关联 |
| 产品内自动采集 | Windows 后端授权创建任务 → 已认证 Linux 节点常驻领取 → 固定 Collector → 原始证据入库；OpenWrt 182 包、Ubuntu 1790 包均成功，不依赖手工上传 |
| 可信真实漏洞 | 资产 1：curl/libcurl `8.5.0-2ubuntu10.15`；CVE-2026-94266；Canonical USN-8932-1 给出 noble 修复版本 `8.5.0-2ubuntu10.16` |
| 四智能体 | `m44-real-841d76e9aa` completed，四角色真实调用、零降级；不是规则直通或合成案例 |
| 研判 | confirmed_affected；scheduled_fix；static_evidence_only；stale_verified；人工门禁 pending_human_review，置信度 0.60 |
| 影子隔离 | 该运行前后 **126 条正式 RiskAssessment 的全部字段一致**；16 条既有影子记录全文保持不变 |
| Harness | 同风险、同影子计划哈希关联；只读调查 needs_evidence；修复 blocked；错误审批和执行均 409；未授予任何修复授权 |
| 一致性 | 数据库、原始证据、Trace、计划和历史纠正 **11/11** 检查通过；计划关联 39 个真实原始证据 ID，全部可解析 |
| OpenWrt CVE | 本轮产品内新鲜采集完成；官方限定匹配真实 0 条，不伪造适用漏洞 |
| 回归 | **677 passed / 0 failed**；22 项 M4.4 必要回归；相关采集/Harness 专项 86 passed；前端构建通过 |

## 2. 原错误与通用纠正

M4.3 将 Ubuntu 安装版 `3.0.13-0ubuntu3.16` 与上游修复版 `3.4.7` 比较，给出 potentially_affected 并建议升级 openssl。该跨分支比较不能证明 Ubuntu 漏洞适用性。

本轮重新采集确认：Ubuntu 24.04；`/usr/bin/openssl` 属于 openssl 包；实际 CLI 与动态链接的 libssl/libcrypto 均为 OpenSSL 3.0.13；dpkg 源包版本为 `3.0.13-0ubuntu3.16`。本地 apt 元数据列出 noble-updates/noble-security 官方包来源。这里的来源证据是已安装包元数据和本地仓库策略，不宣称重新验证过所有已安装文件的签名或字节完整性，也未执行 apt update。

[Canonical CVE 官方记录](https://ubuntu.com/security/cves/CVE-2026-63073.json) 对 noble/openssl 明确为 not-affected；[USN-8678-1](https://ubuntu.com/security/notices/USN-8678-1) 也将该问题限定于 Ubuntu 26.04。**本例是分支不适用，不应描述成“已证实该 CVE 被 noble 回移植修复”。**

- 纠正 #9：风险 12 / 原匹配 87 → 官方分支匹配 435（not_affected，fixed_version 为空）；旧风险和 8 次关联影子结果保留。
- 原始官方证据 `ADV-3965853ccfbe4820a174c680209e02bb`；SHA256 `b4891e8f30cbdc5d957c5541dda945237a7bc70f045c62ff5dd2422ed9f7ecaa`。
- `canonical_official.py` 保存原始 JSON、内容摘要、来源 URL、取得时间和失败状态；`ApplicabilityCorrection` 保存前后结论及历史运行关联。M4.3 报告顶部已加纠正说明。
- 匹配规则通用处理所有 Ubuntu 候选：官方精确发行版/源包状态优先；厂商记录缺失时，上游比较只保留候选语义，不能据此确认受影响或已修复；官方状态不得继承另一分支的上游修复版。
- 修正统一证据预取与路由对 `CVE:release:package` 的错误解析；同步统一发行代号映射；ignored 不再等价于 not-affected。

共对 **126 个真实候选 CVE** 发起官方核验，51 个取得可用官方记录，75 个尚无可用记录（不可达、限流或官方未提供对应条目等，均逐次留痕，不能当作“不受影响”）。产生 15 条适用性纠正：8 条转 not_affected，7 条转 fixed。仍有 110 条 active unknown 候选，未冒充确认漏洞。

## 3. 自动采集与身份边界

沿用 `DeviceConnection → HarnessRun/锁 → collection_tasks → 固定 Collector → asset_parser`。新增 pull 节点 runner，不新增执行框架。

| 设备 | 验收采集任务 | Trace / 原始证据 |
| --- | --- | --- |
| OpenWrt / 资产 2 | `70d2a8fcd4763086374ea97292756c62` | `TR-20261016135126-635a99` / `INV-70d2a8fcd4763086374ea97292756c62` |
| Ubuntu / 资产 1 | `07beb2493127f6e0daae34ed2c0eefc7` | `TR-20261016135128-809fe5` / `INV-07beb2493127f6e0daae34ed2c0eefc7` |

OpenWrt 使用既有 ED25519 私钥环境变量引用、授权地址白名单及受信 SSH 指纹。Ubuntu 是明确绑定该资产的节点本机采集，身份标为 authenticated_collection_node；SSH 字段为 not_applicable，**没有伪装为 SSH 核验成功**。原始 stdout 以 INV 记录和 SHA256 保存在数据库，成功提交后原子更新资产；失败保留旧清单，不能显示为本轮成功。

节点独立认证 `X-Collection-Node-Token` 与产品控制令牌分离；校验节点登记、Linux 平台、任务领取状态、计划/连接/脚本摘要、SSH 认证声明、输出摘要/字节数及资产身份。节点只收到环境变量名，不收到私钥内容。Windows 仍不执行产品设备 SSH。验收时通过钉扎 SSH 回环隧道连接 Linux 常驻 `--serve` runner，没有放开防火墙或新增远程写命令。

主要接口：`POST /api/iot/connections/{id}/collection-runs`、`POST /api/iot/collection-runs/{id}/execute`、`GET /api/iot/collection-node/claim`、`POST /api/iot/collection-node/results/{id}`、`GET /api/iot/collection-evidence/{evidence_id}`。配置说明见 `backend/.env.example` 和 runner 文档。

## 4. 可信 curl 业务链与四智能体

真实安装包与源包：curl、libcurl4t64 等属于 curl 源包，版本 `8.5.0-2ubuntu10.15`。相关原始清单 `INV-1da86ccfed562d2bf9c3ab02311de333`（本轮较早的一次真实节点采集，原文留存，不以最终重采覆盖历史）。

官方证据：`ADV-473f76939811489caab6009b0f648be1`，来自 [Canonical CVE JSON](https://ubuntu.com/security/cves/CVE-2026-94266.json)。[USN-8932-1](https://ubuntu.com/security/notices/USN-8932-1) 的 noble/curl 源包修复版为 `8.5.0-2ubuntu10.16`。[curl 上游公告](https://curl.se/docs/CVE-2026-94266.html) 解释了 `.netrc` 凭据可能泄漏到 effective URL 的前置条件。

官方 CVE 状态表仍为 needed，而同一原始 JSON 内的 USN 已给出修复版本。本轮同时保留 canonical_table_status=needed、USN 编号、精确 release/source-package/version 及差异说明，再采用该发行版 USN 的修复信息；不使用 resolute 或上游 8.23.0 版本代替 noble 修复包。

业务链：资产 1 → 匹配 `CVE-2026-94266:noble:curl` → 风险 126 → INV/ADV/SE 原始证据 → `m44-real-841d76e9aa` → `TR-20261016135101-38986d` → 确定性人工门禁 → 待审批计划 → Harness 调查与拦截。

四角色全部实际成功：asset_investigator（6 次工具调用）、vulnerability_analyst（4 次）、runtime_analyst（日志显示 10 次工具调用，经过有界结构校验）、decision_planner（直接消费前三者报告、确定性事实与补查结果）。Runtime 输出 7 条发现，引用 7 个真实 SE ID，例如 `SE-dc5caea23dd3f7eb`、`SE-b714b73573711a88`，记录历史巡检/转发器行为与无 curl 特异证据的缺口；不把这些行为解释为该 CVE 已利用。Decision Planner 最终确认静态适用性，并独立将动态证据标为 stale_verified / monitoring_unavailable。

本轮修复两项真实运行阻塞：官方状态包单记录结构被当成列表，导致真 ADV ID 被错判自造；模型回显 JSON Schema 被默认值解析成“成功的空运行时报告”。两者均已进入业务层回归和有界校验，未做刷分实验。失败运行 `m44-real-0f50c24861` 与空报告运行 `m44-real-33395231a5` 均保留，不作为最终验收结果。

## 5. 处置与 Harness

候选计划区分 update_package curl（漏洞修复）、forwarder spool 备份（回滚准备）、Falco 采集链恢复（采集器健康恢复）、只读验证与回滚要求。源包/已安装二进制映射与同发行版修复版本由 plan_guard 复核；引用原始证据、关联 risk-126，所有动作 requires_approval=true。

注意：本轮只读检查显示 Falco 服务 active，但产品心跳过期；这说明转发/上报链仍需排查，**不能据过期心跳断言 Falco 进程停转**。模型提出的恢复/重启项仍须核实单元、通道、spool 与业务影响后人工审阅，既非已执行动作，也非 CVE 修复成果。未检查 `.netrc` 内容或读取用户凭据。

- 只读调查：`2dc572f6d9ad41b9abd0168063d37ba2` / `TR-20261016135715-e882c9`，needs_evidence，零 side_effect 工具调用。
- 修复门禁：`8e4241c90c4c4687840647046c33bf41` / `TR-20261016135716-1a5c16`，blocked：现有 Harness 设备修复仅支持完整 OpenWrt 清单、正式授权风险与登记产物；Ubuntu 不满足，不扩展授权。
- 两任务的假哈希审批及无资格审批均 409；blocked 修复执行 409。影子计划只提供 provenance/plan_sha256，authorization=none；无修复审批、设备安装、配置修改、真实回滚或自动补丁。
- Ubuntu 调查复用已有数据库清单检查，避免误下发 OpenWrt Collector。未重建第二套执行框架或改变现有 Harness 审批规则。

## 6. 前端与验证

复用物联网接入、资产抽屉、风险详情与 AgentOps：展示采集节点、任务/INV/Trace、身份方式、失败原因；查询 Canonical 原始记录和纠正 #9；明确候选/不受影响/已修复；同一风险详情关联官方公告及最终影子运行；AgentOps 展示四角色真实输出/引用、静态结论与运行时缺口、动作分类及两条 Harness 结果。浏览器实测通过，截图保存在本地证据目录。另从正常前端按钮发起 Ubuntu 采集，任务 `58ff0db47893fdf35428161426d330c5` 由常驻节点自动完成 1790 包采集，生成 `INV-58ff0db47893fdf35428161426d330c5` / `TR-20261016141113-cb9889`，不是操作员代为逐次 SSH。

运行器 `backend/scripts/m44_real_cve_closure.py` 提供 collect / verify / shadow / harness / validate 五阶段。影子入口仍直接复用原 LangGraph runner（sink=None），仅隔离验收请求完整四角色，不切换全局 flag。

测试：`python -m pytest -q` → **677 passed，0 failed，5 个既有 utcnow 弃用警告，487.00 秒**；必要 M4.4 专项 22 passed；采集/Harness 相关专项 86 passed；`npm run build` 通过。未扩展无关实验案例。

Mimosa 深度扫描：`scan-2026-10-16T14-09-21.519Z-da2ab63a6201`，0 findings，seal `sha256:f1a18ebd1b11ee95b113717e1d714bd1499946a0e4bcf867a58b2177f6f1f954`。工具覆盖为 **partial / inconclusive**（223 文件解析无失败，但威胁建模及发现阶段覆盖不完整），不宣称全局安全证明。此前发现的验收 HTTP 客户端 SSRF 告警已通过固定回环 http.client、无重定向方式修复。最终封印与敏感检查详情见 `ai_collaboration/TEST_RESULTS.md`。

敏感检查：本轮改动逐文件与本地凭据值比对、私钥材料扫描均无发现；Mimosa Git 历史凭据扫描无发现。真实清单、业务库、地址、节点日志和截图仅在 gitignored `reports/m44-work/`，不推送。

## 7. 未完成的真实环境边界

1. 75 个候选尚无可用 Canonical 记录；继续保持待核验，不归入确认漏洞。
2. 运行时证据约 48.7 小时前，转发链/心跳未恢复；没有新鲜 curl 行为或 CVE 利用证据。本轮不擅自重启服务或修改探针。
3. 主机端口-进程关联、外部可达性及实际 `.netrc`/effective URL 使用方式仍有缺口，不把候选漏洞说成正在利用。
4. Ubuntu 真实修复执行不在现有设备 Harness 的支持/授权范围；本轮仅验证候选与拒绝路径，真实执行需另行隔离实验方案和明确批准。
5. 节点服务当前由开发会话中的已认证进程承接；重启开发后端/采集节点后需重新提供环境变量并启动 runner，不将临时会话误报为已部署持久 systemd 服务。

## 8. Git 交付

实现及实机验证提交：`c7ca5a3e2a558b52799c4b113643e25ab3ac44c7`（已推送）。最终报告/协作文档提交可用 `git log -1 --format=%H -- IOTGUARD_REAL_CVE_CLOSURE_REPORT.md` 精确解析；最终完整哈希同时在交付消息给出。仅推送 IoTGuard-Public；完成后停止，不切换 flag、不退役旧编排器、不执行真实修复。
