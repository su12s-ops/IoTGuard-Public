# Stage 10 最终交付核查：克隆修复证据与交付边界

日期：2026-10-18（Asia/Shanghai）。本次核查代码提交为 `da336783904010a3a7f0436c612de86390bd557e`，父提交为 `76eac0b3b734d04dcf6b89d8daaa046f38110d95`。最终核查只读取已有原始证据、数据库与运行状态，修订交付文档；未重新运行四智能体，未操作设备修复、回滚、服务或生产发布。本文当前结论优先于更早报告；原始失败、审批、数据库与日志均保留，不补签、不回写。

## 验收结论

隔离克隆的真实软件包升级、完整复采、官方重新匹配已完成，Harness 状态 `verified`。源 Ubuntu Falco 常驻恢复并连续运行超过 10 分钟，有本轮主动触发的真实事件入库。生产和实验后端最终均关闭设备写及实验写开关，实验执行许可已撤销。前后端服务已恢复，超时缺口已修复并通过回归。

本次完成的是隔离克隆的安装、自动复采与确定性版本核验链。**修复后四智能体复评、最终人工业务接受、修复后真实回滚验证和最终代码的 Docker/nginx 生产部署均未完成。安全扫描仍为 partial / inconclusive，不能声明最终代码通过完整安全验收。** 历史运行状态仅代表记录对应时点，不代表长期稳定性。

## 最终授权链核查

授权一不包含实际软件包安装，也不自动授予授权二。后续独立授权依据来自原始会话，而不是由快照恢复、root runner 启动或旧授权推导：

1. 2026-10-17T13:25:01.932Z（北京时间21:25:01），原始用户答复中保留了询问：“克隆风险 127 的四智能体结论为‘确认受影响、建议修复’，但人工裁定尚为空。请给出你的裁定及审核人名称（例如‘确认风险127并同意在隔离克隆升级这三个 curl 同源包，审核人：××’）。”用户答复“可以的”。本次核查将该上下文中的明确肯定答复认定为后续独立的克隆三包升级授权；用户未提供实名。
2. 2026-10-17T13:26:31.708972Z，风险127治理事件8记录 `human_review / confirm`，actor 为 `operator:29504 (current chat authorization)`。其 payload 中 **`repair_authorization=false`**，说明这条对象级人审本身不是安装许可；不得将该字段改写为 true，或宣称人审自动授予执行权限。
3. 2026-10-18T11:09:20.175Z，用户针对尚缺的实际修复工作回复“我已经执行该指令，请继续这些缺失的部分，确保完成”。结合前述具体升级许可，代理随后完成实验计划审批。启动 root runner 的事实仅证明执行条件，不单独证明授权。
4. 成功运行的 `plan_hash` 与 `approval_hash` 均为 `3684566174c9e815324f8191116f0b4cb1c947b7413dfe5b8e017752f293bf56`，审批 actor 是 **`codex:operator-authorized-current-chat-20261018`**。这属于代理依据用户授权执行的精确计划审批。**未找到用户亲自签署该完整哈希，或逐项复述 LAB 开关/许可字段的消息；不能描述为用户实名或亲自签署哈希。** 不追加或伪造审批。
5. 实验执行回执保留独立实验库、资产3作用域、clone-only 节点、root UID0预演与精确计划许可。许可中的资产3、machine-id SHA256 `0691eeb5df31a579f71cfd893abf592149ba891f86b2ab50b71739b07100e574`、上述计划哈希、`isolated_clone=true`、`restore_verified=true`、快照 `stage10-baseline-20261017T115000Z`、同一审批 actor 及过期时间 `1792323690.7817984` 均有原始执行记录。
6. 运行创建于2026-10-18T11:26:11.607195Z，完成于11:26:48.953896Z，真实 dpkg 执行退出码0。11:27:21.666902Z回收回执记录实验开关0、本地许可不存在、远端许可不存在。本次核查生产与实验配置的两个写开关仍均为0；两个正在运行的后端 `/api/unified/specs` 也均返回 `device_repair_enabled=false / ubuntu_lab_repair_enabled=false`。保持冻结，不进行后续写操作。

授权原始会话分别位于本机 Codex sessions 的 `2026/10/17/rollout-2026-10-17T21-15-46-01a14a01-107a-74b1-8f22-1585ae5bf074.jsonl` 和 `2026/10/18/rollout-2026-10-18T19-01-12-01a14eac-3955-74d1-80d5-3003d81e3c95.jsonl`。只摘录必要语句，不将完整会话、令牌或原始回执发布到公共仓库。

## 真实修复与独立复验

- 目标仅为资产 3 / 连接 3，Ubuntu 24.04 noble 克隆 `192.168.183.110`，实验节点 `stage10-lab-clone-node`。源资产 1 未执行本次 CVE 软件包升级。
- 用户在克隆控制台启动 root runner；新预演记录实际 UID=0、`ready=true`、issues=[]。授权与代理审批的区别见上节，不能仅以 runner 已启动代替安装授权。
- 成功修复运行 `ddc385a143ed4a50bb6ef109041155fc`；Trace `TR-20261018112611-7758c7`；最终计划 SHA256 `3684566174c9e815324f8191116f0b4cb1c947b7413dfe5b8e017752f293bf56`。
- 精确升级 `curl`、`libcurl3t64-gnutls:amd64`、`libcurl4t64:amd64`，均从 `8.5.0-2ubuntu10.15` 到 `8.5.0-2ubuntu10.16`。候选来自 Ubuntu noble-security，下载归档与预演 SHA256 一致，执行记录 `command_succeeded`。
- 修复后完整清单 `INV-f82d1efa67e74f1e8f4b5a6e59d24c50`，SHA256 `d3d89baca1d51f640ea8fb039ea36bee3a412cf961f2d4e130ef0b7a676e5f5f`。
- 重新获取 Canonical 原文：`ADV-1cb06180a4dd413b99030d7fc40af833`，2026-10-18T11:26:48.928945 UTC，SHA256 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`。针对该公告/CVE 的三个二进制匹配均 `fixed`，不是对资产所有漏洞的全面消除声明。
- 风险建议 `fixed_pending_human_acceptance`，`original_risk_unchanged=true`；业务接受字段仍为 `requires_isolated_experiment_acceptance`。未自动把生产风险127或126裁定为已关闭。
- 独立 SSH 检查三包均 installed/.16，`dpkg --audit` 空输出，`curl --version` 正常，官方 HTTP 与实验 API 隧道均返回200，各命令退出码0。独立检查源 Ubuntu 三包仍为 .15。

本地回执：`local-archive/stage10-continuation/lab/second-repair-latest.json`、`local-archive/stage10-completion/clone-business-smoke.json`、`independent-package-smoke.json`。后者含实验后端重启时的一次瞬时 HTTP 空响应，后续独立 smoke 的200已验证恢复，未删除失败记录。

### 原始 INV、官方原文与复评边界

本次以 SQLite 只读方式核对原始清单，重新计算 raw_text SHA256，均与库中 content_sha256 一致。三个 curl 同源包在各清单中版本一致，包数均为1790。

| 证据 | UTC时间 | 三包版本 | 原文 SHA256 |
|---|---|---|---|
| 克隆初始 `INV-3bef62a8eb2a912606f16643299b54e9` | 2026-10-17 12:05:21.999341 | `.15` | `caaa508318ad3cff91b0e85bb03a5e5f6d02c9d1c79ff0e8d1adbde1bc208b92` |
| 失败尝试后、成功重试前 `INV-f6d32bd93c7f43bfbae8c3338c2edca6` | 2026-10-18 11:21:13.228334 | `.15` | `d69d8a598626cac5fadfed0b9bb4a447da451fa488719e6eb8dcec0c5dffbb97` |
| 成功后自动复采 `INV-f82d1efa67e74f1e8f4b5a6e59d24c50` | 2026-10-18 11:26:47.205041 | `.16` | `d3d89baca1d51f640ea8fb039ea36bee3a412cf961f2d4e130ef0b7a676e5f5f` |
| 生产侧独立采集克隆 `INV-ce6ef85e4765550a80ac39052f9bb576` | 2026-10-18 11:32:07.393647 | `.16` | `65a464ff5267884f7a0ff96b9f8ddb2a2fe5313754b8f7dba06cf61ccfac0bcd` |
| 生产侧源资产1 `INV-3c1e621d46a49aff3dbb9e21215bde4d` | 2026-10-18 11:32:09.389618 | `.15` | `5e888963e7fdaf25f36f0bd40b21acacbb4915072e3a94fc2c3d073a450d396d` |

成功复采别名为 `INV-ddc385a143ed4a50bb6ef109041155fc-post`；前一次别名为 `INV-3c089ac1bc2c4b92a65d19d91e4fe0d2-post`。计划内规范化清单哈希 `4866d9ab3a6fb258463e79eaa8847aa986ad4ede993ed1c2f4290530bc662eb8` 与上述原始文本哈希语义不同，不能混用。

官方依据是 [Canonical CVE JSON](https://ubuntu.com/security/cves/CVE-2026-94266.json) 中的 **USN-8932-1 / noble / curl / 8.5.0-2ubuntu10.16**。`ADV-1cb06180a4dd413b99030d7fc40af833` 的 raw_json 哈希已复算相符。原文的 `canonical_table_status=needed` 与公告推导的可用修复状态同时保留；不覆盖原始字段，也不将 resolute 的 USN-8927-1 混为 noble 公告。2026-10-18T11:26:48.950606Z，工具记录83 `ubuntu_official_rematch` 对三包分别返回 `fixed / affected=false / installed_version_fixed`；安装核验为 `fixed_version_verified`。

两库对风险127均仅有修复前四智能体运行 **`UA-b522f38df422-127`**（2026-10-17T12:10:01.978796Z至12:28:43.099281Z），四角色均 succeeded、无错误，结论为 confirmed_affected、待人工复核及 monitoring_missing。**没有修复后四智能体运行**；计划引用的旧 agent_evidence_ids 不能充当新复评。修复后确定性匹配通过不等于四智能体复评通过，更不等于最终业务接受。风险127仍为 `human_confirmed / confirmed_affected / active=1`，未关闭；报告中的 smoke 仅证明有限技术检查，不是用户人工业务签收。

### 源资产1与正式风险126

生产当前风险126与 `production-before-start.db`、`before-final-deploy.db` 两份本轮基准备份的完整行逐字段相同，规范化 JSON SHA256 为 `dee546adc53ccabe62351d1cb52d65fa30dd36426e8aaa185e15d18a91eb8fcd`。保持资产1、active=1、`pending_human_review / confirmed_affected / human_review_required=1`；克隆执行运行未写入生产 Harness 运行表。克隆修复结论仅关联资产3。

“保持原样”限定于本轮克隆修复前后：更早官方复核曾使风险126进入 reanalysis_required，第四轮正式复评 `UA-ada3c8644aab-126` 于2026-10-17T14:05:23Z完成并回到 pending_human_review，历史保留，不能宣称整个 Stage 10 从未变化。源资产1采集元数据、last_seen及 Falco 状态有正常业务更新，不能声称资产整行逐字不变；三个源包仍为 `.15`。

## 首次执行失败及恢复

首次 root 计划 `3c089ac1bc2c4b92a65d19d91e4fe0d2` 在下载阶段180秒超时。VMware NAT 网关 `192.168.183.2` 的 ARP 不可达，服务显示 Running 不能证明网关工作。该次未发生 dpkg 安装；正式复验为 `verification_required / version_unchanged`，仍受影响。

当前 Windows 会话不能管理系统服务，用户在管理员 PowerShell 成功重启 VMware NAT Service 后，网关恢复 REACHABLE，Ubuntu 官方 HTTP200。重新生成、预演并审批新计划后完成上述修复；失败计划保留原结果，不改写为成功。

## 授权回收与回滚证据

- 实验环境使用独立数据库、控制/节点令牌、clone-only /32、资产3作用域及隧道18447；生产写开关全程保持关闭。
- 成功后已撤销本地和克隆许可文件，实验后端重启加载 `LAB=0 / DEVICE=0`；生产同为0。root runner 尚可在线，但无有效执行许可。
- 快照 `stage10-baseline-20261017T115000Z` 的实际恢复验证来自前轮客户机标记回滚证据 `local-archive/stage10-work/restore-evidence.json`：客户机内 r3 标记在恢复后消失，机器身份一致，基准 `.15` 与启动检查通过。早期离线标记无效尝试仍保留，未计为通过。**实际完成的是基准快照恢复验证；未执行升级后的 `.16→.15` 真实回滚，未验证修复后回滚路径。** 许可的 `restore_verified=true` 只引用基准验证，不授予今后的回滚权限。
- 规范化 machine-id SHA256 `0691eeb5df31a579f71cfd893abf592149ba891f86b2ab50b71739b07100e574`；历史含换行原始字节哈希差异已记录，机器身份没有改变。
- 回收回执 `local-archive/stage10-continuation/lab/write-revocation.json`。实验复制库中的旧计划 `1edbaaf5…` 已正式取消。

## Falco 恢复与超过10分钟验收

三个实际原因分别处理：后端只监听 loopback 导致源机无法上传；旧配置令牌401；`Restart=on-failure` 与 `SuccessExitStatus=1` 组合使上传失败退出后不再恢复。后端改为监听0.0.0.0，用户在控制台安装最新0600配置及新systemd单元，单元使用 `Restart=always` / 10秒重试，显式 stop 仍不会重启。

源机 `ActiveEnterTimestamp=2026-10-18 19:26:08 CST`，19:37:01复查仍 active/running，累计 `NRestarts=14` 与本轮恢复成功后的观察值一致，连续10分53秒未再重启。最新覆盖状态 running，心跳21秒；真实事件新鲜度3秒。转发器自报 received2095 / parsed2095 / uploaded2094，rejected0 / retries0 / failed_batches0 / spool_pending0。计数是该时间点快照，received与uploaded瞬时差值不等于丢失；内核 dropped_events 尚不可用，保留 null/unavailable，未虚构为0。

19:36:46 在源机执行无害 curl 请求，带唯一验收标记 `stage10-falco-acceptance-20261018T113650Z`；四条匹配的真实事件入库（ID11406/11407/11408/11410），包含进程执行、服务拉起shell、curl出站。Falco 原生 `source=syscall`，用 `sensor_id=wyh-vmware-virtual-platform:falco` 归属，不能错误按 source=falco 检索。完整证据 `local-archive/stage10-completion/final-verification.json`。临时用户目录中的令牌配置副本已删除，root配置保留。

本次核查还读到了新的心跳2026-10-18T11:46:13.323090Z，读取时 API 心跳新鲜度2秒、事件4秒。历史唯一标记事件的原始发生/入库时间如下；入库时间比客户机事件时间早约70–86ms，存在主客机时钟偏差，不能据此声称已测得正向端到端延迟或时钟完全同步。

| 事件ID | occurred_at（UTC） | created_at入库（UTC） |
|---|---|---|
| 11406 | 2026-10-18T11:36:46.523530731Z | 2026-10-18T11:36:46.452360Z |
| 11407 | 2026-10-18T11:36:46.523530731Z | 2026-10-18T11:36:46.454308Z |
| 11408 | 2026-10-18T11:36:46.528341629Z | 2026-10-18T11:36:46.455806Z |
| 11410 | 2026-10-18T11:36:46.544102015Z | 2026-10-18T11:36:46.458403Z |

## 服务、OpenWrt与生产复采

- 前端 `http://localhost:5173` HTTP200且包含 `/@vite/client`，明确为 **Vite开发页面**。主机生产数据API `http://localhost:8000/api/health` 正常，数据库ok；实验API127.0.0.1:18001正常。历史生产PID5444、实验PID48480仅为当时快照，不作为持续进程承诺。
- 生产唯一统一四智能体 mode=on / formal_writer=unified，源与克隆两个采集节点在线。生产没有运行中的统一研判，两库 Harness 资产锁均0，完整性检查均ok。
- 实验库是第四轮生产备份，保留风险126的一条历史 running 快照记录，未在实验环境启动该研判；它不是活跃执行进程。两库另有历史 `awaiting_preflight` 草案，不能把全部历史非终态称作已清空。
- OpenWrt原VM处于关机，已无界面启动并恢复源机到192.168.100.1的既有路径。经源 Ubuntu 跳板、原SSH密钥和登记主机指纹，执行固定只读logread采集，通过现有batch API入库1260条新事件、16条去重；最后事件时间2026-10-18T11:30:40Z。未新建数据管线或伪造日志。
- Windows直接调用连接1的collect-logs路由仍因网络不可达返回400；成功的是上述跳板只读采集及现有批次入库。OpenWrt是按需pull，心跳随后stale，不能宣称常驻eBPF或所有传感器健康。该限制保留。

正式生产清单采集均 completed（只采集，不自动改变风险裁定）：

| 资产 | 清单数量 | 运行 / 清单证据 |
|---|---:|---|
| 源Ubuntu 1 | 1790 | `3c1e621d46a49aff3dbb9e21215bde4d` / `INV-3c1e621d46a49aff3dbb9e21215bde4d` |
| 克隆Ubuntu 3 | 1790 | `ce6ef85e4765550a80ac39052f9bb576` / `INV-ce6ef85e4765550a80ac39052f9bb576` |
| OpenWrt 2 | 182 | `58e96457521d599ee34698a90286b834` / `INV-58e96457521d599ee34698a90286b834` |

Docker/nginx 核查：`127.0.0.1:18080` 是 nginx SPA200入口，无 Vite client，经反代访问后端健康接口200；对应 Docker 后端绑定 `127.0.0.1:18000`。8080未监听。容器创建于2026-10-17T08:49:40Z，Docker数据视图无登记节点/传感器，与主机8000的实际业务库不同。

- 后端镜像：`sha256:67f9632944953e7cb36e172167ed8c8f6acc777c4ab88d98b3eb26d5d496493e`。
- 前端镜像：`sha256:967623949d9c7f39f560a9029000129b50a350abce0adc10e163e74b10bc9e59`。
- 对容器 `/app/app/services/agent_infra.py`、`unified/agent_base.py`、`ubuntu_repair.py` 做只读 SHA256 比较，三者均与当前工作区不同。例如 agent_infra 容器哈希 `42f96029b9409e60b7d8f14c9357036ffcdcf1ceca39b402d86aa2b22f8d4a65`，当前提交文件哈希 `63925d79517e472c3a7115b8c28d51b2712a2247653e7b47b46f228c1e34520d`。

因此 Docker/nginx 证明的是**较早镜像的打包入口可用**，不能认定为 `da33678` 最终代码已生产部署。最终状态是代码交付、开发页面和主机业务服务可用，Docker入口存在但版本滞后；本次不构建、不重启、不部署。

## 超时修复及回归

LLM等待新增角色绝对截止时间；SDK每次请求的timeout取剩余预算且禁用内部重试；结构化反馈及事实重试共享角色预算；过期运行不再额外获赠5秒。迟到HTTP响应不再恢复工具执行或写库，反馈调用用量不再重复计数。

边界：HTTP工作线程只能隔离/丢弃迟到结果，不声称可强制取消网络请求；迟到响应用量未知；同步只读工具仍不能强制中断。未重新运行42分钟的真实LLM研判，不声称实测新的真实模型总耗时。

- 后端全量 **705通过、0失败**，530.01秒；5个既有datetime.utcnow弃用警告。日志 `local-archive/stage10-completion/backend-tests.log`。
- 新增7项截止时间测试覆盖阻塞HTTP、迟到工具不执行、反馈共享预算、事实重试不重置预算、SDK超时上限；包含在705中。
- 前端 **23通过、0失败**，30.9秒；生产构建通过。
- 根权限门禁后端专项及前端回归保留；历史主机服务恢复前排空队列并一致性备份，备份完整性ok；这不证明最终 Docker 镜像已部署。

### 测试、扫描与实际提交对应关系

原始会话记录表明：截止时间代码修改在2026-10-18T11:13:28Z，7项测试新增于11:14:52Z，后端全量与前端 build/e2e 于11:20:14Z启动；前端结果11:21:26.839Z为23通过，后端结果11:29:32.814Z为705通过。`da336783904010a3a7f0436c612de86390bd557e` 于11:39:49Z提交；本次核查开始时工作区干净，未改源码。测试对应该次提交包含的后端/前端实现；它们是提交前本地执行证据，**没有当时整树 Git tree 哈希绑定或 CI 签章，不宣称最终提交的完整整树认证**。

测试启动后11:20:44Z仍修改过 Falco systemd单元与脚本，11:21:02Z修改其说明文档。这些采集部署材料不在705项后端/23项前端覆盖范围内；其运行验证依据是本报告的实际 Falco 事件与连续运行记录。归档 `evidence-manifest.json` 的14项原始证据哈希已逐项复算相符。文档核查不需要重跑昂贵研判或全量测试；最终文档变更另以 diff检查和敏感检查验证。

已有安全扫描 `scan-2026-10-17T09-08-58.996Z-4dc68ad6cebb`，seal `sha256:53c54180ef65df31cf37704572b2bfe31f23998c9a8d37bd871c59795f3a8822`，结论为 **`completeness=partial / runStatus=inconclusive`**、threatModel入口点0。它早于本次代码提交，不能作为 `da33678` 或最终文档提交的安全全通过证明。其 write_private 路径穿越提示已有人工审查记录及 local-archive 路径包含加固；保留发现与误报判断，不把它改成扫描通过。本次没有可用的新扫描器，未生成新的完整安全扫描；公开交付不等于生产安全验收。

## 公开交付与证据保管

最终核查查到了后续独立的三包升级许可，并按原始问答上下文核定其范围；精确计划审批的代理身份已明确披露，没有因此补签或扩大授权。未确认新的安全阻断，但扫描覆盖不完整仍是明确的验收限制。本次仅授权文档与 Git 交付，生产两个写开关继续为0，不再操作设备。

敏感检查覆盖333个受跟踪文件、原本待推送的21个新增/变更blob，使用本地环境中的7个实际敏感值做不输出内容的精确匹配，并检查私钥、常见访问令牌和危险文件路径；未发现命中。该检查是公开仓库泄密检查，不代替安全漏洞扫描。最终文档提交前再次执行暂存差异和忽略规则检查。

凭据、原始数据库/日志/清单/会话与虚拟机材料不加入 Git：`local-archive/`、`backend/data/`、环境私密配置、密钥、VM文件与日志仍受忽略规则保护。原始材料不删除、不改写；只交付必要的文档结论与既有代码提交。最终推送结果与完整 Commit Hash 以交付回复及远端读回核对为准，不在推送前预写成功声明。

## 仍需人工作出的决定

风险126与Q1–Q8对象级裁定、风险12归档确认、未授权补证申请、克隆业务接受仍保留。当前会话对继续技术工作的授权不等于替用户做这些业务裁定。生产软件包写授权未申请、未开启；OpenWrt常驻采集/直接路由完善与长期稳定性验收也不包含在本次完成声明内。
