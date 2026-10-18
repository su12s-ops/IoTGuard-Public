# Stage 10 第五轮完成记录：真实克隆修复、运行时恢复与超时约束

日期：2026-10-18（Asia/Shanghai）。代码基线 `76eac0b`；本轮承接并保留第四轮未提交改动。本文的当前结论优先于第四轮及更早报告，历史失败证据不覆盖。

## 验收结论

隔离克隆的真实软件包升级、完整复采、官方重新匹配已完成，Harness 状态 `verified`。源 Ubuntu Falco 常驻恢复并连续运行超过 10 分钟，有本轮主动触发的真实事件入库。生产和实验后端最终均关闭设备写及实验写开关，实验执行许可已撤销。前后端服务已恢复，超时缺口已修复并通过回归。

这证明本次隔离实验的技术闭环成立；风险人工裁定、克隆业务接受及生产发布仍有各自门禁，不据此宣称整个项目可稳定生产运行。

## 真实修复与独立复验

- 目标仅为资产 3 / 连接 3，Ubuntu 24.04 noble 克隆 `192.168.183.110`，实验节点 `stage10-lab-clone-node`。源资产 1 未执行本次 CVE 软件包升级。
- 用户先在克隆控制台启动 root runner，并明确要求继续完成缺失部分。新预演记录实际 UID=0、`ready=true`、issues=[]。沿用当前会话授权，审批 actor `codex:operator-authorized-current-chat-20261018`，未编造实名签署。
- 成功修复运行 `ddc385a143ed4a50bb6ef109041155fc`；Trace `TR-20261018112611-7758c7`；最终计划 SHA256 `3684566174c9e815324f8191116f0b4cb1c947b7413dfe5b8e017752f293bf56`。
- 精确升级 `curl`、`libcurl3t64-gnutls:amd64`、`libcurl4t64:amd64`，均从 `8.5.0-2ubuntu10.15` 到 `8.5.0-2ubuntu10.16`。候选来自 Ubuntu noble-security，下载归档与预演 SHA256 一致，执行记录 `command_succeeded`。
- 修复后完整清单 `INV-f82d1efa67e74f1e8f4b5a6e59d24c50`，SHA256 `d3d89baca1d51f640ea8fb039ea36bee3a412cf961f2d4e130ef0b7a676e5f5f`。
- 重新获取 Canonical 原文：`ADV-1cb06180a4dd413b99030d7fc40af833`，2026-10-18T11:26:48.928945 UTC，SHA256 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`。针对该公告/CVE 的三个二进制匹配均 `fixed`，不是对资产所有漏洞的全面消除声明。
- 风险建议 `fixed_pending_human_acceptance`，`original_risk_unchanged=true`；业务接受字段仍为 `requires_isolated_experiment_acceptance`。未自动把生产风险127或126裁定为已关闭。
- 独立 SSH 检查三包均 installed/.16，`dpkg --audit` 空输出，`curl --version` 正常，官方 HTTP 与实验 API 隧道均返回200，各命令退出码0。独立检查源 Ubuntu 三包仍为 .15。

本地回执：`local-archive/stage10-continuation/lab/second-repair-latest.json`、`local-archive/stage10-completion/clone-business-smoke.json`、`independent-package-smoke.json`。后者含实验后端重启时的一次瞬时 HTTP 空响应，后续独立 smoke 的200已验证恢复，未删除失败记录。

## 首次执行失败及恢复

首次 root 计划 `3c089ac1bc2c4b92a65d19d91e4fe0d2` 在下载阶段180秒超时。VMware NAT 网关 `192.168.183.2` 的 ARP 不可达，服务显示 Running 不能证明网关工作。该次未发生 dpkg 安装；正式复验为 `verification_required / version_unchanged`，仍受影响。

当前 Windows 会话不能管理系统服务，用户在管理员 PowerShell 成功重启 VMware NAT Service 后，网关恢复 REACHABLE，Ubuntu 官方 HTTP200。重新生成、预演并审批新计划后完成上述修复；失败计划保留原结果，不改写为成功。

## 授权回收与回滚证据

- 实验环境使用独立数据库、控制/节点令牌、clone-only /32、资产3作用域及隧道18447；生产写开关全程保持关闭。
- 成功后已撤销本地和克隆许可文件，实验后端重启加载 `LAB=0 / DEVICE=0`；生产同为0。root runner 尚可在线，但无有效执行许可。
- 快照 `stage10-baseline-20261017T115000Z` 的实际恢复验证来自前轮客户机标记回滚证据 `local-archive/stage10-work/restore-evidence.json`；本次成功升级后没有再次回滚，避免撤销修复结果。
- 规范化 machine-id SHA256 `0691eeb5df31a579f71cfd893abf592149ba891f86b2ab50b71739b07100e574`；历史含换行原始字节哈希差异已记录，机器身份没有改变。
- 回收回执 `local-archive/stage10-continuation/lab/write-revocation.json`。实验复制库中的旧计划 `1edbaaf5…` 已正式取消。

## Falco 恢复与超过10分钟验收

三个实际原因分别处理：后端只监听 loopback 导致源机无法上传；旧配置令牌401；`Restart=on-failure` 与 `SuccessExitStatus=1` 组合使上传失败退出后不再恢复。后端改为监听0.0.0.0，用户在控制台安装最新0600配置及新systemd单元，单元使用 `Restart=always` / 10秒重试，显式 stop 仍不会重启。

源机 `ActiveEnterTimestamp=2026-10-18 19:26:08 CST`，19:37:01复查仍 active/running，累计 `NRestarts=14` 与本轮恢复成功后的观察值一致，连续10分53秒未再重启。最新覆盖状态 running，心跳21秒；真实事件新鲜度3秒。转发器自报 received2095 / parsed2095 / uploaded2094，rejected0 / retries0 / failed_batches0 / spool_pending0。计数是该时间点快照，received与uploaded瞬时差值不等于丢失；内核 dropped_events 尚不可用，保留 null/unavailable，未虚构为0。

19:36:46 在源机执行无害 curl 请求，带唯一验收标记 `stage10-falco-acceptance-20261018T113650Z`；四条匹配的真实事件入库（ID11406/11407/11408/11410），包含进程执行、服务拉起shell、curl出站。Falco 原生 `source=syscall`，用 `sensor_id=wyh-vmware-virtual-platform:falco` 归属，不能错误按 source=falco 检索。完整证据 `local-archive/stage10-completion/final-verification.json`。临时用户目录中的令牌配置副本已删除，root配置保留。

## 服务、OpenWrt与生产复采

- 前端 `http://localhost:5173` HTTP200；生产API `http://localhost:8000/api/health` 正常，数据库ok；实验API127.0.0.1:18001正常。生产PID5444，实验PID48480为本次验收快照。
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

## 超时修复及回归

LLM等待新增角色绝对截止时间；SDK每次请求的timeout取剩余预算且禁用内部重试；结构化反馈及事实重试共享角色预算；过期运行不再额外获赠5秒。迟到HTTP响应不再恢复工具执行或写库，反馈调用用量不再重复计数。

边界：HTTP工作线程只能隔离/丢弃迟到结果，不声称可强制取消网络请求；迟到响应用量未知；同步只读工具仍不能强制中断。未重新运行42分钟的真实LLM研判，不声称实测新的真实模型总耗时。

- 后端全量 **705通过、0失败**，530.01秒；5个既有datetime.utcnow弃用警告。日志 `local-archive/stage10-completion/backend-tests.log`。
- 新增7项截止时间测试覆盖阻塞HTTP、迟到工具不执行、反馈共享预算、事实重试不重置预算、SDK超时上限；包含在705中。
- 前端 **23通过、0失败**，30.9秒；生产构建通过。
- 根权限门禁后端专项及前端回归保留；部署最终代码前已排空实际队列并一致性备份，备份完整性ok。

## 仍需人工作出的决定

风险126与Q1–Q8对象级裁定、风险12归档确认、未授权补证申请、克隆业务接受仍保留。当前会话对继续技术工作的授权不等于替用户做这些业务裁定。生产软件包写授权未申请、未开启；OpenWrt常驻采集/直接路由完善与长期稳定性验收也不包含在本次完成声明内。
