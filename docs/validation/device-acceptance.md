# 设备验收与收尾

> 下文包含 2026-10-19 至 20 的设备验收记录和验收要求，旧实例数量不作为当前部署。当前单网关状态见 [项目状态](../status.md)。

更新：2026-10-19。本轮使用现有 VMware OpenWrt 原机、独立 OpenWrt-Lab 与 QEMU Zephyr；Ubuntu 仅作为采集及构建基础设施。没有实体板卡验收，不将虚拟设备结果外推至硬件。

## 本轮已完成

| 对象 | 重新执行的检查 | 结果 |
|---|---|---|
| 宿主控制面 | 停止状态确认、无活动研判/资产锁检查、SQLite 一致性备份、API 恢复、节点重连 | API 正常；模型已配置；原有采集节点自动重连 |
| OpenWrt 原机 | SSH 指纹钉扎、新完整清单、原机身份与包集合对比、HTTP、DNS TCP 查询、匿名访问检查 | 182 包；身份及包集合不变；LuCI 受保护页面 403；匿名 ubus 拒绝；DNS 有效响应 |
| OpenWrt-Lab | 独立连接同项检查、cgi-io 精确版本、通用匹配器再匹配、日志周期回传 | 182 包；身份及包集合不变；cgi-io 精确 fixed；HTTP/DNS/匿名访问检查通过 |
| Zephyr | 身份、RTOS/应用版本、熵自检、错误路径与方法、分片请求、空闲及超长客户端恢复、20 次读取、平台复采；受控重启后重跑回归 | RTOS 4.4.2 / 应用 0.3.0；重启前后 HTTP 回归均通过；约 11.85 秒恢复，身份/版本不变 |
| Ubuntu Falco | 管理员启动服务、BPF 探针、仅允许既有节点的 VMnet 回传、带标识只读请求与真实事件核对 | 已恢复；进程/网络验收事件入库；与两台 logread 合计 3/3 传感器健康 |
| 历史闭环连续性 | 原 Harness、历史风险、安装调用次数与验收前对比 | 原 Harness verified / attempts=2、风险 resolved；安装仍为一次，未重复执行 |

OpenWrt 原机与 Lab 的 logread 现已回传近期证据；它们不是 eBPF，也不能提供完整 HTTP/execve 覆盖或证明没有攻击。Zephyr 的温湿度为模拟数据；熵源依赖受信任 QEMU 宿主，不能外推到实体板。

## 安全验收仍开放的项

1. 本轮 OpenWrt 匹配仍包含 CVE-2026-62948 的 LuCI/odhcpd 分支候选。进一步通过钉扎 SSH 只读确认两台设备均启用 DHCPv6 server、RA server，odhcpd 运行并监听 UDP/547，记录了二进制与 LuCI 文件哈希。[官方公告](https://github.com/openwrt/openwrt/security/advisories/GHSA-hhmc-92hw-535f)描述的链路涉及 DHCPv6 主机名写入和管理员租约页面；因此相关前置条件不能以“不存在”排除。本轮未发送注入载荷、未改租约或网络配置，源码/补丁适用性仍未闭合，不能因 cgi-io 已修复而接受所有漏洞。
2. Zephyr 官方匹配：0 条精确确认受影响、54 条 potentially_affected、71 条 insufficient_data、156 条 not_in_reported_range。候选和证据不足均不是已确认漏洞，也不能当作已排除；尚需逐条 Kconfig/组件/链接及可达性核验。
3. Ubuntu Falco 初始停止，管理员已启动。现有服务回传至宿主 VMnet 地址，本轮用仅允许该注册节点的本机转发恢复连接，未修改远程凭据；真实只读验收请求已有进程与网络事件回执。其丢失计数仍 unavailable，不能写成 0；Ubuntu 探针也不替代 OpenWrt 或 RTOS 的运行时覆盖。
4. 本轮新清单的正式修复后复评已结束，约50分18秒；报告为 human_review，门禁 pending_human_review。资产、运行时、决策角色完成，漏洞角色引用未注册的外部编号/URL/哈希作为系统证据ID，被拒绝并降级；补查未取得合格报告。门禁保留 agent_degraded、confidence_below_0.70、evidence_partial，不能记为完整四角色通过；原始失败与补查回执均保留。
5. 人工业务签收由操作员明确记录；机器检查、模型建议与用户要求“进行验收”不自动构成签署接受剩余风险。本轮没有代签。
6. Zephyr 签名 OTA、设备侧镜像验证、断电恢复和实体硬件仍未实现/验收。本轮没有刷写固件、降级软件包或重复快照操作。

## 逐设备验收记录

每个资产单独留一份验收记录，不能用网关通过替代 LAN 设备通过，也不能用模拟器结果
替代真实固件。记录代码提交、资产/设备身份、固件/内核/板卡、采集器版本和配置哈希、
授权范围、开始/结束时间、原始回执路径及哈希。逐项填写 `passed`、`failed`、
`not_applicable` 或 `not_run`，并为失败和不适用给出证据与理由：

1. 身份与授权：设备序列/MAC/主机密钥、资产绑定、目标范围与只读/写入权限。
2. 组件清单：完整性、包数、版本/修订、固件构建配置与可复采性。
3. 情报：公告源、在线获取结果或快照时间/哈希；TLS、DNS、代理错误保留原始错误。
4. 适用性：每项候选对应的组件、版本域、修订/补丁、配置、可达性和独立结论。
5. 遥测：采集器健康、事件类别受控触发、服务端入库/去重/重试/丢弃计数与覆盖边界。
6. 业务：HTTP/MQTT/RTSP 等设备功能与授权业务检查；记录执行前后状态。
7. 复验：修复必须有明确审批、变更记录、重新采集与业务回归；未执行不得记通过。
8. 签收：业务负责人逐项确认剩余风险；机器状态和模型输出不能代签。

24 小时长稳验收必须覆盖传感器、forwarder/WAL、网络回传和后端入库整条链路；仅有
原生传感器本机 `soak.py` 通过不算端到端通过。每 30 秒保存健康/计数采样，并核对
探针发出、WAL 接收、服务端确认、数据库新事件与重复事件。应有受控事件持续触发且
端到端身份/哈希可关联。进程重启、机器重启、断网恢复和证据队列增长分别记作中断
或恢复阶段，不得拼成连续 24 小时。任何丢失计数不可用、计数对不上、健康文件过期、
资产身份改变或未解释的缺口都将验收结果置为 `incomplete`，保留原始材料后再复测。

### 可执行验收工具

在仓库根目录运行只读观察器（为每个资产/传感器重复传入 `--sensor`）：

```powershell
python scripts/runtime_soak.py --base-url http://127.0.0.1:8000 --sensor 1:falco --seconds 86400 --interval 30 --output reports/runtime-soak-new
```

目标目录必须不存在。工具逐次落盘健康和可靠性原始 JSONL，并保存带原始文件哈希的
结果。心跳过期、采样中断、计数回退、上传/入库增量不一致、队列未清空记失败；指标
缺失记材料不足。退出码 1 表示观察到失败，2 表示验收材料仍不完整。此 API 无法证明
内核发出量、进程身份或受控事件关联，即使观察满一天也不会自行签发通过结论。

逐设备 JSON 记录可用以下命令校验：

```powershell
python scripts/validate_device_acceptance.py reports/device-record.json --evidence-root reports/device-evidence
```

顶层字段：`asset_id`、`device_identity`、`environment`（physical/virtual/simulator）、
`firmware`、`kernel`、`board`、`code_revision`、`collector_version`、`config_sha256`、
`authorization_ref`、带时区的 `started_at` / `ended_at`。`checks` 必须包含 identity、
inventory、intelligence、applicability、telemetry、business、remediation、signoff。
每项含 `status`、`reason`（非 passed 时必填）和 `evidence` 数组；原始材料逐个用
`{"path":"相对证据目录路径","sha256":"实际文件哈希"}` 引用。passed/failed/not_applicable
必须有材料；修复 passed 需 `approval_ref`，签收 passed 需 `reviewer` 与 `decision_ref`。
工具拒绝越界路径和哈希不符；`record_complete` 仅表示记录齐全，不能证明材料真实、
签名有效或代替业务负责人接受剩余风险。

## 2026-10-20 后续修复

以上记录保留 2026-10-19 当时结果。后续已修复持久写权限域隔离、演示密码存储与官方证据引用，并完成真实隔离 QEMU 宿主签名更新/回退验收；当前用户范围仅为虚拟设备。最新 Zephyr 快照为 281 条（54 条可能受影响、71 条资料不足、156 条不在所报范围）。最新运行、测试与剩余边界见 [本轮交付](../archive/2026-10-20-delivery.md)，不将后续结果倒填为历史通过。

## 交付边界

目前可接受的是已执行的虚拟设备功能检查及既定 cgi-io 修复结果，尚不能宣布生产安全验收全部通过。写权限域隔离和遗留演示密码入库问题仍见完善程度报告，不能用关闭开关代替修复其实现。

标准 Compose 已显式关闭三个修复开关。正式worker结束且资产锁排空后，宿主验收API以三个开关均为0重载；4个资产当前风险汇总与数据库逐项核对通过，无令牌变更请求返回401，节点和3个传感器恢复。原6条风险治理事件完整保留，新增请求与复评事件均 business_accepted=false；原修复仍只安装过一次。Docker仍为独立验证快照，未用宿主库覆盖。

模型关于旧窗口中传感器停止、认证未知或官方原文不可得的叙述，仅代表它读取的窗口和引用限制。本轮独立检查已有受保护页面403、匿名ubus拒绝与三个健康传感器；这些事实没有被伪造为模型已消费的注册证据。校验失败不等于官方公告不存在，也不构成按IP归并资产的授权；本轮没有执行模型提出的台账归并或配置变更。

宿主 API、开发前端和 VMnet 转发为本轮已启动的本地进程，复用既有采集节点监督器；不把当前在线等同于宿主重启后自动恢复或长期稳定性验收。Falco 与 QEMU 使用现有 systemd 服务。

原始证据、备份、业务检查脚本、HTTP 回归结果和复评回执保存在 gitignored `reports/device-acceptance-20261019/`。其中可能含实验环境身份，公开交付只包含本页等脱敏说明，不提交数据库、运行日志或凭据。

历史软件包修复与真实 S2→S1→S2 快照恢复见 [OpenWrt 专项报告](../archive/2026-10-19-openwrt-security-closure.md)。


## 2026-10-20 最终虚拟设备验收

最终汇总见 [IOTGUARD_VIRTUAL_IOT_FINAL_ACCEPTANCE_REPORT.md](../archive/2026-10-20-virtual-iot-acceptance.md)。125 条开放 Zephyr 复核项分类为 54 条 potentially_affected、71 条 insufficient_data；确认 affected 为 0。最长连续健康窗口约 600 秒，未达到 24 小时。Windows CI Run 39299728933 在提交 1c234b7 上成功。
