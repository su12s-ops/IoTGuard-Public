# OpenWrt 与 Zephyr 更新闭环实测

日期：2026-10-18（北京时间）。本次直接操作既有 OpenWrt VMware 实例和既有 Zephyr QEMU 实例，没有用新建模拟资产替代。Ubuntu 仅作为 SSH 跳板、构建与 QEMU 宿主。

## 更新结果

| 对象 | 更新前 | 更新后 | 实测结果 |
|---|---|---|---|
| OpenWrt，资产 2 / 连接 1 | 25.12.5，内核 6.12.94 | 25.12.6，内核 6.12.112，r33311-981c978eff | 官方镜像校验、保留配置升级、重启、网络与服务检查、正式清单复采通过 |
| Zephyr，DEV-432A952D70DF | 内核 4.4.2，应用 0.1.0-stage7 | 内核 4.4.2，应用 0.3.0-iotguard | 实际编译、HTTP 边界测试、熵源自检、部署、回退 0.2、再次部署、崩溃恢复、正式刷新和匹配通过 |

核查时官方 Zephyr 最新发布为 v4.4.2，因此本次更新的是应用固件和构建配置，未虚构内核升级。设备 UID 保持 ZEPHYR-SENSOR-0001，仍使用原 8080 入口，board 为 qemu_cortex_a9。

## 本轮闭环补充

- Zephyr 0.3.0 ELF SHA256：`759bb5b6b00e412574cdd49782defa5916d79fcff7d82ccf53250112a34e4d2c`。QEMU 专用宿主 `/dev/urandom` 半主机熵通道已启用，启动自检通过；这是受信任 QEMU 的测试方案，不是实体设备 TRNG。
- 原 8080 服务完成 `0.2.0 → 0.3.0 → 0.2.0 → 0.3.0`，强制终止 QEMU 后 systemd 自动恢复。`loginctl` 已验证 `Linger=yes`，宿主无用户登录时的自启动条件已具备。
- OpenWrt 已创建关机快照 `iotguard-25.12.6-verified-20261018`，写入临时标记、恢复快照后标记消失；版本、网络、防火墙、DNS、HTTPS、dnsmasq/uhttpd/dropbear 均通过。该演练验证的是当前版本回退能力，不是降回旧漏洞版本。
- 后端重启到包含最新代码的 PID 23300，数据库重启前备份已保存；最终匹配、Zephyr、发现与升级专项回归 `46 passed in 153.86s`。正式 Zephyr refresh trace 为 `TR-20261018144142-7723fd`，match trace 为 `TR-20261018144142-2fc4fa`，结果为 `unassessed`，原因是当前没有可适用的官方设备公告，空匹配不作为安全结论。
- 已保存 Zephyr 官方 v4.4.2 源码核验及 OpenWrt 25.12.6 实机包证据。当前官方情报快照已抓取 281 条 Zephyr 公告；HTTP 服务器通配静态文件、ICMP 统计、VLAN 等公告只有在对应 Kconfig/应用路径启用时才适用，本固件配置明确关闭相关父功能。CVE-2026-10666 的危险 IPv4 端口复制代码在当前源码中已不存在，完整 utils.c 与官方 v4.4.2 文件逐字节相同，SHA256 为 `f6e397cdcf73d531702ef1d3ec8ff04a2f3c6ced47fe29646e39a18961ca2942`；不能仅凭公告尚未填写修复版本就判当前固件有该缺陷。
- OpenWrt 恢复后的正式采集 `f949265b6e55914850b6e1671795848c` 已 completed，Linux 节点认证、SSH 主机身份核验通过，182 包全部解析，inventory_complete=true；正式台账为 25.12.6。
- 最终在原 8080 入口通过可重复执行的 `firmware/zephyr-sensor-01/verify_live.py`：身份与版本、熵自检、路径前缀/穿越拒绝、错误方法/请求行拒绝、分片请求、空闲/超长输入后恢复、连续 20 次请求。另在隔离 8082 负向候选中关闭半主机通道，五轮均无法取得 HTTP 身份；这仅验证缺少通道时不会暴露正常接口，不等于覆盖所有熵源故障类型。

## 当前验收范围

已完成现有两种实例的更新、实际回退/恢复、功能测试和正式平台复采闭环。尚不能宣称全量漏洞处置闭环：281 条公告快照不等于已全部入库并验证适用性；正式设备匹配仍无适用公告，运行时日志连续性与丢失统计尚未验收。签名 OTA、实体板熵驱动与实体硬件业务验收也未完成。上述限制必须保留，不能用空匹配代替安全验收。

重复执行本轮 HTTP 验证：

```powershell
python firmware/zephyr-sensor-01/verify_live.py --host 192.168.183.129 --port 8080 --output reports/iot-update-20261018/zephyr-live-regression.json
```

## 首次更新证据（历史记录，最终状态以上方本轮补充为准）

### OpenWrt

- 官方版本源：<https://downloads.openwrt.org/.versions.json>。镜像为 `openwrt-25.12.6-x86-64-generic-ext4-combined.img.gz`，大小 13,619,564 字节。
- SHA256 与官方 HTTPS 校验清单一致：`f8538784d0288b4133a99ac2a68443e4922ffde6343e80df56a5882364b9d499`。
- `sysupgrade -T` 通过，实际以 `sysupgrade -k` 保留配置和软件包清单完成升级，SSH 主机身份钉扎仍有效。
- LAN/WAN 的 `up` 均为 true；`fw4 check`、nft 规则表、dnsmasq/uhttpd/dropbear、DNS 与 HTTPS 检查通过。
- 刷新官方软件源后，可升级软件包列表为空；安装包数量为 182 → 182。数量相同不作为包集合完全相同的证明，原始清单已留存。
- 正式采集运行 `97d52d1a07c26e6e5962c1ebfbb1c20f` 已 completed；资产清单完整，采集时间为 2026-10-18T14:09:40.018992Z，正式台账读回新版本与新内核。
- 重启后 logread 有新 boot_id 与新事件入库；这是周期 SSH 拉取。运行时覆盖接口仍显示 unknown / stopped，不能宣称常驻探针健康或无丢失。

宿主私有备份目录 `~/iotguard-update-20261018/` 留存配置归档、升级前包清单、board 信息及 126,353,408 字节在线磁盘读取备份。在线磁盘备份不等于一致性 VM 快照；本次没有执行 OpenWrt 降级或恢复演练。

### Zephyr

- 官方发布源：<https://github.com/zephyrproject-rtos/zephyr/releases/tag/v4.4.2>。
- 固件源码修正发送零字节处理、接收/发送超时、有界分片请求读取、请求行检查及精确路径匹配；构建禁用 IPv6，启用 socket 超时并增加连接资源上限。
- 实际构建 ELF SHA256：`c6e239ec947be79d72970388944be9ab4dd3888d2e387671ccbbbffeaeb0b5ef`；build_id 为 `Oct 18 2026 22:05:29`。
- 候选端口验证：合法身份请求、前缀路径拒绝 404、POST 与额外请求行字段拒绝 400、分片请求、空闲连接恢复、超长输入后恢复、连续 20 次身份请求均通过。这些是有限输入的功能/健壮性检查，不能替代完整协议安全测试。
- 原入口实际完成 `0.1.0-stage7 → 0.2.0-iotguard → 0.1.0-stage7 → 0.2.0-iotguard`，每次均核对同一设备 UID，构成真实应用固件回退演练。
- 用户级 `iotguard-zephyr.service` 已启用且 active，配置故障重启；额外执行服务重启后，新版本身份检查通过。当前 Linger=no，未验收宿主重启后无人登录自动启动。
- 正式刷新 trace：`TR-20261018140937-e51c3e`；正式匹配 trace：`TR-20261018140937-969fc8`。平台已读回新固件；匹配为空不代表安全通过。

旧源码与旧构建分别保存在宿主备份目录的 `zephyr-before/`、`zephyr-before-artifacts/`。本次部署是宿主控制 QEMU ELF 切换，不是签名 OTA，也不是实体开发板刷写。

## 首次更新时的缺口（历史记录）

本次完成两种既有设备实例的更新、功能验证和平台复采；Zephyr 另完成实际回退演练。不能据此宣称全部漏洞已修复或完整安全闭环已完成：

1. 正式 `openwrt_advisory` 与 `iot_device_advisory` 表均为 0；必须建设官方公告入库及包版本、内核与 Kconfig 适用性判定。版本命中候选也不能直接当作已确认漏洞。
2. Zephyr 当前 QEMU 板仍使用 `CONFIG_TEST_RANDOM_GENERATOR` / `CONFIG_TEST_CSPRNG_GENERATOR`，不满足生产随机源要求；关闭部分网络功能不消除这一限制。
3. Zephyr 正式组件台账仍残留旧版 HTTP 服务组件，新版组件已加入；需修复组件身份和当前清单替换语义，并保留历史证据。本次未手工删除数据库历史行。
4. OpenWrt 回退仅有备份准备，尚未实测；日志持续性和丢失统计也未完成常驻监控验收。
5. 两者均为真实系统/固件的虚拟化实例，温湿度遥测仍为模拟数据，未完成实体硬件或全业务安全验收。

后续开发优先用于上述 IoT 检测和修复缺口；Ubuntu 保持基础设施角色。原始诊断脚本、平台响应与脱离密钥的验证结果保存在本地忽略目录 `reports/iot-update-20261018/`，配置与磁盘备份不随公共仓库发布。
# 更新后连通性复验

2026-10-18 22:57–22:59 已完成 26 项实际链路检查及 Zephyr 原 8080 协议回归，均通过；新的 OpenWrt 资产采集、日志回传和 Zephyr 刷新均已验证。入口区别、trace、证据和未覆盖范围见 [连通性报告](IOTGUARD_CONNECTIVITY_REPORT.md)。此段为更新后补充，安全适用性和公告入库缺口仍有效。

