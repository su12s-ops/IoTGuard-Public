# 采集节点与传感器恢复记录

> 历史记录：保留当时的结果、失败与限制，不代表当前部署状态。当前入口见 [项目状态](../status.md)。

2026-10-25，北京时间。针对当前 Docker 控制台与既有 Ubuntu/OpenWrt 虚拟设备。

## 原因与修复

| 异常 | 已确认原因 | 修复 |
|---|---|---|
| m45-linux-node 离线 | 宿主监督进程未运行；脚本仍访问旧 18000 端口 | 回传改为现有 18080 同源代理，恢复钉扎 Ubuntu SSH 的 18445 反向隧道与只读 pull runner |
| Ubuntu Falco 心跳过期 | 原生 Falco 在运行，平台 `linuxguard-falco` 转发服务停止 | 备份原有环境，回传指向隧道，恢复原传感器 ID，启动并启用该服务；停用原生探针开机启动，避免重复加载 |
| OpenWrt 原机无近期日志 | 原机虚拟机已关闭；周期连接列表只包含 Lab | 无界面启动已登记的原机，原有 DHCP 网络恢复；连接 1 与 4 都纳入 60 秒周期只读采集 |
| 宿主重新登录后可能再次离线 | 未配置当前用户自启动 | 增加用户启动目录的 `IoTGuard Collection Node.lnk`，使用已有 Python 环境和 SSH 密钥；监督器增加进程锁，避免重复隧道 |

Linux 节点继续在容器外运行；设备身份、SSH 指纹、节点令牌和只读任务范围继续校验。没有开启设备修复开关，没有修改 OpenWrt 固件、软件包或设备配置。

Ubuntu 的 sudo 凭据仅通过交互标准输入传给 sudo，未写入修复脚本、服务环境、启动快捷方式或本记录。服务控制令牌只进入原有 root-only 环境文件；临时私有配置在使用后删除。配置备份位于节点 `/etc/linuxguard/falco.env.<时间>.bak`，权限 0600。

## 实际验证

- 节点 `m45-linux-node` 连续心跳在线。
- `wyh-vmware-virtual-platform:falco` 为 `running`，真实 syscall 事件持续入库。
- `openwrt-logread-1` 与 `openwrt-logread-4` 为 `reporting`，连续多个周期收到成功回执。
- 健康接口显示 **3/3 传感器健康**，运行时证据 `fresh=true`。
- Falco 转发指标显示已上传事件、0 个失败批次及 0 个待续传 spool；重启后发生的网络重试如实计数。
- 再次启动宿主监督脚本时，第二个进程因已有运行锁而退出，没有创建重复隧道。
- Falco 服务已设为开机启用。宿主监督器设为当前 Windows 用户登录时启动。

验证记录与监督日志位于被 Git 忽略的 `reports/runtime-recovery-20261025/` 与 `reports/collection-node/`。

## 边界与维护

- OpenWrt 的 logread 是周期拉取，可靠性端点中的窗口 `stopped` 表示本次读取结束；整体健康由最近成功采集时间判断，不等于传感器故障。
- Falco 内核丢失量及 logread 环形缓冲覆盖丢失仍为 `unavailable`，不能把未知写成 0。
- 当前恢复不等于完成宿主重启、虚拟机重启或 24 小时稳定性验收。Windows 用户未登录、Ubuntu 或 OpenWrt 虚拟机关闭时，对应链路仍不可用。
- 本轮未启动新的多智能体检测，也没有改写已保存的风险裁定。

维护入口：`scripts/run_docker_collection_node.py`；节点上的一次性修复工具源码：`scripts/repair_falco_service.py`。后端环境的 `LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS` 当前为 `1,4`。
