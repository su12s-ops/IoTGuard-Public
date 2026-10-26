# OpenWrt 单实例清理（2026-10-26）

> 历史记录：保留当时的结果、失败与限制，不代表当前部署状态。当前入口见 [项目状态](../status.md)。

用户要求保留一台 OpenWrt，用于 LAN 物联网设备实验。

## 当前状态

- 保留资产 2：`OpenWrt-000c2915a8c8`，`192.168.100.1`。
- 原机虚拟机配置：`D:\OpenWrt_虚拟机\其他 Linux 6.x 内核 64 位.vmx`。
- 原机仍依赖基础磁盘 `D:\IoTGuard-Lab\OpenWrt-Router\OpenWrt-Router.vmdk`。此目录必须保留。
- 克隆资产 4：`OpenWrt-Lab-0050563ab001`，`192.168.206.2`，已通过身份固定的 SSH 正常关机。
- 克隆机目录 `D:\IoTGuard-Lab\OpenWrt-Lab` **尚未删除**：VMware `deleteVM` 返回权限不足，随后目录删除操作被自动审批以 `blocked by policy` 拒绝。没有释放此目录的磁盘空间；需用户在 VMware 中删除这台已关机的克隆机。
- 其余 Ubuntu 虚拟机属于独立资产，本次没有删除。

## 平台和配置清理

已停止数据库写入进程后，同时清理主机版和 Docker 版数据库中的克隆资产、连接、软件清单、风险、传感器、日志证据、采集任务及专属分析记录。共享历史分析报告保留。仅属于原机的低可信重复发现占位记录也已清理。

维护工具 `scripts/retire_asset.py` 校验资产编号、IP、MAC 与发行版，默认只预览；执行前须确认写入进程停止。删除前保存所选行的 gzip JSONL 归档，使用外键依赖顺序删除，并验证各表行数变化和外键一致性。出现异常回滚事务。

- 主机归档：`reports/openwrt-retirement-20261026/host-asset4.jsonl.gz`，约 32.7 MB。
- Docker 归档：数据卷 `/app/data/retired-openwrt-lab-20261026.jsonl.gz`，约 9.4 MB。
- `.env` 和 `.env.docker` 的日志连接仅保留 `1`，移除克隆机发现地址。
- Docker 覆盖配置移除克隆机修复产物和 SSH 密钥挂载。
- Ubuntu 拉取采集器移除克隆机身份及其密钥环境变量；已重新启动采集器与主机/Docker 后端。

## 验证

- 18080 前端代理与 8000 主机 API 都仅返回一台 OpenWrt，且没有连接 4。
- 前端资产页面实际刷新后显示 `OpenWrt 1`；截图位于 `reports/openwrt-retirement-20261026/assets-after.png`。
- Docker 后端和前端健康；原机保留 193 条软件包记录。
- 原机 `iotguard-lan` 服务运行，四个命名空间和 DHCP 地址 `.20`、`.21`、`.22`、`.23` 保留。
- 运行时仅保留 Ubuntu Falco 与原机 logread 两个传感器；原机重新完成日志采集。
- VMware 当前运行列表仅包含原机和两台 Ubuntu，克隆 OpenWrt 不再运行。

本次验证说明原机、模拟设备和采集链路可运行，不等于此前多智能体未完成项或外部情报更新失败已全部解决。
