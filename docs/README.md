# 文档导航

首次了解项目从 [项目介绍](../README.md)和[当前状态](status.md)开始。本文档集以当前运行方式为主；有日期的实验结果集中归档。

## 部署与使用

| 文档 | 用途 |
| --- | --- |
| [部署指南](guides/deployment.md) | Docker、本地开发、采集接线、数据与常驻运行 |
| [环境重建](../deploy/README.md) | VMware、Ubuntu、OpenWrt、Zephyr 与系统服务模板 |
| [单网关 LAN 模拟](guides/openwrt-lan.md) | 两台摄像头、传感器、插座的独立 IP 接入与维护 |
| [隔离本地运行](guides/local-runtime.md) | 不读取现场配置的临时验证实例 |
| [QEMU 固件更新](guides/virtual-firmware.md) | 宿主签名、固件切换、失败恢复与能力边界 |

## 架构与实现

| 文档 | 用途 |
| --- | --- |
| [架构总览](architecture/overview.md) | 控制台、四角色、执行节点、证据与权限关系 |
| [控制台流程](architecture/console-workflow.md) | 开始、阶段进度、审核、刷新与中断语义 |
| [任务图运行方式](architecture/task-graph-runtime.md) | 当前报告复用、预算、并发和真实实验范围 |
| [多智能体设计](architecture/multi-agent-design.md) | 目标设计及尚未完整实现的部分 |
| [权限模型](reference/security-model.md) | 身份、令牌、修复域、证据与审批 |
| [维护规则](reference/maintenance.md) | 证据引用、历史材料与结论约束 |

## 验证与开发

- [验证方法](validation/testing.md)：命令、CI 和现场验证边界。
- [智能体黑盒检查](validation/agent-blackbox.md)：只通过公开 HTTP 契约定位故障。
- [智能体质量基准](validation/agent-quality-bench.md)：固定事实、策略对照与重复实验。
- [设备验收](validation/device-acceptance.md)：设备独立验收要求及历史检查结果。
- [贡献与命名](../CONTRIBUTING.md)：资料归类、文件命名与提交检查。
- 模块说明：[后端](../backend/README.md)、[前端](../frontend/README.md)、[模拟器](../simulator/README.md)、[Falco](../collector/deploy/falco/README.md)、[原生 eBPF](../collector/native/README.md)。

## 历史资料

[历史记录索引](archive/README.md)保留官方情报匹配、虚拟设备验收、故障修复与失败样本。归档中的旧设备数量、端口、实验身份及测试数属于当时窗口；当前情况以 [status.md](status.md)为准。

原临时盘点脚本及 CSV/XLSX、重复协作备忘、未使用的多主题静态原型已移出当前源码树；可从 Git 历史查阅。运行数据库、凭据、原始日志和本地回执保存在 Git 忽略目录中。
