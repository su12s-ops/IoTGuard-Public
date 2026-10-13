# 当前任务

> 每完成一个任务更新本文件。最后更新：2026-10-13

## 最近完成

**Git 完整托管与自动同步机制建设**（2026-10-13）
- [x] 整改提交 6f4724b 推送 Private
- [x] ai_collaboration/ 协作文件、GitHub 模板（Issue/PR）、CI 工作流
- [x] scripts/sync_public.py 自动同步脚本（流式导出+敏感扫描+增量推送，幂等）
- [x] Public 仓库建立（PUBLIC、独立历史）并完成首次同步（223 文件，来源哈希可追踪）

## 下一步（等待指令，不自动开始）

- OpenWrt 异构终端接入实施（方案见 2026-10-13 接入准备报告：复用 VMnet2 上的 OpenWrt VM；Ubuntu 双实例拓扑；人工前置：VM 确认/SSH 凭据/密钥路径）
- 人工前置项：Windows→Ubuntu SSH 凭据恢复；OpenWrt 主机指纹核验

## 已知事项

- 后端 4 个真实套接字测试文件（test_iot_device_upgrade / test_mqtt_remediation_workflow / test_scan_runs 部分）与 conftest 审计钩子冲突，常规回归显式排除（与交付回归口径一致），待加独立 profile 开关
- Private 初始提交 a05f3c8 历史含整改前环境标识——Private 保持历史不重写；Public 不继承该历史（独立初始化）
- 竞赛章程对公开时点的要求待用户确认（Public 仓库内容已脱敏）
