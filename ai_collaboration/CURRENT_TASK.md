# 当前任务

> 每完成一个任务更新本文件。最后更新：2026-10-13

## 最近完成

**Git 完整托管与自动同步机制建设**（2026-10-13）
- [x] 整改提交 6f4724b 推送 Private
- [x] ai_collaboration/ 协作文件、GitHub 模板（Issue/PR）、CI 工作流
- [x] scripts/sync_public.py 自动同步脚本（流式导出+敏感扫描+增量推送，幂等）
- [x] Public 仓库建立（PUBLIC、独立历史）并完成首次同步（223 文件，来源哈希可追踪）

## 最近完成

**第六阶段：OpenWrt 异构终端真实接入**（2026-10-13，证据 reports/openwrt-live-*，本地留存）
- [x] 环境：复用运行中的 OpenWrt 25.12.5 VM（VMnet2 实验段），TCP 22/80/443/53 全通
- [x] 主机指纹：SSH 握手取证与历史受信记录完全一致（ed25519）
- [x] 自动发现：真实 API 双 /25 扫描 → 观察证据 → 协议指纹（dropbear/http/https）→ IotDevice 建档（16/16 验收点）
- [x] CVE 分级诚实呈现：dropbear 横幅无版本 token → 组件无版本证据 → 按规则延迟匹配（非伪造零命中）
- [x] 复扫幂等、未授权网段 400、零修复/Harness 副作用
- [x] 回归：后端 81 项 + SmartCam 真实闭环 16/16，无新增回归
- [ ] **受阻**：SSH 资产采集（主机线）——Ubuntu 采集节点登录凭据失效（publickey denied），按策略禁止从 Windows 执行设备采集/复制密钥；需人工恢复 Windows→Ubuntu SSH 授权后继续

## 下一步（等待指令，不自动开始）

- 解除 Ubuntu SSH 阻塞后补全主机线：SSH 只读采集（软件包/Board/内核）→ match_openwrt 精确匹配 → 新旧清单差异对比
- Zephyr 观测接入（未开始）

## 已知事项

- 后端 4 个真实套接字测试文件（test_iot_device_upgrade / test_mqtt_remediation_workflow / test_scan_runs 部分）与 conftest 审计钩子冲突，常规回归显式排除（与交付回归口径一致），待加独立 profile 开关
- Private 初始提交 a05f3c8 历史含整改前环境标识——Private 保持历史不重写；Public 不继承该历史（独立初始化）
- 竞赛章程对公开时点的要求待用户确认（Public 仓库内容已脱敏）
