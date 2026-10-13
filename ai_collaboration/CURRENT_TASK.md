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
- [x] **阻塞已解除（同日）**：根因为 id_ed25519_vms 非默认身份名且 agent 停用（历史 BatchMode 从未真正提供该钥匙）；显式 `-i` 认证即成功，Ubuntu 零改动
- [x] 主机线补全：SSH 隧道 → 既有 collection_only 节点 → 复用采集任务 2 次真实采集（host identity verified / 密钥认证 succeeded / 182 包 / collector exit 0）
- [x] 幂等：同 request_id 复用同任务不重放 SSH；新 request_id 二采不重复建档（assets=1/connections=1）
- [x] 身份链闭合：采集 MAC 与 VMware .vmx 网卡地址逐字一致；主机指纹与受信记录一致
- [x] 新旧对比：181/182 一致 + 1 处真实包变化（kmod-nls-iso8859 → kmod-nls-iso8859-1）
- [x] CVE 分级消费：本轮快照入引擎（幂等 0 伪造结论；全部落在"无充分证据"层——未登记公告/情报）

## 最近完成

**第七阶段：Zephyr RTOS 终端接入**（2026-10-13，部分完成）
- [x] Zephyr v4.4.2 + SDK v1.0.1（模块化免 root 部署，Ubuntu 用户空间）
- [x] Zephyr-Sensor-01 固件：真实 Zephyr 应用（TCP 服务线程 + DHCP + 模拟传感 + /api/system 身份 JSON），qemu_x86_64 构建成功（5.7MB ELF + 28KB locore）
- [x] 后端适配：capabilities OS 能力画像（增量字段）+ discovery_pipeline Zephyr 能力边界标注（ssh/package/eBPF = unsupported）
- [x] device_inventory 增强固件扩展元数据（board/soc/arch/build_id/telemetry→metadata）
- [x] Mock 测试 5 项 + 回归 26 项全过（发现→Zephyr 身份→建档→版本化组件→CVE 三层→双实例不合并→幂等→能力画像）
- [ ] **阻塞**：QEMU 运行——SDK 捆绑 QEMU v10.0.2 与 locore 启动链不兼容（内核加载后无串口输出，多种加载方式均试）。Ubuntu 无 sudo 无法安装系统 QEMU 或 GCC（native_sim 也不可用）。待解决：安装 Ubuntu 系统 QEMU < v10 或 host GCC

## 下一步（等待指令，不自动开始）

- 解除 QEMU 阻塞（需 sudo apt install qemu-system-x86 或 gcc）后：启动固件 → IoTGuard Ubuntu 标准模式发现 → 真实端到端验收
- 可选增强：为主机线登记真实 OpenWrt 官方公告

## 已知事项

- 后端 4 个真实套接字测试文件（test_iot_device_upgrade / test_mqtt_remediation_workflow / test_scan_runs 部分）与 conftest 审计钩子冲突，常规回归显式排除（与交付回归口径一致），待加独立 profile 开关
- Private 初始提交 a05f3c8 历史含整改前环境标识——Private 保持历史不重写；Public 不继承该历史（独立初始化）
- 竞赛章程对公开时点的要求待用户确认（Public 仓库内容已脱敏）
