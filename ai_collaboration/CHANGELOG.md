# 变更日志

> 重要版本变化，新条目置顶。格式：日期 / Commit / 变更。

## 2026-10-14 — 第七阶段完成：Zephyr 真实端到端联调（QEMU 阻塞解除）

- 阻塞解除：Ubuntu 24.04 VM 安装 qemu-system-arm 8.2.2 / gcc / build-essential（用户执行）；SSH 重连验证（Ubuntu 用户 + VMnet8 管理地址，显式 id_ed25519_vms；具体标识见本地证据）
- 板级切换落地：qemu_cortex_a9 构建成功（arm-zephyr-eabi，含完整网络栈 eth_xlnx_gem+DHCP+TCP）
- 三处真实修复：①CMSIS 模块路径与 west 清单对齐 + .west 工作区 + stage7-cmsis-wiring 接线模块（源码包部署环境缺口）；②Zephyr 树补丁 patches/0001（soc 未映射 SLCR → GEM 初始化翻译错误，8 行）；③固件 /api/system JSON 拼接缺陷（"port"键重复 → 非法 JSON，真实探测发现，mock 不可暴露）
- QEMU 运行打通：xilinx-zynq-a9 + `-nic user,model=cadence_gem`（SoC 内建网卡标准挂载）+ SLIRP hostfwd 8080→:80；DHCP ok、http on :80
- 真实网络链路：Windows 后端 → VMnet2 → Ubuntu 宿主（VMnet2 地址:8080）→ QEMU 固件（跨主机真实 TCP/HTTP）
- 真实联调验收：stage7_zephyr_live.py 20/20 ALL PASS（发现→身份接口建档 0.9→固件元数据→版本化组件→能力 unsupported→CVE 清洁库诚实零+TEST-FIXTURE 三层→复扫幂等→未授权 400→零修复副作用）；证据 reports/zephyr-live-20261014-085507/
- 回归：26/26 复跑通过（zephyr+discovery+identity_edge+api_smoke）
- 诚实记录：Ubuntu 宿主 VMnet2 地址为 SLIRP 入口（NAT 拓扑边界写入证据）；上轮"ARM 构建成功"无产物支撑（build-arm 为失败半成品），本轮重建才真正完成

## 2026-10-13 — 第七阶段：Zephyr RTOS 终端接入（固件+后端+测试就绪，QEMU 阻塞）

- 固件：Zephyr-Sensor-01（真实 Zephyr v4.4.2 应用，TCP+DHCP+传感+/api/system 身份）构建成功
- 后端：OS 能力画像 + Zephyr unsupported 标注 + 固件扩展元数据（增量适配）
- 测试：5 项 Mock + 26 项回归全过
- 阻塞：QEMU v10.0.2 locore 启动链不兼容（需系统 QEMU 或 GCC，待 sudo）

## 2026-10-13 — 第六阶段收尾：主机线端到端闭环

- SSH 阻塞根因定位（非默认身份名 + agent 停用）并解除；Ubuntu 侧零改动
- 主机线真实采集 2 次全过（指纹钉扎 verified、密钥认证、182 包、幂等、无重复建档）
- 采集身份与 VMware .vmx MAC 闭合；与基线 diff 捕获 1 处真实包演进
- 本轮快照 CVE 分级消费：诚实三层呈现（无证据 → 拒绝下结论）

## 2026-10-13 — 第六阶段：OpenWrt 真实接入（设备线）

- 新增 stage6_openwrt_live.py：OpenWrt VM 真实发现联调入口（指纹比对/发现/建档/幂等/边界 16 项）
- 真实成果：授权段内自动发现 OpenWrt 并以真实协议横幅建档；主机指纹与受信记录一致
- 已知阻塞：Ubuntu 采集节点 SSH 凭据失效 → 主机线采集与精确 CVE 匹配待恢复（未绕过、未伪造）

## 2026-10-13 — 托管机制落地（Private 0a679e9 / Public d14f354）

- 双仓体系投入运行：Private（完整历史）与 Public（独立干净历史，PUBLIC 可见）
- sync_public.py 首次同步 223 文件；commit message 携带 Source-Commit 溯源；幂等复跑验证通过
- gh 令牌补齐 workflow scope（CI 文件推送所需）

## 2026-10-13 — Commit 6f4724b（Private）+ Public 首次发布

### 安全
- 公开前整改：删除含用户名截图、旧工程路径占位符化、夹具主机名合成化、样本全合成化、用户目录脱敏（详见 EXECUTION_REPORT）

### 机制
- 建立 Private（su12s-ops/IoTGuard-Project，完整历史）+ Public（su12s-ops/IoTGuard-Public，独立干净历史）双仓体系
- 新增 `scripts/sync_public.py` 自动同步（导出→扫描→增量提交→推送，来源 hash 可追踪）
- 新增 `ai_collaboration/` 协作文件、GitHub Issue/PR 模板、CI 工作流

## 2026-10-13 — Commit a05f3c8（初始基线，Private）

- IoTGuard 工程基线：backend（FastAPI，30+ 表，341 项测试）/ frontend（Vue3，16 视图）/ collector（eBPF+采集器）/ simulator（SmartCam-X1）/ 技术文档
- 初始提交含整改前环境标识（后续 6f4724b 已在工作区修复；历史按授权保留）
