# 变更日志

> 重要版本变化，新条目置顶。格式：日期 / Commit / 变更。

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
