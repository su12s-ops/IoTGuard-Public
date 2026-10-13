# 变更日志

> 重要版本变化，新条目置顶。格式：日期 / Commit / 变更。

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
