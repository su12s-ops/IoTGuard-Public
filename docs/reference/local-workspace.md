# 本地工作区与实验资料

仓库只发布源码、可复现的模拟器、测试和脱敏后的文档。运行数据库、设备凭据、模型响应原文、虚拟磁盘和实验原始目录保留在本地，并由 `.gitignore` 阻止提交。

## 目录用途

| 目录 | 用途 | 处理规则 |
| --- | --- | --- |
| `backend/data/` | 当前本地运行数据和传感器事件 | 保留；需要重置时先导出必要证据 |
| `reports/` | 实验结果、日志、截图和可复核摘要 | 保留最新结果和报告；清理已被摘要覆盖的数据库快照 |
| `local-archive/` | 历史部署、迁移和私有备份 | 保留最终验收材料、OpenWrt 材料和清单；删除重复数据库与旧环境 |
| `frontend/node_modules/` | 前端依赖 | 保留，便于直接运行 Edge 测试 |
| `dist/`、`test-results/`、`.pytest_cache/` | 可再生构建和测试产物 | 随时删除，不进入 Git |

## 当前验证边界

本地记录以模拟设备为主，覆盖 HTTP/MJPEG、MQTT、有限 RTSP、SSH/设备身份和 LAN 隔离。实验数据库快照是内部复核材料，不等于真实硬件证据；短时窗口也不能推导 24 小时稳定运行结论。真实设备和长期运行验收须单独归档，不能用旧快照补算。

## 维护命令

在 Windows PowerShell 中使用已安装的 Edge 执行前端回归：

```powershell
$env:PLAYWRIGHT_CHANNEL = 'msedge'
npm --prefix frontend run test:e2e
```

构建和测试结束后，`frontend/dist/`、`frontend/test-results/`、`.pytest_cache/` 可以安全删除。不要把 `reports/` 或 `local-archive/` 直接加入 Git；需要公开结果时，应先提炼为 `docs/archive/` 或 `docs/validation/` 中的脱敏 Markdown。
