# IoTGuard Frontend — Console

Vue 3 + Vite 的桌面安全控制台。只保留一套 Console 视觉系统，不依赖 Element Plus / ECharts 或旧工作台页面。

## 页面

| 路径 | 页面 |
| --- | --- |
| `/` | 安全总览（KPI、拓扑、风险分布、优先处置、智能体运行） |
| `/assets` | 资产与发现（设备类型、拓扑/列表、最近发现、采集覆盖） |
| `/risks` | 漏洞与风险（分布、矩阵、风险列表） |
| `/risks/:id` | 风险详情 / 人工裁决 |
| `/agents` | 智能研判中心（任务流程、四智能体协作、实时消息流） |
| `/repairs` | 修复与验证（五步流程、方案、审批、执行验证） |
| `/runtime` | 运行监控与审计（事件强度、类型、主机分布、事件列表） |

旧的 `/workbench/*`、`/iot`、`/device-tasks`、`/risk`、`/agent-ops` 等入口均重定向到上述页面。`/reports` 与 `/soc` 已下线：报告能力保留在总览与 API，SOC 的实时信息由运行监控覆盖，旧地址分别重定向到 `/` 和 `/runtime`。

## 设计系统

- `src/styles/console.css`：浅色安全控制台。深海军蓝侧栏、白色卡片、橙色指令强调、蓝色情报强调；全部 token 与组件样式集中在这一个文件。
- `src/styles/app.css`：应用 shell 级别的滚动与页面工具类。
- `src/components/`：图标 sprite、PageHeader + TopActions、KpiCard、TopologyMap、AreaChart、DonutChart、WorkflowStrip、EmptyState、Modal、Toast。
- `src/views/`：6 个工作台页面与风险详情；图表用 SVG/CSS 绘制，不依赖图表库。

核心 token：背景 `#eef4fb`、表面 `#ffffff`、正文 `#0d1b2e`、指令橙 `#f4622a`、情报蓝 `#2f6fed`、侧栏 `#0d1a2c`。卡片圆角 14px，KPI 数字 30px/800，正文 13–14px；数字使用 Inter 的可变字体与 tabular-nums，中文回落到 Noto Sans SC / PingFang SC / Microsoft YaHei。

## 开发

```powershell
# frontend 目录
Copy-Item .env.example .env
npm ci
npm run dev
npm run build
npm run test:e2e
```

开发入口 <http://localhost:5173>。

`VITE_API_BASE` 默认 `http://localhost:8000/api`（本地 uvicorn）。如果只启动 Docker Compose 的 backend，使用 `http://127.0.0.1:18000/api`；生产镜像由 nginx 将 `/api` 反向代理到 backend，构建时 `VITE_API_BASE=/api`。

## 令牌与数据

- 只读页面不需要令牌；审批、设备写、存档与清理需要顶栏“操作令牌”。
- 令牌只保存在当前页面内存中，刷新即清除，不写入 localStorage、URL 或报告。
- 数据来自现有 FastAPI 接口；接口超时或未配置时页面显示错误/空态，不伪造数值。

## 本轮实验与存档

- 侧栏“本轮实验 → 管理与新一轮”打开生命周期面板，先展示保留项与将清理项。
- **保留**：资产、组件、服务、设备连接、发现记录、传感器、采集配置、扫描目标、策略与官方公告。
- **归档并清理**：漏洞情报、匹配、风险、研判运行、修复任务、运行时事件、追踪与审计记录；全局 CVE 情报缓存保留以加速下一轮。
- “仅归档结果”只写快照；“归档并开始新一轮”会先写归档，再清理衍生数据，然后回到安全总览。页面刷新不会自动清空，避免误删。
- 后端 `LINUXGUARD_ARCHIVE_ON_STARTUP=1` 时，服务启动会先写结果存档再清理；本地 `scripts/run_local_backend.py` 强制为 0。
- 接口：`GET /api/experiment/state`、`POST /api/experiment/archive`、`POST /api/experiment/reset`、`GET /api/experiment/archives/{filename}`。存档默认写入 `backend/data/archives`（或 `REPORT_ARCHIVE_DIR`）。

## 测试

`shell.spec.js` 使用 Playwright 路由拦截 API，验证 shell、导航、KPI、下线路由重定向、实验生命周期面板和风险裁决页。Windows 可设置 `$env:PLAYWRIGHT_CHANNEL='msedge'` 使用 Edge。

## 设计参考

`mockups/v2/` 保留早期方向的静态设计稿，仅作历史参考；实际页面以 `src/views` 与 `src/styles/console.css` 为准。六页总览截图见 `reports/ui/final-sixpage.jpg`。
