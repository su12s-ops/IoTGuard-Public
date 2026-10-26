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

在项目根目录执行：

```powershell
Copy-Item frontend/.env.example frontend/.env
npm --prefix frontend ci
npm --prefix frontend run dev
npm --prefix frontend run build
node --test frontend/tests/*.test.js
npm --prefix frontend run test:e2e
```

开发入口 <http://localhost:5173>。页面始终请求同源 `/api`，Vite 转发到本机 API 8000；Docker nginx 转发到内部 backend，浏览器不直连后端端口。配置见 `frontend/.env.example`。

## 控制请求与数据

Docker 与配置齐全的本地代理在服务端注入控制令牌，浏览器通过会话状态识别 managed 模式；没有托管代理时，手动令牌只保存在页面内存，刷新即清除，不写入 localStorage、URL 或报告。服务端仍校验控制请求，设备写入另有作用域与审批门禁。

接口超时、模型缺失、无传感器或未完成状态如实显示。流程进度、运行角色、预算和耗时来自后端数据；不根据 `completed` 推断四角色均成功。

## 本轮流程

“开始”执行情报、匹配、风险、四角色研判及逐项审核，复用持久化控制台流程。“刷新本轮”需无活动任务，按专门契约清理本轮数据；旧归档 API 仍兼容，但控制台不再展示旧归档面板。完整语义见 [控制台流程](../docs/architecture/console-workflow.md)。

## 测试与维护

Playwright 启动隔离 Vite 并拦截 API，验证导航、状态展示与操作契约；Windows 可设置 `$env:PLAYWRIGHT_CHANNEL='msedge'`。Node 测试验证状态、时间和请求逻辑。它们不证明现场设备或模型质量已通过。

当前页面以 `src/views/` 和 `src/styles/console.css` 为准，已移除不参与构建的历史多主题静态原型。入口与规则见 [部署指南](../docs/guides/deployment.md)、[验证方法](../docs/validation/testing.md)及[文档导航](../docs/README.md)。
