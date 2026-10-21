# IoTGuard Frontend — Editorial

Vue 3 + Vite 的桌面安全控制台。只保留一套 Editorial 视觉系统，不再包含 Element Plus / ECharts 或旧工作台页面。

## 页面

| 路径 | 页面 |
| --- | --- |
| `/` | 安全态势 |
| `/assets` | 资产与发现 |
| `/risks` | 漏洞与风险 |
| `/risks/:id` | 风险详情 / 人工裁决 |
| `/agents` | 智能研判 |
| `/repairs` | 修复与验证 |
| `/runtime` | 运行与审计 |
| `/reports` | 报告与归档 |
| `/soc` | SOC 态势大屏（无侧栏） |

旧的 `/workbench/*`、`/iot`、`/device-tasks`、`/risk`、`/runtime`（同地址）、`/agent-ops` 等入口均重定向到上述页面。

## 设计系统

- `src/styles/editorial.css`：奶油纸底、黑边框、衬线数字、朱红强调；token 和组件都在这一个文件。
- `src/styles/app.css`：应用 shell、滚动、模态、toast、表单和少量页面级工具类。
- `src/components/`：图标 sprite、PageHeader、EmptyState、Modal、Toast、GaugeRing、DonutChart。
- `src/views/`：9 个模块；图表用 SVG/CSS 绘制，不依赖图表库。

主色 `--accent: #d9482b`，纸底 `#f5eee2`，墨色 `#181410`；数字使用 Georgia，正文使用 Segoe UI / Microsoft YaHei。

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

- 只读页面不需要令牌；审批、设备写和部分审计查询需要顶栏“操作令牌”。
- 令牌只保存在当前页面内存中，刷新即清除，不写入 localStorage、URL 或报告。
- 数据来自现有 FastAPI 接口；接口超时或未配置时页面显示错误/空态，不伪造数值。

## 测试

`shell.spec.js` 使用 Playwright 路由拦截 API，验证 shell、导航、SOC bare 布局和风险裁决页。Windows 可设置 `$env:PLAYWRIGHT_CHANNEL='msedge'` 使用 Edge。

## 设计参考

`mockups/v2/` 保留了本次 Editorial 方向的静态设计稿与 9 模块总览，仅作参考；实际页面以 `src/views` 为准。
