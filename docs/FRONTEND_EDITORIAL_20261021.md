# Editorial 前端替换（2026-10-21）

`frontend/` 已整体替换为 Editorial 视觉系统，旧工作台代码删除，只保留新的九模块控制台。

## 替换范围

已删除：

- 旧页面：`Workbench.vue`、`IoTOverview.vue`、`RiskRanking.vue`、`AgentOps.vue`、`DeviceTasks.vue`、`RuntimeMonitor.vue`、`ReportExport.vue` 等全部旧 views。
- 旧组件：Element Plus 表格/图表/证据面板等；旧 `src/design/light.css`、`soc.css`、`styles.css`、`workbench.css`。
- 旧 `workspaces.js`、`demoProgress.js`、`scanOperations.js`、旧 e2e 测试和验证脚本。
- 依赖：`element-plus`、`@element-plus/icons-vue`、`echarts` 已从 `package.json` / lockfile 移除。

新增：

- Vue 3 + Vite + Editorial CSS；SVG 图标、手绘图表、自建 Modal/Toast/空态。
- 九条路由：`/`、`/assets`、`/risks`、`/risks/:id`、`/agents`、`/repairs`、`/runtime`、`/reports`、`/soc`。
- 旧 URL（`/workbench/*`、`/iot`、`/devices`、`/scans`、`/risk`、`/vulnerabilities`、`/agent-ops`、`/workflow`、`/device-tasks`、`/remediation`）重定向到最接近的新模块。

## 设计

- 奶油纸底 `#f5eee2`、墨色 `#181410`、朱红 `--accent: #d9482b`；数字用 Georgia，正文 Segoe UI / Microsoft YaHei。
- 无阴影大卡、1px 黑边框、硬边按钮、发丝线；图表与指标不使用渐变装饰。
- `src/styles/editorial.css` 是 token 与组件的唯一入口；`app.css` 只放应用布局、滚动、模态与表单。
- 设计参考保留在 `mockups/v2/`（三方向静态稿）；实际页面以 `src/views` 为准。

## 数据与权限

- 数据全部走现有 FastAPI；接口超时或未配置时显示错误/空态，不伪造数值。
- 只读页面不需要令牌；人工裁决、Harness 批准/执行、资产导入/发现、运行时证据上传需要顶栏“操作令牌”。
- 令牌只存在内存，刷新即清除，不写入 localStorage / URL / 报告。

## 保留的写入入口

- 风险详情：确认受影响 / 判为不受影响（`/analysis/risks/{id}/human-review`）。
- 修复与验证：批准计划、执行已批准计划（`/harness/runs/{id}/approve|execute`）。
- 资产与发现：清单导入（`/assets/upload`）、授权发现（`/iot/discovery`）。
- 运行与审计：证据上传（`/runtime/ebpf/upload`）、事件 CSV 导出。
- 报告与归档：Markdown / JSON / CSV 下载与浏览器打印。

## 尚未迁移

旧版中的 IoT 接入向导、扫描中心、设备任务创建、修复建议生成、AgentOps 授权/继续、Trace 深层钻取没有在新 IA 中重做；旧入口会重定向到最接近的新模块。下一轮应按 Editorial 组件补齐这些流程，而不是恢复旧页面。

## 验证

- `npm run build` 通过（Vue 3 + Vite，无 Element Plus/ECharts）。
- `npm run test:e2e` 通过 3 项：shell/导航、SOC bare 布局、风险裁决页。
- 连接 Docker backend（18000）在 1440×900 做过真实数据冒烟；密集页面在 900 高度下使用主区域纵向滚动，不出现横向溢出。

## 开发提示

- 本地 uvicorn：`VITE_API_BASE=http://localhost:8000/api`。
- 只用 Docker backend：`VITE_API_BASE=http://127.0.0.1:18000/api`。
- 生产镜像由 nginx 把 `/api` 反向代理到 backend，构建参数 `VITE_API_BASE=/api`。
