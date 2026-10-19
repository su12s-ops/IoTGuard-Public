# IoTGuard Frontend

Vue 3 + Vite + Element Plus + ECharts；Node.js 24。

```powershell
# frontend 目录
Copy-Item .env.example .env
npm ci
npm run dev
npm run build
npm run test:e2e
```

开发入口 <http://localhost:5173>，默认 API `http://localhost:8000/api`；Docker 由 nginx 提供 dist 和 API 反向代理。

默认首页是 IoT 工作台，SOC 位于 `/soc`。控制令牌仅保留于前端内存会话。浏览器回归默认 Chromium，首次执行前安装 `npx playwright install chromium`；Windows 可设置 `$env:PLAYWRIGHT_CHANNEL='msedge'` 使用已安装 Edge。

参见 [项目首页](../README.md)和[部署说明](../DEPLOYMENT.md)。
