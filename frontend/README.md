# LinuxGuard Frontend

Vue 3 + Vite + Element Plus + ECharts frontend for LinuxGuard.

## Start

```powershell
cd <PROJECT_ROOT>\代码\frontend
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:5173`.

## IoT upgrade (0.2)

New routes: /iot and /device-tasks; /runtime includes coverage, timelines and comparison. OpenWrt remediation routes to approved device tasks instead of manual success status changes.

Device operation tokens remain in memory. All API data is real at runtime; synthetic devices are only in Playwright fixtures.

Run npm run build and npm run test:e2e -- --workers=2 (Microsoft Edge required by the current Playwright configuration).
