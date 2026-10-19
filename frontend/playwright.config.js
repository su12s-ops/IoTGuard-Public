import { defineConfig, devices } from "@playwright/test";

// The development environment may define an HTTP proxy. Playwright's
// webServer readiness probe must always reach the local Vite server directly.
const localNoProxy = ["localhost", "127.0.0.1", "::1", process.env.NO_PROXY, process.env.no_proxy]
  .filter(Boolean)
  .join(",");
process.env.NO_PROXY = localNoProxy;
process.env.no_proxy = localNoProxy;
const browserChannel = process.env.PLAYWRIGHT_CHANNEL;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  expect: {
    timeout: 5_000
  },
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  workers: process.env.CI ? 2 : undefined,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4174",
    serviceWorkers: "block",
    trace: "on-first-retry",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: "npx vite --host 127.0.0.1 --port 4174 --strictPort --mode e2e",
    env: { VITE_API_BASE: "http://127.0.0.1:4174/api" },
    url: "http://127.0.0.1:4174",
    reuseExistingServer: false,
    timeout: 60_000
  },
  projects: [
    {
      name: browserChannel || "chromium",
      use: { ...devices["Desktop Chrome"], ...(browserChannel ? { channel: browserChannel } : {}) }
    }
  ]
});
