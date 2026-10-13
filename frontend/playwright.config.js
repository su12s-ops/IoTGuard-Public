import { defineConfig, devices } from "@playwright/test";

// The development environment may define an HTTP proxy. Playwright's
// webServer readiness probe must always reach the local Vite server directly.
const localNoProxy = ["localhost", "127.0.0.1", "::1", process.env.NO_PROXY, process.env.no_proxy]
  .filter(Boolean)
  .join(",");
process.env.NO_PROXY = localNoProxy;
process.env.no_proxy = localNoProxy;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  expect: {
    timeout: 5_000
  },
  fullyParallel: true,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4174",
    trace: "on-first-retry",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: "npx vite --host 0.0.0.0 --port 4174",
    url: "http://127.0.0.1:4174",
    reuseExistingServer: false,
    timeout: 60_000
  },
  projects: [
    {
      name: "msedge",
      use: { ...devices["Desktop Edge"], channel: "msedge" }
    }
  ]
});
