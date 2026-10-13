import { expect, test } from "@playwright/test";

// 阶段六：互联网授权目标扫描——登记授权、令牌门禁、扫描生命周期与结果呈现。
// API fixtures 均为合成数据；浏览器测试不接触任何真实主机。
const capabilities = {
  control_configured: true,
  allowed_networks: ["203.0.113.0/24"],
  limits: { max_ports: 128, timeout: 2.5, workers: 16, default_ports: [22, 80] },
  note: "仅支持 IP 字面量目标；不做漏洞利用验证。",
};
const completedRun = {
  run_id: "SCAN-TEST01", target_id: 1, target_ip: "203.0.113.10", status: "completed",
  ports_scanned: [22, 443, 9000], ports_scanned_count: 3,
  open_ports: [443, 9000], open_ports_count: 2,
  identified_services: [
    { port: 443, service_type: "https", product: "nginx/1.18.0", version: "1.18.0", auth_state: "unknown" },
  ],
  identified_count: 1,
  unmatched_ports: [{ port: 9000, banner: "CUSTOM-GATEWAY 3.2.1 ready." }],
  vulnerability_hits: 1, device_id: "DEV-TEST000001",
  findings: {
    security_status: "at_risk",
    boundaries: ["本次未发送任何漏洞利用载荷；CVE 命中为版本比对结论，不代表利用成功。"],
  },
  error: "", created_at: "2026-10-01T10:00:00Z", completed_at: "2026-10-01T10:00:05Z",
};
const targetFixture = {
  id: 1, name: "演示 VPS", ip: "203.0.113.10", authorization_basis: "自有云主机（订单 fixture）",
  ports: [], ports_count: 0, enabled: true, notes: "",
  last_run: { run_id: "SCAN-TEST01", status: "completed", open_ports_count: 2, identified_count: 1, vulnerability_hits: 1 },
};

async function setup(page, overrides = {}) {
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const defaults = {
    "/api/health": { status: "ok" },
    "/api/demo/progress": { running: false, steps_done: [] },
    "/api/scans/capabilities": capabilities,
    "/api/scans/targets": [targetFixture],
    "/api/scans/runs": [completedRun],
    "/api/scans/runs/SCAN-TEST01": completedRun,
  };
  await page.route(/^https?:\/\/[^/]+\/api\//, async route => {
    const path = new URL(route.request().url()).pathname;
    const handler = overrides[path];
    if (typeof handler === "function") return handler(route);
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(handler ?? defaults[path] ?? []) });
  });
  return errors;
}

async function token(page) {
  await page.getByText("设备操作配置", { exact: true }).click();
  await page.getByLabel("设备操作令牌").fill("fixture-token");
}

test("scan target registration requires token and shows backend authorization errors", async ({ page }) => {
  const errors = await setup(page, {
    "/api/scans/targets": async route => {
      if (route.request().method() === "GET") return route.fulfill({ json: [] });
      expect(route.request().headers()["x-control-token"]).toBe("fixture-token");
      expect(route.request().postDataJSON()).toEqual({
        name: "演示 VPS", ip: "example.com", authorization_basis: "自有云主机（订单 fixture）",
        ports: [], notes: "",
      });
      return route.fulfill({ status: 400, json: { detail: "设备地址必须是明确的 IP，不接受域名或 URL" } });
    },
  });
  await page.goto("/scans");
  await expect(page.getByRole("heading", { name: "互联网扫描", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole("button", { name: "登记目标", exact: true })).toBeDisabled();
  await token(page);
  await page.getByLabel("目标名称", { exact: true }).fill("演示 VPS");
  await page.getByLabel("目标 IP", { exact: true }).fill("example.com");
  await page.getByLabel("授权依据", { exact: true }).fill("自有云主机（订单 fixture）");
  await page.getByRole("button", { name: "登记目标", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("必须是明确的 IP");
  expect(await page.evaluate(() => Object.values(localStorage).join(" "))).not.toContain("fixture-token");
  expect(errors).toEqual([]);
});

test("scan lifecycle polls to completion and drawer shows evidence with boundaries", async ({ page }) => {
  let started = false;
  let pollCount = 0;
  const errors = await setup(page, {
    "/api/scans/runs": async route => {
      if (route.request().method() === "POST") {
        expect(route.request().headers()["x-control-token"]).toBe("fixture-token");
        expect(route.request().postDataJSON()).toEqual({ target_id: 1 });
        started = true;
        return route.fulfill({ status: 202, json: { run_id: "SCAN-LIVE01", status: "running", target_id: 1, target_ip: "203.0.113.10", ports: [22, 80, 443] } });
      }
      if (!started) return route.fulfill({ json: [completedRun] });
      pollCount += 1;
      // 首次轮询仍在扫描，随后完成——验证页面持续轮询与完成提示。
      return route.fulfill({ json: pollCount === 1 ? [{ ...completedRun, run_id: "SCAN-LIVE01", status: "running" }] : [completedRun, { ...completedRun, run_id: "SCAN-LIVE01" }] });
    },
  });
  await page.goto("/scans");
  await token(page);
  await expect(page.getByRole("row").filter({ hasText: "演示 VPS" })).toContainText("命中 1");
  await page.getByRole("row").filter({ hasText: "演示 VPS" }).getByRole("button", { name: "扫描", exact: true }).click();
  await expect(page.getByText(/扫描完成：203\.0\.113\.10 识别 1 个服务，命中 1 个受影响 CVE/)).toBeVisible();
  await page.getByRole("row").filter({ hasText: "SCAN-TEST01" }).getByRole("button", { name: "详情", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("nginx/1.18.0");
  await expect(page.getByRole("dialog")).toContainText("CUSTOM-GATEWAY 3.2.1 ready.");
  await expect(page.getByRole("dialog")).toContainText("本次未发送任何漏洞利用载荷");
  await expect(pollCount).toBeGreaterThanOrEqual(2);
  expect(errors).toEqual([]);
});
