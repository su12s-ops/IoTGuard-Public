import { test, expect } from "@playwright/test";

const health = {
  status: "ok",
  build: { revision: "test", created: "2026-10-21" },
  layers: {
    backend_online: true,
    collection_node: { configured: true, registered: ["node-a"], online_ids: ["node-a"], online: true },
    sensors: {
      total: 2,
      healthy: 1,
      status: "degraded",
      sensors: [
        { sensor_id: "falco", asset_id: 1, source: "falco", status: "running", heartbeat_age_seconds: 30 },
        { sensor_id: "logread", asset_id: 2, source: "logread", status: "stale", heartbeat_age_seconds: 3600 }
      ]
    },
    runtime_evidence: { fresh: false, latest_event_age_seconds: 3600, window_seconds: 900, basis: "test" }
  }
};

const summary = {
  total_vulnerabilities: 1200,
  high_risk_vulnerabilities: 4,
  asset_count: 3,
  pending_remediation_tasks: 1,
  risk_level_distribution: { Critical: 1, High: 3, Medium: 8, Low: 9 },
  source_distribution: { "Ubuntu Security API": 900, "NVD CVE API": 300 },
  top_vulnerabilities: [
    { cve_id: "CVE-2026-63073", hostname: "OpenWrt-Lab", score: 80.47, risk_level: "Critical" }
  ]
};

const devices = [
  {
    key: "asset:2",
    name: "OpenWrt-Lab",
    ecosystem: "openwrt",
    version: "25.12.4",
    inventory_complete: true,
    identity_confidence: 0.95,
    component_count: 182,
    matches: { count: 2, confirmed: 1, pending: 1, assessment: "partial" },
    runtime: "requires_sensor_evidence",
    remediation: "requires_device_specific_plan",
    next_action: "review_applicability"
  }
];

const risks = [
  {
    risk_id: 12,
    cve_id: "CVE-2026-63073",
    hostname: "OpenWrt-Lab",
    package_name: "openssl",
    preliminary_score: 80.47,
    preliminary_level: "Critical",
    static_score: 76.44,
    exposure_score: 100,
    runtime_score: 66.12,
    business_score: 50,
    actionability_score: 94.92,
    cvss_score: 98,
    epss_score: 1.16,
    kev_score: 0,
    affected_status: "potentially_affected",
    reachable_status: "internet_exposed",
    runtime_status: "contextual",
    review_status: "pending_human_review",
    human_review_required: true,
    active: true
  }
];

const unifiedRun = {
  run_id: "UA-TEST-0001",
  task_type: "risk_review",
  target_ref: "OpenWrt-Lab",
  mode: "formal",
  status: "completed",
  created_at: "2026-10-21T10:24:00",
  completed_at: "2026-10-21T10:28:00"
};

test.beforeEach(async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    if (!url.pathname.startsWith("/api/")) return route.continue();
    const path = url.pathname.replace(/^\/api/, "");
    let body = {};
    if (path === "/health") body = health;
    else if (path === "/dashboard/summary") body = summary;
    else if (path === "/devices/business/overview") body = { devices };
    else if (path === "/risk/ranking") body = risks;
    else if (path === "/matching/results") body = [];
    else if (path === "/reports/archives") body = { archives: [] };
    else if (path === "/reports/summary.json") body = { overview: summary, review: { status: "human_review" } };
    else if (path === "/unified/runs") body = { runs: [unifiedRun] };
    else if (path.startsWith("/unified/runs/")) body = { ...unifiedRun, agents: {}, final: { policy: { status: "pending_human_review" } }, harness_checks: [] };
    else if (path === "/harness/runs") body = [];
    else if (path === "/runtime/ebpf/status") body = { matched_asset_count: 1, matched_asset_ratio: 33, latest_event_at: "2026-10-21T10:24:00" };
    else if (path === "/runtime/ebpf/summary") body = { total: 2, high_value_count: 1, observation_mode_counts: { ebpf: 2, sensor: 0 } };
    else if (path === "/runtime/ebpf/events") body = { events: [] };
    else if (path === "/experiment/state") body = {
      summary: { assets: 3, iot_devices: 1, risks: 1, high_risks: 1, runtime_events: 2 },
      kept: { linux_asset: 3, asset_package: 1, asset_service: 1, iot_device: 1 },
      cache: { vulnerability_intelligence_source: 0 },
      derived: { vulnerability_info: 1, vulnerability_match: 1, risk_assessment: 1, runtime_event: 2 },
      active_runs: { unified: 0, harness: 0, orchestration: 0 },
      archives: []
    };
    else if (path === "/workflow/behavior-chains") body = [];
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
});

test("shell renders and navigation stays inside the new app", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("h1")).toHaveText("安全总览");
  await expect(page.locator(".rail")).toBeVisible();
  await expect(page.locator(".top-actions")).toBeVisible();
  await expect(page.locator(".kpi-row .kpi")).toHaveCount(4);

  await page.getByRole("link", { name: "资产与发现" }).click();
  await expect(page).toHaveURL(/\/assets$/);
  await expect(page.locator("h1")).toHaveText("资产与发现");
  await expect(page.locator(".kpi-row .kpi")).toHaveCount(4);

  await page.getByRole("link", { name: "漏洞与风险" }).click();
  await expect(page).toHaveURL(/\/risks$/);
  await expect(page.locator("h1")).toHaveText("漏洞与风险");
  await expect(page.locator(".risk-list-card table tbody tr")).toHaveCount(1);
});

test("retired reports and SOC entries redirect to the live workspace", async ({ page }) => {
  await page.goto("/soc");
  await expect(page).toHaveURL(/\/runtime$/);
  await expect(page.locator("h1")).toHaveText("运行监控与审计");

  await page.goto("/reports");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.locator("h1")).toHaveText("安全总览");

  await expect(page.getByRole("link", { name: "报告与归档" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "SOC 态势大屏" })).toHaveCount(0);
});

test("experiment lifecycle shows kept devices and derived data before a new round", async ({ page }) => {
  await page.goto("/");
  await page.locator(".rl-btn").click();
  await expect(page.getByRole("heading", { name: "本轮实验与存档" })).toBeVisible();
  await expect(page.getByText("保留 · 设备与配置")).toBeVisible();
  await expect(page.getByText("归档并清理 · 运行产物")).toBeVisible();
  await expect(page.getByRole("button", { name: "归档并开始新一轮" })).toBeVisible();
  await expect(page.getByText("需要操作令牌")).toBeVisible();
  await expect(page.locator(".exp-token-box input")).toBeVisible();
});

test("risk detail renders the decision layout", async ({ page }) => {
  await page.goto("/risks/CVE-2026-63073");
  await expect(page.locator("h1")).toHaveText("CVE-2026-63073");
  await expect(page.getByText("判定依据")).toBeVisible();
  await expect(page.getByText("人工裁决")).toBeVisible();
  await expect(page.getByRole("button", { name: "确认受影响" })).toBeVisible();
});
