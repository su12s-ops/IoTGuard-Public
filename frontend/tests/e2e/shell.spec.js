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
    if (path === "/console/current") body = { workflow: null };
    else if (path === "/health") body = health;
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
    else if (path === "/runtime/ebpf/reliability") body = { sensors: [{ asset_id: 2, sensor_id: "router-logread", source: "logread", status: "running", dropped_events: "unavailable", server_observed: { stored_events: 92 }, collection_window: { status: "truncated", lines_total: 100, skipped_lines: 8, ring_loss: "unavailable" } }] };
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
  await expect(page.locator(".top-actions")).toHaveCount(0);
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

test("risk detail renders the decision layout", async ({ page }) => {
  await page.goto("/risks/CVE-2026-63073");
  await expect(page.locator("h1")).toHaveText("CVE-2026-63073");
  await expect(page.getByText("判定依据")).toBeVisible();
  await expect(page.getByText("人工裁决")).toBeVisible();
  await expect(page.getByRole("button", { name: "确认受影响" })).toBeVisible();
});

test("one start drives durable stages, survives reload and waits for human audit", async ({ page }) => {
  let flow = null;
  let starts = 0;
  const steps = ['intelligence', 'matching', 'risk', 'agents', 'audit'].map(key => ({ key, label: key, status: 'pending' }));
  await page.route("**/api/console/current", route => route.fulfill({ json: { workflow: flow } }));
  await page.route("**/api/console/start", route => {
    starts++;
    flow = { id: 'FLOW-TEST', status: 'running', stage: 'intelligence', progress_percent: 0, message: 'Fetching official intelligence', steps };
    return route.fulfill({ json: { workflow: flow } });
  });
  await page.goto('/');
  await expect(page.getByRole('button', { name: '开始', exact: true })).toBeVisible();
  await expect(page.getByRole('search')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '管理与新一轮' })).toHaveCount(0);
  await page.getByRole('button', { name: '开始', exact: true }).click();
  await expect(page.getByRole('button', { name: '正在执行' })).toBeDisabled();
  expect(starts).toBe(1);
  flow = { ...flow, stage: 'agents', progress_percent: 60, message: 'Four agents running' };
  await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '60');
  await page.reload();
  await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '60');
  flow = { ...flow, status: 'awaiting_review', stage: 'audit', progress_percent: 80, message: 'Human audit required' };
  await expect(page.getByRole('link', { name: '进入人工审核' })).toBeVisible();
  await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '80');
  flow = { ...flow, status: 'completed', progress_percent: 100, message: 'Review completed' };
  await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100');
});

test("live analysis distinguishes active work, queue, reuse and partial results", async ({ page }) => {
  const flow = { id: "FLOW-task-graph", status: "running", stage: "agents", progress_percent: 63,
    message: "分析窗口结束", steps: [],
    round: { counts: { matches: 29, risks_calculated: 29, processed: 6, selected: 20, remaining: 23 } },
    execution: { profile: "task_graph", queued_objects: 12, reused_reports: 5,
      active: [{ object_id: "risk-7", roles: ["vulnerability_analyst"], elapsed_seconds: 125,
        activity: { roles: [{role: "vulnerability_analyst", status: "running", phase: "queue", elapsed_seconds: 7}],
          timeline: [{role: "vulnerability_analyst", event: "model_waiting", at: "2026-10-25T11:20:00Z"}] } }],
      recent_results: [{object_id: "risk-6", run_id: "old-failed", roles: [{role: "runtime_analyst", status: "degraded", failure_category: "context_limit", error: "context_budget_exceeded"}]}] } };
  await page.route("**/api/console/current", route => route.fulfill({ json: { workflow: flow } }));
  await page.goto("/agents");
  const panel = page.getByRole("region", { name: "本轮自动流程" });
  await expect(panel).toContainText("本批实际运行 1 项 · 排队 12 项 · 复用报告 5 份");
  await expect(panel).toContainText("risk-7 · 漏洞分析 · 已耗时 2 分 5 秒");
  await expect(panel).toContainText("进度比例不代表剩余时间");
  await expect(panel).toContainText("等待模型槽位");
  await panel.getByText("本批最近完成结果与失败原因").click();
  await expect(panel).toContainText("上下文超限：context_budget_exceeded");
  flow.execution.active[0].activity.roles[0].phase = "model";
  await page.reload();
  await expect(panel).toContainText("等待模型生成并返回");
  flow.status = "partial";
  flow.execution.active = [];
  await page.reload();
  await expect(panel).toContainText("未完成项仍需继续分析");
});

test("refresh is one action without archival or token dialogs", async ({ page }) => {
  let resets = 0;
  await page.route('**/api/experiment/refresh', route => {
    resets++;
    expect(route.request().headers()['x-experiment-action']).toBe('refresh');
    return route.fulfill({ json: { cleared: { risk_assessment: 2 }, kept: { assets: 3 } } });
  });
  await page.goto('/agents');
  await page.getByRole('button', { name: '刷新本轮', exact: true }).click();
  await expect(page).toHaveURL(/\/$/);
  expect(resets).toBe(1);
  await expect(page.locator('input[type=password]:visible')).toHaveCount(0);
});

test("runtime exposes unknown losses and clears stale reliability on request failure", async ({ page }) => {
  await page.goto('/runtime');
  const table = page.locator('.sensor-reliability');
  await expect(table).toContainText('router-logread');
  await expect(table).toContainText('不可用');
  await expect(table).toContainText('truncated');
  await expect(table).toContainText('跳过 8');
  await page.route('**/api/runtime/ebpf/reliability', route => route.fulfill({ status: 503, json: { detail: 'unavailable' } }));
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('部分运行时接口暂时不可用');
  await expect(table).not.toContainText('router-logread');
});

test("console snapshot age never promises current remote intelligence", async ({ page }) => {
  await page.route('**/api/console/current', route => route.fulfill({ json: { workflow: {
    id: 'snapshot-test', status: 'partial', steps: [], progress_percent: 20,
    intelligence_snapshots: { openwrt: { status: 'stale', advisory_count: 2,
      oldest_content_updated_at: '2026-10-20T00:00:00+00:00', latest_content_updated_at: '2026-10-26T00:00:00+00:00', sha256: 'a'.repeat(64) } }
  } } }));
  await page.goto('/');
  await page.getByText('官方情报快照与时效').click();
  const panel = page.getByRole('region', { name: '本轮自动流程' });
  await expect(panel).toContainText('含超过一天的本地内容');
  await expect(panel).toContainText('远端最新性未验证');
  await expect(panel).toContainText('a'.repeat(64));
});
