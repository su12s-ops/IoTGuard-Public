import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ page }) => {
  // Fail closed for unmatched API requests; never contact an actual backend.
  await page.route(/^https?:\/\/[^/]+\/api\//, route => route.fulfill({ json: [] }));
  // The runtime timeline now loads assets even before a selection is made.
  // Keep legacy browser tests isolated from any real local backend.
  await page.route("**/api/assets", async route => route.fulfill({ json: [] }));
  await page.route("**/api/health", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ status: "ok", service: "LinuxGuard" }) });
  });
  await page.route("**/api/demo/progress", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        running: false,
        current_step: "",
        current_agent: "",
        steps_done: [],
        planned_steps: [],
        total_steps: 0,
        error: ""
      })
    });
  });
});

test("keeps historical risk separate from scoped postrepair acceptance", async ({ page }) => {
  const cve = "CVE-2099-9001";
  const chain = { chain_id: `3-${cve}`, asset: { id: 3, hostname: "fixture-clone" },
    intelligence: { cve_id: cve }, package: { name: "curl", installed_version: "fixed" },
    matching: {}, attack_scenario: {}, dependency_graph: {}, runtime_verification: {},
    risk: {}, remediation: {} };
  const events = [
    { id: 1, kind: "post_repair_assessment", payload: { run_id: "UA-fixture", trace_id: "TR-fixture",
      decision: { verdicts: [{ impact_status: "not_affected", recommended_action: "monitor" }] }, policy: { status: "pending_human_review" } } },
    { id: 2, kind: "delegated_business_acceptance", actor: "codex:fixture-delegate", payload: {
      run_id: "UA-fixture", status: "fixed_accepted_scoped", scope: "fixture version smoke only",
      limitations: ["no runtime coverage"], raw_model_corrections: ["fixture official notice corrected"] } }
  ];
  await page.route("**/api/workflow/behavior-chains", r => r.fulfill({ json: [chain] }));
  await page.route("**/api/risk/ranking", r => r.fulfill({ json: [{ risk_id: 127, cve_id: cve, hostname: "fixture-clone", active: false,
    review_verdict: "confirmed_affected", governance: { events } }] }));
  await page.route("**/api/vulnerabilities/official/records?**", r => r.fulfill({ json: { records: [], corrections: [] } }));
  let runtimeRequests = 0;
  await page.route("**/api/runtime/cve-evidence?**", r => { runtimeRequests++; return r.fulfill({ status: 404 }); });
  await page.goto(`/behavior-chain/detail?chain_id=3-${cve}`);
  const current = page.getByRole("region", { name: "修复后复评与接受" });
  await expect(current).toContainText("not_affected / monitor");
  await expect(current).toContainText("fixed_accepted_scoped");
  await expect(current).toContainText("codex:fixture-delegate");
  await expect(current).toContainText("不代表所有业务通过");
  await expect(current).toContainText("fixture official notice corrected");
  await expect(page.getByText("历史风险基线", { exact: true })).toBeVisible();
  expect(runtimeRequests).toBe(0);
});

test("opens asset details without runtime data shape errors and counts affected matches only", async ({ page }) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.route("**/api/assets**", async (route) => {
    const isDetail = new URL(route.request().url()).pathname.endsWith("/assets/1");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(isDetail ? {
        id: 1, hostname: "asset-01", ip_address: "10.0.0.1", os_name: "Ubuntu", os_version: "24.04",
        business_level: "core", packages: [], services: []
      } : [{ id: 1, hostname: "asset-01", ip_address: "10.0.0.1", os_name: "Ubuntu", os_version: "24.04", business_level: "core" }])
    });
  });
  await page.route("**/api/matching/results", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([
      { id: 1, asset_id: 1, hostname: "asset-01", cve_id: "CVE-2099-0001", package_name: "nginx", affected: true },
      { id: 2, asset_id: 1, hostname: "asset-01", cve_id: "CVE-2099-0002", package_name: "curl", affected: false }
    ]) });
  });
  await page.route("**/api/risk/ranking", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
  await page.route("**/api/runtime/ebpf/events**", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ count: 1, events: [{ asset_id: 1, hostname: "asset-01", process_name: "nginx" }] }) });
  });

  await page.goto("/assets");
  await expect(page.getByRole("region", { name: "资产概况" })).toContainText("漏洞命中1");
  await page.getByRole("button", { name: "详情", exact: true }).click();
  await expect(page.getByRole("heading", { name: "asset-01" })).toBeVisible();
  await expect(page.getByRole("tab", { name: /运行状态 1/ })).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("renders normalized EPSS and the effective final risk level", async ({ page }) => {
  await page.route("**/api/risk/ranking", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([{
      risk_id: 1, object_id: "risk-1", hostname: "asset-01", cve_id: "CVE-2099-0003", package_name: "nginx",
      preliminary_level: "High", preliminary_score: 72, has_final_conclusion: true, risk_level: "Medium", final_score: 48,
      epss_score: 0.71, risk_factors: { exploit_likelihood: { probability: 0.0071 } }, review_status: "human_confirmed"
    }]) });
  });
  await page.route("**/api/matching/results", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route("**/api/workflow/behavior-chains", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));

  await page.goto("/risk");
  const row = page.getByRole("row").filter({ hasText: "CVE-2099-0003" });
  await expect(row).toContainText("中危");
  await expect(row).toContainText("0.7%");
  await expect(row).not.toContainText("71.0%");
});

test("explains why remediation is empty and exposes only the real review gate", async ({ page }) => {
  const risks = [
    { risk_id: 1, review_status: "human_confirmed", human_review_required: false, risk_level: "High" },
    ...Array.from({ length: 15 }, (_, index) => ({ risk_id: index + 2, review_status: "pending_human_review", human_review_required: true, risk_level: "High" }))
  ];
  await page.route("**/api/risk/ranking", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(risks) }));
  await page.route("**/api/remediation/tasks", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));

  await page.goto("/remediation");
  await expect(page.getByText("尚未生成处置任务")).toBeVisible();
  await expect(page.getByText("待人工审核").last()).toBeVisible();
  await expect(page.getByText("15 条")).toBeVisible();
  await expect(page.getByText("1 条", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /生成 1 条处置方案/ })).toBeEnabled();
  await expect(page.getByRole("button", { name: /人工审批放行/ })).toHaveCount(0);
  await expect(page.getByText("No Data")).toHaveCount(0);
});

test("uses the report overview high-risk total instead of the Top 5 length", async ({ page }) => {
  const topRisks = Array.from({ length: 5 }, (_, index) => ({
    rank: index + 1, asset_id: 1, cve_id: `CVE-2099-10${index}`, preliminary_level: "High", preliminary_score: 70 - index,
    has_final_conclusion: false, review_status: "pending_human_review", risk_factors: { known_exploitation: { is_kev: false }, exploit_likelihood: { probability: 0.01 }, technical_severity: { cvss_score: 8 } }
  }));
  await page.route("**/api/reports/summary.json", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ overview: { asset_count: 3, vulnerability_count: 104, affected_match_count: 16, high_risk_count: 7, human_review_required_count: 15, kev_vulnerability_count: 0 }, top_risks: topRisks }) }));
  await page.route("**/api/reports/archives", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ archives: [] }) }));
  await page.route("**/api/assets", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route("**/api/workflow/behavior-chains", async (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));

  await page.goto("/reports");
  const current = page.getByRole("row").filter({ hasText: "当前有效数据集" });
  await expect(current).toContainText("7");
});

test("loads the intelligence center from the app shell", async ({ page }) => {
  await page.route("**/api/vulnerabilities**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: "[]"
    });
  });

  await page.goto("/vulnerabilities");

  await expect(page.getByRole("main").getByRole("heading", { name: "漏洞情报", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "情报源同步" }).click();
  await expect(page.getByRole("button", { name: /同步 Ubuntu 情报/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /同步 NVD 情报/ })).toBeVisible();
});

test("loads the runtime control center with diagnostics", async ({ page }) => {
  await page.route("**/api/runtime/ebpf/status", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        db_event_count: 2,
        file_event_count: 2,
        asset_count: 1,
        matched_asset_count: 1,
        matched_asset_ratio: 100,
        latest_event_at: "2026-06-26T10:00:00Z",
        unmatched_hosts: [],
        available_hosts: ["vm-runtime-01"],
        available_categories: ["network_activity"],
        available_sources: ["falco_json"],
        source_counts: { falco_json: 2 },
        category_counts: { network_activity: 2 },
        observation_mode_counts: { ebpf: 2 },
        collector_script: "collector/run_falco_capture.sh",
        event_file: "data/ebpf_events.jsonl",
        collector_command: "collector/run_falco_capture.sh http://127.0.0.1:8000/api 60",
        recommendations: ["Runtime evidence is healthy."]
      })
    });
  });
  await page.route("**/api/runtime/ebpf/summary", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        total: 2,
        high_value_count: 1,
        category_counts: { network_activity: 2 },
        severity_counts: { critical: 1, warning: 1 },
        top_processes: [{ name: "nginx", count: 2 }],
        host_counts: { "vm-runtime-01": 2 },
        source_counts: { falco_json: 2 },
        observation_mode_counts: { ebpf: 2 },
        latest_events: []
      })
    });
  });
  await page.route("**/api/runtime/ebpf/events**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        count: 2,
        events: [
          {
            timestamp: "2026-06-26T10:00:00Z",
            hostname: "vm-runtime-01",
            source: "falco_json",
            category: "network_activity",
            rule: "Network connection from nginx",
            process_name: "nginx",
            parent_process: "systemd",
            commandline: "nginx: worker process",
            severity: "critical",
            severity_score: 86,
            tactic: "Command and Control"
          }
        ]
      })
    });
  });
  await page.route("**/api/runtime/ebpf/correlations", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          asset: { id: 1, hostname: "vm-runtime-01", ip_address: "10.0.0.10", os: "Ubuntu 22.04" },
          event_count: 2,
          evidence_score: 88,
          matched_services: ["nginx"],
          matched_packages: ["openssl"]
        }
      ])
    });
  });
  await page.route("**/api/workflow/behavior-chains", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          chain_id: "1-CVE-2099-0001",
          asset: { hostname: "vm-runtime-01" },
          package: { name: "openssl" },
          intelligence: { cve_id: "CVE-2099-0001" },
          runtime_verification: { status: "verified" },
          risk: { adjustment: { runtime: 20 } }
        }
      ])
    });
  });

  await page.goto("/runtime");

  await expect(page.getByRole("main").getByRole("heading", { name: "运行时验证" })).toBeVisible();
  await expect(page.getByRole("button", { name: "生成测试证据" })).toBeVisible();
  await expect(page.getByText("Runtime evidence is healthy.")).toBeVisible();
});

test("shows an ESM-only remediation task as blocked", async ({ page }) => {
  await page.route("**/api/risk/ranking", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  });
  await page.route("**/api/remediation/tasks", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: 1,
          hostname: "legacy-bionic-web",
          cve_id: "CVE-2099-0001:bionic",
          package_name: "openssl",
          current_version: "1.1.1-1ubuntu2.1~18.04.23",
          target_version: "1.1.1-1ubuntu2.1~18.04.23+esm9",
          risk_level: "Medium",
          remediation_command: "sudo pro status  # attach Ubuntu Pro and enable esm-infra first",
          mitigation: "Ubuntu Pro/ESM is required.",
          verification_command: "openssl version",
          status: "blocked"
        }
      ])
    });
  });

  await page.goto("/remediation");

  await expect(page.getByText("前置条件未满足")).toBeVisible();
  await page.locator(".el-table__expand-icon").first().click();
  await expect(page.getByText("Ubuntu Pro/ESM is required.")).toBeVisible();
  await expect(page.getByText("漏洞闭环完成")).not.toBeVisible();
});

test("runs the four-agent review through the task API and renders the result", async ({ page }) => {
  let runCompleted = false;
  let runPollCount = 0;
  const agents = [
    { id: "evidence_audit_agent", name: "证据审计智能体", goal: "审核证据质量" },
    { id: "impact_assessment_agent", name: "漏洞影响研判智能体", goal: "核验漏洞影响" },
    { id: "exposure_runtime_agent", name: "暴露面与运行时智能体", goal: "核验暴露面与运行时证据" },
    { id: "decision_coordinator_agent", name: "处置决策协调智能体", goal: "形成最终裁定" }
  ];
  const completedRun = {
    run_id: "e2e-run-1",
    status: "completed",
    pipeline_version: "deterministic-v2",
    current_stage: "writeback",
    selected_object_count: 1,
    processed_object_count: 1,
    completed_object_count: 1,
    human_review_object_count: 0,
    selected_object_ids: ["asset-1-CVE-2099-0001"],
    answer: "四智能体已完成逐对象联合研判。",
    termination_reason: "pipeline_completed",
    verdict: {
      object_verdicts: [{
        object_id: "asset-1-CVE-2099-0001",
        verdict: "confirmed",
        confidence: 0.92,
        risk_adjustment: 0,
        conflicts: [],
        missing_evidence: [],
        human_review_required: false
      }]
    },
    agent_executions: Object.fromEntries(agents.map((agent) => [agent.id, {
      status: "completed", attempts: 1, duration_ms: 500,
      output_valid: true, opinion_count: 1, error: ""
    }]))
  };

  await page.route("**/api/workflow/overview", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ agents, api_sequence: [], workflow_edges: [] }) });
  });
  await page.route("**/api/analysis/status", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ configured: true, model: "deepseek-v4-flash", agents }) });
  });
  await page.route("**/api/analysis/latest", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(runCompleted ? completedRun : { status: "none" }) });
  });
  await page.route("**/api/analysis/preflight", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      status: runCompleted ? "no_candidates" : "ready",
      asset_count: 1, affected_match_count: 1, candidate_count: runCompleted ? 0 : 1,
      selected_object_count: runCompleted ? 0 : 1,
      selected_object_ids: runCompleted ? [] : ["asset-1-CVE-2099-0001"]
    }) });
  });
  await page.route("**/api/risk/ranking", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([{
      risk_id: 1, asset_id: 1, object_id: "asset-1-CVE-2099-0001",
      hostname: "vm-review-01", cve_id: "CVE-2099-0001", package_name: "nginx",
      preliminary_level: "High", preliminary_score: 82,
      final_score: runCompleted ? 82 : 0, risk_level: runCompleted ? "High" : "Low",
      review_status: runCompleted ? "auto_confirmed" : "candidate",
      review_verdict: runCompleted ? "confirmed" : "",
      has_final_conclusion: runCompleted,
      agent_results: runCompleted ? {
        evidence_audit_agent: {
          evidence_quality: "sufficient", confidence: 0.91,
          reason: "版本与漏洞来源证据完整且可追溯。", valid_evidence_ids: ["EV-PKG", "EV-VULN"]
        },
        impact_assessment_agent: {
          impact_status: "confirmed", confidence: 0.9,
          reason: "已安装版本位于受影响区间。", supporting_evidence_ids: ["EV-PKG"]
        },
        exposure_runtime_agent: {
          exposure_status: "internet_reachable", runtime_status: "contextual", confidence: 0.84,
          reason: "服务对外可达，运行时证据仅用于上下文判断。", supporting_evidence_ids: ["EV-NET", "EV-RT"]
        },
        decision_coordinator_agent: {
          risk_direction: "keep", confidence: 0.88,
          reason: "综合三方意见维持高优先级处置。", evidence_ids: ["EV-PKG", "EV-NET"]
        }
      } : {}
    }]) });
  });
  await page.route("**/api/analysis/runs/e2e-run-1", async (route) => {
    runPollCount += 1;
    if (runPollCount === 1) {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        ...completedRun,
        status: "running",
        current_stage: "agent_reviewing",
        progress_percent: 37,
        current_object_id: "risk-1",
        progress_message: "Evidence agent is running",
        progress_sequence: 4,
        processed_object_count: 0,
        agent_executions: {
          evidence_audit_agent: {
            status: "running", attempts: 1, duration_ms: 0,
            output_valid: false, opinion_count: 0, error: ""
          }
        }
      }) });
      return;
    }
    runCompleted = true;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(completedRun) });
  });
  // createReviewRun always sends retry_failed as a query parameter, so match
  // the pathname plus query string instead of the old query-less URL only.
  await page.route("**/api/analysis/runs?*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      run_id: "e2e-run-1", status: "running", current_stage: "candidate_preflight",
      selected_object_count: 1, pipeline_version: "deterministic-v2"
    }) });
  });

  await page.goto("/workflow");
  await expect(page.getByText("deepseek-v4-flash 已连接")).toBeVisible();
  await page.getByRole("button", { name: "启动风险研判" }).click();
  await expect(page.getByText("Evidence agent is running")).toBeVisible();
  await expect(page.getByText("四智能体已完成逐对象联合研判。")).toBeVisible();
  await expect(page.getByText("审计检查").first()).toBeVisible();
  await expect(page.getByText("版本与漏洞来源证据完整且可追溯。")).toBeVisible();
  await expect(page.getByText("已安装版本位于受影响区间。")).toBeVisible();
  await expect(page.getByText("服务对外可达，运行时证据仅用于上下文判断。")).toBeVisible();
  await expect(page.getByText("综合三方意见维持高优先级处置。")).toBeVisible();
  await expect(page.getByRole("button", { name: "生成整改建议" })).toHaveCount(0);
});
