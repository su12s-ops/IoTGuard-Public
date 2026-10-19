import { expect, test } from "./fixtures.js";
import { fileURLToPath } from "node:url";

// API fixtures are deliberately synthetic; browser tests never access devices.
const asset = { id: 1, hostname: "fixture-openwrt", distribution: "openwrt", device_type: "iot_gateway", inventory_complete: true };
const risk = { risk_id: 1, asset_id: 1, cve_id: "CVE-2099-9999", package_name: "mosquitto", review_status: "human_confirmed" };
const artifact = { id: "fixture-fix", package_name: "mosquitto", version: "2.0.2-test", board_name: "test,board" };

async function setup(page, overrides = {}) {
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const defaults = {
    "/api/health": { status: "ok" },
    "/api/demo/progress": { running: false, steps_done: [] },
    "/api/assets": [asset], "/api/risk/ranking": [risk],
    "/api/iot/capabilities": { control_configured: true, discovery_cidrs: ["192.168.50.0/24"] },
    "/api/iot/connections": [], "/api/iot/observations": [], "/api/iot/advisories": [],
    "/api/harness/runs": [], "/api/harness/artifacts": [artifact],
    "/api/runtime/ebpf/status": { available_hosts: [], available_sources: [], available_categories: [] },
    "/api/runtime/ebpf/summary": { total: 0 },
    "/api/runtime/ebpf/events": { count: 0, events: [] },
    "/api/runtime/ebpf/correlations": [], "/api/workflow/behavior-chains": []
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

for (const blocker of ["official_candidate_unavailable", "root_execution_node_required", "cancelled_plan"]) {
test(`Ubuntu dry-run blocks approval and rollback for ${blocker}`, async ({ page }) => {
  const old = "8.5.0-2ubuntu10.15", fixed = "8.5.0-2ubuntu10.16";
  const run = { id: "fixture-ubuntu", asset_id: 1, risk_id: 1, status: blocker === "cancelled_plan" ? "cancelled" : "preflight_failed", attempts: 1,
    trace_id: "TR-fixture", plan_hash: "a".repeat(64), result: { execution_status: "not_executed" }, tool_calls: [],
    plan: { adapter: "ubuntu-apt-v1", goal: "repair", node_id: "fixture-node", steps: ["ubuntu_dry_run"],
      identity: { hostname: "fixture-ubuntu", release: "24.04" },
      official: { url: "https://ubuntu.com/security/notices/USN-TEST-1", notices: ["USN-TEST-1"], evidence_id: "ADV-fixture", fixed_version: fixed },
      targets: ["curl", "libcurl4t64"].map(binary => ({ binary, source: "curl", version: old })),
      rollback: { status: "awaiting_clone_and_restore_test" }, preflight: { ready: blocker === "cancelled_plan",
        package_ready: blocker === "root_execution_node_required", execution_context: { effective_uid: 1000 },
        candidate_versions: { curl: old, libcurl4t64: old }, issues: blocker === "cancelled_plan" ? [] : [blocker], simulation: "TEST ONLY blocked preflight", removals: [] } } };
  const errors = await setup(page, { "/api/assets": [{ ...asset, hostname: "fixture-ubuntu", distribution: "ubuntu" }],
    "/api/harness/runs": [run], "/api/harness/runs/fixture-ubuntu": run });
  await page.goto("/device-tasks?run=fixture-ubuntu");
  await expect(page.getByRole("heading", { name: "Ubuntu 修复与复检证据" })).toBeVisible();
  await expect(page.getByText(blocker === "cancelled_plan" ? "审批：计划已取消" : blocker, { exact: false })).toBeVisible();
  if (blocker === "root_execution_node_required") {
    await expect(page.getByText("软件包检查：通过 · 节点管理员权限：缺少管理员权限")).toBeVisible();
  }
  await expect(page.getByRole("button", { name: "审批此计划", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "审批并回退", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "执行已审批修复", exact: true })).toHaveCount(0);
  if (blocker === "cancelled_plan") {
    await expect(page.getByRole("button", { name: "只读修复预演", exact: true })).toHaveCount(0);
  } else {
    await expect(page.getByRole("button", { name: "只读修复预演", exact: true })).toBeDisabled();
  }
  await expect(page.getByRole("row").filter({ hasText: "curl / curl" })).toContainText(fixed);
  await expect(page.getByText(/尚无修复后采集/).first()).toBeVisible();
  expect(errors).toEqual([]);
});
}

test("IoT registration requires token and displays structured validation errors", async ({ page }, testInfo) => {
  const errors = await setup(page, { "/api/iot/connections": async route => {
    if (route.request().method() === "GET") return route.fulfill({ json: [] });
    expect(route.request().headers()["x-control-token"]).toBe("fixture-token");
    expect(route.request().postDataJSON()).not.toHaveProperty("password");
    return route.fulfill({ status: 422, json: { detail: [{ loc: ["body", "host"], msg: "管理 IP 不在允许范围内" }] } });
  } });
  await page.goto("/iot");
  await expect(page.getByRole("heading", { name: "物联网接入", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole("button", { name: "登记连接", exact: true })).toBeDisabled();
  await token(page);
  await page.getByRole("button", { name: "登记连接", exact: true }).click();
  await page.getByLabel("管理 IP", { exact: true }).fill("192.168.50.1");
  await page.getByRole("combobox", { name: "认证方式", exact: true }).press("Enter");
  await page.getByRole("option", { name: "密码认证（历史兼容）", exact: true }).click();
  await page.getByLabel("后端凭据变量名称", { exact: true }).fill("LINUXGUARD_DEVICE_FIXTURE");
  await page.getByLabel("SSH 主机 SHA256 指纹", { exact: true }).fill("SHA256:" + "A".repeat(43));
  await page.getByRole("button", { name: "保存连接", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("管理 IP 不在允许范围内");
  expect(await page.evaluate(() => Object.values(localStorage).join(" "))).not.toContain("fixture-token");
  await page.screenshot({ path: testInfo.outputPath("upgrade-iot-registration.png"), fullPage: true });
  expect(errors).toEqual([]);
});

test("discovery displays observations without asserting device identity", async ({ page }, testInfo) => {
  let scanned = false;
  const errors = await setup(page, {
    "/api/iot/discovery": async route => {
      expect(route.request().postDataJSON()).toEqual({ cidr: "192.168.50.0/30", ports: [1883] });
      scanned = true;
      return route.fulfill({ json: { responding_devices: 1 } });
    },
    "/api/iot/observations": route => route.fulfill({ json: scanned ? [{ id: 1, ip_address: "192.168.50.2", source: "tcp_connect", presence: "responded", evidence: { open_ports: [1883], device_type: "unknown" } }] : [] })
  });
  await page.goto("/iot");
  await token(page);
  await page.getByRole("tab", { name: "发现记录" }).click();
  await page.getByLabel("探测网段", { exact: true }).fill("192.168.50.0/30");
  await page.getByLabel("探测端口", { exact: true }).fill("1883");
  await page.getByRole("button", { name: "开始发现", exact: true }).click();
  await expect(page.getByRole("row").filter({ hasText: "192.168.50.2" })).toContainText("探测时有响应");
  await expect(page.getByText(/没有响应不等于设备不存在/)).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("upgrade-iot-discovery.png"), fullPage: true });
  expect(errors).toEqual([]);
});

test("repair UI approves exact plan and offers verification after uncertain write", async ({ page }, testInfo) => {
  let run = null;
  const errors = await setup(page, {
    "/api/harness/runs": async route => {
      if (route.request().method() === "GET") return route.fulfill({ json: run ? [run] : [] });
      expect(route.request().postDataJSON().goal).toBe("repair");
      run = { id: "fixture-run", asset_id: 1, risk_id: 1, plan_hash: "a".repeat(64), status: "awaiting_approval", attempts: 0, plan: { goal: "repair", steps: ["collect_inventory", "install_registered_package", "regression_check", "business_check"], artifact, blocked_reasons: [] }, tool_calls: [], result: {} };
      return route.fulfill({ json: run });
    },
    "/api/harness/runs/fixture-run": route => route.fulfill({ json: run }),
    "/api/harness/runs/fixture-run/approve": route => {
      expect(route.request().postDataJSON().plan_hash).toBe("a".repeat(64));
      run = { ...run, status: "approved", approved_by: "fixture operator" };
      return route.fulfill({ json: run });
    },
    "/api/harness/runs/fixture-run/execute": route => {
      run = { ...run, status: "verification_required", attempts: 1, error: "设备返回超时，需复查状态", tool_calls: [{ id: 1, tool: "install_registered_package", status: "failed", side_effect: true, arguments: {}, output: {}, error: "fixture timeout" }] };
      return route.fulfill({ json: run });
    },
    "/api/harness/runs/fixture-run/verify": route => {
      run = { ...run, status: "verified", error: "", result: { verified: true, fixture_only: true } };
      return route.fulfill({ json: run });
    }
  });
  await page.goto("/device-tasks?asset=1&risk=1");
  await token(page);
  await page.getByRole("combobox", { name: "任务目标" }).press("Enter");
  await page.getByRole("option", { name: "受控软件包修复", exact: true }).click();
  await page.getByRole("combobox", { name: "已登记修复产物" }).press("Enter");
  await page.getByRole("option", { name: /fixture-fix/ }).click();
  await page.getByRole("button", { name: "创建计划", exact: true }).click();
  await expect(page.getByRole("button", { name: "执行已审批修复", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "审批此计划", exact: true }).click();
  await page.getByLabel("操作人署名", { exact: true }).fill("fixture operator");
  await page.getByLabel("审批理由", { exact: true }).fill("isolated browser test");
  await page.getByRole("button", { name: "确认审批", exact: true }).click();
  await page.getByRole("button", { name: "执行已审批修复", exact: true }).click();
  await expect(page.getByRole("button", { name: "重新复查设备", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "执行已审批修复", exact: true })).toHaveCount(0);
  await expect(page.getByText("设备写操作", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("upgrade-harness.png"), fullPage: true });
  await page.getByRole("button", { name: "重新复查设备", exact: true }).click();
  await expect(page.getByRole("heading", { name: /fixture-openwrt · 修复验证通过/ })).toBeVisible();
  expect(errors).toEqual([]);
});

test("runtime timeline exposes stale coverage and non-conclusive comparison", async ({ page }, testInfo) => {
  const errors = await setup(page, {
    "/api/runtime/assets/1/timeline": { coverage: { status: "stale", sensors: [{ sensor_id: "fixture-sensor", status: "stale", age_seconds: 180 }], note: "心跳过期不能证明设备安全" }, events: [], processes: [], edges: [], note: "不凭重复 PID 拼接行为链" },
    "/api/runtime/assets/1/comparison": { before: { count: 0 }, after: { count: 0 }, note: "没有事件不单独证明漏洞已修复" }
  });
  await page.goto("/runtime");
  await page.getByRole("combobox", { name: "时间线资产" }).press("Enter");
  await page.getByRole("option", { name: asset.hostname, exact: true }).click();
  await expect(page.getByText("该资产暂无事件；这不能证明不存在风险")).toBeVisible();
  const picker = page.locator('.el-date-editor input').first();
  await picker.fill("2026-09-30 12:00:00");
  await picker.press("Enter");
  await page.getByRole("button", { name: "比较前后各五分钟", exact: true }).click();
  await expect(page.getByText(/没有事件不单独证明漏洞已修复/)).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("upgrade-runtime.png"), fullPage: true });
  expect(errors).toEqual([]);
});

test("OpenWrt remediation links to controlled task instead of manual success selector", async ({ page }, testInfo) => {
  await setup(page, { "/api/remediation/tasks": [{ id: 1, asset_id: 1, risk_id: 1, distribution: "openwrt", hostname: asset.hostname, cve_id: risk.cve_id, package_name: "mosquitto", status: "pending" }] });
  await page.goto("/remediation");
  const row = page.getByRole("row").filter({ hasText: risk.cve_id });
  await expect(row.getByRole("combobox")).toHaveCount(0);
  await row.getByRole("button", { name: "前往设备任务", exact: true }).click();
  await expect(page).toHaveURL(/device-tasks\?asset=1&risk=1/);
});

test("key registration submits references and binds the selected existing asset", async ({ page }, testInfo) => {
  let connections = [];
  await setup(page, { "/api/iot/connections": async route => {
    if (route.request().method() === "GET") return route.fulfill({ json: connections });
    const payload = route.request().postDataJSON();
    expect(route.request().headers()["x-control-token"]).toBe("fixture-token");
    expect(payload.auth_type).toBe("ssh_key");
    expect(payload.asset_id).toBe(asset.id);
    expect(payload.credential_env).toBe("");
    expect(payload.key_path_env).toBe("LINUXGUARD_DEVICE_FIXTURE_KEY");
    expect(payload).not.toHaveProperty("private_key");
    expect(payload).not.toHaveProperty("password");
    connections = [{ ...payload, id: 1 }];
    return route.fulfill({ json: connections[0] });
  } });
  await page.goto("/iot");
  await token(page);
  await page.getByRole("button", { name: "登记连接", exact: true }).click();
  await page.getByLabel("管理 IP", { exact: true }).fill("192.168.50.1");
  await page.getByLabel("采集节点私钥路径变量名称", { exact: true }).fill("LINUXGUARD_DEVICE_FIXTURE_KEY");
  await page.getByLabel("SSH 主机 SHA256 指纹", { exact: true }).fill("SHA256:" + "A".repeat(43));
  await page.getByRole("combobox", { name: "关联已有资产", exact: true }).press("Enter");
  await page.getByRole("option", { name: asset.hostname, exact: true }).click();
  await page.getByRole("button", { name: "保存连接", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("row").filter({ hasText: "LINUXGUARD_DEVICE_FIXTURE_KEY" })).toContainText("ED25519 密钥");
  await expect(page.getByRole("row").filter({ hasText: "LINUXGUARD_DEVICE_FIXTURE_KEY" })).toContainText("已关联，待身份核验");
  await expect(page.getByRole("region", { name: "物联网接入概况" })).toContainText("已确认网关0");
});

test("JSON structure sample rejection is visible and upload carries the control token", async ({ page }, testInfo) => {
  await setup(page, { "/api/assets/upload": route => {
    expect(route.request().headers()["x-control-token"]).toBe("fixture-token");
    return route.fulfill({ status: 400, json: { detail: "sample_only 结构样本不能作为完整资产入库" } });
  } });
  await page.goto("/iot");
  await expect(page.locator("button").filter({ hasText: "导入 OpenWrt 采集文件" })).toBeDisabled();
  await token(page);
  const sample = fileURLToPath(new URL("../../../backend/tests/fixtures/openwrt_inventory_structure_sample.json", import.meta.url));
  await page.locator('input[type="file"]').setInputFiles(sample);
  await expect(page.getByRole("alert").filter({ hasText: "sample_only" })).toBeVisible();
});

test("collection-only node uses persistent jobs and keeps CVE state separate", async ({ page }, testInfo) => {
  let created = 0; let executed = 0; let job = null;
  const id = "c".repeat(32);
  const connection = { id: 1, asset_id: 1, host: "192.168.50.1", port: 22, enabled: true, auth_type: "ssh_key", key_path_env: "LINUXGUARD_DEVICE_FIXTURE_KEY" };
  const errors = await setup(page, {
    "/api/iot/capabilities": { control_configured: true, collection_only: true, discovery_enabled: false, collector_node: { id: "fixture-ubuntu", platform: "Linux" } },
    "/api/iot/connections": [connection],
    "/api/iot/connections/1/preflight": route => route.fulfill({ json: { ready: true, checks: { node_platform: true }, network_attempted: false, key_loaded: false } }),
    "/api/iot/collection-runs": route => {
      expect(route.request().headers()["x-control-token"]).toBe("fixture-token");
      return route.fulfill({ json: job ? [job] : [] });
    },
    "/api/iot/connections/1/collection-runs": route => {
      created += 1;
      expect(route.request().postDataJSON().request_id).toMatch(/^[a-f0-9-]{36}$/);
      job = { id, asset_id: 1, connection_id: 1, status: "pending", node: { id: "fixture-ubuntu" }, result: { cve_applicability: "not_evaluated" } };
      return route.fulfill({ json: job });
    },
    ["/api/iot/collection-runs/" + id + "/execute"]: route => {
      executed += 1;
      job = { ...job, status: "completed", started_at: "2026-10-13T00:00:00Z", completed_at: "2026-10-13T00:00:02Z",
        result: { ssh_host_identity: "verified", ssh_authentication: "succeeded", asset_collection: "succeeded", cve_applicability: "not_evaluated", package_count: 182, fixture_only: true } };
      return route.fulfill({ json: job });
    }
  });
  await page.goto("/iot");
  await token(page);
  await expect(page.getByRole("tab", { name: "发现记录" })).toHaveCount(0);
  await page.getByRole("button", { name: "配置检查", exact: true }).click();
  await expect(page.getByText("本地配置检查通过；未连接设备、未加载私钥", { exact: true })).toBeVisible();
  expect(created).toBe(0); expect(executed).toBe(0);
  await page.getByRole("button", { name: "采集", exact: true }).click();
  await page.getByRole("tab", { name: "采集记录" }).click();
  const row = page.getByRole("row").filter({ hasText: id });
  await expect(row).toContainText("采集完成");
  await expect(row).toContainText("本次未评估");
  await expect(row).toContainText("182");
  expect(await page.locator(".main").evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await page.getByRole("button", { name: "刷新", exact: true }).click();
  expect(created).toBe(1); expect(executed).toBe(1);
  await page.screenshot({ path: testInfo.outputPath("stage4-fixture-collection.png"), fullPage: true });
  expect(errors).toEqual([]);
});

test("collection failure is audited without claiming authentication failure or retrying", async ({ page }) => {
  const id = "d".repeat(32); let job = null; let executed = 0;
  await setup(page, {
    "/api/iot/connections": [{ id: 1, asset_id: 1, enabled: true, auth_type: "ssh_key" }],
    "/api/iot/collection-runs": route => route.fulfill({ json: job ? [job] : [] }),
    "/api/iot/connections/1/collection-runs": route => {
      job = { id, status: "pending", result: {} };
      return route.fulfill({ json: job });
    },
    ["/api/iot/collection-runs/" + id + "/execute"]: route => {
      executed += 1;
      job = { ...job, status: "failed", error: "采集清单不完整；保留已有资产", result: {
        ssh_host_identity: "verified", ssh_authentication: "succeeded", asset_collection: "failed", cve_applicability: "not_evaluated", fixture_only: true } };
      return route.fulfill({ json: job });
    }
  });
  await page.goto("/iot");
  await token(page);
  await page.getByRole("button", { name: "采集", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "采集清单不完整；保留已有资产" })).toBeVisible();
  await page.getByRole("tab", { name: "采集记录" }).click();
  const row = page.getByRole("row").filter({ hasText: id });
  await expect(row).toContainText("采集失败");
  await expect(row).toContainText("已校验");
  await expect(row).toContainText("成功");
  await expect(row).toContainText("本次未评估");
  await expect(row.getByRole("button", { name: "执行本次采集" })).toHaveCount(0);
  expect(executed).toBe(1);
});

test("device task page recognizes pure collection mode without repair or model review", async ({ page }) => {
  let run = null;
  await setup(page, {
    "/api/iot/capabilities": { control_configured: true, collection_only: true, discovery_enabled: false },
    "/api/harness/runs": async route => {
      if (route.request().method() === "GET") return route.fulfill({ json: run ? [run] : [] });
      const payload = route.request().postDataJSON();
      expect(payload.goal).toBe("collect");
      expect(payload.risk_id).toBeNull();
      expect(payload.model_review).toBe(false);
      expect(payload.artifact_id).toBe("");
      run = { id: "e".repeat(32), asset_id: 1, status: "pending", plan: { goal: "collect", steps: ["collect_inventory"] }, attempts: 0, result: {}, tool_calls: [] };
      return route.fulfill({ json: run });
    }
  });
  await page.goto("/device-tasks?asset=1");
  await token(page);
  await expect(page.getByText("智能体复核", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "检查超时任务" })).toBeDisabled();
  await page.getByRole("button", { name: "创建计划", exact: true }).click();
  await expect(page.getByRole("button", { name: "执行采集", exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "e".repeat(12) })).toContainText("纯资产采集");
});
