// Real-browser acceptance for the OpenWrt lab connection/preflight/inventory flow.
// Uses the existing console at 18080 and the existing backend/collection node.
// No API mocking. Set IOTGUARD_SKIP_COLLECTION=1 to verify an existing run
// (preflight + persisted history) without starting another collection.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const base = process.env.IOTGUARD_UI_BASE || 'http://127.0.0.1:18080';
const token = process.env.LINUXGUARD_CONTROL_TOKEN || '';
const assetName = process.env.IOTGUARD_TARGET_ASSET || 'OpenWrt-Lab-0050563ab001';
const skipCollection = process.env.IOTGUARD_SKIP_COLLECTION === '1';
if (!token) {
  console.error('LINUXGUARD_CONTROL_TOKEN is required');
  process.exit(2);
}
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const outDir = path.resolve(root, 'reports/phase1-openwrt-collection');
fs.mkdirSync(outDir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '');

const result = {
  at: new Date().toISOString(),
  base,
  target_asset: assetName,
  scope: 'real browser + real backend + existing registered Linux collection node',
  skipped_collection: skipCollection,
  steps: [],
  api_requests: [],
  console_errors: [],
  failed_requests: [],
  http_errors: [],
  screenshots: []
};

function note(step, data = {}) {
  result.steps.push({ at: new Date().toISOString(), step, ...data });
}

const browser = await chromium.launch({ channel: 'msedge', headless: true });
const context = await browser.newContext({
  viewport: { width: 1500, height: 1100 },
  locale: 'zh-CN',
  timezoneId: 'Asia/Shanghai'
});
const page = await context.newPage();
page.on('console', (message) => {
  if (message.type() === 'error') result.console_errors.push(message.text());
});
page.on('request', (request) => {
  if (!request.url().includes('/api/')) return;
  result.api_requests.push({ method: request.method(), url: request.url().replace(base, '') });
});
page.on('requestfailed', (request) => {
  result.failed_requests.push({ url: request.url().replace(base, ''), error: request.failure()?.errorText || '' });
});
page.on('response', (response) => {
  if (response.url().includes('/api/') && response.status() >= 400) {
    result.http_errors.push({ status: response.status(), url: response.url().replace(base, '') });
  }
});

async function shot(name) {
  const file = path.join(outDir, `${stamp}-${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  result.screenshots.push(path.relative(root, file));
  return file;
}

async function scrollModalToBottom() {
  await page.locator('.modal-body').evaluate((element) => element.scrollTo(0, element.scrollHeight));
  await page.waitForTimeout(250);
}

try {
  await page.goto(base + '/assets', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.getByText('资产与发现', { exact: false }).first().waitFor({ timeout: 20000 });
  note('assets page loaded');

  await page.getByRole('button', { name: '操作令牌' }).click();
  await page.locator('#control-token').fill(token);
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await page.locator('#control-token').waitFor({ state: 'detached', timeout: 10000 });
  note('control token stored in page memory only');

  await page.locator('.segmented span').filter({ hasText: '列表视图' }).click();
  const row = page.locator('tbody tr').filter({ hasText: assetName }).first();
  await row.waitFor({ timeout: 20000 });
  note('target asset row visible', { asset: assetName });
  await shot('00-asset-list');
  await row.click();

  const dialog = page.getByRole('dialog');
  await dialog.waitFor({ timeout: 10000 });
  await dialog.getByRole('button', { name: '连接与采集' }).click();
  await page.locator('[data-testid="collection-panel"]').waitFor({ timeout: 20000 });
  note('collection tab opened');

  const summary = page.locator('[data-testid="connection-summary"]');
  await summary.waitFor({ timeout: 20000 });
  const connectionText = await summary.innerText();
  if (!connectionText.includes('192.168.206.2') || !connectionText.includes('OpenWrt-Lab-live-e2e')) {
    throw new Error('Registered connection does not match the selected OpenWrt lab asset: ' + connectionText.slice(0, 400));
  }
  if (!connectionText.includes('当前资产 #4')) {
    throw new Error('Connection is not shown as bound to the selected asset: ' + connectionText.slice(0, 400));
  }
  note('connection bound to selected asset', { connection: connectionText.replace(/\s+/g, ' ').slice(0, 300) });
  await shot('01-connection');

  const preflightButton = page.locator('[data-testid="preflight"]');
  await preflightButton.click();
  const preflightResult = page.locator('[data-testid="preflight-result"]');
  await preflightResult.waitFor({ timeout: 30000 });
  const preflightText = await preflightResult.innerText();
  if (!preflightText.includes('预检通过')) throw new Error('Preflight did not pass: ' + preflightText.slice(0, 800));
  if (!preflightText.includes('network_attempted=false')) throw new Error('Preflight did not report network_attempted=false');
  if (!preflightText.includes('key_loaded=false')) throw new Error('Preflight did not report key_loaded=false');
  result.preflight_text = preflightText.replace(/\s+/g, ' ');
  note('preflight passed (metadata only)', { ready: true, network_attempted: false });
  await shot('02-preflight');

  if (skipCollection) {
    if (await page.locator('[data-testid="current-run"]').count()) {
      throw new Error('An active collection run exists; skip mode will not start a duplicate run');
    }
    const history = await page.locator('[data-testid="recent-runs"]').innerText();
    if (!history.includes('采集完成')) throw new Error('Persisted history has no completed inventory run: ' + history.slice(0, 500));
    result.history_text = history.replace(/\s+/g, ' ').slice(0, 1200);
    result.last_success = (await page.locator('[data-testid="last-success"]').innerText()).trim();
    result.inventory_state = (await page.locator('[data-testid="inventory-state"]').innerText()).trim();
    if (result.last_success.includes('尚无成功记录')) throw new Error('Last successful inventory time is missing');
    note('persisted history and last successful inventory verified without a new run', {
      last_success: result.last_success,
      inventory_state: result.inventory_state
    });
    await scrollModalToBottom();
    await shot('03-history');
    await page.getByRole('dialog').getByRole('button', { name: '返回台账' }).click();
    result.detail_text = (await page.getByRole('dialog').locator('.detail-grid').innerText()).replace(/\s+/g, ' ').slice(0, 800);
    await shot('04-detail-overview');
    result.passed = true;
  } else {
    const startButton = page.locator('[data-testid="start-collection"]');
    if (await startButton.isDisabled()) throw new Error('Start collection button is disabled after a passed preflight');
    await startButton.click();
    const runBlock = page.locator('[data-testid="current-run"]');
    await runBlock.waitFor({ timeout: 20000 });
    note('collection run submitted');
    const disabledWhileRunning = await startButton.isDisabled();
    if (!disabledWhileRunning) throw new Error('Start collection button was not disabled after submission (duplicate-click guard missing)');
    result.duplicate_click_guard = true;

    await page.waitForFunction(() => {
      const element = document.querySelector('[data-testid="current-run"]');
      return Boolean(element && /采集完成|采集失败|已中断|已取消/.test(element.innerText));
    }, { timeout: 180000 });
    const runText = await runBlock.innerText();
    const completed = runText.includes('采集完成');
    result.run_completed = completed;
    result.run_text = runText.replace(/\s+/g, ' ');
    result.run_id = (await runBlock.locator('[data-testid="run-id"]').innerText()).trim();
    result.run_status = (await runBlock.locator('[data-testid="run-status"]').innerText()).trim();
    const packageText = (await runBlock.locator('[data-testid="run-package-count"]').innerText()).trim();
    result.run_package_count = Number(packageText);
    if (completed && !(result.run_package_count > 0)) throw new Error('Completed run did not report a positive package count');
    note(completed ? 'collection run reached completed terminal state' : 'collection run reached a failure terminal state', {
      run_id: result.run_id,
      status: result.run_status,
      packages: result.run_package_count
    });

    result.last_success = (await page.locator('[data-testid="last-success"]').innerText()).trim();
    result.inventory_state = (await page.locator('[data-testid="inventory-state"]').innerText()).trim();
    if (completed && result.last_success.includes('尚无成功记录')) throw new Error('Last successful inventory time did not update');

    await runBlock.scrollIntoViewIfNeeded();
    await page.waitForTimeout(250);
    await shot('03-run-result');
    await scrollModalToBottom();
    result.history_text = (await page.locator('[data-testid="recent-runs"]').innerText()).replace(/\s+/g, ' ').slice(0, 1200);
    await shot('04-history');

    await page.getByRole('dialog').getByRole('button', { name: '返回台账' }).click();
    const detailText = await page.getByRole('dialog').locator('.detail-grid').innerText();
    if (completed && !/有效软件清单\s*是/.test(detailText)) {
      throw new Error('Detail does not show a valid software inventory after success: ' + detailText.slice(0, 500));
    }
    result.detail_text = detailText.replace(/\s+/g, ' ').slice(0, 800);
    await shot('05-detail-overview');
    result.passed = completed;
  }

  result.http_errors = result.http_errors.filter((entry) => !entry.url.includes('/api/not-found'));
  result.finished_at = new Date().toISOString();
  fs.writeFileSync(path.join(outDir, `${stamp}-browser-acceptance.json`), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({
    passed: result.passed,
    skipped_collection: result.skipped_collection,
    run_id: result.run_id || null,
    run_status: result.run_status || null,
    run_package_count: result.run_package_count || null,
    last_success: result.last_success,
    inventory_state: result.inventory_state,
    api_request_count: result.api_requests.length,
    console_errors: result.console_errors.length,
    failed_requests: result.failed_requests.length,
    http_errors: result.http_errors.length,
    screenshots: result.screenshots
  }, null, 2));
} catch (error) {
  result.passed = false;
  result.error = String(error && error.stack || error);
  await shot('99-failure').catch(() => {});
  fs.writeFileSync(path.join(outDir, `${stamp}-browser-acceptance.json`), JSON.stringify(result, null, 2));
  console.error(result.error);
  process.exitCode = 1;
} finally {
  await browser.close();
}
