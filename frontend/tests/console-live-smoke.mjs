// Read-only production checks; invalid input verifies write authorization
// without creating a round, calling a model or touching device state.
import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';

const base = process.env.CONSOLE_BASE || 'http://127.0.0.1:18080';
const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('response', r => {
    if (r.url().includes('/api/') && r.status() >= 400) errors.push(`${r.status()} ${new URL(r.url()).pathname}`);
  });
  for (const path of ['/', '/assets', '/risks', '/agents', '/repairs', '/runtime']) {
    await page.goto(base + path);
    await page.waitForLoadState('networkidle');
    assert.equal(await page.locator('h1').count(), 1);
    assert.equal(await page.locator('input[type=password]:visible').count(), 0);
    assert.equal(await page.locator('.top-actions button[title="\u64cd\u4f5c\u4ee4\u724c"]').count(), 0);
    console.log(`PASS ${path}: connected, no token prompt`);
  }
  await page.goto(base + '/agents');
  await page.waitForLoadState('networkidle');
  const start = page.locator('.console-run button.primary');
  assert.equal(await start.count(), 1);
  const current = await page.request.get(base + '/api/console/current');
  if (!(await current.json()).workflow) assert.equal(await start.isEnabled(), true);
  assert.equal(await page.locator('details[open]').count(), 0);
  await page.screenshot({ path: '../reports/console-agents-verified.png', fullPage: true });
  assert.deepEqual(errors, []);

  const archives = await page.request.get(base + '/api/experiment/archives', { headers: { 'X-Console-Request': '1' } });
  assert.equal(archives.status(), 200);
  const first = (await archives.json()).archives?.[0];
  if (first) {
    const download = await page.request.get(base + '/api/experiment/archives/' + encodeURIComponent(first.filename), {
      headers: { 'X-Console-Request': '1' }
    });
    assert.equal(download.status(), 200);
    console.log('PASS archived result download without a browser token');
  }

  // Request validation fails before any mutation; auth must already have passed.
  const validation = await page.request.post(base + '/api/console/start', {
    headers: { 'X-Console-Request': '1', Origin: base }, data: { asset_id: -1 }
  });
  assert.equal(validation.status(), 422);
  const untrusted = await page.request.get(base + '/api/experiment/archives');
  assert.equal(untrusted.status(), 401);
  console.log('PASS managed write authorization; direct unauthenticated API remains blocked');
} finally {
  await browser.close();
}
