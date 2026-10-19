import { expect, test } from './fixtures.js';

test.beforeEach(async ({ page }) => {
  await page.route(/^https?:\/\/[^/]+\/api\//, r => r.fulfill({ json: [] }));
});

test('IoT homepage distinguishes RTOS limitations and infrastructure', async ({ page }) => {
  await page.route('**/api/devices/business/overview', r => r.fulfill({ json: {
    device_count: 1, infrastructure_count: 3,
    official_snapshot_counts: { openwrt: 9, zephyr: 281 },
    devices: [{ key: 'device:test', name: 'Zephyr-QEMU', ecosystem: 'zephyr',
      version: 'Zephyr RTOS 4.4.2', matches: { assessment: 'partial', confirmed: 0, pending: 2 },
      runtime: 'ebpf_not_applicable', remediation: 'firmware_update_not_automated',
      detail_path: '/devices', task_path: '/device-tasks' }]
  } }));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '物联网安全工作台', level: 1 })).toBeVisible();
  await expect(page.getByText('Zephyr-QEMU', { exact: true })).toBeVisible();
  await expect(page.getByText('RTOS 不支持 eBPF，需设备侧证据')).toBeVisible();
  await expect(page.getByText('固件自动更新尚未接通')).toBeVisible();
  await expect(page.getByText(/Ubuntu 等主机记录 3 条/)).toBeVisible();
  await page.getByRole('button', { name: 'SOC 安全总览' }).click();
  await expect(page).toHaveURL(/\/soc$/);
});

test('failed inventory request is not shown as a safe empty fleet', async ({ page }) => {
  await page.route('**/api/devices/business/overview', r => r.fulfill({ status: 503, json: {} }));
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('设备业务概况加载失败');
  await expect(page.getByText('尚无物联网设备记录，请接入 OpenWrt 或发现受支持设备')).toHaveCount(0);
});
