// Isolated regression tests for device connection/inventory state rules.
// Fixtures are synthetic; they are not evidence of a live collection run.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  connectionForAsset,
  connectionsForAsset,
  collectionStatusText,
  collectionStatusTone,
  createRequestId,
  formatBackendTime,
  inventoryState,
  isActiveRun,
  isTerminalRun,
  parseBackendTime,
  preflightChecks,
  runDuration,
  runError,
  runResultLabel,
  summarizeRuns
} from '../src/utils/deviceCollection.js';

const run = (overrides = {}) => ({
  id: 'run-1',
  asset_id: 4,
  connection_id: 4,
  collector_type: 'openwrt_ssh',
  status: 'completed',
  created_at: '2026-10-23T02:31:52.871106',
  started_at: '2026-10-23T02:32:01.317136',
  completed_at: '2026-10-23T02:32:02.810199',
  result: { package_count: 182, error_code: '' },
  error: '',
  tool_calls: [],
  ...overrides
});

test('a connection is only selected for its own bound asset', () => {
  const connections = [
    { id: 4, asset_id: 4, host: '192.168.206.2' },
    { id: 2, asset_id: 1, host: '192.168.183.129' }
  ];
  assert.equal(connectionForAsset(connections, 4).id, 4);
  assert.equal(connectionForAsset(connections, 1).id, 2);
  assert.equal(connectionForAsset(connections, 99), null);
  assert.deepEqual(connectionsForAsset(connections, 4).map((row) => row.id), [4]);
});

test('naive backend timestamps are interpreted as UTC, not browser-local time', () => {
  assert.equal(parseBackendTime('2026-10-23T02:32:02.786855').toISOString(), '2026-10-23T02:32:02.786Z');
  assert.equal(parseBackendTime('2026-10-23 02:32:02').toISOString(), '2026-10-23T02:32:02.000Z');
  assert.equal(parseBackendTime('2026-10-23T02:32:02+00:00').toISOString(), '2026-10-23T02:32:02.000Z');
  assert.equal(parseBackendTime('not-a-date'), null);
  assert.match(formatBackendTime('2026-10-23T02:32:02.786855'), /2026/);
});

test('discovery alone never counts as a valid software inventory', () => {
  const discoveredOnly = inventoryState({ inventory_complete: false, component_count: 0, inventory_collected_at: null }, 0);
  assert.equal(discoveredOnly.valid, false);
  assert.match(discoveredOnly.label, /已发现|尚无/);
  const incompleteNoPackages = inventoryState({ inventory_complete: true, component_count: 0 }, 0);
  assert.equal(incompleteNoPackages.valid, false);
  const valid = inventoryState({ inventory_complete: true, component_count: 182, inventory_collected_at: '2026-10-23T02:32:02' }, 182);
  assert.equal(valid.valid, true);
  assert.equal(valid.count, 182);
  assert.match(valid.label, /有效软件清单/);
});

test('terminal/in-flight statuses and duplicate-submit guards are explicit', () => {
  for (const status of ['completed', 'failed', 'interrupted', 'cancelled']) {
    assert.equal(isTerminalRun(status), true);
    assert.equal(isActiveRun(run({ status })), false);
  }
  for (const status of ['pending', 'running', 'queued_remote']) {
    assert.equal(isTerminalRun(status), false);
    assert.equal(isActiveRun(run({ status })), true);
  }
});

test('run history distinguishes software inventory from runtime log collection', () => {
  const runs = [
    run({ id: 'log', collector_type: 'openwrt_logread', status: 'failed', created_at: '2026-10-24T01:00:00', error: 'log failed' }),
    run({ id: 'old', status: 'completed', created_at: '2026-10-22T01:00:00' }),
    run({ id: 'new-fail', status: 'failed', created_at: '2026-10-24T02:00:00', result: { error_code: 'host_key_mismatch' }, error: 'SSH 主机指纹不匹配' }),
    run({ id: 'log-success', collector_type: 'openwrt_logread', status: 'completed', created_at: '2026-10-24T03:00:00' })
  ];
  const summary = summarizeRuns(runs);
  assert.equal(summary.total, 2);
  assert.equal(summary.latest.id, 'new-fail');
  assert.equal(summary.lastSuccess.id, 'old');
  assert.equal(summary.lastFailure.id, 'new-fail');
  const failure = runError(summary.lastFailure);
  assert.equal(failure.code, 'host_key_mismatch');
  assert.match(failure.message, /指纹/);
  assert.equal(runResultLabel(run({ status: 'completed', result: { package_count: 182 } })), '182 个组件');
  assert.match(runResultLabel(run({ status: 'failed', result: { error_code: 'collector_timeout' } })), /collector_timeout/);
});

test('preflight exposes each metadata check and never claims network reachability', () => {
  const preflight = {
    ready: false,
    checks: {
      asset_bound: true,
      connection_enabled: true,
      host_fingerprint_configured: false,
      authorized_target: true,
      collector_available: true,
      node_platform: true,
      remote_node_configured: true,
      node_identity_configured: true,
      authentication_reference_configured: true,
      passphrase_reference_configured: true
    },
    network_attempted: false,
    key_loaded: false
  };
  const checks = preflightChecks(preflight);
  assert.equal(checks.length, 10);
  assert.equal(checks.find((row) => row.key === 'host_fingerprint_configured').ok, false);
  assert.equal(checks.find((row) => row.key === 'asset_bound').label, '绑定资产');
  assert.equal(preflight.network_attempted, false);
  assert.equal(preflight.key_loaded, false);
});

test('run duration and status labels are derived from real timestamps', () => {
  assert.match(runDuration(run()), /1\.5 秒/);
  assert.equal(collectionStatusText('queued_remote'), '等待采集节点');
  assert.equal(collectionStatusText('failed'), '采集失败');
  assert.equal(collectionStatusTone('completed'), 'low');
  assert.equal(collectionStatusTone('failed'), 'crit');
});

test('request ids are unique, URL/body safe and never contain credentials', () => {
  const first = createRequestId(4);
  const second = createRequestId(4);
  assert.match(first, /^[A-Za-z0-9_.-]{1,128}$/);
  assert.notEqual(first, second);
  assert.match(first, /^ui-4-/);
});
