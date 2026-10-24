// Isolated UI mapping regression: quarantined risks must not read as reviewable.
import test from 'node:test';
import assert from 'node:assert/strict';
import { statusLabel, statusTone } from '../src/utils/format.js';

test('quarantined_mapping is shown as an explicit unmapped/quarantine state', () => {
  assert.equal(statusLabel('quarantined_mapping'), '未映射（待重新映射）');
  assert.notEqual(statusLabel('quarantined_mapping'), statusLabel('candidate'));
  assert.notEqual(statusLabel('quarantined_mapping'), statusLabel('reanalysis_required'));
  assert.match(statusLabel('quarantined_mapping'), /未映射|重新映射|隔离/);
  assert.equal(statusTone('quarantined_mapping'), 'high');
});
