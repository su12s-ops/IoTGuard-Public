// Isolated frontend regression tests; fixtures are not evidence of a live run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { computed, ref } from 'vue';

const source = readFileSync(new URL('../src/views/Agents.vue', import.meta.url), 'utf8');
const script = source.match(/<script setup>([\s\S]*?)<\/script>/)[1].replace(/^import .*;\r?\n/gm, '');
function mount(api) {
  const intervals = new Map();
  const window = { setInterval(fn) { intervals.set(1, fn); return 1; }, clearInterval(id) { intervals.delete(id); } };
  const create = new Function('computed', 'ref', 'onMounted', 'onUnmounted', 'watch', 'api', 'notify', 'ui', 'shortTime', 'statusLabel', 'statusTone', 'consoleState', 'window', `${script}\nreturn { runs, selectedRun, detail, agents, agentSteps, timeline, gateChecks, reviewRunId, reviewRun, reviewPending, runningActive, refreshAll, syncPolling };`);
  const state = create(computed, ref, () => {}, () => {}, () => {}, api, () => {}, {}, (x) => x || '—', (x) => x || '未知', () => 'muted', { workflow: null }, window);
  return { ...state, intervals };
}

test('missing role states and messages are never inferred from completed or running', () => {
  const vm = mount({});
  for (const status of ['running', 'completed']) {
    vm.selectedRun.value = { run_id: 'fixture', status };
    assert.ok(vm.agents.value.every((agent) => agent.state === 'idle' && agent.statusLabel === '未记录'));
    assert.ok(vm.agentSteps.value.every((step) => step.state === 'idle'));
    assert.deepEqual(vm.timeline.value, []);
  }
  vm.detail.value = { agents: { runtime_analyst: { status: 'degraded' }, asset_investigator: { status: 'succeeded' } } };
  assert.equal(vm.agentSteps.value[0].state, 'done');
  assert.equal(vm.agentSteps.value[2].state, 'idle');
  assert.equal(vm.agentSteps.value[2].statusLabel, 'degraded');
});

test('auto_confirmed never grants repair authorization; missing checks are unrecorded', () => {
  const vm = mount({});
  vm.detail.value = { final: { policy: { status: 'auto_confirmed' } } };
  assert.equal(vm.gateChecks.value.find((x) => x.label === '证据引用').value, '未记录');
  assert.equal(vm.gateChecks.value.find((x) => x.label === '修复执行授权').value, '仍需人工审批');
});

test('batch review is polled to terminal without any unified run rows', async () => {
  let status = 'running';
  const calls = [];
  const vm = mount({
    async post(path) { assert.equal(path, '/rounds/start'); return { data: { review: { run_id: 'batch-fixture' } } }; },
    async get(path, options) {
      calls.push([path, options]);
      if (path === '/rounds/current') return { data: { active: { running: false }, devices: [] } };
      if (path === '/unified/runs') return { data: { runs: [] } };
      if (path === '/analysis/runs/batch-fixture') return { data: { run_id: 'batch-fixture', status } };
      throw new Error(`unexpected read ${path}`);
    }
  });
  vm.reviewRunId.value = 'batch-fixture';
  await vm.refreshAll();
  assert.equal(vm.reviewRunId.value, 'batch-fixture');
  assert.equal(vm.reviewPending.value, true);
  assert.equal(vm.intervals.size, 1);
  assert.equal(calls.find(([path]) => path === '/unified/runs')[1].params.mode, 'formal');
  status = 'human_review';
  await vm.refreshAll();
  assert.equal(vm.reviewRun.value.status, 'human_review');
  assert.equal(vm.reviewPending.value, false);
  assert.equal(vm.intervals.size, 0);
  const count = calls.filter(([path]) => path.startsWith('/analysis/runs/')).length;
  await vm.refreshAll();
  assert.equal(calls.filter(([path]) => path.startsWith('/analysis/runs/')).length, count);
});
