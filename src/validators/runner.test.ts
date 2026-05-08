import test from 'node:test';
import assert from 'node:assert/strict';

import { runValidators } from './runner.js';
import type { Validator } from './types.js';

function fakeValidator(name: string, run: Validator['run']): Validator {
  return { name, defaultSeverity: 'advisory', run };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('runValidators runs in parallel by default', async () => {
  const a = fakeValidator('a', async () => {
    await sleep(50);
    return { name: 'a', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const b = fakeValidator('b', async () => {
    await sleep(50);
    return { name: 'b', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const start = Date.now();
  const results = await runValidators({
    txId: 'tx_par', registry: [a, b], workspaceView: '/tmp', realCwd: '/tmp'
  });
  const elapsed = Date.now() - start;
  assert.equal(results.length, 2);
  assert.equal(results[0].name, 'a');
  assert.equal(results[1].name, 'b');
  assert.ok(elapsed < 90, `expected <90ms, got ${elapsed}ms`);
});

test('runValidators serial mode preserves order', async () => {
  const a = fakeValidator('a', async () => {
    await sleep(50);
    return { name: 'a', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const b = fakeValidator('b', async () => {
    await sleep(50);
    return { name: 'b', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const start = Date.now();
  const results = await runValidators({
    txId: 'tx_ser', registry: [a, b], workspaceView: '/tmp', realCwd: '/tmp', serial: true
  });
  const elapsed = Date.now() - start;
  assert.equal(results.length, 2);
  assert.equal(results[0].name, 'a');
  assert.equal(results[1].name, 'b');
  assert.ok(elapsed >= 100, `expected >=100ms, got ${elapsed}ms`);
});

test('runValidators captures thrown errors as status:error and does not bubble', async () => {
  const ok = fakeValidator('ok', async () => ({ name: 'ok', severity: 'advisory', status: 'pass', durationMs: 1 }));
  const boom = fakeValidator('boom', async () => { throw new Error('kaboom'); });
  const results = await runValidators({
    txId: 'tx_err', registry: [ok, boom], workspaceView: '/tmp', realCwd: '/tmp'
  });
  assert.equal(results.length, 2);
  const boomResult = results.find((r) => r.name === 'boom')!;
  assert.equal(boomResult.status, 'error');
  assert.equal(boomResult.severity, 'advisory');
  assert.match(boomResult.message ?? '', /kaboom/);
});

test('runValidators invokes onResult callback for each result', async () => {
  const a = fakeValidator('a', async () => ({ name: 'a', severity: 'advisory', status: 'pass', durationMs: 1 }));
  const seen: string[] = [];
  await runValidators({
    txId: 'tx_cb', registry: [a], workspaceView: '/tmp', realCwd: '/tmp',
    onResult: async (r) => { seen.push(r.name); }
  });
  assert.deepEqual(seen, ['a']);
});
