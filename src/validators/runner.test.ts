import test from 'node:test';
import assert from 'node:assert/strict';

import { runValidators } from './runner.js';
import type { Validator } from './types.js';

function fakeValidator(name: string, run: Validator['run']): Validator {
  return { name, defaultSeverity: 'advisory', run };
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

test('runValidators runs in parallel by default', async () => {
  const started: string[] = [];
  const aDone = deferred();
  const bDone = deferred();
  const a = fakeValidator('a', async () => {
    started.push('a');
    await aDone.promise;
    return { name: 'a', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const b = fakeValidator('b', async () => {
    started.push('b');
    await bDone.promise;
    return { name: 'b', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const resultsPromise = runValidators({
    txId: 'tx_par', registry: [a, b], workspaceView: '/tmp', realCwd: '/tmp'
  });
  assert.deepEqual(started, ['a', 'b']);
  bDone.resolve();
  aDone.resolve();
  const results = await resultsPromise;
  assert.equal(results.length, 2);
  assert.equal(results[0].name, 'a');
  assert.equal(results[1].name, 'b');
});

test('runValidators serial mode preserves order', async () => {
  const events: string[] = [];
  const aDone = deferred();
  const a = fakeValidator('a', async () => {
    events.push('a:start');
    await aDone.promise;
    events.push('a:end');
    return { name: 'a', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const b = fakeValidator('b', async () => {
    events.push('b:start');
    events.push('b:end');
    return { name: 'b', severity: 'advisory', status: 'pass', durationMs: 50 };
  });
  const resultsPromise = runValidators({
    txId: 'tx_ser', registry: [a, b], workspaceView: '/tmp', realCwd: '/tmp', serial: true
  });
  assert.deepEqual(events, ['a:start']);
  aDone.resolve();
  const results = await resultsPromise;
  assert.equal(results.length, 2);
  assert.equal(results[0].name, 'a');
  assert.equal(results[1].name, 'b');
  assert.deepEqual(events, ['a:start', 'a:end', 'b:start', 'b:end']);
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
