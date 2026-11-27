import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fixtureCommandJoinDiagnostic } from './fixture-command-diagnostic.js';

test('an actual fixture command timeout is distinguished without retaining input, paths or error text', () => {
  const started = performance.now();
  const result = spawnSync(process.execPath, ['-e', 'setInterval(()=>{},1000)'], {
    timeout: 5, killSignal: 'SIGKILL', stdio: 'pipe', input: 'not-retained-fixture-input'
  });
  const value = fixtureCommandJoinDiagnostic(result, 5, started)!;
  assert.deepEqual(Object.keys(value).sort(), ['diagnosticOnly', 'elapsedMs', 'errorKind', 'exitCode', 'originalDeadlineMs', 'signal']);
  assert.equal(value.errorKind, 'timeout'); assert.equal(value.originalDeadlineMs, 5);
  assert.equal(value.signal, 'SIGKILL'); assert.equal(value.exitCode, null);
  assert(Number.isSafeInteger(value.elapsedMs) && value.elapsedMs >= 0);
  assert(!JSON.stringify(value).includes('not-retained'));
});

test('a successful fixture command creates no failure diagnostic', () => {
  assert.equal(fixtureCommandJoinDiagnostic({ status: 0, signal: null }, 5000, performance.now()), undefined);
});
