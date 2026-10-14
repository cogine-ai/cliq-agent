// Public native component seam only. No injected clock, cancellation callback,
// native phase, authority observation, or production interface extension.
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';

try {
  assert.equal(process.versions.node, '24.21.0');
  assert(process.getuid() > 0);
  assert.equal(process.argv.length, 3);
  const loaded = { exports: {} };
  process.dlopen(loaded, process.argv[2]);
  const native = loaded.exports;
  assert.equal(native.interfaceVersion, 1);
  assert.equal(native.currentUser().uid, process.getuid());
  const started = performance.now();
  const outcome = await native.userManager({ kind: 'reload' }).then(
    value => ({ kind: 'resolved', value }), error => ({ kind: 'rejected', error }));
  const elapsed = performance.now() - started;
  assert.equal(outcome.kind, 'rejected', 'an unanswered external call must respect the actual native 30-second budget');
  assert.equal(outcome.error.code, 'ERR_CLIQ_CREDENTIAL_PLATFORM', 'ordinary timeout must not poison resource retirement');
  assert.equal(outcome.error.platformCode, 'platform_timeout');
  assert(elapsed >= 25000 && elapsed <= 35000);
  assert.equal(native.currentUser().uid, process.getuid());
  // Both the old request's local bus close and its worker/watchdog/main-loop
  // owners must have joined before another operation can be admitted.
  const healthy = await native.userManager({ kind: 'reload' });
  assert.equal(healthy.kind, 'reload');
  assert.equal(healthy.uid, process.getuid());
  assert.equal(healthy.manager.uid, process.getuid());
  assert.equal(healthy.manager.pid, process.ppid, 'the same ordinary non-root fixture must own the actual service');
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
