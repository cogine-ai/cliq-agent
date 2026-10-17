// Public native component seam only. No injected clock, cancellation callback,
// native phase or authority observation. A real external reply is withheld.
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';

function inspectionNotifications() {
  let enteredResolve, enteredReject, retiredResolve, retiredReject, timer, text = '', bytesRead = 0, count = 0;
  const entered = new Promise((resolve, reject) => { enteredResolve = resolve; enteredReject = reject; });
  const retired = new Promise((resolve, reject) => { retiredResolve = resolve; retiredReject = reject; });
  const cleanup = () => { clearTimeout(timer); process.stdin.off('data', data); process.stdin.off('end', ended); process.stdin.pause(); };
  const fail = () => {
    cleanup(); const error = new Error('external inspection notification refused'); enteredReject(error); retiredReject(error);
  };
  const data = bytes => {
    bytesRead += bytes.length; text += bytes.toString('utf8');
    if (bytesRead > 64) { fail(); return; }
    for (;;) {
      const newline = text.indexOf('\n'); if (newline < 0) break;
      const line = text.slice(0, newline); text = text.slice(newline + 1);
      if (count === 0 && line === 'prepare-started') { count++; clearTimeout(timer); enteredResolve(); }
      else if (count === 1 && line === 'prepare-retired') { count++; retiredResolve(); }
      else { fail(); return; }
    }
  };
  const ended = () => { if (count !== 2 || text) fail(); else cleanup(); };
  process.stdin.on('data', data); process.stdin.once('end', ended);
  timer = setTimeout(fail, 5000);
  void entered.catch(() => {}); void retired.catch(() => {});
  return { entered, retired, cleanup };
}

async function inspectCancellation(native) {
  const selector = { itemId: 'inspection-lifecycle-item', ownerPrincipalId: 'component-principal',
    stateRootIdentityDigest: '1'.repeat(64), creatingOperationId: 'component-create',
    credentialGrantId: 'component-grant', secretGeneration: 1, credentialTargetDigest: '2'.repeat(64) };
  const secret = Buffer.from('component-only-fixed-test-key');
  let observed;
  try { observed = await native.secretService({ kind: 'create_compare', selector, secret }); }
  finally { secret.fill(0); }
  assert.equal(observed.kind, 'stored'); assert.equal(observed.service.pid, process.ppid);
  const outcome = promise => promise.then(value => ({ kind: 'resolved', value }), error => ({ kind: 'rejected', error }));
  const notifications = inspectionNotifications();
  let inspection, result, joining, timer, entered = false, settled = false, timely = false;
  try {
    inspection = native.secretService({ kind: 'inspect', selector, expectedObservation: observed });
    result = outcome(inspection); void result.then(() => { settled = true; });
    await notifications.entered; entered = true;
    assert.equal(settled, false, 'the original inspection must still await its actual unanswered external reply');
    const started = performance.now();
    // The original ABI still reaches the genuine in-flight job. Its missing
    // cancellation owner is RED only after that external call is observed.
    if (typeof inspection.cancelAndJoin === 'function') {
      assert.throws(() => inspection.cancelAndJoin.call({}), 'a structural receiver cannot cancel a native job');
      assert.throws(() => inspection.cancelAndJoin({}), 'cancellation accepts no caller-supplied fields');
      joining = inspection.cancelAndJoin();
      assert.equal(inspection.cancelAndJoin(), joining, 'one original inspection retains one memoized join');
    }
    const joined = await Promise.race([Promise.all([result, joining, notifications.retired]).then(([observation]) => observation),
      new Promise(resolve => { timer = setTimeout(() => resolve(undefined), 1500); })]);
    timely = !!joining && performance.now() - started <= 1500 && joined?.kind === 'rejected' &&
      joined.error.code === 'ERR_CLIQ_CREDENTIAL_PLATFORM' && joined.error.platformCode === 'platform_cancelled';
  } finally {
    clearTimeout(timer);
    // Even expected RED releases the actual remote call and joins its native
    // result, connection and both children. No Promise race abandons work.
    await new Promise((resolve, reject) => process.stdout.write(`release:${timely ? 'timely' : 'late'}\n`,
      error => error ? reject(error) : resolve()));
    if (result) await result;
    if (joining) await joining;
    if (entered) await notifications.retired;
    notifications.cleanup();
  }
  assert.equal(timely, true, 'caller cancellation must join the executing native inspection within 1500ms');
  assert.equal(native.interfaceVersion, 2, 'the owning inspection requires the new signed native ABI');
  assert.equal(native.currentUser().uid, process.getuid());
  // A retained old owner must not cancel the next job, even while its native
  // admission is already occupied and before JS completion can run.
  const healthy = native.secretService({ kind: 'inspect', selector, expectedObservation: observed });
  assert.equal(inspection.cancelAndJoin(), joining);
  const fresh = await healthy;
  assert.equal(fresh.kind, 'present'); assert.equal(fresh.service.pid, process.ppid);
  assert.deepEqual(fresh.selector, observed.selector); assert.deepEqual(fresh.bus, observed.bus);
  assert.deepEqual(fresh.service, observed.service); assert.equal(fresh.collectionPath, observed.collectionPath);
  assert.equal(fresh.itemPath, observed.itemPath);
}

try {
  assert.equal(process.versions.node, '24.21.0');
  assert(process.getuid() > 0);
  assert(process.argv.length === 3 || process.argv.length === 4 && process.argv[3] === '--inspect-cancel');
  const loaded = { exports: {} };
  process.dlopen(loaded, process.argv[2]);
  const native = loaded.exports;
  assert([1, 2].includes(native.interfaceVersion)); // The old ABI must reach the genuine cancellation RED.
  assert.equal(native.currentUser().uid, process.getuid());
  if (process.argv.length === 4) {
    await inspectCancellation(native);
  } else {
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
  }
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
