// The genuine native lifecycle at an explicitly approved component seam. The
// external fixture delays a real D-Bus reply; it supplies no clock, phase,
// cancellation callback, StateOwner, model authority or provider credential.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const outcome = promise => promise.then(value => ({ kind: 'resolved', value }), error => ({ kind: 'rejected', error }));
function externalNotifications() {
  let enteredResolve, enteredReject, retiredResolve, retiredReject, timer, text = '', bytesRead = 0, count = 0;
  const entered = new Promise((resolve, reject) => { enteredResolve = resolve; enteredReject = reject; });
  const retired = new Promise((resolve, reject) => { retiredResolve = resolve; retiredReject = reject; });
  // The retirement subscription already exists before close can be invoked.
  // Fixed messages may be adjacent or share a pipe chunk; retain neither raw
  // external text nor an unbounded buffer, and never reset the close deadline.
  const cleanup = () => { clearTimeout(timer); process.stdin.off('data', data); process.stdin.off('end', ended); process.stdin.pause(); };
  const fail = () => {
    cleanup(); const error = new Error('external fixture notification refused'); enteredReject(error); retiredReject(error);
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

try {
  assert.equal(process.versions.node, '24.21.0');
  assert(process.getuid() > 0);
  assert.equal(process.argv.length, 5);
  const platformModule = { exports: {} }, brokerModule = { exports: {} };
  process.dlopen(platformModule, process.argv[2]); process.dlopen(brokerModule, process.argv[3]);
  const platform = platformModule.exports, broker = brokerModule.exports;
  assert.equal(platform.interfaceVersion, 1);
  assert([1, 2, 3].includes(broker.interfaceVersion)); // Original lifecycle RED remains executable on the original ABI.
  const selector = { itemId: 'preparation-lifecycle-item', ownerPrincipalId: 'component-principal',
    stateRootIdentityDigest: '1'.repeat(64), creatingOperationId: 'component-create',
    credentialGrantId: 'component-grant', secretGeneration: 1, credentialTargetDigest: '2'.repeat(64) };
  const secret = Buffer.from('component-only-fixed-test-key');
  let observed;
  try { observed = await platform.secretService({ kind: 'create_compare', selector, secret }); }
  finally { secret.fill(0); }
  assert.equal(observed.kind, 'stored');
  assert.equal(observed.service.pid, process.ppid, 'the ordinary fixture must own the real external service');
  const trust = await readFile(process.argv[4]), body = Buffer.from('{"model":"component","messages":[]}');
  try {
  let owner, lateOwner, ready, closing, notifications, entered = false, preparationSettled = false, timely = false, timer;
  try {
    notifications = externalNotifications();
    owner = broker.prepareModelTransport({ provider: 'openai-compatible', selector, expectedObservation: observed,
      target: { hostAscii: 'localhost', port: 443, basePath: '/v1', serverNameAscii: 'localhost', spkiSha256Pins: ['3'.repeat(64)] },
      trustStoreBytes: trust, trustStoreDigest: digest(trust), requestPath: '/chat/completions',
      bodyBytes: body, bodyBytesDigest: digest(body) });
    const originalPromise = typeof owner?.then === 'function';
    ready = outcome(originalPromise ? owner.then(value => { lateOwner = value; }) : owner.ready);
    void ready.then(() => { preparationSettled = true; });
    await notifications.entered; entered = true; // Actual external I/O, not a native phase hint.
    assert.equal(preparationSettled, false, 'preparation must still await its original unanswered external reply');
    const started = performance.now();
    // On the old ABI, this continuation cannot even acquire its actual close
    // owner until the unanswered call returns. It is retained for safe cleanup.
    closing = originalPromise ? ready.then(result => result.kind === 'resolved' ? lateOwner.close() : undefined) : owner.close();
    const joined = await Promise.race([Promise.all([ready, closing, notifications.retired]).then(([prepared, closed]) => ({ prepared, closed })),
      new Promise(resolve => { timer = setTimeout(() => resolve(undefined), 1500); })]);
    timely = !originalPromise && performance.now() - started <= 1500 && joined?.prepared.kind === 'rejected' &&
      joined.prepared.error.code === 'ERR_CLIQ_MODEL_BROKER' && joined.closed?.kind === 'broker_transport_closed' &&
      joined.closed.networkStarted === false && joined.closed.requestStarted === false && joined.closed.tokenRevoked === true &&
      joined.closed.matchingActiveReleaseCount === 0 && joined.closed.bodyBytesDigest === digest(body) &&
      joined.closed.brokerFenceTokenDigest === owner.brokerFenceTokenDigest;
  } finally {
    clearTimeout(timer);
    // Always release the external reply and join the old preparation/real
    // handle too. Expected RED is reported only after these owners settle.
    await new Promise((resolve, reject) => process.stdout.write(`release:${timely ? 'timely' : 'late'}\n`,
      error => error ? reject(error) : resolve()));
    if (ready) await ready;
    if (closing) await closing;
    else if (lateOwner) await lateOwner.close();
    else if (owner && typeof owner.close === 'function') await owner.close();
    if (entered) await notifications.retired;
    notifications?.cleanup();
  }
  assert.equal(timely, true, 'close must cancel and join an already executing native preparation within 1500ms');
  let retained, fence, fenceRetained = false;
  try {
    // The same external service now answers normally. No transport connection,
    // StateOwner or permanent SQL claim is fabricated by this component test.
    retained = broker.prepareModelTransport({ provider: 'openai-compatible', selector, expectedObservation: observed,
      target: { hostAscii: 'localhost', port: 443, basePath: '/v1', serverNameAscii: 'localhost', spkiSha256Pins: ['3'.repeat(64)] },
      trustStoreBytes: trust, trustStoreDigest: digest(trust), requestPath: '/chat/completions',
      bodyBytes: body, bodyBytesDigest: digest(body) });
    await retained.ready;
    const binding = { runId: 'component-run', opId: 'component-op', attempt: 0,
      dispatchId: 'component-dispatch', dispatchJournalSeq: 2, requestRef: '4'.repeat(64), requestDigest: '5'.repeat(64),
      targetRef: '6'.repeat(64), targetDigest: '7'.repeat(64), grantRef: '8'.repeat(64),
      supervisorInstanceId: 'component-supervisor', stateOwnerEpoch: 1, leaseEpoch: 1,
      brokerFenceTokenDigest: retained.brokerFenceTokenDigest };
    assert.equal(typeof retained.retainDispatchFence, 'function', 'the original native token must have an explicit pre-claim owner');
    assert.throws(() => retained.acquireNoReleaseFence(binding), 'an unjoined live transport cannot prove no release');
    retained.retainDispatchFence(); fenceRetained = true;
    assert.throws(() => retained.retainDispatchFence(), 'one original transport cannot mint a second retained token');
    const closure = await retained.close();
    assert.equal(closure.networkStarted, false); assert.equal(closure.requestStarted, false);
    assert.equal(closure.tokenRevoked, true); assert.equal(closure.matchingActiveReleaseCount, 0);
    assert.equal(closure.brokerFenceTokenDigest, binding.brokerFenceTokenDigest);
    assert.throws(() => retained.acquireNoReleaseFence({ ...binding, brokerFenceTokenDigest: '0'.repeat(64) }));
    fence = retained.acquireNoReleaseFence(binding);
    fence.assertHeld();
    assert.equal(digest(await readFile(process.argv[4])), digest(trust));
    fence.assertHeld(); // The original mutex remains held across actual async I/O.
    assert.throws(() => fence.assertHeld.call({}), 'structural data cannot impersonate the native mutex owner');
    assert.throws(() => retained.acquireNoReleaseFence(binding), 'the same original mutex cannot be acquired twice');
    assert.throws(() => retained.releaseDispatchFence(), 'a live mutex guard must prevent final owner disposal');
    assert.throws(() => retained.connect(binding), 'retaining the original fence never reopens productive transport');
    fence.assertHeld();
    fence.close();
    assert.throws(() => fence.assertHeld(), 'a dropped guard cannot be reused as transaction evidence');
    assert.throws(() => retained.acquireNoReleaseFence({ ...binding, dispatchId: 'different-claim' }),
      'the original native binding must remain fixed after the first observation');
    retained.releaseDispatchFence(); fenceRetained = false;
    assert.throws(() => retained.acquireNoReleaseFence(binding), 'disposed original tokens cannot be reconstructed');
  } finally {
    try { fence?.close(); }
    finally {
      try {
        if (retained) await retained.close();
        if (fenceRetained) retained.releaseDispatchFence();
      } finally { trust.fill(0); body.fill(0); }
    }
  }
  // Return naturally while the same tracked process still owns a real mutex
  // guard. The fixture requires this exact child's normal exit and namespace
  // preservation; an environment cleanup hang or finalizer UAF must fail it.
  let teardownOwner, teardownFence, teardownRetained = false, handedToEnvironment = false;
  try {
    const teardownTrust = await readFile(process.argv[4]), teardownBody = Buffer.from('{"model":"component","messages":[]}');
    try {
      teardownOwner = broker.prepareModelTransport({ provider: 'openai-compatible', selector, expectedObservation: observed,
        target: { hostAscii: 'localhost', port: 443, basePath: '/v1', serverNameAscii: 'localhost', spkiSha256Pins: ['3'.repeat(64)] },
        trustStoreBytes: teardownTrust, trustStoreDigest: digest(teardownTrust), requestPath: '/chat/completions',
        bodyBytes: teardownBody, bodyBytesDigest: digest(teardownBody) });
      await teardownOwner.ready;
      teardownOwner.retainDispatchFence(); teardownRetained = true;
      await teardownOwner.close();
      teardownFence = teardownOwner.acquireNoReleaseFence({ runId: 'teardown-run', opId: 'teardown-op', attempt: 0,
        dispatchId: 'teardown-dispatch', dispatchJournalSeq: 2, requestRef: '4'.repeat(64), requestDigest: '5'.repeat(64),
        targetRef: '6'.repeat(64), targetDigest: '7'.repeat(64), grantRef: '8'.repeat(64),
        supervisorInstanceId: 'component-supervisor', stateOwnerEpoch: 1, leaseEpoch: 1,
        brokerFenceTokenDigest: teardownOwner.brokerFenceTokenDigest });
      teardownFence.assertHeld();
      globalThis.cliqComponentTeardownOwners = Object.freeze({ owner: teardownOwner, fence: teardownFence });
      handedToEnvironment = true;
    } finally { teardownTrust.fill(0); teardownBody.fill(0); }
  } finally {
    if (!handedToEnvironment) {
      try { teardownFence?.close(); }
      finally {
        if (teardownOwner) await teardownOwner.close();
        if (teardownRetained) teardownOwner.releaseDispatchFence();
      }
    }
  }
  } finally { trust.fill(0); body.fill(0); }
} catch (error) {
  // Only fixed local/native errors, never an external error payload or secret.
  console.error(error);
  process.exitCode = 1;
}
