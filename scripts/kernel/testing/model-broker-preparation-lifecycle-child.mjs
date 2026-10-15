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
  assert([1, 2].includes(broker.interfaceVersion)); // Same behavioral RED can run on the original ABI.
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
    trust.fill(0); body.fill(0);
  }
  assert.equal(timely, true, 'close must cancel and join an already executing native preparation within 1500ms');
} catch (error) {
  // Only fixed local/native errors, never an external error payload or secret.
  console.error(error);
  process.exitCode = 1;
}
