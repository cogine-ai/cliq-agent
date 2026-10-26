// Negative native-object/lifetime component only. No credential observation is
// accepted, no ready transport is claimed, and no Run or authority is created.
// Arguments are only the two already-built, test-owned native module files.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { rootCertificates } = require('node:tls');
const [oldFile, newFile] = process.argv.slice(2);
assert.equal(process.argv.length, 4);
const original = require(oldFile), current = require(newFile);
assert.equal(original.interfaceVersion, 3); assert.equal(current.interfaceVersion, 3);
const ref = 'a'.repeat(64), digest = bytes => createHash('sha256').update(bytes).digest('hex');
const selector = { itemId: 'negative-native-family', ownerPrincipalId: 'negative-native-family', stateRootIdentityDigest: ref,
  creatingOperationId: 'negative-native-family', credentialGrantId: 'negative-native-family', secretGeneration: 1, credentialTargetDigest: ref };
const processData = { uid: process.getuid(), pid: process.pid, processStartToken: 'linux-proc-start-ticks:1' };
const input = { provider: 'openai-compatible', selector,
  // Deliberately unproven negative input. Preparation must refuse or cancel;
  // these syntactic values are never presented as actual platform facts.
  expectedObservation: { selector, bus: { ...processData, guid: 'b'.repeat(32), runtime: { deviceId: '0', fileId: '1' }, socket: { deviceId: '0', fileId: '2' } },
    service: { ...processData, uniqueName: ':1.1' }, collectionPath: '/negative', itemPath: '/negative/item' },
  target: { hostAscii: 'localhost', port: 443, basePath: '/', serverNameAscii: 'localhost', spkiSha256Pins: [ref] },
  trustStoreBytes: Buffer.from(rootCertificates[0]), requestPath: '/chat/completions', bodyBytes: Buffer.from('{}') };
input.trustStoreDigest = digest(input.trustStoreBytes); input.bodyBytesDigest = digest(input.bodyBytes);
async function main() {
  const before = original.prepareModelTransport(input), after = current.prepareModelTransport(input);
  const ready = Promise.allSettled([before.ready, after.ready]);
  let failure;
  try {
    const invalidOwner = error => error instanceof TypeError && error.message === 'Invalid installed model broker owner';
    assert.throws(() => after.releaseDispatchFence.call(before), invalidOwner);
    assert.throws(() => before.releaseDispatchFence.call(after), invalidOwner);
  } catch (error) { failure = error; }
  const closed = await Promise.all([before.close(), after.close()]);
  for (const result of closed) {
    assert.equal(result.kind, 'broker_transport_closed'); assert.equal(result.networkStarted, false);
    assert.equal(result.requestStarted, false); assert.equal(result.tokenRevoked, true);
    assert.equal(result.matchingActiveReleaseCount, 0);
  }
  for (const result of await ready) assert.equal(result.status, 'rejected');
  if (failure) throw failure;
  console.log(JSON.stringify({ kind: 'actual-native-private-family-reject-and-join', node: process.versions.node,
    checks: 2, originalOwnersJoined: true, networkStarted: false, actualSystemdQualified: false, supportedNodeQualified: false }));
}
main().catch(() => { console.error('actual native private family rejection or original join failed'); process.exitCode = 1; });
