import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { decodeDependencyAmbiguity } from './dependency-ambiguity.js';
const ref = (value: string) => canonicalSha256({ inert: value });
const core = { schemaVersion: 1, format: 'cliq-dependency-ambiguity-v1', runId: 'run', opId: 'op', attempt: 0,
  dispatchId: 'dispatch', claimJournalSeq: 2, requestRef: ref('request'), target: 'builtin:dependency-acquire',
  grantRef: ref('grant'), brokerFenceTokenDigest: ref('token') };
test('dependency UNKNOWN data keeps actual joined native fence and dead claiming process exclusive', () => {
  const joined = { ...core, reason: 'original_owner_joined_without_process_result', brokerDispatchClosureRef: ref('joined') };
  const dead = { ...core, reason: 'claiming_owner_dead_before_result', acquisitionEvidenceRef: ref('acquisition'), acquisitionEvidenceDigest: ref('meaning') };
  assert.deepEqual(decodeDependencyAmbiguity(joined), joined); assert.deepEqual(decodeDependencyAmbiguity(dead), dead);
  for (const bad of [{ ...dead, brokerDispatchClosureRef: ref('invented traffic') }, { ...joined, ...dead },
    { ...dead, acquisitionEvidenceDigest: undefined }, { ...dead, target: 'builtin:bash' }, { ...dead, attempt: 1 },
    { ...dead, resultRef: ref('invented result') }, { ...dead, reason: 'controller_closed' }, { ...joined, requestCount: 0 }])
    assert.throws(() => decodeDependencyAmbiguity(bad));
  let traps = 0; assert.throws(() => decodeDependencyAmbiguity(new Proxy({}, { get() { traps++; }, ownKeys() { traps++; return []; } })));
  assert.equal(traps, 0);
});
