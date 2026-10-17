import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { digestOmitting } from './identity.js';
import { decodeBrokerPostClaimNoRelease } from './post-claim-no-release.js';

// Closed retained data only. These literals create no lock, token, StateOwner,
// native observation, failure settlement or authority to refund a claim.
const evidence = { schemaVersion: 1, format: 'cliq-post-claim-no-release-evidence-v1', runId: 'run', opId: 'model-op', attempt: 0,
  dispatchId: 'dispatch', dispatchJournalSeq: 2, operationRequestRef: canonicalSha256('request'), operationRequestDigest: canonicalSha256('request-body'),
  operationTargetRef: canonicalSha256('endpoint'), operationTargetDigest: canonicalSha256('target'), operationGrantRef: canonicalSha256('grant'),
  claimingSupervisorInstanceId: 'original-owner', claimingStateOwnerEpoch: 1, inspectorIdentityRef: canonicalSha256('inspector'),
  inspectorIdentityDigest: canonicalSha256('inspector-identity'), observedAt: '2026-10-17T01:00:00.000Z',
  closure: { kind: 'broker_release_never_started', brokerFenceTokenDigest: canonicalSha256('token'),
    fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero' }, evidenceDigest: '' };
evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');

test('broker no-release data requires the exact closed original-claim fields and literal fence action', () => {
  assert.deepEqual(decodeBrokerPostClaimNoRelease(evidence), evidence);
  for (const change of [{ attempt: -1 }, { dispatchJournalSeq: 0 }, { claimingStateOwnerEpoch: 0 },
    { operationGrantRef: undefined }, { extra: true }, { observedAt: 'yesterday' },
    { closure: { ...evidence.closure, tokenRevoked: true } },
    { closure: { ...evidence.closure, fenceAction: 'closed_report_says_zero' } },
    { closure: { ...evidence.closure, sandboxLaunchSpecRef: canonicalSha256('different-domain') } },
    { closure: { ...evidence.closure, kind: 'process_spawn_never_started' } }]) {
    const value = Object.fromEntries(Object.entries({ ...evidence, ...change, evidenceDigest: '' }).filter(([, value]) => value !== undefined));
    value.evidenceDigest = digestOmitting(value, 'evidenceDigest');
    assert.throws(() => decodeBrokerPostClaimNoRelease(value));
  }
});
