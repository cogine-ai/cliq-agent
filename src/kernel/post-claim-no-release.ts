import { assertArtifactRef, digestOmitting, normalizeBoundedText, parseCanonicalTime } from './identity.js';
import { exactKeys } from '../policy/runtime-authority.js';

/** Implemented broker-only branch. Decoding data proves neither a live fence
 * nor a failed invocation; the original native owner supplies that authority. */
export type BrokerPostClaimNoReleaseEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-post-claim-no-release-evidence-v1'; runId: string; opId: string; attempt: number;
  dispatchId: string; dispatchJournalSeq: number; operationRequestRef: string; operationRequestDigest: string;
  operationTargetRef: string; operationTargetDigest: string; operationGrantRef: string;
  claimingSupervisorInstanceId: string; claimingStateOwnerEpoch: number; inspectorIdentityRef: string;
  inspectorIdentityDigest: string; observedAt: string;
  closure: { kind: 'broker_release_never_started'; brokerFenceTokenDigest: string;
    fenceAction: 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero' };
  evidenceDigest: string;
};

export function decodeBrokerPostClaimNoRelease(value: unknown): BrokerPostClaimNoReleaseEvidenceV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, ['schemaVersion', 'format', 'runId', 'opId',
    'attempt', 'dispatchId', 'dispatchJournalSeq', 'operationRequestRef', 'operationRequestDigest', 'operationTargetRef',
    'operationTargetDigest', 'operationGrantRef', 'claimingSupervisorInstanceId', 'claimingStateOwnerEpoch',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'closure', 'evidenceDigest']))
    throw new TypeError('broker no-release evidence has unknown or missing fields');
  const evidence = value as BrokerPostClaimNoReleaseEvidenceV1;
  if (evidence.schemaVersion !== 1 || evidence.format !== 'cliq-post-claim-no-release-evidence-v1' ||
      !Number.isSafeInteger(evidence.attempt) || evidence.attempt < 0 || !Number.isSafeInteger(evidence.dispatchJournalSeq) ||
      evidence.dispatchJournalSeq < 1 || !Number.isSafeInteger(evidence.claimingStateOwnerEpoch) || evidence.claimingStateOwnerEpoch < 1 ||
      !evidence.closure || !exactKeys(evidence.closure, ['kind', 'brokerFenceTokenDigest', 'fenceAction']) ||
      evidence.closure.kind !== 'broker_release_never_started' ||
      evidence.closure.fenceAction !== 'same_owner_token_revoked_before_release_and_matching_active_release_count_zero')
    throw new TypeError('broker no-release evidence has an invalid identity or fence action');
  for (const key of ['runId', 'opId', 'dispatchId', 'claimingSupervisorInstanceId'] as const)
    if (typeof evidence[key] !== 'string' || normalizeBoundedText(evidence[key], 1, 128) !== evidence[key]) throw new TypeError('invalid broker no-release identity');
  for (const key of ['operationRequestRef', 'operationRequestDigest', 'operationTargetRef', 'operationTargetDigest',
    'operationGrantRef', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest'] as const) assertArtifactRef(evidence[key]);
  assertArtifactRef(evidence.closure.brokerFenceTokenDigest); parseCanonicalTime(evidence.observedAt);
  if (evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest')) throw new TypeError('broker no-release evidence digest differs');
  return evidence;
}
