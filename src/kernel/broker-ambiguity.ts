import { exactKeys } from '../policy/runtime-authority.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime } from './identity.js';

/** Exact broker branch of InvocationAmbiguityEvidenceV1. Decoding data does
 * not prove a live channel observation, token revocation or external effect. */
export type BrokerInvocationAmbiguityEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-invocation-ambiguity-evidence-v1';
  runId: string; frontierRef: string; frontierDigest: string; opId: string; opKind: 'model' | 'tool' | 'mcp';
  attempt: number; dispatchId: string; dispatchJournalSeq: number;
  operationRequestRef: string; operationRequestDigest: string; operationTargetRef: string; operationTargetDigest: string;
  claimingSupervisorInstanceId: string; claimingStateOwnerEpoch: number;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string; evidenceDigest: string;
  ambiguityKind: 'broker_channel_lost_after_claim'; brokerFenceTokenDigest: string;
  failureCode: 'deadline_after_release_possible' | 'connection_lost_after_release_possible' | 'response_stream_interrupted';
  durableTerminalResultAbsent: true;
};

export function decodeBrokerInvocationAmbiguity(value: unknown): BrokerInvocationAmbiguityEvidenceV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, ['schemaVersion', 'format', 'runId',
    'frontierRef', 'frontierDigest', 'opId', 'opKind', 'attempt', 'dispatchId', 'dispatchJournalSeq', 'operationRequestRef',
    'operationRequestDigest', 'operationTargetRef', 'operationTargetDigest', 'claimingSupervisorInstanceId', 'claimingStateOwnerEpoch',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'ambiguityKind', 'brokerFenceTokenDigest',
    'failureCode', 'durableTerminalResultAbsent'])) throw new TypeError('broker ambiguity has an invalid closed shape');
  const evidence = value as BrokerInvocationAmbiguityEvidenceV1;
  if (evidence.schemaVersion !== 1 || evidence.format !== 'cliq-invocation-ambiguity-evidence-v1' ||
      evidence.ambiguityKind !== 'broker_channel_lost_after_claim' || !['model', 'tool', 'mcp'].includes(evidence.opKind) ||
      evidence.durableTerminalResultAbsent !== true || !['deadline_after_release_possible', 'connection_lost_after_release_possible',
        'response_stream_interrupted'].includes(evidence.failureCode) || !Number.isSafeInteger(evidence.attempt) || evidence.attempt < 0 ||
      !Number.isSafeInteger(evidence.dispatchJournalSeq) || evidence.dispatchJournalSeq < 1 ||
      !Number.isSafeInteger(evidence.claimingStateOwnerEpoch) || evidence.claimingStateOwnerEpoch < 1)
    throw new TypeError('broker ambiguity has invalid identity or observation fields');
  for (const key of ['runId', 'opId', 'dispatchId', 'claimingSupervisorInstanceId'] as const)
    if (typeof evidence[key] !== 'string' || !evidence[key] || Buffer.byteLength(evidence[key]) > 256 || evidence[key].includes('\0'))
      throw new TypeError('broker ambiguity identity is invalid');
  for (const key of ['frontierRef', 'frontierDigest', 'operationRequestRef', 'operationRequestDigest', 'operationTargetRef',
    'operationTargetDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest', 'brokerFenceTokenDigest'] as const)
    assertArtifactRef(evidence[key]);
  parseCanonicalTime(evidence.observedAt);
  if (evidence.frontierRef !== evidence.frontierDigest || evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest'))
    throw new TypeError('broker ambiguity digest does not rehash');
  return evidence;
}
