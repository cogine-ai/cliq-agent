import { assertArtifactRef, digestOmitting, parseCanonicalTime } from './identity.js';

/** Historical data only. Decoding cannot observe process death or mint release authority. */
export type BrokerProcessDomainDeathEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-broker-process-domain-death-evidence-v1';
  runId: string; opId: string; attempt: number; dispatchId: string; dispatchJournalSeq: number;
  operationRequestRef: string; operationTargetDigest: string; operationGrantRef: string;
  claimingSupervisorInstanceId: string; claimingStateOwnerEpoch: number;
  claimingProcessIdentityRef: string; claimingProcessIdentityDigest: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; inspectorStateOwnerEpoch: number;
  brokerFenceTokenDigest: string;
  authorityDomain: 'linux_installed_native_creator_process_v1';
  processObservation: 'absent_or_start_token_mismatch';
  observedAt: string; evidenceDigest: string;
};

/** Only the implemented data branch; other dispatch-closure producers remain separate. */
export type BrokerProcessDomainDeathDispatchClosureV1 = {
  schemaVersion: 1; format: 'cliq-invocation-dispatch-closure-evidence-v1';
  runId: string; opId: string; attempt: number; dispatchId: string; unknownJournalSeq: number;
  closure: { kind: 'broker_process_domain_dead'; brokerProcessDeathEvidenceRef: string; brokerProcessDeathEvidenceDigest: string };
  observedAt: string; evidenceDigest: string;
};

export function decodeBrokerProcessDomainDeathDispatchClosure(value: unknown): BrokerProcessDomainDeathDispatchClosureV1 {
  exact(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'unknownJournalSeq',
    'closure', 'observedAt', 'evidenceDigest']);
  if (value.schemaVersion !== 1 || value.format !== 'cliq-invocation-dispatch-closure-evidence-v1')
    throw new TypeError('invalid broker process-domain death dispatch-closure format');
  for (const key of ['runId', 'opId', 'dispatchId']) identity(value[key]);
  integer(value.attempt, 0); integer(value.unknownJournalSeq, 1);
  exact(value.closure, ['kind', 'brokerProcessDeathEvidenceRef', 'brokerProcessDeathEvidenceDigest']);
  if (value.closure.kind !== 'broker_process_domain_dead') throw new TypeError('unimplemented broker process-domain death dispatch branch');
  reference(value.closure.brokerProcessDeathEvidenceRef); reference(value.closure.brokerProcessDeathEvidenceDigest);
  observation(value);
  return value as unknown as BrokerProcessDomainDeathDispatchClosureV1;
}

export function decodeBrokerProcessDomainDeath(value: unknown): BrokerProcessDomainDeathEvidenceV1 {
  exact(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq',
    'operationRequestRef', 'operationTargetDigest', 'operationGrantRef', 'claimingSupervisorInstanceId',
    'claimingStateOwnerEpoch', 'claimingProcessIdentityRef', 'claimingProcessIdentityDigest', 'inspectorIdentityRef',
    'inspectorIdentityDigest', 'inspectorStateOwnerEpoch', 'brokerFenceTokenDigest', 'authorityDomain',
    'processObservation', 'observedAt', 'evidenceDigest']);
  if (value.schemaVersion !== 1 || value.format !== 'cliq-broker-process-domain-death-evidence-v1' ||
      value.authorityDomain !== 'linux_installed_native_creator_process_v1' ||
      value.processObservation !== 'absent_or_start_token_mismatch') throw new TypeError('invalid broker process-domain death format or observation');
  for (const key of ['runId', 'opId', 'dispatchId', 'claimingSupervisorInstanceId']) identity(value[key]);
  integer(value.attempt, 0); integer(value.dispatchJournalSeq, 1);
  integer(value.claimingStateOwnerEpoch, 1); integer(value.inspectorStateOwnerEpoch, 1);
  if ((value.inspectorStateOwnerEpoch as number) <= (value.claimingStateOwnerEpoch as number))
    throw new TypeError('broker process-domain death requires a strictly newer inspector');
  for (const key of ['operationRequestRef', 'operationTargetDigest', 'operationGrantRef', 'claimingProcessIdentityRef',
    'claimingProcessIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'brokerFenceTokenDigest']) reference(value[key]);
  observation(value);
  return value as unknown as BrokerProcessDomainDeathEvidenceV1;
}

function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== keys.length ||
      keys.some(key => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return !descriptor?.enumerable || !Object.hasOwn(descriptor, 'value');
      })) throw new TypeError('broker process-domain death data has unknown, missing or non-data fields');
}
function identity(value: unknown): void {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || value.includes('\0'))
    throw new TypeError('invalid broker process-domain death identity');
}
function integer(value: unknown, minimum: number): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum)
    throw new TypeError('invalid broker process-domain death sequence or epoch');
}
function reference(value: unknown): void {
  if (typeof value !== 'string') throw new TypeError('invalid broker process-domain death reference');
  assertArtifactRef(value);
}
function observation(value: Record<string, unknown>): void {
  if (typeof value.observedAt !== 'string') throw new TypeError('invalid broker process-domain death observation time');
  parseCanonicalTime(value.observedAt); reference(value.evidenceDigest);
  if (value.evidenceDigest !== digestOmitting(value, 'evidenceDigest')) throw new TypeError('broker process-domain death digest does not rehash');
}
