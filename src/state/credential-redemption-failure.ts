import { readStopSourceData } from './stop-source.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeCredentialAuthorityRecord, decodeEndpointAuthorityRecord, decodeEndpointCredentialGrantBinding,
  decodeEndpointRegistration, type CredentialAuthorityRecordV1, type EndpointAuthorityRecordV1,
  type EndpointCredentialGrantBinding, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeModelOperationGrant } from '../kernel/model-grant.js';
import type { CredentialRedemptionFailureEvidenceV1 } from '../kernel/stop.js';
import type { InvocationJournalEntry, RecoveryClosureV1, RunAssemblyV1, RunFrontier } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ModelRequestV1 } from '../model/request.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { stopInvocationHistory } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { childAllocationBudgetFacts, subtractBudget, isZeroBudget } from './invariants.js';
import { readModelGrantClosure } from './model-grant.js';
import { readModelClaimCut } from './reducers/invocation.js';
import { readInvocationAttempt } from './repositories/journal.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import type { HeldCredentialAuthorityLock } from './store.js';

type Refusal = {
  schemaVersion: 1; format: 'cliq-credential-redemption-refusal-v1'; runId: string; opId: string; attempt: number;
  requestRef: string; credentialGrantRef: string; endpointRegistrationRef: string;
  credentialAuthorityRecord: CredentialAuthorityRecordV1; endpointAuthorityRecord: EndpointAuthorityRecordV1;
  observedAt: string; refusalDigest: string;
};

function decodeRefusal(value: unknown): Refusal {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !exactKeys(value, ['schemaVersion', 'format', 'runId',
    'opId', 'attempt', 'requestRef', 'credentialGrantRef', 'endpointRegistrationRef', 'credentialAuthorityRecord',
    'endpointAuthorityRecord', 'observedAt', 'refusalDigest'])) throw new TypeError('credential refusal has unknown or missing fields');
  const refusal = value as Refusal;
  if (refusal.schemaVersion !== 1 || refusal.format !== 'cliq-credential-redemption-refusal-v1' ||
      typeof refusal.runId !== 'string' || !refusal.runId || typeof refusal.opId !== 'string' || !refusal.opId ||
      !Number.isSafeInteger(refusal.attempt) || refusal.attempt < 0 ||
      digestOmitting(refusal, 'refusalDigest') !== refusal.refusalDigest) throw new TypeError('credential refusal identity or digest differs');
  for (const ref of [refusal.requestRef, refusal.credentialGrantRef, refusal.endpointRegistrationRef, refusal.refusalDigest]) assertArtifactRef(ref);
  parseCanonicalTime(refusal.observedAt);
  decodeCredentialAuthorityRecord(refusal.credentialAuthorityRecord); decodeEndpointAuthorityRecord(refusal.endpointAuthorityRecord);
  return refusal;
}

function classify(refusal: Refusal, binding: EndpointCredentialGrantBinding, endpoint: EndpointRegistrationV1) {
  const record = refusal.credentialAuthorityRecord, endpointRecord = refusal.endpointAuthorityRecord, now = refusal.observedAt;
  if (canonicalSha256(endpoint) !== refusal.endpointRegistrationRef || canonicalSha256(binding) !== refusal.credentialGrantRef ||
      binding.endpointRegistrationRef !== refusal.endpointRegistrationRef || binding.purpose !== 'model_endpoint' ||
      binding.ownerPrincipalId !== endpoint.ownerPrincipalId || binding.endpointIdentityDigest !== endpoint.endpointIdentityDigest ||
      binding.tlsPolicyDigest !== endpoint.tlsPolicyDigest || record.credentialGrantId !== binding.credentialGrantId ||
      record.ownerPrincipalId !== binding.ownerPrincipalId || record.purpose !== binding.purpose ||
      record.endpointRegistrationRef !== binding.endpointRegistrationRef || record.endpointIdentityDigest !== binding.endpointIdentityDigest ||
      record.tlsPolicyDigest !== binding.tlsPolicyDigest || record.credentialHandleIdentityDigest !== binding.credentialHandleIdentityDigest ||
      record.credentialServiceRevision !== binding.credentialServiceRevision || record.authorityRevision < binding.authorityRevision ||
      record.secretGeneration < binding.secretGeneration || canonicalSha256(endpointRecord.registration) !== refusal.endpointRegistrationRef ||
      endpointRecord.expectedRegistrationArtifactRef !== refusal.endpointRegistrationRef || endpointRecord.ownerPrincipalId !== binding.ownerPrincipalId ||
      record.createdAt > now || binding.createdAt > now || endpointRecord.createdAt > now || endpoint.createdAt > now ||
      record.createdAt < binding.createdAt || record.externalSubject.observedAt > record.createdAt ||
      record.authorityRevision - binding.authorityRevision !== record.secretGeneration - binding.secretGeneration + (record.state === 'revoked' ? 1 : 0) ||
      record.expiresAt !== undefined && record.expiresAt <= record.createdAt ||
      (record.state === 'revoked' && record.revokedAt > now) || (endpointRecord.state === 'revoked' && endpointRecord.revokedAt > now)) {
    throw new TypeError('credential refusal substitutes its frozen target, identity, revision or causal time');
  }
  if (endpointRecord.state === 'revoked') return { failureCode: 'endpoint_revoked' as const,
    endpointAuthorityRecordDigest: endpointRecord.recordDigest, endpointAuthorityRevision: endpointRecord.authorityRevision };
  if (record.state === 'revoked') return { failureCode: 'revoked' as const };
  if (record.expiresAt !== undefined && record.expiresAt <= now) return { failureCode: 'expired' as const };
  const { state: _state, platformItem: _item, recordDigest: _digest, ...body } = record;
  const current = { ...body, bindingDigest: canonicalSha256(body) };
  decodeEndpointCredentialGrantBinding(current);
  if (canonicalSha256(current) !== refusal.credentialGrantRef) {
    if (record.authorityRevision === binding.authorityRevision) throw new TypeError('credential refusal rewrites the frozen authority revision');
    return { failureCode: 'credential_binding_changed' as const };
  }
  return undefined;
}

/** Only the genuine original credential-lock owner can observe these records.
 * No supplied record, error message or boolean is accepted as live authority. */
export async function publishInstalledCredentialRedemptionRefusal(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, token: HeldCredentialAuthorityLock, prepared: InvocationJournalEntry) {
  token.assertHeld(); assertActiveStateOwner(driver, owner);
  const entries = readInvocationAttempt(driver, prepared.runId, prepared.opId, prepared.attempt);
  if (entries.length !== 1 || prepared.phase !== 'prepared' || prepared.opKind !== 'model' ||
      canonicalSha256(entries[0]) !== canonicalSha256(prepared)) throw new KernelStorageError('REVISION_CONFLICT', 'credential refusal no longer owns one unclaimed preparation');
  const cut = await readModelClaimCut(driver, artifacts, prepared);
  if (cut.assembly.provider.credentialGrantRefs.length !== 1 || cut.authority.target.format !== 'cliq-endpoint-registration-v1')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential refusal requires the exact installed bearer recipe');
  const credentialGrantRef = cut.assembly.provider.credentialGrantRefs[0]!;
  const binding = decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, credentialGrantRef));
  const { readCredentialAuthority, readEndpointAuthority } = await import('./store.js');
  const record = readCredentialAuthority(token, binding.credentialGrantId);
  const endpointRecord = readEndpointAuthority(token, cut.authority.target.endpointRegistrationId);
  const observedAt = sampleCanonicalNow(), fence = readTimeFence(driver);
  if (!record || !endpointRecord || !fence || fence.state !== 'healthy' || observedAt < fence.lastAcceptedAt)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential refusal lacks causal verified authority history');
  const refusal: Refusal = { schemaVersion: 1, format: 'cliq-credential-redemption-refusal-v1', runId: prepared.runId,
    opId: prepared.opId, attempt: prepared.attempt, requestRef: prepared.requestRef, credentialGrantRef,
    endpointRegistrationRef: cut.authority.targetRef, credentialAuthorityRecord: record, endpointAuthorityRecord: endpointRecord,
    observedAt, refusalDigest: '' };
  refusal.refusalDigest = digestOmitting(refusal, 'refusalDigest');
  const cause = classify(decodeRefusal(refusal), binding, cut.authority.target);
  if (!cause) throw new KernelStorageError('RECOVERY_REQUIRED', 'credential refusal cannot reproduce a verified authorization failure');
  const artifact = await artifacts.publishCanonical(refusal, 'cliq-invocation-error-v1');
  token.assertHeld(); assertActiveStateOwner(driver, owner);
  requireEqual(readInvocationAttempt(driver, prepared.runId, prepared.opId, prepared.attempt), entries, 'credential refusal original preparation');
  return artifact;
}

type WithoutWrapper<T> = T extends CredentialRedemptionFailureEvidenceV1 ? Omit<T, 'schemaVersion' | 'format' | 'runId' |
  'inspectorIdentityRef' | 'inspectorIdentityDigest' | 'observedAt' | 'evidenceDigest'> : never;
type FailureCause = WithoutWrapper<CredentialRedemptionFailureEvidenceV1>;

/** Original immutable error/authority closure only; never today's installation
 * or credential state. No claimed/unknown attempt can enter this branch. */
export async function readCredentialRedemptionFailureCause(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, observedAt: string, registeredCheckpointId?: string, registeredRunRevision?: number, registeredJournalSeq?: number): Promise<FailureCause | undefined> {
  const source = readStopSourceData(driver, cut, observedAt, registeredCheckpointId, registeredRunRevision, registeredJournalSeq);
  const children = childAllocationBudgetFacts(cut.run.id, cut.childAllocations);
  if (cut.run.waitingReason && registeredCheckpointId === undefined || !isZeroBudget(subtractBudget(cut.run.budgetReserved, children.reserved))) return undefined;
  const history = [...stopInvocationHistory(source.journal).values()];
  if (history.some(({ entry, hasClaim }) => !['model', 'tool', 'child_admission', 'child_merge', 'child_await', 'skill_resource'].includes(entry.opKind) ||
      entry.phase !== 'completed' && (entry.phase !== 'failed' || hasClaim))) return undefined;
  const latest = history.filter(({ entry }) => entry.opKind === 'model').at(-1);
  if (!latest || latest.entry.phase !== 'failed' || latest.hasClaim || !latest.entry.errorRef || !latest.entry.budgetSettlementRef) return undefined;
  const error = await readCanonicalArtifact<{ format?: unknown }>(artifacts, latest.entry.errorRef);
  if (error.format !== 'cliq-credential-redemption-refusal-v1') return undefined;
  const refusal = decodeRefusal(error);
  const entries = source.journal.filter(entry => entry.opId === latest.entry.opId && entry.attempt === latest.entry.attempt);
  const prepared = entries[0];
  if (entries.length !== 2 || prepared?.phase !== 'prepared' || prepared.opKind !== 'model' || !prepared.grantRef ||
      refusal.runId !== cut.run.id || refusal.opId !== prepared.opId || refusal.attempt !== prepared.attempt ||
      refusal.requestRef !== prepared.requestRef || refusal.observedAt < prepared.timestamp ||
      refusal.observedAt > latest.entry.timestamp || latest.entry.timestamp > observedAt)
    throw new TypeError('credential failure does not own its exact settled no-claim Journal cut');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, cut.runSpec.assemblyRef);
  if (assembly.mcpServers.length || assembly.provider.credentialGrantRefs.length !== 1 ||
      assembly.provider.credentialGrantRefs[0] !== refusal.credentialGrantRef || assembly.provider.endpoint.kind !== 'registered' ||
      assembly.provider.endpoint.endpointRegistrationRef !== refusal.endpointRegistrationRef)
    throw new TypeError('credential failure substitutes its admitted assembly');
  const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
  const grant = decodeModelOperationGrant(await readCanonicalArtifact(artifacts, prepared.grantRef));
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, grant.frontierRef);
  if (frontier.kind !== 'agent' || frontier.contextItemSeq !== source.checkpoint.runItemSeq ||
      source.items.length !== source.checkpoint.runItemSeq || cut.run.frontierRef !== undefined && cut.run.frontierRef !== grant.frontierRef)
    throw new TypeError('credential failure no longer owns the ready frontier');
  const authority = await readModelGrantClosure(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly, frontier,
    frontierRef: grant.frontierRef, request, requestRef: prepared.requestRef, grantRef: prepared.grantRef });
  if (authority.target.format !== 'cliq-endpoint-registration-v1' || prepared.target !== authority.targetRef)
    throw new TypeError('credential failure has no frozen registered target');
  const binding = decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, refusal.credentialGrantRef));
  const endpoint = decodeEndpointRegistration(await readCanonicalArtifact(artifacts, refusal.endpointRegistrationRef));
  const cause = classify(refusal, binding, endpoint);
  if (!cause) throw new TypeError('credential failure has no exact authorization refusal');
  return immutableSnapshot({ frontierRef: grant.frontierRef, frontierDigest: grant.frontierRef, failingOpId: prepared.opId,
    failureKind: 'credential_redemption_failed', credentialGrantRef: refusal.credentialGrantRef, credentialGrantDigest: binding.bindingDigest,
    endpointRegistrationRef: refusal.endpointRegistrationRef, endpointRegistrationDigest: endpoint.registrationDigest,
    credentialAuthorityRecordDigest: refusal.credentialAuthorityRecord.recordDigest,
    authorityRevision: refusal.credentialAuthorityRecord.authorityRevision,
    credentialServiceRevision: refusal.credentialAuthorityRecord.credentialServiceRevision, ...cause });
}
