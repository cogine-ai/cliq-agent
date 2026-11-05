import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeEndpointCredentialGrantBinding, decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeModelOperationGrant, planModelOperationGrant, type ModelGrantFrame, type ModelOperationGrantV1 } from '../kernel/model-grant.js';
import type { InvocationJournalEntry, Run, RunAssemblyV1, RunSpec } from '../kernel/types.js';
import { decodeLocalZeroCostProvenanceData, type LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readRetainedLocalModelRegistration } from './local-model-history.js';

export type ModelTargetClosure = Readonly<{
  principalId: string; targetRef: string; targetDigest: string;
  target: EndpointRegistrationV1 | LocalZeroCostProvenanceV1;
}>;


/** Static retained data only. Installed catalog/price qualification and fresh
 * credential or managed-local boundary authority remain separate release gates. */
export async function readModelTarget(driver: SqliteConnection | SqliteDriver, artifacts: ArtifactCatalog,
  input: { run: Run; spec: RunSpec; assembly: RunAssemblyV1 }): Promise<ModelTargetClosure> {
  const principalId = driver.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(input.run.id)?.principal_id;
  const sessionPrincipal = driver.prepare('SELECT principal_id FROM sessions WHERE id = ?').get<{ principal_id: string }>(input.run.sessionId)?.principal_id;
  if (!principalId || principalId !== sessionPrincipal) throw new KernelStorageError('RECOVERY_REQUIRED', 'model target has no exact admitted principal');
  return readModelTargetData(artifacts, { ...input, principalId });
}

/** Historical readers supply the principal from the immutable Session/workspace
 * closure. This data decoder does not authenticate a caller or authorize I/O. */
export async function readModelTargetData(artifacts: ArtifactCatalog,
  input: { principalId: string; run: Pick<Run, 'createdAt' | 'deadlineAt'>; spec: RunSpec; assembly: RunAssemblyV1 }): Promise<ModelTargetClosure> {
  const { principalId, run, spec, assembly } = input;
  if (!principalId || spec.operation !== 'agent' || canonicalSha256(assembly) !== spec.assemblyRef ||
      assembly.assemblyDigest !== digestOmitting(assembly, 'assemblyDigest')) throw new KernelStorageError('RECOVERY_REQUIRED', 'model target has no exact admitted assembly');
  const endpoint = assembly.provider.endpoint;
  if (endpoint.kind === 'local_zero_cost') {
    const target = decodeLocalZeroCostProvenanceData(await readCanonicalArtifact(artifacts, endpoint.localProvenanceRef));
    if (target.ownerPrincipalId !== principalId || target.provider !== assembly.provider.name || target.model !== assembly.provider.model ||
        target.endpointIdentityDigest !== endpoint.identityDigest || target.capabilityEvidenceRef !== assembly.provider.negotiation.capabilityEvidenceRef ||
        target.capabilityDigest !== assembly.provider.negotiation.capabilityDigest || target.createdAt > run.createdAt || target.validThrough < run.deadlineAt ||
        assembly.provider.credentialGrantRefs.length || assembly.provider.pricing.kind !== 'zero_cost' ||
        assembly.provider.pricing.provenanceRef !== endpoint.localProvenanceRef) throw new TypeError('local model target differs from its frozen assembly');
    await readRetainedLocalModelRegistration(artifacts, { provenance: target, principalId, assembly });
    return immutableSnapshot({ principalId, targetRef: endpoint.localProvenanceRef, targetDigest: target.provenanceDigest, target });
  }
  const target = decodeEndpointRegistration(await readCanonicalArtifact(artifacts, endpoint.endpointRegistrationRef));
  if (target.ownerPrincipalId !== principalId || !target.purposes.includes('model_endpoint') ||
      target.registrationKind !== endpoint.registrationKind || target.endpointIdentityDigest !== endpoint.endpointIdentityDigest ||
      target.tlsPolicyDigest !== endpoint.tlsPolicyDigest || target.createdAt > run.createdAt ||
      target.tls.trustStoreRuntimeBundleRef !== assembly.runtime.runtimeBundleRef ||
      target.tls.trustStoreRuntimeBundleManifestDigest !== assembly.runtime.runtimeBundleManifestDigest) {
    throw new TypeError('registered model target differs from its frozen assembly');
  }
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
  const trust = bundle.entries.filter(entry => entry.entryId === 'default_https_trust_store');
  if (bundle.manifestDigest !== assembly.runtime.runtimeBundleManifestDigest || trust.length !== 1 ||
      trust[0]!.role !== 'trust_store' || trust[0]!.executable || trust[0]!.digest !== target.tls.trustStoreRef ||
      (await artifacts.readBytes(target.tls.trustStoreRef)).length !== trust[0]!.byteCount) throw new TypeError('model target trust store differs from its retained RuntimeBundle');
  if (!assembly.provider.credentialGrantRefs.length) throw new TypeError('registered model target requires frozen credential bindings');
  for (const ref of assembly.provider.credentialGrantRefs) {
    const binding = decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, ref));
    if (binding.ownerPrincipalId !== principalId || binding.purpose !== 'model_endpoint' ||
        binding.endpointRegistrationRef !== endpoint.endpointRegistrationRef || binding.endpointIdentityDigest !== endpoint.endpointIdentityDigest ||
        binding.tlsPolicyDigest !== endpoint.tlsPolicyDigest || binding.createdAt > run.createdAt) throw new TypeError('model credential binding differs from its registered target');
  }
  return immutableSnapshot({ principalId, targetRef: endpoint.endpointRegistrationRef, targetDigest: target.registrationDigest, target });
}

export async function readModelGrantClosure(driver: SqliteConnection | SqliteDriver, artifacts: ArtifactCatalog,
  input: Omit<ModelGrantFrame, 'principalId' | 'targetRef' | 'targetDigest'> & { grantRef: string }) {
  const target = await readModelTarget(driver, artifacts, input);
  return reproduceModelGrantData(artifacts, { ...input, principalId: target.principalId }, target);
}

export async function readModelGrantData(artifacts: ArtifactCatalog,
  input: Omit<ModelGrantFrame, 'targetRef' | 'targetDigest'> & { grantRef: string }) {
  const target = await readModelTargetData(artifacts, input);
  return reproduceModelGrantData(artifacts, input, target);
}
async function reproduceModelGrantData(artifacts: ArtifactCatalog,
  input: Omit<ModelGrantFrame, 'targetRef' | 'targetDigest'> & { grantRef: string }, target: ModelTargetClosure) {
  const grant = decodeModelOperationGrant(await readCanonicalArtifact(artifacts, input.grantRef));
  const expected = planModelOperationGrant({ ...input, ...target }, grant.issuedAt, grant.expiresAt);
  requireEqual(grant, expected, 'model operation grant');
  return immutableSnapshot({ ...target, grant, grantRef: input.grantRef });
}

/** Synchronous current-cut validation reused immediately before claim/release.
 * It grants no I/O and performs no retry, clock advancement or credential lookup. */
export function assertModelGrantDispatch(grant: ModelOperationGrantV1, input: {
  run: Run; prepared: InvocationJournalEntry; history: readonly InvocationJournalEntry[]; now: string;
  includingCurrentClaim?: boolean;
}): void {
  const { run, prepared, history, now } = input;
  const nowMs = parseCanonicalTime(now);
  if (run.nextStep !== 'agent' || run.frontierRef !== grant.frontierRef || prepared.phase !== 'prepared' || prepared.opKind !== 'model' ||
      prepared.runId !== run.id || prepared.opId !== grant.opId || prepared.requestRef !== grant.requestRef ||
      prepared.target !== grant.targetRef || prepared.grantRef !== canonicalSha256(grant) || prepared.timestamp < grant.issuedAt ||
      nowMs < parseCanonicalTime(prepared.timestamp) ||
      nowMs < parseCanonicalTime(grant.issuedAt) || nowMs >= parseCanonicalTime(grant.expiresAt) ||
      nowMs >= parseCanonicalTime(run.deadlineAt)) throw new KernelStorageError('LEASE_FENCED', 'model grant is stale, expired or belongs to another current frame');
  const claims = history.filter(entry => entry.phase === 'dispatch_claimed');
  const uses = claims.filter(entry => entry.grantRef === prepared.grantRef).length;
  const maximum = grant.maxDispatchedAttempts;
  if (input.includingCurrentClaim) {
    const current = claims.filter(entry => entry.attempt === prepared.attempt);
    if (current.length !== 1 || current[0]!.requestRef !== prepared.requestRef || current[0]!.target !== prepared.target ||
        current[0]!.grantRef !== prepared.grantRef || current[0]!.leaseEpoch !== prepared.leaseEpoch ||
        parseCanonicalTime(current[0]!.timestamp) > nowMs) throw new KernelStorageError('LEASE_FENCED', 'model release has no exact permanent current claim');
  }
  if (claims.some(entry => entry.runId !== run.id || entry.opId !== grant.opId || entry.opKind !== 'model') ||
      (input.includingCurrentClaim ? uses > maximum || claims.length > maximum : uses >= maximum || claims.length >= maximum)) {
    throw new KernelStorageError('LEASE_FENCED', 'model grant or operation dispatch capacity is exhausted');
  }
}
