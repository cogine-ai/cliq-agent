import { randomBytes } from 'node:crypto';
import { DependencyScriptAuthorizationRequired, createSourceInspectionErrorResponse as errorResponse, assertSourceInspectionErrorResponse as assertErrorResponse,
  type SourceInspectionErrorResponse as ErrorResponse } from './source-inspection-error.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SourceInspectionAttemptV1, SourceInspectionRetirementEvidenceV1 } from '../kernel/execution.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeDeliveryCaptureTopology } from '../kernel/publication.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { publishGitSourceProjection, publishNonGitSourceProjection, type PublishedNonGitSourceProjection } from '../workspace/source-projection.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries, decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { withHeldInstalledRuntime, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { loadNativeStateOwner, readSourceInspectionStagingRetirement, retireSourceInspectionStaging,
  openRetainedSourceGitInput, openRegisteredAbsentSourceGitInput, readSourceInspectionStagingPresence,
  type HeldSourceInspectionStaging, type HeldWorkspaceRoot, type SourceInspectionStagingRetirement } from './native-owner.js';
import { insertControlRequest, readAdmissionReplay, readControlRequest, readSession, readSessionPrincipalId } from './rows.js';
import { readNextUnretiredSourceInspection, readSourceInspectionAttempt, readSourceInspectionOriginalRequest, readSourceInspectionRequest,
  reserveSourceInspectionAttempt } from './source-inspection.js';
import { assertWorkspaceSourceTrust, holdWorkspaceSourceTrust, type HeldWorkspaceSourceTrust } from './source-trust.js';
import { effectiveSourceExcludes } from '../kernel/dependency-source.js';
import { createVerifiedSourceInspectionTarget, normalizeSourceInspectionRequest, readRetainedSourceInspectionTarget,
  readVerifiedSourceInspectionTarget, recheckVerifiedSourceInspectionTarget, sourceInspectionIntentDigest, resolveDeliverySourceCapture,
  type NormalizedSourceRequest, type SourceCaptureSelection, type SourceInspectionBootstrap, type VerifiedSourceInspectionTarget } from './source-target.js';
import { readVerifiedDeliverySource, type VerifiedDeliverySource } from './delivery-source-authority.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { createInstalledSourceGitCapture, readInstalledSourceGitCapture, type InstalledSourceGitCapture } from './source-git-owner.js';
import { captureSourceGitRules } from './source-git-rules.js';
import { readSourceGitRetirementClosure } from './source-git-retirement.js';
import { retireInstalledRetainedSourceGit, readRecoveredSourceGitRetirement, readSourceGitNativeLifecycle,
  retireInstalledRegisteredAbsentSourceGit, readRegisteredAbsentSourceGitRetirement } from '../sandbox/source-git-native.js';
import { readSourceGitInputIntent } from './source-git-input.js';
import { installSourceInspectionRetirementHandoff, readSourceInspectionRetirementHandoff } from './source-inspection-handoff.js';

export type SourceInspectionOwnerBootstrap = SourceInspectionBootstrap & Readonly<{ controlledHome: string }>;
type Capturing = Extract<SourceInspectionAttemptV1, { phase: 'capturing' }>;
type Retired = Extract<SourceInspectionAttemptV1, { phase: 'retired' }>;
type Unretired = Exclude<SourceInspectionAttemptV1, { phase: 'retired' }>;


export function assertSourceInspectionRequestId(connection: SqliteConnection | SqliteDriver, principalId: string,
  request: { requestId: string; requestDigest: string; method?: 'run.submit' | 'run.apply' }, expectedInspectionId?: string): void {
  const method = request.method ?? 'run.submit';
  const control = readControlRequest(connection, principalId, method, request.requestId);
  const inspection = readSourceInspectionRequest(connection, principalId, request.requestId, method);
  if ((control && control.requestDigest !== request.requestDigest) || (inspection &&
      (inspection.originalRequestDigest !== request.requestDigest ||
       (expectedInspectionId !== undefined && inspection.attempt.inspectionId !== expectedInspectionId))))
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'source request id belongs to different canonical bytes');
}
function closeResources(resources: readonly { close(): void }[], operationError?: unknown): void {
  const failures: unknown[] = [];
  for (const resource of [...resources].reverse()) {
    try { resource.close(); } catch (error) { failures.push(error); }
  }
  if (failures.length) throw new ResourceRetirementError('source inspection resources did not retire',
    new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
  // A failed nested CAS/native join cannot be relabeled as ordinary capture
  // failure merely because these outer descriptors subsequently closed.
  if (operationError instanceof ResourceRetirementError) throw operationError;
}


/** Retained inert response only. The owning capture/replay path establishes
 * retirement and the control association; this friend mints no Run or proof. */
export async function readSourceInspectionErrorResponse(artifacts: ArtifactCatalog, row: SourceInspectionAttemptV1): Promise<ErrorResponse> {
  if (row.phase !== 'retired')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection has no retained refusal response');
  const ref = row.outcome.kind === 'captured' ? row.admissionErrorResponseRef : row.outcome.errorResponseRef;
  if (!ref) throw new KernelStorageError('RECOVERY_REQUIRED', 'captured source has no original admission refusal');
  const response = await readCanonicalArtifact(artifacts, ref);
  assertErrorResponse(response, row.inspectionId, row.method);
  if (row.outcome.kind === 'captured' ? row.method !== 'run.submit' || response.error.code !== 'AUTHORIZATION_REQUIRED' :
      (row.outcome.kind === 'cancelled') !== (response.error.code === 'CANCEL_REQUESTED'))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source outcome differs from its retained refusal');
  return immutableSnapshot(response);
}

/** Original capture provenance, not a writer or an observation made today.
 * The caller also validates the owning target and genuine retirement. */
export async function readDeliveryCaptureTopology(artifacts: ArtifactCatalog,
  row: SourceInspectionAttemptV1, target: import('../kernel/execution.js').SourceInspectionTarget) {
  if (row.phase !== 'retired' || row.method !== 'run.apply' || row.outcome.kind !== 'captured')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery requires its original captured topology');
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(artifacts, row.outcome.captureTopologyRef));
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, target.workspaceIdentityRef));
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, row.outcome.sourceManifestRef));
  const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef));
  const entriesByPath = new Map(entries.entries.map(entry => [entry.path, entry]));
  const expected = new Set<string>();
  for (const entry of entries.entries) {
    const parts = entry.path.split('/'); if (entry.kind !== 'directory') parts.pop();
    for (let index = 1; index <= parts.length; index++) expected.add(parts.slice(0, index).join('/'));
  }
  if (workspace.kind !== 'live' || topology.inspectionId !== row.inspectionId || target.method !== 'run.apply' ||
      topology.topologyDigest !== row.outcome.captureTopologyDigest || topology.capturedWorkspaceRef !== row.outcome.sourceManifestRef ||
      topology.workspaceIdentityRef !== target.workspaceIdentityRef || topology.workspaceIdentityDigest !== row.workspaceIdentityDigest ||
      workspace.identityDigest !== row.workspaceIdentityDigest || source.workspaceIdentityDigest !== row.workspaceIdentityDigest ||
      source.manifestDigest !== row.outcome.sourceManifestDigest || source.treeDigest !== entries.treeDigest ||
      topology.rootIdentity.deviceId !== workspace.rootIdentity.deviceId || topology.rootIdentity.fileId !== workspace.rootIdentity.fileId ||
      topology.rootIdentity.ownerUid !== workspace.rootIdentity.ownerUid || topology.capturedAt < row.createdAt || topology.capturedAt > row.retiredAt ||
      canonicalSha256(topology.directories.map(entry => entry.path)) !== canonicalSha256([...expected].sort((left, right) =>
        Buffer.compare(Buffer.from(left), Buffer.from(right)))) ||
      canonicalSha256(topology.fileModes.map(entry => entry.path)) !== canonicalSha256(entries.entries.filter(entry => entry.kind === 'file').map(entry => entry.path)) ||
      topology.fileModes.some(observed => {
        const entry = entriesByPath.get(observed.path);
        return entry?.kind !== 'file' || entry.mode !== ((observed.mode & 0o111) ? 0o755 : 0o644);
      }))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery topology differs from its exact original capture closure');
  return topology;
}

/** Replay validates retained evidence; it never turns old bytes into a new
 * native observation or authorizes recapture. Only the implemented no-process
 * prefix is accepted until the corresponding fixed-recipe producers exist. */
export async function readSourceInspectionRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, row: Retired,
  runtime: { runtimeBundleRef: string; runtimeBundleManifestDigest: string }): Promise<void> {
  try {
    const evidence = await readCanonicalArtifact<SourceInspectionRetirementEvidenceV1>(artifacts, row.retirementEvidenceRef);
    if (!exactKeys(evidence, ['schemaVersion', 'format', 'inspectionId', 'targetRef', 'stagingNonceDigest',
      'inspectorIdentityRef', 'inspectorIdentityDigest', 'captureOwnerClosure', 'stagingObservation', 'processClosure', 'observedAt', 'evidenceDigest']) ||
        evidence.schemaVersion !== 1 || evidence.format !== 'cliq-source-inspection-retirement-v1' ||
        evidence.inspectionId !== row.inspectionId || evidence.targetRef !== row.targetRef || evidence.stagingNonceDigest !== row.stagingNonceDigest ||
        typeof evidence.inspectorIdentityRef !== 'string' || !/^[0-9a-f]{64}$/.test(evidence.inspectorIdentityRef) ||
        typeof evidence.inspectorIdentityDigest !== 'string' || !/^[0-9a-f]{64}$/.test(evidence.inspectorIdentityDigest) ||
        evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest') ||
        !['exact_reserved_root_absent', 'registered_reserved_root_absent'].includes(evidence.stagingObservation) ||
        typeof evidence.observedAt !== 'string')
      throw new TypeError('source retirement does not bind its exact original capture');
    const observedAt = parseCanonicalTime(evidence.observedAt), retiredAt = parseCanonicalTime(row.retiredAt);
    const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, evidence.inspectorIdentityRef);
    if (!Number.isSafeInteger(inspector.stateOwnerEpoch) || inspector.stateOwnerEpoch < 1)
      throw new TypeError('source retirement inspector has no canonical StateOwner epoch');
    const inspectingOwner = readStateOwner(driver, inspector.stateOwnerEpoch);
    if (!inspectingOwner ||
        observedAt < parseCanonicalTime(row.createdAt) || observedAt < parseCanonicalTime(inspectingOwner.acquiredAt) ||
        retiredAt < observedAt || retiredAt - observedAt > 5000 ||
        (inspectingOwner.state === 'terminal' && retiredAt > parseCanonicalTime(inspectingOwner.releasedAt)))
      throw new TypeError('source retirement has no matching historical owner and fresh retirement cut');
    if (evidence.captureOwnerClosure?.kind === 'local_resources_joined') {
      if (!exactKeys(evidence.captureOwnerClosure, ['kind', 'stateOwnerEpoch', 'supervisorInstanceId']) ||
          evidence.captureOwnerClosure.stateOwnerEpoch !== row.stateOwnerEpoch ||
          evidence.captureOwnerClosure.supervisorInstanceId !== row.supervisorInstanceId ||
          inspectingOwner.ownerEpoch !== row.stateOwnerEpoch || inspectingOwner.supervisorInstanceId !== row.supervisorInstanceId)
        throw new TypeError('local source retirement substitutes its owning task');
    } else if (evidence.captureOwnerClosure?.kind === 'owning_process_dead') {
      if (!exactKeys(evidence.captureOwnerClosure, ['kind', 'stateOwnerAcquisitionEvidenceRef']) ||
          typeof evidence.captureOwnerClosure.stateOwnerAcquisitionEvidenceRef !== 'string' ||
          row.outcome.kind === 'captured') throw new TypeError('successor source cleanup cannot assert capture success');
      const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: row.supervisorInstanceId, ownedAt: row.createdAt });
      if (death.priorOwner.ownerEpoch !== row.stateOwnerEpoch ||
          evidence.captureOwnerClosure.stateOwnerAcquisitionEvidenceRef !== death.acquisitionEvidenceRef ||
          inspectingOwner.ownerEpoch < death.successorOwner.ownerEpoch || evidence.observedAt < death.successorOwner.acquiredAt)
        throw new TypeError('source retirement substitutes its exact predecessor death acquisition');
    } else throw new TypeError('source retirement has no closed capture-owner proof');
    await readSupervisorInspector(artifacts, inspectingOwner, { runtime }, evidence);
    if (row.retirementHandoffRef) await readSourceInspectionRetirementHandoff(driver, artifacts, row, runtime);
    await readSourceGitRetirementClosure(driver, artifacts, row, evidence, runtime);
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection retained retirement is invalid', { cause });
  }
}

/** Retained-only friend shared with installed admission. It never opens live
 * source or starts a capture when the original attempt is absent; the same
 * complete provenance, retirement and request-association checks apply. */
export async function replaySubmittedSource(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: SourceInspectionOwnerBootstrap, request: NormalizedSourceRequest,
  identity: AuthenticatedControlIdentity, signal?: AbortSignal): Promise<SourceInspectionAttemptV1 | undefined> {
  signal?.throwIfAborted();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const key = { principalId: identity.principalId, method: request.method, admissionKey: request.admissionKey,
    admissionIntentDigest: sourceInspectionIntentDigest(identity.principalId, request) };
  assertSourceInspectionRequestId(driver, identity.principalId, request);
  const retained = readSourceInspectionAttempt(driver, key);
  if (!retained) {
    const control = readControlRequest(driver, identity.principalId, request.method, request.requestId);
    const admitted = readAdmissionReplay(driver, 'runs', identity.principalId, request.method, request.admissionKey);
    if (admitted && admitted.admissionIntentDigest !== key.admissionIntentDigest)
      throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'source key belongs to a different admitted intent');
    if (admitted || control) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'source result must replay through Run admission');
    return;
  }
  const originalIndex = readSourceInspectionOriginalRequest(driver, retained.inspectionId);
  const { target, original: sourceRequest } = await readRetainedSourceInspectionTarget(reads, retained, originalIndex, bootstrap, { driver, owner, signal });
  if (retained.phase !== 'retired') throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection still owns unretired capture resources');
  await readSourceInspectionRetirement(driver, reads, retained, target);
  const metadata: PublishedArtifact[] = [];
  if (retained.outcome.kind === 'captured') {
    const source = decodeSourceManifest(await readCanonicalArtifact(reads, retained.outcome.sourceManifestRef));
    if (source.role !== 'base' || source.manifestDigest !== retained.outcome.sourceManifestDigest ||
        source.workspaceIdentityDigest !== retained.workspaceIdentityDigest)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source outcome differs from its exact capture');
    if (sourceRequest.method === 'run.submit') {
      const projection = decodeSourceProjection(await readCanonicalArtifact(reads, source.sourceProjectionRef));
      if (canonicalSha256(projection.explicitExcludes) !== canonicalSha256(effectiveSourceExcludes(sourceRequest)))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source excludes differ from their original fixed dependency intent');
    }
    if (retained.method === 'run.apply') await readDeliveryCaptureTopology(reads, retained, target);
  }
  if (retained.outcome.kind !== 'captured' || retained.admissionErrorResponseRef !== undefined) {
    const errorResponseRef = retained.outcome.kind === 'captured' ? retained.admissionErrorResponseRef! : retained.outcome.errorResponseRef;
    await readSourceInspectionErrorResponse(reads, retained);
    const channel = await validateControlChannelClosure(reads, owner, identity); metadata.push(...channel.metadata);
    let clockRejected = false;
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); assertSourceInspectionRequestId(connection, identity.principalId, request, retained.inspectionId);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.rowDigest !== retained.rowDigest) throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source replay changed');
      const prior = readControlRequest(connection, identity.principalId, request.method, request.requestId);
      if (prior && prior.responseRef !== errorResponseRef) throw new KernelStorageError('RECOVERY_REQUIRED', 'source request has a different first response');
      if (prior) return;
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
      const now = readTimeFence(connection)!.lastAcceptedAt;
      for (const entry of metadata) insertArtifactMetadata(connection, entry, now);
      insertControlRequest(connection, { principalId: identity.principalId, method: request.method, requestId: request.requestId,
        requestDigest: request.requestDigest, channelIdentityRef: identity.channelIdentityRef,
        channelIdentityDigest: identity.channelIdentityDigest, responseRef: errorResponseRef, committedAt: now });
    });
    if (clockRejected) throw new KernelStorageError('RECOVERY_REQUIRED', 'source replay requires canonical time');
  }
  await validateControlChannelClosure(reads, owner, identity); assertActiveStateOwner(driver, owner);
  return retained;
}

async function publishSourceRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  row: Unretired, physical: SourceInspectionStagingRetirement,
  captureOwnerClosure: SourceInspectionRetirementEvidenceV1['captureOwnerClosure'],
  processClosure: SourceInspectionRetirementEvidenceV1['processClosure'] = { kind: 'not_planned' }) {
  const inspectingOwner = assertActiveStateOwner(driver, owner), observedAt = sampleCanonicalNow();
  const receipt = readSourceInspectionStagingRetirement(owner.filesystem, physical);
  if (receipt.inspectionId !== row.inspectionId || receipt.stagingNonceDigest !== row.stagingNonceDigest ||
      canonicalSha256(receipt.stagingIdentity) !== canonicalSha256(row.stagingIdentity))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source cleanup does not bind the reserved staging inode');
  const inspector: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: inspectingOwner.supervisorInstanceId, stateOwnerEpoch: inspectingOwner.ownerEpoch,
    runtimeBundleRef: inspectingOwner.runtimeBundleRef, runtimeBundleManifestDigest: inspectingOwner.runtimeBundleManifestDigest,
    supervisorEntryId: inspectingOwner.supervisorEntryId, supervisorEntryVersion: inspectingOwner.supervisorEntryVersion,
    supervisorExecutableDigest: inspectingOwner.supervisorExecutableDigest, processIdentityRef: inspectingOwner.processIdentityRef,
    processIdentityDigest: inspectingOwner.processIdentityDigest, stateLockIdentityRef: inspectingOwner.stateLockIdentityRef,
    stateLockIdentityDigest: inspectingOwner.stateLockIdentityDigest, instanceNonceDigest: inspectingOwner.instanceNonceDigest,
    activatedAt: inspectingOwner.acquiredAt, identityDigest: '' };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  const inspectorRef = canonicalSha256(inspector);
  const evidence: SourceInspectionRetirementEvidenceV1 = { schemaVersion: 1, format: 'cliq-source-inspection-retirement-v1',
    inspectionId: row.inspectionId, targetRef: row.targetRef, stagingNonceDigest: row.stagingNonceDigest,
    inspectorIdentityRef: inspectorRef, inspectorIdentityDigest: inspector.identityDigest,
    captureOwnerClosure, stagingObservation: receipt.stagingObservation, processClosure, observedAt, evidenceDigest: '' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
  const [inspectorArtifact, evidenceArtifact] = await artifacts.publishCanonicalPair([
    { value: inspector, schemaKind: inspector.format }, { value: evidence, schemaKind: evidence.format }
  ]);
  return { inspectorArtifact, evidenceArtifact, observedAt };
}

/** Startup may retire a dead owner's incomplete capture, never resume it.
 * No client, source path, read capability or reusable process token exists in
 * this branch. Prepared/active recipes await their actual containment closer. */
export async function retireAbandonedSourceInspections(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, bootstrap: SourceInspectionBootstrap | undefined,
  installation?: { runtime: HeldInstalledRuntime; anchor: HeldInstalledAnchor }): Promise<void> {
  let afterInspectionId = '';
  for (;;) {
    let row = readNextUnretiredSourceInspection(driver, afterInspectionId);
    if (!row) return;
    if (!bootstrap) throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires its trusted signed runtime');
    if (row.phase === 'retired' || row.stateOwnerEpoch >= owner.ownerEpoch || row.supervisorInstanceId === owner.supervisorInstanceId)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires its exact dead predecessor');
    const active = assertActiveStateOwner(driver, owner);
    const handoff = row.retirementHandoffRef && await readSourceInspectionRetirementHandoff(driver, artifacts, row, active);
    const original = handoff ? handoff.original : row;
    const { target } = await readRetainedSourceInspectionTarget(artifacts, original,
      readSourceInspectionOriginalRequest(driver, row.inspectionId), bootstrap, { driver, owner });
    if (active.runtimeBundleRef !== target.runtimeBundleRef || active.runtimeBundleManifestDigest !== target.runtimeBundleManifestDigest)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery cannot substitute its frozen signed runtime');
    let death: Awaited<ReturnType<typeof readStateOwnerDeath>>;
    try {
      death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: row.supervisorInstanceId, ownedAt: row.createdAt });
      if (death.priorOwner.ownerEpoch !== row.stateOwnerEpoch || death.successorOwner.ownerEpoch > owner.ownerEpoch ||
          original.updatedAt > death.priorOwner.releasedAt)
        throw new TypeError('source recovery substitutes its original owning lifetime');
    } catch (cause) {
      if (cause instanceof ResourceRetirementError) throw cause;
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery has no exact positive owner-death proof', { cause });
    }
    assertActiveStateOwner(driver, owner);
    const staging = owner.filesystem.openSourceInspectionStaging(row.inspectionId, row.stagingNonceDigest, row.stagingIdentity);
    let processClosure: SourceInspectionRetirementEvidenceV1['processClosure'] = { kind: 'not_planned' };
    let lifecycleBytes: Buffer | undefined, lifecycleArtifact: PublishedArtifact | undefined;
    if (handoff && handoff.handoff.processClosure.kind !== 'source_native_retired') {
      // Exact original program-owned no-input/no-native-attempt closure is
      // already durable. The successor does no capture or reconstruction.
      processClosure = handoff.handoff.processClosure;
    } else if (row.inputRef) {
      if (target.schemaVersion !== 2 || !installation) throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires its genuine installed cleanup-only native owner');
      const input = await readSourceGitInputIntent(artifacts, row.inputRef);
      if (input.inspectionId !== row.inspectionId || input.inputDigest !== row.inputDigest ||
          input.targetRef !== row.targetRef || input.targetDigest !== row.targetDigest)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery input differs from its first original capture transaction');
      const presence = readSourceInspectionStagingPresence(owner.filesystem, staging);
      if (presence === 'absent') {
        const prior = handoff ? handoff.handoff.processClosure : undefined;
        if (!handoff || !prior || prior.kind !== 'source_native_retired' || !handoff.handoff.nativeLifecycleRef)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'absent source staging has no registered complete original native handoff');
        const snapshot = await artifacts.readBoundedBytes(handoff.handoff.nativeLifecycleRef, 1_048_576);
        if (sha256Bytes(snapshot) !== handoff.handoff.nativeLifecycleRef)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'registered source lifecycle bytes differ');
        const absent = openRegisteredAbsentSourceGitInput(owner.filesystem, staging,
          { targetRef: row.targetRef, inputIntentRef: row.inputRef }, snapshot);
        let failure: unknown;
        try {
          const receipt = await retireInstalledRegisteredAbsentSourceGit(installation.runtime, installation.anchor, absent);
          const observation = readRegisteredAbsentSourceGitRetirement(receipt, absent);
          lifecycleBytes = readSourceGitNativeLifecycle(receipt, absent);
          if (sha256Bytes(lifecycleBytes) !== handoff.handoff.nativeLifecycleRef || !lifecycleBytes.equals(snapshot))
            throw new KernelStorageError('RECOVERY_REQUIRED', 'current source checker substituted its exact registered original lifecycle');
          processClosure = { kind: 'source_native_retired', inputRef: row.inputRef, inputDigest: row.inputDigest!,
            nativeBirthIdentity: prior.nativeBirthIdentity, observation };
        } catch (error) { failure = error; }
        try { absent.close(); } catch (error) { throw new ResourceRetirementError('registered absent source reader did not retire',
          failure === undefined ? error : new AggregateError([failure, error])); }
        if (failure !== undefined) throw failure;
      } else {
        // This distinct native tag contains no live workspace/payload root and
        // cannot reserve/capture/continue. Every constructor rechecks the exact
        // observed locator; drift never falls through to the other branch.
        const retained = openRetainedSourceGitInput(owner.filesystem, staging, { targetRef: row.targetRef, inputIntentRef: row.inputRef });
        let failure: unknown;
        try {
          const prior = handoff && handoff.handoff.processClosure;
          if (prior && (prior.kind !== 'source_native_retired' ||
              canonicalSha256(prior.nativeBirthIdentity) !== canonicalSha256(retained.identity.birthIdentity)))
            throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery native birth was replaced after handoff');
          const receipt = await retireInstalledRetainedSourceGit(installation.runtime, installation.anchor, retained);
          const observation = readRecoveredSourceGitRetirement(receipt, retained);
          lifecycleBytes = readSourceGitNativeLifecycle(receipt, retained);
          if (handoff && sha256Bytes(lifecycleBytes) !== handoff.handoff.nativeLifecycleRef)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'source cleanup differs from its registered original full lifecycle');
          processClosure = { kind: 'source_native_retired', inputRef: row.inputRef, inputDigest: row.inputDigest!,
            nativeBirthIdentity: retained.identity.birthIdentity, observation };
        } catch (error) { failure = error; }
        try { retained.close(); } catch (error) { throw new ResourceRetirementError('source recovery birth reader did not retire',
          failure === undefined ? error : new AggregateError([failure, error])); }
        if (failure !== undefined) throw failure;
      }
    } else if (row.phase !== 'capturing') throw new KernelStorageError('RECOVERY_REQUIRED', 'planned source recovery lacks its original fixed input intent');
    const response = await artifacts.publishCanonical(errorResponse(new Error('source capture owner died'), row.inspectionId,
      row.cancelRequested, row.method), 'cliq-control-response-v1');
    if (!handoff && lifecycleBytes) lifecycleArtifact = await artifacts.publishBytes(lifecycleBytes,
      'application/octet-stream', 'cliq-source-native-lifecycle-v2');
    if (!row.retirementHandoffRef) row = await installSourceInspectionRetirementHandoff(driver, artifacts, owner, row, staging, {
      captureOwnerClosure: { kind: 'owning_process_dead', stateOwnerAcquisitionEvidenceRef: death.acquisitionEvidenceRef },
      processClosure, outcome: { kind: row.cancelRequested ? 'cancelled' : 'failed', errorResponseRef: response.ref },
      ...(lifecycleArtifact ? { nativeLifecycleRef: lifecycleArtifact.ref } : {})
    }, [response, ...(lifecycleArtifact ? [lifecycleArtifact] : [])]);
    await readSourceInspectionRetirementHandoff(driver, artifacts, row, active);
    const physical = await retireSourceInspectionStaging(owner.filesystem, staging);
    const { inspectorArtifact, evidenceArtifact, observedAt } = await publishSourceRetirement(driver, artifacts, owner, row, physical,
      { kind: 'owning_process_dead', stateOwnerAcquisitionEvidenceRef: death.acquisitionEvidenceRef }, processClosure);
    const key = { principalId: row.principalId, method: row.method, admissionKey: row.admissionKey, admissionIntentDigest: row.admissionIntentDigest };
    let clockRejected = false;
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.phase !== row.phase || current.rowDigest !== row.rowDigest)
        throw new KernelStorageError('REVISION_CONFLICT', 'source recovery lost its exact original reservation');
      readSourceInspectionStagingRetirement(owner.filesystem, physical);
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
      const now = readTimeFence(connection)!.lastAcceptedAt;
      if (now < observedAt || now < death.successorOwner.acquiredAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery observation is outside the current owner freshness window');
      const retired: Retired = { ...row, phase: 'retired', rowVersion: row.rowVersion + 1, updatedAt: now,
        retirementEvidenceRef: evidenceArtifact.ref, retiredAt: now,
        outcome: { kind: row.cancelRequested ? 'cancelled' : 'failed', errorResponseRef: response.ref }, rowDigest: '' };
      retired.rowDigest = digestOmitting(retired, 'rowDigest');
      for (const metadata of [response, inspectorArtifact, evidenceArtifact]) insertArtifactMetadata(connection, metadata, now);
      const updated = connection.prepare(`UPDATE source_inspection_attempts SET phase = 'retired', row_version = ?, row_json = ?
        WHERE inspection_id = ? AND phase = ? AND row_version = ? AND row_json = ?`)
        .run(retired.rowVersion, canonicalJsonBytes(retired).toString(), row.inspectionId, row.phase, row.rowVersion, canonicalJsonBytes(row).toString());
      if (updated.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'source recovery CAS lost its exact original reservation');
      // This is internal cleanup, not a request from a live peer. The owning
      // outcome/index now retain its first error; authenticated replay alone
      // may associate that same error with an actual channel/request record.
    });
    if (clockRejected) throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires canonical time');
    afterInspectionId = row.inspectionId;
  }
}

/** One owned Promise covers every physical open, capture, close and retirement.
 * It returns no accepted Run or process proof. An uncertain cleanup keeps its
 * durable capturing row and prevents another capture of that workspace. */
export async function captureSubmittedSource(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: SourceInspectionOwnerBootstrap, input: { request: unknown; identity: AuthenticatedControlIdentity; deliverySource?: VerifiedDeliverySource }, signal?: AbortSignal,
  selectedRuntime?: HeldInstalledRuntime, selectedAnchor?: HeldInstalledAnchor):
Promise<SourceInspectionAttemptV1> {
  const normalized = normalizeSourceInspectionRequest(input.request), wire = normalized.request, identity = immutableSnapshot(input.identity);
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  signal?.throwIfAborted(); await validateControlChannelClosure(reads, owner, identity); assertActiveStateOwner(driver, owner);
  const retained = await replaySubmittedSource(driver, artifacts, owner, bootstrap, wire, identity, signal);
  if (retained) return retained;
  signal?.throwIfAborted();
  const deliverySource = wire.method === 'run.apply' ? input.deliverySource ?? await readVerifiedDeliverySource(driver, reads, owner,
    { principalId: identity.principalId, sourceRunId: wire.sourceRunId, expectedRunResultRef: wire.expectedRunResultRef, signal }) : undefined;
  const request: SourceCaptureSelection = wire.method === 'run.apply'
    ? await resolveDeliverySourceCapture(driver, reads, owner, wire, identity.principalId, deliverySource!, signal) : wire;
  if (deliverySource && (deliverySource.assembly.runtime.runtimeBundleRef !== canonicalSha256(bootstrap.bundle) ||
      deliverySource.assembly.runtime.runtimeBundleManifestDigest !== bootstrap.bundle.manifestDigest ||
      deliverySource.spec.sandboxProfileRef !== canonicalSha256(bootstrap.sandboxProfile)))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'delivery capture requires its unchanged source runtime and sandbox profile');
  const resources: Array<{ close(): void }> = [];
  let home: HeldWorkspaceRoot | undefined, workspaceRoot: HeldWorkspaceRoot | undefined, trust: HeldWorkspaceSourceTrust | undefined;
  let target: VerifiedSourceInspectionTarget | undefined, stage: HeldSourceInspectionStaging | undefined, row: Unretired | undefined;
  let graph: PublishedNonGitSourceProjection | undefined, failure: unknown, deadlineTimer: NodeJS.Timeout | undefined;
  let handoffResponse: PublishedArtifact | undefined, admissionRefusal: PublishedArtifact | undefined;
  let dependencyIntent: Awaited<ReturnType<typeof import('./dependency-script-intent.js')['publishDependencyScriptIntent']>> | undefined;
  let nativeLifecycle: Buffer | undefined;
  let gitCapture: InstalledSourceGitCapture | undefined;
  let gitResult: Awaited<ReturnType<InstalledSourceGitCapture['run']>> | undefined;
  let processClosure: SourceInspectionRetirementEvidenceV1['processClosure'] | undefined = { kind: 'not_planned' };
  let retirementFailure: unknown;
  const deadline = new AbortController();
  const captureSignal = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  try {
    const native = selectedRuntime ? await withHeldInstalledRuntime(selectedRuntime, async installed => {
      await installed.revalidate(captureSignal);
      if (installed.bundleDigest !== canonicalSha256(bootstrap.bundle))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'source native loader differs from its selected installed runtime');
      const native = await installed.loadStateOwner(captureSignal); await installed.revalidate(captureSignal); return native;
    }, captureSignal) : await loadNativeStateOwner(bootstrap.bundle);
    captureSignal.throwIfAborted();
    home = native.openWorkspaceRoot(bootstrap.controlledHome); resources.push(home);
    trust = await holdWorkspaceSourceTrust(home, request.workspacePath, captureSignal); resources.push(trust);
    captureSignal.throwIfAborted(); workspaceRoot = native.openWorkspaceRoot(request.workspacePath); resources.push(workspaceRoot);
    target = await createVerifiedSourceInspectionTarget({ driver, artifacts, owner, bootstrap, workspaceRoot, trust,
      selectedRuntime, signal: captureSignal }, normalized.originalRequest, input.identity, deliverySource);
    captureSignal.throwIfAborted();
    const held = readVerifiedSourceInspectionTarget(owner, target);
    stage = owner.filesystem.createSourceInspectionStaging(held.inspectionId, sha256Bytes(randomBytes(32)));
    row = await reserveSourceInspectionAttempt(driver, artifacts, owner, target, stage);
    if (row.inputRef) processClosure = { kind: 'input_not_started', inputRef: row.inputRef, inputDigest: row.inputDigest! };
    let remaining = Math.max(1, parseCanonicalTime(row.deadlineAt) - Date.now());
    const armDeadline = () => {
      const interval = Math.min(remaining, 2_147_483_647); remaining -= interval;
      deadlineTimer = setTimeout(() => {
        if (remaining) armDeadline();
        else deadline.abort(new KernelStorageError('BUDGET_EXHAUSTED', 'source capture deadline elapsed'));
      }, interval); deadlineTimer.unref();
    };
    armDeadline(); captureSignal.throwIfAborted();
    const projectionInput = { workspaceRoot, controlledHome: home, stateOwnerLock: owner.filesystem,
      ...(request.sourceIncludes.length ? { includeCapture: { owner, target } } : {}),
      workspaceIdentityDigest: held.workspace.identityDigest, artifacts, sourceIncludes: request.sourceIncludes, sourceExcludes: request.sourceExcludes,
      maxChangedPaths: request.maxChangedPaths, maxChangedBytes: request.maxChangedBytes, maxEntries: 100_000,
      maxBytes: request.sandboxResources.maxGenerationBytes, maxSingleFileBytes: request.sandboxResources.maxSingleFileBytes, signal: captureSignal,
      ...(wire.method === 'run.apply' ? { deliveryCapture: { inspectionId: row.inspectionId,
        workspaceIdentityRef: held.target.workspaceIdentityRef, capturedAt: sampleCanonicalNow() } } : {}) };
    if (workspaceRoot.repositoryDirectory) {
      if (!selectedRuntime || !selectedAnchor) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'Git source inspection requires its genuine installed native owner');
      gitCapture = createInstalledSourceGitCapture(driver, artifacts, owner, bootstrap,
        { row, target, staging: stage, installed: selectedRuntime, anchor: selectedAnchor, signal: captureSignal });
      processClosure = undefined;
      gitResult = await gitCapture.run(); await gitCapture.close();
      const joined = readInstalledSourceGitCapture(owner, gitCapture); row = joined.row;
      const rules = request.frozenProjection ? undefined : await captureSourceGitRules(driver, artifacts, owner, target, home,
        { index: gitResult.index, exclude: gitResult.exclude, signal: captureSignal });
      const projected = await publishGitSourceProjection({ ...projectionInput, git: {
        privateGitStateRef: gitResult.privateGitStateRef, repositoryIdentityDigest: gitResult.index.repositoryIdentityDigest,
        resources: request.sandboxResources, frozenIgnoreRulesRef: request.frozenProjection?.frozenIgnoreRulesRef ?? rules!.rulesArtifact.ref,
        ...(request.frozenProjection ? { inheritedSourceRef: request.frozenProjection.admittedSourceRef } : {}) } });
      graph = { ...projected, metadata: [...gitResult.metadata, ...(rules?.metadata ?? []), ...projected.metadata] };
    } else graph = await publishNonGitSourceProjection({ ...projectionInput,
      ...(request.frozenProjection ? { inheritedProjection: { admittedSourceRef: request.frozenProjection.admittedSourceRef,
        resources: request.sandboxResources } } : {}) });
    if (request.frozenProjection && (graph.sourceProjectionRef !== request.frozenProjection.sourceProjectionRef ||
        graph.frozenIgnoreRulesRef !== request.frozenProjection.frozenIgnoreRulesRef))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery capture changed its inherited frozen projection');
    await recheckVerifiedSourceInspectionTarget(owner, target);
    assertWorkspaceSourceTrust(trust, request.workspacePath); captureSignal.throwIfAborted();
  } catch (error) { failure = error; }
  finally {
    if (deadlineTimer) clearTimeout(deadlineTimer);
    if (gitCapture) {
      try {
        await gitCapture.close();
        const joined = readInstalledSourceGitCapture(owner, gitCapture); row = joined.row;
        nativeLifecycle = joined.nativeLifecycle;
        processClosure = joined.nativeAttempted
          ? { kind: 'source_native_retired', inputRef: joined.row.inputRef!, inputDigest: joined.row.inputDigest!,
            nativeBirthIdentity: joined.nativeBirthIdentity!, observation: joined.observation!,
            ...(gitResult ? { output: { inspectionOutputRef: gitResult.inspectionOutputRef, privateGitStateRef: gitResult.privateGitStateRef } } : {}) }
          : { kind: 'input_not_started', inputRef: joined.row.inputRef!, inputDigest: joined.row.inputDigest! };
      } catch (error) { retirementFailure = error instanceof ResourceRetirementError ? error :
        new ResourceRetirementError('source native capture has no complete original closure', error); }
    }
    try { closeResources(resources, failure); } catch (error) { retirementFailure = error; }
  }
  // Preserve the original private birth on any uncertain native/consumer join.
  // Removing staging first would destroy the only genuine cleanup provenance.
  if (retirementFailure !== undefined) throw retirementFailure;
  if (!processClosure) throw new ResourceRetirementError('source capture has no complete original process closure', failure);
  if (failure === undefined && graph && row && wire.method === 'run.submit' && wire.dependency.mode === 'locked' &&
      wire.dependency.allowInstallScripts && wire.dependency.installScriptsGrantId === undefined) {
    try {
      if (!selectedRuntime) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'dependency intent requires its genuine installed selection');
      const { readDependencySubmissionConditions } = await import('./dependency-submission.js');
      const material = await readDependencySubmissionConditions(driver, reads, owner, { ...bootstrap, selectedRuntime }, {
        request: wire, sourceManifestRef: graph.baseWorkspaceManifestRef, workspaceEntriesRef: graph.entriesRef,
        ...(graph.privateGitStateRef ? { privateGitStateRef: graph.privateGitStateRef } : {}) }, captureSignal);
      const { conditions } = material;
      const { publishDependencyScriptIntent } = await import('./dependency-script-intent.js');
      dependencyIntent = await publishDependencyScriptIntent(driver, reads, owner, bootstrap, { row, conditions,
        scriptlessPolicy: material.scriptlessPolicy, scriptlessPlan: material.scriptlessPlan, registrySources: material.registrySources }, captureSignal);
      const required = new DependencyScriptAuthorizationRequired({ kind: 'dependency_install_scripts', purpose: 'dependency_install_scripts',
        target: { sessionId: wire.sessionId, sourceInspectionId: row.inspectionId, expectedWorkspaceIdentityDigest: row.workspaceIdentityDigest, conditions } });
      admissionRefusal = await artifacts.publishCanonical(errorResponse(required, row.inspectionId, false, wire.method), 'cliq-control-response-v1');
    } catch (error) { if (error instanceof ResourceRetirementError) throw error; failure = error; }
  }
  if (row && stage && target) {
    let outcome: Retired['outcome'];
    let refusal: PublishedArtifact | undefined;
    if (failure === undefined && graph) {
      if (wire.method === 'run.apply' && (!graph.captureTopologyRef || !graph.captureTopologyDigest))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery capture has no original topology closure');
      const captured = { kind: 'captured' as const, sourceManifestRef: graph.baseWorkspaceManifestRef, sourceManifestDigest: graph.manifestDigest,
        ...(graph.privateGitStateRef ? { privateGitStateRef: graph.privateGitStateRef } : {}) };
      outcome = wire.method === 'run.apply'
        ? { ...captured, captureTopologyRef: graph.captureTopologyRef!, captureTopologyDigest: graph.captureTopologyDigest! } : captured;
    } else {
      if (failure === undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'source capture has no original complete result');
      let cancelled = signal?.aborted === true;
      refusal = await artifacts.publishCanonical(errorResponse(failure, row.inspectionId, cancelled, row.method), 'cliq-control-response-v1');
      if (!cancelled && signal?.aborted) {
        cancelled = true;
        refusal = await artifacts.publishCanonical(errorResponse(failure, row.inspectionId, true, row.method), 'cliq-control-response-v1');
      }
      outcome = { kind: cancelled ? 'cancelled' : 'failed', errorResponseRef: refusal.ref };
      handoffResponse = refusal;
    }
    // Persist the original joined result and ownership before removing the
    // only physical birth. A native closure additionally needs its genuine
    // lifecycle snapshot; a missing snapshot refuses without deleting stage.
    const lifecycle = nativeLifecycle && await artifacts.publishBytes(nativeLifecycle, 'application/octet-stream', 'cliq-source-native-lifecycle-v2');
    row = await installSourceInspectionRetirementHandoff(driver, artifacts, owner, row, stage, {
      captureOwnerClosure: { kind: 'local_resources_joined', stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId },
      processClosure, outcome, ...(lifecycle ? { nativeLifecycleRef: lifecycle.ref } : {})
    }, [...(graph?.metadata ?? []), ...(refusal ? [refusal] : []), ...(lifecycle ? [lifecycle] : [])]);
  }
  let physical: SourceInspectionStagingRetirement | undefined;
  try { if (stage) physical = await retireSourceInspectionStaging(owner.filesystem, stage); }
  catch (error) {
    if (retirementFailure !== undefined) throw new ResourceRetirementError('source capture and staging retirement did not complete',
      new AggregateError([retirementFailure, error]));
    throw error;
  }
  if (retirementFailure !== undefined) throw retirementFailure;
  if (!row || !physical || !target) {
    if (failure !== undefined) throw failure;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection did not commit its exact reservation');
  }
  const heldTarget = await readCanonicalArtifact<import('../kernel/execution.js').SourceInspectionTarget>(artifacts, row.targetRef);
  const { inspectorArtifact, evidenceArtifact, observedAt } = await publishSourceRetirement(driver, artifacts, owner, row, physical,
    { kind: 'local_resources_joined', stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId }, processClosure);
  if (failure === undefined) {
    try { await validateControlChannelClosure(artifacts, owner, identity); }
    catch (error) { if (error instanceof ResourceRetirementError) throw error; failure = error; }
  }
  let response: PublishedArtifact | undefined = handoffResponse ?? admissionRefusal, result: Retired | undefined;
  const key = { principalId: row.principalId, method: row.method, admissionKey: row.admissionKey, admissionIntentDigest: row.admissionIntentDigest };
  // At most one final-cut downgrade, never a new capture/retry or new nonce.
  for (let cut = 0; cut < 2; cut++) {
    let cancelled = signal?.aborted === true;
    if (cancelled && failure === undefined) failure = signal!.reason;
    if (failure !== undefined) {
      const refusal = errorResponse(failure, row.inspectionId, cancelled, row.method);
      if (response?.ref !== canonicalSha256(refusal)) response = await artifacts.publishCanonical(refusal, 'cliq-control-response-v1');
      // Cancellation is monotonic but can arrive during the actual CAS write.
      // Freeze the response/outcome pair at the same final cut; an obsolete
      // ordinary error may remain orphan bytes, never the cancelled result.
      if (!cancelled && signal?.aborted) {
        cancelled = true;
        response = await artifacts.publishCanonical(errorResponse(failure, row.inspectionId, true, row.method), 'cliq-control-response-v1');
      }
    }
    let downgrade: unknown, clockRejected = false;
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); assertSourceInspectionRequestId(connection, row!.principalId, request, row!.inspectionId);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.phase !== row!.phase || current.rowDigest !== row!.rowDigest)
        throw new KernelStorageError('REVISION_CONFLICT', 'source reservation changed before retirement');
      readSourceInspectionStagingRetirement(owner.filesystem, physical!);
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
      const now = readTimeFence(connection)!.lastAcceptedAt;
      if (now < observedAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'source retirement observation is outside the current owner freshness window');
      if (failure === undefined) {
        const session = readSession(connection, request.sessionId);
        if (signal?.aborted) downgrade = signal.reason;
        else if (now >= row!.deadlineAt) downgrade = new KernelStorageError('BUDGET_EXHAUSTED', 'source capture deadline elapsed');
        else if (readSessionPrincipalId(connection, session.id) !== row!.principalId ||
            session.contextRevision !== request.expectedContextRevision || session.workspaceIdentityRef !== heldTarget.workspaceIdentityRef)
          downgrade = new KernelStorageError('ARTIFACT_MISMATCH', 'Session capture cut changed before retirement');
        if (downgrade !== undefined) return;
      }
      if (failure === undefined && wire.method === 'run.apply' && (!graph?.captureTopologyRef || !graph.captureTopologyDigest))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery capture has no original topology closure');
      const branch = failure === undefined && graph
        ? wire.method === 'run.apply'
          ? { method: 'run.apply' as const, outcome: { kind: 'captured' as const, sourceManifestRef: graph.baseWorkspaceManifestRef,
            sourceManifestDigest: graph.manifestDigest, ...(graph.privateGitStateRef ? { privateGitStateRef: graph.privateGitStateRef } : {}),
            captureTopologyRef: graph.captureTopologyRef!, captureTopologyDigest: graph.captureTopologyDigest! } }
          : { method: 'run.submit' as const, outcome: { kind: 'captured' as const, sourceManifestRef: graph.baseWorkspaceManifestRef,
            sourceManifestDigest: graph.manifestDigest, ...(graph.privateGitStateRef ? { privateGitStateRef: graph.privateGitStateRef } : {}) },
            ...(admissionRefusal && dependencyIntent ? { admissionErrorResponseRef: admissionRefusal.ref, dependencyScriptIntentRef: dependencyIntent.artifact.ref } : {}) }
        : { outcome: { kind: cancelled ? 'cancelled' as const : 'failed' as const, errorResponseRef: response!.ref } };
      const retired: Retired = { ...row!, rowVersion: row!.rowVersion + 1, phase: 'retired', updatedAt: now,
        cancelRequested: row!.cancelRequested || branch.outcome.kind === 'cancelled',
        retirementEvidenceRef: evidenceArtifact.ref, retiredAt: now, ...branch, rowDigest: '' };
      retired.rowDigest = digestOmitting(retired, 'rowDigest');
      for (const metadata of [...(graph?.metadata ?? []), ...(failure === undefined ? dependencyIntent?.metadata ?? [] : []),
        inspectorArtifact, evidenceArtifact, ...(response ? [response] : [])])
        insertArtifactMetadata(connection, metadata, now);
      const updated = connection.prepare(`UPDATE source_inspection_attempts SET phase = 'retired', row_version = ?, row_json = ?
        WHERE inspection_id = ? AND phase = ? AND row_version = ? AND row_json = ?`).run(retired.rowVersion,
          canonicalJsonBytes(retired).toString(), row!.inspectionId, row!.phase, row!.rowVersion, canonicalJsonBytes(row!).toString());
      if (updated.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'source retirement CAS lost its exact reservation');
      if (response) insertControlRequest(connection, { principalId: row!.principalId, method: row!.method, requestId: request.requestId,
        requestDigest: request.requestDigest, channelIdentityRef: identity.channelIdentityRef,
        channelIdentityDigest: identity.channelIdentityDigest, responseRef: response.ref, committedAt: now });
      result = immutableSnapshot(retired);
    });
    if (clockRejected) throw new KernelStorageError('RECOVERY_REQUIRED', 'source retirement requires canonical time');
    if (result) return result;
    failure = downgrade;
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'source retirement committed no terminal row');
}
