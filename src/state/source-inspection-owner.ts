import { randomBytes } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SourceInspectionAttemptV1, SourceInspectionRetirementEvidenceV1 } from '../kernel/execution.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { publishNonGitSourceProjection, type PublishedNonGitSourceProjection } from '../workspace/source-projection.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeSourceManifest } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { loadNativeStateOwner, readSourceInspectionStagingRetirement, retireSourceInspectionStaging,
  type HeldSourceInspectionStaging, type HeldWorkspaceRoot, type SourceInspectionStagingRetirement } from './native-owner.js';
import { insertControlRequest, readAdmissionReplay, readControlRequest, readSession, readSessionPrincipalId } from './rows.js';
import { readNextUnretiredSourceInspection, readSourceInspectionAttempt, readSourceInspectionOriginalRequest, readSourceInspectionRequest,
  reserveSourceInspectionAttempt } from './source-inspection.js';
import { assertWorkspaceSourceTrust, holdWorkspaceSourceTrust, type HeldWorkspaceSourceTrust } from './source-trust.js';
import { createVerifiedSourceInspectionTarget, normalizeRunSubmitRequest, readRetainedSourceInspectionTarget,
  readVerifiedSourceInspectionTarget, recheckVerifiedSourceInspectionTarget, runSubmitIntentDigest,
  type SourceInspectionBootstrap, type VerifiedSourceInspectionTarget } from './source-target.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

export type SourceInspectionOwnerBootstrap = SourceInspectionBootstrap & Readonly<{ controlledHome: string }>;
type Capturing = Extract<SourceInspectionAttemptV1, { phase: 'capturing' }>;
type Retired = Extract<SourceInspectionAttemptV1, { phase: 'retired' }>;
type ErrorResponse = { protocolVersion: 1; ok: false; method: 'run.submit'; error:
  | { schemaVersion: 1; messageCode: string; code: 'INVALID_REQUEST'; retryable: false; issues: Array<{ path: string; issueCode: string }> }
  | { schemaVersion: 1; messageCode: string; code: 'INTERNAL'; retryable: false; errorId: string }
  | { schemaVersion: 1; messageCode: string; code: 'CANCEL_REQUESTED' | 'BUDGET_EXHAUSTED' | 'ARTIFACT_MISMATCH'; retryable: false } };

export function assertSourceInspectionRequestId(connection: SqliteConnection | SqliteDriver, principalId: string,
  request: { requestId: string; requestDigest: string }, expectedInspectionId?: string): void {
  const control = readControlRequest(connection, principalId, 'run.submit', request.requestId);
  const inspection = readSourceInspectionRequest(connection, principalId, request.requestId);
  if ((control && control.requestDigest !== request.requestDigest) || (inspection &&
      (inspection.originalRequestDigest !== request.requestDigest ||
       (expectedInspectionId !== undefined && inspection.attempt.inspectionId !== expectedInspectionId))))
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit request id belongs to different canonical bytes');
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
function errorResponse(error: unknown, inspectionId: string, cancelled: boolean): ErrorResponse {
  if (cancelled) return { protocolVersion: 1, ok: false, method: 'run.submit',
    error: { schemaVersion: 1, messageCode: 'source_capture_cancelled', code: 'CANCEL_REQUESTED', retryable: false } };
  if (error instanceof KernelStorageError && (error.code === 'BUDGET_EXHAUSTED' || error.code === 'ARTIFACT_MISMATCH'))
    return { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1,
      messageCode: 'source_capture_rejected', code: error.code, retryable: false } };
  if (error instanceof KernelStorageError || error instanceof TypeError) return { protocolVersion: 1, ok: false, method: 'run.submit',
    error: { schemaVersion: 1, messageCode: 'source_capture_rejected', code: 'INVALID_REQUEST', retryable: false,
      issues: [{ path: 'source', issueCode: 'source_changed_or_unsupported' }] } };
  return { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1, messageCode: 'source_capture_failed',
    code: 'INTERNAL', retryable: false, errorId: identityHash('cliq-source-inspection-error-v1', inspectionId) } };
}
function assertErrorResponse(value: unknown, inspectionId: string): asserts value is ErrorResponse {
  const data = value as ErrorResponse;
  if (!data || canonicalJsonBytes(data).length > 1_048_576 || Object.keys(data).sort().join() !== 'error,method,ok,protocolVersion' ||
      data.protocolVersion !== 1 || data.ok !== false || data.method !== 'run.submit' || !data.error || data.error.schemaVersion !== 1 ||
      data.error.retryable !== false || typeof data.error.messageCode !== 'string' || !/^[a-z_]{1,128}$/u.test(data.error.messageCode))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has the wrong closed response shape');
  const expected = ['schemaVersion', 'messageCode', 'code', 'retryable'];
  if (data.error.code === 'INVALID_REQUEST') {
    expected.push('issues');
    if (!Array.isArray(data.error.issues) || data.error.issues.length !== 1 ||
        Object.keys(data.error.issues[0]).sort().join() !== 'issueCode,path' || data.error.issues[0].path !== 'source' ||
        data.error.issues[0].issueCode !== 'source_changed_or_unsupported')
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has invalid redacted issues');
  } else if (data.error.code === 'INTERNAL') {
    expected.push('errorId');
    if (data.error.errorId !== identityHash('cliq-source-inspection-error-v1', inspectionId))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has invalid correlation id');
  } else if (!['CANCEL_REQUESTED', 'BUDGET_EXHAUSTED', 'ARTIFACT_MISMATCH'].includes(data.error.code))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error is not produced by this recipe');
  if (Object.keys(data.error).sort().join() !== expected.sort().join())
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has unknown fields');
}

/** Replay validates retained evidence; it never turns old bytes into a new
 * native observation or authorizes recapture. Only the implemented no-process
 * prefix is accepted until the corresponding fixed-recipe producers exist. */
async function readRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, row: Retired,
  runtime: { runtimeBundleRef: string; runtimeBundleManifestDigest: string }): Promise<void> {
  try {
    const evidence = await readCanonicalArtifact<SourceInspectionRetirementEvidenceV1>(artifacts, row.retirementEvidenceRef);
    if (!exactKeys(evidence, ['schemaVersion', 'format', 'inspectionId', 'targetRef', 'stagingNonceDigest',
      'inspectorIdentityRef', 'inspectorIdentityDigest', 'captureOwnerClosure', 'stagingObservation', 'processClosure', 'observedAt', 'evidenceDigest']) ||
        evidence.schemaVersion !== 1 || evidence.format !== 'cliq-source-inspection-retirement-v1' ||
        evidence.inspectionId !== row.inspectionId || evidence.targetRef !== row.targetRef || evidence.stagingNonceDigest !== row.stagingNonceDigest ||
        typeof evidence.inspectorIdentityRef !== 'string' || !/^[0-9a-f]{64}$/.test(evidence.inspectorIdentityRef) ||
        typeof evidence.inspectorIdentityDigest !== 'string' || !/^[0-9a-f]{64}$/.test(evidence.inspectorIdentityDigest) ||
        evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest') || evidence.stagingObservation !== 'exact_reserved_root_absent' ||
        !exactKeys(evidence.processClosure, ['kind']) || evidence.processClosure.kind !== 'not_planned' ||
        Object.hasOwn(row, 'inputRef') || Object.hasOwn(row, 'plan') || Object.hasOwn(row, 'processContainmentRef') ||
        (row.outcome.kind === 'captured' && Object.hasOwn(row.outcome, 'privateGitStateRef')) || typeof evidence.observedAt !== 'string')
      throw new TypeError('source retirement does not bind its exact no-process capture prefix');
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
  } catch (cause) {
    if (cause instanceof ResourceRetirementError) throw cause;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection retained retirement is invalid', { cause });
  }
}

async function replay(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: SourceInspectionOwnerBootstrap, request: ReturnType<typeof normalizeRunSubmitRequest>['request'],
  identity: AuthenticatedControlIdentity): Promise<SourceInspectionAttemptV1 | undefined> {
  const key = { principalId: identity.principalId, admissionKey: request.admissionKey,
    admissionIntentDigest: runSubmitIntentDigest(identity.principalId, request) };
  assertSourceInspectionRequestId(driver, identity.principalId, request);
  const retained = readSourceInspectionAttempt(driver, key);
  if (!retained) {
    const control = readControlRequest(driver, identity.principalId, 'run.submit', request.requestId);
    const admitted = readAdmissionReplay(driver, 'runs', identity.principalId, 'run.submit', request.admissionKey);
    if (admitted && admitted.admissionIntentDigest !== key.admissionIntentDigest)
      throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.submit key belongs to a different admitted intent');
    if (admitted || control) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'run.submit result must replay through Run admission');
    return;
  }
  const originalIndex = readSourceInspectionOriginalRequest(driver, retained.inspectionId);
  const { target } = await readRetainedSourceInspectionTarget(artifacts, retained, originalIndex, bootstrap);
  if (retained.phase !== 'retired') throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection still owns unretired capture resources');
  await readRetirement(driver, artifacts, retained, target);
  const metadata: PublishedArtifact[] = [];
  if (retained.outcome.kind === 'captured') {
    const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, retained.outcome.sourceManifestRef));
    if (source.role !== 'base' || source.manifestDigest !== retained.outcome.sourceManifestDigest ||
        source.workspaceIdentityDigest !== retained.workspaceIdentityDigest)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source outcome differs from its exact capture');
  } else {
    const errorResponseRef = retained.outcome.errorResponseRef;
    const error = await readCanonicalArtifact(artifacts, errorResponseRef); assertErrorResponse(error, retained.inspectionId);
    if ((retained.outcome.kind === 'cancelled') !== (error.error.code === 'CANCEL_REQUESTED'))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source outcome differs from its retained error class');
    const channel = await validateControlChannelClosure(artifacts, owner, identity); metadata.push(...channel.metadata);
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); assertSourceInspectionRequestId(connection, identity.principalId, request, retained.inspectionId);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.rowDigest !== retained.rowDigest) throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source replay changed');
      const prior = readControlRequest(connection, identity.principalId, 'run.submit', request.requestId);
      if (prior && prior.responseRef !== errorResponseRef) throw new KernelStorageError('RECOVERY_REQUIRED', 'source request has a different first response');
      if (prior) return;
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'source replay requires canonical time');
      const now = readTimeFence(connection)!.lastAcceptedAt;
      for (const entry of metadata) insertArtifactMetadata(connection, entry, now);
      insertControlRequest(connection, { principalId: identity.principalId, method: 'run.submit', requestId: request.requestId,
        requestDigest: request.requestDigest, channelIdentityRef: identity.channelIdentityRef,
        channelIdentityDigest: identity.channelIdentityDigest, responseRef: errorResponseRef, committedAt: now });
    });
  }
  await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner);
  return retained;
}

async function publishSourceRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  row: Capturing, physical: SourceInspectionStagingRetirement,
  captureOwnerClosure: SourceInspectionRetirementEvidenceV1['captureOwnerClosure']) {
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
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const evidence: SourceInspectionRetirementEvidenceV1 = { schemaVersion: 1, format: 'cliq-source-inspection-retirement-v1',
    inspectionId: row.inspectionId, targetRef: row.targetRef, stagingNonceDigest: row.stagingNonceDigest,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    captureOwnerClosure, stagingObservation: 'exact_reserved_root_absent', processClosure: { kind: 'not_planned' }, observedAt, evidenceDigest: '' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
  const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.format);
  return { inspectorArtifact, evidenceArtifact, observedAt };
}

/** Startup may retire a dead owner's incomplete capture, never resume it.
 * No client, source path, read capability or reusable process token exists in
 * this branch. Prepared/active recipes await their actual containment closer. */
export async function retireAbandonedSourceInspections(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, bootstrap: SourceInspectionBootstrap | undefined): Promise<void> {
  let afterInspectionId = '';
  for (;;) {
    const row = readNextUnretiredSourceInspection(driver, afterInspectionId);
    if (!row) return;
    if (!bootstrap) throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires its trusted signed runtime');
    if (row.phase !== 'capturing' || row.stateOwnerEpoch >= owner.ownerEpoch || row.supervisorInstanceId === owner.supervisorInstanceId)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires a dead predecessor and a supported no-process prefix');
    const active = assertActiveStateOwner(driver, owner);
    const { target } = await readRetainedSourceInspectionTarget(artifacts, row,
      readSourceInspectionOriginalRequest(driver, row.inspectionId), bootstrap);
    if (active.runtimeBundleRef !== target.runtimeBundleRef || active.runtimeBundleManifestDigest !== target.runtimeBundleManifestDigest)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery cannot substitute its frozen signed runtime');
    let death: Awaited<ReturnType<typeof readStateOwnerDeath>>;
    try {
      death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: row.supervisorInstanceId, ownedAt: row.createdAt });
      if (death.priorOwner.ownerEpoch !== row.stateOwnerEpoch || death.successorOwner.ownerEpoch > owner.ownerEpoch ||
          row.updatedAt > death.priorOwner.releasedAt)
        throw new TypeError('source recovery substitutes its original owning lifetime');
    } catch (cause) {
      if (cause instanceof ResourceRetirementError) throw cause;
      throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery has no exact positive owner-death proof', { cause });
    }
    assertActiveStateOwner(driver, owner);
    const staging = owner.filesystem.openSourceInspectionStaging(row.inspectionId, row.stagingNonceDigest, row.stagingIdentity);
    const physical = await retireSourceInspectionStaging(owner.filesystem, staging);
    const response = await artifacts.publishCanonical(errorResponse(new Error('source capture owner died'), row.inspectionId,
      row.cancelRequested), 'cliq-control-response-v1');
    const { inspectorArtifact, evidenceArtifact, observedAt } = await publishSourceRetirement(driver, artifacts, owner, row, physical,
      { kind: 'owning_process_dead', stateOwnerAcquisitionEvidenceRef: death.acquisitionEvidenceRef });
    const key = { principalId: row.principalId, admissionKey: row.admissionKey, admissionIntentDigest: row.admissionIntentDigest };
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.phase !== 'capturing' || current.rowDigest !== row.rowDigest)
        throw new KernelStorageError('REVISION_CONFLICT', 'source recovery lost its exact original reservation');
      readSourceInspectionStagingRetirement(owner.filesystem, physical);
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy')
        throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery requires canonical time');
      const now = readTimeFence(connection)!.lastAcceptedAt;
      if (now < observedAt || now < death.successorOwner.acquiredAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'source recovery observation is outside the current owner freshness window');
      const retired: Retired = { ...row, phase: 'retired', rowVersion: row.rowVersion + 1, updatedAt: now,
        retirementEvidenceRef: evidenceArtifact.ref, retiredAt: now,
        outcome: { kind: row.cancelRequested ? 'cancelled' : 'failed', errorResponseRef: response.ref }, rowDigest: '' };
      retired.rowDigest = digestOmitting(retired, 'rowDigest');
      for (const metadata of [response, inspectorArtifact, evidenceArtifact]) insertArtifactMetadata(connection, metadata, now);
      const updated = connection.prepare(`UPDATE source_inspection_attempts SET phase = 'retired', row_version = ?, row_json = ?
        WHERE inspection_id = ? AND phase = 'capturing' AND row_version = ? AND row_json = ?`)
        .run(retired.rowVersion, canonicalJsonBytes(retired).toString(), row.inspectionId, row.rowVersion, canonicalJsonBytes(row).toString());
      if (updated.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'source recovery CAS lost its exact original reservation');
      // This is internal cleanup, not a request from a live peer. The owning
      // outcome/index now retain its first error; authenticated replay alone
      // may associate that same error with an actual channel/request record.
    });
    afterInspectionId = row.inspectionId;
  }
}

/** One owned Promise covers every physical open, capture, close and retirement.
 * It returns no accepted Run or process proof. An uncertain cleanup keeps its
 * durable capturing row and prevents another capture of that workspace. */
export async function captureSubmittedSource(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: SourceInspectionOwnerBootstrap, input: { request: unknown; identity: AuthenticatedControlIdentity }, signal?: AbortSignal):
Promise<SourceInspectionAttemptV1> {
  const normalized = normalizeRunSubmitRequest(input.request), request = normalized.request, identity = immutableSnapshot(input.identity);
  signal?.throwIfAborted(); await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner);
  const retained = await replay(driver, artifacts, owner, bootstrap, request, identity);
  if (retained) return retained;
  signal?.throwIfAborted();
  const resources: Array<{ close(): void }> = [];
  let home: HeldWorkspaceRoot | undefined, workspaceRoot: HeldWorkspaceRoot | undefined, trust: HeldWorkspaceSourceTrust | undefined;
  let target: VerifiedSourceInspectionTarget | undefined, stage: HeldSourceInspectionStaging | undefined, row: Capturing | undefined;
  let graph: PublishedNonGitSourceProjection | undefined, failure: unknown, deadlineTimer: NodeJS.Timeout | undefined;
  let retirementFailure: unknown;
  const deadline = new AbortController();
  const captureSignal = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  try {
    const native = await loadNativeStateOwner(bootstrap.bundle); captureSignal.throwIfAborted();
    home = native.openWorkspaceRoot(bootstrap.controlledHome); resources.push(home);
    trust = await holdWorkspaceSourceTrust(home, request.workspacePath, captureSignal); resources.push(trust);
    captureSignal.throwIfAborted(); workspaceRoot = native.openWorkspaceRoot(request.workspacePath); resources.push(workspaceRoot);
    target = await createVerifiedSourceInspectionTarget({ driver, artifacts, owner, bootstrap, workspaceRoot, trust }, normalized.originalRequest, identity);
    captureSignal.throwIfAborted();
    const held = readVerifiedSourceInspectionTarget(owner, target);
    stage = owner.filesystem.createSourceInspectionStaging(held.inspectionId, sha256Bytes(randomBytes(32)));
    row = await reserveSourceInspectionAttempt(driver, artifacts, owner, target, stage);
    let remaining = Math.max(1, parseCanonicalTime(row.deadlineAt) - Date.now());
    const armDeadline = () => {
      const interval = Math.min(remaining, 2_147_483_647); remaining -= interval;
      deadlineTimer = setTimeout(() => {
        if (remaining) armDeadline();
        else deadline.abort(new KernelStorageError('BUDGET_EXHAUSTED', 'source capture deadline elapsed'));
      }, interval); deadlineTimer.unref();
    };
    armDeadline(); captureSignal.throwIfAborted();
    // Git needs a genuine reserved fixed-recipe inspector; a valid target or
    // directory staging observation cannot stand in for its sealed result.
    if (workspaceRoot.repositoryDirectory) throw new KernelStorageError('INVALID_REQUEST', 'Git source inspection is not yet implemented');
    graph = await publishNonGitSourceProjection({ workspaceRoot, controlledHome: home, stateOwnerLock: owner.filesystem,
      workspaceIdentityDigest: held.workspace.identityDigest, artifacts, sourceIncludes: request.sourceIncludes, sourceExcludes: request.sourceExcludes,
      maxChangedPaths: request.maxChangedPaths, maxChangedBytes: request.maxChangedBytes, maxEntries: 100_000,
      maxBytes: request.sandboxResources.maxGenerationBytes, maxSingleFileBytes: request.sandboxResources.maxSingleFileBytes, signal: captureSignal });
    await recheckVerifiedSourceInspectionTarget(owner, target);
    assertWorkspaceSourceTrust(trust, request.workspacePath); captureSignal.throwIfAborted();
  } catch (error) { failure = error; }
  finally {
    if (deadlineTimer) clearTimeout(deadlineTimer);
    try { closeResources(resources, failure); } catch (error) { retirementFailure = error; }
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
  const heldTarget = await readCanonicalArtifact<import('../kernel/execution.js').SourceInspectionTargetV1>(artifacts, row.targetRef);
  const { inspectorArtifact, evidenceArtifact, observedAt } = await publishSourceRetirement(driver, artifacts, owner, row, physical,
    { kind: 'local_resources_joined', stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId });
  if (failure === undefined) {
    try { await validateControlChannelClosure(artifacts, owner, identity); }
    catch (error) { if (error instanceof ResourceRetirementError) throw error; failure = error; }
  }
  let response: PublishedArtifact | undefined, result: Retired | undefined;
  const key = { principalId: row.principalId, admissionKey: row.admissionKey, admissionIntentDigest: row.admissionIntentDigest };
  // At most one final-cut downgrade, never a new capture/retry or new nonce.
  for (let cut = 0; cut < 2; cut++) {
    let cancelled = signal?.aborted === true;
    if (cancelled && failure === undefined) failure = signal!.reason;
    if (failure !== undefined) {
      response = await artifacts.publishCanonical(errorResponse(failure, row.inspectionId, cancelled), 'cliq-control-response-v1');
      // Cancellation is monotonic but can arrive during the actual CAS write.
      // Freeze the response/outcome pair at the same final cut; an obsolete
      // ordinary error may remain orphan bytes, never the cancelled result.
      if (!cancelled && signal?.aborted) {
        cancelled = true;
        response = await artifacts.publishCanonical(errorResponse(failure, row.inspectionId, true), 'cliq-control-response-v1');
      }
    }
    let downgrade: unknown;
    driver.transaction(connection => {
      assertActiveStateOwner(connection, owner); assertSourceInspectionRequestId(connection, row!.principalId, request, row!.inspectionId);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.phase !== 'capturing' || current.rowDigest !== row!.rowDigest)
        throw new KernelStorageError('REVISION_CONFLICT', 'source reservation changed before retirement');
      readSourceInspectionStagingRetirement(owner.filesystem, physical!);
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'source retirement requires canonical time');
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
      const outcome: Retired['outcome'] = failure === undefined && graph
        ? { kind: 'captured', sourceManifestRef: graph.baseWorkspaceManifestRef, sourceManifestDigest: graph.manifestDigest }
        : { kind: cancelled ? 'cancelled' : 'failed', errorResponseRef: response!.ref };
      const retired: Retired = { ...row!, rowVersion: row!.rowVersion + 1, phase: 'retired', updatedAt: now,
        cancelRequested: row!.cancelRequested || outcome.kind === 'cancelled',
        retirementEvidenceRef: evidenceArtifact.ref, retiredAt: now, outcome, rowDigest: '' };
      retired.rowDigest = digestOmitting(retired, 'rowDigest');
      for (const metadata of [...(graph?.metadata ?? []), inspectorArtifact, evidenceArtifact, ...(response ? [response] : [])])
        insertArtifactMetadata(connection, metadata, now);
      const updated = connection.prepare(`UPDATE source_inspection_attempts SET phase = 'retired', row_version = ?, row_json = ?
        WHERE inspection_id = ? AND phase = 'capturing' AND row_version = ? AND row_json = ?`).run(retired.rowVersion,
          canonicalJsonBytes(retired).toString(), row!.inspectionId, row!.rowVersion, canonicalJsonBytes(row!).toString());
      if (updated.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'source retirement CAS lost its exact reservation');
      if (response) insertControlRequest(connection, { principalId: row!.principalId, method: 'run.submit', requestId: request.requestId,
        requestDigest: request.requestDigest, channelIdentityRef: identity.channelIdentityRef,
        channelIdentityDigest: identity.channelIdentityDigest, responseRef: response.ref, committedAt: now });
      result = immutableSnapshot(retired);
    });
    if (result) return result;
    failure = downgrade;
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'source retirement committed no terminal row');
}
