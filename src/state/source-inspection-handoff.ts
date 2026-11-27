import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SourceInspectionAttemptV1, SourceInspectionRetirementEvidenceV1,
  SourceInspectionRetirementHandoffV1 } from '../kernel/execution.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { decodeSourceGitNativeLifecycle, readHeldSourceInspectionStaging, type HeldSourceInspectionStaging } from './native-owner.js';
import { decodeSourceInspectionAttempt, readSourceInspectionAttempt } from './source-inspection.js';
import { readSourceGitRetirementClosure } from './source-git-retirement.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import type { SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import { decodePlatformProcessIdentity, decodeStateLockIdentity, decodeStateRootIdentity, decodeWorkspaceIdentity } from './decoders.js';
import { decodeRepositoryIdentity } from './repository-identity.js';
import { readSourceInspectionOriginalRequest } from './source-inspection.js';
import { readSourceInspectionTargetData } from './source-target.js';

type Unretired = Exclude<SourceInspectionAttemptV1, { phase: 'retired' }>;
type Retired = Extract<SourceInspectionAttemptV1, { phase: 'retired' }>;
const MAX_HANDOFF_BYTES = 1_048_576;
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'source retirement handoff differs from its original complete joined capture'); }

async function readData(artifacts: ArtifactCatalog, ref: string): Promise<unknown> {
  const bytes = await artifacts.readBoundedBytes(ref, MAX_HANDOFF_BYTES);
  if (sha256Bytes(bytes) !== ref) return invalid();
  const data: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!canonicalJsonBytes(data).equals(bytes)) return invalid();
  return data;
}
function originalFields(row: SourceInspectionAttemptV1) {
  const { phase: _phase, rowVersion: _version, rowDigest: _digest, updatedAt: _updated,
    cancelRequested: _cancelled, retirementHandoffRef: _handoff, retirementEvidenceRef: _retirement,
    retiredAt: _retiredAt, outcome: _outcome, admissionErrorResponseRef: _admissionError, dependencyScriptIntentRef: _dependencyIntent, ...original } = row;
  return original;
}

async function readNativeClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, original: Unretired,
  data: SourceInspectionRetirementHandoffV1, snapshot: Buffer) {
  if (data.processClosure.kind !== 'source_native_retired') return invalid();
  const lifecycle = decodeSourceGitNativeLifecycle(snapshot), observation = data.processClosure.observation;
  const owner = readStateOwner(driver, original.stateOwnerEpoch);
  if (!owner || lifecycle.lifecycleDigest !== data.nativeLifecycleRef || lifecycle.byteCount !== snapshot.length ||
      lifecycle.inspectionId !== original.inspectionId || lifecycle.stagingNonceDigest !== original.stagingNonceDigest ||
      lifecycle.targetRef !== original.targetRef || lifecycle.inputIntentRef !== original.inputRef ||
      canonicalSha256(lifecycle.birthIdentity) !== canonicalSha256(data.processClosure.nativeBirthIdentity)) return invalid();
  const process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, owner.processIdentityRef));
  const lock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, owner.stateLockIdentityRef));
  const root = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, lock.stateRootIdentityRef));
  if (owner.processIdentityDigest !== process.identityDigest || owner.stateLockIdentityDigest !== lock.identityDigest ||
      root.identityDigest !== lock.stateRootIdentityDigest || root.platform !== 'linux' || process.platform !== 'linux' || process.ownerUid !== root.ownerUid ||
      lifecycle.originalSupervisorPid !== process.pid || lifecycle.originalSupervisorStartToken !== process.processStartToken ||
      lifecycle.stateRoot.deviceId !== root.deviceId || lifecycle.stateRoot.fileId !== root.directoryFileId ||
      lifecycle.stateRoot.ownerUid !== root.ownerUid || lifecycle.stateRoot.mode !== root.mode ||
      lifecycle.staging.deviceId !== original.stagingIdentity.deviceId || lifecycle.staging.fileId !== original.stagingIdentity.fileId ||
      lifecycle.staging.ownerUid !== original.stagingIdentity.ownerUid || lifecycle.staging.mode !== original.stagingIdentity.mode) return invalid();
  const { target } = await readSourceInspectionTargetData(artifacts, original, readSourceInspectionOriginalRequest(driver, original.inspectionId));
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, target.workspaceIdentityRef));
  if (target.schemaVersion !== 2 || workspace.kind !== 'live' || !workspace.repositoryIdentityRef ||
      workspace.identityDigest !== original.workspaceIdentityDigest || lifecycle.workspaceDeviceId !== workspace.rootIdentity.deviceId ||
      lifecycle.workspaceFileId !== workspace.rootIdentity.fileId) return invalid();
  const repository = decodeRepositoryIdentity(await readCanonicalArtifact(artifacts, workspace.repositoryIdentityRef));
  if (repository.repositoryIdentityDigest !== workspace.repositoryIdentityDigest || repository.platform !== 'linux' ||
      lifecycle.gitDeviceId !== repository.gitDirectoryIdentity.deviceId || lifecycle.gitFileId !== repository.gitDirectoryIdentity.fileId) return invalid();
  for (const key of ['lastBirthKind', 'reserved', 'blocked', 'released', 'continued', 'originalControllerPid', 'originalControllerStartToken',
    'cgroupDeviceId', 'cgroupId', 'launchNonceDigest', 'containmentPlanRef', 'sandboxLaunchRef', 'sandboxLaunchDigest', 'snapshotDigest',
    'entryCount', 'shardCount'] as const) if (lifecycle[key] !== observation[key]) return invalid();
  if (lifecycle.sourceByteCount !== observation.byteCount) return invalid();
  if (observation.containment) {
    const death = observation.containment, workers = lifecycle.processes.filter(item => item.role === 'worker');
    const namespaces = lifecycle.processes.filter(item => item.role === 'namespace_init'), monitors = lifecycle.processes.filter(item => item.role === 'monitor');
    const parts = death.namespaceInitStartToken.split(':');
    if (workers.length !== 1 || namespaces.length !== 1 || monitors.length !== 1 ||
        lifecycle.pidNamespaceId !== death.pidNamespaceId ||
        workers[0]!.pid !== death.pid || workers[0]!.processStartToken !== death.processStartToken ||
        namespaces[0]!.pid !== death.namespaceInitPid || namespaces[0]!.processStartToken !== `linux-proc-start-ticks:${parts[2]}` ||
        monitors[0]!.pid !== Number(parts[4]) || monitors[0]!.processStartToken !== `linux-proc-start-ticks:${parts[5]}`) return invalid();
  } else if (lifecycle.pidNamespaceId !== null || lifecycle.processes.some(item => item.role === 'worker' || item.role === 'namespace_init')) return invalid();
  return lifecycle;
}

/** Retained data only. The current cleanup owner must separately prove the
 * old owner/controller death and perform actual staging cleanup/fsync/join. */
export async function readSourceInspectionRetirementHandoff(driver: SqliteDriver, artifacts: ArtifactCatalog,
  row: SourceInspectionAttemptV1, runtime: { runtimeBundleRef: string; runtimeBundleManifestDigest: string }) {
  if (!row.retirementHandoffRef) return invalid();
  const value = await readData(artifacts, row.retirementHandoffRef);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const data = value as SourceInspectionRetirementHandoffV1;
  if (!exactKeys(data, ['schemaVersion', 'format', 'originalAttemptRef', 'inspectorIdentityRef', 'inspectorIdentityDigest',
    'captureOwnerClosure', 'processClosure', 'outcome', 'observedAt', 'handoffDigest', ...(Object.hasOwn(data, 'nativeLifecycleRef') ? ['nativeLifecycleRef'] : [])]) ||
      data.schemaVersion !== 1 || data.format !== 'cliq-source-inspection-retirement-handoff-v1' ||
      data.handoffDigest !== digestOmitting(data, 'handoffDigest')) return invalid();
  for (const ref of [data.originalAttemptRef, data.inspectorIdentityRef, data.inspectorIdentityDigest]) assertArtifactRef(ref);
  const original = decodeSourceInspectionAttempt(await readData(artifacts, data.originalAttemptRef));
  if (original.phase === 'retired' || original.retirementHandoffRef || original.rowVersion >= row.rowVersion ||
      row.phase !== 'retired' && row.phase !== original.phase || original.cancelRequested && !row.cancelRequested ||
      canonicalSha256(originalFields(original)) !== canonicalSha256(originalFields(row)) ||
      data.observedAt < original.updatedAt || data.observedAt > row.updatedAt) return invalid();
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, data.inspectorIdentityRef);
  const inspectingOwner = readStateOwner(driver, inspector.stateOwnerEpoch);
  if (!inspectingOwner || inspectingOwner.state === 'terminal' && data.observedAt > inspectingOwner.releasedAt) return invalid();
  if (data.captureOwnerClosure.kind === 'local_resources_joined') {
    if (!exactKeys(data.captureOwnerClosure, ['kind', 'stateOwnerEpoch', 'supervisorInstanceId']) ||
        data.captureOwnerClosure.stateOwnerEpoch !== original.stateOwnerEpoch ||
        data.captureOwnerClosure.supervisorInstanceId !== original.supervisorInstanceId ||
        inspectingOwner.ownerEpoch !== original.stateOwnerEpoch || inspectingOwner.supervisorInstanceId !== original.supervisorInstanceId) return invalid();
  } else if (data.captureOwnerClosure.kind === 'owning_process_dead') {
    if (!exactKeys(data.captureOwnerClosure, ['kind', 'stateOwnerAcquisitionEvidenceRef']) || data.outcome.kind === 'captured') return invalid();
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: original.supervisorInstanceId, ownedAt: original.createdAt });
    if (death.priorOwner.ownerEpoch !== original.stateOwnerEpoch || original.updatedAt > death.priorOwner.releasedAt ||
        data.captureOwnerClosure.stateOwnerAcquisitionEvidenceRef !== death.acquisitionEvidenceRef ||
        inspectingOwner.ownerEpoch < death.successorOwner.ownerEpoch || data.observedAt < death.successorOwner.acquiredAt) return invalid();
  } else return invalid();
  parseCanonicalTime(data.observedAt);
  await readSupervisorInspector(artifacts, inspectingOwner, { runtime }, data);
  if (data.processClosure.kind === 'source_native_retired') {
    // The native checker additionally validates the full fixed original birth
    // snapshot. Its CAS bytes are not a new native object or a no-spawn proof.
    if (!data.nativeLifecycleRef) return invalid();
    assertArtifactRef(data.nativeLifecycleRef);
    const snapshot = await artifacts.readBoundedBytes(data.nativeLifecycleRef, MAX_HANDOFF_BYTES);
    if (!snapshot.length || sha256Bytes(snapshot) !== data.nativeLifecycleRef) return invalid();
    await readNativeClosure(driver, artifacts, original, data, snapshot);
  } else if (data.nativeLifecycleRef !== undefined) return invalid();
  // Reuse the closed row/closure decoder through an inert historical view.
  // This view is never stored and cannot mint physical retirement evidence.
  const view = decodeSourceInspectionAttempt({ ...original, phase: 'retired', rowVersion: original.rowVersion + 1,
    updatedAt: data.observedAt, retiredAt: data.observedAt, retirementEvidenceRef: row.retirementHandoffRef,
    outcome: data.outcome, rowDigest: digestOmitting({ ...original, phase: 'retired', rowVersion: original.rowVersion + 1,
      updatedAt: data.observedAt, retiredAt: data.observedAt, retirementEvidenceRef: row.retirementHandoffRef,
      outcome: data.outcome }, 'rowDigest') }) as Retired;
  const closure: SourceInspectionRetirementEvidenceV1 = { schemaVersion: 1, format: 'cliq-source-inspection-retirement-v1',
    inspectionId: original.inspectionId, targetRef: original.targetRef, stagingNonceDigest: original.stagingNonceDigest,
    inspectorIdentityRef: data.inspectorIdentityRef, inspectorIdentityDigest: data.inspectorIdentityDigest,
    captureOwnerClosure: data.captureOwnerClosure, stagingObservation: 'exact_reserved_root_absent',
    processClosure: data.processClosure, observedAt: data.observedAt, evidenceDigest: '' };
  await readSourceGitRetirementClosure(driver, artifacts, view, closure, runtime);
  if (row.phase === 'retired' && row.outcome.kind === 'captured' && canonicalSha256(row.outcome) !== canonicalSha256(data.outcome)) return invalid();
  return immutableSnapshot({ handoff: data, original });
}

/** The original program calls this only after its actual producers/readers
 * have joined. The genuine staging handle and StateOwner remain held through
 * the exact same-phase CAS; only then may staging removal begin. */
export async function installSourceInspectionRetirementHandoff(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, row: Unretired, staging: HeldSourceInspectionStaging,
  input: Pick<SourceInspectionRetirementHandoffV1, 'captureOwnerClosure' | 'processClosure' | 'outcome' | 'nativeLifecycleRef'>,
  metadata: readonly PublishedArtifact[]): Promise<Unretired> {
  if (row.retirementHandoffRef || input.processClosure.kind === 'source_native_retired' && !input.nativeLifecycleRef ||
      input.processClosure.kind !== 'source_native_retired' && input.nativeLifecycleRef !== undefined) return invalid();
  const held = readHeldSourceInspectionStaging(owner.filesystem, staging);
  if (held.inspectionId !== row.inspectionId || held.stagingNonceDigest !== row.stagingNonceDigest ||
      canonicalSha256(held.stagingIdentity) !== canonicalSha256(row.stagingIdentity)) return invalid();
  const active = assertActiveStateOwner(driver, owner);
  if (input.captureOwnerClosure.kind === 'local_resources_joined' &&
      (active.ownerEpoch !== row.stateOwnerEpoch || active.supervisorInstanceId !== row.supervisorInstanceId)) return invalid();
  const originalRef = canonicalSha256(row);
  const inspector = supervisorInspectorIdentity(active), observedAt = sampleCanonicalNow();
  const data: SourceInspectionRetirementHandoffV1 = { schemaVersion: 1, format: 'cliq-source-inspection-retirement-handoff-v1',
    originalAttemptRef: originalRef, inspectorIdentityRef: canonicalSha256(inspector), inspectorIdentityDigest: inspector.identityDigest,
    captureOwnerClosure: input.captureOwnerClosure, processClosure: input.processClosure, outcome: input.outcome, observedAt,
    ...(input.nativeLifecycleRef ? { nativeLifecycleRef: input.nativeLifecycleRef } : {}), handoffDigest: '' };
  data.handoffDigest = digestOmitting(data, 'handoffDigest');
  // The original attempt, inspector and handoff are one inert stage. The
  // original physical staging/currentness and fresh five-second SQL gate below
  // still run only after every member is durable, fully reread and joined.
  const [original, inspectorArtifact, handoffArtifact] = await artifacts.publishCanonicalTriple([
    { value: row, schemaKind: 'cliq-source-inspection-attempt-v1' },
    { value: inspector, schemaKind: inspector.format }, { value: data, schemaKind: data.format }
  ]);
  if (original.ref !== originalRef || inspectorArtifact.ref !== data.inspectorIdentityRef || handoffArtifact.ref !== canonicalSha256(data)) return invalid();
  let installed: Unretired | undefined, clockRejected = false;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner); readHeldSourceInspectionStaging(owner.filesystem, staging);
    const current = readSourceInspectionAttempt(connection, row);
    if (!current || current.rowDigest !== row.rowDigest || current.retirementHandoffRef) return invalid();
    if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
    const now = readTimeFence(connection)!.lastAcceptedAt;
    if (now < observedAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000) return invalid();
    const next: Unretired = { ...row, retirementHandoffRef: handoffArtifact.ref, rowVersion: row.rowVersion + 1,
      updatedAt: now, rowDigest: '' };
    next.rowDigest = digestOmitting(next, 'rowDigest');
    for (const entry of [...metadata, original, inspectorArtifact, handoffArtifact]) insertArtifactMetadata(connection, entry, now);
    const updated = connection.prepare(`UPDATE source_inspection_attempts SET row_version=?,row_json=?
      WHERE inspection_id=? AND phase=? AND row_version=? AND row_json=?`).run(next.rowVersion, canonicalJsonBytes(next).toString(),
        row.inspectionId, row.phase, row.rowVersion, canonicalJsonBytes(row).toString());
    if (updated.changes !== 1n) return invalid();
    installed = next;
  });
  if (clockRejected || !installed) return invalid();
  return immutableSnapshot(installed);
}
