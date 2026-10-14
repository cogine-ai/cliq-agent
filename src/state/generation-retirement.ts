import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { Run, RunAssemblyV1, RunSpec, SupervisorInspectorIdentityV1, WorkerLaunch,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readNativeRetainedWorkerRetirement, type NativeRetainedWorkerRetirement } from '../sandbox/linux-worker.js';
import { readRetainedWorkspaceRetirement, type RetainedWorkspaceObservation } from '../workspace/run-workspace/generation.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import { readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertInstalledBrokerQuiescence, type InstalledBrokerQuiescence } from './store.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';

type Retired = Extract<WorkspaceGenerationStateV1, { phase: 'retired' }>;
type Source = Extract<WorkspaceGenerationStateV1, { phase: 'sealed' | 'quarantined' }>;

/** Closed historical data, never a native resource-retirement capability. */
function decodeRetirement(value: WorkspaceGenerationRetirementEvidenceV1): WorkspaceGenerationRetirementEvidenceV1 {
  const common = ['schemaVersion', 'format', 'runId', 'generationRef', 'generationIdentityDigest',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'fromPhase'];
  const branch = value?.fromPhase === 'sealed' ? ['snapshotEvidenceRef', 'snapshotEvidenceDigest', 'workerLaunchId',
    'containmentDeathEvidenceRef', 'containmentDeathEvidenceDigest'] : ['quarantineEvidenceRef', 'quarantineEvidenceDigest',
    'sourceQuarantinedRowVersion', 'activeRunPointerCount', 'nonretiredWorkerLaunchCount', 'liveContainmentCount',
    'activeMountCount', 'releasableBrokerClaimCount'];
  if (!exactKeys(value, [...common, ...branch]) || value.schemaVersion !== 1 ||
      value.format !== 'cliq-workspace-generation-retirement-evidence-v1' ||
      !['sealed', 'quarantined'].includes(value.fromPhase) || typeof value.runId !== 'string' || !value.runId ||
      value.evidenceDigest !== digestOmitting(value, 'evidenceDigest')) throw new TypeError('generation retirement has no exact closed evidence');
  for (const key of ['generationRef', 'generationIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest'])
    assertArtifactRef(value[key as keyof typeof value] as string);
  parseCanonicalTime(value.observedAt);
  if (value.fromPhase === 'sealed') {
    for (const ref of [value.snapshotEvidenceRef, value.snapshotEvidenceDigest, value.containmentDeathEvidenceRef, value.containmentDeathEvidenceDigest]) assertArtifactRef(ref);
    if (typeof value.workerLaunchId !== 'string' || !value.workerLaunchId) throw new TypeError('sealed retirement lacks its last worker');
  } else {
    assertArtifactRef(value.quarantineEvidenceRef); assertArtifactRef(value.quarantineEvidenceDigest);
    if (!Number.isSafeInteger(value.sourceQuarantinedRowVersion) || value.sourceQuarantinedRowVersion < 1 ||
        [value.activeRunPointerCount, value.nonretiredWorkerLaunchCount, value.liveContainmentCount,
          value.activeMountCount, value.releasableBrokerClaimCount].some(count => count !== 0))
      throw new TypeError('quarantined retirement has no exact zero resource cut');
  }
  return immutableSnapshot(value);
}

/** Reconstruct only the immutable source proof of a retired pointer. Its
 * owning seal/quarantine verifier must still validate that full source graph. */
export async function readRetiredGenerationSource(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; generation: Retired;
}): Promise<{ evidence: WorkspaceGenerationRetirementEvidenceV1; source: Source }> {
  const { generation, run } = input;
  const evidence = decodeRetirement(await readCanonicalArtifact(artifacts, generation.retirementEvidenceRef));
  if (evidence.evidenceDigest !== generation.retirementEvidenceDigest || evidence.runId !== run.id || generation.runId !== run.id ||
      evidence.generationRef !== generation.generationRef || evidence.generationIdentityDigest !== generation.generationIdentityDigest ||
      generation.rowVersion < 2 || evidence.observedAt > generation.updatedAt ||
      parseCanonicalTime(generation.updatedAt) - parseCanonicalTime(evidence.observedAt) > 5000)
    throw new TypeError('generation retirement substitutes its pointer or fresh committed cut');
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, evidence.inspectorIdentityRef);
  const owner = readStateOwner(driver, inspector.stateOwnerEpoch);
  if (!owner || owner.acquiredAt > evidence.observedAt || (owner.state === 'terminal' && owner.releasedAt < generation.updatedAt))
    throw new TypeError('generation retirement has no owning historical inspector');
  await readSupervisorInspector(artifacts, owner, input.assembly, evidence);
  assertClosedGenerationPointers(driver, [generation]);
  const { retirementEvidenceRef: _ref, retirementEvidenceDigest: _digest, phase: _phase, ...base } = generation;
  if (evidence.fromPhase === 'sealed') {
    const launch = readRequiredWorkerLaunch(driver, evidence.workerLaunchId);
    if (launch.workspaceGenerationRef !== generation.generationRef || launch.retirementEvidenceRef !== evidence.containmentDeathEvidenceRef ||
        !launch.retiredAt || launch.retiredAt > evidence.observedAt) throw new TypeError('sealed generation retirement substitutes its worker');
    const source: Source = { ...base, rowVersion: generation.rowVersion - 1, updatedAt: launch.retiredAt, phase: 'sealed',
      snapshotEvidenceRef: evidence.snapshotEvidenceRef, snapshotEvidenceDigest: evidence.snapshotEvidenceDigest };
    const death = await readCanonicalArtifact<{ evidenceDigest: string }>(artifacts, evidence.containmentDeathEvidenceRef);
    if (death.evidenceDigest !== evidence.containmentDeathEvidenceDigest) throw new TypeError('sealed retirement death digest differs');
    await validateRetainedWorkerSeal(driver, artifacts, { ...input, generation: source, launch });
    return { evidence, source };
  }
  const quarantine = await readCanonicalArtifact<WorkspaceGenerationQuarantineEvidenceV1>(artifacts, evidence.quarantineEvidenceRef);
  if (evidence.sourceQuarantinedRowVersion !== generation.rowVersion - 1 || quarantine.evidenceDigest !== evidence.quarantineEvidenceDigest ||
      quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest') || quarantine.runId !== run.id ||
      quarantine.generationRef !== generation.generationRef || quarantine.generationIdentityDigest !== generation.generationIdentityDigest ||
      quarantine.observedAt > evidence.observedAt) throw new TypeError('retired generation quarantine source differs');
  let launch: WorkerLaunch;
  if (quarantine.reason === 'worker_recovery') {
    const recovery = await readCanonicalArtifact<{ oldWorkerLaunchId: string }>(artifacts, quarantine.workerRecoveryEvidenceRef);
    launch = readRequiredWorkerLaunch(driver, recovery.oldWorkerLaunchId);
  } else if (quarantine.reason === 'launch_aborted' || quarantine.reason === 'launch_died_before_activation') {
    launch = readRequiredWorkerLaunch(driver, quarantine.workerLaunchId);
  } else throw new TypeError('generation retirement requires an implemented closed quarantine producer');
  if (launch.workspaceGenerationRef !== generation.generationRef || launch.phase !== 'retired' || !launch.retiredAt ||
      launch.retiredAt < quarantine.observedAt || launch.retiredAt > evidence.observedAt)
    throw new TypeError('quarantined generation retirement has no closed source launch');
  return { evidence, source: { ...base, rowVersion: evidence.sourceQuarantinedRowVersion, updatedAt: launch.retiredAt,
    phase: 'quarantined', quarantineEvidenceRef: evidence.quarantineEvidenceRef,
    quarantineEvidenceDigest: evidence.quarantineEvidenceDigest, observedState: quarantine.observedState } };
}

/** SQL-only final cut over already fully validated retained proof rows. This
 * does not manufacture native cgroup/mount/broker observations. */
function assertClosedGenerationPointers(connection: SqliteConnection | SqliteDriver,
  generations: readonly WorkspaceGenerationStateV1[]): void {
  for (const generation of generations.filter(value => value.phase === 'retired')) {
    if (canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation) ||
        connection.prepare(`SELECT 1 FROM runs r JOIN worker_launches w ON r.active_worker_launch_id = w.launch_id
          WHERE json_extract(w.row_json, '$.workspaceGenerationRef') = ? LIMIT 1`).get(generation.generationRef) ||
        connection.prepare(`SELECT 1 FROM worker_launches WHERE phase != 'retired'
          AND json_extract(row_json, '$.workspaceGenerationRef') = ? LIMIT 1`).get(generation.generationRef))
      throw new TypeError('retired generation again has a live Run/launch or a changed proof pointer');
  }
}

export function assertRetiredGenerationCut(connection: SqliteConnection | SqliteDriver, run: Run,
  generations: readonly WorkspaceGenerationStateV1[]): void {
  assertClosedGenerationPointers(connection, generations);
  const byRef = new Map(generations.map(value => [value.generationRef, value]));
  for (const launch of readWorkerLaunchesForRun(connection, run.id)) {
    const generation = byRef.get(launch.workspaceGenerationRef);
    if (launch.phase !== 'retired' || !generation || (generation.phase !== 'sealed' && generation.phase !== 'retired') ||
        (generation.phase === 'sealed' && launch.generationWriteState !== 'sealed'))
      throw new TypeError('terminal stop has no proof-backed closed generation for every worker');
  }
}

/** Sole installed quarantine-retirement producer. Caller-supplied data cannot
 * stand in for any of the three independent joined native resource owners. */
export async function retireQuarantinedGeneration(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  runId: string; expectedRunRevision: number; expectedGenerationRowVersion: number; generationRef: string;
  workerRetirement: NativeRetainedWorkerRetirement; workspaceRetirement: RetainedWorkspaceObservation;
  brokerQuiescence: InstalledBrokerQuiescence;
}): Promise<Retired> {
  // Consume brands before observing the remaining caller-selected metadata.
  let worker = readNativeRetainedWorkerRetirement(input.workerRetirement);
  let workspace = readRetainedWorkspaceRetirement(owner.filesystem, input.workspaceRetirement);
  assertInstalledBrokerQuiescence(input.brokerQuiescence, driver, owner, input.runId);
  const cut = await readRecoveryClosure(driver, artifacts, input.runId), { run } = cut;
  const generation = readRequiredWorkspaceGenerationByRef(driver, input.generationRef);
  if (run.revision !== input.expectedRunRevision || generation.phase !== 'quarantined' || generation.runId !== run.id ||
      generation.rowVersion !== input.expectedGenerationRowVersion || !Number.isSafeInteger(generation.rowVersion + 1) ||
      workspace.generationRef !== generation.generationRef || workspace.generationIdentityDigest !== generation.generationIdentityDigest ||
      canonicalSha256(workspace.observedState) !== canonicalSha256(generation.observedState))
    throw new KernelStorageError('REVISION_CONFLICT', 'generation retirement does not own its exact validated quarantine cut');
  const quarantine = await readCanonicalArtifact<WorkspaceGenerationQuarantineEvidenceV1>(artifacts, generation.quarantineEvidenceRef);
  if (quarantine.reason !== 'worker_recovery')
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'this physical retirement recipe requires its fully validated worker recovery quarantine');
  const launches = readWorkerLaunchesForRun(driver, run.id).filter(launch => launch.workspaceGenerationRef === generation.generationRef);
  if (launches.length !== 1 || launches[0]!.phase !== 'retired' || launches[0]!.processContainmentRef !== canonicalSha256(worker.containment))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'generation retirement substitutes its closed original containment');
  // Bulk immutable-proof I/O grants no freshness. Reobserve the same genuine
  // joined resource owners after it, before proposing their final zero cut.
  worker = readNativeRetainedWorkerRetirement(input.workerRetirement);
  workspace = readRetainedWorkspaceRetirement(owner.filesystem, input.workspaceRetirement);
  assertInstalledBrokerQuiescence(input.brokerQuiescence, driver, owner, run.id);
  const activeOwner = assertActiveStateOwner(driver, owner), observedAt = sampleCanonicalNow();
  if ([worker.observedAt, workspace.observedAt, generation.updatedAt].some(time => time > observedAt) ||
      parseCanonicalTime(observedAt) - parseCanonicalTime(worker.observedAt) > 5000 ||
      parseCanonicalTime(observedAt) - parseCanonicalTime(workspace.observedAt) > 5000)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'generation retirement requires fresh native resource observations');
  const inspector: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: activeOwner.supervisorInstanceId, stateOwnerEpoch: activeOwner.ownerEpoch,
    runtimeBundleRef: activeOwner.runtimeBundleRef, runtimeBundleManifestDigest: activeOwner.runtimeBundleManifestDigest,
    supervisorEntryId: activeOwner.supervisorEntryId, supervisorEntryVersion: activeOwner.supervisorEntryVersion,
    supervisorExecutableDigest: activeOwner.supervisorExecutableDigest, processIdentityRef: activeOwner.processIdentityRef,
    processIdentityDigest: activeOwner.processIdentityDigest, stateLockIdentityRef: activeOwner.stateLockIdentityRef,
    stateLockIdentityDigest: activeOwner.stateLockIdentityDigest, instanceNonceDigest: activeOwner.instanceNonceDigest,
    activatedAt: activeOwner.acquiredAt, identityDigest: '' };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const evidence: WorkspaceGenerationRetirementEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-retirement-evidence-v1',
    runId: run.id, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt, evidenceDigest: '',
    fromPhase: 'quarantined', quarantineEvidenceRef: generation.quarantineEvidenceRef, quarantineEvidenceDigest: generation.quarantineEvidenceDigest,
    sourceQuarantinedRowVersion: generation.rowVersion, activeRunPointerCount: 0, nonretiredWorkerLaunchCount: 0,
    liveContainmentCount: worker.liveContainmentCount, activeMountCount: worker.activeMountCount, releasableBrokerClaimCount: 0 };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeRetirement(evidence);
  const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.format);
  let result: Retired | undefined, fence: TimeFenceAdvance | undefined;
  driver.transaction(connection => {
    const currentOwner = assertActiveStateOwner(connection, owner), current = readRun(connection, run.id);
    if (currentOwner.ownerEpoch !== activeOwner.ownerEpoch || canonicalSha256(current) !== canonicalSha256(run) ||
        canonicalSha256(readRequiredWorkspaceGenerationByRef(connection, generation.generationRef)) !== canonicalSha256(generation))
      throw new KernelStorageError('REVISION_CONFLICT', 'generation retirement current owner or source cut changed');
    const native = readNativeRetainedWorkerRetirement(input.workerRetirement);
    const closedWorkspace = readRetainedWorkspaceRetirement(owner.filesystem, input.workspaceRetirement);
    assertInstalledBrokerQuiescence(input.brokerQuiescence, driver, owner, run.id);
    if (canonicalSha256(native.containment) !== canonicalSha256(worker.containment) || closedWorkspace.generationRef !== generation.generationRef ||
        canonicalSha256(closedWorkspace.observedState) !== canonicalSha256(generation.observedState) ||
        connection.prepare(`SELECT 1 FROM runs r JOIN worker_launches w ON r.active_worker_launch_id = w.launch_id
          WHERE json_extract(w.row_json, '$.workspaceGenerationRef') = ? LIMIT 1`).get(generation.generationRef) ||
        connection.prepare(`SELECT 1 FROM worker_launches WHERE phase != 'retired'
          AND json_extract(row_json, '$.workspaceGenerationRef') = ? LIMIT 1`).get(generation.generationRef))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'generation retirement still has a physical or durable resource owner');
    // SQL release predicates and the genuine native registry must both be
    // closed; an old claimed/unknown effect remains accounted, never refunded.
    const latest = new Map<string, ReturnType<typeof readInvocationJournal>[number]>();
    for (const entry of readInvocationJournal(connection, run.id)) latest.set(`${entry.opId}\0${entry.attempt}`, entry);
    if ([...latest.values()].some(entry => entry.phase === 'dispatch_claimed' && entry.brokerFenceTokenDigest &&
        entry.stateOwnerEpoch === currentOwner.ownerEpoch && entry.supervisorInstanceId === currentOwner.supervisorInstanceId &&
        entry.leaseEpoch === current.leaseEpoch && current.status === 'running' &&
        launches.some(launch => launch.launchId === current.activeWorkerLaunchId && launch.leaseEpoch === entry.leaseEpoch)))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'generation retirement retains a releasable broker claim');
    const now = sampleCanonicalNow(); fence = advanceTimeFence(connection, owner.ownerEpoch, now); if (fence !== 'healthy') return;
    if (now < observedAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000 ||
        native.observedAt > now || closedWorkspace.observedAt > now)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'generation retirement native cut is no longer fresh');
    for (const artifact of [inspectorArtifact, evidenceArtifact]) insertArtifactMetadata(connection, artifact, now);
    const { phase: _phase, quarantineEvidenceRef: _quarantine, quarantineEvidenceDigest: _quarantineDigest, observedState: _state, ...base } = generation;
    result = { ...base, rowVersion: generation.rowVersion + 1, updatedAt: now, phase: 'retired',
      retirementEvidenceRef: evidenceArtifact.ref, retirementEvidenceDigest: evidence.evidenceDigest };
    updateWorkspaceGeneration(connection, generation, result);
  });
  if (fence !== 'healthy' || !result) throw new KernelStorageError('RECOVERY_REQUIRED', 'generation retirement canonical time fence refused publication');
  return immutableSnapshot(result);
}
