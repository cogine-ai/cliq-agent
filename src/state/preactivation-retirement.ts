import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ProcessContainment } from '../kernel/execution.js';
import type { ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1, Run, RunEvent,
  SupervisorInspectorIdentityV1, WorkerIdentity, WorkerLaunch, WorkspaceGenerationQuarantineEvidenceV1,
  WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { assertNativeContainmentDeath, assertNativePreactivationObservation, type LinuxWorkerController,
  type NativePreactivationObservation, openLinuxWorkerLauncher, type LinuxWorkerInstallation } from '../sandbox/linux-worker.js';
import { observeRetainedRunWorkspace, readRetainedWorkspaceObservation } from '../workspace/run-workspace/generation.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { decodeRunSpec, decodeWorkerIdentity, decodeWorkspaceGenerationIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError, stateOperation } from './errors.js';
import { decodeWorkerContainmentPlan, decodeWorkerProcessContainment, decodeWorkerSandboxLaunchSpec,
  readPreactivationWorkerLaunchClosure, type WorkerLaunchClosure } from './execution-closure.js';
import { readRequiredWorkerLaunch, updateWorkerLaunch } from './repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef, updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import { insertRunEvent, readCheckpoint, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

type PreactivationQuarantine = Extract<WorkspaceGenerationQuarantineEvidenceV1,
  { reason: 'launch_aborted' | 'launch_died_before_activation' }>;
type RetirementProof = ProcessContainmentNoSpawnEvidenceV1 | ProcessContainmentDeathEvidenceV1;
const FRESHNESS_MS = 5000;

/** Join qualified abandoned attempts before exposing a successor Store or
 * gracefully releasing its owner. Unqualified retained metadata never proves
 * absence and remains blocking; it is not an installed execution capability. */
export async function retireAbandonedPreactivations(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, installation?: LinuxWorkerInstallation): Promise<void> {
  const rows = driver.prepare("SELECT launch_id FROM worker_launches WHERE phase IN ('reserved','preactivated') ORDER BY rowid")
    .all<{ launch_id: string }>();
  const launches: WorkerLaunch[] = [];
  for (const row of rows) {
    const launch = readRequiredWorkerLaunch(driver, row.launch_id);
    const plan = decodeWorkerContainmentPlan(await readCanonicalArtifact(artifacts, launch.containmentPlanRef));
    if (plan.backend.kind === 'linux' && plan.backend.nativeReservation) launches.push(launch);
  }
  if (launches.length === 0) return;
  let launcher: Awaited<ReturnType<typeof openLinuxWorkerLauncher>> | undefined;
  let primary: { error: unknown } | undefined;
  try {
    launcher = await openLinuxWorkerLauncher(installation);
    for (const launch of launches) {
      const controller = await launcher.startController();
      let failure: { error: unknown } | undefined;
      try { await retirePreactivationLaunch(driver, artifacts, owner, launch.launchId, controller); }
      catch (error) { failure = { error }; throw error; }
      finally {
        try { await controller.close(); }
        catch (error) { throw new ResourceRetirementError('preactivation inspector did not join',
          failure ? new AggregateError([failure.error, error]) : error); }
      }
    }
  } catch (error) { primary = { error }; throw new ResourceRetirementError('abandoned native launch closure is unresolved', error); }
  finally {
    try { await launcher?.close(); }
    catch (error) { throw new ResourceRetirementError('preactivation installation did not retire',
      primary ? new AggregateError([primary.error, error]) : error); }
  }
}

function fresh(now: string, observedAt: string): void {
  const elapsed = parseCanonicalTime(now) - parseCanonicalTime(observedAt);
  if (elapsed < 0 || elapsed > FRESHNESS_MS) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'preactivation retirement observation expired before commit');
  }
}
function checkedCut(connection: SqliteConnection | SqliteDriver, owner: StateOwnerContext, launchId: string) {
  const inspectingOwner = assertActiveStateOwner(connection, owner);
  const launch = readRequiredWorkerLaunch(connection, launchId);
  const run = readRun(connection, launch.runId);
  const generation = readRequiredWorkspaceGenerationByRef(connection, launch.workspaceGenerationRef);
  const checkpoint = readCheckpoint(connection, generation.sourceCheckpointId);
  if ((launch.phase !== 'reserved' && launch.phase !== 'preactivated') ||
      launch.generationWriteState !== 'preactivated_readonly' || launch.leaseVersion !== 0 ||
      launch.leaseEpoch !== undefined || launch.leaseExpiresAt !== undefined ||
      launch.activatedAt !== undefined || launch.quiesceId !== undefined ||
      run.status !== 'queued' || run.activeWorkerLaunchId !== undefined ||
      generation.phase !== 'preactivated_readonly' || generation.runId !== run.id ||
      generation.sourceCheckpointId !== run.latestCheckpointId || checkpoint.runId !== run.id ||
      checkpoint.workspaceStateRef !== generation.sourceWorkspaceStateRef) {
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'preactivation retirement requires its exact powerless queued launch and ready generation');
  }
  return { inspectingOwner, run, launch, generation, checkpoint };
}
function inspectorIdentity(owner: ReturnType<typeof assertActiveStateOwner>): SupervisorInspectorIdentityV1 {
  const inspector: SupervisorInspectorIdentityV1 = {
    schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch,
    runtimeBundleRef: owner.runtimeBundleRef, runtimeBundleManifestDigest: owner.runtimeBundleManifestDigest,
    supervisorEntryId: owner.supervisorEntryId, supervisorEntryVersion: owner.supervisorEntryVersion,
    supervisorExecutableDigest: owner.supervisorExecutableDigest, processIdentityRef: owner.processIdentityRef,
    processIdentityDigest: owner.processIdentityDigest, stateLockIdentityRef: owner.stateLockIdentityRef,
    stateLockIdentityDigest: owner.stateLockIdentityDigest, instanceNonceDigest: owner.instanceNonceDigest,
    activatedAt: owner.acquiredAt, identityDigest: ''
  };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  return inspector;
}
function actualContainment(containment: ProcessContainment, closure: WorkerLaunchClosure): void {
  requireEqual(containment.owner, closure.plan.owner, 'preactivation actual owner');
  requireEqual(containment.filesystemBinding, closure.plan.filesystemBinding, 'preactivation actual generation');
  if (containment.planRef !== closure.containmentPlanRef ||
      containment.sandboxLaunchSpecRef !== closure.sandboxLaunchSpecRef ||
      containment.sandboxLaunchSpecDigest !== closure.spec.launchSpecDigest ||
      containment.launchNonceDigest !== closure.plan.launchNonceDigest ||
      containment.backend.kind !== 'linux' || closure.plan.backend.kind !== 'linux' ||
      containment.backend.cgroupPath !== closure.plan.backend.cgroupPath ||
      containment.backend.pidNamespaceReservationId !== closure.plan.backend.pidNamespaceReservationId ||
      containment.backend.subreaperStartToken !== closure.plan.backend.subreaperStartToken) {
    throw new TypeError('preactivation actual containment substitutes its immutable reservation');
  }
}
async function recordedContainment(artifacts: ArtifactCatalog, launch: WorkerLaunch, closure: WorkerLaunchClosure) {
  const containment = launch.processContainmentRef === undefined ? undefined
    : decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, launch.processContainmentRef));
  let workerIdentity: WorkerIdentity | undefined;
  if (containment) actualContainment(containment, closure);
  if (launch.workerIdentityDigest !== undefined) {
    if (!containment) throw new TypeError('recorded worker identity has no actual containment');
    const identity = decodeWorkerIdentity(await readCanonicalArtifact(artifacts, launch.workerIdentityDigest));
    workerIdentity = identity;
    const executable = closure.spec.executable;
    if (executable.kind !== 'runtime_bundle' || identity.launchId !== launch.launchId ||
        identity.supervisorInstanceId !== launch.supervisorInstanceId ||
        identity.spawnNonceDigest !== launch.spawnNonceDigest ||
        identity.activationNonceDigest !== launch.activationNonceDigest ||
        identity.intendedLeaseEpoch !== closure.plan.owner.intendedLeaseEpoch ||
        identity.processContainmentRef !== launch.processContainmentRef ||
        identity.executableRealpath !== executable.executionPath ||
        identity.executableDigest !== executable.executableDigest) {
      throw new TypeError('recorded preactivation identity substitutes its launch or signed executable');
    }
  }
  return { containment, workerIdentity };
}
function observationTime(value: NativePreactivationObservation): string {
  return value.kind === 'no_spawn' ? value.observedAt : value.death.observedAt;
}
function appendStateEvent(connection: SqliteConnection, run: Run, now: string): void {
  const eventSeq = Number(connection.prepare('SELECT COALESCE(max(event_seq), 0) + 1 AS seq FROM run_events WHERE run_id = ?')
    .get<{ seq: unknown }>(run.id)?.seq);
  const latestRunItemSeq = Number(connection.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?')
    .get<{ seq: unknown }>(run.id)?.seq);
  if (!Number.isSafeInteger(eventSeq) || eventSeq < 1 || !Number.isSafeInteger(latestRunItemSeq) || latestRunItemSeq < 0) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'preactivation retirement event cursor is invalid');
  }
  const event: Extract<RunEvent, { kind: 'state_changed' }> = {
    schemaVersion: 1, kind: 'state_changed', runId: run.id, eventSeq, runRevision: run.revision,
    status: run.status, nextStep: run.nextStep, latestRunItemSeq, occurredAt: now,
    ...(run.frontierRef === undefined ? {} : { frontierRef: run.frontierRef })
  };
  insertRunEvent(connection, event);
}

/** One owning operation for failed execution and successor startup. The supplied
 * controller is a fresh inspector, never an adopted old worker/controller. */
export const retirePreactivationLaunch = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  launchId: string, controller: LinuxWorkerController
): Promise<Run> => {
  const cut = driver.readSnapshot(connection => checkedCut(connection, owner, launchId));
  const closure = await readPreactivationWorkerLaunchClosure(artifacts, cut.inspectingOwner, cut);
  const { containment, workerIdentity } = await recordedContainment(artifacts, cut.launch, closure);
  const backend = closure.plan.backend;
  if (backend.kind !== 'linux' || backend.nativeReservation === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'preactivation retirement requires its actual durable native reservation');
  }
  const reservation = owner.filesystem.openWorkerReservation(launchId, cut.launch.spawnNonceDigest, backend.nativeReservation);
  let operationFailed = false, operationFailure: unknown;
  try {
    const inspect = (expectedContainment?: ProcessContainment) => controller.inspectPreactivation({
      closure, reservation, activationNonceDigest: cut.launch.activationNonceDigest,
      ...(workerIdentity === undefined ? {} : { workerIdentity }),
      ...(expectedContainment === undefined ? {} : { containment: expectedContainment })
    });
    const initial = await inspect(containment);
    assertNativePreactivationObservation(initial, closure);
    if (initial.kind === 'created') {
      assertNativeContainmentDeath(initial.death);
      actualContainment(initial.containment, closure);
      requireEqual(initial.death.containment, initial.containment, 'preactivation death containment');
    } else if (containment !== undefined) {
      throw new TypeError('an observed worker cannot be retired as an unattempted reservation');
    }
    // Whole containment closure precedes the actual descriptor-relative tree walk.
    // Reobserve afterwards: a large legal tree must not refresh a cached timestamp.
    const observation = readRetainedWorkspaceObservation(await observeRetainedRunWorkspace({
      filesystem: owner.filesystem, artifacts, identity: closure.generation,
      sourceRowVersion: cut.generation.rowVersion
    }));
    if (observation.generationRef !== cut.generation.generationRef ||
        observation.generationIdentityDigest !== cut.generation.generationIdentityDigest) {
      throw new TypeError('preactivation tree observation substitutes its retained generation');
    }
    const actual = initial.kind === 'created' ? initial.containment : undefined;
    const observed = await inspect(actual);
    assertNativePreactivationObservation(observed, closure);
    if (observed.kind !== initial.kind) throw new TypeError('native reservation changed during tree observation');
    if (observed.kind === 'created') {
      assertNativeContainmentDeath(observed.death);
      requireEqual(observed.containment, actual, 'fresh preactivation actual containment');
      requireEqual(observed.death.containment, actual, 'fresh preactivation death containment');
    }
    const inspector = inspectorIdentity(cut.inspectingOwner);
    const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
    const inspectorPair = { inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest };
    const common = {
      schemaVersion: 1 as const, planRef: cut.launch.containmentPlanRef,
      sandboxLaunchSpecRef: cut.launch.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: closure.spec.launchSpecDigest,
      owner: closure.plan.owner, launchNonceDigest: cut.launch.spawnNonceDigest,
      inspectorSupervisorInstanceId: cut.inspectingOwner.supervisorInstanceId, ...inspectorPair,
      observedAt: observationTime(observed), evidenceDigest: ''
    };
    const containmentArtifact = observed.kind === 'created'
      ? await artifacts.publishCanonical(observed.containment, 'cliq-process-containment-v1') : undefined;
    if (containmentArtifact && cut.launch.processContainmentRef !== undefined &&
        containmentArtifact.ref !== cut.launch.processContainmentRef) {
      throw new TypeError('native retirement changed the recorded immutable containment');
    }
    const deathBackend = observed.kind === 'created' ? observed.containment.backend : undefined;
    if (deathBackend !== undefined && deathBackend.kind !== 'linux') throw new TypeError('preactivation death is not a Linux observation');
    const proof: RetirementProof = observed.kind === 'no_spawn'
      ? { ...common, kind: 'containment_plan_quiescent', backend: { kind: 'linux',
          cgroupPath: backend.cgroupPath, cgroupObservation: observed.cgroupObservation,
          pidNamespaceObservation: observed.pidNamespaceObservation, subreaperStartToken: backend.subreaperStartToken,
          matchingLaunchNonceProcessCount: observed.matchingLaunchNonceProcessCount } }
      : { ...common, kind: 'containment_all_descendants_dead', containmentRef: containmentArtifact!.ref,
          backend: { ...deathBackend!, cgroupPopulated: 0,
            namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 } };
    proof.evidenceDigest = digestOmitting(proof, 'evidenceDigest');
    const proofArtifact = await artifacts.publishCanonical(proof,
      observed.kind === 'no_spawn' ? 'cliq-process-containment-no-spawn-evidence-v1' : 'cliq-process-containment-death-evidence-v1');
    function requireCurrentCut(connection: SqliteConnection | SqliteDriver): string {
      reservation.assertHeld();
      const current = checkedCut(connection, owner, launchId);
      for (const key of ['run', 'launch', 'generation', 'checkpoint', 'inspectingOwner'] as const) {
        if (canonicalSha256(current[key]) !== canonicalSha256(cut[key])) {
          throw new KernelStorageError('REVISION_CONFLICT', 'preactivation retirement cut changed during observation');
        }
      }
      const now = sampleCanonicalNow();
      fresh(now, proof.observedAt);
      return now;
    }
    // No metadata CAS before the move. After a crash, the same retained v still
    // derives the one exact archive locator; neither scanning nor version guesses.
    requireCurrentCut(driver);
    const move = owner.filesystem.quarantineGeneration(closure.generation, cut.generation.rowVersion);
    const quarantine: PreactivationQuarantine = {
      schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1',
      runId: cut.run.id, generationRef: cut.generation.generationRef,
      generationIdentityDigest: cut.generation.generationIdentityDigest,
      sourceRowVersion: cut.generation.rowVersion, observedState: observation.observedState,
      ...inspectorPair, ...move, observedAt: sampleCanonicalNow(), evidenceDigest: '',
      workerLaunchId: launchId, fromPhase: 'preactivated_readonly',
      ...(observed.kind === 'no_spawn'
        ? { reason: 'launch_aborted', containmentNoSpawnEvidenceRef: proofArtifact.ref,
            containmentNoSpawnEvidenceDigest: proof.evidenceDigest }
        : { reason: 'launch_died_before_activation', containmentDeathEvidenceRef: proofArtifact.ref,
            containmentDeathEvidenceDigest: proof.evidenceDigest })
    };
    quarantine.evidenceDigest = digestOmitting(quarantine, 'evidenceDigest');
    const quarantineArtifact = await artifacts.publishCanonical(quarantine, quarantine.format);
    let updated!: Run, healthy = false;
    driver.transaction(connection => {
      const now = requireCurrentCut(connection);
      fresh(now, quarantine.observedAt);
      if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
      healthy = true;
      if (!Number.isSafeInteger(cut.run.revision + 1)) throw new KernelStorageError('RECOVERY_REQUIRED', 'Run revision overflowed');
      for (const artifact of [inspectorArtifact, containmentArtifact, proofArtifact, quarantineArtifact]) {
        if (artifact) insertArtifactMetadata(connection, artifact, now);
      }
      const generation: WorkspaceGenerationStateV1 = {
        schemaVersion: 1, generationId: cut.generation.generationId, runId: cut.generation.runId,
        generationRef: cut.generation.generationRef, generationIdentityDigest: cut.generation.generationIdentityDigest,
        rowVersion: cut.generation.rowVersion + 1, sourceCheckpointId: cut.generation.sourceCheckpointId,
        sourceWorkspaceStateRef: cut.generation.sourceWorkspaceStateRef,
        sourceWorkspaceStateDigest: cut.generation.sourceWorkspaceStateDigest,
        lastVerifiedTreeDigest: cut.generation.lastVerifiedTreeDigest, updatedAt: now,
        phase: 'quarantined', quarantineEvidenceRef: quarantineArtifact.ref,
        quarantineEvidenceDigest: quarantine.evidenceDigest, observedState: quarantine.observedState
      };
      updateWorkspaceGeneration(connection, cut.generation, generation);
      updateWorkerLaunch(connection, cut.launch, { ...cut.launch, phase: 'retired', retiredAt: now,
        retirementEvidenceRef: proofArtifact.ref,
        ...(containmentArtifact === undefined ? {} : { processContainmentRef: containmentArtifact.ref }) });
      const changed = connection.prepare('UPDATE runs SET revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ?')
        .run(now, cut.run.id, BigInt(cut.run.revision));
      if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'Run changed during preactivation retirement');
      updated = readRun(connection, cut.run.id);
      appendStateEvent(connection, updated, now);
    });
    if (!healthy) throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical clock is not healthy');
    return immutableSnapshot(updated);
  } catch (error) {
    operationFailed = true; operationFailure = error; throw error;
  } finally {
    try { reservation.close(); }
    catch (cause) {
      throw new ResourceRetirementError('preactivation reservation descriptor did not retire',
        operationFailed ? new AggregateError([operationFailure, cause]) : cause);
    }
  }
});

/** Historical verification does not mint a native observation or permit replay
 * of an old handshake. It follows only the exact retained quarantine edge. */
export async function validatePreactivationQuarantine(
  artifacts: ArtifactCatalog, driver: SqliteDriver, run: Run,
  generation: WorkspaceGenerationStateV1, quarantine: PreactivationQuarantine
): Promise<void> {
  if (generation.phase !== 'quarantined') throw new TypeError('preactivation history has no quarantined generation');
  const launch = readRequiredWorkerLaunch(driver, quarantine.workerLaunchId);
  const plan = decodeWorkerContainmentPlan(await readCanonicalArtifact(artifacts, launch.containmentPlanRef));
  const spec = decodeWorkerSandboxLaunchSpec(await readCanonicalArtifact(artifacts, launch.sandboxLaunchSpecRef));
  const identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, generation.generationRef));
  const checkpoint = readCheckpoint(driver, generation.sourceCheckpointId);
  const proofRef = quarantine.reason === 'launch_aborted'
    ? quarantine.containmentNoSpawnEvidenceRef : quarantine.containmentDeathEvidenceRef;
  const proofDigest = quarantine.reason === 'launch_aborted'
    ? quarantine.containmentNoSpawnEvidenceDigest : quarantine.containmentDeathEvidenceDigest;
  const proof = await readCanonicalArtifact<RetirementProof>(artifacts, proofRef);
  const runSpec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, runSpec.assemblyRef));
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, proof.inspectorIdentityRef);
  const inspectingOwner = readStateOwner(driver, inspector.stateOwnerEpoch);
  if (!inspectingOwner || (inspectingOwner.state === 'terminal' && launch.retiredAt! > inspectingOwner.releasedAt)) {
    throw new TypeError('preactivation retirement has no exact inspecting owner lifetime');
  }
  await readSupervisorInspector(artifacts, inspectingOwner, assembly, proof);
  if (launch.phase !== 'retired' || launch.generationWriteState !== 'preactivated_readonly' ||
      launch.leaseVersion !== 0 || launch.leaseEpoch !== undefined || launch.leaseExpiresAt !== undefined ||
      launch.activatedAt !== undefined || launch.quiesceId !== undefined ||
      launch.runId !== run.id || generation.runId !== run.id || launch.workspaceGenerationRef !== generation.generationRef ||
      launch.retirementEvidenceRef !== proofRef || launch.retiredAt !== generation.updatedAt ||
      launch.plannedRunRevision >= run.revision || checkpoint.runId !== run.id ||
      checkpoint.workspaceStateRef !== generation.sourceWorkspaceStateRef ||
      identity.runId !== run.id || identity.generationId !== generation.generationId ||
      identity.identityDigest !== generation.generationIdentityDigest ||
      identity.sourceCheckpointId !== generation.sourceCheckpointId ||
      identity.sourceWorkspaceStateRef !== generation.sourceWorkspaceStateRef ||
      identity.sourceWorkspaceStateDigest !== generation.sourceWorkspaceStateDigest ||
      identity.sourceTreeDigest !== generation.lastVerifiedTreeDigest || identity.locator.kind !== 'linux_directory') {
    throw new TypeError('preactivation retirement substitutes its exact historical launch or source Checkpoint');
  }
  const baseKeys = ['schemaVersion', 'kind', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner',
    'launchNonceDigest', 'inspectorSupervisorInstanceId', 'inspectorIdentityRef', 'inspectorIdentityDigest',
    'backend', 'observedAt', 'evidenceDigest'];
  if (!exactKeys(proof, [...baseKeys, ...(proof.kind === 'containment_all_descendants_dead' ? ['containmentRef'] : [])]) ||
      proof.schemaVersion !== 1 || proof.planRef !== launch.containmentPlanRef ||
      proof.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef ||
      proof.sandboxLaunchSpecDigest !== spec.launchSpecDigest || proof.launchNonceDigest !== launch.spawnNonceDigest ||
      proof.inspectorSupervisorInstanceId !== inspectingOwner.supervisorInstanceId ||
      proof.evidenceDigest !== proofDigest || proof.evidenceDigest !== digestOmitting(proof, 'evidenceDigest') ||
      proof.observedAt < launch.createdAt || quarantine.observedAt < proof.observedAt ||
      quarantine.observedAt > launch.retiredAt! || spec.containmentPlanRef !== launch.containmentPlanRef ||
      spec.containmentPlanDigest !== plan.planDigest || plan.launchNonceDigest !== launch.spawnNonceDigest ||
      plan.owner.runId !== run.id || plan.owner.workerLaunchId !== launch.launchId ||
      plan.backend.kind !== 'linux' || plan.backend.nativeReservation === undefined) {
    throw new TypeError('preactivation retirement proof substitutes its immutable plan, nonce, inspector or time');
  }
  fresh(launch.retiredAt!, proof.observedAt); fresh(launch.retiredAt!, quarantine.observedAt);
  requireEqual(proof.owner, plan.owner, 'historical preactivation proof owner');
  requireEqual(spec.owner, plan.owner, 'historical preactivation launch owner');
  requireEqual(plan.filesystemBinding, { kind: 'run-generation', generationRef: generation.generationRef }, 'historical preactivation generation');
  requireEqual(spec.filesystem, { kind: 'run_generation', generationRef: generation.generationRef,
    access: 'preactivated_readonly', sourceProjectionRef: runSpec.sourceProjectionRef, independentGit: true }, 'historical preactivation write envelope');
  if (proof.backend.kind !== 'linux') throw new TypeError('preactivation history is not a Linux backend observation');
  const containment = launch.processContainmentRef === undefined ? undefined
    : decodeWorkerProcessContainment(await readCanonicalArtifact(artifacts, launch.processContainmentRef));
  if (containment) {
    requireEqual(containment.owner, plan.owner, 'historical actual owner');
    requireEqual(containment.filesystemBinding, plan.filesystemBinding, 'historical actual generation');
    if (containment.backend.kind !== 'linux' || containment.planRef !== launch.containmentPlanRef ||
        containment.sandboxLaunchSpecRef !== launch.sandboxLaunchSpecRef ||
        containment.sandboxLaunchSpecDigest !== spec.launchSpecDigest || containment.launchNonceDigest !== launch.spawnNonceDigest ||
        containment.backend.cgroupPath !== plan.backend.cgroupPath ||
        containment.backend.pidNamespaceReservationId !== plan.backend.pidNamespaceReservationId ||
        containment.backend.subreaperStartToken !== plan.backend.subreaperStartToken ||
        containment.createdAt < launch.createdAt || containment.createdAt > proof.observedAt) {
      throw new TypeError('historical actual containment substitutes its reservation');
    }
  }
  if (quarantine.reason === 'launch_aborted') {
    if (proof.kind !== 'containment_plan_quiescent' ||
        !exactKeys(proof.backend, ['kind', 'cgroupPath', 'cgroupObservation', 'pidNamespaceObservation',
          'subreaperStartToken', 'matchingLaunchNonceProcessCount']) ||
        proof.backend.cgroupPath !== plan.backend.cgroupPath ||
        proof.backend.subreaperStartToken !== plan.backend.subreaperStartToken ||
        proof.backend.matchingLaunchNonceProcessCount !== 0) throw new TypeError('launch abortion has no exact planned backend closure');
    const cgroup = proof.backend.cgroupObservation, namespace = proof.backend.pidNamespaceObservation;
    if (cgroup.kind === 'absent') requireEqual(cgroup, { kind: 'absent' }, 'absent planned cgroup');
    else if (cgroup.kind === 'empty' && typeof cgroup.cgroupId === 'string' && cgroup.cgroupId.length > 0) {
      requireEqual(cgroup, { kind: 'empty', cgroupId: cgroup.cgroupId, populated: 0 }, 'empty planned cgroup');
    } else throw new TypeError('planned cgroup observation is not closed');
    if (namespace.kind === 'never_created') {
      requireEqual(namespace, { kind: 'never_created', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId }, 'uncreated planned namespace');
      if (launch.processContainmentRef !== undefined || launch.workerIdentityDigest !== undefined) {
        throw new TypeError('an observed worker cannot have an uncreated namespace');
      }
    } else if (namespace.kind === 'dead_reaped' && typeof namespace.namespaceInitStartToken === 'string' && namespace.namespaceInitStartToken.length > 0) {
      requireEqual(namespace, { kind: 'dead_reaped', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId,
        namespaceInitStartToken: namespace.namespaceInitStartToken }, 'dead planned namespace');
      if (containment?.backend.kind === 'linux' &&
          (namespace.namespaceInitStartToken !== containment.backend.namespaceInitStartToken ||
            (cgroup.kind === 'empty' && cgroup.cgroupId !== containment.backend.cgroupId))) {
        throw new TypeError('dead planned namespace substitutes its recorded actual identity');
      }
    } else throw new TypeError('planned namespace observation is not closed');
  } else {
    if (proof.kind !== 'containment_all_descendants_dead' || proof.containmentRef !== launch.processContainmentRef) {
      throw new TypeError('created preactivation retirement has no exact actual containment');
    }
    if (!containment) throw new TypeError('created preactivation retirement has no retained actual containment');
    requireEqual(proof.backend, { ...containment.backend, cgroupPopulated: 0,
      namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, 'created preactivation all-descendant death');
  }
  if (launch.workerIdentityDigest !== undefined) {
    const worker = decodeWorkerIdentity(await readCanonicalArtifact(artifacts, launch.workerIdentityDigest));
    const executable = spec.executable;
    if (executable.kind !== 'runtime_bundle' || worker.launchId !== launch.launchId ||
        worker.supervisorInstanceId !== launch.supervisorInstanceId || worker.spawnNonceDigest !== launch.spawnNonceDigest ||
        worker.activationNonceDigest !== launch.activationNonceDigest ||
        worker.intendedLeaseEpoch !== plan.owner.intendedLeaseEpoch || worker.processContainmentRef !== launch.processContainmentRef ||
        worker.executableRealpath !== executable.executionPath || worker.executableDigest !== executable.executableDigest) {
      throw new TypeError('retired preactivation identity substitutes its original spawner or executable');
    }
  }
  const common = {
    schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1',
    runId: run.id, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    sourceRowVersion: generation.rowVersion - 1, observedState: generation.observedState,
    inspectorIdentityRef: proof.inspectorIdentityRef, inspectorIdentityDigest: proof.inspectorIdentityDigest,
    quarantineCanonicalRootRelativePath: 'quarantine/workspace-generations/' + identityHash(generation.generationId, String(generation.rowVersion - 1)),
    quarantineDeviceId: identity.locator.deviceId, quarantineFileId: identity.locator.directoryFileId,
    originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true,
    observedAt: quarantine.observedAt, evidenceDigest: generation.quarantineEvidenceDigest,
    fromPhase: 'preactivated_readonly', workerLaunchId: launch.launchId
  };
  requireEqual(quarantine, { ...common, ...(quarantine.reason === 'launch_aborted'
    ? { reason: 'launch_aborted', containmentNoSpawnEvidenceRef: proofRef, containmentNoSpawnEvidenceDigest: proofDigest }
    : { reason: 'launch_died_before_activation', containmentDeathEvidenceRef: proofRef, containmentDeathEvidenceDigest: proofDigest }) },
    'preactivation quarantine exact closed edge');
  if (!Number.isSafeInteger(quarantine.sourceRowVersion) || quarantine.sourceRowVersion < 1 ||
      quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest')) throw new TypeError('preactivation quarantine version or digest is invalid');
  if (generation.observedState.kind === 'complete_tree') {
    requireEqual(generation.observedState, { kind: 'complete_tree', treeDigest: generation.observedState.treeDigest }, 'quarantine observed tree');
    assertArtifactRef(generation.observedState.treeDigest);
  } else if (generation.observedState.kind === 'unreadable_partial' &&
      ['descriptor_io_failed', 'artifact_missing_or_corrupt', 'path_or_entry_invalid', 'git_closure_invalid'].includes(generation.observedState.failureCode)) {
    requireEqual(generation.observedState, { kind: 'unreadable_partial', failureCode: generation.observedState.failureCode }, 'quarantine closed failure');
  } else throw new TypeError('preactivation quarantine observation is not closed');
}
