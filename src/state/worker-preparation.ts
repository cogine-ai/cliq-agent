import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { PreparingWorkerLaunch, RetiredWorkerPreparation, Run, RunAssemblyV1, WorkerLaunch,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readNativeControllerPreparationBirth, readNativeControllerPreparationRetirement, readNativeWorkerReservationBinding,
  type NativeControllerPreparationBirth, type NativeControllerPreparationRetirement, type NativeWorkerReservationBinding } from '../sandbox/linux-worker.js';
import { publishRunWorkspaceBirthIdentity, readRunWorkspaceBirth, readRunWorkspaceBirthRetirement,
  readUnallocatedRunWorkspaceRetirement, type RunWorkspaceBirth, type RunWorkspaceMaterialization,
  type UnallocatedRunWorkspaceRetirement } from '../workspace/run-workspace/generation.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { decodeRunSpec, decodeWorkspaceEntries, decodeWorkspaceGenerationIdentity, decodeWorkspaceGenerationSnapshotEvidence,
  decodeWorkspaceState } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { decodeWorkerLaunch, decodeWorkspaceGenerationState } from './invariants.js';
import { borrowWorkerReservationForExecution, readWorkerReservationRetirement, type GenerationQuarantineMove,
  type HeldWorkerReservation } from './native-owner.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { insertWorkerLaunch, readRequiredWorkerLaunch, readWorkerLaunchesForRun, updateWorkerLaunch } from './repositories/worker-launches.js';
import { insertWorkspaceGeneration, readRequiredWorkspaceGeneration, readWorkspaceGenerationsForRun,
  updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertInstalledBrokerQuiescence, type InstalledBrokerQuiescence } from './store.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';

type ControllerBirth = Readonly<{ schemaVersion: 1; format: 'cliq-controller-preparation-birth-v1';
  identity: ReturnType<typeof readNativeControllerPreparationBirth>['identity']; birthDigest: string }>;
type Materializing = Extract<WorkspaceGenerationStateV1, { phase: 'materializing' }>;
type PreparationGeneration = Extract<WorkspaceGenerationStateV1, { phase: 'materializing' | 'preactivated_readonly' }>;
type RetiredGeneration = Extract<WorkspaceGenerationStateV1, { phase: 'retired' }>;
type PreparationQuarantine = Extract<WorkspaceGenerationQuarantineEvidenceV1, { reason: 'preparation_retired' }>;
type BornPreparationRetirement = Readonly<{ schemaVersion: 1; format: 'cliq-worker-preparation-retirement-evidence-v1'; kind: 'born';
  launch: PreparingWorkerLaunch; sourceGeneration: PreparationGeneration;
  workspaceRetirementObservedAt: string;
  controllerRetirement?: ReturnType<typeof readNativeControllerPreparationRetirement>;
  reservationRetirement?: HeldWorkerReservation['identity'];
  quarantineMove: GenerationQuarantineMove; inspectorIdentityRef: string; inspectorIdentityDigest: string;
  observedAt: string; evidenceDigest: string }>;
type UnallocatedPreparationRetirement = Readonly<{ schemaVersion: 1; format: 'cliq-worker-preparation-retirement-evidence-v1'; kind: 'unallocated';
  launch: PreparingWorkerLaunch; workspaceRetirement: UnallocatedRunWorkspaceRetirement;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string; evidenceDigest: string }>;
type PreparationRetirement = BornPreparationRetirement | UnallocatedPreparationRetirement;
const preparationOwners = new WeakMap<PreparingWorkerLaunch, { driver: SqliteDriver; owner: StateOwnerContext }>();
function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

function preparing(connection: SqliteConnection | SqliteDriver, owner: StateOwnerContext, launchId: string): PreparingWorkerLaunch {
  assertActiveStateOwner(connection, owner);
  const launch = readRequiredWorkerLaunch(connection, launchId);
  if (launch.phase !== 'preparing' || launch.supervisorInstanceId !== owner.supervisorInstanceId ||
      launch.preparation.stateOwnerEpoch !== owner.ownerEpoch) fail('worker preparation is not owned by this exact StateOwner');
  return launch;
}

function bindableRun(connection: SqliteConnection | SqliteDriver, launch: PreparingWorkerLaunch): Run {
  const run = readRun(connection, launch.runId);
  if (run.status !== 'queued' || run.activeWorkerLaunchId || run.revision < launch.plannedRunRevision ||
      run.latestCheckpointId !== launch.preparation.sourceCheckpointId)
    fail('worker preparation no longer owns its original lease-free source Checkpoint');
  return run;
}

export async function beginWorkerPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  runId: string; expectedRunRevision: number; launchId: string; spawnNonceDigest: string;
  activationNonceDigest: string; generationCreationNonceDigest: string;
}): Promise<PreparingWorkerLaunch> {
  input = immutableSnapshot(input);
  if (!exactKeys(input, ['runId', 'expectedRunRevision', 'launchId', 'spawnNonceDigest', 'activationNonceDigest', 'generationCreationNonceDigest']) ||
      !/^[A-Za-z0-9_-]{43}$/u.test(input.launchId)) throw new KernelStorageError('INVALID_REQUEST', 'worker preparation requires its exact logical intent');
  for (const digest of [input.spawnNonceDigest, input.activationNonceDigest, input.generationCreationNonceDigest]) assertArtifactRef(digest);
  const cut = await readRecoveryClosure(driver, artifacts, input.runId);
  let result: PreparingWorkerLaunch | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    const run = readRun(connection, input.runId);
    requireEqual(run, cut.run, 'worker preparation selected Run');
    if (run.revision !== input.expectedRunRevision || run.status !== 'queued' || run.activeWorkerLaunchId ||
        run.cancelRequested || run.stopIntentRef || now >= run.deadlineAt || run.nextStep !== 'agent' && run.nextStep !== 'tool')
      throw new KernelStorageError('LEASE_FENCED', 'worker preparation requires its unstopped productive queued cut');
    if (readWorkerLaunchesForRun(connection, run.id, true).length ||
        readWorkspaceGenerationsForRun(connection, run.id).some(value => value.phase !== 'retired' && value.phase !== 'sealed'))
      fail('worker preparation retains an original launch or unpaired generation');
    const checkpoint = readCheckpoint(connection, run.latestCheckpointId);
    requireEqual(checkpoint, cut.latestCheckpoint, 'worker preparation source Checkpoint');
    result = { schemaVersion: 1, launchId: input.launchId, runId: run.id, plannedRunRevision: run.revision,
      supervisorInstanceId: owner.supervisorInstanceId, spawnNonceDigest: input.spawnNonceDigest,
      activationNonceDigest: input.activationNonceDigest, phase: 'preparing', createdAt: now,
      activationDeadlineAt: addCanonicalDuration(now, 120_000), preparation: { stateOwnerEpoch: owner.ownerEpoch,
        sourceCheckpointId: checkpoint.id, sourceWorkspaceStateRef: checkpoint.workspaceStateRef,
        generationCreationNonceDigest: input.generationCreationNonceDigest,
        generationId: identityHash(run.id, checkpoint.id, checkpoint.workspaceStateRef, input.generationCreationNonceDigest) } };
    insertWorkerLaunch(connection, result);
  });
  if (!result) fail('worker preparation canonical time fence refused its logical intent');
  const retained = immutableSnapshot(result);
  preparationOwners.set(retained, { driver, owner });
  return retained;
}

/** The actual directory birth and materializing row commit together, before
 * copying. Stop may advance the Run revision, but cannot discard this birth. */
export async function recordWorkerPreparationGeneration(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { launchId: string; birth: RunWorkspaceBirth }): Promise<{
    generationRef: string; generationIdentityDigest: string; generation: Materializing;
  }> {
  const birth = readRunWorkspaceBirth(owner.filesystem, input.birth);
  const before = preparing(driver, owner, input.launchId);
  const authority = await publishRunWorkspaceBirthIdentity(owner.filesystem, artifacts, input.birth);
  const identity = decodeWorkspaceGenerationIdentity(await artifacts.readCanonical(authority.generationRef));
  const metadata = await artifacts.describe(authority.generationRef, 'application/json', identity.format);
  let result: Materializing | undefined;
  driver.transaction(connection => {
    const current = preparing(connection, owner, input.launchId);
    requireEqual(current, before, 'worker preparation before directory registration');
    bindableRun(connection, current);
    const observed = readRunWorkspaceBirth(owner.filesystem, input.birth), preparation = current.preparation;
    requireEqual(observed, birth, 'worker preparation original directory birth');
    if (preparation.generation || observed.generationId !== preparation.generationId || observed.runId !== current.runId ||
        observed.sourceCheckpointId !== preparation.sourceCheckpointId || observed.sourceWorkspaceStateRef !== preparation.sourceWorkspaceStateRef ||
        observed.creationNonceDigest !== preparation.generationCreationNonceDigest || observed.createdAt < current.createdAt ||
        observed.stateRootIdentity.identityDigest !== owner.stateRootIdentityDigest)
      fail('worker preparation directory birth differs from its immutable intent');
    const now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    if (observed.createdAt > now) fail('worker preparation birth registration time precedes physical creation');
    result = { schemaVersion: 1, generationId: identity.generationId, runId: identity.runId,
      generationRef: authority.generationRef, generationIdentityDigest: identity.identityDigest, rowVersion: 1,
      sourceCheckpointId: identity.sourceCheckpointId, sourceWorkspaceStateRef: identity.sourceWorkspaceStateRef,
      sourceWorkspaceStateDigest: identity.sourceWorkspaceStateDigest, lastVerifiedTreeDigest: identity.sourceTreeDigest,
      updatedAt: now, phase: 'materializing' };
    insertArtifactMetadata(connection, metadata, now);
    insertWorkspaceGeneration(connection, result);
    updateWorkerLaunch(connection, current, { ...current, preparation: { ...preparation, generation: authority } });
  });
  if (!result) fail('worker preparation canonical time fence refused its actual directory binding');
  return immutableSnapshot({ ...authority, generation: result });
}

export async function recordWorkerPreparationController(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { launchId: string; birth: NativeControllerPreparationBirth; reservation: HeldWorkerReservation }): Promise<PreparingWorkerLaunch> {
  let observed = readNativeControllerPreparationBirth(input.birth);
  const before = preparing(driver, owner, input.launchId);
  const borrowed = borrowWorkerReservationForExecution(input.reservation, before.launchId, before.spawnNonceDigest);
  try { borrowed.assertHeld(); } finally { borrowed.close(); }
  const birth: ControllerBirth = { schemaVersion: 1, format: 'cliq-controller-preparation-birth-v1',
    identity: observed.identity, birthDigest: observed.controllerBirthDigest };
  const artifact = await artifacts.publishCanonical(birth, birth.format);
  let result: PreparingWorkerLaunch | undefined;
  driver.transaction(connection => {
    const current = preparing(connection, owner, input.launchId);
    requireEqual(current, before, 'worker preparation controller registration');
    bindableRun(connection, current); input.reservation.assertHeld();
    observed = readNativeControllerPreparationBirth(input.birth);
    requireEqual(observed.identity, birth.identity, 'worker preparation original controller birth');
    if (!current.preparation.generation || current.preparation.controller || current.preparation.reservation ||
        observed.controllerBirthDigest !== birth.birthDigest || observed.identity.readyObservedAt < current.createdAt ||
        input.reservation.identity.ownerUid !== owner.filesystem.root.ownerUid)
      fail('worker preparation has an incomplete or substituted controller/reservation birth');
    const now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    if (observed.observedAt > now || parseCanonicalTime(now) - parseCanonicalTime(observed.observedAt) > 5000)
      fail('worker preparation controller registration requires its fresh original native observation');
    insertArtifactMetadata(connection, artifact, now);
    result = { ...current, preparation: { ...current.preparation,
      controller: { birthIdentityRef: artifact.ref, birthIdentityDigest: birth.birthDigest },
      reservation: { ...input.reservation.identity } } };
    updateWorkerLaunch(connection, current, result);
  });
  if (!result) fail('worker preparation canonical time fence refused controller registration');
  return immutableSnapshot(result);
}

/** Called only by the existing reservation transaction. The receipt's owner
 * reasserts the original durable native acknowledgement before authority grows. */
export function assertWorkerPreparationPromotion(connection: SqliteConnection | SqliteDriver, owner: StateOwnerContext,
  launch: PreparingWorkerLaunch, input: { runId: string; launchId: string; expectedRunRevision: number;
    workspaceGenerationRef: string; containmentPlanRef: string; sandboxLaunchSpecRef: string;
    spawnNonceDigest: string; activationNonceDigest: string }, binding: NativeWorkerReservationBinding | undefined): void {
  const current = preparing(connection, owner, launch.launchId);
  requireEqual(current, launch, 'worker preparation exact promotion');
  if (!binding) fail('worker preparation promotion requires the original native BIND acknowledgement');
  const observed = readNativeWorkerReservationBinding(binding);
  const preparation = launch.preparation;
  if (!preparation.generation || !preparation.controller || !preparation.reservation ||
      launch.plannedRunRevision !== input.expectedRunRevision || input.launchId !== launch.launchId || input.runId !== launch.runId ||
      input.spawnNonceDigest !== launch.spawnNonceDigest || input.activationNonceDigest !== launch.activationNonceDigest)
    fail('worker preparation promotion substitutes its original logical or physical identity');
  requireEqual(observed, { runId: launch.runId, launchId: launch.launchId,
    generationRef: input.workspaceGenerationRef, containmentPlanRef: input.containmentPlanRef,
    sandboxLaunchSpecRef: input.sandboxLaunchSpecRef, spawnNonceDigest: input.spawnNonceDigest,
    activationNonceDigest: input.activationNonceDigest, controllerBirthDigest: preparation.controller.birthIdentityDigest,
    reservation: preparation.reservation }, 'worker preparation real BIND closure');
  if (preparation.generation.generationRef !== input.workspaceGenerationRef)
    fail('worker preparation promotion substitutes its actual directory birth');
}

function controllerBirth(value: ControllerBirth): ControllerBirth {
  if (!exactKeys(value, ['schemaVersion', 'format', 'identity', 'birthDigest']) || value.schemaVersion !== 1 ||
      value.format !== 'cliq-controller-preparation-birth-v1' || !exactKeys(value.identity,
        ['rootPath', 'root', 'parent', 'leafName', 'leaf', 'pid', 'processStartToken', 'readyObservedAt']) ||
      canonicalSha256(value.identity) !== value.birthDigest) fail('worker preparation has no exact retained controller birth');
  assertArtifactRef(value.birthDigest);
  const identity = value.identity;
  if (!identity.rootPath.startsWith('/sys/fs/cgroup/') || identity.rootPath.includes('\0') || identity.rootPath.includes('\n') ||
      identity.rootPath.split('/').some(part => part === '.' || part === '..') || !/^controller-[0-9a-f]{32}$/u.test(identity.leafName) ||
      !Number.isSafeInteger(identity.pid) || identity.pid < 1 || !identity.processStartToken || identity.processStartToken.length > 128)
    fail('worker preparation retained controller path or lifetime is invalid');
  parseCanonicalTime(identity.readyObservedAt);
  for (const directory of [identity.root, identity.parent, identity.leaf]) {
    if (!exactKeys(directory, ['deviceId', 'fileId', 'ownerUid', 'ownerGid', 'mode']) ||
        !/^(0|[1-9][0-9]*)$/u.test(directory.deviceId) || !/^(0|[1-9][0-9]*)$/u.test(directory.fileId) ||
        ![directory.ownerUid, directory.ownerGid, directory.mode].every(value => Number.isSafeInteger(value) && value >= 0))
      fail('worker preparation retained controller directory identity is invalid');
  }
  return immutableSnapshot(value);
}

/** Retained birth data only. A live preparation must still belong to its
 * original active owner; owner loss never turns missing births into absence. */
export async function validateWorkerPreparationHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: { run: Run; launches: WorkerLaunch[]; generations: WorkspaceGenerationStateV1[] }): Promise<void> {
  for (const generation of input.generations) {
    if (generation.phase !== 'quarantined') continue;
    // The producer commits both monotone transitions in one transaction. Only
    // a retired row may reconstruct this source through its full owning proof;
    // a missing preparation launch must not make a current edge unowned.
    if (generation.observedState.kind === 'unverified_preparation')
      fail('unverified preparation cannot be a current quarantined generation');
    const quarantine = await readCanonicalArtifact<{ reason?: unknown }>(artifacts, generation.quarantineEvidenceRef);
    if (quarantine.reason === 'preparation_retired')
      fail('preparation quarantine requires its atomically committed retirement');
  }
  for (const launch of input.launches) {
    if (!launch.preparation) continue;
    decodeWorkerLaunch(launch);
    const preparation = launch.preparation, owner = readStateOwner(driver, preparation.stateOwnerEpoch);
    if (!owner || owner.supervisorInstanceId !== launch.supervisorInstanceId || owner.acquiredAt > launch.createdAt ||
        owner.state === 'terminal' && owner.releasedAt < launch.createdAt) fail('worker preparation has no original historical StateOwner');
    const checkpoint = readCheckpoint(driver, preparation.sourceCheckpointId);
    if (checkpoint.runId !== launch.runId || checkpoint.workspaceStateRef !== preparation.sourceWorkspaceStateRef ||
        checkpoint.basedOnRunRevision >= launch.plannedRunRevision || checkpoint.createdAt > launch.createdAt)
      fail('worker preparation substitutes its original ready Checkpoint');
    if (launch.phase === 'preparing' && (owner.state !== 'active' || input.run.status !== 'queued' ||
        input.run.activeWorkerLaunchId || input.run.latestCheckpointId !== preparation.sourceCheckpointId))
      fail('incomplete worker preparation requires its original live owner, not reconstructed birth facts');
    if (preparation.generation) {
      const identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, preparation.generation.generationRef));
      const generation = input.generations.find(value => value.generationId === preparation.generationId);
      if (!generation || identity.runId !== launch.runId || identity.generationId !== preparation.generationId ||
          identity.identityDigest !== preparation.generation.generationIdentityDigest ||
          generation.generationRef !== preparation.generation.generationRef || generation.generationIdentityDigest !== identity.identityDigest ||
          identity.sourceCheckpointId !== preparation.sourceCheckpointId || identity.sourceWorkspaceStateRef !== preparation.sourceWorkspaceStateRef ||
          identity.creationNonceDigest !== preparation.generationCreationNonceDigest || identity.createdAt < launch.createdAt)
        fail('worker preparation generation provenance is incomplete or substituted');
      if (launch.phase === 'preparing' && generation.phase !== 'materializing' && generation.phase !== 'preactivated_readonly')
        fail('preparing worker cannot own an executable or already retired generation');
    } else if (input.generations.some(value => value.generationId === preparation.generationId)) {
      fail('worker preparation directory row has no original atomic birth binding');
    }
    if (preparation.controller) {
      const birth = controllerBirth(await readCanonicalArtifact(artifacts, preparation.controller.birthIdentityRef));
      if (!preparation.generation || birth.birthDigest !== preparation.controller.birthIdentityDigest ||
          birth.identity.readyObservedAt < launch.createdAt) fail('worker preparation controller birth differs');
      if (launch.phase !== 'preparing' && launch.retirementKind !== 'preparation') {
        const { decodeWorkerContainmentPlan } = await import('./execution-closure.js');
        const plan = decodeWorkerContainmentPlan(await readCanonicalArtifact(artifacts, launch.containmentPlanRef));
        if (plan.backend.kind !== 'linux' || plan.backend.subreaperStartToken !==
            `linux-subreaper:${birth.identity.pid}:${birth.identity.processStartToken}` ||
            plan.backend.cgroupPath.slice(0, plan.backend.cgroupPath.lastIndexOf('/')) !== birth.identity.rootPath)
          fail('bound worker preparation substitutes its original controller');
        requireEqual(plan.backend.nativeReservation, preparation.reservation, 'bound worker preparation original reservation');
      }
    } else if (preparation.reservation) fail('worker preparation reservation has no original controller birth');
    if (launch.retirementKind === 'preparation') {
      await validateWorkerPreparationRetirement(driver, artifacts, launch, input.run, input.generations);
    }
  }
}

/** Joined originals only. The initial live producer object is not recovered
 * from its row, and absent birth records never mint an absence observation. */
export async function retireWorkerPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  preparation: PreparingWorkerLaunch; expectedRunRevision: number;
  controllerRetirement?: NativeControllerPreparationRetirement; reservation?: HeldWorkerReservation;
  brokerQuiescence: InstalledBrokerQuiescence;
} & ({ workspaceBirth: RunWorkspaceBirth; unallocatedWorkspace?: never } |
  { workspaceBirth?: never; unallocatedWorkspace: RunWorkspaceMaterialization })): Promise<RetiredWorkerPreparation> {
  const original = preparationOwners.get(input.preparation);
  if (!original || original.driver !== driver || original.owner !== owner)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'preparation retirement requires its original live producer');
  const launch = preparing(driver, owner, input.preparation.launchId), run = bindableRun(driver, launch);
  const { generation: _generationBirth, controller: _controllerBirth, reservation: _reservationBirth, ...logical } = launch.preparation;
  requireEqual({ ...launch, preparation: logical }, input.preparation, 'preparation retirement original live logical producer');
  if (run.revision !== input.expectedRunRevision) fail('preparation retirement lacks its exact stopping cut');
  if (!launch.preparation.generation) {
    if (!input.unallocatedWorkspace || input.workspaceBirth || input.controllerRetirement || input.reservation ||
        launch.preparation.controller || launch.preparation.reservation)
      fail('preparation retirement has no original unallocated producer or complete physical birth');
    return retireUnallocatedPreparation(driver, artifacts, owner, launch, run, input.unallocatedWorkspace, input.brokerQuiescence);
  }
  const workspaceBirth = input.workspaceBirth;
  if (!workspaceBirth || input.unallocatedWorkspace) fail('born preparation retirement requires its original joined workspace birth');
  const generation = readRequiredWorkspaceGeneration(driver, launch.preparation.generationId);
  if (generation.phase !== 'materializing' && generation.phase !== 'preactivated_readonly')
    fail('preparation retirement cannot substitute an activated or already retired generation');
  const identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, generation.generationRef));
  const cut = await readRecoveryClosure(driver, artifacts, run.id);
  requireEqual(cut.run, run, 'preparation retirement selected Run');
  const birth = launch.preparation.controller
    ? controllerBirth(await readCanonicalArtifact(artifacts, launch.preparation.controller.birthIdentityRef)) : undefined;
  const readResources = () => {
    assertActiveStateOwner(driver, owner);
    assertInstalledBrokerQuiescence(input.brokerQuiescence, driver, owner, run.id);
    const workspace = readRunWorkspaceBirthRetirement(owner.filesystem, workspaceBirth);
    if (workspace.generationId !== generation.generationId || workspace.runId !== run.id ||
        workspace.sourceCheckpointId !== launch.preparation.sourceCheckpointId ||
        workspace.creationNonceDigest !== launch.preparation.generationCreationNonceDigest ||
        workspace.directoryIdentity.deviceId !== (identity.locator.kind === 'linux_directory' ? identity.locator.deviceId : undefined) ||
        workspace.directoryIdentity.fileId !== (identity.locator.kind === 'linux_directory' ? identity.locator.directoryFileId : undefined))
      fail('preparation retirement substitutes its exact original joined directory birth');
    let controller: ReturnType<typeof readNativeControllerPreparationRetirement> | undefined;
    if (birth) {
      if (!input.controllerRetirement) fail('preparation retirement has no original controller join');
      controller = readNativeControllerPreparationRetirement(input.controllerRetirement);
      if (controller.controllerBirthDigest !== birth.birthDigest || controller.pid !== birth.identity.pid ||
          controller.processStartToken !== birth.identity.processStartToken)
        fail('preparation retirement substitutes its original native controller lifetime');
    } else if (input.controllerRetirement) fail('preparation retirement controller has no registered actual birth');
    let reservation: HeldWorkerReservation['identity'] | undefined;
    if (launch.preparation.reservation) {
      if (!input.reservation || !controller) fail('preparation retirement has no original reservation/controller closure');
      reservation = readWorkerReservationRetirement(owner.filesystem, input.reservation, launch.launchId, launch.spawnNonceDigest);
      requireEqual(reservation, launch.preparation.reservation, 'preparation retirement exact reservation birth');
    } else if (input.reservation) fail('preparation retirement reservation has no registered actual birth');
    return { workspace, controller, reservation };
  };
  readResources();
  const move = owner.filesystem.quarantineGeneration(identity, generation.rowVersion);
  const resources = readResources(), observedAt = sampleCanonicalNow();
  for (const timestamp of [resources.workspace.observedAt, ...(resources.controller ? [resources.controller.observedAt] : [])]) {
    if (timestamp > observedAt || parseCanonicalTime(observedAt) - parseCanonicalTime(timestamp) > 5000)
      fail('preparation retirement native joins are not fresh');
  }
  const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const evidence: BornPreparationRetirement = { schemaVersion: 1, format: 'cliq-worker-preparation-retirement-evidence-v1', kind: 'born',
    launch, sourceGeneration: generation, workspaceRetirementObservedAt: resources.workspace.observedAt,
    ...(resources.controller ? { controllerRetirement: resources.controller } : {}),
    ...(resources.reservation ? { reservationRetirement: resources.reservation } : {}), quarantineMove: move,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt, evidenceDigest: '' };
  const closedEvidence = { ...evidence, evidenceDigest: digestOmitting(evidence, 'evidenceDigest') };
  const proof = await artifacts.publishCanonical(closedEvidence, evidence.format);
  const quarantine: PreparationQuarantine = { schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1',
    runId: run.id, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    sourceRowVersion: generation.rowVersion, observedState: { kind: 'unverified_preparation' },
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, ...move,
    observedAt, evidenceDigest: '', reason: 'preparation_retired', fromPhase: generation.phase, workerLaunchId: launch.launchId,
    preparationRetirementEvidenceRef: proof.ref, preparationRetirementEvidenceDigest: closedEvidence.evidenceDigest };
  quarantine.evidenceDigest = digestOmitting(quarantine, 'evidenceDigest');
  const quarantineArtifact = await artifacts.publishCanonical(quarantine, quarantine.format);
  const retirement: WorkspaceGenerationRetirementEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-retirement-evidence-v1',
    runId: run.id, generationRef: generation.generationRef, generationIdentityDigest: generation.generationIdentityDigest,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt, evidenceDigest: '',
    fromPhase: 'quarantined', quarantineEvidenceRef: quarantineArtifact.ref, quarantineEvidenceDigest: quarantine.evidenceDigest,
    sourceQuarantinedRowVersion: generation.rowVersion + 1, activeRunPointerCount: 0, nonretiredWorkerLaunchCount: 0,
    liveContainmentCount: 0, activeMountCount: 0, releasableBrokerClaimCount: 0 };
  retirement.evidenceDigest = digestOmitting(retirement, 'evidenceDigest');
  const retirementArtifact = await artifacts.publishCanonical(retirement, retirement.format);
  let result: RetiredWorkerPreparation | undefined;
  driver.transaction(connection => {
    requireEqual(preparing(connection, owner, launch.launchId), launch, 'preparation retirement original lifecycle');
    requireEqual(bindableRun(connection, launch), run, 'preparation retirement current Run');
    requireEqual(readRequiredWorkspaceGeneration(connection, generation.generationId), generation, 'preparation retirement original generation');
    const fresh = readResources(), now = sampleCanonicalNow();
    const moved = owner.filesystem.quarantineGeneration(identity, generation.rowVersion);
    requireEqual(moved, move, 'preparation retirement exact native quarantine');
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    if (now < observedAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000 ||
        fresh.workspace.observedAt > now || fresh.controller && fresh.controller.observedAt > now)
      fail('preparation retirement lost its fresh native commit cut');
    const otherLaunches = readWorkerLaunchesForRun(connection, run.id, true).filter(value => value.launchId !== launch.launchId);
    if (otherLaunches.length || connection.prepare('SELECT 1 FROM runs WHERE active_worker_launch_id = ? LIMIT 1').get(launch.launchId))
      fail('preparation retirement still has another original active launch pointer');
    for (const artifact of [inspectorArtifact, proof, quarantineArtifact, retirementArtifact]) insertArtifactMetadata(connection, artifact, now);
    result = { ...launch, phase: 'retired', retirementKind: 'preparation', retiredAt: now, retirementEvidenceRef: proof.ref };
    updateWorkerLaunch(connection, launch, result);
    const { snapshotEvidenceRef: _snapshot, snapshotEvidenceDigest: _snapshotDigest, ...base } = generation;
    const quarantined: Extract<WorkspaceGenerationStateV1, { phase: 'quarantined' }> = {
      ...base, rowVersion: generation.rowVersion + 1, updatedAt: now, phase: 'quarantined',
      quarantineEvidenceRef: quarantineArtifact.ref, quarantineEvidenceDigest: quarantine.evidenceDigest,
      observedState: quarantine.observedState };
    updateWorkspaceGeneration(connection, generation, quarantined);
    const retired: RetiredGeneration = { ...base, phase: 'retired', rowVersion: generation.rowVersion + 2, updatedAt: now,
      retirementEvidenceRef: retirementArtifact.ref, retirementEvidenceDigest: retirement.evidenceDigest };
    updateWorkspaceGeneration(connection, quarantined, retired);
  });
  if (!result) fail('preparation retirement canonical time fence refused publication');
  return immutableSnapshot(result);
}

async function retireUnallocatedPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  launch: PreparingWorkerLaunch, run: Run, workspace: RunWorkspaceMaterialization,
  broker: InstalledBrokerQuiescence): Promise<RetiredWorkerPreparation> {
  const readResources = () => {
    assertActiveStateOwner(driver, owner); assertInstalledBrokerQuiescence(broker, driver, owner, run.id);
    const observed = readUnallocatedRunWorkspaceRetirement(owner.filesystem, workspace);
    const { observedAt: _observedAt, ...body } = observed;
    requireEqual(body, { runId: run.id, generationId: launch.preparation.generationId,
      sourceCheckpointId: launch.preparation.sourceCheckpointId, sourceWorkspaceStateRef: launch.preparation.sourceWorkspaceStateRef,
      creationNonceDigest: launch.preparation.generationCreationNonceDigest, allocationRequested: false,
      operationsJoined: true }, 'preparation exact original unallocated producer');
    if (readWorkspaceGenerationsForRun(driver, run.id).some(value => value.generationId === launch.preparation.generationId))
      fail('unallocated preparation has an actual generation row');
    return observed;
  };
  const resources = readResources(), observedAt = sampleCanonicalNow();
  if (resources.observedAt > observedAt || parseCanonicalTime(observedAt) - parseCanonicalTime(resources.observedAt) > 5000)
    fail('unallocated preparation has no fresh original joined cut');
  const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const core: UnallocatedPreparationRetirement = { schemaVersion: 1, format: 'cliq-worker-preparation-retirement-evidence-v1', kind: 'unallocated',
    launch, workspaceRetirement: resources, inspectorIdentityRef: inspectorArtifact.ref,
    inspectorIdentityDigest: inspector.identityDigest, observedAt, evidenceDigest: '' };
  const evidence = { ...core, evidenceDigest: digestOmitting(core, 'evidenceDigest') };
  const artifact = await artifacts.publishCanonical(evidence, evidence.format);
  let result: RetiredWorkerPreparation | undefined;
  driver.transaction(connection => {
    requireEqual(preparing(connection, owner, launch.launchId), launch, 'unallocated preparation original lifecycle');
    requireEqual(bindableRun(connection, launch), run, 'unallocated preparation current Run');
    const fresh = readResources(), now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    if (now < observedAt || parseCanonicalTime(now) - parseCanonicalTime(observedAt) > 5000 || fresh.observedAt > now)
      fail('unallocated preparation closure is no longer fresh');
    for (const value of [inspectorArtifact, artifact]) insertArtifactMetadata(connection, value, now);
    result = { ...launch, phase: 'retired', retirementKind: 'preparation', retiredAt: now, retirementEvidenceRef: artifact.ref };
    updateWorkerLaunch(connection, launch, result);
  });
  if (!result) fail('unallocated preparation canonical time fence refused publication');
  return immutableSnapshot(result);
}

async function validateUnallocatedPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, launch: RetiredWorkerPreparation,
  run: Run, generations: WorkspaceGenerationStateV1[], evidence: UnallocatedPreparationRetirement): Promise<UnallocatedPreparationRetirement> {
  if (!exactKeys(evidence, ['schemaVersion', 'format', 'kind', 'launch', 'workspaceRetirement',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest']) || evidence.schemaVersion !== 1 ||
      evidence.format !== 'cliq-worker-preparation-retirement-evidence-v1' || evidence.kind !== 'unallocated' ||
      evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest')) fail('unallocated preparation retirement is not closed');
  const original = decodeWorkerLaunch(evidence.launch);
  if (original.phase !== 'preparing' || launch.preparation.generation || launch.preparation.controller || launch.preparation.reservation ||
      launch.runId !== run.id || generations.some(value => value.generationId === launch.preparation.generationId))
    fail('unallocated preparation cannot substitute an observed physical birth');
  const { phase: _phase, retirementKind: _kind, retiredAt, retirementEvidenceRef: _ref, ...base } = launch;
  requireEqual(original, { ...base, phase: 'preparing' }, 'unallocated preparation original nonexecuting lifecycle');
  const observed = evidence.workspaceRetirement;
  requireEqual(observed, { runId: run.id, generationId: launch.preparation.generationId,
    sourceCheckpointId: launch.preparation.sourceCheckpointId, sourceWorkspaceStateRef: launch.preparation.sourceWorkspaceStateRef,
    creationNonceDigest: launch.preparation.generationCreationNonceDigest, allocationRequested: false, operationsJoined: true,
    observedAt: observed.observedAt }, 'unallocated preparation exact joined program-domain closure');
  for (const time of [observed.observedAt, evidence.observedAt, retiredAt]) parseCanonicalTime(time);
  if (observed.observedAt < launch.createdAt || observed.observedAt > evidence.observedAt || evidence.observedAt > retiredAt ||
      parseCanonicalTime(evidence.observedAt) - parseCanonicalTime(observed.observedAt) > 5000 ||
      parseCanonicalTime(retiredAt) - parseCanonicalTime(evidence.observedAt) > 5000)
    fail('unallocated preparation has no causal original joined commit cut');
  const owner = readStateOwner(driver, launch.preparation.stateOwnerEpoch);
  if (!owner || owner.supervisorInstanceId !== launch.supervisorInstanceId || owner.acquiredAt > evidence.observedAt ||
      owner.state === 'terminal' && owner.releasedAt < retiredAt) fail('unallocated preparation lost its original inspector owner');
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  await readSupervisorInspector(artifacts, owner, assembly, evidence);
  return immutableSnapshot(evidence);
}

/** Full retained consumer of the preparation producer. Data here never mints
 * a live owner, a BIND acknowledgement or a native retirement capability. */
export async function validateWorkerPreparationRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  launch: RetiredWorkerPreparation, run: Run, generations: WorkspaceGenerationStateV1[]): Promise<PreparationRetirement> {
  const value = await readCanonicalArtifact<PreparationRetirement>(artifacts, launch.retirementEvidenceRef);
  if (value.kind === 'unallocated') return validateUnallocatedPreparation(driver, artifacts, launch, run, generations, value);
  const proof = value;
  const fields = ['schemaVersion', 'format', 'kind', 'launch', 'sourceGeneration', 'workspaceRetirementObservedAt', 'quarantineMove',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest',
    ...(launch.preparation.controller ? ['controllerRetirement'] : []), ...(launch.preparation.reservation ? ['reservationRetirement'] : [])];
  if (!exactKeys(proof, fields) || proof.schemaVersion !== 1 || proof.kind !== 'born' || proof.format !== 'cliq-worker-preparation-retirement-evidence-v1' ||
      proof.evidenceDigest !== digestOmitting(proof, 'evidenceDigest')) fail('preparation retirement proof is not a complete closed original');
  const original = decodeWorkerLaunch(proof.launch);
  if (original.phase !== 'preparing') fail('preparation retirement substitutes an executable worker phase');
  const { phase: _phase, retiredAt, retirementKind: _kind, retirementEvidenceRef: _ref, ...base } = launch;
  requireEqual(original, { ...base, phase: 'preparing' }, 'preparation retirement original lifecycle');
  const source = decodeWorkspaceGenerationState(proof.sourceGeneration);
  if (source.phase !== 'materializing' && source.phase !== 'preactivated_readonly') fail('preparation retirement has an executable source generation');
  const generation = generations.find(value => value.generationId === source.generationId);
  if (!generation || generation.phase !== 'retired' || source.runId !== run.id || launch.runId !== run.id ||
      source.generationId !== launch.preparation.generationId || !launch.preparation.generation ||
      source.generationRef !== launch.preparation.generation.generationRef ||
      source.generationIdentityDigest !== launch.preparation.generation.generationIdentityDigest ||
      generation.rowVersion !== source.rowVersion + 2 || generation.updatedAt !== retiredAt || proof.observedAt > retiredAt ||
      parseCanonicalTime(retiredAt) - parseCanonicalTime(proof.observedAt) > 5000)
    fail('preparation retirement substitutes its exact generation or committed cut');
  const owner = readStateOwner(driver, launch.preparation.stateOwnerEpoch);
  if (!owner || owner.supervisorInstanceId !== launch.supervisorInstanceId || owner.acquiredAt > proof.observedAt ||
      owner.state === 'terminal' && owner.releasedAt < retiredAt) fail('preparation retirement has no owning original StateOwner');
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  const inspector = await readSupervisorInspector(artifacts, owner, assembly, proof);
  if (inspector.stateOwnerEpoch !== launch.preparation.stateOwnerEpoch) fail('preparation retirement substitutes its original inspector');
  const identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, source.generationRef));
  if (identity.locator.kind !== 'linux_directory') fail('preparation retirement requires its implemented Linux directory source');
  if (identity.generationId !== original.preparation.generationId || identity.runId !== original.runId ||
      identity.creationNonceDigest !== original.preparation.generationCreationNonceDigest ||
      identity.sourceCheckpointId !== original.preparation.sourceCheckpointId ||
      identity.sourceWorkspaceStateRef !== original.preparation.sourceWorkspaceStateRef ||
      identity.identityDigest !== source.generationIdentityDigest || identity.createdAt < original.createdAt)
    fail('preparation retirement birth differs from its original intent and generation identity');
  const { snapshotEvidenceRef: _snapshot, snapshotEvidenceDigest: _snapshotDigest, ...sourceBase } = source;
  requireEqual(generation, { ...sourceBase, phase: 'retired', rowVersion: source.rowVersion + 2, updatedAt: retiredAt,
    retirementEvidenceRef: generation.retirementEvidenceRef, retirementEvidenceDigest: generation.retirementEvidenceDigest },
  'preparation retirement exact original generation transition');
  requireEqual(proof.quarantineMove, { quarantineCanonicalRootRelativePath:
    `quarantine/workspace-generations/${identityHash(source.generationId, String(source.rowVersion))}`,
    quarantineDeviceId: identity.locator.deviceId, quarantineFileId: identity.locator.directoryFileId,
    originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true }, 'preparation retirement exact quarantine anchor');
  for (const observed of [proof.workspaceRetirementObservedAt, ...(proof.controllerRetirement ? [proof.controllerRetirement.observedAt] : [])]) {
    if (observed < original.createdAt || observed > proof.observedAt || parseCanonicalTime(proof.observedAt) - parseCanonicalTime(observed) > 5000)
      fail('preparation retirement retained native observations are not causal and fresh');
  }
  if (original.preparation.controller) {
    const birth = controllerBirth(await readCanonicalArtifact(artifacts, original.preparation.controller.birthIdentityRef));
    const native = proof.controllerRetirement!;
    requireEqual(native, { pid: birth.identity.pid, processStartToken: birth.identity.processStartToken,
      controllerBirthDigest: birth.birthDigest, observedAt: native.observedAt, controllerJoined: true,
      controllerLeafAbsent: true, workerCreationRequested: false, liveContainmentCount: 0, activeMountCount: 0 },
    'preparation retirement complete original controller closure');
  }
  if (original.preparation.reservation) requireEqual(proof.reservationRetirement, original.preparation.reservation,
    'preparation retirement complete original reservation closure');
  if (source.phase === 'preactivated_readonly') {
    const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, source.snapshotEvidenceRef));
    const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, source.sourceWorkspaceStateRef));
    const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, state.entriesRef));
    if (snapshot.evidenceDigest !== source.snapshotEvidenceDigest || snapshot.purpose !== 'materialized_from_checkpoint' ||
        snapshot.runId !== run.id || snapshot.generationRef !== source.generationRef ||
        snapshot.generationIdentityDigest !== source.generationIdentityDigest || snapshot.checkpointId !== source.sourceCheckpointId ||
        snapshot.workspaceStateRef !== source.sourceWorkspaceStateRef || snapshot.workspaceStateDigest !== source.sourceWorkspaceStateDigest ||
        snapshot.workspaceStateDigest !== state.stateDigest || snapshot.entriesRef !== state.entriesRef ||
        snapshot.privateGitStateRef !== state.privateGitStateRef || snapshot.treeDigest !== entries.treeDigest ||
        snapshot.treeDigest !== source.lastVerifiedTreeDigest) fail('preparation retirement substitutes its original readonly snapshot');
  }
  const retirement = await readCanonicalArtifact<WorkspaceGenerationRetirementEvidenceV1>(artifacts, generation.retirementEvidenceRef);
  if (retirement.fromPhase !== 'quarantined' || retirement.evidenceDigest !== generation.retirementEvidenceDigest ||
      retirement.evidenceDigest !== digestOmitting(retirement, 'evidenceDigest')) fail('preparation retirement lost its generation retirement closure');
  const quarantine = await readCanonicalArtifact<PreparationQuarantine>(artifacts, retirement.quarantineEvidenceRef);
  requireEqual(retirement, { schemaVersion: 1, format: 'cliq-workspace-generation-retirement-evidence-v1',
    runId: run.id, generationRef: source.generationRef, generationIdentityDigest: source.generationIdentityDigest,
    inspectorIdentityRef: proof.inspectorIdentityRef, inspectorIdentityDigest: proof.inspectorIdentityDigest,
    observedAt: proof.observedAt, evidenceDigest: retirement.evidenceDigest, fromPhase: 'quarantined',
    quarantineEvidenceRef: retirement.quarantineEvidenceRef, quarantineEvidenceDigest: quarantine.evidenceDigest,
    sourceQuarantinedRowVersion: source.rowVersion + 1, activeRunPointerCount: 0, nonretiredWorkerLaunchCount: 0,
    liveContainmentCount: 0, activeMountCount: 0, releasableBrokerClaimCount: 0 }, 'preparation retirement complete generation zero cut');
  const expected: PreparationQuarantine = { schemaVersion: 1, format: 'cliq-workspace-generation-quarantine-evidence-v1',
    runId: run.id, generationRef: source.generationRef, generationIdentityDigest: source.generationIdentityDigest,
    sourceRowVersion: source.rowVersion, observedState: { kind: 'unverified_preparation' },
    inspectorIdentityRef: proof.inspectorIdentityRef, inspectorIdentityDigest: proof.inspectorIdentityDigest,
    ...proof.quarantineMove, observedAt: proof.observedAt, evidenceDigest: quarantine.evidenceDigest,
    reason: 'preparation_retired', fromPhase: source.phase, workerLaunchId: launch.launchId,
    preparationRetirementEvidenceRef: launch.retirementEvidenceRef, preparationRetirementEvidenceDigest: proof.evidenceDigest };
  requireEqual(quarantine, expected, 'preparation retirement exact closed quarantine');
  if (quarantine.evidenceDigest !== digestOmitting(quarantine, 'evidenceDigest')) fail('preparation quarantine digest differs');
  return immutableSnapshot(proof);
}
