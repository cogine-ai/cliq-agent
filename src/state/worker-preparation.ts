import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { PreparingWorkerLaunch, RetiredWorkerPreparation, Run, RunAssemblyV1, RunFrontier, WorkerLaunch,
  WorkspaceGenerationQuarantineEvidenceV1, WorkspaceGenerationRetirementEvidenceV1, WorkspaceGenerationStateV1, RecoveryClosureV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readNativeControllerPreparationBirth, readNativeControllerPreparationRetirement, readNativeWorkerReservationBinding,
  readNativeRetainedPreparingGitRetirement, assertLinuxWorkerController,
  type NativePreparingGitRecipe, type NativeRetainedPreparingGitRetirement, type LinuxWorkerController,
  type NativeControllerPreparationBirth, type NativeControllerPreparationRetirement, type NativeWorkerReservationBinding } from '../sandbox/linux-worker.js';
import { publishRunWorkspaceBirthIdentity, readRunWorkspaceBirth, readRunWorkspaceBirthRetirement, readRunWorkspacePreparingGit,
  readUnallocatedRunWorkspaceRetirement, type RunWorkspaceBirth, type RunWorkspaceMaterialization,
  type UnallocatedRunWorkspaceRetirement } from '../workspace/run-workspace/generation.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { decodeRunSpec, decodeWorkspaceEntries, decodeWorkspaceGenerationIdentity, decodeWorkspaceGenerationSnapshotEvidence,
  decodeWorkspaceState, decodeStateOwnerRecord, decodePlatformProcessIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { readPublicationPrefix } from './delivery-publication-progress.js';
import { decodeWorkerLaunch, decodeWorkspaceGenerationState } from './invariants.js';
import { borrowWorkerReservationForExecution, readWorkerReservationRetirement, type GenerationQuarantineMove,
  type HeldWorkerReservation, type HeldRetainedPreparingGitInput, stateRootIdentityForLock,
  openRetainedPreparingGitInput, assertRetainedPreparingGitInputOwner } from './native-owner.js';
import { readRecoveryClosure, readPreparingCleanupClosure } from './recovery-closure.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { insertWorkerLaunch, readRequiredWorkerLaunch, readWorkerLaunchesForRun, updateWorkerLaunch } from './repositories/worker-launches.js';
import { insertWorkspaceGeneration, readRequiredWorkspaceGeneration, readWorkspaceGenerationsForRun,
  updateWorkspaceGeneration } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertInstalledBrokerQuiescence, type InstalledBrokerQuiescence } from './store.js';
import { readSupervisorInspector, supervisorInspectorIdentity } from './supervisor-inspector.js';
import { readVerifierProgress } from './verifier-recovery.js';
import { stopInvocationHistory } from '../runtime/stop.js';
import { readPrivateGitData, privateGitInspectionOutput } from '../workspace/private-git-data.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { decodeSourceManifest } from './decoders.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { observeRetainedPreparingGeneration, readRetainedPreparingGenerationRetirement,
  type RetainedPreparingGenerationRetirementData } from '../workspace/run-workspace/preparation-retirement.js';

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
type PreparingNativeRetirementData = Readonly<{
  observation: ReturnType<typeof readNativeRetainedPreparingGitRetirement>['observation'];
  input: HeldRetainedPreparingGitInput['identity']; recipe: NativePreparingGitRecipe;
  checker: ReturnType<typeof readNativeRetainedPreparingGitRetirement>['checker']; checkerBirth: ControllerBirth;
}>;
type CurrentCheckerPreparationRetirement = Omit<BornPreparationRetirement,
  'kind' | 'workspaceRetirementObservedAt' | 'controllerRetirement' | 'reservationRetirement'> & Readonly<{
  kind: 'born_current_checker'; workspaceRetirement: RetainedPreparingGenerationRetirementData;
  nativeRetirement: PreparingNativeRetirementData; reservationRetirement: HeldWorkerReservation['identity'];
  ownerDeathAcquisitionEvidenceRef: string; ownerDeathAcquisitionEvidenceDigest: string;
}>;
type PreparationRetirement = BornPreparationRetirement | CurrentCheckerPreparationRetirement | UnallocatedPreparationRetirement;
const preparationOwners = new WeakMap<PreparingWorkerLaunch, { driver: SqliteDriver; owner: StateOwnerContext }>();
function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** A read-only exception for one dead preparation owner. This never adopts a
 * producer, activates a generation, or supplies retirement authority. */
declare const workerPreparationCleanupContextBrand: unique symbol;
export type WorkerPreparationCleanupContext = Readonly<{ [workerPreparationCleanupContextBrand]: true }>;
type PreparationOwnerDeath = Awaited<ReturnType<typeof readStateOwnerDeath>>;
const cleanupContexts = new WeakMap<WorkerPreparationCleanupContext, {
  driver: SqliteDriver; owner: StateOwnerContext; launch: PreparingWorkerLaunch;
  death: PreparationOwnerDeath; originalStateOwnerRowDigest: string;
  ownerIdentity: ReturnType<typeof cleanupOwnerIdentity>; filesystem: StateOwnerContext['filesystem'];
  cut?: RecoveryClosureV1; generation?: PreparationGeneration; identity?: ReturnType<typeof decodeWorkspaceGenerationIdentity>;
  originalController?: ControllerBirth; recipe?: NativePreparingGitRecipe; retirementStarted?: boolean;
}>();

function cleanupOwnerIdentity(owner: StateOwnerContext) {
  const { filesystem: _filesystem, ...identity } = owner; return immutableSnapshot(identity);
}
function cleanupOwner(driver: SqliteDriver, owner: StateOwnerContext): void {
  // An arbitrary structural assertHeld callback cannot create this context.
  const root = stateRootIdentityForLock(owner.filesystem);
  if (canonicalSha256(root) !== owner.stateRootIdentityRef || root.identityDigest !== owner.stateRootIdentityDigest)
    fail('preparation cleanup substitutes its genuine StateRoot owner');
  assertActiveStateOwner(driver, owner);
}

export function assertWorkerPreparationCleanupContext(driver: SqliteDriver, context: WorkerPreparationCleanupContext, runId: string): void {
  const held = cleanupContexts.get(context);
  if (!held || held.driver !== driver || held.launch.runId !== runId) throw new TypeError('preparation cleanup requires its genuine read-only inspection context');
  if (held.owner.filesystem !== held.filesystem) fail('preparation cleanup substitutes its physical owner');
  requireEqual(cleanupOwnerIdentity(held.owner), held.ownerIdentity, 'preparation cleanup inspecting StateOwner');
  cleanupOwner(driver, held.owner);
  requireEqual(readRequiredWorkerLaunch(driver, held.launch.launchId), held.launch, 'preparation cleanup exact original lifecycle');
  requireEqual(readStateOwner(driver, held.death.priorOwner.ownerEpoch), held.death.priorOwner, 'preparation cleanup original dead StateOwner');
  const run = bindableRun(driver, held.launch);
  if (run.id !== runId || held.owner.ownerEpoch < held.death.successorOwner.ownerEpoch)
    fail('preparation cleanup lacks its current successor owner');
}

export async function openWorkerPreparationCleanupContext(driver: SqliteDriver, artifacts: ArtifactCatalog,
  owner: StateOwnerContext, launchId: string): Promise<WorkerPreparationCleanupContext> {
  cleanupOwner(driver, owner);
  const ownerIdentity = cleanupOwnerIdentity(owner), filesystem = owner.filesystem;
  const launch = readRequiredWorkerLaunch(driver, launchId);
  if (launch.phase !== 'preparing' || launch.supervisorInstanceId === owner.supervisorInstanceId ||
      launch.preparation.stateOwnerEpoch >= owner.ownerEpoch) fail('preparation cleanup requires an exact earlier nonexecuting owner');
  bindableRun(driver, launch);
  const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: launch.supervisorInstanceId, ownedAt: launch.createdAt });
  if (death.priorOwner.ownerEpoch !== launch.preparation.stateOwnerEpoch || owner.ownerEpoch < death.successorOwner.ownerEpoch)
    fail('preparation cleanup death closure names another original owner');
  // Terminalization only appends these exact fields to the immutable active
  // row. Reconstruct its canonical digest as inert native-prefix data; never
  // create a StateOwnerContext or write an active row for this dead process.
  const { releasedAt: _released, terminalReason: _reason, transitionEvidenceRef: _transition,
    transitionEvidenceDigest: _transitionDigest, ...base } = death.priorOwner;
  const prior = { ...base, state: 'active' as const, rowVersion: 1 as const, rowDigest: '' };
  prior.rowDigest = digestOmitting(prior, 'rowDigest'); decodeStateOwnerRecord(prior);
  const context = Object.freeze({}) as WorkerPreparationCleanupContext;
  cleanupContexts.set(context, { driver, owner, launch: immutableSnapshot(launch), death: immutableSnapshot(death),
    originalStateOwnerRowDigest: prior.rowDigest, ownerIdentity, filesystem });
  assertWorkerPreparationCleanupContext(driver, context, launch.runId);
  // Retain the one complete read cut for this same retirement operation. This
  // is neither cached image verification nor permission to repeat an attempt.
  const cut = await readPreparingCleanupClosure(driver, artifacts, launch.runId, context);
  requireEqual(bindableRun(driver, launch), cut.run, 'preparation cleanup inspected Run');
  const held = cleanupContexts.get(context)!; held.cut = immutableSnapshot(cut);
  if (launch.preparation.generation) {
    const generation = readRequiredWorkspaceGeneration(driver, launch.preparation.generationId);
    if (generation.phase !== 'materializing' && generation.phase !== 'preactivated_readonly') fail('preparation cleanup generation became executable');
    held.generation = immutableSnapshot(generation);
    held.identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, generation.generationRef));
  }
  if (launch.preparation.controller)
    held.originalController = controllerBirth(await readCanonicalArtifact(artifacts, launch.preparation.controller.birthIdentityRef));
  if (launch.preparation.controller?.privateGitInputRef) {
    const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, launch.preparation.sourceWorkspaceStateRef));
    const baseSource = decodeSourceManifest(await readCanonicalArtifact(artifacts, state.baseWorkspaceManifestRef));
    const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, cut.runSpec.sandboxProfileRef));
    if (!baseSource.git || !state.privateGitStateRef) fail('preparing cleanup lost its frozen Git source');
    held.recipe = immutableSnapshot({ ...profile.resources, stateOwnerEpoch: launch.preparation.stateOwnerEpoch,
      supervisorInstanceId: launch.supervisorInstanceId, stateOwnerRowDigest: held.originalStateOwnerRowDigest,
      sessionId: cut.run.sessionId, sourceCheckpointId: launch.preparation.sourceCheckpointId,
      sourceWorkspaceStateRef: launch.preparation.sourceWorkspaceStateRef, repositoryIdentityDigest: baseSource.git.repositoryIdentityDigest });
  }
  assertWorkerPreparationCleanupContext(driver, context, launch.runId); return context;
}

/** Closed data from the genuine inspection, not an original producer or a
 * successor execution/retirement token. */
export function readWorkerPreparationCleanupTarget(driver: SqliteDriver, owner: StateOwnerContext,
  context: WorkerPreparationCleanupContext) {
  const held = cleanupContexts.get(context);
  if (!held || held.owner !== owner) throw new TypeError('preparation cleanup inspection belongs to another physical owner');
  assertWorkerPreparationCleanupContext(driver, context, held.launch.runId);
  if (!held.cut) fail('preparation cleanup complete retained read has not joined');
  return Object.freeze({ launch: held.launch, death: held.death, originalStateOwnerRowDigest: held.originalStateOwnerRowDigest,
    cut: held.cut, generation: held.generation, identity: held.identity, originalController: held.originalController, recipe: held.recipe });
}

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
/** Fresh original-owner cut before each preparation authority increase. A
 * regressed clock remains committed even though no native action is allowed. */
export function assertWorkerPreparationRelease(driver: SqliteDriver, owner: StateOwnerContext, launchId: string): PreparingWorkerLaunch {
  let result: PreparingWorkerLaunch | undefined;
  driver.transaction(connection => {
    const launch = preparing(connection, owner, launchId), run = bindableRun(connection, launch), now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    if (run.cancelRequested || run.stopIntentRef || now >= run.deadlineAt || now >= launch.activationDeadlineAt)
      fail('worker preparation cannot release after cancellation or its original deadline');
    if (!launch.preparation.generation || !launch.preparation.controller || !launch.preparation.reservation)
      fail('worker preparation release requires all original registered resource births');
    result = launch;
  });
  if (!result) fail('worker preparation canonical time fence refused release');
  return result;
}

// This is only a same-transaction SQL snapshot. It does not replace the full
// retained readers or authorize a physical birth from structural CAS data.
function preparationSqlCut(connection: SqliteConnection, runId: string) {
  const run = readRun(connection, runId);
  return { run, checkpoint: readCheckpoint(connection, run.latestCheckpointId), session: readSession(connection, run.sessionId),
    principalId: readSessionPrincipalId(connection, run.sessionId),
    admission: connection.prepare(`SELECT principal_id,admission_method,admission_key,admission_intent_digest,
      admitted_request_digest,admission_request_id FROM runs WHERE id=?`).get(runId),
    journal: readInvocationJournal(connection, runId), launches: readWorkerLaunchesForRun(connection, runId),
    generations: readWorkspaceGenerationsForRun(connection, runId),
    items: connection.prepare('SELECT item_id,session_id,run_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
      .all<{ item_id: string; session_id: string | null; run_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(runId)
      .map(row => ({ ...row, item_seq: Number(row.item_seq) })),
    childAllocations: readChildAllocationsForRun(connection, runId),
    children: connection.prepare('SELECT id FROM runs WHERE parent_run_id=? ORDER BY id').all<{ id: string }>(runId) };
}

export async function beginWorkerPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  runId: string; expectedRunRevision: number; launchId: string; spawnNonceDigest: string;
  activationNonceDigest: string; generationCreationNonceDigest: string;
}): Promise<PreparingWorkerLaunch> {
  input = immutableSnapshot(input);
  if (!exactKeys(input, ['runId', 'expectedRunRevision', 'launchId', 'spawnNonceDigest', 'activationNonceDigest', 'generationCreationNonceDigest']) ||
      !/^[A-Za-z0-9_-]{43}$/u.test(input.launchId)) throw new KernelStorageError('INVALID_REQUEST', 'worker preparation requires its exact logical intent');
  for (const digest of [input.spawnNonceDigest, input.activationNonceDigest, input.generationCreationNonceDigest]) assertArtifactRef(digest);
  const original = driver.readSnapshot(connection => preparationSqlCut(connection, input.runId));
  const cut = await readRecoveryClosure(driver, artifacts, input.runId);
  const verifier = cut.run.nextStep === 'verify' ? await readVerifierProgress(driver, artifacts, cut) : undefined;
  if (verifier && (verifier.complete || [...stopInvocationHistory(cut.journal).values()].some(({ entry }) =>
    entry.opKind === 'verifier' && entry.phase !== 'completed' && entry.phase !== 'failed')))
    fail('verifier worker preparation cannot overtake a complete plan or unsettled original invocation');
  const delivery = cut.run.nextStep === 'delivery' && cut.runSpec.operation === 'delivery'
    ? await readPublicationPrefix(driver, artifacts, cut) : undefined;
  let source: ReturnType<typeof preparationSqlCut> | undefined;
  if (delivery) {
    const authorization = delivery.authorization;
    if (!authorization?.grant || !authorization.grantRef || authorization.decision.decision !== 'allow' ||
        delivery.abort.length || delivery.abortResults.length || delivery.forward.length >= authorization.context.plan.forwardOperations.length ||
        delivery.entries.size !== delivery.forward.length || [...delivery.entries.values()].some(entry =>
          entry.preparationClosure || entry.receivedHandoff || entry.sequence !== 'forward' ||
          !entry.claim || entry.result?.item.outcome !== 'completed' || entry.history.at(-1)?.phase !== 'completed'))
      throw new KernelStorageError('LEASE_FENCED', 'delivery worker preparation requires its complete settled forward prefix and another path');
    if (!cut.run.frontierRef) fail('delivery worker preparation has no exact authorized publish frontier');
    requireEqual(await readCanonicalArtifact<RunFrontier>(artifacts, cut.run.frontierRef),
      { ...authorization.frontier, phase: 'publish', nextPathOperationIndex: delivery.forward.length },
      'delivery worker preparation exact next unpublished path');
    requireEqual(cut.latestCheckpoint, delivery.previousCheckpoint, 'delivery worker preparation original ordered result Checkpoint');
    source = driver.readSnapshot(connection => preparationSqlCut(connection, delivery.admission.source.run.id));
    requireEqual(source.run, delivery.admission.source.run, 'delivery worker preparation verified source Run');
    requireEqual(source.session, delivery.admission.source.session, 'delivery worker preparation original source Session');
    if (source.principalId !== authorization.grant.principalId || original.principalId !== authorization.grant.principalId)
      fail('delivery worker preparation changed its original principal');
  }
  let result: PreparingWorkerLaunch | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    const now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') return;
    const run = readRun(connection, input.runId);
    requireEqual(run, cut.run, 'worker preparation selected Run');
    if (canonicalSha256(preparationSqlCut(connection, input.runId)) !== canonicalSha256(original) || source &&
        canonicalSha256(preparationSqlCut(connection, source.run.id)) !== canonicalSha256(source))
      throw new KernelStorageError('REVISION_CONFLICT', 'worker preparation original continuation, Session or source SQL cut changed');
    if (run.revision !== input.expectedRunRevision || run.status !== 'queued' || run.activeWorkerLaunchId ||
        run.cancelRequested || run.stopIntentRef || now >= run.deadlineAt ||
        run.nextStep !== 'agent' && run.nextStep !== 'tool' && !(run.nextStep === 'verify' && verifier) &&
          !(run.nextStep === 'delivery' && delivery?.authorization?.grant &&
            now >= delivery.authorization.grant.issuedAt && now < delivery.authorization.grant.expiresAt))
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
  input: { launchId: string; birth: NativeControllerPreparationBirth; reservation: HeldWorkerReservation;
    workspaceBirth?: RunWorkspaceBirth }): Promise<PreparingWorkerLaunch> {
  let observed = readNativeControllerPreparationBirth(input.birth);
  const before = preparing(driver, owner, input.launchId);
  const borrowed = borrowWorkerReservationForExecution(input.reservation, before.launchId, before.spawnNonceDigest);
  try { borrowed.assertHeld(); } finally { borrowed.close(); }
  const birth: ControllerBirth = { schemaVersion: 1, format: 'cliq-controller-preparation-birth-v1',
    identity: observed.identity, birthDigest: observed.controllerBirthDigest };
  const artifact = await artifacts.publishCanonical(birth, birth.format);
  const git = input.workspaceBirth && readRunWorkspacePreparingGit(owner.filesystem, input.workspaceBirth);
  const gitArtifact = git ? await artifacts.describe(git.metadataRef, 'application/json', 'cliq-source-git-inspection-output-v1') : undefined;
  if (git) {
    const bytes = await artifacts.readBoundedBytes(git.metadataRef, git.metadata.byteLength);
    if (!bytes.equals(git.metadata)) fail('worker preparation metadata differs from its original fully read Checkpoint');
  }
  let result: PreparingWorkerLaunch | undefined;
  driver.transaction(connection => {
    const current = preparing(connection, owner, input.launchId);
    requireEqual(current, before, 'worker preparation controller registration');
    bindableRun(connection, current); input.reservation.assertHeld();
    if (input.workspaceBirth) {
      const original = readRunWorkspaceBirth(owner.filesystem, input.workspaceBirth);
      if (original.runId !== current.runId || original.generationId !== current.preparation.generationId ||
          original.sourceWorkspaceStateRef !== current.preparation.sourceWorkspaceStateRef ||
          original.sourceCheckpointId !== current.preparation.sourceCheckpointId) fail('worker preparation Git input substitutes its original directory birth');
    }
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
    if (gitArtifact) insertArtifactMetadata(connection, gitArtifact, now);
    result = { ...current, preparation: { ...current.preparation,
      controller: { birthIdentityRef: artifact.ref, birthIdentityDigest: birth.birthDigest,
        ...(git ? { privateGitInputRef: git.metadataRef } : {}) },
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
  input: { run: Run; launches: WorkerLaunch[]; generations: WorkspaceGenerationStateV1[] },
  cleanupContext?: WorkerPreparationCleanupContext): Promise<void> {
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
    if (launch.phase === 'preparing') {
      if (input.run.status !== 'queued' || input.run.activeWorkerLaunchId || input.run.latestCheckpointId !== preparation.sourceCheckpointId)
        fail('incomplete worker preparation lost its original nonexecuting Run/Checkpoint');
      if (owner.state !== 'active') {
        if (!cleanupContext) fail('incomplete worker preparation requires its original live owner, not reconstructed birth facts');
        assertWorkerPreparationCleanupContext(driver, cleanupContext, input.run.id);
        const original = cleanupContexts.get(cleanupContext)!;
        requireEqual(original.launch, launch, 'preparation read-only cleanup exact dead original');
      }
    }
    if (preparation.generation) {
      const identity = decodeWorkspaceGenerationIdentity(await readCanonicalArtifact(artifacts, preparation.generation.generationRef));
      const generation = input.generations.find(value => value.generationId === preparation.generationId);
      if (!generation || identity.runId !== launch.runId || identity.generationId !== preparation.generationId ||
          identity.identityDigest !== preparation.generation.generationIdentityDigest ||
          generation.generationRef !== preparation.generation.generationRef || generation.generationIdentityDigest !== identity.identityDigest ||
          identity.sourceCheckpointId !== preparation.sourceCheckpointId || identity.sourceWorkspaceStateRef !== preparation.sourceWorkspaceStateRef ||
          identity.creationNonceDigest !== preparation.generationCreationNonceDigest || identity.createdAt < launch.createdAt ||
          owner.state === 'terminal' && identity.createdAt > owner.releasedAt)
        fail('worker preparation generation provenance is incomplete or substituted');
      if (launch.phase === 'preparing' && generation.phase !== 'materializing' && generation.phase !== 'preactivated_readonly')
        fail('preparing worker cannot own an executable or already retired generation');
    } else if (input.generations.some(value => value.generationId === preparation.generationId)) {
      fail('worker preparation directory row has no original atomic birth binding');
    }
    if (preparation.controller) {
      const birth = controllerBirth(await readCanonicalArtifact(artifacts, preparation.controller.birthIdentityRef));
      if (!preparation.generation || birth.birthDigest !== preparation.controller.birthIdentityDigest ||
          birth.identity.readyObservedAt < launch.createdAt || owner.state === 'terminal' && birth.identity.readyObservedAt > owner.releasedAt)
        fail('worker preparation controller birth differs');
      const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, preparation.sourceWorkspaceStateRef));
      const base = decodeSourceManifest(await readCanonicalArtifact(artifacts, state.baseWorkspaceManifestRef));
      if (preparation.controller.privateGitInputRef) {
        if (!state.privateGitStateRef || !base.git) fail('worker preparation Git leaf has no original frozen Git Checkpoint');
        const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, input.run.specRef));
        const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, spec.sandboxProfileRef));
        const data = await readPrivateGitData(artifacts, state.privateGitStateRef,
          { repositoryIdentityDigest: base.git.repositoryIdentityDigest, resources: profile.resources });
        const metadata = await artifacts.readBoundedBytes(preparation.controller.privateGitInputRef,
          Math.min(profile.resources.maxInvocationOutputBytes, profile.resources.maxSingleFileBytes));
        if (canonicalSha256(privateGitInspectionOutput(data)) !== preparation.controller.privateGitInputRef ||
            canonicalSha256(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metadata))) !== preparation.controller.privateGitInputRef)
          fail('worker preparation Git leaf differs from its complete original CAS closure');
      } else if (state.privateGitStateRef) {
        const manifest = await readCanonicalArtifact<{ objectClosureRef: string }>(artifacts, state.privateGitStateRef);
        const closure = await readCanonicalArtifact<{ packs: unknown[] }>(artifacts, manifest.objectClosureRef);
        if (!Array.isArray(closure.packs) || closure.packs.length) fail('nonempty Git preparation lost its original input metadata registration');
      }
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
  const readResources = (connection: SqliteConnection | SqliteDriver = driver) => {
    assertActiveStateOwner(connection, owner);
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
    return { kind: 'original_owner' as const, workspace, controller, reservation };
  };
  return publishPreparationRetirement(driver, artifacts, owner, launch, run, generation, identity, readResources);
}

/** Own one powerless successor cleanup. The context was created only after its
 * complete original graph joined; all physical results stay genuine and the
 * shared publisher below remains the sole terminal transaction. */
export async function retireRetainedWorkerPreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  context: WorkerPreparationCleanupContext, controller: LinuxWorkerController,
  brokerQuiescence: InstalledBrokerQuiescence, signal?: AbortSignal): Promise<RetiredWorkerPreparation> {
  assertLinuxWorkerController(controller);
  let reservation: HeldWorkerReservation | undefined, input: HeldRetainedPreparingGitInput | undefined;
  let primary: { error: unknown } | undefined;
  try {
    const target = readWorkerPreparationCleanupTarget(driver, owner, context), held = cleanupContexts.get(context)!;
    const { launch, generation, identity, originalController, recipe } = target;
    if (held.retirementStarted) fail('preparation cleanup inspection cannot start another physical attempt');
    held.retirementStarted = true;
    if (!generation || !identity || !originalController || !recipe || identity.locator.kind !== 'linux_directory' ||
        !launch.preparation.reservation || !launch.preparation.controller?.privateGitInputRef)
      fail('preparation cleanup still lacks complete original generation/controller/reservation/input births');
    requireEqual(bindableRun(driver, launch), target.cut.run, 'preparation cleanup complete inspected Run');
    const checker = readNativeControllerPreparationBirth(controller.preparationBirth);
    const checkerBirth: ControllerBirth = { schemaVersion: 1, format: 'cliq-controller-preparation-birth-v1',
      identity: checker.identity, birthDigest: checker.controllerBirthDigest };
    const process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, target.death.priorOwner.processIdentityRef));
    if (process.platform !== 'linux' || process.identityDigest !== target.death.priorOwner.processIdentityDigest)
      fail('preparation cleanup has no exact original Linux Supervisor identity');
    assertWorkerPreparationCleanupContext(driver, context, launch.runId);
    assertInstalledBrokerQuiescence(brokerQuiescence, driver, owner, launch.runId);
    reservation = owner.filesystem.openWorkerReservation(launch.launchId, launch.spawnNonceDigest, launch.preparation.reservation);
    input = openRetainedPreparingGitInput(owner.filesystem, reservation, { runId: launch.runId,
      generationId: launch.preparation.generationId, launchId: launch.launchId, spawnNonceDigest: launch.spawnNonceDigest,
      activationNonceDigest: launch.activationNonceDigest, generationCreationNonceDigest: launch.preparation.generationCreationNonceDigest,
      generationRef: generation.generationRef, inputIntentRef: launch.preparation.controller.privateGitInputRef },
    { deviceId: identity.locator.deviceId, fileId: identity.locator.directoryFileId, ownerUid: identity.locator.ownerUid },
    { pid: process.pid, processStartToken: process.processStartToken });
    const receipt = await controller.cleanupRetainedPreparingGit({ input, recipe, signal });
    // The genuine wrapper joins the current checker before returning. Its
    // input/reservation readers must also actually close before tree retirement.
    input.close(); reservation.close();
    const workspace = observeRetainedPreparingGeneration(owner.filesystem, identity, generation.rowVersion, receipt);
    const observed = readNativeRetainedPreparingGitRetirement(receipt);
    const nativeRetirement: PreparingNativeRetirementData = immutableSnapshot({ observation: observed.observation,
      input: observed.input.identity, recipe: observed.recipe, checker: observed.checker, checkerBirth });
    const readResources = (connection: SqliteConnection | SqliteDriver = driver): CurrentPreparingRetirementResources => {
      assertActiveStateOwner(connection, owner); assertWorkerPreparationCleanupContext(driver, context, launch.runId);
      assertInstalledBrokerQuiescence(brokerQuiescence, driver, owner, launch.runId);
      const current = readNativeRetainedPreparingGitRetirement(receipt);
      assertRetainedPreparingGitInputOwner(owner.filesystem, current.input);
      if (current.input !== input) fail('preparation cleanup substitutes its original closed input');
      requireEqual({ observation: current.observation, input: current.input.identity, recipe: current.recipe,
        checker: current.checker, checkerBirth }, nativeRetirement, 'preparation cleanup original genuine native result');
      requireEqual(current.recipe, recipe, 'preparation cleanup original closed recipe');
      requireEqual(current.input.identity.reservation, launch.preparation.reservation, 'preparation cleanup original reservation input');
      if (current.observation.origin !== 'original_birth_current_checker' || current.observation.completed !== 0 ||
          ![0, 2, 4, 5, 6, 7, 8, 9, 10].includes(current.observation.lastBirthPhase) ||
          current.observation.originalControllerPid !== originalController.identity.pid ||
          current.observation.originalControllerStartToken !== originalController.identity.processStartToken ||
          current.observation.originalSupervisorPid !== process.pid || current.observation.originalSupervisorStartToken !== process.processStartToken ||
          current.checker.controllerBirthDigest !== checkerBirth.birthDigest || current.checker.pid !== checkerBirth.identity.pid ||
          current.checker.processStartToken !== checkerBirth.identity.processStartToken || current.checker.joined !== true)
        fail('preparation cleanup has no whole original prefix and real current-checker join');
      const reservationRetirement = readWorkerReservationRetirement(owner.filesystem, reservation!, launch.launchId, launch.spawnNonceDigest);
      requireEqual(reservationRetirement, launch.preparation.reservation, 'preparation cleanup actual reservation reader join');
      const closedWorkspace = readRetainedPreparingGenerationRetirement(owner.filesystem, workspace, receipt);
      if (closedWorkspace.generationRef !== generation.generationRef || closedWorkspace.generationIdentityDigest !== generation.generationIdentityDigest ||
          closedWorkspace.sourceRowVersion !== generation.rowVersion) fail('preparation cleanup substitutes its actual registered directory');
      return { kind: 'current_checker', workspace: closedWorkspace,
        controller: { observedAt: new Date(current.observation.observedAtMs).toISOString() }, reservation: reservationRetirement, nativeRetirement,
        ownerDeathAcquisitionEvidenceRef: target.death.acquisitionEvidenceRef,
        ownerDeathAcquisitionEvidenceDigest: target.death.acquisitionEvidenceDigest };
    };
    return await publishPreparationRetirement(driver, artifacts, owner, launch, target.cut.run, generation, identity, readResources);
  } catch (error) { primary = { error }; throw error; }
  finally {
    const failures: unknown[] = [];
    // Construction may have claimed its input before a scope escaped. Preserve
    // the same cancel/whole-controller join, then consume only original FDs.
    try { await controller.close(); } catch (error) { failures.push(error); }
    try { input?.close(); } catch (error) { failures.push(error); }
    try { reservation?.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw new ResourceRetirementError('preparation current checker resources did not completely join',
      new AggregateError([...(primary ? [primary.error] : []), ...failures]));
  }
}

type OriginalPreparingRetirementResources = { kind: 'original_owner'; workspace: ReturnType<typeof readRunWorkspaceBirthRetirement>;
  controller: ReturnType<typeof readNativeControllerPreparationRetirement> | undefined; reservation: HeldWorkerReservation['identity'] | undefined };
type CurrentPreparingRetirementResources = { kind: 'current_checker'; workspace: RetainedPreparingGenerationRetirementData;
  controller: { observedAt: string }; reservation: HeldWorkerReservation['identity']; nativeRetirement: PreparingNativeRetirementData;
  ownerDeathAcquisitionEvidenceRef: string; ownerDeathAcquisitionEvidenceDigest: string };
type PreparingRetirementResources = OriginalPreparingRetirementResources | CurrentPreparingRetirementResources;
/** One physical quarantine and terminal transaction for every preparation
 * inspector. Resource readers retain their genuine original native brands. */
async function publishPreparationRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  launch: PreparingWorkerLaunch, run: Run, generation: PreparationGeneration,
  identity: ReturnType<typeof decodeWorkspaceGenerationIdentity>,
  readResources: (connection?: SqliteConnection | SqliteDriver) => PreparingRetirementResources): Promise<RetiredWorkerPreparation> {
  readResources();
  const move = owner.filesystem.quarantineGeneration(identity, generation.rowVersion);
  const resources = readResources(), observedAt = sampleCanonicalNow();
  for (const timestamp of [resources.workspace.observedAt, ...(resources.controller ? [resources.controller.observedAt] : [])]) {
    if (timestamp > observedAt || parseCanonicalTime(observedAt) - parseCanonicalTime(timestamp) > 5000)
      fail('preparation retirement native joins are not fresh');
  }
  const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const baseEvidence = { schemaVersion: 1 as const, format: 'cliq-worker-preparation-retirement-evidence-v1' as const,
    launch, sourceGeneration: generation, quarantineMove: move, inspectorIdentityRef: inspectorArtifact.ref,
    inspectorIdentityDigest: inspector.identityDigest, observedAt, evidenceDigest: '' };
  const evidence: BornPreparationRetirement | CurrentCheckerPreparationRetirement = resources.kind === 'original_owner'
    ? { ...baseEvidence, kind: 'born', workspaceRetirementObservedAt: resources.workspace.observedAt,
      ...(resources.controller ? { controllerRetirement: resources.controller } : {}),
      ...(resources.reservation ? { reservationRetirement: resources.reservation } : {}) }
    : { ...baseEvidence, kind: 'born_current_checker', workspaceRetirement: resources.workspace,
      nativeRetirement: resources.nativeRetirement, reservationRetirement: resources.reservation,
      ownerDeathAcquisitionEvidenceRef: resources.ownerDeathAcquisitionEvidenceRef,
      ownerDeathAcquisitionEvidenceDigest: resources.ownerDeathAcquisitionEvidenceDigest };
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
    const fresh = readResources(connection);
    requireEqual(fresh.kind === 'original_owner' ? preparing(connection, owner, launch.launchId) : readRequiredWorkerLaunch(connection, launch.launchId),
      launch, 'preparation retirement original lifecycle');
    requireEqual(bindableRun(connection, launch), run, 'preparation retirement current Run');
    requireEqual(readRequiredWorkspaceGeneration(connection, generation.generationId), generation, 'preparation retirement original generation');
    const moved = owner.filesystem.quarantineGeneration(identity, generation.rowVersion);
    requireEqual(moved, move, 'preparation retirement exact native quarantine');
    const now = sampleCanonicalNow();
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
  const readResources = (connection: SqliteConnection | SqliteDriver = driver) => {
    assertActiveStateOwner(connection, owner); assertInstalledBrokerQuiescence(broker, driver, owner, run.id);
    const observed = readUnallocatedRunWorkspaceRetirement(owner.filesystem, workspace);
    const { observedAt: _observedAt, ...body } = observed;
    requireEqual(body, { runId: run.id, generationId: launch.preparation.generationId,
      sourceCheckpointId: launch.preparation.sourceCheckpointId, sourceWorkspaceStateRef: launch.preparation.sourceWorkspaceStateRef,
      creationNonceDigest: launch.preparation.generationCreationNonceDigest, allocationRequested: false,
      operationsJoined: true }, 'preparation exact original unallocated producer');
    if (readWorkspaceGenerationsForRun(connection, run.id).some(value => value.generationId === launch.preparation.generationId))
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
    const fresh = readResources(connection), now = sampleCanonicalNow();
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
  const proof = value, currentChecker = value.kind === 'born_current_checker';
  const fields = ['schemaVersion', 'format', 'kind', 'launch', 'sourceGeneration', 'quarantineMove',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest',
    ...(currentChecker ? ['workspaceRetirement', 'nativeRetirement', 'reservationRetirement', 'ownerDeathAcquisitionEvidenceRef', 'ownerDeathAcquisitionEvidenceDigest']
      : ['workspaceRetirementObservedAt', ...(launch.preparation.controller ? ['controllerRetirement'] : []),
        ...(launch.preparation.reservation ? ['reservationRetirement'] : [])])];
  if (!exactKeys(proof, fields) || proof.schemaVersion !== 1 || (!currentChecker && proof.kind !== 'born') || proof.format !== 'cliq-worker-preparation-retirement-evidence-v1' ||
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
  const originalOwner = readStateOwner(driver, launch.preparation.stateOwnerEpoch);
  if (!originalOwner || originalOwner.supervisorInstanceId !== launch.supervisorInstanceId)
    fail('preparation retirement has no original StateOwner');
  const inspectorHeader = currentChecker ? await readCanonicalArtifact<{ stateOwnerEpoch: number }>(artifacts, proof.inspectorIdentityRef) : undefined;
  const owner = currentChecker ? readStateOwner(driver, inspectorHeader!.stateOwnerEpoch) : originalOwner;
  if (!owner || owner.acquiredAt > proof.observedAt || owner.state === 'terminal' && owner.releasedAt < retiredAt ||
      currentChecker && owner.ownerEpoch <= originalOwner.ownerEpoch) fail('preparation retirement has no owning inspector lifetime');
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  const inspector = await readSupervisorInspector(artifacts, owner, assembly, proof);
  if (inspector.stateOwnerEpoch !== owner.ownerEpoch || !currentChecker && inspector.stateOwnerEpoch !== launch.preparation.stateOwnerEpoch)
    fail('preparation retirement substitutes its actual inspector');
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
  const workspaceObservedAt = proof.kind === 'born_current_checker' ? proof.workspaceRetirement.observedAt : proof.workspaceRetirementObservedAt;
  const controllerObservedAt = proof.kind === 'born_current_checker' ? new Date(proof.nativeRetirement.observation.observedAtMs).toISOString() : proof.controllerRetirement?.observedAt;
  for (const observed of [workspaceObservedAt, ...(controllerObservedAt ? [controllerObservedAt] : [])]) {
    if (observed < original.createdAt || observed > proof.observedAt || parseCanonicalTime(proof.observedAt) - parseCanonicalTime(observed) > 5000)
      fail('preparation retirement retained native observations are not causal and fresh');
  }
  if (proof.kind === 'born_current_checker') await validateCurrentPreparingRetirement(driver, artifacts, proof, original, identity, owner, spec);
  else if (original.preparation.controller) {
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

/** Independent retained-data checks. These data never mint a native receipt or
 * restore an old input, nonce, worker binding or generation seal. */
async function validateCurrentPreparingRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog,
  proof: CurrentCheckerPreparationRetirement, original: PreparingWorkerLaunch,
  identity: ReturnType<typeof decodeWorkspaceGenerationIdentity>, inspectorOwner: NonNullable<ReturnType<typeof readStateOwner>>,
  spec: ReturnType<typeof decodeRunSpec>): Promise<void> {
  const preparation = original.preparation;
  if (!preparation.generation || !preparation.controller?.privateGitInputRef || !preparation.reservation || identity.locator.kind !== 'linux_directory')
    fail('current preparation checker lost its complete original registered births');
  const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: original.supervisorInstanceId, ownedAt: original.createdAt });
  if (death.priorOwner.ownerEpoch !== preparation.stateOwnerEpoch || inspectorOwner.ownerEpoch < death.successorOwner.ownerEpoch ||
      proof.ownerDeathAcquisitionEvidenceRef !== death.acquisitionEvidenceRef || proof.ownerDeathAcquisitionEvidenceDigest !== death.acquisitionEvidenceDigest)
    fail('current preparation checker substitutes its original owner death acquisition');
  const process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, death.priorOwner.processIdentityRef));
  if (process.platform !== 'linux' || process.identityDigest !== death.priorOwner.processIdentityDigest || identity.createdAt > death.priorOwner.releasedAt)
    fail('current preparation checker has no original Linux process and causal directory birth');
  const oldBirth = controllerBirth(await readCanonicalArtifact(artifacts, preparation.controller.birthIdentityRef));
  if (oldBirth.birthDigest !== preparation.controller.birthIdentityDigest || oldBirth.identity.readyObservedAt > death.priorOwner.releasedAt)
    fail('current preparation checker substitutes its original controller birth');
  const native = proof.nativeRetirement;
  if (!exactKeys(native, ['observation', 'input', 'recipe', 'checker', 'checkerBirth'])) fail('current preparation native observation is not closed');
  const born = controllerBirth(native.checkerBirth), observed = native.observation;
  if (!Number.isSafeInteger(observed.observedAtMs) || observed.observedAtMs < 1 ||
      ![0, 2, 4, 5, 6, 7, 8, 9, 10].includes(observed.lastBirthPhase)) fail('current preparation checker has a missing/half original prefix');
  const observedAt = new Date(observed.observedAtMs).toISOString(); parseCanonicalTime(observedAt);
  requireEqual(observed, { origin: 'original_birth_current_checker', observedAtMs: observed.observedAtMs, completed: 0,
    lastBirthPhase: observed.lastBirthPhase, runId: original.runId, generationId: preparation.generationId,
    launchId: original.launchId, spawnNonceDigest: original.spawnNonceDigest, activationNonceDigest: original.activationNonceDigest,
    generationCreationNonceDigest: preparation.generationCreationNonceDigest, generationRef: preparation.generation.generationRef,
    inputIntentRef: preparation.controller.privateGitInputRef, originalControllerPid: oldBirth.identity.pid,
    originalControllerStartToken: oldBirth.identity.processStartToken, originalSupervisorPid: process.pid,
    originalSupervisorStartToken: process.processStartToken }, 'current preparation checker complete original nonproductive observation');
  requireEqual(native.input, { runId: original.runId, generationId: preparation.generationId, launchId: original.launchId,
    spawnNonceDigest: original.spawnNonceDigest, activationNonceDigest: original.activationNonceDigest,
    generationCreationNonceDigest: preparation.generationCreationNonceDigest, generationRef: preparation.generation.generationRef,
    inputIntentRef: preparation.controller.privateGitInputRef, reservation: preparation.reservation,
    generation: { deviceId: identity.locator.deviceId, fileId: identity.locator.directoryFileId, ownerUid: identity.locator.ownerUid },
    originalSupervisorPid: process.pid, originalSupervisorStartToken: process.processStartToken }, 'current preparation checker exact original input identity');
  requireEqual(native.checker, { pid: born.identity.pid, processStartToken: born.identity.processStartToken,
    controllerBirthDigest: born.birthDigest, joined: true }, 'current preparation checker actual joined controller birth');
  if (born.identity.readyObservedAt < inspectorOwner.acquiredAt || born.identity.readyObservedAt > observedAt ||
      observedAt < death.priorOwner.releasedAt || observedAt < inspectorOwner.acquiredAt || observedAt > proof.workspaceRetirement.observedAt ||
      born.identity.pid === oldBirth.identity.pid && born.identity.processStartToken === oldBirth.identity.processStartToken ||
      born.identity.pid === process.pid && born.identity.processStartToken === process.processStartToken)
    fail('current preparation checker substitutes or adopts an earlier process lifetime');
  const { releasedAt: _released, terminalReason: _reason, transitionEvidenceRef: _transition,
    transitionEvidenceDigest: _transitionDigest, ...base } = death.priorOwner;
  const active = { ...base, state: 'active' as const, rowVersion: 1 as const, rowDigest: '' };
  active.rowDigest = digestOmitting(active, 'rowDigest'); decodeStateOwnerRecord(active);
  const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, spec.sandboxProfileRef));
  const state = decodeWorkspaceState(await readCanonicalArtifact(artifacts, preparation.sourceWorkspaceStateRef));
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, state.baseWorkspaceManifestRef));
  if (!source.git || !state.privateGitStateRef) fail('current preparation checker lost its original complete Git Checkpoint');
  requireEqual(native.recipe, { ...profile.resources, stateOwnerEpoch: preparation.stateOwnerEpoch,
    supervisorInstanceId: original.supervisorInstanceId, stateOwnerRowDigest: active.rowDigest, sessionId: readRun(driver, original.runId).sessionId, sourceCheckpointId: preparation.sourceCheckpointId,
    sourceWorkspaceStateRef: preparation.sourceWorkspaceStateRef, repositoryIdentityDigest: source.git.repositoryIdentityDigest },
  'current preparation checker complete original fixed recipe');
  const workspace = proof.workspaceRetirement;
  requireEqual(workspace, { generationRef: proof.sourceGeneration.generationRef, generationIdentityDigest: identity.identityDigest,
    runId: original.runId, generationId: preparation.generationId, sourceRowVersion: proof.sourceGeneration.rowVersion,
    directoryIdentity: { deviceId: identity.locator.deviceId, fileId: identity.locator.directoryFileId, ownerUid: identity.locator.ownerUid },
    observedState: { kind: 'unverified_preparation' }, observedAt: workspace.observedAt }, 'current preparation checker actual closed original directory');
  if (workspace.observedAt < inspectorOwner.acquiredAt) fail('current preparation directory observation predates its actual inspector');
  requireEqual(proof.reservationRetirement, preparation.reservation, 'current preparation checker complete original reservation join');
}
