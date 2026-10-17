import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxRuntimeBindingV1 } from '../kernel/execution.js';
import type { Run, PreparingWorkerLaunch, StateOwnerRecordV1, SupervisorInspectorIdentityV1, WorkerIdentity, WorkspaceGenerationSnapshotEvidenceV1, WorkerDeathWait } from '../kernel/types.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly, type RunAssemblyValidationMaterial } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual, type RuntimeBundleManifest, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { assertNativeContainmentDeath, assertNativePreactivationObservation, LINUX_WORKER_RECIPE,
  openInstalledLinuxWorkerLauncher, openLinuxWorkerLauncher, type LinuxBlockedWorker, type LinuxWorkerController,
  type LinuxWorkerInstallation, type NativePreactivationRetirement, type NativeRetainedWorkerRetirement } from '../sandbox/linux-worker.js';
import { borrowRunWorkspaceForExecution, createRunWorkspaceMaterialization, observeRetainedRunWorkspace,
  type RunWorkspaceGeneration, type RunWorkspaceMaterialization, type RunWorkspaceBirth } from '../workspace/run-workspace/generation.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile, readBuiltinEditLaunchClosure, readWorkerLaunchClosure, readRetainedWorkerLaunchClosure, readQuarantinedWorkerLaunchClosure, decodeWorkerProcessContainment, type WorkerLaunchClosure } from './execution-closure.js';
import { loadAgentRun } from './reducers/agent.js';
import { assertLiveDispatchState, markInvocationUnknown } from './reducers/invocation.js';
import { beginWorkerRecovery, beginWorkerRecoveryProbe, closeWorkerRecoveryProbe, completeWorkerRecoveryProbe } from './reducers/worker-recovery.js';
import { activateWorkerLeaseWithinDeadline, beginGenerationCheckpoint, beginGenerationRevocation, recordWorkerPreactivated, renewWorkerLease, reserveWorkerLaunch } from './reducers/worker-launch.js';
import { sealWorkerGeneration } from './reducers/worker-launch.js';
import { recordWorkspaceGenerationPreactivated } from './reducers/workspace-transition.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, assertFenceHealthy, type StateOwnerContext } from './state-owner.js';
import { startWorkerRecoveryTask, type WorkerRecoveryTask } from './worker-recovery-task.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { readToolCut } from './tool-cut.js';
import { decodeRunSpec, decodeWorkerIdentity, decodeWorkspaceGenerationIdentity } from './decoders.js';
import { retirePreactivationLaunch } from './preactivation-retirement.js';
import type { HeldWorkerReservation } from './native-owner.js';
import { withInstalledWorkerRoot, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { stopCheckpointId, stopInvocationHistory } from '../runtime/stop.js';
import { retireQuarantinedGeneration } from './generation-retirement.js';
import { observeInstalledBrokerQuiescence, type StateStore } from './store.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { hasOnlySettledInstalledModelUnknowns } from './worker-recovery.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { beginWorkerPreparation, recordWorkerPreparationGeneration, recordWorkerPreparationController, retireWorkerPreparation } from './worker-preparation.js';
import { validateInstalledModelNoReleaseHistory } from './broker-no-release.js';

/** Trusted installation paths belong to Supervisor bootstrap, not a Run or a control frame. */
export type RunExecutionInstallation = Pick<LinuxWorkerInstallation, 'installationRoot' | 'cgroupParent'>;
export type LoadRunExecutionInput = { runId: string; material: RunAssemblyValidationMaterial };
export type RunExecution = Readonly<{
  requestStop(): Promise<void>;
  activateCurrentWorker(input: { expectedRunRevision: number }): Promise<Run>;
  assertCurrentModelWorker(input: { runId: string; leaseEpoch: number; launchId: string; generationRef: string; workerIdentityDigest: string }): void;
  renewCurrentWorkerLease(): 'inactive' | 'unchanged' | 'renewed' | 'expired';
  executeCurrentTool(input: { expectedRunRevision: number }): Promise<Run>;
  finishCurrentStop(input: { expectedRunRevision: number }): Promise<Run>;
  resumeCurrentRetirement(input: { expectedRunRevision: number }): Promise<Run>;
  recoverWorker(input: { expectedRunRevision: number }): Promise<Run>;
}>;

const nonce = () => sha256Bytes(randomBytes(32));
type WorkerSpec = Extract<SandboxLaunchSpecV1, { purpose: 'worker_activation' }>;
type EditSpec = Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }>;
type WorkerActivationCut = Pick<Awaited<ReturnType<typeof readRecoveryClosure>>,
  'run' | 'runSpec' | 'latestCheckpoint' | 'workspaceGenerations'>;
type ActiveWorker = {
  authority: { generationRef: string; generationIdentityDigest: string };
  recipe: Awaited<ReturnType<typeof publishWorkerRecipe>>;
  reserved: Awaited<ReturnType<typeof reserveWorkerLaunch>>;
  activated: ReturnType<typeof activateWorkerLeaseWithinDeadline>;
  processContainmentRef: string;
  closure: WorkerLaunchClosure;
};

async function publishWorkerRecipe(artifacts: ArtifactCatalog, controller: LinuxWorkerController,
  installation: Pick<RunExecutionInstallation, 'cgroupParent'>, selected: Pick<WorkerActivationCut, 'run' | 'runSpec'>, generationRef: string,
  reservation: HeldWorkerReservation, launchId: string, spawnNonceDigest: string, activationNonceDigest: string) {
  const { run, runSpec } = selected;
  const assembly = decodeRetainedRunAssembly(await artifacts.readCanonical(runSpec.assemblyRef));
  const bundle = await artifacts.readCanonical<RuntimeBundleManifest>(assembly.runtime.runtimeBundleRef);
  const profile = decodeSandboxProfile(await artifacts.readCanonical(runSpec.sandboxProfileRef));
  const launcher = bundle.entries.find(entry => entry.entryId === LINUX_WORKER_RECIPE.launcherId);
  if (!launcher || launcher.role !== 'platform_helper' || !launcher.executable || assembly.runtime.workerExecutableId !== LINUX_WORKER_RECIPE.workerId) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen Run does not select the installed worker recipe');
  }
  const owner = { kind: 'worker_activation' as const, runId: run.id, intendedLeaseEpoch: run.leaseEpoch + 1, workerLaunchId: launchId };
  const cgroupNameReservationDigest = canonicalSha256(['cliq-worker-cgroup-v1', run.id, launchId]);
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef }, launchNonceDigest: spawnNonceDigest,
    backend: { kind: 'linux', cgroupPath: path.posix.join(installation.cgroupParent, `cliq-${cgroupNameReservationDigest}`),
      cgroupNameReservationDigest,
      pidNamespaceReservationId: identityHash('cliq-worker-namespace-v1', run.id, launchId), subreaperStartToken: controller.subreaperStartToken,
      nativeReservation: reservation.identity },
    createdAt: sampleCanonicalNow(), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const containmentPlanRef = (await artifacts.publishCanonical(plan, plan.format)).ref;
  const runtime: SandboxRuntimeBindingV1 = { runtimeBundleRef: assembly.runtime.runtimeBundleRef,
    runtimeBundleManifestDigest: assembly.runtime.runtimeBundleManifestDigest, sandboxBackend: 'linux_namespace', toolchain: { kind: 'none' },
    launcher: { executableId: launcher.entryId, executableDigest: launcher.digest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const mounts = LINUX_WORKER_RECIPE.mounts.map(mount => ({ ...mount, privateRootId: identityHash(launchId, mount.purpose) }));
  const spec: WorkerSpec = { schemaVersion: 1, format: 'cliq-sandbox-launch-v1', owner, purpose: 'worker_activation', runtime,
    executable: { kind: 'runtime_bundle', runtimeBundleRef: runtime.runtimeBundleRef, runtimeBundleManifestDigest: runtime.runtimeBundleManifestDigest,
      executableId: assembly.runtime.workerExecutableId, executableDigest: assembly.runtime.workerExecutableDigest,
      role: 'worker', executionPath: LINUX_WORKER_RECIPE.workerPath },
    processInvocation: { kind: 'worker_entrypoint', purpose: 'worker_activation', recipe: 'cliq-worker-entrypoint-v1', runtimeSource: 'launch_runtime',
      executableSource: 'launch_executable', argvSource: 'fixed_empty', cwdSource: 'generation_root',
      stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_worker_channel_only' } },
    environment: LINUX_WORKER_RECIPE.environment,
    filesystem: { kind: 'run_generation', generationRef, access: 'preactivated_readonly', sourceProjectionRef: runSpec.sourceProjectionRef, independentGit: true },
    mounts, mountsDigest: canonicalSha256(mounts), sandboxProfileRef: runSpec.sandboxProfileRef, sandboxProfileDigest: profile.profileDigest,
    resources: profile.resources, resourcesDigest: canonicalSha256(profile.resources), containmentPlanRef,
    containmentPlanDigest: plan.planDigest, createdAt: sampleCanonicalNow(), launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  const sandboxLaunchSpecRef = (await artifacts.publishCanonical(spec, spec.format)).ref;
  return { spec, input: { launchId, runId: run.id, expectedRunRevision: run.revision, spawnNonceDigest, activationNonceDigest,
    workspaceGenerationRef: generationRef, containmentPlanRef, sandboxLaunchSpecRef } };
}

async function publishEditRecipe(artifacts: ArtifactCatalog, workerSpec: WorkerSpec, parentContainmentRef: string,
  parentCgroup: string, prepared: Extract<Awaited<ReturnType<Awaited<ReturnType<typeof loadAgentRun>>['prepareTool']>>, { disposition: 'prepared' }>, dispatchId: string) {
  if (prepared.target.execution.kind !== 'builtin' || prepared.target.execution.adapterId !== LINUX_WORKER_RECIPE.editId) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'edit does not select the installed contained adapter');
  }
  if (workerSpec.filesystem.kind !== 'run_generation') throw new KernelStorageError('ARTIFACT_MISMATCH', 'edit requires a private Run generation');
  const owner = { kind: 'run_invocation' as const, runId: prepared.run.id, intendedLeaseEpoch: prepared.run.leaseEpoch,
    workerLaunchId: workerSpec.owner.workerLaunchId, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId };
  if (workerSpec.containmentPlanRef === parentContainmentRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'actual parent containment is required');
  const cgroupNameReservationDigest = canonicalSha256(['cliq-edit-cgroup-v1', dispatchId]);
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef: workerSpec.filesystem.generationRef }, parentContainmentRef,
    launchNonceDigest: nonce(), backend: { kind: 'linux', cgroupPath: path.posix.join(parentCgroup, `cliq-${cgroupNameReservationDigest}`),
      cgroupNameReservationDigest, pidNamespaceReservationId: identityHash('cliq-edit-namespace-v1', dispatchId),
      subreaperStartToken: '' }, createdAt: sampleCanonicalNow(), planDigest: '' };
  const parentPlan = await artifacts.readCanonical<ProcessContainmentPlanV1>(workerSpec.containmentPlanRef);
  if (parentPlan.backend.kind !== 'linux' || plan.backend.kind !== 'linux') throw new KernelStorageError('ARTIFACT_MISMATCH', 'edit requires the exact Linux parent');
  plan.backend.subreaperStartToken = parentPlan.backend.subreaperStartToken;
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const containmentPlanRef = (await artifacts.publishCanonical(plan, plan.format)).ref;
  const spec: EditSpec = { ...workerSpec, owner, purpose: 'tool',
    executable: { kind: 'runtime_bundle', runtimeBundleRef: workerSpec.runtime.runtimeBundleRef,
      runtimeBundleManifestDigest: workerSpec.runtime.runtimeBundleManifestDigest, executableId: prepared.target.execution.adapterId,
      executableDigest: prepared.target.execution.adapterCodeDigest, role: 'tool_adapter', executionPath: LINUX_WORKER_RECIPE.editPath },
    processInvocation: { kind: 'run_request', purpose: 'tool', recipe: 'cliq-tool-launch-v1', requestRef: prepared.entry.requestRef,
      requestDigest: prepared.request.requestDigest, targetRef: prepared.entry.target, targetDigest: prepared.target.targetDigest,
      argvCwdSource: 'trusted_recipe_decode_of_request_and_target',
      stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' } },
    filesystem: { ...workerSpec.filesystem, access: 'read_write' }, parentWorkerContainmentRef: parentContainmentRef,
    requestRef: prepared.entry.requestRef, requestDigest: prepared.request.requestDigest, targetRef: prepared.entry.target,
    targetDigest: prepared.target.targetDigest, operationGrantRef: prepared.entry.grantRef!, containmentPlanRef,
    containmentPlanDigest: plan.planDigest, createdAt: sampleCanonicalNow(), launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  return (await artifacts.publishCanonical(spec, spec.format)).ref;
}

async function publishInspector(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1) {
  const inspector: SupervisorInspectorIdentityV1 = { schemaVersion: 1, format: 'cliq-supervisor-inspector-identity-v1',
    supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch, runtimeBundleRef: owner.runtimeBundleRef,
    runtimeBundleManifestDigest: owner.runtimeBundleManifestDigest, supervisorEntryId: owner.supervisorEntryId,
    supervisorEntryVersion: owner.supervisorEntryVersion, supervisorExecutableDigest: owner.supervisorExecutableDigest,
    processIdentityRef: owner.processIdentityRef, processIdentityDigest: owner.processIdentityDigest,
    stateLockIdentityRef: owner.stateLockIdentityRef, stateLockIdentityDigest: owner.stateLockIdentityDigest,
    instanceNonceDigest: owner.instanceNonceDigest, activatedAt: owner.acquiredAt, identityDigest: '' };
  inspector.identityDigest = digestOmitting(inspector, 'identityDigest');
  return { inspectorIdentityRef: (await artifacts.publishCanonical(inspector, inspector.format)).ref, inspectorIdentityDigest: inspector.identityDigest };
}

/** Deep internal resource owner. Opening validates only; process creation is lazy.
 * Durable lifecycle, retry and budgets remain exclusively in the existing reducers. */
export async function loadRunExecution(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; execution?: RunExecutionInstallation } | undefined,
  input: LoadRunExecutionInput, isClosing: () => boolean = () => false,
  selectedRuntime?: HeldInstalledRuntime, installedAnchor?: HeldInstalledAnchor, executionStore?: StateStore
): Promise<{ execution: RunExecution; closeWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }): Promise<Run>; close(): Promise<void> }> {
  // Validation material includes trusted resolver functions; retain those
  // functions while snapshotting their data, just like loadAgentRun does.
  input = { runId: input.runId, material: Object.fromEntries(Object.entries(input.material).map(([key, value]) =>
    [key, typeof value === 'function' ? value : immutableSnapshot(value)])) as RunAssemblyValidationMaterial };
  const runId = input.runId;
  const installed = selectedRuntime !== undefined || installedAnchor !== undefined;
  let installation: Pick<RunExecutionInstallation, 'cgroupParent'> | undefined;
  if (installed) {
    withInstalledWorkerRoot(selectedRuntime!, installedAnchor!, (_fd, cgroupParent) => { installation = { cgroupParent }; });
  } else installation = bootstrap?.execution && immutableSnapshot(bootstrap.execution);
  const launcher = installed ? await openInstalledLinuxWorkerLauncher(selectedRuntime!, installedAnchor!) :
    await openLinuxWorkerLauncher(bootstrap?.execution && { ...immutableSnapshot(bootstrap.execution), runtimeAuthority: bootstrap });
  let worker: LinuxBlockedWorker | undefined;
  async function reobserveRetirement() {
    if (closed || isClosing() || !worker || !activeWorker) {
      throw new KernelStorageError('LEASE_FENCED', 'native worker retirement scope is closing or unavailable');
    }
    assertActiveStateOwner(driver, owner);
    return observeOriginalWorkerDeath(activeWorker);
  }
  let agent: Awaited<ReturnType<typeof loadAgentRun>>;
  try {
    agent = await loadAgentRun(driver, artifacts, owner, { runId, material: input.material, releaseKeys: bootstrap!.releaseKeys },
      reobserveRetirement, selectedRuntime);
    const run = readRun(driver, runId);
    if (run.parentRunId !== undefined) throw new KernelStorageError('INVALID_REQUEST', 'this installed execution recipe does not support child Runs');
    const runSpec = decodeRunSpec(await artifacts.readCanonical(run.specRef));
    const assembly = decodeRetainedRunAssembly(await artifacts.readCanonical(runSpec.assemblyRef));
    const profile = decodeSandboxProfile(await artifacts.readCanonical(runSpec.sandboxProfileRef));
    const currentOwner = assertActiveStateOwner(driver, owner);
    if (assembly.runtime.sandboxBackend !== 'linux_namespace' || assembly.runtime.workerExecutableId !== LINUX_WORKER_RECIPE.workerId ||
        assembly.runtime.runtimeBundleRef !== currentOwner.runtimeBundleRef || profile.backend !== 'linux_namespace' ||
        !profile.allowedOwners.includes('worker_activation') || !profile.allowedOwners.includes('run_invocation') || profile.resources.maxProcesses < 8) {
      throw new KernelStorageError('INVALID_REQUEST', 'frozen Run requires an unsupported execution recipe');
    }
  } catch (error) {
    try { await launcher.close(); }
    catch (failure) { throw new ResourceRetirementError('execution opening failed and its installation cleanup did not complete', failure); }
    throw error;
  }
  let pending: Promise<Run> | undefined, closed = false, cleanupFailure: unknown;
  let operationAbort: AbortController | undefined, closing: Promise<void> | undefined;
  let probe: { run: Run; wait: WorkerDeathWait; task: WorkerRecoveryTask; closure?: Promise<Run> } | undefined;
  let generation: RunWorkspaceGeneration | undefined, controller: LinuxWorkerController | undefined;
  let reservation: HeldWorkerReservation | undefined;
  let ownedLaunchId: string | undefined;
  let activeWorker: ActiveWorker | undefined;
  let stopJoin: Promise<void> | undefined;
  let toolPhase: 'preparing' | 'claimed' | 'received' | undefined;
  let retirementController: LinuxWorkerController | undefined;
  let preparation: PreparingWorkerLaunch | undefined, materialization: RunWorkspaceMaterialization | undefined;
  let workspaceBirth: RunWorkspaceBirth | undefined;
  async function observeOriginalWorkerDeath(current: ActiveWorker) {
    if (current !== activeWorker || !worker) throw new KernelStorageError('LEASE_FENCED', 'worker retirement lost its original physical owner');
    if (!stopJoin) {
      try { return await worker.stop(); }
      catch (error) {
        // Stop may revoke this channel while its already-started STOP reply
        // is pending. Only the retained original irreversible join permits
        // a fresh inspector; uncertain descriptor retirement never does.
        if (!stopJoin || error instanceof ResourceRetirementError) throw error;
      }
    }
    await stopJoin;
    retirementController ??= await launcher.startController();
    const identity = decodeWorkerIdentity(await artifacts.readCanonical(current.activated.launch.workerIdentityDigest!));
    return retirementController.terminateRetained({ closure: current.closure, containment: worker.containment, workerIdentity: identity });
  }
  async function retireResources() {
    const retainedGeneration = generation, retainedController = controller, retainedReservation = reservation, retainedRetirement = retirementController,
      retainedMaterialization = materialization;
    retirementController = undefined;
    let retainedPreparation = preparation !== undefined;
    if (preparation) {
      try { retainedPreparation = readRequiredWorkerLaunch(driver, preparation.launchId).phase === 'preparing'; }
      catch (failure) { cleanupFailure ??= failure; }
    }
    // Failed preparation closure retains the original opaque producers even
    // after descriptor joins. An unresolved row must not lose its only true
    // birth owner merely because the caller received an operation error.
    if (!retainedPreparation) {
      materialization = undefined; workspaceBirth = undefined; preparation = undefined;
      generation = undefined; controller = undefined; reservation = undefined;
    }
    worker = undefined; ownedLaunchId = undefined; activeWorker = undefined;
    try { retainedGeneration?.close(); }
    catch (failure) { cleanupFailure ??= failure; }
    try { await retainedMaterialization?.close(); }
    catch (failure) { cleanupFailure ??= failure; }
    // One failed release must not bypass the independent process join.
    try { await retainedController?.close(); }
    catch (failure) { cleanupFailure ??= failure; }
    try { await retainedRetirement?.close(); }
    catch (failure) { cleanupFailure ??= failure; }
    try { retainedReservation?.close(); }
    catch (failure) { cleanupFailure ??= failure; }
    if (cleanupFailure !== undefined) throw cleanupFailure;
  }
  const revision = (value: { expectedRunRevision: number }) => {
    if (!exactKeys(value, ['expectedRunRevision']) || !Number.isSafeInteger(value.expectedRunRevision) || value.expectedRunRevision < 1) {
      throw new KernelStorageError('INVALID_REQUEST', 'execution requires one exact Run revision');
    }
    if (closed || isClosing()) throw new KernelStorageError('LEASE_FENCED', 'Run execution scope is closing or closed');
    if (cleanupFailure !== undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'Run execution scope has an unresolved retirement failure');
    if (pending) throw new KernelStorageError('REVISION_CONFLICT', 'Run execution already has an operation in flight');
    if (readRun(driver, runId).revision !== value.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'Run execution revision changed');
    assertActiveStateOwner(driver, owner);
    return value.expectedRunRevision;
  };
  /** One actual birth spine for model and tool frontiers. Success retains the
   * original resources; the existing operation owner joins them on failure. */
  async function activateWorker(selected: WorkerActivationCut, signal: AbortSignal): Promise<ActiveWorker> {
    if (activeWorker || worker || generation || controller || reservation || ownedLaunchId !== undefined) {
      throw new KernelStorageError('REVISION_CONFLICT', 'Run execution already owns native worker resources');
    }
    const { run } = selected;
    if (run.status !== 'queued' || run.activeWorkerLaunchId !== undefined || run.cancelRequested || run.stopIntentRef ||
        sampleCanonicalNow() >= run.deadlineAt) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker activation requires its unstopped lease-free queued cut');
    }
    const candidates = selected.workspaceGenerations.filter(row => row.phase === 'materializing' || row.phase === 'preactivated_readonly');
    if (selected.workspaceGenerations.some(row => !['sealed', 'retired', 'materializing', 'preactivated_readonly'].includes(row.phase)))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'worker activation requires positive retirement of every predecessor generation');
    if (candidates.length !== 0) {
      // Old unpaired replacements have no genuine preparation provenance.
      // Neither invent a launch for them nor lend them execution authority.
      throw new KernelStorageError('RECOVERY_REQUIRED', 'worker activation retains a private generation requiring its original preparation retirement');
    }
    const launchId = identityHash('cliq-worker-launch-v1', runId, String(run.leaseEpoch + 1), nonce());
    const spawnNonceDigest = nonce(), activationNonceDigest = nonce(), generationCreationNonceDigest = nonce();
    preparation = await beginWorkerPreparation(driver, artifacts, owner, { runId, expectedRunRevision: run.revision,
      launchId, spawnNonceDigest, activationNonceDigest, generationCreationNonceDigest });
    materialization = createRunWorkspaceMaterialization({ filesystem: owner.filesystem, artifacts,
      checkpoint: selected.latestCheckpoint, generationCreationNonceDigest, signal });
    workspaceBirth = await materialization.birth();
    const born = await recordWorkerPreparationGeneration(driver, artifacts, owner, { launchId, birth: workspaceBirth });
    signal.throwIfAborted();
    generation = await materialization.finish();
    const authority = await generation.publishMaterializedAuthority();
    if (authority.generationRef !== born.generationRef || authority.generationIdentityDigest !== born.generationIdentityDigest)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'ready generation differs from its original registered directory birth');
    const preactivatedGeneration = await recordWorkspaceGenerationPreactivated(driver, artifacts, owner, { generationId: generation.generationId,
      expectedRowVersion: born.generation.rowVersion, snapshotEvidenceRef: authority.snapshotEvidenceRef, snapshotEvidenceDigest: authority.snapshotEvidenceDigest });
    // Keep the existing two-write readonly pair intact across cancellation.
    signal.throwIfAborted();
    const profile = decodeSandboxProfile(await artifacts.readCanonical(selected.runSpec.sandboxProfileRef));
    const borrowed = borrowRunWorkspaceForExecution(generation);
    try { borrowed.assertQuota(profile.resources.maxGenerationBytes); } finally { borrowed.close(); }
    controller = await launcher.startController({ signal });
    reservation = owner.filesystem.createWorkerReservation(launchId, spawnNonceDigest);
    await recordWorkerPreparationController(driver, artifacts, owner, { launchId, birth: controller.preparationBirth, reservation });
    const recipe = await publishWorkerRecipe(artifacts, controller, installation!, selected, authority.generationRef,
      reservation, launchId, spawnNonceDigest, activationNonceDigest);
    const closure = await readWorkerLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { ...recipe.input, run });
    signal.throwIfAborted();
    const binding = await controller.bindWorkerReservation({ closure, reservation, activationNonceDigest });
    signal.throwIfAborted();
    const reserved = await reserveWorkerLaunch(driver, artifacts, owner, recipe.input, binding);
    ownedLaunchId = reserved.launchId;
    worker = await controller.launchWorker({ closure, generation, activationNonceDigest: reserved.activationNonceDigest });
    const processIdentity = await worker.observeProcess();
    const processContainmentRef = (await artifacts.publishCanonical(worker.containment, 'cliq-process-containment-v1')).ref;
    const workerIdentity: WorkerIdentity = { schemaVersion: 1, ...processIdentity, spawnNonceDigest: reserved.spawnNonceDigest,
      activationNonceDigest: reserved.activationNonceDigest, intendedLeaseEpoch: recipe.spec.owner.intendedLeaseEpoch, launchId: reserved.launchId,
      supervisorInstanceId: reserved.supervisorInstanceId, processContainmentRef };
    const workerIdentityDigest = (await artifacts.publishCanonical(workerIdentity, 'cliq-worker-identity-v1')).ref;
    await recordWorkerPreactivated(driver, artifacts, owner, { launchId: reserved.launchId, workerIdentityDigest, processContainmentRef });
    const activated = activateWorkerLeaseWithinDeadline(driver, owner, { launchId: reserved.launchId, expectedRunRevision: run.revision,
      expectedGenerationRowVersion: preactivatedGeneration.rowVersion });
    signal.throwIfAborted();
    await worker.activateCommitted(activated.launch);
    signal.throwIfAborted();
    activeWorker = { authority, recipe, reserved, activated, processContainmentRef, closure };
    return activeWorker;
  }
  /** Tool completion and stop drain share the original physical worker's
   * quiescence/snapshot spine. A retained artifact cannot supply this owner. */
  async function retireToCheckpoint(current: ActiveWorker, checkpointId: string, signal: AbortSignal) {
    if (current !== activeWorker || !worker || !generation || ownedLaunchId !== current.activated.launch.launchId) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'checkpoint retirement lost its original physical worker owner');
    }
    const currentWorker = worker, currentGeneration = generation;
    const { authority, recipe, reserved, activated, processContainmentRef } = current;
    const beforeSeal = await readRecoveryClosure(driver, artifacts, runId);
    signal.throwIfAborted();
    const activeGeneration = beforeSeal.workspaceGenerations.find(row => row.generationRef === authority.generationRef);
    const activeLaunch = beforeSeal.workerLaunches.find(row => row.launchId === activated.launch.launchId);
    if (!activeGeneration || !activeLaunch || activeLaunch.phase !== 'activated' || beforeSeal.run.activeWorkerLaunchId !== activeLaunch.launchId ||
        beforeSeal.run.leaseEpoch !== activeLaunch.leaseEpoch || activeLaunch.workspaceGenerationRef !== authority.generationRef ||
        activeLaunch.workerIdentityDigest !== activated.launch.workerIdentityDigest || activeLaunch.processContainmentRef !== processContainmentRef) {
      throw new KernelStorageError('LEASE_FENCED', 'checkpoint retirement differs from the original worker and generation');
    }
    const quiesceId = identityHash('cliq-worker-quiesce-v1', activated.launch.launchId, checkpointId);
    const revoking = beginGenerationRevocation(driver, owner, { launchId: activeLaunch.launchId,
      expectedLeaseVersion: activeLaunch.leaseVersion, expectedGenerationRowVersion: activeGeneration.rowVersion, quiesceId });
    const death = await observeOriginalWorkerDeath(current);
    assertNativeContainmentDeath(death);
    requireEqual(death.containment, currentWorker.containment, 'checkpoint original native containment');
    const checkpointing = beginGenerationCheckpoint(driver, owner, { launchId: activeLaunch.launchId, expectedLeaseVersion: revoking.launch.leaseVersion,
      expectedGenerationRowVersion: revoking.generation.rowVersion, quiesceId });
    const observed = await currentGeneration.observe({ signal });
    const inspector = await publishInspector(artifacts, assertActiveStateOwner(driver, owner));
    const deathCore = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: processContainmentRef,
      planRef: recipe.input.containmentPlanRef, sandboxLaunchSpecRef: recipe.input.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: recipe.spec.launchSpecDigest, owner: death.containment.owner, launchNonceDigest: reserved.spawnNonceDigest,
      inspectorSupervisorInstanceId: owner.supervisorInstanceId, ...inspector,
      backend: { ...death.containment.backend, cgroupPopulated: death.cgroupPopulated,
        namespaceInitDeadAndReaped: death.namespaceInitDeadAndReaped, remainingTrackedDescendants: death.remainingTrackedDescendants }, observedAt: death.observedAt };
    const retirement = await artifacts.publishCanonical({ ...deathCore, evidenceDigest: canonicalSha256(deathCore) }, 'cliq-process-containment-death-evidence-v1');
    const state = await artifacts.readCanonical<import('../kernel/types.js').WorkspaceStateManifest>(observed.workspaceStateRef);
    const snapshot: WorkspaceGenerationSnapshotEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1',
      purpose: 'sealed_to_checkpoint', quiescenceEvidenceRef: retirement.ref, runId,
      generationRef: authority.generationRef, generationIdentityDigest: authority.generationIdentityDigest,
      checkpointId, workspaceStateRef: observed.workspaceStateRef, workspaceStateDigest: observed.workspaceStateDigest,
      entriesRef: observed.entriesRef, treeDigest: observed.treeDigest,
      ...(state.privateGitStateRef ? { privateGitStateRef: state.privateGitStateRef } : {}),
      descriptorRewalkComplete: observed.descriptorRewalkComplete, fileFsyncComplete: observed.fileFsyncComplete,
      directoryFsyncComplete: observed.directoryFsyncComplete, observedAt: sampleCanonicalNow(), evidenceDigest: '' };
    snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
    const snapshotEvidenceRef = (await artifacts.publishCanonical(snapshot, snapshot.format)).ref;
    return { postEffect: { workspaceStateRef: observed.workspaceStateRef, snapshotEvidenceRef, retirementEvidenceRef: retirement.ref },
      snapshot, checkpointing, quiesceId };
  }
  function ownOperation(work: Promise<Run>, abort: AbortController, retainWorker = false): Promise<Run> {
    let operationFailure: { error: unknown } | undefined;
    const operation = work.catch(async error => {
      operationFailure = { error };
      if (error instanceof ResourceRetirementError) cleanupFailure ??= error;
      let retiringPreparation = false;
      try {
        const run = readRun(driver, runId);
        if (preparation && readRequiredWorkerLaunch(driver, preparation.launchId).phase === 'preparing') {
          retiringPreparation = true;
          // Keep the original producer and actual births until the genuine
          // preparation retirement has committed. Descriptor close alone is
          // not a durable proof of either tree or controller retirement.
          const original = preparation, birth = workspaceBirth;
          await materialization?.close();
          const controllerRetirement = controller ? await controller.closePreparation() : undefined;
          reservation?.close();
          if ((!birth && !materialization) || !executionStore) throw new ResourceRetirementError('worker preparation has no complete original birth/retirement closure', error);
          await retireWorkerPreparation(driver, artifacts, owner, { preparation: original,
            expectedRunRevision: readRun(driver, runId).revision,
            ...(birth ? { workspaceBirth: birth } : { unallocatedWorkspace: materialization! }),
            ...(controllerRetirement ? { controllerRetirement } : {}), ...(reservation ? { reservation } : {}),
            brokerQuiescence: observeInstalledBrokerQuiescence(executionStore, runId) });
        } else if (ownedLaunchId !== undefined && run.activeWorkerLaunchId === ownedLaunchId) {
          await beginWorkerRecovery(driver, artifacts, owner, { runId, expectedRunRevision: run.revision });
        } else if (ownedLaunchId !== undefined && run.status === 'queued') {
          // Join the original spawner first. A new controller can only inspect
          // the exact witness; it cannot release the old activation channel.
          await controller?.close();
          controller = await launcher.startController();
          await retirePreactivationLaunch(driver, artifacts, owner, ownedLaunchId, controller);
          worker = undefined;
        }
      } catch (failure) {
        // Losing the state fence cannot bypass actual resource retirement or
        // be mistaken for a graceful owner release.
        cleanupFailure ??= retiringPreparation
          ? new ResourceRetirementError('worker preparation physical retirement did not complete', failure) : failure;
      } finally {
        if (worker) {
          try { const death = activeWorker ? await observeOriginalWorkerDeath(activeWorker) : await worker.stop(); assertNativeContainmentDeath(death); }
          catch (failure) { cleanupFailure ??= failure; }
        }
      }
      throw error;
    }).finally(async () => {
      try { if (!retainWorker || operationFailure) await retireResources(); }
      catch (failure) {
        if (operationFailure && operationFailure.error !== failure) {
          cleanupFailure = new ResourceRetirementError('Run execution failed and its resources did not retire',
            new AggregateError([operationFailure.error, failure], 'execution and retirement failures'));
          throw cleanupFailure;
        }
        throw failure;
      } finally { pending = undefined; toolPhase = undefined; if (operationAbort === abort) operationAbort = undefined; }
    });
    pending = operation;
    return operation;
  }
  async function closeProbe(input: { runId: string; expectedRunRevision: number }, waitForDeadline = false): Promise<Run> {
    input = immutableSnapshot(input);
    if (!exactKeys(input, ['runId', 'expectedRunRevision']) || input.runId !== runId ||
        !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) {
      throw new KernelStorageError('INVALID_REQUEST', 'worker timeout requires this Run and one exact revision');
    }
    const run = readRun(driver, runId);
    if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'worker timeout Run revision changed');
    const retained = probe;
    if (!retained || run.waitingOnRef !== retained.run.waitingOnRef) {
      // No task in this resource owner is not proof of cancellation/join.
      return closeWorkerRecoveryProbe(driver, artifacts, owner, input);
    }
    if (retained.wait.probeState.phase !== 'automatic_in_flight') throw new KernelStorageError('RECOVERY_REQUIRED', 'registered worker task has no dispatch');
    const deadline = retained.wait.probeState.dispatch.probeDeadlineAt;
    if (!waitForDeadline && sampleCanonicalNow() < deadline) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker inspection deadline has not elapsed');
    }
    if (retained.closure) return retained.closure;
    const closingProbe = (async () => {
      const receipt = await retained.task.cancelAndJoin();
      // A matching completion may have won before cancellation. Shutdown can
      // then release normally; a public stale-revision closure cannot.
      let current = readRun(driver, runId);
      if (current.waitingOnRef !== retained.run.waitingOnRef) {
        if (waitForDeadline) return current;
        throw new KernelStorageError('REVISION_CONFLICT', 'worker inspection completed before cancellation');
      }
      const boundedUntil = performance.now() + 31_000;
      while (sampleCanonicalNow() < deadline) {
        const fence = assertFenceHealthy(readTimeFence(driver));
        const now = sampleCanonicalNow();
        if (now < fence.lastAcceptedAt || performance.now() >= boundedUntil) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'worker shutdown cannot advance its stored deadline under a regressed clock');
        }
        await delay(Math.min(1000, Math.max(1, Date.parse(deadline) - Date.parse(now))));
      }
      current = readRun(driver, runId);
      const result = await closeWorkerRecoveryProbe(driver, artifacts, owner,
        { runId, expectedRunRevision: waitForDeadline ? current.revision : input.expectedRunRevision }, receipt);
      if (probe === retained) probe = undefined;
      return result;
    })();
    retained.closure = closingProbe;
    try { return await closingProbe; }
    catch (error) {
      if (error instanceof ResourceRetirementError) cleanupFailure ??= error;
      if (retained.closure === closingProbe) retained.closure = undefined;
      throw error;
    }
  }
  const execution: RunExecution = Object.freeze({
    requestStop: () => {
      if (stopJoin) return stopJoin;
      const current = readRun(driver, runId);
      assertActiveStateOwner(driver, owner);
      if (!current.stopIntentRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'productive revocation requires the committed StopIntent');
      // Inspections are authority reducing and retain their own original join.
      // A stop must not cancel the very proof needed to close that wait.
      if (probe && current.status === 'waiting' && current.waitingOnRef === probe.run.waitingOnRef) return Promise.resolve();
      if (toolPhase !== 'claimed' && toolPhase !== 'received') operationAbort?.abort();
      const retainedController = controller, retainedWorker = worker;
      // close enters irreversible native channel revocation synchronously,
      // before the control request can acknowledge its durable intent.
      const revoked = retainedController?.close();
      stopJoin = (async () => {
        await revoked;
        await retainedWorker?.closeAfterControllerJoin();
      })().catch(error => {
        cleanupFailure ??= error;
        throw error;
      });
      return stopJoin;
    },
    renewCurrentWorkerLease: () => {
      // An operation in flight owns its current lease. Maintenance cannot
      // race its native activation, revocation or Checkpoint transition.
      if (closed || isClosing() || pending || !activeWorker || !worker || !generation || !controller || !reservation) return 'inactive';
      if (cleanupFailure !== undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker maintenance retains a resource retirement failure');
      const retained = activeWorker, run = readRun(driver, runId);
      if (run.status !== 'running' || run.cancelRequested || run.stopIntentRef !== undefined || run.activeWorkerLaunchId === undefined) return 'inactive';
      const launch = readRequiredWorkerLaunch(driver, run.activeWorkerLaunchId);
      if (launch.phase !== 'activated' || launch.generationWriteState !== 'active') return 'inactive';
      if (launch.launchId !== ownedLaunchId || launch.launchId !== retained.activated.launch.launchId ||
          launch.leaseEpoch !== retained.activated.launch.leaseEpoch || launch.workerIdentityDigest !== retained.activated.launch.workerIdentityDigest ||
          launch.workspaceGenerationRef !== retained.authority.generationRef || launch.processContainmentRef !== retained.processContainmentRef) {
        throw new KernelStorageError('LEASE_FENCED', 'worker maintenance differs from its original physical owner');
      }
      reservation.assertHeld();
      worker.assertHeld();
      assertActiveStateOwner(driver, owner);
      const now = sampleCanonicalNow(), nowMs = parseCanonicalTime(now);
      if (!launch.leaseExpiresAt || nowMs >= parseCanonicalTime(launch.leaseExpiresAt) || nowMs >= parseCanonicalTime(run.deadlineAt)) return 'expired';
      const live = assertLiveDispatchState(driver, owner, runId, run.revision, run.leaseEpoch, now);
      requireEqual(live.launch, launch, 'worker maintenance current launch');
      requireEqual(live.generation, retained.activated.generation, 'worker maintenance original active generation');
      if (parseCanonicalTime(launch.leaseExpiresAt) - nowMs > 30_000) return 'unchanged';
      const renewed = renewWorkerLease(driver, owner, { launchId: launch.launchId, expectedLeaseVersion: launch.leaseVersion,
        runId, leaseEpoch: run.leaseEpoch, workerIdentityDigest: launch.workerIdentityDigest!,
        newLeaseExpiresAt: new Date(Math.min(nowMs + 60_000, parseCanonicalTime(run.deadlineAt))).toISOString() });
      retained.activated = { ...retained.activated, launch: renewed };
      return 'renewed';
    },
    assertCurrentModelWorker: value => {
      if (!exactKeys(value, ['runId', 'leaseEpoch', 'launchId', 'generationRef', 'workerIdentityDigest']) ||
          value.runId !== runId || !Number.isSafeInteger(value.leaseEpoch) || value.leaseEpoch < 1 ||
          closed || isClosing() || cleanupFailure !== undefined || pending || !activeWorker || !worker || !generation || !controller || !reservation ||
          value.launchId !== ownedLaunchId || value.launchId !== activeWorker.activated.launch.launchId ||
          value.generationRef !== activeWorker.authority.generationRef || value.workerIdentityDigest !== activeWorker.activated.launch.workerIdentityDigest) {
        throw new KernelStorageError('LEASE_FENCED', 'model release does not name this execution owner\'s original physical worker');
      }
      const run = readRun(driver, runId);
      const live = assertLiveDispatchState(driver, owner, runId, run.revision, value.leaseEpoch, sampleCanonicalNow());
      if (run.nextStep !== 'agent' || live.launch.launchId !== value.launchId || live.launch.workerIdentityDigest !== value.workerIdentityDigest ||
          live.launch.workspaceGenerationRef !== value.generationRef || live.launch.processContainmentRef !== activeWorker.processContainmentRef) {
        throw new KernelStorageError('LEASE_FENCED', 'model release durable worker identity changed');
      }
      reservation.assertHeld();
      worker.assertHeld();
      // The native worker already retains the original generation borrow;
      // its assertion verifies that descriptor, mount, quota identity and owner.
      assertActiveStateOwner(driver, owner);
    },
    activateCurrentWorker: async value => {
      const expectedRunRevision = revision(value);
      const abort = new AbortController();
      operationAbort = abort;
      const signal = abort.signal;
      const work = (async () => {
        signal.throwIfAborted();
        const selected = await readRecoveryClosure(driver, artifacts, runId);
        signal.throwIfAborted();
        if (selected.run.revision !== expectedRunRevision || selected.run.nextStep !== 'agent' || !selected.run.frontierRef) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model worker activation requires its current agent frontier');
        }
        const frontier = await artifacts.readCanonical<import('../kernel/types.js').RunFrontier>(selected.run.frontierRef);
        if (frontier.kind !== 'agent' || !['model_turn', 'context_compaction'].includes(frontier.phase)) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model worker activation requires a validated model frontier');
        }
        signal.throwIfAborted();
        const activated = await activateWorker(selected, signal);
        return activated.activated.run;
      })();
      return ownOperation(work, abort, true);
    },
    executeCurrentTool: async value => {
      const expectedRunRevision = revision(value);
      const abort = new AbortController();
      operationAbort = abort;
      const signal = abort.signal;
      toolPhase = 'preparing';
      let claimedTool: Awaited<ReturnType<typeof agent.claimTool>> | undefined;
      const work = (async () => {
        signal.throwIfAborted();
        const selected = await readToolCut(driver, artifacts, runId, agent.resolveToolInput);
        signal.throwIfAborted();
        const queued = selected.run.status === 'queued' && selected.run.activeWorkerLaunchId === undefined;
        const retained = selected.run.status === 'running' && activeWorker !== undefined && worker !== undefined && generation !== undefined &&
          selected.run.activeWorkerLaunchId === activeWorker.activated.launch.launchId;
        if (selected.run.revision !== expectedRunRevision || (!queued && !retained) || selected.run.cancelRequested ||
            selected.run.stopIntentRef || sampleCanonicalNow() >= selected.run.deadlineAt) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool execution requires its queued cut or this owner\'s live native worker');
        }
        if (retained) {
          const live = assertLiveDispatchState(driver, owner, runId, expectedRunRevision, selected.run.leaseEpoch, sampleCanonicalNow());
          if (live.launch.workspaceGenerationRef !== activeWorker!.authority.generationRef ||
              live.launch.processContainmentRef !== activeWorker!.processContainmentRef || live.launch.launchId !== ownedLaunchId) {
            throw new KernelStorageError('LEASE_FENCED', 'tool cut differs from this execution owner\'s original worker');
          }
          await worker!.observeProcess();
          signal.throwIfAborted();
        }
        if (selected.call.toolName !== 'edit') throw new KernelStorageError('INVALID_REQUEST', 'this installed recipe supports only the current builtin edit');
        const projection = await agent.readToolInvocation();
        requireEqual(projection.run, selected.run, 'current native tool projection');
        if (projection.kind !== 'tool' || projection.execution.kind !== 'builtin' || projection.execution.adapterId !== LINUX_WORKER_RECIPE.editId) {
          throw new KernelStorageError('INVALID_REQUEST', 'this installed recipe does not support the frozen tool execution identity');
        }
        const workspaceCut = await readRecoveryClosure(driver, artifacts, runId);
        requireEqual(workspaceCut.run, selected.run, 'native tool workspace cut');
        const current = queued ? await activateWorker(workspaceCut, signal) : activeWorker!;
        const { recipe, processContainmentRef } = current;
        const activated = { ...current.activated, run: queued ? current.activated.run : selected.run };
        if (!worker || !generation) throw new KernelStorageError('RECOVERY_REQUIRED', 'native tool execution lost its original physical owner');
        const currentWorker = worker;
        signal.throwIfAborted();
        const prepared = await agent.prepareTool({ expectedRunRevision: activated.run.revision, leaseEpoch: activated.run.leaseEpoch });
        if (prepared.disposition !== 'prepared') {
          const checkpointId = prepared.disposition === 'approval_required' ? prepared.checkpointId
            : identityHash('cliq-denied-tool-worker-checkpoint-v1', runId, prepared.run.latestCheckpointId, nonce());
          const proof = await retireToCheckpoint(current, checkpointId, signal);
          if (prepared.disposition === 'approval_required') {
            await agent.waitForToolApproval({ expectedRunRevision: prepared.run.revision, waitingOnRef: prepared.waitingOnRef, checkpoint: proof.postEffect });
          } else {
            const current = await readRecoveryClosure(driver, artifacts, runId);
            await sealWorkerGeneration(driver, artifacts, owner, { launchId: activated.launch.launchId,
              expectedRunRevision: current.run.revision, expectedGenerationRowVersion: proof.checkpointing.generation.rowVersion,
              quiesceId: proof.quiesceId, checkpointId, contextManifestRef: current.latestCheckpoint.contextManifestRef,
              ...proof.postEffect, snapshotEvidenceDigest: proof.snapshot.evidenceDigest, checkpointReason: 'auto' }, reobserveRetirement);
          }
          return readRun(driver, runId);
        }
        const dispatchId = identityHash('cliq-tool-dispatch-v1', runId, prepared.entry.opId, String(prepared.entry.attempt), nonce());
        if (currentWorker.containment.backend.kind !== 'linux') throw new KernelStorageError('ARTIFACT_MISMATCH', 'native edit parent is not Linux');
        const sandboxLaunchSpecRef = await publishEditRecipe(artifacts, recipe.spec, processContainmentRef, currentWorker.containment.backend.cgroupPath, prepared, dispatchId);
        // The permanent claim precedes even blocked invocation process creation.
        signal.throwIfAborted();
        const claimed = await agent.claimTool({ expectedRunRevision: prepared.run.revision, leaseEpoch: activated.run.leaseEpoch,
          opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId, sandboxLaunchSpecRef });
        claimedTool = claimed;
        toolPhase = 'claimed';
        const call = await artifacts.readCanonical<import('../protocol/agent-ir.js').ToolCallInputV1>(claimed.request.inputRef);
        const grant = await artifacts.readCanonical<import('../kernel/tool-authorization.js').ToolOperationGrantV1>(claimed.entry.grantRef!);
        const live = assertLiveDispatchState(driver, owner, runId, prepared.run.revision, activated.run.leaseEpoch, sampleCanonicalNow());
        const edit = await readBuiltinEditLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { ...live, prepared: prepared.entry,
          request: claimed.request, target: claimed.target, call, grant, dispatchId, sandboxLaunchSpecRef });
        const invocation = await currentWorker.createInvocation(edit);
        await invocation.observeProcess();
        signal.throwIfAborted();
        await claimed.release(invocation);
        const result = await invocation.result();
        toolPhase = 'received';
        const observedAt = sampleCanonicalNow();
        const proof = await retireToCheckpoint(current, toolCheckpointId(runId, prepared.entry.opId, prepared.entry.attempt), signal);
        const base = { schemaVersion: 1 as const, format: 'cliq-tool-observation-v1' as const, runId, opId: claimed.entry.opId,
          attempt: claimed.entry.attempt, requestRef: claimed.entry.requestRef, targetRef: claimed.entry.target,
          grantRef: claimed.entry.grantRef!, dispatchId, observedAt,
          postEffect: proof.postEffect };
        let observation: ToolObservationV1;
        if (result === 'ok') observation = { ...base, outcome: 'executed', content: { ok: true }, observationDigest: '' };
        else {
          const diagnostic = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_EXECUTION_FAILED' }, 'cliq-tool-output-diagnostic-v1');
          observation = { ...base, outcome: 'error', code: 'TOOL_EXECUTION_FAILED', diagnosticRef: diagnostic.ref, diagnosticDigest: diagnostic.ref, observationDigest: '' };
        }
        observation.observationDigest = digestOmitting(observation, 'observationDigest');
        const observationRef = (await artifacts.publishCanonical(observation, observation.format)).ref;
        // A user stop changes Run revision, not this original producer's
        // genuinely observed outcome. Retain the immutable result while the
        // owning reducer revalidates the current cut; never replay the tool.
        // That reducer still rejects a changed frontier, claim or lease.
        for (let completion = 0; ; completion++) {
          const current = readRun(driver, runId);
          if (current.leaseEpoch !== claimed.entry.leaseEpoch || current.activeWorkerLaunchId !== ownedLaunchId) {
            throw new KernelStorageError('LEASE_FENCED', 'tool result no longer belongs to its original active worker');
          }
          try {
            await agent.completeTool({ opId: claimed.entry.opId, attempt: claimed.entry.attempt,
              expectedRunRevision: current.revision, observationRef });
            break;
          } catch (error) {
            if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT' || completion >= 7 ||
                readRun(driver, runId).revision === current.revision) throw error;
          }
        }
        return readRun(driver, runId);
      })().catch(async error => {
        if (claimedTool && toolPhase !== 'received') {
          // A permanent claim is possibly dispatched even when cancellation
          // wins before the blocked child/RELEASE handshake. Join the actual
          // producer, preserve uncertainty and charge once; only the separate
          // genuine private rollback closure may later resolve that unknown.
          if (!stopJoin) {
            const retainedController = controller, retainedWorker = worker;
            const revoke = retainedController?.close();
            stopJoin = (async () => { await revoke; await retainedWorker?.closeAfterControllerJoin(); })();
          }
          await stopJoin;
          const history = readInvocationAttempt(driver, runId, claimedTool.entry.opId, claimedTool.entry.attempt);
          if (history.at(-1)?.phase === 'dispatch_claimed') {
            const ambiguity = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-private-tool-ambiguity-v1',
              runId, opId: claimedTool.entry.opId, attempt: claimedTool.entry.attempt, dispatchId: claimedTool.entry.dispatchId,
              claimJournalSeq: claimedTool.entry.seq, requestRef: claimedTool.entry.requestRef, targetRef: claimedTool.entry.target,
              grantRef: claimedTool.entry.grantRef, reason: 'original_producer_joined_without_result' }, 'cliq-private-tool-ambiguity-v1');
            await markInvocationUnknown(driver, artifacts, owner, { runId, opId: claimedTool.entry.opId,
              attempt: claimedTool.entry.attempt, expectedRunRevision: readRun(driver, runId).revision,
              evidenceRef: ambiguity.ref, evidenceDigest: ambiguity.ref });
          }
        }
        throw error;
      });
      return ownOperation(work, abort);
    },
    finishCurrentStop: async value => {
      const expectedRunRevision = revision(value);
      const selected = await readRecoveryClosure(driver, artifacts, runId);
      // A read may yield to close or another operation. Revalidate the exact
      // scope/revision before taking operation ownership or changing resources.
      revision({ expectedRunRevision });
      if (selected.run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'stop drain revision changed');
      const stopIntentRef = selected.run.stopIntentRef;
      if (!stopIntentRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop drain requires the persisted StopIntent');
      // Refuse BEFORE ownOperation: its failure handler intentionally performs
      // physical recovery. An unclosed claim must not enter that lifecycle just
      // because a terminal request is unsupported. The model-death path below
      // is worker-free; it cannot authorize sealing an active worker.
      if (selected.run.activeWorkerLaunchId !== undefined) {
        const noRelease = await validateInstalledModelNoReleaseHistory(driver, artifacts, selected);
        for (const { entry, hasClaim } of stopInvocationHistory(selected.journal).values()) {
          if (!['model', 'tool'].includes(entry.opKind) || (!['prepared', 'completed'].includes(entry.phase) &&
              (entry.phase !== 'failed' || hasClaim && !(entry.opKind === 'model' && noRelease.has(entry.seq))))) {
            throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
          }
        }
      }
      const abort = new AbortController();
      operationAbort = abort;
      const signal = abort.signal;
      const work = (async () => {
        signal.throwIfAborted();
        if (selected.run.activeWorkerLaunchId === undefined) {
          if (activeWorker || worker || generation || controller || reservation || ownedLaunchId !== undefined) {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'worker-free stop retains unresolved physical execution resources');
          }
          // The reducer requires every original generation sealed or backed
          // by retirement evidence; this branch supplies no new authority.
          return (await agent.commitTerminalStop({ expectedRunRevision })).run;
        }
        if (!activeWorker || !worker || !generation || !controller || !reservation ||
            selected.run.activeWorkerLaunchId !== ownedLaunchId || selected.run.activeWorkerLaunchId !== activeWorker.activated.launch.launchId) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'stop drain cannot adopt another worker\'s retirement authority');
        }
        const proof = await retireToCheckpoint(activeWorker, stopCheckpointId(runId, stopIntentRef), signal);
        signal.throwIfAborted();
        // commitTerminalStop checks exact settled invocation history, the
        // currently accounted workspace, and refreshes actual native death
        // before its one atomic Checkpoint/Session/terminal transition.
        return (await agent.commitTerminalStop({ expectedRunRevision, checkpoint: proof.postEffect })).run;
      })();
      return ownOperation(work, abort);
    },
    resumeCurrentRetirement: async value => {
      const expectedRunRevision = revision(value);
      const abort = new AbortController(); operationAbort = abort;
      const signal = abort.signal;
      const work = (async () => {
        let cut = await readRecoveryClosure(driver, artifacts, runId);
        signal.throwIfAborted();
        if (cut.run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'retirement resume revision changed');
        const eligible: Array<{ row: (typeof cut.workspaceGenerations)[number];
          quarantine: import('../kernel/types.js').WorkspaceGenerationQuarantineEvidenceV1 }> = [];
        // The recovery closure validates worker-recovery and preactivation
        // graphs. An unsupported producer must not become a successful no-op.
        for (const row of cut.workspaceGenerations) {
          if (row.phase !== 'quarantined') continue;
          signal.throwIfAborted();
          const quarantine = await artifacts.readCanonical<import('../kernel/types.js').WorkspaceGenerationQuarantineEvidenceV1>(row.quarantineEvidenceRef);
          if (quarantine.reason === 'worker_recovery' || quarantine.reason === 'launch_aborted' || quarantine.reason === 'launch_died_before_activation')
            eligible.push({ row, quarantine });
          else {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'retirement resume has no validated recipe for this quarantine producer');
          }
        }
        signal.throwIfAborted();
        if (eligible.length === 0) return cut.run;
        if (cut.run.status !== 'queued' || cut.run.activeWorkerLaunchId !== undefined ||
            activeWorker || worker || generation || controller || reservation || ownedLaunchId !== undefined || !executionStore) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'retirement resume requires its lease-free queued cut and original installed resource owner');
        }
        for (const { row, quarantine } of eligible) {
          signal.throwIfAborted();
          const launches = readWorkerLaunchesForRun(driver, runId).filter(launch => launch.workspaceGenerationRef === row.generationRef);
          if (launches.length !== 1) throw new KernelStorageError('RECOVERY_REQUIRED', 'retirement resume has no unique original worker launch');
          const launch = launches[0]!;
          const closure = await readQuarantinedWorkerLaunchClosure(driver, artifacts, owner, { run: cut.run, launch, generation: row });
          controller = await launcher.startController({ signal });
          let retirement: { workerRetirement: NativeRetainedWorkerRetirement } | { preactivationRetirement: NativePreactivationRetirement };
          if (quarantine.reason === 'worker_recovery') {
            const containment = decodeWorkerProcessContainment(await artifacts.readCanonical(launch.processContainmentRef!));
            const workerIdentity = decodeWorkerIdentity(await artifacts.readCanonical(launch.workerIdentityDigest!));
            const death = await controller.terminateRetained({ closure, containment, workerIdentity, signal });
            assertNativeContainmentDeath(death);
            retirement = { workerRetirement: await controller.closeRetained() };
          } else {
            const backend = closure.plan.backend;
            if (backend.kind !== 'linux' || !backend.nativeReservation)
              throw new KernelStorageError('RECOVERY_REQUIRED', 'preactivation generation retirement has no exact native reservation');
            reservation = owner.filesystem.openWorkerReservation(launch.launchId, launch.spawnNonceDigest, backend.nativeReservation);
            const containment = launch.processContainmentRef === undefined ? undefined
              : decodeWorkerProcessContainment(await artifacts.readCanonical(launch.processContainmentRef));
            const workerIdentity = launch.workerIdentityDigest === undefined ? undefined
              : decodeWorkerIdentity(await artifacts.readCanonical(launch.workerIdentityDigest));
            const observed = await controller.inspectPreactivation({ closure, reservation, activationNonceDigest: launch.activationNonceDigest,
              ...(containment === undefined ? {} : { containment }), ...(workerIdentity === undefined ? {} : { workerIdentity }) });
            assertNativePreactivationObservation(observed, closure);
            if ((quarantine.reason === 'launch_aborted') !== (observed.kind === 'no_spawn'))
              throw new KernelStorageError('ARTIFACT_MISMATCH', 'preactivation retirement changed its original no-spawn or created branch');
            if (observed.kind === 'created') assertNativeContainmentDeath(observed.death);
            retirement = { preactivationRetirement: await controller.closePreactivation() };
          }
          const workspaceRetirement = await observeRetainedRunWorkspace({ filesystem: owner.filesystem, artifacts,
            identity: closure.generation, sourceRowVersion: quarantine.sourceRowVersion, signal });
          signal.throwIfAborted();
          const brokerQuiescence = observeInstalledBrokerQuiescence(executionStore, runId);
          await retireQuarantinedGeneration(driver, artifacts, owner, { runId, expectedRunRevision: cut.run.revision,
            expectedGenerationRowVersion: row.rowVersion, generationRef: row.generationRef, ...retirement, workspaceRetirement, brokerQuiescence });
          await retireResources();
          cut = await readRecoveryClosure(driver, artifacts, runId);
        }
        return cut.run;
      })();
      return ownOperation(work, abort, true);
    },
    recoverWorker: async value => {
      const expectedRunRevision = revision(value);
      let registered: WorkerRecoveryTask | undefined;
      const sameInspectionStopCut = (previous: Run, current: Run): boolean => {
        if (canonicalSha256(previous) === canonicalSha256(current)) return true;
        const stable = ({ revision: _revision, updatedAt: _time, stopIntentRef: _intent, cancelRequested: _cancel, ...data }: Run) => data;
        return current.revision > previous.revision && current.updatedAt >= previous.updatedAt &&
          !!current.stopIntentRef && (!previous.cancelRequested || current.cancelRequested) &&
          canonicalSha256(stable(current)) === canonicalSha256(stable(previous));
      };
      const inspect = async (run: Run, wait: WorkerDeathWait, signal: AbortSignal): Promise<Run> => {
        signal.throwIfAborted();
        const cut = await readRecoveryClosure(driver, artifacts, runId);
        signal.throwIfAborted();
        if (!sameInspectionStopCut(run, cut.run)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'worker inspection dispatch cut changed');
        }
        const launch = cut.workerLaunches.find(row => row.launchId === wait.subject.oldWorkerLaunchId)!;
        const oldGeneration = cut.workspaceGenerations.find(row => row.generationRef === wait.subject.workspaceGenerationRef)!;
        const closure = await readRetainedWorkerLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { run: cut.run, launch, generation: oldGeneration });
        const containment = decodeWorkerProcessContainment(await artifacts.readCanonical(launch.processContainmentRef!));
        const workerIdentity = decodeWorkerIdentity(await artifacts.readCanonical(launch.workerIdentityDigest!));
        signal.throwIfAborted();
        controller = await launcher.startController({ signal });
        // This separate authority-reducing action terminates the retained
        // domain; the persisted inspector task itself grants no mutation.
        const death = await controller.terminateRetained({ closure, containment, workerIdentity, signal });
        assertNativeContainmentDeath(death);
        signal.throwIfAborted();
        const handoff = cut.run.nextStep === 'agent' ? await agent.readModelAttempt() : undefined;
        if (handoff && !sameInspectionStopCut(cut.run, handoff.run)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery model handoff cut changed');
        }
        const unknownHandoff = handoff?.state.phase === 'unknown' && hasOnlySettledInstalledModelUnknowns(
          decodeRetainedRunAssembly(await artifacts.readCanonical(cut.runSpec.assemblyRef)), cut.journal);
        const replacement = cut.workspaceGenerations.filter(row => row.phase === 'preactivated_readonly' || row.phase === 'materializing');
        if (unknownHandoff && replacement.length !== 0) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'unknown model worker quarantine cannot retain an unused replacement generation');
        }
        if (replacement.length > 0 && (replacement.length !== 1 || replacement[0]!.phase !== 'preactivated_readonly')) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery retains an incomplete or competing replacement');
        }
        // Recovery owns only the predecessor's physical closure. Never create
        // its successor before that generation has actually retired: a stop
        // may win at any inspection await. Ordinary queued activation restores
        // the ready Checkpoint lazily, after retirement and current eligibility.
        // Historical replacements remain explicit retained resources, not a
        // reason to invent a second birth or silently discard the first one.
        const current = await readRecoveryClosure(driver, artifacts, runId);
        if (!sameInspectionStopCut(cut.run, current.run) ||
            canonicalSha256(current.journal) !== canonicalSha256(cut.journal) ||
            canonicalSha256(current.workerLaunches) !== canonicalSha256(cut.workerLaunches) ||
            canonicalSha256(current.workspaceGenerations) !== canonicalSha256(cut.workspaceGenerations)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery original subject changed during physical inspection');
        }
        // Retain the original zero-release owner even when stop wins later
        // during the descriptor walk; it grants no productive authority.
        const brokerQuiescence = observeInstalledBrokerQuiescence(executionStore!, runId);
        // Artifact validation awaited after the closure's SQL snapshot. A stop
        // may have advanced only its authority-reducing fields meanwhile.
        // Enter completion synchronously at that exact current revision; its
        // fresh SQL snapshot and all original probe/native checks remain strict.
        const completionRun = readRun(driver, runId);
        if (!sameInspectionStopCut(current.run, completionRun)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery completion subject changed before entry');
        }
        const recovered = await completeWorkerRecoveryProbe(driver, artifacts, owner,
          { runId, expectedRunRevision: completionRun.revision }, death, signal, brokerQuiescence,
          { retire: () => controller!.closeRetained(), finish: async plan =>
            (await agent.commitTerminalStop({ expectedRunRevision: readRun(driver, runId).revision }, plan)).run });
        signal.throwIfAborted();
        // The owning task joins its actual resources before returning. The
        // installed driver separately resumes quarantine retirement with
        // fresh native/tree/broker observations; recovery itself stops here.
        return recovered;
      };
      const work = (async () => {
        if (closed || isClosing()) throw new KernelStorageError('LEASE_FENCED', 'Run execution is closing');
        let run = readRun(driver, runId);
        if (run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery revision changed');
        if (run.activeWorkerLaunchId !== undefined) run = await beginWorkerRecovery(driver, artifacts, owner, { runId, expectedRunRevision });
        if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker recovery requires its installed worker wait');
        }
        const wait = await artifacts.readCanonical<WorkerDeathWait>(run.waitingOnRef);
        if (wait.subject.kind !== 'worker_death') throw new KernelStorageError('INVALID_REQUEST', 'this execution scope cannot reconcile another subject');
        if (activeWorker) {
          if (wait.subject.oldWorkerLaunchId !== ownedLaunchId || !worker) {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery does not name this scope\'s retained physical worker');
          }
          const death = await observeOriginalWorkerDeath(activeWorker);
          assertNativeContainmentDeath(death);
          // The inspection below uses a fresh controller and the retained
          // original containment. Never overwrite an unjoined physical owner.
          await retireResources();
        }
        if (wait.probeState.phase === 'automatic_in_flight' && wait.probeState.dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId) {
          // A successor closes, rather than resumes, the predecessor task.
          // Return its committed schedule; do not hide the backoff in a loop.
          return closeWorkerRecoveryProbe(driver, artifacts, owner, { runId, expectedRunRevision: run.revision });
        }
        if (wait.probeState.phase === 'automatic_pending') {
          await beginWorkerRecoveryProbe(driver, artifacts, owner, { runId, expectedRunRevision: run.revision }, (dispatched, persisted) => {
            // Synchronous registration immediately after the dispatch commits,
            // before the producer can perform its first inspection I/O.
            const task = startWorkerRecoveryTask({ run: dispatched, wait: persisted, owner },
              signal => inspect(dispatched, persisted, signal), retireResources);
            probe = { run: dispatched, wait: persisted, task };
            registered = task;
            if (closed || isClosing()) void task.cancelAndJoin().catch(() => {});
          });
          if (!registered || !probe) throw new KernelStorageError('RECOVERY_REQUIRED', 'worker dispatch has no registered producer');
          const dispatch = probe.wait.probeState;
          if (dispatch.phase !== 'automatic_in_flight') throw new KernelStorageError('RECOVERY_REQUIRED', 'worker producer has no persisted deadline');
          const timer = setTimeout(() => { void registered!.cancelAndJoin().catch(() => {}); },
            Math.max(0, Date.parse(dispatch.dispatch.probeDeadlineAt) - Date.now()));
          try { return await registered.work; }
          catch (error) {
            const current = readRun(driver, runId);
            if (sampleCanonicalNow() >= dispatch.dispatch.probeDeadlineAt && current.waitingOnRef === probe?.run.waitingOnRef) {
              return closeProbe({ runId, expectedRunRevision: current.revision });
            }
            throw error;
          } finally { clearTimeout(timer); }
        }
        if (wait.probeState.phase === 'automatic_in_flight' && probe?.run.waitingOnRef === run.waitingOnRef &&
            sampleCanonicalNow() >= wait.probeState.dispatch.probeDeadlineAt) {
          return closeProbe({ runId, expectedRunRevision: run.revision });
        }
        throw new KernelStorageError('RECOVERY_REQUIRED', 'worker inspection requires its exact registered producer; an existing nonce cannot be adopted');
      })();
      const operation = work.catch(error => {
        if (error instanceof ResourceRetirementError) cleanupFailure ??= error;
        throw error;
      }).finally(async () => {
        try { if (!registered) await retireResources(); }
        finally {
          const retainedProbe = probe;
          if (retainedProbe && retainedProbe.task === registered && readRun(driver, runId).waitingOnRef !== retainedProbe.run.waitingOnRef) probe = undefined;
          pending = undefined;
        }
      });
      pending = operation;
      return operation;
    }
  });
  return { execution, closeWorkerRecoveryProbe: input => closeProbe(input), close() {
    if (closing) return closing;
    closed = true;
    operationAbort?.abort();
    // Abort first: native inspection polling synchronously starts its own
    // revocation/join, and file walkers stop at their real stream checkpoints.
    const cancel = probe?.task.cancelAndJoin();
    const attempt = (async () => {
      const joins = await Promise.allSettled([...(cancel ? [cancel] : []), ...(pending ? [pending.catch(() => {})] : [])]);
      const failure = joins.find(result => result.status === 'rejected');
      if (failure?.status === 'rejected') cleanupFailure ??= failure.reason;
      if (activeWorker) {
        try {
          const run = readRun(driver, runId);
          if (run.activeWorkerLaunchId !== ownedLaunchId) {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'shutdown lost its retained worker\'s durable owner');
          }
          await beginWorkerRecovery(driver, artifacts, owner, { runId, expectedRunRevision: run.revision });
        } catch (error) { cleanupFailure ??= error; }
        try {
          if (!worker) throw new KernelStorageError('RECOVERY_REQUIRED', 'shutdown lost its original physical worker');
          const death = await observeOriginalWorkerDeath(activeWorker);
          assertNativeContainmentDeath(death);
        } catch (error) { cleanupFailure ??= error; }
        try { await retireResources(); }
        catch (error) { cleanupFailure ??= error; }
      }
      // Installation image release must not invalidate the execution's actual
      // retirement observation, and is still attempted after a failed join.
      try { await launcher.close(); }
      catch (error) { cleanupFailure ??= error; }
      if (cleanupFailure !== undefined) throw cleanupFailure;
      const run = readRun(driver, runId);
      if (probe && run.waitingOnRef === probe.run.waitingOnRef) {
        await closeProbe({ runId, expectedRunRevision: run.revision }, true);
      }
    })();
    closing = attempt.catch(error => { closing = undefined; throw error; });
    return closing;
  } };
}
