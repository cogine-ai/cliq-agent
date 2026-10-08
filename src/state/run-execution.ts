import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxRuntimeBindingV1 } from '../kernel/execution.js';
import type { Run, StateOwnerRecordV1, SupervisorInspectorIdentityV1, WorkerIdentity, WorkspaceGenerationSnapshotEvidenceV1, WorkerDeathWait } from '../kernel/types.js';
import type { ToolObservationV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly, type RunAssemblyValidationMaterial } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual, type RuntimeBundleManifest, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { assertNativeContainmentDeath, LINUX_WORKER_RECIPE, openLinuxWorkerLauncher,
  type LinuxBlockedWorker, type LinuxWorkerController, type LinuxWorkerInstallation } from '../sandbox/linux-worker.js';
import { borrowRunWorkspaceForExecution, materializeRunWorkspace, reopenRunWorkspace, type RunWorkspaceGeneration } from '../workspace/run-workspace/generation.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile, readBuiltinEditLaunchClosure, readWorkerLaunchClosure, readRetainedWorkerLaunchClosure, decodeWorkerProcessContainment } from './execution-closure.js';
import { loadAgentRun } from './reducers/agent.js';
import { assertLiveDispatchState } from './reducers/invocation.js';
import { beginWorkerRecovery, beginWorkerRecoveryProbe, closeWorkerRecoveryProbe, completeWorkerRecoveryProbe } from './reducers/worker-recovery.js';
import { activateWorkerLease, beginGenerationCheckpoint, beginGenerationRevocation, recordWorkerPreactivated, reserveWorkerLaunch } from './reducers/worker-launch.js';
import { sealWorkerGeneration } from './reducers/worker-launch.js';
import { registerWorkspaceGeneration, recordWorkspaceGenerationPreactivated } from './reducers/workspace-transition.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, assertFenceHealthy, type StateOwnerContext } from './state-owner.js';
import { startWorkerRecoveryTask, type WorkerRecoveryTask } from './worker-recovery-task.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { readToolCut } from './tool-cut.js';
import { decodeRunSpec, decodeWorkerIdentity, decodeWorkspaceGenerationIdentity } from './decoders.js';

/** Trusted installation paths belong to Supervisor bootstrap, not a Run or a control frame. */
export type RunExecutionInstallation = Pick<LinuxWorkerInstallation, 'installationRoot' | 'cgroupParent'>;
export type LoadRunExecutionInput = { runId: string; material: RunAssemblyValidationMaterial };
export type RunExecution = Readonly<{
  executeCurrentTool(input: { expectedRunRevision: number }): Promise<Run>;
  recoverWorker(input: { expectedRunRevision: number }): Promise<Run>;
}>;

const nonce = () => sha256Bytes(randomBytes(32));
type WorkerSpec = Extract<SandboxLaunchSpecV1, { purpose: 'worker_activation' }>;
type EditSpec = Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }>;

async function publishWorkerRecipe(artifacts: ArtifactCatalog, controller: LinuxWorkerController,
  installation: RunExecutionInstallation, selected: Awaited<ReturnType<typeof readToolCut>>, generationRef: string) {
  const { run, runSpec } = selected;
  const assembly = decodeRetainedRunAssembly(await artifacts.readCanonical(runSpec.assemblyRef));
  const bundle = await artifacts.readCanonical<RuntimeBundleManifest>(assembly.runtime.runtimeBundleRef);
  const profile = decodeSandboxProfile(await artifacts.readCanonical(runSpec.sandboxProfileRef));
  const launcher = bundle.entries.find(entry => entry.entryId === LINUX_WORKER_RECIPE.launcherId);
  if (!launcher || launcher.role !== 'platform_helper' || !launcher.executable || assembly.runtime.workerExecutableId !== LINUX_WORKER_RECIPE.workerId) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen Run does not select the installed worker recipe');
  }
  const launchId = identityHash('cliq-worker-launch-v1', run.id, String(run.leaseEpoch + 1), nonce());
  const spawnNonceDigest = nonce(), activationNonceDigest = nonce();
  const owner = { kind: 'worker_activation' as const, runId: run.id, intendedLeaseEpoch: run.leaseEpoch + 1, workerLaunchId: launchId };
  const cgroupNameReservationDigest = canonicalSha256(['cliq-worker-cgroup-v1', run.id, launchId]);
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef }, launchNonceDigest: spawnNonceDigest,
    backend: { kind: 'linux', cgroupPath: path.posix.join(installation.cgroupParent, `cliq-${cgroupNameReservationDigest}`),
      cgroupNameReservationDigest,
      pidNamespaceReservationId: identityHash('cliq-worker-namespace-v1', run.id, launchId), subreaperStartToken: controller.subreaperStartToken },
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
  input: LoadRunExecutionInput, isClosing: () => boolean = () => false
): Promise<{ execution: RunExecution; closeWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }): Promise<Run>; close(): Promise<void> }> {
  // Validation material includes trusted resolver functions; retain those
  // functions while snapshotting their data, just like loadAgentRun does.
  input = { runId: input.runId, material: Object.fromEntries(Object.entries(input.material).map(([key, value]) =>
    [key, typeof value === 'function' ? value : immutableSnapshot(value)])) as RunAssemblyValidationMaterial };
  const runId = input.runId;
  const installation = bootstrap?.execution && immutableSnapshot(bootstrap.execution);
  const launcher = await openLinuxWorkerLauncher(installation && bootstrap && { ...installation, runtimeAuthority: bootstrap });
  let agent: Awaited<ReturnType<typeof loadAgentRun>>;
  try {
    agent = await loadAgentRun(driver, artifacts, owner, { runId, material: input.material, releaseKeys: bootstrap!.releaseKeys });
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
  let worker: LinuxBlockedWorker | undefined, generation: RunWorkspaceGeneration | undefined, controller: LinuxWorkerController | undefined;
  let ownedLaunchId: string | undefined;
  async function retireResources() {
    const retainedGeneration = generation, retainedController = controller;
    generation = undefined; controller = undefined; worker = undefined; ownedLaunchId = undefined;
    try { retainedGeneration?.close(); }
    catch (failure) { cleanupFailure ??= failure; }
    // One failed release must not bypass the independent process join.
    try { await retainedController?.close(); }
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
    executeCurrentTool: async value => {
      const expectedRunRevision = revision(value);
      const abort = new AbortController();
      operationAbort = abort;
      const signal = abort.signal;
      const work = (async () => {
        signal.throwIfAborted();
        const selected = await readToolCut(driver, artifacts, runId, agent.resolveToolInput);
        signal.throwIfAborted();
        if (selected.run.revision !== expectedRunRevision || selected.run.status !== 'queued' || selected.run.activeWorkerLaunchId !== undefined ||
            selected.run.cancelRequested || selected.run.stopIntentRef || sampleCanonicalNow() >= selected.run.deadlineAt) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool execution requires its unstopped lease-free queued cut');
        }
        if (selected.call.toolName !== 'edit') throw new KernelStorageError('INVALID_REQUEST', 'this installed recipe supports only the current builtin edit');
        const projection = await agent.readToolInvocation();
        requireEqual(projection.run, selected.run, 'current native tool projection');
        if (projection.kind !== 'tool' || projection.execution.kind !== 'builtin' || projection.execution.adapterId !== LINUX_WORKER_RECIPE.editId) {
          throw new KernelStorageError('INVALID_REQUEST', 'this installed recipe does not support the frozen tool execution identity');
        }
        const workspaceCut = await readRecoveryClosure(driver, artifacts, runId);
        requireEqual(workspaceCut.run, selected.run, 'native tool workspace cut');
        const candidates = workspaceCut.workspaceGenerations.filter(row => row.phase === 'materializing' || row.phase === 'preactivated_readonly');
        if (candidates.length > 1 || candidates.some(row => row.phase === 'materializing')) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'tool execution retains an incomplete or competing private generation');
        }
        let authority: { generationRef: string; generationIdentityDigest: string };
        let preactivatedGeneration: Extract<import('../kernel/types.js').WorkspaceGenerationStateV1, { phase: 'preactivated_readonly' }>;
        const retained = candidates[0];
        if (retained?.phase === 'preactivated_readonly') {
          if (retained.sourceCheckpointId !== selected.latestCheckpoint.id || retained.sourceWorkspaceStateRef !== selected.latestCheckpoint.workspaceStateRef) {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'retained private generation does not restore the current ready Checkpoint');
          }
          const identity = decodeWorkspaceGenerationIdentity(await artifacts.readCanonical(retained.generationRef));
          generation = await reopenRunWorkspace({ filesystem: owner.filesystem, artifacts, identity, checkpoint: selected.latestCheckpoint, signal });
          authority = { generationRef: retained.generationRef, generationIdentityDigest: retained.generationIdentityDigest };
          preactivatedGeneration = retained;
        } else {
          generation = await materializeRunWorkspace({ filesystem: owner.filesystem, artifacts, checkpoint: selected.latestCheckpoint, signal });
          const materialized = await generation.publishMaterializedAuthority();
          authority = materialized;
          const materializing = await registerWorkspaceGeneration(driver, artifacts, owner, { runId, generationRef: authority.generationRef,
            generationIdentityDigest: authority.generationIdentityDigest });
          preactivatedGeneration = await recordWorkspaceGenerationPreactivated(driver, artifacts, owner, { generationId: generation.generationId,
            expectedRowVersion: materializing.rowVersion, snapshotEvidenceRef: materialized.snapshotEvidenceRef, snapshotEvidenceDigest: materialized.snapshotEvidenceDigest });
        }
        // The two durable generation writes above finish as a readonly pair,
        // even if shutdown arrives between them.
        signal.throwIfAborted();
        // Quota is checked before reserving a launch and again by the native launcher before process creation.
        const profile = decodeSandboxProfile(await artifacts.readCanonical(selected.runSpec.sandboxProfileRef));
        const borrowed = borrowRunWorkspaceForExecution(generation);
        try { borrowed.assertQuota(profile.resources.maxGenerationBytes); } finally { borrowed.close(); }
        controller = await launcher.startController({ signal });
        const recipe = await publishWorkerRecipe(artifacts, controller, installation!, selected, authority.generationRef);
        const closure = await readWorkerLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { ...recipe.input, run: selected.run });
        signal.throwIfAborted();
        const reserved = await reserveWorkerLaunch(driver, artifacts, owner, recipe.input);
        ownedLaunchId = reserved.launchId;
        worker = await controller.launchWorker({ closure, generation, activationNonceDigest: reserved.activationNonceDigest });
        const processIdentity = await worker.observeProcess();
        const processContainmentRef = (await artifacts.publishCanonical(worker.containment, 'cliq-process-containment-v1')).ref;
        const workerIdentity: WorkerIdentity = { schemaVersion: 1, ...processIdentity, spawnNonceDigest: reserved.spawnNonceDigest,
          activationNonceDigest: reserved.activationNonceDigest, intendedLeaseEpoch: recipe.spec.owner.intendedLeaseEpoch, launchId: reserved.launchId,
          supervisorInstanceId: reserved.supervisorInstanceId, processContainmentRef };
        const workerIdentityDigest = (await artifacts.publishCanonical(workerIdentity, 'cliq-worker-identity-v1')).ref;
        await recordWorkerPreactivated(driver, artifacts, owner, { launchId: reserved.launchId, workerIdentityDigest, processContainmentRef });
        const activated = activateWorkerLease(driver, owner, { launchId: reserved.launchId, expectedRunRevision,
          expectedGenerationRowVersion: preactivatedGeneration.rowVersion, leaseDurationMs: 60_000 });
        signal.throwIfAborted();
        await worker.activateCommitted(activated.launch);
        async function retireToCheckpoint(checkpointId: string) {
          const beforeSeal = await readRecoveryClosure(driver, artifacts, runId);
          const activeGeneration = beforeSeal.workspaceGenerations.find(row => row.generationRef === authority.generationRef)!;
          const activeLaunch = beforeSeal.workerLaunches.find(row => row.launchId === activated.launch.launchId)!;
          const quiesceId = identityHash('cliq-worker-quiesce-v1', activated.launch.launchId, checkpointId);
          const revoking = beginGenerationRevocation(driver, owner, { launchId: activeLaunch.launchId,
            expectedLeaseVersion: activeLaunch.leaseVersion, expectedGenerationRowVersion: activeGeneration.rowVersion, quiesceId });
          const death = await worker!.stop();
          assertNativeContainmentDeath(death);
          const checkpointing = beginGenerationCheckpoint(driver, owner, { launchId: activeLaunch.launchId, expectedLeaseVersion: revoking.launch.leaseVersion,
            expectedGenerationRowVersion: revoking.generation.rowVersion, quiesceId });
          const observed = await generation!.observe({ signal });
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
            purpose: 'sealed_to_checkpoint', runId, generationRef: authority.generationRef, generationIdentityDigest: authority.generationIdentityDigest,
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
        signal.throwIfAborted();
        const prepared = await agent.prepareTool({ expectedRunRevision: activated.run.revision, leaseEpoch: activated.run.leaseEpoch });
        if (prepared.disposition !== 'prepared') {
          const checkpointId = prepared.disposition === 'approval_required' ? prepared.checkpointId
            : identityHash('cliq-denied-tool-worker-checkpoint-v1', runId, prepared.run.latestCheckpointId, nonce());
          const proof = await retireToCheckpoint(checkpointId);
          if (prepared.disposition === 'approval_required') {
            await agent.waitForToolApproval({ expectedRunRevision: prepared.run.revision, waitingOnRef: prepared.waitingOnRef, checkpoint: proof.postEffect });
          } else {
            const current = await readRecoveryClosure(driver, artifacts, runId);
            await sealWorkerGeneration(driver, artifacts, owner, { launchId: activated.launch.launchId,
              expectedRunRevision: current.run.revision, expectedGenerationRowVersion: proof.checkpointing.generation.rowVersion,
              quiesceId: proof.quiesceId, checkpointId, contextManifestRef: current.latestCheckpoint.contextManifestRef,
              ...proof.postEffect, snapshotEvidenceDigest: proof.snapshot.evidenceDigest, checkpointReason: 'auto' });
          }
          return readRun(driver, runId);
        }
        const dispatchId = identityHash('cliq-tool-dispatch-v1', runId, prepared.entry.opId, String(prepared.entry.attempt), nonce());
        if (worker.containment.backend.kind !== 'linux') throw new KernelStorageError('ARTIFACT_MISMATCH', 'native edit parent is not Linux');
        const sandboxLaunchSpecRef = await publishEditRecipe(artifacts, recipe.spec, processContainmentRef, worker.containment.backend.cgroupPath, prepared, dispatchId);
        // The permanent claim precedes even blocked invocation process creation.
        signal.throwIfAborted();
        const claimed = await agent.claimTool({ expectedRunRevision: prepared.run.revision, leaseEpoch: activated.run.leaseEpoch,
          opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId, sandboxLaunchSpecRef });
        const call = await artifacts.readCanonical<import('../protocol/agent-ir.js').ToolCallInputV1>(claimed.request.inputRef);
        const grant = await artifacts.readCanonical<import('../kernel/tool-authorization.js').ToolOperationGrantV1>(claimed.entry.grantRef!);
        const live = assertLiveDispatchState(driver, owner, runId, prepared.run.revision, activated.run.leaseEpoch, sampleCanonicalNow());
        const edit = await readBuiltinEditLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { ...live, prepared: prepared.entry,
          request: claimed.request, target: claimed.target, call, grant, dispatchId, sandboxLaunchSpecRef });
        const invocation = await worker.createInvocation(edit);
        await invocation.observeProcess();
        signal.throwIfAborted();
        await claimed.release(invocation);
        const result = await invocation.result();
        const observedAt = sampleCanonicalNow();
        const proof = await retireToCheckpoint(toolCheckpointId(runId, prepared.entry.opId, prepared.entry.attempt));
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
        await agent.completeTool({ opId: claimed.entry.opId, attempt: claimed.entry.attempt, expectedRunRevision: prepared.run.revision, observationRef });
        return readRun(driver, runId);
      })();
      const operation = work.catch(async error => {
        if (error instanceof ResourceRetirementError) cleanupFailure ??= error;
        try {
          const run = readRun(driver, runId);
          if (ownedLaunchId !== undefined && run.activeWorkerLaunchId === ownedLaunchId) {
            await beginWorkerRecovery(driver, artifacts, owner, { runId, expectedRunRevision: run.revision });
          }
        } catch (failure) {
          // Losing the state fence cannot bypass actual resource retirement or
          // be mistaken for a graceful owner release.
          cleanupFailure ??= failure;
        } finally {
          if (worker) {
            try { const death = await worker.stop(); assertNativeContainmentDeath(death); }
            catch (failure) { cleanupFailure ??= failure; }
          }
        }
        if (cleanupFailure !== undefined) throw cleanupFailure;
        throw error;
      }).finally(async () => {
        try { await retireResources(); }
        finally { pending = undefined; if (operationAbort === abort) operationAbort = undefined; }
      });
      pending = operation;
      return operation;
    },
    recoverWorker: async value => {
      const expectedRunRevision = revision(value);
      let registered: WorkerRecoveryTask | undefined;
      const inspect = async (run: Run, wait: WorkerDeathWait, signal: AbortSignal): Promise<Run> => {
        signal.throwIfAborted();
        const cut = await readRecoveryClosure(driver, artifacts, runId);
        signal.throwIfAborted();
        if (cut.run.waitingOnRef !== run.waitingOnRef || cut.run.revision !== run.revision) {
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
        const replacement = cut.workspaceGenerations.filter(row => row.phase === 'preactivated_readonly' || row.phase === 'materializing');
        if (replacement.length === 0) {
          generation = await materializeRunWorkspace({ filesystem: owner.filesystem, artifacts, checkpoint: cut.latestCheckpoint, signal });
          const authority = await generation.publishMaterializedAuthority();
          // Do not insert a cancellation point between these two writes: a
          // cancelled inspector must not manufacture a stranded materializing
          // replacement that the next inspection cannot reuse.
          const materializing = await registerWorkspaceGeneration(driver, artifacts, owner, { runId, generationRef: authority.generationRef,
            generationIdentityDigest: authority.generationIdentityDigest });
          await recordWorkspaceGenerationPreactivated(driver, artifacts, owner, { generationId: generation.generationId,
            expectedRowVersion: materializing.rowVersion, snapshotEvidenceRef: authority.snapshotEvidenceRef, snapshotEvidenceDigest: authority.snapshotEvidenceDigest });
          signal.throwIfAborted();
        } else if (replacement.length !== 1 || replacement[0]!.phase !== 'preactivated_readonly') {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery retains an incomplete or competing replacement');
        }
        return completeWorkerRecoveryProbe(driver, artifacts, owner, { runId, expectedRunRevision: cut.run.revision }, death, signal);
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
        finally { pending = undefined; }
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
