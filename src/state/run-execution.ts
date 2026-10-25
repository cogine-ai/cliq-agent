import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1, SandboxRuntimeBindingV1 } from '../kernel/execution.js';
import type { Run, PreparingWorkerLaunch, StateOwnerRecordV1, SupervisorInspectorIdentityV1, WorkerIdentity, WorkspaceGenerationSnapshotEvidenceV1, WorkerDeathWait } from '../kernel/types.js';
import type { ToolCheckpointProof, ToolObservationV1 } from '../kernel/tool-authorization.js';
import { decodeRetainedRunAssembly, type RunAssemblyValidationMaterial } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual, type RuntimeBundleManifest, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { assertNativeContainmentDeath, assertNativePreactivationObservation, LINUX_WORKER_RECIPE, LINUX_VERIFIER_RECIPE,
  openInstalledLinuxWorkerLauncher, openLinuxWorkerLauncher, type LinuxBlockedWorker, type LinuxWorkerController,
  type LinuxWorkerInstallation, type NativePreactivationRetirement, type NativeRetainedWorkerRetirement } from '../sandbox/linux-worker.js';
import { borrowRunWorkspaceForExecution, createRunWorkspaceMaterialization, observeRetainedRunWorkspace,
  type RunWorkspaceGeneration, type RunWorkspaceMaterialization, type RunWorkspaceBirth } from '../workspace/run-workspace/generation.js';
import type { ArtifactCatalog } from './artifacts.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile, readBuiltinEditLaunchClosure, readWorkerLaunchClosure, readRetainedWorkerLaunchClosure, readQuarantinedWorkerLaunchClosure, decodeWorkerProcessContainment, readVerifierLaunchClosure, type WorkerLaunchClosure } from './execution-closure.js';
import { loadAgentRun } from './reducers/agent.js';
import { loadDeliveryContinuation, type DeliveryContinuation } from './run-continuation.js';
import { assertLiveDispatchState, markInvocationUnknown } from './reducers/invocation.js';
import { beginWorkerRecovery, beginWorkerRecoveryProbe, closeWorkerRecoveryProbe, completeWorkerRecoveryProbe } from './reducers/worker-recovery.js';
import { activateWorkerLeaseWithinDeadline, beginGenerationCheckpoint, beginGenerationRevocation, recordWorkerPreactivated, renewWorkerLease, reserveWorkerLaunch } from './reducers/worker-launch.js';
import { sealWorkerGeneration } from './reducers/worker-launch.js';
import { recordWorkspaceGenerationPreactivated } from './reducers/workspace-transition.js';
import { readDeliveryPublicationClosure, readRecoveryClosure } from './recovery-closure.js';
import { readRun } from './rows.js';
import { assertSqliteConnectionOwnedBy, isRolledBackSqliteTransactionFailure, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { startWorkerRecoveryTask, type WorkerRecoveryTask } from './worker-recovery-task.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { readToolCut } from './tool-cut.js';
import { decodeRunSpec, decodeWorkerIdentity, decodeWorkspaceGenerationIdentity, decodeWorkspaceIdentity } from './decoders.js';
import { retirePreactivationLaunch } from './preactivation-retirement.js';
import { loadNativeStateOwner, type HeldWorkerReservation, type HeldWorkspaceRoot } from './native-owner.js';
import { withHeldInstalledRuntime, withInstalledWorkerRoot, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { stopCheckpointId, stopInvocationHistory } from '../runtime/stop.js';
import { retireQuarantinedGeneration } from './generation-retirement.js';
import { observeInstalledBrokerQuiescence, type StateStore } from './store.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { hasOnlySettledInstalledModelUnknowns } from './worker-recovery.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { beginWorkerPreparation, recordWorkerPreparationGeneration, recordWorkerPreparationController, retireWorkerPreparation } from './worker-preparation.js';
import { validateInstalledModelNoReleaseHistory } from './broker-no-release.js';
import { readVerifierProgress } from './verifier-recovery.js';
import { decodeGuestToolchainManifest } from './guest-toolchain.js';
import { decodeVerifierCommand } from './verifier-artifacts.js';
import { validateVerifierStoppedHistory } from './verifier-stop-history.js';
import type { PublicationInvocationOwner } from './publication-invocation.js';
import { deliveryPublicationCheckpointId } from './delivery-publication-progress.js';
import type { PublicationPathWait } from '../kernel/reconciliation.js';
import type { InstalledControlResponseV1, RunReconcileRequestV1 } from '../kernel/control-wire.js';
import type { AuthenticatedControlIdentity } from './control-channel.js';
import type { PublicationReconciliationTask } from './publication-reconciliation-task.js';

/** Trusted installation paths belong to Supervisor bootstrap, not a Run or a control frame. */
export type RunExecutionInstallation = Pick<LinuxWorkerInstallation, 'installationRoot' | 'cgroupParent'>;
export type LoadRunExecutionInput =
  | { runId: string; operation?: 'agent'; material: RunAssemblyValidationMaterial }
  | { runId: string; operation: 'delivery' };
export type RunExecutionWorkerIdentity = { runId: string; leaseEpoch: number; launchId: string; generationRef: string; workerIdentityDigest: string };
export type RunExecution = Readonly<{
  requestStop(): Promise<void>;
  activateCurrentWorker(input: { expectedRunRevision: number }): Promise<Run>;
  assertCurrentModelWorker(input: RunExecutionWorkerIdentity): void;
  assertCurrentDeliveryWorker(input: RunExecutionWorkerIdentity): void;
  renewCurrentWorkerLease(): 'inactive' | 'unchanged' | 'renewed' | 'expired';
  executeCurrentTool(input: { expectedRunRevision: number }): Promise<Run>;
  executeCurrentVerifier(input: { expectedRunRevision: number }): Promise<Run>;
  executeCurrentPublication(input: { expectedRunRevision: number }): Promise<Run>;
  executeCurrentNoOpDelivery(input: { expectedRunRevision: number }): Promise<Run>;
  executeCurrentPublicationMaintenance(input: { expectedRunRevision: number }): Promise<Run>;
  hasPendingOperation(): boolean;
  reconcilePublication(input: { expectedRunRevision: number }): Promise<Run>;
  enqueuePublicationReconciliation(input: { request: RunReconcileRequestV1; identity: AuthenticatedControlIdentity }):
    Promise<{ run: Run; response: Extract<InstalledControlResponseV1, { ok: true }>; completion: Promise<Run> }>;
  hasPendingCompletion(error?: unknown): boolean;
  resumeCurrentCompletion(input: { expectedRunRevision: number }): Promise<Run>;
  finishCurrentFinalTurn(input: { expectedRunRevision: number }): Promise<Run>;
  finishCurrentStop(input: { expectedRunRevision: number }): Promise<Run>;
  resumeCurrentRetirement(input: { expectedRunRevision: number }): Promise<Run>;
  recoverWorker(input: { expectedRunRevision: number }): Promise<Run>;
}>;
const deliveryExecutions = new WeakMap<object, { driver: SqliteDriver; owner: StateOwnerContext; runId: string }>();
const publicationTaskBrand: unique symbol = Symbol('DeliveryPublicationTask');
export type DeliveryPublicationTask = Readonly<{ readonly [publicationTaskBrand]: true }>;
const noOpTaskBrand: unique symbol = Symbol('DeliveryNoOpTask');
export type DeliveryNoOpTask = Readonly<{ readonly [noOpTaskBrand]: true }>;
const publicationMaintenanceTaskBrand: unique symbol = Symbol('DeliveryPublicationMaintenanceTask');
export type DeliveryPublicationMaintenanceTask = Readonly<{ readonly [publicationMaintenanceTaskBrand]: true }>;
const publicationReceivedTaskBrand: unique symbol = Symbol('DeliveryPublicationReceivedTask');
export type DeliveryPublicationReceivedTask = Readonly<{ readonly [publicationReceivedTaskBrand]: true }>;
const publicationReconciliationTaskBrand: unique symbol = Symbol('DeliveryPublicationReconciliationTask');
export type DeliveryPublicationReconciliationTask = Readonly<{ readonly [publicationReconciliationTaskBrand]: true }>;
type DeliveryRootResources = Readonly<{
  runId: string; expectedRunRevision: number; workspaceRoot: HeldWorkspaceRoot; controlledHome: HeldWorkspaceRoot; signal: AbortSignal;
}>;
type DeliveryMaintenanceResources = DeliveryRootResources & Readonly<{
  publicationOwners: readonly PublicationInvocationOwner[];
  retire?: PublicationExecutionResources['retire'];
  reobserveRetirement: PublicationExecutionResources['reobserveRetirement'];
}>;
type DeliveryRootTaskBinding<R extends DeliveryRootResources = DeliveryRootResources> = {
  driver: SqliteDriver; owner: StateOwnerContext; execution: RunExecution; artifacts: ArtifactCatalog;
  assertOwned(): void; resources(connection?: SqliteConnection): R;
};
const noOpTasks = new WeakMap<object, DeliveryRootTaskBinding>();
const publicationMaintenanceTasks = new WeakMap<object, DeliveryRootTaskBinding<DeliveryMaintenanceResources>>();
const publicationReceivedTasks = new WeakMap<object, DeliveryRootTaskBinding>();
type PublicationReconciliationResources = DeliveryRootResources & Readonly<{
  publicationOwners: readonly PublicationInvocationOwner[];
}>;
const publicationReconciliationTasks = new WeakMap<object, DeliveryRootTaskBinding<PublicationReconciliationResources> & {
  assertRegistered(): void;
}>();
type PublicationExecutionResources = Readonly<{
  workspaceRoot: HeldWorkspaceRoot; controlledHome: HeldWorkspaceRoot;
  publicationOwners: readonly PublicationInvocationOwner[];
  signal: AbortSignal;
  retire(): Promise<{ postEffect: ToolCheckpointProof; snapshot: WorkspaceGenerationSnapshotEvidenceV1 }>;
  reobserveRetirement: import('./tool-checkpoint.js').NativeWorkerRetirement;
}>;
const publicationTasks = new WeakMap<object, { driver: SqliteDriver; owner: StateOwnerContext;
  execution: RunExecution; worker: RunExecutionWorkerIdentity; assertCurrent(connection?: SqliteConnection): void; resources(): PublicationExecutionResources }>();

function rootTaskBinding<R extends DeliveryRootResources>(tasks: WeakMap<object, DeliveryRootTaskBinding<R>>, driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: unknown, artifacts: ArtifactCatalog): DeliveryRootTaskBinding<R> {
  // No caller getters, SQL, native borrow or Catalog access before all exact
  // issuer references agree. A retained artifact cannot reconstitute a task.
  const held = execution !== null && typeof execution === 'object' ? deliveryExecutions.get(execution) : undefined;
  const original = task !== null && typeof task === 'object' ? tasks.get(task) : undefined;
  if (!held || !original || held.driver !== driver || held.owner !== owner || original.driver !== driver ||
      original.owner !== owner || original.execution !== execution || original.artifacts !== artifacts)
    throw new TypeError('delivery requires its genuine same-owner original task and ArtifactCatalog');
  return original;
}
function ownedRootTask<R extends DeliveryRootResources>(tasks: WeakMap<object, DeliveryRootTaskBinding<R>>, driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: unknown, artifacts: ArtifactCatalog): DeliveryRootTaskBinding<R> {
  const original = rootTaskBinding(tasks, driver, owner, execution, task, artifacts);
  original.assertOwned(); return original;
}

/** Lifetime assertion only: no worker lease, grant, projection or dispatch
 * authority is minted by this same-scope task brand. */
export function assertOwnedNoOpDeliveryTask(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  task: DeliveryNoOpTask, artifacts: ArtifactCatalog): void {
  ownedRootTask(noOpTasks, driver, owner, execution, task, artifacts);
}

export async function readOwnedNoOpDeliveryExecutionResources(driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: DeliveryNoOpTask, artifacts: ArtifactCatalog): Promise<DeliveryRootResources> {
  return ownedRootTask(noOpTasks, driver, owner, execution, task, artifacts).resources();
}

/** A stopped maintenance task owns its actual roots, not a productive worker.
 * The maintenance producer still proves the complete Stop/prefix/creator graph
 * and its exact zero-budget SQL transition before any cleanup release. */
export function assertDeliveryPublicationMaintenanceExecution(driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationMaintenanceTask, artifacts: ArtifactCatalog, connection: SqliteConnection = driver): DeliveryMaintenanceResources {
  const original = ownedRootTask(publicationMaintenanceTasks, driver, owner, execution, task, artifacts);
  assertSqliteConnectionOwnedBy(driver, connection); return original.resources(connection);
}

/** A known result can repeat only read-only final validation. This genuine
 * execution task contains no worker, release gate, native owner or retry. */
export function assertDeliveryPublicationReceivedExecution(driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReceivedTask, artifacts: ArtifactCatalog, connection: SqliteConnection = driver): DeliveryRootResources {
  const original = ownedRootTask(publicationReceivedTasks, driver, owner, execution, task, artifacts);
  assertSqliteConnectionOwnedBy(driver, connection); return original.resources(connection);
}

/** Owns only the actual roots and previously issued publication handles. It
 * contains no worker activation, semantic release or replacement M authority.
 * The producer must still validate the committed exact inspection dispatch. */
export function assertDeliveryPublicationReconciliationExecution(driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReconciliationTask, artifacts: ArtifactCatalog, connection: SqliteConnection = driver): PublicationReconciliationResources {
  const original = ownedRootTask(publicationReconciliationTasks, driver, owner, execution, task, artifacts);
  assertSqliteConnectionOwnedBy(driver, connection); return original.resources(connection);
}

/** Registration/closure only, including when shutdown won immediately after
 * the nonce committed. No root, signal, worker or I/O authority is returned.
 * Actual inspection still requires the separate live resource assertion. */
export function assertOwnedPublicationReconciliationTask(driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, task: DeliveryPublicationReconciliationTask, artifacts: ArtifactCatalog): void {
  rootTaskBinding(publicationReconciliationTasks, driver, owner, execution, task, artifacts);
  publicationReconciliationTasks.get(task)!.assertRegistered();
}

/** A structural callback or an execution from another Store cannot satisfy
 * the physical publication gate. The original owner retains every native FD. */
export function assertDeliveryExecution(driver: SqliteDriver, owner: StateOwnerContext, value: unknown,
  identity: RunExecutionWorkerIdentity): void {
  const held = value !== null && typeof value === 'object' ? deliveryExecutions.get(value) : undefined;
  if (!held || held.driver !== driver || held.owner !== owner || held.runId !== identity.runId)
    throw new TypeError('publication requires its genuine same-owner Run execution');
  (value as RunExecution).assertCurrentDeliveryWorker(identity);
}

/** Only the original in-flight publication task can borrow its execution's
 * held worker. Ordinary callers still cannot release while any task is pending;
 * a callback, retained artifact or another execution cannot waive that gate. */
export function assertDeliveryPublicationExecution(driver: SqliteDriver, owner: StateOwnerContext, execution: unknown,
  worker: RunExecutionWorkerIdentity, task: DeliveryPublicationTask, connection: SqliteConnection = driver): void {
  const held = execution !== null && typeof execution === 'object' ? deliveryExecutions.get(execution) : undefined;
  const original = task !== null && typeof task === 'object' ? publicationTasks.get(task) : undefined;
  if (!held || !original || held.driver !== driver || held.owner !== owner || original.driver !== driver ||
      original.owner !== owner || original.execution !== execution || held.runId !== original.worker.runId)
    throw new TypeError('publication requires its genuine same-owner in-flight execution task');
  requireEqual(worker, original.worker, 'publication original in-flight worker identity');
  assertSqliteConnectionOwnedBy(driver, connection); original.assertCurrent(connection);
}

/** The real task supplies its continuously held roots and original worker's
 * one retirement closure. A caller cannot provide a path, proof, Checkpoint or
 * callback in their place. This friend permits completion after revocation,
 * never a new semantic publication release. */
export async function readOwnedPublicationExecutionResources(driver: SqliteDriver, owner: StateOwnerContext,
  execution: unknown, publicationOwner: PublicationInvocationOwner): Promise<PublicationExecutionResources> {
  const held = execution !== null && typeof execution === 'object' ? deliveryExecutions.get(execution) : undefined;
  if (!held || held.driver !== driver || held.owner !== owner)
    throw new TypeError('publication retirement requires its genuine same-owner execution');
  const { assertOwnedPublicationPath } = await import('./publication-invocation.js');
  const path = assertOwnedPublicationPath(driver, owner, execution, publicationOwner, driver);
  const original = publicationTasks.get(path.task);
  if (!original || original.driver !== driver || original.owner !== owner || original.execution !== execution ||
      held.runId !== original.worker.runId)
    throw new TypeError('publication retirement requires its original execution task');
  requireEqual(path.worker, original.worker, 'publication retirement original worker');
  return original.resources();
}

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
type ReceivedCompletion = ({ kind: 'tool' | 'final_turn' | 'verifier' | 'publication'; worker: LinuxBlockedWorker;
  activeWorker: ActiveWorker } | { kind: 'publication_maintenance' | 'publication_received' | 'publication_reconciliation';
    worker?: LinuxBlockedWorker; activeWorker?: ActiveWorker }) & {
  finish(): Promise<Run>; failure?: unknown };

/** Pure retry classification only. The caller must already own the genuine
 * received producer; its fixed completion still validates the entire Stop
 * graph and current SQL cut before any durable result can be committed. */
export function isPublicationStopRevisionConflict(kind: ReceivedCompletion['kind'], error: unknown,
  stopIntentRef: string | null | undefined): boolean {
  return (kind === 'publication_received' || kind === 'publication_reconciliation') &&
    error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT' && !!stopIntentRef;
}

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

async function publishVerifierRecipe(artifacts: ArtifactCatalog, workerSpec: WorkerSpec, parentContainmentRef: string, parentCgroup: string,
  prepared: Extract<Awaited<ReturnType<Awaited<ReturnType<typeof loadAgentRun>>['prepareVerifier']>>, { disposition: 'prepared' }>, dispatchId: string) {
  const command = decodeVerifierCommand(await artifacts.readCanonical(prepared.target.commandRef));
  if (command.executable.kind !== 'guest_toolchain' || workerSpec.filesystem.kind !== 'run_generation')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier requires its exact signed guest and private generation');
  const executable = command.executable;
  const guest = decodeGuestToolchainManifest(await artifacts.readCanonical(executable.guestToolchainManifestRef));
  const owner = { kind: 'run_invocation' as const, runId: prepared.run.id, intendedLeaseEpoch: prepared.run.leaseEpoch,
    workerLaunchId: workerSpec.owner.workerLaunchId, opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId };
  const parentPlan = await artifacts.readCanonical<ProcessContainmentPlanV1>(workerSpec.containmentPlanRef);
  if (parentPlan.backend.kind !== 'linux') throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier requires its original Linux parent');
  const cgroupNameReservationDigest = canonicalSha256(['cliq-verifier-cgroup-v1', dispatchId]);
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef: workerSpec.filesystem.generationRef }, parentContainmentRef,
    launchNonceDigest: nonce(), backend: { kind: 'linux', cgroupPath: path.posix.join(parentCgroup, `cliq-${cgroupNameReservationDigest}`),
      cgroupNameReservationDigest, pidNamespaceReservationId: identityHash('cliq-verifier-namespace-v1', dispatchId),
      subreaperStartToken: parentPlan.backend.subreaperStartToken }, createdAt: sampleCanonicalNow(), planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const containmentPlanRef = (await artifacts.publishCanonical(plan, plan.format)).ref;
  const runtime: SandboxRuntimeBindingV1 = { ...workerSpec.runtime, toolchain: { kind: 'guest_toolchain',
    guestToolchainManifestRef: executable.guestToolchainManifestRef, guestToolchainManifestDigest: guest.manifestDigest,
    guestImageRef: guest.guestImageRef, guestImageDigest: guest.guestImageDigest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const mounts = LINUX_VERIFIER_RECIPE.mounts.map(mount => ({ ...mount, privateRootId: identityHash(dispatchId, mount.purpose) }));
  const spec: EditSpec = { ...workerSpec, owner, purpose: 'verifier', runtime,
    executable: { kind: 'guest_toolchain', guestToolchainManifestRef: executable.guestToolchainManifestRef,
      guestToolchainManifestDigest: guest.manifestDigest, toolId: executable.toolId, role: 'verifier',
      executionPath: executable.executionPath, executableDigest: executable.executableDigest },
    processInvocation: { kind: 'run_request', purpose: 'verifier', recipe: 'cliq-verifier-command-v1',
      requestRef: prepared.entry.requestRef, requestDigest: prepared.request.requestDigest,
      targetRef: prepared.entry.target, targetDigest: prepared.target.targetDigest, argvCwdSource: 'trusted_recipe_decode_of_request_and_target',
      stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' } },
    filesystem: { ...workerSpec.filesystem, access: 'read_only' }, environment: LINUX_VERIFIER_RECIPE.environment,
    mounts, mountsDigest: canonicalSha256(mounts), parentWorkerContainmentRef: parentContainmentRef,
    requestRef: prepared.entry.requestRef, requestDigest: prepared.request.requestDigest, targetRef: prepared.entry.target,
    targetDigest: prepared.target.targetDigest, operationGrantRef: prepared.entry.grantRef!, containmentPlanRef,
    containmentPlanDigest: plan.planDigest, createdAt: sampleCanonicalNow(), launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  return (await artifacts.publishCanonical(spec, spec.format)).ref;
}

/** Inert installed shutdown diagnosis, never retirement evidence or authority. */
export type RunRetirementPhase = 'history' | 'quarantine_closure' | 'native_retirement' |
  'workspace_observation' | 'retirement_commit' | 'resource_join';
/** Fixed current work labels only, never publication or retirement evidence. */
export type RunPublicationPhase = 'publication_select' | 'publication_worker_activate' | 'publication_roots_open' |
  'publication_prepare' | 'publication_prepare_read' | 'publication_prepare_grant' | 'publication_prepare_cut' |
  'publication_prepare_physical' | 'publication_prepare_admit' | 'publication_dispatch' | 'publication_settlement' |
  'publication_received_retirement' | 'publication_received_read' | 'publication_received_proof' | 'publication_received_settle';
/** Deep internal resource owner. Opening validates only; process creation is lazy.
 * Durable lifecycle, retry and budgets remain exclusively in the existing reducers. */
export async function loadRunExecution(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; execution?: RunExecutionInstallation;
    sourceInspection?: { controlledHome: string } } | undefined,
  input: LoadRunExecutionInput, isClosing: () => boolean = () => false,
  selectedRuntime?: HeldInstalledRuntime, installedAnchor?: HeldInstalledAnchor, executionStore?: StateStore, openingSignal?: AbortSignal,
  onRetirementPhase?: (phase: RunRetirementPhase) => void,
  onPublicationPhase?: (phase: RunPublicationPhase) => void
): Promise<{ execution: RunExecution; closeWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }): Promise<Run>;
  beginClose(): Promise<void>; close(): Promise<void> }> {
  openingSignal?.throwIfAborted();
  const openingReads = openingSignal ? artifacts.withReadSignal(openingSignal) : artifacts;
  const runId = input.runId;
  const retirementPhase = (phase: RunRetirementPhase) => { try { onRetirementPhase?.(phase); } catch { /* Diagnosis cannot decide retirement. */ } };
  const publicationPhase = (phase: RunPublicationPhase) => { try { onPublicationPhase?.(phase); } catch { /* Diagnosis cannot decide publication. */ } };
  // Delivery never reads or validates live model material. Agent resolvers
  // retain their original trusted functions and snapshot BEFORE the first
  // asynchronous read. The explicit selector is checked against retained State,
  // never treated as permission or cast into another operation's authority.
  const material = input.operation === 'delivery' ? undefined : Object.fromEntries(Object.entries(input.material).map(([key, value]) =>
    [key, typeof value === 'function' ? value : immutableSnapshot(value)])) as RunAssemblyValidationMaterial;
  const selectedSpec = decodeRunSpec(await openingReads.readCanonical(readRun(driver, runId).specRef));
  if (selectedSpec.operation !== (input.operation ?? 'agent'))
    throw new KernelStorageError('INVALID_REQUEST', 'execution selector does not match its retained Run operation');
  const installed = selectedRuntime !== undefined || installedAnchor !== undefined;
  let installation: Pick<RunExecutionInstallation, 'cgroupParent'> | undefined;
  if (installed) {
    withInstalledWorkerRoot(selectedRuntime!, installedAnchor!, (_fd, cgroupParent) => { installation = { cgroupParent }; });
  } else installation = bootstrap?.execution && immutableSnapshot(bootstrap.execution);
  const launcher = installed ? await openInstalledLinuxWorkerLauncher(selectedRuntime!, installedAnchor!, { ...(openingSignal ? { signal: openingSignal } : {}) }) :
    await openLinuxWorkerLauncher(bootstrap?.execution && { ...immutableSnapshot(bootstrap.execution), runtimeAuthority: bootstrap });
  let worker: LinuxBlockedWorker | undefined;
  async function reobserveRetirement() {
    // An already received result still belongs to its original producer.
    // Closing forbids new work, not that exact producer's final death check.
    const completingOriginal = closingCompletion !== undefined && operationPhase === 'received' &&
      (closingCompletion.operation === pending || receivedCompletion !== undefined && closingCompletion.completion === receivedCompletion) &&
      closingCompletion.worker === worker && closingCompletion.activeWorker === activeWorker;
    if (((closed || isClosing()) && !completingOriginal) || !worker || !activeWorker) {
      throw new KernelStorageError('LEASE_FENCED', 'native worker retirement scope is closing or unavailable');
    }
    assertActiveStateOwner(driver, owner);
    return observeOriginalWorkerDeath(activeWorker);
  }
  let continuation: Awaited<ReturnType<typeof loadAgentRun>> | DeliveryContinuation;
  function requireAgent() {
    if (continuation.operation !== 'agent') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'this action requires an Agent Run execution');
    return continuation;
  }
  try {
    openingSignal?.throwIfAborted();
    continuation = selectedSpec.operation === 'agent'
      ? await loadAgentRun(driver, artifacts, owner, { runId, material: material!, releaseKeys: bootstrap!.releaseKeys },
          reobserveRetirement, selectedRuntime, openingSignal)
      : await loadDeliveryContinuation(driver, artifacts, owner, { runId, releaseKeys: bootstrap!.releaseKeys },
          reobserveRetirement, selectedRuntime, openingSignal);
    openingSignal?.throwIfAborted();
    const run = readRun(driver, runId);
    if (run.parentRunId !== undefined) throw new KernelStorageError('INVALID_REQUEST', 'this installed execution recipe does not support child Runs');
    const runSpec = decodeRunSpec(await openingReads.readCanonical(run.specRef));
    const assembly = decodeRetainedRunAssembly(await openingReads.readCanonical(runSpec.assemblyRef));
    const profile = decodeSandboxProfile(await openingReads.readCanonical(runSpec.sandboxProfileRef));
    const currentOwner = assertActiveStateOwner(driver, owner);
    if (assembly.runtime.sandboxBackend !== 'linux_namespace' || assembly.runtime.workerExecutableId !== LINUX_WORKER_RECIPE.workerId ||
        assembly.runtime.runtimeBundleRef !== currentOwner.runtimeBundleRef || profile.backend !== 'linux_namespace' ||
        !profile.allowedOwners.includes('worker_activation') || !profile.allowedOwners.includes('run_invocation') || profile.resources.maxProcesses < 8) {
      throw new KernelStorageError('INVALID_REQUEST', 'frozen Run requires an unsupported execution recipe');
    }
    openingSignal?.throwIfAborted();
  } catch (error) {
    try { await launcher.close(); }
    catch (failure) { throw new ResourceRetirementError('execution opening failed and its installation cleanup did not complete', failure); }
    throw error;
  }
  let pending: Promise<Run> | undefined, closed = false, cleanupFailure: unknown;
  let operationAbort: AbortController | undefined, revoking: Promise<void> | undefined, closing: Promise<void> | undefined;
  // Preflight reads do not own productive retirement, but still belong to this
  // genuine execution scope before an operation/probe can be registered.
  const preflightAbort = new AbortController(), preflightReads = artifacts.withReadSignal(preflightAbort.signal);
  let probe: { run: Run; wait: WorkerDeathWait; task: WorkerRecoveryTask; closure?: Promise<Run> } | undefined;
  let generation: RunWorkspaceGeneration | undefined, controller: LinuxWorkerController | undefined;
  let reservation: HeldWorkerReservation | undefined;
  let ownedLaunchId: string | undefined;
  let activeWorker: ActiveWorker | undefined;
  let stopJoin: Promise<void> | undefined;
  let operationPhase: 'preparing' | 'claimed' | 'received' | undefined;
  let verifierReleased = false;
  let receivedCompletion: ReceivedCompletion | undefined;
  let closingCompletion: { operation?: Promise<Run>; completion?: typeof receivedCompletion; worker: LinuxBlockedWorker; activeWorker: ActiveWorker } | undefined;
  let retirementController: LinuxWorkerController | undefined;
  let preparation: PreparingWorkerLaunch | undefined, materialization: RunWorkspaceMaterialization | undefined;
  let workspaceBirth: RunWorkspaceBirth | undefined;
  const publicationOwners = new Set<PublicationInvocationOwner>();
  let publicationTask: DeliveryPublicationTask | undefined;
  let noOpTask: DeliveryNoOpTask | undefined;
  let publicationMaintenanceTask: DeliveryPublicationMaintenanceTask | undefined;
  let publicationReceivedTask: DeliveryPublicationReceivedTask | undefined;
  let publicationReconciliationTask: DeliveryPublicationReconciliationTask | undefined;
  let publicationProbe: { run: Run; wait: PublicationPathWait; task: PublicationReconciliationTask;
    rootTask: DeliveryPublicationReconciliationTask; closure?: Promise<Run> } | undefined;
  let publicationEnqueue: { requestId: string; requestDigest: string; principalId: string;
    result: ReturnType<RunExecution['enqueuePublicationReconciliation']> } | undefined;
  // Created only after a genuine durable known-result handoff. Cancelling
  // projection never cancels the original effect or M-retirement authority.
  let publicationProjectionAbort: AbortController | undefined;
  let settleReceivedPublication: ((expectedRunRevision: number) => Promise<Run>) | undefined;
  let publicationRoots: { workspaceRoot: HeldWorkspaceRoot; controlledHome: HeldWorkspaceRoot } | undefined;
  let publicationRetirement: { worker: ActiveWorker; checkpointId: string; retire: ReturnType<typeof checkpointRetirement>;
    cancellation: AbortController } | undefined;
  function revokePublications(): void {
    // Revoke every original release gate synchronously, before waiting for any
    // worker, CAS or database completion. Revocation is not cleanup evidence.
    for (const original of publicationOwners) {
      try { original.revoke(); }
      catch (error) { cleanupFailure ??= error; }
    }
  }
  function closePublications(): void {
    revokePublications();
    for (const original of publicationOwners) {
      try { original.close(); }
      catch (error) { cleanupFailure ??= error; }
    }
  }
  async function holdPublicationRoots(workspacePath: string, signal: AbortSignal) {
    if (publicationRoots) {
      signal.throwIfAborted(); publicationRoots.workspaceRoot.assertHeld(); publicationRoots.controlledHome.assertHeld();
      return publicationRoots;
    }
    if (!bootstrap?.sourceInspection) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication lacks its trusted controlled home');
    const native = selectedRuntime ? await withHeldInstalledRuntime(selectedRuntime, async installed => {
      await installed.revalidate(signal);
      if (installed.bundleDigest !== canonicalSha256(bootstrap.bundle))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'publication native image differs from its original selected runtime');
      const native = await installed.loadStateOwner(signal); await installed.revalidate(signal); return native;
    }, signal) : await loadNativeStateOwner(bootstrap.bundle);
    signal.throwIfAborted();
    if (closed || isClosing()) throw new KernelStorageError('LEASE_FENCED', 'publication scope closed before opening its roots');
    const controlledHome = native.openWorkspaceRoot(bootstrap.sourceInspection.controlledHome);
    try {
      // No await between birth and resource registration. The real same-owner
      // preflight subsequently binds this root to the original approved A.
      const workspaceRoot = native.openWorkspaceRoot(workspacePath);
      return publicationRoots = { controlledHome, workspaceRoot };
    } catch (error) {
      try { controlledHome.close(); }
      catch (failure) { throw new ResourceRetirementError('publication root opening did not join its controlled home', new AggregateError([error, failure])); }
      throw error;
    }
  }
  function revokeOriginalWorker(): Promise<void> {
    if (stopJoin) return stopJoin;
    const retainedController = controller, retainedWorker = worker;
    // Enter irreversible native revocation before returning to a draining
    // caller. Its original join remains available to result/recovery owners.
    let revoked: Promise<void> | undefined;
    try { revoked = retainedController?.close(); }
    catch (error) { revoked = Promise.reject(error); }
    stopJoin = (async () => {
      await revoked;
      await retainedWorker?.closeAfterControllerJoin();
    })().catch(error => {
      cleanupFailure ??= error;
      throw error;
    });
    void stopJoin.catch(() => {});
    return stopJoin;
  }
  function beginClose(): Promise<void> {
    if (revoking) return revoking;
    closed = true;
    preflightAbort.abort(new KernelStorageError('LEASE_FENCED', 'execution read-only preflight is closing'));
    revokePublications();
    publicationProjectionAbort?.abort(new KernelStorageError('LEASE_FENCED', 'publication read-only projection scope is closing'));
    if ((pending || receivedCompletion) && worker && activeWorker && (operationPhase === 'claimed' || operationPhase === 'received')) {
      closingCompletion = { operation: pending, completion: receivedCompletion, worker, activeWorker };
    }
    // A claimed producer may still deliver its genuine result after native
    // revocation. Do not abort that result's Checkpoint/settlement path.
    if (operationPhase !== 'claimed' && operationPhase !== 'received') operationAbort?.abort();
    const joins: Promise<unknown>[] = [];
    // Idle model workers remain physically held until StateStore has joined
    // their original broker settlement. Pending executions enter actual
    // revocation before inspector cancellation, including BIND/READY polls
    // that do not consume the abort signal.
    try { if (pending || receivedCompletion) joins.push(revokeOriginalWorker()); }
    catch (error) { cleanupFailure ??= error; }
    try { if (probe) joins.push(probe.task.cancelAndJoin()); }
    catch (error) { cleanupFailure ??= error; }
    try { if (publicationProbe) joins.push(publicationProbe.task.cancelAndJoin()); }
    catch (error) { cleanupFailure ??= error; }
    revoking = Promise.allSettled(joins).then(results => {
      const failed = results.find(result => result.status === 'rejected');
      if (failed?.status === 'rejected') cleanupFailure ??= failed.reason;
      if (cleanupFailure !== undefined) throw cleanupFailure;
    });
    void revoking.catch(() => {});
    return revoking;
  }
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
  async function retireWorkerResources() {
    const retainedGeneration = generation, retainedController = controller, retainedReservation = reservation, retainedRetirement = retirementController,
      retainedMaterialization = materialization;
    retirementController = undefined;
    // Worker death cannot discard the original UNKNOWN publication's only
    // continuously held reconciliation handles. They remain irreversibly
    // revoked; retaining them supplies no new semantic release authority.
    // Publication owns a separate lifetime. Its genuine producer joins its
    // completed envelope, or execution.close joins the original unresolved
    // handles; worker retirement must not implicitly destroy that owner.
    revokePublications();
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
    const retainedPublicationRetirement = publicationRetirement;
    worker = undefined; ownedLaunchId = undefined; activeWorker = undefined; publicationRetirement = undefined;
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
    retainedPublicationRetirement?.cancellation.abort();
    if (cleanupFailure !== undefined) throw cleanupFailure;
  }
  const revision = (value: { expectedRunRevision: number }, completingReceived = false) => {
    if (!exactKeys(value, ['expectedRunRevision']) || !Number.isSafeInteger(value.expectedRunRevision) || value.expectedRunRevision < 1) {
      throw new KernelStorageError('INVALID_REQUEST', 'execution requires one exact Run revision');
    }
    if (closed || isClosing()) throw new KernelStorageError('LEASE_FENCED', 'Run execution scope is closing or closed');
    if (cleanupFailure !== undefined) throw new KernelStorageError('RECOVERY_REQUIRED', 'Run execution scope has an unresolved retirement failure');
    if (pending) throw new KernelStorageError('REVISION_CONFLICT', 'Run execution already has an operation in flight');
    if (receivedCompletion && !completingReceived) throw new KernelStorageError('REVISION_CONFLICT', 'Run execution retains its original completion');
    if (readRun(driver, runId).revision !== value.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'Run execution revision changed');
    assertActiveStateOwner(driver, owner);
    return value.expectedRunRevision;
  };
  function assertCurrentWorker(value: RunExecutionWorkerIdentity, nextStep: 'agent' | 'delivery', task?: DeliveryPublicationTask,
    connection: SqliteConnection = driver) {
    const action = nextStep === 'agent' ? 'model' : 'delivery';
    const originalPublication = nextStep === 'delivery' && task !== undefined && publicationTask === task && pending !== undefined &&
      publicationTasks.get(task)?.execution === execution;
    if (!exactKeys(value, ['runId', 'leaseEpoch', 'launchId', 'generationRef', 'workerIdentityDigest']) ||
        value.runId !== runId || !Number.isSafeInteger(value.leaseEpoch) || value.leaseEpoch < 1 ||
        closed || isClosing() || cleanupFailure !== undefined || pending && !originalPublication || receivedCompletion && !originalPublication ||
        !activeWorker || !worker || !generation || !controller || !reservation ||
        value.launchId !== ownedLaunchId || value.launchId !== activeWorker.activated.launch.launchId ||
        value.generationRef !== activeWorker.authority.generationRef || value.workerIdentityDigest !== activeWorker.activated.launch.workerIdentityDigest) {
      throw new KernelStorageError('LEASE_FENCED', `${action} release does not name this execution owner's original physical worker`);
    }
    const run = readRun(connection, runId);
    const live = assertLiveDispatchState(connection, owner, runId, run.revision, value.leaseEpoch, sampleCanonicalNow());
    if (run.nextStep !== nextStep || live.launch.launchId !== value.launchId || live.launch.workerIdentityDigest !== value.workerIdentityDigest ||
        live.launch.workspaceGenerationRef !== value.generationRef || live.launch.processContainmentRef !== activeWorker.processContainmentRef) {
      throw new KernelStorageError('LEASE_FENCED', `${action} release durable worker identity changed`);
    }
    reservation.assertHeld();
    worker.assertHeld();
    // The native worker already retains the original generation borrow;
    // its assertion verifies that descriptor, mount, quota identity and owner.
    assertActiveStateOwner(connection, owner);
  }
  /** One actual birth spine for productive Run frontiers. Success retains the
   * original resources; the existing operation owner joins them on failure. */
  async function activateWorker(selected: WorkerActivationCut, signal: AbortSignal): Promise<ActiveWorker> {
    const reads = artifacts.withReadSignal(signal);
    reads.assertReadActive();
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
    preparation = await beginWorkerPreparation(driver, reads, owner, { runId, expectedRunRevision: run.revision,
      launchId, spawnNonceDigest, activationNonceDigest, generationCreationNonceDigest });
    materialization = createRunWorkspaceMaterialization({ filesystem: owner.filesystem, artifacts: reads,
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
    const profile = decodeSandboxProfile(await reads.readCanonical(selected.runSpec.sandboxProfileRef));
    const borrowed = borrowRunWorkspaceForExecution(generation);
    try { borrowed.assertQuota(profile.resources.maxGenerationBytes); } finally { borrowed.close(); }
    controller = await launcher.startController({ signal });
    reservation = owner.filesystem.createWorkerReservation(launchId, spawnNonceDigest);
    await recordWorkerPreparationController(driver, artifacts, owner, { launchId, birth: controller.preparationBirth, reservation });
    const recipe = await publishWorkerRecipe(reads, controller, installation!, selected, authority.generationRef,
      reservation, launchId, spawnNonceDigest, activationNonceDigest);
    const closure = await readWorkerLaunchClosure(reads, assertActiveStateOwner(driver, owner), { ...recipe.input, run });
    signal.throwIfAborted();
    const binding = await controller.bindWorkerReservation({ closure, reservation, activationNonceDigest });
    signal.throwIfAborted();
    const reserved = await reserveWorkerLaunch(driver, reads, owner, recipe.input, binding);
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
  function checkpointRetirement(current: ActiveWorker, checkpointId: string, signal: AbortSignal) {
    if (current !== activeWorker || !worker || !generation || ownedLaunchId !== current.activated.launch.launchId) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'checkpoint retirement lost its original physical worker owner');
    }
    const currentWorker = worker, currentGeneration = generation;
    const { authority, recipe, reserved, activated, processContainmentRef } = current;
    const quiesceId = identityHash('cliq-worker-quiesce-v1', activated.launch.launchId, checkpointId);
    let revoking: ReturnType<typeof beginGenerationRevocation> | undefined;
    let death: Awaited<ReturnType<typeof observeOriginalWorkerDeath>> | undefined;
    let checkpointing: ReturnType<typeof beginGenerationCheckpoint> | undefined;
    let observed: Awaited<ReturnType<RunWorkspaceGeneration['observe']>> | undefined;
    let inspector: Awaited<ReturnType<typeof publishInspector>> | undefined;
    let retirementBody: ReturnType<typeof deathBody> | undefined;
    let retirement: Awaited<ReturnType<ArtifactCatalog['publishCanonical']>> | undefined;
    let snapshot: WorkspaceGenerationSnapshotEvidenceV1 | undefined;
    let snapshotEvidenceRef: string | undefined;
    function deathBody(actualDeath: Awaited<ReturnType<typeof observeOriginalWorkerDeath>>, actualInspector: Awaited<ReturnType<typeof publishInspector>>) {
      const core = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: processContainmentRef,
        planRef: recipe.input.containmentPlanRef, sandboxLaunchSpecRef: recipe.input.sandboxLaunchSpecRef,
        sandboxLaunchSpecDigest: recipe.spec.launchSpecDigest, owner: actualDeath.containment.owner, launchNonceDigest: reserved.spawnNonceDigest,
        inspectorSupervisorInstanceId: owner.supervisorInstanceId, ...actualInspector,
        backend: { ...actualDeath.containment.backend, cgroupPopulated: actualDeath.cgroupPopulated,
          namespaceInitDeadAndReaped: actualDeath.namespaceInitDeadAndReaped, remainingTrackedDescendants: actualDeath.remainingTrackedDescendants },
        observedAt: actualDeath.observedAt };
      return { ...core, evidenceDigest: canonicalSha256(core) };
    }
    return async () => {
      if (current !== activeWorker || worker !== currentWorker || generation !== currentGeneration || ownedLaunchId !== activated.launch.launchId) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'checkpoint continuation lost its original physical owner');
      }
      assertActiveStateOwner(driver, owner);
      const beforeSeal = await readRecoveryClosure(driver, artifacts, runId);
      signal.throwIfAborted();
      const activeGeneration = beforeSeal.workspaceGenerations.find(row => row.generationRef === authority.generationRef);
      const activeLaunch = beforeSeal.workerLaunches.find(row => row.launchId === activated.launch.launchId);
      if (!activeGeneration || !activeLaunch || activeLaunch.phase !== 'activated' || beforeSeal.run.activeWorkerLaunchId !== activeLaunch.launchId ||
          beforeSeal.run.leaseEpoch !== activeLaunch.leaseEpoch || activeLaunch.workspaceGenerationRef !== authority.generationRef ||
          activeLaunch.workerIdentityDigest !== activated.launch.workerIdentityDigest || activeLaunch.processContainmentRef !== processContainmentRef) {
        throw new KernelStorageError('LEASE_FENCED', 'checkpoint retirement differs from the original worker and generation');
      }
      const retainedStage = checkpointing ?? revoking;
      if (retainedStage) {
        requireEqual(activeLaunch, retainedStage.launch, 'checkpoint continuation original launch stage');
        requireEqual(activeGeneration, retainedStage.generation, 'checkpoint continuation original generation stage');
      }
      revoking ??= beginGenerationRevocation(driver, owner, { launchId: activeLaunch.launchId,
        expectedLeaseVersion: activeLaunch.leaseVersion, expectedGenerationRowVersion: activeGeneration.rowVersion, quiesceId });
      death ??= await observeOriginalWorkerDeath(current);
      assertNativeContainmentDeath(death);
      requireEqual(death.containment, currentWorker.containment, 'checkpoint original native containment');
      checkpointing ??= beginGenerationCheckpoint(driver, owner, { launchId: activeLaunch.launchId, expectedLeaseVersion: revoking.launch.leaseVersion,
        expectedGenerationRowVersion: revoking.generation.rowVersion, quiesceId });
      observed ??= await currentGeneration.observe({ signal });
      inspector ??= await publishInspector(artifacts, assertActiveStateOwner(driver, owner));
      retirementBody ??= deathBody(death, inspector);
      retirement ??= await artifacts.publishCanonical(retirementBody, 'cliq-process-containment-death-evidence-v1');
      const state = await artifacts.readCanonical<import('../kernel/types.js').WorkspaceStateManifest>(observed.workspaceStateRef);
      snapshot ??= { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1',
        purpose: 'sealed_to_checkpoint', quiescenceEvidenceRef: retirement.ref, runId,
        generationRef: authority.generationRef, generationIdentityDigest: authority.generationIdentityDigest,
        checkpointId, workspaceStateRef: observed.workspaceStateRef, workspaceStateDigest: observed.workspaceStateDigest,
        entriesRef: observed.entriesRef, treeDigest: observed.treeDigest,
        ...(state.privateGitStateRef ? { privateGitStateRef: state.privateGitStateRef } : {}),
        descriptorRewalkComplete: observed.descriptorRewalkComplete, fileFsyncComplete: observed.fileFsyncComplete,
        directoryFsyncComplete: observed.directoryFsyncComplete, observedAt: sampleCanonicalNow(), evidenceDigest: '' };
      snapshot.evidenceDigest = digestOmitting(snapshot, 'evidenceDigest');
      snapshotEvidenceRef ??= (await artifacts.publishCanonical(snapshot, snapshot.format)).ref;
      return { postEffect: { workspaceStateRef: observed.workspaceStateRef, snapshotEvidenceRef, retirementEvidenceRef: retirement.ref },
        snapshot, checkpointing, quiesceId };
    };
  }
  async function retireToCheckpoint(current: ActiveWorker, checkpointId: string, signal: AbortSignal) {
    return checkpointRetirement(current, checkpointId, signal)();
  }
  function publicationCheckpointRetirement(current: ActiveWorker, planRef: string) {
    const checkpointId = deliveryPublicationCheckpointId(runId, planRef);
    if (publicationRetirement) {
      if (publicationRetirement.worker !== current || publicationRetirement.checkpointId !== checkpointId)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'publication cannot replace its original M retirement owner');
      return publicationRetirement.retire;
    }
    // M belongs to this whole resource scope, not the first semantic path.
    // Stop may abort that path between SQL claim and arm; its no-effect result
    // must still be able to retire the same M later. This scope-owned signal
    // ends only after the original resources have joined. It grants no release
    // and does not solve the separate bounded shutdown/projection handoff.
    const cancellation = new AbortController();
    const retire = checkpointRetirement(current, checkpointId, cancellation.signal);
    publicationRetirement = { worker: current, checkpointId, retire, cancellation }; return retire;
  }
  async function openPublicationMaintenanceTask(selected: Awaited<ReturnType<typeof readRecoveryClosure>>,
    expectedRunRevision: number, signal: AbortSignal): Promise<DeliveryPublicationMaintenanceTask> {
    signal.throwIfAborted();
    if (selected.run.revision !== expectedRunRevision || selected.run.nextStep !== 'delivery' ||
        !selected.run.stopIntentRef || !['queued', 'running'].includes(selected.run.status))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication maintenance requires its exact durable stopping cut');
    const reads = artifacts.withReadSignal(signal);
    const { readDeliveryRunAdmission } = await import('./reducers/delivery-admission.js');
    const admission = await readDeliveryRunAdmission(driver, reads, runId, { signal });
    requireEqual(admission.run, selected.run, 'publication maintenance original admission cut');
    const { readPublicationPrefix } = await import('./delivery-publication-progress.js');
    const prefix = await readPublicationPrefix(driver, reads, selected);
    if (!prefix.authorization) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication maintenance has no original approved Plan');
    const workspace = decodeWorkspaceIdentity(await reads.readCanonical(admission.target.workspaceIdentityRef));
    if (workspace.kind !== 'live' || workspace.identityDigest !== admission.target.workspaceIdentityDigest)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'publication maintenance lost its original live workspace');
    const roots = await holdPublicationRoots(workspace.canonicalRootPath, signal);
    const retire = activeWorker ? publicationCheckpointRetirement(activeWorker, prefix.authorization.context.planRef) : undefined;
    const task: DeliveryPublicationMaintenanceTask = Object.freeze({ [publicationMaintenanceTaskBrand]: true as const });
    publicationMaintenanceTask = task;
    const assertOwned = () => {
      if (publicationMaintenanceTask !== task || !pending || closed || isClosing() || cleanupFailure !== undefined)
        throw new KernelStorageError('LEASE_FENCED', 'publication maintenance lost its original in-flight task');
      signal.throwIfAborted();
    };
    publicationMaintenanceTasks.set(task, { driver, owner, execution, artifacts, assertOwned,
      resources(connection = driver) {
        assertOwned(); assertActiveStateOwner(connection, owner);
        if (publicationRoots !== roots) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication maintenance lost its original held roots');
        roots.workspaceRoot.assertHeld(); roots.controlledHome.assertHeld();
        return Object.freeze({ runId, expectedRunRevision, ...roots, signal,
          publicationOwners: Object.freeze([...publicationOwners]), ...(retire ? { retire } : {}), reobserveRetirement });
      } });
    return task;
  }
  async function openPublicationReconciliationTask(selected: Awaited<ReturnType<typeof readRecoveryClosure>>,
    expectedRunRevision: number, signal: AbortSignal): Promise<DeliveryPublicationReconciliationTask> {
    signal.throwIfAborted();
    if (selected.run.revision !== expectedRunRevision || selected.run.nextStep !== 'delivery' ||
        !['queued', 'waiting'].includes(selected.run.status) || selected.run.activeWorkerLaunchId ||
        selected.workerLaunches.length || selected.workspaceGenerations.some(row => row.phase !== 'retired' && row.phase !== 'sealed') ||
        activeWorker || worker || generation || controller || reservation || ownedLaunchId)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication inspection requires the genuinely retired original worker resources');
    const reads = artifacts.withReadSignal(signal);
    const { readPublicationPrefix } = await import('./delivery-publication-progress.js');
    const prefix = await readPublicationPrefix(driver, reads, selected), workspace = prefix.authorization?.workspace;
    if (!workspace || workspace.kind !== 'live')
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication inspection has no original approved live workspace');
    const unresolved = [...prefix.entries.values()].filter(entry => entry.claim && !entry.pendingReceivedHandoff &&
      (!entry.result || entry.result.item.outcome === 'unknown'));
    if (unresolved.length !== 1)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication inspection requires one exact original unresolved claim');
    const originalEntry = unresolved[0]!, originalClaim = originalEntry.claim!;
    const launches = readWorkerLaunchesForRun(driver, runId).filter(launch => launch.leaseEpoch === originalClaim.leaseEpoch &&
      launch.retirementKind !== 'preparation');
    const originalGeneration = launches.length === 1
      ? selected.workspaceGenerations.find(row => row.generationRef === launches[0]!.workspaceGenerationRef) : undefined;
    // Earlier verifier generations may genuinely remain sealed. The exact
    // forward claim's M must be retired; an abort maintenance claim may instead
    // use its already genuinely sealed M. Neither branch recreates a worker or
    // changes a sealed/retired generation's phase to manufacture evidence.
    const closedMaintenance = originalEntry.sequence === 'abort' && !!selected.run.stopIntentRef;
    if (launches.length !== 1 || launches[0]!.phase !== 'retired' || !originalGeneration ||
        originalGeneration.phase !== 'retired' && !(closedMaintenance && originalGeneration.phase === 'sealed'))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication inspection original claimed M is not genuinely retired');
    const roots = await holdPublicationRoots(workspace.canonicalRootPath, signal);
    const task: DeliveryPublicationReconciliationTask = Object.freeze({ [publicationReconciliationTaskBrand]: true as const });
    publicationReconciliationTask = task;
    const assertRegistered = () => {
      if (publicationReconciliationTask !== task || !pending && publicationProbe?.rootTask !== task ||
          cleanupFailure !== undefined || publicationRoots !== roots ||
          activeWorker || worker || generation || controller || reservation || ownedLaunchId)
        throw new KernelStorageError('LEASE_FENCED', 'publication inspection lost its original registered task');
    };
    const assertOwned = () => {
      assertRegistered();
      if (closed || isClosing())
        throw new KernelStorageError('LEASE_FENCED', 'publication inspection lost its original authority-reducing task');
      signal.throwIfAborted();
    };
    publicationReconciliationTasks.set(task, { driver, owner, execution, artifacts, assertOwned, assertRegistered,
      resources(connection = driver) {
        assertOwned(); assertActiveStateOwner(connection, owner);
        roots.workspaceRoot.assertHeld(); roots.controlledHome.assertHeld();
        return Object.freeze({ runId, expectedRunRevision, ...roots, signal, publicationOwners: Object.freeze([...publicationOwners]) });
      } });
    return task;
  }
  async function finishReceivedPublication() {
    publicationPhase('publication_settlement');
    // Joined CAS/rolled-back SQL retries keep the same genuine result token
    // and fixed once-only BudgetSettlement. A new task must not reset it.
    if (settleReceivedPublication) return settleReceivedPublication(readRun(driver, runId).revision);
    publicationPhase('publication_received_read');
    const abort = new AbortController(); publicationProjectionAbort = abort;
    if (closed || isClosing()) abort.abort(new KernelStorageError('LEASE_FENCED', 'publication read-only projection scope is closing'));
    const signal = abort.signal, reads = artifacts.withReadSignal(signal);
    signal.throwIfAborted();
    const { readPublicationPrefix } = await import('./delivery-publication-progress.js');
    const { prepareOwnedPublicationReceivedResult } = await import('./publication-finalization.js');
    const { preparePublicationReceivedSettlement } = await import('./publication-settlement.js');
    const { cut: selected, prefix } = await readDeliveryPublicationClosure(driver, reads, runId);
    const entry = prefix.forward.at(-1), workspace = prefix.authorization?.workspace;
    if (!entry?.pendingReceivedHandoff || !workspace || workspace.kind !== 'live' ||
        selected.run.status !== 'queued' || selected.run.nextStep !== 'delivery' || selected.run.activeWorkerLaunchId ||
        selected.workerLaunches.length || prefix.abortResults.length)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication has no complete original read-only received handoff');
    const roots = await holdPublicationRoots(workspace.canonicalRootPath, signal);
    const task: DeliveryPublicationReceivedTask = Object.freeze({ [publicationReceivedTaskBrand]: true as const });
    publicationReceivedTask = task;
    const assertOwned = () => {
      if (publicationReceivedTask !== task || !pending || closed || isClosing() || cleanupFailure !== undefined ||
          publicationProjectionAbort !== abort || publicationRoots !== roots)
        throw new KernelStorageError('LEASE_FENCED', 'publication received result lost its original read-only task');
      signal.throwIfAborted();
    };
    publicationReceivedTasks.set(task, { driver, artifacts, owner, execution, assertOwned,
      resources(connection = driver) {
        assertOwned(); assertActiveStateOwner(connection, owner);
        roots.workspaceRoot.assertHeld(); roots.controlledHome.assertHeld();
        return Object.freeze({ runId, expectedRunRevision: selected.run.revision, ...roots, signal });
      } });
    publicationPhase('publication_received_proof');
    const receivedResult = await prepareOwnedPublicationReceivedResult(driver, artifacts, owner, execution, task);
    const settlement = await preparePublicationReceivedSettlement(driver, artifacts, owner, { execution, receivedResult });
    settleReceivedPublication = async expected => {
      publicationPhase('publication_received_settle');
      return (await settlement.settle({ expectedRunRevision: expected })).run;
    };
    return settleReceivedPublication(readRun(driver, runId).revision);
  }
  function ownOperation(work: Promise<Run>, abort: AbortController, retainWorker = false): Promise<Run> {
    let operationFailure: { error: unknown } | undefined;
    let retainedCompletion = false;
    const operation = work.catch(async error => {
      operationFailure = { error };
      if (receivedCompletion?.kind === 'publication_received') {
        // A durable handoff already proves the original M/arenas retired. No
        // new preactivation recovery or physical operation can be inferred
        // from a cancelled/failed read-only projection.
        if (error instanceof ResourceRetirementError) cleanupFailure ??= error;
        if (!closed && !isClosing() && cleanupFailure === undefined &&
            (isJoinedCasPublicationFailure(error) || isRolledBackSqliteTransactionFailure(driver, error) ||
              isPublicationStopRevisionConflict(receivedCompletion.kind, error, readRun(driver, runId).stopIntentRef))) {
          // SQL Stop presence permits retaining this known readonly owner,
          // never accepting the Stop or granting an effect. The same fixed
          // adapter must still fully validate the new original Stop graph.
          receivedCompletion.failure = error; retainedCompletion = true;
        }
        throw error;
      }
      if (receivedCompletion && cleanupFailure === undefined && receivedCompletion.worker === worker && receivedCompletion.activeWorker === activeWorker &&
          (isJoinedCasPublicationFailure(error) || isRolledBackSqliteTransactionFailure(driver, error) ||
            isPublicationStopRevisionConflict(receivedCompletion.kind, error, readRun(driver, runId).stopIntentRef))) {
        // A known result is not UNKNOWN. Keep its exact physical owner and
        // unfinished immutable publications after positively joined I/O failure
        // or an intervening Stop. The same original completion must reselect
        // and validate that Stop, including during shutdown; it may not be
        // replaced by probe_cancelled or a deadline observation.
        receivedCompletion.failure = error;
        retainedCompletion = true;
        throw error;
      }
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
      try { if (!retainedCompletion && (!retainWorker || operationFailure)) await retireWorkerResources(); }
      catch (failure) {
        if (operationFailure && operationFailure.error !== failure) {
          cleanupFailure = new ResourceRetirementError('Run execution failed and its resources did not retire',
            new AggregateError([operationFailure.error, failure], 'execution and retirement failures'));
          throw cleanupFailure;
        }
        throw failure;
      } finally {
        if (!retainedCompletion) {
          receivedCompletion = undefined;
          publicationTask = undefined;
          noOpTask = undefined;
          publicationMaintenanceTask = undefined;
          publicationReceivedTask = undefined;
          if (!publicationProbe || readRun(driver, runId).waitingOnRef !== publicationProbe.run.waitingOnRef)
            publicationReconciliationTask = undefined;
          publicationProjectionAbort = undefined;
          settleReceivedPublication = undefined;
          if (closingCompletion?.operation === operation || closingCompletion?.completion !== undefined) closingCompletion = undefined;
          operationPhase = undefined;
        }
        pending = undefined; if (operationAbort === abort) operationAbort = undefined;
      }
    });
    pending = operation;
    return operation;
  }
  function resumeOwnedCompletion(abort: AbortController): Promise<Run> {
    const original = receivedCompletion;
    if (!original) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run execution has no original completion to resume');
    // A publication may still own its original unarmed birth after joined CAS
    // failure. Its first productive assertion must see the registered pending
    // task, exactly as on initial dispatch, not a special relaxed release gate.
    const publication = original.kind === 'publication' || original.kind === 'publication_maintenance' ||
      original.kind === 'publication_received' || original.kind === 'publication_reconciliation';
    const work = publication ? Promise.resolve().then(() => original.finish()) : original.finish();
    return ownOperation(work, abort, publication);
  }
  async function closeProbe(input: { runId: string; expectedRunRevision: number }, shutdown = false): Promise<Run> {
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
    if (!shutdown && sampleCanonicalNow() < deadline) {
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker inspection deadline has not elapsed');
    }
    if (retained.closure) return retained.closure;
    const closingProbe = (async () => {
      const receipt = await retained.task.cancelAndJoin();
      // A matching completion may have won before cancellation. Shutdown can
      // then release normally; a public stale-revision closure cannot.
      let current = readRun(driver, runId);
      if (current.waitingOnRef !== retained.run.waitingOnRef) {
        if (shutdown) return current;
        throw new KernelStorageError('REVISION_CONFLICT', 'worker inspection completed before cancellation');
      }
      // An earlier uncertain retirement still owns this wait and StateOwner.
      // A later joined task cannot erase that uncertainty by closing its nonce.
      if (cleanupFailure !== undefined) throw cleanupFailure;
      // A real shutdown closes this same cancelled-and-joined nonce, not its
      // unelapsed deadline. The reducer persists the distinct closure before
      // this original receipt/owner may be released; failures retain both.
      const result = await closeWorkerRecoveryProbe(driver, artifacts, owner,
        { runId, expectedRunRevision: shutdown ? current.revision : input.expectedRunRevision }, receipt, shutdown ? 'shutdown' : 'deadline');
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
  async function closePublicationProbe(expectedRunRevision: number, kind: 'shutdown' | 'deadline'): Promise<Run> {
    if (receivedCompletion)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication closure must first persist its actual received result');
    const retained = publicationProbe;
    if (!retained) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication closure has no original registered probe');
    const current = readRun(driver, runId);
    if (current.revision !== expectedRunRevision)
      throw new KernelStorageError('REVISION_CONFLICT', 'publication closure Run revision changed');
    if (current.waitingOnRef !== retained.run.waitingOnRef) return current;
    if (retained.closure) return retained.closure;
    const closingProbe = (async () => {
      const receipt = await retained.task.cancelAndJoin();
      const current = readRun(driver, runId);
      // A genuinely received completion wins over cancellation of its probe.
      if (current.waitingOnRef !== retained.run.waitingOnRef) return current;
      const { closePublicationReconciliationProbe } = await import('./publication-reconciliation.js');
      const result = await closePublicationReconciliationProbe(driver, artifacts, owner, { runId,
        expectedRunRevision: current.revision, execution, task: retained.rootTask, closure: { kind, receipt } });
      if (publicationProbe === retained) publicationProbe = undefined;
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

  function runPublicationReconciliation(value: { expectedRunRevision: number },
    mutation?: { request: RunReconcileRequestV1; identity: AuthenticatedControlIdentity },
    onEnqueued?: (result: { run: Run; response: Extract<InstalledControlResponseV1, { ok: true }> }) => void): Promise<Run> {
    if (continuation.operation !== 'delivery')
      throw new KernelStorageError('INVALID_REQUEST', 'publication reconciliation requires its original Delivery execution');
    const expectedRunRevision = revision(value, true);
    const abort = new AbortController(); operationAbort = abort;
    if (receivedCompletion) {
      if (mutation || receivedCompletion.kind !== 'publication_reconciliation')
        throw new KernelStorageError('REVISION_CONFLICT', 'publication inspection cannot replace an original pending result');
      return resumeOwnedCompletion(abort);
    }
    operationPhase = 'preparing';
    const signal = abort.signal, reads = artifacts.withReadSignal(signal);
    const work = Promise.resolve().then(async () => {
      const reconciliation = await import('./publication-reconciliation.js');
      const retained = publicationProbe;
      if (retained && readRun(driver, runId).waitingOnRef === retained.run.waitingOnRef) {
        if (mutation) throw new KernelStorageError('INVALID_REQUEST', 'publication probe is already in flight');
        const state = retained.wait.probeState;
        if ((state.phase === 'automatic_in_flight' || state.phase === 'user_in_flight') && sampleCanonicalNow() >= state.dispatch.probeDeadlineAt)
          return closePublicationProbe(readRun(driver, runId).revision, 'deadline');
        return readRun(driver, runId);
      }
      if (retained) publicationProbe = undefined;
      let selected = await reconciliation.readPublicationReconciliation(driver, reads, runId);
      if (selected && selected.run.revision !== expectedRunRevision)
        throw new KernelStorageError('REVISION_CONFLICT', 'publication inspection initial cut changed');
      if (selected && !mutation) {
        const state = selected.wait.probeState;
        if (state.phase === 'automatic_exhausted' || state.phase === 'automatic_pending' && sampleCanonicalNow() < state.nextProbeAt)
          return selected.run;
      }
      let cut = selected?.cut ?? await readRecoveryClosure(driver, reads, runId);
      let task = await openPublicationReconciliationTask(cut, expectedRunRevision, signal);
      if (!selected) {
        const { readPublicationPrefix } = await import('./delivery-publication-progress.js');
        const prefix = await readPublicationPrefix(driver, reads, cut);
        const initial = [...prefix.entries.values()].filter(entry => entry.sequence === 'abort' && entry.claim &&
          !entry.result && !entry.pendingReceivedHandoff && entry.history.length === 2 && entry.history.at(-1)!.phase === 'dispatch_claimed');
        if (initial.length === 1) {
          // This claim has no live worker to put into a fictitious death wait.
          // Its genuine readonly task proves the already-closed M, exact old
          // maintenance claim/Stop/grant and actual original-owner death.
          const { prepareOwnedPublicationMaintenanceAmbiguity } = await import('./publication-invocation.js');
          const { preparePublicationInitialAmbiguitySettlement } = await import('./publication-settlement.js');
          const ambiguity = await prepareOwnedPublicationMaintenanceAmbiguity(driver, artifacts, owner, execution, task);
          const settlement = await preparePublicationInitialAmbiguitySettlement(driver, artifacts, owner, ambiguity);
          await settlement.settle({ expectedRunRevision: cut.run.revision });
          cut = await readRecoveryClosure(driver, reads, runId);
          task = await openPublicationReconciliationTask(cut, cut.run.revision, signal);
        }
        selected = await reconciliation.preparePublicationReconciliation(driver, artifacts, owner,
          { runId, expectedRunRevision: cut.run.revision, execution, task });
      }
      const priorState = selected.wait.probeState;
      if ((priorState.phase === 'automatic_in_flight' || priorState.phase === 'user_in_flight') &&
          priorState.dispatch.owningSupervisorInstanceId !== owner.supervisorInstanceId) {
        if (mutation) throw new KernelStorageError('INVALID_REQUEST', 'a predecessor publication probe must first close');
        return reconciliation.closePublicationReconciliationProbe(driver, artifacts, owner, { runId,
          expectedRunRevision: selected.run.revision, execution, task, closure: { kind: 'deadline' } });
      }
      const { startPublicationReconciliationTask } = await import('./publication-reconciliation-task.js');
      const dispatched = await reconciliation.beginPublicationReconciliationProbe(driver, artifacts, owner,
        { runId, expectedRunRevision: selected.run.revision, execution, task, ...(mutation ? { mutation } : {}) });
      if (dispatched.replayed) {
        if (!dispatched.response) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication enqueue replay lost its response');
        onEnqueued?.({ run: dispatched.run, response: dispatched.response }); return readRun(driver, runId);
      }
      // Do not throw for cancellation in this commit-to-registration gap.
      // Register the actual original queued operation first, so shutdown can
      // attest its real cancelled-before-I/O join rather than invent a task.
      let producer: { cancelAndJoin(): Promise<void> } | undefined;
      let probeTask: PublicationReconciliationTask;
      try { probeTask = startPublicationReconciliationTask({ driver, artifacts, owner, execution, task,
        run: dispatched.run, wait: dispatched.wait }, async probeSignal => {
        const cancelRead = () => abort.abort(probeSignal.reason);
        probeSignal.addEventListener('abort', cancelRead, { once: true });
        if (probeSignal.aborted) cancelRead();
        try {
          const publication = await import('./publication-invocation.js');
          const actual = await publication.prepareOwnedPublicationReconciliation(driver, artifacts, owner, execution, task);
          producer = actual;
          if (probeSignal.aborted) void actual.cancelAndJoin().catch(() => {});
          const finish = async () => {
            const completed = publication.classifyOwnedPublicationReconciliationCompletion(driver, artifacts, owner, execution, await actual.finish());
            if (completed.kind === 'late_audit') {
              const writer = await reconciliation.preparePublicationLateObservation(driver, artifacts, owner,
                { execution, lateObservation: completed.lateObservation });
              // This appends audit only. The owning probe is joined/closed
              // separately, with its original nonce and original deadline.
              return writer.commit({ expectedRunRevision: readRun(driver, runId).revision });
            }
            const token = completed.result;
            const result = await publication.readOwnedPublicationReconciliationResult(driver, artifacts, owner, execution, token);
            if (result.disposition === 'received' && result.isLastForwardPath) {
              const { handoffOwnedReconciledPublicationResult } = await import('./publication-finalization.js');
              return handoffOwnedReconciledPublicationResult(driver, artifacts, owner, execution, token);
            }
            const { preparePublicationReconciliationSettlement } = await import('./publication-settlement.js');
            const settlement = await preparePublicationReconciliationSettlement(driver, artifacts, owner,
              { execution, recoveryResult: token });
            return (await settlement.settle({ expectedRunRevision: readRun(driver, runId).revision })).run;
          };
          // Preserve this actual producer before awaiting its fixed result or
          // durable writes. Its genuine private state, not a caught error,
          // distinguishes a cancelled pre-result read from a received outcome.
          operationPhase = 'received';
          const completion: ReceivedCompletion = { kind: 'publication_reconciliation', finish };
          receivedCompletion = completion;
          try { return await finish(); }
          catch (error) {
            if (!actual.hasReceivedResult() && receivedCompletion === completion) {
              receivedCompletion = undefined; operationPhase = 'preparing';
            }
            throw error;
          }
        } finally { probeSignal.removeEventListener('abort', cancelRead); }
      }, async () => { await producer?.cancelAndJoin(); }); }
      catch (cause) {
        throw cleanupFailure = new ResourceRetirementError('committed publication probe lost its original task registration', cause);
      }
      publicationProbe = { run: dispatched.run, wait: dispatched.wait, rootTask: task, task: probeTask };
      if (mutation) {
        if (!dispatched.response) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication enqueue did not retain its response');
        onEnqueued?.({ run: dispatched.run, response: dispatched.response });
      }
      if (closed || isClosing()) void probeTask.cancelAndJoin().catch(() => {});
      const state = dispatched.wait.probeState;
      if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight')
        throw new KernelStorageError('RECOVERY_REQUIRED', 'publication producer has no persisted deadline');
      const timer = setTimeout(() => { void probeTask.cancelAndJoin().catch(() => {}); },
        Math.max(0, Date.parse(state.dispatch.probeDeadlineAt) - Date.now()));
      try { return await probeTask.work; }
      catch (error) {
        if (!receivedCompletion && !closed && !isClosing() && sampleCanonicalNow() >= state.dispatch.probeDeadlineAt &&
            readRun(driver, runId).waitingOnRef === dispatched.run.waitingOnRef)
          return closePublicationProbe(readRun(driver, runId).revision, 'deadline');
        throw error;
      } finally {
        clearTimeout(timer);
        if (publicationProbe?.task === probeTask && readRun(driver, runId).waitingOnRef !== dispatched.run.waitingOnRef) {
          publicationProbe = undefined;
        }
      }
    });
    return ownOperation(work, abort, true);
  }
  const execution: RunExecution = Object.freeze({
    hasPendingOperation: () => pending !== undefined,
    reconcilePublication: value => runPublicationReconciliation(value),
    enqueuePublicationReconciliation: input => {
      const request = immutableSnapshot(input.request);
      if (publicationEnqueue?.requestId === request.requestId && publicationEnqueue.principalId === input.identity.principalId) {
        if (publicationEnqueue.requestDigest !== request.requestDigest)
          return Promise.reject(new KernelStorageError('REQUEST_ID_CONFLICT', 'publication probe requestId was reused'));
        return publicationEnqueue.result;
      }
      const result: ReturnType<RunExecution['enqueuePublicationReconciliation']> = new Promise((resolve, reject) => {
        try {
          const completion = runPublicationReconciliation({ expectedRunRevision: request.expectedRevision },
            { request, identity: input.identity }, result => resolve({ ...result, completion }));
          void completion.catch(reject);
        } catch (error) { reject(error); }
      });
      const flight = { requestId: request.requestId, requestDigest: request.requestDigest, principalId: input.identity.principalId, result };
      publicationEnqueue = flight;
      const clear = () => { if (publicationEnqueue === flight) publicationEnqueue = undefined; };
      void result.then(clear, clear);
      return result;
    },
    hasPendingCompletion: error => receivedCompletion !== undefined && (error === undefined || receivedCompletion.failure === error),
    resumeCurrentCompletion: async value => {
      revision(value, true);
      if (!receivedCompletion) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run execution has no original completion to resume');
      const abort = new AbortController(); operationAbort = abort;
      return resumeOwnedCompletion(abort);
    },
    requestStop: () => {
      const current = readRun(driver, runId);
      assertActiveStateOwner(driver, owner);
      if (!current.stopIntentRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'productive revocation requires the committed StopIntent');
      revokePublications();
      if (stopJoin) return stopJoin;
      // Inspections are authority reducing and retain their own original join.
      // A stop must not cancel the very proof needed to close that wait.
      if (probe && current.status === 'waiting' && current.waitingOnRef === probe.run.waitingOnRef) return Promise.resolve();
      if (continuation.operation === 'delivery' && publicationReconciliationTask &&
          current.status === 'waiting' && current.waitingReason === 'reconciliation') return Promise.resolve();
      if (operationPhase !== 'claimed' && operationPhase !== 'received') operationAbort?.abort();
      // close enters irreversible native channel revocation synchronously,
      // before the control request can acknowledge its durable intent.
      return revokeOriginalWorker();
    },
    renewCurrentWorkerLease: () => {
      // An operation in flight owns its current lease. Maintenance cannot
      // race its native activation, revocation or Checkpoint transition.
      if (closed || isClosing() || pending && !(verifierReleased && operationPhase === 'claimed') || receivedCompletion ||
          !activeWorker || !worker || !generation || !controller || !reservation) return 'inactive';
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
      requireAgent();
      assertCurrentWorker(value, 'agent');
    },
    assertCurrentDeliveryWorker: value => {
      if (continuation.operation !== 'delivery') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication requires a Delivery Run execution');
      assertCurrentWorker(value, 'delivery');
    },
    activateCurrentWorker: async value => {
      const expectedRunRevision = revision(value);
      const abort = new AbortController();
      operationAbort = abort;
      const signal = abort.signal;
      const reads = artifacts.withReadSignal(signal);
      const work = (async () => {
        signal.throwIfAborted();
        const selected = await readRecoveryClosure(driver, reads, runId);
        signal.throwIfAborted();
        if (selected.run.revision !== expectedRunRevision || !selected.run.frontierRef)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'worker activation requires its current Run frontier');
        const frontier = await reads.readCanonical<import('../kernel/types.js').RunFrontier>(selected.run.frontierRef);
        if (continuation.operation === 'agent') {
          if (selected.run.nextStep !== 'agent' || frontier.kind !== 'agent' || !['model_turn', 'context_compaction'].includes(frontier.phase))
            throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model worker activation requires a validated model frontier');
        } else if (selected.run.nextStep !== 'delivery' || frontier.kind !== 'delivery' || frontier.phase !== 'publish')
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery worker activation requires its exact publication frontier');
        signal.throwIfAborted();
        const activated = await activateWorker(selected, signal);
        return activated.activated.run;
      })();
      return ownOperation(work, abort, true);
    },
    executeCurrentNoOpDelivery: async value => {
      if (continuation.operation !== 'delivery') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'no-op projection requires a Delivery Run execution');
      const expectedRunRevision = revision(value);
      const abort = new AbortController(); operationAbort = abort;
      const signal = abort.signal;
      operationPhase = 'preparing';
      const work = Promise.resolve().then(async () => {
        signal.throwIfAborted();
        const reads = artifacts.withReadSignal(signal);
        const selected = await readRecoveryClosure(driver, reads, runId);
        if (selected.run.revision !== expectedRunRevision || selected.run.nextStep !== 'verify' ||
            selected.run.status !== 'queued' || selected.run.stopIntentRef || selected.run.cancelRequested ||
            selected.run.activeWorkerLaunchId !== undefined || activeWorker || worker || generation || controller || reservation || ownedLaunchId !== undefined)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'no-op delivery requires its exact worker-free verification cut');
        const { readDeliveryRunAdmission } = await import('./reducers/delivery-admission.js');
        const admission = await readDeliveryRunAdmission(driver, reads, runId, { signal });
        requireEqual(admission.run, selected.run, 'no-op original admission cut');
        const workspace = decodeWorkspaceIdentity(await reads.readCanonical(admission.target.workspaceIdentityRef));
        if (workspace.kind !== 'live' || workspace.identityDigest !== admission.target.workspaceIdentityDigest)
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'no-op delivery lost its original live workspace');
        const roots = await holdPublicationRoots(workspace.canonicalRootPath, signal);
        const task: DeliveryNoOpTask = Object.freeze({ [noOpTaskBrand]: true as const });
        noOpTask = task;
        const assertOwned = () => {
          if (noOpTask !== task || !pending || closed || isClosing() || cleanupFailure !== undefined)
            throw new KernelStorageError('LEASE_FENCED', 'no-op projection lost its original in-flight execution task');
          signal.throwIfAborted();
        };
        noOpTasks.set(task, { driver, owner, execution, artifacts, assertOwned,
          resources() {
            assertOwned(); assertActiveStateOwner(driver, owner);
            if (publicationRoots !== roots) throw new KernelStorageError('RECOVERY_REQUIRED', 'no-op projection lost its original held roots');
            roots.workspaceRoot.assertHeld(); roots.controlledHome.assertHeld();
            return Object.freeze({ runId, expectedRunRevision, ...roots, signal });
          } });
        const { completeOwnedNoOpDelivery } = await import('./delivery-noop-finalization.js');
        return completeOwnedNoOpDelivery(driver, artifacts, owner, execution, task);
      });
      return ownOperation(work, abort);
    },
    executeCurrentPublicationMaintenance: async value => {
      if (continuation.operation !== 'delivery') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication maintenance requires a Delivery Run execution');
      const expectedRunRevision = revision(value, true);
      if (receivedCompletion && receivedCompletion.kind !== 'publication_maintenance')
        throw new KernelStorageError('REVISION_CONFLICT', 'maintenance cannot replace another original completion');
      const abort = new AbortController(); operationAbort = abort;
      if (receivedCompletion) return resumeOwnedCompletion(abort);
      const signal = abort.signal;
      operationPhase = 'preparing';
      const work = Promise.resolve().then(async () => {
        signal.throwIfAborted();
        const reads = artifacts.withReadSignal(signal);
        const selected = await readRecoveryClosure(driver, reads, runId);
        const task = await openPublicationMaintenanceTask(selected, expectedRunRevision, signal);
        const roots = assertDeliveryPublicationMaintenanceExecution(driver, owner, execution, task, artifacts);
        const publication = await import('./publication-invocation.js');
        const prepared = await publication.preparePublicationMaintenance(driver, artifacts, owner,
          { execution, task, workspaceRoot: roots.workspaceRoot, expectedRunRevision, signal });
        if (prepared.kind === 'not_created') return prepared.run;
        const original = prepared.publicationOwner;
        publicationOwners.add(original);
        if (closed || isClosing() || signal.aborted) original.revoke();
        // Register the original completion even when Stop won during prepare.
        // Its claim gate remains revoked; the same owner's catch below must
        // close the preparation rather than losing it to generic cleanup.
        const originalWorker = worker, originalActive = activeWorker;
        let claimed = false;
        receivedCompletion = { kind: 'publication_maintenance', worker: originalWorker, activeWorker: originalActive,
          finish: async () => {
            if (worker !== originalWorker || activeWorker !== originalActive)
              throw new KernelStorageError('RECOVERY_REQUIRED', 'publication maintenance lost its original execution resources');
            if (!claimed) {
              try { await publication.claimPublicationInvocation(driver, owner, original); }
              catch (error) {
                if (!(error instanceof KernelStorageError && error.code === 'LEASE_FENCED') &&
                    !(signal.aborted && error === signal.reason)) throw error;
                const status = publication.readOwnedPublicationDispatchState(driver, owner, execution, original);
                if (status.phase === 'prepared') return publication.retirePublicationPreparation(driver, owner, execution, original);
                if (status.armed) throw error;
                original.revoke();
              }
              claimed = true;
            }
            operationPhase = 'claimed';
            await publication.advancePublicationPath(driver, owner, execution, original);
            operationPhase = 'received';
            const { preparePublicationSettlement } = await import('./publication-settlement.js');
            const settlement = await preparePublicationSettlement(driver, artifacts, owner, { execution, publicationOwner: original });
            return (await settlement.settle({ expectedRunRevision: readRun(driver, runId).revision })).run;
          } };
        if (closingCompletion && closingCompletion.worker === originalWorker && closingCompletion.activeWorker === originalActive)
          closingCompletion.completion = receivedCompletion;
        return receivedCompletion.finish();
      });
      return ownOperation(work, abort, true);
    },
    executeCurrentPublication: async value => {
      if (continuation.operation !== 'delivery') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication requires a Delivery Run execution');
      const expectedRunRevision = revision(value, true);
      if (receivedCompletion && receivedCompletion.kind !== 'publication' && receivedCompletion.kind !== 'publication_received')
        throw new KernelStorageError('REVISION_CONFLICT', 'another original result cannot become publication');
      const abort = new AbortController(); operationAbort = abort;
      if (receivedCompletion) return resumeOwnedCompletion(abort);
      const signal = abort.signal;
      const reads = artifacts.withReadSignal(signal);
      operationPhase = 'preparing';
      // Start only after ownOperation registers the pending task. In particular
      // no native birth, request preparation or await escapes that ownership.
      const work = Promise.resolve().then(async () => {
        signal.throwIfAborted();
        const publication = await import('./publication-invocation.js');
        const { preparePublicationSettlement } = await import('./publication-settlement.js');
        const { readPublicationPrefix } = await import('./delivery-publication-progress.js');
        publicationPhase('publication_select');
        const { cut: selected, prefix } = await readDeliveryPublicationClosure(driver, reads, runId);
        signal.throwIfAborted();
        if (prefix.forward.at(-1)?.pendingReceivedHandoff) {
          if (selected.run.revision !== expectedRunRevision)
            throw new KernelStorageError('REVISION_CONFLICT', 'publication received handoff revision changed');
          // Retained evidence is accepted only by the complete typed reader.
          // This branch is before activateWorker and has no release capability.
          operationPhase = 'received';
          receivedCompletion = { kind: 'publication_received', finish: finishReceivedPublication };
          return receivedCompletion.finish();
        }
        const authorization = prefix.authorization;
        const queued = selected.run.status === 'queued' && selected.run.activeWorkerLaunchId === undefined;
        const retained = selected.run.status === 'running' && activeWorker !== undefined && worker !== undefined && generation !== undefined &&
          selected.run.activeWorkerLaunchId === ownedLaunchId;
        if (selected.run.revision !== expectedRunRevision || (!queued && !retained) || selected.run.nextStep !== 'delivery' ||
            selected.run.cancelRequested || selected.run.stopIntentRef || sampleCanonicalNow() >= selected.run.deadlineAt ||
            !authorization?.grant || authorization.workspace.kind !== 'live' || prefix.abortResults.length ||
            prefix.forward.some(entry => entry.result?.item.outcome !== 'completed'))
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication requires its exact unstopped approved forward prefix');
        const operationIndex = prefix.forward.length;
        if (!authorization.context.plan.forwardOperations[operationIndex])
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'publication has no remaining approved forward operation');
        requireEqual(await reads.readCanonical(selected.run.frontierRef!), { ...authorization.frontier,
          phase: 'publish', nextPathOperationIndex: operationIndex }, 'publication execution exact current frontier');
        if (queued) publicationPhase('publication_worker_activate');
        const current = queued ? await activateWorker(selected, signal) : activeWorker!;
        if (!worker || !generation || !controller || !reservation || ownedLaunchId !== current.activated.launch.launchId)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'publication lost its original physical worker');
        const currentWorker = worker;
        const identity: RunExecutionWorkerIdentity = Object.freeze({ runId, leaseEpoch: current.activated.run.leaseEpoch,
          launchId: current.activated.launch.launchId, generationRef: current.authority.generationRef,
          workerIdentityDigest: current.activated.launch.workerIdentityDigest! });
        const task: DeliveryPublicationTask = Object.freeze({ [publicationTaskBrand]: true as const });
        publicationTask = task;
        publicationPhase('publication_roots_open');
        const roots = await holdPublicationRoots(authorization.workspace.canonicalRootPath, signal);
        const retire = publicationCheckpointRetirement(current, authorization.context.planRef);
        publicationTasks.set(task, { driver, owner, execution, worker: identity,
          assertCurrent: (connection = driver) => assertCurrentWorker(identity, 'delivery', task, connection),
          resources() {
            if (activeWorker !== current || worker !== currentWorker || publicationRoots !== roots ||
                ownedLaunchId !== identity.launchId || cleanupFailure !== undefined)
              throw new KernelStorageError('RECOVERY_REQUIRED', 'publication retirement lost its original execution resources');
            assertActiveStateOwner(driver, owner); roots.workspaceRoot.assertHeld(); roots.controlledHome.assertHeld();
            return Object.freeze({ ...roots, publicationOwners: Object.freeze([...publicationOwners]), signal, retire,
              reobserveRetirement });
          } });
        assertCurrentWorker(identity, 'delivery', task);
        publicationPhase('publication_prepare');
        const original = await publication.preparePublicationInvocation(driver, artifacts, owner, {
          execution, task, worker: identity, workspaceRoot: roots.workspaceRoot,
          expectedRunRevision: readRun(driver, runId).revision, signal }, publicationPhase);
        publicationOwners.add(original);
        // The preparation can finish after Stop. Register its original owner
        // before inspecting the signal, so all close paths retain its join.
        if (closed || isClosing() || signal.aborted || readRun(driver, runId).stopIntentRef) original.revoke();
        // Do not throw before registering the original completion: a revoked
        // claim must drain this exact preparation, never only close its FDs.
        let claimed = false;
        // Physical release and its CAS publications are one original producer.
        // Joined I/O/rolled-back SQL errors preserve this exact owner, including
        // commitAttempted, rather than opening or dispatching another arena.
        receivedCompletion = { kind: 'publication', worker: currentWorker, activeWorker: current, finish: async () => {
          publicationPhase('publication_dispatch');
          if (activeWorker !== current || worker !== currentWorker || ownedLaunchId !== identity.launchId)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'publication completion lost its original worker');
          if (!claimed) {
            try { await publication.claimPublicationInvocation(driver, owner, original); }
            catch (error) {
              // Stop/expiry can win after the permanent SQL claim but before
              // the real native arm. Only this issuer's unarmed object may
              // then enter no-effect retirement; never infer an arm from SQL.
              if (!(error instanceof KernelStorageError && error.code === 'LEASE_FENCED') &&
                  !(signal.aborted && error === signal.reason)) throw error;
              const status = publication.readOwnedPublicationDispatchState(driver, owner, execution, original);
              if (status.phase === 'prepared') return publication.retirePublicationPreparation(driver, owner, execution, original);
              if (status.armed) throw error;
              original.revoke();
            }
            claimed = true;
          }
          operationPhase = 'claimed';
          await publication.advancePublicationPath(driver, owner, execution, original);
          operationPhase = 'received';
          publicationPhase('publication_settlement');
          const completed = publication.readOwnedPublicationCompletion(driver, owner, execution, original, driver);
          if (completed.disposition === 'received' && completed.isLastForwardPath) {
            const { handoffOwnedPublicationResult } = await import('./publication-finalization.js');
            await handoffOwnedPublicationResult(driver, artifacts, owner, execution, original);
            // Only the committed handoff permits cancellation of subsequent
            // read-only work. First join the already-retired original resources.
            receivedCompletion = { kind: 'publication_received', finish: finishReceivedPublication };
            publicationPhase('publication_received_retirement');
            await retireWorkerResources();
            return receivedCompletion.finish();
          }
          const settlement = await preparePublicationSettlement(driver, artifacts, owner, { execution, publicationOwner: original });
          const settled = await settlement.settle({ expectedRunRevision: readRun(driver, runId).revision });
          if (settled.run.status === 'succeeded' || settled.run.status === 'completed_unverified') await retireWorkerResources();
          return settled.run;
        } };
        if (closingCompletion?.worker === currentWorker && closingCompletion.activeWorker === current)
          closingCompletion.completion = receivedCompletion;
        return receivedCompletion.finish();
      });
      return ownOperation(work, abort, true);
    },
    finishCurrentFinalTurn: async value => {
      const currentAgent = requireAgent();
      const expectedRunRevision = revision(value, true);
      if (receivedCompletion && receivedCompletion.kind !== 'final_turn') throw new KernelStorageError('REVISION_CONFLICT', 'another result cannot become a final-turn completion');
      const abort = new AbortController(); operationAbort = abort;
      if (receivedCompletion) return ownOperation(receivedCompletion.finish(), abort);
      const signal = abort.signal;
      operationPhase = 'preparing';
      const work = (async () => {
        signal.throwIfAborted();
        if (!activeWorker || !worker || !generation || !controller || !reservation ||
            ownedLaunchId !== activeWorker.activated.launch.launchId) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'final turn requires its original physical worker owner');
        }
        const current = activeWorker, currentWorker = worker;
        // Fix the completed producer before the first quiescence or immutable
        // publication. This is not permission to request another model turn.
        const candidate = await currentAgent.beginFinalCandidate({ expectedRunRevision }, signal);
        signal.throwIfAborted();
        const retire = checkpointRetirement(current, candidate.checkpointId, signal);
        let proof: Awaited<ReturnType<typeof retire>> | undefined;
        operationPhase = 'received';
        receivedCompletion = { kind: 'final_turn', worker: currentWorker, activeWorker: current, finish: async () => {
          if (activeWorker !== current || worker !== currentWorker || ownedLaunchId !== current.activated.launch.launchId) {
            throw new KernelStorageError('LEASE_FENCED', 'final-turn completion lost its original physical owner');
          }
          assertActiveStateOwner(driver, owner);
          proof ??= await retire();
          for (let completion = 0; ; completion++) {
            const selected = readRun(driver, runId);
            if (selected.activeWorkerLaunchId !== ownedLaunchId || selected.leaseEpoch !== current.activated.launch.leaseEpoch) {
              throw new KernelStorageError('LEASE_FENCED', 'final turn no longer belongs to its original active worker');
            }
            try {
              return (await candidate.complete({ expectedRunRevision: selected.revision, checkpoint: proof.postEffect })).run;
            } catch (error) {
              if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT' || completion >= 7 ||
                  readRun(driver, runId).revision === selected.revision) throw error;
            }
          }
        } };
        if (closingCompletion?.worker === currentWorker && closingCompletion.activeWorker === current)
          closingCompletion.completion = receivedCompletion;
        return receivedCompletion.finish();
      })();
      return ownOperation(work, abort);
    },
    executeCurrentVerifier: async value => {
      const expectedRunRevision = revision(value, true);
      if (receivedCompletion && receivedCompletion.kind !== 'verifier')
        throw new KernelStorageError('REVISION_CONFLICT', 'another received result cannot become a verifier execution');
      const abort = new AbortController(); operationAbort = abort;
      if (receivedCompletion) return ownOperation(receivedCompletion.finish(), abort);
      const signal = abort.signal;
      const reads = artifacts.withReadSignal(signal);
      operationPhase = 'preparing';
      let preparedVerifier: Extract<Awaited<ReturnType<typeof continuation.prepareVerifier>>, { disposition: 'prepared' }> | undefined;
      let claimedVerifier: Awaited<ReturnType<typeof continuation.claimVerifier>> | undefined;
      const work = (async () => {
        signal.throwIfAborted();
        const selected = await readRecoveryClosure(driver, reads, runId);
        signal.throwIfAborted();
        const progress = await readVerifierProgress(driver, reads, selected);
        if (selected.run.revision !== expectedRunRevision || selected.run.nextStep !== 'verify' || progress.complete ||
            selected.run.cancelRequested || selected.run.stopIntentRef || sampleCanonicalNow() >= selected.run.deadlineAt)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'verifier requires its exact unstopped pending candidate');
        const queued = selected.run.status === 'queued' && !selected.run.activeWorkerLaunchId;
        const current = queued ? await activateWorker(selected, signal) : activeWorker;
        if (!current || !worker || !generation || !controller || !reservation ||
            ownedLaunchId !== current.activated.launch.launchId || readRun(driver, runId).activeWorkerLaunchId !== ownedLaunchId)
          throw new KernelStorageError('LEASE_FENCED', 'verifier cannot adopt another parent worker');
        const currentWorker = worker, run = readRun(driver, runId);
        const prepared = await continuation.prepareVerifier({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch }, signal);
        if (prepared.disposition !== 'prepared') {
          const stopped = await continuation.stopForVerifierPolicyDenial({ expectedRunRevision: prepared.run.revision });
          const checkpointId = stopCheckpointId(runId, stopped.run.stopIntentRef!);
          const proof = await retireToCheckpoint(current, checkpointId, signal);
          return (await continuation.commitTerminalStop({ expectedRunRevision: readRun(driver, runId).revision, checkpoint: proof.postEffect })).run;
        }
        preparedVerifier = prepared;
        signal.throwIfAborted();
        if (currentWorker.containment.backend.kind !== 'linux') throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier parent is not Linux');
        const dispatchId = identityHash('cliq-verifier-dispatch-v1', runId, prepared.entry.opId, String(prepared.entry.attempt), nonce());
        const sandboxLaunchSpecRef = await publishVerifierRecipe(reads, current.recipe.spec, current.processContainmentRef,
          currentWorker.containment.backend.cgroupPath, prepared, dispatchId);
        signal.throwIfAborted();
        const claimed = await continuation.claimVerifier({ expectedRunRevision: prepared.run.revision, leaseEpoch: prepared.run.leaseEpoch,
          opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId, sandboxLaunchSpecRef }, signal);
        claimedVerifier = claimed; operationPhase = 'claimed';
        const grant = await artifacts.readCanonical<import('../kernel/verifier-invocation.js').VerifierOperationGrantV1>(claimed.entry.grantRef!);
        const evidence = await artifacts.readCanonical<import('../kernel/verifier-invocation.js').VerifierPolicyChannelEvidenceV1>(grant.provenance.channelEvidenceRef);
        const live = assertLiveDispatchState(driver, owner, runId, prepared.run.revision, prepared.run.leaseEpoch, sampleCanonicalNow());
        const closure = await readVerifierLaunchClosure(artifacts, assertActiveStateOwner(driver, owner), { ...live, prepared: prepared.entry,
          request: claimed.request, target: claimed.target, grant, evidence, dispatchId, sandboxLaunchSpecRef }, bootstrap!.releaseKeys, signal);
        const invocation = await currentWorker.createVerifier(closure, { signal });
        signal.throwIfAborted();
        await claimed.release(invocation); verifierReleased = true;
        const result = await invocation.result();
        verifierReleased = false; operationPhase = 'received';
        // Register before any post-result await. Closing can revoke the
        // original producer but cannot replace its genuinely received result.
        let completion: Awaited<ReturnType<typeof continuation.beginVerifierCompletion>> | undefined;
        const retire = checkpointRetirement(current, prepared.checkpointId, signal);
        let proof: Awaited<ReturnType<typeof retire>> | undefined;
        receivedCompletion = { kind: 'verifier', worker: currentWorker, activeWorker: current, finish: async () => {
          if (activeWorker !== current || worker !== currentWorker || ownedLaunchId !== current.activated.launch.launchId)
            throw new KernelStorageError('LEASE_FENCED', 'verifier result lost its original physical producer');
          assertActiveStateOwner(driver, owner);
          let actual = readRun(driver, runId);
          if (!actual.stopIntentRef && sampleCanonicalNow() >= actual.deadlineAt)
            actual = (await continuation.expireRun({ expectedRunRevision: actual.revision })).run;
          completion ??= await continuation.beginVerifierCompletion({ expectedRunRevision: actual.revision,
            opId: prepared.entry.opId, attempt: prepared.entry.attempt, result });
          proof ??= await retire();
          return (await completion.complete({ expectedRunRevision: readRun(driver, runId).revision, checkpoint: proof.postEffect })).run;
        } };
        if (closingCompletion?.worker === currentWorker && closingCompletion.activeWorker === current) closingCompletion.completion = receivedCompletion;
        return receivedCompletion.finish();
      })().catch(async error => {
        verifierReleased = false;
        if (claimedVerifier && operationPhase !== 'received') {
          await revokeOriginalWorker();
          const history = readInvocationAttempt(driver, runId, claimedVerifier.entry.opId, claimedVerifier.entry.attempt);
          if (history.at(-1)?.phase === 'dispatch_claimed') {
            const ambiguity = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-verifier-ambiguity-v1', runId,
              opId: claimedVerifier.entry.opId, attempt: claimedVerifier.entry.attempt, dispatchId: claimedVerifier.entry.dispatchId,
              claimJournalSeq: claimedVerifier.entry.seq, requestRef: claimedVerifier.entry.requestRef,
              targetRef: claimedVerifier.entry.target, grantRef: claimedVerifier.entry.grantRef,
              reason: 'original_producer_joined_without_result' }, 'cliq-verifier-ambiguity-v1');
            await markInvocationUnknown(driver, artifacts, owner, { runId, opId: claimedVerifier.entry.opId,
              attempt: claimedVerifier.entry.attempt, expectedRunRevision: readRun(driver, runId).revision,
              evidenceRef: ambiguity.ref, evidenceDigest: ambiguity.ref });
          }
        } else if (preparedVerifier && operationPhase !== 'received') {
          await continuation.failVerifierPreparation({ expectedRunRevision: readRun(driver, runId).revision,
            opId: preparedVerifier.entry.opId, attempt: preparedVerifier.entry.attempt });
        }
        throw error;
      });
      return ownOperation(work, abort);
    },
    executeCurrentTool: async value => {
      const currentAgent = requireAgent();
      const expectedRunRevision = revision(value, true);
      if (receivedCompletion && receivedCompletion.kind !== 'tool') throw new KernelStorageError('REVISION_CONFLICT', 'another result cannot become a tool execution');
      const abort = new AbortController();
      operationAbort = abort;
      if (receivedCompletion) return ownOperation(receivedCompletion.finish(), abort);
      const signal = abort.signal;
      const reads = artifacts.withReadSignal(signal);
      operationPhase = 'preparing';
      let claimedTool: Awaited<ReturnType<typeof currentAgent.claimTool>> | undefined;
      const work = (async () => {
        signal.throwIfAborted();
        const selected = await readToolCut(driver, reads, runId, currentAgent.resolveToolInput);
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
        const projection = await currentAgent.readToolInvocation(signal);
        requireEqual(projection.run, selected.run, 'current native tool projection');
        if (projection.kind !== 'tool' || projection.execution.kind !== 'builtin' || projection.execution.adapterId !== LINUX_WORKER_RECIPE.editId) {
          throw new KernelStorageError('INVALID_REQUEST', 'this installed recipe does not support the frozen tool execution identity');
        }
        const workspaceCut = await readRecoveryClosure(driver, reads, runId);
        requireEqual(workspaceCut.run, selected.run, 'native tool workspace cut');
        const current = queued ? await activateWorker(workspaceCut, signal) : activeWorker!;
        const { recipe, processContainmentRef } = current;
        const activated = { ...current.activated, run: queued ? current.activated.run : selected.run };
        if (!worker || !generation) throw new KernelStorageError('RECOVERY_REQUIRED', 'native tool execution lost its original physical owner');
        const currentWorker = worker;
        signal.throwIfAborted();
        const prepared = await currentAgent.prepareTool({ expectedRunRevision: activated.run.revision, leaseEpoch: activated.run.leaseEpoch }, signal);
        if (prepared.disposition !== 'prepared') {
          const checkpointId = prepared.disposition === 'approval_required' ? prepared.checkpointId
            : identityHash('cliq-denied-tool-worker-checkpoint-v1', runId, prepared.run.latestCheckpointId, nonce());
          const proof = await retireToCheckpoint(current, checkpointId, signal);
          if (prepared.disposition === 'approval_required') {
            await currentAgent.waitForToolApproval({ expectedRunRevision: prepared.run.revision, waitingOnRef: prepared.waitingOnRef, checkpoint: proof.postEffect });
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
        const sandboxLaunchSpecRef = await publishEditRecipe(reads, recipe.spec, processContainmentRef, currentWorker.containment.backend.cgroupPath, prepared, dispatchId);
        // The permanent claim precedes even blocked invocation process creation.
        signal.throwIfAborted();
        const claimed = await currentAgent.claimTool({ expectedRunRevision: prepared.run.revision, leaseEpoch: activated.run.leaseEpoch,
          opId: prepared.entry.opId, attempt: prepared.entry.attempt, dispatchId, sandboxLaunchSpecRef }, signal);
        claimedTool = claimed;
        operationPhase = 'claimed';
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
        operationPhase = 'received';
        const observedAt = sampleCanonicalNow();
        // Register the original result before the first post-effect await.
        // This closure owns only that result's persistence, never a new dispatch.
        const retire = checkpointRetirement(current, toolCheckpointId(runId, prepared.entry.opId, prepared.entry.attempt), signal);
        let proof: Awaited<ReturnType<typeof retire>> | undefined;
        let diagnostic: Awaited<ReturnType<ArtifactCatalog['publishCanonical']>> | undefined;
        let observation: ToolObservationV1 | undefined;
        let observationRef: string | undefined;
        receivedCompletion = { kind: 'tool', worker: currentWorker, activeWorker: current, finish: async () => {
          if (activeWorker !== current || worker !== currentWorker || ownedLaunchId !== activated.launch.launchId) {
            throw new KernelStorageError('LEASE_FENCED', 'received tool completion lost its original physical owner');
          }
          assertActiveStateOwner(driver, owner);
          proof ??= await retire();
          const base = { schemaVersion: 1 as const, format: 'cliq-tool-observation-v1' as const, runId, opId: claimed.entry.opId,
            attempt: claimed.entry.attempt, requestRef: claimed.entry.requestRef, targetRef: claimed.entry.target,
            grantRef: claimed.entry.grantRef!, dispatchId, observedAt,
            postEffect: proof.postEffect };
          if (!observation) {
            if (result === 'ok') observation = { ...base, outcome: 'executed', content: { ok: true }, observationDigest: '' };
            else {
              diagnostic ??= await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_EXECUTION_FAILED' }, 'cliq-tool-output-diagnostic-v1');
              observation = { ...base, outcome: 'error', code: 'TOOL_EXECUTION_FAILED', diagnosticRef: diagnostic.ref, diagnosticDigest: diagnostic.ref, observationDigest: '' };
            }
            observation.observationDigest = digestOmitting(observation, 'observationDigest');
          }
          observationRef ??= (await artifacts.publishCanonical(observation, observation.format)).ref;
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
              await currentAgent.completeTool({ opId: claimed.entry.opId, attempt: claimed.entry.attempt,
                expectedRunRevision: current.revision, observationRef });
              break;
            } catch (error) {
              if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT' || completion >= 7 ||
                  readRun(driver, runId).revision === current.revision) throw error;
            }
          }
          return readRun(driver, runId);
        } };
        if (closingCompletion?.worker === currentWorker && closingCompletion.activeWorker === current) closingCompletion.completion = receivedCompletion;
        return receivedCompletion.finish();
      })().catch(async error => {
        if (claimedTool && operationPhase !== 'received') {
          // A permanent claim is possibly dispatched even when cancellation
          // wins before the blocked child/RELEASE handshake. Join the actual
          // producer, preserve uncertainty and charge once; only the separate
          // genuine private rollback closure may later resolve that unknown.
          await revokeOriginalWorker();
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
      const selected = await readRecoveryClosure(driver, preflightReads, runId);
      // A read may yield to close or another operation. Revalidate the exact
      // scope/revision before taking operation ownership or changing resources.
      revision({ expectedRunRevision });
      if (selected.run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'stop drain revision changed');
      const stopIntentRef = selected.run.stopIntentRef;
      if (!stopIntentRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop drain requires the persisted StopIntent');
      if (continuation.operation === 'delivery' && selected.journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed')) {
        const { readPublicationPrefix } = await import('./delivery-publication-progress.js');
        const prefix = await readPublicationPrefix(driver, preflightReads, selected);
        if (!prefix.authorization || prefix.forward.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
            prefix.abortResults.length !== prefix.authorization.context.plan.abortOperations.length ||
            prefix.abortResults.some(entry => !entry.result || entry.result.item.outcome === 'unknown'))
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal publication stop awaits its complete original nonambiguous cleanup prefix');
        // Refuse unsupported/unclosed cuts before taking operation ownership:
        // ownOperation's failure retirement must not authorize a missing path.
        revision({ expectedRunRevision });
        const abort = new AbortController(); operationAbort = abort;
        operationPhase = 'preparing';
        const work = Promise.resolve().then(async () => {
          const task = await openPublicationMaintenanceTask(selected, expectedRunRevision, abort.signal);
          const { prepareOwnedPublicationAbortFinalization, closeOwnedPublicationAbortFinalization } =
            await import('./publication-abort-finalization.js');
          const finalization = await prepareOwnedPublicationAbortFinalization(driver, artifacts, owner, execution, task);
          try {
            return (await continuation.commitTerminalStop({ expectedRunRevision }, undefined, finalization)).run;
          } finally { closeOwnedPublicationAbortFinalization(driver, owner, finalization); }
        });
        return ownOperation(work, abort);
      }
      // Refuse BEFORE ownOperation: its failure handler intentionally performs
      // physical recovery. An unclosed claim must not enter that lifecycle just
      // because a terminal request is unsupported. The model-death path below
      // is worker-free; it cannot authorize sealing an active worker.
      if (selected.run.activeWorkerLaunchId !== undefined) {
        const noRelease = await validateInstalledModelNoReleaseHistory(driver, preflightReads, selected);
        const stoppedVerifiers = await validateVerifierStoppedHistory(driver, preflightReads, selected);
        const stoppedPreparations = continuation.operation === 'delivery' && selected.journal.some(entry => entry.opKind === 'publish')
          ? await (await import('./delivery-publication-recovery.js')).readUnclaimedPublicationStopHistory(driver, preflightReads, selected)
          : new Set<number>();
        for (const { entry, hasClaim } of stopInvocationHistory(selected.journal).values()) {
          // Only the full original no-claim preparation closure supplies this
          // exact terminal seq. A failed phase or refunded budget alone never
          // substitutes for native retirement, and M still retires below.
          if (entry.opKind === 'publish' && !hasClaim && stoppedPreparations.has(entry.seq)) continue;
          if (!['model', 'tool', 'verifier'].includes(entry.opKind) || (!['prepared', 'completed'].includes(entry.phase) &&
              (entry.phase !== 'failed' || hasClaim && !(entry.opKind === 'model' && noRelease.has(entry.seq)) &&
                !(entry.opKind === 'verifier' && stoppedVerifiers.has(entry.seq))))) {
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
          return (await continuation.commitTerminalStop({ expectedRunRevision })).run;
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
        return (await continuation.commitTerminalStop({ expectedRunRevision, checkpoint: proof.postEffect })).run;
      })();
      return ownOperation(work, abort);
    },
    resumeCurrentRetirement: async value => {
      const expectedRunRevision = revision(value);
      const abort = new AbortController(); operationAbort = abort;
      const signal = abort.signal;
      const reads = artifacts.withReadSignal(signal);
      const work = (async () => {
        retirementPhase('history');
        let cut = await readRecoveryClosure(driver, reads, runId);
        signal.throwIfAborted();
        if (cut.run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'retirement resume revision changed');
        const eligible: Array<{ row: (typeof cut.workspaceGenerations)[number];
          quarantine: import('../kernel/types.js').WorkspaceGenerationQuarantineEvidenceV1 }> = [];
        // The recovery closure validates worker-recovery and preactivation
        // graphs. An unsupported producer must not become a successful no-op.
        for (const row of cut.workspaceGenerations) {
          if (row.phase !== 'quarantined') continue;
          signal.throwIfAborted();
          const quarantine = await reads.readCanonical<import('../kernel/types.js').WorkspaceGenerationQuarantineEvidenceV1>(row.quarantineEvidenceRef);
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
          retirementPhase('quarantine_closure');
          const closure = await readQuarantinedWorkerLaunchClosure(driver, reads, owner, { run: cut.run, launch, generation: row });
          retirementPhase('native_retirement');
          controller = await launcher.startController({ signal });
          let retirement: { workerRetirement: NativeRetainedWorkerRetirement } | { preactivationRetirement: NativePreactivationRetirement };
          if (quarantine.reason === 'worker_recovery') {
            const containment = decodeWorkerProcessContainment(await reads.readCanonical(launch.processContainmentRef!));
            const workerIdentity = decodeWorkerIdentity(await reads.readCanonical(launch.workerIdentityDigest!));
            const death = await controller.terminateRetained({ closure, containment, workerIdentity, signal });
            assertNativeContainmentDeath(death);
            retirement = { workerRetirement: await controller.closeRetained() };
          } else {
            const backend = closure.plan.backend;
            if (backend.kind !== 'linux' || !backend.nativeReservation)
              throw new KernelStorageError('RECOVERY_REQUIRED', 'preactivation generation retirement has no exact native reservation');
            reservation = owner.filesystem.openWorkerReservation(launch.launchId, launch.spawnNonceDigest, backend.nativeReservation);
            const containment = launch.processContainmentRef === undefined ? undefined
              : decodeWorkerProcessContainment(await reads.readCanonical(launch.processContainmentRef));
            const workerIdentity = launch.workerIdentityDigest === undefined ? undefined
              : decodeWorkerIdentity(await reads.readCanonical(launch.workerIdentityDigest));
            const observed = await controller.inspectPreactivation({ closure, reservation, activationNonceDigest: launch.activationNonceDigest,
              ...(containment === undefined ? {} : { containment }), ...(workerIdentity === undefined ? {} : { workerIdentity }) });
            assertNativePreactivationObservation(observed, closure);
            if ((quarantine.reason === 'launch_aborted') !== (observed.kind === 'no_spawn'))
              throw new KernelStorageError('ARTIFACT_MISMATCH', 'preactivation retirement changed its original no-spawn or created branch');
            if (observed.kind === 'created') assertNativeContainmentDeath(observed.death);
            retirement = { preactivationRetirement: await controller.closePreactivation() };
          }
          retirementPhase('workspace_observation');
          const workspaceRetirement = await observeRetainedRunWorkspace({ filesystem: owner.filesystem, artifacts: reads,
            identity: closure.generation, sourceRowVersion: quarantine.sourceRowVersion, signal });
          signal.throwIfAborted();
          const brokerQuiescence = observeInstalledBrokerQuiescence(executionStore, runId);
          retirementPhase('retirement_commit');
          await retireQuarantinedGeneration(driver, reads, owner, { runId, expectedRunRevision: cut.run.revision,
            expectedGenerationRowVersion: row.rowVersion, generationRef: row.generationRef, ...retirement, workspaceRetirement, brokerQuiescence });
          retirementPhase('resource_join');
          await retireWorkerResources();
          retirementPhase('history');
          cut = await readRecoveryClosure(driver, reads, runId);
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
        const reads = artifacts.withReadSignal(signal);
        signal.throwIfAborted();
        const cut = await readRecoveryClosure(driver, reads, runId);
        signal.throwIfAborted();
        if (!sameInspectionStopCut(run, cut.run)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'worker inspection dispatch cut changed');
        }
        const launch = cut.workerLaunches.find(row => row.launchId === wait.subject.oldWorkerLaunchId)!;
        const oldGeneration = cut.workspaceGenerations.find(row => row.generationRef === wait.subject.workspaceGenerationRef)!;
        const closure = await readRetainedWorkerLaunchClosure(reads, assertActiveStateOwner(driver, owner), { run: cut.run, launch, generation: oldGeneration });
        const containment = decodeWorkerProcessContainment(await reads.readCanonical(launch.processContainmentRef!));
        const workerIdentity = decodeWorkerIdentity(await reads.readCanonical(launch.workerIdentityDigest!));
        signal.throwIfAborted();
        controller = await launcher.startController({ signal });
        // This separate authority-reducing action terminates the retained
        // domain; the persisted inspector task itself grants no mutation.
        const death = await controller.terminateRetained({ closure, containment, workerIdentity, signal });
        assertNativeContainmentDeath(death);
        signal.throwIfAborted();
        const handoff = cut.run.nextStep === 'agent' ? await requireAgent().readModelAttempt(signal) : undefined;
        if (handoff && !sameInspectionStopCut(cut.run, handoff.run)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'worker recovery model handoff cut changed');
        }
        const unknownHandoff = handoff?.state.phase === 'unknown' && hasOnlySettledInstalledModelUnknowns(
          decodeRetainedRunAssembly(await reads.readCanonical(cut.runSpec.assemblyRef)), cut.journal);
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
        const current = await readRecoveryClosure(driver, reads, runId);
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
        const recovered = await completeWorkerRecoveryProbe(driver, reads, owner,
          { runId, expectedRunRevision: completionRun.revision }, death, signal, brokerQuiescence,
          { retire: () => controller!.closeRetained(), finish: async plan =>
            (await continuation.commitTerminalStop({ expectedRunRevision: readRun(driver, runId).revision }, plan)).run });
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
        const wait = await preflightReads.readCanonical<WorkerDeathWait>(run.waitingOnRef);
        if (wait.subject.kind !== 'worker_death') throw new KernelStorageError('INVALID_REQUEST', 'this execution scope cannot reconcile another subject');
        if (activeWorker) {
          if (wait.subject.oldWorkerLaunchId !== ownedLaunchId || !worker) {
            throw new KernelStorageError('RECOVERY_REQUIRED', 'worker recovery does not name this scope\'s retained physical worker');
          }
          const death = await observeOriginalWorkerDeath(activeWorker);
          assertNativeContainmentDeath(death);
          // The inspection below uses a fresh controller and the retained
          // original containment. Never overwrite an unjoined physical owner.
          await retireWorkerResources();
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
              signal => inspect(dispatched, persisted, signal), retireWorkerResources);
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
        try { if (!registered) await retireWorkerResources(); }
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
  if (continuation.operation === 'delivery') deliveryExecutions.set(execution, { driver, owner, runId });
  return { execution, closeWorkerRecoveryProbe: input => closeProbe(input), beginClose, close() {
    if (closing) return closing;
    const revoked = beginClose();
    const attempt = (async () => {
      const joins = await Promise.allSettled([revoked, ...(pending ? [pending.catch(() => {})] : [])]);
      const failure = joins.find(result => result.status === 'rejected');
      if (failure?.status === 'rejected') cleanupFailure ??= failure.reason;
      if (receivedCompletion?.kind === 'publication_received') {
        // Its actual receipt, M seal and arena retirement are already rooted
        // durably. A successor may only revalidate; shutdown does not re-run
        // an expensive cancelled projection or settle before that validation.
        receivedCompletion = undefined;
      } else if (receivedCompletion) {
        // Close cannot turn a received result into recovery or release its
        // image owner while its exact durable completion remains unfinished.
        const abort = new AbortController();
        operationAbort = abort;
        await resumeOwnedCompletion(abort);
      }
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
        try { await retireWorkerResources(); }
        catch (error) { cleanupFailure ??= error; }
      }
      if (publicationProbe && readRun(driver, runId).waitingOnRef === publicationProbe.run.waitingOnRef) {
        // Unlike deadline expiry, genuine shutdown cancellation may close
        // this nonce before thirty seconds only after its actual task joins.
        // A failed join/write keeps the StateOwner; it is never a fake timeout.
        await closePublicationProbe(readRun(driver, runId).revision, 'shutdown');
      }
      const run = readRun(driver, runId);
      if (probe && run.waitingOnRef === probe.run.waitingOnRef) {
        // Retain the original receipt and image owner until the actual
        // cancelled task has a durable, distinct closure for this nonce.
        await closeProbe({ runId, expectedRunRevision: run.revision }, true);
      }
      // Installation image release must not invalidate the execution's actual
      // retirement observation, and is still attempted after a failed join.
      closePublications();
      for (const root of [publicationRoots?.workspaceRoot, publicationRoots?.controlledHome]) {
        try { root?.close(); } catch (error) { cleanupFailure ??= error; }
      }
      try { await launcher.close(); }
      catch (error) { cleanupFailure ??= error; }
      if (cleanupFailure !== undefined) throw cleanupFailure;
    })();
    closing = attempt.catch(error => { closing = undefined; throw error; });
    return closing;
  } };
}
