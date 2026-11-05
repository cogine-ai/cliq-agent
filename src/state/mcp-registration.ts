// Original AdminOperation and immutable registry provenance. No Run, worker
// lease or tool budget is borrowed by registration or discovery.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { decodeAdminOperation, decodeAdminProbeClosureEvidence, decodeAdminProbePayloadCore,
  decodeMcpAdminProbeResult, decodeMcpAdminProbeTarget, decodeMcpHttpCapture,
  decodeMcpInitializeResult, decodeMcpRegistrationReceipt, decodeMcpRegistryRevision,
  decodeMcpToolsListResult, mcpRegistrySummary, type AdminOperationV1, type McpRegistryRevisionV1,
  mcpExposedToolName, mcpExposedToolDescription, type McpMutationRequestV1, type McpAdminProbeTargetV1 } from '../kernel/mcp.js';
import { decodeMcpMutationRequest, mcpMutationCoreDigest, normalizeMcpLifecycle, type AdminProbePayloadCoreV1, type McpAdminProbeResultV1,
  type AdminProbeClosureEvidenceV1, type McpRegistrationReceiptV1, type AdminProbeErrorV1, decodeAdminProbeError } from '../kernel/mcp.js';
import { decodeMcpHttpCaptureData } from '../kernel/mcp-wire.js';
import { decodeEndpointCredentialGrantBinding, decodeEndpointRegistration } from '../kernel/credential-authority.js';
import type { ToolContractManifestV1 } from '../kernel/continuation.js';
import type { ControlApplicationResponseV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { exactKeys } from '../policy/runtime-authority.js';
import type { ProcessContainment, ProcessContainmentDeathEvidenceV1, ProcessContainmentPlanV1,
  SandboxLaunchSpecV1, ProcessContainmentNoSpawnEvidenceV1 } from '../kernel/execution.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { insertArtifactMetadata } from './artifacts.js';
import { sampleCanonicalNow, advanceTimeFence } from './canonical-time.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { requireHealthyFence } from './reducers/invocation.js';
import { readControlRequest, insertControlRequest } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, readLatestStateOwner, type StateOwnerContext } from './state-owner.js';
import { decodeLocalSocketPeerObservation, decodePlatformProcessIdentity } from './decoders.js';
import { MCP_ADMIN_HELPER_ENTRY_ID, MCP_ADMIN_HELPER_RELATIVE_PATH } from './mcp-broker-native.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeAdminMcpLifecycleData, openAdminMcpInput, openRetainedAdminMcpInput, stateRootIdentityForLock, type AdminMcpInputBinding } from './native-owner.js';
import { withHeldInstalledRuntime, withInstalledWorkerRoot, type HeldInstalledRuntime, type HeldInstalledAnchor } from './installed-runtime.js';
import { retainInstalledMcpAdminRecipe } from './installed-runtime.js';
import { openInstalledLinuxWorkerLauncher, type LinuxWorkerController } from '../sandbox/linux-worker.js';
import { openInstalledMcpHttpAdminScope } from '../sandbox/mcp-http-admin-native.js';
import { retireInstalledRetainedMcpHttpAdmin, readInstalledMcpAdminCleanup } from '../sandbox/mcp-http-admin-native.js';
import type { McpAdminScopeObservation, NativeAdminCleanupObservation, InstalledMcpHttpAdminScope, InstalledMcpAdminCleanup,
  McpAdminPhysicalJoined } from '../sandbox/mcp-http-admin-native.js';
import type { HeldAdminMcpInput } from './native-owner.js';
import { readRetainedVerifierToolchain } from './guest-toolchain.js';
import { resolveInstalledMcpTransport, withInstalledMcpHttpAuthority } from './store.js';
import { loadInstalledMcpHttpBroker } from './mcp-native-binding.js';
import { driveMcpAdminProtocol } from './mcp-execution.js';
import { assertInstalledMcpAdminJoined } from './mcp-native-binding.js';
import { mcpInitializeRequestData, mcpInitializedNotificationData, mcpToolsListRequestData } from '../kernel/mcp-wire.js';
import type { AdminMcpHttpBinding, NativeMcpAdminHttpOwner } from './mcp-broker-native.js';
import type { InstalledControlResponseV1 } from '../kernel/control-wire.js';
import { decodeSandboxRootProfile } from './execution-closure.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { readMcpStdioRegistrationConsent } from './mcp-stdio-consent.js';
import { readMcpStdioLaunchRecipeData } from './mcp-stdio-launch.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { assertControlWireJson, controlWireRecord, controlWireRef } from '../kernel/control-wire-data.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { decodeMcpStdioLifecycleData, decodeMcpStdioCleanupData } from './native-owner.js';
import type { McpStdioNativeLifecycle } from './mcp-stdio-lifecycle.js';
import { decodeMcpStdioRecipeData } from './mcp-stdio-recipe.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
import { observeMcpAdminWork } from './mcp-admin-diagnostics.js';
import { readMcpStdioCapture } from './mcp-stdio-history.js';
import { publishMcpAdminDiscovery } from './mcp-admin-publication.js';
import { deriveMcpRecoveryToolContracts, readMcpRecoveryTemplates, publishMcpRequestedRecovery,
  validateMcpOriginalRequestedRecovery, mcpRequestedRecoveryFromRegistry } from './mcp-recovery-contract.js';
import { publishMcpAdminCurrentRetirement, readMcpAdminCurrentRetirementData, type McpAdminRetirementScope } from './mcp-admin-current-retirement.js';
import { prepareMcpStdioAuthorization, consumeMcpStdioAuthorization, mcpStdioAuthorizationData, assertMcpStdioAuthorizationConsumed,
  type PreparedMcpStdioAuthorization } from './mcp-stdio-authorization.js';
import { prepareMcpStdioAdminAttempt } from './mcp-stdio-admin.js';
import { publishMcpStdioLaunch } from './mcp-stdio-launch.js';
import type { AdminMcpStdioBinding } from './mcp-stdio-broker-native.js';
import { readInstalledMcpStdioAdminReady, retireInstalledRetainedMcpStdioAdmin, readInstalledMcpStdioAdminCleanup } from '../sandbox/mcp-stdio-native.js';
import type { InstalledMcpStdioAdminScope, InstalledMcpStdioAdminCleanup, McpStdioPhysicalJoined } from '../sandbox/mcp-stdio-native.js';
import { openRetainedAdminMcpStdioInput, type HeldAdminMcpStdioInput, type AdminMcpStdioInputBinding } from './native-owner.js';
import type { McpStdioNativeCleanup } from './mcp-stdio-lifecycle.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
type RegistrySource = Readonly<{ registry: McpRegistryRevisionV1; assertUnchanged(connection: SqliteConnection): void }>;
type RegistryReadContext = { sources: Map<string, Promise<RegistrySource>>; assertions: Map<string, (connection: SqliteConnection) => void> };
function registryReadContext(): RegistryReadContext { return { sources: new Map(), assertions: new Map() }; }
const MCP_ADMIN_RESOURCES = Object.freeze({ maxProcesses: 16, memoryBytes: 256 * 1024 ** 2, cpuQuotaMicrosPerSecond: 100_000,
  maxOpenFiles: 128, maxSingleFileBytes: 256 * 1024 ** 2, maxGenerationBytes: 512 * 1024 ** 2,
  maxInvocationOutputBytes: 65_536, maxIpcFrameBytes: 16 * 1024 ** 2, maxQueuedIpcBytes: 64 * 1024 ** 2 });
type AdminResource = { close(): Promise<void> };
const adminResources = new WeakMap<SqliteDriver, Set<AdminResource>>();
const adminProducers = new WeakMap<SqliteDriver, Map<string, { digest: string; task?: Promise<unknown>; resume?: () => Promise<unknown> }>>();
class McpAdminRetryPending extends Error { constructor(readonly retryAt: string) { super('original MCP Admin recovery backoff'); } }
export async function closeMcpAdminOperations(driver: SqliteDriver): Promise<void> {
  const results = await Promise.allSettled([...(adminResources.get(driver) ?? [])].map(resource => resource.close()));
  const failed = results.find(result => result.status === 'rejected');
  if (failed?.status === 'rejected') throw failed.reason instanceof ResourceRetirementError ? failed.reason
    : new ResourceRetirementError('original MCP Admin resources did not join', failed.reason);
}
/** Successor startup never adopts or renews an old Admin probe. The genuine
 * retained native input/current checker proves the original Supervisor,
 * controller and complete recorded domain dead, preserving the unchanged raw
 * birth chain plus a separate current cleanup observation. */
export async function retireRetainedMcpAdminOperations(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, signal?: AbortSignal): Promise<void> {
  const rows = driver.prepare("SELECT principal_id,method,request_id FROM admin_operations WHERE state IN ('prepared','active') ORDER BY principal_id,method,request_id,attempt LIMIT 1025")
    .all<{principal_id:string;method:string;request_id:string}>();
  if (rows.length > 1024) invalid('MCP original retained Admin inventory exceeds its bounded recovery cut');
  for (const row of rows) {
    signal?.throwIfAborted(); const operation = readMcpAdminOperation(driver, row.principal_id, row.method, row.request_id);
    if (!operation || !['prepared', 'active'].includes(operation.phase)) invalid('MCP startup original Admin attempt changed its phase');
    const target = decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, operation.targetRef));
    const originalRequest = await readOriginalAdminRequest(driver, artifacts, operation, target);
    const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, operation.plannedContainmentRef);
    if (target.resolvedTransport.kind === 'stdio') {
      const claiming = originalRequest.ownerHistory.entries.find(value => value.owner.supervisorInstanceId === operation.supervisorInstanceId);
      if (!claiming) invalid('MCP original stdio Admin owning Supervisor is absent from its retained history');
      await retireRetainedMcpStdioAdminOperation(driver, artifacts, owner, selected, anchor, operation, target,
        retainedStdioAdminInputBinding(operation, plan, claiming.process), signal);
      continue;
    }
    const binding = retainedAdminInputBinding(operation, plan);
    const current = assertActiveStateOwner(driver, owner);
    if (operation.supervisorInstanceId === current.supervisorInstanceId) invalid('MCP startup cannot replace its own original live Admin producer');
    const launcher = await observeMcpAdminWork('http', 'launcher_open', () => openInstalledLinuxWorkerLauncher(selected, anchor, { ...(signal ? {signal} : {}) }));
    let controller: LinuxWorkerController | undefined, input: ReturnType<typeof openRetainedAdminMcpInput> | undefined;
    let controllerOpening: Promise<LinuxWorkerController> | undefined;
    let cleanupTask: ReturnType<typeof retireInstalledRetainedMcpHttpAdmin> | undefined;
    const cancellation = new AbortController(), cleanupSignal = signal ? AbortSignal.any([signal, cancellation.signal]) : cancellation.signal;
    let retiring: Promise<void> | undefined;
    const resource: AdminResource = { close: () => { cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP successor checker is closing')); return retiring ??= (async () => {
      const errors: unknown[] = [];
      try { await cleanupTask; } catch (error) { errors.push(error); }
      try { await observeMcpAdminWork('http', 'controller_close', async () => { await (controller ?? await controllerOpening)?.close(); }); } catch (error) { errors.push(error); }
      try { await observeMcpAdminWork('http', 'launcher_close', () => launcher.close()); } catch (error) { errors.push(error); }
      try { input?.close(); } catch (error) { errors.push(error); }
      if (errors.length) throw errors.find(error => error instanceof ResourceRetirementError) ??
        new ResourceRetirementError('MCP original Admin successor checker did not retire', new AggregateError(errors));
    })(); } };
    let resources = adminResources.get(driver); if (!resources) adminResources.set(driver, resources = new Set()); resources.add(resource);
    let failure: unknown;
    try {
      controllerOpening = observeMcpAdminWork('http', 'controller_start', () => launcher.startController({ signal: cleanupSignal }));
      controller = await controllerOpening; cleanupSignal.throwIfAborted();
      input = openRetainedAdminMcpInput(owner.filesystem, binding);
      cleanupTask = observeMcpAdminWork('http', 'retained_cleanup', () => retireInstalledRetainedMcpHttpAdmin(selected, anchor, controller!, owner.filesystem, input!, binding,
        { supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch }, { signal: cleanupSignal }));
      const receipt = await cleanupTask;
      const closed = readInstalledMcpAdminCleanup(receipt, input);
      // This is the actual current checker, not a reconstruction of the old
      // owner's unavailable FD/socket joins. Close its owning controller too.
      await observeMcpAdminWork('http', 'controller_close', () => controller!.close());
      const retirement = await publishAdminRetirement(artifacts, owner, driver, operation, closed.lifecycleSnapshot, closed.joined.observation, closed.observation);
      readInstalledMcpAdminCleanup(receipt, input);
      await finishFailedAdminAttempt(driver, artifacts, owner, operation, retirement, { principalId: operation.principalId,
        channelIdentityRef: target.channelIdentityRef, channelIdentityDigest: target.channelIdentityDigest }, false,
        { kind: 'cleanup', receipt, input });
      input.close(); input = undefined;
    } catch (error) { failure = error; }
    finally {
      try { await resource.close(); if (failure === undefined) resources.delete(resource); }
      catch (error) { failure = error; }
    }
    if (failure !== undefined) throw failure instanceof ResourceRetirementError ? failure :
      new ResourceRetirementError('MCP original Admin birth/current cleanup remains unresolved', failure);
  }
}

async function publishMcpAdminLaunch(artifacts: ArtifactCatalog, owner: StateOwnerContext, controller: LinuxWorkerController,
  cgroupParent: string, bundle: RuntimeBundleManifest, target: McpAdminProbeTargetV1, targetRef: string,
  core: AdminProbePayloadCoreV1, coreRef: string, adminOperationId: string, controlRequestDigest: string, attempt: number, nonce: string, createdAt: string) {
  const roots = bundle.entries.filter(entry => entry.entryId === 'installed-empty-root');
  const launcher = bundle.entries.find(entry => entry.entryId === 'linux_worker_controller');
  const guestRoots = bundle.structuredArtifacts.filter(root => root.kind === 'guest_toolchain');
  if (roots.length !== 1 || roots[0]!.role !== 'sandbox_root_profile' || roots[0]!.executable || !launcher?.executable ||
      launcher.role !== 'platform_helper' || guestRoots.length !== 1) invalid('MCP Admin lacks its exact signed empty-root, guest and launcher');
  const rootProfile = decodeSandboxRootProfile(await readCanonicalArtifact(artifacts, roots[0]!.digest));
  const toolchain = await readRetainedVerifierToolchain(artifacts, { bundle, releaseKeys: artifacts.releaseTrustRoots(), guestToolchainManifestRef: guestRoots[0]!.artifactRef });
  const identity = stateRootIdentityForLock(owner.filesystem), rootImage = { schemaVersion: 1 as const, format: 'cliq-sandbox-root-image-v1' as const,
    runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest, entryId: roots[0]!.entryId,
    entryVersion: roots[0]!.version, entryDigest: roots[0]!.digest, protocol: rootProfile.protocol, filesystemKind: rootProfile.filesystemKind,
    fixedDirectories: rootProfile.fixedDirectories, ownerUid: identity.ownerUid, persistent: false as const, networkConfiguration: 'none' as const, imageDigest: '' };
  rootImage.imageDigest = digestOmitting(rootImage, 'imageDigest');
  const image = await artifacts.publishCanonical(rootImage, rootImage.format);
  const processOwner = { kind: 'admin_probe' as const, adminOperationId, attempt, principalId: target.ownerPrincipalId,
    method: target.method, originalRequestDigest: controlRequestDigest, targetRef, supervisorInstanceId: owner.supervisorInstanceId };
  const plan: ProcessContainmentPlanV1 = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner: processOwner,
    filesystemBinding: { kind: 'isolated-empty-root', rootImageRef: image.ref, rootImageDigest: rootImage.imageDigest },
    launchNonceDigest: sha256Bytes(Buffer.from(nonce)), backend: { kind: 'linux', cgroupPath: `${cgroupParent}/cliq-mcp-admin-${nonce}`,
      cgroupNameReservationDigest: canonicalSha256(['cliq-mcp-admin-cgroup-v1', adminOperationId, attempt, nonce]),
      pidNamespaceReservationId: `cliq-mcp-admin-pidns:${nonce}`, subreaperStartToken: controller.subreaperStartToken }, createdAt, planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest'); const planArtifact = await artifacts.publishCanonical(plan, plan.format);
  const profile = { schemaVersion: 1 as const, format: 'cliq-sandbox-profile-v1' as const, backend: 'linux_namespace' as const,
    allowedOwners: ['admin_probe'] as ['admin_probe'], filesystemPolicy: 'typed_launch_spec_only' as const,
    hostFilesystemReachability: 'none' as const, networkAtSpawn: 'none' as const, networkAfterRelease: 'typed_broker_only' as const,
    credentialReachability: 'typed_broker_only' as const, stateRootReachability: 'none' as const, inheritedHostEnvironment: false as const,
    resources: MCP_ADMIN_RESOURCES, profileDigest: '' };
  profile.profileDigest = digestOmitting(profile, 'profileDigest'); const profileArtifact = await artifacts.publishCanonical(profile, profile.format);
  const runtime = { runtimeBundleRef: core.runtimeBundleRef, runtimeBundleManifestDigest: core.runtimeBundleManifestDigest,
    sandboxBackend: 'linux_namespace' as const, toolchain: { kind: 'guest_toolchain' as const, guestToolchainManifestRef: toolchain.manifestRef,
      guestToolchainManifestDigest: toolchain.manifest.manifestDigest, guestImageRef: toolchain.manifest.guestImageRef,
      guestImageDigest: toolchain.manifest.guestImageDigest }, launcher: { executableId: launcher.entryId, executableDigest: launcher.digest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const environment = { schemaVersion: 1 as const, format: 'cliq-sanitized-sandbox-environment-v1' as const, controlledPath: ['/usr/bin'],
    locale: { lang: 'C', lcAll: 'C' }, home: '/scratch/home', tmpdir: '/scratch/tmp', variables: [], inheritedHostEnvironment: false as const,
    secretMaterial: 'none' as const, brokerAccessAtSpawn: 'none' as const, networkMode: 'broker_ipc_only' as const, environmentDigest: '' };
  environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
  const mounts = [{ kind: 'cas_artifact' as const, artifactRef: core.adapterExecutableDigest, artifactDigest: core.adapterExecutableDigest,
    targetPath: '/runtime/cliq-mcp-http-admin-probe.mjs', access: 'read_only' as const, purpose: 'runtime' as const },
  { kind: 'private_ephemeral' as const, privateRootId: identityHash('cliq-mcp-admin-scratch-v1', adminOperationId, attempt, nonce),
    targetPath: '/scratch', access: 'read_write' as const, purpose: 'output' as const }];
  const spec: SandboxLaunchSpecV1 & { purpose: 'admin_mcp_http_probe' } = { schemaVersion: 1, format: 'cliq-sandbox-launch-v1', owner: processOwner,
    purpose: 'admin_mcp_http_probe', runtime, executable: { kind: 'guest_toolchain', guestToolchainManifestRef: toolchain.manifestRef,
      guestToolchainManifestDigest: toolchain.manifest.manifestDigest, toolId: toolchain.manifest.node.logicalName, role: 'tool',
      executionPath: '/usr/bin/node', executableDigest: toolchain.manifest.node.digest }, processInvocation: { kind: 'admin_probe',
      purpose: 'admin_mcp_http_probe', recipe: 'cliq-admin-mcp-http-probe-v1', targetRef, targetDigest: target.targetDigest,
      probePayloadCoreRef: coreRef, argvCwdSource: 'trusted_recipe_decode_of_admin_target_and_probe_core',
      stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' } }, environment,
    filesystem: { kind: 'isolated_empty_root', rootImageRef: image.ref, rootImageDigest: rootImage.imageDigest, persistentWritableMounts: false },
    mounts, mountsDigest: canonicalSha256(mounts), sandboxProfileRef: profileArtifact.ref, sandboxProfileDigest: profile.profileDigest,
    resources: MCP_ADMIN_RESOURCES, resourcesDigest: canonicalSha256(MCP_ADMIN_RESOURCES), containmentPlanRef: planArtifact.ref,
    containmentPlanDigest: plan.planDigest, createdAt, launchSpecDigest: '', adminTargetRef: targetRef, adminTargetDigest: target.targetDigest,
    probePayloadCoreRef: coreRef };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest'); const specArtifact = await artifacts.publishCanonical(spec, spec.format);
  return { plan, planArtifact, spec, specArtifact, toolchain };
}
function retainedAdminInputBinding(operation: AdminOperationV1, plan: ProcessContainmentPlanV1): AdminMcpInputBinding {
  const nonce = plan.backend.kind === 'linux' ? plan.backend.cgroupPath.split('/').at(-1)?.match(/^cliq-mcp-admin-([0-9a-f]{64})$/u)?.[1] : undefined;
  if (!nonce) invalid('MCP original Admin plan has no exact native input nonce');
  return { adminOperationId: operation.adminOperationId, attempt: operation.attempt, principalId: operation.principalId, nonce,
    targetRef: operation.targetRef, targetDigest: operation.targetDigest, probePayloadCoreRef: operation.probePayloadCoreRef,
    probePayloadCoreDigest: operation.probePayloadCoreDigest, plannedContainmentRef: operation.plannedContainmentRef,
    plannedContainmentDigest: operation.plannedContainmentDigest, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest };
}
function retainedStdioAdminInputBinding(operation: AdminOperationV1, plan: ProcessContainmentPlanV1,
  original: Readonly<{ pid: number; processStartToken: string }>): AdminMcpStdioInputBinding {
  const nonce = plan.backend.kind === 'linux' ? plan.backend.cgroupPath.split('/').at(-1)?.match(/^cliq-mcp-stdio-admin-([0-9a-f]{64})$/u)?.[1] : undefined;
  if (!nonce || plan.backend.kind !== 'linux' || plan.backend.pidNamespaceReservationId !== `linux-mcp-stdio:admin:${nonce}`)
    invalid('MCP original stdio Admin plan has no exact closed native purpose/nonce');
  return { adminOperationId: operation.adminOperationId, attempt: operation.attempt, principalId: operation.principalId, nonce,
    targetRef: operation.targetRef, targetDigest: operation.targetDigest, probePayloadCoreRef: operation.probePayloadCoreRef,
    probePayloadCoreDigest: operation.probePayloadCoreDigest, plannedContainmentRef: operation.plannedContainmentRef,
    plannedContainmentDigest: operation.plannedContainmentDigest, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest, originalSupervisorPid: original.pid, originalSupervisorStartToken: original.processStartToken };
}
function adminProbeRequestDigest(operation: AdminOperationV1, target: McpAdminProbeTargetV1, dispatchId: string): string {
  if (!('processContainmentRef' in operation) || !operation.processContainmentRef) invalid('MCP Admin probe has no actual blocked original containment');
  return canonicalSha256({ schemaVersion: 1, kind: 'mcp_registry_probe', adminOperationId: operation.adminOperationId,
    attempt: operation.attempt, principalId: operation.principalId, method: operation.method, originalRequestDigest: operation.requestDigest,
    targetRef: operation.targetRef, targetDigest: operation.targetDigest, dispatchId, supervisorInstanceId: operation.supervisorInstanceId,
    containmentRef: operation.processContainmentRef, target: target.resolvedTransport, payloadRef: operation.probePayloadCoreRef,
    payloadDigest: operation.probePayloadCoreDigest, expiresAt: operation.deadlineAt });
}
async function retireRetainedMcpStdioAdminOperation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, operation: AdminOperationV1, target: McpAdminProbeTargetV1,
  binding: AdminMcpStdioInputBinding, signal?: AbortSignal) {
  const current = assertActiveStateOwner(driver, owner);
  if (current.supervisorInstanceId === operation.supervisorInstanceId) invalid('MCP stdio successor cannot replace its own original live Admin attempt');
  const cancellation = new AbortController(), combined = signal ? AbortSignal.any([signal, cancellation.signal]) : cancellation.signal;
  const launcher = await observeMcpAdminWork('stdio', 'launcher_open', () => openInstalledLinuxWorkerLauncher(selected, anchor, { signal: combined }));
  let controller: LinuxWorkerController | undefined, opening: Promise<LinuxWorkerController> | undefined;
  let physical: HeldAdminMcpStdioInput | undefined, cleanupTask: ReturnType<typeof retireInstalledRetainedMcpStdioAdmin> | undefined, closing: Promise<void> | undefined;
  const resource: AdminResource = { close: () => closing ??= (async () => {
    cancellation.abort(new KernelStorageError('LEASE_FENCED', 'MCP stdio current Admin checker is closing'));
    const failures: unknown[] = [];
    const revoke = observeMcpAdminWork('stdio', 'controller_close', async () => { const held = controller ?? await opening; await held?.close(); });
    for (const result of await Promise.allSettled([cleanupTask, revoke])) if (result.status === 'rejected') failures.push(result.reason);
    try { await observeMcpAdminWork('stdio', 'launcher_close', () => launcher.close()); } catch (error) { failures.push(error); }
    try { physical?.close(); } catch (error) { failures.push(error); }
    if (failures.length) throw new ResourceRetirementError('MCP stdio Admin current checker did not completely join', new AggregateError(failures));
  })() };
  let owners = adminResources.get(driver); if (!owners) adminResources.set(driver, owners = new Set()); owners.add(resource);
  let failure: unknown;
  try {
    opening = observeMcpAdminWork('stdio', 'controller_start', () => launcher.startController({ signal: combined })); controller = await opening; combined.throwIfAborted();
    physical = openRetainedAdminMcpStdioInput(owner.filesystem, binding);
    cleanupTask = observeMcpAdminWork('stdio', 'retained_cleanup', () => retireInstalledRetainedMcpStdioAdmin({ selected, anchor, controller: controller!, lock: owner.filesystem, input: physical!, inputBinding: binding,
      checker: { supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch }, signal: combined }));
    const receipt = await cleanupTask, actual = readInstalledMcpStdioAdminCleanup(receipt, physical);
    const retirement = await publishAdminRetirement(artifacts, owner, driver, operation, actual.lifecycleSnapshot, actual.joined.observation, undefined,
      { binding, cleanup: { observation: actual.observation, cleanupSnapshot: actual.cleanupSnapshot } });
    await finishFailedAdminAttempt(driver, artifacts, owner, operation, retirement, { principalId: operation.principalId,
      channelIdentityRef: target.channelIdentityRef, channelIdentityDigest: target.channelIdentityDigest }, false,
      { kind: 'stdio_cleanup', receipt, input: physical });
  } catch (error) { failure = error; }
  finally {
    try { await resource.close(); if (failure === undefined) owners.delete(resource); } catch (error) { failure = error; }
  }
  if (failure !== undefined) throw failure instanceof ResourceRetirementError ? failure :
    new ResourceRetirementError('MCP stdio original Admin birth/current cleanup remains unresolved', failure);
}
async function publishAdminRetirement(artifacts: ArtifactCatalog, owner: StateOwnerContext, driver: SqliteDriver,
  operation: AdminOperationV1, lifecycleBytes: Buffer, observation: McpAdminScopeObservation, cleanup?: NativeAdminCleanupObservation,
  stdio?: Readonly<{ binding: AdminMcpStdioInputBinding; cleanup?: Readonly<{ observation: McpStdioNativeCleanup; cleanupSnapshot: Buffer }> }>,
  originalScope?: McpAdminRetirementScope) {
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, operation.plannedContainmentRef);
  if (plan.backend.kind !== 'linux' || plan.filesystemBinding.kind !== 'isolated-empty-root') invalid('MCP original Admin plan changed its physical purpose');
  const binding = stdio?.binding ?? retainedAdminInputBinding(operation, plan), stdioLifecycle = stdio ? decodeMcpStdioLifecycleData(lifecycleBytes) : undefined;
  const lifecycle = stdioLifecycle ?? decodeAdminMcpLifecycleData(lifecycleBytes), actualCleanup = stdio?.cleanup?.observation ?? cleanup;
  requireEqual(lifecycle.binding, stdio ? { kind: 'admin', ...binding } : binding, 'MCP original complete native birth');
  if (!actualCleanup && (!lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired || stdioLifecycle && !stdioLifecycle.joined.ownerDrained))
    invalid('MCP original Admin lifecycle has no actual complete resource join');
  if (stdioLifecycle?.joined.responseRefused) invalid('MCP unsafe original stdio event remains pending recovery');
  if (actualCleanup && (actualCleanup.originalBirthDigest !== sha256Bytes(lifecycleBytes) || canonicalSha256(actualCleanup.originalBinding) !== canonicalSha256(stdio ? { kind: 'admin', ...binding } : binding) ||
      !actualCleanup.priorControllerDead || !actualCleanup.priorSupervisorDead || !actualCleanup.outputCustodyRetired || actualCleanup.remainingDescendants !== 0 ||
      cleanup && !cleanup.networkJoined))
    invalid('MCP original Admin cleanup does not close its complete unchanged birth');
  if (observation.cgroupPopulated !== 0 || observation.remainingTrackedDescendants !== 0 ||
      lifecycle.reservation.cgroupInode !== observation.cgroupId) invalid('MCP original Admin domain is not actually empty');
  const current = assertActiveStateOwner(driver, owner), inspector = supervisorInspectorIdentity(current), observedAt = new Date(actualCleanup?.observedAtMs ?? observation.observedAtMs).toISOString();
  const inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const lifecycleArtifact = await artifacts.publishBytes(lifecycleBytes, 'application/octet-stream', stdio ? 'cliq-mcp-stdio-native-lifecycle-bytes-v1' : 'cliq-mcp-admin-native-lifecycle-bytes-v1');
  const projectionArtifact = await artifacts.publishCanonical(lifecycle, lifecycle.format);
  const stdioCleanupRaw = stdio?.cleanup ? await artifacts.publishBytes(stdio.cleanup.cleanupSnapshot, 'application/octet-stream', 'cliq-mcp-stdio-native-cleanup-bytes-v1') : undefined;
  const stdioCleanupProjection = stdio?.cleanup ? await artifacts.publishCanonical(stdio.cleanup.observation, stdio.cleanup.observation.format) : undefined;
  const cleanupArtifact = stdioCleanupRaw && stdioCleanupProjection ? await artifacts.publishCanonical({ schemaVersion: 1,
    format: 'cliq-mcp-stdio-admin-cleanup-root-v1', cleanupRawRef: stdioCleanupRaw.ref, cleanupProjectionRef: stdioCleanupProjection.ref }, 'cliq-mcp-stdio-admin-cleanup-root-v1')
    : cleanup ? await artifacts.publishCanonical(cleanup, 'cliq-mcp-admin-retained-cleanup-v1') : undefined;
  const metadata: PublishedArtifact[] = [inspectorArtifact, lifecycleArtifact, projectionArtifact, ...(cleanupArtifact ? [cleanupArtifact] : []),
    ...(stdioCleanupRaw ? [stdioCleanupRaw, stdioCleanupProjection!] : [])];
  const common = { schemaVersion: 1 as const, format: 'cliq-admin-probe-closure-evidence-v1' as const, adminOperationId: operation.adminOperationId,
    attempt: operation.attempt, targetRef: operation.targetRef, targetDigest: operation.targetDigest,
    plannedContainmentRef: operation.plannedContainmentRef, plannedContainmentDigest: operation.plannedContainmentDigest,
    sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, observedAt,
    nativeLifecycleRef: lifecycleArtifact.ref, nativeLifecycleDigest: lifecycleArtifact.ref,
    nativeLifecycleProjectionRef: projectionArtifact.ref, nativeLifecycleProjectionDigest: projectionArtifact.ref,
    ...(cleanupArtifact ? { nativeCleanupRef: cleanupArtifact.ref, nativeCleanupDigest: cleanupArtifact.ref } : {}) };
  let closure: AdminProbeClosureEvidenceV1, processContainmentRef: string | undefined;
  if (lifecycle.containment === null) {
    if (stdioLifecycle && (stdioLifecycle.joined.spawnAttempted || stdioLifecycle.joined.execReleased || observation.namespaceInitPid !== 0 ||
        observation.namespaceInitDeadAndReaped !== 0 || !actualCleanup && stdioLifecycle.progressKind !== 9))
      invalid('MCP missing stdio READY cannot prove that its original namespace was never created');
    if ('probeDispatch' in operation && operation.probeDispatch && operation.probeDispatch.state !== 'blocked') invalid('claimed MCP Admin cannot invent a no-spawn branch');
    const evidence: ProcessContainmentNoSpawnEvidenceV1 = { schemaVersion: 1, kind: 'containment_plan_quiescent', planRef: operation.plannedContainmentRef,
      sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest, owner: plan.owner,
      launchNonceDigest: plan.launchNonceDigest, inspectorSupervisorInstanceId: owner.supervisorInstanceId,
      inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, backend: { kind: 'linux',
        cgroupPath: plan.backend.cgroupPath, cgroupObservation: { kind: 'empty', cgroupId: observation.cgroupId, populated: 0 },
        pidNamespaceObservation: { kind: 'never_created', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
        subreaperStartToken: plan.backend.subreaperStartToken, matchingLaunchNonceProcessCount: 0 }, observedAt, evidenceDigest: '' };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); const evidenceArtifact = await artifacts.publishCanonical(evidence, 'cliq-process-containment-no-spawn-evidence-v1'); metadata.push(evidenceArtifact);
    closure = { ...common, closureKind: 'no_spawn', noSpawnEvidenceRef: evidenceArtifact.ref, noSpawnEvidenceDigest: evidence.evidenceDigest, evidenceDigest: '' };
  } else {
    const actual = lifecycle.containment;
    if (observation.namespaceInitDeadAndReaped !== 1 || actual.pidNamespaceId !== observation.pidNamespaceId || actual.namespaceInitStartToken !== observation.namespaceInitStartToken)
      invalid('MCP original spawned namespace is not positively retired');
    const retained = 'processContainmentRef' in operation ? operation.processContainmentRef : undefined;
    const containment: ProcessContainment = retained ? await readCanonicalArtifact(artifacts, retained) : {
      schemaVersion: 1, planRef: operation.plannedContainmentRef, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest, owner: plan.owner, filesystemBinding: plan.filesystemBinding,
      launchNonceDigest: plan.launchNonceDigest, backend: { kind: 'linux', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId,
        pidNamespaceId: actual.pidNamespaceId, cgroupPath: plan.backend.cgroupPath, cgroupId: actual.cgroupId,
        namespaceInitStartToken: actual.namespaceInitStartToken, subreaperStartToken: plan.backend.subreaperStartToken }, createdAt: new Date(actual.observedAtMs).toISOString() };
    const containmentArtifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1'); metadata.push(containmentArtifact); processContainmentRef = containmentArtifact.ref;
    const evidence: ProcessContainmentDeathEvidenceV1 = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: processContainmentRef,
      planRef: operation.plannedContainmentRef, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest,
      owner: plan.owner, launchNonceDigest: plan.launchNonceDigest, inspectorSupervisorInstanceId: owner.supervisorInstanceId,
      inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest, backend: { ...containment.backend as Extract<ProcessContainment['backend'], {kind:'linux'}>,
        cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, observedAt, evidenceDigest: '' };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); const evidenceArtifact = await artifacts.publishCanonical(evidence, 'cliq-process-containment-death-evidence-v1'); metadata.push(evidenceArtifact);
    const dispatch = 'probeDispatch' in operation ? operation.probeDispatch : undefined;
    closure = { ...common, closureKind: 'containment_dead', processContainmentRef, ...(dispatch && dispatch.state !== 'blocked'
      ? { dispatchId: dispatch.dispatchId, probeRequestDigest: dispatch.probeRequestDigest } : {}), deathEvidenceRef: evidenceArtifact.ref,
      deathEvidenceDigest: evidence.evidenceDigest, evidenceDigest: '' };
  }
  const root = stateRootIdentityForLock(owner.filesystem);
  const currentRetirement = originalScope && closure.closureKind === 'containment_dead' && closure.dispatchId &&
    'probeDispatch' in operation && operation.probeDispatch?.state === 'released'
    ? await publishMcpAdminCurrentRetirement(artifacts, originalScope, lifecycleBytes, lifecycle, {
      supervisorInstanceId: current.supervisorInstanceId, stateOwnerEpoch: current.ownerEpoch,
      pid: lifecycle.originalSupervisor.pid, processStartToken: lifecycle.originalSupervisor.processStartToken, acquiredAt: current.acquiredAt,
      stateRootIdentity: { deviceId: root.deviceId, fileId: root.directoryFileId, ownerUid: root.ownerUid } }) : undefined;
  if (currentRetirement) { closure = { ...closure, nativeCurrentRetirement: currentRetirement.edge }; metadata.push(...currentRetirement.metadata); }
  (closure as {evidenceDigest:string}).evidenceDigest = digestOmitting(closure, 'evidenceDigest'); decodeAdminProbeClosureEvidence(closure);
  const artifact = await artifacts.publishCanonical(closure, closure.format); metadata.push(artifact);
  return { closure, artifact, metadata, processContainmentRef, observedAt, lifecycle, binding, currentRetirement };
}
async function finishFailedAdminAttempt(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, operation: AdminOperationV1,
  retirement: Pick<Awaited<ReturnType<typeof publishAdminRetirement>>, 'artifact' | 'closure' | 'metadata' | 'processContainmentRef' | 'currentRetirement'>,
  identity: AuthenticatedControlIdentity | undefined, deterministic: boolean,
  physical: Readonly<{ kind:'original'; scope:InstalledMcpHttpAdminScope; joined:McpAdminPhysicalJoined }> |
    Readonly<{ kind:'cleanup'; receipt:InstalledMcpAdminCleanup; input:HeldAdminMcpInput }> |
    Readonly<{ kind:'stdio_original'; scope:InstalledMcpStdioAdminScope; joined:McpStdioPhysicalJoined }> |
    Readonly<{ kind:'stdio_cleanup'; receipt:InstalledMcpStdioAdminCleanup; input:HeldAdminMcpStdioInput }>) {
  const code = deterministic ? 'schema_invalid' as const : 'transport_failed_no_effect' as const;
  const diagnostic = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-admin-probe-diagnostic-v1', code }, 'cliq-admin-probe-diagnostic-v1');
  const finishedAt = sampleCanonicalNow(), error: AdminProbeErrorV1 = { schemaVersion: 1, format: 'cliq-admin-probe-error-v1',
    adminOperationId: operation.adminOperationId, attempt: operation.attempt, targetRef: operation.targetRef, targetDigest: operation.targetDigest,
    closureEvidenceRef: retirement.artifact.ref, closureEvidenceDigest: retirement.closure.evidenceDigest,
    diagnosticRef: diagnostic.ref, diagnosticDigest: diagnostic.ref, code, deterministicRejection: deterministic, createdAt: finishedAt, errorDigest: '' } as AdminProbeErrorV1;
  (error as {errorDigest:string}).errorDigest = digestOmitting(error, 'errorDigest'); decodeAdminProbeError(error);
  const errorArtifact = await artifacts.publishCanonical(error, error.format);
  const disposition = deterministic ? 'final_rejection' as const : operation.attempt === 3 ? 'retry_exhausted' as const : 'retryable_recovery' as const;
  const response: InstalledControlResponseV1 = { protocolVersion: 1, ok: false, method: operation.method,
    error: { schemaVersion: 1, code: 'INVALID_REQUEST', messageCode: deterministic ? 'MCP_PROTOCOL_REJECTED' : 'MCP_ADMIN_RETRY_EXHAUSTED', retryable: false, issues: [] } };
  const responseArtifact = disposition === 'retryable_recovery' ? undefined : await artifacts.publishCanonical(response, 'cliq-control-response-v1');
  const { phase: _phase, ...base } = operation;
  const failed: AdminOperationV1 = { ...base, phase: 'failed', failureDisposition: disposition,
    ...(retirement.processContainmentRef ? { processContainmentRef: retirement.processContainmentRef,
      probeDispatch: 'probeDispatch' in operation && operation.probeDispatch ? operation.probeDispatch : { state: 'blocked' as const } } : {}),
    evidenceRef: retirement.artifact.ref, evidenceDigest: retirement.closure.evidenceDigest, errorRef: errorArtifact.ref,
    errorDigest: error.errorDigest, rowVersion: operation.rowVersion + 1, finishedAt,
    ...(responseArtifact ? { controlResponseRef: responseArtifact.ref, controlResponseDigest: responseArtifact.ref }
      : { retryNotBeforeAt: new Date(Date.parse(finishedAt) + (operation.attempt === 1 ? 1000 : 5000)).toISOString() }) } as AdminOperationV1;
  // Remove active-only lease data; the canonical failed branch retains only
  // its original containment/dispatch pair, never productive lease authority.
  delete (failed as unknown as Record<string, unknown>).leaseExpiresAt;
  if (!retirement.processContainmentRef) { delete (failed as unknown as Record<string, unknown>).processContainmentRef; delete (failed as unknown as Record<string, unknown>).probeDispatch; }
  decodeAdminOperation(failed);
  let clock: ReturnType<typeof advanceTimeFence> | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    if (physical.kind === 'original') physical.scope.assertJoined(physical.joined);
    else if (physical.kind === 'stdio_original') physical.scope.assertJoined(physical.joined);
    else if (physical.kind === 'cleanup') readInstalledMcpAdminCleanup(physical.receipt, physical.input);
    else readInstalledMcpStdioAdminCleanup(physical.receipt, physical.input);
    retirement.currentRetirement?.assertCurrent();
    const now = sampleCanonicalNow(); clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
    requireEqual(readMcpAdminOperation(connection, operation.principalId, operation.method, operation.requestId, operation.attempt), operation, 'MCP original retired failure attempt');
    const observedAtMs = retirement.currentRetirement?.current.observedAtMs ?? Date.parse(retirement.closure.observedAt);
    if (now < finishedAt || Date.parse(now) < observedAtMs || Date.parse(now) - observedAtMs > 5_000)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP Admin retirement is stale at its actual failure commit');
    for (const item of [...retirement.metadata, diagnostic, errorArtifact, ...(responseArtifact ? [responseArtifact] : [])]) insertArtifactMetadata(connection, item, finishedAt);
    connection.prepare('UPDATE admin_operations SET state=?,row_json=? WHERE principal_id=? AND method=? AND request_id=? AND attempt=?')
      .run('failed', canonicalJsonBytes(failed).toString('utf8'), operation.principalId, operation.method, operation.requestId, operation.attempt);
    if (responseArtifact) {
      if (!identity) invalid('final MCP recovery response lost its original authenticated request channel');
      insertControlRequest(connection, { principalId: operation.principalId, method: operation.method, requestId: operation.requestId,
        requestDigest: operation.requestDigest, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
        responseRef: responseArtifact.ref, committedAt: now });
    }
  }); requireHealthyFence(clock);
  return { failed, response };
}
function assertMcpHttpProfile(target: McpAdminProbeTargetV1): void {
  if (target.resolvedTransport.kind !== 'streamable_http' || target.resolvedTransport.credentialGrantRefs.length > 1 ||
      target.requestedToolRecovery.some(item => item.recovery.kind === 'reconcile'))
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP HTTP requires at most one Bearer credential and manual or explicitly risk-consented retry recovery');
}
function assertMcpProfile(target: McpAdminProbeTargetV1): void {
  if (target.resolvedTransport.kind === 'streamable_http') return assertMcpHttpProfile(target);
  if (target.resolvedTransport.executable.kind !== 'runtime_bundle')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP stdio requires its exact signed executable closure');
}
export function readMcpAdminOperation(connection: SqliteConnection, principalId: string, method: string,
  requestId: string, attempt?: number): AdminOperationV1 | undefined {
  const row = attempt === undefined
    ? connection.prepare('SELECT attempt,state,row_json FROM admin_operations WHERE principal_id=? AND method=? AND request_id=? ORDER BY attempt DESC LIMIT 1')
      .get<{ attempt: bigint; state: string; row_json: string }>(principalId, method, requestId)
    : connection.prepare('SELECT attempt,state,row_json FROM admin_operations WHERE principal_id=? AND method=? AND request_id=? AND attempt=?')
      .get<{ attempt: bigint; state: string; row_json: string }>(principalId, method, requestId, attempt);
  if (!row) return undefined;
  const operation = decodeAdminOperation(JSON.parse(row.row_json));
  if (operation.principalId !== principalId || operation.method !== method || operation.requestId !== requestId ||
      operation.attempt !== Number(row.attempt) || operation.phase !== row.state ||
      attempt !== undefined && operation.attempt !== attempt) invalid('MCP Admin index differs from its original identity');
  return operation;
}

export async function readMcpHttpCapture(artifacts: ArtifactCatalog, reference: string) {
  const capture = decodeMcpHttpCapture(await readCanonicalArtifact(artifacts, reference));
  const bytes = await artifacts.readBoundedBytes(capture.rawResponseRef, capture.rawFinitePrefixBytes);
  const decoded = decodeMcpHttpCaptureData({ bytes, mediaType: capture.mediaType,
    reportedCompletion: capture.termination, expectedId: capture.expectedId });
  requireEqual({ bytes: decoded.rawFinitePrefixBytes, digest: decoded.rawFinitePrefixDigest,
    tail: decoded.receivedTailBytes, offset: decoded.responseEventEndOffset ?? null },
  { bytes: capture.rawFinitePrefixBytes, digest: capture.rawFinitePrefixDigest,
    tail: capture.receivedTailBytes, offset: capture.responseEventEndOffset ?? null }, 'MCP exact retained finite response');
  return { capture, decoded };
}
async function readOriginalAdminRequest(driver: SqliteDriver, artifacts: ArtifactCatalog, operation: AdminOperationV1, target: McpAdminProbeTargetV1,
  context: RegistryReadContext = registryReadContext()) {
  const request = decodeMcpMutationRequest(await readCanonicalArtifact(artifacts, target.originalRequestRef));
  const channel = await readHistoricalControlChannel(driver, artifacts, { principalId: operation.principalId,
    channelIdentityRef: target.channelIdentityRef, channelIdentityDigest: target.channelIdentityDigest });
  const first = readMcpAdminOperation(driver, operation.principalId, operation.method, operation.requestId, 1);
  if (!first || request.requestId !== operation.requestId || request.requestDigest !== operation.requestDigest || request.method !== operation.method ||
      request.registrationId !== target.registrationId || target.ownerPrincipalId !== operation.principalId || target.requestCoreDigest !== mcpMutationCoreDigest(request) ||
      first.targetRef !== operation.targetRef || first.probePayloadCoreRef !== operation.probePayloadCoreRef || first.adminOperationId !== operation.adminOperationId ||
      channel.channel.openedAt > target.createdAt || target.createdAt > first.createdAt)
    invalid('MCP Admin original request/channel provenance differs from its first prepared intent');
  const latestOwner = readLatestStateOwner(driver);
  if (!latestOwner) invalid('MCP original channel has no retained owner history');
  const ownerHistory = await readRetainedStateOwnerHistory(driver, artifacts, latestOwner.ownerEpoch);
  const firstOwners = ownerHistory.entries.filter(entry => entry.owner.supervisorInstanceId === first.supervisorInstanceId);
  const firstOwner = firstOwners[0];
  if (firstOwners.length !== 1 || !firstOwner || channel.channel.openedAt < firstOwner.owner.acquiredAt ||
      first.createdAt < firstOwner.owner.acquiredAt || firstOwner.owner.state === 'terminal' && first.createdAt > firstOwner.owner.releasedAt)
    invalid('MCP original channel/prepared interval is outside its exact first StateOwner');
  if (channel.channel.transport.kind === 'uds_peer') {
    const peer = decodeLocalSocketPeerObservation(await readCanonicalArtifact(artifacts, channel.channel.transport.peerObservationRef));
    // UDS peer PID names the client. Only the retained server-owner interval
    // binds this original authenticated channel to its actual StateOwner.
    if (peer.observedAt < firstOwner.owner.acquiredAt || peer.observedAt > channel.channel.openedAt)
      invalid('MCP original UDS peer observation predates its exact first server owner');
  } else {
    const processIdentity = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, channel.channel.transport.processIdentityRef));
    if (processIdentity.pid !== firstOwner.process.pid || processIdentity.processStartToken !== firstOwner.process.processStartToken ||
        processIdentity.executableImageDigest !== firstOwner.process.executableImageDigest)
      invalid('MCP original in-process channel substitutes its exact first Supervisor');
  }
  let source: RegistrySource | undefined;
  if (request.method === 'mcp.register') {
    if (request.target.kind === 'stdio' && target.resolvedTransport.kind === 'stdio') {
      if (request.target.executionIdentityGrantId !== target.resolvedTransport.executionIdentityGrantId)
        invalid('MCP stdio original request changes its one-use identity grant');
      requireEqual(request.target.argv, target.resolvedTransport.argv, 'MCP stdio exact original non-secret argv');
      const consent = await readMcpStdioRegistrationConsent(driver, artifacts, operation.principalId, target.registrationId, target.resolvedTransport);
      if (consent.history.consumption?.operationId !== first.adminOperationId || consent.history.consumption.requestId !== first.requestId)
        invalid('MCP stdio identity read was not consumed by this exact first prepared operation');
      context.assertions.set(`stdio-identity:${consent.grant.grantId}`, consent.assertUnchanged);
    } else if (request.target.kind === 'streamable_http' && target.resolvedTransport.kind === 'streamable_http') {
      if (request.target.credentialGrantIds.length !== target.resolvedTransport.credentialGrantRefs.length)
        invalid('MCP original registration changed its credential cardinality');
      const endpoint = decodeEndpointRegistration(await readCanonicalArtifact(artifacts, target.resolvedTransport.endpointRegistrationRef));
      if (endpoint.endpointRegistrationId !== request.target.endpointRegistrationId) invalid('MCP original endpoint id differs from retained target');
      const credentials = await artifacts.mapReads(target.resolvedTransport.credentialGrantRefs, async ref =>
        decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, ref)));
      requireEqual(credentials.map(value => value.credentialGrantId), request.target.credentialGrantIds, 'MCP exact original credential IDs');
    } else invalid('MCP original registration target changed its exact original transport');
    requireEqual(target.lifecycle, normalizeMcpLifecycle(request.lifecycle), 'MCP original requested lifecycle');
    await validateMcpOriginalRequestedRecovery(artifacts, request, target);
  } else {
    if (target.expectedRegistryRevision !== request.expectedRegistryRevision || !target.sourceRegistryRevisionRef)
      invalid('MCP original refresh lost its expected source revision');
    source = await readMcpRefreshSource(driver, artifacts, target.sourceRegistryRevisionRef, operation.principalId, target.registrationId, request.expectedRegistryRevision, context);
    requireEqual(target.resolvedTransport, source.registry.transport, 'MCP copy-only refresh original transport');
    requireEqual(target.lifecycle, source.registry.lifecycle, 'MCP copy-only refresh original lifecycle');
    requireEqual(target.requestedToolRecovery, await mcpRequestedRecoveryFromRegistry(artifacts, source.registry), 'MCP copy-only refresh original recovery');
  }
  return { request, channel, first, ownerHistory, firstOwner, source };
}
async function readMcpRefreshSource(driver: SqliteDriver, artifacts: ArtifactCatalog, reference: string, principalId: string, registrationId: string,
  expectedRevision: number, context: RegistryReadContext): Promise<RegistrySource> {
  const data = decodeMcpRegistryRevision(await readCanonicalArtifact(artifacts, reference));
  if (data.ownerPrincipalId !== principalId || data.registrationId !== registrationId || data.registryRevision !== expectedRevision)
    invalid('MCP refresh does not name its exact original lower immutable revision');
  const key = canonicalSha256([reference, principalId, registrationId, expectedRevision]);
  let selected = context.sources.get(key);
  if (!selected) {
    selected = (async () => {
      const closed = await readMcpRegistryClosureInContext(driver, artifacts, reference, principalId, context);
      return { registry: closed.registry, assertUnchanged: closed.assertUnchanged };
    })();
    context.sources.set(key, selected);
  }
  return selected;
}
async function readAdminFailureHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  operation: Extract<AdminOperationV1, { phase: 'failed' }>, context: RegistryReadContext = registryReadContext()) {
  const target = decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, operation.targetRef));
  await readOriginalAdminRequest(driver, artifacts, operation, target, context);
  const closure = decodeAdminProbeClosureEvidence(await readCanonicalArtifact(artifacts, operation.evidenceRef));
  const error = decodeAdminProbeError(await readCanonicalArtifact(artifacts, operation.errorRef));
  if (error.errorDigest !== operation.errorDigest || error.adminOperationId !== operation.adminOperationId || error.attempt !== operation.attempt ||
      error.targetRef !== operation.targetRef || error.targetDigest !== operation.targetDigest || error.closureEvidenceRef !== operation.evidenceRef ||
      error.closureEvidenceDigest !== closure.evidenceDigest || closure.evidenceDigest !== operation.evidenceDigest ||
      error.deterministicRejection !== (operation.failureDisposition === 'final_rejection') ||
      Date.parse(operation.deadlineAt) - Date.parse(operation.createdAt) !== target.lifecycle.launchTimeoutMs ||
      closure.observedAt > error.createdAt || error.createdAt > operation.finishedAt ||
      closure.adminOperationId !== operation.adminOperationId || closure.attempt !== operation.attempt || closure.targetRef !== operation.targetRef ||
      closure.targetDigest !== operation.targetDigest || closure.plannedContainmentRef !== operation.plannedContainmentRef ||
      closure.plannedContainmentDigest !== operation.plannedContainmentDigest || closure.sandboxLaunchSpecRef !== operation.sandboxLaunchSpecRef ||
      closure.sandboxLaunchSpecDigest !== operation.sandboxLaunchSpecDigest || !closure.nativeLifecycleRef || !closure.nativeLifecycleDigest ||
      !closure.nativeLifecycleProjectionRef || !closure.nativeLifecycleProjectionDigest) invalid('MCP failed attempt lost its exact disposition or original resource closure');
  const diagnostic = await readCanonicalArtifact(artifacts, error.diagnosticRef);
  if (canonicalSha256(diagnostic) !== error.diagnosticDigest) invalid('MCP original failure diagnostic changed its complete bytes');
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, operation.plannedContainmentRef);
  const spec = await readCanonicalArtifact<SandboxLaunchSpecV1>(artifacts, operation.sandboxLaunchSpecRef);
  const raw = await artifacts.readBoundedBytes(closure.nativeLifecycleRef, 16_777_216), stdio = target.resolvedTransport.kind === 'stdio';
  if (sha256Bytes(raw) !== closure.nativeLifecycleDigest || closure.nativeLifecycleRef !== closure.nativeLifecycleDigest)
    invalid('MCP failed original birth/progress bytes differ');
  const stdioLifecycle = stdio ? decodeMcpStdioLifecycleData(raw) : undefined, lifecycle = stdioLifecycle ?? decodeAdminMcpLifecycleData(raw);
  const binding = stdio ? retainedStdioAdminInputBinding(operation, plan, lifecycle.originalSupervisor) : retainedAdminInputBinding(operation, plan);
  const projection = await readCanonicalArtifact(artifacts, closure.nativeLifecycleProjectionRef);
  requireEqual(lifecycle, projection, 'MCP failed original full binary birth/progress projection');
  requireEqual(lifecycle.binding, stdio ? { kind: 'admin', ...binding } : binding, 'MCP failed original prepared native binding');
  if (stdioLifecycle?.joined.responseRefused) invalid('MCP unsafe original stdio event cannot become an ordinary local failure/retry');
  if (canonicalSha256(projection) !== closure.nativeLifecycleProjectionDigest || plan.planDigest !== operation.plannedContainmentDigest ||
      plan.planDigest !== digestOmitting(plan, 'planDigest') || spec.launchSpecDigest !== operation.sandboxLaunchSpecDigest ||
      spec.launchSpecDigest !== digestOmitting(spec, 'launchSpecDigest') || plan.backend.kind !== 'linux' ||
      plan.backend.subreaperStartToken !== `linux-subreaper:${lifecycle.controller.pid}:${lifecycle.controller.processStartToken}` ||
      plan.backend.cgroupPath.split('/').at(-1) !== lifecycle.reservation.cgroupName || lifecycle.birthIdentity.ownerUid !== lifecycle.privateParentIdentity.ownerUid)
    invalid('MCP failed native birth does not match its original plan/spec and physical directory');
  const inspector = await readCanonicalArtifact<import('../kernel/types.js').SupervisorInspectorIdentityV1>(artifacts, closure.inspectorIdentityRef);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, inspector.stateOwnerEpoch);
  const original = history.entries.filter(item => item.owner.supervisorInstanceId === operation.supervisorInstanceId), inspecting = history.entries.find(item => item.owner.ownerEpoch === inspector.stateOwnerEpoch)!;
  if (original.length !== 1 || original[0]!.owner.acquiredAt > operation.createdAt || lifecycle.birthIdentity.ownerUid !== history.rootIdentity.ownerUid ||
      original[0]!.owner.state === 'terminal' && operation.createdAt > original[0]!.owner.releasedAt ||
      !inspecting || inspecting.owner.acquiredAt > closure.observedAt || inspecting.owner.state === 'terminal' && closure.observedAt > inspecting.owner.releasedAt ||
      lifecycle.originalSupervisor.pid !== original[0]!.process.pid || lifecycle.originalSupervisor.processStartToken !== original[0]!.process.processStartToken ||
      lifecycle.stateRootIdentity.deviceId !== history.rootIdentity.deviceId || lifecycle.stateRootIdentity.fileId !== history.rootIdentity.directoryFileId ||
      [lifecycle.stateRootIdentity, lifecycle.runtimeIdentity, lifecycle.birthIdentity, lifecycle.privateParentIdentity].some(value => value.ownerUid !== history.rootIdentity.ownerUid))
    invalid('MCP failure resource evidence is outside its exact original owner/inspector history');
  const recipe = await readAdminLaunchRecipe(artifacts, operation, plan, spec, history);
  if (stdioLifecycle) await auditStdioAdminNativeRecipeData(artifacts, stdioLifecycle, target, recipe.core);
  if (original[0]!.owner.runtimeBundleRef !== recipe.core.runtimeBundleRef || original[0]!.owner.runtimeBundleManifestDigest !== recipe.core.runtimeBundleManifestDigest)
    invalid('MCP original failed probe borrows another signed runtime');
  let actualRetirement = lifecycle.retirement;
  if (closure.nativeCleanupRef && stdioLifecycle) {
    const cleanup = await readStdioAdminCleanupData(artifacts, closure.nativeCleanupRef);
    if (closure.nativeCleanupDigest !== closure.nativeCleanupRef || cleanup.originalBirthDigest !== sha256Bytes(raw) ||
        canonicalSha256(cleanup.originalBinding) !== canonicalSha256({ kind: 'admin', ...binding }) || !cleanup.priorSupervisorDead || !cleanup.priorControllerDead ||
        !cleanup.outputCustodyRetired || cleanup.remainingDescendants !== 0 ||
        canonicalSha256(cleanup.originalController) !== canonicalSha256(lifecycle.controller) ||
        cleanup.originalReservation.cgroupName !== lifecycle.reservation.cgroupName || cleanup.originalReservation.cgroupDevice !== lifecycle.reservation.cgroupDevice ||
        cleanup.originalReservation.cgroupInode !== lifecycle.reservation.cgroupInode || cleanup.currentChecker.stateOwnerEpoch !== inspecting.owner.ownerEpoch ||
        cleanup.currentChecker.supervisorInstanceId !== inspecting.owner.supervisorInstanceId || cleanup.currentChecker.supervisorPid !== inspecting.process.pid ||
        cleanup.currentChecker.supervisorStartToken !== inspecting.process.processStartToken || inspecting.owner.ownerEpoch <= original[0]!.owner.ownerEpoch ||
        new Date(cleanup.observedAtMs).toISOString() !== closure.observedAt)
      invalid('MCP stdio successor cleanup substitutes the exact old domain/current inspector');
    actualRetirement = cleanup.retirement;
  } else if (closure.nativeCleanupRef) {
    const cleanup = await readCanonicalArtifact<NativeAdminCleanupObservation>(artifacts, closure.nativeCleanupRef);
    if (closure.nativeCleanupDigest !== closure.nativeCleanupRef || canonicalSha256(cleanup) !== closure.nativeCleanupDigest || cleanup.originalBirthDigest !== sha256Bytes(raw) ||
        canonicalSha256(cleanup.originalBinding) !== canonicalSha256(binding) || !cleanup.priorSupervisorDead || !cleanup.priorControllerDead ||
        !cleanup.networkJoined || !cleanup.outputCustodyRetired || cleanup.remainingDescendants !== 0 ||
        cleanup.originalController.pid !== lifecycle.controller.pid || cleanup.originalController.processStartToken !== lifecycle.controller.processStartToken ||
        cleanup.originalReservation.cgroupName !== lifecycle.reservation.cgroupName || cleanup.originalReservation.deviceId !== lifecycle.reservation.cgroupDevice ||
        cleanup.originalReservation.fileId !== lifecycle.reservation.cgroupInode || cleanup.currentChecker.stateOwnerEpoch !== inspecting.owner.ownerEpoch ||
        cleanup.currentChecker.supervisorInstanceId !== inspecting.owner.supervisorInstanceId || cleanup.currentChecker.supervisorPid !== inspecting.process.pid ||
        cleanup.currentChecker.supervisorStartToken !== inspecting.process.processStartToken || inspecting.owner.ownerEpoch <= original[0]!.owner.ownerEpoch ||
        new Date(cleanup.observedAtMs).toISOString() !== closure.observedAt)
      invalid('MCP separate actual successor cleanup substitutes an original domain or current inspector');
  } else {
    if (!lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired || stdioLifecycle && !stdioLifecycle.joined.ownerDrained || !lifecycle.retirement || inspecting.owner.ownerEpoch !== original[0]!.owner.ownerEpoch ||
        lifecycle.retirement.cgroupPopulated !== 0 || lifecycle.retirement.remainingTrackedDescendants !== 0 ||
        lifecycle.retirement.cgroupId !== lifecycle.reservation.cgroupInode || new Date(lifecycle.retirement.observedAtMs).toISOString() !== closure.observedAt ||
        lifecycle.containment && (lifecycle.retirement.namespaceInitDeadAndReaped !== 1 || lifecycle.retirement.pidNamespaceId !== lifecycle.containment.pidNamespaceId ||
          lifecycle.retirement.namespaceInitStartToken !== lifecycle.containment.namespaceInitStartToken))
      invalid('MCP failed original owner has no positive native all-resource join of the exact born domain');
  }
  await readSupervisorInspector(artifacts, inspecting.owner, { runtime: { runtimeBundleRef: inspecting.owner.runtimeBundleRef,
    runtimeBundleManifestDigest: inspecting.owner.runtimeBundleManifestDigest } }, closure);
  const originalOwner = original[0]!;
  const currentRetirement = await readMcpAdminCurrentRetirementData(artifacts, closure, raw, lifecycle, {
    supervisorInstanceId: originalOwner.owner.supervisorInstanceId, stateOwnerEpoch: originalOwner.owner.ownerEpoch,
    pid: originalOwner.process.pid, processStartToken: originalOwner.process.processStartToken, acquiredAt: originalOwner.owner.acquiredAt,
    ...(originalOwner.owner.state === 'terminal' ? { releasedAt: originalOwner.owner.releasedAt } : {}),
    stateRootIdentity: { deviceId: history.rootIdentity.deviceId, fileId: history.rootIdentity.directoryFileId, ownerUid: history.rootIdentity.ownerUid } });
  if (currentRetirement && (inspecting.owner.ownerEpoch !== originalOwner.owner.ownerEpoch ||
      currentRetirement.observedAtMs > Date.parse(error.createdAt) || Date.parse(operation.finishedAt) - currentRetirement.observedAtMs > 5_000))
    invalid('MCP failed current observation is outside its actual same-owner finalization interval');
  if (closure.closureKind === 'no_spawn') {
    if (lifecycle.containment !== null || operation.processContainmentRef !== undefined || operation.probeDispatch !== undefined)
      invalid('MCP no-spawn failure substitutes an actual blocked/claimed process');
    if (stdioLifecycle && (stdioLifecycle.joined.spawnAttempted || stdioLifecycle.joined.execReleased || !actualRetirement ||
        actualRetirement.namespaceInitPid !== 0 || actualRetirement.namespaceInitDeadAndReaped !== 0))
      invalid('MCP missing stdio READY cannot prove a never-created namespace');
    const noSpawn = await readCanonicalArtifact<ProcessContainmentNoSpawnEvidenceV1>(artifacts, closure.noSpawnEvidenceRef);
    requireEqual(noSpawn, { schemaVersion: 1, kind: 'containment_plan_quiescent', planRef: operation.plannedContainmentRef,
      sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest, owner: plan.owner,
      launchNonceDigest: plan.launchNonceDigest, inspectorSupervisorInstanceId: inspecting.owner.supervisorInstanceId,
      inspectorIdentityRef: closure.inspectorIdentityRef, inspectorIdentityDigest: closure.inspectorIdentityDigest,
      backend: { kind: 'linux', cgroupPath: plan.backend.cgroupPath, cgroupObservation: { kind: 'empty', cgroupId: lifecycle.reservation.cgroupInode, populated: 0 },
        pidNamespaceObservation: { kind: 'never_created', pidNamespaceReservationId: plan.backend.pidNamespaceReservationId },
        subreaperStartToken: plan.backend.subreaperStartToken, matchingLaunchNonceProcessCount: 0 }, observedAt: closure.observedAt,
      evidenceDigest: closure.noSpawnEvidenceDigest }, 'MCP exact original positively proved no-spawn closure');
    if (noSpawn.evidenceDigest !== digestOmitting(noSpawn, 'evidenceDigest')) invalid('MCP no-spawn evidence does not rehash');
  } else {
    if (!lifecycle.containment || operation.processContainmentRef !== closure.processContainmentRef || !operation.probeDispatch)
      invalid('MCP failed spawned original domain has no exact retained containment');
    const containment = await readCanonicalArtifact<ProcessContainment>(artifacts, closure.processContainmentRef);
    const death = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, closure.deathEvidenceRef);
    if (containment.backend.kind !== 'linux') invalid('MCP original failed containment changed its backend');
    const physical = lifecycle.containment;
    if (stdioLifecycle && (!actualRetirement || actualRetirement.namespaceInitDeadAndReaped !== 1 || actualRetirement.cgroupPopulated !== 0 ||
        actualRetirement.remainingTrackedDescendants !== 0 || actualRetirement.namespaceInitPid !== physical.namespaceInitPid ||
        actualRetirement.pidNamespaceId !== physical.pidNamespaceId || actualRetirement.namespaceInitStartToken !== physical.namespaceInitStartToken ||
        actualRetirement.observedAtMs !== Date.parse(closure.observedAt))) invalid('MCP current stdio retirement lost its actual original namespace identity');
    requireEqual(containment, { schemaVersion: 1, planRef: operation.plannedContainmentRef, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest, owner: plan.owner, filesystemBinding: plan.filesystemBinding,
      launchNonceDigest: plan.launchNonceDigest, backend: { kind: 'linux', cgroupPath: plan.backend.cgroupPath,
        cgroupId: lifecycle.reservation.cgroupInode, pidNamespaceReservationId: plan.backend.pidNamespaceReservationId,
        pidNamespaceId: physical.pidNamespaceId, namespaceInitStartToken: physical.namespaceInitStartToken, subreaperStartToken: plan.backend.subreaperStartToken },
      createdAt: new Date(physical.observedAtMs).toISOString() }, 'MCP full original failed/born physical containment');
    if (physical.cgroupPopulated !== 1 || physical.namespaceInitDeadAndReaped !== 0 || physical.observedAtMs < Date.parse(operation.createdAt) ||
        physical.observedAtMs > Date.parse(closure.observedAt)) invalid('MCP failed READY birth is outside its original attempt/closure interval');
    requireEqual(death, { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: closure.processContainmentRef,
      planRef: operation.plannedContainmentRef, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest,
      owner: plan.owner, launchNonceDigest: plan.launchNonceDigest, inspectorSupervisorInstanceId: inspecting.owner.supervisorInstanceId,
      inspectorIdentityRef: closure.inspectorIdentityRef, inspectorIdentityDigest: closure.inspectorIdentityDigest,
      backend: { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 },
      observedAt: closure.observedAt, evidenceDigest: closure.deathEvidenceDigest }, 'MCP original failed all-descendant death');
    if (death.evidenceDigest !== digestOmitting(death, 'evidenceDigest') || containment.planRef !== operation.plannedContainmentRef ||
        containment.sandboxLaunchSpecRef !== operation.sandboxLaunchSpecRef || containment.backend.cgroupId !== lifecycle.reservation.cgroupInode ||
        containment.backend.pidNamespaceId !== lifecycle.containment.pidNamespaceId || containment.backend.namespaceInitStartToken !== lifecycle.containment.namespaceInitStartToken)
      invalid('MCP failed domain death does not match its full original native birth');
    const dispatch = operation.probeDispatch;
    if (dispatch.state === 'blocked' ? closure.dispatchId !== undefined || closure.probeRequestDigest !== undefined
      : closure.dispatchId !== dispatch.dispatchId || closure.probeRequestDigest !== dispatch.probeRequestDigest ||
        dispatch.probeRequestDigest !== adminProbeRequestDigest(operation, target, dispatch.dispatchId))
      invalid('MCP failed closure lost its exact original dispatch phase');
  }
  const key = canonicalSha256(['mcp-original-failed-row', operation.adminOperationId, operation.attempt]);
  context.assertions.set(key, connection => {
    history.assertUnchanged(connection);
    requireEqual(readMcpAdminOperation(connection, operation.principalId, operation.method, operation.requestId, operation.attempt), operation,
      'MCP immutable original failed attempt');
  });
  return { operation, target, closure, error, history, assertUnchanged(connection: SqliteConnection) {
    for (const assertion of context.assertions.values()) assertion(connection);
  } };
}

export function decodeMcpStdioAdminCleanupRoot(value: unknown) {
  assertControlWireJson(value); assertBoundedJsonValue(value, 'MCP stdio current-cleanup root');
  const root = controlWireRecord(value, ['schemaVersion', 'format', 'cleanupRawRef', 'cleanupProjectionRef']);
  if (root.schemaVersion !== 1 || root.format !== 'cliq-mcp-stdio-admin-cleanup-root-v1') invalid('MCP stdio cleanup has no closed original raw/current projection root');
  return immutableSnapshot({ schemaVersion: 1 as const, format: 'cliq-mcp-stdio-admin-cleanup-root-v1' as const,
    cleanupRawRef: controlWireRef(root.cleanupRawRef), cleanupProjectionRef: controlWireRef(root.cleanupProjectionRef) });
}
export async function readStdioAdminCleanupData(artifacts: ArtifactCatalog, reference: string) {
  const root = decodeMcpStdioAdminCleanupRoot(await readCanonicalArtifact(artifacts, reference));
  if (canonicalSha256(root) !== reference) invalid('MCP stdio cleanup root complete bytes changed');
  const bytes = await artifacts.readBoundedBytes(root.cleanupRawRef, 16_777_216), cleanup = decodeMcpStdioCleanupData(bytes);
  if (sha256Bytes(bytes) !== root.cleanupRawRef || canonicalSha256(cleanup) !== root.cleanupProjectionRef) invalid('MCP stdio actual cleanup bytes/projection changed');
  requireEqual(await readCanonicalArtifact(artifacts, root.cleanupProjectionRef), cleanup, 'MCP stdio complete actual native cleanup byte projection');
  return cleanup;
}
async function auditStdioAdminNativeRecipeData(artifacts: ArtifactCatalog, lifecycle: McpStdioNativeLifecycle, target: McpAdminProbeTargetV1,
  core: AdminProbePayloadCoreV1) {
  const transport = target.resolvedTransport;
  if (transport.kind !== 'stdio' || transport.executable.kind !== 'runtime_bundle' || lifecycle.binding.kind !== 'admin')
    invalid('MCP stdio original native recipe has another purpose/transport');
  const executable = transport.executable;
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, core.runtimeBundleRef); verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
  const server = bundle.entries.filter(entry => entry.entryId === executable.executableId), client = bundle.entries.filter(entry => entry.entryId === 'linux_worker_controller'),
    isolation = bundle.entries.filter(entry => entry.entryId === 'linux_bubblewrap');
  if (server.length !== 1 || server[0]!.role !== 'mcp_server' || !server[0]!.executable || server[0]!.digest !== transport.executable.executableDigest ||
      client.length !== 1 || client[0]!.role !== 'platform_helper' || !client[0]!.executable || client[0]!.digest !== core.adapterExecutableDigest ||
      isolation.length !== 1 || isolation[0]!.role !== 'platform_helper' || !isolation[0]!.executable)
    invalid('MCP stdio original native images are outside its complete original signed runtime');
  requireEqual(lifecycle.images.server, { digest: server[0]!.digest, byteCount: server[0]!.byteCount }, 'MCP stdio original signed server image');
  requireEqual(lifecycle.images.client, { digest: client[0]!.digest, byteCount: client[0]!.byteCount }, 'MCP stdio original fixed signed client image');
  requireEqual(lifecycle.images.isolation, { digest: isolation[0]!.digest, byteCount: isolation[0]!.byteCount }, 'MCP stdio original fixed signed isolation image');
  const bytes = await artifacts.readBoundedBytes(lifecycle.images.recipe.digest, lifecycle.images.recipe.byteCount), recipe = decodeMcpStdioRecipeData(bytes);
  if (recipe.recipeDigest !== lifecycle.images.recipe.digest || recipe.byteCount !== lifecycle.images.recipe.byteCount)
    invalid('MCP stdio original sealed recipe full bytes differ from native birth');
  assertMcpStdioRecipeData(recipe, { purpose: 'admin', transport, serverByteCount: server[0]!.byteCount, resources: DEFAULT_SANDBOX_RESOURCES });
}

async function readMcpAdminResourceClosure(driver: SqliteDriver, artifacts: ArtifactCatalog,
  operation: Extract<AdminOperationV1, { phase: 'completed' }>, core: ReturnType<typeof decodeAdminProbePayloadCore>,
  closure: ReturnType<typeof decodeAdminProbeClosureEvidence>) {
  if (closure.closureKind !== 'containment_dead') invalid('MCP completed probe requires actual original containment death');
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, operation.plannedContainmentRef);
  const spec = await readCanonicalArtifact<SandboxLaunchSpecV1>(artifacts, operation.sandboxLaunchSpecRef);
  const containment = await readCanonicalArtifact<ProcessContainment>(artifacts, operation.processContainmentRef);
  const death = await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, closure.deathEvidenceRef);
  if (!closure.nativeLifecycleRef || !closure.nativeLifecycleDigest || !closure.nativeLifecycleProjectionRef || !closure.nativeLifecycleProjectionDigest)
    invalid('MCP Admin closure has no complete original native birth/progress capture');
  const lifecycleBytes = await artifacts.readBoundedBytes(closure.nativeLifecycleRef, 16_777_216);
  if (closure.nativeLifecycleDigest !== closure.nativeLifecycleRef) invalid('MCP native lifecycle raw digest differs');
  const stdio = core.probeKind === 'mcp_stdio';
  const lifecycle = stdio ? decodeMcpStdioLifecycleData(lifecycleBytes) : decodeAdminMcpLifecycleData(lifecycleBytes);
  const lifecycleProjection = await readCanonicalArtifact(artifacts, closure.nativeLifecycleProjectionRef);
  if (canonicalSha256(lifecycleProjection) !== closure.nativeLifecycleProjectionDigest)
    invalid('MCP original native lifecycle projection does not rehash');
  requireEqual(lifecycle, lifecycleProjection, 'MCP complete original binary birth/hash-chain projection');
  if (!lifecycle.joined.protocolCompleted || stdio && (!('responseRefused' in lifecycle.joined) || lifecycle.joined.responseRefused || !lifecycle.joined.ownerDrained))
    invalid('MCP successful registry probe did not complete and drain its real original protocol');
  const owner = { kind: 'admin_probe', adminOperationId: operation.adminOperationId, attempt: operation.attempt,
    principalId: operation.principalId, method: operation.method, originalRequestDigest: operation.requestDigest,
    targetRef: operation.targetRef, supervisorInstanceId: operation.supervisorInstanceId };
  if (plan.schemaVersion !== 1 || plan.format !== 'cliq-process-containment-plan-v1' || plan.planDigest !== operation.plannedContainmentDigest ||
      plan.planDigest !== digestOmitting(plan, 'planDigest') || plan.backend.kind !== 'linux' ||
      plan.filesystemBinding.kind !== 'isolated-empty-root' || spec.owner.kind !== 'admin_probe' ||
      spec.purpose !== (stdio ? 'admin_mcp_stdio_probe' : 'admin_mcp_http_probe') || spec.schemaVersion !== 1 || spec.format !== 'cliq-sandbox-launch-v1' ||
      spec.launchSpecDigest !== operation.sandboxLaunchSpecDigest || spec.launchSpecDigest !== digestOmitting(spec, 'launchSpecDigest') ||
      spec.runtime.runtimeBundleRef !== core.runtimeBundleRef || spec.runtime.runtimeBundleManifestDigest !== core.runtimeBundleManifestDigest ||
      spec.containmentPlanRef !== operation.plannedContainmentRef || spec.containmentPlanDigest !== plan.planDigest ||
      spec.adminTargetRef !== operation.targetRef || spec.adminTargetDigest !== operation.targetDigest ||
      spec.probePayloadCoreRef !== operation.probePayloadCoreRef || spec.processInvocation.kind !== 'admin_probe' ||
      spec.processInvocation.recipe !== (stdio ? 'cliq-admin-mcp-stdio-probe-v1' : 'cliq-admin-mcp-http-probe-v1') ||
      spec.processInvocation.purpose !== (stdio ? 'admin_mcp_stdio_probe' : 'admin_mcp_http_probe') ||
      spec.processInvocation.targetRef !== operation.targetRef || spec.processInvocation.targetDigest !== operation.targetDigest ||
      spec.processInvocation.probePayloadCoreRef !== operation.probePayloadCoreRef ||
      spec.processInvocation.argvCwdSource !== 'trusted_recipe_decode_of_admin_target_and_probe_core' ||
      containment.schemaVersion !== 1 || containment.backend.kind !== 'linux' || containment.parentContainmentRef !== undefined ||
      containment.planRef !== operation.plannedContainmentRef || containment.sandboxLaunchSpecRef !== operation.sandboxLaunchSpecRef ||
      containment.sandboxLaunchSpecDigest !== operation.sandboxLaunchSpecDigest || containment.launchNonceDigest !== plan.launchNonceDigest ||
      containment.createdAt < operation.createdAt || containment.createdAt > operation.probeDispatch.claimedAt ||
      plan.createdAt < operation.createdAt || spec.createdAt < operation.createdAt || plan.createdAt > containment.createdAt ||
      spec.createdAt > containment.createdAt || death.observedAt > closure.observedAt || death.observedAt < operation.probeDispatch.releasedAt)
    invalid('MCP Admin resource closure substitutes its original fixed launch');
  requireEqual(plan.owner, owner, 'MCP original planned Admin owner');
  requireEqual(spec.owner, owner, 'MCP original Admin sandbox owner');
  const target = decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, operation.targetRef));
  if (operation.probeDispatch.probeRequestDigest !== adminProbeRequestDigest(operation, target, operation.probeDispatch.dispatchId))
    invalid('MCP Admin claim request digest does not bind the exact original broker envelope');
  requireEqual(containment.owner, owner, 'MCP actual original Admin owner');
  requireEqual(containment.filesystemBinding, plan.filesystemBinding, 'MCP actual isolated empty root');
  const backend = containment.backend;
  const nonce = plan.backend.cgroupPath.split('/').at(-1)?.match(stdio ? /^cliq-mcp-stdio-admin-([0-9a-f]{64})$/u : /^cliq-mcp-admin-([0-9a-f]{64})$/u)?.[1];
  if (!nonce) invalid('MCP Admin native reservation has no exact original nonce');
  const expectedInput: AdminMcpInputBinding = { adminOperationId: operation.adminOperationId, attempt: operation.attempt,
    principalId: operation.principalId, nonce, targetRef: operation.targetRef, targetDigest: operation.targetDigest,
    probePayloadCoreRef: operation.probePayloadCoreRef, probePayloadCoreDigest: operation.probePayloadCoreDigest,
    plannedContainmentRef: operation.plannedContainmentRef, plannedContainmentDigest: operation.plannedContainmentDigest,
    sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest };
  requireEqual(lifecycle.binding, stdio ? { kind: 'admin', ...expectedInput, originalSupervisorPid: lifecycle.originalSupervisor.pid,
    originalSupervisorStartToken: lifecycle.originalSupervisor.processStartToken } : expectedInput, 'MCP native birth original prepared intent');
  const physical = lifecycle.containment, retirement = lifecycle.retirement;
  if (!physical || !retirement || !lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired ||
      lifecycle.reservation.cgroupName !== (stdio ? `cliq-mcp-stdio-admin-${nonce}` : `cliq-mcp-admin-${nonce}`) || lifecycle.reservation.cgroupInode !== backend.cgroupId ||
      plan.backend.pidNamespaceReservationId !== (stdio ? `linux-mcp-stdio:admin:${nonce}` : `cliq-mcp-admin-pidns:${nonce}`) ||
      plan.backend.subreaperStartToken !== `linux-subreaper:${lifecycle.controller.pid}:${lifecycle.controller.processStartToken}` ||
      physical.pidNamespaceId !== backend.pidNamespaceId || physical.cgroupId !== backend.cgroupId ||
      physical.namespaceInitStartToken !== backend.namespaceInitStartToken || physical.cgroupPopulated !== 1 ||
      physical.namespaceInitDeadAndReaped !== 0 || physical.observedAtMs !== Date.parse(containment.createdAt) ||
      retirement.pidNamespaceId !== physical.pidNamespaceId || retirement.cgroupId !== physical.cgroupId ||
      retirement.namespaceInitStartToken !== physical.namespaceInitStartToken || retirement.namespaceInitPid !== physical.namespaceInitPid ||
      retirement.cgroupPopulated !== 0 || retirement.namespaceInitDeadAndReaped !== 1 || retirement.remainingTrackedDescendants !== 0 ||
      retirement.observedAtMs < physical.observedAtMs || retirement.observedAtMs !== Date.parse(death.observedAt))
    invalid('MCP original native READY birth and separate retirement do not close the same complete domain');
  if (backend.cgroupPath !== plan.backend.cgroupPath || backend.pidNamespaceReservationId !== plan.backend.pidNamespaceReservationId ||
      backend.subreaperStartToken !== plan.backend.subreaperStartToken ||
      !exactKeys(containment, ['schemaVersion', 'planRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'owner', 'filesystemBinding', 'launchNonceDigest', 'backend', 'createdAt']))
    invalid('MCP actual Admin domain differs from its original planned native reservation');
  const { evidenceDigest: _digest, ...deathCore } = death;
  requireEqual(deathCore, { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: operation.processContainmentRef,
    planRef: operation.plannedContainmentRef, sandboxLaunchSpecRef: operation.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: operation.sandboxLaunchSpecDigest, owner, launchNonceDigest: plan.launchNonceDigest,
    inspectorSupervisorInstanceId: death.inspectorSupervisorInstanceId, inspectorIdentityRef: closure.inspectorIdentityRef,
    inspectorIdentityDigest: closure.inspectorIdentityDigest, backend: { ...backend, cgroupPopulated: 0,
      namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, observedAt: death.observedAt }, 'MCP complete original all-descendant death');
  if (death.evidenceDigest !== closure.deathEvidenceDigest || death.evidenceDigest !== canonicalSha256(deathCore))
    invalid('MCP original Admin death evidence does not rehash');
  const inspector = await readCanonicalArtifact<import('../kernel/types.js').SupervisorInspectorIdentityV1>(artifacts, closure.inspectorIdentityRef);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, inspector.stateOwnerEpoch);
  const inspecting = history.entries.find(entry => entry.owner.ownerEpoch === inspector.stateOwnerEpoch);
  const claiming = history.entries.filter(entry => entry.owner.supervisorInstanceId === operation.supervisorInstanceId);
  if (!inspecting || claiming.length !== 1 || inspecting.owner.ownerEpoch < claiming[0]!.owner.ownerEpoch ||
      claiming[0]!.owner.acquiredAt > operation.createdAt || claiming[0]!.owner.runtimeBundleRef !== core.runtimeBundleRef ||
      claiming[0]!.owner.runtimeBundleManifestDigest !== core.runtimeBundleManifestDigest ||
      claiming[0]!.owner.state === 'terminal' && claiming[0]!.owner.releasedAt < operation.probeDispatch.releasedAt ||
      death.inspectorSupervisorInstanceId !== inspecting.owner.supervisorInstanceId ||
      inspecting.owner.state === 'terminal' && inspecting.owner.releasedAt < closure.observedAt)
    invalid('MCP Admin physical closure is outside its original retained StateOwner history');
  if (lifecycle.originalSupervisor.pid !== claiming[0]!.process.pid || lifecycle.originalSupervisor.processStartToken !== claiming[0]!.process.processStartToken ||
      lifecycle.stateRootIdentity.deviceId !== history.rootIdentity.deviceId || lifecycle.stateRootIdentity.fileId !== history.rootIdentity.directoryFileId ||
      [lifecycle.stateRootIdentity, lifecycle.runtimeIdentity, lifecycle.birthIdentity, lifecycle.privateParentIdentity].some(identity => identity.ownerUid !== history.rootIdentity.ownerUid) ||
      inspecting.owner.acquiredAt > closure.observedAt || Date.parse(closure.observedAt) - retirement.observedAtMs > 5_000)
    invalid('MCP original native birth substitutes its Supervisor, StateRoot or physical retirement interval');
  await readSupervisorInspector(artifacts, inspecting.owner,
    { runtime: { runtimeBundleRef: inspecting.owner.runtimeBundleRef, runtimeBundleManifestDigest: inspecting.owner.runtimeBundleManifestDigest } }, closure);
  await readAdminLaunchRecipe(artifacts, operation, plan, spec, history);
  if (stdio) await auditStdioAdminNativeRecipeData(artifacts, decodeMcpStdioLifecycleData(lifecycleBytes), target, core);
  const originalOwner = claiming[0]!;
  const currentRetirement = await readMcpAdminCurrentRetirementData(artifacts, closure, lifecycleBytes, lifecycle, {
    supervisorInstanceId: originalOwner.owner.supervisorInstanceId, stateOwnerEpoch: originalOwner.owner.ownerEpoch,
    pid: originalOwner.process.pid, processStartToken: originalOwner.process.processStartToken, acquiredAt: originalOwner.owner.acquiredAt,
    ...(originalOwner.owner.state === 'terminal' ? { releasedAt: originalOwner.owner.releasedAt } : {}),
    stateRootIdentity: { deviceId: history.rootIdentity.deviceId, fileId: history.rootIdentity.directoryFileId, ownerUid: history.rootIdentity.ownerUid } });
  if (currentRetirement && (inspecting.owner.ownerEpoch !== originalOwner.owner.ownerEpoch || currentRetirement.observedAtMs > Date.parse(operation.finishedAt)))
    invalid('MCP successful current observation is outside its actual same-owner finalization interval');
  return { plan, spec, containment, death, history, currentRetirement };
}
/** Same original signed launch recipe for completed, no-spawn, failed and
 * successor-retired attempts. A failure row cannot relax physical history. */
async function readAdminLaunchRecipe(artifacts: ArtifactCatalog, operation: AdminOperationV1, plan: ProcessContainmentPlanV1,
  spec: SandboxLaunchSpecV1, history: Awaited<ReturnType<typeof readRetainedStateOwnerHistory>>) {
  const core = decodeAdminProbePayloadCore(await readCanonicalArtifact(artifacts, operation.probePayloadCoreRef));
  if (core.probeKind === 'mcp_stdio') {
    const target = decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, operation.targetRef));
    const nonce = plan.backend.kind === 'linux' && plan.backend.cgroupPath.split('/').at(-1)?.match(/^cliq-mcp-stdio-admin-([0-9a-f]{64})$/u)?.[1];
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, core.runtimeBundleRef);
    const launcher = bundle.entries.filter(entry => entry.entryId === 'linux_worker_controller');
    if (!nonce || plan.backend.kind !== 'linux' || target.resolvedTransport.kind !== 'stdio' || target.resolvedTransport.executable.kind !== 'runtime_bundle' ||
        core.payloadCoreDigest !== operation.probePayloadCoreDigest || core.runtimeBundleManifestDigest !== bundle.manifestDigest ||
        core.protocolRecipe !== 'mcp-initialize-capabilities-tools-list-v1' || core.maximumResponseBytes !== 1_048_576 ||
        launcher.length !== 1 || launcher[0]!.role !== 'platform_helper' || !launcher[0]!.executable || core.adapterExecutableId !== launcher[0]!.entryId ||
        core.adapterVersion !== launcher[0]!.version || core.adapterExecutableDigest !== launcher[0]!.digest ||
        plan.createdAt !== operation.createdAt || spec.createdAt !== operation.createdAt)
      invalid('MCP stdio Admin core substitutes its original fixed signed C driver, bounded protocol or prepared interval');
    const expectedOwner = { kind: 'admin_probe' as const, adminOperationId: operation.adminOperationId, attempt: operation.attempt,
      principalId: operation.principalId, method: operation.method, originalRequestDigest: operation.requestDigest,
      targetRef: operation.targetRef, supervisorInstanceId: operation.supervisorInstanceId };
    await readMcpStdioLaunchRecipeData(artifacts, { purpose: { kind: 'admin', owner: expectedOwner, targetRef: operation.targetRef,
      targetDigest: operation.targetDigest, probePayloadCoreRef: operation.probePayloadCoreRef }, bundle,
      originalController: { subreaperStartToken: plan.backend.subreaperStartToken }, cgroupParent: plan.backend.cgroupPath.slice(0, plan.backend.cgroupPath.lastIndexOf('/')),
      ownerUid: history.rootIdentity.ownerUid, executable: target.resolvedTransport.executable, nonce, createdAt: operation.createdAt,
      resources: DEFAULT_SANDBOX_RESOURCES, plan, spec });
    for await (const _chunk of artifacts.readChunks(launcher[0]!.digest, launcher[0]!.byteCount)) artifacts.assertReadActive();
    return { core };
  }
  const nonce = plan.backend.kind === 'linux' && plan.backend.cgroupPath.split('/').at(-1)?.match(/^cliq-mcp-admin-([0-9a-f]{64})$/u)?.[1];
  if (!nonce || core.payloadCoreDigest !== operation.probePayloadCoreDigest || core.probeKind !== 'mcp_streamable_http' ||
      core.protocolRecipe !== 'mcp-initialize-capabilities-tools-list-v1' || core.maximumResponseBytes !== 1_048_576 ||
      plan.backend.kind !== 'linux' || plan.filesystemBinding.kind !== 'isolated-empty-root' ||
      !exactKeys(plan, ['schemaVersion', 'format', 'owner', 'filesystemBinding', 'launchNonceDigest', 'backend', 'createdAt', 'planDigest']) ||
      !exactKeys(plan.backend, ['kind', 'cgroupPath', 'cgroupNameReservationDigest', 'pidNamespaceReservationId', 'subreaperStartToken']) ||
      !exactKeys(spec, ['schemaVersion', 'format', 'owner', 'purpose', 'runtime', 'executable', 'processInvocation', 'environment', 'filesystem', 'mounts',
        'mountsDigest', 'sandboxProfileRef', 'sandboxProfileDigest', 'resources', 'resourcesDigest', 'containmentPlanRef', 'containmentPlanDigest',
        'adminTargetRef', 'adminTargetDigest', 'probePayloadCoreRef', 'createdAt', 'launchSpecDigest']) ||
      plan.planDigest !== operation.plannedContainmentDigest || plan.planDigest !== digestOmitting(plan, 'planDigest') ||
      spec.launchSpecDigest !== operation.sandboxLaunchSpecDigest || spec.launchSpecDigest !== digestOmitting(spec, 'launchSpecDigest') ||
      spec.purpose !== 'admin_mcp_http_probe' || spec.containmentPlanRef !== operation.plannedContainmentRef || spec.containmentPlanDigest !== plan.planDigest ||
      spec.runtime.runtimeBundleRef !== core.runtimeBundleRef || spec.runtime.runtimeBundleManifestDigest !== core.runtimeBundleManifestDigest ||
      spec.adminTargetRef !== operation.targetRef || spec.adminTargetDigest !== operation.targetDigest || spec.probePayloadCoreRef !== operation.probePayloadCoreRef ||
      spec.processInvocation.kind !== 'admin_probe' || spec.processInvocation.recipe !== 'cliq-admin-mcp-http-probe-v1' ||
      spec.processInvocation.purpose !== 'admin_mcp_http_probe' || spec.processInvocation.targetRef !== operation.targetRef ||
      spec.processInvocation.targetDigest !== operation.targetDigest || spec.processInvocation.probePayloadCoreRef !== operation.probePayloadCoreRef ||
      spec.processInvocation.argvCwdSource !== 'trusted_recipe_decode_of_admin_target_and_probe_core' ||
      plan.createdAt !== operation.createdAt || spec.createdAt !== operation.createdAt)
    invalid('MCP original Admin launch lost its immutable prepared recipe');
  const expectedOwner = { kind: 'admin_probe', adminOperationId: operation.adminOperationId, attempt: operation.attempt,
    principalId: operation.principalId, method: operation.method, originalRequestDigest: operation.requestDigest,
    targetRef: operation.targetRef, supervisorInstanceId: operation.supervisorInstanceId };
  requireEqual(plan.owner, expectedOwner, 'MCP exact original planned purpose owner');
  requireEqual(spec.owner, expectedOwner, 'MCP exact original sandbox purpose owner');
  const originalBundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, core.runtimeBundleRef);
  verifyRuntimeBundle(originalBundle, artifacts.releaseTrustRoots());
  const helpers = originalBundle.entries.filter(entry => entry.entryId === MCP_ADMIN_HELPER_ENTRY_ID);
  if (helpers.length !== 1 || helpers[0]!.version !== '1' || helpers[0]!.role !== 'platform_helper' || helpers[0]!.executable ||
      helpers[0]!.relativePath !== MCP_ADMIN_HELPER_RELATIVE_PATH || helpers[0]!.digest !== core.adapterExecutableDigest ||
      core.adapterExecutableId !== MCP_ADMIN_HELPER_ENTRY_ID || core.adapterVersion !== '1' || originalBundle.manifestDigest !== core.runtimeBundleManifestDigest)
    invalid('MCP original Admin core is not its exact signed fixed helper image');
  for await (const _chunk of artifacts.readChunks(helpers[0]!.digest, helpers[0]!.byteCount)) { /* Read original held recipe bytes as data only. */ }
  const rootImage = await readCanonicalArtifact<import('../kernel/execution.js').SandboxRootImageV1>(artifacts, plan.filesystemBinding.rootImageRef);
  const rootEntry = originalBundle.entries.find(entry => entry.entryId === 'installed-empty-root'), launcher = originalBundle.entries.find(entry => entry.entryId === 'linux_worker_controller');
  if (!rootEntry || rootEntry.executable || rootEntry.role !== 'sandbox_root_profile' || !launcher?.executable || launcher.role !== 'platform_helper' ||
      spec.runtime.toolchain.kind !== 'guest_toolchain') invalid('MCP original Admin fixed signed assets are incomplete');
  const rootProfile = decodeSandboxRootProfile(await readCanonicalArtifact(artifacts, rootEntry.digest));
  const guest = await readRetainedVerifierToolchain(artifacts, { bundle: originalBundle, releaseKeys: artifacts.releaseTrustRoots(),
    guestToolchainManifestRef: spec.runtime.toolchain.guestToolchainManifestRef });
  requireEqual(rootImage, { schemaVersion: 1, format: 'cliq-sandbox-root-image-v1', runtimeBundleRef: core.runtimeBundleRef,
    runtimeBundleManifestDigest: core.runtimeBundleManifestDigest, entryId: rootEntry.entryId, entryVersion: rootEntry.version, entryDigest: rootEntry.digest,
    protocol: rootProfile.protocol, filesystemKind: rootProfile.filesystemKind, fixedDirectories: rootProfile.fixedDirectories,
    ownerUid: history.rootIdentity.ownerUid, persistent: false, networkConfiguration: 'none', imageDigest: rootImage.imageDigest }, 'MCP original fixed isolated root image');
  if (rootImage.imageDigest !== digestOmitting(rootImage, 'imageDigest') || rootImage.imageDigest !== plan.filesystemBinding.rootImageDigest ||
      plan.launchNonceDigest !== sha256Bytes(Buffer.from(nonce)) || plan.backend.cgroupNameReservationDigest !== canonicalSha256(['cliq-mcp-admin-cgroup-v1', operation.adminOperationId, operation.attempt, nonce]))
    invalid('MCP original Admin root or native reservation does not rehash');
  const runtimeCore = { runtimeBundleRef: core.runtimeBundleRef, runtimeBundleManifestDigest: core.runtimeBundleManifestDigest,
    sandboxBackend: 'linux_namespace', toolchain: { kind: 'guest_toolchain', guestToolchainManifestRef: guest.manifestRef,
      guestToolchainManifestDigest: guest.manifest.manifestDigest, guestImageRef: guest.manifest.guestImageRef, guestImageDigest: guest.manifest.guestImageDigest },
    launcher: { executableId: launcher.entryId, executableDigest: launcher.digest } };
  requireEqual(spec.runtime, { ...runtimeCore, runtimeDigest: canonicalSha256(runtimeCore) }, 'MCP exact original signed launch runtime');
  requireEqual(spec.executable, { kind: 'guest_toolchain', guestToolchainManifestRef: guest.manifestRef, guestToolchainManifestDigest: guest.manifest.manifestDigest,
    toolId: guest.manifest.node.logicalName, role: 'tool', executionPath: '/usr/bin/node', executableDigest: guest.manifest.node.digest }, 'MCP exact signed guest Node');
  const environmentCore = { schemaVersion: 1, format: 'cliq-sanitized-sandbox-environment-v1', controlledPath: ['/usr/bin'], locale: { lang: 'C', lcAll: 'C' },
    home: '/scratch/home', tmpdir: '/scratch/tmp', variables: [], inheritedHostEnvironment: false, secretMaterial: 'none', brokerAccessAtSpawn: 'none', networkMode: 'broker_ipc_only' };
  requireEqual(spec.environment, { ...environmentCore, environmentDigest: canonicalSha256(environmentCore) }, 'MCP exact secretless Admin environment');
  requireEqual(spec.resources, MCP_ADMIN_RESOURCES, 'MCP exact fixed Admin resource profile');
  requireEqual(spec.processInvocation.stdio, { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' }, 'MCP exact Admin channels');
  const profile = await readCanonicalArtifact(artifacts, spec.sandboxProfileRef);
  const profileCore = { schemaVersion: 1, format: 'cliq-sandbox-profile-v1', backend: 'linux_namespace', allowedOwners: ['admin_probe'],
    filesystemPolicy: 'typed_launch_spec_only', hostFilesystemReachability: 'none', networkAtSpawn: 'none', networkAfterRelease: 'typed_broker_only',
    credentialReachability: 'typed_broker_only', stateRootReachability: 'none', inheritedHostEnvironment: false, resources: MCP_ADMIN_RESOURCES };
  requireEqual(profile, { ...profileCore, profileDigest: canonicalSha256(profileCore) }, 'MCP exact original Admin sandbox profile');
  if (spec.sandboxProfileDigest !== canonicalSha256(profileCore)) invalid('MCP Admin profile digest differs from its original fixed resource policy');
  requireEqual(spec.filesystem, { kind: 'isolated_empty_root', rootImageRef: plan.filesystemBinding.rootImageRef,
    rootImageDigest: rootImage.imageDigest, persistentWritableMounts: false }, 'MCP exact no-host filesystem');
  requireEqual(spec.mounts, [{ kind: 'cas_artifact', artifactRef: core.adapterExecutableDigest, artifactDigest: core.adapterExecutableDigest,
    targetPath: '/runtime/cliq-mcp-http-admin-probe.mjs', access: 'read_only', purpose: 'runtime' },
  { kind: 'private_ephemeral', privateRootId: identityHash('cliq-mcp-admin-scratch-v1', operation.adminOperationId, operation.attempt, nonce),
    targetPath: '/scratch', access: 'read_write', purpose: 'output' }], 'MCP exact signed helper and private scratch mounts');
  if (spec.resourcesDigest !== canonicalSha256(spec.resources) || spec.mountsDigest !== canonicalSha256(spec.mounts)) invalid('MCP original Admin resources or mounts do not rehash');
  return { core };
}

/** Retained-only verification follows the actual completed attempt, raw bytes,
 * separate data-response captures, closure and original signed recipe. A CAS
 * registry by itself is never registration authority. */
export async function readMcpRegistryClosure(driver: SqliteDriver, artifacts: ArtifactCatalog,
  reference: string, principalId: string) {
  return readMcpRegistryClosureInContext(driver, artifacts, reference, principalId, registryReadContext());
}
async function readMcpRegistryClosureInContext(driver: SqliteDriver, artifacts: ArtifactCatalog,
  reference: string, principalId: string, context: RegistryReadContext) {
  const registry = decodeMcpRegistryRevision(await readCanonicalArtifact(artifacts, reference));
  if (registry.ownerPrincipalId !== principalId) throw new KernelStorageError('NOT_FOUND', 'MCP registry is unavailable');
  const receipt = decodeMcpRegistrationReceipt(await readCanonicalArtifact(artifacts, registry.registrationReceiptRef));
  const rows = driver.prepare(`SELECT method,request_id,attempt FROM admin_operations WHERE principal_id=? AND attempt=?
    AND json_extract(row_json,'$.adminOperationId')=?`).all<{ method:string;request_id:string;attempt:bigint }>(principalId, receipt.adminAttempt, receipt.adminOperationId);
  if (rows.length !== 1) invalid('MCP registry has no unique original Admin attempt');
  const operation = readMcpAdminOperation(driver, principalId, rows[0]!.method, rows[0]!.request_id, Number(rows[0]!.attempt));
  if (!operation || operation.phase !== 'completed' || operation.adminOperationId !== receipt.adminOperationId) invalid('MCP registry has no completed original indexed Admin attempt');
  for (let attempt = 1; attempt < operation.attempt; attempt++) {
    const prior = readMcpAdminOperation(driver, principalId, operation.method, operation.requestId, attempt);
    if (!prior || prior.phase !== 'failed' || prior.failureDisposition !== 'retryable_recovery' || prior.targetRef !== operation.targetRef ||
        prior.probePayloadCoreRef !== operation.probePayloadCoreRef || prior.requestDigest !== operation.requestDigest ||
        prior.adminOperationId !== operation.adminOperationId || prior.retryNotBeforeAt > (attempt + 1 === operation.attempt ? operation.createdAt :
          readMcpAdminOperation(driver, principalId, operation.method, operation.requestId, attempt + 1)?.createdAt ?? ''))
      invalid('MCP registry skipped an original retired attempt or its fixed backoff');
    await readAdminFailureHistory(driver, artifacts, prior, context);
  }
  const target = decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, operation.targetRef));
  if (registry.registryRevision !== (target.method === 'mcp.register' ? 1 : target.expectedRegistryRevision! + 1))
    invalid('MCP immutable registry revision is not its original register/copy-only refresh successor');
  await readOriginalAdminRequest(driver, artifacts, operation, target, context);
  assertMcpProfile(target);
  const core = decodeAdminProbePayloadCore(await readCanonicalArtifact(artifacts, operation.probePayloadCoreRef));
  const result = decodeMcpAdminProbeResult(await readCanonicalArtifact(artifacts, operation.resultRef));
  const closure = decodeAdminProbeClosureEvidence(await readCanonicalArtifact(artifacts, operation.evidenceRef));
  const resources = await readMcpAdminResourceClosure(driver, artifacts, operation, core, closure);
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, core.runtimeBundleRef);
  verifyRuntimeBundle(bundle, artifacts.releaseTrustRoots());
  const stdio = registry.transport.kind === 'stdio';
  const helper = bundle.entries.filter(entry => entry.entryId === (stdio ? 'linux_worker_controller' : MCP_ADMIN_HELPER_ENTRY_ID));
  if (helper.length !== 1 || helper[0]!.executable !== stdio || helper[0]!.role !== 'platform_helper' ||
      !stdio && helper[0]!.relativePath !== MCP_ADMIN_HELPER_RELATIVE_PATH || helper[0]!.version !== '1' ||
      core.adapterExecutableId !== helper[0]!.entryId || core.adapterVersion !== helper[0]!.version ||
      core.adapterExecutableDigest !== helper[0]!.digest || bundle.manifestDigest !== core.runtimeBundleManifestDigest ||
      core.probeKind !== (stdio ? 'mcp_stdio' : 'mcp_streamable_http')) invalid('MCP registry substitutes its original signed Admin protocol recipe');
  for await (const _chunk of artifacts.readChunks(helper[0]!.digest, helper[0]!.byteCount)) artifacts.assertReadActive();
  if (!result.initializeCaptureRef || !result.toolsListCaptureRef) invalid('MCP probe has no retained original finite captures');
  const initialized = stdio ? await readMcpStdioCapture(artifacts, result.initializeCaptureRef) : await readMcpHttpCapture(artifacts, result.initializeCaptureRef);
  const listed = stdio ? await readMcpStdioCapture(artifacts, result.toolsListCaptureRef) : await readMcpHttpCapture(artifacts, result.toolsListCaptureRef);
  if (initialized.capture.phase !== 'initialize' || listed.capture.phase !== 'tools_list' ||
      initialized.decoded.response.kind !== 'result' || listed.decoded.response.kind !== 'result') invalid('MCP registry discovery was not received successfully');
  const negotiation = decodeMcpInitializeResult(initialized.decoded.response.result), tools = decodeMcpToolsListResult(listed.decoded.response.result);
  const interfaces = tools.map(tool => tool.interface);
  if (result.initializeResponseRef !== initialized.capture.rawResponseRef || result.initializeResponseDigest !== initialized.decoded.rawFinitePrefixDigest ||
      result.capabilityResponseRef !== result.initializeResponseRef || result.capabilityResponseDigest !== result.initializeResponseDigest ||
      result.toolsListResponseRef !== listed.capture.rawResponseRef || result.toolsListResponseDigest !== listed.decoded.rawFinitePrefixDigest ||
      result.initializeDigest !== negotiation.initializeDigest || result.capabilityDigest !== negotiation.capabilityDigest ||
      canonicalSha256(interfaces) !== result.probedToolsListDigest) invalid('MCP discovery semantic projections differ from original received bytes');
  requireEqual(result.normalizedTools, interfaces, 'MCP original complete discovered interfaces');
  const derivedRecovery = await deriveMcpRecoveryToolContracts(artifacts, { target, targetRef: operation.targetRef,
    result, resultRef: operation.resultRef, probePayloadCoreRef: operation.probePayloadCoreRef, registryRevision: registry.registryRevision });
  await readMcpRecoveryTemplates(artifacts, derivedRecovery);
  requireEqual(registry.tools, derivedRecovery.tools, 'MCP exact original discovered interfaces plus original proven recovery contracts');
  for (const tool of tools) {
    requireEqual(await readCanonicalArtifact(artifacts, tool.interface.inputSchemaRef), tool.inputSchema, 'MCP retained input schema');
    if (tool.outputSchema) requireEqual(await readCanonicalArtifact(artifacts, tool.interface.outputSchemaRef!), tool.outputSchema, 'MCP retained output schema');
  }
  if (target.ownerPrincipalId !== principalId || target.registrationId !== registry.registrationId ||
      target.targetDigest !== operation.targetDigest || core.payloadCoreDigest !== operation.probePayloadCoreDigest ||
      result.adminOperationId !== operation.adminOperationId || result.attempt !== operation.attempt ||
      result.dispatchId !== operation.probeDispatch.dispatchId || result.probeRequestDigest !== operation.probeDispatch.probeRequestDigest ||
      result.targetRef !== operation.targetRef || result.targetDigest !== operation.targetDigest ||
      result.probePayloadCoreRef !== operation.probePayloadCoreRef || result.probePayloadCoreDigest !== operation.probePayloadCoreDigest ||
      result.processContainmentRef !== operation.processContainmentRef || closure.closureKind !== 'containment_dead' ||
      closure.adminOperationId !== operation.adminOperationId || closure.attempt !== operation.attempt ||
      closure.targetRef !== operation.targetRef || closure.targetDigest !== operation.targetDigest ||
      closure.processContainmentRef !== operation.processContainmentRef || closure.dispatchId !== operation.probeDispatch.dispatchId ||
      closure.probeRequestDigest !== operation.probeDispatch.probeRequestDigest || closure.plannedContainmentRef !== operation.plannedContainmentRef ||
      closure.plannedContainmentDigest !== operation.plannedContainmentDigest || closure.sandboxLaunchSpecRef !== operation.sandboxLaunchSpecRef ||
      closure.sandboxLaunchSpecDigest !== operation.sandboxLaunchSpecDigest || result.completedAt > closure.observedAt ||
      closure.observedAt > operation.finishedAt || operation.resultDigest !== result.resultDigest || operation.evidenceDigest !== closure.evidenceDigest)
    invalid('MCP registry lost its original Admin claim or physical closure');
  const { registrationReceiptRef: _receipt, manifestDigest: _manifest, ...registryCore } = registry;
  if (receipt.registrationId !== registry.registrationId || receipt.registryRevision !== registry.registryRevision ||
      receipt.ownerPrincipalId !== principalId || receipt.adminOperationId !== operation.adminOperationId || receipt.adminAttempt !== operation.attempt ||
      receipt.requestDigest !== operation.requestDigest || receipt.dispatchId !== result.dispatchId || receipt.probeRequestDigest !== result.probeRequestDigest ||
      receipt.adminProbeTargetRef !== operation.targetRef || receipt.adminProbeTargetDigest !== target.targetDigest ||
      receipt.probeResultRef !== operation.resultRef || receipt.probeResultDigest !== result.resultDigest ||
      receipt.probeClosureEvidenceRef !== operation.evidenceRef || receipt.probeClosureEvidenceDigest !== closure.evidenceDigest ||
      receipt.registryCoreDigest !== canonicalSha256(registryCore) || receipt.initializeDigest !== registry.initializeDigest ||
      receipt.capabilityDigest !== registry.capabilityDigest || receipt.probedToolsListDigest !== registry.probedToolsListDigest ||
      receipt.toolsListDigest !== registry.toolsListDigest || registry.initializeDigest !== result.initializeDigest ||
      registry.capabilityDigest !== result.capabilityDigest || registry.probedToolsListDigest !== result.probedToolsListDigest ||
      receipt.createdAt !== registry.createdAt || registry.createdAt !== operation.finishedAt)
    invalid('MCP publication receipt does not reproduce its one completed original attempt');
  requireEqual(registry.transport, target.resolvedTransport, 'MCP original transport');
  requireEqual(registry.lifecycle, target.lifecycle, 'MCP original lifecycle');
  if (registry.transport.kind === 'streamable_http') {
    const endpoint = decodeEndpointRegistration(await readCanonicalArtifact(artifacts, registry.transport.endpointRegistrationRef));
    if (endpoint.ownerPrincipalId !== principalId || !endpoint.purposes.includes('mcp_streamable_http') ||
        endpoint.endpointIdentityDigest !== registry.transport.endpointIdentityDigest || endpoint.tlsPolicyDigest !== registry.transport.tlsPolicyDigest)
      invalid('MCP registry is not rooted in its principal-bound endpoint');
    for (const ref of registry.transport.credentialGrantRefs) {
      const credential = decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, ref));
      if (credential.ownerPrincipalId !== principalId || credential.purpose !== 'mcp_streamable_http' ||
          credential.endpointRegistrationRef !== registry.transport.endpointRegistrationRef || credential.endpointIdentityDigest !== endpoint.endpointIdentityDigest ||
          credential.tlsPolicyDigest !== endpoint.tlsPolicyDigest) invalid('MCP registry borrows another purpose or endpoint credential');
    }
  } else {
    const consent = await readMcpStdioRegistrationConsent(driver, artifacts, principalId, registry.registrationId, registry.transport);
    context.assertions.set(`stdio-identity:${consent.grant.grantId}`, consent.assertUnchanged);
  }
  const response = await readCanonicalArtifact<ControlApplicationResponseV1>(artifacts, operation.controlResponseRef);
  if (!response.ok || response.result.method !== operation.method ||
      !('registry' in response.result) || canonicalSha256(response.result.registry) !== canonicalSha256(mcpRegistrySummary(registry)) ||
      operation.controlResponseDigest !== canonicalSha256(response))
    invalid('MCP publication has no exact retained first control response');
  const control = readControlRequest(driver, principalId, operation.method, operation.requestId);
  if (!control || control.requestDigest !== operation.requestDigest || control.responseRef !== operation.controlResponseRef ||
      control.committedAt < operation.finishedAt || Date.parse(control.committedAt) < (resources.currentRetirement?.observedAtMs ?? Date.parse(closure.observedAt)) ||
      Date.parse(control.committedAt) - (resources.currentRetirement?.observedAtMs ?? Date.parse(closure.observedAt)) > 5_000)
    invalid('MCP publication lost its original first response or actual fresh control commit interval');
  const responseChannel = await readHistoricalControlChannel(driver, artifacts, { principalId, channelIdentityRef: control.channelIdentityRef,
    channelIdentityDigest: control.channelIdentityDigest });
  const responding = resources.history.entries.find(entry => entry.owner.supervisorInstanceId === operation.supervisorInstanceId);
  if (!responding || responseChannel.channel.openedAt < responding.owner.acquiredAt || responseChannel.channel.openedAt > operation.createdAt ||
      responding.owner.state === 'terminal' && control.committedAt > responding.owner.releasedAt)
    invalid('MCP first response channel/actual commit is outside its exact completing StateOwner');
  if (responseChannel.channel.transport.kind === 'uds_peer') {
    const peer = decodeLocalSocketPeerObservation(await readCanonicalArtifact(artifacts, responseChannel.channel.transport.peerObservationRef));
    if (peer.observedAt < responding.owner.acquiredAt) invalid('MCP first response peer observation predates its completing server owner');
  } else {
    const processIdentity = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, responseChannel.channel.transport.processIdentityRef));
    if (processIdentity.pid !== responding.process.pid || processIdentity.processStartToken !== responding.process.processStartToken ||
        processIdentity.executableImageDigest !== responding.process.executableImageDigest) invalid('MCP first response in-process owner changed');
  }
  const operationSnapshot = canonicalSha256(operation), controlSnapshot = canonicalSha256(control);
  context.assertions.set(reference, connection => {
      const retained = readMcpAdminOperation(connection, principalId, operation.method, operation.requestId, operation.attempt);
      const indexed = readControlRequest(connection, principalId, operation.method, operation.requestId);
      resources.history.assertUnchanged(connection);
      if (!retained || !indexed || canonicalSha256(retained) !== operationSnapshot || canonicalSha256(indexed) !== controlSnapshot)
        throw new KernelStorageError('REVISION_CONFLICT', 'original completed MCP registry provenance changed');
  });
  return { ...immutableSnapshot({ ref: reference, registry, receipt, target, operation, result, closure, tools }),
    assertUnchanged(connection: SqliteConnection) {
      for (const assertion of context.assertions.values()) assertion(connection);
    } };
}

export async function readMcpRegistry(driver: SqliteDriver, artifacts: ArtifactCatalog, principalId: string, registrationId: string) {
  const row = driver.prepare('SELECT current_revision,current_revision_ref FROM mcp_registrations WHERE owner_principal_id=? AND registration_id=?')
    .get<{ current_revision: bigint; current_revision_ref: string }>(principalId, registrationId);
  if (!row) throw new KernelStorageError('NOT_FOUND', 'MCP registration is unavailable');
  const closure = await readMcpRegistryClosure(driver, artifacts, row.current_revision_ref, principalId);
  if (closure.registry.registrationId !== registrationId || closure.registry.registryRevision !== Number(row.current_revision))
    invalid('MCP registry pointer differs from its retained revision');
  return { ref: closure.ref, registry: closure.registry, assertUnchanged(connection: SqliteConnection) {
    closure.assertUnchanged(connection);
    const current = connection.prepare('SELECT current_revision,current_revision_ref FROM mcp_registrations WHERE owner_principal_id=? AND registration_id=?')
      .get<{ current_revision: bigint; current_revision_ref: string }>(principalId, registrationId);
    if (!current || current.current_revision_ref !== row.current_revision_ref || Number(current.current_revision) !== Number(row.current_revision))
      throw new KernelStorageError('REVISION_CONFLICT', 'MCP current registry selection changed before admission');
  } };
}

/** Derivation only. Callers independently authenticate every original registry
 * and signed builtin member before accepting this unsigned combined manifest. */
export function combineMcpToolManifest(builtin: ToolContractManifestV1,
  registries: readonly Readonly<{ ref: string; registry: McpRegistryRevisionV1 }>[]): ToolContractManifestV1 {
  const entries = [...builtin.entries];
  const selected = new Set<string>();
  for (const { ref, registry: value } of registries) {
    const registry = decodeMcpRegistryRevision(value);
    if (selected.has(registry.registrationId) || ref !== canonicalSha256(registry)) throw new TypeError('duplicate or substituted frozen MCP registry');
    selected.add(registry.registrationId);
    for (const tool of registry.tools) {
      entries.push({ name: mcpExposedToolName(registry.registrationId, tool.name), version: tool.version,
        description: mcpExposedToolDescription(registry.registrationId, tool.name, tool.description),
        access: 'exec', inputSchemaRef: tool.inputSchemaRef, inputSchemaDigest: tool.inputSchemaDigest,
        ...(tool.outputSchemaRef ? { outputSchemaRef: tool.outputSchemaRef, outputSchemaDigest: tool.outputSchemaDigest } : {}),
        replayClass: tool.recovery.kind, execution: { kind: 'mcp', registrationId: registry.registrationId,
          registryRevisionRef: ref, registryManifestDigest: registry.manifestDigest, serverToolName: tool.name, toolContractDigest: tool.toolContractDigest } });
    }
  }
  entries.sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));
  if (entries.some((entry, index) => index > 0 && entry.name === entries[index - 1]!.name)) throw new TypeError('frozen MCP tools collide with the original tool manifest');
  const core = { schemaVersion: 1 as const, format: 'cliq-tool-contracts-v1' as const, entries };
  return immutableSnapshot({ ...core, manifestDigest: canonicalSha256(core) });
}

/** Called before real Admin input creation. Only immutable artifacts and the
 * original prepared row are installed; no physical resource is inferred. */
export async function persistPreparedMcpAdminOperation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  request: McpMutationRequestV1, identity: AuthenticatedControlIdentity, value: AdminOperationV1,
  stdioPreparation?: Readonly<{ authorization?: PreparedMcpStdioAuthorization; recipe: PublishedArtifact }>) {
  const operation = decodeAdminOperation(value);
  const liveAuthorization = operation.attempt === 1 ? await validateControlChannelClosure(artifacts, owner, identity) : undefined;
  if (operation.phase !== 'prepared' || operation.principalId !== identity.principalId || operation.method !== request.method ||
      operation.requestId !== request.requestId || operation.requestDigest !== request.requestDigest || operation.rowVersion !== 1)
    throw new TypeError('MCP prepared intent does not belong to its authenticated original request');
  const target = decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, operation.targetRef));
  const historicalAuthorization = operation.attempt > 1 ? await readHistoricalControlChannel(driver, artifacts, { principalId: operation.principalId,
    channelIdentityRef: target.channelIdentityRef, channelIdentityDigest: target.channelIdentityDigest }) : undefined;
  const originalRequest = decodeMcpMutationRequest(await readCanonicalArtifact(artifacts, target.originalRequestRef));
  if (originalRequest.requestDigest !== request.requestDigest || originalRequest.requestId !== request.requestId ||
      originalRequest.method !== request.method || operation.attempt === 1 &&
      (target.channelIdentityRef !== identity.channelIdentityRef || target.channelIdentityDigest !== identity.channelIdentityDigest))
    throw new TypeError('MCP prepared intent lost its original authenticated request/channel provenance');
  assertMcpProfile(target);
  const stdio = target.resolvedTransport.kind === 'stdio';
  const firstConsent = stdio && request.method === 'mcp.register' && operation.attempt === 1;
  if (stdio !== (stdioPreparation !== undefined) || firstConsent !== (stdioPreparation?.authorization !== undefined))
    invalid('MCP stdio first prepared intent requires its original opaque one-use identity authorization and sealed recipe');
  const consentData = stdioPreparation?.authorization ? mcpStdioAuthorizationData(owner, stdioPreparation.authorization) : undefined;
  if (consentData) requireEqual(consentData.transport, target.resolvedTransport, 'MCP first prepared original one-use executable identity');
  const retainedConsent = stdio && !firstConsent ? await readMcpStdioRegistrationConsent(driver, artifacts, operation.principalId,
    target.registrationId, target.resolvedTransport as Extract<McpRegistryRevisionV1['transport'], { kind: 'stdio' }>) : undefined;
  const core = decodeAdminProbePayloadCore(await readCanonicalArtifact(artifacts, operation.probePayloadCoreRef));
  if (target.ownerPrincipalId !== identity.principalId || target.registrationId !== request.registrationId || target.requestCoreDigest !== mcpMutationCoreDigest(request) ||
      target.targetDigest !== operation.targetDigest || core.payloadCoreDigest !== operation.probePayloadCoreDigest)
    throw new TypeError('MCP prepared intent substitutes target or static probe core');
  const members = [[operation.targetRef, target.format], [operation.probePayloadCoreRef, core.format],
    [operation.plannedContainmentRef, 'cliq-process-containment-plan-v1'], [operation.sandboxLaunchSpecRef, 'cliq-sandbox-launch-v1'],
    [target.originalRequestRef, 'cliq-mcp-original-request-v1']] as const;
  const metadata = await artifacts.mapReads(members, ([ref, format]) => artifacts.describe(ref, 'application/json', format));
  for (const item of target.requestedToolRecovery) if (item.recovery.kind === 'retry') {
    metadata.push(await artifacts.describe(item.recovery.explicitRiskConsentRef, 'application/json', 'cliq-mcp-retry-risk-consent-v1'),
      await artifacts.describe(item.recovery.safetyAssertionRef, 'application/json', 'cliq-mcp-retry-safety-assertion-v1'));
  }
  if (originalRequest.method === 'mcp.register') await validateMcpOriginalRequestedRecovery(artifacts, originalRequest, target);
  const prior = readMcpAdminOperation(driver, operation.principalId, operation.method, operation.requestId);
  const priorHistory = prior?.phase === 'failed' ? await readAdminFailureHistory(driver, artifacts, prior) : undefined;
  let outcome: ReturnType<typeof advanceTimeFence> | undefined;
  driver.transaction(connection => {
    const current = assertActiveStateOwner(connection, owner), now = sampleCanonicalNow();
    outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    if (current.supervisorInstanceId !== operation.supervisorInstanceId || now < operation.createdAt || now >= operation.deadlineAt ||
        Date.parse(operation.deadlineAt) - Date.parse(operation.createdAt) !== target.lifecycle.launchTimeoutMs)
      throw new KernelStorageError('LEASE_FENCED', 'MCP prepared owner or original control deadline changed');
    const existing = readMcpAdminOperation(connection, identity.principalId, request.method, request.requestId);
    retainedConsent?.assertUnchanged(connection);
    priorHistory?.assertUnchanged(connection);
    if (operation.attempt > 1 && !priorHistory) invalid('MCP successor attempt has no original positive failure closure');
    if (existing && (operation.attempt !== existing.attempt + 1 || existing.phase !== 'failed' || existing.failureDisposition !== 'retryable_recovery' ||
        existing.targetRef !== operation.targetRef || existing.probePayloadCoreRef !== operation.probePayloadCoreRef || now < existing.retryNotBeforeAt)) {
      if (existing.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'MCP request id names another intent');
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original attempt must be retired and pass its exact backoff before another producer');
    }
    if (stdioPreparation?.authorization) consumeMcpStdioAuthorization(connection, owner, stdioPreparation.authorization, target,
      request.requestId, request.requestDigest, now);
    for (const artifact of [...metadata, ...(liveAuthorization?.metadata ?? historicalAuthorization?.metadata ?? []),
      ...(consentData?.metadata ?? []), ...(stdioPreparation ? [stdioPreparation.recipe] : [])]) insertArtifactMetadata(connection, artifact, now);
    connection.prepare('INSERT INTO admin_operations(principal_id,method,request_id,attempt,state,row_json) VALUES(?,?,?,?,?,?)')
      .run(identity.principalId, request.method, request.requestId, operation.attempt, 'prepared', canonicalJsonBytes(operation).toString('utf8'));
  });
  requireHealthyFence(outcome);
  if (stdioPreparation?.authorization) assertMcpStdioAuthorizationConsumed(driver, owner, stdioPreparation.authorization);
  return operation;
}

async function executeMcpStdioAdminAttempt(input: Readonly<{
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor;
  request: McpMutationRequestV1; identity: AuthenticatedControlIdentity; target: McpAdminProbeTargetV1; targetArtifact: PublishedArtifact;
  core: AdminProbePayloadCoreV1; coreArtifact: PublishedArtifact; runtime: RuntimeBundleManifest; createdAt: string; deadlineAt: string;
  attempt: number; adminOperationId: string; nonce: string; original?: Awaited<ReturnType<typeof readMcpRegistry>>;
  priorClosure?: Awaited<ReturnType<typeof readAdminFailureHistory>>; authorization?: PreparedMcpStdioAuthorization;
  producer: { digest: string; task?: Promise<unknown>; resume?: () => Promise<unknown> }; key: string; signal: AbortSignal;
}>) {
  const { driver, artifacts, owner, selected, anchor, request, identity, target, targetArtifact, core, coreArtifact, runtime,
    createdAt, deadlineAt, attempt, adminOperationId, nonce, original, priorClosure, authorization, producer, key, signal } = input;
  const transport = target.resolvedTransport;
  if (transport.kind !== 'stdio') throw new TypeError('MCP stdio Admin received another frozen transport');
  const consent = authorization ? undefined : await readMcpStdioRegistrationConsent(driver, artifacts, identity.principalId, request.registrationId, transport);
  const launcher = await observeMcpAdminWork('stdio', 'launcher_open', () => openInstalledLinuxWorkerLauncher(selected, anchor, { signal }));
  let controller: LinuxWorkerController;
  try { controller = await observeMcpAdminWork('stdio', 'controller_start', () => launcher.startController({ signal })); }
  catch (error) { await observeMcpAdminWork('stdio', 'launcher_close', () => launcher.close()); throw error; }
  let cgroupParent = ''; withInstalledWorkerRoot(selected, anchor, (_fd, value) => { cgroupParent = value; });
  const nativeAttempt = prepareMcpStdioAdminAttempt({ selected, anchor, controller, owner, artifacts, transport, deadlineMs: Date.parse(deadlineAt), signal });
  let stopping = false, closed: Promise<void> | undefined;
  const resource: AdminResource = { close() { stopping = true; return closed ??= (async () => {
    const failures: unknown[] = [];
    // Unlike HTTP, stdio closes its original pipe owner and waits for the
    // graceful drain/ACK before joining this dedicated controller and launcher.
    try { await observeMcpAdminWork('stdio', 'native_close', () => nativeAttempt.close()); } catch (error) { failures.push(error); }
    try { await observeMcpAdminWork('stdio', 'controller_close', () => controller.close()); } catch (error) { failures.push(error); }
    try { await observeMcpAdminWork('stdio', 'launcher_close', () => launcher.close()); } catch (error) { failures.push(error); }
    if (failures.length) throw new ResourceRetirementError('MCP stdio Admin original resources did not join', new AggregateError(failures));
  })(); } };
  let owners = adminResources.get(driver); if (!owners) adminResources.set(driver, owners = new Set()); owners.add(resource);
  let scope: InstalledMcpStdioAdminScope | undefined, inputBinding: AdminMcpStdioInputBinding | undefined;
  try {
    const nativePreparation = await observeMcpAdminWork('stdio', 'native_prepare', () => nativeAttempt.prepare()); signal.throwIfAborted();
    const launch = await observeMcpAdminWork('stdio', 'plan_publish', () => publishMcpStdioLaunch(artifacts, { purpose: { kind: 'admin', owner: { kind: 'admin_probe',
      adminOperationId, attempt, principalId: identity.principalId, method: request.method, originalRequestDigest: request.requestDigest,
      targetRef: targetArtifact.ref, supervisorInstanceId: owner.supervisorInstanceId },
      targetRef: targetArtifact.ref, targetDigest: target.targetDigest, probePayloadCoreRef: coreArtifact.ref }, bundle: runtime,
      controller, cgroupParent, lock: owner.filesystem,
      executable: transport.executable, nonce, createdAt, resources: DEFAULT_SANDBOX_RESOURCES }));
    const prepared: AdminOperationV1 = { schemaVersion: 1, adminOperationId, principalId: identity.principalId, method: request.method,
      requestId: request.requestId, requestDigest: request.requestDigest, attempt, maxAttempts: 3, deadlineAt, targetRef: targetArtifact.ref,
      targetDigest: target.targetDigest, probePayloadCoreRef: coreArtifact.ref, probePayloadCoreDigest: core.payloadCoreDigest,
      supervisorInstanceId: owner.supervisorInstanceId, plannedContainmentRef: launch.planArtifact.ref, plannedContainmentDigest: launch.plan.planDigest,
      sandboxLaunchSpecRef: launch.specArtifact.ref, sandboxLaunchSpecDigest: launch.spec.launchSpecDigest, rowVersion: 1, createdAt, phase: 'prepared' };
    await observeMcpAdminWork('stdio', 'prepared_write', () => persistPreparedMcpAdminOperation(driver, artifacts, owner, request, identity, prepared,
      { ...(authorization ? { authorization } : {}), recipe: nativePreparation.recipe }));
    priorClosure?.assertUnchanged(driver); consent?.assertUnchanged(driver);
    const current = assertActiveStateOwner(driver, owner), process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, current.processIdentityRef));
    inputBinding = { adminOperationId, attempt, principalId: identity.principalId, nonce, targetRef: prepared.targetRef, targetDigest: prepared.targetDigest,
      probePayloadCoreRef: prepared.probePayloadCoreRef, probePayloadCoreDigest: prepared.probePayloadCoreDigest,
      plannedContainmentRef: prepared.plannedContainmentRef, plannedContainmentDigest: prepared.plannedContainmentDigest,
      sandboxLaunchSpecRef: prepared.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: prepared.sandboxLaunchSpecDigest,
      originalSupervisorPid: process.pid, originalSupervisorStartToken: process.processStartToken };
    signal.throwIfAborted(); scope = nativeAttempt.createScope(inputBinding);
    await observeMcpAdminWork('stdio', 'scope_reserve', () => scope!.reservation()); scope.createBlocked();
    const ready = await observeMcpAdminWork('stdio', 'scope_ready', () => scope!.ready());
    if (launch.plan.backend.kind !== 'linux') throw new TypeError('MCP stdio Admin original native plan is not Linux');
    const containment: ProcessContainment = { schemaVersion: 1, planRef: launch.planArtifact.ref, sandboxLaunchSpecRef: launch.specArtifact.ref,
      sandboxLaunchSpecDigest: launch.spec.launchSpecDigest, owner: launch.plan.owner, filesystemBinding: launch.plan.filesystemBinding,
      launchNonceDigest: launch.plan.launchNonceDigest, backend: { kind: 'linux', pidNamespaceReservationId: launch.plan.backend.pidNamespaceReservationId,
        pidNamespaceId: ready.pidNamespaceId, cgroupPath: launch.plan.backend.cgroupPath, cgroupId: ready.cgroupId,
        namespaceInitStartToken: ready.namespaceInitStartToken, subreaperStartToken: launch.plan.backend.subreaperStartToken }, createdAt: new Date(ready.observedAtMs).toISOString() };
    const containmentArtifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1');
    let active: Extract<AdminOperationV1, { phase: 'active' }> = { ...prepared, phase: 'active', processContainmentRef: containmentArtifact.ref,
      leaseExpiresAt: deadlineAt, probeDispatch: { state: 'blocked' }, rowVersion: 2 };
    const write = (next: AdminOperationV1, previous: AdminOperationV1) => {
      let clock: ReturnType<typeof advanceTimeFence> | undefined;
      driver.transaction(connection => {
        assertActiveStateOwner(connection, owner); nativeAttempt.original().input.assertHeld(); const now = sampleCanonicalNow();
        clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
        consent?.assertUnchanged(connection); if (authorization) assertMcpStdioAuthorizationConsumed(connection, owner, authorization);
        readInstalledMcpStdioAdminReady(scope!, nativeAttempt.original().input);
        if (stopping || now >= deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'MCP stdio Admin original owner/deadline is revoked');
        requireEqual(readMcpAdminOperation(connection, identity.principalId, request.method, request.requestId, attempt), previous, 'MCP stdio exact original Admin transition');
        for (const metadata of [targetArtifact, coreArtifact, launch.planArtifact, launch.specArtifact, containmentArtifact]) insertArtifactMetadata(connection, metadata, now);
        connection.prepare('UPDATE admin_operations SET state=?,row_json=? WHERE principal_id=? AND method=? AND request_id=? AND attempt=?')
          .run(next.phase, canonicalJsonBytes(decodeAdminOperation(next)).toString('utf8'), identity.principalId, request.method, request.requestId, attempt);
      }); requireHealthyFence(clock);
    };
    write(active, prepared);
    const dispatchId = identityHash('cliq-mcp-admin-dispatch-v1', adminOperationId, attempt, nonce), claimedAt = sampleCanonicalNow();
    const probeRequestDigest = adminProbeRequestDigest(active, target, dispatchId);
    const claimed: typeof active = { ...active, rowVersion: 3, probeDispatch: { state: 'claimed', probeRequestDigest, dispatchId, claimedAt } };
    write(claimed, active); active = claimed;
    const binding: AdminMcpStdioBinding = { adminOperationId, attempt, principalId: identity.principalId, method: request.method,
      controlRequestDigest: request.requestDigest, targetRef: prepared.targetRef, targetDigest: prepared.targetDigest,
      probePayloadCoreRef: prepared.probePayloadCoreRef, probePayloadCoreDigest: prepared.probePayloadCoreDigest, probeRequestDigest, dispatchId,
      supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch, processContainmentRef: containmentArtifact.ref,
      plannedContainmentRef: prepared.plannedContainmentRef, plannedContainmentDigest: prepared.plannedContainmentDigest,
      sandboxLaunchSpecRef: prepared.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: prepared.sandboxLaunchSpecDigest, nonce, deadlineMs: Date.parse(deadlineAt) };
    const gate = () => {
      let clock: ReturnType<typeof advanceTimeFence> | undefined;
      driver.transaction(connection => {
        const current = assertActiveStateOwner(connection, owner), now = sampleCanonicalNow(); nativeAttempt.original().input.assertHeld();
        clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
        consent?.assertUnchanged(connection); if (authorization) assertMcpStdioAuthorizationConsumed(connection, owner, authorization);
        if (stopping || now >= deadlineAt || current.supervisorInstanceId !== active.supervisorInstanceId || current.ownerEpoch !== binding.stateOwnerEpoch)
          throw new KernelStorageError('LEASE_FENCED', 'MCP stdio Admin original current claim is revoked');
        requireEqual(readMcpAdminOperation(connection, identity.principalId, request.method, request.requestId, attempt), active, 'MCP stdio original permanent probe gate');
      }); requireHealthyFence(clock);
    };
    const released: typeof active = { ...active, rowVersion: 4, probeDispatch: { state: 'released', probeRequestDigest, dispatchId, claimedAt, releasedAt: sampleCanonicalNow() } };
    write(released, active); active = released;
    const received = await nativeAttempt.bindAndDrive(binding, gate); await resource.close();
    const actual = nativeAttempt.joined(), lifecycle = actual.originalLifecycle;
    if (lifecycle.format !== 'cliq-mcp-stdio-native-lifecycle-v1' || lifecycle.binding.kind !== 'admin')
      invalid('MCP Admin publication cannot borrow a Run or recovery-purpose native lifecycle');
    if (!lifecycle.joined.protocolCompleted || !lifecycle.joined.ownerDrained || lifecycle.joined.responseRefused || !lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired)
      invalid('MCP stdio original Admin probe did not actually finish and join its fixed protocol');
    const finish = async (): Promise<InstalledControlResponseV1> => {
      const published = await received.publish(artifacts, actual.ownerJoined), originalPhysical = nativeAttempt.original();
      const response = await publishMcpAdminDiscovery({ driver, artifacts, owner, request, identity, target, prepared, active, launch, containment,
        containmentArtifact, lifecycleBytes: actual.lifecycleSnapshot, lifecycle, published, ...(original ? { original } : {}),
        physical: { kind: 'stdio', native: originalPhysical.native, binding, scope: originalPhysical.scope, joined: actual.joined, ownerJoined: actual.ownerJoined } });
      nativeAttempt.release(); owners!.delete(resource); adminProducers.get(driver)!.delete(key); return response;
    };
    producer.resume = () => observeMcpAdminWork('stdio', 'discovery_publish', finish); return producer.resume() as Promise<InstalledControlResponseV1>;
  } catch (failure) {
    if (producer.resume) throw failure;
    await resource.close();
    const operation = readMcpAdminOperation(driver, identity.principalId, request.method, request.requestId, attempt);
    if (!operation && !scope) { owners!.delete(resource); throw failure; }
    if (!scope || !inputBinding) throw new ResourceRetirementError('MCP stdio Admin construction lacks its complete original resource birth', failure);
    if (!operation || !['prepared', 'active'].includes(operation.phase)) throw failure;
    const actual = nativeAttempt.joined(), original = nativeAttempt.original();
    let retirement: Awaited<ReturnType<typeof publishAdminRetirement>> | undefined;
    const finish = async (): Promise<InstalledControlResponseV1> => {
      retirement = await publishAdminRetirement(artifacts, owner, driver, operation, actual.lifecycleSnapshot, actual.joined.observation, undefined,
        { binding: inputBinding! }, original.scope);
      const finalized = await finishFailedAdminAttempt(driver, artifacts, owner, operation, retirement, identity, failure instanceof TypeError,
        { kind: 'stdio_original', scope: original.scope, joined: actual.joined });
      nativeAttempt.release(); owners!.delete(resource); producer.resume = undefined;
      if (finalized.failed.phase === 'failed' && finalized.failed.failureDisposition === 'retryable_recovery') throw new McpAdminRetryPending(finalized.failed.retryNotBeforeAt);
      adminProducers.get(driver)!.delete(key); return finalized.response;
    };
    producer.resume = finish; return finish();
  } finally { await resource.close(); if (producer.resume) owners!.delete(resource); }
}

/** One authenticated original producer. A disconnected observer cannot cancel
 * its claimed probe or discard a positively received result. Same-id recovery
 * resumes only this producer's persistence or reads its retained first reply. */
export async function mutateInstalledMcpRegistration(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor, rawRequest: unknown, identity: AuthenticatedControlIdentity, signal: AbortSignal) {
  const request = decodeMcpMutationRequest(rawRequest);
  await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner);
  const priorResponse = readControlRequest(driver, identity.principalId, request.method, request.requestId);
  if (priorResponse) {
    if (priorResponse.requestDigest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'MCP request id names a different original request');
    const response = await readCanonicalArtifact<InstalledControlResponseV1>(artifacts, priorResponse.responseRef);
    await validateControlChannelClosure(artifacts, owner, identity); return response;
  }
  let producers = adminProducers.get(driver); if (!producers) adminProducers.set(driver, producers = new Map());
  const key = canonicalSha256([identity.principalId, request.method, request.requestId]), retained = producers.get(key);
  if (retained) {
    if (retained.digest !== request.requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'MCP request id names another producer');
    if (retained.task) return retained.task as Promise<InstalledControlResponseV1>;
    if (!retained.resume) invalid('original MCP Admin attempt requires physical recovery');
  }
  const producer: { digest: string; task?: Promise<unknown>; resume?: () => Promise<unknown> } = retained ?? { digest: request.requestDigest };
  let initialResume = retained?.resume;
  producers.set(key, producer);
  const executeAttempt = async (): Promise<InstalledControlResponseV1> => {
    const previous = readMcpAdminOperation(driver, identity.principalId, request.method, request.requestId);
    if (previous && (previous.requestDigest !== request.requestDigest || previous.phase !== 'failed' || previous.failureDisposition !== 'retryable_recovery'))
      invalid('original retained MCP Admin attempt must be physically retired before a successor probe');
    if (previous?.phase === 'failed' && previous.failureDisposition === 'retryable_recovery' && sampleCanonicalNow() < previous.retryNotBeforeAt)
      throw new McpAdminRetryPending(previous.retryNotBeforeAt);
    const priorClosure = previous?.phase === 'failed' ? await readAdminFailureHistory(driver, artifacts, previous) : undefined;
    const attempt = (previous?.attempt ?? 0) + 1;
    if (attempt > 3) invalid('MCP original Admin maximum attempts is exhausted');
    const existing = driver.prepare('SELECT current_revision,current_revision_ref FROM mcp_registrations WHERE owner_principal_id=? AND registration_id=?')
      .get<{ current_revision: bigint; current_revision_ref: string }>(identity.principalId, request.registrationId);
    if (request.method === 'mcp.register' && existing) throw new KernelStorageError('REVISION_CONFLICT', 'MCP registration already exists; refresh requires its expected revision');
    const original = request.method === 'mcp.refresh' ? await readMcpRegistry(driver, artifacts, identity.principalId, request.registrationId) : undefined;
    if (request.method === 'mcp.refresh' && original?.registry.registryRevision !== request.expectedRegistryRevision)
      throw new KernelStorageError('REVISION_CONFLICT', 'MCP refresh expected revision changed');
    if (request.method === 'mcp.register' && request.target.kind === 'streamable_http' &&
        (request.target.credentialGrantIds.length > 1 || Object.values(request.toolRecovery).some(value => value.kind === 'reconcile')))
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP HTTP requires at most one credential and cannot borrow a signed stdio status profile');
    const runtime = await withHeldInstalledRuntime(selected, async installed => { await installed.revalidate(signal); return immutableSnapshot(installed.bundle); }, signal);
    let stdioAuthorization: PreparedMcpStdioAuthorization | undefined;
    const retainedTarget = previous ? decodeMcpAdminProbeTarget(await readCanonicalArtifact(artifacts, previous.targetRef)) : undefined;
    let transport: McpAdminProbeTargetV1['resolvedTransport'];
    if (retainedTarget) transport = retainedTarget.resolvedTransport;
    else if (request.method === 'mcp.refresh') transport = original!.registry.transport;
    else if (request.target.kind === 'streamable_http') transport = await resolveInstalledMcpTransport(selected, artifacts, identity.principalId,
      request.target.endpointRegistrationId, request.target.credentialGrantIds, signal);
    else {
      stdioAuthorization = await prepareMcpStdioAuthorization(driver, artifacts, owner, { bundle: runtime, releaseKeys: artifacts.releaseTrustRoots() },
        identity.principalId, request, signal);
      transport = mcpStdioAuthorizationData(owner, stdioAuthorization).transport;
    }
    if (transport.kind === 'streamable_http') {
      if (transport.credentialGrantRefs.length > 1) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP refresh selects multiple retained credentials');
      await withInstalledMcpHttpAuthority(selected, owner, artifacts, identity.principalId, transport,
        async authority => { authority.assertCurrent(); }, signal);
    } else if (!stdioAuthorization) await readMcpStdioRegistrationConsent(driver, artifacts, identity.principalId, request.registrationId, transport);
    const createdAt = sampleCanonicalNow();
    const originalRequestArtifact = retainedTarget ? undefined : await artifacts.publishCanonical(request, 'cliq-mcp-original-request-v1');
    const requestedToolRecovery = retainedTarget?.requestedToolRecovery ?? (request.method === 'mcp.register'
      ? (await publishMcpRequestedRecovery(artifacts, request, identity, createdAt)).requested
      : await mcpRequestedRecoveryFromRegistry(artifacts, original!.registry));
    const target: McpAdminProbeTargetV1 = retainedTarget ?? { schemaVersion: 1, format: 'cliq-mcp-admin-probe-target-v1', ownerPrincipalId: identity.principalId,
      originalRequestRef: originalRequestArtifact!.ref, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
      registrationId: request.registrationId, method: request.method, resolvedTransport: transport, assertStatelessPerCall: true,
      requestedToolRecovery,
      lifecycle: request.method === 'mcp.register' ? normalizeMcpLifecycle(request.lifecycle) : original!.registry.lifecycle,
      requestCoreDigest: mcpMutationCoreDigest(request), targetDigest: '', createdAt,
      ...(request.method === 'mcp.refresh' ? { expectedRegistryRevision: request.expectedRegistryRevision, sourceRegistryRevisionRef: original!.ref } : {}) };
    if (!retainedTarget) (target as { targetDigest: string }).targetDigest = digestOmitting(target, 'targetDigest'); assertMcpProfile(target);
    const deadlineAt = new Date(Date.parse(createdAt) + target.lifecycle.launchTimeoutMs).toISOString();
    const targetArtifact = await artifacts.publishCanonical(target, target.format);
    const helper = runtime.entries.find(entry => entry.entryId === (transport.kind === 'stdio' ? 'linux_worker_controller' : MCP_ADMIN_HELPER_ENTRY_ID));
    if (!helper || helper.role !== 'platform_helper' || helper.version !== '1' || (transport.kind === 'stdio' ? !helper.executable : helper.executable || helper.relativePath !== MCP_ADMIN_HELPER_RELATIVE_PATH))
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'fixed signed MCP Admin helper is unavailable');
    if (transport.kind === 'streamable_http') await retainInstalledMcpAdminRecipe(selected, signal);
    const core: AdminProbePayloadCoreV1 = previous ? decodeAdminProbePayloadCore(await readCanonicalArtifact(artifacts, previous.probePayloadCoreRef)) : { schemaVersion: 1, format: 'cliq-admin-probe-payload-core-v1', probeKind: transport.kind === 'stdio' ? 'mcp_stdio' : 'mcp_streamable_http',
      runtimeBundleRef: canonicalSha256(runtime), runtimeBundleManifestDigest: runtime.manifestDigest, adapterExecutableId: helper.entryId,
      adapterVersion: helper.version, adapterExecutableDigest: helper.digest, protocolRecipe: 'mcp-initialize-capabilities-tools-list-v1',
      maximumResponseBytes: 1_048_576, payloadCoreDigest: '' };
    if (!previous) (core as { payloadCoreDigest: string }).payloadCoreDigest = digestOmitting(core, 'payloadCoreDigest');
    if (core.runtimeBundleRef !== canonicalSha256(runtime) || core.runtimeBundleManifestDigest !== runtime.manifestDigest ||
        core.adapterExecutableDigest !== helper.digest || core.adapterExecutableId !== helper.entryId || core.adapterVersion !== helper.version)
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'MCP recovery requires its original immutable signed Admin recipe');
    const coreArtifact = await artifacts.publishCanonical(core, core.format), nonce = randomBytes(32).toString('hex');
    const adminOperationId = identityHash('cliq-mcp-admin-operation-v1', identity.principalId, request.method, request.requestId, request.requestDigest, target.targetDigest);
    if (transport.kind === 'stdio') return executeMcpStdioAdminAttempt({ driver, artifacts, owner, selected, anchor, request, identity, target,
      targetArtifact, core, coreArtifact, runtime, createdAt, deadlineAt, attempt, adminOperationId, nonce,
      ...(original ? { original } : {}), ...(priorClosure ? { priorClosure } : {}), ...(stdioAuthorization ? { authorization: stdioAuthorization } : {}), producer, key, signal });
    signal.throwIfAborted();
    const launcher = await openInstalledLinuxWorkerLauncher(selected, anchor, { signal });
    let controller: LinuxWorkerController;
    try { controller = await launcher.startController({ signal }); } catch (error) { await launcher.close(); throw error; }
    let cgroupParent = ''; withInstalledWorkerRoot(selected, anchor, (_fd, value) => { cgroupParent = value; });
    let native: NativeMcpAdminHttpOwner | undefined, scope: Awaited<ReturnType<typeof openInstalledMcpHttpAdminScope>> | undefined;
    let physicalInput: ReturnType<typeof openAdminMcpInput> | undefined, closed: Promise<void> | undefined, stopping = false, domainRetained = false;
    const resource: AdminResource = { close() {
      stopping = true;
      return closed ??= (async () => {
        // This attempt created its own controller above. Revoke its channel
        // together with the native owner so an outstanding READY request is
        // interrupted now, rather than after the scope's Stop2 join expires.
        const failures: unknown[] = [];
        const joins: Promise<unknown>[] = [];
        try { if (native) joins.push(native.close()); } catch (error) { failures.push(error); }
        try { joins.push(controller.close()); } catch (error) { failures.push(error); }
        for (const result of await Promise.allSettled(joins)) if (result.status === 'rejected') failures.push(result.reason);
        // The original scope's JS receivers remain fenced while controller
        // cleanup is pending. Observe/assert it only after the actual join;
        // native completion must retain its original birth/ACK/input custody.
        try { await scope?.close(); } catch (error) { failures.push(error); }
        try { await launcher.close(); } catch (error) { failures.push(error); }
        if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
          new ResourceRetirementError('MCP original Admin owner did not completely join', new AggregateError(failures));
      })();
    } };
    let owners = adminResources.get(driver); if (!owners) adminResources.set(driver, owners = new Set()); owners.add(resource);
    try {
      const launch = await publishMcpAdminLaunch(artifacts, owner, controller, cgroupParent, runtime, target, targetArtifact.ref, core, coreArtifact.ref,
        adminOperationId, request.requestDigest, attempt, nonce, createdAt);
      const prepared: AdminOperationV1 = { schemaVersion: 1, adminOperationId, principalId: identity.principalId, method: request.method,
        requestId: request.requestId, requestDigest: request.requestDigest, attempt, maxAttempts: 3, deadlineAt, targetRef: targetArtifact.ref,
        targetDigest: target.targetDigest, probePayloadCoreRef: coreArtifact.ref, probePayloadCoreDigest: core.payloadCoreDigest,
        supervisorInstanceId: owner.supervisorInstanceId, plannedContainmentRef: launch.planArtifact.ref, plannedContainmentDigest: launch.plan.planDigest,
        sandboxLaunchSpecRef: launch.specArtifact.ref, sandboxLaunchSpecDigest: launch.spec.launchSpecDigest, rowVersion: 1, createdAt, phase: 'prepared' };
      await persistPreparedMcpAdminOperation(driver, artifacts, owner, request, identity, prepared);
      priorClosure?.assertUnchanged(driver);
      const inputBinding: AdminMcpInputBinding = { adminOperationId, attempt, principalId: identity.principalId, nonce,
        targetRef: prepared.targetRef, targetDigest: prepared.targetDigest, probePayloadCoreRef: prepared.probePayloadCoreRef,
        probePayloadCoreDigest: prepared.probePayloadCoreDigest, plannedContainmentRef: prepared.plannedContainmentRef,
        plannedContainmentDigest: prepared.plannedContainmentDigest, sandboxLaunchSpecRef: prepared.sandboxLaunchSpecRef,
        sandboxLaunchSpecDigest: prepared.sandboxLaunchSpecDigest };
      // The first Admin-specific physical creation is AFTER prepared commit.
      signal.throwIfAborted(); physicalInput = openAdminMcpInput(owner.filesystem, inputBinding);
      const frames = [mcpInitializeRequestData(1, '0.15.0'), mcpInitializedNotificationData(), mcpToolsListRequestData(2)];
      const config = canonicalJsonBytes({ nonce, recipe: frames.map(frame => ({ phase: frame.phase, bodyJson: frame.json })) });
      scope = await openInstalledMcpHttpAdminScope(selected, anchor, controller, owner.filesystem, physicalInput, inputBinding, launch.toolchain, config, { signal });
      await scope.reservation(); scope.createBlocked(); const ready = await scope.ready();
      const containment: ProcessContainment = { schemaVersion: 1, planRef: launch.planArtifact.ref, sandboxLaunchSpecRef: launch.specArtifact.ref,
        sandboxLaunchSpecDigest: launch.spec.launchSpecDigest, owner: launch.plan.owner, filesystemBinding: launch.plan.filesystemBinding,
        launchNonceDigest: launch.plan.launchNonceDigest, backend: { kind: 'linux', pidNamespaceReservationId: `cliq-mcp-admin-pidns:${nonce}`,
          pidNamespaceId: ready.pidNamespaceId, cgroupPath: `${cgroupParent}/cliq-mcp-admin-${nonce}`, cgroupId: ready.cgroupId,
          namespaceInitStartToken: ready.namespaceInitStartToken, subreaperStartToken: controller.subreaperStartToken }, createdAt: new Date(ready.observedAtMs).toISOString() };
      const containmentArtifact = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1');
      let active: Extract<AdminOperationV1, { phase: 'active' }> = { ...prepared, phase: 'active', processContainmentRef: containmentArtifact.ref,
        leaseExpiresAt: deadlineAt, probeDispatch: { state: 'blocked' }, rowVersion: 2 };
      const write = (next: AdminOperationV1, previous: AdminOperationV1) => {
        let clock: ReturnType<typeof advanceTimeFence> | undefined;
        driver.transaction(connection => {
          assertActiveStateOwner(connection, owner); physicalInput!.assertHeld(); const now = sampleCanonicalNow();
          clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
          if (stopping || now >= deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'MCP Admin original deadline or owner is revoked');
          requireEqual(readMcpAdminOperation(connection, identity.principalId, request.method, request.requestId, attempt), previous, 'MCP original Admin transition');
          for (const metadata of [targetArtifact, coreArtifact, launch.planArtifact, launch.specArtifact, containmentArtifact]) insertArtifactMetadata(connection, metadata, now);
          connection.prepare('UPDATE admin_operations SET state=?,row_json=? WHERE principal_id=? AND method=? AND request_id=? AND attempt=?')
            .run(next.phase, canonicalJsonBytes(decodeAdminOperation(next)).toString('utf8'), identity.principalId, request.method, request.requestId, attempt);
        }); requireHealthyFence(clock);
      };
      write(active, prepared);
      const broker = await loadInstalledMcpHttpBroker(selected, signal);
      const trust = await readCanonicalArtifact<import('../kernel/credential-authority.js').EndpointRegistrationV1>(artifacts, transport.endpointRegistrationRef);
      const trustStoreBytes = await artifacts.readBytes(trust.tls.trustStoreRef);
      return await withInstalledMcpHttpAuthority(selected, owner, artifacts, identity.principalId, transport, async authority => {
        const remaining = Date.parse(deadlineAt) - Date.parse(sampleCanonicalNow()); if (remaining <= 0) throw new KernelStorageError('LEASE_FENCED', 'MCP original control deadline expired');
        native = broker.prepareAdminHttp({ authentication: authority.authentication, target: { hostAscii: trust.target.hostAscii, port: trust.target.port,
          path: trust.target.basePath, serverNameAscii: trust.tls.serverNameAscii, spkiSha256Pins: trust.tls.spkiSha256Pins }, trustStoreBytes,
          trustStoreDigest: trust.tls.trustStoreDigest, maximumResponseBytes: core.maximumResponseBytes, remainingDeadlineMs: remaining,
          recipe: frames.map(frame => ({ phase: frame.phase, bodyBytes: Buffer.from(frame.json), bodyBytesDigest: frame.digest })) });
        await native.ready; native.retainDomain(); domainRetained = true; native.attachProtocolPeer(scope!.peer);
        const dispatchId = identityHash('cliq-mcp-admin-dispatch-v1', adminOperationId, attempt, nonce), claimedAt = sampleCanonicalNow();
        const probeRequestDigest = adminProbeRequestDigest(active, target, dispatchId);
        const claimed: typeof active = { ...active, rowVersion: 3, probeDispatch: { state: 'claimed', probeRequestDigest, dispatchId, claimedAt } };
        authority.assertCurrent(); write(claimed, active); active = claimed;
        const binding: AdminMcpHttpBinding = { adminOperationId, attempt, principalId: identity.principalId, method: request.method,
          controlRequestDigest: request.requestDigest, targetRef: prepared.targetRef, targetDigest: prepared.targetDigest,
          probePayloadCoreRef: prepared.probePayloadCoreRef, probePayloadCoreDigest: prepared.probePayloadCoreDigest, probeRequestDigest, dispatchId,
          supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch, processContainmentRef: containmentArtifact.ref,
          plannedContainmentRef: prepared.plannedContainmentRef, plannedContainmentDigest: prepared.plannedContainmentDigest,
          sandboxLaunchSpecRef: prepared.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: prepared.sandboxLaunchSpecDigest, deadlineMs: Date.parse(deadlineAt) };
        native.bind(binding);
        const gate = () => {
          authority.assertCurrent(); physicalInput!.assertHeld();
          let clock: ReturnType<typeof advanceTimeFence> | undefined;
          driver.transaction(connection => {
            const current = assertActiveStateOwner(connection, owner), now = sampleCanonicalNow();
            clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
            if (stopping || now >= deadlineAt || current.supervisorInstanceId !== active.supervisorInstanceId || current.ownerEpoch !== binding.stateOwnerEpoch)
              throw new KernelStorageError('LEASE_FENCED', 'MCP Admin current owner or original deadline is revoked');
            requireEqual(readMcpAdminOperation(connection, identity.principalId, request.method, request.requestId, attempt), active, 'MCP current original permanent Admin dispatch');
          }); requireHealthyFence(clock);
        };
        const released: typeof active = { ...active, rowVersion: 4, probeDispatch: { state: 'released', probeRequestDigest, dispatchId, claimedAt, releasedAt: sampleCanonicalNow() } };
        authority.assertCurrent(); write(released, active); active = released; gate(); scope!.releaseRecipe(binding);
        const received = await driveMcpAdminProtocol(native, binding, gate);
        await resource.close(); const joined = await scope!.close(), lifecycleBytes = scope!.lifecycleSnapshot();
        const lifecycle = decodeAdminMcpLifecycleData(lifecycleBytes); requireEqual(lifecycle.binding, inputBinding, 'MCP actual original native birth binding');
        if (!lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired || !lifecycle.joined.protocolCompleted)
          invalid('MCP actual Admin native lifecycle did not complete and join its original helper protocol');
        physicalInput!.close();
        const finish = async (): Promise<InstalledControlResponseV1> => {
          const published = await received.publish(artifacts);
          const response = await publishMcpAdminDiscovery({ driver, artifacts, owner, request, identity, target, prepared, active, launch,
            containment, containmentArtifact, lifecycleBytes, lifecycle, published, ...(original ? { original } : {}),
            physical: { kind: 'http', native: native!, binding, scope: scope!, joined, ownerJoined: published.joined } });
          native!.releaseDomain(); owners!.delete(resource); producers!.delete(key); return response;
        };
        producer.resume = finish; return finish();
      }, signal);
    } catch (failure) {
      // A received successful probe already owns its fixed persistence
      // continuation. Storage refusal cannot turn it into another probe.
      if (producer.resume) throw failure;
      await resource.close();
      if (!scope) throw new ResourceRetirementError('MCP Admin construction has no complete original birth/retirement witness', failure);
      const originalOperation = readMcpAdminOperation(driver, identity.principalId, request.method, request.requestId, attempt);
      if (!originalOperation || !['prepared', 'active'].includes(originalOperation.phase)) throw failure;
      const joined = await scope.close(), lifecycleBytes = scope.lifecycleSnapshot();
      let retirement: Awaited<ReturnType<typeof publishAdminRetirement>> | undefined;
      const finishFailure = async (): Promise<InstalledControlResponseV1> => {
        retirement = await publishAdminRetirement(artifacts, owner, driver, originalOperation, lifecycleBytes, joined.observation, undefined, undefined, scope);
        const finalized = await finishFailedAdminAttempt(driver, artifacts, owner, originalOperation, retirement, identity, failure instanceof TypeError,
          { kind: 'original', scope: scope!, joined });
        if (domainRetained) { native!.releaseDomain(); domainRetained = false; }
        physicalInput!.close(); owners!.delete(resource); producer.resume = undefined;
        if (finalized.failed.phase === 'failed' && finalized.failed.failureDisposition === 'retryable_recovery')
          throw new McpAdminRetryPending(finalized.failed.retryNotBeforeAt);
        producers!.delete(key); return finalized.response;
      };
      producer.resume = finishFailure; return finishFailure();
    } finally {
      await resource.close();
      // A missing/partial original birth remains retained for physical
      // recovery. Closing a JS handle cannot manufacture a no-spawn proof.
      if (producer.resume) owners!.delete(resource);
    }
  };
  const work = (async () => { for (;;) { try {
    if (initialResume) { const resume = initialResume; initialResume = undefined; return await resume() as InstalledControlResponseV1; }
    return await executeAttempt();
  } catch (error) {
    if (!(error instanceof McpAdminRetryPending)) throw error;
    await delay(Math.max(0, Date.parse(error.retryAt) - Date.now()), undefined, { signal });
  } } })();
  producer.task = work;
  try { return await work; } finally {
    producer.task = undefined;
    const operation = readMcpAdminOperation(driver, identity.principalId, request.method, request.requestId);
    // A refusal before prepared intent publishes no resource/no-spawn fact.
    // A positively retired failed row can be rejoined by the next fresh
    // authenticated frame; only a live/partial original birth stays fenced.
    if (!producer.resume && (!operation || operation.phase === 'failed') && producers.get(key) === producer) producers.delete(key);
  }
}
