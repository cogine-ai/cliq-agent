// One fixed publication transaction shared by the genuine HTTP and stdio
// Admin consumers. Each branch repeats its own native opaque custody assertion.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeMcpInitializeResult, decodeMcpToolsListResult, decodeMcpRegistryRevision, decodeAdminOperation, mcpRegistrySummary,
  type McpAdminProbeResultV1, type AdminProbeClosureEvidenceV1, type McpRegistrationReceiptV1, type AdminOperationV1,
  type McpMutationRequestV1, type McpAdminProbeTargetV1, type McpRegistryRevisionV1 } from '../kernel/mcp.js';
import type { McpHttpCaptureV1 } from '../kernel/mcp.js';
import type { McpStdioCaptureV1 } from '../kernel/mcp-stdio.js';
import type { ProcessContainment, ProcessContainmentPlanV1, ProcessContainmentDeathEvidenceV1, SandboxLaunchSpecV1 } from '../kernel/types.js';
import type { InstalledControlResponseV1 } from '../kernel/control-wire.js';
import type { McpInboundMessageData } from '../kernel/mcp-wire.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow, advanceTimeFence } from './canonical-time.js';
import type { AuthenticatedControlIdentity } from './control-channel.js';
import { KernelStorageError } from './errors.js';
import { readMcpAdminOperation } from './mcp-registration.js';
import { requireHealthyFence } from './reducers/invocation.js';
import { insertControlRequest } from './rows.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { assertInstalledMcpAdminJoined } from './mcp-native-binding.js';
import { assertInstalledMcpStdioAdminJoined } from './mcp-stdio-native-binding.js';
import type { AdminMcpHttpBinding, NativeMcpAdminHttpOwner, NativeMcpAdminJoined } from './mcp-broker-native.js';
import type { AdminMcpStdioBinding, NativeMcpStdioAdminOwner, NativeMcpStdioAdminJoined } from './mcp-stdio-broker-native.js';
import type { InstalledMcpHttpAdminScope, McpAdminPhysicalJoined } from '../sandbox/mcp-http-admin-native.js';
import type { InstalledMcpStdioAdminScope, McpStdioPhysicalJoined } from '../sandbox/mcp-stdio-native.js';
import type { AdminMcpNativeLifecycle } from './native-owner.js';
import { decodeAdminMcpLifecycleData, decodeMcpStdioLifecycleData, stateRootIdentityForLock } from './native-owner.js';
import { publishMcpAdminCurrentRetirement } from './mcp-admin-current-retirement.js';
import { deriveMcpRecoveryToolContracts } from './mcp-recovery-contract.js';
import type { McpStdioNativeLifecycle } from './mcp-stdio-lifecycle.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

type Physical = Readonly<{ kind: 'http'; native: NativeMcpAdminHttpOwner; ownerJoined: NativeMcpAdminJoined;
  binding: AdminMcpHttpBinding; scope: InstalledMcpHttpAdminScope; joined: McpAdminPhysicalJoined }> |
  Readonly<{ kind: 'stdio'; native: NativeMcpStdioAdminOwner; ownerJoined: NativeMcpStdioAdminJoined;
    binding: AdminMcpStdioBinding; scope: InstalledMcpStdioAdminScope; joined: McpStdioPhysicalJoined }>;
type Capture = Readonly<{ captureRef: string; descriptor: McpHttpCaptureV1 | McpStdioCaptureV1;
  response: Extract<McpInboundMessageData, { kind: 'result' | 'error' }> }>;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export async function publishMcpAdminDiscovery(input: Readonly<{
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; request: McpMutationRequestV1; identity: AuthenticatedControlIdentity;
  target: McpAdminProbeTargetV1; prepared: AdminOperationV1; active: Extract<AdminOperationV1, { phase: 'active' }>;
  launch: Readonly<{ plan: ProcessContainmentPlanV1; planArtifact: PublishedArtifact; spec: SandboxLaunchSpecV1; specArtifact: PublishedArtifact }>;
  containment: ProcessContainment; containmentArtifact: PublishedArtifact; lifecycleBytes: Buffer;
  lifecycle: AdminMcpNativeLifecycle | McpStdioNativeLifecycle; physical: Physical;
  published: Readonly<{ captures: Readonly<{ get(phase: 'initialize' | 'tools_list'): Capture | undefined }>; metadata: PublishedArtifact[] }>;
  original?: Readonly<{ registry: McpRegistryRevisionV1; assertUnchanged(connection: SqliteConnection): void }>;
}>) {
  const { driver, artifacts, owner, request, identity, target, prepared, active, launch, containment, containmentArtifact,
    lifecycleBytes, lifecycle, physical, published, original } = input;
  if (active.probeDispatch.state !== 'released') invalid('MCP original publication has no released permanent Admin claim');
  const { dispatchId, probeRequestDigest } = active.probeDispatch, { adminOperationId, attempt } = prepared;
  const transport = target.resolvedTransport, joined = physical.joined;
  const bound = physical.binding;
  if (bound.adminOperationId !== prepared.adminOperationId || bound.attempt !== prepared.attempt || bound.principalId !== identity.principalId ||
      bound.method !== request.method || bound.controlRequestDigest !== request.requestDigest || bound.targetRef !== prepared.targetRef ||
      bound.targetDigest !== prepared.targetDigest || bound.probePayloadCoreRef !== prepared.probePayloadCoreRef ||
      bound.probePayloadCoreDigest !== prepared.probePayloadCoreDigest || bound.processContainmentRef !== containmentArtifact.ref ||
      bound.plannedContainmentRef !== prepared.plannedContainmentRef || bound.plannedContainmentDigest !== prepared.plannedContainmentDigest ||
      bound.sandboxLaunchSpecRef !== prepared.sandboxLaunchSpecRef || bound.sandboxLaunchSpecDigest !== prepared.sandboxLaunchSpecDigest ||
      bound.supervisorInstanceId !== active.supervisorInstanceId || bound.stateOwnerEpoch !== owner.ownerEpoch ||
      bound.dispatchId !== dispatchId || bound.probeRequestDigest !== probeRequestDigest || bound.deadlineMs !== Date.parse(prepared.deadlineAt) ||
      canonicalSha256(containment) !== containmentArtifact.ref || canonicalSha256(launch.plan) !== prepared.plannedContainmentRef ||
      canonicalSha256(launch.spec) !== prepared.sandboxLaunchSpecRef || canonicalSha256(target) !== prepared.targetRef ||
      target.registrationId !== request.registrationId || canonicalSha256(request) !== target.originalRequestRef)
    invalid('MCP publication substitutes its actual original bound native operation/plan/containment');
  if (!lifecycleBytes.equals(physical.scope.lifecycleSnapshot())) invalid('MCP publication substitutes its original opaque native lifecycle bytes');
  requireEqual(lifecycle, physical.kind === 'http' ? decodeAdminMcpLifecycleData(lifecycleBytes) : decodeMcpStdioLifecycleData(lifecycleBytes),
    'MCP publication exact original native byte projection');
  const initialize = published.captures.get('initialize')!, listed = published.captures.get('tools_list')!;
  const rawDigest = (capture: Capture) => capture.descriptor.format === 'cliq-mcp-http-capture-v1'
    ? capture.descriptor.rawFinitePrefixDigest : capture.descriptor.rawResponseRef;
  if (initialize.response.kind !== 'result' || listed.response.kind !== 'result') invalid('MCP original discovery was rejected');
  const negotiation = decodeMcpInitializeResult(initialize.response.result), discovered = decodeMcpToolsListResult(listed.response.result);
  const schemaMetadata: PublishedArtifact[] = [];
  for (const tool of discovered) { schemaMetadata.push(await artifacts.publishCanonical(tool.inputSchema, 'cliq-mcp-tool-input-schema-v1'));
    if (tool.outputSchema) schemaMetadata.push(await artifacts.publishCanonical(tool.outputSchema, 'cliq-mcp-tool-output-schema-v1')); }
  const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner)), inspectorArtifact = await artifacts.publishCanonical(inspector, inspector.format);
  const observedAt = new Date(joined.observation.observedAtMs).toISOString();
  const death: ProcessContainmentDeathEvidenceV1 = { schemaVersion: 1, kind: 'containment_all_descendants_dead', containmentRef: containmentArtifact.ref,
    planRef: launch.planArtifact.ref, sandboxLaunchSpecRef: launch.specArtifact.ref, sandboxLaunchSpecDigest: launch.spec.launchSpecDigest,
    owner: launch.plan.owner, launchNonceDigest: launch.plan.launchNonceDigest, inspectorSupervisorInstanceId: owner.supervisorInstanceId,
    inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    backend: { ...containment.backend as Extract<ProcessContainment['backend'], {kind:'linux'}>, cgroupPopulated: 0,
      namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, observedAt, evidenceDigest: '' };
  death.evidenceDigest = digestOmitting(death, 'evidenceDigest'); const deathArtifact = await artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1');
  const lifecycleArtifact = await artifacts.publishBytes(lifecycleBytes, 'application/octet-stream', physical.kind === 'stdio' ? 'cliq-mcp-stdio-native-lifecycle-bytes-v1' : 'cliq-mcp-admin-native-lifecycle-bytes-v1');
  const lifecycleProjection = await artifacts.publishCanonical(lifecycle, lifecycle.format);
  const currentOwner = assertActiveStateOwner(driver, owner), rootIdentity = stateRootIdentityForLock(owner.filesystem);
  const currentRetirement = await publishMcpAdminCurrentRetirement(artifacts, physical.scope, lifecycleBytes, lifecycle, {
    supervisorInstanceId: currentOwner.supervisorInstanceId, stateOwnerEpoch: currentOwner.ownerEpoch,
    pid: lifecycle.originalSupervisor.pid, processStartToken: lifecycle.originalSupervisor.processStartToken, acquiredAt: currentOwner.acquiredAt,
    stateRootIdentity: { deviceId: rootIdentity.deviceId, fileId: rootIdentity.directoryFileId, ownerUid: rootIdentity.ownerUid } });
  const closure: AdminProbeClosureEvidenceV1 = { schemaVersion: 1, format: 'cliq-admin-probe-closure-evidence-v1', adminOperationId, attempt,
    targetRef: prepared.targetRef, targetDigest: prepared.targetDigest, plannedContainmentRef: prepared.plannedContainmentRef,
    plannedContainmentDigest: prepared.plannedContainmentDigest, sandboxLaunchSpecRef: prepared.sandboxLaunchSpecRef,
    sandboxLaunchSpecDigest: prepared.sandboxLaunchSpecDigest, inspectorIdentityRef: inspectorArtifact.ref, inspectorIdentityDigest: inspector.identityDigest,
    observedAt, closureKind: 'containment_dead', processContainmentRef: containmentArtifact.ref, dispatchId, probeRequestDigest,
    deathEvidenceRef: deathArtifact.ref, deathEvidenceDigest: death.evidenceDigest, nativeLifecycleRef: lifecycleArtifact.ref,
    nativeLifecycleDigest: lifecycleArtifact.ref, nativeLifecycleProjectionRef: lifecycleProjection.ref, nativeLifecycleProjectionDigest: lifecycleProjection.ref,
    nativeCurrentRetirement: currentRetirement.edge, evidenceDigest: '' };
  (closure as {evidenceDigest:string}).evidenceDigest = digestOmitting(closure, 'evidenceDigest');
  const closureArtifact = await artifacts.publishCanonical(closure, closure.format), completedAt = observedAt;
  const result: McpAdminProbeResultV1 = { schemaVersion: 1, format: 'cliq-mcp-admin-probe-result-v1', adminOperationId, attempt, dispatchId,
    probeRequestDigest, targetRef: prepared.targetRef, targetDigest: prepared.targetDigest, probePayloadCoreRef: prepared.probePayloadCoreRef,
    probePayloadCoreDigest: prepared.probePayloadCoreDigest, processContainmentRef: containmentArtifact.ref,
    initializeResponseRef: initialize.descriptor.rawResponseRef, initializeResponseDigest: rawDigest(initialize),
    capabilityResponseRef: initialize.descriptor.rawResponseRef, capabilityResponseDigest: rawDigest(initialize),
    toolsListResponseRef: listed.descriptor.rawResponseRef, toolsListResponseDigest: rawDigest(listed),
    initializeCaptureRef: initialize.captureRef, toolsListCaptureRef: listed.captureRef, initializeDigest: negotiation.initializeDigest,
    capabilityDigest: negotiation.capabilityDigest, normalizedTools: discovered.map(item => item.interface),
    probedToolsListDigest: canonicalSha256(discovered.map(item => item.interface)), completedAt, resultDigest: '' };
  (result as {resultDigest:string}).resultDigest = digestOmitting(result, 'resultDigest'); const resultArtifact = await artifacts.publishCanonical(result, result.format);
  const revision = (original?.registry.registryRevision ?? 0) + 1;
  const derived = await deriveMcpRecoveryToolContracts(artifacts, { target, targetRef: prepared.targetRef,
    result, resultRef: resultArtifact.ref, probePayloadCoreRef: prepared.probePayloadCoreRef, registryRevision: revision });
  const recoveryMetadata: PublishedArtifact[] = [];
  for (const template of derived.templates) recoveryMetadata.push(await artifacts.publishCanonical(template, template.format));
  const tools = derived.tools, finishedAt = sampleCanonicalNow();
  const registryCore = { schemaVersion: 1 as const, format: 'cliq-mcp-registry-v1' as const, registrationId: request.registrationId,
    registryRevision: revision, ownerPrincipalId: identity.principalId, transport, initializeDigest: negotiation.initializeDigest,
    capabilityDigest: negotiation.capabilityDigest, probedToolsListDigest: result.probedToolsListDigest, toolsListDigest: canonicalSha256(tools),
    stateModel: 'stateless_per_call' as const, tools, lifecycle: target.lifecycle, createdAt: finishedAt };
  const receipt: McpRegistrationReceiptV1 = { schemaVersion: 1, format: 'cliq-mcp-registration-receipt-v1', registrationId: request.registrationId,
    registryRevision: revision, ownerPrincipalId: identity.principalId, requestDigest: request.requestDigest, adminOperationId, adminAttempt: attempt,
    dispatchId, probeRequestDigest, adminProbeTargetRef: prepared.targetRef, adminProbeTargetDigest: prepared.targetDigest,
    probeResultRef: resultArtifact.ref, probeResultDigest: result.resultDigest, probeClosureEvidenceRef: closureArtifact.ref,
    probeClosureEvidenceDigest: closure.evidenceDigest, initializeDigest: negotiation.initializeDigest, capabilityDigest: negotiation.capabilityDigest,
    probedToolsListDigest: result.probedToolsListDigest, toolsListDigest: registryCore.toolsListDigest,
    registryCoreDigest: canonicalSha256(registryCore), createdAt: finishedAt, receiptDigest: '' };
  (receipt as {receiptDigest:string}).receiptDigest = digestOmitting(receipt, 'receiptDigest'); const receiptArtifact = await artifacts.publishCanonical(receipt, receipt.format);
  const registryValue = { ...registryCore, registrationReceiptRef: receiptArtifact.ref, manifestDigest: '' };
  registryValue.manifestDigest = digestOmitting(registryValue, 'manifestDigest'); const registry = decodeMcpRegistryRevision(registryValue);
  const registryArtifact = await artifacts.publishCanonical(registry, registry.format);
  const response: Extract<InstalledControlResponseV1,{ok:true}> = { protocolVersion: 1, ok: true, result: { method: request.method, registry: mcpRegistrySummary(registry) } };
  const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
  const completed: AdminOperationV1 = { ...active, phase: 'completed', probeDispatch: active.probeDispatch,
    resultRef: resultArtifact.ref, resultDigest: result.resultDigest, evidenceRef: closureArtifact.ref, evidenceDigest: closure.evidenceDigest,
    controlResponseRef: responseArtifact.ref, controlResponseDigest: responseArtifact.ref, finishedAt };
  // The lifecycle closes first. One original transaction publishes the
  // completed attempt, immutable revision pointer and first response.
  let clock: ReturnType<typeof advanceTimeFence> | undefined;
  driver.transaction(connection => {
    assertActiveStateOwner(connection, owner);
    if (physical.kind === 'http') { assertInstalledMcpAdminJoined(physical.native, physical.ownerJoined, physical.binding); physical.scope.assertJoined(physical.joined); }
    else { assertInstalledMcpStdioAdminJoined(physical.native, physical.ownerJoined, physical.binding); physical.scope.assertJoined(physical.joined); }
    currentRetirement.assertCurrent();
    const now = sampleCanonicalNow();
    clock = advanceTimeFence(connection, owner.ownerEpoch, now); if (clock !== 'healthy') return;
    requireEqual(readMcpAdminOperation(connection, identity.principalId, request.method, request.requestId, attempt), active, 'MCP original completed Admin claim');
    original?.assertUnchanged(connection);
    const current = connection.prepare('SELECT current_revision FROM mcp_registrations WHERE owner_principal_id=? AND registration_id=?')
      .get<{current_revision:bigint}>(identity.principalId, request.registrationId);
    if ((current ? Number(current.current_revision) : 0) !== revision - 1 || now < finishedAt)
      throw new KernelStorageError('REVISION_CONFLICT', 'MCP registry revision changed before immutable publication');
    if (Date.parse(now) < currentRetirement.current.observedAtMs || Date.parse(now) - currentRetirement.current.observedAtMs > 5_000)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original Admin retirement is stale at its actual publication commit');
    for (const item of [...published.metadata, ...schemaMetadata, ...recoveryMetadata, inspectorArtifact, deathArtifact, lifecycleArtifact, lifecycleProjection, ...currentRetirement.metadata,
      closureArtifact, resultArtifact, receiptArtifact, registryArtifact, responseArtifact]) insertArtifactMetadata(connection, item, finishedAt);
    connection.prepare('UPDATE admin_operations SET state=?,row_json=? WHERE principal_id=? AND method=? AND request_id=? AND attempt=?')
      .run('completed', canonicalJsonBytes(decodeAdminOperation(completed)).toString('utf8'), identity.principalId, request.method, request.requestId, attempt);
    connection.prepare(`INSERT INTO mcp_registrations(owner_principal_id,registration_id,current_revision,current_revision_ref) VALUES(?,?,?,?)
      ON CONFLICT(owner_principal_id,registration_id) DO UPDATE SET current_revision=excluded.current_revision,current_revision_ref=excluded.current_revision_ref`)
      .run(identity.principalId, request.registrationId, revision, registryArtifact.ref);
    insertControlRequest(connection, { principalId: identity.principalId, method: request.method, requestId: request.requestId,
      requestDigest: request.requestDigest, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
      responseRef: responseArtifact.ref, committedAt: now });
  }); requireHealthyFence(clock);
  return response;
}
