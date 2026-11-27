// Complete original native lifecycle and separate successor cleanup audit.
// Death closes local launch custody; it says nothing about remote/tool effect.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, normalizeAbsolutePath, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import { decodeMcpServerInstanceIdentity, decodeMcpServerLaunchReceipt, decodeMcpServerStoppedItem, type McpServerLaunchReceiptV1 } from '../kernel/mcp-stdio.js';
import { decodeMcpServerLaunchFailure, decodeMcpServerLaunchRequest, decodeMcpServerLaunchTarget, decodeMcpServerFailedStoppedItem,
  decodeMcpServerPolicyChannelEvidence, decodeMcpServerPolicyDecisionItem, countMcpServerLaunchClaims } from '../kernel/mcp-server-authorization.js';
import { decodeMcpServerLaunchPreparation } from '../kernel/mcp-server-authorization.js';
import { controlWireRecord } from '../kernel/control-wire-data.js';
import { decodeAgentStop } from '../runtime/stop.js';
import type { InvocationJournalEntry, Run, RunAssemblyV1, RunSpec, ProcessContainment, ProcessContainmentPlanV1, ProcessContainmentDeathEvidenceV1,
  ProcessContainmentNoSpawnEvidenceV1, SandboxLaunchSpecV1, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import type { ToolOperationGrantV1, ToolRequestV1, ToolTargetV1, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeBudgetSettlement, decodeWorkspaceIdentity } from './decoders.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { readMcpStdioLaunchRecipeData } from './mcp-stdio-launch.js';
import { decodeMcpStdioRecipeData } from './mcp-stdio-recipe.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
import { readMcpRequestArguments } from './mcp-request-arguments.js';
import { KernelStorageError } from './errors.js';
import { readMcpRegistryClosure } from './mcp-registration.js';
import { loadMcpServerPolicy, planMcpServerLaunch, decodeMcpStdioExecutableIdentity } from './mcp-server-policy.js';
import { readMcpServerGrant, readMcpServerApproval, mcpServerPolicyItem } from './mcp-server-permission.js';
import { decodeMcpStdioLifecycleData, decodeMcpStdioCleanupData } from './native-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { readInvocationAttempt, readInvocationJournal } from './repositories/journal.js';
import { mcpAttemptHasClaim, mcpServerOwningAttempt } from './mcp-server-owning-attempt.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export async function readMcpServerPermissionContextData(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec,
  assembly: RunAssemblyV1, requestRef: string, targetRef: string) {
  const request = decodeMcpServerLaunchRequest(await readCanonicalArtifact(artifacts, requestRef));
  const target = decodeMcpServerLaunchTarget(await readCanonicalArtifact(artifacts, targetRef));
  const tool = await readCanonicalArtifact<ToolRequestV1>(artifacts, request.toolRequestRef), effect = await readCanonicalArtifact<ToolTargetV1>(artifacts, tool.targetRef);
  if (request.runId !== run.id || canonicalSha256(request) !== requestRef || canonicalSha256(target) !== targetRef ||
      request.assemblyRef !== spec.assemblyRef || canonicalSha256(assembly) !== spec.assemblyRef || request.targetRef !== targetRef ||
      target.targetDigest !== request.targetDigest || tool.requestDigest !== request.toolRequestDigest || digestOmitting(tool, 'requestDigest') !== tool.requestDigest ||
      effect.targetDigest !== tool.targetDigest || digestOmitting(effect, 'targetDigest') !== effect.targetDigest || effect.execution.kind !== 'mcp')
    invalid('MCP server launch history substitutes its original Run/request/target/effect');
  const principalId = readSessionPrincipalId(driver, run.sessionId), registry = await readMcpRegistryClosure(driver, artifacts, request.registryRevisionRef, principalId);
  const planned = planMcpServerLaunch({ request: tool, target: effect, registryRef: registry.ref, registry: registry.registry, lifecycleSeq: request.lifecycleSeq });
  requireEqual(planned, { request, target }, 'MCP server exact original request/target projection');
  if (registry.registry.transport.kind !== 'stdio') invalid('MCP server history lost its original stdio executable identity');
  const executable = decodeMcpStdioExecutableIdentity(await readCanonicalArtifact(artifacts, target.executableIdentityRef));
  requireEqual(executable, registry.registry.transport.executable, 'MCP original executable identity full artifact');
  if (canonicalSha256(executable) !== target.executableIdentityDigest) invalid('MCP original executable identity complete-byte digest changed');
  const batchRow = driver.prepare('SELECT payload_ref FROM items WHERE run_id=? AND item_id=?')
    .get<{ payload_ref: string }>(run.id, request.batchItemId);
  const batch = batchRow && await readCanonicalArtifact<import('../kernel/types.js').ToolBatchItem>(artifacts, batchRow.payload_ref);
  const frontier = await readCanonicalArtifact<import('../kernel/types.js').RunFrontier>(artifacts, request.frontierRef);
  if (!batch || batch.kind !== 'assistant_tool_batch' || batch.runId !== run.id || batch.itemId !== request.batchItemId ||
      batch.calls[request.callIndex]?.callId !== request.callId || batch.calls[request.callIndex]?.inputRef !== tool.inputRef ||
      batch.calls[request.callIndex]?.inputDigest !== tool.inputDigest || batch.calls[request.callIndex]?.toolName !== tool.toolName ||
      frontier.kind !== 'tool' || frontier.batchItemId !== batch.itemId || frontier.nextCallIndex !== request.callIndex ||
      canonicalSha256(frontier.orderedCallIds) !== canonicalSha256(batch.calls.map(call => call.callId)))
    invalid('MCP server permission changes its real immutable originating batch/call/index/frontier');
  const session = readSession(driver, run.sessionId), workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, spec.policyRef);
  const evaluator = loadMcpServerPolicy({ policy, policyRef: spec.policyRef, assembly, principalId, workspaceIdentityDigest: workspace.identityDigest, request, target });
  return { run, spec, assembly, request, target, tool, effect, registry, principalId, evaluator };
}
export async function readMcpServerLaunchContext(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec,
  assembly: RunAssemblyV1, prepared: InvocationJournalEntry) {
  const data = await readMcpServerPermissionContextData(driver, artifacts, run, spec, assembly, prepared.requestRef, prepared.target);
  if (prepared.opKind !== 'mcp-server' || prepared.phase !== 'prepared' || prepared.opId !== data.request.opId || prepared.runId !== run.id || !prepared.grantRef)
    invalid('MCP server prepared history has no exact request/target and independent launch grant');
  const permission = await readMcpServerGrant(driver, artifacts, data, prepared.grantRef);
  if (!prepared.evidenceRef || !prepared.evidenceDigest) invalid('MCP stdio server has no complete original first-prepared native resource intent');
  const preparation = decodeMcpServerLaunchPreparation(await readCanonicalArtifact(artifacts, prepared.evidenceRef));
  if (preparation.preparationDigest !== prepared.evidenceDigest || preparation.runId !== run.id || preparation.launchOpId !== prepared.opId || preparation.attempt !== prepared.attempt ||
      preparation.leaseEpoch !== prepared.leaseEpoch || preparation.requestRef !== prepared.requestRef || preparation.requestDigest !== data.request.requestDigest ||
      preparation.targetRef !== prepared.target || preparation.targetDigest !== data.target.targetDigest || preparation.grantRef !== prepared.grantRef || preparation.grantDigest !== permission.grant.grantDigest ||
      preparation.createdAt !== prepared.timestamp || preparation.batchItemId !== data.request.batchItemId || preparation.callId !== data.request.callId || preparation.callIndex !== data.request.callIndex ||
      preparation.lifecycleSeq !== data.request.lifecycleSeq || preparation.registryRef !== data.registry.ref || preparation.manifestDigest !== data.registry.registry.manifestDigest ||
      preparation.toolRequestRef !== data.request.toolRequestRef || preparation.toolRequestDigest !== data.request.toolRequestDigest || preparation.principalId !== data.principalId)
    invalid('MCP first-prepared resource intent substitutes its original semantic permission/call/attempt');
  const effect = mcpServerOwningAttempt(readInvocationJournal(driver, run.id), prepared, data.request.toolRequestRef);
  if (!effect?.owning.grantRef) invalid('MCP server preparation lost its exact preceding owning effect attempt and worker lease');
  return { ...data, permission, preparation, owningPrepared: effect.owning, firstPrepared: effect.first };
}
type Context = Awaited<ReturnType<typeof readMcpServerLaunchContext>>;
export async function readMcpServerNativeResources(driver: SqliteDriver, artifacts: ArtifactCatalog, context: Context,
  prepared: InvocationJournalEntry, claim: InvocationJournalEntry | undefined, input: Readonly<{
    nativeClosure: McpServerLaunchReceiptV1['nativeClosure']; processContainmentRef?: string; deathEvidenceRef?: string; noSpawnEvidenceRef?: string;
  }>) {
  const preparation = context.preparation;
  if (claim && (!claim.sandboxLaunchSpecRef || claim.opKind !== 'mcp-server' || claim.phase !== 'dispatch_claimed' || claim.opId !== prepared.opId || claim.attempt !== prepared.attempt ||
      claim.supervisorInstanceId === undefined || claim.stateOwnerEpoch === undefined || !claim.dispatchId)) invalid('MCP server has no exact original contained launch claim');
  // This is the durable preparation's original creator/plan declaration,
  // never a fabricated claim or permission to create a domain.
  const origin = { supervisorInstanceId: preparation.supervisorInstanceId, stateOwnerEpoch: preparation.stateOwnerEpoch,
    leaseEpoch: preparation.leaseEpoch, dispatchId: preparation.dispatchId, sandboxLaunchSpecRef: preparation.sandboxLaunchSpecRef,
    observedAt: claim?.timestamp ?? prepared.timestamp };
  if (!claim && readInvocationAttempt(driver, prepared.runId, prepared.opId, prepared.attempt).some(entry => entry.phase === 'dispatch_claimed'))
    invalid('MCP unclaimed native closure cannot hide an original permanent launch claim');
  const raw = await artifacts.readBoundedBytes(input.nativeClosure.lifecycleRawRef, 16777216), lifecycle = decodeMcpStdioLifecycleData(raw);
  requireEqual(await readCanonicalArtifact(artifacts, input.nativeClosure.lifecycleProjectionRef), lifecycle, 'MCP server complete original native bytes/hash-chain projection');
  if (canonicalSha256(lifecycle) !== input.nativeClosure.lifecycleProjectionRef || lifecycle.binding.kind !== 'run') invalid('MCP server native root changes its purpose or projection hash');
  const binding = lifecycle.binding;
  requireEqual(lifecycle.controller, preparation.controller, 'MCP native birth original first-prepared controller');
  requireEqual(lifecycle.originalSupervisor, preparation.originalSupervisor, 'MCP native birth original first-prepared Supervisor');
  if (claim && (claim.evidenceRef !== prepared.evidenceRef || claim.evidenceDigest !== prepared.evidenceDigest || claim.dispatchId !== origin.dispatchId ||
      claim.sandboxLaunchSpecRef !== origin.sandboxLaunchSpecRef || claim.supervisorInstanceId !== origin.supervisorInstanceId ||
      claim.stateOwnerEpoch !== origin.stateOwnerEpoch || claim.leaseEpoch !== origin.leaseEpoch) || binding.nonce !== preparation.nonce ||
      binding.plannedContainmentRef !== preparation.plannedContainmentRef || binding.plannedContainmentDigest !== preparation.plannedContainmentDigest ||
      binding.sandboxLaunchSpecDigest !== preparation.sandboxLaunchSpecDigest || binding.callDeadlineMs !== preparation.callDeadlineMs || binding.launchDeadlineMs !== preparation.launchDeadlineMs)
    invalid('MCP native birth/claim changes its original durable first-prepared resource intent');
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, binding.plannedContainmentRef);
  const launch = await readCanonicalArtifact<SandboxLaunchSpecV1>(artifacts, origin.sandboxLaunchSpecRef);
  const originalOwner = { kind: 'run_invocation' as const, runId: prepared.runId, intendedLeaseEpoch: origin.leaseEpoch,
    workerLaunchId: binding.workerLaunchId, opId: prepared.opId, attempt: prepared.attempt, dispatchId: origin.dispatchId };
  if (binding.runId !== prepared.runId || binding.launchOpId !== prepared.opId || binding.attempt !== prepared.attempt || binding.principalId !== context.principalId ||
      binding.requestRef !== prepared.requestRef || binding.requestDigest !== context.request.requestDigest || binding.targetRef !== prepared.target || binding.targetDigest !== context.target.targetDigest ||
      binding.grantRef !== prepared.grantRef || binding.grantDigest !== context.permission.grant.grantDigest || binding.registryRef !== context.registry.ref || binding.manifestDigest !== context.registry.registry.manifestDigest ||
      binding.toolRequestRef !== context.request.toolRequestRef || binding.toolRequestDigest !== context.request.toolRequestDigest || binding.batchItemId !== context.request.batchItemId ||
      binding.callId !== context.request.callId || binding.callIndex !== context.request.callIndex || binding.lifecycleSeq !== context.request.lifecycleSeq || binding.leaseEpoch !== origin.leaseEpoch ||
      binding.supervisorInstanceId !== origin.supervisorInstanceId || binding.stateOwnerEpoch !== origin.stateOwnerEpoch || binding.sandboxLaunchSpecRef !== origin.sandboxLaunchSpecRef ||
      !/^[0-9a-f]{64}$/u.test(binding.nonce) || binding.plannedContainmentDigest !== plan.planDigest || binding.sandboxLaunchSpecDigest !== launch.launchSpecDigest ||
      plan.planDigest !== digestOmitting(plan, 'planDigest') || launch.launchSpecDigest !== digestOmitting(launch, 'launchSpecDigest') ||
      plan.schemaVersion !== 1 || plan.format !== 'cliq-process-containment-plan-v1' || plan.backend.kind !== 'linux' ||
      plan.filesystemBinding.kind !== 'isolated-empty-root' || plan.launchNonceDigest !== sha256Bytes(Buffer.from(binding.nonce)) ||
      plan.backend.pidNamespaceReservationId !== `linux-mcp-stdio:run:${binding.nonce}` ||
      normalizeAbsolutePath(plan.backend.cgroupPath) !== plan.backend.cgroupPath || !plan.backend.cgroupPath.endsWith(`/cliq-mcp-stdio-run-${binding.nonce}`) ||
      plan.backend.subreaperStartToken !== `linux-subreaper:${lifecycle.controller.pid}:${lifecycle.controller.processStartToken}` ||
      lifecycle.reservation.cgroupName !== `cliq-mcp-stdio-run-${binding.nonce}` || launch.owner.kind !== 'run_invocation' || launch.purpose !== 'mcp_stdio' ||
      launch.containmentPlanRef !== binding.plannedContainmentRef || launch.containmentPlanDigest !== plan.planDigest || launch.requestRef !== prepared.requestRef ||
      launch.requestDigest !== context.request.requestDigest || launch.targetRef !== prepared.target || launch.targetDigest !== context.target.targetDigest || launch.operationGrantRef !== prepared.grantRef ||
      launch.processInvocation.kind !== 'run_request' || launch.processInvocation.purpose !== 'mcp_stdio' || launch.processInvocation.recipe !== 'cliq-mcp-stdio-launch-v1' ||
      launch.processInvocation.argvCwdSource !== 'trusted_recipe_decode_of_request_and_target' || launch.processInvocation.requestRef !== prepared.requestRef ||
      launch.processInvocation.requestDigest !== context.request.requestDigest || launch.processInvocation.targetRef !== prepared.target || launch.processInvocation.targetDigest !== context.target.targetDigest)
    invalid('MCP server original native input/plan/spec changes its exact launch purpose or immutable data');
  requireEqual(plan.owner, originalOwner, 'MCP server original planned owner'); requireEqual(launch.owner, originalOwner, 'MCP server original launch owner');
  requireEqual(launch.processInvocation.stdio, { stdin: 'mcp_framed', stdout: 'mcp_framed', stderr: 'captured', extraFileDescriptors: 'none' }, 'MCP server original stdio-only execution');
  const worker = readRequiredWorkerLaunch(driver, binding.workerLaunchId), owningTool = context.owningPrepared;
  if (!owningTool?.grantRef || !worker.leaseExpiresAt || worker.runId !== prepared.runId || worker.leaseEpoch !== origin.leaseEpoch || worker.supervisorInstanceId !== origin.supervisorInstanceId ||
      launch.parentWorkerContainmentRef !== worker.processContainmentRef || prepared.timestamp < worker.activatedAt! || origin.observedAt >= worker.leaseExpiresAt)
    invalid('MCP server original worker lease or exact prepared owning tool changed');
  const effectGrant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, owningTool.grantRef);
  if (effectGrant.grantDigest !== digestOmitting(effectGrant, 'grantDigest') || binding.callDeadlineMs > Math.min(parseCanonicalTime(context.firstPrepared.timestamp) + context.target.callTimeoutMs,
    parseCanonicalTime(context.run.deadlineAt), parseCanonicalTime(context.permission.grant.expiresAt), parseCanonicalTime(effectGrant.expiresAt), parseCanonicalTime(worker.leaseExpiresAt)) ||
      binding.launchDeadlineMs !== Math.min(parseCanonicalTime(prepared.timestamp) + context.target.launchTimeoutMs, binding.callDeadlineMs) || parseCanonicalTime(origin.observedAt) >= binding.launchDeadlineMs)
    invalid('MCP server native input extends its original launch/call/grant/Run/lease deadline');
  const evidence = input.deathEvidenceRef ? await readCanonicalArtifact<ProcessContainmentDeathEvidenceV1>(artifacts, input.deathEvidenceRef)
    : input.noSpawnEvidenceRef ? await readCanonicalArtifact<ProcessContainmentNoSpawnEvidenceV1>(artifacts, input.noSpawnEvidenceRef) : undefined;
  if (!evidence || evidence.evidenceDigest !== digestOmitting(evidence, 'evidenceDigest')) invalid('MCP server has no exact local retirement artifact');
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, evidence.inspectorIdentityRef);
  const history = await readRetainedStateOwnerHistory(driver, artifacts, inspector.stateOwnerEpoch);
  const claiming = history.entries.find(entry => entry.owner.ownerEpoch === origin.stateOwnerEpoch), inspecting = history.entries.find(entry => entry.owner.ownerEpoch === inspector.stateOwnerEpoch);
  if (!claiming || !inspecting || claiming.owner.supervisorInstanceId !== origin.supervisorInstanceId || claiming.owner.acquiredAt > prepared.timestamp ||
      claiming.owner.state === 'terminal' && claiming.owner.releasedAt < origin.observedAt || inspecting.owner.acquiredAt > evidence.observedAt ||
      inspecting.owner.state === 'terminal' && inspecting.owner.releasedAt < evidence.observedAt || evidence.inspectorSupervisorInstanceId !== inspecting.owner.supervisorInstanceId ||
      claiming.owner.runtimeBundleRef !== context.assembly.runtime.runtimeBundleRef || claiming.owner.runtimeBundleManifestDigest !== context.assembly.runtime.runtimeBundleManifestDigest ||
      lifecycle.originalSupervisor.pid !== claiming.process.pid || lifecycle.originalSupervisor.processStartToken !== claiming.process.processStartToken ||
      binding.originalSupervisorPid !== claiming.process.pid || binding.originalSupervisorStartToken !== claiming.process.processStartToken ||
      lifecycle.stateRootIdentity.deviceId !== history.rootIdentity.deviceId || lifecycle.stateRootIdentity.fileId !== history.rootIdentity.directoryFileId ||
      [lifecycle.stateRootIdentity, lifecycle.runtimeIdentity, lifecycle.privateParentIdentity, lifecycle.birthIdentity].some(identity => identity.ownerUid !== history.rootIdentity.ownerUid))
    invalid('MCP server original native birth substitutes its retained StateOwner/root/process/runtime');
  await readSupervisorInspector(artifacts, inspecting.owner, { runtime: { runtimeBundleRef: inspecting.owner.runtimeBundleRef,
    runtimeBundleManifestDigest: inspecting.owner.runtimeBundleManifestDigest } }, evidence);
  // A refused matching event never handed out a screened receipt. It cannot
  // be relabeled a lost response or a completed normal lifecycle on recovery.
  if (lifecycle.joined.responseRefused) invalid('MCP server original response refusal remains pending recovery');
  if (!claim && (input.processContainmentRef !== undefined || input.deathEvidenceRef !== undefined || !input.noSpawnEvidenceRef ||
      lifecycle.containment !== null || lifecycle.joined.spawnAttempted || lifecycle.joined.execReleased || lifecycle.joined.effectReleased))
    invalid('MCP unclaimed local closure requires positive original no-spawn without any execution or effect release');
  let retirement = lifecycle.retirement;
  if (input.nativeClosure.kind === 'linux_original_join') {
    if (inspecting.owner.ownerEpoch !== claiming.owner.ownerEpoch || !lifecycle.joined.deathJoined || !lifecycle.joined.outputCustodyRetired ||
        !lifecycle.joined.ownerDrained || !retirement)
      invalid('MCP server original closure has no complete original local custody join');
  } else {
    const cleanupBytes = await artifacts.readBoundedBytes(input.nativeClosure.cleanupRawRef, 16777216), cleanup = decodeMcpStdioCleanupData(cleanupBytes);
    requireEqual(await readCanonicalArtifact(artifacts, input.nativeClosure.cleanupProjectionRef), cleanup, 'MCP server separate actual currentchecker raw/projection');
    requireEqual(cleanup.originalBinding, lifecycle.binding, 'MCP server cleanup original complete native input');
    requireEqual(cleanup.originalController, lifecycle.controller, 'MCP server cleanup original actual controller');
    requireEqual(cleanup.originalReservation, lifecycle.reservation, 'MCP server cleanup original reserved cgroup');
    if (canonicalSha256(cleanup) !== input.nativeClosure.cleanupProjectionRef || cleanup.originalBirthDigest !== sha256Bytes(raw) ||
        cleanup.currentChecker.stateOwnerEpoch !== inspecting.owner.ownerEpoch || cleanup.currentChecker.supervisorInstanceId !== inspecting.owner.supervisorInstanceId ||
        cleanup.currentChecker.supervisorPid !== inspecting.process.pid || cleanup.currentChecker.supervisorStartToken !== inspecting.process.processStartToken ||
        cleanup.currentChecker.stateOwnerEpoch <= claiming.owner.ownerEpoch || !cleanup.priorSupervisorDead || !cleanup.priorControllerDead ||
        !cleanup.outputCustodyRetired || cleanup.remainingDescendants !== 0 || cleanup.observedAtMs !== Date.parse(evidence.observedAt))
      invalid('MCP server successor cleanup changes its exact old birth/current checker/death/action join');
    retirement = cleanup.retirement;
  }
  if (!retirement || retirement.cgroupPopulated !== 0 || retirement.remainingTrackedDescendants !== 0 ||
      retirement.cgroupId !== lifecycle.reservation.cgroupInode || retirement.observedAtMs !== Date.parse(evidence.observedAt))
    invalid('MCP server local retirement does not close the exact original reserved native domain');
  requireEqual(evidence.owner, originalOwner, 'MCP server local retirement original owner');
  if (evidence.planRef !== binding.plannedContainmentRef || evidence.sandboxLaunchSpecRef !== origin.sandboxLaunchSpecRef ||
      evidence.sandboxLaunchSpecDigest !== launch.launchSpecDigest || evidence.launchNonceDigest !== plan.launchNonceDigest || evidence.observedAt < origin.observedAt)
    invalid('MCP server local retirement substitutes the original plan/spec/nonce or precedes claim');
  let containment: ProcessContainment | undefined;
  if (input.processContainmentRef && evidence.kind === 'containment_all_descendants_dead') {
    containment = await readCanonicalArtifact<ProcessContainment>(artifacts, input.processContainmentRef);
    const birth = lifecycle.containment;
    if (!birth || retirement.namespaceInitDeadAndReaped !== 1 || containment.backend.kind !== 'linux' || evidence.backend.kind !== 'linux' || evidence.containmentRef !== input.processContainmentRef ||
        containment.planRef !== binding.plannedContainmentRef || containment.sandboxLaunchSpecRef !== origin.sandboxLaunchSpecRef || containment.sandboxLaunchSpecDigest !== launch.launchSpecDigest ||
        containment.launchNonceDigest !== plan.launchNonceDigest || containment.backend.cgroupPath !== plan.backend.cgroupPath || containment.backend.cgroupId !== birth.cgroupId ||
        containment.backend.pidNamespaceId !== birth.pidNamespaceId || containment.backend.namespaceInitStartToken !== birth.namespaceInitStartToken ||
        containment.backend.pidNamespaceReservationId !== plan.backend.pidNamespaceReservationId || containment.backend.subreaperStartToken !== plan.backend.subreaperStartToken ||
        birth.cgroupPopulated !== 1 || birth.namespaceInitDeadAndReaped !== 0 || birth.observedAtMs !== Date.parse(containment.createdAt) ||
        retirement.pidNamespaceId !== birth.pidNamespaceId || retirement.namespaceInitStartToken !== birth.namespaceInitStartToken || retirement.namespaceInitPid !== birth.namespaceInitPid ||
        containment.createdAt < origin.observedAt || containment.createdAt > evidence.observedAt)
      invalid('MCP server original READY and retired namespace/cgroup identities differ');
    requireEqual(containment.owner, originalOwner, 'MCP server actual original domain owner'); requireEqual(containment.filesystemBinding, plan.filesystemBinding, 'MCP server empty root binding');
    requireEqual(evidence.backend, { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }, 'MCP server exact all-descendant death backend');
  } else if (input.noSpawnEvidenceRef && evidence.kind === 'containment_plan_quiescent') {
    if (input.processContainmentRef || lifecycle.containment !== null || retirement.namespaceInitPid !== 0 || retirement.namespaceInitDeadAndReaped !== 0 ||
        lifecycle.joined.spawnAttempted || evidence.backend.kind !== 'linux')
      invalid('MCP server no-spawn proof cannot borrow a created instance');
    requireEqual(evidence.backend, { kind: 'linux', cgroupPath: plan.backend.cgroupPath,
      cgroupObservation: { kind: 'empty', cgroupId: retirement.cgroupId, populated: 0 }, pidNamespaceObservation: { kind: 'never_created',
        pidNamespaceReservationId: plan.backend.pidNamespaceReservationId }, subreaperStartToken: plan.backend.subreaperStartToken,
      matchingLaunchNonceProcessCount: 0 }, 'MCP server exact native no-spawn reservation');
  } else invalid('MCP server local retirement artifact has a mixed dead/no-spawn purpose');
  const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, claiming.owner.runtimeBundleRef);
  const transport = context.registry.registry.transport;
  if (transport.kind !== 'stdio' || transport.executable.kind !== 'runtime_bundle' || !worker.processContainmentRef)
    invalid('MCP server original launch has no exact signed executable or owning worker domain');
  const originalProfile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, context.spec.sandboxProfileRef));
  if (plan.createdAt !== preparation.createdAt || plan.createdAt > origin.observedAt)
    invalid('MCP server immutable plan is outside its original prepared/claim interval');
  const recipe = await readMcpStdioLaunchRecipeData(artifacts, { purpose: { kind: 'run', owner: originalOwner, requestRef: prepared.requestRef,
    requestDigest: context.request.requestDigest, targetRef: prepared.target, targetDigest: context.target.targetDigest, grantRef: prepared.grantRef!,
    parentWorkerContainmentRef: worker.processContainmentRef }, bundle, originalController: { subreaperStartToken: plan.backend.subreaperStartToken },
    cgroupParent: plan.backend.cgroupPath.slice(0, plan.backend.cgroupPath.lastIndexOf('/')), ownerUid: history.rootIdentity.ownerUid,
    executable: transport.executable, nonce: binding.nonce, createdAt: plan.createdAt, resources: originalProfile.resources, plan, spec: launch });
  const isolation = bundle.entries.filter(entry => entry.entryId === 'linux_bubblewrap');
  if (isolation.length !== 1 || isolation[0]!.role !== 'platform_helper' || !isolation[0]!.executable) invalid('MCP stdio original native isolation image is absent');
  requireEqual(lifecycle.images.server, { digest: recipe.serverEntry.digest, byteCount: recipe.serverEntry.byteCount }, 'MCP native exact original signed server image');
  requireEqual(lifecycle.images.client, { digest: recipe.launcherEntry.digest, byteCount: recipe.launcherEntry.byteCount }, 'MCP native exact original signed C client image');
  requireEqual(lifecycle.images.isolation, { digest: isolation[0]!.digest, byteCount: isolation[0]!.byteCount }, 'MCP native exact original signed isolation image');
  if (lifecycle.images.recipe.digest !== preparation.nativeRecipeRef) invalid('MCP native scope recipe changed from its exact first-prepared artifact');
  const nativeRecipeBytes = await artifacts.readBoundedBytes(preparation.nativeRecipeRef, lifecycle.images.recipe.byteCount), nativeRecipe = decodeMcpStdioRecipeData(nativeRecipeBytes);
  if (nativeRecipe.byteCount !== lifecycle.images.recipe.byteCount || nativeRecipe.recipeDigest !== preparation.nativeRecipeRef)
    invalid('MCP original sealed native recipe bytes differ from its recorded full image hash');
  const call = await readCanonicalArtifact<import('../protocol/agent-ir.js').ToolCallInputV1>(artifacts, context.tool.inputRef);
  if (context.effect.execution.kind !== 'mcp') invalid('MCP original native recipe has no exact owning tool identity');
  const argumentsValue = await readMcpRequestArguments(artifacts, { request: context.tool, target: context.effect,
    registry: context.registry.registry, registryRef: context.registry.ref, call });
  assertMcpStdioRecipeData(nativeRecipe, { purpose: 'run', transport, serverByteCount: recipe.serverEntry.byteCount,
    resources: originalProfile.resources, serverToolName: context.effect.execution.serverToolName, arguments: argumentsValue });
  return { context, lifecycle, raw, plan, launch, containment, evidence, history, retirement, binding,
    assertUnchanged(connection: import('./sqlite-driver.js').SqliteConnection) { history.assertUnchanged(connection); context.registry.assertUnchanged(connection); context.permission.assertUnchanged(connection); } };
}
export async function readMcpServerClosedAttempt(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec, assembly: RunAssemblyV1,
  prepared: InvocationJournalEntry, entries: readonly InvocationJournalEntry[]) {
  const context = await readMcpServerLaunchContext(driver, artifacts, run, spec, assembly, prepared);
  const claim = entries[1]?.phase === 'dispatch_claimed' ? entries[1] : undefined, terminal = entries.at(-1);
  if (entries.length !== (claim ? 3 : 2) || !terminal?.budgetSettlementRef || !['completed', 'failed'].includes(terminal.phase) ||
      !claim && terminal.phase !== 'failed') invalid('MCP server closed attempt has no exact prepared/optional-claim/retired terminal chain');
  if (terminal.evidenceRef !== prepared.evidenceRef || terminal.evidenceDigest !== prepared.evidenceDigest)
    invalid('MCP local terminal changes its original prepared-resource evidence attachment');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
  if (settlement.runId !== run.id || settlement.opId !== prepared.opId || settlement.attempt !== prepared.attempt || settlement.preparedJournalSeq !== prepared.seq ||
      settlement.terminalJournalSeq !== terminal.seq || settlement.terminalPhase !== terminal.phase || settlement.settledAt !== terminal.timestamp)
    invalid('MCP server closed attempt changes its exact independent settlement');
  requireEqual(settlement.reserved, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'MCP server original separate tool-call reservation');
  requireEqual(settlement.consumed, claim ? settlement.reserved : { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
    'MCP server claimed full-once or genuinely unclaimed zero charge');
  requireEqual(settlement.released, settlement.reserved, 'MCP server local terminal releases its own exact reservation');
  if (terminal.phase === 'failed') {
    if (!terminal.errorRef) invalid('MCP server failed launch has no complete retained local closure');
    const failure = decodeMcpServerLaunchFailure(await readCanonicalArtifact(artifacts, terminal.errorRef));
    if (failure.runId !== run.id || failure.launchOpId !== prepared.opId || failure.attempt !== prepared.attempt || failure.preparedJournalSeq !== prepared.seq ||
        failure.requestRef !== prepared.requestRef || failure.targetRef !== prepared.target || failure.grantRef !== prepared.grantRef || failure.stoppedAt > terminal.timestamp ||
        (claim ? failure.claimStatus !== undefined || failure.claimedJournalSeq !== claim.seq || failure.dispatchId !== claim.dispatchId || failure.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef
          : failure.claimStatus !== 'not_claimed' || failure.dispatchId !== context.preparation.dispatchId || failure.sandboxLaunchSpecRef !== context.preparation.sandboxLaunchSpecRef))
      invalid('MCP server failed lifecycle changes its exact original claim');
    const resources = await readMcpServerNativeResources(driver, artifacts, context, prepared, claim, { nativeClosure: failure.nativeClosure,
      ...(failure.closure === 'containment_dead' ? { processContainmentRef: failure.processContainmentRef, deathEvidenceRef: failure.containmentDeathEvidenceRef }
        : { noSpawnEvidenceRef: failure.noSpawnEvidenceRef }) });
    if (failure.reason === 'creator_lost_before_effect_claim') {
      const journal = readInvocationJournal(driver, run.id), tool = context.owningPrepared;
      if (tool.seq >= prepared.seq || mcpAttemptHasClaim(journal, tool, terminal.seq) ||
          resources.lifecycle.joined.effectReleased || failure.nativeClosure.kind !== 'linux_successor_cleanup' ||
          (resources.lifecycle.joined.execReleased ? failure.instance !== 'setup_outcome_unavailable' : failure.instance !== 'not_initialized'))
        invalid('MCP successor local closure cannot replace an ordinary effect claim or guess its unavailable setup outcome');
    }
    if (!claim) {
      if (failure.claimStatus !== 'not_claimed' || failure.instance !== 'not_initialized' || failure.closure !== 'plan_quiescent')
        invalid('MCP zero-charge failure substitutes a claimed, initialized or created local domain');
      return { context, terminal, settlement, failure, resources, instance: undefined, instanceInitialized: false };
    }
    const instance = failure.instance === 'initialized' ? decodeMcpServerInstanceIdentity(await readCanonicalArtifact(artifacts, failure.instanceIdentityRef)) : undefined;
    if (instance && (instance.identityDigest !== failure.instanceIdentityDigest || instance.runId !== run.id || instance.batchItemId !== context.request.batchItemId ||
        instance.callId !== context.request.callId || instance.callIndex !== context.request.callIndex || instance.launchOpId !== prepared.opId || instance.launchAttempt !== prepared.attempt ||
        instance.launchDispatchId !== claim.dispatchId || instance.registryRevisionRef !== context.registry.ref || instance.registryManifestDigest !== context.registry.registry.manifestDigest ||
        instance.lifecycleSeq !== context.request.lifecycleSeq || instance.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || failure.closure !== 'containment_dead' ||
        instance.processContainmentRef !== failure.processContainmentRef || instance.instanceNonceDigest !== resources.plan.launchNonceDigest || instance.initializedAt < claim.timestamp ||
        instance.initializeDigest !== context.registry.registry.initializeDigest || instance.capabilityDigest !== context.registry.registry.capabilityDigest ||
        instance.probedToolsListDigest !== context.registry.registry.probedToolsListDigest || instance.initializedAt > failure.stoppedAt)) invalid('MCP server failed initialized instance changes its original identity/claim/discovery');
    if (failure.reason === 'owning_call_unknown') {
      const owningPrepared = context.owningPrepared;
      const owning = readInvocationJournal(driver, run.id).filter(entry => entry.opId === owningPrepared.opId && entry.attempt === owningPrepared.attempt);
      const unknown = owning?.[2];
      if (!instance || !owningPrepared || !unknown || unknown.phase !== 'unknown' || owning?.[1]?.phase !== 'dispatch_claimed' ||
          unknown.seq + 1 !== terminal.seq || unknown.timestamp !== terminal.timestamp || !unknown.budgetSettlementRef || failure.closure !== 'containment_dead')
        invalid('MCP local owning-call-unknown failure has no exact same-transaction original uncertain effect');
      const effectSettlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef));
      requireEqual(effectSettlement.budgetConsumedAfter, settlement.budgetConsumedBefore, 'MCP unknown effect precedes its separate local launch charge');
      requireEqual(effectSettlement.budgetReservedAfter, settlement.budgetReservedBefore, 'MCP unknown effect releases only its own original reservation');
      const row = driver.prepare('SELECT payload_ref,item_seq,created_at FROM items WHERE run_id=? AND item_id=?')
        .get<{ payload_ref: string; item_seq: bigint; created_at: string }>(run.id, failure.stoppedItemId);
      if (!row) invalid('MCP local unknown failure has no exact atomic stopped audit');
      const stopped = decodeMcpServerFailedStoppedItem(await readCanonicalArtifact(artifacts, row.payload_ref));
      if (stopped.disposition !== 'owning_call_unknown' || stopped.cause !== 'lease_release' || stopped.runId !== run.id || stopped.itemId !== failure.stoppedItemId || stopped.batchItemId !== context.request.batchItemId || stopped.callId !== context.request.callId ||
          stopped.callIndex !== context.request.callIndex || stopped.serverManifestRef !== context.registry.ref || stopped.lifecycleSeq !== context.request.lifecycleSeq ||
          stopped.launchOpId !== prepared.opId || stopped.instanceIdentityRef !== failure.instanceIdentityRef || stopped.instanceIdentityDigest !== instance.identityDigest ||
          stopped.launchFailureRef !== terminal.errorRef || stopped.launchFailureDigest !== failure.failureDigest || stopped.containmentEvidenceRef !== failure.containmentDeathEvidenceRef ||
          stopped.createdAt !== failure.stoppedAt || row.created_at !== stopped.createdAt)
        invalid('MCP local unknown failure stopped audit changes its original local closure or implies another effect');
    } else if (failure.disposition === 'owning_call_not_dispatched') {
      const journal = readInvocationJournal(driver, run.id), owningPrepared = context.owningPrepared;
      if (!instance || mcpAttemptHasClaim(journal, owningPrepared, terminal.seq) ||
          resources.lifecycle.joined.effectReleased || owningPrepared.seq >= prepared.seq)
        invalid('MCP local undispatched closure cannot replace any permanent owning effect claim');
      const cause = failure.owningCallClosureCause;
      if (cause.kind === 'original_call_deadline') {
        if (cause.deadlineMs !== context.preparation.callDeadlineMs || Date.parse(terminal.timestamp) < cause.deadlineMs || failure.reason !== 'deadline')
          invalid('MCP local undispatched expiry rewrites its original owning call deadline');
      } else {
        let reference = run.stopIntentRef, found = false; const visited = new Set<string>();
        while (reference) {
          if (visited.has(reference)) invalid('MCP local undispatched Stop lineage cycles'); visited.add(reference);
          const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, reference), run);
          if (reference === cause.stopIntentRef) {
            if (stop.createdAt > terminal.timestamp || failure.reason !== (stop.origin === 'deadline' ? 'deadline' : 'cancel'))
              invalid('MCP local undispatched closure substitutes its original true Stop');
            found = true; break;
          }
          reference = stop.supersedesStopIntentRef;
        }
        if (!found) invalid('MCP local undispatched closure is outside its authenticated original Stop lineage');
      }
      const row = driver.prepare('SELECT payload_ref,item_seq,created_at FROM items WHERE run_id=? AND item_id=?')
        .get<{ payload_ref: string; item_seq: bigint; created_at: string }>(run.id, failure.stoppedItemId);
      if (!row) invalid('MCP local undispatched closure lost its exact excluded stopped audit');
      const stopped = decodeMcpServerFailedStoppedItem(await readCanonicalArtifact(artifacts, row.payload_ref));
      if (stopped.disposition !== 'owning_call_not_dispatched' || stopped.cause !== failure.reason || stopped.runId !== run.id ||
          stopped.itemId !== failure.stoppedItemId || stopped.batchItemId !== context.request.batchItemId || stopped.callId !== context.request.callId ||
          stopped.callIndex !== context.request.callIndex || stopped.serverManifestRef !== context.registry.ref || stopped.lifecycleSeq !== context.request.lifecycleSeq ||
          stopped.launchOpId !== prepared.opId || stopped.instanceIdentityRef !== failure.instanceIdentityRef || stopped.instanceIdentityDigest !== instance.identityDigest ||
          stopped.launchFailureRef !== terminal.errorRef || stopped.launchFailureDigest !== failure.failureDigest || stopped.containmentEvidenceRef !== failure.containmentDeathEvidenceRef ||
          stopped.createdAt !== failure.stoppedAt || row.created_at !== stopped.createdAt)
        invalid('MCP local undispatched stopped audit substitutes another initialized instance or closure');
    }
    return { context, terminal, settlement, failure, resources, instance, instanceInitialized: Boolean(instance) };
  }
  if (!claim) invalid('MCP completed local launch has no original permanent claim');
  if (!terminal.resultRef || !terminal.receiptRef) invalid('MCP server completed launch has no original instance/receipt');
  const instance = decodeMcpServerInstanceIdentity(await readCanonicalArtifact(artifacts, terminal.resultRef)), receipt = decodeMcpServerLaunchReceipt(await readCanonicalArtifact(artifacts, terminal.receiptRef));
  if (receipt.instanceIdentityRef !== terminal.resultRef || receipt.instanceIdentityDigest !== instance.identityDigest || receipt.preparedJournalSeq !== prepared.seq ||
      receipt.claimedJournalSeq !== claim.seq || receipt.completedJournalSeq !== terminal.seq || receipt.budgetSettlementRef !== terminal.budgetSettlementRef || receipt.stoppedAt > terminal.timestamp ||
      instance.runId !== run.id || instance.launchOpId !== prepared.opId || instance.launchAttempt !== prepared.attempt || instance.launchDispatchId !== claim.dispatchId ||
      instance.batchItemId !== context.request.batchItemId || instance.callId !== context.request.callId || instance.callIndex !== context.request.callIndex ||
      instance.lifecycleSeq !== context.request.lifecycleSeq || instance.registryRevisionRef !== context.registry.ref || instance.registryManifestDigest !== context.registry.registry.manifestDigest ||
      instance.registrationId !== context.registry.registry.registrationId || instance.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || instance.initializedAt < claim.timestamp)
    invalid('MCP completed server receipt changes its exact original initialized lifecycle');
  const resources = await readMcpServerNativeResources(driver, artifacts, context, prepared, claim, { nativeClosure: receipt.nativeClosure,
    processContainmentRef: instance.processContainmentRef, deathEvidenceRef: receipt.containmentDeathEvidenceRef });
  if (!resources.lifecycle.joined.protocolCompleted || instance.instanceNonceDigest !== resources.plan.launchNonceDigest ||
      instance.initializeDigest !== context.registry.registry.initializeDigest || instance.capabilityDigest !== context.registry.registry.capabilityDigest ||
      instance.probedToolsListDigest !== context.registry.registry.probedToolsListDigest) invalid('MCP completed server substitutes discovery or original protocol completion');
  const row = driver.prepare('SELECT payload_ref,item_seq,created_at FROM items WHERE run_id=? AND item_id=?')
    .get<{ payload_ref: string; item_seq: bigint; created_at: string }>(run.id, receipt.stoppedItemId);
  if (!row) invalid('MCP completed server has no atomically committed stopped item');
  const stopped = decodeMcpServerStoppedItem(await readCanonicalArtifact(artifacts, row.payload_ref));
  if (stopped.runId !== run.id || stopped.itemId !== receipt.stoppedItemId || stopped.batchItemId !== instance.batchItemId || stopped.callId !== instance.callId ||
      stopped.callIndex !== instance.callIndex || stopped.serverManifestRef !== instance.registryRevisionRef || stopped.lifecycleSeq !== instance.lifecycleSeq ||
      stopped.launchOpId !== instance.launchOpId || stopped.instanceIdentityRef !== terminal.resultRef || stopped.instanceIdentityDigest !== instance.identityDigest ||
      stopped.launchReceiptRef !== terminal.receiptRef || stopped.launchReceiptDigest !== receipt.receiptDigest || stopped.containmentEvidenceRef !== receipt.containmentDeathEvidenceRef ||
      stopped.createdAt !== receipt.stoppedAt || row.created_at !== stopped.createdAt)
    invalid('MCP completed server stopped item changes its complete original instance/receipt/death identity');
  return { context, terminal, settlement, receipt, resources, instance, stopped, instanceInitialized: true };
}
export async function validateMcpServerHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec, assembly: RunAssemblyV1,
  items: ReadonlyMap<string, import('../kernel/types.js').ContinuationItem>, journal: readonly InvocationJournalEntry[]) {
  const requests = new Map<string, ReturnType<typeof decodeMcpServerLaunchRequest>>();
  const contexts: Array<Awaited<ReturnType<typeof readMcpServerLaunchContext>>> = [];
  const stoppedIds = new Set<string>();
  const callDeadlines = new Map<string, number>();
  for (const prepared of journal.filter(entry => entry.opKind === 'mcp-server' && entry.phase === 'prepared')) {
    const context = await readMcpServerLaunchContext(driver, artifacts, run, spec, assembly, prepared); requests.set(prepared.requestRef, context.request); contexts.push(context);
    const priorDeadline = callDeadlines.get(context.request.toolRequestRef);
    if (priorDeadline !== undefined && context.preparation.callDeadlineMs > priorDeadline)
      invalid('MCP replacement preparation extends its original immutable owning call deadline');
    callDeadlines.set(context.request.toolRequestRef, Math.min(priorDeadline ?? context.preparation.callDeadlineMs, context.preparation.callDeadlineMs));
    const entries = journal.filter(entry => entry.opId === prepared.opId && entry.attempt === prepared.attempt), terminal = entries.at(-1)!;
    if (['completed', 'failed'].includes(terminal.phase)) {
      const closed = await readMcpServerClosedAttempt(driver, artifacts, run, spec, assembly, prepared, entries);
      const failure = 'failure' in closed ? closed.failure : undefined;
      if (failure && (failure.reason === 'owning_call_unknown' || failure.disposition === 'owning_call_not_dispatched')) stoppedIds.add(failure.stoppedItemId);
      if (closed.terminal.phase === 'completed') {
        const owning = journal.filter(entry => entry.opKind === 'mcp' && entry.opId === context.owningPrepared.opId && entry.attempt === context.owningPrepared.attempt);
        const effect = owning.find(entry => entry.phase === 'completed');
        const stopped = 'stopped' in closed ? closed.stopped : undefined;
        if (stopped) stoppedIds.add(stopped.itemId);
        if (!effect || effect.seq + 1 !== closed.terminal.seq || effect.timestamp !== closed.terminal.timestamp || !stopped)
          invalid('MCP successful server completion has no exact same-transaction owning result');
        const ordered = [...items.values()], index = ordered.findIndex(item => item.itemId === stopped.itemId), result = ordered[index + 1];
        if (index < 0 || result?.kind !== 'tool_result' || result.batchItemId !== stopped.batchItemId || result.callId !== stopped.callId || result.index !== stopped.callIndex ||
            result.opId !== effect.opId || !['executed', 'error'].includes(result.outcome)) invalid('MCP server successful stopped audit does not immediately precede its exact visible result');
      }
    } else if (!['prepared', 'dispatch_claimed'].includes(terminal.phase) || ['failed', 'cancelled', 'succeeded'].includes(run.status))
      invalid('MCP server unretired local lifecycle cannot be terminal, abandoned or reconciled as a remote effect');
  }
  for (const item of items.values()) if (item.kind === 'mcp_server_stopped' && !stoppedIds.has(item.itemId))
    invalid('MCP server stopped audit has no exact original completed or local-owning-call-unknown writer');
  for (const context of contexts) {
    const count = countMcpServerLaunchClaims(journal, requests, { runId: run.id, batchItemId: context.request.batchItemId, callId: context.request.callId,
      callIndex: context.request.callIndex, registryRevisionRef: context.registry.ref, registryManifestDigest: context.registry.registry.manifestDigest });
    if (count > context.target.maxLaunches) invalid('MCP server new grants/replacements reset the immutable original per-call launch ceiling');
  }
  for (const prepared of journal.filter(entry => entry.opKind === 'mcp' && entry.phase === 'prepared')) {
    const rows = journal.filter(entry => entry.opId === prepared.opId && entry.attempt === prepared.attempt), failed = rows.at(-1);
    if (rows.length !== 2 || failed?.phase !== 'failed' || !failed.errorRef) continue;
    const diagnostic = await readCanonicalArtifact<Record<string, unknown>>(artifacts, failed.errorRef);
    if (['mcp_server_launch_exhausted', 'mcp_call_deadline_exceeded'].includes(diagnostic.reason as string))
      await readMcpServerLocalUnavailableHistory(driver, artifacts, run, spec, assembly, items, journal, prepared, failed);
  }
  for (const raw of items.values()) if (raw.kind === 'policy_decision' && raw.subjectKind === 'mcp_server_launch') {
    const item = decodeMcpServerPolicyDecisionItem(raw), evidence = decodeMcpServerPolicyChannelEvidence(await readCanonicalArtifact(artifacts, item.policyChannelEvidenceRef));
    const context = await readMcpServerPermissionContextData(driver, artifacts, run, spec, assembly, evidence.requestRef, evidence.targetRef);
    const priorResults = [...items.values()].slice(0, [...items.keys()].indexOf(item.itemId)).filter(prior => prior.kind === 'tool_result' && prior.batchItemId === context.request.batchItemId);
    if (priorResults.length !== context.request.callIndex || item.policyChannelEvidenceDigest !== evidence.evidenceDigest || item.opId !== context.request.opId || item.principalId !== context.principalId)
      invalid('MCP server policy history overtakes its exact original ordered call');
    if (item.decisionSource === 'interactive_approval') {
      const approved = await readMcpServerApproval(driver, artifacts, context, item.decisionRef); requireEqual(approved.item, item, 'MCP server exact original committed approval item');
    } else if (item.decision === 'allow') {
      const proof = await readMcpServerGrant(driver, artifacts, context, item.grantRef); requireEqual(item, mcpServerPolicyItem(proof.evidence, { grant: proof.grant }), 'MCP server exact direct allow item');
    } else {
      requireEqual(evidence, context.evaluator.evaluate(evidence.evaluatedAt), 'MCP server original direct denying policy');
      if (evidence.effectiveDisposition !== 'deny' || item.decisionRef !== canonicalSha256(evidence)) invalid('MCP server direct denial changes its policy source');
      const result = [...items.values()].find(value => canonicalSha256(value) === item.denialOutcome.outcomeItemRef);
      if (result?.kind !== 'tool_result' || result.outcome !== 'denied' || result.batchItemId !== context.request.batchItemId || result.callId !== context.request.callId || result.index !== context.request.callIndex)
        invalid('MCP server direct denial lacks its exact normalized originating tool result');
    }
  }
}

export async function readMcpServerLocalUnavailableHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, spec: RunSpec, assembly: RunAssemblyV1,
  items: ReadonlyMap<string, import('../kernel/types.js').ContinuationItem>, journal: readonly InvocationJournalEntry[], prepared: InvocationJournalEntry, failed: InvocationJournalEntry) {
  const diagnostic = await readCanonicalArtifact<Record<string, unknown>>(artifacts, failed.errorRef!);
  const deadline = diagnostic.reason === 'mcp_call_deadline_exceeded';
  if (!deadline && diagnostic.reason !== 'mcp_server_launch_exhausted') invalid('foreign MCP local unavailable reason');
  controlWireRecord(diagnostic, ['schemaVersion', 'format', 'code', 'reason', 'requestRef', 'registryRef',
    ...(deadline ? ['callDeadlineMs'] : ['maxLaunchesPerCall', 'lastLaunchOpId', 'lastLaunchAttempt', 'lastLaunchErrorRef'])]);
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, prepared.requestRef), target = await readCanonicalArtifact<ToolTargetV1>(artifacts, prepared.target);
  const grant = prepared.grantRef && await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, prepared.grantRef);
  if (!grant || target.execution.kind !== 'mcp' || diagnostic.schemaVersion !== 1 || diagnostic.format !== 'cliq-tool-output-diagnostic-v1' ||
      diagnostic.code !== 'TOOL_AUTHORITY_UNAVAILABLE' || diagnostic.requestRef !== prepared.requestRef || diagnostic.registryRef !== target.execution.registryRevisionRef ||
      prepared.phase !== 'prepared' || failed.phase !== 'failed' || prepared.opKind !== 'mcp' || failed.opKind !== 'mcp' ||
      prepared.requestRef !== failed.requestRef || prepared.target !== failed.target || prepared.grantRef !== failed.grantRef ||
      journal.some(entry => entry.opId === prepared.opId && entry.phase === 'dispatch_claimed') || failed.timestamp >= run.deadlineAt ||
      failed.timestamp < prepared.timestamp || request.assemblyRef !== spec.assemblyRef)
    invalid('MCP local unavailable result cannot replace a dispatched effect, its original call or true Run expiry');
  requireEqual(journal.filter(entry => entry.opId === prepared.opId && entry.attempt === prepared.attempt), [prepared, failed], 'MCP local unavailable exact original unclaimed effect chain');
  const registry = await readMcpRegistryClosure(driver, artifacts, diagnostic.registryRef as string, readSessionPrincipalId(driver, run.sessionId));
  if (registry.registry.transport.kind !== 'stdio') invalid('MCP local unavailable result borrows another transport');
  const requests = new Map<string, ReturnType<typeof decodeMcpServerLaunchRequest>>(), related: Array<{ prepared: InvocationJournalEntry; closed: Awaited<ReturnType<typeof readMcpServerClosedAttempt>> }> = [];
  let callDeadlineMs = Math.min(parseCanonicalTime(prepared.timestamp) + registry.registry.lifecycle.callTimeoutMs, parseCanonicalTime(run.deadlineAt), parseCanonicalTime(grant.expiresAt));
  for (const serverPrepared of journal.filter(entry => entry.opKind === 'mcp-server' && entry.phase === 'prepared')) {
    const serverRequest = decodeMcpServerLaunchRequest(await readCanonicalArtifact(artifacts, serverPrepared.requestRef)); requests.set(serverPrepared.requestRef, serverRequest);
    if (serverRequest.toolRequestRef !== prepared.requestRef) continue;
    const rows = journal.filter(entry => entry.opId === serverPrepared.opId && entry.attempt === serverPrepared.attempt);
    const closed = await readMcpServerClosedAttempt(driver, artifacts, run, spec, assembly, serverPrepared, rows);
    if (closed.terminal.phase !== 'failed' || closed.terminal.seq >= failed.seq || closed.terminal.timestamp > failed.timestamp)
      invalid('MCP local unavailable result hides an unresolved or successful original local server');
    related.push({ prepared: serverPrepared, closed }); callDeadlineMs = Math.min(callDeadlineMs, closed.context.preparation.callDeadlineMs);
  }
  const count = countMcpServerLaunchClaims(journal, requests, { runId: run.id, batchItemId: request.batchItemId, callId: request.callId,
    callIndex: request.callIndex, registryRevisionRef: registry.ref, registryManifestDigest: registry.registry.manifestDigest });
  if (deadline) {
    if (diagnostic.callDeadlineMs !== callDeadlineMs || Date.parse(failed.timestamp) < callDeadlineMs)
      invalid('MCP local unavailable result replaces its original immutable call deadline');
  } else {
    const last = related.at(-1);
    if (!last || count !== registry.registry.lifecycle.maxLaunchesPerCall || diagnostic.maxLaunchesPerCall !== count ||
        diagnostic.lastLaunchOpId !== last.prepared.opId || diagnostic.lastLaunchAttempt !== last.prepared.attempt || diagnostic.lastLaunchErrorRef !== last.closed.terminal.errorRef)
      invalid('MCP local unavailable result has no exact original immutable launch ceiling');
  }
  if (!failed.budgetSettlementRef) invalid('MCP unavailable result lost its unused original effect reservation settlement');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, failed.budgetSettlementRef));
  requireEqual(settlement.consumed, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, 'MCP local unavailable original unclaimed effect consumes zero');
  requireEqual(failed.budgetDelta, settlement.consumed, 'MCP local unavailable original unclaimed effect Journal charge');
  requireEqual(settlement.reserved, prepared.budgetDelta, 'MCP local unavailable original ordinary effect reservation');
  if (settlement.terminalPhase !== 'failed' || settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== failed.seq || settlement.settledAt !== failed.timestamp ||
      settlement.runId !== run.id || settlement.opId !== prepared.opId || settlement.attempt !== prepared.attempt)
    invalid('MCP local unavailable result changes its unused original effect settlement');
  const item = [...items.values()].find(value => value.kind === 'tool_result' && value.opId === prepared.opId);
  if (item?.kind !== 'tool_result' || item.outcome !== 'error' || item.createdAt !== failed.timestamp || item.batchItemId !== request.batchItemId || item.callId !== request.callId || item.index !== request.callIndex)
    invalid('MCP local unavailable result has no exact ordered normalized ToolResult');
  const payload = await readCanonicalArtifact<import('../kernel/types.js').ToolResultPayloadV1>(artifacts, item.resultRef);
  if (payload.outcome !== 'error' || payload.code !== 'TOOL_AUTHORITY_UNAVAILABLE' || payload.opId !== prepared.opId || payload.attempt !== prepared.attempt ||
      payload.journalErrorRef !== failed.errorRef || payload.journalErrorDigest !== failed.errorRef || payload.diagnosticRef !== failed.errorRef || payload.diagnosticDigest !== failed.errorRef)
    invalid('MCP local unavailable ToolResult substitutes its fixed reason');
  const model = await readCanonicalArtifact<import('../kernel/types.js').ToolResultModelContentV1>(artifacts, payload.modelContentRef);
  requireEqual(model.content, { code: 'TOOL_AUTHORITY_UNAVAILABLE' }, 'MCP local unavailable model-safe content');
  const checkpoint = driver.prepare('SELECT journal_seq,run_item_seq,created_at FROM checkpoints WHERE id=? AND run_id=?')
    .get<{ journal_seq: bigint; run_item_seq: bigint; created_at: string }>((await import('./tool-checkpoint.js')).toolCheckpointId(run.id, prepared.opId, prepared.attempt), run.id);
  if (!checkpoint || Number(checkpoint.journal_seq) !== failed.seq || Number(checkpoint.run_item_seq) !== [...items.keys()].indexOf(item.itemId) + 1 || checkpoint.created_at < failed.timestamp)
    invalid('MCP local unavailable ToolResult lost its same-transaction ready Checkpoint');
  return { diagnostic, related, settlement };
}
