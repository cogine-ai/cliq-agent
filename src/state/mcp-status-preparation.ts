// Exact source reconstruction for one already registered read-only probe.
// No retained artifact can recreate a native owner, peer, token or process.
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { parseCanonicalTime, identityHash } from '../kernel/identity.js';
import { MCP_RESPONSE_BYTES } from '../kernel/mcp.js';
import { decodeMcpInvocationWait, decodeMcpStatusProbePreparation, type McpStatusProbePreparationV1, type McpInvocationWaitV1 } from '../kernel/mcp-status.js';
import type { ProcessContainmentPlanV1, SandboxLaunchSpecV1 } from '../kernel/execution.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { KernelStorageError } from './errors.js';
import { readMcpStdioLaunchRecipeData } from './mcp-stdio-launch.js';
import { decodeMcpStdioRecipeData, MCP_STDIO_RECIPE_HEADER_BYTES } from './mcp-stdio-recipe.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
import type { McpStdioRecoveryBinding } from './mcp-stdio-broker-native.js';
import type { RecoveryMcpStdioInputBinding } from './native-owner.js';
import { decodeMcpStatusProbeWrapper } from './mcp-status-proof.js';
import { mcpReadonlyStatusRequestData, type readMcpReconcileSource } from './mcp-status-source.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import type { SqliteDriver } from './sqlite-driver.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
type Source = Awaited<ReturnType<typeof readMcpReconcileSource>>;
export async function readMcpStatusProbePreparation(driver: SqliteDriver, artifacts: ArtifactCatalog, waitValue: McpInvocationWaitV1, source: Source) {
  const wait = decodeMcpInvocationWait(waitValue), state = wait.probeState;
  if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || state.dispatch.subjectKind !== 'mcp_recovery')
    fail('MCP status preparation has no exact original in-flight probe');
  const dispatch = state.dispatch, preparation = decodeMcpStatusProbePreparation(await readCanonicalArtifact(artifacts, dispatch.preparationRef));
  if (preparation.preparationDigest !== dispatch.preparationDigest || preparation.runId !== wait.runId ||
      preparation.principalId !== source.original.principalId || preparation.previousWaitingSubjectRef !== dispatch.previousWaitingSubjectRef ||
      preparation.reconciliationSubjectDigest !== dispatch.reconciliationSubjectDigest || preparation.probeKind !== dispatch.probeKind ||
      preparation.probeOrdinal !== dispatch.probeOrdinal || preparation.probeNonceDigest !== dispatch.probeNonceDigest ||
      preparation.createdAt !== dispatch.probeStartedAt || preparation.probeDeadlineAt !== dispatch.probeDeadlineAt ||
      preparation.brokerDispatchId !== dispatch.brokerDispatchId || preparation.brokerFenceTokenDigest !== dispatch.brokerFenceTokenDigest ||
      preparation.brokerRequestDigest !== dispatch.brokerRequestDigest || preparation.brokerTargetDigest !== dispatch.brokerTargetDigest ||
      preparation.inspectorSupervisorInstanceId !== dispatch.owningSupervisorInstanceId)
    fail('MCP probe changes its original persisted preparation/request/target/fence/owner/deadline');
  if (preparation.brokerDispatchId !== identityHash('cliq-mcp-readonly-status-dispatch-v1', wait.runId, canonicalSha256(source.subject),
    dispatch.probeKind, dispatch.probeOrdinal, dispatch.probeNonceDigest))
    fail('MCP status original broker dispatch lost its fixed domain-separated identity');
  const previous = decodeMcpInvocationWait(await readCanonicalArtifact(artifacts, preparation.previousWaitingSubjectRef));
  const { probeState: _state, ...base } = wait, { probeState: previousState, ...previousBase } = previous;
  requireEqual(base, previousBase, 'MCP status immutable original wait source');
  requireEqual(wait.subject, source.subject, 'MCP status exact original signed invocation subject');
  if (dispatch.probeKind === 'automatic' ? previousState.phase !== 'automatic_pending' ||
      dispatch.probeOrdinal !== previousState.automaticProbeCount + 1 || dispatch.probeStartedAt < previousState.nextProbeAt
    : previousState.phase !== 'automatic_exhausted' || dispatch.probeOrdinal !== previousState.userProbeCount + 1)
    fail('MCP status probe changes its original bounded count, user exhaustion or real backoff');
  if (previousState.phase === 'automatic_exhausted') {
    const last = decodeMcpStatusProbeWrapper(await readCanonicalArtifact(artifacts, previousState.lastProbeEvidenceRef));
    if (last.evidenceDigest !== previousState.lastProbeEvidenceDigest || dispatch.probeStartedAt < last.observedAt)
      fail('MCP user status preparation regressed the exact original last probe closure');
  }
  const request = mcpReadonlyStatusRequestData(source, { previousWaitingSubjectRef: preparation.previousWaitingSubjectRef, wait: previous,
    probeKind: preparation.probeKind, probeOrdinal: preparation.probeOrdinal, probeNonceDigest: preparation.probeNonceDigest,
    probeStartedAt: preparation.createdAt, probeDeadlineAt: preparation.probeDeadlineAt, supervisorInstanceId: preparation.inspectorSupervisorInstanceId,
    stateOwnerEpoch: preparation.inspectorStateOwnerEpoch });
  if (request.requestArtifact.ref !== preparation.brokerRequestRef || request.request.requestDigest !== preparation.brokerRequestDigest ||
      request.targetArtifact.ref !== preparation.brokerTargetRef || request.target.targetDigest !== preparation.brokerTargetDigest)
    fail('MCP probe substitutes its exact acyclic original broker request or target');
  requireEqual(await readCanonicalArtifact(artifacts, preparation.brokerRequestRef), request.request, 'MCP complete original status broker request');
  requireEqual(await readCanonicalArtifact(artifacts, preparation.brokerTargetRef), request.target, 'MCP complete original signed status target');
  requireEqual(await artifacts.readBytes(request.statusRequest.ref), request.statusRequest.bytes, 'MCP complete exact original read-only status frame');
  const history = await readRetainedStateOwnerHistory(driver, artifacts, preparation.inspectorStateOwnerEpoch);
  const original = history.entries.find(entry => entry.owner.ownerEpoch === preparation.inspectorStateOwnerEpoch);
  if (!original || original.owner.supervisorInstanceId !== preparation.inspectorSupervisorInstanceId || original.owner.acquiredAt > preparation.createdAt ||
      original.owner.state === 'terminal' && original.owner.releasedAt < preparation.createdAt ||
      original.owner.runtimeBundleRef !== source.assembly.runtime.runtimeBundleRef || original.owner.runtimeBundleManifestDigest !== source.assembly.runtime.runtimeBundleManifestDigest ||
      original.process.pid !== preparation.originalSupervisor.pid || original.process.processStartToken !== preparation.originalSupervisor.processStartToken)
    fail('MCP status intent has no actual original signed StateOwner process provenance');
  const resources = decodeSandboxProfile(await readCanonicalArtifact(artifacts, source.spec.sandboxProfileRef)).resources;
  const plan = await readCanonicalArtifact<ProcessContainmentPlanV1>(artifacts, preparation.plannedContainmentRef), spec = await readCanonicalArtifact<SandboxLaunchSpecV1>(artifacts, preparation.sandboxLaunchSpecRef);
  if (plan.backend.kind !== 'linux') fail('MCP signed status recovery lost its exact original Linux containment');
  const processOwner = { kind: 'reconciliation_probe' as const, runId: wait.runId, principalId: source.original.principalId,
    originalOpId: source.claim.opId, originalAttempt: source.claim.attempt, originalDispatchId: source.claim.dispatchId!,
    previousWaitingSubjectRef: preparation.previousWaitingSubjectRef, probeKind: preparation.probeKind, probeOrdinal: preparation.probeOrdinal,
    probeNonceDigest: preparation.probeNonceDigest, brokerDispatchId: preparation.brokerDispatchId,
    supervisorInstanceId: preparation.inspectorSupervisorInstanceId, stateOwnerEpoch: preparation.inspectorStateOwnerEpoch };
  await readMcpStdioLaunchRecipeData(artifacts, { purpose: { kind: 'recovery', owner: processOwner, requestRef: preparation.brokerRequestRef,
    requestDigest: preparation.brokerRequestDigest, targetRef: preparation.brokerTargetRef, targetDigest: preparation.brokerTargetDigest },
    bundle: source.bundle, originalController: { subreaperStartToken: `linux-subreaper:${preparation.controller.pid}:${preparation.controller.processStartToken}` },
    cgroupParent: path.posix.dirname(plan.backend.cgroupPath), ownerUid: history.rootIdentity.ownerUid, executable: source.transport.executable,
    nonce: preparation.nonce, createdAt: preparation.createdAt, resources, plan, spec });
  if (plan.planDigest !== preparation.plannedContainmentDigest || spec.launchSpecDigest !== preparation.sandboxLaunchSpecDigest)
    fail('MCP status intent substitutes its complete original plan/spec digests');
  const recipeBytes = await artifacts.readBoundedBytes(preparation.nativeRecipeRef, MCP_STDIO_RECIPE_HEADER_BYTES + 128 * 8193 + 4 * MCP_RESPONSE_BYTES), recipe = decodeMcpStdioRecipeData(recipeBytes);
  const server = source.bundle.entries.find(entry => entry.entryId === source.executable.executableId);
  if (!server || recipe.recipeDigest !== preparation.nativeRecipeRef) fail('MCP status lost its exact original sealed recipe bytes');
  assertMcpStdioRecipeData(recipe, { purpose: 'recovery', transport: source.transport, serverByteCount: server.byteCount, resources,
    effectServerToolName: source.original.execution.serverToolName, statusOperationName: source.template.statusOperationName, arguments: source.argumentsValue });
  return { wait, previous, dispatch, preparation, request, history, original, resources, plan, spec, recipe, recipeBytes,
    ...mcpStatusProbeBinding(source, wait, preparation) };
}

/** Pure projection, not a native handle or permission. */
export function mcpStatusProbeBinding(source: Source, wait: McpInvocationWaitV1, preparation: McpStatusProbePreparationV1) {
  const state = wait.probeState;
  if ((state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight') || state.dispatch.subjectKind !== 'mcp_recovery')
    fail('MCP status binding has no exact persisted native purpose3 dispatch');
  const dispatch = state.dispatch;
  const binding: McpStdioRecoveryBinding = { runId: wait.runId, principalId: source.original.principalId, probeKind: preparation.probeKind,
    brokerDispatchId: preparation.brokerDispatchId, inspectorSupervisorInstanceId: preparation.inspectorSupervisorInstanceId,
    originalOpId: source.claim.opId, originalDispatchId: source.claim.dispatchId!, effectServerToolName: source.original.execution.serverToolName,
    adapterExecutableId: source.manifest.entryId, profileId: source.profile.profileId, statusOperationName: source.template.statusOperationName,
    previousWaitingSubjectRef: preparation.previousWaitingSubjectRef, waitingSubjectRef: canonicalSha256(wait), reconciliationSubjectDigest: canonicalSha256(source.subject),
    probeNonceDigest: preparation.probeNonceDigest, probeDispatchDigest: dispatch.dispatchDigest, brokerRequestDigest: preparation.brokerRequestDigest,
    brokerTargetDigest: preparation.brokerTargetDigest, brokerFenceTokenDigest: preparation.brokerFenceTokenDigest,
    originalInstanceIdentityRef: source.claim.evidenceRef!, originalInstanceIdentityDigest: source.claim.evidenceDigest!,
    registryRevisionRef: source.registry.ref, registryManifestDigest: source.registry.registry.manifestDigest,
    adapterRef: source.recovery.adapterRef, adapterDigest: source.recovery.adapterDigest, adapterExecutableDigest: source.manifest.executableDigest,
    profileDigest: source.profile.profileDigest, statusRequestTemplateRef: source.recovery.statusRequestTemplateRef,
    statusRequestTemplateDigest: source.recovery.statusRequestTemplateDigest, statusRequestDigest: source.statusRequest.digest,
    plannedContainmentRef: preparation.plannedContainmentRef, plannedContainmentDigest: preparation.plannedContainmentDigest,
    sandboxLaunchSpecRef: preparation.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: preparation.sandboxLaunchSpecDigest, nonce: preparation.nonce,
    probeOrdinal: preparation.probeOrdinal, probeStartedAtMs: parseCanonicalTime(preparation.createdAt), probeDeadlineAtMs: parseCanonicalTime(preparation.probeDeadlineAt),
    inspectorStateOwnerEpoch: preparation.inspectorStateOwnerEpoch, originalAttempt: source.claim.attempt, originalDispatchJournalSeq: source.claim.seq };
  const inputBinding: RecoveryMcpStdioInputBinding = { ...binding, originalSupervisorPid: preparation.originalSupervisor.pid,
    originalSupervisorStartToken: preparation.originalSupervisor.processStartToken };
  return { binding, inputBinding };
}
