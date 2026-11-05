// Owning State transitions for the independently charged call-scoped server.
// The ordinary MCP effect keeps its existing request/grant/claim and budget.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { parseCanonicalTime, identityHash, digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { countMcpServerLaunchClaims, decodeMcpServerLaunchRequest, decodeMcpServerApprovalWait,
  decodeMcpServerPolicyChannelEvidence, decodeMcpServerLaunchPreparation } from '../kernel/mcp-server-authorization.js';
import type { Run, RunAssemblyV1, RunSpec, InvocationJournalEntry } from '../kernel/types.js';
import type { RunPolicySnapshotV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { ArtifactCatalog } from './artifacts.js';
import { insertArtifactMetadata } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { assertChildAncestryRelease } from './child-ancestry.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { planMcpServerLaunch, loadMcpServerPolicy, decodeMcpStdioExecutableIdentity } from './mcp-server-policy.js';
import { readMcpServerGrant, readMcpServerApproval, readMcpServerApprovalWait, mcpServerPolicyItem, mcpServerApprovalCheckpointId,
  mcpServerDecisionCheckpointId, type McpServerPermissionContext } from './mcp-server-permission.js';
import { readMcpRegistryClosure } from './mcp-registration.js';
import type { NativeMcpStdioRunOwner, RunMcpStdioLaunchBinding } from './mcp-stdio-broker-native.js';
import { assertInstalledMcpStdioRunOwner, readInstalledMcpStdioRecipeData } from './mcp-stdio-native-binding.js';
import { decodeMcpStdioRecipeData } from './mcp-stdio-recipe.js';
import { assertMcpStdioRecipeData } from './mcp-stdio-recipe-audit.js';
import { readMcpRequestArguments } from './mcp-request-arguments.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { readHighestPreparedAttempt, readInvocationAttempt, readInvocationJournal, nextJournalSequence } from './repositories/journal.js';
import { appendRunStateEvent, assertLiveDispatchState, claimValidatedInvocation, requireHealthyFence,
  settleValidatedInvocation, type ClaimInvocationDispatchInput } from './reducers/invocation.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRun, readControlRequest, insertControlRequest } from './rows.js';
import { ZERO_BUDGET } from './rows.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { validateControlChannelClosure } from './control-channel.js';
import { toolApprovalDecision, toolApprovalRequestDigest, type ToolApprovalInput } from '../policy/tool-approval.js';
import type { ApprovalResponse } from './tool-approval-recovery.js';
import { assertBudgetWithin, addBudget } from './invariants.js';
import { randomBytes } from 'node:crypto';
import type { LinuxWorkerController } from '../sandbox/linux-worker.js';
import { assertLinuxWorkerController } from '../sandbox/linux-worker.js';
import { withHeldInstalledRuntime, withInstalledWorkerRoot, type HeldInstalledRuntime, type HeldInstalledAnchor } from './installed-runtime.js';
import { publishMcpStdioLaunch } from './mcp-stdio-launch.js';
import { readRequiredWorkerLaunch } from './repositories/worker-launches.js';
import { decodePlatformProcessIdentity } from './decoders.js';
import { appendInvocationJournalEntry } from './repositories/journal.js';
import { readInstalledMcpStdioRunReservation, type InstalledMcpStdioRunScope } from '../sandbox/mcp-stdio-native.js';
import type { HeldRunMcpStdioInput } from './native-owner.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import type { ToolCut } from './tool-cut.js';

const LAUNCH_BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
export type McpServerLifecycleComposition = Readonly<{
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; principalId: string; workspaceIdentityDigest: string;
  cut(revision?: number, reads?: ArtifactCatalog): Promise<ToolCut>;
  requestFor(selected: ToolCut): Readonly<{ request: ToolRequestV1; target: ToolTargetV1 }>;
  assertCut(connection: SqliteConnection, run: Run, selected: ToolCut): void;
  assertRuntime(reads: ArtifactCatalog, signal?: AbortSignal): Promise<void>;
}>;
/** Composition is captured by the original loaded tool continuation. It is
 * neither a StateStore option nor a public callback-selected authority. */
export function loadMcpServerLifecycle(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  original: McpServerLifecycleComposition) {
  const runId = original.run.id;
  const liveLaunches = new Map<string, { native: NativeMcpStdioRunOwner; binding: RunMcpStdioLaunchBinding; claim: InvocationJournalEntry }>();
  async function context(selected: ToolCut, reads: ArtifactCatalog) {
    const effect = original.requestFor(selected);
    if (effect.target.execution.kind !== 'mcp') return undefined;
    const registry = await readMcpRegistryClosure(driver, reads, effect.target.execution.registryRevisionRef, original.principalId);
    if (registry.registry.transport.kind !== 'stdio') return undefined;
    const related: Array<{ prepared: InvocationJournalEntry; request: ReturnType<typeof decodeMcpServerLaunchRequest> }> = [];
    const requests = new Map<string, ReturnType<typeof decodeMcpServerLaunchRequest>>();
    for (const prepared of selected.journal.filter(row => row.opKind === 'mcp-server' && row.phase === 'prepared')) {
      const request = decodeMcpServerLaunchRequest(await readCanonicalArtifact(reads, prepared.requestRef));
      requests.set(prepared.requestRef, request);
      if (request.runId !== runId) throw new TypeError('MCP server history substitutes its owning Run');
      if (request.batchItemId === effect.request.batchItemId && request.callId === effect.request.callId && request.callIndex === effect.request.callIndex) {
        if (request.toolRequestRef !== canonicalSha256(effect.request) || request.toolRequestDigest !== effect.request.requestDigest ||
            request.registryRevisionRef !== registry.ref || request.registryManifestDigest !== registry.registry.manifestDigest)
          throw new TypeError('MCP server lifecycle substitutes its exact originating call/registry');
        related.push({ prepared, request });
      }
    }
    const latest = related.at(-1), entries = latest && readInvocationAttempt(driver, runId, latest.prepared.opId, latest.prepared.attempt);
    if (latest && entries?.at(-1)?.phase === 'dispatch_claimed') {
      const live = liveLaunches.get(JSON.stringify([latest.prepared.opId, latest.prepared.attempt]));
      if (!live) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original server launch needs its retained native owner or separate actual cleanup');
      requireEqual(live.claim, entries.at(-1), 'MCP server exact original retained permanent claim');
      assertInstalledMcpStdioRunOwner(live.native, live.binding);
    }
    // The next lifecycle is selected only by the purpose-specific retained
    // positive failure/death reader. An arbitrary failed row is insufficient.
    const previous = latest && entries && ['failed', 'completed', 'unknown', 'abandoned'].includes(entries.at(-1)!.phase)
      ? await (await import('./mcp-server-history.js')).readMcpServerClosedAttempt(driver, reads, original.run, original.spec, original.assembly,
        latest.prepared, entries) : undefined;
    if (previous?.terminal.phase === 'completed') throw new KernelStorageError('RECOVERY_REQUIRED', 'completed MCP server launch cannot retain an unanswered owning tool frontier');
    const lifecycleSeq = latest ? latest.request.lifecycleSeq + (previous?.instanceInitialized ? 1 : 0) : 0;
    const planned = planMcpServerLaunch({ ...effect, registryRef: registry.ref, registry: registry.registry, lifecycleSeq });
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(reads, original.spec.policyRef);
    const evaluator = loadMcpServerPolicy({ policy, policyRef: original.spec.policyRef, assembly: original.assembly,
      principalId: original.principalId, workspaceIdentityDigest: original.workspaceIdentityDigest, ...planned });
    const permission: McpServerPermissionContext = { run: selected.run, spec: original.spec, ...planned, evaluator };
    const claims = countMcpServerLaunchClaims(selected.journal, requests, { ...requestIdentity(effect.request),
      registryRevisionRef: registry.ref, registryManifestDigest: registry.registry.manifestDigest });
    const originalEffect = readHighestPreparedAttempt(driver, runId, effect.request.opId);
    let callDeadlineMs: number | undefined;
    if (originalEffect?.grantRef) {
      const grant = await readCanonicalArtifact<import('../kernel/tool-authorization.js').ToolOperationGrantV1>(reads, originalEffect.grantRef);
      const firstEffect = selected.journal.find(entry => entry.opId === originalEffect.opId && entry.phase === 'prepared');
      if (!firstEffect) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original call lost its first owning effect preparation');
      callDeadlineMs = Math.min(parseCanonicalTime(firstEffect.timestamp) + registry.registry.lifecycle.callTimeoutMs,
        parseCanonicalTime(selected.run.deadlineAt), parseCanonicalTime(grant.expiresAt));
    }
    for (const prior of related) {
      if (!prior.prepared.evidenceRef) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original call deadline has no mandatory first-prepared resource intent');
      const preparation = decodeMcpServerLaunchPreparation(await readCanonicalArtifact(reads, prior.prepared.evidenceRef));
      if (preparation.preparationDigest !== prior.prepared.evidenceDigest || preparation.toolRequestRef !== canonicalSha256(effect.request))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original call deadline borrows another preparation');
      callDeadlineMs = Math.min(callDeadlineMs ?? preparation.callDeadlineMs, preparation.callDeadlineMs);
    }
    return { ...permission, effect, registry, executable: decodeMcpStdioExecutableIdentity(registry.registry.transport.executable),
      related, latest, entries, previous, claims, callDeadlineMs, items: selected.items, journal: selected.journal };
  }
  const requestIdentity = (request: ToolRequestV1) => ({ runId: request.runId, batchItemId: request.batchItemId, callId: request.callId, callIndex: request.callIndex });
  async function choose(selected: NonNullable<Awaited<ReturnType<typeof context>>>, at: string, reads: ArtifactCatalog) {
    const evidence = selected.evaluator.evaluate(at);
    if (selected.callDeadlineMs !== undefined && parseCanonicalTime(at) >= selected.callDeadlineMs)
      return { evidence, grant: undefined, prior: undefined, existing: false, exhausted: false as const, unavailableReason: 'mcp_call_deadline_exceeded' as const };
    const priorItems = selected.items.filter(row => row.item.kind === 'policy_decision' && row.item.subjectKind === 'mcp_server_launch' && row.item.opId === selected.request.opId)
      .map(row => row.item);
    const approved = priorItems.filter(item => item.kind === 'policy_decision' && item.subjectKind === 'mcp_server_launch' && item.decision === 'allow').at(-1);
    const priorRef = approved?.kind === 'policy_decision' && approved.subjectKind === 'mcp_server_launch' && approved.decision === 'allow'
      ? approved.grantRef : selected.latest?.prepared.opId === selected.request.opId ? selected.latest.prepared.grantRef : undefined;
    if (priorRef) {
      const prior = await readMcpServerGrant(driver, reads, selected, priorRef);
      const uses = selected.related.filter(row => row.prepared.grantRef === priorRef)
        .reduce((count, row) => count + readInvocationAttempt(driver, runId, row.prepared.opId, row.prepared.attempt).filter(entry => entry.phase === 'dispatch_claimed').length, 0);
      if (at < prior.grant.expiresAt && uses < prior.grant.maxDispatchedAttempts && selected.claims < prior.grant.maxLaunches)
        return { evidence: prior.evidence, grant: prior.grant, prior, existing: true, exhausted: false as const, unavailableReason: undefined };
    }
    if (selected.claims >= selected.target.maxLaunches) return { evidence, grant: undefined, prior: undefined, existing: false, exhausted: true as const,
      unavailableReason: 'mcp_server_launch_exhausted' as const };
    return { evidence, grant: evidence.effectiveDisposition === 'allow' ? selected.evaluator.grant(evidence, at, selected.run.deadlineAt) : undefined,
      prior: undefined, existing: false, exhausted: false as const, unavailableReason: undefined };
  }
  async function selection(selected: ToolCut, reads: ArtifactCatalog) {
    const selectedContext = await context(selected, reads);
    if (!selectedContext) return undefined;
    const permission = await choose(selectedContext, sampleCanonicalNow(), reads);
    return { context: selectedContext, ...permission };
  }
  async function originalRecipe(selected: NonNullable<Awaited<ReturnType<typeof context>>>, native: NativeMcpStdioRunOwner, reads: ArtifactCatalog) {
    const transport = selected.registry.registry.transport;
    if (transport.kind !== 'stdio' || transport.executable.kind !== 'runtime_bundle' || selected.effect.target.execution.kind !== 'mcp')
      throw new TypeError('MCP server original native recipe has no exact stdio runtime target');
    const bytes = readInstalledMcpStdioRecipeData(native), data = decodeMcpStdioRecipeData(bytes);
    const bundle = await readCanonicalArtifact<import('../policy/runtime-authority.js').RuntimeBundleManifest>(reads, transport.executable.runtimeBundleRef);
    const executableId = transport.executable.executableId, server = bundle.entries.filter(entry => entry.entryId === executableId);
    if (server.length !== 1 || server[0]!.role !== 'mcp_server' || !server[0]!.executable || server[0]!.digest !== transport.executable.executableDigest)
      throw new TypeError('MCP original native recipe substitutes its exact signed server bytes');
    const resources = decodeSandboxProfile(await readCanonicalArtifact(reads, original.spec.sandboxProfileRef)).resources;
    const call = await readCanonicalArtifact<import('../protocol/agent-ir.js').ToolCallInputV1>(reads, selected.effect.request.inputRef);
    if (canonicalSha256(call) !== selected.effect.request.inputRef || call.inputDigest !== selected.effect.request.inputDigest)
      throw new TypeError('MCP original native recipe changes the normalized owning effect input');
    const argumentsValue = await readMcpRequestArguments(reads, { ...selected.effect, registry: selected.registry.registry, registryRef: selected.registry.ref, call });
    assertMcpStdioRecipeData(data, { purpose: 'run', transport, serverByteCount: server[0]!.byteCount, resources,
      serverToolName: selected.effect.target.execution.serverToolName, arguments: argumentsValue });
    return { bytes, data };
  }
  return Object.freeze({
    selectMcpServerPermission: selection,
    settleMcpServerUnavailable: stateOperation('RECOVERY_REQUIRED', async (selectedCut: ToolCut, reads: ArtifactCatalog) => {
      const selected = await selection(selectedCut, reads);
      if (!selected?.unavailableReason || (selected.unavailableReason === 'mcp_server_launch_exhausted'
        ? selected.context.claims !== selected.context.target.maxLaunches || !selected.context.previous
        : selected.context.callDeadlineMs === undefined || Date.now() < selected.context.callDeadlineMs))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP local unavailable result requires its exact original launch ceiling or immutable call expiry and positive closure');
      for (const prior of selected.context.related) {
        const rows = readInvocationAttempt(driver, runId, prior.prepared.opId, prior.prepared.attempt);
        await (await import('./mcp-server-history.js')).readMcpServerClosedAttempt(driver, reads, selectedCut.run, original.spec, original.assembly, prior.prepared, rows);
      }
      const effect = readHighestPreparedAttempt(driver, runId, selected.context.effect.request.opId);
      if (!effect || effect.phase !== 'prepared' || readInvocationAttempt(driver, runId, effect.opId, effect.attempt).length !== 1 ||
          effect.requestRef !== selected.context.request.toolRequestRef || selectedCut.run.stopIntentRef || selectedCut.run.cancelRequested)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP exhausted server cannot replace an ordinary claimed effect or Stop');
      const diagnostic = await reads.publishCanonical({ schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1', code: 'TOOL_AUTHORITY_UNAVAILABLE',
        reason: selected.unavailableReason, requestRef: effect.requestRef, registryRef: selected.context.registry.ref,
        ...(selected.unavailableReason === 'mcp_server_launch_exhausted' ? { maxLaunchesPerCall: selected.context.target.maxLaunches,
          lastLaunchOpId: selected.context.latest!.prepared.opId, lastLaunchAttempt: selected.context.latest!.prepared.attempt,
          lastLaunchErrorRef: selected.context.previous!.terminal.errorRef! } : { callDeadlineMs: selected.context.callDeadlineMs }) }, 'cliq-tool-output-diagnostic-v1');
      const { planToolInvocationResult, nextToolFrontier } = await import('./reducers/tool.js');
      const result = await settleValidatedInvocation(driver, reads, owner, { runId, opId: effect.opId, attempt: effect.attempt,
        expectedRunRevision: selectedCut.run.revision }, { phase: 'failed', errorRef: diagnostic.ref, consumed: ZERO_BUDGET, requireClaim: false },
      async ({ settlement }) => {
        const result = planToolInvocationResult(selected.context.effect.request, settlement.settledAt, { outcome: 'error', code: 'TOOL_AUTHORITY_UNAVAILABLE',
          opId: effect.opId, attempt: effect.attempt, journalErrorRef: diagnostic.ref, journalErrorDigest: diagnostic.ref,
          diagnosticRef: diagnostic.ref, diagnosticDigest: diagnostic.ref }, { code: 'TOOL_AUTHORITY_UNAVAILABLE' });
        const graph = await prepareContinuationCommit(reads, { context: selectedCut.context, existingItems: selectedCut.items, items: [result.item],
          frontier: nextToolFrontier(selectedCut, 1), checkpointId: toolCheckpointId(runId, effect.opId, effect.attempt),
          workspaceStateRef: selectedCut.checkpoint.workspaceStateRef, artifacts: result.artifacts });
        return { metadata: [diagnostic, ...graph.metadata], validate(connection, run, now) {
          original.assertCut(connection, run, selectedCut); selected.context.registry.assertUnchanged(connection);
          requireEqual(readInvocationJournal(connection, runId), selectedCut.journal, 'MCP exhaustion exact original positive closed launch history');
          requireEqual(readInvocationAttempt(connection, runId, effect.opId, effect.attempt), [effect], 'MCP exhaustion original unclaimed ordinary effect');
          assertLiveDispatchState(connection, owner, runId, selectedCut.run.revision, selectedCut.run.leaseEpoch, now);
          if (run.cancelRequested || run.stopIntentRef || now >= run.deadlineAt ||
              selected.unavailableReason === 'mcp_call_deadline_exceeded' && parseCanonicalTime(now) < selected.context.callDeadlineMs!)
            throw new KernelStorageError('LEASE_FENCED', 'MCP local unavailable result cannot overtake its true Stop/Run deadline or precede original call expiry');
        }, commit(connection, run, entry, now) { graph.commit(connection, run, entry.seq, now); } };
      });
      return immutableSnapshot({ disposition: 'denied' as const, run: result.run });
    }),
    async publishMcpServerApproval(selected: ToolCut, reads: ArtifactCatalog) {
      const permission = await selection(selected, reads);
      if (!permission || permission.grant || permission.evidence.effectiveDisposition !== 'ask' || selected.run.activeWorkerLaunchId)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server approval requires its own exact worker-free asking cut');
      const wait = permission.context.evaluator.approvalWait(permission.evidence, selected.run.revision);
      const metadata = await reads.mapReads([planCanonicalArtifact(permission.context.request, permission.context.request.format),
        planCanonicalArtifact(permission.context.target, permission.context.target.format), planCanonicalArtifact(permission.evidence, permission.evidence.format),
        planCanonicalArtifact(wait, 'cliq-waiting-subject-v1'),
        planCanonicalArtifact(permission.context.executable, 'cliq-mcp-server-executable-identity-v1')], plan => reads.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
      return immutableSnapshot({ disposition: 'mcp_server_approval_required' as const, run: selected.run,
        waitingOnRef: canonicalSha256(wait), checkpointId: mcpServerApprovalCheckpointId(canonicalSha256(wait)), metadata });
    },
    waitForMcpServerApproval: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; waitingOnRef: string }) => {
      await original.assertRuntime(artifacts);
      const cut = await original.cut(input.expectedRunRevision), selected = await context(cut, artifacts);
      const wait = decodeMcpServerApprovalWait(await readCanonicalArtifact(artifacts, input.waitingOnRef));
      const evidence = decodeMcpServerPolicyChannelEvidence(await readCanonicalArtifact(artifacts, wait.subject.policyChannelEvidenceRef));
      if (!selected || cut.run.status !== 'queued' || cut.run.activeWorkerLaunchId || cut.run.stopIntentRef || cut.run.cancelRequested)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server wait requires its original worker-free unanswered tool cut');
      requireEqual(wait, selected.evaluator.approvalWait(evidence, cut.run.revision), 'MCP server exact original prospective wait');
      const tool = readHighestPreparedAttempt(driver, runId, selected.effect.request.opId);
      if (tool) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP launch wait cannot overtake an already prepared owning effect');
      const plan = await prepareContinuationCommit(artifacts, { context: cut.context, existingItems: cut.items, items: [], frontier: cut.frontier,
        checkpointId: mcpServerApprovalCheckpointId(input.waitingOnRef), workspaceStateRef: cut.checkpoint.workspaceStateRef });
      const metadata = await artifacts.mapReads([[input.waitingOnRef, 'cliq-waiting-subject-v1'], [canonicalSha256(evidence), evidence.format],
        [canonicalSha256(selected.request), selected.request.format], [canonicalSha256(selected.target), selected.target.format],
        [selected.target.executableIdentityRef, 'cliq-mcp-server-executable-identity-v1']],
      ([ref, format]) => artifacts.describe(ref!, 'application/json', format!));
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      driver.transaction(connection => {
        assertActiveStateOwner(connection, owner); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        requireEqual(readRun(connection, runId), cut.run, 'MCP launch exact waiting Run cut');
        requireEqual(readInvocationJournal(connection, runId), cut.journal, 'MCP launch exact waiting complete Journal cut');
        original.assertCut(connection, cut.run, cut); selected.registry.assertUnchanged(connection);
        if (now < wait.createdAt || now >= cut.run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'MCP launch asking evidence or Run lifetime changed');
        for (const artifact of [...metadata, ...plan.metadata]) insertArtifactMetadata(connection, artifact, now);
        plan.commit(connection, cut.run, nextJournalSequence(connection, runId) - 1, now);
        connection.prepare("UPDATE runs SET status='waiting',waiting_reason='approval',waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?")
          .run(input.waitingOnRef, now, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, now);
      }); requireHealthyFence(outcome); return immutableSnapshot({ run: updated, waitingOnRef: input.waitingOnRef });
    }),
    approveMcpServer: stateOperation('INVALID_REQUEST', async (input: ToolApprovalInput, signal?: AbortSignal) => {
      input = immutableSnapshot(input);
      if (input.principalId !== original.principalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP server approval caller does not own the exact Run');
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts, requestDigest = toolApprovalRequestDigest(runId, input);
      const channel = await validateControlChannelClosure(reads, owner, input); await original.assertRuntime(reads, signal);
      const wait = decodeMcpServerApprovalWait(await readCanonicalArtifact(reads, input.waitingOnRef));
      const evidence = decodeMcpServerPolicyChannelEvidence(await readCanonicalArtifact(reads, wait.subject.policyChannelEvidenceRef));
      const permission = await (await import('./mcp-server-history.js')).readMcpServerPermissionContextData(driver, reads,
        readRun(driver, runId), original.spec, original.assembly, evidence.requestRef, evidence.targetRef);
      async function replay() {
        const row = readControlRequest(driver, input.principalId, 'run.approve', input.requestId); if (!row) return undefined;
        if (row.requestDigest !== requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'MCP server approval requestId names different exact wire bytes');
        const response = await readCanonicalArtifact<ApprovalResponse>(reads, row.responseRef);
        const verified = await readMcpServerApproval(driver, reads, permission, response.result.decisionRef);
        requireEqual(verified.control, row, 'MCP server replay original control row'); requireEqual(response, verified.response, 'MCP server replay complete first response');
        return immutableSnapshot({ replayed: true, run: response.result.snapshot.run, response });
      }
      const replayed = await replay(); if (replayed) return replayed;
      const selected = await original.cut(input.expectedRunRevision, reads);
      if (selected.run.status !== 'waiting' || selected.run.waitingReason !== 'approval' || selected.run.waitingOnRef !== input.waitingOnRef || selected.run.activeWorkerLaunchId ||
          selected.run.stopIntentRef || selected.run.cancelRequested) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server approval requires its exact unretired worker-free current wait');
      requireEqual(original.requestFor(selected).request, permission.tool, 'MCP server approval exact original pending effect');
      const proof = await readMcpServerApprovalWait(driver, reads, permission, input.waitingOnRef);
      const { planToolInvocationResult, nextToolFrontier } = await import('./reducers/tool.js');
      for (let retry = 0; retry < 8; retry++) {
        const createdAt = sampleCanonicalNow(), decision = toolApprovalDecision(proof.wait, input, createdAt, selected.run.deadlineAt);
        const grant = permission.evaluator.approve(proof.evidence, proof.wait, decision, selected.run.deadlineAt);
        const decisionPlan = planCanonicalArtifact(decision, decision.format), grantPlan = grant && planCanonicalArtifact(grant, grant.format);
        const denied = grant ? undefined : planToolInvocationResult(permission.tool, createdAt, { outcome: 'denied', code: 'TOOL_CALL_DENIED',
          denial: { source: 'user', approvalDecisionRef: decisionPlan.ref, approvalDecisionDigest: decision.decisionDigest } }, { code: 'TOOL_CALL_DENIED' });
        const item = mcpServerPolicyItem(proof.evidence, grant ? { grant } : { outcomeItemRef: canonicalSha256(denied!.item) }, decision);
        const graph = await prepareContinuationCommit(reads, { context: selected.context, existingItems: selected.items, items: [item, ...(denied ? [denied.item] : [])],
          frontier: grant ? selected.frontier : nextToolFrontier(selected, 2), checkpointId: mcpServerDecisionCheckpointId(decisionPlan.ref),
          workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [decisionPlan, ...(grantPlan ? [grantPlan] : []), ...(denied?.artifacts ?? [])] });
        const { waitingOnRef: _wait, waitingReason: _reason, ...base } = selected.run;
        const next: Run = { ...base, ...graph.runUpdate, revision: selected.run.revision + 1, status: 'queued', updatedAt: createdAt };
        const response: ApprovalResponse = { protocolVersion: 1, ok: true, result: { method: 'run.approve', decisionRef: decisionPlan.ref,
          snapshot: { schemaVersion: 1, operation: 'agent', run: next, latestRunItemSeq: graph.throughItemSeq } } };
        const responseArtifact = await reads.publishCanonical(response, 'cliq-control-application-response-v1'); reads.assertReadActive();
        let outcome: TimeFenceAdvance | undefined, committed = false;
        driver.transaction(connection => {
          reads.assertReadActive(); assertActiveStateOwner(connection, owner);
          if (readControlRequest(connection, input.principalId, 'run.approve', input.requestId)) return;
          const now = sampleCanonicalNow(), fence = readTimeFence(connection); if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP server approval has no canonical time fence');
          if (now < createdAt || now < fence.lastAcceptedAt) { outcome = advanceTimeFence(connection, owner.ownerEpoch, now); return; }
          if (createdAt < fence.lastAcceptedAt) return;
          requireEqual(readRun(connection, runId), selected.run, 'MCP server exact approval Run cut');
          requireEqual(readInvocationJournal(connection, runId), selected.journal, 'MCP server exact approval complete Journal cut');
          original.assertCut(connection, selected.run, selected); permission.registry.assertUnchanged(connection);
          outcome = advanceTimeFence(connection, owner.ownerEpoch, createdAt); if (outcome !== 'healthy') return;
          for (const artifact of [...channel.metadata, ...graph.metadata, responseArtifact]) insertArtifactMetadata(connection, artifact, createdAt);
          graph.commit(connection, selected.run, nextJournalSequence(connection, runId) - 1, createdAt);
          connection.prepare("UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,revision=revision+1,updated_at=? WHERE id=?").run(createdAt, runId);
          requireEqual(readRun(connection, runId), next, 'MCP server exact committed approval snapshot'); appendRunStateEvent(connection, next, createdAt);
          insertControlRequest(connection, { principalId: input.principalId, method: 'run.approve', requestId: input.requestId,
            channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, requestDigest, responseRef: responseArtifact.ref, committedAt: createdAt });
          committed = true;
        }); requireHealthyFence(outcome); if (committed) return immutableSnapshot({ replayed: false, run: next, response });
        const existing = await replay(); if (existing) return existing;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'MCP server original approval cut kept changing');
    }),
    denyMcpServerCall: stateOperation('RECOVERY_REQUIRED', async (selectedCut: ToolCut, reads: ArtifactCatalog) => {
      const selected = await selection(selectedCut, reads);
      if (!selected || selected.grant || selected.evidence.effectiveDisposition !== 'deny') throw new TypeError('MCP server normalized denial has no exact original policy deny');
      const { planToolInvocationResult, nextToolFrontier } = await import('./reducers/tool.js');
      const result = planToolInvocationResult(selected.context.effect.request, selected.evidence.evaluatedAt,
        { outcome: 'denied', code: 'TOOL_CALL_DENIED', denial: { source: 'policy', policyRef: original.spec.policyRef, decisionDigest: selected.evidence.evidenceDigest } },
        { code: 'TOOL_CALL_DENIED' });
      const item = mcpServerPolicyItem(selected.evidence, { outcomeItemRef: canonicalSha256(result.item) });
      const graph = await prepareContinuationCommit(reads, { context: selectedCut.context, existingItems: selectedCut.items, items: [item, result.item],
        frontier: nextToolFrontier(selectedCut, 2), checkpointId: identityHash('cliq-mcp-server-denial-checkpoint-v1', runId, selected.context.request.opId),
        workspaceStateRef: selectedCut.checkpoint.workspaceStateRef, artifacts: [...result.artifacts, planCanonicalArtifact(selected.context.request, selected.context.request.format),
          planCanonicalArtifact(selected.context.target, selected.context.target.format), planCanonicalArtifact(selected.evidence, selected.evidence.format),
          planCanonicalArtifact(selected.context.executable, 'cliq-mcp-server-executable-identity-v1')] });
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      driver.transaction(connection => {
        reads.assertReadActive(); assertActiveStateOwner(connection, owner); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        requireEqual(readRun(connection, runId), selectedCut.run, 'MCP launch exact denied Run cut');
        requireEqual(readInvocationJournal(connection, runId), selectedCut.journal, 'MCP launch exact denied complete Journal cut');
        original.assertCut(connection, selectedCut.run, selectedCut); selected.context.registry.assertUnchanged(connection);
        if (readHighestPreparedAttempt(connection, runId, selected.context.effect.request.opId) || now < selected.evidence.evaluatedAt)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server denial cannot overtake a prepared effect or its original evidence');
        for (const artifact of graph.metadata) insertArtifactMetadata(connection, artifact, now);
        graph.commit(connection, selectedCut.run, nextJournalSequence(connection, runId) - 1, now);
        connection.prepare('UPDATE runs SET revision=revision+1,updated_at=? WHERE id=?').run(now, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, now);
      }); requireHealthyFence(outcome); return immutableSnapshot({ disposition: 'denied' as const, run: updated });
    }),
    prepareMcpServer: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; leaseEpoch: number }, native: NativeMcpStdioRunOwner,
      platform: { selected: HeldInstalledRuntime; anchor: HeldInstalledAnchor; controller: LinuxWorkerController }, signal?: AbortSignal) => {
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts; reads.assertReadActive();
      await original.assertRuntime(reads, signal); assertLinuxWorkerController(platform.controller);
      const cut = await original.cut(input.expectedRunRevision, reads), selected = await selection(cut, reads);
      if (!selected?.grant) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server launch requires its own exact permission before preparation');
      const expectedTool = readHighestPreparedAttempt(driver, runId, selected.context.effect.request.opId);
      if (!expectedTool?.grantRef || expectedTool.opKind !== 'mcp' || expectedTool.requestRef !== canonicalSha256(selected.context.effect.request) ||
          readInvocationAttempt(driver, runId, expectedTool.opId, expectedTool.attempt).length !== 1)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server launch has no exact unclaimed owning tool preparation');
      const highest = readHighestPreparedAttempt(driver, runId, selected.context.request.opId);
      if (highest && !selected.context.previous)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP original prepared native birth must be resumed by its original owner or positively retired');
      const attempt = (highest?.attempt ?? -1) + 1, createdAt = sampleCanonicalNow(), nonce = randomBytes(32).toString('hex');
      const dispatchId = identityHash('cliq-mcp-server-dispatch-v1', runId, selected.context.request.opId, attempt, nonce);
      const parent = readRequiredWorkerLaunch(driver, cut.run.activeWorkerLaunchId!);
      if (!parent.processContainmentRef || !parent.leaseExpiresAt) throw new KernelStorageError('LEASE_FENCED', 'MCP server original parent lease/domain is unavailable');
      const effectGrant = await readCanonicalArtifact<import('../kernel/tool-authorization.js').ToolOperationGrantV1>(reads, expectedTool.grantRef);
      const resources = decodeSandboxProfile(await readCanonicalArtifact(reads, original.spec.sandboxProfileRef)).resources;
      const callDeadlineMs = Math.min(parseCanonicalTime(expectedTool.timestamp) + selected.context.target.callTimeoutMs,
        parseCanonicalTime(cut.run.deadlineAt), parseCanonicalTime(effectGrant.expiresAt), parseCanonicalTime(selected.grant.expiresAt),
        parseCanonicalTime(parent.leaseExpiresAt), selected.context.callDeadlineMs ?? Number.MAX_SAFE_INTEGER);
      const launchDeadlineMs = Math.min(parseCanonicalTime(createdAt) + selected.context.target.launchTimeoutMs, callDeadlineMs);
      if (parseCanonicalTime(createdAt) >= launchDeadlineMs) throw new KernelStorageError('LEASE_FENCED', 'MCP original call permission expired before server preparation');
      const runtime = await withHeldInstalledRuntime(platform.selected, async held => { await held.revalidate(signal); return held.bundle; }, signal);
      const transport = selected.context.registry.registry.transport;
      if (transport.kind !== 'stdio') throw new TypeError('MCP server original preparation changed its transport');
      let cgroupParent = ''; withInstalledWorkerRoot(platform.selected, platform.anchor, (_fd, root) => { cgroupParent = root; });
      const originalSupervisor = decodePlatformProcessIdentity(await readCanonicalArtifact(reads, owner.processIdentityRef));
      const processOwner = { kind: 'run_invocation' as const, runId, intendedLeaseEpoch: input.leaseEpoch, workerLaunchId: parent.launchId,
        opId: selected.context.request.opId, attempt, dispatchId };
      const launch = await publishMcpStdioLaunch(reads, { purpose: { kind: 'run', owner: processOwner,
        requestRef: canonicalSha256(selected.context.request), requestDigest: selected.context.request.requestDigest,
        targetRef: canonicalSha256(selected.context.target), targetDigest: selected.context.target.targetDigest,
        grantRef: canonicalSha256(selected.grant), parentWorkerContainmentRef: parent.processContainmentRef }, bundle: runtime,
        controller: platform.controller, cgroupParent, lock: owner.filesystem, executable: transport.executable, nonce, createdAt, resources });
      const recipe = await originalRecipe(selected.context, native, reads);
      const recipeArtifact = await reads.publishBytes(recipe.bytes, 'application/octet-stream', 'cliq-mcp-stdio-native-recipe-bytes-v1');
      const preparationCore = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-preparation-v1' as const, runId,
        principalId: original.principalId, launchOpId: selected.context.request.opId, attempt, batchItemId: selected.context.request.batchItemId,
        callId: selected.context.request.callId, callIndex: selected.context.request.callIndex, lifecycleSeq: selected.context.request.lifecycleSeq,
        registryRef: selected.context.registry.ref, manifestDigest: selected.context.registry.registry.manifestDigest,
        toolRequestRef: expectedTool.requestRef, toolRequestDigest: selected.context.effect.request.requestDigest,
        requestRef: canonicalSha256(selected.context.request), requestDigest: selected.context.request.requestDigest,
        targetRef: canonicalSha256(selected.context.target), targetDigest: selected.context.target.targetDigest,
        grantRef: canonicalSha256(selected.grant), grantDigest: selected.grant.grantDigest, workerLaunchId: parent.launchId, leaseEpoch: input.leaseEpoch,
        supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch, originalSupervisor: { pid: originalSupervisor.pid, processStartToken: originalSupervisor.processStartToken },
        controller: { pid: platform.controller.pid, processStartToken: platform.controller.processStartToken }, nonce, dispatchId, nativeRecipeRef: recipeArtifact.ref,
        plannedContainmentRef: launch.planArtifact.ref, plannedContainmentDigest: launch.plan.planDigest, sandboxLaunchSpecRef: launch.specArtifact.ref,
        sandboxLaunchSpecDigest: launch.spec.launchSpecDigest, callDeadlineMs, launchDeadlineMs, createdAt };
      const preparation = decodeMcpServerLaunchPreparation({ ...preparationCore, preparationDigest: canonicalSha256(preparationCore) });
      const preparationArtifact = await reads.publishCanonical(preparation, preparation.format);
      const plans = [planCanonicalArtifact(selected.context.request, selected.context.request.format),
        planCanonicalArtifact(selected.context.target, selected.context.target.format), planCanonicalArtifact(selected.grant, selected.grant.format),
        planCanonicalArtifact(selected.evidence, selected.evidence.format),
        planCanonicalArtifact(transport.executable, 'cliq-mcp-server-executable-identity-v1')];
      const metadata = await reads.mapReads(plans, plan => reads.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind));
      const items = selected.existing ? [] : [mcpServerPolicyItem(selected.evidence, { grant: selected.grant })];
      const graph = await prepareContinuationCommit(reads, { context: cut.context, existingItems: cut.items, items,
        frontier: cut.frontier, checkpointId: identityHash('cliq-mcp-server-prepared-checkpoint-v1', runId, selected.context.request.opId, String(attempt)),
        workspaceStateRef: cut.checkpoint.workspaceStateRef });
      let outcome: TimeFenceAdvance | undefined, prepared!: InvocationJournalEntry, updated!: Run;
      driver.transaction(connection => {
        reads.assertReadActive(); assertActiveStateOwner(connection, owner); assertLinuxWorkerController(platform.controller);
        const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        const live = assertLiveDispatchState(connection, owner, runId, input.expectedRunRevision, input.leaseEpoch, now);
        requireEqual(live.run, cut.run, 'MCP server original whole preparation Run cut');
        requireEqual(readInvocationJournal(connection, runId), cut.journal, 'MCP server original whole preparation Journal cut');
        requireEqual(readHighestPreparedAttempt(connection, runId, selected.context.request.opId), highest, 'MCP server exact contiguous original attempt');
        requireEqual(readHighestPreparedAttempt(connection, runId, expectedTool.opId), expectedTool, 'MCP server original unanswered prepared tool');
        requireEqual(live.launch, parent, 'MCP server actual original parent worker lease');
        original.assertCut(connection, live.run, cut); selected.context.registry.assertUnchanged(connection); selected.prior?.assertUnchanged(connection);
        selected.context.previous?.resources.assertUnchanged(connection);
        if (readInvocationAttempt(connection, runId, expectedTool.opId, expectedTool.attempt).length !== 1 || now < createdAt ||
            now < selected.grant!.issuedAt || now >= selected.grant!.expiresAt || parseCanonicalTime(now) >= launchDeadlineMs ||
            sha256Bytes(readInstalledMcpStdioRecipeData(native)) !== recipe.data.recipeDigest || selected.context.claims >= selected.context.target.maxLaunches)
          throw new KernelStorageError('LEASE_FENCED', 'MCP original preparation lost its exact grant/deadline/recipe/remaining launch bound');
        assertBudgetWithin(live.run.budgetConsumed, live.run.budgetReserved, LAUNCH_BUDGET, original.spec.budgets);
        prepared = { seq: nextJournalSequence(connection, runId), runId, opId: selected.context.request.opId, opKind: 'mcp-server', attempt,
          leaseEpoch: input.leaseEpoch, phase: 'prepared', target: preparation.targetRef, requestRef: preparation.requestRef, replayClass: 'retry',
          grantRef: preparation.grantRef, evidenceRef: preparationArtifact.ref, evidenceDigest: preparation.preparationDigest, budgetDelta: LAUNCH_BUDGET, timestamp: createdAt };
        for (const artifact of [...metadata, ...graph.metadata, ...launch.metadata, recipeArtifact, preparationArtifact])
          insertArtifactMetadata(connection, artifact, createdAt);
        appendInvocationJournalEntry(connection, prepared);
        const reserved = addBudget(live.run.budgetReserved, LAUNCH_BUDGET, 'MCP separate server launch reservation');
        const changed = connection.prepare('UPDATE runs SET budget_reserved_json=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND budget_reserved_json=?')
          .run(JSON.stringify(reserved), now, runId, BigInt(live.run.revision), JSON.stringify(live.run.budgetReserved));
        if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'MCP original server preparation budget CAS changed');
        graph.commit(connection, live.run, prepared.seq, now); updated = readRun(connection, runId); appendRunStateEvent(connection, updated, now);
      }); requireHealthyFence(outcome);
      return { run: immutableSnapshot(updated), entry: immutableSnapshot(prepared), request: selected.context.request, target: selected.context.target,
        grant: selected.grant, preparation, launch };
    }),
    claimMcpServer: stateOperation('RECOVERY_REQUIRED', async (input: Omit<ClaimInvocationDispatchInput, 'runId'>,
      native: NativeMcpStdioRunOwner, binding: RunMcpStdioLaunchBinding,
      physical: Readonly<{ scope: InstalledMcpStdioRunScope; input: HeldRunMcpStdioInput }>, signal?: AbortSignal) => {
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts; reads.assertReadActive();
      await original.assertRuntime(reads, signal);
      const cut = await original.cut(input.expectedRunRevision, reads), selected = await context(cut, reads);
      const prepared = readHighestPreparedAttempt(driver, runId, input.opId);
      if (!selected || !prepared?.grantRef || prepared.opKind !== 'mcp-server' || prepared.attempt !== input.attempt || prepared.requestRef !== canonicalSha256(selected.request) ||
          !input.sandboxLaunchSpecRef || input.brokerFenceTokenDigest !== undefined)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server claim has no exact original prepared native launch');
      const proof = await readMcpServerGrant(driver, reads, selected, prepared.grantRef);
      if (!prepared.evidenceRef || !prepared.evidenceDigest) throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP server claim has no original durable native resource intent');
      const preparation = decodeMcpServerLaunchPreparation(await readCanonicalArtifact(reads, prepared.evidenceRef));
      if (preparation.preparationDigest !== prepared.evidenceDigest || preparation.createdAt !== prepared.timestamp)
        throw new TypeError('MCP server original native resource preparation digest/time differs');
      const { schemaVersion: _version, format: _format, originalSupervisor: _supervisor, controller: originalController,
        nativeRecipeRef, createdAt: _created, preparationDigest: _digest, ...preparedBinding } = preparation;
      requireEqual(binding, { ...preparedBinding, dispatchJournalSeq: binding.dispatchJournalSeq,
        releaseFenceTokenDigest: native.releaseFenceTokenDigest }, 'MCP server exact original prepared native binding');
      const reservation = readInstalledMcpStdioRunReservation(physical.scope, physical.input);
      requireEqual(reservation.controller, originalController, 'MCP server actual reserved controller and first-prepared identity');
      const recipe = await originalRecipe(selected, native, reads);
      if (nativeRecipeRef !== recipe.data.recipeDigest) throw new TypeError('MCP server claim replaces its exact first-prepared native recipe');
      requireEqual(await reads.readBytes(recipe.data.recipeDigest), recipe.bytes, 'MCP server original native recipe registered with preparation');
      const originalTool = readHighestPreparedAttempt(driver, runId, selected.effect.request.opId);
      if (!originalTool?.grantRef || originalTool.requestRef !== selected.request.toolRequestRef)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP server claim lost its exact original owning tool preparation');
      const effectGrant = await readCanonicalArtifact<import('../kernel/tool-authorization.js').ToolOperationGrantV1>(reads, originalTool.grantRef);
      if (effectGrant.grantDigest !== digestOmitting(effectGrant, 'grantDigest') || effectGrant.requestRef !== originalTool.requestRef ||
          effectGrant.subject.kind !== 'tool_call' || effectGrant.opId !== originalTool.opId || effectGrant.runId !== runId)
        throw new TypeError('MCP server call deadline has no exact original owning effect grant');
      assertInstalledMcpStdioRunOwner(native, binding);
      if (binding.runId !== runId || binding.launchOpId !== prepared.opId || binding.attempt !== prepared.attempt || binding.dispatchId !== input.dispatchId ||
          binding.requestRef !== prepared.requestRef || binding.requestDigest !== selected.request.requestDigest || binding.targetRef !== prepared.target ||
          binding.targetDigest !== selected.target.targetDigest || binding.grantRef !== prepared.grantRef || binding.grantDigest !== proof.grant.grantDigest ||
          binding.principalId !== original.principalId || binding.workerLaunchId !== cut.run.activeWorkerLaunchId || binding.leaseEpoch !== input.leaseEpoch ||
          binding.supervisorInstanceId !== owner.supervisorInstanceId || binding.stateOwnerEpoch !== owner.ownerEpoch ||
          binding.sandboxLaunchSpecRef !== input.sandboxLaunchSpecRef || binding.registryRef !== selected.registry.ref || binding.manifestDigest !== selected.registry.registry.manifestDigest ||
          binding.batchItemId !== selected.request.batchItemId || binding.callId !== selected.request.callId || binding.callIndex !== selected.request.callIndex ||
          binding.lifecycleSeq !== selected.request.lifecycleSeq || binding.toolRequestRef !== selected.request.toolRequestRef || binding.toolRequestDigest !== selected.request.toolRequestDigest)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP server native launch owner changes its exact independent original claim');
      const claimed = await claimValidatedInvocation(driver, reads, owner, { ...input, runId }, (connection, run, highest, now) => {
        original.assertCut(connection, run, cut); requireEqual(highest, prepared, 'MCP server original highest preparation');
        requireEqual(readInvocationJournal(connection, runId), cut.journal, 'MCP server complete original Journal claim cut');
        const recipeMetadata = connection.prepare('SELECT byte_length,created_at FROM artifacts WHERE ref=?').get<{ byte_length: bigint; created_at: string }>(recipe.data.recipeDigest);
        if (!recipeMetadata || Number(recipeMetadata.byte_length) !== recipe.data.byteCount || recipeMetadata.created_at > prepared.timestamp ||
            sha256Bytes(readInstalledMcpStdioRecipeData(native)) !== recipe.data.recipeDigest)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP server claim lost its first-prepared exact immutable native recipe metadata');
        selected.registry.assertUnchanged(connection); proof.assertUnchanged(connection); assertInstalledMcpStdioRunOwner(native, binding);
        physical.input.assertHeld();
        requireEqual(readInstalledMcpStdioRunReservation(physical.scope, physical.input).controller, originalController,
          'MCP server actual original reserved controller at permanent claim');
        const live = assertLiveDispatchState(connection, owner, runId, input.expectedRunRevision, input.leaseEpoch, now);
        const tool = readHighestPreparedAttempt(connection, runId, selected.effect.request.opId);
        requireEqual(tool, originalTool, 'MCP server fixed original owning effect preparation');
        if (!tool || tool.requestRef !== selected.request.toolRequestRef || readInvocationAttempt(connection, runId, tool.opId, tool.attempt).length !== 1 ||
            binding.dispatchJournalSeq !== nextJournalSequence(connection, runId) || now < proof.grant.issuedAt || now >= proof.grant.expiresAt ||
            !live.launch.leaseExpiresAt || binding.callDeadlineMs !== Math.min(parseCanonicalTime(tool.timestamp) + selected.target.callTimeoutMs,
              parseCanonicalTime(run.deadlineAt), parseCanonicalTime(proof.grant.expiresAt), parseCanonicalTime(effectGrant.expiresAt),
              parseCanonicalTime(live.launch.leaseExpiresAt), selected.callDeadlineMs ?? Number.MAX_SAFE_INTEGER) ||
            binding.launchDeadlineMs !== Math.min(parseCanonicalTime(prepared.timestamp) + selected.target.launchTimeoutMs, binding.callDeadlineMs) ||
            parseCanonicalTime(now) >= binding.launchDeadlineMs)
          throw new KernelStorageError('LEASE_FENCED', 'MCP server original claim sequence, owning call or fixed deadlines changed');
      });
      liveLaunches.set(JSON.stringify([prepared.opId, prepared.attempt]), { native, binding, claim: claimed });
      const originalSelected = selected, originalPrepared = prepared;
      function assertLaunchRelease() {
        let outcome: TimeFenceAdvance | undefined;
        driver.transaction(connection => {
          assertActiveStateOwner(connection, owner); const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
          if (outcome !== 'healthy') return;
          const live = assertLiveDispatchState(connection, owner, runId, input.expectedRunRevision, input.leaseEpoch, now);
          original.assertCut(connection, live.run, cut); assertChildAncestryRelease(connection, runId, now); originalSelected.registry.assertUnchanged(connection); proof.assertUnchanged(connection);
          requireEqual(readInvocationAttempt(connection, runId, originalPrepared.opId, originalPrepared.attempt), [originalPrepared, claimed], 'MCP server sole original permanent launch claim');
          assertInstalledMcpStdioRunOwner(native, binding);
          if (now < proof.grant.issuedAt || now >= proof.grant.expiresAt || parseCanonicalTime(now) >= binding.launchDeadlineMs ||
              claimed.supervisorInstanceId !== owner.supervisorInstanceId || claimed.stateOwnerEpoch !== owner.ownerEpoch)
            throw new KernelStorageError('LEASE_FENCED', 'MCP server original setup release lost its exact grant/deadline/owner');
        }); requireHealthyFence(outcome);
      }
      return Object.freeze({ entry: claimed, request: selected.request, target: selected.target, grant: proof.grant, assertLaunchRelease });
    })
  });
}
