import { readCurrentSessionContextGraph, assertCurrentSessionContextGraph } from '../session-context-stream.js';
import { publishSessionContextAppend } from '../session-context-publication.js';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../kernel/identity.js';
import type { BudgetSettlementV1, ContinuationItem, InvocationJournalEntry, Run, RunAssemblyV1, RunCancel, RunFrontier, RunSpec, Session, SessionRunTerminalItem } from '../../kernel/types.js';
import type { ToolCheckpointProof } from '../../kernel/tool-authorization.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ResolveToolInput } from '../../model/attempt.js';
import { exactKeys, requireEqual } from '../../policy/runtime-authority.js';
import { toolOperationId } from '../../policy/tool-policy.js';
import { cancelledCall, cancelRequestDigest, agentStopDetail, openStopBatch, selectAgentStop, recordAgentStopPredecessor, stopCheckpointId, stopInvocationHistory, type AgentStopIntent } from '../../runtime/stop.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from '../artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { validateControlChannelClosure } from '../control-channel.js';
import { prepareContinuationCommit } from '../continuation-commit.js';
import { decodeAdmittedContext, decodeContextManifest, decodeSessionProjection } from '../decoders.js';
import { KernelStorageError, RunTerminalError, stateOperation } from '../errors.js';
import { isZeroBudget, subtractBudget } from '../invariants.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { appendInvocationJournalEntry, nextJournalSequence } from '../repositories/journal.js';
import { readRequiredWorkerLaunch, readWorkerLaunchesForRun } from '../repositories/worker-launches.js';
import { readRequiredWorkspaceGenerationByRef } from '../repositories/workspace-generations.js';
import { insertControlRequest, readControlRequest, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { readCancelResponse, readAgentStop, type CancelResponse } from '../stop-recovery.js';
import { prepareResourceStopCause } from '../resource-stop.js';
import { prepareModelFailureStop } from '../model-failure.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from '../tool-checkpoint.js';
import { readToolCut } from '../tool-cut.js';
import { assertRetiredGenerationCut } from '../generation-retirement.js';
import { withInstalledBrokerTerminalClosure } from '../broker-ambiguity.js';
import type { HeldInstalledRuntime } from '../installed-runtime.js';
import { readWorkerRecoveryTerminalPlan, type WorkerRecoveryTerminalPlan } from '../worker-recovery-terminal.js';
import { planPrivateRollbackResult } from '../private-tool-rollback.js';
import { validateInstalledModelNoReleaseHistory } from '../broker-no-release.js';
import { appendRunStateEvent, requireHealthyFence, resolvePrivateRollbackInvocation } from './invocation.js';
import { decodeVerificationClosure } from '../result-artifacts.js';
import { readVerifierProgress } from '../verifier-recovery.js';
import { readVerifierFailureCause, readVerifierIntegrityCause, readVerifierPolicyDenial, validateVerifierStoppedHistory } from '../verifier-stop-history.js';
import type { VerifierPolicyDecisionItem } from '../../kernel/verifier-invocation.js';
import { assertDeliveryModelFreeCut } from '../run-model-free.js';
import { closeOwnedPublicationAbortFinalization, readOwnedPublicationAbortFinalization,
  type OwnedPublicationAbortFinalization } from '../publication-abort-finalization.js';
import { readUnclaimedPublicationStopHistory } from '../delivery-publication-recovery.js';
import { readChildAllocationsForRun } from '../repositories/child-allocations.js';
import { readParentStopRevocation } from '../parent-stop-revocation.js';
import { prepareChildTerminalAllocation } from '../child-terminal-publication.js';
import { readManualInvocationFinalization, stageManualInvocationFinalization, validateMcpStopComposition,
  type ManualInvocationFinalization } from '../manual-reconciliation.js';
import { manualStopTimeOrderIsValid } from '../manual-stop-time.js';
import { prepareMcpRetryTerminalClosure } from '../mcp-retry-admission.js';
import { isMcpRetryFinalization, readMcpRetryFinalization, stageMcpRetryFinalization, planMcpRetryCancelledItem, type McpRetryFinalization } from '../mcp-retry-terminal.js';
import { decodeRetryUnknownCancelledResult, retryUnknownHasLaterClaim } from '../../kernel/retry-unknown.js';
import { planMcpNoReleaseResult } from '../mcp-execution.js';

/** Loaded authority only. Cancellation fences immediately; terminal drain independently proves the entire current cut. */
export function loadAgentStop(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, authority: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; principalId: string; resolveToolInput: ResolveToolInput;
  assertAuthority: () => Promise<void>;
}, reobserve?: NativeWorkerRetirement, installedRuntime?: HeldInstalledRuntime) {
  const { run: admitted, spec, assembly, principalId } = authority;
  const runId = admitted.id;
  const result = (run: Run) => ({ run, checkpointId: stopCheckpointId(runId, run.stopIntentRef!) });
  const deadlineIntent = (createdAt: string): AgentStopIntent => ({ schemaVersion: 1, runId, createdAt, origin: 'deadline',
    targetStatus: 'failed', reason: 'budget_exhausted', deadlineAt: admitted.deadlineAt });
  async function cut(revision: number, allowWorkerRecovery = false, allowUnstartedCandidate = false, fencing = false) {
    if (!Number.isSafeInteger(revision) || revision < 1) throw new TypeError('invalid stop revision');
    const selected = await readRecoveryClosure(driver, artifacts, runId);
    const { run } = selected;
    if (run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run revision changed');
    if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt) throw new TypeError('stop authority no longer belongs to this Run');
    if (spec.operation === 'delivery') assertDeliveryModelFreeCut(selected);
    if (!fencing && selected.childAllocations.some(row => row.parentRunId === runId && row.state !== 'settled'))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'parent stop requires its exact child stop settlement reducer');
    if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status)) throw new RunTerminalError();
    if (run.nextStep === 'verify' || run.nextStep === 'finalize') {
      // The full recovery reader validates the original candidate, frozen
      // verifier progress and exact active/death-wait lifecycle. A stop only
      // adds a fence; terminal drain below still requires the original claim
      // and invocation/parent retirement, never a worker-free substitution.
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      if (allowUnstartedCandidate && run.status === 'waiting' && run.waitingReason === 'approval' && frontier.kind === 'verify' && frontier.phase === 'dependencies') {
        const original = await (await import('../dependency-script-approval.js')).readDependencyScriptWaitingRun(driver, artifacts, run);
        requireEqual(frontier, original.frontier, 'Stop retains its original dependency consent frontier');
        return selected;
      }
      if (allowUnstartedCandidate && run.status === 'waiting' && run.waitingReason === 'approval' && frontier.kind === 'verify' && frontier.phase === 'verifiers') {
        const original = await (await import('../verifier-permission-history.js')).readVerifierWaitingRun(driver, artifacts, run, spec);
        requireEqual(frontier, await readCanonicalArtifact(artifacts, original.wait.frontierRef), 'Stop retains its exact verifier consent frontier');
        return selected;
      }
      if (!allowUnstartedCandidate || !['queued', 'running', 'waiting'].includes(run.status) || frontier.schemaVersion !== 1 ||
          run.status === 'waiting' && !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate stop requires its exact verification lifecycle');
      if (frontier.kind === 'verify' && run.nextStep === 'verify' && exactKeys(frontier, ['schemaVersion', 'kind', 'phase', 'candidateItemId',
        'resultSourceRef', 'verifierPlanRef', 'nextVerifierIndex', 'afterPass', ...(spec.dependencyPolicyRef ? ['dependencyPlanRef'] : [])]) &&
          (frontier.phase === 'verifiers' || frontier.phase === 'dependencies') &&
          frontier.afterPass === (spec.operation === 'agent' ? 'finalize' : 'delivery_approval')) {
        const progress = await readVerifierProgress(driver, artifacts, selected, frontier.candidateItemId);
        const dependencyPending = progress.dependency && !progress.dependency.ready;
        if (frontier.phase !== (dependencyPending ? 'dependencies' : 'verifiers') ||
            frontier.dependencyPlanRef !== progress.dependency?.planRef ||
            frontier.nextVerifierIndex !== (dependencyPending ? 0 : progress.nextVerifierIndex) || frontier.verifierPlanRef !== progress.planRef ||
            frontier.resultSourceRef !== progress.candidate.resultSourceRef) throw new TypeError('stop substituted its exact verifier progress');
        return selected;
      }
      if (frontier.kind !== 'finalize' || run.nextStep !== 'finalize' || frontier.operation !== spec.operation ||
          run.status !== 'queued' || run.activeWorkerLaunchId || run.waitingReason || run.waitingOnRef ||
          !exactKeys(frontier, ['schemaVersion', 'kind', 'operation', 'candidateItemId', 'resultSourceRef', 'verificationClosureRef',
            ...(spec.operation === 'delivery' ? ['deliveryTerminalProjectionEvidenceRef'] : [])]))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate stop requires its exact unstarted verification or consent-backed finalization');
      const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, frontier.verificationClosureRef));
      if (closure.runId !== run.id || closure.candidateItemId !== frontier.candidateItemId || closure.resultSourceRef !== frontier.resultSourceRef ||
          spec.operation === 'agent' && (closure.verification.kind !== 'local' || closure.verification.unverifiedConsentRef !== spec.unverifiedConsentRef) ||
          spec.operation === 'delivery' && closure.verification.kind === 'local' && closure.verification.outcome !== 'verified')
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate stop has no exact unverified closure');
      return selected;
    }
    if (spec.operation === 'delivery') {
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      if (!['queued', 'running', 'waiting'].includes(run.status) || run.nextStep !== 'delivery' || frontier.kind !== 'delivery' ||
          run.status === 'waiting' && !(run.waitingReason === 'approval' && frontier.phase === 'approval') &&
            !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery stop requires its exact retained delivery continuation');
      return selected;
    }
    // Cancellation/deadline may fence a validated worker-death wait, but cannot clear it or drain it.
    if (!['queued', 'running', 'waiting'].includes(run.status) || !['agent', 'tool'].includes(run.nextStep ?? '') ||
        (run.status === 'waiting' && !['approval', 'input', ...(fencing ? ['child'] : [])].includes(run.waitingReason ?? '') &&
          !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop requires an agent continuation or ordinary control wait');
    return selected;
  }
  function assertCut(connection: SqliteConnection, selected: Awaited<ReturnType<typeof cut>>) {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(selected.run)) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run cut changed');
    if (nextJournalSequence(connection, runId) !== selected.journal.length + 1 ||
        Number(connection.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?').get<{ seq: bigint }>(runId)?.seq) !== selected.items.length ||
        canonicalSha256(readChildAllocationsForRun(connection, runId)) !== canonicalSha256(selected.childAllocations))
      throw new KernelStorageError('REVISION_CONFLICT', 'stop continuation changed');
  }
  function acceptTime(connection: SqliteConnection, now: string): { accepted: boolean; outcome?: TimeFenceAdvance } {
    assertActiveStateOwner(connection, owner);
    const sampled = sampleCanonicalNow(), fence = readTimeFence(connection);
    if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'stop canonical time fence is missing');
    if (sampled < now || sampled < fence.lastAcceptedAt) return { accepted: false, outcome: advanceTimeFence(connection, owner.ownerEpoch, sampled) };
    if (now < fence.lastAcceptedAt) return { accepted: false };
    const outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
    return { accepted: outcome === 'healthy', outcome };
  }
  async function commitDerivedStop(selected: Awaited<ReturnType<typeof cut>>, derive: (now: string) => Promise<{
    intent: AgentStopIntent; metadata?: PublishedArtifact[]; commit?: (connection: SqliteConnection, run: Run, committedAt: string) => void;
  } | undefined>) {
    const prior = selected.run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
    for (let retry = 0; retry < 8; retry++) {
      const now = sampleCanonicalNow();
      const proposal = await derive(now);
      if (!proposal) {
        if (prior) return immutableSnapshot(result(selected.run));
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'current continuation has no supported failure');
      }
      const observesParent = proposal.intent.origin === 'parent_cancel' && selected.run.parentCancellationRef === undefined,
        wins = selectAgentStop(prior, proposal.intent) !== prior;
      if (!wins && !observesParent) return immutableSnapshot(result(selected.run));
      const recorded = recordAgentStopPredecessor(proposal.intent, wins ? selected.run.stopIntentRef : undefined,
        selected.latestCheckpoint.id, selected.run.revision, selected.journal.length), intent = wins ? recorded : prior!;
      // A losing parent observation is anchored by its own immutable Run
      // field. It never claims to have superseded the existing higher Stop.
      const observation = observesParent ? await artifacts.publishCanonical(recorded, 'cliq-stop-intent-v1') : undefined;
      const artifact = wins ? observation ?? await artifacts.publishCanonical(intent, 'cliq-stop-intent-v1') : undefined;
      let time: ReturnType<typeof acceptTime> | undefined, updated: Run | undefined;
      driver.transaction((connection) => {
        time = acceptTime(connection, now);
        if (!time.accepted) return;
        assertCut(connection, selected);
        if (intent.origin === 'runtime' && intent.runtimeSubtype === 'runtime' &&
            parseCanonicalTime(sampleCanonicalNow()) - parseCanonicalTime(now) > 5_000) {
          throw new KernelStorageError('RECOVERY_REQUIRED', 'model failure observation is stale; reobserve the Journal');
        }
        for (const metadata of proposal.metadata ?? []) insertArtifactMetadata(connection, metadata, now);
        if (artifact) insertArtifactMetadata(connection, artifact, now);
        if (observation && observation !== artifact) insertArtifactMetadata(connection, observation, now);
        proposal.commit?.(connection, selected.run, now);
        connection.prepare(`UPDATE runs SET stop_intent_ref = ?,parent_cancellation_ref=COALESCE(parent_cancellation_ref,?),
          cancel_requested=CASE WHEN ?=1 THEN 1 ELSE cancel_requested END,revision=revision+1,updated_at=? WHERE id=?`)
          .run(artifact?.ref ?? selected.run.stopIntentRef!, observation?.ref ?? null, proposal.intent.origin === 'parent_cancel' ? 1 : 0, now, runId);
        updated = readRun(connection, runId);
        appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(time?.outcome);
      if (updated) return immutableSnapshot(result(updated));
    }
    throw new KernelStorageError('REVISION_CONFLICT', 'failure/time cut kept changing');
  }
  return {
    /** No-write terminal reader. Replay has no later cut in cancelRun, so this
     * path owns one complete fresh walk before every request outcome. Earlier
     * closed material is data only and cannot stand in for that history. */
    cancelTerminalRun: stateOperation('INVALID_REQUEST', async (input: RunCancel, session: Session) => {
      input = immutableSnapshot(input); session = immutableSnapshot(session);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision']))
        throw new TypeError('unknown run.cancel field');
      const digest = cancelRequestDigest(runId, input);
      const assertCurrent = () => {
        artifacts.assertReadActive(); assertActiveStateOwner(driver, owner);
        if (canonicalSha256(readRun(driver, runId)) !== canonicalSha256(admitted) ||
            canonicalSha256(readSession(driver, admitted.sessionId)) !== canonicalSha256(session))
          throw new KernelStorageError('REVISION_CONFLICT', 'terminal cancellation original Run or Session changed');
        if (session.id !== admitted.sessionId || readSessionPrincipalId(driver, session.id) !== principalId ||
            driver.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(runId)?.principal_id !== principalId)
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'terminal cancellation has a foreign Run or Session principal');
      };
      artifacts.assertReadActive(); assertActiveStateOwner(driver, owner);
      if (input.principalId !== principalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'cancellation caller does not own this Run');
      await validateControlChannelClosure(artifacts, owner, input);
      const selected = await readRecoveryClosure(driver, artifacts, runId);
      assertCurrent();
      requireEqual(selected.run, admitted, 'terminal cancellation complete original Run');
      requireEqual(selected.runSpec, spec, 'terminal cancellation complete original RunSpec');
      if (spec.operation === 'delivery') assertDeliveryModelFreeCut(selected);
      if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(selected.run.status))
        throw new KernelStorageError('REVISION_CONFLICT', 'terminal cancellation lost its original terminal cut');
      await validateControlChannelClosure(artifacts, owner, input);
      assertCurrent();
      const row = readControlRequest(driver, principalId, 'run.cancel', input.requestId);
      if (row) {
        if (row.requestDigest !== digest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.cancel requestId was reused with different bytes');
        const { response } = await readCancelResponse(driver, artifacts, admitted, principalId, input.requestId);
        await validateControlChannelClosure(artifacts, owner, input);
        assertCurrent();
        const current = readControlRequest(driver, principalId, 'run.cancel', input.requestId);
        if (!current || canonicalSha256(current) !== canonicalSha256(row))
          throw new KernelStorageError('REVISION_CONFLICT', 'terminal cancellation original replay request changed');
        return immutableSnapshot({ replayed: true, ...result(response.result.snapshot.run), response });
      }
      if (!Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1) throw new TypeError('invalid stop revision');
      if (admitted.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run revision changed');
      throw new RunTerminalError();
    }),
    cancelRun: stateOperation('INVALID_REQUEST', async (input: RunCancel) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision'])) throw new TypeError('unknown run.cancel field');
      const digest = cancelRequestDigest(runId, input);
      assertActiveStateOwner(driver, owner);
      if (input.principalId !== principalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'cancellation caller does not own this Run');
      const channel = await validateControlChannelClosure(artifacts, owner, input);
      const replay = async () => {
        const row = readControlRequest(driver, principalId, 'run.cancel', input.requestId);
        if (!row) return undefined;
        if (row.requestDigest !== digest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.cancel requestId was reused with different bytes');
        const { response } = await readCancelResponse(driver, artifacts, readRun(driver, runId), principalId, input.requestId);
        return immutableSnapshot({ replayed: true, ...result(response.result.snapshot.run), response });
      };
      const existing = await replay();
      if (existing) return existing;
      const selected = await cut(input.expectedRunRevision, true, true, true);
      const prior = selected.run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
      for (let retry = 0; retry < 8; retry++) {
        const now = sampleCanonicalNow();
        // The cancellation fence is monotonic even when integrity already
        // outranks it. Equal precedence preserves the first committed intent.
        const intent = selectAgentStop(prior, recordAgentStopPredecessor({
          schemaVersion: 1, runId, createdAt: now, origin: 'user_cancel', targetStatus: 'cancelled', reason: 'cancelled_by_user',
          requestId: input.requestId, principalId }, selected.run.stopIntentRef, selected.latestCheckpoint.id, selected.run.revision, selected.journal.length));
        const intentArtifact = await artifacts.publishCanonical(intent, 'cliq-stop-intent-v1');
        const next: Run = { ...selected.run, stopIntentRef: intentArtifact.ref, cancelRequested: true, revision: selected.run.revision + 1, updatedAt: now };
        const response: CancelResponse = { protocolVersion: 1, ok: true, result: { method: 'run.cancel',
          snapshot: { schemaVersion: 1, operation: spec.operation, run: next, latestRunItemSeq: selected.items.length } } };
        const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-application-response-v1');
        let time: ReturnType<typeof acceptTime> | undefined, committed = false;
        driver.transaction((connection) => {
          assertActiveStateOwner(connection, owner);
          if (readControlRequest(connection, principalId, 'run.cancel', input.requestId)) return;
          time = acceptTime(connection, now);
          if (!time.accepted) return;
          assertCut(connection, selected);
          for (const artifact of [...channel.metadata, intentArtifact, responseArtifact]) insertArtifactMetadata(connection, artifact, now);
          connection.prepare('UPDATE runs SET stop_intent_ref = ?, cancel_requested = 1, revision = revision + 1, updated_at = ? WHERE id = ?')
            .run(intentArtifact.ref, now, runId);
          requireEqual(readRun(connection, runId), next, 'committed cancellation snapshot');
          appendRunStateEvent(connection, next, now);
          insertControlRequest(connection, { principalId, method: 'run.cancel', requestId: input.requestId, requestDigest: digest,
            channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, responseRef: responseArtifact.ref, committedAt: now });
          committed = true;
        });
        requireHealthyFence(time?.outcome);
        if (committed) return immutableSnapshot({ replayed: false, ...result(next), response });
        const replayed = await replay();
        if (replayed) return replayed;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'cancellation cut kept changing');
    }),
    stopFromParent: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('parent stop accepts only its original child revision');
      const selected = await cut(input.expectedRunRevision, true, true, true);
      const source = await readParentStopRevocation(driver, artifacts, runId);
      return commitDerivedStop(selected, async now => ({ intent: {
        schemaVersion: 1, runId, createdAt: now, origin: 'parent_cancel', targetStatus: 'cancelled', reason: 'parent_cancelled',
        sourceRunId: source.parent.id, sourceStopIntentRef: source.sourceStopIntentRef },
        commit: connection => source.assertUnchanged(connection) }));
    }),
    expireRun: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown deadline stop field');
      const selected = await cut(input.expectedRunRevision, true, true, true);
      if (sampleCanonicalNow() < selected.run.deadlineAt) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run deadline has not elapsed');
      return commitDerivedStop(selected, async (now) => {
        if (now < selected.run.deadlineAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'deadline clock regressed');
        return { intent: deadlineIntent(now) };
      });
    }),
    stopForResourceFailure: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown resource stop field');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, spec.operation === 'delivery', true);
      return commitDerivedStop(selected, async (now) => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const prepared = await prepareResourceStopCause(driver, artifacts, selected, now);
        return prepared ? { intent: { schemaVersion: 1, runId, createdAt: now, ...prepared.cause },
          commit: prepared.commit } : undefined;
      });
    }),
    stopForModelFailure: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; inspectorIdentityRef: string; inspectorIdentityDigest: string;
    }) => {
      if (spec.operation !== 'agent') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'model failure requires an Agent Run');
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'inspectorIdentityRef', 'inspectorIdentityDigest'])) throw new TypeError('unknown model failure stop field');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, false, true);
      return commitDerivedStop(selected, async (now) => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        return prepareModelFailureStop(driver, artifacts, assertActiveStateOwner(driver, owner), assembly, selected, {
          inspectorIdentityRef: input.inspectorIdentityRef, inspectorIdentityDigest: input.inspectorIdentityDigest
        }, now);
      });
    }),
    stopForMcpKnownUnusable: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; inspectorIdentityRef: string; inspectorIdentityDigest: string;
    }) => {
      input = immutableSnapshot(input);
      if (spec.operation !== 'agent' || !exactKeys(input, ['expectedRunRevision', 'inspectorIdentityRef', 'inspectorIdentityDigest'])) {
        throw new TypeError('MCP unusable result Stop requires its original Agent inspector');
      }
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, false, true);
      return commitDerivedStop(selected, async now => {
        const cause = await (await import('../mcp-execution.js')).readMcpKnownUnusableCause(driver, artifacts, selected, now);
        if (!cause) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP unusable result Stop has no original completed received cause');
        }
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        return prepareModelFailureStop(driver, artifacts, assertActiveStateOwner(driver, owner), assembly, selected, {
          inspectorIdentityRef: input.inspectorIdentityRef, inspectorIdentityDigest: input.inspectorIdentityDigest
        }, now);
      });
    }),
    stopForDependencyFailure: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; inspectorIdentityRef: string; inspectorIdentityDigest: string;
    }) => {
      input = immutableSnapshot(input);
      if (!spec.dependencyPolicyRef || !exactKeys(input, ['expectedRunRevision', 'inspectorIdentityRef', 'inspectorIdentityDigest']))
        throw new TypeError('dependency failure requires its exact frozen policy and owning inspector');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, true, true);
      return commitDerivedStop(selected, async now => {
        const cause = await (await import('../dependency-failure-cause.js')).readDependencyFailureCause(driver, artifacts, selected, now);
        if (!cause) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'dependency failure has no complete positively received original cause');
        const integrity = await (await import('../dependency-failure-cause.js')).readDependencyIntegrityCause(driver, artifacts, selected, now);
        if (integrity) return { intent: integrity };
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        return prepareModelFailureStop(driver, artifacts, assertActiveStateOwner(driver, owner), assembly, selected, {
          inspectorIdentityRef: input.inspectorIdentityRef, inspectorIdentityDigest: input.inspectorIdentityDigest }, now);
      });
    }),
    stopForDependencyAmbiguity: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; inspectorIdentityRef: string; inspectorIdentityDigest: string }) => {
      input = immutableSnapshot(input);
      if (!spec.dependencyPolicyRef || !exactKeys(input, ['expectedRunRevision', 'inspectorIdentityRef', 'inspectorIdentityDigest']))
        throw new TypeError('dependency ambiguity requires its frozen policy and original inspector');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, true, true, true);
      return commitDerivedStop(selected, async now => {
        const cause = await (await import('../dependency-failure-cause.js')).readDependencyAmbiguityCause(driver, artifacts, selected, now);
        if (!cause) return undefined;
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        return prepareModelFailureStop(driver, artifacts, assertActiveStateOwner(driver, owner), assembly, selected,
          { inspectorIdentityRef: input.inspectorIdentityRef, inspectorIdentityDigest: input.inspectorIdentityDigest }, now);
      });
    }),
    stopForDependencyScriptDenial: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!spec.dependencyPolicyRef || !exactKeys(input, ['expectedRunRevision']))
        throw new TypeError('dependency script denial requires its original frozen dependency policy');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, true, true);
      return commitDerivedStop(selected, async now => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await (await import('../dependency-script-approval.js')).readDependencyScriptDenialCause(driver, artifacts, runId, { observedAt: now });
        if (!cause) return undefined;
        const metadata = await artifacts.mapReads(cause.plans, async plan => {
          const published = await artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind);
          requireEqual(published, { ref: plan.ref, byteLength: plan.bytes.length, mediaType: plan.mediaType,
            schemaKind: plan.schemaKind }, 'dependency script denial complete original artifacts');
          return published;
        });
        const intent: AgentStopIntent = { schemaVersion: 1, runId, createdAt: now, origin: 'policy_deny',
          subjectKind: 'dependency_install_scripts', targetStatus: 'failed', reason: 'runtime_failed', opId: cause.opId,
          policyChannelEvidenceRef: cause.policyChannelEvidenceRef, policyChannelEvidenceDigest: cause.policyChannelEvidenceDigest };
        return { intent, metadata, commit(connection: SqliteConnection) { cause.assertUnchanged(connection); } };
      });
    }),
    stopForVerification: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown verification stop field');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, true, true, true);
      return commitDerivedStop(selected, async now => {
        const integrity = await readVerifierIntegrityCause(driver, artifacts, selected, now);
        if (integrity) return { intent: integrity };
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await readVerifierFailureCause(driver, artifacts, selected, now);
        return cause ? { intent: cause } : undefined;
      });
    }),
    stopForVerifierPolicyDenial: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown verifier policy stop field');
      assertActiveStateOwner(driver, owner); await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision, false, true, true);
      return commitDerivedStop(selected, async now => {
        const integrity = await readVerifierIntegrityCause(driver, artifacts, selected, now);
        if (integrity) return { intent: integrity };
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await readVerifierPolicyDenial(driver, artifacts, selected, now);
        if (!cause) return undefined;
        const evidence = await artifacts.publishCanonical(cause.evidence, cause.evidence.format);
        const intent = recordAgentStopPredecessor({ schemaVersion: 1, runId, createdAt: now, origin: 'policy_deny', subjectKind: 'verifier',
          targetStatus: 'failed', reason: 'verification_failed', opId: cause.planned.request.opId,
          policyChannelEvidenceRef: evidence.ref, policyChannelEvidenceDigest: cause.evidence.evidenceDigest }, selected.run.stopIntentRef, selected.latestCheckpoint.id, selected.run.revision, selected.journal.length) as Extract<AgentStopIntent, { origin: 'policy_deny' }>;
        const intentRef = planCanonicalArtifact(intent, 'cliq-stop-intent-v1').ref;
        const item: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
          itemId: identityHash('cliq-verifier-policy-item-v1', runId, intent.opId, evidence.ref), runId, opId: intent.opId,
          principalId: cause.principalId, decisionRef: evidence.ref, policyChannelEvidenceRef: evidence.ref,
          policyChannelEvidenceDigest: cause.evidence.evidenceDigest, createdAt: now, decisionSource: 'direct_policy', decision: 'deny',
          denialOutcome: { kind: 'stop_intent', subjectKind: 'verifier_launch', stopIntentRef: intentRef } };
        const checkpointId = identityHash('cliq-verifier-denial-checkpoint-v1', runId, intent.opId, evidence.ref);
        const graph = await prepareContinuationCommit(artifacts, {
          context: decodeContextManifest(await readCanonicalArtifact(artifacts, selected.latestCheckpoint.contextManifestRef)),
          existingItems: await artifacts.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
            item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })),
          items: [item], frontier: cause.frontier, checkpointId, workspaceStateRef: selected.latestCheckpoint.workspaceStateRef,
          artifacts: [planCanonicalArtifact(cause.planned.request, cause.planned.request.format), planCanonicalArtifact(cause.planned.target, cause.planned.target.format)]
        });
        return { intent, metadata: [evidence, ...graph.metadata],
          commit(connection: SqliteConnection, run: Run, committedAt: string) { graph.commit(connection, run, selected.journal.length, committedAt); } };
      });
    }),
    commitTerminalStop: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; checkpoint?: ToolCheckpointProof },
      recovery?: WorkerRecoveryTerminalPlan, publicationFinalization?: OwnedPublicationAbortFinalization,
      terminalFinalization?: ManualInvocationFinalization | McpRetryFinalization) => {
      const mcpRetryPlan = terminalFinalization && isMcpRetryFinalization(terminalFinalization)
        ? readMcpRetryFinalization(driver, artifacts, owner, terminalFinalization, runId) : undefined;
      const manual = terminalFinalization && !isMcpRetryFinalization(terminalFinalization)
        ? readManualInvocationFinalization(driver, owner, terminalFinalization, runId) : undefined;
      if (mcpRetryPlan && (manual || recovery || publicationFinalization || input.checkpoint))
        throw new TypeError('MCP retry finalization cannot borrow another physical terminal owner');
      if (manual && (recovery || publicationFinalization || input.checkpoint)) {
        throw new TypeError('manual terminal closure cannot borrow worker or publication authority');
      }
      const publication = publicationFinalization === undefined ? undefined
        : readOwnedPublicationAbortFinalization(driver, owner, publicationFinalization, runId);
      try {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', ...(input.checkpoint === undefined ? [] : ['checkpoint'])])) throw new TypeError('unknown terminal stop field');
      if (publication && (spec.operation !== 'delivery' || recovery !== undefined || input.checkpoint !== undefined))
        throw new TypeError('owned publication stop cannot substitute a checkpoint or worker-recovery plan');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const recovered = await readRecoveryClosure(driver, artifacts, runId);
      if (recovered.run.stopIntentRef && ['failed', 'cancelled'].includes(recovered.run.status) &&
          [recovered.run.revision, recovered.latestCheckpoint.basedOnRunRevision].includes(input.expectedRunRevision)) {
        return immutableSnapshot({ run: recovered.run });
      }
      const workerRecovery = recovery === undefined ? undefined : readWorkerRecoveryTerminalPlan(driver, owner, recovery, runId);
      const selected = await cut(input.expectedRunRevision, workerRecovery !== undefined || manual !== undefined, true);
      const { run: originalRun, latestCheckpoint: checkpoint } = selected;
      let run = originalRun;
      if (mcpRetryPlan) requireEqual(selected, mcpRetryPlan.cut, 'MCP retry terminal exact original worker-free cut');
      if (manual) requireEqual(selected, manual.cut, 'manual terminal exact original waiting cut');
      if (workerRecovery) requireEqual(selected, workerRecovery.cut, 'terminal original worker recovery cut');
      if (publication) requireEqual(selected, publication.cut, 'terminal original owned publication cut');
      if (!run.stopIntentRef && !manual && !mcpRetryPlan) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal drain requires its original persisted or typed atomic StopIntent');
      const mcpClosure = mcpRetryPlan?.closure ?? (selected.journal.some(entry => entry.opKind === 'mcp' && entry.replayClass === 'retry' && entry.phase === 'unknown')
        ? await prepareMcpRetryTerminalClosure(driver, artifacts, owner, installedRuntime, selected) : undefined);
      const mcpNoRelease = assembly.mcpServers.length || selected.journal.some(entry => entry.opKind === 'mcp' || entry.opKind === 'mcp-server')
        ? await validateMcpStopComposition(driver, artifacts, selected, manual, mcpClosure) : new Set<number>();
      // The public recovery cut already verified every sealed worker proof;
      // stop additionally forbids the preactivation and fenced branches.
      if (readWorkerLaunchesForRun(driver, runId).some(launch => launch.phase === 'retired' && launch.retirementKind !== 'preparation' && launch.generationWriteState !== 'sealed' &&
          !selected.workspaceGenerations.some(generation => generation.generationRef === launch.workspaceGenerationRef && generation.phase === 'retired'))) {
        throw new TypeError('terminal stop retains an unsealed retired worker');
      }
      let manualPreparedAt = manual ? sampleCanonicalNow() : undefined;
      let manualStage = manual ? stageManualInvocationFinalization(manual, manualPreparedAt!, selected.journal.length + 1) : undefined;
      let retryStage = mcpRetryPlan ? stageMcpRetryFinalization(mcpRetryPlan, sampleCanonicalNow()) : undefined;
      const prior = run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
      let intent = manualStage || retryStage ? selectAgentStop(prior, (manualStage ?? retryStage)!.intent) : prior!;
      let stagedStop = (manualStage ?? retryStage)?.intent === intent ? planCanonicalArtifact(intent, 'cliq-stop-intent-v1') : undefined;
      if (stagedStop) run = { ...run, stopIntentRef: stagedStop.ref, ...(manualStage ? { cancelRequested: true } : {}) };
      const integrity = await readVerifierIntegrityCause(driver, artifacts, selected, sampleCanonicalNow());
      if (integrity && (intent.origin !== 'kernel_integrity' || intent.reason !== 'verifier_mutated_source' || intent.verifierOpId !== integrity.verifierOpId ||
          intent.integrityEvidenceRef !== integrity.integrityEvidenceRef || intent.integrityEvidenceDigest !== integrity.integrityEvidenceDigest))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop requires the higher-priority retained verifier integrity intent');
      const dependencyIntegrity = await (await import('../dependency-failure-cause.js')).readDependencyIntegrityCause(driver, artifacts, selected, sampleCanonicalNow());
      if (dependencyIntegrity && (intent.origin !== 'kernel_integrity' || intent.reason !== 'runtime_failed' || intent.source !== 'dependency_acquisition' ||
          intent.failingOpId !== dependencyIntegrity.failingOpId || intent.integrityEvidenceRef !== dependencyIntegrity.integrityEvidenceRef ||
          intent.integrityEvidenceDigest !== dependencyIntegrity.integrityEvidenceDigest))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop requires the higher-priority original dependency integrity intent');
      let checkpointId = stopCheckpointId(runId, run.stopIntentRef!);
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      const items = await artifacts.mapReads(selected.items, async (row) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
      const pending = openStopBatch(items.map(({ item }) => item));
      const synthetic = frontier.kind === 'tool' ? items.find(row => row.item.itemId === frontier.batchItemId)?.item : undefined;
      if (synthetic?.kind === 'child_merge_batch') {
        requireEqual(frontier.kind === 'tool' ? frontier.orderedCallIds : null, synthetic.calls.map(call => call.callId), 'Stop exact synthetic merge call order');
        if (frontier.kind !== 'tool' || !Number.isSafeInteger(frontier.nextCallIndex) || frontier.nextCallIndex < 0 || frontier.nextCallIndex >= synthetic.calls.length ||
            synthetic.resume.kind === 'await_tool' && (!pending || pending.batch.itemId !== synthetic.resume.batchItemId ||
              pending.next !== synthetic.resume.callIndex || pending.batch.calls[pending.next]?.callId !== synthetic.resume.callId) ||
            synthetic.resume.kind === 'finalize_settlement' && pending !== undefined)
          throw new TypeError('Stop changed the original synthetic merge/provider resume');
        // Full child merge/wait/permission history owns this kernel audit
        // cursor. It is never a fake provider batch or an executable tool.
      } else {
        if (frontier.kind !== run.nextStep || (pending !== undefined) !== (frontier.kind === 'tool')) throw new TypeError('stop frontier differs from its open batch');
        if (frontier.kind === 'tool' && !manual) await readToolCut(driver, artifacts, runId, authority.resolveToolInput);
      }
      const prepared: InvocationJournalEntry[] = [];
      const unknowns: InvocationJournalEntry[] = [];
      const rollback = workerRecovery?.rollback;
      const noRelease = await validateInstalledModelNoReleaseHistory(driver, artifacts, selected);
      const verifierStops = await validateVerifierStoppedHistory(driver, artifacts, selected);
      const dependencyClosed = new Set<number>();
      if (spec.dependencyPolicyRef) for (const progress of (await (await import('../dependency-history.js')).readDependencyHistory(driver, artifacts, selected)).values()) {
        if (progress.failed) { const row = selected.journal.find(entry => entry.opId === progress.failed!.opId && entry.attempt === progress.failed!.attempt && entry.phase === 'failed'); if (row) dependencyClosed.add(row.seq); }
      }
      const unclaimedPublications = !publication && spec.operation === 'delivery' &&
        selected.journal.some(entry => entry.opKind === 'publish') &&
        !selected.journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed')
        ? await readUnclaimedPublicationStopHistory(driver, artifacts, selected) : new Set<number>();
      for (const { entry, hasClaim } of stopInvocationHistory(selected.journal).values()) {
        if (manual && entry.seq === manual.original.unknown.seq) continue;
        if (entry.opKind === 'publish') {
          if (!publication?.closedJournalSeqs.has(entry.seq) && !unclaimedPublications.has(entry.seq))
            throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact publication retirement and projection closure');
          continue;
        }
        if (rollback && entry.opKind === 'tool' && entry.phase === 'unknown' && entry.seq === rollback.unknown.seq) continue;
        if (installedRuntime && ['model', 'mcp'].includes(entry.opKind) && entry.replayClass === 'retry' && entry.phase === 'unknown') {
          unknowns.push(entry);
          continue;
        }
        if (entry.opKind === 'verifier' && entry.replayClass === 'retry' && entry.phase === 'unknown' &&
            workerRecovery?.verifierAbandoned.some(closed => closed.opId === entry.opId && closed.attempt === entry.attempt &&
              closed.unknownJournalSeq === entry.seq && closed.budgetSettlementRef === entry.budgetSettlementRef)) {
          unknowns.push(entry);
          continue;
        }
        if (entry.opKind === 'tool' && entry.target === 'builtin:dependency-acquire' && entry.replayClass === 'workspace-rollback-retry' && entry.phase === 'unknown' &&
            workerRecovery?.dependencyAbandoned.some(closed => closed.opId === entry.opId && closed.attempt === entry.attempt &&
              closed.unknownJournalSeq === entry.seq && closed.budgetSettlementRef === entry.budgetSettlementRef)) {
          unknowns.push(entry); continue;
        }
        if (entry.opKind === 'mcp-server' && ['completed', 'failed'].includes(entry.phase) && mcpNoRelease.has(entry.seq)) {
          // Exact typed server history already verified its real physical retirement and independent settlement.
          continue;
        }
        if (!['model', 'tool', 'mcp', 'verifier', 'child_admission', 'child_merge', 'child_await', 'skill_resource'].includes(entry.opKind) || (!['prepared', 'completed'].includes(entry.phase) &&
            (entry.phase !== 'failed' || hasClaim && !(entry.opKind === 'model' && noRelease.has(entry.seq) ||
              entry.opKind === 'mcp' && mcpNoRelease.has(entry.seq) || entry.opKind === 'verifier' && verifierStops.has(entry.seq) || entry.opKind === 'tool' && dependencyClosed.has(entry.seq)))))
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
        if (entry.phase === 'prepared') prepared.push(entry);
      }
      // Terminal abandonment is worker-free. A still-unknown model/verifier
      // cannot begin sealing a live worker before its dispatch is closed.
      if (unknowns.length && run.activeWorkerLaunchId) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
      }
      if (pending && pending.batch.calls.slice(pending.next).some((call) => selected.journal.some((entry) =>
          entry.opId === toolOperationId(runId, pending.batch.itemId, call.callId) && entry.phase === 'dispatch_claimed' &&
          !(manual && entry.seq === manual.original.claim.seq) &&
          !mcpClosure?.abandonedRetryInvocations.some(closed => closed.opId === entry.opId && closed.attempt === entry.attempt) &&
          !(entry.opKind === 'mcp' && selected.journal.some(closed => closed.opId === entry.opId && closed.attempt === entry.attempt &&
            closed.phase === 'failed' && mcpNoRelease.has(closed.seq))) &&
          !(rollback && entry.seq === rollback.claim.seq)))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'an already dispatched call needs its real result');
      if (rollback && (!pending || rollback.request.batchItemId !== pending.batch.itemId || rollback.request.callIndex !== pending.next ||
          rollback.request.callId !== pending.batch.calls[pending.next]?.callId))
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'private rollback is not the current ordered stopped call');
      if (manual && (!pending || manual.original.request.batchItemId !== pending.batch.itemId || manual.original.request.callIndex !== pending.next ||
          manual.original.request.callId !== pending.batch.calls[pending.next]?.callId)) {
        throw new TypeError('manual acknowledgement changed the current original ordered call');
      }
      let seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
      if (publication) {
        seal = publication.seal;
        if (!!run.activeWorkerLaunchId !== !!seal) throw new TypeError('owned publication stop lost its original M seal or worker-free proof');
      } else if (run.activeWorkerLaunchId) {
        if (!input.checkpoint || !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']) ||
            input.checkpoint.workspaceStateRef !== checkpoint.workspaceStateRef) throw new TypeError('stop requires positive retirement over the current accounted workspace');
        seal = await prepareToolCheckpoint(driver, artifacts, owner, { run, spec, assembly, checkpointId,
          observedAt: intent.createdAt, postEffect: input.checkpoint }, reobserve);
      } else if (input.checkpoint !== undefined) throw new TypeError('worker-free stop cannot substitute a workspace proof');
      return withInstalledBrokerTerminalClosure(driver, artifacts, owner, installedRuntime, selected, async (brokerClosure) => {
        // The owning plan proves every exact model/retry unknown, never a
        // generic unknown phase or an already dispatched tool cancellation.
        const abandoned = [...brokerClosure.abandonedRetryInvocations, ...(mcpClosure?.abandonedRetryInvocations ?? []),
          ...(workerRecovery?.verifierAbandoned ?? []), ...(workerRecovery?.dependencyAbandoned ?? [])]
          .sort((left, right) => left.unknownJournalSeq - right.unknownJournalSeq ||
            Buffer.compare(Buffer.from(left.opId), Buffer.from(right.opId)) || left.attempt - right.attempt);
        if (abandoned.length !== unknowns.length || unknowns.some(entry => abandoned.filter(closed =>
          closed.opId === entry.opId && closed.attempt === entry.attempt && closed.unknownJournalSeq === entry.seq &&
          closed.budgetSettlementRef === entry.budgetSettlementRef).length !== 1)) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
        }
        for (let retry = 0; retry < 8; retry++) {
          if (manual) {
            manualPreparedAt = sampleCanonicalNow();
            manualStage = stageManualInvocationFinalization(manual, manualPreparedAt, selected.journal.length + 1);
            intent = selectAgentStop(prior, manualStage.intent);
            stagedStop = intent === manualStage.intent ? planCanonicalArtifact(intent, 'cliq-stop-intent-v1') : undefined;
            run = stagedStop ? { ...originalRun, stopIntentRef: stagedStop.ref, cancelRequested: true } : originalRun;
            checkpointId = stopCheckpointId(runId, run.stopIntentRef!);
          }
          const now = manualPreparedAt ?? sampleCanonicalNow();
          if (mcpRetryPlan) {
            retryStage = stageMcpRetryFinalization(mcpRetryPlan, now); intent = selectAgentStop(prior, retryStage.intent);
            stagedStop = intent === retryStage.intent ? planCanonicalArtifact(intent, 'cliq-stop-intent-v1') : undefined;
            run = stagedStop ? { ...originalRun, stopIntentRef: stagedStop.ref } : originalRun;
            checkpointId = stopCheckpointId(runId, run.stopIntentRef!);
          }
          if (publication && now < publication.observedAt)
            throw new KernelStorageError('RECOVERY_REQUIRED', 'publication terminal preparation predates its actual root projection');
          const refunds: Array<{ artifact: PlannedArtifact; closure?: PlannedArtifact; entry: InvocationJournalEntry }> = [];
          let reserved = run.budgetReserved;
          for (const entry of prepared.sort((a, b) => a.seq - b.seq)) {
            const remaining = subtractBudget(reserved, entry.budgetDelta, 'stop refund');
            const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId, opId: entry.opId,
              attempt: entry.attempt, preparedJournalSeq: entry.seq, terminalJournalSeq: selected.journal.length + (manual ? 1 : 0) + (rollback ? 1 : 0) + refunds.length + 1,
              terminalPhase: 'failed', reserved: entry.budgetDelta, consumed: ZERO_BUDGET, released: entry.budgetDelta,
              budgetConsumedBefore: run.budgetConsumed, budgetConsumedAfter: run.budgetConsumed,
              budgetReservedBefore: reserved, budgetReservedAfter: remaining, settledAt: now, settlementDigest: '' };
            settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
            const artifact = planCanonicalArtifact(settlement, settlement.format);
            const closure = entry.opKind === 'verifier' ? planCanonicalArtifact({ schemaVersion: 1,
              format: 'cliq-verifier-preparation-closure-v1', runId, opId: entry.opId, attempt: entry.attempt,
              preparedJournalSeq: entry.seq, requestRef: entry.requestRef, targetRef: entry.target, grantRef: entry.grantRef,
              disposition: 'unclaimed' }, 'cliq-verifier-preparation-closure-v1') : undefined;
            refunds.push({ artifact, ...(closure ? { closure } : {}), entry: { ...entry, phase: 'failed' as const, seq: settlement.terminalJournalSeq,
              budgetDelta: ZERO_BUDGET, errorRef: closure?.ref ?? run.stopIntentRef, budgetSettlementRef: artifact.ref, timestamp: now } });
            if (entry.opKind === 'mcp' && entry.replayClass === 'retry' && entry.attempt > 0) {
              delete refunds.at(-1)!.entry.evidenceRef; delete refunds.at(-1)!.entry.evidenceDigest;
            }
            reserved = remaining;
          }
          if (!isZeroBudget(reserved)) throw new TypeError('stop retains an unexplained reservation');
          const rollbackResult = rollback ? planPrivateRollbackResult(rollback.request, rollback.evidence, now) : undefined;
          const currentOpId = pending && toolOperationId(runId, pending.batch.itemId, pending.batch.calls[pending.next]!.callId);
          const mcpUnknown = currentOpId && mcpClosure?.abandonedRetryInvocations.filter(entry => entry.opId === currentOpId &&
            !retryUnknownHasLaterClaim(selected.journal, entry)).at(-1);
          const mcpFailed = currentOpId && selected.journal.filter(entry => entry.opId === currentOpId && entry.opKind === 'mcp' &&
            entry.replayClass === 'retry' && entry.phase === 'failed' && mcpNoRelease.has(entry.seq) &&
            selected.journal.some(claim => claim.opId === entry.opId && claim.attempt === entry.attempt && claim.phase === 'dispatch_claimed') &&
            !retryUnknownHasLaterClaim(selected.journal, entry)).at(-1);
          if (mcpUnknown && mcpFailed) throw new TypeError('MCP terminal call cannot select both uncertain and positively failed outcomes');
          const mcpFailedResult = mcpFailed ? planMcpNoReleaseResult(await readCanonicalArtifact(artifacts, mcpFailed.requestRef), mcpFailed, now) : undefined;
          const mcpUnknownResult = mcpUnknown ? planMcpRetryCancelledItem(await readCanonicalArtifact<import('../../kernel/tool-authorization.js').ToolRequestV1>(artifacts,
            selected.journal.find(entry => entry.seq === mcpUnknown.unknownJournalSeq)!.requestRef), decodeRetryUnknownCancelledResult({ schemaVersion: 1,
            kind: 'retry_unknown_cancelled', ...mcpUnknown, message: 'Run stopped without using the ambiguous result' }), now) : undefined;
          if (retryStage && (!mcpUnknownResult || canonicalSha256(mcpUnknownResult.item) !== canonicalSha256(retryStage.item)))
            throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP retry terminal proposal changed its exact current unused result');
          const nextCancelled = (pending?.next ?? 0) + (rollback ? 1 : 0) + (manual ? 1 : 0) + (mcpUnknownResult || mcpFailedResult ? 1 : 0);
          const cancelled = pending ? pending.batch.calls.slice(nextCancelled).map((_, index) => cancelledCall(pending.batch, nextCancelled + index, run.stopIntentRef!, now)) : [];
          const detail = planCanonicalArtifact({ ...agentStopDetail(intent, run.stopIntentRef!, now),
            abandonedRetryInvocations: abandoned,
            ...(manualStage ? { abandonedManualInvocation: manualStage.detail } : {}),
            ...(publication ? { publicationResultItemRefs: publication.publicationResultItemRefs,
              deliveryTerminalProjectionEvidenceRef: publication.evidenceRef } : {}) }, 'cliq-terminal-detail-v1');
          const continuation = await prepareContinuationCommit(artifacts, { context: decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef)),
            existingItems: items, items: [...(manualStage ? [manualStage.item] : []), ...(rollbackResult ? [rollbackResult.item] : []),
              ...(mcpUnknownResult ? [mcpUnknownResult.item] : []), ...(mcpFailedResult ? [mcpFailedResult.item] : []), ...cancelled.map(({ item }) => item)], frontier, checkpointId, workspaceStateRef: checkpoint.workspaceStateRef,
            artifacts: [detail, ...(manualStage ? [manualStage.artifact] : []), ...(stagedStop ? [stagedStop] : []), ...(retryStage?.artifacts ?? []),
              ...(mcpUnknownResult && !retryStage ? [mcpUnknownResult.artifact] : []), ...(mcpFailedResult?.artifacts ?? []), ...(rollbackResult?.artifacts ?? []), ...refunds.flatMap(({ artifact, closure }) => [artifact, ...(closure ? [closure] : [])]),
              ...cancelled.flatMap(({ artifacts }) => artifacts)] });
          const childTerminal = run.parentRunId ? await prepareChildTerminalAllocation(driver, artifacts, owner,
            { run: originalRun, status: intent.targetStatus, terminalReason: intent.reason, terminalDetailRef: detail.ref }) : undefined;
          let manualSessionRaced = false;
          const sessionPlan = !run.parentRunId ? await (async () => {
          const session = readSession(driver, run.sessionId);
          if (manual && session.updatedAt > now) {
            manualSessionRaced = true;
            return undefined;
          }
          const sessionContext = await readCurrentSessionContextGraph(driver, artifacts,
            readSessionPrincipalId(driver, session.id), session.id, session.contextRevision);
          if (canonicalSha256(sessionContext.cut.session) !== canonicalSha256(session))
            throw new KernelStorageError('REVISION_CONFLICT', 'Session stop context changed during its complete graph read');
          const admittedContext = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
          const sessionItem: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
            itemKey: `run-terminal:${runId}`, runId, operation: spec.operation, admittedSessionItemSeq: admittedContext.throughSessionItemSeq,
            status: intent.targetStatus, terminalReason: intent.reason, terminalDetailRef: detail.ref };
          const terminalArtifact = await artifacts.publishCanonical(sessionItem, sessionItem.format);
          const itemId = identityHash('cliq-session-run-terminal-item-v1', session.id, runId), seq = session.latestItemSeq + 1;
          const appended = await publishSessionContextAppend(driver, artifacts, owner, sessionContext.projection,
            { kind: 'raw', fromItemSeq: seq, throughItemSeq: seq,
              items: [{ sourceSessionId: session.id, itemSeq: seq, itemId, kind: 'run_terminal', payloadRef: terminalArtifact.ref }] });
            return { session, sessionCut: sessionContext.cut, projectionArtifact: appended.artifact, terminalArtifact, itemId, seq };
          })() : undefined;
          if (manualSessionRaced) continue;
          // New manual branch has two honest times: immutable logical
          // projection P, then true sampled commit/time-fence C. P is never a
          // physical observation, expiry extension or execution permission.
          const { frontierRef: _frontier, waitingOnRef: _wait, waitingReason: _reason, activeWorkerLaunchId: _worker, ...retainedRun } = run;
          const projectedManualRun: Run | undefined = manual ? {
            ...retainedRun, status: intent.targetStatus, nextStep: null,
            latestCheckpointId: checkpointId, budgetReserved: { ...ZERO_BUDGET }, terminalReason: intent.reason,
            terminalDetailRef: detail.ref, revision: originalRun.revision + 1, updatedAt: now
          } : undefined;
          const manualResponse = manual && manualStage && projectedManualRun ? {
            protocolVersion: 1 as const, ok: true as const,
            result: {
              method: 'run.reconcile' as const,
              snapshot: { schemaVersion: 1 as const, operation: spec.operation, run: projectedManualRun, latestRunItemSeq: continuation.throughItemSeq },
              resolution: { kind: 'abandoned_run' as const, attestationRef: manualStage.artifact.ref, terminalDetailRef: detail.ref }
            }
          } : undefined;
          const manualResponseArtifact = manualResponse ? await artifacts.publishCanonical(manualResponse, 'cliq-control-response-v1') : undefined;
          await seal?.refresh();
          let time: ReturnType<typeof acceptTime> | undefined, updated: Run | undefined;
          driver.transaction((connection) => {
            assertActiveStateOwner(connection, owner);
            if (sessionPlan && canonicalSha256(readSession(connection, sessionPlan.session.id)) !== canonicalSha256(sessionPlan.session)) {
              if (seal && !publication) throw new KernelStorageError('REVISION_CONFLICT', 'terminal Session changed after sealed completion preparation');
              return;
            }
            if (sessionPlan) assertCurrentSessionContextGraph(connection, sessionPlan.sessionCut);
            // P describes this selected Run/Session projection. Unrelated
            // maintenance may advance the global fence while CAS publishes;
            // only the actual fresh transaction sample C must honor it.
            const priorManualFence = manual ? readTimeFence(connection)?.lastAcceptedAt : undefined;
            brokerClosure.reobserve(connection);
            mcpClosure?.reobserve(connection);
            workerRecovery?.reobserve(connection);
            manual?.reobserve(connection);
            const committedAt = sampleCanonicalNow();
            time = acceptTime(connection, committedAt);
            if (!time.accepted) return;
            if (manual && (!priorManualFence || !manualStopTimeOrderIsValid({
              projectionAt: now, sourceRunUpdatedAt: originalRun.updatedAt, sourceCheckpointCreatedAt: checkpoint.createdAt,
              ...(sessionPlan ? { sourceSessionUpdatedAt: sessionPlan.session.updatedAt } : {}), committedAt, lastAcceptedAt: priorManualFence
            }))) {
              throw new KernelStorageError('RECOVERY_REQUIRED', 'manual terminal projection or true commit time regressed');
            }
            if (committedAt < now) throw new KernelStorageError('RECOVERY_REQUIRED', 'terminal transaction precedes its prepared artifacts');
            assertCut(connection, selected);
            if ((abandoned.length || manual) && parseCanonicalTime(committedAt) - parseCanonicalTime(now) > 5_000) {
              throw new KernelStorageError('RECOVERY_REQUIRED', 'broker terminal closure preparation is stale; reobserve the original claim');
            }
            brokerClosure.validate(connection, originalRun, committedAt);
            mcpClosure?.validate(connection, originalRun, committedAt);
            manual?.validate(connection, committedAt);
            publication?.validate(connection, run, committedAt);
            workerRecovery?.validate(connection, committedAt);
            for (const artifact of workerRecovery?.metadata ?? []) insertArtifactMetadata(connection, artifact, committedAt);
            workerRecovery?.commit(connection, committedAt);
            if (rollback) resolvePrivateRollbackInvocation(connection, driver, owner, recovery!, runId, now);
            if (connection.prepare("SELECT 1 FROM worker_launches WHERE run_id = ? AND phase != 'retired' AND launch_id != ? LIMIT 1")
              .get(runId, run.activeWorkerLaunchId ?? '')) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop cannot retain a pending worker launch');
            for (const artifact of [...continuation.metadata, ...(seal?.metadata ?? []), ...(publication?.metadata(connection) ?? []),
              ...brokerClosure.metadata, ...(mcpClosure?.metadata ?? []), ...(manual?.metadata ?? []), ...(manualResponseArtifact ? [manualResponseArtifact] : []), ...(childTerminal?.metadata ?? []), ...(sessionPlan ? [sessionPlan.terminalArtifact, sessionPlan.projectionArtifact] : [])]) insertArtifactMetadata(connection, artifact, committedAt);
            publication?.validate(connection, run, committedAt);
            if (publication && sessionPlan && canonicalSha256(readSession(connection, sessionPlan.session.id)) !== canonicalSha256(sessionPlan.session))
              throw new KernelStorageError('REVISION_CONFLICT', 'publication terminal Session changed during artifact registration');
            seal?.commit(connection, run, committedAt);
            publication?.commit(connection, run, committedAt);
            if (connection.prepare("SELECT 1 FROM workspace_generations WHERE run_id = ? AND phase NOT IN ('sealed','retired') LIMIT 1").get(runId)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop requires every workspace generation sealed or positively retired');
            assertRetiredGenerationCut(connection, run, selected.workspaceGenerations.map(generation =>
              workerRecovery?.generation.generationRef === generation.generationRef ||
              seal && generation.generationRef === readRequiredWorkerLaunch(connection, run.activeWorkerLaunchId!).workspaceGenerationRef
                ? readRequiredWorkspaceGenerationByRef(connection, generation.generationRef) : generation));
            if (manualStage) appendInvocationJournalEntry(connection, manualStage.abandoned);
            for (const refund of refunds) appendInvocationJournalEntry(connection, refund.entry);
            const logicalAt = manual ? now : committedAt;
            continuation.commit(connection, originalRun, selected.journal.length + (manual ? 1 : 0) + (rollback ? 1 : 0) + refunds.length, logicalAt);
            connection.prepare(`UPDATE runs SET status = ?, next_step = NULL, frontier_ref = NULL, waiting_reason = NULL, waiting_on_ref = NULL,
              active_worker_launch_id = NULL, budget_reserved_json = ?, terminal_reason = ?, terminal_detail_ref = ?,stop_intent_ref=?,cancel_requested=?, revision = revision + 1, updated_at = ? WHERE id = ?`)
              .run(intent.targetStatus, JSON.stringify(ZERO_BUDGET), intent.reason, detail.ref, run.stopIntentRef!, run.cancelRequested ? 1 : 0, logicalAt, runId);
            childTerminal?.commit(connection, logicalAt);
            if (sessionPlan) {
              const { session, terminalArtifact, projectionArtifact, itemId, seq } = sessionPlan;
            connection.prepare("INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, ?, NULL, ?, 'run_terminal', ?, ?)")
              .run(itemId, session.id, BigInt(seq), terminalArtifact.ref, logicalAt);
            connection.prepare('UPDATE sessions SET latest_item_seq = ?, context_revision = context_revision + 1, context_projection_ref = ?, updated_at = ? WHERE id = ?')
              .run(BigInt(seq), projectionArtifact.ref, logicalAt, session.id);
            }
            updated = readRun(connection, runId);
            if (manual && manualResponseArtifact && projectedManualRun) {
              requireEqual(updated, projectedManualRun, 'manual first response exact SQL terminal projection');
              if (readControlRequest(connection, manual.mutation.identity.principalId, 'run.reconcile', manual.mutation.request.requestId)) {
                throw new KernelStorageError('REQUEST_ID_CONFLICT', 'manual request already has a retained response');
              }
              insertControlRequest(connection, {
                principalId: manual.mutation.identity.principalId, method: 'run.reconcile', requestId: manual.mutation.request.requestId,
                requestDigest: manual.mutation.request.requestDigest, channelIdentityRef: manual.mutation.identity.channelIdentityRef,
                channelIdentityDigest: manual.mutation.identity.channelIdentityDigest, responseRef: manualResponseArtifact.ref, committedAt
              });
            }
            publication?.assertFresh(committedAt, connection);
            if (publicationFinalization) closeOwnedPublicationAbortFinalization(driver, owner, publicationFinalization);
            appendRunStateEvent(connection, updated, logicalAt);
          });
          requireHealthyFence(time?.outcome);
          if (updated) {
            manual?.release();
            await mcpClosure?.acknowledge();
            return immutableSnapshot({ run: updated });
          }
          if (seal && !publication) throw new KernelStorageError('RECOVERY_REQUIRED', 'terminal time cut changed after sealed completion preparation');
        }
        throw new KernelStorageError('REVISION_CONFLICT', 'terminal Session/time cut kept changing');
      }, terminalFinalization);
      } finally {
        if (publicationFinalization) closeOwnedPublicationAbortFinalization(driver, owner, publicationFinalization);
      }
    })
  };
}
