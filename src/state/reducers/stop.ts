import { canonicalSha256 } from '../../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../kernel/identity.js';
import type { BudgetSettlementV1, ContinuationItem, InvocationJournalEntry, Run, RunAssemblyV1, RunCancel, RunFrontier, RunSpec, SessionRunTerminalItem } from '../../kernel/types.js';
import type { ToolCheckpointProof } from '../../kernel/tool-authorization.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ResolveToolInput } from '../../model/attempt.js';
import { exactKeys, requireEqual } from '../../policy/runtime-authority.js';
import { toolOperationId } from '../../policy/tool-policy.js';
import { cancelledCall, cancelRequestDigest, agentStopDetail, openStopBatch, selectAgentStop, stopCheckpointId, stopInvocationHistory, type AgentStopIntent } from '../../runtime/stop.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from '../artifacts.js';
import { mapArtifactReads } from '../bounded-artifact-reads.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { validateControlChannelClosure } from '../control-channel.js';
import { prepareContinuationCommit } from '../continuation-commit.js';
import { decodeAdmittedContext, decodeContextManifest, decodeSessionProjection } from '../decoders.js';
import { KernelStorageError, stateOperation } from '../errors.js';
import { isZeroBudget, subtractBudget } from '../invariants.js';
import { readRecoveryClosure } from '../recovery-closure.js';
import { appendInvocationJournalEntry, nextJournalSequence } from '../repositories/journal.js';
import { readWorkerLaunchesForRun } from '../repositories/worker-launches.js';
import { insertControlRequest, readControlRequest, readRun, readSession, ZERO_BUDGET } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { readCancelResponse, readAgentStop, type CancelResponse } from '../stop-recovery.js';
import { readResourceStopCause } from '../resource-stop.js';
import { prepareModelFailureStop } from '../model-failure.js';
import { prepareToolCheckpoint, validateRetainedWorkerSeal } from '../tool-checkpoint.js';
import { readToolCut } from '../tool-cut.js';
import { appendRunStateEvent, requireHealthyFence } from './invocation.js';

/** Loaded authority only. Cancellation fences immediately; terminal drain independently proves the entire current cut. */
export function loadAgentStop(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, authority: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; principalId: string; resolveToolInput: ResolveToolInput;
  assertAuthority: () => Promise<void>;
}) {
  const { run: admitted, spec, assembly, principalId } = authority;
  const runId = admitted.id;
  const result = (run: Run) => ({ run, checkpointId: stopCheckpointId(runId, run.stopIntentRef!) });
  const deadlineIntent = (createdAt: string): AgentStopIntent => ({ schemaVersion: 1, runId, createdAt, origin: 'deadline',
    targetStatus: 'failed', reason: 'budget_exhausted', deadlineAt: admitted.deadlineAt });
  async function cut(revision: number, allowWorkerRecovery = false) {
    if (!Number.isSafeInteger(revision) || revision < 1) throw new TypeError('invalid stop revision');
    const selected = await readRecoveryClosure(driver, artifacts, runId);
    const { run } = selected;
    if (run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run revision changed');
    if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt) throw new TypeError('stop authority no longer belongs to this Run');
    if (spec.operation !== 'agent' || run.parentRunId || selected.childAllocations.length ||
        driver.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(runId)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child stop requires the parent/child settlement reducer');
    // Cancellation/deadline may fence a validated worker-death wait, but cannot clear it or drain it.
    if (!['queued', 'running', 'waiting'].includes(run.status) || !['agent', 'tool'].includes(run.nextStep ?? '') ||
        (run.status === 'waiting' && !['approval', 'input'].includes(run.waitingReason ?? '') &&
          !(allowWorkerRecovery && run.waitingReason === 'reconciliation'))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop requires an agent continuation or ordinary control wait');
    return selected;
  }
  function assertCut(connection: SqliteConnection, selected: Awaited<ReturnType<typeof cut>>) {
    assertActiveStateOwner(connection, owner);
    if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(selected.run)) throw new KernelStorageError('REVISION_CONFLICT', 'stop Run cut changed');
    if (nextJournalSequence(connection, runId) !== selected.journal.length + 1 ||
        Number(connection.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?').get<{ seq: bigint }>(runId)?.seq) !== selected.items.length ||
        connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id = ? LIMIT 1').get(runId) ||
        connection.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(runId)) throw new KernelStorageError('REVISION_CONFLICT', 'stop continuation changed');
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
    intent: AgentStopIntent; metadata?: PublishedArtifact[];
  } | undefined>) {
    const prior = selected.run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
    if (prior?.origin === 'user_cancel') return immutableSnapshot(result(selected.run));
    for (let retry = 0; retry < 8; retry++) {
      const now = sampleCanonicalNow();
      const proposal = await derive(now);
      if (!proposal) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'current continuation has no supported failure');
      const intent = selectAgentStop(prior, proposal.intent);
      if (intent === prior) return immutableSnapshot(result(selected.run));
      const artifact = await artifacts.publishCanonical(intent, 'cliq-stop-intent-v1');
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
        insertArtifactMetadata(connection, artifact, now);
        connection.prepare('UPDATE runs SET stop_intent_ref = ?, revision = revision + 1, updated_at = ? WHERE id = ?').run(artifact.ref, now, runId);
        updated = readRun(connection, runId);
        appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(time?.outcome);
      if (updated) return immutableSnapshot(result(updated));
    }
    throw new KernelStorageError('REVISION_CONFLICT', 'failure/time cut kept changing');
  }
  return {
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
      const selected = await cut(input.expectedRunRevision, true);
      const prior = selected.run.stopIntentRef ? await readAgentStop(driver, artifacts, selected) : undefined;
      for (let retry = 0; retry < 8; retry++) {
        const now = sampleCanonicalNow();
        // User cancellation outranks a deadline; equal precedence preserves the first committed intent.
        const intent: AgentStopIntent = prior?.origin === 'user_cancel' ? prior : {
          schemaVersion: 1, runId, createdAt: now, origin: 'user_cancel', targetStatus: 'cancelled', reason: 'cancelled_by_user',
          requestId: input.requestId, principalId };
        const intentArtifact = await artifacts.publishCanonical(intent, 'cliq-stop-intent-v1');
        const next: Run = { ...selected.run, stopIntentRef: intentArtifact.ref, cancelRequested: true, revision: selected.run.revision + 1, updatedAt: now };
        const response: CancelResponse = { protocolVersion: 1, ok: true, result: { method: 'run.cancel',
          snapshot: { schemaVersion: 1, operation: 'agent', run: next, latestRunItemSeq: selected.items.length } } };
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
    expireRun: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('unknown deadline stop field');
      const selected = await cut(input.expectedRunRevision, true);
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
      const selected = await cut(input.expectedRunRevision);
      return commitDerivedStop(selected, async (now) => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        const cause = await readResourceStopCause(driver, artifacts, selected, now);
        return cause ? { intent: { schemaVersion: 1, runId, createdAt: now, ...cause } } : undefined;
      });
    }),
    stopForModelFailure: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; inspectorIdentityRef: string; inspectorIdentityDigest: string;
    }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'inspectorIdentityRef', 'inspectorIdentityDigest'])) throw new TypeError('unknown model failure stop field');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const selected = await cut(input.expectedRunRevision);
      return commitDerivedStop(selected, async (now) => {
        if (now >= selected.run.deadlineAt) return { intent: deadlineIntent(now) };
        return prepareModelFailureStop(artifacts, assertActiveStateOwner(driver, owner), assembly, selected, {
          inspectorIdentityRef: input.inspectorIdentityRef, inspectorIdentityDigest: input.inspectorIdentityDigest
        }, now);
      });
    }),
    commitTerminalStop: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; checkpoint?: ToolCheckpointProof }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', ...(input.checkpoint === undefined ? [] : ['checkpoint'])])) throw new TypeError('unknown terminal stop field');
      assertActiveStateOwner(driver, owner);
      await authority.assertAuthority();
      const recovered = await readRecoveryClosure(driver, artifacts, runId);
      if (recovered.run.stopIntentRef && ['failed', 'cancelled'].includes(recovered.run.status) &&
          [recovered.run.revision, recovered.latestCheckpoint.basedOnRunRevision].includes(input.expectedRunRevision)) {
        return immutableSnapshot({ run: recovered.run });
      }
      const selected = await cut(input.expectedRunRevision);
      const { run, latestCheckpoint: checkpoint } = selected;
      if (!run.stopIntentRef) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal drain requires a persisted StopIntent');
      if (assembly.mcpServers.length) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'MCP stop requires server-containment closure');
      for (const launch of readWorkerLaunchesForRun(driver, runId).filter((launch) => launch.phase === 'retired')) {
        const generation = selected.workspaceGenerations.find((generation) => generation.generationRef === launch.workspaceGenerationRef);
        if (!generation) throw new TypeError('retired worker has no generation');
        await validateRetainedWorkerSeal(driver, artifacts, { run, spec, assembly, launch, generation });
      }
      const intent = await readAgentStop(driver, artifacts, selected);
      const checkpointId = stopCheckpointId(runId, run.stopIntentRef);
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
      const items = await mapArtifactReads(selected.items, async (row) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
      const pending = openStopBatch(items.map(({ item }) => item));
      if (frontier.kind !== run.nextStep || (pending !== undefined) !== (frontier.kind === 'tool')) throw new TypeError('stop frontier differs from its open batch');
      if (frontier.kind === 'tool') await readToolCut(driver, artifacts, runId, authority.resolveToolInput);
      const prepared = [];
      for (const { entry, hasClaim } of stopInvocationHistory(selected.journal).values()) {
        if (!['model', 'tool'].includes(entry.opKind) || (!['prepared', 'completed'].includes(entry.phase) &&
            (entry.phase !== 'failed' || hasClaim))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'terminal stop awaits exact dispatch/reconciliation closure');
        if (entry.phase === 'prepared') prepared.push(entry);
      }
      if (pending && pending.batch.calls.slice(pending.next).some((call) => selected.journal.some((entry) =>
          entry.opId === toolOperationId(runId, pending.batch.itemId, call.callId) && entry.phase === 'dispatch_claimed'))) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'an already dispatched call needs its real result');
      let seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
      if (run.activeWorkerLaunchId) {
        if (!input.checkpoint || !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']) ||
            input.checkpoint.workspaceStateRef !== checkpoint.workspaceStateRef) throw new TypeError('stop requires positive retirement over the current accounted workspace');
        seal = await prepareToolCheckpoint(driver, artifacts, owner, { run, spec, assembly, checkpointId,
          observedAt: intent.createdAt, postEffect: input.checkpoint });
      } else if (input.checkpoint !== undefined) throw new TypeError('worker-free stop cannot substitute a workspace proof');
      for (let retry = 0; retry < 8; retry++) {
        const now = sampleCanonicalNow();
        const refunds: Array<{ artifact: PlannedArtifact; entry: InvocationJournalEntry }> = [];
        let reserved = run.budgetReserved;
        for (const entry of prepared.sort((a, b) => a.seq - b.seq)) {
          const remaining = subtractBudget(reserved, entry.budgetDelta, 'stop refund');
          const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId, opId: entry.opId,
            attempt: entry.attempt, preparedJournalSeq: entry.seq, terminalJournalSeq: selected.journal.length + refunds.length + 1,
            terminalPhase: 'failed', reserved: entry.budgetDelta, consumed: ZERO_BUDGET, released: entry.budgetDelta,
            budgetConsumedBefore: run.budgetConsumed, budgetConsumedAfter: run.budgetConsumed,
            budgetReservedBefore: reserved, budgetReservedAfter: remaining, settledAt: now, settlementDigest: '' };
          settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
          const artifact = planCanonicalArtifact(settlement, settlement.format);
          refunds.push({ artifact, entry: { ...entry, phase: 'failed' as const, seq: settlement.terminalJournalSeq,
            budgetDelta: ZERO_BUDGET, errorRef: run.stopIntentRef, budgetSettlementRef: artifact.ref, timestamp: now } });
          reserved = remaining;
        }
        if (!isZeroBudget(reserved)) throw new TypeError('stop retains an unexplained reservation');
        const cancelled = pending ? pending.batch.calls.slice(pending.next).map((_, index) => cancelledCall(pending.batch, pending.next + index, run.stopIntentRef!, now)) : [];
        const detail = planCanonicalArtifact(agentStopDetail(intent, run.stopIntentRef, now), 'cliq-terminal-detail-v1');
        const continuation = await prepareContinuationCommit(artifacts, { context: decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef)),
          existingItems: items, items: cancelled.map(({ item }) => item), frontier, checkpointId, workspaceStateRef: checkpoint.workspaceStateRef,
          artifacts: [detail, ...refunds.map(({ artifact }) => artifact), ...cancelled.flatMap(({ artifacts }) => artifacts)] });
        const session = readSession(driver, run.sessionId);
        const projection = decodeSessionProjection(await readCanonicalArtifact(artifacts, session.contextProjectionRef));
        if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq) throw new TypeError('Session stop projection is not current');
        const admittedContext = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
        const sessionItem: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
          itemKey: `run-terminal:${runId}`, runId, operation: 'agent', admittedSessionItemSeq: admittedContext.throughSessionItemSeq,
          status: intent.targetStatus, terminalReason: intent.reason, terminalDetailRef: detail.ref };
        const terminalArtifact = await artifacts.publishCanonical(sessionItem, sessionItem.format);
        const itemId = identityHash('cliq-session-run-terminal-item-v1', session.id, runId), seq = session.latestItemSeq + 1;
        projection.contextRevision++;
        projection.throughItemSeq = seq;
        projection.segments.push({ kind: 'raw', fromItemSeq: seq, throughItemSeq: seq,
          items: [{ sourceSessionId: session.id, itemSeq: seq, itemId, kind: 'run_terminal', payloadRef: terminalArtifact.ref }] });
        projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
        const projectionArtifact = await artifacts.publishCanonical(projection, projection.format);
        let time: ReturnType<typeof acceptTime> | undefined, updated: Run | undefined;
        driver.transaction((connection) => {
          assertActiveStateOwner(connection, owner);
          if (canonicalSha256(readSession(connection, session.id)) !== canonicalSha256(session)) return;
          time = acceptTime(connection, now);
          if (!time.accepted) return;
          assertCut(connection, selected);
          if (connection.prepare("SELECT 1 FROM worker_launches WHERE run_id = ? AND phase != 'retired' AND launch_id != ? LIMIT 1")
            .get(runId, run.activeWorkerLaunchId ?? '')) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop cannot retain a pending worker launch');
          for (const artifact of [...continuation.metadata, ...(seal?.metadata ?? []), terminalArtifact, projectionArtifact]) insertArtifactMetadata(connection, artifact, now);
          seal?.commit(connection, run, now);
          if (connection.prepare("SELECT 1 FROM workspace_generations WHERE run_id = ? AND phase != 'sealed' LIMIT 1").get(runId)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stop requires every workspace generation sealed');
          for (const refund of refunds) appendInvocationJournalEntry(connection, refund.entry);
          continuation.commit(connection, run, selected.journal.length + refunds.length, now);
          connection.prepare(`UPDATE runs SET status = ?, next_step = NULL, frontier_ref = NULL, waiting_reason = NULL, waiting_on_ref = NULL,
            active_worker_launch_id = NULL, budget_reserved_json = ?, terminal_reason = ?, terminal_detail_ref = ?, revision = revision + 1, updated_at = ? WHERE id = ?`)
            .run(intent.targetStatus, JSON.stringify(ZERO_BUDGET), intent.reason, detail.ref, now, runId);
          connection.prepare("INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, ?, NULL, ?, 'run_terminal', ?, ?)")
            .run(itemId, session.id, BigInt(seq), terminalArtifact.ref, now);
          connection.prepare('UPDATE sessions SET latest_item_seq = ?, context_revision = context_revision + 1, context_projection_ref = ?, updated_at = ? WHERE id = ?')
            .run(BigInt(seq), projectionArtifact.ref, now, session.id);
          updated = readRun(connection, runId);
          appendRunStateEvent(connection, updated, now);
        });
        requireHealthyFence(time?.outcome);
        if (updated) return immutableSnapshot({ run: updated });
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'terminal Session/time cut kept changing');
    })
  };
}
