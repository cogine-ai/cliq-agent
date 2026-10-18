import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { identityHash, modelOperationId } from '../kernel/identity.js';
import type { ContinuationItem, FinalCandidateItem, Run, RunAssemblyV1, RunFrontier, RunSpec } from '../kernel/types.js';
import type { ToolCheckpointProof } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ModelRequestV1 } from '../model/request.js';
import type { ResolveToolInput } from '../model/attempt.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { validateModelTurn } from '../runtime/continuation.js';
import { readCanonicalArtifact, readModelTurnMaterial } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { finalCandidateCheckpointId, finalCandidateItemId, readCandidateVerifierPlan } from './final-candidate-plan.js';
import { isZeroBudget } from './invariants.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal, readHighestPreparedAttempt } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun } from './rows.js';
import { publishCandidateSource } from './result-source.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from './tool-checkpoint.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';

/** A candidate is a quiesced, inspectable proposal, never a verified result or
 * a delivery grant. All source, summary and verifier inputs are store-derived. */
export function loadFinalCandidate(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, authority: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; resolveToolInput: ResolveToolInput;
}, reobserve?: NativeWorkerRetirement) {
  const { run: admitted, spec, assembly, resolveToolInput } = authority;
  const runId = admitted.id;
  return {
    prepareFinalCandidate: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; checkpoint: ToolCheckpointProof;
    }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'checkpoint']) || !Number.isSafeInteger(input.expectedRunRevision) ||
          input.expectedRunRevision < 1 || !input.checkpoint ||
          !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef'])) {
        throw new TypeError('invalid final candidate input');
      }
      assertActiveStateOwner(driver, owner);
      const selected = await readRecoveryClosure(driver, artifacts, runId);
      const { run } = selected;
      const launches = readWorkerLaunchesForRun(driver, runId), generations = readWorkspaceGenerationsForRun(driver, runId);
      const itemRows = (connection: SqliteConnection) => connection.prepare(
        'SELECT item_id, item_seq, kind, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
        .all<{ item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string }>(runId)
        .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
      const originalItems = itemRows(driver);
      if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'candidate Run revision changed');
      if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt) {
        throw new TypeError('candidate authority no longer belongs to this Run');
      }
      const rejectChildren = (connection: SqliteConnection) => {
        if (spec.operation !== 'agent' || run.parentRunId || selected.childAllocations.length ||
            connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id = ? LIMIT 1').get(runId) ||
            connection.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(runId)) {
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires child finalize settlement');
        }
      };
      rejectChildren(driver);
      if (run.status !== 'running' || run.nextStep !== 'agent' || !run.frontierRef || !run.activeWorkerLaunchId ||
          run.waitingReason || run.waitingOnRef || run.stopIntentRef || run.cancelRequested || !isZeroBudget(run.budgetReserved) ||
          selected.workerLaunches.length !== 1 || selected.workerLaunches[0]!.launchId !== run.activeWorkerLaunchId) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires the exact unstopped final model cut');
      }
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
      if (frontier.kind !== 'agent' || frontier.phase !== 'model_turn' || frontier.compactionPlanRef !== undefined) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires a normal final model frontier');
      }
      const opId = modelOperationId(runId, frontier);
      const prepared = readHighestPreparedAttempt(driver, runId, opId);
      const completion = prepared && selected.journal.find(entry => entry.opId === opId && entry.attempt === prepared.attempt && entry.phase === 'completed');
      const lastByOperation = new Map(selected.journal.map(entry => [`${entry.opId}\0${entry.attempt}`, entry]));
      if (!prepared || prepared.opKind !== 'model' || !completion?.resultRef ||
          [...lastByOperation.values()].some(entry => entry.phase !== 'completed' && entry.phase !== 'failed')) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires settled invocations and the highest completed model attempt');
      }
      const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
      const material = await readModelTurnMaterial(artifacts, completion.resultRef);
      validateModelTurn(request, material, resolveToolInput);
      const producerId = identityHash('cliq-model-turn-item-v1', runId, opId, String(prepared.attempt));
      const producerRow = selected.items.at(-1);
      const producer = producerRow && await readCanonicalArtifact<ContinuationItem>(artifacts, producerRow.payloadRef);
      if (request.kind !== 'normal' || request.opId !== opId || request.attempt !== prepared.attempt || request.runId !== runId ||
          material.turn.stopReason !== 'end' || material.turn.toolCalls.length || !material.text.utf8.trim() ||
          producer?.kind !== 'model_turn' || producer.itemId !== producerId || producer.modelOpId !== opId ||
          producer.modelAttempt !== prepared.attempt || producer.modelTurnRef !== completion.resultRef || producer.stopReason !== 'end' ||
          producer.textRef !== material.turn.textRef) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate has no exact final producer and summary');
      }
      const checkpointId = finalCandidateCheckpointId(runId, producerId);
      const seal = await prepareToolCheckpoint(driver, artifacts, owner, { run, spec, assembly, checkpointId,
        observedAt: completion.timestamp, postEffect: input.checkpoint }, reobserve);
      const source = await publishCandidateSource(artifacts, spec, input.checkpoint.workspaceStateRef);
      const createdAt = sampleCanonicalNow();
      const candidate: FinalCandidateItem = { schemaVersion: 1, kind: 'final_candidate', operation: 'agent', runId,
        itemId: finalCandidateItemId(runId, producerId), producingItemId: producerId, producingOpId: opId,
        baseSourceRef: spec.baseWorkspaceManifestRef, resultSourceRef: source.sourceRef, diffRef: source.diffRef,
        summaryRef: producer.textRef, sourceDigest: source.source.manifestDigest, diffDigest: source.diff.diffDigest, createdAt };
      const verifierPlan = await readCandidateVerifierPlan(artifacts, spec, {
        runId, candidateItemId: candidate.itemId, resultSourceRef: source.sourceRef });
      const plan = planCanonicalArtifact(verifierPlan, 'cliq-verifier-plan-v1');
      const nextFrontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: candidate.itemId,
        resultSourceRef: source.sourceRef, verifierPlanRef: plan.ref, nextVerifierIndex: 0, afterPass: 'finalize' };
      const context = decodeContextManifest(await readCanonicalArtifact(artifacts, selected.latestCheckpoint.contextManifestRef));
      const existingItems = await Promise.all(selected.items.map(async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })));
      const continuation = await prepareContinuationCommit(artifacts, { context, existingItems, items: [candidate], frontier: nextFrontier,
        checkpointId, workspaceStateRef: input.checkpoint.workspaceStateRef, artifacts: [plan] });
      function assertCut(connection: SqliteConnection) {
        assertActiveStateOwner(connection, owner);
        rejectChildren(connection);
        if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(run) ||
            canonicalSha256(readCheckpoint(connection, run.latestCheckpointId)) !== canonicalSha256(selected.latestCheckpoint) ||
            canonicalSha256(readInvocationJournal(connection, runId)) !== canonicalSha256(selected.journal) ||
            canonicalSha256(readWorkerLaunchesForRun(connection, runId)) !== canonicalSha256(launches) ||
            canonicalSha256(readWorkspaceGenerationsForRun(connection, runId)) !== canonicalSha256(generations) ||
            canonicalSha256(itemRows(connection)) !== canonicalSha256(originalItems)) {
          throw new KernelStorageError('REVISION_CONFLICT', 'candidate producer cut changed before commit');
        }
      }
      await seal.refresh();
      let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
      driver.transaction(connection => {
        assertCut(connection);
        const now = sampleCanonicalNow(), fence = readTimeFence(connection);
        if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'candidate canonical time fence is missing');
        outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
        if (outcome !== 'healthy') return;
        if (now < createdAt || now < run.updatedAt || now >= run.deadlineAt) {
          throw new KernelStorageError('LEASE_FENCED', 'candidate is outside its healthy Run lifetime');
        }
        for (const metadata of [...source.metadata, ...seal.metadata, ...continuation.metadata]) insertArtifactMetadata(connection, metadata, now);
        // Large metadata graphs must not consume the proof's freshness budget
        // after it has already been accepted. Sample the actual seal time only
        // after those writes, then retain the original strict freshness check.
        const committedAt = sampleCanonicalNow();
        if (committedAt < now || committedAt >= run.deadlineAt) {
          throw new KernelStorageError('LEASE_FENCED', 'candidate lifetime changed during artifact registration');
        }
        outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
        if (outcome !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'candidate canonical clock changed during registration');
        seal.commit(connection, run, committedAt);
        continuation.commit(connection, run, selected.journal.length, committedAt);
        connection.prepare('UPDATE runs SET revision = revision + 1, updated_at = ? WHERE id = ?').run(committedAt, runId);
        updated = readRun(connection, runId);
        appendRunStateEvent(connection, updated, committedAt);
      });
      requireHealthyFence(outcome);
      if (!updated) throw new KernelStorageError('RECOVERY_REQUIRED', 'candidate did not commit under the canonical time fence');
      return immutableSnapshot({ run: updated, candidateItemId: candidate.itemId, checkpointId });
    })
  };
}
