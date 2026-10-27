import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { DeliveryMergeConflictItem, DeliveryMergeItem } from '../kernel/delivery.js';
import type { ContinuationItem, FinalCandidateItem, Run, RunFrontier, RunSpec } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { deliveryMergeConflictArtifact, deliveryMergeConflictCheckpointId, deliveryMergeConflictItemId,
  deliveryMergeConflictStop, deliveryMergeItemId, readDeliveryMergeSource } from './delivery-recovery.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { finalCandidateCheckpointId, finalCandidateItemId, readCandidateVerificationData } from './final-candidate-plan.js';
import { isZeroBudget } from './invariants.js';
import { prepareDeliveryMergePlan } from './publication-merge-plan.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import { readCheckpoint, readRun } from './rows.js';
import { isRolledBackSqliteTransactionFailure, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

export type DeliveryMergeCompletion = { disposition: 'candidate' | 'conflict'; run: Run; checkpointId: string; itemId: string }
  | { disposition: 'resource_limited'; run: Run };
const same = (left: unknown, right: unknown) => canonicalSha256(left) === canonicalSha256(right);

/** One original CAS-only merge owner. It retains its diff3 plan and exact
 * publication graph across joined CAS/rolled-back SQL failures. Nothing here
 * launches a worker, fabricates a generation/seal, grants permission or writes
 * the user's workspace. Physical preparation is the existing later lifecycle. */
export function loadDeliveryMerge(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: { run: Run; spec: RunSpec }) {
  const admitted = immutableSnapshot(authority.run), spec = immutableSnapshot(authority.spec), runId = admitted.id;
  let pending: Promise<DeliveryMergeCompletion> | undefined;
  let retained: {
    cut: Awaited<ReturnType<typeof readRecoveryClosure>>; source: Awaited<ReturnType<typeof readDeliveryMergeSource>>;
    prepared?: Awaited<ReturnType<typeof prepareDeliveryMergePlan>>;
    graph?: ReturnType<typeof planContinuationCommit>; graphMetadata?: Awaited<ReturnType<ReturnType<typeof planContinuationCommit>['publish']>>;
    metadata: PublishedArtifact[]; conflictStopRef?: string; checkpointId?: string; itemId?: string; disposition?: 'candidate' | 'conflict';
  } | undefined;
  let failure: unknown, completed: DeliveryMergeCompletion | undefined, completedFrom: number | undefined;
  function itemRows(connection: SqliteConnection) {
    return connection.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq').all(runId);
  }
  function assertCut(connection: SqliteConnection, expected: Run, cut: Awaited<ReturnType<typeof readRecoveryClosure>>) {
    assertActiveStateOwner(connection, owner);
    if (!same(readRun(connection, runId), expected) || !same(readCheckpoint(connection, expected.latestCheckpointId), cut.latestCheckpoint) ||
        readInvocationJournal(connection, runId).length || itemRows(connection).length ||
        readWorkerLaunchesForRun(connection, runId).length || readWorkspaceGenerationsForRun(connection, runId).length ||
        connection.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(runId, runId) ||
        connection.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(runId))
      throw new KernelStorageError('REVISION_CONFLICT', 'delivery original immutable merge cut changed');
  }
  async function merge(expectedRunRevision: number, signal?: AbortSignal): Promise<DeliveryMergeCompletion> {
    signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
    if (spec.operation !== 'delivery') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'only a delivery Run can own a delivery merge');
    const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
    if (completed) {
      if (![completedFrom, completed.run.revision].includes(expectedRunRevision) || !same(readRun(driver, runId), completed.run))
        throw new KernelStorageError('REVISION_CONFLICT', 'delivery merge replay differs from its completed cut');
      await readRecoveryClosure(driver, reads, runId); return immutableSnapshot(completed);
    }
    if (failure && !isJoinedCasPublicationFailure(failure) && !isRolledBackSqliteTransactionFailure(driver, failure)) throw failure;
    if (!retained) {
      const cut = await readRecoveryClosure(driver, reads, runId), { run } = cut;
      if (run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'delivery merge revision changed');
      if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt)
        throw new TypeError('delivery merge no longer belongs to its loaded Run');
      if (run.status !== 'queued' || run.revision !== 1 || run.nextStep !== 'delivery' || !run.frontierRef || run.activeWorkerLaunchId ||
          run.waitingReason || run.waitingOnRef || run.stopIntentRef || run.cancelRequested || !isZeroBudget(run.budgetReserved) ||
          !isZeroBudget(run.budgetConsumed) || cut.items.length || cut.journal.length || cut.workspaceGenerations.length || cut.workerLaunches.length)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery merge requires its exact original worker-free admission cut');
      if (sampleCanonicalNow() >= run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'delivery merge requires its persisted deadline stop');
      const source = await readDeliveryMergeSource(driver, reads, runId, signal);
      const frontier: RunFrontier = { schemaVersion: 1, kind: 'delivery', phase: 'merge',
        sourceRunResultRef: source.admission.request.expectedRunResultRef, capturedWorkspaceRef: spec.baseWorkspaceManifestRef };
      if (!same(await readCanonicalArtifact(reads, run.frontierRef), frontier) || !same(source.admission.run, run))
        throw new TypeError('delivery merge substituted its original admitted source/capture frontier');
      assertCut(driver, run, cut);
      retained = { cut, source, metadata: [] };
    }
    const state = retained, { run } = state.cut;
    if (run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'delivery merge cannot replace its original plan');
    assertCut(driver, run, state.cut);
    if (sampleCanonicalNow() >= run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'delivery merge requires its persisted deadline stop');
    if (state.source.source.kind === 'limited') return { disposition: 'resource_limited', run: immutableSnapshot(run) };
    const sourceRunResultRef = state.source.admission.request.expectedRunResultRef;
    if (!state.graph) {
      let items: ContinuationItem[], frontier: RunFrontier, workspaceStateRef: string;
      const createdAt = sampleCanonicalNow();
      if (state.source.source.kind === 'ready') {
        const original = state.source.source;
        const inspection = state.source.admission.inspection;
        if (inspection.outcome.kind !== 'captured') throw new TypeError('delivery merge lost its original capture topology');
        state.prepared ??= await prepareDeliveryMergePlan(artifacts, original, { deliveryRunId: runId, sourceRunResultRef,
          captureTopologyRef: inspection.outcome.captureTopologyRef, sandboxProfileRef: spec.sandboxProfileRef,
          ...(state.source.admission.workspaceState.privateGitStateRef ? { privateGitStateRef: state.source.admission.workspaceState.privateGitStateRef } : {}) }, signal);
        state.metadata = state.prepared.metadata;
        const item: DeliveryMergeItem = { schemaVersion: 1, itemId: deliveryMergeItemId(runId, sourceRunResultRef, spec.baseWorkspaceManifestRef),
          runId, kind: 'delivery_merge', sourceRunResultRef, ...original.input, resultSourceRef: original.sourceRef, diffRef: original.diffRef,
          summaryRef: original.summaryRef, deliveryPlanRef: state.prepared.planRef, createdAt };
        const candidate: FinalCandidateItem = { schemaVersion: 1, kind: 'final_candidate', operation: 'delivery', runId,
          itemId: finalCandidateItemId(runId, item.itemId), producingItemId: item.itemId,
          baseSourceRef: spec.baseWorkspaceManifestRef, resultSourceRef: original.sourceRef, diffRef: original.diffRef,
          summaryRef: original.summaryRef, sourceDigest: original.source.manifestDigest, diffDigest: original.diff.diffDigest, createdAt };
        const { verifierPlan, dependency } = await readCandidateVerificationData(reads, spec, { runId,
          candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef });
        const verifier = planCanonicalArtifact(verifierPlan, 'cliq-verifier-plan-v1');
        frontier = { schemaVersion: 1, kind: 'verify', phase: dependency ? 'dependencies' : 'verifiers', candidateItemId: candidate.itemId,
          resultSourceRef: candidate.resultSourceRef, verifierPlanRef: verifier.ref, nextVerifierIndex: 0, afterPass: 'delivery_approval' };
        if (dependency) frontier.dependencyPlanRef = canonicalSha256(dependency.plan);
        state.checkpointId = finalCandidateCheckpointId(runId, item.itemId); state.itemId = item.itemId;
        state.disposition = 'candidate'; workspaceStateRef = state.prepared.workspaceStateRef; items = [item, candidate];
        state.graph = planContinuationCommit(artifacts, { context: decodeContextManifest(await readCanonicalArtifact(reads,
          state.cut.latestCheckpoint.contextManifestRef)), existingItems: [], items, frontier, checkpointId: state.checkpointId,
          workspaceStateRef, artifacts: [verifier, ...(dependency ? [planCanonicalArtifact(dependency.plan, dependency.plan.format)] : [])] });
      } else {
        const original = state.source.source, conflict = deliveryMergeConflictArtifact(runId, sourceRunResultRef, original);
        const payload = planCanonicalArtifact(conflict, conflict.format);
        const item: DeliveryMergeConflictItem = { schemaVersion: 1, itemId: deliveryMergeConflictItemId(runId, sourceRunResultRef, spec.baseWorkspaceManifestRef),
          runId, kind: 'delivery_merge_conflict', sourceRunResultRef, ...original.input, mergeAlgorithm: 'cliq-diff3-v1',
          conflictRef: payload.ref, createdAt };
        const stop = planCanonicalArtifact(deliveryMergeConflictStop(item, planCanonicalArtifact(item, 'cliq-delivery-merge-conflict-item-v1').ref), 'cliq-stop-intent-v1');
        frontier = { schemaVersion: 1, kind: 'delivery', phase: 'merge', sourceRunResultRef, capturedWorkspaceRef: spec.baseWorkspaceManifestRef };
        state.checkpointId = deliveryMergeConflictCheckpointId(runId, item.itemId); state.itemId = item.itemId;
        state.disposition = 'conflict'; state.conflictStopRef = stop.ref; workspaceStateRef = state.cut.latestCheckpoint.workspaceStateRef; items = [item];
        state.metadata = original.metadata;
        state.graph = planContinuationCommit(artifacts, { context: decodeContextManifest(await readCanonicalArtifact(reads,
          state.cut.latestCheckpoint.contextManifestRef)), existingItems: [], items, frontier, checkpointId: state.checkpointId,
          workspaceStateRef, artifacts: [payload, stop] });
      }
    }
    signal?.throwIfAborted(); state.graphMetadata ??= await state.graph.publish(); signal?.throwIfAborted();
    let outcome: TimeFenceAdvance | undefined, committed: DeliveryMergeCompletion | undefined;
    driver.transaction(connection => {
      signal?.throwIfAborted(); assertCut(connection, run, state.cut);
      const now = sampleCanonicalNow();
      if (now >= run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'delivery merge requires its persisted deadline stop');
      outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
      for (const metadata of [...state.metadata, ...state.graphMetadata!.metadata]) insertArtifactMetadata(connection, metadata, now);
      signal?.throwIfAborted(); assertCut(connection, run, state.cut);
      const committedAt = sampleCanonicalNow();
      if (committedAt >= run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'delivery merge deadline elapsed during artifact registration');
      outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
      if (outcome !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery merge canonical time fence changed during registration');
      state.graphMetadata!.commit(connection, run, 0, committedAt);
      connection.prepare('UPDATE runs SET stop_intent_ref=?,revision=revision+1,updated_at=? WHERE id=?')
        .run(state.conflictStopRef ?? null, committedAt, runId);
      const updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
      committed = { disposition: state.disposition!, run: updated, checkpointId: state.checkpointId!, itemId: state.itemId! };
    });
    requireHealthyFence(outcome);
    if (!committed) throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery merge did not commit under its canonical time fence');
    completedFrom = expectedRunRevision; completed = immutableSnapshot(committed); failure = undefined; return completed;
  }
  return { mergeDelivery: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }, signal?: AbortSignal) => {
    input = immutableSnapshot(input);
    if (!exactKeys(input, ['expectedRunRevision']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
      throw new TypeError('delivery merge requires one exact revision');
    if (pending) throw new KernelStorageError('REVISION_CONFLICT', 'delivery merge is already in flight');
    pending = merge(input.expectedRunRevision, signal);
    try { return await pending; }
    catch (error) {
      if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT') failure = error;
      throw error;
    } finally { pending = undefined; }
  }) };
}
