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
import { decodeAgentStop, selectAgentStop, type AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact, readModelTurnMaterial } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { planContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { finalCandidateCheckpointId, finalCandidateItemId, readCandidateVerificationData } from './final-candidate-plan.js';
import { isZeroBudget } from './invariants.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal, readHighestPreparedAttempt } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun } from './rows.js';
import { CandidateSourceLimitError, prepareCandidateSource } from './result-source.js';
import { isRolledBackSqliteTransactionFailure, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from './tool-checkpoint.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';

export type FinalCandidateCompletion =
  | { disposition: 'candidate'; run: Run; candidateItemId: string; checkpointId: string }
  | { disposition: 'stopped'; run: Run; checkpointId: string };
export type FinalCandidateOwner = Readonly<{ checkpointId: string;
  complete(input: { expectedRunRevision: number; checkpoint: ToolCheckpointProof }): Promise<FinalCandidateCompletion> }>;

class CandidateDeadlineReached extends KernelStorageError {
  constructor() { super('LEASE_FENCED', 'candidate requires its persisted deadline stop'); }
}

/** Established before quiescence: one original model, physical seal and
 * immutable publication graph, never a claim or a second recovery lifecycle. */
export function loadFinalCandidate(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, authority: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; resolveToolInput: ResolveToolInput;
  expireRun(input: { expectedRunRevision: number }): Promise<{ run: Run }>;
  stopForResourceFailure(input: { expectedRunRevision: number }): Promise<{ run: Run }>;
}, reobserve?: NativeWorkerRetirement) {
  const { run: admitted, spec, assembly, resolveToolInput } = authority, runId = admitted.id;
  let beginning: Promise<FinalCandidateOwner> | undefined, retained: FinalCandidateOwner | undefined;
  const itemRows = (connection: SqliteConnection) => connection.prepare(
    'SELECT item_id, item_seq, kind, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
  function rejectChildren(connection: SqliteConnection) {
    if (spec.operation !== 'agent' ||
        connection.prepare("SELECT 1 FROM child_allocations WHERE parent_run_id = ? AND state != 'settled' LIMIT 1").get(runId))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires child finalize settlement');
  }
  async function begin(expectedRunRevision: number, signal?: AbortSignal): Promise<FinalCandidateOwner> {
    const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
    reads.assertReadActive();
    assertActiveStateOwner(driver, owner);
    const selected = await readRecoveryClosure(driver, reads, runId), { run } = selected;
    const launches = readWorkerLaunchesForRun(driver, runId), generations = readWorkspaceGenerationsForRun(driver, runId), originalItems = itemRows(driver);
    if (run.revision !== expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'candidate Run revision changed');
    if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt)
      throw new TypeError('candidate authority no longer belongs to this Run');
    rejectChildren(driver);
    if (run.status !== 'running' || run.nextStep !== 'agent' || !run.frontierRef || !run.activeWorkerLaunchId ||
        run.waitingReason || run.waitingOnRef || run.stopIntentRef || run.cancelRequested || !isZeroBudget(run.budgetReserved) ||
        selected.workerLaunches.length !== 1 || selected.workerLaunches[0]!.launchId !== run.activeWorkerLaunchId)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires the exact unstopped final model cut');
    if (sampleCanonicalNow() >= run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'candidate Run deadline has elapsed');
    const launch = selected.workerLaunches[0]!;
    const generation = generations.find(row => row.generationRef === launch.workspaceGenerationRef);
    if (launch.phase !== 'activated' || launch.generationWriteState !== 'active' || !generation || generation.phase !== 'active' ||
        generation.activeWorkerLaunchId !== launch.launchId || generation.leaseEpoch !== run.leaseEpoch)
      throw new KernelStorageError('LEASE_FENCED', 'candidate must begin before its original worker quiesces');
    const frontier = await readCanonicalArtifact<RunFrontier>(reads, run.frontierRef);
    if (frontier.kind !== 'agent' || frontier.phase !== 'model_turn' || frontier.compactionPlanRef !== undefined)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires a normal final model frontier');
    const opId = modelOperationId(runId, frontier), prepared = readHighestPreparedAttempt(driver, runId, opId);
    const completion = prepared && selected.journal.find(entry => entry.opId === opId && entry.attempt === prepared.attempt && entry.phase === 'completed');
    const lastByOperation = new Map(selected.journal.map(entry => [`${entry.opId}\0${entry.attempt}`, entry]));
    if (!prepared || prepared.opKind !== 'model' || !completion?.resultRef ||
        [...lastByOperation.values()].some(entry => entry.phase !== 'completed' && entry.phase !== 'failed'))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate requires settled invocations and the highest completed model attempt');
    const request = await readCanonicalArtifact<ModelRequestV1>(reads, prepared.requestRef);
    const material = await readModelTurnMaterial(reads, completion.resultRef);
    validateModelTurn(request, material, resolveToolInput);
    const producerId = identityHash('cliq-model-turn-item-v1', runId, opId, String(prepared.attempt));
    const producerRow = selected.items.at(-1), producer = producerRow && await readCanonicalArtifact<ContinuationItem>(reads, producerRow.payloadRef);
    if (request.kind !== 'normal' || request.opId !== opId || request.attempt !== prepared.attempt || request.runId !== runId ||
        material.turn.stopReason !== 'end' || material.turn.toolCalls.length || !material.text.utf8.trim() ||
        producer?.kind !== 'model_turn' || producer.itemId !== producerId || producer.modelOpId !== opId ||
        producer.modelAttempt !== prepared.attempt || producer.modelTurnRef !== completion.resultRef || producer.stopReason !== 'end' ||
        producer.textRef !== material.turn.textRef)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'candidate has no exact final producer and summary');
    const checkpointId = finalCandidateCheckpointId(runId, producerId);
    const same = (left: unknown, right: unknown) => canonicalSha256(left) === canonicalSha256(right);
    function unchangedData(connection: SqliteConnection) {
      assertActiveStateOwner(connection, owner); rejectChildren(connection);
      if (!same(readCheckpoint(connection, run.latestCheckpointId), selected.latestCheckpoint) ||
          !same(readInvocationJournal(connection, runId), selected.journal) || !same(itemRows(connection), originalItems))
        throw new KernelStorageError('REVISION_CONFLICT', 'candidate original producer or ready cut changed');
    }
    unchangedData(driver);
    if (!same(readRun(driver, runId), run) || !same(readWorkerLaunchesForRun(driver, runId), launches) ||
        !same(readWorkspaceGenerationsForRun(driver, runId), generations))
      throw new KernelStorageError('REVISION_CONFLICT', 'candidate original cut changed while beginning');

    let proofInput: ToolCheckpointProof | undefined, seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
    let sealedLaunches: typeof launches | undefined, sealedGenerations: typeof generations | undefined;
    let source: Awaited<ReturnType<typeof prepareCandidateSource>> | undefined;
    let graph: ReturnType<typeof planContinuationCommit> | undefined;
    let graphMetadata: Awaited<ReturnType<ReturnType<typeof planContinuationCommit>['publish']>> | undefined;
    let candidate: FinalCandidateItem | undefined, checkedRun = run, checkedStop: AgentStopIntent | undefined;
    let failure: unknown, completed: FinalCandidateCompletion | undefined, completedFrom: number | undefined, refreshed = false;
    let completing: Promise<FinalCandidateCompletion> | undefined;
    let completingInput: { expectedRunRevision: number; checkpoint: ToolCheckpointProof } | undefined;
    const stable = ({ revision: _revision, updatedAt: _time, stopIntentRef: _intent, cancelRequested: _cancel, parentCancellationRef: _parentCancellation, ...value }: Run) => value;
    function originalRun(current: Run) {
      if (!same(stable(current), stable(run)) || current.revision < run.revision || current.updatedAt < run.updatedAt ||
          !same(current, run) && (!current.stopIntentRef || current.revision <= run.revision))
        throw new KernelStorageError('REVISION_CONFLICT', 'candidate original Run cut changed');
    }
    function physicalCut(connection: SqliteConnection) {
      const currentLaunches = readWorkerLaunchesForRun(connection, runId), currentGenerations = readWorkspaceGenerationsForRun(connection, runId);
      if (sealedLaunches && sealedGenerations) {
        if (!same(currentLaunches, sealedLaunches) || !same(currentGenerations, sealedGenerations))
          throw new KernelStorageError('REVISION_CONFLICT', 'candidate prepared seal cut changed');
        return;
      }
      const currentLaunch = currentLaunches.find(row => row.launchId === launch.launchId);
      const currentGeneration = currentGenerations.find(row => row.generationRef === generation!.generationRef);
      if (!currentLaunch || !currentGeneration || currentLaunch.phase !== 'activated' || !currentLaunch.quiesceId ||
          currentGeneration.phase !== 'checkpointing' || currentGeneration.updatedAt < generation!.updatedAt ||
          currentGeneration.quiesceId !== currentLaunch.quiesceId ||
          !same(currentLaunches, launches.map(row => row.launchId === launch.launchId ?
            { ...launch, generationWriteState: 'checkpointing', quiesceId: currentLaunch.quiesceId } : row)) ||
          !same(currentGenerations, generations.map(row => row.generationRef === generation!.generationRef ?
            { ...generation, phase: 'checkpointing', rowVersion: generation!.rowVersion + 2,
              quiesceId: currentLaunch.quiesceId, updatedAt: currentGeneration.updatedAt } : row)))
        throw new KernelStorageError('REVISION_CONFLICT', 'candidate did not follow its original two quiescence transitions');
    }
    async function checkCut(expected: number) {
      const current = readRun(driver, runId);
      if (current.revision !== expected) throw new KernelStorageError('REVISION_CONFLICT', 'candidate completion revision changed');
      originalRun(current); unchangedData(driver); physicalCut(driver);
      if (!same(current, checkedRun)) {
        const next = await readRecoveryClosure(driver, artifacts, runId);
        originalRun(next.run); unchangedData(driver); physicalCut(driver);
        if (next.run.revision !== expected || !same(readRun(driver, runId), next.run) || next.run.updatedAt < checkedRun.updatedAt ||
            checkedRun.cancelRequested && !next.run.cancelRequested || !next.run.stopIntentRef)
          throw new KernelStorageError('REVISION_CONFLICT', 'candidate StopIntent cut changed during validation');
        const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, next.run.stopIntentRef), next.run);
        if (next.run.stopIntentRef !== checkedRun.stopIntentRef &&
            (selectAgentStop(checkedStop, stop) !== stop || checkedStop && stop.createdAt < checkedStop.createdAt))
          throw new KernelStorageError('REVISION_CONFLICT', 'candidate StopIntent is not a monotonic upgrade');
        if (!same(readRun(driver, runId), next.run)) throw new KernelStorageError('REVISION_CONFLICT', 'candidate StopIntent changed while decoding');
        checkedRun = next.run; checkedStop = stop; refreshed = false;
      }
      return checkedRun;
    }
    const complete = stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; checkpoint: ToolCheckpointProof }): Promise<FinalCandidateCompletion> => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'checkpoint']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1 ||
          !input.checkpoint || !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']))
        throw new TypeError('invalid final candidate completion');
      if (proofInput && !same(proofInput, input.checkpoint)) throw new KernelStorageError('REVISION_CONFLICT', 'candidate owner cannot substitute its original checkpoint proof');
      assertActiveStateOwner(driver, owner);
      if (completed) {
        if (![completedFrom, completed.run.revision].includes(input.expectedRunRevision) || !same(readRun(driver, runId), completed.run))
          throw new KernelStorageError('REVISION_CONFLICT', 'candidate replay differs from its completed cut');
        await readRecoveryClosure(driver, artifacts, runId);
        return immutableSnapshot(completed);
      }
      if (completing) {
        if (same(completingInput, input)) return completing;
        throw new KernelStorageError('REVISION_CONFLICT', 'candidate completion is already in flight with different input');
      }
      const operation = (async () => {
        let expected = input.expectedRunRevision, current: Run;
        try { current = await checkCut(expected); }
        catch (error) {
          if (!(error instanceof KernelStorageError) || error.code !== 'REVISION_CONFLICT') failure = error;
          throw error;
        }
        if (failure && !isJoinedCasPublicationFailure(failure) && !isRolledBackSqliteTransactionFailure(driver, failure)) throw failure;
        const retryCommit = failure !== undefined && isRolledBackSqliteTransactionFailure(driver, failure);
        if (current.stopIntentRef && input.checkpoint.workspaceStateRef !== selected.latestCheckpoint.workspaceStateRef)
          throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stopped candidate cannot adopt an unaccounted workspace');
        const work = (async () => {
          for (;;) {
            try {
              current = await checkCut(expected);
              if (!current.stopIntentRef && sampleCanonicalNow() >= current.deadlineAt) {
                current = (await authority.expireRun({ expectedRunRevision: expected })).run;
                expected = current.revision;
                current = await checkCut(expected);
              }
              if (!seal) {
                seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: current, spec, assembly, checkpointId,
                  observedAt: completion.timestamp, postEffect: input.checkpoint }, reobserve);
                proofInput = input.checkpoint;
                // Reject any drift during immutable proof reads before fixing the
                // exact checkpointing cut retained by every later attempt.
                physicalCut(driver);
                sealedLaunches = readWorkerLaunchesForRun(driver, runId); sealedGenerations = readWorkspaceGenerationsForRun(driver, runId);
              }
              let latest = await checkCut(expected);
              if (!latest.stopIntentRef) {
                try { source ??= await prepareCandidateSource(artifacts, spec, input.checkpoint.workspaceStateRef); }
                catch (error) {
                  // The exception requests a fresh authoritative derivation; none
                  // of its fields are evidence. Never seal an unaccounted tree.
                  if (!(error instanceof CandidateSourceLimitError) || input.checkpoint.workspaceStateRef !== selected.latestCheckpoint.workspaceStateRef) throw error;
                  const stopped = await authority.stopForResourceFailure({ expectedRunRevision: expected });
                  expected = stopped.run.revision;
                  continue;
                }
                await source.publish();
                if (!candidate) {
                  const createdAt = sampleCanonicalNow();
                  candidate = { schemaVersion: 1, kind: 'final_candidate', operation: 'agent', runId,
                    itemId: finalCandidateItemId(runId, producerId), producingItemId: producerId, producingOpId: opId,
                    baseSourceRef: spec.baseWorkspaceManifestRef, resultSourceRef: source.graph.sourceRef, diffRef: source.graph.diffRef,
                    summaryRef: producer.textRef, sourceDigest: source.graph.source.manifestDigest, diffDigest: source.graph.diff.diffDigest, createdAt };
                  const { verifierPlan, dependency } = await readCandidateVerificationData(artifacts, spec, { runId,
                    candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef });
                  const plan = planCanonicalArtifact(verifierPlan, 'cliq-verifier-plan-v1');
                  const nextFrontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: dependency ? 'dependencies' : 'verifiers', candidateItemId: candidate.itemId,
                    resultSourceRef: candidate.resultSourceRef, verifierPlanRef: plan.ref, nextVerifierIndex: 0, afterPass: 'finalize' };
                  if (dependency) nextFrontier.dependencyPlanRef = canonicalSha256(dependency.plan);
                  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, selected.latestCheckpoint.contextManifestRef));
                  const existingItems = await artifacts.mapReads(selected.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
                    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
                  graph = planContinuationCommit(artifacts, { context, existingItems, items: [candidate], frontier: nextFrontier,
                    checkpointId, workspaceStateRef: input.checkpoint.workspaceStateRef, artifacts: [plan,
                      ...(dependency ? [planCanonicalArtifact(dependency.plan, dependency.plan.format)] : [])] });
                }
                graphMetadata ??= await graph!.publish();
              }
              latest = await checkCut(expected);
              if (latest.stopIntentRef && input.checkpoint.workspaceStateRef !== selected.latestCheckpoint.workspaceStateRef)
                throw new KernelStorageError('STATE_TRANSITION_INVALID', 'stopped candidate cannot adopt an unaccounted workspace');
              if (!refreshed || retryCommit) {
                // Retain the same attempt counter and any unfinished D1 bytes if
                // this small publication fails after an earlier accepted D1.
                refreshed = false; await seal.refresh(); refreshed = true;
              }
              let outcome: TimeFenceAdvance | undefined, result: FinalCandidateCompletion | undefined;
              driver.transaction(connection => {
                unchangedData(connection); physicalCut(connection);
                const actual = readRun(connection, runId);
                if (!same(actual, checkedRun)) throw new KernelStorageError('REVISION_CONFLICT', 'candidate exact checked StopIntent cut changed');
                const stopped = actual.stopIntentRef !== undefined, now = sampleCanonicalNow();
                if (!stopped && now >= actual.deadlineAt) throw new CandidateDeadlineReached();
                if (now < actual.updatedAt || !stopped && (!candidate || now < candidate.createdAt))
                  throw new KernelStorageError('LEASE_FENCED', 'candidate is outside its healthy lifetime');
                outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
                for (const metadata of [...(stopped ? [] : [...source!.graph.metadata, ...graphMetadata!.metadata]), ...seal!.metadata])
                  insertArtifactMetadata(connection, metadata, now);
                const committedAt = sampleCanonicalNow();
                if (!stopped && committedAt >= actual.deadlineAt) throw new CandidateDeadlineReached();
                if (committedAt < now)
                  throw new KernelStorageError('LEASE_FENCED', 'candidate lifetime changed during artifact registration');
                outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt);
                if (outcome !== 'healthy') throw new KernelStorageError('RECOVERY_REQUIRED', 'candidate clock changed during registration');
                seal!.commit(connection, actual, committedAt);
                if (stopped) connection.prepare(`INSERT INTO checkpoints (id, schema_version, run_id, based_on_run_revision, run_item_seq,
                  context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'auto')`)
                  .run(checkpointId, runId, BigInt(actual.revision), BigInt(selected.items.length), selected.latestCheckpoint.contextManifestRef,
                    BigInt(selected.journal.length), input.checkpoint.workspaceStateRef, committedAt);
                else graphMetadata!.commit(connection, actual, selected.journal.length, committedAt);
                connection.prepare('UPDATE runs SET latest_checkpoint_id = ?, revision = revision + 1, updated_at = ? WHERE id = ?')
                  .run(checkpointId, committedAt, runId);
                const updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
                result = stopped ? { disposition: 'stopped', run: updated, checkpointId } :
                  { disposition: 'candidate', run: updated, checkpointId, candidateItemId: candidate!.itemId };
              });
              requireHealthyFence(outcome);
              if (!result) throw new KernelStorageError('RECOVERY_REQUIRED', 'candidate did not commit under the canonical time fence');
              completedFrom = input.expectedRunRevision; completed = immutableSnapshot(result); failure = undefined;
              return completed;
            } catch (error) {
              if (error instanceof CandidateDeadlineReached) {
                refreshed = false;
                expected = readRun(driver, runId).revision;
                continue;
              }
              // Only the original owner may verify a Stop-only conflict or persist
              // the now-required deadline StopIntent without replacing its seal.
              if (error instanceof KernelStorageError && error.code === 'REVISION_CONFLICT' && readRun(driver, runId).stopIntentRef &&
                  readRun(driver, runId).revision > expected) {
                try { originalRun(readRun(driver, runId)); unchangedData(driver); physicalCut(driver); }
                catch { failure = error; throw error; }
              } else failure = error;
              throw error;
            }
          }
        })();
        return await work;
      })();
      completing = operation; completingInput = input;
      try { return await operation; } finally { completing = undefined; completingInput = undefined; }
    });
    const candidateOwner: FinalCandidateOwner = Object.freeze({ checkpointId,
      async complete(input: { expectedRunRevision: number; checkpoint: ToolCheckpointProof }) {
        const result = await complete(input);
        // Only this producer's genuinely completed transaction releases its
        // slot. Failures retain it, and an old replay cannot clear a new owner.
        if (retained === candidateOwner) retained = undefined;
        return result;
      } });
    return candidateOwner;
  }
  return { beginFinalCandidate: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }, readSignal?: AbortSignal) => {
    input = immutableSnapshot(input);
    if (!exactKeys(input, ['expectedRunRevision']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
      throw new TypeError('candidate beginning requires one exact revision');
    if (retained || beginning) throw new KernelStorageError('REVISION_CONFLICT', 'this agent already retains its final-turn owner');
    beginning = begin(input.expectedRunRevision, readSignal);
    try { return retained = await beginning; } finally { beginning = undefined; }
  }) };
}
