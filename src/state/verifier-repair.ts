import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ContinuationItem, Run, RunFrontier, RunSpec } from '../kernel/types.js';
import type { RepairDiagnosticItem, VerifierRepairDiagnosticV1 } from '../kernel/verifier.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { decodeContextManifest } from './decoders.js';
import { KernelStorageError, stateOperation } from './errors.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { addBudget, assertBudgetWithin, isZeroBudget } from './invariants.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { decodeRepairDiagnosticItem, decodeVerifierRepairDiagnostic, verifierRepairModelContent } from './verifier-artifacts.js';
import { readVerifierProgress, type VerifierProgress } from './verifier-recovery.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';

/** Pure, deterministic audit-to-model projection. This graph is data, never
 * execution or repair authority; the producer and history reader bind the
 * complete original Journal, native retirement and candidate independently. */
export function planVerifierRepair(progress: VerifierProgress, input: { runId: string; repairOrdinal: number; createdAt: string }) {
  parseCanonicalTime(input.createdAt);
  if (!Number.isSafeInteger(input.repairOrdinal) || input.repairOrdinal < 1 || input.repairOrdinal > 5)
    throw new TypeError('repair ordinal is outside the fixed bound');
  const failures = progress.entries.filter(entry => entry.planEntry.required && entry.receipt?.outcome === 'assertion_failed');
  if (!failures.length) throw new TypeError('repair requires a current required assertion failure');
  const plans: PlannedArtifact[] = [], diagnostics: RepairDiagnosticItem['diagnostics'] = [], ids: string[] = [];
  for (const entry of failures) {
    const receipt = entry.receipt!, result = entry.resultItem, terminal = entry.terminalJournal;
    if (!result || !terminal || terminal.phase !== 'completed' || result.outcome !== 'assertion_failed' ||
        result.receiptRef !== canonicalSha256(receipt) || terminal.receiptRef !== result.receiptRef ||
        receipt.runId !== input.runId || entry.specEntry.id !== receipt.verifierId)
      throw new TypeError('repair assertion lacks its exact owned result and receipt');
    const content = verifierRepairModelContent(receipt), contentPlan = planCanonicalArtifact(content, content.format);
    const diagnostic: VerifierRepairDiagnosticV1 = { schemaVersion: 1, format: 'cliq-verifier-repair-diagnostic-v1',
      runId: input.runId, candidateItemId: progress.candidate.itemId, verifierPlanRef: progress.planRef, verifierId: receipt.verifierId,
      receiptRef: result.receiptRef, receiptDigest: receipt.receiptDigest, stdoutRef: receipt.stdoutRef, stderrRef: receipt.stderrRef,
      redactionAlgorithm: 'cliq-verifier-repair-redaction-v1', modelContentRef: contentPlan.ref,
      modelContentDigest: content.contentDigest, diagnosticDigest: '' };
    diagnostic.diagnosticDigest = digestOmitting(diagnostic, 'diagnosticDigest');
    decodeVerifierRepairDiagnostic(diagnostic);
    const diagnosticPlan = planCanonicalArtifact(diagnostic, diagnostic.format);
    plans.push(contentPlan, diagnosticPlan); ids.push(result.itemId);
    diagnostics.push({ verifierId: receipt.verifierId, diagnosticRef: diagnosticPlan.ref, diagnosticDigest: diagnostic.diagnosticDigest,
      modelContentRef: contentPlan.ref, modelContentDigest: content.contentDigest });
  }
  const item: RepairDiagnosticItem = { schemaVersion: 1, kind: 'repair_diagnostic',
    itemId: identityHash('cliq-verifier-repair-item-v1', input.runId, progress.candidate.itemId, String(input.repairOrdinal)), runId: input.runId,
    candidateItemId: progress.candidate.itemId, verifierPlanRef: progress.planRef, failedVerifierResultItemIds: ids,
    diagnostics, repairOrdinal: input.repairOrdinal, createdAt: input.createdAt };
  decodeRepairDiagnosticItem(item);
  return { item, plans,
    checkpointId: identityHash('cliq-verifier-repair-checkpoint-v1', input.runId, progress.candidate.itemId, String(input.repairOrdinal)),
    frontier: { schemaVersion: 1 as const, kind: 'agent' as const, phase: 'model_turn' as const,
      turnId: identityHash('cliq-verifier-repair-turn-v1', input.runId, progress.candidate.itemId, String(input.repairOrdinal)), cause: 'repair' as const } };
}

const REPAIR_BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 1 });

/** The sole repair authorization transaction. No caller supplies diagnostics,
 * receipts, counters, a frontier or permission to execute the next model. */
export function loadVerifierRepair(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: { run: Run; spec: RunSpec }) {
  const { run: admitted, spec } = authority, runId = admitted.id;
  return {
    authorizeVerifierRepair: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision']) || !Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1)
        throw new TypeError('repair requires one exact expected revision');
      assertActiveStateOwner(driver, owner);
      const cut = await readRecoveryClosure(driver, artifacts, runId), { run } = cut;
      if (run.specRef !== admitted.specRef || run.createdAt !== admitted.createdAt || run.deadlineAt !== admitted.deadlineAt ||
          canonicalSha256(cut.runSpec) !== canonicalSha256(spec)) throw new TypeError('repair belongs to another Run authority');
      if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'repair revision changed');
      if (run.status !== 'queued' || run.nextStep !== 'verify' || !run.frontierRef || run.activeWorkerLaunchId || run.waitingReason ||
          run.waitingOnRef || run.cancelRequested || run.stopIntentRef || run.parentRunId || run.resultRef || run.terminalReason ||
          !isZeroBudget(run.budgetReserved) || spec.operation !== 'agent' || spec.dependencyPolicyRef !== undefined)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'repair requires its unstopped lease-free root verifier frontier');
      const progress = await readVerifierProgress(driver, artifacts, cut);
      const frontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: 'verifiers', candidateItemId: progress.candidate.itemId,
        resultSourceRef: progress.candidate.resultSourceRef, verifierPlanRef: progress.planRef,
        nextVerifierIndex: progress.nextVerifierIndex, afterPass: 'finalize' };
      requireEqual(await readCanonicalArtifact(artifacts, run.frontierRef), frontier, 'repair exact original verifier frontier');
      const existingItems = await artifacts.mapReads(cut.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
        item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
      const latest = new Map<string, (typeof cut.journal)[number]>();
      for (const entry of cut.journal) latest.set(`${entry.opId}\0${entry.attempt}`, entry);
      if ([...latest.values()].some(entry => !['completed', 'failed'].includes(entry.phase)) ||
          progress.entries.some(entry => entry.receipt?.outcome === 'source_mutation') ||
          existingItems.some(row => row.itemSeq > cut.items.find(value => value.itemId === progress.candidate.itemId)!.itemSeq && row.item.kind === 'repair_diagnostic'))
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'repair retains an unsettled, integrity-failed or already repaired candidate');
      if (run.repairCount !== run.budgetConsumed.repairAttempts || run.repairCount >= spec.budgets.repairAttempts)
        throw new KernelStorageError('BUDGET_EXHAUSTED', 'repair has no remaining frozen allowance');
      assertBudgetWithin(run.budgetConsumed, run.budgetReserved, REPAIR_BUDGET, spec.budgets);
      assertRetiredGenerationCut(driver, run, cut.workspaceGenerations);
      const createdAt = sampleCanonicalNow(), plan = planVerifierRepair(progress, { runId, repairOrdinal: run.repairCount + 1, createdAt });
      const context = decodeContextManifest(await readCanonicalArtifact(artifacts, cut.latestCheckpoint.contextManifestRef));
      const graph = await prepareContinuationCommit(artifacts, { context, existingItems, items: [plan.item],
        frontier: { ...plan.frontier, contextItemSeq: context.throughItemSeq + 1 }, checkpointId: plan.checkpointId,
        workspaceStateRef: cut.latestCheckpoint.workspaceStateRef, artifacts: plan.plans });
      const itemRows = (connection: SqliteConnection | SqliteDriver) => connection.prepare(
        'SELECT item_id, item_seq, payload_ref, created_at FROM items WHERE run_id = ? ORDER BY item_seq')
        .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(runId)
        .map(row => ({ itemId: row.item_id, itemSeq: Number(row.item_seq), payloadRef: row.payload_ref, createdAt: row.created_at }));
      const beforeItems = cut.items.map(({ itemId, itemSeq, payloadRef, createdAt }) => ({ itemId, itemSeq, payloadRef, createdAt }));
      const launches = readWorkerLaunchesForRun(driver, runId);
      let outcome: TimeFenceAdvance | undefined, updated: Run | undefined;
      driver.transaction(connection => {
        assertActiveStateOwner(connection, owner);
        if (canonicalSha256(readRun(connection, runId)) !== canonicalSha256(run) ||
            canonicalSha256(readCheckpoint(connection, run.latestCheckpointId)) !== canonicalSha256(cut.latestCheckpoint) ||
            canonicalSha256(readInvocationJournal(connection, runId)) !== canonicalSha256(cut.journal) ||
            canonicalSha256(itemRows(connection)) !== canonicalSha256(beforeItems) ||
            canonicalSha256(readWorkerLaunchesForRun(connection, runId)) !== canonicalSha256(launches) ||
            canonicalSha256(readWorkspaceGenerationsForRun(connection, runId)) !== canonicalSha256(cut.workspaceGenerations))
          throw new KernelStorageError('REVISION_CONFLICT', 'repair original candidate, retirement or Journal cut changed');
        assertRetiredGenerationCut(connection, run, cut.workspaceGenerations);
        const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
        if (outcome !== 'healthy') return;
        if (createdAt < run.updatedAt || now < createdAt || now >= run.deadlineAt)
          throw new KernelStorageError('LEASE_FENCED', 'repair is outside its immutable healthy Run lifetime');
        assertBudgetWithin(run.budgetConsumed, run.budgetReserved, REPAIR_BUDGET, spec.budgets);
        for (const metadata of graph.metadata) insertArtifactMetadata(connection, metadata, now);
        graph.commit(connection, run, cut.journal.length, now);
        connection.prepare('UPDATE runs SET repair_count = repair_count + 1, budget_consumed_json = ?, revision = revision + 1, updated_at = ? WHERE id = ?')
          .run(JSON.stringify(addBudget(run.budgetConsumed, REPAIR_BUDGET)), now, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(outcome);
      if (!updated) throw new KernelStorageError('RECOVERY_REQUIRED', 'repair authorization did not commit');
      return immutableSnapshot({ run: updated, item: plan.item, checkpointId: plan.checkpointId });
    })
  };
}
