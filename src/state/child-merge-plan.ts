// Full CAS-only child merge input. This is neither a permission, a productive
// claim, a new physical generation nor evidence that a worker has been born.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ChildMergeBatchItem, ChildResultItem } from '../kernel/children.js';
import type { ContinuationItem, RunFrontier } from '../kernel/types.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildTerminalData } from './child-terminal.js';
import { decodeContextManifest, decodeWorkspaceState } from './decoders.js';
import { planChildMergeSource } from './delivery-source.js';
import { KernelStorageError } from './errors.js';
import { childAllocationBudgetFacts } from './invariants.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCandidateSource } from './result-source.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child merge ${message}`); }

export async function readChildMergePlan(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, options: { signal?: AbortSignal } = {}) {
  const reads = options.signal ? artifacts.withReadSignal(options.signal) : artifacts;
  const cut = await readRecoveryClosure(driver, reads, runId), { run } = cut;
  if (cut.runSpec.operation !== 'agent' || run.status !== 'queued' || run.nextStep !== 'tool' || !run.frontierRef ||
      run.cancelRequested || run.stopIntentRef || run.activeWorkerLaunchId || cut.workerLaunches.length)
    invalid('requires its original worker-free fully settled parent cut');
  requireEqual(run.budgetReserved, childAllocationBudgetFacts(runId, cut.childAllocations).reserved,
    'child merge retains exactly conservative outstanding child reservations');
  const last = new Map<string, typeof cut.journal[number]>();
  for (const row of cut.journal) last.set(`${row.opId}:${row.attempt}`, row);
  if ([...last.values()].some(row => !['completed', 'failed'].includes(row.phase)))
    invalid('cannot overtake the parent original unresolved invocation');
  const frontier = await readCanonicalArtifact<RunFrontier>(reads, run.frontierRef);
  if (frontier.kind !== 'tool') invalid('has no exact current merge cursor');
  const selected = await readRetainedChildMergePlan(driver, reads, runId, { mergeBatchItemId: frontier.batchItemId,
    callIndex: frontier.nextCallIndex, sourceCheckpointId: cut.latestCheckpoint.id, signal: options.signal });
  requireEqual(selected.run, run, 'current child merge full recovery cut');
  requireEqual(frontier.orderedCallIds, selected.batch.calls.map(call => call.callId), 'current child merge complete call cursor');
  if (selected.generations.some(generation => !['sealed', 'retired'].includes(generation.phase)) ||
      selected.workers.some(worker => worker.phase !== 'retired')) invalid('retains an original mutable worker/generation');
  return Object.freeze({ ...selected, frontier });
}

/** Original immutable SQL locators only. This does not call the parent's
 * whole recovery (which audits authorization), substitute today's A for an
 * original source, or authorize an effect. The enclosing request/subject/
 * Journal reader verifies the exact original locator registration. */
export async function readRetainedChildMergePlan(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string,
  input: { mergeBatchItemId: string; callIndex: number; sourceCheckpointId: string; signal?: AbortSignal }) {
  const reads = input.signal ? artifacts.withReadSignal(input.signal) : artifacts;
  reads.assertReadActive();
  const run = readRun(driver, runId), spec = (await import('./decoders.js')).decodeRunSpec(await readCanonicalArtifact(reads, run.specRef));
  if (spec.operation !== 'agent' || !Number.isSafeInteger(input.callIndex) || input.callIndex < 0)
    invalid('has no exact original parent/call source');
  const checkpoint = readCheckpoint(driver, input.sourceCheckpointId), currentCheckpoint = readCheckpoint(driver, run.latestCheckpointId);
  if (checkpoint.runId !== runId || checkpoint.createdAt < run.createdAt || checkpoint.createdAt > run.updatedAt)
    invalid('source Checkpoint is outside the original parent lifetime');
  const rows = driver.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string }>(runId);
  const items = await reads.mapReads(rows, async row => {
    const item = await readCanonicalArtifact<ContinuationItem>(reads, row.payload_ref);
    if (item.itemId !== row.item_id || item.kind !== row.kind || item.runId !== runId || item.createdAt !== row.created_at)
      invalid('item source differs from its actual SQL owner');
    return { itemSeq: Number(row.item_seq), itemRef: row.payload_ref, item };
  });
  const context = decodeContextManifest(await readCanonicalArtifact(reads, currentCheckpoint.contextManifestRef));
  validateContextItems(context, items);
  const sourceContext = decodeContextManifest(await readCanonicalArtifact(reads, checkpoint.contextManifestRef));
  validateContextItems(sourceContext, items.slice(0, checkpoint.runItemSeq));
  const batchRow = items.find(row => row.item.itemId === input.mergeBatchItemId), batch = batchRow?.item;
  if (batch?.kind !== 'child_merge_batch' || !batchRow || batchRow.itemSeq > checkpoint.runItemSeq ||
      !exactKeys(batch, ['schemaVersion', 'kind', 'itemId', 'runId', 'resume', 'childResultItemIds', 'calls', 'createdAt']) ||
      batch.schemaVersion !== 1 || batch.runId !== runId || batch.createdAt > checkpoint.createdAt)
    invalid('changed its complete original synthetic audit batch');
  const call = batch.calls[input.callIndex];
  if (!call || call.index !== input.callIndex) invalid('has no current bounded merge call');
  const resultItem = items.find(row => row.item.kind === 'child_result' && row.item.childRunId === call.childRunId)?.item;
  if (resultItem?.kind !== 'child_result' || resultItem.mode !== 'mutating' ||
      !['succeeded', 'completed_unverified'].includes(resultItem.status) || !('patchManifestRef' in resultItem) ||
      resultItem.patchManifestRef !== call.patchManifestRef || !batch.childResultItemIds.includes(resultItem.itemId)) invalid('has no successful owned patch result');
  const child = await readChildTerminalData(driver, reads, call.childRunId, { signal: input.signal });
  if (child.run.parentRunId !== runId || !child.result || !child.patch || child.allocation.state !== 'settled' ||
      child.allocation.childResultItemId !== resultItem.itemId || child.spec.baseWorkspaceManifestRef !== call.admittedForkBaseRef ||
      canonicalSha256(child.patch) !== call.patchManifestRef) invalid('changed its complete original child terminal patch source');
  const journal = readInvocationJournal(driver, runId), allocations = readChildAllocationsForRun(driver, runId), generations = readWorkspaceGenerationsForRun(driver, runId), workers = readWorkerLaunchesForRun(driver, runId);
  const current = await readCandidateSource(reads, spec, checkpoint.workspaceStateRef, input.signal);
  const computation = await planChildMergeSource(reads, { sourceBaseRef: call.admittedForkBaseRef,
    sourceDesiredRef: child.result.resultSourceRef, capturedWorkspaceRef: current.sourceRef, sandboxProfileRef: spec.sandboxProfileRef, capturedSource: current.source }, { signal: input.signal });
  const workspace = decodeWorkspaceState(await readCanonicalArtifact(reads, checkpoint.workspaceStateRef));
  const workspacePlan = computation.kind === 'ready' ? (() => {
    const merged = { ...workspace, entriesRef: computation.source.entriesRef, stateDigest: '' };
    merged.stateDigest = digestOmitting(merged, 'stateDigest'); return planCanonicalArtifact(merged, merged.format);
  })() : undefined;
  const changedPaths = child.patch.operations.map(operation => operation.path);
  const capturedPlan = planCanonicalArtifact(current.source, current.source.format);
  const plans: readonly PlannedArtifact[] = Object.freeze([capturedPlan, ...(computation.kind === 'ready' ? computation.publications : []),
    ...(workspacePlan ? [workspacePlan] : [])]);
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(reads, spec.assemblyRef));
  const itemRows = (connection: SqliteConnection) => connection.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: unknown; kind: string; payload_ref: string; created_at: string }>(runId)
    .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
  const originalRows = itemRows(driver);
  const assertUnchanged = (connection: SqliteConnection) => {
    requireEqual(readRun(connection, runId), run, 'child merge selected parent Run');
    requireEqual(readCheckpoint(connection, checkpoint.id), checkpoint, 'child merge original ready Checkpoint');
    requireEqual(readCheckpoint(connection, currentCheckpoint.id), currentCheckpoint, 'child merge current ready Checkpoint');
    requireEqual(readInvocationJournal(connection, runId), journal, 'child merge original Journal');
    requireEqual(readChildAllocationsForRun(connection, runId), allocations, 'child merge original inclusive allocation cut');
    requireEqual(readWorkspaceGenerationsForRun(connection, runId), generations, 'child merge original sealed generations');
    requireEqual(readWorkerLaunchesForRun(connection, runId), workers, 'child merge original retired workers');
    requireEqual(itemRows(connection), originalRows, 'child merge original complete audit prefix');
    child.assertUnchanged(connection);
  };
  assertUnchanged(driver); reads.assertReadActive();
  return Object.freeze({ run, spec, assembly, checkpoint, context, items, journal, currentCheckpoint, sourceContext, generations, workers,
    batch: batch as ChildMergeBatchItem, call, child, resultItem: resultItem as ChildResultItem,
    sourceBaseRef: call.admittedForkBaseRef, sourceDesiredRef: child.result.resultSourceRef, capturedWorkspaceRef: current.sourceRef,
    changedPaths: Object.freeze(changedPaths), computation, workspacePlan, plans, assertUnchanged });
}
export type ChildMergePlan = Awaited<ReturnType<typeof readChildMergePlan>>;
export type RetainedChildMergePlan = Awaited<ReturnType<typeof readRetainedChildMergePlan>>;
