import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDeliveryMergeItem, type DeliveryMergeConflictItem, type DeliveryMergeItem } from '../kernel/delivery.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, FinalCandidateItem, InvocationJournalEntry, RecoveryClosureV1,
  Run, RunItemReferenceV1, RunSpec, WorkspaceStateManifest } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest, decodeWorkspaceState } from './decoders.js';
import { planDeliverySource, type DeliverySourcePlan } from './delivery-source.js';
import { finalCandidateCheckpointId, finalCandidateItemId } from './final-candidate-plan.js';
import { planDeliveryPublication } from './publication-plan.js';
import { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { decodeFinalCandidateItem } from './result-artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readCheckpoint } from './rows.js';
import type { DeliveryMergeLimitCause } from '../kernel/stop.js';
import { isZeroBudget } from './invariants.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';

export const deliveryMergeItemId = (runId: string, sourceRunResultRef: string, capturedWorkspaceRef: string) =>
  identityHash('cliq-delivery-merge-item-v1', runId, sourceRunResultRef, capturedWorkspaceRef);
export const deliveryMergeConflictItemId = (runId: string, sourceRunResultRef: string, capturedWorkspaceRef: string) =>
  identityHash('cliq-delivery-merge-conflict-item-v1', runId, sourceRunResultRef, capturedWorkspaceRef);
export const deliveryMergeConflictCheckpointId = (runId: string, itemId: string) =>
  identityHash('cliq-delivery-merge-conflict-checkpoint-v1', runId, itemId);

/** The payload is a deterministic projection of the existing diff3 result,
 * never an exception, caller-selected diagnosis or new execution authority. */
export function deliveryMergeConflictArtifact(runId: string, sourceRunResultRef: string,
  source: Extract<DeliverySourcePlan, { kind: 'conflict' }>) {
  const value = { schemaVersion: 1 as const, format: 'cliq-delivery-merge-conflict-v1' as const, runId,
    sourceRunResultRef, ...source.input, mergeAlgorithm: 'cliq-diff3-v1' as const, conflicts: source.conflicts, conflictDigest: '' };
  value.conflictDigest = digestOmitting(value, 'conflictDigest'); return value;
}

export type DeliveryRecoveryCut = {
  run: Run; runSpec: RunSpec; items: RunItemReferenceV1[]; journal: InvocationJournalEntry[]; checkpoints: Checkpoint[];
  decodedItems: ReadonlyMap<string, ContinuationItem>;
};
export type RetainedDeliveryMerge = {
  merge: Readonly<DeliveryMergeItem>; candidate: FinalCandidateItem; checkpoint: Checkpoint;
  source: Extract<DeliverySourcePlan, { kind: 'ready' }>;
  plan: Awaited<ReturnType<typeof planDeliveryPublication>>['plan']; planRef: string;
};

export async function readDeliveryMergeSource(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, signal?: AbortSignal) {
  if (signal) artifacts = artifacts.withReadSignal(signal);
  const admission = await readDeliveryRunAdmission(driver, artifacts, runId, { signal });
  const source = await planDeliverySource(artifacts, { sourceBaseRef: admission.source.result.baseSourceRef,
    sourceDesiredRef: admission.source.result.resultSourceRef, capturedWorkspaceRef: admission.spec.baseWorkspaceManifestRef,
    sandboxProfileRef: admission.spec.sandboxProfileRef }, { signal });
  signal?.throwIfAborted(); return { admission, source };
}

function originalCheckpoint(input: DeliveryRecoveryCut, id: string, through: number, createdAt: string): Checkpoint {
  const matches = input.checkpoints.filter(checkpoint => checkpoint.id === id), checkpoint = matches[0];
  if (matches.length !== 1 || !checkpoint || checkpoint.schemaVersion !== 1 || checkpoint.runId !== input.run.id ||
      checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== through || checkpoint.journalSeq !== 0 ||
      checkpoint.basedOnRunRevision !== 1 || checkpoint.basedOnRunRevision >= input.run.revision ||
      checkpoint.createdAt < createdAt || checkpoint.createdAt >= input.run.deadlineAt)
    throw new TypeError('delivery merge lost its unique original worker-free Checkpoint');
  return checkpoint;
}
async function originalContext(artifacts: ArtifactCatalog, input: DeliveryRecoveryCut, checkpoint: Checkpoint) {
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  if (context.runId !== input.run.id || context.assemblyRef !== input.runSpec.assemblyRef ||
      context.admittedContextRef !== input.runSpec.admittedContextRef || context.throughItemSeq !== checkpoint.runItemSeq)
    throw new TypeError('delivery merge Checkpoint has a foreign original context');
  validateContextItems(context, input.items.slice(0, checkpoint.runItemSeq).map(row => ({ itemSeq: row.itemSeq,
    itemRef: row.payloadRef, item: input.decodedItems.get(row.itemId)! })));
  return context;
}

/** Reproduce B/S/A/M, A→M, summary, Plan and W_M from the original admission.
 * This reader never publishes, materializes, claims, samples native death or
 * mints a verified-source brand. Every original blob stream is exhausted. */
export async function validateDeliveryRecovery(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: DeliveryRecoveryCut): Promise<ReadonlyMap<string, RetainedDeliveryMerge>> {
  const merges = input.items.filter(row => ['delivery_merge', 'delivery_merge_conflict'].includes(input.decodedItems.get(row.itemId)?.kind ?? ''));
  if (input.runSpec.operation !== 'delivery') {
    if (merges.length || [...input.decodedItems.values()].some(item => ['delivery_merge', 'delivery_merge_conflict'].includes(item.kind)))
      throw new TypeError('an Agent Run cannot own a delivery merge');
    return new Map();
  }
  const admission = await readDeliveryRunAdmission(driver, artifacts, input.run.id);
  return validateDeliveryRecoveryData(driver, artifacts, input, admission);
}

/** Internal fresh-epoch data flow. It conveys no owner or execution proof. */
export async function validateDeliveryRecoveryData(driver: SqliteDriver, artifacts: ArtifactCatalog,
  input: DeliveryRecoveryCut, admission: Awaited<ReturnType<typeof readDeliveryRunAdmission>>): Promise<ReadonlyMap<string, RetainedDeliveryMerge>> {
  const merges = input.items.filter(row => ['delivery_merge', 'delivery_merge_conflict'].includes(input.decodedItems.get(row.itemId)?.kind ?? ''));
  requireEqual(admission.run, input.run, 'delivery recovery original Run cut');
  requireEqual(admission.spec, input.runSpec, 'delivery recovery original RunSpec');
  const result = new Map<string, RetainedDeliveryMerge>();
  if (merges.length > 1 || input.items.some((row, index) => row.itemSeq !== index + 1) ||
      merges.length && merges[0]!.itemSeq !== 1)
    throw new TypeError('delivery has more than one merge or a non-original merge position');
  if (merges.length === 0) {
    if (input.items.length || input.journal.length || input.run.latestCheckpointId !== admission.initialCheckpoint.id &&
        !(input.run.stopIntentRef && ['failed', 'cancelled'].includes(input.run.status)))
      throw new TypeError('delivery continuation advanced without its original merge owner');
    if (input.run.frontierRef) requireEqual(await readCanonicalArtifact(artifacts, input.run.frontierRef), {
      schemaVersion: 1, kind: 'delivery', phase: 'merge', sourceRunResultRef: admission.request.expectedRunResultRef,
      capturedWorkspaceRef: input.runSpec.baseWorkspaceManifestRef
    }, 'delivery original merge frontier');
    return result;
  }
  const source = await planDeliverySource(artifacts, { sourceBaseRef: admission.source.result.baseSourceRef,
    sourceDesiredRef: admission.source.result.resultSourceRef, capturedWorkspaceRef: admission.spec.baseWorkspaceManifestRef,
    sandboxProfileRef: admission.spec.sandboxProfileRef });
  if (source.kind === 'limited') throw new TypeError('limited delivery output cannot own a merged candidate or conflict item');
  const row = merges[0]!, decoded = input.decodedItems.get(row.itemId);
  if (!decoded || decoded.itemId !== row.itemId || decoded.runId !== input.run.id ||
      decoded.createdAt !== row.createdAt || row.payloadDigest !== row.payloadRef || decoded.createdAt < input.run.createdAt ||
      decoded.createdAt >= input.run.deadlineAt) throw new TypeError('delivery merge does not match its original owned item');
  if (source.kind === 'conflict') {
    const conflict = decoded as DeliveryMergeConflictItem;
    const payload = deliveryMergeConflictArtifact(input.run.id, admission.request.expectedRunResultRef, source);
    const expected: DeliveryMergeConflictItem = { schemaVersion: 1, itemId: deliveryMergeConflictItemId(input.run.id,
      admission.request.expectedRunResultRef, input.runSpec.baseWorkspaceManifestRef), runId: input.run.id, kind: 'delivery_merge_conflict',
      sourceRunResultRef: admission.request.expectedRunResultRef, ...source.input, mergeAlgorithm: 'cliq-diff3-v1',
      conflictRef: canonicalSha256(payload), createdAt: conflict.createdAt };
    requireEqual(conflict, expected, 'delivery exact original diff3 conflict item');
    requireEqual(await readCanonicalArtifact(artifacts, conflict.conflictRef), payload, 'delivery exact original diff3 conflicts');
    if (input.items.length !== 1 || input.journal.length || !input.run.stopIntentRef ||
        [...input.decodedItems.values()].some(item => item.kind === 'final_candidate'))
      throw new TypeError('delivery merge conflict acquired a candidate, invocation or lost its stop');
    const checkpoint = originalCheckpoint(input, deliveryMergeConflictCheckpointId(input.run.id, conflict.itemId), 1, conflict.createdAt);
    if (checkpoint.workspaceStateRef !== admission.initialCheckpoint.workspaceStateRef)
      throw new TypeError('delivery conflict changed its admitted workspace');
    await originalContext(artifacts, input, checkpoint);
    const cause = deliveryMergeConflictStop(conflict, row.payloadRef);
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(cause)), cause, 'delivery original conflict StopIntent');
    return result;
  }
  const merge = decodeDeliveryMergeItem(decoded);
  const expectedMerge: DeliveryMergeItem = { schemaVersion: 1, itemId: deliveryMergeItemId(input.run.id,
    admission.request.expectedRunResultRef, input.runSpec.baseWorkspaceManifestRef), runId: input.run.id, kind: 'delivery_merge',
    sourceRunResultRef: admission.request.expectedRunResultRef, ...source.input, resultSourceRef: source.sourceRef,
    diffRef: source.diffRef, summaryRef: source.summaryRef, deliveryPlanRef: merge.deliveryPlanRef, createdAt: merge.createdAt };
  requireEqual(merge, expectedMerge, 'delivery exact deterministic B/S/A/M merge item');
  // Newly merged bytes must already be durable; the deterministic planned
  // graph is compared through the actual immutable CAS, never published here.
  for (const artifact of source.publications) {
    const bytes = await artifacts.readBytes(artifact.ref);
    if (!bytes.equals(artifact.bytes)) throw new TypeError('delivery retained merge substituted its planned artifact');
  }
  const planned = await planDeliveryPublication(artifacts, { deliveryRunId: input.run.id,
    sourceRunResultRef: admission.request.expectedRunResultRef, ...source.input,
    captureTopologyRef: admission.inspection.outcome.kind === 'captured' ? admission.inspection.outcome.captureTopologyRef : '',
    desiredSourceRef: source.sourceRef, diffRef: source.diffRef }, undefined, input.runSpec.sandboxProfileRef);
  if (planned.planRef !== merge.deliveryPlanRef) throw new TypeError('delivery merge names a different complete publication Plan');
  requireEqual(await readCanonicalArtifact(artifacts, planned.planRef), planned.plan, 'delivery original complete publication Plan');
  const candidateRow = input.items[1], candidate = candidateRow && input.decodedItems.get(candidateRow.itemId);
  const expectedCandidate: FinalCandidateItem = { schemaVersion: 1, runId: input.run.id,
    itemId: finalCandidateItemId(input.run.id, merge.itemId), kind: 'final_candidate', operation: 'delivery', producingItemId: merge.itemId,
    baseSourceRef: input.runSpec.baseWorkspaceManifestRef, resultSourceRef: source.sourceRef, diffRef: source.diffRef,
    summaryRef: source.summaryRef, sourceDigest: source.source.manifestDigest, diffDigest: source.diff.diffDigest, createdAt: merge.createdAt };
  if (!candidateRow || candidateRow.itemSeq !== 2 || candidate?.kind !== 'final_candidate' ||
      candidateRow.payloadRef !== canonicalSha256(expectedCandidate) || candidateRow.payloadDigest !== candidateRow.payloadRef ||
      candidateRow.createdAt !== merge.createdAt) throw new TypeError('delivery merge has no exact immediately following candidate');
  requireEqual(decodeFinalCandidateItem(candidate), expectedCandidate, 'delivery candidate original merge producer');
  const checkpoint = originalCheckpoint(input, finalCandidateCheckpointId(input.run.id, merge.itemId), 2, merge.createdAt);
  const workspace: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId: input.run.id,
    baseWorkspaceManifestRef: input.runSpec.baseWorkspaceManifestRef, entriesRef: source.source.entriesRef,
    invalidatedEphemeralPaths: [], sourceProjectionDigest: source.source.sourceProjectionDigest,
    ...(admission.workspaceState.privateGitStateRef ? { privateGitStateRef: admission.workspaceState.privateGitStateRef } : {}), stateDigest: '' };
  workspace.stateDigest = digestOmitting(workspace, 'stateDigest');
  if (checkpoint.workspaceStateRef !== canonicalSha256(workspace)) throw new TypeError('delivery merge Checkpoint substituted its W_M');
  requireEqual(decodeWorkspaceState(await readCanonicalArtifact(artifacts, checkpoint.workspaceStateRef)), workspace, 'delivery original restorable W_M');
  await originalContext(artifacts, input, checkpoint);
  result.set(merge.itemId, { merge, candidate: expectedCandidate, checkpoint, source, plan: planned.plan, planRef: planned.planRef });
  return result;
}

export function deliveryMergeConflictStop(item: DeliveryMergeConflictItem, itemRef: string) {
  return { schemaVersion: 1 as const, runId: item.runId, createdAt: item.createdAt, origin: 'runtime' as const,
    targetStatus: 'failed' as const, reason: 'runtime_failed' as const, runtimeSubtype: 'delivery_merge_conflict' as const,
    deliveryMergeConflictItemRef: itemRef, conflictRef: item.conflictRef };
}

/** Exact positive conflict cause. No public method accepts a caller's error,
 * conflict list or reference as authority to stop a delivery. */
export async function readDeliveryMergeConflictCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('delivery conflict cannot stop an Agent Run');
  const checkpoints = driver.prepare('SELECT id FROM checkpoints WHERE run_id = ? ORDER BY rowid').all<{ id: string }>(cut.run.id);
  const decodedItems = new Map<string, ContinuationItem>();
  for (const row of cut.items) decodedItems.set(row.itemId, await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef));
  await validateDeliveryRecovery(driver, artifacts, { ...cut, checkpoints: checkpoints.map(row => readCheckpoint(driver, row.id)), decodedItems });
  const row = cut.items.find(row => decodedItems.get(row.itemId)?.kind === 'delivery_merge_conflict');
  if (!row) throw new TypeError('delivery conflict stop has no original owned conflict');
  return deliveryMergeConflictStop(decodedItems.get(row.itemId) as DeliveryMergeConflictItem, row.payloadRef);
}

/** Recompute a zero-effect refusal from the original verified source and W_A.
 * The planned M never needs publication and no error/caller measurement is
 * evidence. Stop/reopen may replace only the latest pointer, not this cut. */
export async function readDeliveryMergeLimitCause(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1): Promise<DeliveryMergeLimitCause | undefined> {
  const { run, runSpec: spec, latestCheckpoint: checkpoint } = cut;
  if (spec.operation !== 'delivery') return undefined;
  assertDeliveryModelFreeCut(cut);
  if (!['queued', 'failed', 'cancelled'].includes(run.status) || run.activeWorkerLaunchId || run.waitingReason || run.waitingOnRef ||
      run.leaseEpoch !== 0 || cut.items.length || cut.journal.length || cut.workerLaunches.length || cut.workspaceGenerations.length ||
      cut.childAllocations.length || !isZeroBudget(run.budgetReserved) || !isZeroBudget(run.budgetConsumed)) return undefined;
  const { admission, source } = await readDeliveryMergeSource(driver, artifacts, run.id);
  requireEqual(admission.run, run, 'delivery source limit original Run cut');
  requireEqual(admission.spec, spec, 'delivery source limit original RunSpec');
  const initial = admission.initialCheckpoint;
  if (checkpoint.workspaceStateRef !== initial.workspaceStateRef || checkpoint.contextManifestRef !== initial.contextManifestRef ||
      checkpoint.runItemSeq !== 0 || checkpoint.journalSeq !== 0)
    throw new TypeError('delivery source limit changed its original worker-free W_A or context');
  if (run.nextStep !== null) {
    if (run.status !== 'queued' || run.nextStep !== 'delivery' || checkpoint.id !== initial.id || !run.frontierRef)
      throw new TypeError('delivery source limit no longer owns its original merge cut');
    requireEqual(await readCanonicalArtifact(artifacts, run.frontierRef), { schemaVersion: 1, kind: 'delivery', phase: 'merge',
      sourceRunResultRef: admission.request.expectedRunResultRef, capturedWorkspaceRef: spec.baseWorkspaceManifestRef },
    'delivery source limit original merge frontier');
  } else if (!['failed', 'cancelled'].includes(run.status) || !run.stopIntentRef)
    throw new TypeError('delivery source limit has no original active merge or terminal Stop');
  if (source.kind !== 'limited') return undefined;
  return { sourceCheckpointId: initial.id, workspaceStateRef: initial.workspaceStateRef,
    sourceRunResultRef: admission.request.expectedRunResultRef, ...source.input, sourceProjectionRef: spec.sourceProjectionRef,
    sandboxProfileRef: spec.sandboxProfileRef, mergeAlgorithm: 'cliq-diff3-v1', limitKind: source.limit.kind,
    observed: source.limit.observed, limit: source.limit.limit };
}
