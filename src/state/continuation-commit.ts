import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ContextManifest, ContinuationItem, Run, RunFrontier } from '../kernel/types.js';
import { contextSourceDigest, validateContextItems, type ContextItem } from '../runtime/context-compaction.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { joinResourceOperations, ResourceRetirementError } from './errors.js';
import type { SqliteConnection } from './sqlite-driver.js';

/** Internal continuation commit plan. No StateStore caller can append arbitrary items or patch a frontier. */
export function planContinuationCommit(artifacts: ArtifactCatalog, input: {
  context: ContextManifest; existingItems: ContextItem[]; items: ContinuationItem[]; frontier: RunFrontier;
  checkpointId: string; workspaceStateRef: string; artifacts?: PlannedArtifact[];
}) {
  const { checkpointId, workspaceStateRef } = input;
  const items = structuredClone(input.items), frontierKind = input.frontier.kind;
  const itemPlans = items.map((item) => planCanonicalArtifact(item, `cliq-${item.kind.replaceAll('_', '-')}-item-v1`));
  const added = items.map((item, index) => ({ item, itemRef: itemPlans[index]!.ref, itemSeq: input.context.throughItemSeq + index + 1 }));
  const context = structuredClone(input.context);
  for (const entry of added) {
    const range = { fromItemSeq: entry.itemSeq, throughItemSeq: entry.itemSeq };
    context.segments.push(entry.item.kind === 'model_turn' || entry.item.kind === 'tool_result' || entry.item.kind === 'user_input'
      ? { kind: 'raw', ...range, items: [{ itemSeq: entry.itemSeq, itemRef: entry.itemRef }] }
      : { kind: 'excluded_control', ...range, sourceItemsDigest: contextSourceDigest([entry]) });
  }
  context.throughItemSeq += items.length;
  context.projectionDigest = digestOmitting(context, 'projectionDigest');
  validateContextItems(context, [...input.existingItems, ...added]);
  const contextPlan = planCanonicalArtifact(context, context.format);
  const frontierPlan = planCanonicalArtifact(input.frontier, 'cliq-run-frontier-v1');
  const plans = [...itemPlans, contextPlan, frontierPlan, ...(input.artifacts ?? [])];
  const published: Array<PublishedArtifact | undefined> = plans.map(() => undefined);
  let publishing: Promise<PublishedArtifact[]> | undefined;
  const plan = { throughItemSeq: context.throughItemSeq,
    runUpdate: { latestCheckpointId: checkpointId, frontierRef: frontierPlan.ref, nextStep: frontierKind },
    commit(connection: SqliteConnection, run: Run, journalSeq: number, createdAt: string) {
    for (const entry of added) connection.prepare(
      'INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, NULL, ?, ?, ?, ?, ?)'
    ).run(entry.item.itemId, run.id, BigInt(entry.itemSeq), entry.item.kind, entry.itemRef, entry.item.createdAt);
    connection.prepare(`INSERT INTO checkpoints (id, schema_version, run_id, based_on_run_revision, run_item_seq,
      context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'auto')`)
      .run(checkpointId, run.id, BigInt(run.revision), BigInt(context.throughItemSeq), contextPlan.ref,
        BigInt(journalSeq), workspaceStateRef, createdAt);
    connection.prepare('UPDATE runs SET latest_checkpoint_id = ?, frontier_ref = ?, next_step = ? WHERE id = ?')
      .run(checkpointId, frontierPlan.ref, frontierKind, run.id);
  } };
  return { ...plan, publish() {
    if (!publishing) {
      let blocking: { error: unknown } | undefined;
      publishing = joinResourceOperations(plans.map(async (artifact, index) => {
        try { return published[index] ??= await artifacts.publishBytes(artifact.bytes, artifact.mediaType, artifact.schemaKind); }
        catch (error) {
          // All siblings still join. A joined ENOSPC cannot classify another
          // sibling's integrity or resource-retirement refusal as resumable.
          if (!isJoinedCasPublicationFailure(error)) blocking ??= { error };
          throw error;
        }
      })).catch(error => { throw error instanceof ResourceRetirementError ? error : blocking?.error ?? error; })
        .finally(() => { publishing = undefined; });
    }
    return publishing.then(metadata => ({ ...plan, metadata }));
  } };
}

/** One-shot callers keep the original publication/join contract. Retained
 * completion owners instead keep one planned graph across joined CAS errors. */
export async function prepareContinuationCommit(artifacts: ArtifactCatalog, input: Parameters<typeof planContinuationCommit>[1]) {
  return planContinuationCommit(artifacts, input).publish();
}
