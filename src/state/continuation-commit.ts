import { planCanonicalArtifact, type PlannedArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ContextManifest, ContinuationItem, Run, RunFrontier } from '../kernel/types.js';
import { contextSourceDigest, validateContextItems, type ContextItem } from '../runtime/context-compaction.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { SqliteConnection } from './sqlite-driver.js';

/** Internal continuation commit plan. No StateStore caller can append arbitrary items or patch a frontier. */
export async function prepareContinuationCommit(artifacts: ArtifactCatalog, input: {
  context: ContextManifest; existingItems: ContextItem[]; items: ContinuationItem[]; frontier: RunFrontier;
  checkpointId: string; workspaceStateRef: string; artifacts?: PlannedArtifact[];
}) {
  const { items, checkpointId, workspaceStateRef } = input;
  const itemPlans = items.map((item) => planCanonicalArtifact(item, `cliq-${item.kind.replaceAll('_', '-')}-item-v1`));
  const added = items.map((item, index) => ({ item, itemRef: itemPlans[index]!.ref, itemSeq: input.context.throughItemSeq + index + 1 }));
  const context = structuredClone(input.context);
  for (const entry of added) {
    const range = { fromItemSeq: entry.itemSeq, throughItemSeq: entry.itemSeq };
    context.segments.push(entry.item.kind === 'model_turn' || entry.item.kind === 'tool_result'
      ? { kind: 'raw', ...range, items: [{ itemSeq: entry.itemSeq, itemRef: entry.itemRef }] }
      : { kind: 'excluded_control', ...range, sourceItemsDigest: contextSourceDigest([entry]) });
  }
  context.throughItemSeq += items.length;
  context.projectionDigest = digestOmitting(context, 'projectionDigest');
  validateContextItems(context, [...input.existingItems, ...added]);
  const contextPlan = planCanonicalArtifact(context, context.format);
  const frontierPlan = planCanonicalArtifact(input.frontier, 'cliq-run-frontier-v1');
  const metadata = await Promise.all([...itemPlans, contextPlan, frontierPlan, ...(input.artifacts ?? [])]
    .map((plan) => artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)));
  return { metadata, commit(connection: SqliteConnection, run: Run, journalSeq: number, createdAt: string) {
    for (const entry of added) connection.prepare(
      'INSERT INTO items (item_id, session_id, run_id, item_seq, kind, payload_ref, created_at) VALUES (?, NULL, ?, ?, ?, ?, ?)'
    ).run(entry.item.itemId, run.id, BigInt(entry.itemSeq), entry.item.kind, entry.itemRef, entry.item.createdAt);
    connection.prepare(`INSERT INTO checkpoints (id, schema_version, run_id, based_on_run_revision, run_item_seq,
      context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'auto')`)
      .run(checkpointId, run.id, BigInt(run.revision), BigInt(context.throughItemSeq), contextPlan.ref,
        BigInt(journalSeq), workspaceStateRef, createdAt);
    connection.prepare('UPDATE runs SET latest_checkpoint_id = ?, frontier_ref = ?, next_step = ? WHERE id = ?')
      .run(checkpointId, frontierPlan.ref, input.frontier.kind, run.id);
  } };
}
