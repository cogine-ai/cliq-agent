import { canonicalSha256 } from '../kernel/canonical.js';
import type { ContinuationItem, RunFrontier, ToolBatchItem } from '../kernel/types.js';
import type { ResolveToolInput } from '../model/attempt.js';
import { validateModelTurn } from '../runtime/continuation.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import type { ModelRequestV1 } from '../model/request.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact, readModelTurnMaterial } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest } from './decoders.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import type { SqliteDriver } from './sqlite-driver.js';

/** The SQLite cut owns the cursor. Control evidence may intervene, but results still close calls once in order. */
export const readToolCut = stateOperation('RECOVERY_REQUIRED', async (
  driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, resolveToolInput: ResolveToolInput
) => {
  const closure = await readRecoveryClosure(driver, artifacts, runId);
  const { run, latestCheckpoint: checkpoint } = closure;
  if (!run.frontierRef || run.nextStep !== 'tool') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'Run is not at a tool frontier');
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
  if (frontier.kind !== 'tool' || !exactKeys(frontier, ['schemaVersion', 'kind', 'batchItemId', 'orderedCallIds', 'nextCallIndex'])) {
    throw new TypeError('tool step requires an exact tool frontier');
  }
  const items = await joinResourceOperations(closure.items.map(async (row) => ({
    itemSeq: row.itemSeq, itemRef: row.payloadRef, item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef)
  })));
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  validateContextItems(context, items);
  if (context.throughItemSeq !== checkpoint.runItemSeq || checkpoint.runItemSeq !== items.length) throw new TypeError('tool cut is not at its ready context');
  const batchIndex = items.findIndex(({ item }) => item.itemId === frontier.batchItemId);
  const batch = items[batchIndex]?.item as ToolBatchItem | undefined;
  if (!batch || batch.kind !== 'assistant_tool_batch') throw new TypeError('current tool batch is missing');
  const material = await readModelTurnMaterial(artifacts, batch.modelTurnRef);
  const prepared = closure.journal.filter((entry) => entry.opId === batch.modelOpId && entry.phase === 'prepared').at(-1);
  if (!prepared || prepared.attempt !== batch.modelAttempt) throw new TypeError('tool batch has no current model owner');
  validateModelTurn(await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef), material, resolveToolInput);
  let next = 0;
  for (const { item } of items.slice(batchIndex + 1)) {
    if (item.kind === 'policy_decision') {
      if (item.subjectKind !== 'tool_call') throw new TypeError('unexpected policy subject inside tool batch');
    } else if (item.kind === 'input_request' || item.kind === 'user_input') {
      if (item.batchItemId !== batch.itemId || item.index !== next || item.callId !== batch.calls[next]?.callId) {
        throw new TypeError('input control item differs from its result-less call');
      }
    } else if (item.kind === 'tool_result' && item.batchItemId === batch.itemId && item.index === next && item.callId === batch.calls[next]?.callId) next++;
    else throw new TypeError('tool frontier has a non-contiguous result prefix');
  }
  if (frontier.schemaVersion !== 1 || canonicalSha256(frontier.orderedCallIds) !== canonicalSha256(batch.calls.map((call) => call.callId)) ||
      !Number.isSafeInteger(frontier.nextCallIndex) || frontier.nextCallIndex !== next || next >= batch.calls.length ||
      material.inputs.some(({ value }) => value.disposition !== 'resolved')) throw new TypeError('tool frontier differs from its fully validated batch');
  return { ...closure, checkpoint, context, frontier, batch, items, call: material.inputs[next]!.value };
});

export type ToolCut = Awaited<ReturnType<typeof readToolCut>>;
