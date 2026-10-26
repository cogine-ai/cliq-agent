import { readChildAdmission } from './child-admission.js';
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
import { KernelStorageError, stateOperation } from './errors.js';
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
  const items = await artifacts.mapReads(closure.items, async (row) => ({
    itemSeq: row.itemSeq, itemRef: row.payloadRef, item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef)
  }));
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
      if (item.subjectKind === 'child_merge') {
        const result = items.find(row => row.item.kind === 'child_merge_result' && row.item.policyDecisionItemRef === canonicalSha256(item))?.item;
        const audit = result?.kind === 'child_merge_result' ? items.find(row => row.item.itemId === result.mergeBatchItemId)?.item :
          items.find(row => row.item.kind === 'child_merge_batch' && row.item.resume.kind === 'await_tool' && row.item.resume.batchItemId === batch.itemId &&
            row.item.resume.callIndex === next && row.item.resume.callId === batch.calls[next]?.callId)?.item;
        if (audit?.kind !== 'child_merge_batch' || audit.resume.kind !== 'await_tool' || audit.resume.batchItemId !== batch.itemId ||
            audit.resume.callIndex !== next || audit.resume.callId !== batch.calls[next]?.callId)
          throw new TypeError('merge policy audit overtakes its real owning await call');
      } else if (item.subjectKind !== 'tool_call') throw new TypeError('unexpected policy subject inside tool batch');
    } else if (item.kind === 'child_handle') {
      const selectedCall = batch.calls[next];
      if (selectedCall?.toolName !== 'delegate' || item.delegateBatchItemId !== batch.itemId || item.delegateCallIndex !== next ||
          item.delegateCallId !== selectedCall.callId || item.runId !== run.id) throw new TypeError('child handle overtakes its owning delegate call');
      const admitted = await readChildAdmission(driver, artifacts, item.childRunId);
      if (admitted.parent.id !== run.id || canonicalSha256(admitted.handle) !== canonicalSha256(item) ||
          admitted.receipt.childHandleItemRef !== canonicalSha256(item)) throw new TypeError('child handle has no exact original admitted source');
    } else if (item.kind === 'input_request' || item.kind === 'user_input') {
      if (item.batchItemId !== batch.itemId || item.index !== next || item.callId !== batch.calls[next]?.callId) {
        throw new TypeError('input control item differs from its result-less call');
      }
    } else if (item.kind === 'child_merge_batch' || item.kind === 'child_merge_result') {
      const audit = item.kind === 'child_merge_batch' ? item : items.find(row => row.item.itemId === item.mergeBatchItemId)?.item;
      if (audit?.kind !== 'child_merge_batch' || audit.resume.kind !== 'await_tool' || audit.resume.batchItemId !== batch.itemId ||
          audit.resume.callIndex !== next || audit.resume.callId !== batch.calls[next]?.callId)
        throw new TypeError('merge audit overtakes its real owning await call');
    } else if (item.kind === 'child_result') {
      if (item.delivery.kind === 'stop_settlement' && run.stopIntentRef) continue; // Full recovery independently owns this audit-only Stop settlement.
      if (item.delivery.kind !== 'await_tool' || batch.calls[next]?.toolName !== 'await_children' ||
          item.delivery.awaitBatchItemId !== batch.itemId || item.delivery.awaitCallIndex !== next ||
          item.delivery.awaitCallId !== batch.calls[next]?.callId)
        throw new TypeError('child result overtakes its original owning await call');
    } else if (item.kind === 'tool_result' && item.batchItemId === batch.itemId && item.index === next && item.callId === batch.calls[next]?.callId) next++;
    else throw new TypeError('tool frontier has a non-contiguous result prefix');
  }
  if (frontier.schemaVersion !== 1 || canonicalSha256(frontier.orderedCallIds) !== canonicalSha256(batch.calls.map((call) => call.callId)) ||
      !Number.isSafeInteger(frontier.nextCallIndex) || frontier.nextCallIndex !== next || next >= batch.calls.length ||
      material.inputs.some(({ value }) => value.disposition !== 'resolved')) throw new TypeError('tool frontier differs from its fully validated batch');
  return { ...closure, checkpoint, context, frontier, batch, items, call: material.inputs[next]!.value };
});

export type ToolCut = Awaited<ReturnType<typeof readToolCut>>;
