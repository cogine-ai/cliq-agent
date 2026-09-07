import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type {
  ContextManifest, ContinuationItem, InvocationJournalEntry, Run, RunItemReferenceV1, RunSpec,
  ToolResultPayloadV1, ToolResultModelContentV1, RunContextCompactionPlan, RunAssemblyV1
} from '../kernel/types.js';
import type { ModelUnusableResponseV1 } from '../protocol/agent-ir.js';
import { modelResponseDigest } from '../model/attempt.js';
import { toolOperationId } from '../policy/tool-policy.js';
import type { ModelRequestV1, NormalPromptProjectionV1, ModelVisiblePromptV1 } from '../model/request.js';
import { validateUnusableModelResponse } from '../runtime/continuation.js';
import { assertSameModelOperation, modelRetryState } from '../runtime/model-retry.js';
import { contextSourceDigest, validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact, readModelTurnMaterial, readText } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { validateToolRecovery } from './tool-recovery.js';
import { validateUserInputRecovery } from './input-recovery.js';
import type { Checkpoint } from '../kernel/types.js';

/** Recovery checks retained reachability/identity; loading the agent additionally reproduces native requests and validates schemas. */
export async function validateAgentRecovery(input: {
  artifacts: ArtifactCatalog; run: Run; spec: RunSpec; items: RunItemReferenceV1[];
  journal: InvocationJournalEntry[]; context: ContextManifest;
  checkpoints: Checkpoint[];
}): Promise<void> {
  const { artifacts, run, spec, journal } = input;
  const requests = new Map<string, ModelRequestV1>();
  const operationRequests = new Map<string, ModelRequestV1>();
  for (const prepared of journal.filter((entry) => entry.opKind === 'model' && entry.phase === 'prepared')) {
    const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, prepared.requestRef);
    if (request.schemaVersion !== 1 || request.format !== 'cliq-model-request-v1' ||
        request.runId !== run.id || request.assemblyRef !== spec.assemblyRef || request.opId !== prepared.opId ||
        request.attempt !== prepared.attempt || request.model !== prepared.target || request.requestDigest !== digestOmitting(request, 'requestDigest')) {
      throw new TypeError('model Journal request identity does not rehash');
    }
    const bytes = await artifacts.readBytes(request.bodyBytesRef);
    if (bytes.byteLength !== request.bodyByteCount) throw new TypeError('model Journal native body byte count mismatch');
    if (canonicalSha256(prepared.budgetDelta) !== canonicalSha256({ modelTokens: request.reservation.modelTokens,
      costMicros: request.reservation.costMicros, toolCalls: 0, repairAttempts: 0 })) throw new TypeError('model Journal reservation mismatch');
    const projection = await readCanonicalArtifact<NormalPromptProjectionV1 | ModelVisiblePromptV1>(artifacts, request.promptProjectionRef);
    if (request.kind === 'normal' ? !('projectionDigest' in projection) || projection.projectionDigest !== request.promptProjectionDigest ||
        digestOmitting(projection, 'projectionDigest') !== projection.projectionDigest
      : projection.format !== 'cliq-compaction-prompt-v1' || request.promptProjectionDigest !== request.promptProjectionRef) {
      throw new TypeError('model Journal projection digest mismatch');
    }
    if ('contextManifestRef' in projection) {
      await readCanonicalArtifact(artifacts, projection.contextManifestRef);
      await readCanonicalArtifact(artifacts, projection.frontierDigest);
    } else {
      if (!request.compactionPlanRef) throw new TypeError('compaction request has no plan');
      const plan = await readCanonicalArtifact<RunContextCompactionPlan>(artifacts, request.compactionPlanRef);
      if (plan.runId !== run.id) throw new TypeError('compaction plan belongs to another Run');
      await readCanonicalArtifact(artifacts, plan.sourceContextManifestRef);
    }
    const first = operationRequests.get(prepared.opId);
    if (first) assertSameModelOperation(first, request);
    else operationRequests.set(prepared.opId, request);
    requests.set(prepared.requestRef, request);
  }
  if (operationRequests.size) {
    const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
    for (const opId of operationRequests.keys()) modelRetryState(assembly.retry.model, journal.filter((entry) => entry.opId === opId), run.updatedAt);
  }
  const turns = new Map<string, Awaited<ReturnType<typeof readModelTurnMaterial>>>();
  for (const entry of journal.filter((entry) => entry.opKind === 'model' && entry.phase === 'completed')) {
    const request = requests.get(entry.requestRef);
    if (!request || !entry.resultRef || entry.receiptRef) throw new TypeError('model completion has no single typed result');
    const root = await readCanonicalArtifact<{ format: string }>(artifacts, entry.resultRef);
    if (root.format === 'cliq-model-unusable-response-v1') {
      const response = root as ModelUnusableResponseV1;
      validateUnusableModelResponse(request, entry.requestRef, response);
      if ((await artifacts.readBytes(response.observedResponse.bytesRef)).byteLength !== response.observedResponse.byteCount) {
        throw new TypeError('model unusable observation byte count mismatch');
      }
    } else if (root.format === 'cliq-agent-model-turn-v1') {
      const material = await readModelTurnMaterial(artifacts, entry.resultRef);
      const turn = material.turn;
      if (turn.requestDigest !== request.requestDigest || turn.promptProjectionRef !== request.promptProjectionRef ||
          turn.promptProjectionDigest !== request.promptProjectionDigest || turn.responseDigest !== modelResponseDigest(turn)) {
        throw new TypeError('retained model turn differs from its request');
      }
      turns.set(entry.resultRef, material);
    } else throw new TypeError('model completion has an untyped result');
  }
  const items = new Map<string, ContinuationItem>();
  for (const row of input.items) {
    const item = await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef);
    if (item.runId !== run.id || item.itemId !== row.itemId || item.createdAt !== row.createdAt) {
      throw new TypeError('Run item differs from its durable owner row');
    }
    items.set(item.itemId, item);
    if (item.kind === 'model_turn' || item.kind === 'assistant_tool_batch') {
      const turn = turns.get(item.modelTurnRef)?.turn;
      const completion = journal.find((entry) => entry.opKind === 'model' && entry.phase === 'completed' &&
        entry.opId === item.modelOpId && entry.attempt === item.modelAttempt && entry.resultRef === item.modelTurnRef);
      if (!turn || !completion || requests.get(completion.requestRef)?.kind !== 'normal' || item.textRef !== turn.textRef || (item.kind === 'model_turn'
        ? item.stopReason !== turn.stopReason : canonicalSha256(item.calls) !== canonicalSha256(turn.toolCalls))) {
        throw new TypeError('model item is not owned by the matching completed Journal attempt');
      }
    } else if (item.kind === 'context_compaction') {
      const completion = journal.find((entry) => entry.opKind === 'model' && entry.phase === 'completed' &&
        entry.opId === item.modelOpId && entry.attempt === item.modelAttempt);
      const request = completion && requests.get(completion.requestRef);
      const turn = completion?.resultRef ? turns.get(completion.resultRef)?.turn : undefined;
      const plan = await readCanonicalArtifact<RunContextCompactionPlan>(artifacts, item.planRef);
      const text = await readText(artifacts, item.summaryRef, item.summaryDigest);
      const source = input.items.slice(item.coveredFromItemSeq - 1, item.coveredThroughItemSeq).map((row) => ({
        itemSeq: row.itemSeq, itemRef: row.payloadRef, item: items.get(row.itemId)!
      }));
      if (request?.kind !== 'context_compaction' || request.compactionPlanRef !== item.planRef || turn?.stopReason !== 'end' ||
          turn.textRef !== item.summaryRef || text.byteCount > plan.maxSummaryBytes || plan.runId !== run.id ||
          plan.compactFromItemSeq !== item.coveredFromItemSeq || plan.compactThroughItemSeq !== item.coveredThroughItemSeq ||
          plan.sourceItemsDigest !== item.sourceItemsDigest || contextSourceDigest(source) !== item.sourceItemsDigest) {
        throw new TypeError('context summary is not owned by the matching completed compaction attempt');
      }
      await readCanonicalArtifact(artifacts, plan.sourceContextManifestRef);
    } else if (item.kind === 'tool_result') {
      const batch = items.get(item.batchItemId);
      const call = batch?.kind === 'assistant_tool_batch' ? batch.calls[item.index] : undefined;
      const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
      const content = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, payload.modelContentRef);
      if (!call || call.callId !== item.callId || payload.runId !== run.id || payload.batchItemId !== item.batchItemId ||
          payload.callId !== item.callId || payload.index !== item.index || payload.toolName !== call.toolName ||
          payload.outcome !== item.outcome || digestOmitting(payload, 'payloadDigest') !== payload.payloadDigest ||
          content.callId !== item.callId || content.index !== item.index || content.toolName !== call.toolName || content.outcome !== item.outcome ||
          digestOmitting(content, 'contentDigest') !== payload.modelContentDigest || content.contentDigest !== payload.modelContentDigest) {
        throw new TypeError('tool result is not owned by its retained batch call');
      }
      if (payload.outcome === 'executed') {
        if (payload.source === 'invocation') {
          if (item.opId !== payload.opId || payload.opId !== toolOperationId(run.id, item.batchItemId, item.callId) ||
              !journal.some((entry) => (entry.opKind === 'tool' || entry.opKind === 'mcp') &&
              entry.phase === 'completed' && entry.opId === payload.opId && entry.attempt === payload.attempt &&
              entry.resultRef === payload.journalResultRef)) throw new TypeError('executed invocation result has no completed Journal owner');
        } else if (payload.source !== 'user_input') throw new TypeError('executed tool result has an unknown source');
      }
      if (payload.outcome === 'error') await artifacts.readBytes(payload.diagnosticRef);
    }
  }
  await validateToolRecovery({ artifacts, run, spec, items, journal, checkpoints: input.checkpoints });
  await validateUserInputRecovery({ artifacts, run, spec, items, journal, checkpoints: input.checkpoints });
  validateContextItems(input.context, input.items.map((row) => ({
    itemSeq: row.itemSeq, itemRef: row.payloadRef, item: items.get(row.itemId)!
  })));
}
