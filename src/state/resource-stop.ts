import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, modelOperationId } from '../kernel/identity.js';
import type { BudgetUsage, ContextManifest, ContinuationItem, RecoveryClosureV1, RunAssemblyV1, RunContextCompactionPlan, RunFrontier, ToolContractManifestV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1, ModelUnusableResponseV1, ModelTextV1 } from '../protocol/agent-ir.js';
import { createModelRequestReservation, priceTableDigest, type ModelPriceTableV1, type LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { estimatePromptTokens, projectModelVisiblePrompt, type CompactionPromptEnvelopeV1, type ModelRequestV1, type NormalPromptProjectionV1 } from '../model/request.js';
import { loadToolPolicy, planToolRequest, toolOperationId } from '../policy/tool-policy.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { planContextCompaction, replaceCompactedPrefix, validateContextItems, type ContextItem } from '../runtime/context-compaction.js';
import { planModelContinuation, validateModelTurn, validateUnusableModelResponse } from '../runtime/continuation.js';
import { openStopBatch, stopInvocationHistory, type ResourceStopIntent } from '../runtime/stop.js';
import { loadInstructionText, readCanonicalArtifact, readModelContext, readModelTurnMaterial } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest, decodeWorkspaceIdentity } from './decoders.js';
import { isZeroBudget } from './invariants.js';
import { readCheckpoint, readSession } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readToolApproval } from './tool-approval-recovery.js';
import { joinResourceOperations, stateOperation } from './errors.js';
import { readHighestPreparedAttempt } from './repositories/journal.js';
import { readCandidateSourceLimit } from './result-source.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';
import { readDeliveryVerificationMode } from './run-result-recovery.js';
import { readVerifierPendingPolicy } from './verifier-stop-history.js';
import { readDeliveryAuthorization } from './delivery-approval.js';
import { readDeliveryMergeLimitCause } from './delivery-recovery.js';
import { frozenSessionCompactionIndex } from './session-context.js';

type WithoutIdentity<T> = T extends ResourceStopIntent ? Omit<T, 'schemaVersion' | 'runId' | 'createdAt'> : never;
type ResourceCause = WithoutIdentity<ResourceStopIntent>;

/** Reproduce deterministic resource failure from retained facts, not a caught error or caller reason. */
export const readResourceStopCause = stateOperation('RECOVERY_REQUIRED', async function readResourceStopCause(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, observedAt: string
): Promise<ResourceCause | undefined> {
  const { run, runSpec: spec, latestCheckpoint: checkpoint, journal } = cut;
  if (run.waitingReason || !isZeroBudget(run.budgetReserved)) return undefined;
  const history = [...stopInvocationHistory(journal).values()];
  // A resource proof must remain true during drain. Unresolved external results can still change the
  // continuation/consumption; their owning reconciliation reducer must settle them first.
  if (history.some(({ entry, hasClaim }) => entry.phase !== 'completed' && (entry.phase !== 'failed' || hasClaim))) return undefined;
  const budgetCause = (required: BudgetUsage): ResourceCause | undefined => {
    for (const counter of ['modelTokens', 'costMicros', 'toolCalls'] as const) {
      const ceiling = spec.budgets[counter], consumed = run.budgetConsumed[counter], reserved = run.budgetReserved[counter];
      if (BigInt(consumed) + BigInt(reserved) + BigInt(required[counter]) > BigInt(ceiling)) {
        return { origin: 'budget', targetStatus: 'failed', reason: 'budget_exhausted', counter, ceiling, consumed, reserved, required: required[counter] };
      }
    }
    return undefined;
  };
  // Delivery has no model request, pricing, tool schema or context-compaction
  // admission. Select its actual frozen productive invocation before testing
  // the same complete budget counters as Agent Runs.
  if (spec.operation === 'delivery') {
    const limit = await readDeliveryMergeLimitCause(driver, artifacts, cut);
    if (limit) return { origin: 'runtime', targetStatus: 'failed', reason: 'runtime_failed',
      runtimeSubtype: 'delivery_merge_limit_exceeded', ...limit };
    const required = await readDeliveryPendingReservation(driver, artifacts, cut, observedAt);
    return required && budgetCause(required);
  }
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  if (assembly.mcpServers.length) return undefined;
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
  if (manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) throw new TypeError('resource tool manifest mismatch');
  const contracts = await artifacts.mapReads(manifest.entries, async (entry) => {
    const inputSchema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
    if (canonicalSha256(inputSchema) !== entry.inputSchemaDigest) throw new TypeError('resource tool schema mismatch');
    return { ...entry, inputSchema };
  });
  const allItems: ContextItem[] = await artifacts.mapReads(cut.items, async (row) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
  // Terminal drain adds only an undispatched suffix. Reconstruct the pre-drain call cut for its stop proof.
  const items = allItems.filter(({ item }) => item.kind !== 'tool_result' || item.outcome !== 'cancelled');
  const pending = openStopBatch(items.map(({ item }) => item));
  const lastItem = items.at(-1)?.item;
  if (lastItem?.kind === 'model_turn' && lastItem.stopReason === 'end') {
    // A completed final response requires no next model reservation or context
    // compaction. Its result limits are a separate immutable resource fact.
    return readFinalSourceLimit(driver, artifacts, cut, assembly, items, observedAt);
  }
  if (pending) {
    const callIdentity = pending.batch.calls[pending.next]!;
    const opId = toolOperationId(run.id, pending.batch.itemId, callIdentity.callId);
    // Refunding a pre-claim attempt restores this call's full capacity; it is not budget exhaustion.
    if (history.some(({ entry }) => entry.opId === opId)) return undefined;
    const call = await readCanonicalArtifact<ToolCallInputV1>(artifacts, callIdentity.inputRef);
    const entry = contracts.find((entry) => entry.name === call.toolName);
    if (!entry || entry.access === 'control' || call.disposition !== 'resolved') return undefined;
    const session = readSession(driver, run.sessionId);
    const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, spec.policyRef);
    const frontierRef = canonicalSha256({ schemaVersion: 1, kind: 'tool', batchItemId: pending.batch.itemId,
      orderedCallIds: pending.batch.calls.map((call) => call.callId), nextCallIndex: pending.next });
    const { request, target } = planToolRequest({ runId: run.id, frontierRef, batchItemId: pending.batch.itemId,
      assemblyRef: spec.assemblyRef, assembly, workspaceIdentityRef: session.workspaceIdentityRef,
      workspaceIdentityDigest: workspace.identityDigest, entry, call });
    const evaluator = loadToolPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
      principalId: workspace.ownerPrincipalId, workspaceIdentityRef: session.workspaceIdentityRef,
      workspaceIdentityDigest: workspace.identityDigest, contracts });
    const evidence = evaluator.evaluate(request, target, call, observedAt);
    const decision = items.map(({ item }) => item).filter((item) => item.kind === 'policy_decision' && item.opId === opId).at(-1);
    let approved = false;
    if (decision?.kind === 'policy_decision' && decision.decision === 'allow' && decision.decisionSource === 'interactive_approval') {
      const proof = await readToolApproval(driver, artifacts, run, evaluator, decision.decisionRef);
      if (!proof.grant) throw new TypeError('resource stop requires the retained allow decision');
      requireEqual(proof.request, request, 'resource approved tool request');
      requireEqual(canonicalSha256(proof.grant), decision.grantRef, 'resource approved tool grant');
      approved = proof.grant.issuedAt <= observedAt && proof.grant.expiresAt > observedAt;
    }
    if (evidence.effectiveDisposition === 'deny' || (evidence.effectiveDisposition === 'ask' && !approved)) return undefined;
    return budgetCause({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
  }
  if (items.length !== allItems.length) throw new TypeError('resource model stop has an unexpected cancelled call');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const systemInstruction = await loadInstructionText(artifacts, assembly);
  const tools = contracts.map((entry) => ({ name: entry.name, description: entry.description, inputSchemaRef: entry.inputSchemaRef,
    inputSchemaDigest: entry.inputSchemaDigest, inputSchema: entry.inputSchema, replayClass: entry.replayClass }));
  const project = (value: ContextManifest) => readModelContext({ artifacts, run, spec, assembly, context: value, systemInstruction, tools,
    sessionCompactionIndex: projection => frozenSessionCompactionIndex(driver, run.sessionId, projection.throughItemSeq) });
  const projection = await project(context);
  const envelopeRef = assembly.context.compactionPromptEnvelopeRef;
  const envelope = await readCanonicalArtifact<CompactionPromptEnvelopeV1>(artifacts, envelopeRef);
  const [system, prefix, suffix] = await joinResourceOperations([
    envelope.systemInstructionRef, envelope.userPrefixRef, envelope.userSuffixRef
  ].map(ref => readCanonicalArtifact<ModelTextV1>(artifacts, ref)));
  const compactionEnvelope = { ref: envelopeRef, value: envelope,
    systemInstruction: { ref: envelope.systemInstructionRef, value: system! },
    userPrefix: { ref: envelope.userPrefixRef, value: prefix! }, userSuffix: { ref: envelope.userSuffixRef, value: suffix! } };
  // Map insertion order is preparation order; late audit rows cannot select an older attempt.
  const latest = history.filter(({ entry }) => entry.opKind === 'model').at(-1)?.entry;
  if (latest) {
    const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, latest.requestRef);
    if (latest.phase === 'completed') {
      if (request.kind === 'context_compaction') {
        const plan = await readCanonicalArtifact<RunContextCompactionPlan>(artifacts, request.compactionPlanRef!);
        if (checkpoint.contextManifestRef === plan.sourceContextManifestRef) {
          const selection = planContextCompaction({ context, contextRef: checkpoint.contextManifestRef, items, projection,
            policy: assembly.context, provider: assembly.provider, compactionEnvelope, createdAt: plan.createdAt });
          if (selection.kind !== 'compact' || canonicalSha256(selection.plan) !== request.compactionPlanRef) throw new TypeError('failed compaction plan cannot be reproduced');
          const root = await readCanonicalArtifact<{ format: string }>(artifacts, latest.resultRef!);
          if (root.format === 'cliq-model-unusable-response-v1') {
            validateUnusableModelResponse(request, latest.requestRef, root as ModelUnusableResponseV1);
          } else {
            const material = await readModelTurnMaterial(artifacts, latest.resultRef!);
            validateModelTurn(request, material, () => { throw new TypeError('compaction cannot resolve tool calls'); });
            const replacement = replaceCompactedPrefix(context, plan, {
              itemId: identityHash('cliq-run-compaction-item-v1', run.id, latest.opId, String(latest.attempt)),
              summaryRef: material.turn.textRef, summaryDigest: material.text.textDigest });
            if (estimatePromptTokens(projectModelVisiblePrompt(await project(replacement), assembly.provider.negotiation.mode)) <
                estimatePromptTokens(projectModelVisiblePrompt(projection, assembly.provider.negotiation.mode))) throw new TypeError('a reducing compaction cannot prove resource failure');
          }
          return { origin: 'runtime', targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'context_compaction_failed',
            compactionPlanRef: request.compactionPlanRef!, modelOpId: latest.opId, attempt: latest.attempt };
        }
      } else {
        const result = await readCanonicalArtifact<{ format: string; stopReason?: string }>(artifacts, latest.resultRef!);
        if (result.format !== 'cliq-agent-model-turn-v1' || result.stopReason !== 'tool_calls') return undefined;
      }
    }
  }
  const selection = planContextCompaction({ context, contextRef: checkpoint.contextManifestRef, items, projection,
    policy: assembly.context, provider: assembly.provider, compactionEnvelope, createdAt: observedAt });
  if (selection.kind === 'exhausted') {
    const { contextManifestRef, nextPromptTokens, triggerThresholdTokens, hardPromptTokens, protectedTokens, sourceInputTokenCap } = selection.evidence;
    const cause = { origin: 'runtime' as const, targetStatus: 'failed' as const, reason: 'runtime_failed' as const,
      runtimeSubtype: 'context_window_exhausted' as const,
      contextManifestRef, nextPromptTokens, triggerThresholdTokens, hardPromptTokens, protectedTokens, sourceInputTokenCap };
    return 'trigger' in selection.evidence && selection.evidence.trigger === 'request_body_bytes' ? { ...cause, trigger: selection.evidence.trigger,
        modelVisiblePromptDigest: selection.evidence.modelVisiblePromptDigest, requestBodyBytes: selection.evidence.requestBodyBytes,
        requestBodyLimitBytes: selection.evidence.requestBodyLimitBytes } : cause;
  }
  const bound = assembly.provider.pricing;
  const output = selection.kind === 'compact' ? assembly.context.summaryTokenCap : assembly.context.reservedOutputTokens;
  let reservation;
  if (bound.kind === 'trusted_price_table') {
    const table = await readCanonicalArtifact<ModelPriceTableV1>(artifacts, bound.priceTableRef);
    requireEqual(priceTableDigest(table), bound.priceTableDigest, 'resource price table');
    reservation = createModelRequestReservation(assembly.context.contextLimitTokens, output, { kind: bound.kind, bound, table });
  } else {
    const provenance = await readCanonicalArtifact<LocalZeroCostProvenanceV1>(artifacts, bound.provenanceRef);
    requireEqual(digestOmitting(provenance, 'provenanceDigest'), provenance.provenanceDigest, 'resource zero-cost provenance');
    reservation = createModelRequestReservation(assembly.context.contextLimitTokens, output, { kind: bound.kind, bound, provenance });
  }
  return budgetCause({ modelTokens: reservation.modelTokens, costMicros: reservation.costMicros, toolCalls: 0, repairAttempts: 0 });
});

async function readDeliveryPendingReservation(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, observedAt: string): Promise<BudgetUsage | undefined> {
  assertDeliveryModelFreeCut(cut);
  const candidates = await artifacts.mapReads(cut.items, async row => ({ row,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) }));
  if (candidates.filter(({ item }) => item.kind === 'final_candidate').length !== 1) return undefined;
  // Publication requires its full ordered progress/physical closure. Until
  // that reader owns the cut, an approval or raw path result is deliberately
  // not promoted to a reproducible next-path capacity fact.
  if (await readDeliveryAuthorization(driver, artifacts, cut)) return undefined;
  const mode = await readDeliveryVerificationMode(driver, artifacts, cut);
  if (mode.kind === 'inherited') return undefined;
  const pending = await readVerifierPendingPolicy(driver, artifacts, cut, observedAt);
  if (!pending || pending.evidence.effectiveDisposition !== 'allow' ||
      pending.progress.entries.slice(0, pending.frontier.nextVerifierIndex).some(entry => !entry.disposition)) return undefined;
  const attempts = cut.journal.filter(entry => entry.opId === pending.planned.request.opId), last = attempts.at(-1);
  if (last && !(last.phase === 'completed' && pending.current.receipt?.outcome === 'infra_failed' &&
      pending.current.terminalJournal?.seq === last.seq && attempts.filter(entry => entry.phase === 'dispatch_claimed').length < pending.current.planEntry.maxAttempts))
    return undefined;
  if (pending.current.resultItem && pending.current.receipt?.outcome !== 'infra_failed') return undefined;
  return { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 };
}

/** Reproduce the original model continuation, not a later seal/terminal's
 * mutable latest pointer. No caught exception or caller count is evidence. */
async function readFinalSourceLimit(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'latestCheckpoint' | 'items' | 'journal'>,
  assembly: RunAssemblyV1, items: ContextItem[], observedAt: string): Promise<ResourceCause | undefined> {
  const { run, runSpec: spec, journal, latestCheckpoint: latest } = cut;
  const row = cut.items.at(-1)!, producer = items.at(-1)!.item, completed = journal.at(-1);
  if (spec.operation !== 'agent' || run.parentRunId || producer.kind !== 'model_turn' || producer.stopReason !== 'end' ||
      !exactKeys(producer, ['schemaVersion', 'itemId', 'runId', 'kind', 'modelOpId', 'modelAttempt', 'modelTurnRef', 'stopReason', 'textRef', 'createdAt']) ||
      !completed || completed.opKind !== 'model' || completed.phase !== 'completed' || !completed.resultRef || completed.receiptRef ||
      completed.opId !== producer.modelOpId || completed.attempt !== producer.modelAttempt || completed.resultRef !== producer.modelTurnRef ||
      row.itemId !== producer.itemId || row.itemSeq !== cut.items.length || row.payloadDigest !== row.payloadRef || producer.schemaVersion !== 1 ||
      row.payloadRef !== canonicalSha256(producer) || producer.runId !== run.id || producer.createdAt !== completed.timestamp ||
      row.createdAt !== completed.timestamp || completed.timestamp > observedAt)
    throw new TypeError('result resource failure has no exact final model producer');
  const prepared = readHighestPreparedAttempt(driver, run.id, completed.opId);
  if (!prepared || prepared.attempt !== completed.attempt || prepared.opKind !== 'model' || prepared.requestRef !== completed.requestRef)
    throw new TypeError('result resource failure does not own the highest final model attempt');
  const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, completed.requestRef);
  const material = await readModelTurnMaterial(artifacts, completed.resultRef);
  const noToolInput = () => { throw new TypeError('final result resource failure cannot resolve a tool call'); };
  validateModelTurn(request, material, noToolInput);
  if (request.kind !== 'normal' || request.compactionPlanRef !== undefined || request.runId !== run.id || request.opId !== completed.opId ||
      request.attempt !== completed.attempt || request.assemblyRef !== spec.assemblyRef || request.assemblyDigest !== assembly.assemblyDigest ||
      request.provider !== assembly.provider.name || request.model !== assembly.provider.model ||
      request.negotiatedMode !== assembly.provider.negotiation.mode || request.requestDigest !== digestOmitting(request, 'requestDigest') ||
      material.turn.stopReason !== 'end' || material.turn.toolCalls.length || material.inputs.length || !material.text.utf8.trim())
    throw new TypeError('result resource failure is not a usable final normal response');
  const projection = await readCanonicalArtifact<NormalPromptProjectionV1>(artifacts, request.promptProjectionRef);
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, projection.frontierDigest);
  if (!exactKeys(projection, ['schemaVersion', 'format', 'runId', 'basedOnRunRevision', 'frontierDigest', 'runSpecRef', 'assemblyRef',
      'assemblyDigest', 'contextManifestRef', 'contextManifestDigest', 'messages', 'tools', 'projectionDigest']) ||
      projection.schemaVersion !== 1 || projection.format !== 'cliq-normal-prompt-projection-v1' || projection.runId !== run.id || projection.runSpecRef !== run.specRef ||
      projection.assemblyRef !== spec.assemblyRef || projection.assemblyDigest !== assembly.assemblyDigest ||
      projection.projectionDigest !== request.promptProjectionDigest || projection.projectionDigest !== digestOmitting(projection, 'projectionDigest') ||
      !Number.isSafeInteger(projection.basedOnRunRevision) || projection.basedOnRunRevision < 1 ||
      !exactKeys(frontier, ['schemaVersion', 'kind', 'phase', 'turnId', 'contextItemSeq', 'cause']) ||
      frontier.schemaVersion !== 1 || frontier.kind !== 'agent' || frontier.phase !== 'model_turn' || frontier.compactionPlanRef !== undefined ||
      modelOperationId(run.id, frontier) !== completed.opId || run.frontierRef !== undefined && run.frontierRef !== projection.frontierDigest)
    throw new TypeError('result resource failure substitutes its original normal frontier');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, projection.contextManifestRef));
  if (context.projectionDigest !== projection.contextManifestDigest || context.throughItemSeq + 1 !== row.itemSeq || frontier.contextItemSeq !== context.throughItemSeq)
    throw new TypeError('result resource failure has a foreign pre-model context');
  validateContextItems(context, items.slice(0, -1));
  const continuation = planModelContinuation({ request, turnRef: completed.resultRef, material, throughItemSeq: context.throughItemSeq,
    createdAt: completed.timestamp, resolveToolInput: noToolInput });
  requireEqual(continuation.items, [producer], 'result resource final continuation');
  const post = structuredClone(context);
  post.segments.push({ kind: 'raw', fromItemSeq: row.itemSeq, throughItemSeq: row.itemSeq,
    items: [{ itemSeq: row.itemSeq, itemRef: row.payloadRef }] });
  post.throughItemSeq++;
  post.projectionDigest = digestOmitting(post, 'projectionDigest');
  const contextRef = canonicalSha256(post), sourceCheckpointId = identityHash('cliq-continuation-checkpoint-v1', run.id, completed.resultRef, contextRef);
  requireEqual(await readCanonicalArtifact(artifacts, contextRef), post, 'result resource original post-model context');
  validateContextItems(post, items);
  const checkpoint = readCheckpoint(driver, sourceCheckpointId);
  if (checkpoint.runId !== run.id || checkpoint.reason !== 'auto' || checkpoint.contextManifestRef !== contextRef ||
      checkpoint.runItemSeq !== row.itemSeq || checkpoint.journalSeq !== completed.seq || completed.seq !== journal.length ||
      checkpoint.createdAt !== completed.timestamp || checkpoint.basedOnRunRevision < 1 || checkpoint.basedOnRunRevision >= run.revision ||
      projection.basedOnRunRevision > checkpoint.basedOnRunRevision ||
      latest.contextManifestRef !== contextRef || latest.workspaceStateRef !== checkpoint.workspaceStateRef ||
      latest.runItemSeq !== row.itemSeq || latest.journalSeq !== completed.seq)
    throw new TypeError('result resource failure has no original accounted model Checkpoint');
  const limit = await readCandidateSourceLimit(artifacts, spec, checkpoint.workspaceStateRef);
  return limit ? { origin: 'runtime', targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'result_source_limit_exceeded',
    sourceCheckpointId, workspaceStateRef: checkpoint.workspaceStateRef, producingItemId: producer.itemId,
    modelOpId: completed.opId, attempt: completed.attempt, limitKind: limit.reason, observed: limit.observed, limit: limit.limit } : undefined;
}
