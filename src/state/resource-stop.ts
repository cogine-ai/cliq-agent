import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { BudgetUsage, ContextManifest, ContinuationItem, RecoveryClosureV1, RunAssemblyV1, RunContextCompactionPlan, ToolContractManifestV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, ToolOperationGrantV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1, ModelUnusableResponseV1 } from '../protocol/agent-ir.js';
import { createModelRequestReservation, priceTableDigest, type ModelPriceTableV1, type LocalZeroCostProvenanceV1 } from '../model/pricing.js';
import { estimatePromptTokens, projectModelVisiblePrompt, type ModelRequestV1 } from '../model/request.js';
import { loadToolPolicy, planToolRequest, toolOperationId } from '../policy/tool-policy.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { planContextCompaction, replaceCompactedPrefix, type ContextItem } from '../runtime/context-compaction.js';
import { validateModelTurn, validateUnusableModelResponse } from '../runtime/continuation.js';
import { openStopBatch, stopInvocationHistory, type ResourceStopIntent } from '../runtime/stop.js';
import { loadInstructionText, readCanonicalArtifact, readModelContext, readModelTurnMaterial } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeContextManifest, decodeWorkspaceIdentity } from './decoders.js';
import { isZeroBudget } from './invariants.js';
import { readSession } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

type WithoutIdentity<T> = T extends ResourceStopIntent ? Omit<T, 'schemaVersion' | 'runId' | 'createdAt'> : never;
type ResourceCause = WithoutIdentity<ResourceStopIntent>;

/** Reproduce deterministic resource failure from retained facts, not a caught error or caller reason. */
export async function readResourceStopCause(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: Pick<RecoveryClosureV1, 'run' | 'runSpec' | 'latestCheckpoint' | 'items' | 'journal'>, observedAt: string
): Promise<ResourceCause | undefined> {
  const { run, runSpec: spec, latestCheckpoint: checkpoint, journal } = cut;
  if (run.waitingReason || !isZeroBudget(run.budgetReserved)) return undefined;
  const history = [...stopInvocationHistory(journal).values()];
  // A resource proof must remain true during drain. Unresolved external results can still change the
  // continuation/consumption; their owning reconciliation reducer must settle them first.
  if (history.some(({ entry, hasClaim }) => entry.phase !== 'completed' && (entry.phase !== 'failed' || hasClaim))) return undefined;
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  if (assembly.mcpServers.length) return undefined;
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
  if (manifest.manifestDigest !== assembly.tools.manifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) throw new TypeError('resource tool manifest mismatch');
  const contracts = await Promise.all(manifest.entries.map(async (entry) => {
    const inputSchema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
    if (canonicalSha256(inputSchema) !== entry.inputSchemaDigest) throw new TypeError('resource tool schema mismatch');
    return { ...entry, inputSchema };
  }));
  const allItems: ContextItem[] = await Promise.all(cut.items.map(async (row) => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) })));
  // Terminal drain adds only an undispatched suffix. Reconstruct the pre-drain call cut for its stop proof.
  const items = allItems.filter(({ item }) => item.kind !== 'tool_result' || item.outcome !== 'cancelled');
  const pending = openStopBatch(items.map(({ item }) => item));
  const budgetCause = (required: BudgetUsage): ResourceCause | undefined => {
    for (const counter of ['modelTokens', 'costMicros', 'toolCalls'] as const) {
      const ceiling = spec.budgets[counter], consumed = run.budgetConsumed[counter], reserved = run.budgetReserved[counter];
      if (BigInt(consumed) + BigInt(reserved) + BigInt(required[counter]) > BigInt(ceiling)) {
        return { origin: 'budget', targetStatus: 'failed', reason: 'budget_exhausted', counter, ceiling, consumed, reserved, required: required[counter] };
      }
    }
    return undefined;
  };
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
      const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, decision.grantRef);
      approved = grant.requestRef === canonicalSha256(request) && grant.issuedAt <= observedAt && grant.expiresAt > observedAt;
    }
    if (evidence.effectiveDisposition === 'deny' || (evidence.effectiveDisposition === 'ask' && !approved)) return undefined;
    return budgetCause({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
  }
  if (items.length !== allItems.length) throw new TypeError('resource model stop has an unexpected cancelled call');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const systemInstruction = await loadInstructionText(artifacts, assembly);
  const tools = contracts.map((entry) => ({ name: entry.name, description: entry.description, inputSchemaRef: entry.inputSchemaRef,
    inputSchemaDigest: entry.inputSchemaDigest, inputSchema: entry.inputSchema, replayClass: entry.replayClass }));
  const project = (value: ContextManifest) => readModelContext({ artifacts, run, spec, assembly, context: value, systemInstruction, tools });
  const projection = await project(context);
  // Map insertion order is preparation order; late audit rows cannot select an older attempt.
  const latest = history.filter(({ entry }) => entry.opKind === 'model').at(-1)?.entry;
  if (latest) {
    const request = await readCanonicalArtifact<ModelRequestV1>(artifacts, latest.requestRef);
    if (latest.phase === 'completed') {
      if (request.kind === 'context_compaction') {
        const plan = await readCanonicalArtifact<RunContextCompactionPlan>(artifacts, request.compactionPlanRef!);
        if (checkpoint.contextManifestRef === plan.sourceContextManifestRef) {
          const selection = planContextCompaction({ context, contextRef: checkpoint.contextManifestRef, items, projection,
            policy: assembly.context, createdAt: plan.createdAt });
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
    policy: assembly.context, createdAt: observedAt });
  if (selection.kind === 'exhausted') {
    const { contextManifestRef, nextPromptTokens, triggerThresholdTokens, hardPromptTokens, protectedTokens, sourceInputTokenCap } = selection.evidence;
    return { origin: 'runtime', targetStatus: 'failed', reason: 'runtime_failed', runtimeSubtype: 'context_window_exhausted',
      contextManifestRef, nextPromptTokens, triggerThresholdTokens, hardPromptTokens, protectedTokens, sourceInputTokenCap };
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
}
