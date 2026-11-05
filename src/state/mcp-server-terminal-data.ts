// Pure terminal data. The live original scope or a genuine current cleanup
// owner must separately authorize every physical fact before using this plan.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeMcpServerLaunchReceipt, decodeMcpServerStoppedItem, decodeMcpServerInstanceIdentity, type McpServerInstanceIdentityV1,
  type McpServerLaunchReceiptV1 } from '../kernel/mcp-stdio.js';
import { decodeMcpServerLaunchFailure, decodeMcpServerFailedStoppedItem } from '../kernel/mcp-server-authorization.js';
import type { BudgetSettlementV1, InvocationJournalEntry, Run } from '../kernel/types.js';
import { addBudget, subtractBudget } from './invariants.js';
import { requireEqual } from '../policy/runtime-authority.js';

/** Data relation only. A writer must additionally recheck the exact original
 * whole Journal and never-claimed effect before preparing the new Stop cut. */
export function isMcpLocalStopAdvance(original: Run, current: Run): boolean {
  const stable = ({ revision: _revision, updatedAt: _updated, stopIntentRef: _stop, cancelRequested: _cancel, parentCancellationRef: _parent, ...rest }: Run) => rest;
  return current.revision > original.revision && current.updatedAt >= original.updatedAt &&
    current.cancelRequested && current.stopIntentRef !== undefined && canonicalSha256(stable(current)) === canonicalSha256(stable(original));
}

/** Pure failed-launch accounting only. The owning writer separately proves
 * the exact original joined no-spawn/death closure before using this data. */
export function mcpServerFailedLaunchData(input: Readonly<{
  failure: unknown; prepared: InvocationJournalEntry; claim?: InvocationJournalEntry;
  run: Pick<Run, 'id' | 'budgetConsumed' | 'budgetReserved'>; terminalSeq: number; settledAt: string;
}>) {
  const { prepared, claim, run } = input, failure = decodeMcpServerLaunchFailure(input.failure);
  requireEqual(prepared.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'MCP original failed launch reservation');
  if (prepared.phase !== 'prepared' || prepared.opKind !== 'mcp-server' || prepared.replayClass !== 'retry' ||
      prepared.runId !== run.id || failure.runId !== run.id || failure.launchOpId !== prepared.opId || failure.attempt !== prepared.attempt ||
      failure.preparedJournalSeq !== prepared.seq || failure.requestRef !== prepared.requestRef || failure.targetRef !== prepared.target || failure.grantRef !== prepared.grantRef ||
      !['not_initialized', 'setup_outcome_unavailable'].includes(failure.instance) || failure.disposition !== undefined || failure.reason === 'owning_call_unknown' ||
      !Number.isSafeInteger(input.terminalSeq) || input.terminalSeq <= (claim?.seq ?? prepared.seq) ||
      parseCanonicalTime(failure.stoppedAt) < parseCanonicalTime(claim?.timestamp ?? prepared.timestamp) ||
      parseCanonicalTime(input.settledAt) < parseCanonicalTime(failure.stoppedAt))
    throw new TypeError('MCP failed launch changes its original local preparation, branch or terminal order');
  if (claim) {
    for (const key of ['runId', 'opId', 'opKind', 'attempt', 'requestRef', 'target', 'grantRef', 'leaseEpoch', 'evidenceRef', 'evidenceDigest'] as const)
      if (claim[key] !== prepared[key]) throw new TypeError('MCP failed launch changes its original permanent claim');
    if (claim.phase !== 'dispatch_claimed' || failure.claimStatus !== undefined || failure.claimedJournalSeq !== claim.seq ||
        failure.dispatchId !== claim.dispatchId || failure.sandboxLaunchSpecRef !== claim.sandboxLaunchSpecRef || prepared.seq >= claim.seq)
      throw new TypeError('MCP failed launch has no matching original claim');
  } else if (failure.claimStatus !== 'not_claimed' || failure.closure !== 'plan_quiescent')
    throw new TypeError('MCP zero-charge failure requires its actual unclaimed no-spawn branch');
  const consumed = claim ? prepared.budgetDelta : { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  const core = { schemaVersion: 1 as const, format: 'cliq-budget-settlement-v1' as const, runId: run.id, opId: prepared.opId,
    attempt: prepared.attempt, preparedJournalSeq: prepared.seq, terminalJournalSeq: input.terminalSeq, terminalPhase: 'failed' as const,
    reserved: prepared.budgetDelta, consumed, released: prepared.budgetDelta, budgetConsumedBefore: run.budgetConsumed,
    budgetConsumedAfter: addBudget(run.budgetConsumed, consumed, 'MCP failed local launch charge'), budgetReservedBefore: run.budgetReserved,
    budgetReservedAfter: subtractBudget(run.budgetReserved, prepared.budgetDelta, 'MCP failed local launch reservation'), settledAt: input.settledAt };
  const settlement: BudgetSettlementV1 = { ...core, settlementDigest: canonicalSha256(core) };
  const failurePlan = planCanonicalArtifact(failure, failure.format), settlementPlan = planCanonicalArtifact(settlement, settlement.format);
  const terminal: InvocationJournalEntry = { ...(claim ?? prepared), seq: input.terminalSeq, phase: 'failed', budgetDelta: consumed,
    errorRef: failurePlan.ref, budgetSettlementRef: settlementPlan.ref, timestamp: input.settledAt };
  return { failure, failurePlan, settlement, settlementPlan, terminal };
}

export function mcpServerTerminalData(input: Readonly<{
  effect: BudgetSettlementV1; prepared: InvocationJournalEntry; claim: InvocationJournalEntry;
  instance: McpServerInstanceIdentityV1; instanceRef: string; deathRef: string; observedAt: string;
  nativeClosure: McpServerLaunchReceiptV1['nativeClosure']; disposition: 'completed' | 'owning_call_unknown';
}>) {
  const { effect, prepared, claim, instance, disposition } = input;
  decodeMcpServerInstanceIdentity(instance);
  requireEqual(prepared.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'MCP independent original local launch reservation');
  for (const usage of [effect.reserved, effect.consumed, effect.released]) requireEqual(usage, prepared.budgetDelta, 'MCP original owning effect full-once charge');
  requireEqual(effect.budgetConsumedAfter, addBudget(effect.budgetConsumedBefore, effect.consumed, 'MCP owning effect consumed budget'), 'MCP original owning effect budget sum');
  requireEqual(effect.budgetReservedAfter, subtractBudget(effect.budgetReservedBefore, effect.released, 'MCP owning effect reservation'), 'MCP original owning effect reservation sum');
  for (const key of ['requestRef', 'target', 'grantRef', 'leaseEpoch', 'evidenceRef', 'evidenceDigest'] as const)
    if (claim[key] !== prepared[key]) throw new TypeError('MCP local terminal changes its exact original prepared resource and permission roots');
  if (prepared.phase !== 'prepared' || prepared.opKind !== 'mcp-server' || prepared.replayClass !== 'retry' || claim.replayClass !== 'retry' ||
      claim.phase !== 'dispatch_claimed' || claim.opKind !== 'mcp-server' ||
      claim.runId !== prepared.runId || claim.opId !== prepared.opId || claim.attempt !== prepared.attempt || instance.runId !== effect.runId ||
      effect.runId !== prepared.runId || instance.launchOpId !== prepared.opId || instance.launchAttempt !== prepared.attempt ||
      instance.launchDispatchId !== claim.dispatchId || effect.terminalPhase !== (disposition === 'completed' ? 'completed' : 'unknown') ||
      prepared.seq >= claim.seq || claim.seq >= effect.terminalJournalSeq || effect.opId === prepared.opId ||
      input.observedAt > effect.settledAt || canonicalSha256(instance) !== input.instanceRef)
    throw new TypeError('MCP local terminal data changes its separate original launch/effect identities or terminal order');
  const terminalSeq = effect.terminalJournalSeq + 1;
  const settlementCore = { schemaVersion: 1 as const, format: 'cliq-budget-settlement-v1' as const, runId: effect.runId,
    opId: prepared.opId, attempt: prepared.attempt, preparedJournalSeq: prepared.seq, terminalJournalSeq: terminalSeq,
    terminalPhase: disposition === 'completed' ? 'completed' as const : 'failed' as const, reserved: prepared.budgetDelta,
    consumed: prepared.budgetDelta, released: prepared.budgetDelta, budgetConsumedBefore: effect.budgetConsumedAfter,
    budgetConsumedAfter: addBudget(effect.budgetConsumedAfter, prepared.budgetDelta, 'MCP separate local launch charge'), budgetReservedBefore: effect.budgetReservedAfter,
    budgetReservedAfter: subtractBudget(effect.budgetReservedAfter, prepared.budgetDelta, 'MCP separate local launch reservation'), settledAt: effect.settledAt };
  const settlement: BudgetSettlementV1 = { ...settlementCore, settlementDigest: canonicalSha256(settlementCore) };
  const settlementPlan = planCanonicalArtifact(settlement, settlement.format);
  const stoppedItemId = identityHash('cliq-mcp-server-stopped-item-v1', effect.runId, prepared.opId, prepared.attempt, claim.dispatchId);
  const receiptCore = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-receipt-v1' as const,
    instanceIdentityRef: input.instanceRef, instanceIdentityDigest: instance.identityDigest, preparedJournalSeq: prepared.seq, claimedJournalSeq: claim.seq,
    completedJournalSeq: terminalSeq, budgetSettlementRef: settlementPlan.ref, stoppedItemId, containmentDeathEvidenceRef: input.deathRef,
    stoppedAt: input.observedAt, nativeClosure: input.nativeClosure };
  const failureCore = { schemaVersion: 1 as const, format: 'cliq-mcp-server-launch-failure-v1' as const, runId: effect.runId,
    launchOpId: prepared.opId, attempt: prepared.attempt, preparedJournalSeq: prepared.seq, claimedJournalSeq: claim.seq,
    targetRef: prepared.target, requestRef: prepared.requestRef, grantRef: prepared.grantRef!, dispatchId: claim.dispatchId!,
    sandboxLaunchSpecRef: instance.sandboxLaunchSpecRef, nativeClosure: input.nativeClosure, stoppedAt: input.observedAt, instance: 'initialized' as const,
    instanceIdentityRef: input.instanceRef, instanceIdentityDigest: instance.identityDigest, closure: 'containment_dead' as const,
    processContainmentRef: instance.processContainmentRef, containmentDeathEvidenceRef: input.deathRef, reason: 'owning_call_unknown' as const, stoppedItemId };
  const value = disposition === 'completed' ? decodeMcpServerLaunchReceipt({ ...receiptCore, receiptDigest: canonicalSha256(receiptCore) })
    : decodeMcpServerLaunchFailure({ ...failureCore, failureDigest: canonicalSha256(failureCore) });
  const terminalPlan = planCanonicalArtifact(value, value.format);
  const stoppedBase = { schemaVersion: 1 as const, kind: 'mcp_server_stopped' as const, itemId: stoppedItemId, runId: effect.runId,
    batchItemId: instance.batchItemId, callId: instance.callId, callIndex: instance.callIndex, serverManifestRef: instance.registryRevisionRef,
    lifecycleSeq: instance.lifecycleSeq, launchOpId: instance.launchOpId, instanceIdentityRef: input.instanceRef, instanceIdentityDigest: instance.identityDigest,
    containmentEvidenceRef: input.deathRef, createdAt: input.observedAt };
  const stopped = value.format === 'cliq-mcp-server-launch-receipt-v1' ? decodeMcpServerStoppedItem({ ...stoppedBase,
    launchReceiptRef: terminalPlan.ref, launchReceiptDigest: value.receiptDigest, cause: 'normal' })
    : decodeMcpServerFailedStoppedItem({ ...stoppedBase, disposition: 'owning_call_unknown', launchFailureRef: terminalPlan.ref,
      launchFailureDigest: value.failureDigest, cause: 'lease_release' });
  return { settlement, settlementPlan, terminalPlan, terminalSeq, stoppedItemId, stopped, disposition };
}
