import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ChildAllocationV1, ContinuationItem, Run, RunFrontier, ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { AwaitChildrenResult, ChildMergeBatchItem, ChildResultItem, ChildWaitingSubject, ChildWaitSet } from '../kernel/children.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { decodeAwaitChildrenRequest } from '../tools/child-inputs.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import { readChildAdmission } from './child-admission.js';
import { assertChildAncestryRelease } from './child-ancestry.js';
import { readChildTerminalData } from './child-terminal.js';
import { prepareContinuationCommit } from './continuation-commit.js';
import { joinResourceOperations, KernelStorageError, stateOperation } from './errors.js';
import { addBudget, assertBudgetWithin, decodeChildAllocation, subtractBudget } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readCheckpoint, readRun, ZERO_BUDGET } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readToolCut, type ToolCut } from './tool-cut.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';
import type { RunAuthority } from './run-authority.js';
import { readAgentStop, readRetainedAgentStop } from './stop-recovery.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { decodeContextManifest } from './decoders.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { contextSourceDigest } from '../runtime/context-compaction.js';
import { prepareToolCheckpoint, type NativeWorkerRetirement } from './tool-checkpoint.js';
import type { ToolCheckpointProof } from '../kernel/tool-authorization.js';
import { planChildAwaitRegistration, CHILD_AWAIT_COST, childAwaitDispatchId, childAwaitIdempotencyKey } from './child-await-artifacts.js';
import { appendInvocationJournalEntry, nextJournalSequence } from './repositories/journal.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';
import { readChildAwaitModelResult } from './child-await-model.js';

type ChildSettlementCut = Pick<ToolCut, 'run' | 'runSpec' | 'checkpoint' | 'context' | 'items' | 'journal' | 'childAllocations'>;

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child wait ${message}`); }

function awaitSet(selected: ToolCut): ChildWaitSet {
  const call = decodeAwaitChildrenRequest(selected.call.value);
  return { schemaVersion: 1, parentRunId: selected.run.id, purpose: { kind: 'await_tool', awaitBatchItemId: selected.batch.itemId,
    awaitCallId: selected.call.callId, awaitCallIndex: selected.call.index }, childRunIds: call.childRunIds };
}
const waitCheckpointId = (runId: string, ref: string) => identityHash('cliq-child-wait-checkpoint-v1', runId, ref);
const resultId = (runId: string, childId: string) => identityHash('cliq-child-result-item-v1', runId, childId);

/** One owning Run's children, using its same ordinary continuation and
 * expected-revision transaction. A new explicit await registers one closed
 * local accounting triplet; wake/Stop/finalize never repeat that charge or
 * create a native grant, worker, execution attempt or child budget. */
export function loadChildWaitContinuation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  authority: RunAuthority['controlAuthority'], reobserve?: NativeWorkerRetirement) {
  const runId = authority.run.id;
  async function selectedAt(revision: number, reads = artifacts) {
    await authority.assertAuthority();
    const selected = await readToolCut(driver, reads, runId, authority.resolveToolInput);
    if (selected.run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'child wait Run revision changed');
    const contract = await reads.readCanonical<import('../kernel/types.js').ToolContractManifestV1>(authority.assembly.tools.manifestRef);
    const entry = contract.entries.find(entry => entry.name === selected.call.toolName);
    if (entry?.execution.kind !== 'supervisor_control' || entry.execution.handlerId !== 'await_children' ||
        selected.call.toolName !== 'await_children') invalid('does not have its exact signed control handler');
    if (selected.run.activeWorkerLaunchId || selected.workerLaunches.length ||
        !['queued', 'waiting'].includes(selected.run.status) || selected.run.cancelRequested || selected.run.stopIntentRef)
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child wait requires its original worker-free unstopped Run');
    return selected;
  }
  async function ownedSet(selected: ChildSettlementCut, set: ChildWaitSet, reads = artifacts) {
    const owned = await reads.mapReads(set.childRunIds, async childRunId => {
      const admitted = await readChildAdmission(driver, reads, childRunId);
      if (admitted.parent.id !== runId || !selected.items.some(row => row.item.kind === 'child_handle' &&
          row.item.childRunId === childRunId && row.itemRef === admitted.receipt.childHandleItemRef))
        invalid('names a foreign or unowned direct child handle');
      return admitted;
    });
    return { set, owned, setPlan: planCanonicalArtifact(set, 'cliq-child-wait-set-v1') };
  }
  function assertCut(connection: SqliteConnection, selected: ChildSettlementCut, now: string, stopping = false) {
    assertActiveStateOwner(connection, owner);
    requireEqual(readRun(connection, runId), selected.run, 'child wait original parent Run cut');
    requireEqual(readCheckpoint(connection, selected.checkpoint.id), selected.checkpoint, 'child wait original Checkpoint');
    requireEqual(readInvocationJournal(connection, runId), selected.journal, 'child wait original Journal');
    requireEqual(readChildAllocationsForRun(connection, runId), selected.childAllocations, 'child wait original allocation cut');
    if (!stopping && now >= selected.run.deadlineAt || connection.prepare("SELECT 1 FROM worker_launches WHERE run_id=? AND phase!='retired' LIMIT 1").get(runId))
      throw new KernelStorageError('LEASE_FENCED', 'child wait retained an original worker or passed its deadline');
    if (!stopping) assertChildAncestryRelease(connection, runId, now);
  }
  async function prepareAwaitRegistration(selected: ChildSettlementCut, set: ChildWaitSet, checkpointId: string, preparedAt: string, reads: ArtifactCatalog) {
    if (set.purpose.kind !== 'await_tool' || selected.run.status !== 'queued') invalid('new await accounting requires its original productive provider call');
    const purpose = set.purpose, batch = selected.items.find(row => row.item.itemId === purpose.awaitBatchItemId)?.item;
    if (batch?.kind !== 'assistant_tool_batch') invalid('await registration lost its actual assistant batch');
    const call = batch.calls[purpose.awaitCallIndex];
    if (!call || call.callId !== purpose.awaitCallId || call.toolName !== 'await_children') invalid('await registration changed its normalized call identity');
    const normalized = await reads.readCanonical<import('../protocol/agent-ir.js').ToolCallInputV1>(call.inputRef);
    requireEqual(decodeAwaitChildrenRequest(normalized.value).childRunIds, set.childRunIds, 'await registration exact supplied handle order');
    const manifest = await reads.readCanonical<import('../kernel/types.js').ToolContractManifestV1>(authority.assembly.tools.manifestRef),
      entry = manifest.entries.find(entry => entry.name === 'await_children');
    if (entry?.execution.kind !== 'supervisor_control' || entry.execution.handlerId !== 'await_children') invalid('await registration has no signed control contract');
    const active = assertActiveStateOwner(driver, owner), sequence = nextJournalSequence(driver, runId);
    const planned = planChildAwaitRegistration({ run: selected.run, assemblyRef: selected.runSpec.assemblyRef, execution: entry.execution,
      batchItemId: batch.itemId, callId: call.callId, callIndex: purpose.awaitCallIndex, inputRef: call.inputRef, inputDigest: call.inputDigest,
      waitSetRef: canonicalSha256(set), checkpointId, journalSeq: sequence, inspector: supervisorInspectorIdentity(active), preparedAt });
    if (selected.journal.some(row => row.opId === planned.opId)) invalid('explicit await registration was already committed');
    assertBudgetWithin(planned.consumed, selected.run.budgetReserved, ZERO_BUDGET, selected.runSpec.budgets);
    const metadata = await joinResourceOperations(planned.plans.map(plan => reads.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)));
    let used = false;
    return { metadata, consumed: planned.consumed, journalSeq: sequence + 2, commit(connection: SqliteConnection, committedAt: string) {
      if (used) invalid('await registration accounting was used twice');
      requireEqual(assertActiveStateOwner(connection, owner), active, 'await registration actual original Supervisor owner');
      assertCut(connection, selected, committedAt);
      if (committedAt < preparedAt || sequence !== nextJournalSequence(connection, runId)) invalid('await registration commit changed its original cut');
      assertBudgetWithin(planned.consumed, selected.run.budgetReserved, ZERO_BUDGET, selected.runSpec.budgets);
      const common = { runId, opId: planned.opId, opKind: 'child_await' as const, attempt: 0, leaseEpoch: 0,
        target: planned.targetPlan.ref, requestRef: planned.requestPlan.ref, replayClass: 'retry' as const,
        idempotencyKey: childAwaitIdempotencyKey(runId, planned.opId), timestamp: preparedAt, localCommittedAt: committedAt },
        claim = { dispatchId: childAwaitDispatchId(runId, planned.opId, planned.requestPlan.ref),
          stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId };
      appendInvocationJournalEntry(connection, { ...common, seq: sequence, phase: 'prepared', budgetDelta: CHILD_AWAIT_COST });
      appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 1, phase: 'dispatch_claimed', budgetDelta: ZERO_BUDGET });
      appendInvocationJournalEntry(connection, { ...common, ...claim, seq: sequence + 2, phase: 'completed', budgetDelta: CHILD_AWAIT_COST,
        resultRef: planned.receiptPlan.ref, budgetSettlementRef: planned.settlementPlan.ref });
      used = true;
    } };
  }
  async function complete(selected: ChildSettlementCut, set: ChildWaitSet, reads = artifacts, registerAwait = false) {
    const purpose = set.purpose, stopping = purpose.kind === 'stop_settlement';
    if (stopping) {
      const closure = await readRecoveryClosure(driver, reads, runId);
      requireEqual(closure.run, selected.run, 'child Stop settlement original parent cut');
      await readRetainedAgentStop(driver, reads, closure, purpose.stopIntentRef);
    }
    const { owned, setPlan } = await ownedSet(selected, set, reads);
    if (owned.some(child => child.allocation.state === 'reserved')) return undefined;
    const terminals = await reads.mapReads(owned, child => readChildTerminalData(driver, reads, child.run.id));
    const createdAt = sampleCanonicalNow(), added: ChildResultItem[] = [];
    const checkpointId = identityHash('cliq-child-settlement-checkpoint-v1', runId, setPlan.ref),
      registration = registerAwait ? await prepareAwaitRegistration(selected, set, checkpointId, createdAt, reads) : undefined;
    const allResults: ChildResultItem[] = [], settled: ChildAllocationV1[] = [];
    let consumed = { ...(registration?.consumed ?? selected.run.budgetConsumed) }, reserved = { ...selected.run.budgetReserved };
    for (const terminal of terminals) {
      const row = terminal.allocation;
      if (row.state === 'settled') {
        const original = selected.items.find(entry => entry.item.itemId === row.childResultItemId)?.item;
        if (!original || original.kind !== 'child_result' || original.childRunId !== row.childRunId ||
            original.delivery.kind === 'stop_settlement') invalid('reread lost its original model-visible child result');
        allResults.push(original);
        continue;
      }
      const result: ChildResultItem = { schemaVersion: 1, kind: 'child_result', itemId: resultId(runId, row.childRunId), runId,
        delivery: purpose.kind === 'stop_settlement' ? { kind: 'stop_settlement', stopIntentRef: purpose.stopIntentRef, waitSetRef: setPlan.ref }
          : { ...purpose, waitSetRef: setPlan.ref }, childRunId: row.childRunId,
        inclusiveBudgetUsage: row.inclusiveBudgetUsage, ...row.terminal, createdAt };
      allResults.push(result); added.push(result);
      consumed = addBudget(consumed, row.inclusiveBudgetUsage);
      reserved = subtractBudget(reserved, row.grantedAdditiveCeilings);
      const settlement: ChildAllocationV1 = { ...row, state: 'settled', childResultItemId: result.itemId,
        parentSettlementRevision: selected.run.revision + 1,
        releasedUnusedBudget: subtractBudget(row.grantedAdditiveCeilings, row.inclusiveBudgetUsage), settledAt: createdAt };
      decodeChildAllocation(settlement); settled.push(settlement);
    }
    assertBudgetWithin(consumed, reserved, ZERO_BUDGET, selected.runSpec.budgets);
    const patches = (stopping ? [] : added).filter((item): item is ChildResultItem & { mode: 'mutating'; status: 'succeeded' | 'completed_unverified'; patchManifestRef: string } =>
      item.mode === 'mutating' && (item.status === 'succeeded' || item.status === 'completed_unverified'));
    const items: ContinuationItem[] = [...added];
    let frontier: RunFrontier;
    const extra = [setPlan];
    if (patches.length) {
      if (purpose.kind === 'stop_settlement') invalid('Stop settlement cannot create a merge');
      const merge: ChildMergeBatchItem = { schemaVersion: 1, kind: 'child_merge_batch',
        itemId: identityHash('cliq-child-merge-batch-v1', runId, setPlan.ref), runId,
        resume: purpose.kind === 'await_tool' ? { kind: 'await_tool', batchItemId: purpose.awaitBatchItemId, callId: purpose.awaitCallId, callIndex: purpose.awaitCallIndex }
          : { kind: 'finalize_settlement', modelTurnItemId: purpose.modelTurnItemId },
        childResultItemIds: allResults.map(item => item.itemId), calls: patches.map((item, index) => ({ index,
          callId: identityHash('cliq-child-merge-call-v1', runId, setPlan.ref, item.childRunId), childRunId: item.childRunId,
          patchManifestRef: item.patchManifestRef,
          admittedForkBaseRef: terminals.find(terminal => terminal.run.id === item.childRunId)!.spec.baseWorkspaceManifestRef })), createdAt };
      items.push(merge); frontier = { schemaVersion: 1, kind: 'tool', batchItemId: merge.itemId,
        orderedCallIds: merge.calls.map(call => call.callId), nextCallIndex: 0 };
    } else if (purpose.kind === 'stop_settlement') {
      // Accounting/audit only: do not merge patches, answer an await call or
      // create a productive model frontier while its owning Stop is active.
      frontier = await readCanonicalArtifact<RunFrontier>(reads, selected.run.frontierRef!);
    } else if (purpose.kind === 'finalize_settlement') {
      frontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
        turnId: identityHash('cliq-child-results-turn-v1', runId, setPlan.ref),
        contextItemSeq: selected.context.throughItemSeq + items.length, cause: 'child_results' };
    } else {
      const batch = selected.items.find(row => row.item.itemId === purpose.awaitBatchItemId)?.item;
      if (batch?.kind !== 'assistant_tool_batch') invalid('lost its original provider await batch');
      const result: AwaitChildrenResult = await readChildAwaitModelResult(reads, allResults);
      const content: ToolResultModelContentV1 = { schemaVersion: 1, format: 'cliq-tool-result-model-content-v1',
        callId: purpose.awaitCallId, index: purpose.awaitCallIndex, toolName: 'await_children', outcome: 'executed', content: result, contentDigest: '' };
      content.contentDigest = digestOmitting(content, 'contentDigest');
      const contentPlan = planCanonicalArtifact(content, content.format);
      const payload: ToolResultPayloadV1 = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId, batchItemId: purpose.awaitBatchItemId,
        callId: purpose.awaitCallId, index: purpose.awaitCallIndex, toolName: 'await_children', outcome: 'executed', source: 'child_results',
        waitSetRef: setPlan.ref, childResultItemRefs: allResults.map(item => canonicalSha256(item)),
        modelContentRef: contentPlan.ref, modelContentDigest: content.contentDigest, payloadDigest: '' };
      payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
      const payloadPlan = planCanonicalArtifact(payload, payload.format); extra.push(contentPlan, payloadPlan);
      const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result', itemId: identityHash('cliq-tool-result-item-v1', runId,
        purpose.awaitBatchItemId, purpose.awaitCallId), runId, batchItemId: purpose.awaitBatchItemId, callId: purpose.awaitCallId,
        index: purpose.awaitCallIndex, outcome: 'executed', resultRef: payloadPlan.ref, createdAt };
      items.push(item);
      frontier = purpose.awaitCallIndex + 1 < batch.calls.length
        ? { schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId, orderedCallIds: batch.calls.map(call => call.callId), nextCallIndex: purpose.awaitCallIndex + 1 }
        : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', runId, purpose.awaitBatchItemId),
          contextItemSeq: selected.context.throughItemSeq + items.length, cause: 'child_results' };
    }
    const graph = await prepareContinuationCommit(reads, { context: selected.context, existingItems: selected.items, items, frontier,
      checkpointId,
      workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: extra });
    let outcome: TimeFenceAdvance | undefined, updated!: Run;
    driver.transaction(connection => {
      const now = sampleCanonicalNow(); assertCut(connection, selected, now, stopping);
      outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
      for (const terminal of terminals) terminal.assertUnchanged(connection);
      for (const metadata of [...(registration?.metadata ?? []), ...graph.metadata]) insertArtifactMetadata(connection, metadata, createdAt);
      const committedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt); if (outcome !== 'healthy') return;
      assertCut(connection, selected, committedAt, stopping);
      if (committedAt < createdAt) invalid('settlement commit predates its preparation');
      registration?.commit(connection, committedAt);
      for (const row of settled) {
        // The immutable artifact's preparedAt remains P; the actual settlement
        // timestamp is C and is never borrowed as a new grant or expiry.
        const final = { ...row, settledAt: committedAt }; decodeChildAllocation(final);
        connection.prepare('UPDATE child_allocations SET state=?,row_json=? WHERE parent_run_id=? AND child_run_id=?')
          .run('settled', JSON.stringify(final), runId, row.childRunId);
      }
      graph.commit(connection, selected.run, registration?.journalSeq ?? selected.journal.at(-1)?.seq ?? 0, committedAt);
      connection.prepare(`UPDATE runs SET status='queued',waiting_reason=NULL,waiting_on_ref=NULL,budget_reserved_json=?,
        budget_consumed_json=?,revision=revision+1,updated_at=? WHERE id=?`)
        .run(JSON.stringify(reserved), JSON.stringify(consumed), committedAt, runId);
      updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
    });
    requireHealthyFence(outcome); return immutableSnapshot({ run: updated });
  }
  async function settlementCut(revision: number, reads = artifacts): Promise<ChildSettlementCut> {
    await authority.assertAuthority();
    const closure = await readRecoveryClosure(driver, reads, runId);
    if (closure.run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'child settlement Run changed');
    const items = await reads.mapReads(closure.items, async row => ({ itemSeq: row.itemSeq, itemRef: row.payloadRef,
      item: await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef) }));
    const context = decodeContextManifest(await readCanonicalArtifact(reads, closure.latestCheckpoint.contextManifestRef));
    validateContextItems(context, items);
    return { ...closure, checkpoint: closure.latestCheckpoint, context, items };
  }
  async function stopSelection(revision: number, reads = artifacts) {
    const selected = await settlementCut(revision, reads);
    const children = selected.childAllocations.filter(row => row.parentRunId === runId && row.state !== 'settled');
    if (!children.length) invalid('Stop wait has no unsettled owned children');
    if (!selected.run.stopIntentRef || !['queued', 'running', 'waiting'].includes(selected.run.status))
      invalid('Stop wait requires its actually registered StopIntent');
    const closure = await readRecoveryClosure(driver, reads, runId);
    requireEqual(closure.run, selected.run, 'child Stop exact parent recovery cut');
    const intent = await readAgentStop(driver, reads, closure);
    let awaitOrigin: { batchItemId: string; callId: string; callIndex: number } | undefined;
    if (selected.run.waitingReason === 'child' && selected.run.waitingOnRef) {
      const original = await readCanonicalArtifact<ChildWaitingSubject>(reads, selected.run.waitingOnRef);
      if (original.subject.kind === 'await_tool') awaitOrigin = { batchItemId: original.subject.awaitBatchItemId,
        callId: original.subject.awaitCallId, callIndex: original.subject.awaitCallIndex };
      else if (original.subject.kind === 'stop_settlement') awaitOrigin = original.subject.awaitOrigin;
    }
    const set: ChildWaitSet = { schemaVersion: 1, parentRunId: runId,
      purpose: { kind: 'stop_settlement', stopIntentRef: selected.run.stopIntentRef,
        ...(selected.run.waitingReason === 'child' && selected.run.waitingOnRef ? { interruptedWaitRef: selected.run.waitingOnRef } : {}),
        ...(awaitOrigin ? { awaitOrigin } : {}) },
      childRunIds: children.map(child => child.childRunId).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))) };
    return { selected, intent, set, checkpointId: identityHash('cliq-child-stop-wait-checkpoint-v1', runId, canonicalSha256(set)) };
  }
  async function finalSelection(revision: number, reads = artifacts, allowStoppedCompletion = false) {
    const selected = await settlementCut(revision, reads);
    const children = selected.childAllocations.filter(row => row.parentRunId === runId && row.state !== 'settled');
    if (!children.length) return undefined;
    const producer = selected.items.at(-1)?.item;
    if (selected.run.status !== 'running' || selected.run.nextStep !== 'agent' || !selected.run.frontierRef ||
        !selected.run.activeWorkerLaunchId || !allowStoppedCompletion && (selected.run.stopIntentRef || selected.run.cancelRequested) ||
        producer?.kind !== 'model_turn' || producer.stopReason !== 'end' || selected.checkpoint.runItemSeq !== selected.items.length)
      invalid('final child settlement has no original complete final turn and live parent');
    const last = new Map<string, typeof selected.journal[number]>();
    for (const row of selected.journal) last.set(`${row.opId}:${row.attempt}`, row);
    if ([...last.values()].some(row => !['completed', 'failed'].includes(row.phase)))
      invalid('final child selection cannot overtake original unresolved work');
    const set: ChildWaitSet = { schemaVersion: 1, parentRunId: runId,
      purpose: { kind: 'finalize_settlement', modelTurnItemId: producer.itemId },
      childRunIds: children.map(child => child.childRunId).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))) };
    return { selected, producer, set, checkpointId: identityHash('cliq-child-final-wait-checkpoint-v1', runId, canonicalSha256(set)) };
  }
  return {
    planStoppedChildren: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }, signal?: AbortSignal) => {
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('child Stop selection accepts only its original Run revision');
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
      const selected = await settlementCut(input.expectedRunRevision, reads);
      if (!selected.childAllocations.some(row => row.parentRunId === runId && row.state !== 'settled'))
        return immutableSnapshot({ disposition: 'terminal' as const });
      const planned = await stopSelection(input.expectedRunRevision, reads);
      if (selected.run.waitingReason === 'child' && selected.run.waitingOnRef) {
        const subject = await readCanonicalArtifact<ChildWaitingSubject>(reads, selected.run.waitingOnRef);
        if (subject.subject.kind === 'stop_settlement') return immutableSnapshot({ disposition: 'child_stop_waiting' as const, run: selected.run });
      }
      return immutableSnapshot({ disposition: 'child_stop_required' as const, run: selected.run, checkpointId: planned.checkpointId });
    }),
    waitForStoppedChildren: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; checkpoint?: ToolCheckpointProof }, signal?: AbortSignal) => {
      if (!exactKeys(input, ['expectedRunRevision', ...(input.checkpoint ? ['checkpoint'] : [])])) throw new TypeError('child Stop wait accepts only original retirement proof');
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
      const { selected, intent, set, checkpointId } = await stopSelection(input.expectedRunRevision, reads);
      const { setPlan, owned } = await ownedSet(selected, set, reads), createdAt = sampleCanonicalNow();
      const subject: ChildWaitingSubject = { schemaVersion: 1, kind: 'child', runId, createdFromRevision: selected.run.revision,
        createdAt, frontierRef: selected.run.frontierRef!, subject: { ...set.purpose, waitSetRef: setPlan.ref } };
      const subjectPlan = planCanonicalArtifact(subject, 'cliq-waiting-subject-v1');
      const frontier = await readCanonicalArtifact<RunFrontier>(reads, selected.run.frontierRef!);
      const graph = await prepareContinuationCommit(reads, { context: selected.context, existingItems: selected.items, items: [], frontier,
        checkpointId, workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [setPlan, subjectPlan] });
      if (selected.run.activeWorkerLaunchId === undefined && input.checkpoint !== undefined) invalid('worker-free Stop wait cannot substitute a physical proof');
      if (selected.run.activeWorkerLaunchId !== undefined && input.checkpoint === undefined) invalid('Stop wait requires its original parent worker retirement');
      const seal = input.checkpoint === undefined ? undefined : await prepareToolCheckpoint(driver, reads, owner,
        { run: selected.run, spec: selected.runSpec, assembly: authority.assembly, checkpointId, observedAt: intent.createdAt,
          postEffect: input.checkpoint }, reobserve);
      await seal?.refresh(); reads.assertReadActive();
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      const check = (connection: SqliteConnection) => {
        assertActiveStateOwner(connection, owner);
        requireEqual(readRun(connection, runId), selected.run, 'child Stop original Run cut');
        requireEqual(readCheckpoint(connection, selected.checkpoint.id), selected.checkpoint, 'child Stop original Checkpoint');
        requireEqual(readInvocationJournal(connection, runId), selected.journal, 'child Stop original Journal');
        requireEqual(readChildAllocationsForRun(connection, runId), selected.childAllocations, 'child Stop original allocation cut');
        for (const child of owned) child.assertUnchanged(connection);
        if (!seal && connection.prepare("SELECT 1 FROM worker_launches WHERE run_id=? AND phase!='retired' LIMIT 1").get(runId))
          invalid('Stop wait retained an unretired original worker');
      };
      driver.transaction(connection => {
        check(connection);
        const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        for (const metadata of [...graph.metadata, ...(seal?.metadata ?? [])]) insertArtifactMetadata(connection, metadata, createdAt);
        const committedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt); if (outcome !== 'healthy') return;
        check(connection); if (committedAt < createdAt) invalid('Stop wait commit predates preparation');
        seal?.commit(connection, selected.run, committedAt); graph.commit(connection, selected.run, selected.journal.at(-1)?.seq ?? 0, committedAt);
        connection.prepare("UPDATE runs SET status='waiting',waiting_reason='child',waiting_on_ref=?,active_worker_launch_id=NULL,revision=revision+1,updated_at=? WHERE id=?")
          .run(subjectPlan.ref, committedAt, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
      });
      requireHealthyFence(outcome); return immutableSnapshot({ run: updated });
    }),
    planFinalChildren: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }, signal?: AbortSignal) => {
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('child final selection accepts only its current expected revision');
      const planned = await finalSelection(input.expectedRunRevision, signal ? artifacts.withReadSignal(signal) : artifacts);
      return planned ? immutableSnapshot({ disposition: 'child_final_required' as const, run: planned.selected.run, checkpointId: planned.checkpointId })
        : immutableSnapshot({ disposition: 'candidate' as const });
    }),
    waitForFinalChildren: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number; checkpoint: ToolCheckpointProof }, signal?: AbortSignal) => {
      if (!exactKeys(input, ['expectedRunRevision', 'checkpoint'])) throw new TypeError('child final wait accepts only original retirement proof');
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts, planned = await finalSelection(input.expectedRunRevision, reads, true);
      if (!planned) invalid('final child selection no longer has outstanding owned children');
      const { selected, producer, set, checkpointId } = planned;
      if (selected.run.stopIntentRef) {
        const closure = await readRecoveryClosure(driver, reads, runId);
        requireEqual(closure.run, selected.run, 'final completion original Stop cut');
        if ((await readAgentStop(driver, reads, closure)).createdAt < producer.createdAt) invalid('final model result was produced after its Stop');
      }
      if (input.checkpoint.workspaceStateRef !== selected.checkpoint.workspaceStateRef) invalid('final child wait changed its original ready workspace');
      const { setPlan, owned } = await ownedSet(selected, set, reads), createdAt = sampleCanonicalNow();
      const subject: ChildWaitingSubject = { schemaVersion: 1, kind: 'child', runId, createdFromRevision: selected.run.revision,
        createdAt, frontierRef: selected.run.frontierRef!, subject: { kind: 'finalize_settlement', waitSetRef: setPlan.ref, modelTurnItemId: producer.itemId,
          ...(selected.run.stopIntentRef ? { observedStopIntentRef: selected.run.stopIntentRef } : {}) } };
      const subjectPlan = planCanonicalArtifact(subject, 'cliq-waiting-subject-v1');
      const context = structuredClone(selected.context), last = context.segments.at(-1), source = selected.items.at(-1)!;
      if (last?.kind !== 'raw' || last.fromItemSeq !== source.itemSeq || last.throughItemSeq !== source.itemSeq ||
          last.items.length !== 1 || last.items[0]!.itemRef !== source.itemRef) invalid('premature final text lost its exact original context segment');
      context.segments[context.segments.length - 1] = { kind: 'excluded_control', fromItemSeq: source.itemSeq,
        throughItemSeq: source.itemSeq, sourceItemsDigest: contextSourceDigest([source]) };
      context.projectionDigest = digestOmitting(context, 'projectionDigest');
      const frontier = await readCanonicalArtifact<RunFrontier>(reads, selected.run.frontierRef!);
      const graph = await prepareContinuationCommit(reads, { context, existingItems: selected.items, items: [], frontier,
        checkpointId, workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [setPlan, subjectPlan] });
      const seal = await prepareToolCheckpoint(driver, reads, owner, { run: selected.run, spec: selected.runSpec,
        assembly: authority.assembly, checkpointId, observedAt: producer.createdAt, postEffect: input.checkpoint }, reobserve);
      await seal.refresh(); reads.assertReadActive();
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      const assertSelected = (connection: SqliteConnection) => {
        assertActiveStateOwner(connection, owner);
        requireEqual(readRun(connection, runId), selected.run, 'final child original parent Run');
        requireEqual(readCheckpoint(connection, selected.checkpoint.id), selected.checkpoint, 'final child original Checkpoint');
        requireEqual(readInvocationJournal(connection, runId), selected.journal, 'final child original settled Journal');
        requireEqual(readChildAllocationsForRun(connection, runId), selected.childAllocations, 'final child original outstanding allocation cut');
        for (const child of owned) child.assertUnchanged(connection);
      };
      driver.transaction(connection => {
        assertSelected(connection);
        const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        for (const metadata of [...graph.metadata, ...seal.metadata]) insertArtifactMetadata(connection, metadata, createdAt);
        const committedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt); if (outcome !== 'healthy') return;
        assertSelected(connection); if (!selected.run.stopIntentRef) assertChildAncestryRelease(connection, runId, committedAt);
        if (committedAt < createdAt || !selected.run.stopIntentRef && committedAt >= selected.run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'final child wait passed its original deadline');
        seal.commit(connection, selected.run, committedAt); graph.commit(connection, selected.run, selected.journal.at(-1)?.seq ?? 0, committedAt);
        connection.prepare("UPDATE runs SET status='waiting',waiting_reason='child',waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=?")
          .run(subjectPlan.ref, committedAt, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
      });
      requireHealthyFence(outcome); return immutableSnapshot({ run: updated });
    }),
    async plan(selected: ToolCut) {
      await authority.assertAuthority();
      const { setPlan } = await ownedSet(selected, awaitSet(selected));
      return immutableSnapshot({ disposition: 'children_required' as const, run: selected.run, waitSetRef: setPlan.ref });
    },
    waitForChildren: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }, signal?: AbortSignal) => {
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('child wait accepts only its original expected revision');
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
      const selected = await selectedAt(input.expectedRunRevision, reads);
      if (selected.run.status !== 'queued') throw new KernelStorageError('STATE_TRANSITION_INVALID', 'new child wait requires a queued parent');
      const completed = await complete(selected, awaitSet(selected), reads, true); if (completed) return completed;
      const { setPlan, owned } = await ownedSet(selected, awaitSet(selected), reads), createdAt = sampleCanonicalNow();
      const subject: ChildWaitingSubject = { schemaVersion: 1, kind: 'child', runId, createdFromRevision: selected.run.revision,
        createdAt, frontierRef: selected.run.frontierRef!, subject: { kind: 'await_tool', waitSetRef: setPlan.ref,
          awaitBatchItemId: selected.batch.itemId, awaitCallId: selected.call.callId, awaitCallIndex: selected.call.index } };
      const subjectPlan = planCanonicalArtifact(subject, 'cliq-waiting-subject-v1');
      const registration = await prepareAwaitRegistration(selected, awaitSet(selected), waitCheckpointId(runId, subjectPlan.ref), createdAt, reads);
      const graph = await prepareContinuationCommit(reads, { context: selected.context, existingItems: selected.items, items: [],
        frontier: selected.frontier, checkpointId: waitCheckpointId(runId, subjectPlan.ref),
        workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [setPlan, subjectPlan] });
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      driver.transaction(connection => {
        const now = sampleCanonicalNow(); assertCut(connection, selected, now);
        outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
        for (const child of owned) child.assertUnchanged(connection);
        for (const metadata of [...registration.metadata, ...graph.metadata]) insertArtifactMetadata(connection, metadata, createdAt);
        const committedAt = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, committedAt); if (outcome !== 'healthy') return;
        assertCut(connection, selected, committedAt); if (committedAt < createdAt) invalid('wait commit predates its preparation');
        registration.commit(connection, committedAt);
        graph.commit(connection, selected.run, registration.journalSeq, committedAt);
        connection.prepare("UPDATE runs SET status='waiting',waiting_reason='child',waiting_on_ref=?,budget_consumed_json=?,revision=revision+1,updated_at=? WHERE id=?")
          .run(subjectPlan.ref, JSON.stringify(registration.consumed), committedAt, runId);
        updated = readRun(connection, runId); appendRunStateEvent(connection, updated, committedAt);
      });
      requireHealthyFence(outcome); return immutableSnapshot({ run: updated });
    }),
    settleChildren: stateOperation('INVALID_REQUEST', async (input: { expectedRunRevision: number }, signal?: AbortSignal) => {
      if (!exactKeys(input, ['expectedRunRevision'])) throw new TypeError('child settlement accepts only its original expected revision');
      const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
      const current = readRun(driver, runId);
      if (current.revision !== input.expectedRunRevision || current.status !== 'waiting' || current.waitingReason !== 'child' || !current.waitingOnRef)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child wake requires its original exact wait');
      const originalSubject = await readCanonicalArtifact<ChildWaitingSubject>(reads, current.waitingOnRef);
      if (current.stopIntentRef && originalSubject.subject.kind !== 'stop_settlement')
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'registered Stop requires the original Stop child settlement transition');
      if (originalSubject.subject.kind === 'stop_settlement') {
        const selected = await settlementCut(input.expectedRunRevision, reads);
        const set = await readCanonicalArtifact<ChildWaitSet>(reads, originalSubject.subject.waitSetRef);
        if (set.purpose.kind !== 'stop_settlement' || set.purpose.stopIntentRef !== originalSubject.subject.stopIntentRef)
          invalid('Stop subject replaced its original revocation source');
        return await complete(selected, set, reads) ?? immutableSnapshot({ run: selected.run });
      }
      if (originalSubject.subject.kind === 'finalize_settlement') {
        const selected = await settlementCut(input.expectedRunRevision, reads);
        const set = await readCanonicalArtifact<ChildWaitSet>(reads, originalSubject.subject.waitSetRef);
        if (set.purpose.kind !== 'finalize_settlement' || set.purpose.modelTurnItemId !== originalSubject.subject.modelTurnItemId)
          invalid('final subject replaced its original complete model turn');
        return await complete(selected, set, reads) ?? immutableSnapshot({ run: selected.run });
      }
      const selected = await selectedAt(input.expectedRunRevision, reads);
      if (selected.run.status !== 'waiting' || selected.run.waitingReason !== 'child' || !selected.run.waitingOnRef)
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child wake requires its original exact wait');
      const subject = await readCanonicalArtifact<ChildWaitingSubject>(reads, selected.run.waitingOnRef);
      const set = awaitSet(selected);
      requireEqual(subject, { schemaVersion: 1, kind: 'child', runId, createdFromRevision: selected.run.revision - 1,
        createdAt: subject.createdAt, frontierRef: selected.run.frontierRef!, subject: { kind: 'await_tool', waitSetRef: canonicalSha256(set),
          awaitBatchItemId: selected.batch.itemId, awaitCallId: selected.call.callId, awaitCallIndex: selected.call.index } }, 'original exact child wait');
      if (selected.checkpoint.id !== waitCheckpointId(runId, selected.run.waitingOnRef) || subject.createdAt > selected.run.updatedAt)
        invalid('subject has no same-lifecycle wait Checkpoint');
      await readCanonicalArtifact(reads, canonicalSha256(set));
      return await complete(selected, set, reads) ?? immutableSnapshot({ run: selected.run });
    })
  };
}
