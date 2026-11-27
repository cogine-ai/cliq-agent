// Read-only history of the single control effect "register this await".
// No parent full-recovery callback, execution grant or native lease is minted.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { identityHash } from '../kernel/identity.js';
import type { ChildAwaitReceiptV1, ChildAwaitRequestV1 } from '../kernel/child-await.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, RunSpec, SupervisorInspectorIdentityV1,
  ToolContractManifestV1, ToolResultPayloadV1 } from '../kernel/types.js';
import type { ChildWaitSet, ChildWaitingSubject } from '../kernel/children.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { decodeAwaitChildrenRequest } from '../tools/child-inputs.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { planChildAwaitRegistration, childAwaitDispatchId, childAwaitIdempotencyKey } from './child-await-artifacts.js';
import { readChildAdmission } from './child-admission.js';
import { decodeBudgetSettlement } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { addBudget } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal, readOperationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readCheckpoint, readRun, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child await history ${message}`); }
const immutableRun = (run: Run) => ({ id: run.id, parentRunId: run.parentRunId ?? null, sessionId: run.sessionId, specRef: run.specRef,
  createdAt: run.createdAt, deadlineAt: run.deadlineAt });

export async function validateChildAwaitHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; spec: RunSpec; items: ReadonlyMap<string, ContinuationItem>; journal: readonly InvocationJournalEntry[]; checkpoints: readonly Checkpoint[];
}) {
  const { run, spec, items, journal, checkpoints } = input;
  requireEqual(readRun(driver, run.id), run, 'await history actual original recovery Run');
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef)),
    manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef),
    contract = manifest.entries.find(entry => entry.name === 'await_children'), registrations = new Map<string, string>();
  for (const prepared of journal.filter(row => row.opKind === 'child_await' && row.phase === 'prepared')) {
    if (contract?.execution.kind !== 'supervisor_control' || contract.execution.handlerId !== 'await_children') invalid('lost its original signed control contract');
    const rows = readOperationJournal(driver, run.id, prepared.opId), [first, claim, completed] = rows;
    if (rows.length !== 3 || rows.map(row => row.phase).join(',') !== 'prepared,dispatch_claimed,completed' ||
        rows.some((row, i) => row.opKind !== 'child_await' || row.seq !== prepared.seq + i || row.grantRef !== undefined ||
          row.leaseEpoch !== 0 || row.attempt !== 0 || row.replayClass !== 'retry' || row.timestamp !== prepared.timestamp ||
          row.localCommittedAt !== prepared.localCommittedAt || row.requestRef !== prepared.requestRef || row.target !== prepared.target))
      invalid('changed its exact one-time no-grant local accounting triplet');
    requireEqual(first, prepared, 'actual original await preparation');
    const request = await readCanonicalArtifact<ChildAwaitRequestV1>(artifacts, prepared.requestRef),
      original = decodeWireRun(await readCanonicalArtifact(artifacts, request.parentRunSnapshotRef)),
      receipt = await readCanonicalArtifact<ChildAwaitReceiptV1>(artifacts, completed.resultRef!),
      source = readCheckpoint(driver, request.sourceCheckpointId), checkpoint = checkpoints.find(row => row.id === receipt.checkpointId);
    requireEqual(immutableRun(original), immutableRun(run), 'await immutable parent snapshot');
    if (original.status !== 'queued' || original.nextStep !== 'tool' || original.activeWorkerLaunchId || original.stopIntentRef || original.cancelRequested ||
        original.waitingOnRef || original.waitingReason || original.revision >= run.revision || original.latestCheckpointId !== source.id ||
        original.revision !== source.basedOnRunRevision + 1 || original.updatedAt !== source.createdAt || source.runId !== run.id ||
        prepared.seq !== source.journalSeq + 1 || prepared.timestamp < original.updatedAt || request.preparedAt !== prepared.timestamp ||
        !checkpoint || checkpoint.runId !== run.id || checkpoint.basedOnRunRevision !== original.revision || checkpoint.journalSeq !== completed.seq ||
        checkpoint.workspaceStateRef !== source.workspaceStateRef || checkpoint.createdAt !== prepared.localCommittedAt ||
        checkpoint.createdAt < prepared.timestamp || checkpoint.createdAt >= original.deadlineAt) invalid('lost its actual source/registration Checkpoint or commit interval');
    const latest = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? AND based_on_run_revision<? ORDER BY based_on_run_revision DESC,rowid DESC LIMIT 1')
      .get<{ id: string }>(run.id, original.revision);
    if (latest?.id !== source.id) invalid('substituted another original source Checkpoint');
    const batch = items.get(request.batchItemId), call = batch?.kind === 'assistant_tool_batch' && batch.calls[request.callIndex];
    if (!call || batch?.kind !== 'assistant_tool_batch' || call.toolName !== 'await_children' || call.callId !== request.callId ||
        call.inputRef !== request.inputRef || call.inputDigest !== request.inputDigest) invalid('substituted its exact real provider call');
    const frontier: RunFrontier = { schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId, orderedCallIds: batch.calls.map(call => call.callId), nextCallIndex: request.callIndex };
    if (original.frontierRef !== canonicalSha256(frontier)) invalid('lost its exact original provider cursor');
    const normalized = await readCanonicalArtifact<import('../protocol/agent-ir.js').ToolCallInputV1>(artifacts, call.inputRef),
      set = await readCanonicalArtifact<ChildWaitSet>(artifacts, request.waitSetRef), childIds = decodeAwaitChildrenRequest(normalized.value).childRunIds;
    requireEqual(set, { schemaVersion: 1, parentRunId: run.id, purpose: { kind: 'await_tool', awaitBatchItemId: batch.itemId,
      awaitCallId: call.callId, awaitCallIndex: request.callIndex }, childRunIds: childIds }, 'complete original awaited handle order');
    const prefix = [...items.values()].slice(0, source.runItemSeq), repairs = prefix.filter(item => item.kind === 'repair_diagnostic');
    if (repairs.length !== original.repairCount || repairs.some((item, i) => item.kind !== 'repair_diagnostic' || item.repairOrdinal !== i + 1)) invalid('changed its original repair budget');
    let consumed = { ...ZERO_BUDGET, repairAttempts: original.repairCount }, reserved = { ...ZERO_BUDGET };
    const groups = new Map<string, InvocationJournalEntry[]>();
    for (const [i, row] of journal.slice(0, source.journalSeq).entries()) {
      if (row.seq !== i + 1) invalid('original Journal prefix has a gap');
      const key = `${row.opId}\0${row.attempt}`, group = groups.get(key) ?? []; group.push(row); groups.set(key, group);
    }
    for (const group of groups.values()) {
      const terminal = group.find(row => ['completed', 'failed', 'unknown'].includes(row.phase));
      if (group[0]?.phase !== 'prepared' || !terminal?.budgetSettlementRef || !['completed', 'failed'].includes(group.at(-1)!.phase)) invalid('overtook original unresolved work');
      const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
      if (settlement.runId !== run.id || settlement.opId !== group[0].opId || settlement.attempt !== group[0].attempt ||
          settlement.preparedJournalSeq !== group[0].seq || settlement.terminalJournalSeq !== terminal.seq || settlement.settledAt !== terminal.timestamp)
        invalid('lost an original own budget settlement');
      requireEqual(settlement.consumed, terminal.budgetDelta, 'await source own consumption'); consumed = addBudget(consumed, settlement.consumed);
    }
    const admittedOps = new Set(journal.slice(0, source.journalSeq).filter(row => row.opKind === 'child_admission' && row.phase === 'completed').map(row => row.opId));
    for (const allocation of readChildAllocationsForRun(driver, run.id).filter(row => row.parentRunId === run.id && admittedOps.has(row.delegateOpId))) {
      if (allocation.state === 'settled' && allocation.parentSettlementRevision <= original.revision) {
        const result = prefix.find(item => item.itemId === allocation.childResultItemId);
        if (result?.kind !== 'child_result' || result.childRunId !== allocation.childRunId || allocation.settledAt > source.createdAt) invalid('lost an original child budget settlement');
        consumed = addBudget(consumed, allocation.inclusiveBudgetUsage);
      } else reserved = addBudget(reserved, allocation.grantedAdditiveCeilings);
    }
    requireEqual(consumed, original.budgetConsumed, 'await exact original inclusive consumption');
    requireEqual(reserved, original.budgetReserved, 'await exact original conservative reservations');
    const leases = readWorkerLaunchesForRun(driver, run.id).flatMap(worker => worker.activatedAt && worker.leaseEpoch !== undefined &&
      worker.plannedRunRevision < original.revision ? [worker.leaseEpoch] : []);
    if (original.leaseEpoch !== Math.max(0, ...leases)) invalid('invented an execution lease');
    for (const id of childIds) {
      const admitted = await readChildAdmission(driver, artifacts, id);
      if (admitted.parent.id !== run.id || !prefix.some(item => item.kind === 'child_handle' && item.childRunId === id &&
          canonicalSha256(item) === admitted.receipt.childHandleItemRef)) invalid('registered a foreign or not-yet-owned child handle');
      admitted.assertUnchanged(driver);
    }
    const subject: ChildWaitingSubject = { schemaVersion: 1, kind: 'child', runId: run.id, createdFromRevision: original.revision, createdAt: prepared.timestamp,
      frontierRef: original.frontierRef!, subject: { ...set.purpose, waitSetRef: request.waitSetRef } },
      waitCheckpoint = identityHash('cliq-child-wait-checkpoint-v1', run.id, canonicalSha256(subject)),
      settlementCheckpoint = identityHash('cliq-child-settlement-checkpoint-v1', run.id, request.waitSetRef);
    if (checkpoint.id === waitCheckpoint) {
      requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(subject)), subject, 'actual registered await subject');
      if (checkpoint.contextManifestRef !== source.contextManifestRef || checkpoint.runItemSeq !== source.runItemSeq) invalid('waiting registration invented a context effect');
    } else if (checkpoint.id !== settlementCheckpoint) invalid('invented another registration lifecycle');
    const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, receipt.inspectorIdentityRef),
      ownerHistory = await readRetainedStateOwnerHistory(driver, artifacts, inspector.stateOwnerEpoch), owner = ownerHistory.entries.at(-1)!.owner;
    const identity = await readSupervisorInspector(artifacts, owner, assembly, { ...receipt, observedAt: checkpoint.createdAt });
    if (owner.acquiredAt > prepared.timestamp || owner.state === 'terminal' && owner.releasedAt < checkpoint.createdAt ||
        identity.supervisorEntryId !== contract.execution.supervisorEntryId || identity.supervisorEntryVersion !== contract.execution.supervisorEntryVersion ||
        identity.supervisorExecutableDigest !== contract.execution.supervisorExecutableDigest || claim.stateOwnerEpoch !== owner.ownerEpoch ||
        claim.supervisorInstanceId !== owner.supervisorInstanceId || completed.stateOwnerEpoch !== claim.stateOwnerEpoch || completed.supervisorInstanceId !== claim.supervisorInstanceId)
      invalid('lost its actual signed control Supervisor through commit');
    const expected = planChildAwaitRegistration({ run: original, assemblyRef: spec.assemblyRef, execution: contract.execution,
      batchItemId: batch.itemId, callId: call.callId, callIndex: request.callIndex, inputRef: call.inputRef, inputDigest: call.inputDigest,
      waitSetRef: request.waitSetRef, checkpointId: checkpoint.id, journalSeq: prepared.seq, inspector, preparedAt: prepared.timestamp });
    if (prepared.opId !== expected.opId || prepared.requestRef !== expected.requestPlan.ref || prepared.target !== expected.targetPlan.ref ||
        prepared.idempotencyKey !== childAwaitIdempotencyKey(run.id, prepared.opId) || claim.dispatchId !== childAwaitDispatchId(run.id, prepared.opId, prepared.requestRef) ||
        completed.dispatchId !== claim.dispatchId || completed.resultRef !== expected.receiptPlan.ref || completed.budgetSettlementRef !== expected.settlementPlan.ref)
      invalid('changed its original one-use registration identity');
    for (const plan of expected.plans) if (!Buffer.from(await artifacts.readBytes(plan.ref)).equals(Buffer.from(plan.bytes))) invalid('complete registration data changed');
    if (registrations.has(`${batch.itemId}\0${call.callId}\0${request.callIndex}`)) invalid('registered a real await call twice');
    registrations.set(`${batch.itemId}\0${call.callId}\0${request.callIndex}`, request.waitSetRef); ownerHistory.assertUnchanged(driver);
  }
  for (const item of items.values()) if (item.kind === 'tool_result' && item.outcome === 'executed') {
    const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
    if (payload.outcome === 'executed' && payload.source === 'child_results' &&
        registrations.get(`${item.batchItemId}\0${item.callId}\0${item.index}`) !== payload.waitSetRef) invalid('real await result has no exact paid original registration');
  }
  if (run.waitingReason === 'child' && run.waitingOnRef) {
    const subject = await readCanonicalArtifact<ChildWaitingSubject>(artifacts, run.waitingOnRef);
    if (subject.subject.kind === 'await_tool' && registrations.get(`${subject.subject.awaitBatchItemId}\0${subject.subject.awaitCallId}\0${subject.subject.awaitCallIndex}`) !== subject.subject.waitSetRef)
      invalid('active wait has no exact paid original registration');
  }
  requireEqual(readInvocationJournal(driver, run.id), journal, 'await history complete original Journal cut');
  requireEqual(readRun(driver, run.id), run, 'await history final original recovery Run');
}
