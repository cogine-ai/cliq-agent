// Directed descendant audit only. Incoming allocations are verified by the
// admission reader; this never traverses a parent's mutable full recovery.
import { assertArtifactRef } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Checkpoint, ContextManifest, ContinuationItem, Run, RunSpec, ToolBatchItem, ToolResultModelContentV1, ToolResultPayloadV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import type { ChildResultItem, ChildWaitSet, ChildWaitingSubject } from '../kernel/children.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { decodeAwaitChildrenRequest } from '../tools/child-inputs.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildTerminalData } from './child-terminal.js';
import { KernelStorageError } from './errors.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readRegisteredAgentStop } from './stop-registration.js';
import { decodeContextManifest, decodeWorkspaceGenerationSnapshotEvidence } from './decoders.js';
import { readChildAwaitModelResult } from './child-await-model.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child result history ${message}`); }

export async function readAwaitChildSet(artifacts: ArtifactCatalog, parentId: string, ref: string,
  items: ReadonlyMap<string, ContinuationItem>) {
  const set = await readCanonicalArtifact<ChildWaitSet>(artifacts, ref);
  if (!exactKeys(set, ['schemaVersion', 'parentRunId', 'purpose', 'childRunIds']) || set.schemaVersion !== 1 ||
      set.parentRunId !== parentId || set.purpose.kind !== 'await_tool' ||
      !exactKeys(set.purpose, ['kind', 'awaitBatchItemId', 'awaitCallId', 'awaitCallIndex'])) invalid('has no closed original await purpose');
  const batch = items.get(set.purpose.awaitBatchItemId);
  if (batch?.kind !== 'assistant_tool_batch') invalid('has no original assistant batch');
  const call = batch.calls[set.purpose.awaitCallIndex];
  if (!call || call.callId !== set.purpose.awaitCallId || call.toolName !== 'await_children') invalid('changed its exact owning await call');
  const input = await readCanonicalArtifact<ToolCallInputV1>(artifacts, call.inputRef);
  if (input.disposition !== 'resolved' || input.inputDigest !== call.inputDigest || input.toolName !== call.toolName ||
      input.callId !== call.callId || input.index !== call.index) invalid('changed its normalized await input');
  requireEqual(decodeAwaitChildrenRequest(input.value).childRunIds, set.childRunIds, 'original exact ordered awaited children');
  return { set, batch };
}

export async function validateChildWaitHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; spec: RunSpec; items: ReadonlyMap<string, ContinuationItem>; journal: readonly import('../kernel/types.js').InvocationJournalEntry[]; checkpoints: readonly Checkpoint[];
  context: ContextManifest; mergedAwaitResults?: ReadonlyMap<string, string>; workspaceGenerations: readonly WorkspaceGenerationStateV1[];
}) {
  const { run, items, checkpoints } = input;
  const outgoing = readChildAllocationsForRun(driver, run.id).filter(row => row.parentRunId === run.id);
  const finalSets = new Map<string, ChildWaitSet>();
  async function readFinalSet(ref: string) {
    const set = await readCanonicalArtifact<ChildWaitSet>(artifacts, ref);
    if (!exactKeys(set, ['schemaVersion', 'parentRunId', 'purpose', 'childRunIds']) || set.schemaVersion !== 1 || set.parentRunId !== run.id ||
        set.purpose.kind !== 'finalize_settlement' || !exactKeys(set.purpose, ['kind', 'modelTurnItemId'])) invalid('has no closed original final-turn purpose');
    const producer = items.get(set.purpose.modelTurnItemId);
    if (producer?.kind !== 'model_turn' || producer.stopReason !== 'end') invalid('lost its actual premature complete model turn');
    const checkpoint = checkpoints.find(checkpoint => checkpoint.id === identityHash('cliq-child-final-wait-checkpoint-v1', run.id, ref));
    if (!checkpoint) invalid('final child wait lost its actual Checkpoint');
    const expected = outgoing.filter(row => input.journal.some(entry => entry.opKind === 'child_admission' && entry.phase === 'prepared' &&
      entry.opId === row.delegateOpId && entry.seq <= checkpoint.journalSeq) &&
      (row.state !== 'settled' || row.parentSettlementRevision > checkpoint.basedOnRunRevision)).map(row => row.childRunId)
      .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    decodeAwaitChildrenRequest({ childRunIds: set.childRunIds });
    requireEqual(set.childRunIds, expected, 'all-and-only original outstanding final-turn children');
    const position = [...items.keys()].indexOf(producer.itemId) + 1;
    if (!checkpoint || checkpoint.runItemSeq !== position || checkpoint.createdAt < producer.createdAt)
      invalid('premature final has no exact same-lifecycle wait Checkpoint');
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
    if (!context.segments.some(segment => segment.kind === 'excluded_control' && segment.fromItemSeq === position && segment.throughItemSeq === position))
      invalid('premature final text was not excluded from the next context');
    const snapshots = await artifacts.mapReads(input.workspaceGenerations.filter(generation => generation.phase === 'sealed'), async generation =>
      decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, generation.snapshotEvidenceRef!)));
    if (snapshots.filter(snapshot => snapshot.purpose === 'sealed_to_checkpoint' && snapshot.checkpointId === checkpoint.id &&
        snapshot.workspaceStateRef === checkpoint.workspaceStateRef).length !== 1) invalid('premature final wait has no exact original worker seal');
    finalSets.set(ref, set); return { set };
  }
  async function readStopSet(ref: string) {
    const set = await readCanonicalArtifact<ChildWaitSet>(artifacts, ref);
    if (!exactKeys(set, ['schemaVersion', 'parentRunId', 'purpose', 'childRunIds']) || set.schemaVersion !== 1 || set.parentRunId !== run.id ||
        set.purpose.kind !== 'stop_settlement' || !exactKeys(set.purpose, ['kind', 'stopIntentRef',
          ...(set.purpose.interruptedWaitRef ? ['interruptedWaitRef'] : []), ...(set.purpose.awaitOrigin ? ['awaitOrigin'] : [])])) invalid('Stop settlement lost its closed original purpose');
    const purpose = set.purpose, stop = await readRegisteredAgentStop(artifacts, run, purpose.stopIntentRef);
    const checkpoint = checkpoints.find(row => row.id === identityHash('cliq-child-stop-wait-checkpoint-v1', run.id, ref));
    if (!checkpoint || checkpoint.createdAt < stop.createdAt) invalid('Stop settlement has no registered worker-free Checkpoint');
    decodeAwaitChildrenRequest({ childRunIds: set.childRunIds });
    const expected = outgoing.filter(row => input.journal.some(entry => entry.opKind === 'child_admission' && entry.phase === 'prepared' &&
      entry.opId === row.delegateOpId && entry.seq <= checkpoint.journalSeq) &&
      (row.state !== 'settled' || row.parentSettlementRevision > checkpoint.basedOnRunRevision)).map(row => row.childRunId)
      .sort((a,b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    requireEqual(set.childRunIds, expected, 'Stop all-and-only outstanding direct children');
    if (purpose.interruptedWaitRef) {
      assertArtifactRef(purpose.interruptedWaitRef);
      const subject = await readCanonicalArtifact<ChildWaitingSubject>(artifacts, purpose.interruptedWaitRef);
      if (subject.schemaVersion !== 1 || subject.kind !== 'child' || subject.runId !== run.id ||
          subject.createdFromRevision >= checkpoint.basedOnRunRevision || subject.createdAt > checkpoint.createdAt ||
          subject.subject.kind === 'stop_settlement') invalid('Stop changed its original interrupted wait');
      const prior = subject.subject.kind === 'await_tool' ? await readAwaitChildSet(artifacts, run.id, subject.subject.waitSetRef, items)
        : await readFinalSet(subject.subject.waitSetRef);
      const observedStop = subject.subject.kind === 'finalize_settlement' ? subject.subject.observedStopIntentRef : undefined;
      if (observedStop) {
        const observed = await readRegisteredAgentStop(artifacts, run, observedStop);
        const producer = prior.set.purpose.kind === 'finalize_settlement' ? items.get(prior.set.purpose.modelTurnItemId) : undefined;
        if (producer?.kind !== 'model_turn' || observed.createdAt < producer.createdAt || observed.createdAt > subject.createdAt)
          invalid('interrupted final completion lost its actually observed Stop');
      }
      requireEqual(subject.subject, { ...prior.set.purpose, waitSetRef: subject.subject.waitSetRef,
        ...(observedStop ? { observedStopIntentRef: observedStop } : {}) }, 'Stop original interrupted wait subject');
      const priorId = subject.subject.kind === 'await_tool' ? identityHash('cliq-child-wait-checkpoint-v1', run.id, purpose.interruptedWaitRef)
        : identityHash('cliq-child-final-wait-checkpoint-v1', run.id, subject.subject.waitSetRef);
      const priorCheckpoint = checkpoints.find(row => row.id === priorId);
      if (!priorCheckpoint || priorCheckpoint.basedOnRunRevision !== subject.createdFromRevision ||
          priorCheckpoint.createdAt < subject.createdAt || priorCheckpoint.createdAt > checkpoint.createdAt) invalid('Stop lost its actual original wait Checkpoint');
      const expectedOrigin = subject.subject.kind === 'await_tool' ? { batchItemId: subject.subject.awaitBatchItemId,
        callId: subject.subject.awaitCallId, callIndex: subject.subject.awaitCallIndex } : undefined;
      requireEqual(purpose.awaitOrigin ?? null, expectedOrigin ?? null, 'Stop original interrupted provider await identity');
    } else if (purpose.awaitOrigin) invalid('Stop invented an interrupted await origin');
    return { set };
  }
  const readSet = async (ref: string, kind: 'await_tool' | 'finalize_settlement' | 'stop_settlement') => kind === 'await_tool'
    ? readAwaitChildSet(artifacts, run.id, ref, items) : kind === 'finalize_settlement' ? readFinalSet(ref) : readStopSet(ref);
  const results = [...items.values()].filter((item): item is ChildResultItem => item.kind === 'child_result');
  if (outgoing.filter(row => row.state === 'settled').length !== results.length)
    invalid('has a missing or duplicate one-time settled child result');
  for (const item of results) {
    const row = outgoing.find(row => row.childRunId === item.childRunId);
    if (!row || row.state !== 'settled' || row.childResultItemId !== item.itemId || item.runId !== run.id ||
        item.itemId !== identityHash('cliq-child-result-item-v1', run.id, item.childRunId) || item.createdAt > row.settledAt ||
        item.createdAt < row.terminalAt) invalid('has no exact monotonic owned allocation settlement');
    parseCanonicalTime(item.createdAt);
    const terminal = await readChildTerminalData(driver, artifacts, item.childRunId);
    requireEqual(terminal.allocation, row, 'settled original child terminal allocation');
    const { set } = await readSet(item.delivery.waitSetRef, item.delivery.kind);
    requireEqual(item.delivery, set.purpose.kind === 'stop_settlement' ? { kind: 'stop_settlement', stopIntentRef: set.purpose.stopIntentRef, waitSetRef: item.delivery.waitSetRef }
      : { ...set.purpose, waitSetRef: item.delivery.waitSetRef },
    'child result exact owning await delivery');
    if (!set.childRunIds.includes(item.childRunId)) invalid('is outside its exact frozen wait set');
    requireEqual(item, { schemaVersion: 1, kind: 'child_result', itemId: row.childResultItemId, runId: run.id,
      delivery: item.delivery, childRunId: row.childRunId, inclusiveBudgetUsage: row.inclusiveBudgetUsage,
      ...row.terminal, createdAt: item.createdAt }, 'complete closed child result item');
    const checkpoint = checkpoints.find(checkpoint => checkpoint.id === identityHash('cliq-child-settlement-checkpoint-v1', run.id, item.delivery.waitSetRef));
    if (!checkpoint || checkpoint.basedOnRunRevision !== row.parentSettlementRevision - 1 || checkpoint.createdAt !== row.settledAt ||
        checkpoint.createdAt < item.createdAt || checkpoint.reason !== 'auto') invalid('has no same-transaction parent settlement Checkpoint');
    terminal.assertUnchanged(driver);
  }
  for (const item of items.values()) {
    if (item.kind === 'child_merge_batch') {
      if (!item.childResultItemIds.length || !item.calls.length ||
          new Set(item.childResultItemIds).size !== item.childResultItemIds.length) invalid('synthetic merge audit lost its exact original result set');
      const ordered = item.childResultItemIds.map(id => {
        const result = items.get(id); if (result?.kind !== 'child_result') invalid('synthetic merge has an unknown child result');
        return result;
      });
      const first = ordered.find(result => result.childRunId === item.calls[0]!.childRunId);
      if (!first || first.delivery.kind === 'stop_settlement') invalid('synthetic merge has no exact first patch source subject');
      const { set } = await readSet(first.delivery.waitSetRef, first.delivery.kind);
      requireEqual(ordered.map(result => result.childRunId), set.childRunIds, 'synthetic merge all ordered await results');
      if (set.purpose.kind === 'stop_settlement') invalid('stop cannot create a merge batch');
      requireEqual(item.resume, set.purpose.kind === 'await_tool' ? { kind: 'await_tool', batchItemId: set.purpose.awaitBatchItemId,
        callId: set.purpose.awaitCallId, callIndex: set.purpose.awaitCallIndex } : { ...set.purpose }, 'synthetic merge exact provider resume');
      if (item.itemId !== identityHash('cliq-child-merge-batch-v1', run.id, first.delivery.waitSetRef)) invalid('synthetic merge batch id changed');
      const originalCheckpoint = checkpoints.find(row => row.id === identityHash('cliq-child-settlement-checkpoint-v1', run.id, first.delivery.waitSetRef));
      if (!originalCheckpoint || originalCheckpoint.runItemSeq !== [...items.keys()].indexOf(item.itemId) + 1)
        invalid('synthetic merge lost its exact original one-time settlement Checkpoint');
      const patches = ordered.filter(result => outgoing.find(row => row.childRunId === result.childRunId)?.parentSettlementRevision ===
        originalCheckpoint.basedOnRunRevision + 1 && result.delivery.kind !== 'stop_settlement' &&
        result.delivery.waitSetRef === first.delivery.waitSetRef && result.mode === 'mutating' &&
        (result.status === 'succeeded' || result.status === 'completed_unverified'));
      const expectedCalls = await artifacts.mapReads(patches, async (result, index) => {
        if (!('patchManifestRef' in result)) invalid('successful mutating result lost its patch');
        const terminal = await readChildTerminalData(driver, artifacts, result.childRunId);
        return { index, callId: identityHash('cliq-child-merge-call-v1', run.id, first.delivery.waitSetRef, result.childRunId),
          childRunId: result.childRunId, patchManifestRef: result.patchManifestRef,
          admittedForkBaseRef: terminal.spec.baseWorkspaceManifestRef };
      });
      requireEqual(item, { schemaVersion: 1, kind: 'child_merge_batch', itemId: item.itemId, runId: run.id, resume: item.resume,
        childResultItemIds: ordered.map(result => result.itemId), calls: expectedCalls, createdAt: item.createdAt }, 'complete synthetic merge audit');
      continue;
    }
    if (item.kind !== 'tool_result' || item.outcome !== 'executed') continue;
    const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
    if (payload.outcome !== 'executed' || payload.source !== 'child_results') continue;
    if (payload.mergeResultItemRefs !== undefined) {
      if (input.mergedAwaitResults?.get(item.itemId) !== canonicalSha256(payload)) invalid('merge/await result lost its complete original local effect closure');
      continue;
    }
    if (item.opId !== undefined || !exactKeys(payload, ['schemaVersion', 'format', 'runId', 'batchItemId', 'callId', 'index',
      'toolName', 'outcome', 'source', 'waitSetRef', 'childResultItemRefs', 'modelContentRef', 'modelContentDigest', 'payloadDigest']))
      invalid('await control acquired an invocation or unknown result fields');
    const { set, batch } = await readAwaitChildSet(artifacts, run.id, payload.waitSetRef, items);
    if (set.purpose.kind !== 'await_tool' || payload.batchItemId !== set.purpose.awaitBatchItemId ||
        payload.callId !== set.purpose.awaitCallId || payload.index !== set.purpose.awaitCallIndex ||
        item.batchItemId !== payload.batchItemId || item.callId !== payload.callId || item.index !== payload.index ||
        item.itemId !== identityHash('cliq-tool-result-item-v1', run.id, item.batchItemId, item.callId)) invalid('substitutes its original await call');
    const ordered = set.childRunIds.map(childId => {
      const child = results.find(result => result.childRunId === childId);
      if (!child || child.delivery.kind === 'stop_settlement' || child.createdAt > item.createdAt) invalid('await reread has no original owned model-visible result');
      return child;
    });
    requireEqual(payload.childResultItemRefs, ordered.map(child => canonicalSha256(child)), 'all-and-only ordered awaited result references');
    if (payload.schemaVersion !== 1 || payload.format !== 'cliq-tool-result-payload-v1' || payload.toolName !== 'await_children' ||
        payload.runId !== run.id || digestOmitting(payload, 'payloadDigest') !== payload.payloadDigest) invalid('has an invalid closed await result');
    const model = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, payload.modelContentRef);
    const expected = { schemaVersion: 1, format: 'cliq-tool-result-model-content-v1', callId: item.callId, index: item.index,
      toolName: 'await_children', outcome: 'executed', content: await readChildAwaitModelResult(artifacts, ordered) };
    requireEqual(model, { ...expected, contentDigest: canonicalSha256(expected) }, 'closed model-safe await reread projection');
    if (model.contentDigest !== payload.modelContentDigest) invalid('changed its model-safe await digest');
    const checkpoint = checkpoints.find(checkpoint => checkpoint.id === identityHash('cliq-child-settlement-checkpoint-v1', run.id, payload.waitSetRef));
    if (!checkpoint || checkpoint.createdAt < item.createdAt) invalid('await result has no atomic original continuation Checkpoint');
    const frontier = item.index + 1 < batch.calls.length
      ? { schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId, orderedCallIds: batch.calls.map(call => call.callId), nextCallIndex: item.index + 1 }
      : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', run.id, batch.itemId),
        contextItemSeq: checkpoint.runItemSeq, cause: 'child_results' };
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(frontier)), frontier, 'await exact original next frontier');
  }
  if (run.waitingReason === 'child') {
    if (run.status !== 'waiting' || run.activeWorkerLaunchId || !run.waitingOnRef || !run.frontierRef) invalid('current wait retains execution or lacks an exact subject');
    const subject = await readCanonicalArtifact<ChildWaitingSubject>(artifacts, run.waitingOnRef);
    parseCanonicalTime(subject.createdAt);
    const { set } = await readSet(subject.subject.waitSetRef, subject.subject.kind);
    requireEqual(subject, { schemaVersion: 1, kind: 'child', runId: run.id, createdFromRevision: subject.createdFromRevision,
      createdAt: subject.createdAt, frontierRef: run.frontierRef, subject: { ...set.purpose, waitSetRef: subject.subject.waitSetRef,
        ...(subject.subject.kind === 'finalize_settlement' && subject.subject.observedStopIntentRef ? { observedStopIntentRef: subject.subject.observedStopIntentRef } : {}) } }, 'closed current child wait');
    const checkpoint = checkpoints.find(checkpoint => checkpoint.id === run.latestCheckpointId);
    const checkpointId = subject.subject.kind === 'await_tool' ? identityHash('cliq-child-wait-checkpoint-v1', run.id, run.waitingOnRef)
      : subject.subject.kind === 'stop_settlement' ? identityHash('cliq-child-stop-wait-checkpoint-v1', run.id, subject.subject.waitSetRef)
        : identityHash('cliq-child-final-wait-checkpoint-v1', run.id, subject.subject.waitSetRef);
    if (!checkpoint || checkpoint.id !== checkpointId ||
        checkpoint.basedOnRunRevision !== subject.createdFromRevision || checkpoint.createdAt > run.updatedAt || subject.createdAt > checkpoint.createdAt ||
        (!run.stopIntentRef && (run.revision !== subject.createdFromRevision + 1 || checkpoint.createdAt !== run.updatedAt)) ||
        run.revision < subject.createdFromRevision + 1)
      invalid('current subject has no original atomic wait Checkpoint');
    if (subject.subject.kind === 'finalize_settlement' && subject.subject.observedStopIntentRef) {
      const observed = await readRegisteredAgentStop(artifacts, run, subject.subject.observedStopIntentRef);
      const producer = items.get(subject.subject.modelTurnItemId);
      if (producer?.kind !== 'model_turn' || producer.createdAt > observed.createdAt || observed.createdAt > subject.createdAt)
        invalid('final completion did not retain its actual pre-Stop result and observed fence');
    } else if (run.stopIntentRef && subject.subject.kind !== 'stop_settlement' &&
        (await readRegisteredAgentStop(artifacts, run)).createdAt < checkpoint.createdAt)
      invalid('a productive child wait was committed after its registered Stop fence');
  }
  for (const segment of input.context.segments) if (segment.kind === 'excluded_control') {
    for (const item of [...items.values()].slice(segment.fromItemSeq - 1, segment.throughItemSeq)) if (item.kind === 'model_turn') {
      if (item.stopReason !== 'end' || ![...finalSets.values()].some(set => set.purpose.kind === 'finalize_settlement' && set.purpose.modelTurnItemId === item.itemId))
        invalid('excluded assistant text has no original child-finalization subject');
    }
  }
}
