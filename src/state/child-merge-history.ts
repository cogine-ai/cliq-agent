// Retained data only. No whole-parent recovery callback, mutable generation
// adoption, native grant, broker token or retry authority can be produced here.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { identityHash } from '../kernel/identity.js';
import type { ChildMergeBatchItem, ChildMergeResultItem, ChildResultItem } from '../kernel/children.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, SupervisorInspectorIdentityV1,
  ToolResultItem, ToolResultModelContentV1, ToolResultPayloadV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { childMergeSourceData, readChildMergeAuthorization } from './child-merge-authorization.js';
import { childMergeCheckpointId, childMergeDiagnostic, decodeChildMergeModelContent, planChildMergeEffect,
  planChildMergeModelContent, type ChildMergeReceiptV1 } from './child-merge-effect.js';
import { KernelStorageError } from './errors.js';
import { readOperationJournal } from './repositories/journal.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readChildAwaitModelResult } from './child-await-model.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child merge history ${message}`); }
const immutableRun = (run: Run) => ({ id: run.id, parentRunId: run.parentRunId ?? null, sessionId: run.sessionId, specRef: run.specRef,
  createdAt: run.createdAt, deadlineAt: run.deadlineAt });

export async function validateChildMergeHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; items: ReadonlyMap<string, ContinuationItem>; journal: readonly InvocationJournalEntry[]; checkpoints: readonly Checkpoint[];
}) {
  const { run, items, checkpoints } = input;
  requireEqual(readRun(driver, run.id), run, 'child merge original actual recovery Run');
  const ordered = [...items.values()], outcomes = ordered.filter((item): item is ChildMergeResultItem => item.kind === 'child_merge_result');
  const local = input.journal.filter(row => row.opKind === 'child_merge' && row.phase === 'prepared');
  const mergedAwaitResults = new Map<string, string>();
  if (local.length !== outcomes.filter(item => item.outcome !== 'denied').length)
    invalid('has a missing or extra registered local merge outcome');
  const seenOps = new Set<string>();
  for (const item of outcomes) {
    if (seenOps.has(item.opId) || item.runId !== run.id) invalid('repeated or foreign local operation');
    seenOps.add(item.opId);
    const policy = ordered.find(candidate => canonicalSha256(candidate) === item.policyDecisionItemRef);
    if (policy?.kind !== 'policy_decision' || policy.subjectKind !== 'child_merge' || policy.opId !== item.opId)
      invalid('outcome has no exact original registered permission item');
    const authority = await readChildMergeAuthorization(driver, artifacts, run.id, policy.itemId);
    if (authority.request.opId !== item.opId || canonicalSha256(authority.request) !== item.requestRef ||
        authority.request.mergeBatchItemId !== item.mergeBatchItemId || authority.request.callId !== item.callId ||
        authority.request.callIndex !== item.callIndex || authority.item.decision !== (item.outcome === 'denied' ? 'deny' : 'allow'))
      invalid('outcome substituted its exact original authorized call');
    const receipt = await readCanonicalArtifact<ChildMergeReceiptV1>(artifacts, item.resultRef);
    const original = decodeWireRun(await readCanonicalArtifact(artifacts, receipt.parentRunSnapshotRef));
    requireEqual(immutableRun(original), immutableRun(run), 'merge original immutable parent snapshot');
    requireEqual(original.budgetConsumed, authority.original.budgetConsumed, 'merge original inclusive consumed cut');
    requireEqual(original.budgetReserved, authority.original.budgetReserved, 'merge original conservative reserved cut');
    if (original.status !== 'queued' || original.nextStep !== 'tool' || original.activeWorkerLaunchId || original.stopIntentRef || original.cancelRequested ||
        original.frontierRef !== authority.request.frontierRef || original.leaseEpoch !== authority.original.leaseEpoch ||
        original.repairCount !== authority.original.repairCount || original.updatedAt > item.createdAt || item.createdAt !== receipt.preparedAt ||
        original.revision < authority.original.revision || original.revision >= run.revision)
      invalid('receipt invented an active lease or original ready parent cut');
    const prior = readCheckpoint(driver, original.latestCheckpointId);
    const latest = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? AND based_on_run_revision<? ORDER BY based_on_run_revision DESC,rowid DESC LIMIT 1')
      .get<{ id: string }>(run.id, original.revision);
    if (latest?.id !== prior.id || prior.runId !== run.id || prior.createdAt > original.updatedAt ||
        prior.journalSeq !== authority.source.checkpoint.journalSeq || prior.workspaceStateRef !== authority.request.workspaceStateRef)
      invalid('receipt lost its actual ready Checkpoint at the original revision');
    const checkpoint = checkpoints.find(row => row.id === childMergeCheckpointId(run.id, item.opId));
    if (!checkpoint || checkpoint.basedOnRunRevision !== original.revision || checkpoint.createdAt < receipt.preparedAt ||
        checkpoint.createdAt >= original.deadlineAt || checkpoint.reason !== 'auto') invalid('outcome has no exact atomic logical Checkpoint');
    const rows = readOperationJournal(driver, run.id, item.opId);
    if (item.outcome === 'denied' ? rows.length !== 0 : rows.length !== 3 || rows[2]!.resultRef !== item.resultRef ||
        rows[0]!.timestamp !== item.createdAt || rows[0]!.localCommittedAt !== checkpoint.createdAt)
      invalid('outcome invented or lost its local effect/one-time charge');
    const identity = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, receipt.inspectorIdentityRef);
    const ownerHistory = await readRetainedStateOwnerHistory(driver, artifacts, identity.stateOwnerEpoch);
    const owner = ownerHistory.entries.at(-1)!.owner;
    const inspector = await readSupervisorInspector(artifacts, owner, authority.source.assembly, { ...receipt, observedAt: checkpoint.createdAt });
    if (owner.acquiredAt > receipt.preparedAt || owner.state === 'terminal' && owner.releasedAt < checkpoint.createdAt ||
        inspector.supervisorEntryId !== authority.target.execution.supervisorEntryId ||
        inspector.supervisorEntryVersion !== authority.target.execution.supervisorEntryVersion ||
        inspector.supervisorExecutableDigest !== authority.target.execution.supervisorExecutableDigest ||
        rows.length && (rows[1]!.stateOwnerEpoch !== owner.ownerEpoch || rows[1]!.supervisorInstanceId !== owner.supervisorInstanceId))
      invalid('outcome lost its actual signed local Supervisor owner through commit');
    const expected = planChildMergeEffect({ source: childMergeSourceData(authority.source), request: authority.request,
      requestRef: item.requestRef, decisionItemRef: item.policyDecisionItemRef, disposition: authority.grant ? 'allow' : 'deny',
      parentRunSnapshotRef: receipt.parentRunSnapshotRef, inspector: identity, preparedAt: item.createdAt });
    requireEqual(receipt, expected.receipt, 'complete original B/S/A merge receipt');
    for (const plan of expected.plans) if (!Buffer.from(await artifacts.readBytes(plan.ref)).equals(Buffer.from(plan.bytes)))
      invalid('complete merge audit bytes changed');
    if (checkpoint.workspaceStateRef !== expected.workspaceStateRef || checkpoint.journalSeq !== (rows.at(-1)?.seq ?? prior.journalSeq))
      invalid('logical Checkpoint changed its actual merged workspace or Journal cut');
    const batch = items.get(item.mergeBatchItemId);
    if (batch?.kind !== 'child_merge_batch') invalid('outcome lost its original synthetic audit batch');
    const prefix = outcomes.filter(row => row.mergeBatchItemId === batch.itemId && row.callIndex <= item.callIndex);
    const done = item.outcome !== 'merged' || item.callIndex + 1 === batch.calls.length;
    const expectedItem = { ...expected.item };
    let frontier: RunFrontier, tail: ContinuationItem[] = [];
    if (done && batch.resume.kind === 'finalize_settlement') {
      const diagnostic = childMergeDiagnostic(childMergeSourceData(authority.source), prefix);
      const modelPlan = planChildMergeModelContent(run.id, batch.itemId, diagnostic);
      const model = decodeChildMergeModelContent(await readCanonicalArtifact(artifacts, modelPlan.ref));
      expectedItem.modelContentRef = modelPlan.ref; expectedItem.modelContentDigest = model.contentDigest;
      frontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-child-merged-results-turn-v1', run.id, batch.itemId),
        contextItemSeq: checkpoint.runItemSeq, cause: 'child_results' };
    } else if (done) {
      if (batch.resume.kind !== 'await_tool') invalid('merge resume changed its original provider branch');
      const resume = batch.resume, provider = items.get(resume.batchItemId);
      if (provider?.kind !== 'assistant_tool_batch' || provider.calls[resume.callIndex]?.callId !== resume.callId)
        invalid('merge result has no matching real provider await call');
      const result = ordered.find((row): row is ToolResultItem => row.kind === 'tool_result' && row.batchItemId === resume.batchItemId &&
        row.callId === resume.callId && row.index === resume.callIndex);
      if (!result || result.opId !== undefined || result.createdAt !== item.createdAt || result.outcome !== 'executed')
        invalid('final merge has no single real await ToolResult');
      const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, result.resultRef);
      if (payload.outcome !== 'executed' || payload.source !== 'child_results') invalid('merge invented a provider tool result');
      const childResults = batch.childResultItemIds.map(id => {
        const row = items.get(id); if (row?.kind !== 'child_result' || row.delivery.kind === 'stop_settlement') invalid('merge lost an original child result'); return row;
      });
      const first = childResults.find(row => row.childRunId === authority.source.call.childRunId)!;
      const diagnostic = childMergeDiagnostic(childMergeSourceData(authority.source), prefix);
      const modelCore = { schemaVersion: 1, format: 'cliq-tool-result-model-content-v1', callId: resume.callId,
        index: resume.callIndex, toolName: 'await_children', outcome: 'executed', content: await readChildAwaitModelResult(artifacts, childResults, diagnostic) };
      const model = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, payload.modelContentRef);
      requireEqual(model, { ...modelCore, contentDigest: canonicalSha256(modelCore) }, 'ref-free closed merge/await model projection');
      const payloadCore = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: run.id, batchItemId: resume.batchItemId,
        callId: resume.callId, index: resume.callIndex, toolName: 'await_children', outcome: 'executed', source: 'child_results',
        waitSetRef: first.delivery.waitSetRef, childResultItemRefs: childResults.map(row => canonicalSha256(row)),
        mergeResultItemRefs: prefix.map(row => canonicalSha256(row)), modelContentRef: canonicalSha256(model), modelContentDigest: model.contentDigest };
      requireEqual(payload, { ...payloadCore, payloadDigest: canonicalSha256(payloadCore) }, 'complete final merge/await payload');
      requireEqual(result, { schemaVersion: 1, kind: 'tool_result', itemId: identityHash('cliq-tool-result-item-v1', run.id, resume.batchItemId, resume.callId),
        runId: run.id, batchItemId: resume.batchItemId, callId: resume.callId, index: resume.callIndex,
        outcome: 'executed', resultRef: canonicalSha256(payload), createdAt: item.createdAt }, 'one real provider await result');
      mergedAwaitResults.set(result.itemId, canonicalSha256(payload)); tail = [result];
      frontier = resume.callIndex + 1 < provider.calls.length ? { schemaVersion: 1, kind: 'tool', batchItemId: provider.itemId,
        orderedCallIds: provider.calls.map(call => call.callId), nextCallIndex: resume.callIndex + 1 }
        : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', run.id, resume.batchItemId),
          contextItemSeq: checkpoint.runItemSeq, cause: 'child_results' };
    } else frontier = { schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId,
      orderedCallIds: batch.calls.map(call => call.callId), nextCallIndex: item.callIndex + 1 };
    requireEqual(item, expectedItem, 'closed original synthetic merge result item');
    const appended = [ ...(policy.decisionSource === 'direct_policy' ? [policy] : []), item, ...tail ];
    requireEqual(ordered.slice(prior.runItemSeq, checkpoint.runItemSeq), appended, 'merge atomic audit/provider item suffix');
    if (run.latestCheckpointId === checkpoint.id && (run.frontierRef !== canonicalSha256(frontier) || run.nextStep !== frontier.kind))
      invalid('current merge cursor differs from its actual logical ready Checkpoint');
    authority.assertUnchanged(driver); ownerHistory.assertUnchanged(driver);
  }
  for (const batch of ordered.filter((item): item is ChildMergeBatchItem => item.kind === 'child_merge_batch')) {
    const prefix = outcomes.filter(item => item.mergeBatchItemId === batch.itemId);
    if (prefix.length > batch.calls.length || prefix.some((item, index) => item.callIndex !== index ||
        item.callId !== batch.calls[index]?.callId || index < prefix.length - 1 && item.outcome !== 'merged')) invalid('serial merge prefix is duplicated, skipped or retried after failure');
    const done = prefix.length && (prefix.at(-1)!.outcome !== 'merged' || prefix.length === batch.calls.length);
    if (done && !['failed', 'cancelled'].includes(run.status) && run.frontierRef) {
      const current = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
      if (current.kind === 'tool' && current.batchItemId === batch.itemId) invalid('completed merge retained an executable synthetic cursor');
    }
    if (!done && !['failed', 'cancelled'].includes(run.status)) {
      if (run.nextStep !== 'tool' || !run.frontierRef) invalid('unfinished merge was abandoned by a productive frontier');
      const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
      requireEqual(frontier, { schemaVersion: 1, kind: 'tool', batchItemId: batch.itemId,
        orderedCallIds: batch.calls.map(call => call.callId), nextCallIndex: prefix.length }, 'current exact unexecuted serial merge suffix');
    }
  }
  requireEqual(readRun(driver, run.id), run, 'completed child merge original recovery cut');
  return mergedAwaitResults;
}
