// Full read-only provenance of a committed no-child result. No child,
// capability, dispatch authority or retry permission is created by this read.
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { ChildAdmissionRefusalRequestV1, ChildAdmissionRefusalReceiptV1 } from '../kernel/child-admission-refusal.js';
import type { Checkpoint, ChildAllocationV1, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, SupervisorInspectorIdentityV1,
  ToolContractManifestV1 } from '../kernel/types.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { planChildBudgetAllocation } from '../kernel/child-budget.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { loadToolPolicy, planToolRequest } from '../policy/tool-policy.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { decodeDelegateRequest } from '../tools/child-inputs.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { readCanonicalArtifact } from './agent-context.js';
import { readModelTurnMaterial } from './agent-context.js';
import type { ModelRequestV1, NormalPromptProjectionV1 } from '../model/request.js';
import { validateModelTurn } from '../runtime/continuation.js';
import { readModelGrantData } from './model-grant.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildAdmission, childAdmissionKey } from './child-admission.js';
import { planChildAdmissionRefusal, childAdmissionRefusalCheckpointId } from './child-admission-refusal-artifacts.js';
import { readChildContinuationBudgetFloor } from './child-budget-floor.js';
import { decodeRunSpec, decodeSourceManifest } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { addBudget, childAllocationBudgetFacts, decodeChildAllocation } from './invariants.js';
import { readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal, readOperationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readRootRunAdmissionOrigin } from './run-admission-origin.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readToolApproval } from './tool-approval-recovery.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child refusal history ${message}`); }
const immutable = (run: Run) => ({ id: run.id, parentRunId: run.parentRunId ?? null, sessionId: run.sessionId, specRef: run.specRef, createdAt: run.createdAt, deadlineAt: run.deadlineAt });
function allocationOrigin(row: ChildAllocationV1) {
  const { state: _state, terminal: _terminal, inclusiveBudgetUsage: _usage, terminalAt: _at, childResultItemId: _item,
    parentSettlementRevision: _revision, releasedUnusedBudget: _unused, settledAt: _settled, ...origin } = row; return origin;
}

export async function validateChildAdmissionRefusalHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; items: ReadonlyMap<string, ContinuationItem>; journal: readonly InvocationJournalEntry[]; checkpoints: readonly Checkpoint[];
}) {
  const refused = new Set<string>(), { run, items, journal, checkpoints } = input, allItems = [...items.values()];
  const candidates = await artifacts.mapReads(journal.filter(row => row.opKind === 'child_admission' && row.phase === 'prepared'), async prepared => {
    const request = await readCanonicalArtifact<{ format?: string }>(artifacts, prepared.requestRef);
    if (request.format !== 'cliq-child-admission-refusal-request-v1' && request.format !== 'cliq-child-admission-request-v1') invalid('local admission has an unknown result branch');
    return { prepared, refusal: request.format === 'cliq-child-admission-refusal-request-v1' };
  });
  if (!candidates.some(row => row.refusal)) return refused;
  requireEqual(readRun(driver, run.id), run, 'refusal original recovery Run');
  const root = run.parentRunId ? undefined : await readRootRunAdmissionOrigin(driver, artifacts, run.id),
    incoming = run.parentRunId ? await readChildAdmission(driver, artifacts, run.id) : undefined,
    spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef)),
    assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef)),
    manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef),
    contracts = await artifacts.mapReads(manifest.entries, async entry => {
      const inputSchema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
      if (canonicalSha256(inputSchema) !== entry.inputSchemaDigest || entry.outputSchemaRef !== undefined &&
          canonicalSha256(await readCanonicalArtifact(artifacts, entry.outputSchemaRef)) !== entry.outputSchemaDigest) invalid('changed an original tool schema');
      return { ...entry, inputSchema };
    }),
    toolContracts = loadToolContracts(contracts), session = readSession(driver, run.sessionId), principalId = readSessionPrincipalId(driver, run.sessionId),
    sourceManifest = decodeSourceManifest(await readCanonicalArtifact(artifacts, spec.baseWorkspaceManifestRef)),
    policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, spec.policyRef),
    evaluator = loadToolPolicy({ policy, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef, principalId,
      workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: sourceManifest.workspaceIdentityDigest, contracts });
  if (manifest.schemaVersion !== 1 || manifest.format !== 'cliq-tool-contracts-v1' || manifest.manifestDigest !== assembly.tools.manifestDigest ||
      digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) invalid('lost its complete frozen tool manifest');
  for (const { prepared, refusal } of candidates) {
    if (!refusal) continue;
    const request = await readCanonicalArtifact<ChildAdmissionRefusalRequestV1>(artifacts, prepared.requestRef),
      original = decodeWireRun(await readCanonicalArtifact(artifacts, request.parentRunSnapshotRef)), checkpoint = readCheckpoint(driver, request.sourceCheckpointId),
      rows = readOperationJournal(driver, run.id, prepared.opId), [first, claim, completed] = rows;
    if (rows.length !== 3 || rows.map(row => row.phase).join(',') !== 'prepared,dispatch_claimed,completed' || rows.some((row, i) => row.seq !== prepared.seq + i ||
        row.opKind !== 'child_admission' || row.leaseEpoch !== 0 || row.attempt !== 0 || row.replayClass !== 'retry' || row.timestamp !== prepared.timestamp ||
        row.localCommittedAt !== prepared.localCommittedAt || row.requestRef !== prepared.requestRef || row.grantRef !== request.delegateOperationGrantRef || row.target !== prepared.target))
      invalid('lost its exact original local attempt');
    requireEqual(first, prepared, 'original actual no-child preparation'); requireEqual(immutable(original), immutable(run), 'refusal immutable parent origin');
    if (original.status !== 'queued' || original.nextStep !== 'tool' || original.activeWorkerLaunchId || original.stopIntentRef || original.cancelRequested ||
        original.waitingReason || original.waitingOnRef || original.revision >= run.revision || original.latestCheckpointId !== checkpoint.id ||
        checkpoint.runId !== run.id || original.revision !== checkpoint.basedOnRunRevision + 1 || original.updatedAt !== checkpoint.createdAt ||
        checkpoint.journalSeq !== prepared.seq - 1 || prepared.timestamp < original.updatedAt || request.preparedAt !== prepared.timestamp)
      invalid('original refusal did not own a ready parent Checkpoint');
    const latest = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? AND based_on_run_revision<? ORDER BY based_on_run_revision DESC,rowid DESC LIMIT 1')
      .get<{id:string}>(run.id, original.revision);
    if (latest?.id !== checkpoint.id) invalid('substituted another original source Checkpoint');
    const retainedToolRequest = await readCanonicalArtifact<import('../kernel/tool-authorization.js').ToolRequestV1>(artifacts, request.toolRequestRef),
      actualBatch = items.get(retainedToolRequest.batchItemId);
    if (actualBatch?.kind !== 'assistant_tool_batch') invalid('lost its real delegate assistant batch');
    const identity = actualBatch.calls[retainedToolRequest.callIndex], observed = identity && await readCanonicalArtifact<ToolCallInputV1>(artifacts, identity.inputRef);
    if (!identity || !observed || identity.callId !== retainedToolRequest.callId || identity.toolName !== 'delegate' || observed.disposition !== 'resolved' ||
        observed.callId !== identity.callId || observed.index !== identity.index || observed.toolName !== identity.toolName || observed.inputDigest !== identity.inputDigest)
      invalid('changed its normalized real delegate call');
    const observedInput = await readCanonicalArtifact<import('../protocol/agent-ir.js').ObservedToolCallInputV1>(artifacts, observed.observedInputRef),
      resolved = toolContracts.resolveToolInput({ callId: observed.callId, index: observed.index, toolName: observed.toolName, observedInput });
    if (resolved.kind !== 'resolved' || resolved.inputSchemaRef !== observed.inputSchemaRef || resolved.inputSchemaDigest !== observed.inputSchemaDigest ||
        canonicalSha256(resolved.value) !== canonicalSha256(observed.value)) invalid('original delegate no longer satisfies its frozen input contract');
    const call = observed;
    if (allItems.indexOf(actualBatch) + 1 > checkpoint.runItemSeq) invalid('borrowed an assistant batch after its original source cut');
    const modelCompleted = journal.find(row => row.opKind === 'model' && row.phase === 'completed' && row.opId === actualBatch.modelOpId &&
      row.attempt === actualBatch.modelAttempt && row.resultRef === actualBatch.modelTurnRef && row.seq < prepared.seq),
      modelPrepared = modelCompleted && journal.find(row => row.opId === modelCompleted.opId && row.attempt === modelCompleted.attempt && row.phase === 'prepared');
    if (!modelCompleted || !modelPrepared?.grantRef) invalid('has no originating complete model invocation');
    const modelRequest = await readCanonicalArtifact<ModelRequestV1>(artifacts, modelPrepared.requestRef),
      modelProjection = await readCanonicalArtifact<NormalPromptProjectionV1>(artifacts, modelRequest.promptProjectionRef),
      modelFrontier = await readCanonicalArtifact<RunFrontier>(artifacts, modelProjection.frontierDigest);
    if (modelFrontier.kind !== 'agent') invalid('lost the original model frontier');
    await readModelGrantData(artifacts, { principalId, run: original, spec, assembly, frontier: modelFrontier, frontierRef: modelProjection.frontierDigest,
      request: modelRequest, requestRef: modelPrepared.requestRef, grantRef: modelPrepared.grantRef });
    const modelMaterial = await readModelTurnMaterial(artifacts, actualBatch.modelTurnRef);
    validateModelTurn(modelRequest, modelMaterial, toolContracts.resolveToolInput);
    requireEqual(actualBatch.calls, modelMaterial.turn.toolCalls, 'complete original no-child assistant batch');
    if ((await artifacts.readBytes(modelRequest.bodyBytesRef)).byteLength !== modelRequest.bodyByteCount) invalid('original model request bytes changed');
    const delegated = decodeDelegateRequest(call.value), frontier: RunFrontier = { schemaVersion: 1, kind: 'tool', batchItemId: actualBatch.itemId,
      orderedCallIds: actualBatch.calls.map(call => call.callId), nextCallIndex: retainedToolRequest.callIndex };
    if (original.frontierRef !== canonicalSha256(frontier)) invalid('changed its original provider cursor');
    const entry = contracts.find(entry => entry.name === 'delegate');
    if (entry?.execution.kind !== 'supervisor_operation' || entry.execution.handlerId !== 'delegate') invalid('lost its signed Supervisor delegate contract');
    const planned = planToolRequest({ runId: run.id, frontierRef: original.frontierRef!, batchItemId: actualBatch.itemId, assemblyRef: spec.assemblyRef,
      assembly, workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: sourceManifest.workspaceIdentityDigest, entry, call });
    requireEqual(retainedToolRequest, planned.request, 'complete original no-child tool request');
    const capturedValue = await readCanonicalArtifact<unknown>(artifacts, request.parentChildAllocationsRef);
    if (!Array.isArray(capturedValue)) invalid('has no original outgoing allocation snapshot');
    const captured = capturedValue.map(decodeChildAllocation), prior = readChildAllocationsForRun(driver, run.id).filter(row => row.parentRunId === run.id &&
      (readOperationJournal(driver, run.id, row.delegateOpId)[0]?.seq ?? Number.MAX_SAFE_INTEGER) < prepared.seq), rank = { reserved: 0, child_terminal: 1, settled: 2 };
    if (captured.length !== prior.length) invalid('original sibling set is incomplete');
    for (const [i, row] of captured.entries()) {
      const current = prior[i]; if (!current || row.parentRunId !== run.id || row.childRunId !== current.childRunId || row.createdAt > prepared.timestamp) invalid('changed its exact original sibling order');
      requireEqual(allocationOrigin(row), allocationOrigin(current), 'immutable original refusal sibling');
      if (rank[row.state] > rank[current.state] || row.state !== 'reserved' && (current.state === 'reserved' || row.terminalAt > prepared.localCommittedAt! ||
          canonicalSha256(row.terminal) !== canonicalSha256(current.terminal) || canonicalSha256(row.inclusiveBudgetUsage) !== canonicalSha256(current.inclusiveBudgetUsage))) invalid('invented an original sibling terminal');
      if (row.state === 'settled') requireEqual(row, current, 'original refusal sibling settlement');
    }
    const prefix = allItems.slice(0, checkpoint.runItemSeq), repairs = prefix.filter(item => item.kind === 'repair_diagnostic'), groups = new Map<string, InvocationJournalEntry[]>();
    if (repairs.length !== original.repairCount || repairs.some((item, i) => item.kind !== 'repair_diagnostic' || item.repairOrdinal !== i + 1)) invalid('changed original repair history');
    let consumed = { ...ZERO_BUDGET, repairAttempts: original.repairCount }, reserved = { ...ZERO_BUDGET };
    for (const [i, row] of journal.slice(0, checkpoint.journalSeq).entries()) { if (row.seq !== i + 1) invalid('original Journal prefix has a gap');
      const key = `${row.opId}\0${row.attempt}`, group = groups.get(key) ?? []; group.push(row); groups.set(key, group); }
    for (const group of groups.values()) { const terminal = group.find(row => ['completed', 'failed', 'unknown'].includes(row.phase));
      if (group[0]?.phase !== 'prepared' || !terminal || !['completed', 'failed'].includes(group.at(-1)!.phase)) invalid('overtook an original unresolved invocation');
      consumed = addBudget(consumed, terminal.budgetDelta); }
    const budgetFacts = childAllocationBudgetFacts(run.id, captured); consumed = addBudget(consumed, budgetFacts.consumed); reserved = addBudget(reserved, budgetFacts.reserved);
    requireEqual(consumed, original.budgetConsumed, 'refusal exact original inclusive consumed budget');
    requireEqual(reserved, original.budgetReserved, 'refusal exact original conservative budget');
    const leases = readWorkerLaunchesForRun(driver, run.id).flatMap(worker => worker.activatedAt && worker.leaseEpoch !== undefined && worker.plannedRunRevision < original.revision ? [worker.leaseEpoch] : []);
    if (original.leaseEpoch !== Math.max(0, ...leases)) invalid('invented an original worker lease');
    const floor = await readChildContinuationBudgetFloor(artifacts, { parentRunId: run.id, assembly, allocations: captured, nextMode: delegated.mode }),
      proposal = planChildBudgetAllocation({ parent: { budgets: spec.budgets, consumed, reserved, deadlineAt: original.deadlineAt }, requestedBudgets: delegated.requestedBudgets,
        createdAt: prepared.timestamp, nonterminalDirectChildren: budgetFacts.nonterminalDirectChildren, continuationFloor: floor });
    if (proposal.kind !== 'refused' || proposal.reason !== request.reason) invalid('has no reproducible original no-child condition');
    requireEqual(floor, request.continuationFloor, 'exact shared original continuation floor');
    const evidence = evaluator.evaluate(planned.request, planned.target, call, prepared.timestamp), policyItem = prefix.filter(item => item.kind === 'policy_decision' && item.opId === prepared.opId).at(-1),
      approved = policyItem?.kind === 'policy_decision' && policyItem.decisionSource === 'interactive_approval' && policyItem.decision === 'allow'
        ? await readToolApproval(driver, artifacts, original, evaluator, policyItem.decisionRef) : undefined;
    const grant = approved?.grant && approved.grant.expiresAt > prepared.timestamp ? approved.grant
      : evidence.effectiveDisposition === 'allow' ? evaluator.grant(planned.request, planned.target, call, evidence, prepared.timestamp, original.deadlineAt) : undefined;
    if (!grant || grant.issuedAt > prepared.timestamp || grant.expiresAt <= prepared.localCommittedAt! || prepared.localCommittedAt! >= original.deadlineAt) invalid('has no original live exact delegate permission');
    const receipt = await readCanonicalArtifact<ChildAdmissionRefusalReceiptV1>(artifacts, completed.resultRef!), inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, receipt.inspectorIdentityRef),
      ownerHistory = await readRetainedStateOwnerHistory(driver, artifacts, inspector.stateOwnerEpoch), owner = ownerHistory.entries.at(-1)!.owner,
      checked = await readSupervisorInspector(artifacts, owner, assembly, { ...receipt, observedAt: prepared.localCommittedAt! });
    if (owner.acquiredAt > prepared.timestamp || owner.state === 'terminal' && owner.releasedAt < prepared.localCommittedAt! || claim.stateOwnerEpoch !== owner.ownerEpoch ||
        claim.supervisorInstanceId !== owner.supervisorInstanceId || checked.supervisorEntryId !== entry.execution.supervisorEntryId ||
        checked.supervisorEntryVersion !== entry.execution.supervisorEntryVersion || checked.supervisorExecutableDigest !== entry.execution.supervisorExecutableDigest)
      invalid('lost actual signed Supervisor provenance through its commit');
    const expected = planChildAdmissionRefusal({ parent: original, allocations: captured, request: planned.request, target: planned.target, grant, evidence, inspector,
      preparedAt: prepared.timestamp, reason: proposal.reason, continuationFloor: floor, journalSeq: prepared.seq });
    if (expected.requestPlan.ref !== prepared.requestRef || expected.grantPlan.ref !== prepared.grantRef || prepared.target !== planned.request.targetRef || completed.resultRef !== expected.receiptPlan.ref ||
        completed.budgetSettlementRef !== expected.settlementPlan.ref || prepared.idempotencyKey !== childAdmissionKey(run.id, actualBatch.itemId, call.callId, call.index, call.inputDigest) ||
        claim.dispatchId !== identityHash('cliq-child-local-claim-v1', run.id, prepared.opId, prepared.requestRef) || completed.dispatchId !== claim.dispatchId)
      invalid('changed the unique original refusal request or accounting identity');
    for (const plan of expected.plans) if (!Buffer.from(await artifacts.readBytes(plan.ref)).equals(Buffer.from(plan.bytes))) invalid('complete original refusal bytes changed');
    const committed = checkpoints.find(cp => cp.id === childAdmissionRefusalCheckpointId(run.id, prepared.opId)), appended = [...(approved ? [] : [expected.decision]), expected.item];
    if (!committed || committed.basedOnRunRevision !== original.revision || committed.createdAt !== prepared.localCommittedAt || committed.workspaceStateRef !== checkpoint.workspaceStateRef ||
        committed.journalSeq !== completed.seq || committed.runItemSeq !== checkpoint.runItemSeq + appended.length) invalid('has no unique atomic refusal result Checkpoint');
    requireEqual(allItems.slice(checkpoint.runItemSeq, committed.runItemSeq), appended, 'exact no-child audit/result suffix');
    if (prior.some(row => row.delegateOpId === prepared.opId) || driver.prepare("SELECT 1 FROM runs WHERE parent_run_id=? AND admission_request_id=?").get(run.id, prepared.opId)) invalid('refusal also admitted a child');
    ownerHistory.assertUnchanged(driver); refused.add(prepared.opId);
  }
  root?.assertUnchanged(driver);
  if (incoming) { for (const edge of [incoming, ...incoming.ancestors]) edge.assertUnchanged(driver); incoming.rootOrigin.assertUnchanged(driver); }
  requireEqual(readInvocationJournal(driver, run.id), journal, 'refusal final exact Journal'); requireEqual(readRun(driver, run.id), run, 'refusal final actual Run');
  return refused;
}
