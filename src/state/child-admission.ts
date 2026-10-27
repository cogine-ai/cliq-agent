// Retained child admission data only. This never opens a workspace, creates a
// StateOwner/Run, consumes another grant or authorizes execution/settlement.
import { planChildBudgetAllocation } from '../kernel/child-budget.js';
import { readChildContinuationBudgetFloor } from './child-budget-floor.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeWireRun } from '../kernel/control-wire-data.js';
import { digestOmitting, identityHash, addCanonicalDuration } from '../kernel/identity.js';
import type { ChildAdmissionReceiptV1, ChildAdmissionRequestV1, ChildCapabilityGrantV1, ChildHandleItem } from '../kernel/children.js';
import type { ChildAllocationV1, ContinuationItem, Run, RunAssemblyV1, RunFrontier, RunSpec, ToolBatchItem, ToolContractManifestV1 } from '../kernel/types.js';
import type { ToolOperationGrantV1, ToolPolicyChannelEvidenceV1, ToolRequestV1, ToolTargetV1, RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import type { ModelRequestV1, NormalPromptProjectionV1 } from '../model/request.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { childDelegateOperationId, loadToolPolicy } from '../policy/tool-policy.js';
import { loadToolContracts } from '../tools/input-contract.js';
import { decodeDelegateRequest } from '../tools/child-inputs.js';
import { validateModelTurn } from '../runtime/continuation.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact, readModelTurnMaterial } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { planChildAdmittedContext } from './child-context.js';
import { planChildComposition } from './child-composition.js';
import { decodeContextManifest, decodeRunSpec, decodeRunObjective, decodeWorkspaceState, decodeSourceManifest } from './decoders.js';
import { readIncomingChildAllocation, readChildAllocationsForRun } from './repositories/child-allocations.js';
import { readInvocationJournal, readOperationJournal } from './repositories/journal.js';
import { readCheckpoint, readRun, readSession } from './rows.js';
import { readCandidateSource } from './result-source.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readRootRunAdmissionOrigin } from './run-admission-origin.js';
import { KernelStorageError } from './errors.js';
import { addBudget, childAllocationBudgetFacts, decodeChildAllocation } from './invariants.js';
import { readModelGrantData } from './model-grant.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readToolApproval } from './tool-approval-recovery.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child admission ${message}`); }
export const childAdmissionKey = (runId: string, batch: string, call: string, index: number, inputDigest: string) =>
  identityHash('cliq-child-admission-key-v1', runId, batch, String(index), call, inputDigest);
const immutableRun = (run: Run) => ({ id: run.id, sessionId: run.sessionId, parentRunId: run.parentRunId ?? null,
  specRef: run.specRef, createdAt: run.createdAt, deadlineAt: run.deadlineAt });

/** Full original input/SQL ownership graph; callers still verify their current
 * signed runtime and the child-bound verifier/consent branch independently. */
async function readDirectChildAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, childRunId: string,
  options: { signal?: AbortSignal } = {}) {
  const reads = options.signal ? artifacts.withReadSignal(options.signal) : artifacts;
  reads.assertReadActive();
  const cut = driver.readSnapshot(connection => {
    const run = readRun(connection, childRunId), allocation = readIncomingChildAllocation(connection, childRunId);
    if (!run.parentRunId || !allocation || allocation.parentRunId !== run.parentRunId) invalid('has no unique direct original parent');
    const parent = readRun(connection, run.parentRunId), rows = readOperationJournal(connection, parent.id, allocation.delegateOpId);
    const admission = connection.prepare(`SELECT principal_id,admission_method,admission_key,admission_intent_digest,
      admitted_request_digest,admission_request_id FROM runs WHERE id = ?`).get<{
      principal_id: string; admission_method: string; admission_key: string; admission_intent_digest: string;
      admitted_request_digest: string; admission_request_id: string }>(childRunId);
    const parentPrincipal = connection.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(parent.id)?.principal_id;
    return { run, parent, allocation, rows, admission, parentPrincipal };
  });
  const { run, parent: currentParent, allocation, rows, admission } = cut;
  if (!admission || !cut.parentPrincipal || admission.principal_id !== cut.parentPrincipal || admission.admission_method !== 'delegate' ||
      rows.length !== 3 || rows.map(row => row.phase).join(',') !== 'prepared,dispatch_claimed,completed') invalid('has no complete original local Journal owner');
  const [prepared, claim, completed] = rows;
  if (rows.some((row, i) => row.opKind !== 'child_admission' || row.runId !== currentParent.id || row.opId !== allocation.delegateOpId ||
      row.attempt !== 0 || row.leaseEpoch !== 0 || row.replayClass !== 'retry' || row.seq !== prepared.seq + i ||
      row.timestamp !== prepared.timestamp || row.localCommittedAt !== prepared.localCommittedAt || row.requestRef !== prepared.requestRef ||
      row.grantRef !== allocation.delegateOperationGrantRef || row.idempotencyKey !== allocation.admissionKey) ||
      claim.dispatchId !== completed.dispatchId || claim.stateOwnerEpoch !== completed.stateOwnerEpoch ||
      claim.supervisorInstanceId !== completed.supervisorInstanceId || completed.resultRef === undefined)
    invalid('changed its local operation identity or atomic commit');
  const request = await readCanonicalArtifact<ChildAdmissionRequestV1>(reads, prepared.requestRef);
  if (!exactKeys(request, ['schemaVersion', 'format', 'parentRunId', 'childRunId', 'parentRunSnapshotRef', 'parentChildAllocationsRef',
    'parentCheckpointId', 'toolRequestRef', 'delegateOperationGrantRef', 'capabilityGrantRef', 'admissionKey', 'childSpecRef',
    'childWorkspaceStateRef', 'childContextManifestRef', 'childFrontierRef', 'preparedAt', 'requestDigest']) ||
      request.schemaVersion !== 1 || request.format !== 'cliq-child-admission-request-v1' ||
      request.requestDigest !== digestOmitting(request, 'requestDigest') || request.parentRunId !== currentParent.id || request.childRunId !== run.id ||
      request.admissionKey !== allocation.admissionKey || request.delegateOperationGrantRef !== allocation.delegateOperationGrantRef ||
      request.capabilityGrantRef !== allocation.capabilityGrantRef || request.childSpecRef !== run.specRef ||
      admission.admitted_request_digest !== prepared.requestRef || admission.admission_intent_digest !== request.toolRequestRef ||
      admission.admission_key !== allocation.admissionKey || admission.admission_request_id !== allocation.delegateOpId ||
      request.preparedAt !== prepared.timestamp || run.createdAt !== request.preparedAt || allocation.createdAt !== request.preparedAt)
    invalid('request is not its exact committed immutable origin');
  const parent = decodeWireRun(await readCanonicalArtifact(reads, request.parentRunSnapshotRef));
  requireEqual(immutableRun(parent), immutableRun(currentParent), 'child original parent immutable fields');
  if (parent.status !== 'queued' || parent.activeWorkerLaunchId || parent.cancelRequested || parent.stopIntentRef ||
      parent.revision >= currentParent.revision || parent.latestCheckpointId !== request.parentCheckpointId ||
      parent.sessionId !== run.sessionId || parent.createdAt > run.createdAt || parent.deadlineAt < run.deadlineAt)
    invalid('original parent was not its worker-free current productive cut');
  const parentSpec = decodeRunSpec(await readCanonicalArtifact(reads, parent.specRef));
  const spec = decodeRunSpec(await readCanonicalArtifact(reads, run.specRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(reads, parentSpec.assemblyRef));
  const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(reads, parentSpec.policyRef);
  const checkpoint = readCheckpoint(driver, parent.latestCheckpointId);
  if (checkpoint.runId !== parent.id || checkpoint.journalSeq !== prepared.seq - 1 || checkpoint.basedOnRunRevision >= parent.revision)
    invalid('source Checkpoint does not precede its exact local Journal');
  const parentContext = decodeContextManifest(await readCanonicalArtifact(reads, checkpoint.contextManifestRef));
  const parentWorkspace = decodeWorkspaceState(await readCanonicalArtifact(reads, checkpoint.workspaceStateRef));
  if (parentContext.runId !== parent.id || parentContext.assemblyRef !== parentSpec.assemblyRef ||
      parentContext.admittedContextRef !== parentSpec.admittedContextRef || parentContext.throughItemSeq !== checkpoint.runItemSeq ||
      parentWorkspace.runId !== parent.id || parentWorkspace.baseWorkspaceManifestRef !== parentSpec.baseWorkspaceManifestRef)
    invalid('source context or workspace substituted its original parent Checkpoint');
  const readContextRows = (connection: SqliteConnection) => connection.prepare('SELECT item_id,kind,item_seq,payload_ref FROM items WHERE run_id = ? AND item_seq <= ? ORDER BY item_seq')
    .all<{ item_id: string; kind: string; item_seq: unknown; payload_ref: string }>(parent.id, checkpoint.runItemSeq)
    .map(row => ({ ...row, item_seq: Number(row.item_seq) }));
  const contextRows = readContextRows(driver);
  const contextItems = await reads.mapReads(contextRows, async row => {
    const item = await readCanonicalArtifact<ContinuationItem>(reads, row.payload_ref);
    if (item.itemId !== row.item_id || item.kind !== row.kind) invalid('original parent context item changed its SQL owner');
    return { itemSeq: row.item_seq, itemRef: row.payload_ref, item };
  });
  if (contextItems.length !== checkpoint.runItemSeq) invalid('original parent context is not its complete retained item prefix');
  validateContextItems(parentContext, contextItems);
  const toolRequest = await readCanonicalArtifact<ToolRequestV1>(reads, request.toolRequestRef);
  const target = await readCanonicalArtifact<ToolTargetV1>(reads, toolRequest.targetRef);
  const call = await readCanonicalArtifact<ToolCallInputV1>(reads, toolRequest.inputRef);
  const delegated = decodeDelegateRequest(call.value);
  if (toolRequest.toolName !== 'delegate' || target.execution.kind !== 'supervisor_operation' || target.execution.handlerId !== 'delegate' ||
      prepared.target !== toolRequest.targetRef || toolRequest.opId !== allocation.delegateOpId ||
      toolRequest.batchItemId !== allocation.delegateBatchItemId || toolRequest.callId !== allocation.delegateCallId ||
      toolRequest.callIndex !== allocation.delegateCallIndex || toolRequest.opId !== childDelegateOperationId(parent.id,
        toolRequest.batchItemId, toolRequest.callId, toolRequest.callIndex, toolRequest.inputDigest) ||
      allocation.admissionKey !== childAdmissionKey(parent.id, toolRequest.batchItemId, toolRequest.callId, toolRequest.callIndex, toolRequest.inputDigest) ||
      run.id !== identityHash('cliq-run-id-v1', cut.parentPrincipal, 'delegate', allocation.admissionKey))
    invalid('does not bind the complete normalized original delegate identity');
  const manifest = await readCanonicalArtifact<ToolContractManifestV1>(reads, assembly.tools.manifestRef);
  const contracts = await reads.mapReads(manifest.entries, async entry => ({ ...entry,
    inputSchema: await readCanonicalArtifact(reads, entry.inputSchemaRef) }));
  const tools = loadToolContracts(contracts);
  const batchRow = driver.prepare('SELECT run_id,kind,payload_ref,item_seq FROM items WHERE item_id = ?')
    .get<{ run_id: string; kind: string; payload_ref: string; item_seq: unknown }>(allocation.delegateBatchItemId);
  if (!batchRow || batchRow.run_id !== parent.id || batchRow.kind !== 'assistant_tool_batch' || Number(batchRow.item_seq) > checkpoint.runItemSeq)
    invalid('delegate has no original owned assistant batch');
  const batch = await readCanonicalArtifact<ToolBatchItem>(reads, batchRow.payload_ref);
  const selectedCall = batch.calls[allocation.delegateCallIndex];
  if (!selectedCall || selectedCall.callId !== allocation.delegateCallId || selectedCall.toolName !== 'delegate' ||
      selectedCall.inputRef !== toolRequest.inputRef || selectedCall.inputDigest !== call.inputDigest)
    invalid('delegate input was substituted behind its model batch');
  const parentJournal = readInvocationJournal(driver, parent.id);
  const modelCompleted = parentJournal.find(row => row.opKind === 'model' && row.phase === 'completed' &&
    row.opId === batch.modelOpId && row.attempt === batch.modelAttempt && row.resultRef === batch.modelTurnRef && row.seq < prepared.seq);
  const modelPrepared = modelCompleted && parentJournal.find(row => row.opId === modelCompleted.opId && row.attempt === modelCompleted.attempt && row.phase === 'prepared');
  if (!modelCompleted || !modelPrepared?.grantRef) invalid('delegate has no original completed model request');
  const modelRequest = await readCanonicalArtifact<ModelRequestV1>(reads, modelPrepared.requestRef);
  const projection = await readCanonicalArtifact<NormalPromptProjectionV1>(reads, modelRequest.promptProjectionRef);
  const modelFrontier = await readCanonicalArtifact<RunFrontier>(reads, projection.frontierDigest);
  if (modelFrontier.kind !== 'agent') invalid('delegate model source has no original agent frontier');
  await readModelGrantData(reads, { principalId: cut.parentPrincipal, run: parent, spec: parentSpec, assembly,
    frontier: modelFrontier, frontierRef: projection.frontierDigest, request: modelRequest, requestRef: modelPrepared.requestRef, grantRef: modelPrepared.grantRef });
  const modelMaterial = await readModelTurnMaterial(reads, batch.modelTurnRef);
  validateModelTurn(modelRequest, modelMaterial, tools.resolveToolInput);
  requireEqual(batch.calls, modelMaterial.turn.toolCalls, 'original delegate assistant call batch');
  if ((await reads.readBytes(modelRequest.bodyBytesRef)).byteLength !== modelRequest.bodyByteCount) invalid('original model request bytes changed');
  const base = decodeSourceManifest(await readCanonicalArtifact(reads, parentSpec.baseWorkspaceManifestRef));
  const session = readSession(driver, parent.sessionId);
  const evaluator = loadToolPolicy({ policy, policyRef: parentSpec.policyRef, assembly, assemblyRef: parentSpec.assemblyRef,
    principalId: cut.parentPrincipal, workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: base.workspaceIdentityDigest, contracts });
  const grant = await readCanonicalArtifact<ToolOperationGrantV1>(reads, allocation.delegateOperationGrantRef);
  const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(reads, grant.provenance.channelEvidenceRef);
  const expectedGrant = grant.provenance.kind === 'user_approval'
    ? (await readToolApproval(driver, reads, parent, evaluator, grant.provenance.decisionRef)).grant
    : evaluator.grant(toolRequest, target, call, evidence, grant.issuedAt, grant.expiresAt);
  requireEqual(grant, expectedGrant, 'exact original delegate operation grant');
  if (grant.subject.policySubjectKind !== 'child_delegate' || grant.subject.mode !== allocation.mode || delegated.mode !== allocation.mode ||
      prepared.timestamp < grant.issuedAt || prepared.localCommittedAt! < grant.issuedAt || prepared.localCommittedAt! >= grant.expiresAt ||
      prepared.localCommittedAt! >= parent.deadlineAt || prepared.localCommittedAt! >= run.deadlineAt)
    invalid('local admission exceeds its mode, original grant or true final commit lifetime');
  const capabilityGrant = await readCanonicalArtifact<ChildCapabilityGrantV1>(reads, allocation.capabilityGrantRef);
  if (!exactKeys(capabilityGrant, ['schemaVersion', 'format', 'parentRunId', 'delegateBatchItemId', 'delegateCallId', 'delegateCallIndex', 'delegateOpId',
    'mode', 'parentAssemblyRef', 'parentPolicyRef', 'granted', 'childToolManifestRef', 'childToolManifestDigest', 'childAssemblyRef', 'childPolicyRef',
    'verifierMode', 'childVerifierSpecRef', 'childCredentialGrantRefs', 'grantedBudgets', 'childDeadlineAt', 'grantCoreDigest', 'grantDigest',
    ...(capabilityGrant.childDependencyPolicyRef === undefined ? [] : ['childDependencyPolicyRef']),
    ...(capabilityGrant.derivedUnverifiedConsentRef === undefined ? [] : ['derivedUnverifiedConsentRef'])]) ||
      capabilityGrant.schemaVersion !== 1 || capabilityGrant.format !== 'cliq-child-capability-grant-v1' ||
      capabilityGrant.grantDigest !== digestOmitting(capabilityGrant, 'grantDigest')) invalid('capability grant is not closed original data');
  const { grantDigest: _digest, grantCoreDigest: _core, derivedUnverifiedConsentRef: _consent, ...grantCore } = capabilityGrant;
  if (canonicalSha256(grantCore) !== capabilityGrant.grantCoreDigest || capabilityGrant.parentRunId !== parent.id ||
      capabilityGrant.delegateBatchItemId !== allocation.delegateBatchItemId || capabilityGrant.delegateCallId !== allocation.delegateCallId ||
      capabilityGrant.delegateCallIndex !== allocation.delegateCallIndex || capabilityGrant.delegateOpId !== allocation.delegateOpId ||
      capabilityGrant.mode !== allocation.mode || capabilityGrant.parentAssemblyRef !== parentSpec.assemblyRef || capabilityGrant.parentPolicyRef !== parentSpec.policyRef ||
      capabilityGrant.childAssemblyRef !== spec.assemblyRef || capabilityGrant.childPolicyRef !== spec.policyRef ||
      capabilityGrant.childVerifierSpecRef !== spec.verifierSpecRef || capabilityGrant.childDependencyPolicyRef !== spec.dependencyPolicyRef ||
      capabilityGrant.derivedUnverifiedConsentRef !== spec.unverifiedConsentRef || capabilityGrant.childDeadlineAt !== run.deadlineAt ||
      capabilityGrant.verifierMode !== delegated.verifierMode || run.deadlineAt !== addCanonicalDuration(run.createdAt, spec.budgets.wallTimeMs))
    invalid('capability grant changed the exact original delegate or child spec');
  requireEqual(capabilityGrant.grantedBudgets, spec.budgets, 'child exact granted Run ceilings');
  requireEqual(allocation.grantedAdditiveCeilings, { modelTokens: spec.budgets.modelTokens, costMicros: spec.budgets.costMicros,
    toolCalls: spec.budgets.toolCalls, repairAttempts: spec.budgets.repairAttempts }, 'child exact allocation additive projection');
  if (allocation.grantedChildDepth !== spec.budgets.childDepth || allocation.grantedChildConcurrency !== spec.budgets.childConcurrency)
    invalid('allocation changed the original granted depth or concurrency');
  if (decodeRunObjective(await readCanonicalArtifact(reads, spec.objectiveRef)).utf8 !== delegated.objective)
    invalid('objective differs from the original normalized delegate request');
  const composition = await planChildComposition(reads, { request: delegated, parentSpec, principalId: cut.parentPrincipal,
    workspaceIdentityDigest: base.workspaceIdentityDigest, delegateRequestRef: request.toolRequestRef, grantedBudgets: spec.budgets, createdAt: run.createdAt });
  requireEqual(capabilityGrant.granted, composition.granted, 'child exact capability intersection');
  requireEqual(spec.credentialGrantRefs, composition.credentialGrantRefs, 'child exact original credential union');
  requireEqual(capabilityGrant.childCredentialGrantRefs, composition.credentialGrantRefs, 'child capability credential union');
  if (canonicalSha256(composition.assembly) !== spec.assemblyRef || canonicalSha256(composition.policy) !== spec.policyRef ||
      capabilityGrant.childToolManifestRef !== composition.assembly.tools.manifestRef || capabilityGrant.childToolManifestDigest !== composition.tools.manifestDigest)
    invalid('child assembly or policy is not its original deterministic narrowing');
  const contextPlan = await planChildAdmittedContext(driver, reads, { parent, parentSpec, assembly, context: parentContext, request: delegated });
  if (contextPlan.plan.ref !== spec.admittedContextRef) invalid('child model context is not its full original parent-visible projection');
  await readCanonicalArtifact(reads, spec.admittedContextRef);
  for (const text of contextPlan.textPlans) await readCanonicalArtifact(reads, text.ref);
  const parentSource = await readCandidateSource(reads, parentSpec, checkpoint.workspaceStateRef, options.signal);
  const childBase = { ...parentSource.source, role: 'base' as const, manifestDigest: '' };
  childBase.manifestDigest = digestOmitting(childBase, 'manifestDigest');
  if (canonicalSha256(childBase) !== spec.baseWorkspaceManifestRef || spec.sourceProjectionRef !== parentSpec.sourceProjectionRef ||
      spec.sandboxProfileRef !== parentSpec.sandboxProfileRef) invalid('child fork changed its exact original ready source graph');
  const childInitial = readCheckpoint(driver, identityHash('cliq-checkpoint-id-v1', run.id, 'initial', 0));
  const workspace = decodeWorkspaceState(await readCanonicalArtifact(reads, request.childWorkspaceStateRef));
  const childWorkspace = { ...parentWorkspace, runId: run.id, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef, stateDigest: '' };
  childWorkspace.stateDigest = digestOmitting(childWorkspace, 'stateDigest');
  requireEqual(workspace, childWorkspace, 'child independent Run workspace origin');
  const initialContext = decodeContextManifest(await readCanonicalArtifact(reads, request.childContextManifestRef));
  requireEqual(initialContext, { schemaVersion: 1, format: 'cliq-context-manifest-v1', runId: run.id, throughItemSeq: 0,
    admittedContextRef: spec.admittedContextRef, segments: [], assemblyRef: spec.assemblyRef,
    projectionDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-context-manifest-v1', runId: run.id, throughItemSeq: 0,
      admittedContextRef: spec.admittedContextRef, segments: [], assemblyRef: spec.assemblyRef }) }, 'child initial context');
  const initialFrontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: identityHash('cliq-turn-id-v1', run.id, 'initial'), contextItemSeq: 0, cause: 'initial' };
  if (canonicalSha256(initialFrontier) !== request.childFrontierRef) invalid('initial child frontier is not its exact independent Run origin');
  await readCanonicalArtifact(reads, request.childFrontierRef);
  if (childInitial.basedOnRunRevision !== 0 || childInitial.runItemSeq !== 0 || childInitial.journalSeq !== 0 || childInitial.createdAt !== run.createdAt ||
      childInitial.contextManifestRef !== request.childContextManifestRef || childInitial.workspaceStateRef !== request.childWorkspaceStateRef)
    invalid('lost its exact initial independent Checkpoint');
  const receipt = await readCanonicalArtifact<ChildAdmissionReceiptV1>(reads, completed.resultRef);
  if (!exactKeys(receipt, ['schemaVersion', 'format', 'parentRunId', 'childRunId', 'requestRef', 'childSpecRef', 'childHandleItemRef',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'preparedAt', 'receiptDigest']) || receipt.schemaVersion !== 1 ||
      receipt.format !== 'cliq-child-admission-receipt-v1' || receipt.receiptDigest !== digestOmitting(receipt, 'receiptDigest') ||
      receipt.parentRunId !== parent.id || receipt.childRunId !== run.id || receipt.requestRef !== prepared.requestRef ||
      receipt.childSpecRef !== run.specRef || receipt.preparedAt !== request.preparedAt) invalid('receipt is not the original local result');
  const handle = await readCanonicalArtifact<ChildHandleItem>(reads, receipt.childHandleItemRef);
  requireEqual(handle, { schemaVersion: 1, itemId: identityHash('cliq-child-handle-v1', parent.id, allocation.delegateOpId), runId: parent.id,
    kind: 'child_handle', delegateBatchItemId: allocation.delegateBatchItemId, delegateCallId: allocation.delegateCallId,
    delegateCallIndex: allocation.delegateCallIndex, delegateOpId: allocation.delegateOpId, childRunId: run.id,
    admittedSpecRef: run.specRef, mode: allocation.mode, createdAt: run.createdAt }, 'original child handle');
  const handleRow = driver.prepare('SELECT run_id,kind,payload_ref FROM items WHERE item_id = ?')
    .get<{ run_id: string; kind: string; payload_ref: string }>(handle.itemId);
  if (handleRow?.run_id !== parent.id || handleRow.kind !== 'child_handle' || handleRow.payload_ref !== receipt.childHandleItemRef)
    invalid('has no committed parent-owned handle');
  const ownerHistory = await readRetainedStateOwnerHistory(driver, reads, claim.stateOwnerEpoch!);
  const originalOwner = ownerHistory.entries.at(-1)!.owner;
  const inspector = await readSupervisorInspector(reads, originalOwner, assembly, { ...receipt, observedAt: prepared.localCommittedAt! });
  if (originalOwner.supervisorInstanceId !== claim.supervisorInstanceId || prepared.timestamp < originalOwner.acquiredAt ||
      originalOwner.state === 'terminal' && prepared.localCommittedAt! > originalOwner.releasedAt ||
      target.execution.supervisorEntryId !== inspector.supervisorEntryId || target.execution.supervisorEntryVersion !== inspector.supervisorEntryVersion ||
      target.execution.supervisorExecutableDigest !== inspector.supervisorExecutableDigest) invalid('has no exact original signed local Supervisor owner');
  const capturedAllocationsValue = await readCanonicalArtifact<unknown>(reads, request.parentChildAllocationsRef);
  if (!Array.isArray(capturedAllocationsValue)) invalid('original outgoing allocation snapshot is not an array');
  const capturedAllocations = capturedAllocationsValue.map(decodeChildAllocation);
  const priorAllocations = readChildAllocationsForRun(driver, parent.id).filter(row => row.parentRunId === parent.id &&
    (readOperationJournal(driver, parent.id, row.delegateOpId)[0]?.seq ?? Number.MAX_SAFE_INTEGER) < prepared.seq);
  if (capturedAllocations.length !== priorAllocations.length || capturedAllocations.some((row, i) => row.parentRunId !== parent.id ||
      row.childRunId !== priorAllocations[i]?.childRunId || row.createdAt > prepared.timestamp)) invalid('original outgoing allocation set is not all-and-only prior admissions');
  const rank = { reserved: 0, child_terminal: 1, settled: 2 };
  const allocationOrigin = (row: ChildAllocationV1) => {
    const { state: _state, terminal: _terminal, inclusiveBudgetUsage: _usage, terminalAt: _terminalAt,
      childResultItemId: _result, parentSettlementRevision: _revision, releasedUnusedBudget: _unused, settledAt: _at, ...origin } = row;
    return origin;
  };
  for (const [i, captured] of capturedAllocations.entries()) {
    const retained = priorAllocations[i]!;
    requireEqual(allocationOrigin(captured), allocationOrigin(retained), 'original immutable sibling allocation');
    if (rank[captured.state] > rank[retained.state] || captured.state !== 'reserved' &&
        (captured.terminalAt > prepared.localCommittedAt! || retained.state === 'reserved' ||
          canonicalSha256(captured.terminal) !== canonicalSha256(retained.terminal) ||
          canonicalSha256(captured.inclusiveBudgetUsage) !== canonicalSha256(retained.inclusiveBudgetUsage) || captured.terminalAt !== retained.terminalAt))
      invalid('captured outgoing state cannot be an original prefix of its monotonic retained allocation');
    if (captured.state === 'settled') requireEqual(captured, retained, 'original immutable sibling settlement');
  }
  let ownReserved = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
  let ownConsumed = { ...ownReserved, repairAttempts: parent.repairCount };
  const groups = new Map<string, typeof rows>();
  for (const row of parentJournal.filter(row => row.seq < prepared.seq)) {
    const key = `${row.opId}:${row.attempt}`;
    const group = groups.get(key) ?? []; group.push(row); groups.set(key, group);
  }
  for (const group of groups.values()) {
    if (group[0]?.phase !== 'prepared') invalid('parent budget has no complete original prepared operation');
    const terminal = group.find(row => ['completed', 'failed', 'unknown'].includes(row.phase));
    if (terminal) ownConsumed = addBudget(ownConsumed, terminal.budgetDelta);
    else ownReserved = addBudget(ownReserved, group[0].budgetDelta);
  }
  const childBudget = childAllocationBudgetFacts(parent.id, capturedAllocations);
  ownConsumed = addBudget(ownConsumed, childBudget.consumed);
  ownReserved = addBudget(ownReserved, childBudget.reserved);
  requireEqual(ownConsumed, parent.budgetConsumed, 'original complete parent inclusive consumed equation');
  requireEqual(ownReserved, parent.budgetReserved, 'original complete parent conservative reserved equation');
  const budget = planChildBudgetAllocation({ parent: { budgets: parentSpec.budgets, consumed: parent.budgetConsumed,
    reserved: parent.budgetReserved, deadlineAt: parent.deadlineAt }, requestedBudgets: delegated.requestedBudgets,
    createdAt: prepared.timestamp, nonterminalDirectChildren: childBudget.nonterminalDirectChildren,
    continuationFloor: await readChildContinuationBudgetFloor(reads, { parentRunId: parent.id, assembly,
      allocations: capturedAllocations, nextMode: delegated.mode }) });
  if (budget.kind !== 'available') invalid('original child allocation did not have available parent budget or concurrency');
  requireEqual(spec.budgets, budget.grantedBudgets, 'original exact child budget intersection');
  ownerHistory.assertUnchanged(driver);
  requireEqual(readRun(driver, run.id), run, 'child admission reader original Run cut');
  reads.assertReadActive();
  const assertUnchanged = (connection: SqliteConnection) => {
    requireEqual(immutableRun(readRun(connection, run.id)), immutableRun(run), 'child immutable admission origin');
    requireEqual(immutableRun(readRun(connection, parent.id)), immutableRun(parent), 'child immutable parent origin');
    requireEqual(readIncomingChildAllocation(connection, run.id), allocation, 'child original incoming allocation cut');
    requireEqual(readOperationJournal(connection, parent.id, allocation.delegateOpId), rows, 'child original local Journal');
    requireEqual(readCheckpoint(connection, checkpoint.id), checkpoint, 'child original parent Checkpoint');
    requireEqual(readCheckpoint(connection, childInitial.id), childInitial, 'child original initial Checkpoint');
    requireEqual(readContextRows(connection), contextRows, 'child original parent item prefix');
    requireEqual(connection.prepare('SELECT run_id,kind,payload_ref FROM items WHERE item_id = ?').get(handle.itemId), handleRow,
      'child original handle owner');
    requireEqual(connection.prepare(`SELECT principal_id,admission_method,admission_key,admission_intent_digest,
      admitted_request_digest,admission_request_id FROM runs WHERE id = ?`).get(run.id), admission, 'child immutable admission columns');
    ownerHistory.assertUnchanged(connection);
  };
  assertUnchanged(driver);
  return Object.freeze({ ...immutableSnapshot({ run, spec, allocation, parent, parentSpec, assembly, policy, checkpoint,
    parentContext, parentWorkspace, request, receipt, handle, capabilityGrant, delegated, toolRequest, target, call, grant, evidence,
    originalOwner, inspector, principalId: cut.parentPrincipal, localCommittedAt: prepared.localCommittedAt!, capturedAllocations }),
    ownerHistory, assertUnchanged, journal: Object.freeze(rows) });
}
/** One bounded original ancestry, independent from a parent's mutable full
 * recovery projection. Every edge has its own admission/owner/capability cut;
 * the final root must close its actual authenticated original control source. */
export async function readChildAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, childRunId: string,
  options: { signal?: AbortSignal } = {}) {
  const seen = new Set<string>(), chain: Array<Awaited<ReturnType<typeof readDirectChildAdmission>>> = [];
  let id = childRunId;
  for (;;) {
    options.signal?.throwIfAborted();
    if (seen.has(id) || chain.length > 8) invalid('original ancestry is cyclic or exceeds its admitted depth');
    seen.add(id);
    const row = readRun(driver, id);
    if (!row.parentRunId) {
      if (!chain.length) invalid('root Run is not a delegated child');
      const rootOrigin = await readRootRunAdmissionOrigin(driver, artifacts, id, options);
      const origin = chain.at(-1)!;
      requireEqual(immutableRun(origin.parent), immutableRun(rootOrigin.run), 'original child chain root admission');
      for (const [i, edge] of chain.entries()) {
        const next = chain[i + 1];
        if (next) requireEqual(immutableRun(edge.parent), immutableRun(next.run), 'original immutable child ancestry edge');
        edge.ownerHistory.assertUnchanged(driver);
      }
      rootOrigin.assertUnchanged(driver);
      const result = Object.freeze({ ...chain[0]!, ancestors: Object.freeze(chain.slice(1)), rootOrigin });
      const { validateChildVerifierData } = await import('./child-verifier-admission.js');
      await validateChildVerifierData(artifacts, result);
      if (result.spec.dependencyPolicyRef) await (await import('./dependency-inherited.js')).validateChildDependencyOrigin(driver, artifacts, result);
      for (const edge of chain) edge.assertUnchanged(driver);
      rootOrigin.assertUnchanged(driver);
      requireEqual(readRun(driver, childRunId), result.run, 'original child source read cut');
      return result;
    }
    const original = await readDirectChildAdmission(driver, artifacts, id, options);
    chain.push(original); id = original.parent.id;
  }
}
export type ChildAdmissionData = Awaited<ReturnType<typeof readChildAdmission>>;

/** Every local admission has all-and-only its ordinary child, allocation,
 * original handle, ordered provider result and atomic parent Checkpoint.
 * Individual object reachability or a structurally plausible Journal is not
 * a substitute for this complete retained business effect. */
export async function validateChildAdmissionHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  run: Run; items: ReadonlyMap<string, import('../kernel/types.js').ContinuationItem>;
  journal: readonly import('../kernel/types.js').InvocationJournalEntry[]; checkpoints: readonly import('../kernel/types.js').Checkpoint[];
}) {
  const outgoing = readChildAllocationsForRun(driver, input.run.id).filter(row => row.parentRunId === input.run.id);
  const refused = await (await import('./child-admission-refusal-history.js')).validateChildAdmissionRefusalHistory(driver, artifacts, input);
  const prepared = input.journal.filter(row => row.opKind === 'child_admission' && row.phase === 'prepared' && !refused.has(row.opId));
  const handles = [...input.items.values()].filter(item => item.kind === 'child_handle');
  if (outgoing.length !== prepared.length || handles.length !== outgoing.length)
    invalid('history has a missing or extra local admission/allocation/handle');
  for (const allocation of outgoing) {
    const original = await readChildAdmission(driver, artifacts, allocation.childRunId);
    const { request, receipt, handle, toolRequest } = original;
    const owned = prepared.filter(row => row.opId === allocation.delegateOpId && row.requestRef === receipt.requestRef);
    if (owned.length !== 1 || original.parent.id !== input.run.id ||
        canonicalSha256(input.items.get(handle.itemId)) !== canonicalSha256(handle)) invalid('history lost the original parent-owned admission source');
    const results = [...input.items.values()].filter(item => item.kind === 'tool_result' && item.batchItemId === allocation.delegateBatchItemId &&
      item.callId === allocation.delegateCallId && item.index === allocation.delegateCallIndex);
    if (results.length !== 1 || results[0]!.kind !== 'tool_result' || results[0]!.opId !== allocation.delegateOpId || results[0]!.outcome !== 'executed')
      invalid('history lost its unique ordered delegate result');
    const result = results[0]!;
    const payload = await readCanonicalArtifact<import('../kernel/types.js').ToolResultPayloadV1>(artifacts, result.resultRef);
    const content = await readCanonicalArtifact<import('../kernel/types.js').ToolResultModelContentV1>(artifacts, payload.modelContentRef);
    if (payload.outcome !== 'executed' || payload.source !== 'child_admission' || payload.opId !== allocation.delegateOpId ||
        payload.journalResultRef !== original.journal[2]!.resultRef || payload.journalResultDigest !== receipt.receiptDigest ||
        payload.childHandleItemRef !== receipt.childHandleItemRef || payload.runId !== input.run.id || payload.batchItemId !== allocation.delegateBatchItemId ||
        payload.callId !== allocation.delegateCallId || payload.index !== allocation.delegateCallIndex || payload.toolName !== 'delegate' ||
        payload.payloadDigest !== digestOmitting(payload, 'payloadDigest') || result.createdAt !== request.preparedAt ||
        content.contentDigest !== payload.modelContentDigest || content.contentDigest !== digestOmitting(content, 'contentDigest'))
      invalid('delegate model result substituted its actual local admission receipt');
    requireEqual(content.content, { schemaVersion: 1, childHandleItemId: handle.itemId,
      childRunId: allocation.childRunId, admittedSpecRef: request.childSpecRef }, 'model-safe original delegate result');
    const id = identityHash('cliq-child-admission-checkpoint-v1', input.run.id, allocation.delegateOpId);
    const checkpoints = input.checkpoints.filter(row => row.id === id);
    if (checkpoints.length !== 1 || checkpoints[0]!.basedOnRunRevision !== original.parent.revision ||
        checkpoints[0]!.createdAt !== original.localCommittedAt || checkpoints[0]!.workspaceStateRef !== original.checkpoint.workspaceStateRef ||
        checkpoints[0]!.journalSeq !== original.journal[2]!.seq || checkpoints[0]!.runItemSeq <= original.checkpoint.runItemSeq)
      invalid('delegate has no exact parent budget/result/frontier Checkpoint transaction');
    const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoints[0]!.contextManifestRef));
    if (context.throughItemSeq !== checkpoints[0]!.runItemSeq || context.runId !== input.run.id ||
        context.assemblyRef !== original.parentSpec.assemblyRef || context.admittedContextRef !== original.parentSpec.admittedContextRef ||
        toolRequest.opId !== result.opId) invalid('delegate continuation differs from its original complete source');
  }
}
