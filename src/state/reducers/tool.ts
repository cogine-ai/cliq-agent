import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { planCanonicalArtifact } from '../../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../kernel/identity.js';
import type { Run, RunAssemblyV1, RunFrontier, RunSpec, ToolResultItem, ToolResultPayloadV1, ToolResultModelContentV1, ControlResultV1 } from '../../kernel/types.js';
import type { PolicyEngineProfileV1, RunPolicySnapshotV1, ToolObservationV1, ToolOperationGrantV1,
  ToolPolicyChannelEvidenceV1, ToolPolicyDecisionItem, ToolRequestV1, ToolTargetV1, ToolApprovalWait, ToolApprovalDecisionV1,
  ToolCheckpointProof, ToolGrantExpiryV1 } from '../../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../../protocol/agent-ir.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ResolveToolInput } from '../../model/attempt.js';
import { loadToolContracts, type ToolInputAuthority } from '../../tools/input-contract.js';
import { compileOutputSchema } from '../../tools/input-schema.js';
import { loadToolPolicy, toolOperationId } from '../../policy/tool-policy.js';
import { toolApprovalCheckpointId, toolApprovalDecision, toolApprovalRequestDigest, type ToolApprovalInput } from '../../policy/tool-approval.js';
import { exactKeys, requireEqual, verifyToolRuntimeAuthority, type ReleaseTrustKey, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from '../artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { readRetainedControlChannelClosure, validateControlChannelClosure } from '../control-channel.js';
import { prepareContinuationCommit } from '../continuation-commit.js';
import { decodeWorkspaceIdentity } from '../decoders.js';
import { KernelStorageError, stateOperation } from '../errors.js';
import { nextJournalSequence, readHighestPreparedAttempt, readInvocationAttempt } from '../repositories/journal.js';
import { insertControlRequest, readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { prepareToolCheckpoint, toolCheckpointId } from '../tool-checkpoint.js';
import { readToolCut, type ToolCut } from '../tool-cut.js';
import { loadAgentStop } from './stop.js';
import { appendRunStateEvent, assertLiveDispatchState, claimValidatedInvocation, prepareValidatedInvocation,
  requireHealthyFence, settleValidatedInvocation, type ClaimInvocationDispatchInput } from './invocation.js';
import { loadInputContinuation } from './input.js';

const TOOL_BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
type ApprovalResponse = { protocolVersion: 1; ok: true; result: Extract<ControlResultV1, { method: 'run.approve' }> };
type ResultFields<T = Exclude<ToolResultPayloadV1, { source: 'user_input' }>> = T extends ToolResultPayloadV1
  ? Omit<T, 'schemaVersion' | 'format' | 'runId' | 'batchItemId' | 'callId' | 'index' | 'toolName' | 'modelContentRef' | 'modelContentDigest' | 'payloadDigest'> : never;

function policyItem(evidence: ToolPolicyChannelEvidenceV1, decision: { grantRef: string } | { outcomeItemRef: string },
  approval?: ToolApprovalDecisionV1): ToolPolicyDecisionItem {
  const evidenceRef = canonicalSha256(evidence);
  const decisionRef = approval ? canonicalSha256(approval) : evidenceRef;
  const base = { schemaVersion: 1 as const, kind: 'policy_decision' as const,
    itemId: identityHash('cliq-tool-policy-item-v1', evidence.runId, evidence.opId, decisionRef), runId: evidence.runId,
    subjectKind: 'tool_call' as const, opId: evidence.opId, principalId: evidence.principalId, decisionRef,
    policyChannelEvidenceRef: evidenceRef, policyChannelEvidenceDigest: evidence.evidenceDigest,
    createdAt: approval?.createdAt ?? evidence.evaluatedAt,
    ...(approval ? { decisionSource: 'interactive_approval' as const, waitingSubjectRef: approval.waitingSubjectRef }
      : { decisionSource: 'direct_policy' as const }) };
  return 'grantRef' in decision ? { ...base, decision: 'allow', grantRef: decision.grantRef }
    : { ...base, decision: 'deny', denialOutcome: { kind: 'tool_result_denied', subjectKind: 'tool_call', outcomeItemRef: decision.outcomeItemRef } };
}

function resultPlan(request: ToolRequestV1, createdAt: string,
  payload: ResultFields,
  content: unknown
) {
  const modelCore = { schemaVersion: 1 as const, format: 'cliq-tool-result-model-content-v1' as const,
    callId: request.callId, index: request.callIndex, toolName: request.toolName, outcome: payload.outcome, content };
  const model: ToolResultModelContentV1 = { ...modelCore, contentDigest: canonicalSha256(modelCore) };
  const modelPlan = planCanonicalArtifact(model, model.format);
  const core = { schemaVersion: 1, format: 'cliq-tool-result-payload-v1', runId: request.runId,
    batchItemId: request.batchItemId, callId: request.callId, index: request.callIndex, toolName: request.toolName,
    modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest, ...payload };
  const result = planCanonicalArtifact({ ...core, payloadDigest: canonicalSha256(core) }, core.format);
  const opId = payload.outcome === 'executed' || payload.outcome === 'error' ? request.opId : undefined;
  const item: ToolResultItem = { schemaVersion: 1, kind: 'tool_result',
    itemId: identityHash('cliq-tool-result-item-v1', request.runId, request.batchItemId, request.callId),
    runId: request.runId, batchItemId: request.batchItemId, callId: request.callId, index: request.callIndex,
    outcome: payload.outcome, resultRef: result.ref, createdAt, ...(opId === undefined ? {} : { opId }) };
  return { item, artifacts: [modelPlan, result] };
}

function nextFrontier(cut: ToolCut, addedItems: number): RunFrontier {
  return cut.frontier.nextCallIndex + 1 < cut.batch.calls.length ? { ...cut.frontier, nextCallIndex: cut.frontier.nextCallIndex + 1 }
    : { schemaVersion: 1, kind: 'agent', phase: 'model_turn', turnId: identityHash('cliq-agent-turn-v1', cut.run.id, cut.batch.itemId),
        contextItemSeq: cut.context.throughItemSeq + addedItems, cause: 'tool_batch_complete' };
}

/** Internal to the loaded Run. Static authority is shared; every mutable selection comes from SQLite again. */
export async function loadToolContinuation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: {
  run: Run; spec: RunSpec; assembly: RunAssemblyV1; contracts: ToolInputAuthority[];
  resolveToolInput: ResolveToolInput; releaseKeys?: readonly ReleaseTrustKey[];
}) {
  const { run: admittedRun, spec, assembly, contracts, resolveToolInput } = input;
  const runId = admittedRun.id;
  const session = readSession(driver, admittedRun.sessionId);
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  if (readSessionPrincipalId(driver, session.id) !== workspace.ownerPrincipalId ||
      driver.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(runId)?.principal_id !== workspace.ownerPrincipalId) {
    throw new TypeError('Run, Session and workspace do not share one principal');
  }
  let policy: ReturnType<typeof loadToolPolicy> | undefined;
  let policyArtifactRefs: readonly string[] = [];
  if (input.releaseKeys !== undefined) {
    const snapshot = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, spec.policyRef);
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, assembly.runtime.runtimeBundleRef);
    const profile = await readCanonicalArtifact<PolicyEngineProfileV1>(artifacts, snapshot.engine.profileRef);
    verifyToolRuntimeAuthority({ assembly, policy: snapshot, bundle, profile, tools: contracts.map(({ inputSchema: _schema, ...entry }) => entry), releaseKeys: input.releaseKeys });
    policyArtifactRefs = [...new Set([spec.policyRef, assembly.runtime.runtimeBundleRef, snapshot.engine.profileRef,
      ...snapshot.decisionRules.flatMap((rule) => rule.sourceRef ? [rule.sourceRef] : [])])];
    for (const ref of policyArtifactRefs) await artifacts.readBytes(ref);
    policy = loadToolPolicy({ policy: snapshot, policyRef: spec.policyRef, assembly, assemblyRef: spec.assemblyRef,
      principalId: workspace.ownerPrincipalId, workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest, contracts });
  }
  const requirePolicy = () => {
    if (!policy) throw new KernelStorageError('RECOVERY_REQUIRED', 'tool authority requires the trusted release key set and canonical policy/profile closure');
    return policy;
  };
  const compiled = loadToolContracts(contracts);
  const outputSchemas = new Map(await Promise.all(contracts.filter((entry) => entry.outputSchemaRef !== undefined).map(async (entry) =>
    [entry.name, compileOutputSchema(await readCanonicalArtifact(artifacts, entry.outputSchemaRef!))] as const)));
  const cut = async (revision?: number) => {
    const selected = await readToolCut(driver, artifacts, runId, resolveToolInput);
    if (selected.run.specRef !== admittedRun.specRef || selected.run.deadlineAt !== admittedRun.deadlineAt || selected.run.createdAt !== admittedRun.createdAt) {
      throw new TypeError('loaded tool authority no longer belongs to this Run');
    }
    if (revision !== undefined && selected.run.revision !== revision) throw new KernelStorageError('REVISION_CONFLICT', 'tool Run revision changed');
    return selected;
  };
  function assertCut(connection: SqliteConnection, run: Run, selected: ToolCut): void {
    const seq = Number(connection.prepare('SELECT COALESCE(max(item_seq), 0) AS seq FROM items WHERE run_id = ?').get<{ seq: unknown }>(run.id)?.seq);
    if (run.frontierRef !== selected.run.frontierRef || run.latestCheckpointId !== selected.run.latestCheckpointId || seq !== selected.context.throughItemSeq) {
      throw new KernelStorageError('REVISION_CONFLICT', 'tool continuation cut changed');
    }
  }
  function requestFor(selected: ToolCut) {
    const call = selected.call;
    const entry = contracts.find((entry) => entry.name === call.toolName)!;
    const { inputSchema: _schema, ...contract } = entry;
    const targetCore = { schemaVersion: 1 as const, format: 'cliq-tool-target-v1' as const, runId,
      workspaceIdentityRef: session.workspaceIdentityRef, workspaceIdentityDigest: workspace.identityDigest,
      toolManifestRef: assembly.tools.manifestRef, toolManifestDigest: assembly.tools.manifestDigest,
      toolName: call.toolName, toolContractDigest: canonicalSha256(contract), execution: entry.execution };
    const target: ToolTargetV1 = { ...targetCore, targetDigest: canonicalSha256(targetCore) };
    const opId = toolOperationId(runId, selected.batch.itemId, call.callId);
    const core = { schemaVersion: 1 as const, format: 'cliq-tool-request-v1' as const, runId, opId,
      frontierRef: selected.run.frontierRef!, assemblyRef: spec.assemblyRef, batchItemId: selected.batch.itemId,
      callId: call.callId, callIndex: call.index, toolName: call.toolName, inputRef: canonicalSha256(call), inputDigest: call.inputDigest,
      targetRef: canonicalSha256(target), targetDigest: target.targetDigest,
      ...(entry.execution.kind === 'mcp' ? { idempotencyKey: identityHash('cliq-mcp-tool-idempotency-v1', runId, opId,
        entry.execution.registryRevisionRef, entry.execution.serverToolName) } : {}) };
    return { request: { ...core, requestDigest: canonicalSha256(core) } satisfies ToolRequestV1, target, entry };
  }
  async function verifyGrant(grantRef: string) {
    const evaluator = requirePolicy();
    const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, grantRef);
    const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, grant.requestRef);
    const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, request.targetRef);
    const call = await readCanonicalArtifact<ToolCallInputV1>(artifacts, request.inputRef);
    const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(artifacts, grant.provenance.channelEvidenceRef);
    requireEqual(grant, grant.provenance.kind === 'user_approval' ? (await verifyApproval(grant.provenance.decisionRef)).grant
      : evaluator.grant(request, target, call, evidence, grant.issuedAt, grant.expiresAt), 'operation grant');
    if (grant.runId !== runId || grant.expiresAt > admittedRun.deadlineAt || grant.issuedAt < admittedRun.createdAt) throw new TypeError('tool grant exceeds Run authority lifetime');
    return { grant, request, target, call, evidence };
  }

  async function waitProof(waitingOnRef: string) {
    const wait = await readCanonicalArtifact<ToolApprovalWait>(artifacts, waitingOnRef);
    const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(artifacts, wait.subject.policyChannelEvidenceRef);
    const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, evidence.requestRef);
    const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, request.targetRef);
    const call = await readCanonicalArtifact<ToolCallInputV1>(artifacts, request.inputRef);
    requireEqual(evidence, requirePolicy().evaluate(request, target, call, evidence.evaluatedAt), 'waiting policy evidence');
    requireEqual(wait, requirePolicy().approvalWait(request, target, evidence, wait.createdFromRevision), 'tool approval wait');
    if (wait.runId !== runId || wait.createdAt < admittedRun.createdAt || wait.createdAt >= admittedRun.deadlineAt) throw new TypeError('approval wait exceeds its Run');
    return { wait, evidence, request, target, call };
  }

  async function verifyApproval(decisionRef: string) {
    const decision = await readCanonicalArtifact<ToolApprovalDecisionV1>(artifacts, decisionRef);
    const proof = await waitProof(decision.waitingSubjectRef);
    const grant = requirePolicy().approve(proof.request, proof.target, proof.call, proof.evidence, proof.wait, decision, admittedRun.deadlineAt);
    const row = driver.prepare(`SELECT request_digest, channel_identity_ref, channel_identity_digest, response_ref, committed_at
      FROM control_requests WHERE principal_id = ? AND method = 'run.approve' AND request_id = ?`)
      .get<{ request_digest: string; channel_identity_ref: string; channel_identity_digest: string; response_ref: string; committed_at: string }>(decision.principalId, decision.requestId);
    if (!row || row.request_digest !== decision.requestDigest || row.channel_identity_ref !== decision.channelIdentityRef ||
        row.channel_identity_digest !== decision.channelIdentityDigest || row.committed_at !== decision.createdAt) {
      throw new TypeError('approval decision has no exact authenticated control-row owner');
    }
    await readRetainedControlChannelClosure(artifacts, owner, decision);
    const response = await readCanonicalArtifact<ApprovalResponse>(artifacts, row.response_ref);
    const checkpointId = identityHash('cliq-tool-approval-decision-checkpoint-v1', decisionRef);
    const checkpoint = readCheckpoint(driver, checkpointId);
    if (response.protocolVersion !== 1 || response.ok !== true || response.result.method !== 'run.approve' ||
        response.result.decisionRef !== decisionRef || response.result.snapshot.operation !== 'agent' || response.result.snapshot.schemaVersion !== 1 ||
        response.result.snapshot.latestRunItemSeq !== checkpoint.runItemSeq || response.result.snapshot.run.latestCheckpointId !== checkpointId ||
        response.result.snapshot.run.specRef !== admittedRun.specRef || response.result.snapshot.run.sessionId !== admittedRun.sessionId ||
        (decision.decision === 'allow' && response.result.snapshot.run.frontierRef !== proof.wait.frontierRef) ||
        response.result.snapshot.run.id !== runId || response.result.snapshot.run.revision !== decision.expectedRunRevision + 1 ||
        response.result.snapshot.run.updatedAt !== decision.createdAt || response.result.snapshot.run.status !== 'queued' ||
        response.result.snapshot.run.waitingOnRef !== undefined || response.result.snapshot.run.activeWorkerLaunchId !== undefined) {
      throw new TypeError('approval response substitutes its committed decision or Run snapshot');
    }
    return { ...proof, decision, grant, response };
  }

  function assertApprovalCut(connection: SqliteConnection, current: Run, selected: ToolCut): void {
    assertCut(connection, current, selected);
    if (current.revision !== selected.run.revision || current.status !== selected.run.status ||
        current.waitingOnRef !== selected.run.waitingOnRef || current.cancelRequested || current.stopIntentRef ||
        sampleCanonicalNow() >= current.deadlineAt) throw new KernelStorageError('REVISION_CONFLICT', 'approval Run is stopped, expired or changed');
    if (connection.prepare("SELECT 1 FROM worker_launches WHERE run_id = ? AND phase != 'retired' AND launch_id != ? LIMIT 1")
      .get(runId, current.activeWorkerLaunchId ?? '')) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'approval must not retain another pending worker launch');
  }

  async function approvedGrant(selected: ToolCut, request: ToolRequestV1) {
    const item = selected.items.map(({ item }) => item).filter((item) => item.kind === 'policy_decision' && item.opId === request.opId).at(-1);
    if (item?.kind !== 'policy_decision' || item.decisionSource !== 'interactive_approval' || item.decision !== 'allow') return undefined;
    const proof = await verifyGrant(item.grantRef);
    requireEqual(proof.request, request, 'approved current tool request');
    return { ...proof, grantRef: item.grantRef };
  }

  async function retryAfterExpiry(request: ToolRequestV1): Promise<boolean> {
    const prepared = readHighestPreparedAttempt(driver, runId, request.opId);
    if (!prepared) return false;
    const entries = readInvocationAttempt(driver, runId, request.opId, prepared.attempt);
    const failed = entries.at(-1);
    if (entries.length !== 2 || failed?.phase !== 'failed' || !failed.errorRef) return false;
    const expiry = await readCanonicalArtifact<ToolGrantExpiryV1>(artifacts, failed.errorRef);
    return expiry.format === 'cliq-tool-grant-expiry-v1' && expiry.grantRef === prepared.grantRef &&
      expiry.preparedJournalSeq === prepared.seq && expiry.waitingSubjectRef !== undefined;
  }

  // Recovery independently reproduces committed decisions, including deny, before exposing a usable handle.
  const retained = driver.prepare("SELECT payload_ref FROM items WHERE run_id = ? AND kind = 'policy_decision' ORDER BY item_seq")
    .all<{ payload_ref: string }>(runId);
  for (const row of retained) {
    const item = await readCanonicalArtifact<ToolPolicyDecisionItem>(artifacts, row.payload_ref);
    const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(artifacts, item.policyChannelEvidenceRef);
    const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, evidence.requestRef);
    const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, evidence.targetRef);
    const call = await readCanonicalArtifact<ToolCallInputV1>(artifacts, request.inputRef);
    requireEqual(evidence, requirePolicy().evaluate(request, target, call, evidence.evaluatedAt), 'retained policy decision');
    if (item.decision === 'allow') await verifyGrant(item.grantRef);
    const approval = item.decisionSource === 'interactive_approval' ? (await verifyApproval(item.decisionRef)).decision : undefined;
    requireEqual(item, policyItem(evidence, item.decision === 'allow' ? { grantRef: item.grantRef } : { outcomeItemRef: item.denialOutcome.outcomeItemRef }, approval), 'policy item');
    if (item.decision !== (approval?.decision ?? evidence.effectiveDisposition)) throw new TypeError('policy item disposition mismatch');
  }
  if (admittedRun.waitingReason === 'approval' && admittedRun.waitingOnRef) {
    const selected = await cut();
    const proof = await waitProof(admittedRun.waitingOnRef);
    requireEqual(proof.request, requestFor(selected).request, 'waiting current tool request');
  }

  const controlAuthority = {
    run: admittedRun, spec, assembly, principalId: workspace.ownerPrincipalId, resolveToolInput,
    async assertAuthority() {
      requirePolicy();
      for (const ref of policyArtifactRefs) await artifacts.readBytes(ref);
    }
  };
  const inputContinuation = await loadInputContinuation(driver, artifacts, owner, { ...controlAuthority, contracts });

  return {
    ...loadAgentStop(driver, artifacts, owner, controlAuthority),
    waitForInput: inputContinuation.waitForInput,
    submitInput: inputContinuation.submitInput,
    prepareTool: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; leaseEpoch: number }) => {
      const { expectedRunRevision, leaseEpoch } = input;
      const evaluator = requirePolicy();
      // Before the first decision there is no retained policy item for recovery to walk yet.
      // Static in-memory authority must not hide loss of its durable policy/profile/source bytes.
      for (const ref of policyArtifactRefs) await artifacts.readBytes(ref);
      const selected = await cut(expectedRunRevision);
      if (selected.run.status !== 'queued') assertLiveDispatchState(driver, owner, runId, expectedRunRevision, leaseEpoch, sampleCanonicalNow());
      else if (selected.run.activeWorkerLaunchId || selected.run.leaseEpoch !== leaseEpoch || selected.run.cancelRequested ||
          selected.run.stopIntentRef || sampleCanonicalNow() >= selected.run.deadlineAt) throw new KernelStorageError('LEASE_FENCED', 'queued approval selection is stale');
      const { request, target, entry } = requestFor(selected);
      if (entry.access === 'control') return inputContinuation.plan(selected);
      const approved = await approvedGrant(selected, request);
      const prior = readHighestPreparedAttempt(driver, runId, request.opId);
      const canRenew = approved && approved.grant.expiresAt <= sampleCanonicalNow() && prior?.grantRef === approved.grantRef &&
        readInvocationAttempt(driver, runId, request.opId, prior.attempt).length === 1;
      if (prior && !canRenew && !await retryAfterExpiry(request)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool attempt already exists; retry/reconciliation requires its owning recovery reducer');
      const evaluatedAt = sampleCanonicalNow();
      const evidence = evaluator.evaluate(request, target, selected.call, evaluatedAt);
      const requestPlan = planCanonicalArtifact(request, request.format), targetPlan = planCanonicalArtifact(target, target.format);
      await artifacts.publishCanonical(request, request.format);
      await artifacts.publishCanonical(target, target.format);
      const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.format);
      if (evidence.effectiveDisposition === 'ask' && (!approved || approved.grant.expiresAt <= evaluatedAt)) {
        const wait = evaluator.approvalWait(request, target, evidence, selected.run.revision);
        const waiting = await artifacts.publishCanonical(wait, 'cliq-waiting-subject-v1');
        return immutableSnapshot({ disposition: 'approval_required' as const, run: selected.run, evidenceRef: evidenceArtifact.ref, evidence,
          waitingOnRef: waiting.ref, checkpointId: toolApprovalCheckpointId(waiting.ref) });
      }
      if (evidence.effectiveDisposition === 'deny') {
        const result = resultPlan(request, evaluatedAt, { outcome: 'denied', code: 'TOOL_CALL_DENIED',
          denial: { source: 'policy', policyRef: spec.policyRef, decisionDigest: evidence.evidenceDigest } }, { code: 'TOOL_CALL_DENIED' });
        const decision = policyItem(evidence, { outcomeItemRef: canonicalSha256(result.item) });
        const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
          items: [decision, result.item], frontier: nextFrontier(selected, 2), checkpointId: identityHash('cliq-tool-denial-checkpoint-v1', runId, request.opId),
          workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [...result.artifacts, requestPlan, targetPlan] });
        let outcome: TimeFenceAdvance | undefined, updated!: Run;
        driver.transaction((connection) => {
          assertActiveStateOwner(connection, owner);
          const now = sampleCanonicalNow();
          outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
          if (outcome !== 'healthy') return;
          const { run } = assertLiveDispatchState(connection, owner, runId, expectedRunRevision, leaseEpoch, now);
          assertCut(connection, run, selected);
          if (readHighestPreparedAttempt(connection, runId, request.opId)) throw new KernelStorageError('REVISION_CONFLICT', 'tool denial cannot overtake a prepared effect');
          for (const artifact of [...plan.metadata, evidenceArtifact]) insertArtifactMetadata(connection, artifact, now);
          plan.commit(connection, run, nextJournalSequence(connection, runId) - 1, now);
          connection.prepare('UPDATE runs SET revision = revision + 1, updated_at = ? WHERE id = ?').run(now, runId);
          updated = readRun(connection, runId);
          appendRunStateEvent(connection, updated, now);
        });
        requireHealthyFence(outcome);
        return immutableSnapshot({ disposition: 'denied' as const, run: updated });
      }
      const grant = approved?.grant ?? evaluator.grant(request, target, selected.call, evidence, evaluatedAt, selected.run.deadlineAt);
      const grantPlan = planCanonicalArtifact(grant, grant.format);
      const decision = policyItem(evidence, { grantRef: grantPlan.ref });
      const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
        items: approved ? [] : [decision], frontier: selected.frontier,
        checkpointId: identityHash('cliq-tool-admission-checkpoint-v1', grantPlan.ref),
        workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [requestPlan, targetPlan, grantPlan] });
      const prepared = await prepareValidatedInvocation(driver, artifacts, owner, { runId, expectedRunRevision, leaseEpoch,
        opId: request.opId, opKind: entry.execution.kind === 'mcp' ? 'mcp' : 'tool', target: request.targetRef,
        requestRef: requestPlan.ref, replayClass: entry.replayClass, grantRef: grantPlan.ref,
        ...(request.idempotencyKey === undefined ? {} : { idempotencyKey: request.idempotencyKey }), reservation: TOOL_BUDGET
      }, { metadata: [...plan.metadata, evidenceArtifact], validate(connection, run, attempt) {
        assertCut(connection, run, selected);
        if (attempt !== (prior ? prior.attempt + 1 : 0) || sampleCanonicalNow() >= grant.expiresAt) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool grant is expired or attempt identity changed');
      }, commit(connection, run, journal) { plan.commit(connection, run, journal.seq, journal.timestamp); } });
      return immutableSnapshot({ disposition: 'prepared' as const, ...prepared, request, target,
        checkpointId: toolCheckpointId(runId, request.opId, prepared.entry.attempt) });
    }),
    waitForToolApproval: stateOperation('INVALID_REQUEST', async (input: {
      expectedRunRevision: number; waitingOnRef: string; checkpoint?: ToolCheckpointProof;
    }) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['expectedRunRevision', 'waitingOnRef', ...(input.checkpoint === undefined ? [] : ['checkpoint'])])) throw new TypeError('unknown tool approval wait field');
      const selected = await cut(input.expectedRunRevision);
      const proof = await waitProof(input.waitingOnRef);
      const { request } = requestFor(selected);
      requireEqual(proof.request, request, 'waiting current request');
      if (proof.wait.createdFromRevision !== selected.run.revision || !['running', 'queued'].includes(selected.run.status)) {
        throw new KernelStorageError('REVISION_CONFLICT', 'approval wait does not name the current result-less Run cut');
      }
      const approved = await approvedGrant(selected, request);
      if (approved && approved.grant.expiresAt > proof.wait.createdAt) throw new TypeError('unexpired approval cannot be replaced by another wait');
      const prior = readHighestPreparedAttempt(driver, runId, request.opId);
      const pending = prior && readInvocationAttempt(driver, runId, request.opId, prior.attempt).length === 1 ? prior : undefined;
      if (prior && !pending && !await retryAfterExpiry(request)) throw new TypeError('approval wait cannot overtake a claimed or unresolved tool');
      if (pending && (!approved || pending.grantRef !== approved.grantRef)) throw new TypeError('approval wait cannot refund a different prepared grant');
      const checkpointId = toolApprovalCheckpointId(input.waitingOnRef);
      let seal: Awaited<ReturnType<typeof prepareToolCheckpoint>> | undefined;
      if (selected.run.activeWorkerLaunchId) {
        if (!input.checkpoint || !exactKeys(input.checkpoint, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']) ||
            input.checkpoint.workspaceStateRef !== selected.checkpoint.workspaceStateRef) {
          throw new TypeError('approval wait requires retirement proof over the unchanged ready workspace');
        }
        seal = await prepareToolCheckpoint(driver, artifacts, owner, { run: selected.run, spec, assembly, checkpointId,
          observedAt: proof.wait.createdAt, postEffect: input.checkpoint });
      } else if (selected.run.status !== 'queued' || input.checkpoint !== undefined) {
        throw new TypeError('only a worker-free queued Run can wait without a generation seal');
      }
      const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items, items: [],
        frontier: selected.frontier, checkpointId, workspaceStateRef: selected.checkpoint.workspaceStateRef });
      const metadata = [...plan.metadata, ...(seal?.metadata ?? []), ...await Promise.all([
        [input.waitingOnRef, 'cliq-waiting-subject-v1'], [canonicalSha256(proof.evidence), proof.evidence.format],
        [canonicalSha256(proof.request), proof.request.format], [canonicalSha256(proof.target), proof.target.format]
      ].map(([ref, format]) => artifacts.describe(ref!, 'application/json', format!)))];
      const commit = (connection: SqliteConnection, run: Run, journalSeq: number, now: string) => {
        assertApprovalCut(connection, run, selected);
        if (now < proof.wait.createdAt) throw new TypeError('approval wait precedes its evidence');
        seal?.commit(connection, run, now);
        plan.commit(connection, run, journalSeq, now);
        connection.prepare("UPDATE runs SET status = 'waiting', waiting_reason = 'approval', waiting_on_ref = ? WHERE id = ?")
          .run(input.waitingOnRef, runId);
      };
      if (pending) {
        const expiry: ToolGrantExpiryV1 = { schemaVersion: 1, format: 'cliq-tool-grant-expiry-v1', code: 'TOOL_GRANT_EXPIRED_BEFORE_DISPATCH',
          runId, opId: pending.opId, attempt: pending.attempt, preparedJournalSeq: pending.seq, grantRef: pending.grantRef!,
          waitingSubjectRef: input.waitingOnRef, observedAt: proof.wait.createdAt };
        const error = await artifacts.publishCanonical(expiry, expiry.format);
        const settled = await settleValidatedInvocation(driver, artifacts, owner,
          { runId, expectedRunRevision: input.expectedRunRevision, opId: pending.opId, attempt: pending.attempt },
          { phase: 'failed', requireClaim: false, errorRef: error.ref, consumed: ZERO_BUDGET }, async () => ({ metadata: [...metadata, error],
            commit(connection, run, journal) { commit(connection, run, journal.seq, journal.timestamp); } }));
        return immutableSnapshot({ run: settled.run, waitingOnRef: input.waitingOnRef });
      }
      let outcome: TimeFenceAdvance | undefined, updated!: Run;
      driver.transaction((connection) => {
        assertActiveStateOwner(connection, owner);
        const now = sampleCanonicalNow();
        outcome = advanceTimeFence(connection, owner.ownerEpoch, now);
        if (outcome !== 'healthy') return;
        const current = readRun(connection, runId);
        // Claims do not bump Run.revision. Compare the Journal cut as well as the continuation cut.
        if (nextJournalSequence(connection, runId) - 1 !== (selected.journal.at(-1)?.seq ?? 0)) throw new KernelStorageError('REVISION_CONFLICT', 'tool Journal changed before approval wait');
        for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
        commit(connection, current, nextJournalSequence(connection, runId) - 1, now);
        connection.prepare('UPDATE runs SET revision = revision + 1, updated_at = ? WHERE id = ?').run(now, runId);
        updated = readRun(connection, runId);
        appendRunStateEvent(connection, updated, now);
      });
      requireHealthyFence(outcome);
      return immutableSnapshot({ run: updated, waitingOnRef: input.waitingOnRef });
    }),
    approveTool: stateOperation('INVALID_REQUEST', async (input: ToolApprovalInput) => {
      input = immutableSnapshot(input);
      if (!exactKeys(input, ['principalId', 'channelIdentityRef', 'channelIdentityDigest', 'requestId', 'expectedRunRevision',
        'waitingOnRef', 'decision', ...(input.ttlMs === undefined ? [] : ['ttlMs'])])) throw new TypeError('unknown run.approve field');
      const requestDigest = toolApprovalRequestDigest(runId, input);
      if (input.principalId !== workspace.ownerPrincipalId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'approval caller does not own this Run');
      const channel = await validateControlChannelClosure(artifacts, owner, input);
      const replay = async () => {
        const existing = readControlRequest(driver, input.principalId, 'run.approve', input.requestId);
        if (!existing) return undefined;
        if (existing.requestDigest !== requestDigest) throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.approve requestId was reused with different bytes');
        const response = await readCanonicalArtifact<ApprovalResponse>(artifacts, existing.responseRef);
        const verified = await verifyApproval(response.result.decisionRef);
        requireEqual(response, verified.response, 'replayed approval response');
        return immutableSnapshot({ replayed: true, run: response.result.snapshot.run, response });
      };
      const existing = await replay();
      if (existing) return existing;
      const selected = await cut(input.expectedRunRevision);
      if (selected.run.status !== 'waiting' || selected.run.waitingReason !== 'approval' || selected.run.waitingOnRef !== input.waitingOnRef ||
          selected.run.activeWorkerLaunchId) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'run.approve requires its exact worker-free approval wait');
      const proof = await waitProof(input.waitingOnRef);
      requireEqual(proof.request, requestFor(selected).request, 'approved waiting request');
      for (let retry = 0; retry < 8; retry++) {
        const createdAt = sampleCanonicalNow();
        const decision = toolApprovalDecision(proof.wait, input, createdAt, selected.run.deadlineAt);
        const grant = requirePolicy().approve(proof.request, proof.target, proof.call, proof.evidence, proof.wait, decision, selected.run.deadlineAt);
        const decisionPlan = planCanonicalArtifact(decision, decision.format);
        const grantPlan = grant && planCanonicalArtifact(grant, grant.format);
        const result = grant ? undefined : resultPlan(proof.request, createdAt, { outcome: 'denied', code: 'TOOL_CALL_DENIED',
          denial: { source: 'user', approvalDecisionRef: decisionPlan.ref, approvalDecisionDigest: decision.decisionDigest } }, { code: 'TOOL_CALL_DENIED' });
        const item = policyItem(proof.evidence, grantPlan ? { grantRef: grantPlan.ref } : { outcomeItemRef: canonicalSha256(result!.item) }, decision);
        const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
          items: [item, ...(result ? [result.item] : [])], frontier: grant ? selected.frontier : nextFrontier(selected, 2),
          checkpointId: identityHash('cliq-tool-approval-decision-checkpoint-v1', decisionPlan.ref), workspaceStateRef: selected.checkpoint.workspaceStateRef,
          artifacts: [decisionPlan, ...(grantPlan ? [grantPlan] : []), ...(result?.artifacts ?? [])] });
        const { waitingOnRef: _wait, waitingReason: _reason, ...current } = selected.run;
        const next: Run = { ...current, ...plan.runUpdate, revision: current.revision + 1, status: 'queued', updatedAt: createdAt };
        const response: ApprovalResponse = { protocolVersion: 1, ok: true, result: { method: 'run.approve', decisionRef: decisionPlan.ref,
          snapshot: { schemaVersion: 1, operation: 'agent', run: next, latestRunItemSeq: plan.throughItemSeq } } };
        const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-application-response-v1');
        let outcome: TimeFenceAdvance | undefined, committed = false;
        driver.transaction((connection) => {
          assertActiveStateOwner(connection, owner);
          if (readControlRequest(connection, input.principalId, 'run.approve', input.requestId)) return;
          const now = sampleCanonicalNow(), fence = readTimeFence(connection);
          if (!fence) throw new KernelStorageError('RECOVERY_REQUIRED', 'approval canonical time fence is missing');
          if (now < createdAt || now < fence.lastAcceptedAt) { outcome = advanceTimeFence(connection, owner.ownerEpoch, now); return; }
          if (createdAt < fence.lastAcceptedAt) return; // Re-plan the timestamped immutable response, not a partial SQL update.
          const run = readRun(connection, runId);
          assertApprovalCut(connection, run, selected);
          outcome = advanceTimeFence(connection, owner.ownerEpoch, createdAt);
          if (outcome !== 'healthy') return;
          for (const artifact of [...channel.metadata, ...plan.metadata, responseArtifact]) insertArtifactMetadata(connection, artifact, createdAt);
          plan.commit(connection, run, nextJournalSequence(connection, runId) - 1, createdAt);
          connection.prepare("UPDATE runs SET status = 'queued', waiting_reason = NULL, waiting_on_ref = NULL, revision = revision + 1, updated_at = ? WHERE id = ?")
            .run(createdAt, runId);
          requireEqual(readRun(connection, runId), next, 'committed approval snapshot');
          appendRunStateEvent(connection, next, createdAt);
          insertControlRequest(connection, { principalId: input.principalId, method: 'run.approve', requestId: input.requestId,
            channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, requestDigest,
            responseRef: responseArtifact.ref, committedAt: createdAt });
          committed = true;
        });
        requireHealthyFence(outcome);
        if (committed) return immutableSnapshot({ replayed: false, run: next, response });
        const replayed = await replay();
        if (replayed) return replayed;
      }
      throw new KernelStorageError('REVISION_CONFLICT', 'approval control cut kept changing');
    }),
    claimTool: stateOperation('RECOVERY_REQUIRED', async (input: Omit<ClaimInvocationDispatchInput, 'runId'>) => {
      input = { ...input };
      const selected = await cut(input.expectedRunRevision);
      const expected = requestFor(selected);
      const prepared = readHighestPreparedAttempt(driver, runId, input.opId);
      if (!prepared?.grantRef || prepared.requestRef !== canonicalSha256(expected.request) || prepared.attempt !== input.attempt) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool claim is not the current prepared call');
      }
      const proof = await verifyGrant(prepared.grantRef);
      requireEqual(proof.request, expected.request, 'current tool request');
      const claimed = await claimValidatedInvocation(driver, artifacts, owner, { ...input, runId }, (connection, run, current, now) => {
        assertCut(connection, run, selected);
        requireEqual(current, prepared, 'prepared tool claim');
        const uses = Number(connection.prepare("SELECT count(*) AS count FROM run_journal WHERE run_id = ? AND op_id = ? AND phase = 'dispatch_claimed'")
          .get<{ count: unknown }>(runId, input.opId)?.count);
        if (now < proof.grant.issuedAt || now >= proof.grant.expiresAt || uses >= proof.grant.maxDispatchedAttempts) {
          throw new KernelStorageError('LEASE_FENCED', 'tool grant is expired, not yet valid or exhausted');
        }
      });
      return immutableSnapshot({ entry: claimed, request: proof.request, target: proof.target,
        ...compiled.projectInvocation({ callId: selected.call.callId, index: selected.call.index, toolName: selected.call.toolName, input: selected.call.value! }) });
    }),
    completeTool: stateOperation('INVALID_REQUEST', async (input: {
      opId: string; attempt: number; expectedRunRevision: number; observationRef: string;
    }) => {
      input = immutableSnapshot(input);
      const selected = await cut(input.expectedRunRevision);
      const expected = requestFor(selected);
      const entries = readInvocationAttempt(driver, runId, input.opId, input.attempt);
      const prepared = entries.find((entry) => entry.phase === 'prepared'), claim = entries.find((entry) => entry.phase === 'dispatch_claimed');
      if (!prepared?.grantRef || !claim || input.opId !== expected.request.opId || readHighestPreparedAttempt(driver, runId, input.opId)?.attempt !== input.attempt) {
        throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool completion requires its current permanent dispatch claim');
      }
      const proof = await verifyGrant(prepared.grantRef);
      requireEqual(proof.request, expected.request, 'completed tool request');
      let observationRef = input.observationRef;
      let observation = await readCanonicalArtifact<ToolObservationV1>(artifacts, observationRef);
      if (!exactKeys(observation, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'requestRef', 'targetRef', 'grantRef', 'dispatchId',
        'observedAt', 'observationDigest', 'outcome', ...(observation.postEffect === undefined ? [] : ['postEffect']),
        ...(observation.outcome === 'executed' ? ['content'] : ['code', 'diagnosticRef', 'diagnosticDigest'])]) ||
          observation.schemaVersion !== 1 || observation.format !== 'cliq-tool-observation-v1' || observation.runId !== runId ||
          observation.opId !== input.opId || observation.attempt !== input.attempt || observation.requestRef !== prepared.requestRef ||
          observation.targetRef !== prepared.target || observation.grantRef !== prepared.grantRef || observation.dispatchId !== claim.dispatchId ||
          digestOmitting(observation, 'observationDigest') !== observation.observationDigest || observation.observedAt < claim.timestamp ||
          parseCanonicalTime(observation.observedAt) > parseCanonicalTime(sampleCanonicalNow())) throw new TypeError('tool observation does not match its claimed request');
      if (observation.outcome === 'executed' && (canonicalJsonBytes(observation.content).byteLength > 1_048_576 ||
          outputSchemas.get(expected.entry.name)?.(observation.content) === false)) {
        const diagnostic = await artifacts.publishCanonical({ schemaVersion: 1, format: 'cliq-tool-output-diagnostic-v1',
          code: 'TOOL_PROTOCOL_ERROR', observationRef }, 'cliq-tool-output-diagnostic-v1');
        const { content: _content, observationDigest: _digest, ...base } = observation;
        const core = { ...base, outcome: 'error' as const, code: 'TOOL_PROTOCOL_ERROR' as const, diagnosticRef: diagnostic.ref, diagnosticDigest: diagnostic.ref };
        observation = { ...core, observationDigest: canonicalSha256(core) };
        observationRef = (await artifacts.publishCanonical(observation, observation.format)).ref;
      }
      if (observation.outcome === 'error') {
        if (!['TOOL_EXECUTION_FAILED', 'TOOL_PROTOCOL_ERROR', 'TOOL_RESOURCE_EXHAUSTED'].includes(observation.code) ||
            canonicalSha256(await readCanonicalArtifact(artifacts, observation.diagnosticRef)) !== observation.diagnosticDigest) throw new TypeError('tool error diagnostic mismatch');
      } else if (observation.outcome !== 'executed') throw new TypeError('unknown tool observation outcome');
      const mutating = expected.entry.access !== 'read';
      if (mutating !== (observation.postEffect !== undefined) || (observation.postEffect !== undefined &&
          !exactKeys(observation.postEffect, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef']))) {
        throw new TypeError('mutating tool completion requires its exact post-effect checkpoint; read-only tools cannot replace workspace state');
      }
      const checkpointId = toolCheckpointId(runId, input.opId, input.attempt);
      const seal = observation.postEffect === undefined ? undefined : await prepareToolCheckpoint(driver, artifacts, owner, {
        run: selected.run, spec, assembly, checkpointId, observedAt: observation.observedAt, postEffect: observation.postEffect
      });
      const observed = observation;
      // A received tool error is a known, executed result, not proof that dispatch released nothing.
      return immutableSnapshot(await settleValidatedInvocation(driver, artifacts, owner, { ...input, runId },
        { phase: 'completed', resultRef: observationRef, consumed: TOOL_BUDGET }, async ({ run, settlement }) => {
        const payload = observed.outcome === 'executed' ? { outcome: 'executed' as const, source: 'invocation' as const, opId: input.opId, attempt: input.attempt,
          journalResultRef: observationRef, journalResultDigest: observed.observationDigest,
          ...(expected.entry.outputSchemaRef ? { outputSchemaRef: expected.entry.outputSchemaRef, outputSchemaDigest: expected.entry.outputSchemaDigest } : {}) }
          : { outcome: 'error' as const, code: observed.code, opId: input.opId, attempt: input.attempt,
              journalErrorRef: observationRef, journalErrorDigest: observed.observationDigest,
              diagnosticRef: observed.diagnosticRef, diagnosticDigest: observed.diagnosticDigest };
        const result = resultPlan(expected.request, settlement.settledAt, payload, observed.outcome === 'executed' ? observed.content : { code: observed.code });
        const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
          items: [result.item], frontier: nextFrontier(selected, 1), checkpointId,
          workspaceStateRef: observed.postEffect?.workspaceStateRef ?? selected.checkpoint.workspaceStateRef, artifacts: result.artifacts });
        const observationMetadata = await artifacts.describe(observationRef, 'application/json', observed.format);
        return { metadata: [observationMetadata, ...plan.metadata, ...(seal?.metadata ?? [])], commit(connection, current, journal) {
          assertCut(connection, current, selected);
          if (settlement.settledAt < observed.observedAt || run.revision !== selected.run.revision) throw new TypeError('tool settlement precedes its observation');
          seal?.commit(connection, current, settlement.settledAt);
          plan.commit(connection, current, journal.seq, settlement.settledAt);
        } };
      }));
    })
  };
}
