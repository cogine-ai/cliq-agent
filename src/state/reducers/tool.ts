import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import { planCanonicalArtifact } from '../../kernel/artifact-plan.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../kernel/identity.js';
import type { Run, RunAssemblyV1, RunFrontier, RunSpec, ToolResultItem, ToolResultPayloadV1, ToolResultModelContentV1 } from '../../kernel/types.js';
import type { PolicyEngineProfileV1, RunPolicySnapshotV1, ToolObservationV1, ToolOperationGrantV1,
  ToolPolicyChannelEvidenceV1, ToolPolicyDecisionItem, ToolRequestV1, ToolTargetV1 } from '../../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../../protocol/agent-ir.js';
import { immutableSnapshot } from '../../model/immutable.js';
import type { ResolveToolInput } from '../../model/attempt.js';
import { loadToolContracts, type ToolInputAuthority } from '../../tools/input-contract.js';
import { compileOutputSchema } from '../../tools/input-schema.js';
import { loadToolPolicy, toolOperationId } from '../../policy/tool-policy.js';
import { exactKeys, requireEqual, verifyToolRuntimeAuthority, type ReleaseTrustKey, type RuntimeBundleManifest } from '../../policy/runtime-authority.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { prepareContinuationCommit } from '../continuation-commit.js';
import { decodeWorkspaceIdentity } from '../decoders.js';
import { KernelStorageError, stateOperation } from '../errors.js';
import { nextJournalSequence, readHighestPreparedAttempt, readInvocationAttempt } from '../repositories/journal.js';
import { readRun, readSession, readSessionPrincipalId } from '../rows.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import { prepareToolCheckpoint, toolCheckpointId } from '../tool-checkpoint.js';
import { readToolCut, type ToolCut } from '../tool-cut.js';
import { appendRunStateEvent, assertLiveDispatchState, claimValidatedInvocation, prepareValidatedInvocation,
  requireHealthyFence, settleValidatedInvocation, type ClaimInvocationDispatchInput } from './invocation.js';

const TOOL_BUDGET = Object.freeze({ modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 });
type ResultFields<T = ToolResultPayloadV1> = T extends ToolResultPayloadV1
  ? Omit<T, 'schemaVersion' | 'format' | 'runId' | 'batchItemId' | 'callId' | 'index' | 'toolName' | 'modelContentRef' | 'modelContentDigest' | 'payloadDigest'> : never;

function policyItem(evidence: ToolPolicyChannelEvidenceV1, decision: { grantRef: string } | { outcomeItemRef: string }): ToolPolicyDecisionItem {
  const evidenceRef = canonicalSha256(evidence);
  const base = { schemaVersion: 1 as const, kind: 'policy_decision' as const,
    itemId: identityHash('cliq-tool-policy-item-v1', evidence.runId, evidence.opId, evidenceRef), runId: evidence.runId,
    subjectKind: 'tool_call' as const, opId: evidence.opId, principalId: evidence.principalId, decisionRef: evidenceRef,
    policyChannelEvidenceRef: evidenceRef, policyChannelEvidenceDigest: evidence.evidenceDigest,
    createdAt: evidence.evaluatedAt, decisionSource: 'direct_policy' as const };
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
    requireEqual(grant, evaluator.grant(request, target, call, evidence, grant.issuedAt, grant.expiresAt), 'operation grant');
    if (grant.runId !== runId || grant.expiresAt > admittedRun.deadlineAt || grant.issuedAt < admittedRun.createdAt) throw new TypeError('tool grant exceeds Run authority lifetime');
    return { grant, request, target, call, evidence };
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
    requireEqual(item, policyItem(evidence, item.decision === 'allow' ? { grantRef: item.grantRef } : { outcomeItemRef: item.denialOutcome.outcomeItemRef }), 'policy item');
    if (item.decision !== evidence.effectiveDisposition) throw new TypeError('policy item disposition mismatch');
  }

  return {
    prepareTool: stateOperation('RECOVERY_REQUIRED', async (input: { expectedRunRevision: number; leaseEpoch: number }) => {
      const { expectedRunRevision, leaseEpoch } = input;
      const evaluator = requirePolicy();
      // Before the first decision there is no retained policy item for recovery to walk yet.
      // Static in-memory authority must not hide loss of its durable policy/profile/source bytes.
      for (const ref of policyArtifactRefs) await artifacts.readBytes(ref);
      const selected = await cut(expectedRunRevision);
      assertLiveDispatchState(driver, owner, runId, expectedRunRevision, leaseEpoch, sampleCanonicalNow());
      const { request, target, entry } = requestFor(selected);
      if (readHighestPreparedAttempt(driver, runId, request.opId)) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool attempt already exists; retry/reconciliation requires its owning recovery reducer');
      const evaluatedAt = sampleCanonicalNow();
      const evidence = evaluator.evaluate(request, target, selected.call, evaluatedAt);
      const requestPlan = planCanonicalArtifact(request, request.format), targetPlan = planCanonicalArtifact(target, target.format);
      await artifacts.publishCanonical(request, request.format);
      await artifacts.publishCanonical(target, target.format);
      const evidenceArtifact = await artifacts.publishCanonical(evidence, evidence.format);
      if (evidence.effectiveDisposition === 'ask') return immutableSnapshot({ disposition: 'approval_required' as const, run: selected.run, evidenceRef: evidenceArtifact.ref, evidence });
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
      const grant = evaluator.grant(request, target, selected.call, evidence, evaluatedAt, selected.run.deadlineAt);
      const grantPlan = planCanonicalArtifact(grant, grant.format);
      const decision = policyItem(evidence, { grantRef: grantPlan.ref });
      const plan = await prepareContinuationCommit(artifacts, { context: selected.context, existingItems: selected.items,
        items: [decision], frontier: selected.frontier, checkpointId: identityHash('cliq-tool-admission-checkpoint-v1', grantPlan.ref),
        workspaceStateRef: selected.checkpoint.workspaceStateRef, artifacts: [requestPlan, targetPlan, grantPlan] });
      const prepared = await prepareValidatedInvocation(driver, artifacts, owner, { runId, expectedRunRevision, leaseEpoch,
        opId: request.opId, opKind: entry.execution.kind === 'mcp' ? 'mcp' : 'tool', target: request.targetRef,
        requestRef: requestPlan.ref, replayClass: entry.replayClass, grantRef: grantPlan.ref,
        ...(request.idempotencyKey === undefined ? {} : { idempotencyKey: request.idempotencyKey }), reservation: TOOL_BUDGET
      }, { metadata: [...plan.metadata, evidenceArtifact], validate(connection, run, attempt) {
        assertCut(connection, run, selected);
        if (attempt !== 0 || sampleCanonicalNow() >= grant.expiresAt) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'tool grant is expired or attempt identity changed');
      }, commit(connection, run, journal) { plan.commit(connection, run, journal.seq, journal.timestamp); } });
      return immutableSnapshot({ disposition: 'prepared' as const, ...prepared, request, target,
        checkpointId: toolCheckpointId(runId, request.opId, prepared.entry.attempt) });
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
        const payload = observed.outcome === 'executed' ? { outcome: 'executed' as const, opId: input.opId, attempt: input.attempt,
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
