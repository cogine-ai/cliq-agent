import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, RunSpec, ToolContractManifestV1, ToolResultPayloadV1, ToolResultModelContentV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, ToolObservationV1, ToolOperationGrantV1, ToolPolicyChannelEvidenceV1, ToolPolicyDecisionItem,
  ToolRequestV1, ToolTargetV1, ToolApprovalWait, ToolApprovalDecisionV1, ToolGrantExpiryV1 } from '../kernel/tool-authorization.js';
import { toolOperationId } from '../policy/tool-policy.js';
import { toolApprovalCheckpointId, toolApprovalDecision } from '../policy/tool-approval.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeWorkspaceGenerationSnapshotEvidence, decodeWorkspaceState, decodeWorkspaceEntries } from './decoders.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { compileOutputSchema } from '../tools/input-schema.js';

/** Reachability and durable ownership. The loaded Run additionally verifies release signatures and replays the fixed evaluator. */
export async function validateToolRecovery(input: {
  artifacts: ArtifactCatalog; run: Run; spec: RunSpec; items: Map<string, ContinuationItem>; journal: InvocationJournalEntry[];
  checkpoints: Checkpoint[];
}): Promise<void> {
  const { artifacts, run, spec, items, journal } = input;
  const decisions = new Map<string, ToolPolicyDecisionItem>();
  const requests = new Map<string, ToolRequestV1>();
  const calls = [...items.values()].filter((item) => item.kind === 'assistant_tool_batch');
  async function policyRequest(evidenceRef: string) {
    const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(artifacts, evidenceRef);
    const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, evidence.requestRef);
    const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, evidence.targetRef);
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, evidence.frontierRef);
    const batch = calls.find((batch) => batch.itemId === request.batchItemId);
    const call = batch?.calls[request.callIndex];
    if (digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest || evidence.runId !== run.id || evidence.policyRef !== spec.policyRef ||
        request.format !== 'cliq-tool-request-v1' || request.requestDigest !== evidence.requestDigest ||
        digestOmitting(request, 'requestDigest') !== request.requestDigest || request.runId !== run.id || request.assemblyRef !== spec.assemblyRef ||
        request.opId !== evidence.opId || request.opId !== toolOperationId(run.id, request.batchItemId, request.callId) ||
        request.frontierRef !== evidence.frontierRef || request.targetRef !== evidence.targetRef || request.targetDigest !== evidence.targetDigest ||
        target.targetDigest !== request.targetDigest || digestOmitting(target, 'targetDigest') !== target.targetDigest ||
        target.runId !== run.id || target.toolName !== request.toolName || !call || call.callId !== request.callId || call.toolName !== request.toolName ||
        call.inputRef !== request.inputRef || call.inputDigest !== request.inputDigest ||
        frontier.kind !== 'tool' || frontier.batchItemId !== batch!.itemId || frontier.nextCallIndex !== request.callIndex) {
      throw new TypeError('policy decision does not bind its retained batch, request and frontier');
    }
    requireEqual(frontier.orderedCallIds, batch!.calls.map((call) => call.callId), 'policy frontier call order');
    const policy = await readCanonicalArtifact<RunPolicySnapshotV1>(artifacts, evidence.policyRef);
    if (policy.policyDigest !== evidence.policyDigest || digestOmitting(policy, 'policyDigest') !== policy.policyDigest) throw new TypeError('policy evidence snapshot digest mismatch');
    await artifacts.readBytes(policy.engine.runtimeBundleRef);
    await artifacts.readBytes(policy.engine.profileRef);
    const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, policy.toolManifestRef);
    const contract = manifest.entries.find((entry) => entry.name === request.toolName);
    if (manifest.manifestDigest !== policy.toolManifestDigest || digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest ||
        target.toolManifestRef !== policy.toolManifestRef || target.toolManifestDigest !== manifest.manifestDigest ||
        !contract || canonicalSha256(contract) !== target.toolContractDigest) throw new TypeError('tool approval/decision substitutes its frozen contract');
    for (const rule of policy.decisionRules) if (rule.sourceRef) await artifacts.readBytes(rule.sourceRef);
    requests.set(evidence.requestRef, request);
    return { evidence, request, target, frontier, batch: batch!, call: call!, contract };
  }
  async function approvalWait(waitingRef: string) {
    const wait = await readCanonicalArtifact<ToolApprovalWait>(artifacts, waitingRef);
    const proof = await policyRequest(wait.subject.policyChannelEvidenceRef);
    const { evidence, request, target, contract } = proof;
    if (!exactKeys(wait, ['schemaVersion', 'kind', 'runId', 'createdFromRevision', 'createdAt', 'frontierRef', 'subject']) ||
        wait.schemaVersion !== 1 || wait.kind !== 'approval' || wait.runId !== run.id || wait.frontierRef !== request.frontierRef ||
        !Number.isSafeInteger(wait.createdFromRevision) || wait.createdFromRevision < 1 || wait.createdAt !== evidence.evaluatedAt ||
        wait.createdAt < run.createdAt || wait.createdAt >= run.deadlineAt || evidence.effectiveDisposition !== 'ask') throw new TypeError('invalid retained tool approval wait');
    parseCanonicalTime(wait.createdAt);
    requireEqual(wait.subject, { kind: 'tool_call', policySubjectKind: 'ordinary_tool', batchItemId: request.batchItemId,
      callId: request.callId, callIndex: request.callIndex, opId: request.opId, target: request.targetRef, toolName: request.toolName,
      toolContractDigest: target.toolContractDigest, replayClass: contract.replayClass,
      policyChannelEvidenceRef: canonicalSha256(evidence), policyChannelEvidenceDigest: evidence.evidenceDigest }, 'retained approval subject');
    const checkpoint = input.checkpoints.find((checkpoint) => checkpoint.id === toolApprovalCheckpointId(waitingRef));
    const prior = input.checkpoints.filter((checkpoint) => checkpoint.basedOnRunRevision < wait.createdFromRevision).at(-1);
    if (!checkpoint || !prior || checkpoint.basedOnRunRevision !== wait.createdFromRevision || checkpoint.createdAt < wait.createdAt ||
        checkpoint.workspaceStateRef !== prior.workspaceStateRef || checkpoint.contextManifestRef !== prior.contextManifestRef ||
        checkpoint.runItemSeq !== prior.runItemSeq) throw new TypeError('approval wait has no unchanged ready Checkpoint');
    return { ...proof, wait, checkpoint };
  }
  // Worker-death reconciliation is validated against the full Run/launch/
  // generation/Journal cut by readRecoveryClosure, not as a tool approval.
  if (run.waitingReason === 'approval' || (run.status === 'waiting' && run.nextStep === 'tool' &&
      run.waitingReason !== 'input' && run.waitingReason !== 'reconciliation')) {
    if (run.status !== 'waiting' || run.waitingReason !== 'approval' || !run.waitingOnRef || run.activeWorkerLaunchId || run.nextStep !== 'tool') {
      throw new TypeError('approval wait retains an execution worker or lacks its exact subject');
    }
    const { wait, checkpoint } = await approvalWait(run.waitingOnRef);
    if ((run.stopIntentRef ? run.revision < wait.createdFromRevision + 1 : run.revision !== wait.createdFromRevision + 1) || run.frontierRef !== wait.frontierRef || run.latestCheckpointId !== checkpoint.id) {
      throw new TypeError('waiting Run substitutes its revision, frontier or Checkpoint');
    }
  }
  const approvedWaits = new Set<string>();
  for (const item of items.values()) if (item.kind === 'policy_decision') {
    const { evidence, request, target, batch, call } = await policyRequest(item.policyChannelEvidenceRef);
    const priorResults = [...items.values()].slice(0, [...items.keys()].indexOf(item.itemId))
      .filter((prior) => prior.kind === 'tool_result' && prior.batchItemId === request.batchItemId);
    if (item.runId !== run.id || item.subjectKind !== 'tool_call' || evidence.evidenceDigest !== item.policyChannelEvidenceDigest ||
        evidence.opId !== item.opId || evidence.principalId !== item.principalId || priorResults.length !== request.callIndex ||
        !['direct_policy', 'interactive_approval'].includes(item.decisionSource)) throw new TypeError('policy decision does not own the current ordered call');
    let approval: ToolApprovalDecisionV1 | undefined;
    if (item.decisionSource === 'direct_policy') {
      if (item.waitingSubjectRef !== undefined || item.decisionRef !== item.policyChannelEvidenceRef || evidence.effectiveDisposition !== item.decision) {
        throw new TypeError('direct policy decision substitutes its evidence or invents a wait');
      }
    } else {
      if (approvedWaits.has(item.waitingSubjectRef)) throw new TypeError('one approval wait cannot have two decisions');
      approvedWaits.add(item.waitingSubjectRef);
      const proof = await approvalWait(item.waitingSubjectRef);
      approval = await readCanonicalArtifact<ToolApprovalDecisionV1>(artifacts, item.decisionRef);
      requireEqual(proof.evidence, evidence, 'approval item policy evidence');
      requireEqual(approval, toolApprovalDecision(proof.wait, { principalId: evidence.principalId, channelIdentityRef: approval.channelIdentityRef,
        channelIdentityDigest: approval.channelIdentityDigest, requestId: approval.requestId, expectedRunRevision: approval.expectedRunRevision,
        waitingOnRef: item.waitingSubjectRef, decision: item.decision, ...(approval.requestedTtlMs === undefined ? {} : { ttlMs: approval.requestedTtlMs }) },
        approval.createdAt, run.deadlineAt), 'retained approval decision');
      await artifacts.readBytes(approval.channelIdentityRef);
      const checkpoint = input.checkpoints.find((checkpoint) => checkpoint.id === identityHash('cliq-tool-approval-decision-checkpoint-v1', item.decisionRef));
      if (!checkpoint || checkpoint.createdAt !== approval.createdAt || checkpoint.basedOnRunRevision !== approval.expectedRunRevision ||
          checkpoint.workspaceStateRef !== proof.checkpoint.workspaceStateRef || checkpoint.journalSeq !== proof.checkpoint.journalSeq ||
          checkpoint.runItemSeq !== [...items.keys()].indexOf(item.itemId) + (item.decision === 'allow' ? 1 : 2)) throw new TypeError('approval decision has no atomic continuation Checkpoint');
    }
    if (item.decision === 'allow') {
      if (decisions.has(item.grantRef)) throw new TypeError('one operation grant cannot have duplicate decision items');
      const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, item.grantRef);
      if (grant.grantDigest !== digestOmitting(grant, 'grantDigest') ||
          grant.provenance.kind !== (approval ? 'user_approval' : 'policy_snapshot') ||
          grant.provenance.channelEvidenceRef !== item.policyChannelEvidenceRef || grant.provenance.channelEvidenceDigest !== evidence.evidenceDigest ||
          grant.requestRef !== evidence.requestRef || grant.requestDigest !== evidence.requestDigest || grant.targetRef !== evidence.targetRef ||
          grant.targetDigest !== evidence.targetDigest || grant.opId !== request.opId || grant.runId !== run.id || grant.frontierRef !== evidence.frontierRef ||
          grant.subject.callId !== call.callId || grant.subject.callIndex !== call.index || grant.subject.batchItemId !== batch!.itemId ||
          grant.subject.toolName !== call.toolName || grant.subject.toolContractDigest !== target.toolContractDigest ||
          grant.issuedAt < evidence.evaluatedAt || grant.expiresAt > run.deadlineAt || parseCanonicalTime(grant.expiresAt) <= parseCanonicalTime(grant.issuedAt)) {
        throw new TypeError('retained grant differs from its committed policy decision');
      }
      if (approval) {
        requireEqual(grant.provenance, { kind: 'user_approval', waitingSubjectRef: approval.waitingSubjectRef, decisionRef: item.decisionRef,
          requestId: approval.requestId, channelEvidenceRef: item.policyChannelEvidenceRef, channelEvidenceDigest: evidence.evidenceDigest }, 'approval grant provenance');
        if (grant.issuedAt !== approval.createdAt || grant.expiresAt !== approval.grantExpiresAt) throw new TypeError('approval grant substitutes its lifetime');
      }
      decisions.set(item.grantRef, item);
    } else {
      const outcome = await readCanonicalArtifact<ContinuationItem>(artifacts, item.denialOutcome.outcomeItemRef);
      if (outcome.kind !== 'tool_result' || outcome.outcome !== 'denied' || outcome.batchItemId !== batch!.itemId ||
          outcome.callId !== call.callId || outcome.index !== call.index || !items.has(outcome.itemId)) throw new TypeError('policy denial has no owning ordered result');
      requireEqual(outcome, items.get(outcome.itemId), 'committed denied outcome');
      const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, outcome.resultRef);
      if (payload.outcome !== 'denied' || payload.code !== 'TOOL_CALL_DENIED') throw new TypeError('denied result substitutes its policy proof');
      requireEqual(payload.denial, approval ? { source: 'user', approvalDecisionRef: item.decisionRef, approvalDecisionDigest: approval.decisionDigest }
        : { source: 'policy', policyRef: spec.policyRef, decisionDigest: evidence.evidenceDigest }, 'denial authority');
      const content = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, payload.modelContentRef);
      requireEqual(content.content, { code: 'TOOL_CALL_DENIED' }, 'model-safe denial');
    }
  }
  for (const prepared of journal.filter((entry) => entry.phase === 'prepared' && (entry.opKind === 'tool' || entry.opKind === 'mcp'))) {
    const request = requests.get(prepared.requestRef);
    if (!request || !prepared.grantRef || !decisions.has(prepared.grantRef) || prepared.opId !== request.opId || prepared.target !== request.targetRef ||
        prepared.idempotencyKey !== request.idempotencyKey) throw new TypeError('tool Journal has no committed exact policy/grant owner');
    const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, prepared.grantRef);
    const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, request.targetRef);
    if (prepared.replayClass !== grant.subject.replayClass || grant.requestRef !== prepared.requestRef ||
        prepared.opKind !== (target.execution.kind === 'mcp' ? 'mcp' : 'tool')) throw new TypeError('tool Journal substitutes the grant contract');
    requireEqual(prepared.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, 'tool reservation');
    const attempts = journal.filter((entry) => entry.opId === prepared.opId);
    const claims = attempts.filter((entry) => entry.phase === 'dispatch_claimed');
    const grantClaims = claims.filter((entry) => entry.grantRef === prepared.grantRef);
    if (claims.length > grant.maxDispatchedAttempts || grantClaims.some((entry) =>
        entry.timestamp < grant.issuedAt || entry.timestamp >= grant.expiresAt)) throw new TypeError('tool grant claim lifetime or use count mismatch');
    if (prepared.timestamp < grant.issuedAt || prepared.timestamp >= grant.expiresAt) throw new TypeError('tool preparation uses an expired grant');
    const failed = attempts.find((entry) => entry.attempt === prepared.attempt && entry.phase === 'failed');
    if (failed && run.stopIntentRef && failed.errorRef === run.stopIntentRef) {
      if (!['failed', 'cancelled'].includes(run.status) || failed.timestamp !== run.updatedAt ||
          claims.some((claim) => claim.attempt === prepared.attempt)) throw new TypeError('stop refund is not an atomic undispatched terminal closure');
      requireEqual(failed.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, 'stop no-dispatch refund');
    } else if (failed) {
      const expiry = await readCanonicalArtifact<ToolGrantExpiryV1>(artifacts, failed.errorRef!);
      const proof = await approvalWait(expiry.waitingSubjectRef);
      requireEqual(proof.request, request, 'renewed approval request');
      requireEqual(expiry, { schemaVersion: 1, format: 'cliq-tool-grant-expiry-v1', code: 'TOOL_GRANT_EXPIRED_BEFORE_DISPATCH',
        runId: run.id, opId: prepared.opId, attempt: prepared.attempt, preparedJournalSeq: prepared.seq,
        grantRef: prepared.grantRef, waitingSubjectRef: expiry.waitingSubjectRef, observedAt: proof.wait.createdAt }, 'no-dispatch expiry');
      if (grant.provenance.kind !== 'user_approval' || claims.some((claim) => claim.attempt === prepared.attempt) ||
          expiry.observedAt < grant.expiresAt || failed.timestamp < expiry.observedAt || proof.checkpoint.journalSeq !== failed.seq ||
          proof.checkpoint.createdAt !== failed.timestamp) throw new TypeError('expired tool grant has no atomic positive no-dispatch closure');
      requireEqual(failed.budgetDelta, { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, 'no-dispatch refund');
    }
    const completion = attempts.find((entry) => entry.attempt === prepared.attempt && entry.phase === 'completed');
    if (!completion) continue;
    const claim = claims.find((entry) => entry.attempt === completion.attempt);
    const result = completion.resultRef && await readCanonicalArtifact<ToolObservationV1>(artifacts, completion.resultRef);
    const item = [...items.values()].find((item) => item.kind === 'tool_result' && item.opId === prepared.opId);
    if (!claim || !result || !exactKeys(result, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'requestRef', 'targetRef', 'grantRef', 'dispatchId',
      'observedAt', 'observationDigest', 'outcome', ...(result.postEffect === undefined ? [] : ['postEffect']),
      ...(result.outcome === 'executed' ? ['content'] : ['code', 'diagnosticRef', 'diagnosticDigest'])]) ||
        result.schemaVersion !== 1 || result.format !== 'cliq-tool-observation-v1' || result.observationDigest !== digestOmitting(result, 'observationDigest') ||
        result.runId !== run.id || result.opId !== prepared.opId || result.attempt !== prepared.attempt || result.requestRef !== prepared.requestRef ||
        result.targetRef !== prepared.target || result.grantRef !== prepared.grantRef || result.dispatchId !== claim.dispatchId ||
        result.observedAt < claim.timestamp || result.observedAt > completion.timestamp || item?.kind !== 'tool_result') {
      throw new TypeError('completed tool has no matching typed observation and ordered result');
    }
    requireEqual(completion.budgetDelta, prepared.budgetDelta, 'tool completion charge');
    const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
    const content = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, payload.modelContentRef);
    const manifest = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, target.toolManifestRef);
    const contract = manifest.entries.find((entry) => entry.name === request.toolName);
    if (!contract || canonicalSha256(contract) !== target.toolContractDigest || manifest.manifestDigest !== target.toolManifestDigest ||
        digestOmitting(manifest, 'manifestDigest') !== manifest.manifestDigest) throw new TypeError('tool result contract substitution');
    if (result.outcome === 'executed') {
      if (payload.outcome !== 'executed' || payload.source !== 'invocation' || payload.journalResultRef !== completion.resultRef ||
          payload.journalResultDigest !== result.observationDigest || payload.outputSchemaRef !== contract.outputSchemaRef ||
          payload.outputSchemaDigest !== contract.outputSchemaDigest) throw new TypeError('executed result substitutes its Journal source');
      requireEqual(content.content, result.content, 'executed model content');
      if (canonicalJsonBytes(result.content).byteLength > 1_048_576) throw new TypeError('retained tool output exceeds its byte bound');
      if (contract.outputSchemaRef) {
        const schema = await readCanonicalArtifact(artifacts, contract.outputSchemaRef);
        if (canonicalSha256(schema) !== contract.outputSchemaDigest || !compileOutputSchema(schema)(result.content)) throw new TypeError('retained tool output violates its frozen schema');
      }
    } else {
      if (result.outcome !== 'error' || !['TOOL_EXECUTION_FAILED', 'TOOL_PROTOCOL_ERROR', 'TOOL_RESOURCE_EXHAUSTED'].includes(result.code) ||
          payload.outcome !== 'error' || payload.journalErrorRef !== completion.resultRef ||
          payload.journalErrorDigest !== result.observationDigest || payload.diagnosticRef !== result.diagnosticRef ||
          payload.diagnosticDigest !== result.diagnosticDigest || payload.code !== result.code) throw new TypeError('tool error substitutes its Journal source');
      const diagnostic = await readCanonicalArtifact<{ observationRef?: string }>(artifacts, result.diagnosticRef);
      if (canonicalSha256(diagnostic) !== result.diagnosticDigest) throw new TypeError('tool error diagnostic does not rehash');
      if (diagnostic.observationRef) await artifacts.readBytes(diagnostic.observationRef);
      requireEqual(content.content, { code: result.code }, 'model-safe tool error');
    }
    if (!('opId' in payload) || payload.opId !== prepared.opId || payload.attempt !== prepared.attempt) throw new TypeError('tool payload operation identity mismatch');
    const checkpoint = input.checkpoints.find((checkpoint) => checkpoint.id === toolCheckpointId(run.id, prepared.opId, prepared.attempt));
    const itemSeq = [...items.keys()].indexOf(item.itemId) + 1;
    if (!checkpoint || checkpoint.runId !== run.id || checkpoint.journalSeq !== completion.seq || checkpoint.runItemSeq !== itemSeq ||
        checkpoint.createdAt !== completion.timestamp) throw new TypeError('tool result has no atomically matching ready Checkpoint');
    if ((contract.access !== 'read') !== (result.postEffect !== undefined)) throw new TypeError('tool result post-effect proof does not match its access class');
    if (result.postEffect) {
      if (!exactKeys(result.postEffect, ['workspaceStateRef', 'snapshotEvidenceRef', 'retirementEvidenceRef'])) throw new TypeError('unknown post-effect proof field');
      const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, result.postEffect.snapshotEvidenceRef));
      const workspace = decodeWorkspaceState(await readCanonicalArtifact(artifacts, result.postEffect.workspaceStateRef));
      const entries = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, workspace.entriesRef));
      if (checkpoint.workspaceStateRef !== result.postEffect.workspaceStateRef || snapshot.checkpointId !== checkpoint.id ||
          snapshot.purpose !== 'sealed_to_checkpoint' || snapshot.workspaceStateRef !== checkpoint.workspaceStateRef ||
          workspace.runId !== run.id || workspace.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef ||
          snapshot.workspaceStateDigest !== workspace.stateDigest || snapshot.entriesRef !== workspace.entriesRef || snapshot.treeDigest !== entries.treeDigest ||
          snapshot.privateGitStateRef !== workspace.privateGitStateRef ||
          snapshot.runId !== run.id || snapshot.observedAt < result.observedAt || snapshot.observedAt > completion.timestamp) {
        throw new TypeError('completed mutating tool cannot recover over its pre-effect workspace');
      }
      for (const entry of entries.entries) if (entry.kind === 'file' && (await artifacts.readBytes(entry.blobRef)).byteLength !== entry.size) {
        throw new TypeError('retained post-effect file byte count mismatch');
      }
      if (workspace.privateGitStateRef) await artifacts.readBytes(workspace.privateGitStateRef);
      await artifacts.readBytes(snapshot.generationRef);
      const death = await readCanonicalArtifact<{ inspectorIdentityRef: string }>(artifacts, result.postEffect.retirementEvidenceRef);
      await artifacts.readBytes(death.inspectorIdentityRef);
    } else {
      const prior = input.checkpoints.filter((candidate) => candidate.basedOnRunRevision < checkpoint.basedOnRunRevision).at(-1);
      if (!prior || checkpoint.workspaceStateRef !== prior.workspaceStateRef) throw new TypeError('read-only completion replaced workspace state');
    }
  }
}
