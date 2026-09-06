import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, Run, RunFrontier, RunSpec, ToolContractManifestV1, ToolResultPayloadV1, ToolResultModelContentV1 } from '../kernel/types.js';
import type { RunPolicySnapshotV1, ToolObservationV1, ToolOperationGrantV1, ToolPolicyChannelEvidenceV1, ToolPolicyDecisionItem,
  ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import { toolOperationId } from '../policy/tool-policy.js';
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
  for (const item of items.values()) if (item.kind === 'policy_decision') {
    const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(artifacts, item.policyChannelEvidenceRef);
    const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, evidence.requestRef);
    const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, evidence.targetRef);
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, evidence.frontierRef);
    const batch = calls.find((batch) => batch.itemId === request.batchItemId);
    const call = batch?.calls[request.callIndex];
    if (item.runId !== run.id || item.subjectKind !== 'tool_call' || item.decisionSource !== 'direct_policy' ||
        item.decisionRef !== item.policyChannelEvidenceRef || evidence.evidenceDigest !== item.policyChannelEvidenceDigest ||
        digestOmitting(evidence, 'evidenceDigest') !== evidence.evidenceDigest || evidence.effectiveDisposition !== item.decision ||
        evidence.opId !== item.opId || evidence.principalId !== item.principalId || evidence.runId !== run.id || evidence.policyRef !== spec.policyRef ||
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
    await artifacts.readBytes(policy.toolManifestRef);
    for (const rule of policy.decisionRules) if (rule.sourceRef) await artifacts.readBytes(rule.sourceRef);
    requests.set(evidence.requestRef, request);
    if (item.decision === 'allow') {
      if (decisions.has(item.grantRef)) throw new TypeError('one operation grant cannot have duplicate decision items');
      const grant = await readCanonicalArtifact<ToolOperationGrantV1>(artifacts, item.grantRef);
      if (grant.grantDigest !== digestOmitting(grant, 'grantDigest') || grant.provenance.kind !== 'policy_snapshot' ||
          grant.provenance.channelEvidenceRef !== item.policyChannelEvidenceRef || grant.provenance.channelEvidenceDigest !== evidence.evidenceDigest ||
          grant.requestRef !== evidence.requestRef || grant.requestDigest !== evidence.requestDigest || grant.targetRef !== evidence.targetRef ||
          grant.targetDigest !== evidence.targetDigest || grant.opId !== request.opId || grant.runId !== run.id || grant.frontierRef !== evidence.frontierRef ||
          grant.subject.callId !== call.callId || grant.subject.callIndex !== call.index || grant.subject.batchItemId !== batch!.itemId ||
          grant.subject.toolName !== call.toolName || grant.subject.toolContractDigest !== target.toolContractDigest ||
          grant.issuedAt < evidence.evaluatedAt || grant.expiresAt > run.deadlineAt || parseCanonicalTime(grant.expiresAt) <= parseCanonicalTime(grant.issuedAt)) {
        throw new TypeError('retained grant differs from its committed direct-policy decision');
      }
      decisions.set(item.grantRef, item);
    } else {
      const outcome = await readCanonicalArtifact<ContinuationItem>(artifacts, item.denialOutcome.outcomeItemRef);
      if (outcome.kind !== 'tool_result' || outcome.outcome !== 'denied' || outcome.batchItemId !== batch!.itemId ||
          outcome.callId !== call.callId || outcome.index !== call.index || !items.has(outcome.itemId)) throw new TypeError('policy denial has no owning ordered result');
      requireEqual(outcome, items.get(outcome.itemId), 'committed denied outcome');
      const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, outcome.resultRef);
      if (payload.outcome !== 'denied' || payload.denial.source !== 'policy' || payload.denial.policyRef !== spec.policyRef ||
          payload.denial.decisionDigest !== evidence.evidenceDigest || payload.code !== 'TOOL_CALL_DENIED') throw new TypeError('denied result substitutes its policy proof');
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
    if (claims.length > grant.maxDispatchedAttempts || claims.some((entry) => entry.grantRef !== prepared.grantRef ||
        entry.timestamp < grant.issuedAt || entry.timestamp >= grant.expiresAt)) throw new TypeError('tool grant claim lifetime or use count mismatch');
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
      if (payload.outcome !== 'executed' || payload.journalResultRef !== completion.resultRef ||
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
    if (payload.opId !== prepared.opId || payload.attempt !== prepared.attempt) throw new TypeError('tool payload operation identity mismatch');
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
