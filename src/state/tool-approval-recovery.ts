import { identityHash } from '../kernel/identity.js';
import type { ControlResultV1, Run } from '../kernel/types.js';
import type { ToolApprovalDecisionV1, ToolApprovalWait, ToolPolicyChannelEvidenceV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import type { loadToolPolicy } from '../policy/tool-policy.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { readCheckpoint, readControlRequest } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

export type ApprovalResponse = { protocolVersion: 1; ok: true; result: Extract<ControlResultV1, { method: 'run.approve' }> };
type ToolPolicy = ReturnType<typeof loadToolPolicy>;

export async function readToolApprovalWait(artifacts: ArtifactCatalog, run: Run, policy: ToolPolicy, waitingOnRef: string) {
  const wait = await readCanonicalArtifact<ToolApprovalWait>(artifacts, waitingOnRef);
  const evidence = await readCanonicalArtifact<ToolPolicyChannelEvidenceV1>(artifacts, wait.subject.policyChannelEvidenceRef);
  const request = await readCanonicalArtifact<ToolRequestV1>(artifacts, evidence.requestRef);
  const target = await readCanonicalArtifact<ToolTargetV1>(artifacts, request.targetRef);
  const call = await readCanonicalArtifact<ToolCallInputV1>(artifacts, request.inputRef);
  requireEqual(evidence, policy.evaluate(request, target, call, evidence.evaluatedAt), 'waiting policy evidence');
  requireEqual(wait, policy.approvalWait(request, target, evidence, wait.createdFromRevision), 'tool approval wait');
  if (wait.runId !== run.id || wait.createdAt < run.createdAt || wait.createdAt >= run.deadlineAt) throw new TypeError('approval wait exceeds its Run');
  return { wait, evidence, request, target, call };
}

/** Shared complete historical proof: a grant without its authenticated control commit is not approval. */
export async function readToolApproval(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, policy: ToolPolicy, decisionRef: string) {
  const decision = await readCanonicalArtifact<ToolApprovalDecisionV1>(artifacts, decisionRef);
  const proof = await readToolApprovalWait(artifacts, run, policy, decision.waitingSubjectRef);
  const grant = policy.approve(proof.request, proof.target, proof.call, proof.evidence, proof.wait, decision, run.deadlineAt);
  const row = readControlRequest(driver, decision.principalId, 'run.approve', decision.requestId);
  if (!row || row.requestDigest !== decision.requestDigest || row.channelIdentityRef !== decision.channelIdentityRef ||
      row.channelIdentityDigest !== decision.channelIdentityDigest || row.committedAt !== decision.createdAt) {
    throw new TypeError('approval decision has no exact authenticated control-row owner');
  }
  await readHistoricalControlChannel(driver, artifacts, decision);
  const response = await readCanonicalArtifact<ApprovalResponse>(artifacts, row.responseRef);
  const checkpointId = identityHash('cliq-tool-approval-decision-checkpoint-v1', decisionRef);
  const checkpoint = readCheckpoint(driver, checkpointId);
  if (response.protocolVersion !== 1 || response.ok !== true || response.result.method !== 'run.approve' ||
      response.result.decisionRef !== decisionRef || response.result.snapshot.operation !== 'agent' || response.result.snapshot.schemaVersion !== 1 ||
      response.result.snapshot.latestRunItemSeq !== checkpoint.runItemSeq || response.result.snapshot.run.latestCheckpointId !== checkpointId ||
      response.result.snapshot.run.specRef !== run.specRef || response.result.snapshot.run.sessionId !== run.sessionId ||
      (decision.decision === 'allow' && response.result.snapshot.run.frontierRef !== proof.wait.frontierRef) ||
      response.result.snapshot.run.id !== run.id || response.result.snapshot.run.revision !== decision.expectedRunRevision + 1 ||
      response.result.snapshot.run.updatedAt !== decision.createdAt || response.result.snapshot.run.status !== 'queued' ||
      response.result.snapshot.run.waitingOnRef !== undefined || response.result.snapshot.run.activeWorkerLaunchId !== undefined) {
    throw new TypeError('approval response substitutes its committed decision or Run snapshot');
  }
  return { ...proof, decision, grant, response };
}
