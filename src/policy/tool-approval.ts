import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, assertRequestId, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ToolApprovalDecisionV1, ToolApprovalWait } from '../kernel/tool-authorization.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Wire intent excludes the authenticated channel, so a fresh connection can replay the same request. */
export type ToolApprovalInput = {
  principalId: string; channelIdentityRef: string; channelIdentityDigest: string;
  requestId: string; expectedRunRevision: number; waitingOnRef: string; decision: 'allow' | 'deny'; ttlMs?: number;
};

export function toolApprovalRequestDigest(runId: string, input: ToolApprovalInput): string {
  assertRequestId(input.requestId);
  assertArtifactRef(input.waitingOnRef);
  if (!Number.isSafeInteger(input.expectedRunRevision) || input.expectedRunRevision < 1 ||
      !['allow', 'deny'].includes(input.decision) || (input.ttlMs !== undefined &&
        (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1 || input.ttlMs > 86_400_000))) {
    throw new TypeError('invalid run.approve revision, decision or bounded TTL');
  }
  return canonicalSha256({ protocolVersion: 1, method: 'run.approve', runId, requestId: input.requestId,
    expectedRevision: input.expectedRunRevision, waitingOnRef: input.waitingOnRef, decision: input.decision,
    ...(input.ttlMs === undefined ? {} : { ttlMs: input.ttlMs }) });
}

export const toolApprovalCheckpointId = (waitingOnRef: string) => identityHash('cliq-tool-approval-checkpoint-v1', waitingOnRef);

/** Deterministic retained decision; authenticating its channel and committing its control row are State's job. */
export function toolApprovalDecision(wait: ToolApprovalWait, input: ToolApprovalInput, createdAt: string, deadlineAt: string): ToolApprovalDecisionV1 {
  const requestDigest = toolApprovalRequestDigest(wait.runId, input);
  assertArtifactRef(input.channelIdentityRef);
  assertArtifactRef(input.channelIdentityDigest);
  const now = parseCanonicalTime(createdAt), deadline = parseCanonicalTime(deadlineAt);
  if (input.waitingOnRef !== canonicalSha256(wait) || input.expectedRunRevision !== wait.createdFromRevision + 1 ||
      now < parseCanonicalTime(wait.createdAt) || now >= deadline) throw new TypeError('approval decision does not match its current wait or lifetime');
  const core = { schemaVersion: 1 as const, format: 'cliq-approval-decision-v1' as const,
    decisionId: identityHash(input.principalId, wait.runId, input.waitingOnRef, input.requestId, requestDigest),
    principalId: input.principalId, channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest,
    runId: wait.runId, waitingSubjectRef: input.waitingOnRef, waitingSubjectDigest: canonicalSha256(wait), frontierRef: wait.frontierRef,
    subject: wait.subject, subjectDigest: canonicalSha256(wait.subject), requestId: input.requestId, requestDigest,
    expectedRunRevision: input.expectedRunRevision, decision: input.decision,
    ...(input.ttlMs === undefined ? {} : { requestedTtlMs: input.ttlMs }),
    ...(input.decision === 'deny' ? {} : { grantExpiresAt: new Date(Math.min(now + (input.ttlMs ?? 3_600_000), deadline)).toISOString() }), createdAt };
  return immutableSnapshot({ ...core, decisionDigest: canonicalSha256(core) });
}
