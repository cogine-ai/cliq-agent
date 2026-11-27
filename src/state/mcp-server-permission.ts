// Original named launch permission/history. The fixed policy evaluator and
// exact committed approval own the decision; no decoded receipt grants exec.
import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { decodeInstalledControlResponse } from '../kernel/control-wire.js';
import { decodeMcpServerApprovalDecision, decodeMcpServerApprovalWait, decodeMcpServerOperationGrant,
  decodeMcpServerPolicyChannelEvidence, decodeMcpServerPolicyDecisionItem, type McpServerOperationGrantV1,
  type McpServerPolicyChannelEvidenceV1, type McpServerPolicyDecisionItem, type McpServerApprovalDecisionV1,
  type McpServerLaunchRequestV1, type McpServerLaunchTargetV1 } from '../kernel/mcp-server-authorization.js';
import type { Run, RunSpec, RunFrontier, ContinuationItem } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { validateContextItems } from '../runtime/context-compaction.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeContextManifest } from './decoders.js';
import { KernelStorageError } from './errors.js';
import type { loadMcpServerPolicy } from './mcp-server-policy.js';
import { readCheckpoint, readControlRequest } from './rows.js';
import { readInvocationJournal } from './repositories/journal.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';

export type McpServerPermissionContext = Readonly<{ run: Run; spec: RunSpec; request: McpServerLaunchRequestV1;
  target: McpServerLaunchTargetV1; evaluator: ReturnType<typeof loadMcpServerPolicy> }>;
export const mcpServerApprovalCheckpointId = (ref: string) => identityHash('cliq-mcp-server-approval-checkpoint-v1', ref);
export const mcpServerDecisionCheckpointId = (ref: string) => identityHash('cliq-mcp-server-decision-checkpoint-v1', ref);
export function mcpServerPolicyItem(evidence: McpServerPolicyChannelEvidenceV1,
  disposition: { grant: McpServerOperationGrantV1 } | { outcomeItemRef: string }, approval?: McpServerApprovalDecisionV1): McpServerPolicyDecisionItem {
  const decisionRef = approval ? canonicalSha256(approval) : canonicalSha256(evidence), createdAt = approval?.createdAt ?? evidence.evaluatedAt;
  const core = { schemaVersion: 1 as const, itemId: identityHash('cliq-mcp-server-policy-item-v1', evidence.runId, evidence.opId, decisionRef),
    runId: evidence.runId, kind: 'policy_decision' as const, subjectKind: 'mcp_server_launch' as const, opId: evidence.opId,
    principalId: evidence.principalId, decisionRef, policyChannelEvidenceRef: canonicalSha256(evidence),
    policyChannelEvidenceDigest: evidence.evidenceDigest, createdAt,
    ...(approval ? { decisionSource: 'interactive_approval' as const, waitingSubjectRef: approval.waitingSubjectRef }
      : { decisionSource: 'direct_policy' as const }) };
  return decodeMcpServerPolicyDecisionItem('grant' in disposition ? { ...core, decision: 'allow', grantRef: canonicalSha256(disposition.grant) }
    : { ...core, decision: 'deny', denialOutcome: { kind: 'tool_result_denied', subjectKind: 'mcp_server_launch', outcomeItemRef: disposition.outcomeItemRef } });
}
async function checkpointContext(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string, checkpoint: ReturnType<typeof readCheckpoint>) {
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const rows = driver.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? AND item_seq<=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(runId, BigInt(checkpoint.runItemSeq));
  const items = await artifacts.mapReads(rows, async row => ({ itemSeq: Number(row.item_seq), itemRef: row.payload_ref,
    item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payload_ref) }));
  validateContextItems(context, items);
  if (context.runId !== runId || context.throughItemSeq !== checkpoint.runItemSeq) throw new TypeError('MCP launch permission checkpoint loses its complete context');
  return { context, items, rows };
}
export async function readMcpServerApprovalWait(driver: SqliteDriver, artifacts: ArtifactCatalog, context: McpServerPermissionContext, reference: string) {
  const wait = decodeMcpServerApprovalWait(await readCanonicalArtifact(artifacts, reference));
  const evidence = decodeMcpServerPolicyChannelEvidence(await readCanonicalArtifact(artifacts, wait.subject.policyChannelEvidenceRef));
  requireEqual(wait, context.evaluator.approvalWait(evidence, wait.createdFromRevision), 'MCP server original exact asking wait');
  requireEqual(await readCanonicalArtifact(artifacts, evidence.requestRef), context.request, 'MCP server original waiting request');
  requireEqual(await readCanonicalArtifact(artifacts, evidence.targetRef), context.target, 'MCP server original waiting target');
  const checkpoint = readCheckpoint(driver, mcpServerApprovalCheckpointId(reference));
  const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, wait.frontierRef);
  if (canonicalSha256(wait) !== reference || wait.runId !== context.run.id || wait.createdAt < context.run.createdAt || wait.createdAt >= context.run.deadlineAt ||
      checkpoint.runId !== context.run.id || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== wait.createdFromRevision || checkpoint.createdAt < wait.createdAt ||
      frontier.kind !== 'tool' || frontier.batchItemId !== context.request.batchItemId || frontier.nextCallIndex !== context.request.callIndex ||
      frontier.orderedCallIds[frontier.nextCallIndex] !== context.request.callId) throw new TypeError('MCP launch wait loses its exact ready call/checkpoint');
  const material = await checkpointContext(driver, artifacts, context.run.id, checkpoint);
  const batch = material.items.find(row => row.item.itemId === context.request.batchItemId)?.item;
  if (batch?.kind !== 'assistant_tool_batch' || batch.calls[context.request.callIndex]?.callId !== context.request.callId)
    throw new TypeError('MCP launch wait changes its immutable originating batch');
  const journal = readInvocationJournal(driver, context.run.id);
  if (checkpoint.journalSeq > journal.length || journal.slice(0, checkpoint.journalSeq).some(entry =>
    entry.opKind === 'mcp-server' && entry.opId === context.request.opId && entry.phase === 'dispatch_claimed' &&
    !journal.slice(0, checkpoint.journalSeq).some(last => last.opId === entry.opId && last.attempt === entry.attempt && ['completed', 'failed'].includes(last.phase))))
    throw new TypeError('MCP launch approval cannot overtake its unretired prior server');
  return { wait, evidence, checkpoint, ...material };
}
export async function readMcpServerApproval(driver: SqliteDriver, artifacts: ArtifactCatalog, context: McpServerPermissionContext, reference: string) {
  const decision = decodeMcpServerApprovalDecision(await readCanonicalArtifact(artifacts, reference));
  const original = await readMcpServerApprovalWait(driver, artifacts, context, decision.waitingSubjectRef);
  const grant = context.evaluator.approve(original.evidence, original.wait, decision, context.run.deadlineAt);
  const control = readControlRequest(driver, decision.principalId, 'run.approve', decision.requestId);
  if (reference !== canonicalSha256(decision) || !control || control.requestDigest !== decision.requestDigest || control.channelIdentityRef !== decision.channelIdentityRef ||
      control.channelIdentityDigest !== decision.channelIdentityDigest || control.committedAt !== decision.createdAt)
    throw new TypeError('MCP launch approval loses its exact original authenticated control row');
  const channel = await readHistoricalControlChannel(driver, artifacts, decision);
  const latestOwner = readLatestStateOwner(driver);
  if (!latestOwner) throw new TypeError('MCP launch approval lost its retained StateOwner history');
  const history = await readRetainedStateOwnerHistory(driver, artifacts, latestOwner.ownerEpoch);
  const responding = history.entries.filter(entry => entry.owner.acquiredAt <= decision.createdAt &&
    (entry.owner.state !== 'terminal' || decision.createdAt <= entry.owner.releasedAt));
  if (responding.length !== 1 || channel.channel.openedAt < responding[0]!.owner.acquiredAt || channel.channel.openedAt > decision.createdAt)
    throw new TypeError('MCP launch approval is outside its actual original authenticated owner/channel interval');
  const request = { protocolVersion: 1 as const, method: 'run.approve' as const, runId: context.run.id, requestId: decision.requestId,
    requestDigest: decision.requestDigest, expectedRevision: decision.expectedRunRevision, waitingOnRef: decision.waitingSubjectRef,
    decision: decision.decision, ...(decision.requestedTtlMs === undefined ? {} : { ttlMs: decision.requestedTtlMs }) };
  const { requestDigest: _digest, ...requestCore } = request;
  requireEqual(await readCanonicalArtifact(artifacts, control.requestDigest), requestCore, 'MCP launch original approval request');
  const response = decodeInstalledControlResponse(await readCanonicalArtifact(artifacts, control.responseRef), request);
  if (!response.ok || response.result.method !== 'run.approve') throw new TypeError('MCP launch approval lacks its accepted original response');
  const checkpoint = readCheckpoint(driver, mcpServerDecisionCheckpointId(reference)), material = await checkpointContext(driver, artifacts, context.run.id, checkpoint);
  const policyItems = material.items.filter(row => row.item.kind === 'policy_decision' && row.item.subjectKind === 'mcp_server_launch' && row.item.decisionRef === reference);
  if (policyItems.length !== 1) throw new TypeError('MCP launch approval lacks its unique exact committed policy item');
  const item = decodeMcpServerPolicyDecisionItem(policyItems[0]!.item);
  const denied = !grant && item.decision === 'deny' ? item.denialOutcome.outcomeItemRef : undefined;
  requireEqual(item, mcpServerPolicyItem(original.evidence, grant ? { grant } : { outcomeItemRef: denied! }, decision), 'MCP launch exact interactive policy item');
  const snapshot = response.result.snapshot;
  const immutableRun = (value: Run) => ({ id: value.id, sessionId: value.sessionId, specRef: value.specRef, createdAt: value.createdAt, deadlineAt: value.deadlineAt });
  requireEqual(immutableRun(snapshot.run), immutableRun(context.run), 'MCP launch approval immutable Run');
  if (snapshot.operation !== 'agent' || snapshot.run.revision !== decision.expectedRunRevision + 1 || snapshot.run.latestCheckpointId !== checkpoint.id ||
      snapshot.run.updatedAt !== decision.createdAt || snapshot.run.status !== 'queued' || snapshot.run.activeWorkerLaunchId || snapshot.run.waitingOnRef || snapshot.run.waitingReason ||
      checkpoint.runId !== context.run.id || checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== decision.expectedRunRevision || checkpoint.createdAt !== decision.createdAt ||
      checkpoint.workspaceStateRef !== original.checkpoint.workspaceStateRef || checkpoint.journalSeq !== original.checkpoint.journalSeq ||
      checkpoint.runItemSeq !== original.checkpoint.runItemSeq + (grant ? 1 : 2) || snapshot.latestRunItemSeq !== checkpoint.runItemSeq ||
      policyItems[0]!.itemSeq !== original.checkpoint.runItemSeq + 1 || grant && snapshot.run.frontierRef !== original.wait.frontierRef)
    throw new TypeError('MCP server approval response changes its exact atomic checkpoint');
  if (!grant) {
    const result = material.items.find(row => row.itemSeq === checkpoint.runItemSeq);
    if (result?.item.kind !== 'tool_result' || result.item.outcome !== 'denied' || result.item.batchItemId !== context.request.batchItemId ||
        result.item.callId !== context.request.callId || result.item.index !== context.request.callIndex || result.itemRef !== denied)
      throw new TypeError('MCP server denial lacks its exact originating denied tool result');
  }
  function assertUnchanged(connection: SqliteConnection) {
    history.assertUnchanged(connection);
    requireEqual(readControlRequest(connection, decision.principalId, 'run.approve', decision.requestId), control, 'MCP launch original approval registration');
    requireEqual(readCheckpoint(connection, checkpoint.id), checkpoint, 'MCP launch exact decision checkpoint');
    requireEqual(readCheckpoint(connection, original.checkpoint.id), original.checkpoint, 'MCP launch exact waiting checkpoint');
  }
  assertUnchanged(driver); return { ...original, decision, grant, control, response, checkpoint, item, assertUnchanged };
}
export async function readMcpServerGrant(driver: SqliteDriver, artifacts: ArtifactCatalog, context: McpServerPermissionContext, reference: string) {
  const grant = decodeMcpServerOperationGrant(await readCanonicalArtifact(artifacts, reference));
  const evidence = decodeMcpServerPolicyChannelEvidence(await readCanonicalArtifact(artifacts, grant.provenance.channelEvidenceRef));
  const approved = grant.provenance.kind === 'user_approval' ? await readMcpServerApproval(driver, artifacts, context, grant.provenance.decisionRef) : undefined;
  requireEqual(grant, approved ? approved.grant : context.evaluator.grant(evidence, grant.issuedAt, grant.expiresAt), 'MCP server original complete grant');
  if (canonicalSha256(grant) !== reference || grant.runId !== context.run.id || grant.issuedAt < context.run.createdAt || grant.expiresAt > context.run.deadlineAt ||
      grant.maxLaunches !== context.target.maxLaunches || grant.subject.lifecycleSeq !== context.request.lifecycleSeq)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'MCP server grant exceeds its exact original call/lifecycle/Run lifetime');
  return { grant, evidence, approval: approved, assertUnchanged(connection: SqliteConnection) { approved?.assertUnchanged(connection); } };
}
