// The sole exception to ordinary MCP result capture is a signed read-only
// status resolution of the same fully charged UNKNOWN. No old payload or
// positive no-release failure is manufactured by this retained reader.
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import { decodeMcpReconciledEffectResult } from '../kernel/mcp-status.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, ToolResultPayloadV1, ToolResultModelContentV1 } from '../kernel/types.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { readMcpStatusProbeEvidence, readMcpStatusWaitHistory, type McpStatusHistoryCut } from './mcp-status-history.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { toolCheckpointId } from './tool-checkpoint.js';
import { ZERO_BUDGET } from './rows.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
export async function readMcpReconciledEffectHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: McpStatusHistoryCut,
  prepared: InvocationJournalEntry, terminal: InvocationJournalEntry) {
  const entries = cut.journal.filter(entry => entry.opId === prepared.opId && entry.attempt === prepared.attempt), claim = entries[1], unknown = entries[2];
  if (prepared.opKind !== 'mcp' || prepared.replayClass !== 'reconcile' || entries.length !== 4 || entries[0]?.phase !== 'prepared' ||
      claim?.phase !== 'dispatch_claimed' || unknown?.phase !== 'unknown' || entries[3]?.seq !== terminal.seq ||
      !['completed', 'failed'].includes(terminal.phase) || !unknown.budgetSettlementRef || terminal.budgetSettlementRef !== unknown.budgetSettlementRef ||
      entries.some(entry => entry.opKind !== 'mcp' || entry.replayClass !== 'reconcile'))
    fail('MCP status resolution lacks its sole original claim, full-once UNKNOWN and one zero-charge terminal row');
  for (const row of [claim, unknown, terminal]) for (const key of ['runId', 'opId', 'attempt', 'leaseEpoch', 'requestRef', 'target', 'grantRef', 'idempotencyKey'] as const)
    requireEqual(row[key] ?? null, prepared[key] ?? null, 'MCP signed status original immutable effect identity');
  for (const key of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest'] as const)
    requireEqual(terminal[key] ?? null, claim[key] ?? null, 'MCP signed status original claimed authority');
  requireEqual(terminal.budgetDelta, ZERO_BUDGET, 'MCP signed status cannot consume or refund the original settlement twice');
  const reference = terminal.phase === 'completed' ? terminal.resultRef : terminal.errorRef;
  if (!reference || terminal.phase === 'completed' && terminal.errorRef || terminal.phase === 'failed' && terminal.resultRef)
    fail('MCP signed status terminal changed its precise result/error branch');
  const result = decodeMcpReconciledEffectResult(await readCanonicalArtifact(artifacts, reference));
  if (result.runId !== cut.run.id || result.opId !== prepared.opId || result.attempt !== prepared.attempt || result.originalDispatchId !== claim.dispatchId ||
      result.unknownJournalSeq !== unknown.seq || result.budgetSettlementRef !== unknown.budgetSettlementRef || result.disposition !== terminal.phase ||
      result.observedAt < unknown.timestamp || result.observedAt > terminal.timestamp)
    fail('MCP signed status result changed its original UNKNOWN, actual disposition or observation time');
  const wrapper = (await import('./mcp-status-proof.js')).decodeMcpStatusProbeWrapper(await readCanonicalArtifact(artifacts, result.probeEvidenceRef));
  if (wrapper.outcome !== 'subject_observation' || wrapper.subjectEvidenceKind !== 'mcp_recovery') fail('MCP signed resolution cannot use a timeout, cancellation or late audit');
  const wait = (await import('../kernel/mcp-status.js')).decodeMcpInvocationWait(await readCanonicalArtifact(artifacts, wrapper.waitingSubjectRef));
  const { source } = await readMcpStatusWaitHistory(driver, artifacts, cut, wait);
  const proof = await readMcpStatusProbeEvidence(driver, artifacts, source, result.probeEvidenceRef, result.probeEvidenceDigest);
  if (!proof.evidence || proof.evidence.disposition !== result.disposition || proof.evidence.observedAt !== result.observedAt ||
      terminal.timestamp >= proof.wrapper.probeDeadlineAt)
    fail('MCP signed status resolution lacks a complete original authoritative observation before its exact deadline');
  if (terminal.phase === 'completed') {
    requireEqual(terminal.evidenceRef, claim.evidenceRef, 'MCP completed status retains its original server instance identity');
    requireEqual(terminal.evidenceDigest, claim.evidenceDigest, 'MCP completed status retains its original instance digest');
  } else if (terminal.evidenceRef !== result.probeEvidenceRef || terminal.evidenceDigest !== result.probeEvidenceDigest)
    fail('MCP failed status must retain its genuine signed effect failure proof');
  return { result, reference, source, proof, prepared, claim, unknown, terminal };
}

export async function validateMcpReconciledToolResult(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: McpStatusHistoryCut,
  prepared: InvocationJournalEntry, terminal: InvocationJournalEntry, items: Map<string, ContinuationItem>, checkpoints: readonly Checkpoint[]) {
  const history = await readMcpReconciledEffectHistory(driver, artifacts, cut, prepared, terminal), { result, reference, source } = history;
  const request = source.original.request;
  const matches = [...items.values()].filter(item => item.kind === 'tool_result' && item.opId === prepared.opId), item = matches[0];
  if (matches.length !== 1 || item?.kind !== 'tool_result' || item.outcome !== 'error' || item.runId !== cut.run.id ||
      item.itemId !== identityHash('cliq-tool-result-item-v1', cut.run.id, request.batchItemId, request.callId) ||
      item.batchItemId !== request.batchItemId || item.callId !== request.callId || item.index !== request.callIndex ||
      item.createdAt < result.observedAt || item.createdAt > terminal.timestamp)
    fail('MCP signed status has no one exact ordered local result with a truthful unavailable original response');
  const payload = await readCanonicalArtifact<ToolResultPayloadV1>(artifacts, item.resultRef);
  if (payload.outcome !== 'error' || !exactKeys(payload, ['schemaVersion', 'format', 'runId', 'batchItemId', 'callId', 'index', 'toolName',
    'modelContentRef', 'modelContentDigest', 'outcome', 'code', 'opId', 'attempt', 'diagnosticRef', 'diagnosticDigest', 'payloadDigest',
    ...(result.disposition === 'failed' ? ['journalErrorRef', 'journalErrorDigest'] : [])]) || payload.schemaVersion !== 1 ||
      payload.format !== 'cliq-tool-result-payload-v1' || payload.payloadDigest !== digestOmitting(payload, 'payloadDigest') ||
      payload.runId !== cut.run.id || payload.batchItemId !== request.batchItemId || payload.callId !== request.callId || payload.index !== request.callIndex ||
      payload.toolName !== request.toolName || payload.opId !== prepared.opId || payload.attempt !== prepared.attempt || payload.code !== result.code ||
      payload.diagnosticRef !== reference || payload.diagnosticDigest !== result.resultDigest ||
      (result.disposition === 'failed' ? payload.journalErrorRef !== reference || payload.journalErrorDigest !== result.resultDigest :
        payload.journalErrorRef !== undefined || payload.journalErrorDigest !== undefined))
    fail('MCP signed status local payload changed the real Journal outcome or invented the original effect response');
  const model = await readCanonicalArtifact<ToolResultModelContentV1>(artifacts, payload.modelContentRef);
  if (!exactKeys(model, ['schemaVersion', 'format', 'callId', 'index', 'toolName', 'outcome', 'content', 'contentDigest']) || model.schemaVersion !== 1 ||
      model.format !== 'cliq-tool-result-model-content-v1' || model.contentDigest !== digestOmitting(model, 'contentDigest') || model.contentDigest !== payload.modelContentDigest ||
      model.callId !== request.callId || model.index !== request.callIndex || model.toolName !== request.toolName || model.outcome !== 'error')
    fail('MCP status model-safe unavailable-result projection lost its exact source');
  requireEqual(model.content, { code: result.code, effect: result.effect, originalResponse: 'unavailable' }, 'MCP signed status truthful effect/result distinction');
  const checkpoint = checkpoints.find(value => value.id === toolCheckpointId(cut.run.id, prepared.opId, prepared.attempt));
  const itemSeq = [...items.keys()].indexOf(item.itemId) + 1;
  if (!checkpoint || checkpoint.runId !== cut.run.id || checkpoint.journalSeq !== terminal.seq || checkpoint.runItemSeq !== itemSeq ||
      checkpoint.createdAt < terminal.timestamp)
    fail('MCP signed status result has no same-transaction original ready Checkpoint');
  const before = checkpoints.filter(value => value.runId === cut.run.id && value.id !== checkpoint.id && value.createdAt <= history.proof.wait.createdAt &&
    value.basedOnRunRevision <= history.proof.wait.createdFromRevision && value.journalSeq === source.original.stdioClosed!.terminal.seq);
  if (!before.length || before.some(value => value.workspaceStateRef !== checkpoint.workspaceStateRef))
    fail('MCP read-only status cannot replace the original ready workspace with an unobserved effect snapshot');
  return history;
}
