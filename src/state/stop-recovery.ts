import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import type { ControlApplicationResponseV1, ControlResultV1, ContinuationItem, RecoveryClosureV1, Run, RunAssemblyV1, SessionRunTerminalItem } from '../kernel/types.js';
import { cancelledCall, controlStopDetail, decodeControlStop, openStopBatch, stopCheckpointId } from '../runtime/stop.js';
import { toolOperationId } from '../policy/tool-policy.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAdmittedContext, decodeControlChannel, decodeLocalPrincipalIdentity, decodePlatformProcessIdentity, decodeSessionProjection } from './decoders.js';
import { isZeroBudget } from './invariants.js';
import { readControlRequest, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';

export type CancelResponse = Extract<ControlApplicationResponseV1, { ok: true }> & { result: Extract<ControlResultV1, { method: 'run.cancel' }> };

/** Historical control ownership. Live replay must additionally authenticate its newly supplied channel. */
export async function readCancelResponse(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, principalId: string, requestId: string) {
  const row = readControlRequest(driver, principalId, 'run.cancel', requestId);
  if (!row) throw new TypeError('cancellation has no durable control request');
  const response = await readCanonicalArtifact<CancelResponse>(artifacts, row.responseRef);
  const snapshot = response.result?.snapshot;
  if (response.protocolVersion !== 1 || response.ok !== true || response.result.method !== 'run.cancel' ||
      snapshot.schemaVersion !== 1 || snapshot.operation !== 'agent' || snapshot.run.id !== run.id ||
      snapshot.run.sessionId !== run.sessionId || snapshot.run.specRef !== run.specRef || snapshot.run.createdAt !== run.createdAt ||
      snapshot.run.deadlineAt !== run.deadlineAt || snapshot.run.updatedAt !== row.committedAt || !snapshot.run.cancelRequested ||
      !Number.isSafeInteger(snapshot.run.revision) || snapshot.run.revision < 2 || snapshot.run.revision > run.revision ||
      !Number.isSafeInteger(snapshot.latestRunItemSeq) || snapshot.latestRunItemSeq < 0) throw new TypeError('cancellation response substitutes its Run snapshot');
  requireEqual(row.requestDigest, canonicalSha256({ protocolVersion: 1, method: 'run.cancel', requestId, runId: run.id,
    expectedRevision: snapshot.run.revision - 1 }), 'cancel request digest');
  const channel = decodeControlChannel(await readCanonicalArtifact(artifacts, row.channelIdentityRef));
  const principal = decodeLocalPrincipalIdentity(await readCanonicalArtifact(artifacts, channel.principalIdentityRef));
  if (channel.channelIdentityDigest !== row.channelIdentityDigest || channel.principalId !== principalId || principal.principalId !== principalId ||
      principal.identityDigest !== channel.principalIdentityDigest || channel.openedAt > row.committedAt ||
      readSessionPrincipalId(driver, run.sessionId) !== principalId ||
      driver.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(run.id)?.principal_id !== principalId) throw new TypeError('cancellation control channel has a foreign owner');
  if (channel.transport.kind !== 'in_process') throw new TypeError('unsupported retained cancellation transport');
  const process = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, channel.transport.processIdentityRef));
  if (process.identityDigest !== channel.transport.processIdentityDigest || process.ownerUid !== principal.effectiveUid ||
      process.platform !== principal.platform || process.observedAt !== channel.openedAt) throw new TypeError('cancellation channel process identity mismatch');
  const stop = decodeControlStop(await readCanonicalArtifact(artifacts, snapshot.run.stopIntentRef!), snapshot.run);
  if (stop.origin !== 'user_cancel' || stop.principalId !== principalId) throw new TypeError('cancellation snapshot has no owning StopIntent');
  return { response, row };
}

export async function readControlStop(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run) {
  const intent = decodeControlStop(await readCanonicalArtifact(artifacts, run.stopIntentRef!), run);
  if (intent.origin === 'user_cancel') {
    if (!run.cancelRequested) throw new TypeError('cancellation lost its monotonic dispatch fence');
    const { response, row } = await readCancelResponse(driver, artifacts, run, intent.principalId, intent.requestId);
    if (response.result.snapshot.run.stopIntentRef !== run.stopIntentRef || row.committedAt !== intent.createdAt) throw new TypeError('winning cancellation has no exact control-row owner');
  } else if (run.cancelRequested) throw new TypeError('deadline cannot override user cancellation');
  return intent;
}

export async function validateStopRecovery(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1) {
  const { run, runSpec: spec, latestCheckpoint: checkpoint, journal } = closure;
  const terminal = run.status === 'failed' || run.status === 'cancelled';
  if (!run.stopIntentRef) {
    if (terminal) throw new TypeError('terminal stop has no winning StopIntent');
    return;
  }
  const intent = await readControlStop(driver, artifacts, run);
  if (!terminal) {
    if (!['queued', 'running', 'waiting'].includes(run.status) || run.terminalReason || run.terminalDetailRef || run.resultRef) throw new TypeError('nonterminal stop has terminal fields');
    return;
  }
  if (spec.operation !== 'agent' || run.parentRunId || closure.childAllocations.length || !isZeroBudget(run.budgetReserved) ||
      run.status !== intent.targetStatus || run.terminalReason !== intent.reason || !run.terminalDetailRef || run.resultRef ||
      run.nextStep !== null || run.frontierRef || run.activeWorkerLaunchId || run.waitingOnRef || run.waitingReason ||
      closure.workerLaunches.some((launch) => launch.phase !== 'retired') ||
      closure.workspaceGenerations.some((generation) => generation.phase !== 'sealed') ||
      checkpoint.id !== stopCheckpointId(run.id, run.stopIntentRef) || checkpoint.createdAt !== run.updatedAt ||
      checkpoint.journalSeq !== journal.length || checkpoint.runItemSeq !== closure.items.length) throw new TypeError('terminal stop has an open Run/worker/budget cut');
  requireEqual(await readCanonicalArtifact(artifacts, run.terminalDetailRef), controlStopDetail(intent, run.stopIntentRef, run.updatedAt), 'terminal reason closure');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  if (assembly.mcpServers.length) throw new TypeError('terminal stop lacks MCP server containment closure');
  for (const launch of readWorkerLaunchesForRun(driver, run.id)) {
    const generation = closure.workspaceGenerations.find((generation) => generation.generationRef === launch.workspaceGenerationRef);
    if (!generation) throw new TypeError('retired worker has no generation');
    await validateRetainedWorkerSeal(driver, artifacts, { run, spec, assembly, launch, generation });
  }
  const latest = new Map<string, typeof journal[number]>();
  for (const entry of journal) latest.set(`${entry.opId}:${entry.attempt}`, entry);
  for (const entry of latest.values()) {
    const history = journal.filter((row) => row.opId === entry.opId && row.attempt === entry.attempt);
    if (!['model', 'tool'].includes(entry.opKind) || (entry.phase !== 'completed' &&
        (entry.phase !== 'failed' || history.some((row) => row.phase === 'dispatch_claimed')))) throw new TypeError('terminal stop retains unresolved dispatch evidence');
    if (entry.phase === 'failed' && entry.errorRef === run.stopIntentRef && entry.timestamp !== run.updatedAt) throw new TypeError('stop refund has no atomic terminal owner');
  }
  const items = await Promise.all(closure.items.map((row) => readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef)));
  if (openStopBatch(items)) throw new TypeError('terminal stop retains an unclosed tool batch');
  for (const item of items) if (item.kind === 'tool_result' && item.outcome === 'cancelled') {
    const batch = items.find((candidate) => candidate.kind === 'assistant_tool_batch' && candidate.itemId === item.batchItemId);
    if (batch?.kind !== 'assistant_tool_batch' || item.createdAt !== run.updatedAt || journal.some((row) =>
        row.opId === toolOperationId(run.id, item.batchItemId, item.callId) && row.phase === 'dispatch_claimed')) throw new TypeError('cancelled result does not prove an undispatched call');
    const plan = cancelledCall(batch, item.index, run.stopIntentRef, run.updatedAt);
    requireEqual(item, plan.item, 'ordered stop result');
    for (const artifact of plan.artifacts) if (!(await artifacts.readBytes(artifact.ref)).equals(Buffer.from(artifact.bytes))) throw new TypeError('stop result artifact substitution');
  }
  const admitted = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
  const expected: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
    itemKey: `run-terminal:${run.id}`, runId: run.id, operation: 'agent', admittedSessionItemSeq: admitted.throughSessionItemSeq,
    status: run.status, terminalReason: run.terminalReason!, terminalDetailRef: run.terminalDetailRef };
  const itemId = identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id);
  const row = driver.prepare('SELECT session_id, run_id, item_seq, kind, payload_ref, created_at FROM items WHERE item_id = ?')
    .get<{ session_id: string; run_id: string | null; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(itemId);
  if (!row || row.session_id !== run.sessionId || row.run_id !== null || row.kind !== 'run_terminal' || row.created_at !== run.updatedAt ||
      row.payload_ref !== canonicalSha256(expected)) throw new TypeError('terminal Run has no atomic Session item');
  requireEqual(await readCanonicalArtifact(artifacts, row.payload_ref), expected, 'Session terminal payload');
  const session = readSession(driver, run.sessionId);
  const projection = decodeSessionProjection(await readCanonicalArtifact(artifacts, session.contextProjectionRef));
  if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq) throw new TypeError('terminal Session projection differs from its owner');
  const segment = projection.segments.find((segment) => segment.fromItemSeq <= Number(row.item_seq) && segment.throughItemSeq >= Number(row.item_seq));
  if (!segment || segment.kind !== 'raw') throw new TypeError('terminal Session item is absent from its projection');
  requireEqual(segment, { kind: 'raw', fromItemSeq: Number(row.item_seq), throughItemSeq: Number(row.item_seq),
    items: [{ sourceSessionId: session.id, itemSeq: Number(row.item_seq), itemId, kind: 'run_terminal', payloadRef: row.payload_ref }] }, 'one-item Session terminal segment');
}
