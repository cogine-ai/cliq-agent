import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ControlApplicationResponseV1, ControlResultV1, ContinuationItem, RecoveryClosureV1, Run, RunAssemblyV1, SessionRunTerminalItem, TerminalDetail } from '../kernel/types.js';
import { cancelledCall, agentStopDetail, decodeAgentStop, openStopBatch, stopCheckpointId, stopInvocationHistory } from '../runtime/stop.js';
import { toolOperationId } from '../policy/tool-policy.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeAdmittedContext, decodeSessionProjection } from './decoders.js';
import { joinResourceOperations } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { readCheckpoint, readControlRequest, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readResourceStopCause } from './resource-stop.js';
import { validateModelFailureStop } from './model-failure.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { validateInstalledBrokerTerminalHistory } from './broker-ambiguity.js';
import { validateInstalledModelNoReleaseHistory } from './broker-no-release.js';
import { validatePrivateToolRollbackHistory } from './private-tool-rollback.js';
import { readVerifierFailureCause, readVerifierIntegrityCause, readVerifierPolicyDenial, validateVerifierStoppedHistory } from './verifier-stop-history.js';
import type { VerifierPolicyDecisionItem } from '../kernel/verifier-invocation.js';
import type { VerifierRecoveryCut } from './verifier-recovery.js';

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
  const { channel } = await readHistoricalControlChannel(driver, artifacts,
    { channelIdentityRef: row.channelIdentityRef, channelIdentityDigest: row.channelIdentityDigest, principalId });
  if (channel.openedAt > row.committedAt ||
      readSessionPrincipalId(driver, run.sessionId) !== principalId ||
      driver.prepare('SELECT principal_id FROM runs WHERE id = ?').get<{ principal_id: string }>(run.id)?.principal_id !== principalId) throw new TypeError('cancellation control channel has a foreign owner');
  const stop = decodeAgentStop(await readCanonicalArtifact(artifacts, snapshot.run.stopIntentRef!), snapshot.run);
  // A later cancellation still installs its monotonic fence when an already
  // proven integrity stop wins. This response is control ownership, not proof
  // of the integrity cause (the full recovery walk checks that separately).
  if (!(stop.origin === 'user_cancel' && stop.principalId === principalId || stop.origin === 'kernel_integrity'))
    throw new TypeError('cancellation snapshot has no owning StopIntent');
  return { response, row };
}

export async function readAgentStop(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1) {
  const { run } = closure;
  const intent = decodeAgentStop(await readCanonicalArtifact(artifacts, run.stopIntentRef!), run);
  if (intent.origin === 'user_cancel') {
    if (!run.cancelRequested) throw new TypeError('cancellation lost its monotonic dispatch fence');
    const { response, row } = await readCancelResponse(driver, artifacts, run, intent.principalId, intent.requestId);
    if (response.result.snapshot.run.stopIntentRef !== run.stopIntentRef || row.committedAt !== intent.createdAt) throw new TypeError('winning cancellation has no exact control-row owner');
  } else if (run.cancelRequested) {
    if (intent.origin !== 'kernel_integrity') throw new TypeError('resource/deadline stop cannot override user cancellation');
    const principalId = readSessionPrincipalId(driver, run.sessionId);
    let owned = false;
    for (const row of driver.prepare("SELECT request_id, response_ref FROM control_requests WHERE principal_id = ? AND method = 'run.cancel'")
      .all<{ request_id: string; response_ref: string }>(principalId)) {
      const response = await readCanonicalArtifact<CancelResponse>(artifacts, row.response_ref);
      if (response.result?.snapshot?.run.id !== run.id) continue;
      await readCancelResponse(driver, artifacts, run, principalId, row.request_id); owned = true;
    }
    if (!owned) throw new TypeError('integrity stop lost the original monotonic cancellation owner');
  }
  if (intent.origin === 'runtime' && intent.runtimeSubtype === 'runtime') {
    await validateModelFailureStop(driver, artifacts, closure, intent);
  } else if (intent.origin === 'budget' || intent.origin === 'runtime') {
    const cause = await readResourceStopCause(driver, artifacts, closure, intent.createdAt);
    if (!cause) throw new TypeError('resource stop has no reproducible failure');
    requireEqual(intent, { schemaVersion: 1, runId: run.id, createdAt: intent.createdAt, ...cause }, 'resource stop cause');
  } else if (intent.origin === 'verification') {
    const cause = await readVerifierFailureCause(driver, artifacts, closure, intent.createdAt, intent.candidateItemId);
    if (!cause) throw new TypeError('verification stop has no reproducible exhausted required failure');
    requireEqual(intent, cause, 'verification stop cause');
  } else if (intent.origin === 'kernel_integrity') {
    const cause = await readVerifierIntegrityCause(driver, artifacts, closure, intent.createdAt);
    if (!cause) throw new TypeError('verifier integrity stop has no exact typed mutation evidence');
    requireEqual(intent, cause, 'verifier integrity stop cause');
  }
  await validateVerifierPolicyDenialHistory(driver, artifacts, closure);
  await validateVerifierStoppedHistory(driver, artifacts, closure);
  return intent;
}

/** Validate every retained denial, including one superseded by cancellation.
 * Does not load a RecoveryClosure or infer permission from its caller. */
export async function validateVerifierPolicyDenialHistory(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: VerifierRecoveryCut) {
  const { run } = closure;
  const validated = new Set<string>();
  let currentDenialValidated = false;
  for (const itemRow of closure.items) {
    const item = await readCanonicalArtifact<ContinuationItem>(artifacts, itemRow.payloadRef);
    if (item.kind !== 'policy_decision' || item.subjectKind !== 'verifier_launch' || item.decision !== 'deny') continue;
    if (!run.stopIntentRef) throw new TypeError('verifier denial lost its Run stop fence');
    const stopRef = item.denialOutcome.stopIntentRef;
    const intent = decodeAgentStop(await readCanonicalArtifact(artifacts, stopRef), run);
    if (intent.origin !== 'policy_deny') throw new TypeError('verifier denial does not name its original policy stop');
    const cause = await readVerifierPolicyDenial(driver, artifacts, closure, intent.createdAt, intent.opId);
    if (!cause || canonicalSha256(cause.evidence) !== intent.policyChannelEvidenceRef || cause.evidence.evidenceDigest !== intent.policyChannelEvidenceDigest)
      throw new TypeError('verifier policy denial has no exact reproduced named-action decision');
    requireEqual(await readCanonicalArtifact(artifacts, intent.policyChannelEvidenceRef), cause.evidence, 'retained verifier denial evidence');
    requireEqual(await readCanonicalArtifact(artifacts, cause.evidence.requestRef), cause.planned.request, 'retained verifier denied request');
    requireEqual(await readCanonicalArtifact(artifacts, cause.evidence.targetRef), cause.planned.target, 'retained verifier denied target');
    const expected: VerifierPolicyDecisionItem = { schemaVersion: 1, kind: 'policy_decision', subjectKind: 'verifier_launch',
      itemId: identityHash('cliq-verifier-policy-item-v1', run.id, intent.opId, intent.policyChannelEvidenceRef), runId: run.id,
      opId: intent.opId, principalId: cause.principalId, decisionRef: intent.policyChannelEvidenceRef,
      policyChannelEvidenceRef: intent.policyChannelEvidenceRef, policyChannelEvidenceDigest: intent.policyChannelEvidenceDigest,
      createdAt: intent.createdAt, decisionSource: 'direct_policy', decision: 'deny',
      denialOutcome: { kind: 'stop_intent', subjectKind: 'verifier_launch', stopIntentRef: stopRef } };
    const rows = closure.items.filter(row => row.itemId === expected.itemId);
    if (rows.length !== 1 || rows[0]!.createdAt !== intent.createdAt) throw new TypeError('verifier denial has no unique original policy item');
    requireEqual(await readCanonicalArtifact(artifacts, rows[0]!.payloadRef), expected, 'verifier denied policy item');
    const checkpoint = readCheckpoint(driver, identityHash('cliq-verifier-denial-checkpoint-v1', run.id, intent.opId, intent.policyChannelEvidenceRef));
    if (checkpoint.runId !== run.id || checkpoint.runItemSeq !== rows[0]!.itemSeq || checkpoint.createdAt !== intent.createdAt ||
        checkpoint.journalSeq > closure.journal.length || closure.journal.some(entry => entry.opId === intent.opId))
      throw new TypeError('verifier denied policy item has no exact undispatched atomic Checkpoint');
    if (closure.journal.some(entry => entry.seq > checkpoint.journalSeq && entry.phase === 'prepared'))
      throw new TypeError('verifier policy denial was followed by a productive preparation');
    if (stopRef === run.stopIntentRef) currentDenialValidated = true;
    validated.add(item.itemId);
  }
  if (run.stopIntentRef && decodeAgentStop(await readCanonicalArtifact(artifacts, run.stopIntentRef), run).origin === 'policy_deny' && !currentDenialValidated)
    throw new TypeError('verifier policy denial lacks its original policy decision');
  return validated;
}

export async function validateStopRecovery(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1) {
  const { run, runSpec: spec, latestCheckpoint: checkpoint, journal } = closure;
  const terminal = run.status === 'failed' || run.status === 'cancelled';
  if (!run.stopIntentRef) {
    if (terminal) throw new TypeError('terminal stop has no winning StopIntent');
    return;
  }
  const intent = await readAgentStop(driver, artifacts, closure);
  if (!terminal) {
    if (!['queued', 'running', 'waiting'].includes(run.status) || run.terminalReason || run.terminalDetailRef || run.resultRef) throw new TypeError('nonterminal stop has terminal fields');
    return;
  }
  if (spec.operation !== 'agent' || run.parentRunId || closure.childAllocations.length || !isZeroBudget(run.budgetReserved) ||
      run.status !== intent.targetStatus || run.terminalReason !== intent.reason || !run.terminalDetailRef || run.resultRef ||
      run.nextStep !== null || run.frontierRef || run.activeWorkerLaunchId || run.waitingOnRef || run.waitingReason ||
      closure.workerLaunches.some((launch) => launch.phase !== 'retired') ||
      closure.workspaceGenerations.some((generation) => generation.phase !== 'sealed' && generation.phase !== 'retired') ||
      checkpoint.id !== stopCheckpointId(run.id, run.stopIntentRef) || checkpoint.createdAt !== run.updatedAt ||
      checkpoint.journalSeq !== journal.length || checkpoint.runItemSeq !== closure.items.length) throw new TypeError('terminal stop has an open Run/worker/budget cut');
  const detail = await readCanonicalArtifact<TerminalDetail>(artifacts, run.terminalDetailRef);
  const preparedAt = detail.createdAt;
  parseCanonicalTime(preparedAt);
  if (preparedAt < intent.createdAt || preparedAt > run.updatedAt) throw new TypeError('terminal preparation time is outside its intent and committed Checkpoint');
  const abandoned = await validateInstalledBrokerTerminalHistory(driver, artifacts, closure, detail);
  requireEqual(detail, { ...agentStopDetail(intent, run.stopIntentRef, preparedAt),
    abandonedRetryInvocations: abandoned }, 'terminal reason closure');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  if (assembly.format !== 'cliq-run-assembly-v1' || assembly.mcpServers.length) throw new TypeError('terminal stop lacks its typed containment closure');
  // Common recovery verified every complete seal or retirement/source graph;
  // a phase string alone cannot satisfy this final retained SQL cut.
  assertRetiredGenerationCut(driver, run, closure.workspaceGenerations);
  const modelNoRelease = await validateInstalledModelNoReleaseHistory(driver, artifacts, closure);
  const privateRollbacks = await validatePrivateToolRollbackHistory(driver, artifacts, closure);
  const verifierStops = await validateVerifierStoppedHistory(driver, artifacts, closure);
  for (const { entry, hasClaim } of stopInvocationHistory(journal).values()) {
    if (entry.opKind === 'model' && entry.replayClass === 'retry' && entry.phase === 'unknown' && abandoned.some(closed =>
      closed.opId === entry.opId && closed.attempt === entry.attempt && closed.unknownJournalSeq === entry.seq &&
      closed.budgetSettlementRef === entry.budgetSettlementRef)) continue;
    if (entry.phase === 'failed' && (entry.opKind === 'model' && modelNoRelease.has(entry.seq) ||
        entry.opKind === 'tool' && privateRollbacks.has(entry.seq) || entry.opKind === 'verifier' && verifierStops.has(entry.seq))) continue;
    if (!['model', 'tool', 'verifier'].includes(entry.opKind) || (entry.phase !== 'completed' &&
        (entry.phase !== 'failed' || hasClaim))) throw new TypeError('terminal stop retains unresolved dispatch evidence');
    if (entry.phase === 'failed' && entry.errorRef === run.stopIntentRef && entry.timestamp !== preparedAt) throw new TypeError('stop refund has no atomic terminal owner');
  }
  const items = await joinResourceOperations(closure.items.map((row) => readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef)));
  if (openStopBatch(items)) throw new TypeError('terminal stop retains an unclosed tool batch');
  for (const item of items) if (item.kind === 'tool_result' && item.outcome === 'cancelled') {
    const batch = items.find((candidate) => candidate.kind === 'assistant_tool_batch' && candidate.itemId === item.batchItemId);
    if (batch?.kind !== 'assistant_tool_batch' || item.createdAt !== preparedAt || journal.some((row) =>
        row.opId === toolOperationId(run.id, item.batchItemId, item.callId) && row.phase === 'dispatch_claimed')) throw new TypeError('cancelled result does not prove an undispatched call');
    const plan = cancelledCall(batch, item.index, run.stopIntentRef, preparedAt);
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
