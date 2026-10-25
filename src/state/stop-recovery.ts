import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { ControlApplicationResponseV1, ControlResultV1, ContinuationItem, RecoveryClosureV1, Run, RunAssemblyV1, SessionRunTerminalItem, TerminalDetail } from '../kernel/types.js';
import { cancelledCall, agentStopDetail, decodeAgentStop, openStopBatch, selectAgentStop, stopCheckpointId, stopInvocationHistory, type AgentStopIntent } from '../runtime/stop.js';
import { toolOperationId } from '../policy/tool-policy.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeAdmittedContext, decodeRunSpec, decodeSessionProjection } from './decoders.js';
import { isZeroBudget } from './invariants.js';
import { readCheckpoint, readControlRequest, readSession, readSessionPrincipalId } from './rows.js';
import { assertSessionTerminalProjection } from './session-context.js';
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
import { assertDeliveryModelFreeCut } from './run-model-free.js';
import { readDeliveryMergeConflictCause } from './delivery-recovery.js';
import { readDeliveryPolicyDenial } from './delivery-approval.js';
import { readDeliveryTerminalProjection, readUnclaimedPublicationStopHistory } from './delivery-publication-recovery.js';
import type { DeliveryReadData } from './delivery-read-data.js';
import { validateVerifierUnknownTerminalHistory } from './verifier-unknown-retirement.js';

export type CancelResponse = Extract<ControlApplicationResponseV1, { ok: true }> & { result: Extract<ControlResultV1, { method: 'run.cancel' }> };

/** Historical control ownership. Live replay must additionally authenticate its newly supplied channel. */
export async function readCancelResponse(driver: SqliteDriver, artifacts: ArtifactCatalog, run: Run, principalId: string, requestId: string) {
  const row = readControlRequest(driver, principalId, 'run.cancel', requestId);
  if (!row) throw new TypeError('cancellation has no durable control request');
  const response = await readCanonicalArtifact<CancelResponse>(artifacts, row.responseRef);
  const spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const snapshot = response.result?.snapshot;
  if (response.protocolVersion !== 1 || response.ok !== true || response.result.method !== 'run.cancel' ||
      snapshot.schemaVersion !== 1 || snapshot.operation !== spec.operation || snapshot.run.id !== run.id ||
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
  return readStopReference(driver, artifacts, closure, closure.run.stopIntentRef!, true);
}

export async function readAgentStopInDeliveryEpoch(driver: SqliteDriver, artifacts: ArtifactCatalog,
  closure: RecoveryClosureV1, data: DeliveryReadData) {
  return readStopReference(driver, artifacts, closure, closure.run.stopIntentRef!, true, data);
}

/** An explicit historical edge in the actual retained graph. The original
 * Stop is validated without replacing the Run/current cut with a fabricated
 * snapshot, then must remain the winner or a valid monotonic predecessor. */
export async function readRetainedAgentStop(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1, ref: string) {
  return readRetainedAgentStopData(driver, artifacts, closure, ref);
}

export async function readRetainedAgentStopInDeliveryEpoch(driver: SqliteDriver, artifacts: ArtifactCatalog,
  closure: RecoveryClosureV1, ref: string, data: DeliveryReadData): Promise<AgentStopIntent> {
  return readRetainedAgentStopData(driver, artifacts, closure, ref, data);
}

async function readRetainedAgentStopData(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1,
  ref: string, data?: DeliveryReadData): Promise<AgentStopIntent> {
  const current = data ? await data.stop() : await readAgentStop(driver, artifacts, closure);
  if (ref === closure.run.stopIntentRef) return current;
  const original = await readStopReference(driver, artifacts, closure, ref, false, data);
  if (selectAgentStop(original, current) !== current) throw new TypeError('historical StopIntent is not a monotonic predecessor of the current winner');
  return original;
}

async function readStopReference(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1,
  ref: string, requireCurrentFence: boolean, data?: DeliveryReadData): Promise<AgentStopIntent> {
  if (closure.runSpec.operation === 'delivery') assertDeliveryModelFreeCut(closure);
  const { run } = closure;
  const intent = decodeAgentStop(await readCanonicalArtifact(artifacts, ref), run);
  const deliveryDenial = closure.runSpec.operation === 'delivery'
    ? data ? (await data.authorization())?.stop : await readDeliveryPolicyDenial(driver, artifacts, closure) : undefined;
  if (intent.origin === 'user_cancel') {
    if (!run.cancelRequested) throw new TypeError('cancellation lost its monotonic dispatch fence');
    if (deliveryDenial?.origin === 'user_cancel' && canonicalSha256(deliveryDenial) === ref) {
      // The complete approval reader already checked the original run.approve
      // channel, wait, decision and response. Never pretend it was run.cancel.
      requireEqual(intent, deliveryDenial, 'winning delivery approval denial');
    } else {
      const { response, row } = await readCancelResponse(driver, artifacts, run, intent.principalId, intent.requestId);
      if (response.result.snapshot.run.stopIntentRef !== ref || row.committedAt !== intent.createdAt) throw new TypeError('cancellation has no exact control-row owner');
    }
  } else if (requireCurrentFence && run.cancelRequested) {
    if (intent.origin !== 'kernel_integrity') throw new TypeError('resource/deadline stop cannot override user cancellation');
    const principalId = readSessionPrincipalId(driver, run.sessionId);
    let owned = deliveryDenial?.origin === 'user_cancel';
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
  } else if (intent.origin === 'runtime' && intent.runtimeSubtype === 'delivery_merge_conflict') {
    requireEqual(intent, await readDeliveryMergeConflictCause(driver, artifacts, closure), 'delivery merge conflict cause');
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
  } else if (intent.origin === 'policy_deny' && intent.subjectKind === 'delivery') {
    if (!deliveryDenial) throw new TypeError('delivery policy stop has no original decision');
    requireEqual(intent, deliveryDenial, 'winning delivery direct-policy denial');
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
  if (run.stopIntentRef) {
    const current = decodeAgentStop(await readCanonicalArtifact(artifacts, run.stopIntentRef), run);
    if (current.origin === 'policy_deny' && current.subjectKind === 'verifier' && !currentDenialValidated)
      throw new TypeError('verifier policy denial lacks its original policy decision');
  }
  return validated;
}

export async function validateStopRecovery(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1) {
  return validateStopRecoveryData(driver, artifacts, closure);
}

export async function validateStopRecoveryInDeliveryEpoch(driver: SqliteDriver, artifacts: ArtifactCatalog,
  closure: RecoveryClosureV1, data: DeliveryReadData) {
  return validateStopRecoveryData(driver, artifacts, closure, data);
}

async function validateStopRecoveryData(driver: SqliteDriver, artifacts: ArtifactCatalog, closure: RecoveryClosureV1,
  data?: DeliveryReadData) {
  const { run, runSpec: spec, latestCheckpoint: checkpoint, journal } = closure;
  const terminal = run.status === 'failed' || run.status === 'cancelled';
  if (!run.stopIntentRef) {
    if (terminal) throw new TypeError('terminal stop has no winning StopIntent');
    return;
  }
  const intent = data ? await data.stop() : await readAgentStop(driver, artifacts, closure);
  if (!terminal) {
    if (!['queued', 'running', 'waiting'].includes(run.status) || run.terminalReason || run.terminalDetailRef || run.resultRef) throw new TypeError('nonterminal stop has terminal fields');
    return;
  }
  if (spec.operation === 'delivery') assertDeliveryModelFreeCut(closure);
  if (run.parentRunId || closure.childAllocations.length || !isZeroBudget(run.budgetReserved) ||
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
  const abandoned = [...await validateInstalledBrokerTerminalHistory(driver, artifacts, closure, detail),
    ...await validateVerifierUnknownTerminalHistory(driver, artifacts, closure, detail)]
    .sort((left, right) => left.unknownJournalSeq - right.unknownJournalSeq ||
      Buffer.compare(Buffer.from(left.opId), Buffer.from(right.opId)) || left.attempt - right.attempt);
  const hasPublicationClaim = journal.some(entry => entry.opKind === 'publish' && entry.phase === 'dispatch_claimed');
  const publication = hasPublicationClaim && spec.operation === 'delivery' && detail.deliveryTerminalProjectionEvidenceRef
    ? data ? await data.terminalProjection(detail.deliveryTerminalProjectionEvidenceRef)
      : await readDeliveryTerminalProjection(driver, artifacts, closure, detail.deliveryTerminalProjectionEvidenceRef) : undefined;
  if (hasPublicationClaim && (!publication || publication.evidence.selectedBranch !== 'abort') ||
      !hasPublicationClaim && detail.deliveryTerminalProjectionEvidenceRef !== undefined)
    throw new TypeError('terminal stop lacks its exact original aborted publication projection');
  if (publication && (publication.evidence.observedAt > preparedAt || publication.checkpoint.createdAt !== run.updatedAt ||
      publication.checkpoint.basedOnRunRevision !== checkpoint.basedOnRunRevision ||
      publication.checkpoint.contextManifestRef !== checkpoint.contextManifestRef || publication.checkpoint.workspaceStateRef !== checkpoint.workspaceStateRef))
    throw new TypeError('terminal stop publication projection was not the same original terminal transaction');
  requireEqual(detail, { ...agentStopDetail(intent, run.stopIntentRef, preparedAt),
    abandonedRetryInvocations: abandoned,
    ...(publication ? { publicationResultItemRefs: [...publication.evidence.forwardResultItemRefs, ...publication.evidence.abortResultItemRefs],
      deliveryTerminalProjectionEvidenceRef: publication.evidenceRef } : {}) }, 'terminal reason closure');
  const assembly = await readCanonicalArtifact<RunAssemblyV1>(artifacts, spec.assemblyRef);
  if (assembly.format !== 'cliq-run-assembly-v1' || assembly.mcpServers.length) throw new TypeError('terminal stop lacks its typed containment closure');
  // Common recovery verified every complete seal or retirement/source graph;
  // a phase string alone cannot satisfy this final retained SQL cut.
  assertRetiredGenerationCut(driver, run, closure.workspaceGenerations);
  const modelNoRelease = await validateInstalledModelNoReleaseHistory(driver, artifacts, closure);
  const privateRollbacks = await validatePrivateToolRollbackHistory(driver, artifacts, closure);
  const verifierStops = await validateVerifierStoppedHistory(driver, artifacts, closure);
  const unclaimedPublications = !hasPublicationClaim && spec.operation === 'delivery' && journal.some(entry => entry.opKind === 'publish')
    ? data ? await data.unclaimedStopHistory() : await readUnclaimedPublicationStopHistory(driver, artifacts, closure) : new Set<number>();
  for (const { entry, hasClaim } of stopInvocationHistory(journal).values()) {
    if (entry.opKind === 'publish' && (publication?.closedPublicationJournalSeqs.has(entry.seq) || unclaimedPublications.has(entry.seq))) continue;
    if (['model', 'verifier'].includes(entry.opKind) && entry.replayClass === 'retry' && entry.phase === 'unknown' && abandoned.some(closed =>
      closed.opId === entry.opId && closed.attempt === entry.attempt && closed.unknownJournalSeq === entry.seq &&
      closed.budgetSettlementRef === entry.budgetSettlementRef)) continue;
    if (entry.phase === 'failed' && (entry.opKind === 'model' && modelNoRelease.has(entry.seq) ||
        entry.opKind === 'tool' && privateRollbacks.has(entry.seq) || entry.opKind === 'verifier' && verifierStops.has(entry.seq))) continue;
    if (!['model', 'tool', 'verifier'].includes(entry.opKind) || (entry.phase !== 'completed' &&
        (entry.phase !== 'failed' || hasClaim))) throw new TypeError('terminal stop retains unresolved dispatch evidence');
    if (entry.phase === 'failed' && entry.errorRef === run.stopIntentRef && entry.timestamp !== preparedAt) throw new TypeError('stop refund has no atomic terminal owner');
  }
  const items = await artifacts.mapReads(closure.items, (row) => readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef));
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
    itemKey: `run-terminal:${run.id}`, runId: run.id, operation: spec.operation, admittedSessionItemSeq: admitted.throughSessionItemSeq,
    status: run.status, terminalReason: run.terminalReason!, terminalDetailRef: run.terminalDetailRef };
  const itemId = identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id);
  const row = driver.prepare('SELECT session_id, run_id, item_seq, kind, payload_ref, created_at FROM items WHERE item_id = ?')
    .get<{ session_id: string; run_id: string | null; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(itemId);
  if (!row || row.session_id !== run.sessionId || row.run_id !== null || row.kind !== 'run_terminal' || row.created_at !== run.updatedAt ||
      row.payload_ref !== canonicalSha256(expected)) throw new TypeError('terminal Run has no atomic Session item');
  requireEqual(await readCanonicalArtifact(artifacts, row.payload_ref), expected, 'Session terminal payload');
  await assertSessionTerminalProjection(driver, artifacts, run.sessionId, { itemSeq: Number(row.item_seq), itemId, payloadRef: row.payload_ref });
}
