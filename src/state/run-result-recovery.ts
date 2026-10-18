import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { RunResult, VerificationClosureV1 } from '../kernel/result.js';
import type { ContinuationItem, RecoveryClosureV1, Run, RunFrontier, SessionRunTerminalItem } from '../kernel/types.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { openStopBatch, stopInvocationHistory } from '../runtime/stop.js';
import { readCanonicalArtifact, readText } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeAdmittedContext, decodeSessionProjection, decodeUnverifiedConsent } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { finalCandidateCheckpointId, readCandidateVerifierPlan } from './final-candidate-plan.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { isZeroBudget } from './invariants.js';
import { decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';
import { readCheckpoint, readControlRequest, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readVerifierProgress, verifierCheckpointId } from './verifier-recovery.js';

export const verificationCheckpointId = (runId: string, candidateItemId: string, closureRef: string) =>
  identityHash('cliq-verification-finalize-checkpoint-v1', runId, candidateItemId, closureRef);
export const runResultCheckpointId = (runId: string, candidateItemId: string, resultRef: string) =>
  identityHash('cliq-run-result-checkpoint-v1', runId, candidateItemId, resultRef);

/** Small immutable/admission projection shared by the live reducers and their
 * recovery verifier. The enclosing recovery walk already proves the candidate's
 * producer/source graph and every retained physical seal. No native proof is minted. */
export async function readResultBasis(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  const { run, runSpec: spec } = cut;
  if (spec.operation !== 'agent' || run.parentRunId || spec.dependencyPolicyRef !== undefined ||
      cut.childAllocations.length || driver.prepare('SELECT 1 FROM runs WHERE parent_run_id = ? LIMIT 1').get(run.id) ||
      !isZeroBudget(run.budgetReserved) || cut.workerLaunches.length || run.activeWorkerLaunchId || run.waitingOnRef || run.waitingReason ||
      cut.workspaceGenerations.some(generation => generation.phase !== 'sealed' && generation.phase !== 'retired') ||
      [...stopInvocationHistory(cut.journal).values()].some(({ entry }) =>
        !['model', 'tool', 'verifier'].includes(entry.opKind) || !['completed', 'failed'].includes(entry.phase)))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires the complete worker-free root candidate closure');
  assertRetiredGenerationCut(driver, run, cut.workspaceGenerations);
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  if (assembly.mcpServers.length) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires its implemented MCP containment closure');
  const items = await Promise.all(cut.items.map(row => readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef)));
  if (openStopBatch(items)) throw new TypeError('result retains an open tool batch');
  const progress = await readVerifierProgress(driver, artifacts, cut), { candidate, spec: frozen, plan, planRef } = progress;
  if (candidate.operation !== 'agent' || candidate.runId !== run.id || candidate.baseSourceRef !== spec.baseWorkspaceManifestRef)
    throw new TypeError('result has no current root agent candidate');
  if (!progress.complete || progress.entries.some(entry => !entry.disposition || entry.planEntry.required && entry.disposition.kind !== 'passed'))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires every frozen verifier and all required passes');
  const expectedPlan = await readCandidateVerifierPlan(artifacts, spec, { runId: run.id,
    candidateItemId: candidate.itemId, resultSourceRef: candidate.resultSourceRef });
  requireEqual(plan, expectedPlan, 'result frozen verifier plan');
  const required = frozen.verifiers.some(entry => entry.gate === 'required');
  const consent = required ? undefined : decodeUnverifiedConsent(await readCanonicalArtifact(artifacts, spec.unverifiedConsentRef!));
  if (required && spec.unverifiedConsentRef !== undefined) throw new TypeError('verified result cannot carry unverified consent');
  if (consent && !exactKeys(consent, ['schemaVersion', 'kind', 'principalId', 'client', 'channelIdentityRef', 'channelIdentityDigest',
    'admissionIntentDigest', 'runSpecCoreDigest', 'allowUnverified', 'createdAt', 'consentDigest']))
    throw new TypeError('result consent has unknown or missing fields');
  if (consent) {
    for (const ref of [consent.channelIdentityRef, consent.channelIdentityDigest, consent.admissionIntentDigest,
      consent.runSpecCoreDigest, consent.consentDigest]) assertArtifactRef(ref);
    parseCanonicalTime(consent.createdAt);
  }
  const admission = driver.prepare(`SELECT principal_id, admission_method, admission_key, admission_intent_digest,
    admission_request_id FROM runs WHERE id = ?`).get<{ principal_id: string; admission_method: string; admission_key: string;
      admission_intent_digest: string; admission_request_id: string | null }>(run.id);
  const principalId = readSessionPrincipalId(driver, run.sessionId);
  const original = admission?.admission_request_id && readControlRequest(driver, principalId, 'run.submit', admission.admission_request_id);
  const { unverifiedConsentRef: _consent, ...specCore } = spec;
  if (!admission || admission.principal_id !== principalId || admission.admission_method !== 'run.submit' || !original ||
      run.id !== identityHash('cliq-run-id-v1', principalId, 'run.submit', admission.admission_key) ||
      original.committedAt !== run.createdAt || consent && (consent.principalId !== principalId || consent.createdAt !== run.createdAt ||
      consent.admissionIntentDigest !== admission.admission_intent_digest || consent.runSpecCoreDigest !== canonicalSha256(specCore) ||
      consent.channelIdentityRef !== original.channelIdentityRef || consent.channelIdentityDigest !== original.channelIdentityDigest))
    throw new TypeError('result consent does not close its original admission and RunSpec');
  const initialCheckpointId = identityHash('cliq-checkpoint-id-v1', run.id, 'initial', 0);
  const initialCheckpoint = readCheckpoint(driver, initialCheckpointId);
  const initialFrontier: RunFrontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: identityHash('cliq-turn-id-v1', run.id, 'initial'), contextItemSeq: 0, cause: 'initial' };
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(initialFrontier)), initialFrontier, 'result original admission frontier');
  const initialRun: Run = { id: run.id, sessionId: run.sessionId, specRef: run.specRef, status: 'queued', nextStep: 'agent',
    frontierRef: canonicalSha256(initialFrontier), revision: 1, leaseEpoch: 0, latestCheckpointId: initialCheckpointId,
    budgetReserved: ZERO_BUDGET, budgetConsumed: ZERO_BUDGET, repairCount: 0, cancelRequested: false,
    createdAt: run.createdAt, deadlineAt: run.deadlineAt, updatedAt: run.createdAt };
  if (initialCheckpoint.runId !== run.id || initialCheckpoint.reason !== 'initial' || initialCheckpoint.createdAt !== run.createdAt ||
      initialCheckpoint.basedOnRunRevision !== 0 || initialCheckpoint.runItemSeq !== 0 || initialCheckpoint.journalSeq !== 0)
    throw new TypeError('result original admission Checkpoint differs');
  requireEqual(await readCanonicalArtifact(artifacts, original.responseRef), { protocolVersion: 1, ok: true,
    result: { method: 'run.submit', snapshot: { schemaVersion: 1, operation: 'agent', run: initialRun, latestRunItemSeq: 0 } } },
  'result original admission response');
  const { channel } = await readHistoricalControlChannel(driver, artifacts, { principalId,
    channelIdentityRef: original.channelIdentityRef, channelIdentityDigest: original.channelIdentityDigest });
  if (channel.principalId !== principalId || consent && channel.client !== consent.client || channel.openedAt > original.committedAt)
    throw new TypeError('result consent does not close its original principal and client');
  const summary = await readText(artifacts, candidate.summaryRef);
  if (!summary.utf8.trim()) throw new TypeError('result summary is empty');
  const entries = progress.entries.map(entry => ({ verifierIndex: entry.planEntry.index, verifierId: entry.planEntry.verifierId,
    verifierSpecDigest: entry.planEntry.verifierSpecDigest, verifierEntryDigest: entry.planEntry.verifierEntryDigest,
    required: entry.planEntry.required, disposition: entry.disposition! }));
  const verification: Extract<VerificationClosureV1['verification'], { kind: 'local' }> = required
    ? { kind: 'local', outcome: 'verified', entries }
    : { kind: 'local', outcome: 'unverified', unverifiedConsentRef: spec.unverifiedConsentRef!, entries };
  const verificationReceiptRefs = entries.flatMap(entry => 'receiptRef' in entry.disposition ? [entry.disposition.receiptRef] : []);
  const completion = progress.entries.at(-1);
  const completionCheckpoint = completion?.resultItem
    ? readCheckpoint(driver, verifierCheckpointId(run.id, completion.resultItem.opId, completion.resultItem.attempt))
    : readCheckpoint(driver, finalCandidateCheckpointId(run.id, candidate.producingItemId));
  if (cut.run.nextStep === 'verify' && cut.latestCheckpoint.id !== completionCheckpoint.id)
    throw new TypeError('verification completion does not retain its exact final producer Checkpoint');
  return { candidate, plan, planRef, consent, summary, principalId, admission, original, progress, verification, verificationReceiptRefs,
    completionCheckpoint, status: required ? 'succeeded' as const : 'completed_unverified' as const,
    terminalReason: required ? 'verified' as const : 'no_required_verifier' as const };
}

export function expectedVerificationClosure(basis: Awaited<ReturnType<typeof readResultBasis>>, createdAt: string): VerificationClosureV1 {
  const value: VerificationClosureV1 = { schemaVersion: 1, format: 'cliq-verification-closure-v1', runId: basis.candidate.runId,
    candidateItemId: basis.candidate.itemId, resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef,
    dependency: { kind: 'none' }, verification: basis.verification,
    createdAt, closureDigest: '' };
  value.closureDigest = digestOmitting(value, 'closureDigest');
  return value;
}

/** Historical proof of the actual verification→finalize transaction. A loose
 * closure artifact without its uniquely derived Checkpoint is insufficient. */
export async function readFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  basis: Awaited<ReturnType<typeof readResultBasis>>, closureRef: string) {
  const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, closureRef));
  requireEqual(closure, expectedVerificationClosure(basis, closure.createdAt), 'result exact verification closure');
  const checkpoint = readCheckpoint(driver, verificationCheckpointId(cut.run.id, basis.candidate.itemId, closureRef));
  const candidateCheckpoint = basis.completionCheckpoint;
  if (checkpoint.runId !== cut.run.id || checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== cut.items.length ||
      checkpoint.journalSeq !== cut.journal.length || checkpoint.basedOnRunRevision !== candidateCheckpoint.basedOnRunRevision + 1 ||
      checkpoint.basedOnRunRevision >= cut.run.revision || checkpoint.workspaceStateRef !== candidateCheckpoint.workspaceStateRef ||
      checkpoint.contextManifestRef !== candidateCheckpoint.contextManifestRef || checkpoint.createdAt < candidateCheckpoint.createdAt ||
      closure.createdAt < basis.candidate.createdAt || checkpoint.createdAt < closure.createdAt || checkpoint.createdAt >= cut.run.deadlineAt)
    throw new TypeError('result verification closure has no exact original finalize Checkpoint');
  const frontier: Extract<RunFrontier, { kind: 'finalize'; operation: 'agent' }> = { schemaVersion: 1,
    kind: 'finalize', operation: 'agent', candidateItemId: basis.candidate.itemId,
    resultSourceRef: basis.candidate.resultSourceRef, verificationClosureRef: closureRef };
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(frontier)), frontier, 'result retained finalize frontier');
  return { closure, checkpoint, frontier };
}

/** Invoked only inside the complete recovery walk; never opens a new StateOwner
 * or substitutes today's process/clock for the original retained seal. */
export async function validateRunResultRecovery(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1): Promise<void> {
  const { run } = cut;
  if (run.nextStep !== 'finalize' && run.resultRef === undefined && !['succeeded', 'completed_unverified'].includes(run.status)) return;
  const basis = await readResultBasis(driver, artifacts, cut);
  if (run.nextStep === 'finalize') {
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
    if (frontier.kind !== 'finalize' || frontier.operation !== 'agent' || run.status !== 'queued' || run.resultRef || run.terminalReason || run.terminalDetailRef)
      throw new TypeError('result has an unsupported finalize cut');
    const historical = await readFinalization(driver, artifacts, cut, basis, frontier.verificationClosureRef);
    requireEqual(frontier, historical.frontier, 'current result finalize frontier');
    requireEqual(cut.latestCheckpoint, historical.checkpoint, 'current result finalize Checkpoint');
    if (!run.stopIntentRef && (run.updatedAt !== historical.checkpoint.createdAt || run.revision !== historical.checkpoint.basedOnRunRevision + 1))
      throw new TypeError('result finalize Run revision or time is inconsistent');
    return;
  }
  if (run.status !== basis.status || run.terminalReason !== basis.terminalReason || !run.resultRef ||
      run.stopIntentRef || run.cancelRequested || run.terminalDetailRef || run.nextStep !== null || run.frontierRef)
    throw new TypeError('result terminal status, reason or authority fields are inconsistent');
  const result = decodeRunResult(await readCanonicalArtifact(artifacts, run.resultRef));
  const historical = await readFinalization(driver, artifacts, cut, basis, result.verificationClosureRef);
  const expected: RunResult = { schemaVersion: 1, runId: run.id, baseSourceRef: basis.candidate.baseSourceRef,
    resultSourceRef: basis.candidate.resultSourceRef, diffRef: basis.candidate.diffRef,
    verificationClosureRef: result.verificationClosureRef, verificationReceiptRefs: basis.verificationReceiptRefs, summaryRef: basis.candidate.summaryRef, createdAt: result.createdAt };
  requireEqual(result, expected, 'terminal immutable RunResult');
  const checkpoint = cut.latestCheckpoint;
  if (checkpoint.id !== runResultCheckpointId(run.id, basis.candidate.itemId, run.resultRef) || checkpoint.runId !== run.id ||
      checkpoint.basedOnRunRevision !== run.revision - 1 || checkpoint.basedOnRunRevision !== historical.checkpoint.basedOnRunRevision + 1 ||
      checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== cut.items.length || checkpoint.journalSeq !== cut.journal.length ||
      checkpoint.contextManifestRef !== historical.checkpoint.contextManifestRef || checkpoint.workspaceStateRef !== historical.checkpoint.workspaceStateRef ||
      checkpoint.createdAt !== run.updatedAt || result.createdAt < historical.checkpoint.createdAt || result.createdAt > run.updatedAt || run.updatedAt >= run.deadlineAt)
    throw new TypeError('terminal RunResult has no exact atomic Checkpoint');
  const admitted = decodeAdmittedContext(await readCanonicalArtifact(artifacts, cut.runSpec.admittedContextRef));
  const terminal: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
    itemKey: `run-terminal:${run.id}`, runId: run.id, operation: 'agent', admittedSessionItemSeq: admitted.throughSessionItemSeq,
    status: basis.status, terminalReason: basis.terminalReason, resultRef: run.resultRef,
    summaryRef: result.summaryRef, summaryDigest: basis.summary.textDigest };
  const itemId = identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id);
  const row = driver.prepare('SELECT session_id, run_id, item_seq, kind, payload_ref, created_at FROM items WHERE item_id = ?')
    .get<{ session_id: string; run_id: string | null; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(itemId);
  if (!row || row.session_id !== run.sessionId || row.run_id !== null || row.kind !== 'run_terminal' || row.created_at !== run.updatedAt ||
      row.payload_ref !== canonicalSha256(terminal)) throw new TypeError('terminal result has no atomic root Session item');
  requireEqual(await readCanonicalArtifact(artifacts, row.payload_ref), terminal, 'terminal result Session payload');
  const session = readSession(driver, run.sessionId);
  const projection = decodeSessionProjection(await readCanonicalArtifact(artifacts, session.contextProjectionRef));
  if (projection.sessionId !== session.id || projection.contextRevision !== session.contextRevision || projection.throughItemSeq !== session.latestItemSeq)
    throw new TypeError('terminal result Session projection differs from its owner');
  const segment = projection.segments.find(segment => segment.fromItemSeq <= Number(row.item_seq) && segment.throughItemSeq >= Number(row.item_seq));
  requireEqual(segment, { kind: 'raw', fromItemSeq: Number(row.item_seq), throughItemSeq: Number(row.item_seq),
    items: [{ sourceSessionId: session.id, itemSeq: Number(row.item_seq), itemId, kind: 'run_terminal', payloadRef: row.payload_ref }] },
  'terminal result one-item Session segment');
}
