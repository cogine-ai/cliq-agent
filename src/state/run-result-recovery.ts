import { readChildAdmission } from './child-admission.js';
import { decodeDerivedChildUnverifiedConsent } from '../kernel/child-verifier.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import type { InheritedVerificationProvenanceV1, RunResult, VerificationClosureV1 } from '../kernel/result.js';
import type { ContinuationItem, RecoveryClosureV1, Run, RunFrontier, SessionRunTerminalItem } from '../kernel/types.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { decodeRetainedRunAssembly } from '../model/run-assembly.js';
import { immutableSnapshot } from '../model/immutable.js';
import { openStopBatch, stopInvocationHistory } from '../runtime/stop.js';
import { readCanonicalArtifact, readText } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeAdmittedContext, decodeSessionProjection, decodeUnverifiedConsent } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { finalCandidateCheckpointId, readCandidateVerifierPlan } from './final-candidate-plan.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { isZeroBudget } from './invariants.js';
import { decodeInheritedVerificationProvenance, decodeRunResult, decodeVerificationClosure } from './result-artifacts.js';
import { readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import { assertSessionTerminalProjection } from './session-context.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readVerifierProgress, verifierCheckpointId } from './verifier-recovery.js';
import { validateDeliveryRecoveryData, type RetainedDeliveryMerge } from './delivery-recovery.js';
import { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { assertDeliveryModelFreeCut } from './run-model-free.js';
import { decodeVerificationReceipt } from './verifier-artifacts.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import type { DeliveryReadData } from './delivery-read-data.js';
import { dependencyVerificationProjection } from './dependency-history.js';

function assertDeliveryReadCut(driver: SqliteConnection | SqliteDriver, cut: RecoveryClosureV1) {
  const rows = driver.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(cut.run.id);
  requireEqual(rows.map(row => ({ schemaVersion: 1, itemId: row.item_id, itemSeq: Number(row.item_seq), payloadRef: row.payload_ref,
    payloadDigest: row.payload_ref, createdAt: row.created_at })), cut.items, 'delivery verification exact owning item cut');
  requireEqual(readRun(driver, cut.run.id), cut.run, 'delivery verification exact owning Run cut');
  requireEqual(readCheckpoint(driver, cut.run.latestCheckpointId), cut.latestCheckpoint, 'delivery verification exact ready Checkpoint');
  requireEqual(readInvocationJournal(driver, cut.run.id), cut.journal, 'delivery verification exact owning Journal cut');
  requireEqual(readWorkerLaunchesForRun(driver, cut.run.id).filter(launch => launch.phase !== 'retired'), cut.workerLaunches,
    'delivery verification exact current worker cut');
  requireEqual(readWorkspaceGenerationsForRun(driver, cut.run.id), cut.workspaceGenerations, 'delivery verification exact generation cut');
  if (driver.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1').get(cut.run.id, cut.run.id) ||
      driver.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(cut.run.id))
    throw new TypeError('delivery verification acquired child authority');
}

async function readDeliveryCandidateMaterial(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  assertDeliveryModelFreeCut(cut);
  assertDeliveryReadCut(driver, cut);
  const admission = await readDeliveryRunAdmission(driver, artifacts, cut.run.id);
  return readDeliveryCandidateMaterialData(driver, artifacts, cut, admission);
}

async function readDeliveryCandidateMaterialData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  admission: Awaited<ReturnType<typeof readDeliveryRunAdmission>>, retainedMerges?: ReadonlyMap<string, RetainedDeliveryMerge>) {
  assertDeliveryModelFreeCut(cut);
  assertDeliveryReadCut(driver, cut);
  requireEqual(admission.run, cut.run, 'delivery verification owning Run cut');
  const decodedItems = new Map<string, ContinuationItem>();
  for (const row of cut.items) decodedItems.set(row.itemId, await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef));
  const checkpoints = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid').all<{ id: string }>(cut.run.id)
    .map(row => readCheckpoint(driver, row.id));
  const merges = retainedMerges ?? await validateDeliveryRecoveryData(driver, artifacts, { ...cut, checkpoints, decodedItems }, admission);
  const merged = [...merges.values()][0];
  if (merges.size !== 1 || !merged)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery verification requires its one complete original merge');
  const progress = await readVerifierProgress(driver, artifacts, cut, merged.candidate.itemId);
  const { candidate, spec: frozen, plan, planRef } = progress;
  requireEqual(candidate, merged.candidate, 'delivery verification exact merged candidate');
  if (!frozen.verifiers.some(entry => entry.gate === 'required') || cut.runSpec.unverifiedConsentRef !== undefined)
    throw new TypeError('delivery cannot turn an unverified source into a verified result');
  const summary = await readText(artifacts, candidate.summaryRef);
  requireEqual(summary, merged.source.summary, 'delivery sole deterministic merge summary');
  const principalId = readSessionPrincipalId(driver, cut.run.sessionId);
  const row = driver.prepare(`SELECT principal_id, admission_method, admission_key, admission_intent_digest,
    admission_request_id FROM runs WHERE id=?`).get<{ principal_id: string; admission_method: string; admission_key: string;
      admission_intent_digest: string; admission_request_id: string | null }>(cut.run.id);
  const original = row?.admission_request_id && readControlRequest(driver, principalId, 'run.apply', row.admission_request_id);
  if (!row || !original || row.principal_id !== principalId || row.admission_method !== 'run.apply')
    throw new TypeError('delivery result lost its original authenticated admission');
  const identical = candidate.resultSourceRef === admission.source.result.resultSourceRef;
  assertDeliveryReadCut(driver, cut);
  return { admission, decodedItems, merged, progress, candidate, frozen, plan, planRef, summary, principalId, row, original, identical };
}

/** Routing facts from the same complete retained graph, not permission to
 * execute, inherit or publish. Errors are never interpreted as a fallback. */
export async function readDeliveryVerificationMode(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  const material = await readDeliveryCandidateMaterial(driver, artifacts, cut);
  return Object.freeze({ kind: material.identical ? 'inherited' as const : 'local' as const, noOp: material.merged.source.noOp,
    candidateItemId: material.candidate.itemId, resultSourceRef: material.candidate.resultSourceRef,
    verifierPlanRef: material.planRef, deliveryPlanRef: material.merged.planRef });
}

async function readDeliveryResultBasis(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  return readDeliveryResultBasisData(driver, artifacts, cut, await readDeliveryCandidateMaterial(driver, artifacts, cut));
}

async function readDeliveryResultBasisData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  material: Awaited<ReturnType<typeof readDeliveryCandidateMaterial>>) {
  const { admission, decodedItems, merged, progress, candidate, plan, planRef, summary, principalId, row, original, identical } =
    material;
  let verification: Extract<VerificationClosureV1['verification'], { kind: 'local' }> | undefined;
  let inheritance: Omit<InheritedVerificationProvenanceV1, 'createdAt' | 'provenanceDigest'> | undefined;
  let verificationReceiptRefs: string[], completionCheckpoint = merged.checkpoint;
  if (identical) {
    if (cut.journal.some(entry => entry.opKind === 'verifier') || [...decodedItems.values()].some(item =>
      ['verifier_result', 'verifier_stop'].includes(item.kind) || item.kind === 'policy_decision' && item.subjectKind === 'verifier_launch'))
      throw new TypeError('identical delivery cannot relabel local verifier attempts as inherited receipts');
    if (cut.journal.some(entry => entry.target === 'builtin:dependency-acquire') || [...decodedItems.values()].some(item =>
      item.kind === 'dependency_ready' || item.kind === 'dependency_failure'))
      throw new TypeError('identical delivery cannot relabel its own dependency execution as inherited verification');
    const source = admission.source;
    verificationReceiptRefs = [...source.result.verificationReceiptRefs];
    const verificationReceiptDigests: string[] = [];
    for (const ref of verificationReceiptRefs) verificationReceiptDigests.push(
      decodeVerificationReceipt(await readCanonicalArtifact(artifacts, ref)).receiptDigest);
    if (source.spec.verifierSpecRef !== cut.runSpec.verifierSpecRef || source.verifierSpec.specDigest !== plan.verifierSpecDigest ||
        source.closure.resultSourceRef !== candidate.resultSourceRef || !verificationReceiptRefs.length)
      throw new TypeError('inherited delivery differs from its complete verified source spec, closure or receipts');
    if (progress.dependency && (source.spec.dependencyPolicyRef !== progress.dependency.dependencyPolicyRef ||
        source.closure.dependency.kind === 'none' || source.closure.dependency.dependencyPolicyRef !== progress.dependency.dependencyPolicyRef ||
        source.closure.dependency.dependencyPlanRef !== progress.dependency.planRef))
      throw new TypeError('inherited delivery lost its complete original dependency verification closure');
    inheritance = { schemaVersion: 1, format: 'cliq-inherited-verification-provenance-v1', deliveryRunId: cut.run.id,
      sourceRunId: source.run.id, sourceRunResultRef: admission.request.expectedRunResultRef,
      sourceRunResultDigest: canonicalSha256(source.result), sourceVerificationClosureRef: source.result.verificationClosureRef,
      sourceVerificationClosureDigest: source.closure.closureDigest, resultSourceRef: candidate.resultSourceRef,
      verifierSpecRef: cut.runSpec.verifierSpecRef, verifierSpecDigest: plan.verifierSpecDigest,
      verificationReceiptRefs, verificationReceiptDigests };
  } else {
    if (!progress.complete || progress.entries.some(entry => !entry.disposition || entry.planEntry.required && entry.disposition.kind !== 'passed'))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'delivery requires its own complete ordered verifiers and every required pass');
    const entries = progress.entries.map(entry => ({ verifierIndex: entry.planEntry.index, verifierId: entry.planEntry.verifierId,
      verifierSpecDigest: entry.planEntry.verifierSpecDigest, verifierEntryDigest: entry.planEntry.verifierEntryDigest,
      required: entry.planEntry.required, disposition: entry.disposition! }));
    verification = { kind: 'local', outcome: 'verified', entries };
    verificationReceiptRefs = entries.flatMap(entry => 'receiptRef' in entry.disposition ? [entry.disposition.receiptRef] : []);
    const completion = progress.entries.at(-1);
    if (!completion?.resultItem) throw new TypeError('delivery local verification lost its final receipt-backed result');
    completionCheckpoint = readCheckpoint(driver, verifierCheckpointId(cut.run.id, completion.resultItem.opId, completion.resultItem.attempt));
  }
  assertDeliveryReadCut(driver, cut);
  return { candidate, plan, planRef, consent: undefined, summary, principalId, admission: row, original, progress, verification,
    verificationReceiptRefs, completionCheckpoint, status: 'succeeded' as const, terminalReason: 'verified' as const,
    delivery: { admission, merged, inheritance } };
}

export const verificationCheckpointId = (runId: string, candidateItemId: string, closureRef: string) =>
  identityHash('cliq-verification-finalize-checkpoint-v1', runId, candidateItemId, closureRef);
export const runResultCheckpointId = (runId: string, candidateItemId: string, resultRef: string) =>
  identityHash('cliq-run-result-checkpoint-v1', runId, candidateItemId, resultRef);

/** Canonical data relation only, never proof that observations or a transaction
 * happened. The enclosing reader independently closes their complete graph. */
export function assertRunResultPreparationTime(operation: 'agent' | 'delivery', resultCreatedAt: string,
  publicationCreatedAt: string, committedAt: string, projectionObservedAt?: string): void {
  for (const value of [resultCreatedAt, publicationCreatedAt, committedAt]) parseCanonicalTime(value);
  if (projectionObservedAt !== undefined) parseCanonicalTime(projectionObservedAt);
  const earliest = operation === 'delivery' ? projectionObservedAt : publicationCreatedAt;
  if (earliest === undefined || resultCreatedAt < earliest || resultCreatedAt > committedAt ||
      operation === 'delivery' && publicationCreatedAt !== committedAt ||
      operation !== 'agent' && operation !== 'delivery')
    throw new TypeError('terminal result preparation time differs from its original publication transaction');
}

/** Small immutable/admission projection shared by the live reducers and their
 * recovery verifier. The enclosing recovery walk already proves the candidate's
 * producer/source graph and every retained physical seal. No native proof is minted. */
export async function readResultBasis(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  await assertResultBasisCut(driver, artifacts, cut);
  const { run, runSpec: spec } = cut;
  if (spec.operation === 'delivery') return readDeliveryResultBasis(driver, artifacts, cut);
  return readAgentResultBasis(driver, artifacts, cut);
}

async function assertResultBasisCut(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  const { run, runSpec: spec } = cut;
  if (cut.childAllocations.some(row => row.parentRunId === run.id && row.state !== 'settled') ||
      !isZeroBudget(run.budgetReserved) || cut.workerLaunches.length || run.activeWorkerLaunchId || run.waitingOnRef || run.waitingReason ||
      cut.workspaceGenerations.some(generation => generation.phase !== 'sealed' && generation.phase !== 'retired') ||
      [...stopInvocationHistory(cut.journal).values()].some(({ entry }) =>
        !(spec.operation === 'delivery' ? ['verifier', 'publish', ...(spec.dependencyPolicyRef ? ['tool'] : [])] : ['model', 'tool', 'verifier', 'child_admission', 'child_merge', 'child_await', 'skill_resource']).includes(entry.opKind) ||
        !['completed', 'failed'].includes(entry.phase)))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires the complete worker-free root candidate closure');
  assertRetiredGenerationCut(driver, run, cut.workspaceGenerations);
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(artifacts, spec.assemblyRef));
  if (assembly.mcpServers.length) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'result requires its implemented MCP containment closure');
}

async function readAgentResultBasis(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  const { run, runSpec: spec } = cut;
  const items = await artifacts.mapReads(cut.items, row => readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef));
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
  const childAdmission = run.parentRunId ? await readChildAdmission(driver, artifacts, run.id) : undefined;
  const consent = required ? undefined : childAdmission
    ? decodeDerivedChildUnverifiedConsent(await readCanonicalArtifact(artifacts, spec.unverifiedConsentRef!))
    : decodeUnverifiedConsent(await readCanonicalArtifact(artifacts, spec.unverifiedConsentRef!));
  if (required && spec.unverifiedConsentRef !== undefined) throw new TypeError('verified result cannot carry unverified consent');
  if (consent && consent.kind === 'direct_unverified_consent' && !exactKeys(consent, ['schemaVersion', 'kind', 'principalId', 'client', 'channelIdentityRef', 'channelIdentityDigest',
    'admissionIntentDigest', 'runSpecCoreDigest', 'allowUnverified', 'createdAt', 'consentDigest']))
    throw new TypeError('result consent has unknown or missing fields');
  if (consent && consent.kind !== 'derived_child_unverified_consent') {
    for (const ref of [consent.channelIdentityRef, consent.channelIdentityDigest, consent.admissionIntentDigest,
      consent.runSpecCoreDigest, consent.consentDigest]) assertArtifactRef(ref);
    parseCanonicalTime(consent.createdAt);
  }
  const admission = driver.prepare(`SELECT principal_id, admission_method, admission_key, admission_intent_digest,
    admission_request_id FROM runs WHERE id = ?`).get<{ principal_id: string; admission_method: string; admission_key: string;
      admission_intent_digest: string; admission_request_id: string | null }>(run.id);
  const principalId = readSessionPrincipalId(driver, run.sessionId);
  const original = !childAdmission && admission?.admission_request_id && readControlRequest(driver, principalId, 'run.submit', admission.admission_request_id);
  if (!childAdmission) {
  if (consent?.kind === 'derived_child_unverified_consent') throw new TypeError('root result cannot borrow child consent');
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
  } else {
    requireEqual(childAdmission.spec, spec, 'child result exact admitted spec');
    if (!admission || admission.principal_id !== principalId || admission.admission_method !== 'delegate')
      throw new TypeError('child result has no exact original delegate source');
    childAdmission.assertUnchanged(driver);
  }
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
    : readCheckpoint(driver, progress.dependency?.ready?.readyCheckpointId ?? finalCandidateCheckpointId(run.id, candidate.producingItemId));
  if (cut.run.nextStep === 'verify' && cut.latestCheckpoint.id !== completionCheckpoint.id)
    throw new TypeError('verification completion does not retain its exact final producer Checkpoint');
  return { candidate, plan, planRef, consent, summary, principalId, admission, original: original || undefined, childAdmission, progress, verification, verificationReceiptRefs,
    completionCheckpoint, status: required ? 'succeeded' as const : 'completed_unverified' as const,
    terminalReason: required ? 'verified' as const : 'no_required_verifier' as const, delivery: undefined };
}

export function expectedInheritedVerificationProvenance(basis: Awaited<ReturnType<typeof readResultBasis>>, createdAt: string) {
  if (!basis.delivery?.inheritance) return undefined;
  const provenance: InheritedVerificationProvenanceV1 = { ...basis.delivery.inheritance, createdAt, provenanceDigest: '' };
  provenance.provenanceDigest = digestOmitting(provenance, 'provenanceDigest');
  return decodeInheritedVerificationProvenance(provenance);
}

/** The complete progress reader supplies the original acquired receipt. This
 * projection is data only and cannot convert an inherited ready into a GET. */
export function expectedDependencyVerification(basis: Awaited<ReturnType<typeof readResultBasis>>, createdAt?: string): VerificationClosureV1['dependency'] {
  if (basis.delivery?.inheritance && basis.progress.dependency) {
    if (createdAt === undefined) throw new TypeError('inherited dependency verification requires its original provenance time');
    const provenance = expectedInheritedVerificationProvenance(basis, createdAt)!;
    return { kind: 'inherited_verification', dependencyPolicyRef: basis.progress.dependency.dependencyPolicyRef,
      dependencyPlanRef: basis.progress.dependency.planRef, sourceRunId: provenance.sourceRunId, sourceRunResultRef: provenance.sourceRunResultRef,
      sourceVerificationClosureRef: provenance.sourceVerificationClosureRef, inheritedProvenanceRef: canonicalSha256(provenance) };
  }
  return dependencyVerificationProjection(basis.progress.dependency);
}

export function expectedVerificationClosure(basis: Awaited<ReturnType<typeof readResultBasis>>, createdAt: string): VerificationClosureV1 {
  const provenance = expectedInheritedVerificationProvenance(basis, createdAt);
  const verification = provenance ? { kind: 'inherited_verified' as const, sourceRunId: provenance.sourceRunId,
    sourceRunResultRef: provenance.sourceRunResultRef, sourceVerificationClosureRef: provenance.sourceVerificationClosureRef,
    inheritedProvenanceRef: canonicalSha256(provenance) } : basis.verification;
  if (!verification) throw new TypeError('verification closure lost its independently reproduced local or inherited evidence');
  const value: VerificationClosureV1 = { schemaVersion: 1, format: 'cliq-verification-closure-v1', runId: basis.candidate.runId,
    candidateItemId: basis.candidate.itemId, resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef,
    dependency: expectedDependencyVerification(basis, createdAt), verification,
    createdAt, closureDigest: '' };
  value.closureDigest = digestOmitting(value, 'closureDigest');
  return value;
}

/** CAS preparation for the real no-op root-projection owner. Its one SQL
 * transaction inserts this verification Checkpoint and the actual publication
 * projection Checkpoint, then installs delivery finalize with one revision.
 * No approval/publish frontier, native proof, grant or second lifecycle is
 * manufactured by this immutable preparation. */
export async function prepareDeliveryNoOpVerification(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, createdAt: string) {
  cut = immutableSnapshot(cut);
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('no-op delivery cannot reinterpret an Agent Run');
  const basis = await readResultBasis(driver, artifacts, cut);
  if (!basis.delivery || !basis.delivery.merged.source.noOp || basis.delivery.merged.plan.forwardOperations.length ||
      basis.delivery.merged.plan.abortOperations.length || cut.run.status !== 'queued' || cut.run.nextStep !== 'verify' ||
      !cut.run.frontierRef || cut.run.stopIntentRef || cut.run.cancelRequested || cut.run.resultRef || cut.run.terminalReason || cut.run.terminalDetailRef ||
      parseCanonicalTime(createdAt) < parseCanonicalTime(cut.run.updatedAt) || createdAt >= cut.run.deadlineAt)
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'no-op verification requires its exact unstopped complete no-materialization cut');
  const frontier: RunFrontier = { schemaVersion: 1, kind: 'verify', phase: basis.delivery.inheritance && basis.progress.dependency ? 'dependencies' : 'verifiers', candidateItemId: basis.candidate.itemId,
    resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef,
    nextVerifierIndex: basis.delivery.inheritance ? 0 : basis.plan.entries.length, afterPass: 'delivery_approval' };
  if (basis.progress.dependency) frontier.dependencyPlanRef = basis.progress.dependency.planRef;
  requireEqual(await readCanonicalArtifact(artifacts, cut.run.frontierRef), frontier, 'no-op verification complete source frontier');
  requireEqual(cut.latestCheckpoint, basis.completionCheckpoint, 'no-op verification exact original complete producer Checkpoint');
  const provenance = expectedInheritedVerificationProvenance(basis, createdAt);
  const metadata = provenance ? [await artifacts.publishCanonical(provenance, provenance.format)] : [];
  const closure = decodeVerificationClosure(expectedVerificationClosure(basis, createdAt));
  const closureArtifact = await artifacts.publishCanonical(closure, closure.format); metadata.push(closureArtifact);
  const checkpointId = verificationCheckpointId(cut.run.id, basis.candidate.itemId, closureArtifact.ref);
  const sourceRun = immutableSnapshot(basis.delivery.admission.source.run);
  const workspaceIdentityRef = basis.delivery.admission.source.session.workspaceIdentityRef;
  const retainedMetadata = immutableSnapshot(metadata);
  assertDeliveryReadCut(driver, cut);
  return { basis, closure, verificationClosureRef: closureArtifact.ref, checkpointId, metadata: retainedMetadata,
    commitVerificationCheckpoint(connection: SqliteConnection, committedAt: string) {
      assertDeliveryReadCut(connection, cut);
      const sourceCut = () => {
        requireEqual(readRun(connection, sourceRun.id), sourceRun, 'no-op verification source terminal cut');
        if (readSession(connection, cut.run.sessionId).workspaceIdentityRef !== workspaceIdentityRef)
          throw new KernelStorageError('REVISION_CONFLICT', 'no-op verification original workspace identity changed');
      };
      sourceCut();
      if (parseCanonicalTime(committedAt) < parseCanonicalTime(createdAt) || committedAt >= cut.run.deadlineAt)
        throw new KernelStorageError('LEASE_FENCED', 'no-op verification source identity or Run lifetime changed');
      for (const artifact of retainedMetadata) insertArtifactMetadata(connection, artifact, committedAt);
      assertDeliveryReadCut(connection, cut); sourceCut();
      connection.prepare(`INSERT INTO checkpoints (id,schema_version,run_id,based_on_run_revision,run_item_seq,
        context_manifest_ref,journal_seq,workspace_state_ref,created_at,reason) VALUES (?,1,?,?,?,?,?,?,?,'auto')`)
        .run(checkpointId, cut.run.id, BigInt(cut.run.revision), BigInt(cut.items.length), cut.latestCheckpoint.contextManifestRef,
          BigInt(cut.journal.length), cut.latestCheckpoint.workspaceStateRef, committedAt);
    } };
}

/** Shared retained verification edge for approval, publication and results.
 * Reads the original source graph but never recursively loads this delivery's
 * RecoveryClosure, creates authority or accepts caller receipt/proof lists. */
export async function readDeliveryVerification(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, closureRef: string) {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('delivery verification cannot reinterpret an Agent Run');
  const basis = await readDeliveryResultBasis(driver, artifacts, cut);
  return readDeliveryVerificationBasis(driver, artifacts, cut, closureRef, basis);
}

/** Internal data-only node of one actual fresh recovery traversal. */
export async function readDeliveryResultData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  admission: Awaited<ReturnType<typeof readDeliveryRunAdmission>>, merges: ReadonlyMap<string, RetainedDeliveryMerge>) {
  const material = await readDeliveryCandidateMaterialData(driver, artifacts, cut, admission, merges);
  return readDeliveryResultBasisData(driver, artifacts, cut, material);
}

export async function readDeliveryVerificationBasis(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1, closureRef: string,
  basis: Awaited<ReturnType<typeof readDeliveryResultBasis>>) {
  const closure = decodeVerificationClosure(await readCanonicalArtifact(artifacts, closureRef));
  requireEqual(closure, expectedVerificationClosure(basis, closure.createdAt), 'delivery exact local or inherited verification closure');
  const provenance = expectedInheritedVerificationProvenance(basis, closure.createdAt);
  if (provenance) {
    if (closure.verification.kind !== 'inherited_verified') throw new TypeError('identical delivery lost its inherited provenance');
    requireEqual(decodeInheritedVerificationProvenance(await readCanonicalArtifact(artifacts, closure.verification.inheritedProvenanceRef)),
      provenance, 'delivery complete original-source verification provenance');
  }
  const checkpoint = readCheckpoint(driver, verificationCheckpointId(cut.run.id, basis.candidate.itemId, closureRef));
  const original = basis.completionCheckpoint;
  if (checkpoint.runId !== cut.run.id || checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== original.runItemSeq ||
      checkpoint.journalSeq !== original.journalSeq || checkpoint.basedOnRunRevision !== original.basedOnRunRevision + 1 ||
      checkpoint.basedOnRunRevision >= cut.run.revision || checkpoint.workspaceStateRef !== original.workspaceStateRef ||
      checkpoint.contextManifestRef !== original.contextManifestRef || checkpoint.createdAt < original.createdAt ||
      closure.createdAt < basis.candidate.createdAt || checkpoint.createdAt < closure.createdAt || checkpoint.createdAt >= cut.run.deadlineAt)
    throw new TypeError('delivery verification lost its exact original receipt/merge Checkpoint');
  if (basis.delivery.merged.plan.forwardOperations.length) {
    const frontier: Extract<RunFrontier, { kind: 'delivery'; phase: 'approval' }> = { schemaVersion: 1, kind: 'delivery', phase: 'approval',
      sourceRunResultRef: basis.delivery.admission.request.expectedRunResultRef, candidateItemId: basis.candidate.itemId,
      resultSourceRef: basis.candidate.resultSourceRef, verifierPlanRef: basis.planRef, verificationClosureRef: closureRef,
      deliveryPlanRef: basis.delivery.merged.planRef };
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(frontier)), frontier, 'delivery original proof-carrying approval frontier');
  } else if (!basis.delivery.merged.source.noOp || basis.delivery.merged.plan.abortOperations.length) {
    throw new TypeError('empty delivery Plan is not the exact role-normalized no-op');
  }
  assertDeliveryReadCut(driver, cut);
  return { candidate: basis.candidate, planRef: basis.planRef, deliveryPlan: basis.delivery.merged.plan,
    deliveryPlanRef: basis.delivery.merged.planRef, closure, checkpoint, admission: basis.delivery.admission };
}

/** Historical proof of the actual verification→finalize transaction. A loose
 * closure artifact without its uniquely derived Checkpoint is insufficient. */
export async function readFinalization(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  basis: Awaited<ReturnType<typeof readResultBasis>>, closureRef: string, projectionRef?: string) {
  return readFinalizationData(driver, artifacts, cut, basis, closureRef, projectionRef);
}

async function readFinalizationData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  basis: Awaited<ReturnType<typeof readResultBasis>>, closureRef: string, projectionRef?: string, delivery?: DeliveryReadData) {
  if (cut.runSpec.operation === 'delivery') {
    if (!projectionRef) throw new TypeError('delivery finalization requires the exact retained terminal projection');
    const verified = delivery ? await delivery.verification(closureRef) : await readDeliveryVerification(driver, artifacts, cut, closureRef);
    // The actual owner supplies this reader. A data-valid projection object is
    // never substituted for native publication/root-observation provenance.
    const { readDeliveryTerminalProjection } = await import('./delivery-publication-recovery.js');
    const physical = delivery ? await delivery.terminalProjection(projectionRef) : await readDeliveryTerminalProjection(driver, artifacts, cut, projectionRef);
    // The complete physical reader already requires a handoff for nonempty
    // forward finalization; Plan shape alone never proves that resource edge.
    if (physical.evidenceRef !== projectionRef || physical.evidence.selectedBranch !== 'forward_finalize' ||
        physical.evidence.observedSourceRef !== basis.candidate.resultSourceRef || physical.evidence.deliveryPlanRef !== verified.deliveryPlanRef ||
        physical.checkpoint.id !== identityHash(verified.deliveryPlan.forwardOperations.length
          ? 'cliq-delivery-publication-terminal-checkpoint-v1' : 'cliq-delivery-publication-checkpoint-v1', cut.run.id, verified.deliveryPlanRef) ||
        physical.checkpoint.createdAt < verified.checkpoint.createdAt)
      throw new TypeError('delivery terminal projection differs from its carried verified merge');
    const frontier: Extract<RunFrontier, { kind: 'finalize'; operation: 'delivery' }> = { schemaVersion: 1, kind: 'finalize', operation: 'delivery',
      candidateItemId: basis.candidate.itemId, resultSourceRef: basis.candidate.resultSourceRef,
      verificationClosureRef: closureRef, deliveryTerminalProjectionEvidenceRef: projectionRef };
    requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(frontier)), frontier, 'delivery retained publication finalize frontier');
    return { closure: verified.closure, checkpoint: physical.checkpoint, frontier, projectionObservedAt: physical.evidence.observedAt };
  }
  if (projectionRef !== undefined) throw new TypeError('Agent finalization cannot borrow delivery projection proof');
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
  return { closure, checkpoint, frontier, projectionObservedAt: undefined };
}

/** Invoked only inside the complete recovery walk; never opens a new StateOwner
 * or substitutes today's process/clock for the original retained seal. */
export async function validateRunResultRecovery(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1): Promise<void> {
  return validateRunResultRecoveryData(driver, artifacts, cut);
}

export async function validateRunResultRecoveryInDeliveryEpoch(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: RecoveryClosureV1, delivery: DeliveryReadData): Promise<void> {
  return validateRunResultRecoveryData(driver, artifacts, cut, delivery);
}

async function validateRunResultRecoveryData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  delivery?: DeliveryReadData): Promise<void> {
  const { run } = cut;
  if (cut.runSpec.operation === 'delivery' && run.frontierRef && run.nextStep === 'delivery') {
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef);
    if (frontier.kind === 'delivery' && frontier.phase !== 'merge')
      if (delivery) await delivery.verification(frontier.verificationClosureRef);
      else await readDeliveryVerification(driver, artifacts, cut, frontier.verificationClosureRef);
  }
  if (run.nextStep !== 'finalize' && run.resultRef === undefined && !['succeeded', 'completed_unverified'].includes(run.status)) return;
  if (delivery) await assertResultBasisCut(driver, artifacts, cut);
  const basis = delivery ? await delivery.basis() : await readResultBasis(driver, artifacts, cut);
  if (run.nextStep === 'finalize') {
    const frontier = await readCanonicalArtifact<RunFrontier>(artifacts, run.frontierRef!);
    if (frontier.kind !== 'finalize' || frontier.operation !== cut.runSpec.operation || run.status !== 'queued' || run.resultRef || run.terminalReason || run.terminalDetailRef)
      throw new TypeError('result has an unsupported finalize cut');
    const historical = await readFinalizationData(driver, artifacts, cut, basis, frontier.verificationClosureRef,
      frontier.operation === 'delivery' ? frontier.deliveryTerminalProjectionEvidenceRef : undefined, delivery);
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
  const historical = await readFinalizationData(driver, artifacts, cut, basis, result.verificationClosureRef, result.deliveryTerminalProjectionEvidenceRef, delivery);
  const expected: RunResult = { schemaVersion: 1, runId: run.id, baseSourceRef: basis.candidate.baseSourceRef,
    resultSourceRef: basis.candidate.resultSourceRef, diffRef: basis.candidate.diffRef,
    verificationClosureRef: result.verificationClosureRef, verificationReceiptRefs: basis.verificationReceiptRefs, summaryRef: basis.candidate.summaryRef, createdAt: result.createdAt,
    ...(historical.closure.dependency.kind !== 'none' ? { dependencyPlanRef: historical.closure.dependency.dependencyPlanRef } : {}),
    ...(cut.runSpec.operation === 'delivery' ? { deliveryTerminalProjectionEvidenceRef: result.deliveryTerminalProjectionEvidenceRef } : {}),
    ...(historical.closure.verification.kind === 'inherited_verified' ? { verificationProvenanceRef: historical.closure.verification.inheritedProvenanceRef } : {}) };
  requireEqual(result, expected, 'terminal immutable RunResult');
  assertRunResultPreparationTime(cut.runSpec.operation, result.createdAt, historical.checkpoint.createdAt,
    run.updatedAt, historical.projectionObservedAt);
  const checkpoint = cut.latestCheckpoint;
  if (checkpoint.id !== runResultCheckpointId(run.id, basis.candidate.itemId, run.resultRef) || checkpoint.runId !== run.id ||
      checkpoint.basedOnRunRevision !== run.revision - 1 || checkpoint.basedOnRunRevision !== historical.checkpoint.basedOnRunRevision + 1 ||
      checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== cut.items.length || checkpoint.journalSeq !== cut.journal.length ||
      checkpoint.contextManifestRef !== historical.checkpoint.contextManifestRef || checkpoint.workspaceStateRef !== historical.checkpoint.workspaceStateRef ||
      checkpoint.createdAt !== run.updatedAt || run.updatedAt >= run.deadlineAt)
    throw new TypeError('terminal RunResult has no exact atomic Checkpoint');
  if (run.parentRunId) {
    const child = await readChildAdmission(driver, artifacts, run.id), allocation = child.allocation;
    if (allocation.state === 'reserved' || allocation.terminalAt !== run.updatedAt ||
        allocation.terminal.status !== run.status || !('resultRef' in allocation.terminal) ||
        allocation.terminal.resultRef !== run.resultRef || canonicalSha256(allocation.inclusiveBudgetUsage) !== canonicalSha256(run.budgetConsumed))
      throw new TypeError('terminal child result has no same-transaction incoming allocation effect');
    if (driver.prepare('SELECT 1 FROM items WHERE item_id = ?').get(identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id)))
      throw new TypeError('child result cannot append a root Session terminal');
    return;
  }
  const admitted = decodeAdmittedContext(await readCanonicalArtifact(artifacts, cut.runSpec.admittedContextRef));
  const terminal: SessionRunTerminalItem = { schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
    itemKey: `run-terminal:${run.id}`, runId: run.id, operation: cut.runSpec.operation, admittedSessionItemSeq: admitted.throughSessionItemSeq,
    status: basis.status, terminalReason: basis.terminalReason, resultRef: run.resultRef,
    summaryRef: result.summaryRef, summaryDigest: basis.summary.textDigest };
  const itemId = identityHash('cliq-session-run-terminal-item-v1', run.sessionId, run.id);
  const row = driver.prepare('SELECT session_id, run_id, item_seq, kind, payload_ref, created_at FROM items WHERE item_id = ?')
    .get<{ session_id: string; run_id: string | null; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(itemId);
  if (!row || row.session_id !== run.sessionId || row.run_id !== null || row.kind !== 'run_terminal' || row.created_at !== run.updatedAt ||
      row.payload_ref !== canonicalSha256(terminal)) throw new TypeError('terminal result has no atomic root Session item');
  requireEqual(await readCanonicalArtifact(artifacts, row.payload_ref), terminal, 'terminal result Session payload');
  await assertSessionTerminalProjection(driver, artifacts, run.sessionId, { itemSeq: Number(row.item_seq), itemId, payloadRef: row.payload_ref });
}
