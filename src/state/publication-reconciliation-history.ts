import { canonicalSha256 } from '../kernel/canonical.js';
import { addCanonicalDuration, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodePublicationArenaBirth, type PublicationArenaBirthV1 } from '../kernel/publication.js';
import type { InvocationJournalEntry, RecoveryClosureV1, ReconciliationProbeEvidenceV1, SupervisorInspectorIdentityV1 } from '../kernel/types.js';
import type { PublicationInspectionTargetV1, PublicationPathWait } from '../kernel/reconciliation.js';
import { decodeInstalledControlEnvelope, decodeInstalledControlRequest } from '../kernel/control-wire.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeBudgetSettlement, decodeRunSpec, decodeStateLockIdentity } from './decoders.js';
import { decodePublicationInspectionTarget, decodePublicationPathWait, decodePublicationProbeClosure,
  decodePublicationProbeEvidence, decodePublicationRecoveryOrigin } from './publication-reconciliation-artifacts.js';
import type { RetainedPublicationOperation } from './delivery-publication-progress.js';
import type { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { readCheckpoint, readControlRequest, readRun, readSessionPrincipalId } from './rows.js';
import { readHistoricalControlChannel } from './control-channel.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readStateOwnerDeath } from './state-owner-death.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { WORKER_PROBE_BACKOFF_MS } from './worker-recovery.js';

type Admission = Awaited<ReturnType<typeof readDeliveryRunAdmission>>;
type OriginProof = { recoveryOriginRef?: string; recoveryOriginDigest?: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string };

/** Complete retained current-inspector provenance for one old claim. Returning
 * these immutable records is not a live observation, native owner or permit to
 * reopen/release/clean a path. The actual producer separately owns those. */
export async function readPublicationRecoveryOrigin(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  claim: InvocationJournalEntry, birth: PublicationArenaBirthV1, proof: OriginProof) {
  const run = readRun(driver, admission.run.id), spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  if (spec.operation !== 'delivery' || canonicalSha256(spec) !== canonicalSha256(admission.spec))
    throw new TypeError('publication recovery requires its original Delivery RunSpec');
  requireEqual(run, admission.run, 'publication recovery same retained Run cut');
  const actualClaim = readInvocationAttempt(driver, run.id, claim.opId, claim.attempt).find(row => row.phase === 'dispatch_claimed');
  if (!actualClaim || claim.phase !== 'dispatch_claimed' || claim.opKind !== 'publish' || !claim.supervisorInstanceId ||
      !claim.stateOwnerEpoch || !claim.dispatchId || !claim.evidenceRef || !claim.evidenceDigest ||
      !proof.recoveryOriginRef || !proof.recoveryOriginDigest)
    throw new TypeError('publication recovery has no original permanent claim or exact provenance pair');
  requireEqual(actualClaim, claim, 'publication recovery original durable dispatch');
  const actualBirth = decodePublicationArenaBirth(await readCanonicalArtifact(artifacts, claim.evidenceRef));
  requireEqual(actualBirth, birth, 'publication recovery original native arena birth');
  const origin = decodePublicationRecoveryOrigin(await readCanonicalArtifact(artifacts, proof.recoveryOriginRef));
  if (origin.originDigest !== proof.recoveryOriginDigest || origin.deliveryRunId !== run.id ||
      origin.deliveryPlanRef !== birth.deliveryPlanRef || origin.opId !== claim.opId || origin.attempt !== claim.attempt ||
      origin.dispatchId !== claim.dispatchId || origin.claimJournalSeq !== claim.seq || origin.arenaBirthRef !== claim.evidenceRef ||
      origin.arenaBirthDigest !== claim.evidenceDigest || birth.birthDigest !== claim.evidenceDigest ||
      birth.dispatchId !== claim.dispatchId || birth.opId !== claim.opId || birth.attempt !== claim.attempt ||
      birth.deliveryRunId !== run.id || birth.workspaceIdentityRef !== admission.target.workspaceIdentityRef ||
      birth.workspaceIdentityDigest !== admission.target.workspaceIdentityDigest ||
      origin.inspectorIdentityRef !== proof.inspectorIdentityRef || origin.inspectorIdentityDigest !== proof.inspectorIdentityDigest ||
      origin.observedAt < claim.timestamp || proof.observedAt < origin.observedAt)
    throw new TypeError('publication recovery substituted the original claim, birth or current observation');
  const retainedInspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, origin.inspectorIdentityRef);
  const owner = readStateOwner(driver, retainedInspector.stateOwnerEpoch);
  if (!owner || owner.ownerEpoch <= claim.stateOwnerEpoch || origin.observedAt < owner.acquiredAt ||
      owner.state === 'terminal' && proof.observedAt > owner.releasedAt)
    throw new TypeError('publication recovery requires actual original owner death and a strictly newer inspector lifetime');
  let priorOwner;
  if (origin.gracefulOwnerDeath) {
    const history = await readRetainedStateOwnerHistory(driver, artifacts, owner.ownerEpoch);
    const claiming = history.entries.find(entry => entry.owner.ownerEpoch === claim.stateOwnerEpoch);
    const inspecting = history.entries.find(entry => entry.owner.ownerEpoch === owner.ownerEpoch);
    const death = origin.gracefulOwnerDeath;
    if (!claiming || !inspecting || claiming.owner.state !== 'terminal' || claiming.owner.terminalReason !== 'graceful_release' ||
        claiming.owner.supervisorInstanceId !== claim.supervisorInstanceId || claim.timestamp < claiming.owner.acquiredAt ||
        claim.timestamp > claiming.owner.releasedAt || origin.observedAt < claiming.owner.releasedAt ||
        death.priorOwnerRowDigest !== claiming.owner.rowDigest || death.priorProcessIdentityRef !== claiming.owner.processIdentityRef ||
        death.priorProcessIdentityDigest !== claiming.owner.processIdentityDigest ||
        death.gracefulTransitionEvidenceRef !== claiming.owner.transitionEvidenceRef ||
        death.gracefulTransitionEvidenceDigest !== claiming.owner.transitionEvidenceDigest || claiming.transition?.kind !== 'graceful_release')
      throw new TypeError('publication graceful owner death lost its exact original process and released history');
    requireEqual(inspecting.owner, owner, 'publication graceful-death recorded inspector');
    history.assertUnchanged(driver);
    priorOwner = claiming.owner;
  } else {
    const death = await readStateOwnerDeath(artifacts, driver, { supervisorInstanceId: claim.supervisorInstanceId, ownedAt: claim.timestamp });
    if (death.priorOwner.ownerEpoch !== claim.stateOwnerEpoch || owner.ownerEpoch < death.successorOwner.ownerEpoch ||
        origin.ownerDeathAcquisitionEvidenceRef !== death.acquisitionEvidenceRef ||
        origin.ownerDeathAcquisitionEvidenceDigest !== death.acquisitionEvidenceDigest || origin.observedAt < death.successorOwner.acquiredAt)
      throw new TypeError('publication recovery requires actual original owner death and a strictly newer inspector lifetime');
    priorOwner = death.priorOwner;
  }
  parseCanonicalTime(proof.observedAt);
  const inspector = await readSupervisorInspector(artifacts, owner, admission.source.assembly, proof);
  const lock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, owner.stateLockIdentityRef));
  const originalLock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, priorOwner.stateLockIdentityRef));
  if (lock.stateRootIdentityRef !== originalLock.stateRootIdentityRef || lock.stateRootIdentityDigest !== originalLock.stateRootIdentityDigest ||
      birth.stateRootIdentityRef !== originalLock.stateRootIdentityRef || birth.stateRootIdentityDigest !== originalLock.stateRootIdentityDigest)
    throw new TypeError('publication recovery changed the original StateRoot or lock ownership');
  const birthInspector = await readSupervisorInspector(artifacts, priorOwner, admission.source.assembly, birth);
  if (birthInspector.stateOwnerEpoch !== claim.stateOwnerEpoch || birthInspector.supervisorInstanceId !== claim.supervisorInstanceId ||
      birth.observedAt > claim.timestamp || birth.observedAt > priorOwner.releasedAt)
    throw new TypeError('publication recovery birth is not from its original claimed native owner');
  return immutableSnapshot({ origin, owner, inspector, lock, priorOwner });
}

/** Original public enqueue source; the post-enqueue response never substitutes
 * today's wait, channel, revision, or a caller-selected probe target. */
export async function readPublicationUserProbeSource(driver: SqliteDriver, artifacts: ArtifactCatalog,
  cut: Pick<RecoveryClosureV1, 'run'>, wait: PublicationPathWait) {
  if (wait.probeState.phase !== 'user_in_flight') throw new TypeError('publication user probe has no actual enqueued wait');
  const dispatch = wait.probeState.dispatch, principalId = readSessionPrincipalId(driver, cut.run.sessionId);
  if (dispatch.subjectKind !== 'publication') throw new TypeError('publication public enqueue substituted another subject');
  const row = readControlRequest(driver, principalId, 'run.reconcile', dispatch.controlRequestId);
  if (!row || row.requestDigest !== dispatch.controlRequestDigest) throw new TypeError('publication user probe lost its authenticated enqueue');
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, dispatch.controlRequestDigest);
  const request = decodeInstalledControlRequest({ ...core, requestDigest: dispatch.controlRequestDigest });
  const response = decodeInstalledControlEnvelope(await readCanonicalArtifact(artifacts, row.responseRef), 'run.reconcile');
  if (request.method !== 'run.reconcile' || request.runId !== cut.run.id || request.requestId !== dispatch.controlRequestId || !response.ok ||
      response.result.method !== 'run.reconcile' || response.result.resolution.kind !== 'probe_enqueued')
    throw new TypeError('publication user probe substituted its original request or response');
  const snapshot = response.result.snapshot, enqueued = snapshot.run;
  if (snapshot.operation !== 'delivery' || enqueued.id !== cut.run.id || enqueued.sessionId !== cut.run.sessionId ||
      enqueued.specRef !== cut.run.specRef || enqueued.createdAt !== cut.run.createdAt || enqueued.deadlineAt !== cut.run.deadlineAt ||
      enqueued.revision !== request.expectedRevision + 1 || enqueued.revision > cut.run.revision ||
      enqueued.status !== 'waiting' || enqueued.waitingReason !== 'reconciliation' || enqueued.waitingOnRef !== canonicalSha256(wait) ||
      request.waitingOnRef !== dispatch.previousWaitingSubjectRef ||
      snapshot.latestRunItemSeq !== readCheckpoint(driver, enqueued.latestCheckpointId).runItemSeq ||
      enqueued.updatedAt !== row.committedAt || row.committedAt < dispatch.probeStartedAt || row.committedAt >= dispatch.probeDeadlineAt ||
      response.result.resolution.dispatchDigest !== dispatch.dispatchDigest || response.result.resolution.userProbeCount !== wait.probeState.userProbeCount)
    throw new TypeError('publication user probe changed its durable enqueue snapshot');
  const previous = decodePublicationPathWait(await readCanonicalArtifact(artifacts, request.waitingOnRef));
  if (previous.probeState.phase !== 'automatic_exhausted' || previous.probeState.userProbeCount + 1 !== wait.probeState.userProbeCount)
    throw new TypeError('publication user probe did not enqueue from its exact exhausted predecessor');
  requireEqual({ ...previous, probeState: wait.probeState }, wait, 'publication user probe original immutable subject');
  const { channel } = await readHistoricalControlChannel(driver, artifacts, { principalId,
    channelIdentityRef: row.channelIdentityRef, channelIdentityDigest: row.channelIdentityDigest });
  if (channel.openedAt > row.committedAt) throw new TypeError('publication user probe channel postdates its original request');
  return { row, request, response, previous };
}

/** Validate the exact known observation wrapped by one persisted descriptor-
 * only probe. This is retained data; the producer still needs its true opaque
 * result, actual resources, and original SQL cut before it can commit anything. */
export async function readPublicationReconciliationEvidence(driver: SqliteDriver, artifacts: ArtifactCatalog, input: {
  cut: RecoveryClosureV1; admission: Admission; entry: RetainedPublicationOperation; ref: string; digest: string;
}) {
  const { cut, admission, entry } = input, claim = entry.claim, unknown = entry.history.find(row => row.phase === 'unknown');
  if (!claim || !entry.birth || !unknown?.budgetSettlementRef || !unknown.evidenceRef || !unknown.evidenceDigest)
    throw new TypeError('publication reconciliation has no one original charged unknown claim');
  requireEqual(readRun(driver, cut.run.id), cut.run, 'publication probe same actual Run');
  const wrapper = decodePublicationProbeEvidence(await readCanonicalArtifact(artifacts, input.ref));
  if (wrapper.outcome !== 'subject_observation' || wrapper.subjectEvidenceKind !== 'publication' ||
      !exactKeys(wrapper, ['schemaVersion', 'format', 'runId', 'waitingSubjectRef', 'waitingSubjectDigest', 'probeKind', 'probeOrdinal',
        'probeNonceDigest', 'probeDispatchDigest', 'probeStartedAt', 'probeDeadlineAt', 'inspectorIdentityRef', 'inspectorIdentityDigest',
        'observedAt', 'evidenceDigest', 'outcome', 'subjectEvidenceKind', 'subjectEvidenceRef', 'subjectEvidenceDigest']) ||
      wrapper.schemaVersion !== 1 || wrapper.format !== 'cliq-reconciliation-probe-evidence-v1' || wrapper.runId !== cut.run.id ||
      wrapper.waitingSubjectRef !== wrapper.waitingSubjectDigest || wrapper.evidenceDigest !== input.digest ||
      wrapper.evidenceDigest !== digestOmitting(wrapper, 'evidenceDigest'))
    throw new TypeError('publication reconciliation replaced its exact original probe wrapper');
  const wait = decodePublicationPathWait(await readCanonicalArtifact(artifacts, wrapper.waitingSubjectRef));
  const state = wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight')
    throw new TypeError('publication reconciliation observation has no persisted in-flight task');
  const dispatch = state.dispatch;
  if (dispatch.subjectKind !== 'publication') throw new TypeError('publication probe substituted another inspection target');
  await validatePublicationProbeWait(driver, artifacts, cut, admission, entry, wait);
  if (wait.runId !== cut.run.id || wait.createdFromRevision >= cut.run.revision || wait.createdAt < unknown.timestamp ||
      wait.frontierRef !== entry.request.frontierRef || wait.subject.deliveryPlanRef !== entry.planRef ||
      wait.subject.pathOperationId !== entry.operation.operationId || wait.subject.attempt !== claim.attempt)
    throw new TypeError('publication reconciliation changed its original waiting subject or frontier');
  requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(dispatch)), dispatch, 'publication persisted probe dispatch');
  const target = decodePublicationInspectionTarget(await readCanonicalArtifact(artifacts, dispatch.inspectionTargetDigest));
  requireEqual(target.subject, wait.subject, 'publication frozen inspection subject');
  if (target.runId !== cut.run.id || target.preparedJournalSeq !== entry.prepared.seq || target.claimJournalSeq !== claim.seq ||
      target.unknownJournalSeq !== unknown.seq || target.unknownEvidenceRef !== unknown.evidenceRef ||
      target.unknownBudgetSettlementRef !== unknown.budgetSettlementRef)
    throw new TypeError('publication inspection target substituted its original Journal or accounting');
  for (const row of [entry.prepared, claim, unknown])
    requireEqual(cut.journal.find(actual => actual.seq === row.seq), row, 'publication original probe Journal cut');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef));
  if (settlement.runId !== cut.run.id || settlement.opId !== claim.opId || settlement.attempt !== claim.attempt ||
      settlement.preparedJournalSeq !== entry.prepared.seq || settlement.terminalJournalSeq !== unknown.seq ||
      settlement.terminalPhase !== 'unknown' || settlement.settledAt !== unknown.timestamp)
    throw new TypeError('publication probe changed its original once-only settlement');
  requireEqual(settlement.consumed, unknown.budgetDelta, 'publication original conservative UNKNOWN charge');
  if (target.progress) {
    if (!entry.progress || entry.progress.row.payloadRef !== target.progress.itemRef ||
        target.progress.checkpointId !== identityHash('cliq-publication-progress-checkpoint-v1', cut.run.id, claim.opId, String(claim.attempt)) ||
        readCheckpoint(driver, target.progress.checkpointId).createdAt > wait.createdAt)
      throw new TypeError('publication probe lost its original durable pre-cleanup barrier');
  }
  if (state.phase === 'user_in_flight') await readPublicationUserProbeSource(driver, artifacts, cut, wait);
  const { readOwnedPublicationProof } = await import('./delivery-publication-progress.js');
  const proof = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, wrapper.subjectEvidenceRef, claim);
  if (entry.lateObservations.some(audit => audit.item.evidenceRef === wrapper.subjectEvidenceRef))
    throw new TypeError('a late audit fact cannot be borrowed as another probe nonce observation');
  if (proof.proofDigest !== wrapper.subjectEvidenceDigest || proof.inspectorIdentityRef !== wrapper.inspectorIdentityRef ||
      proof.inspectorIdentityDigest !== wrapper.inspectorIdentityDigest || proof.observedAt !== wrapper.observedAt ||
      proof.observedAt < dispatch.probeStartedAt || proof.observedAt > dispatch.probeDeadlineAt)
    throw new TypeError('publication observation arrived outside its exact task, inspector or deadline');
  const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, proof.inspectorIdentityRef);
  if (inspector.supervisorInstanceId !== dispatch.owningSupervisorInstanceId || wrapper.probeKind !== dispatch.probeKind ||
      wrapper.probeOrdinal !== dispatch.probeOrdinal || wrapper.probeNonceDigest !== dispatch.probeNonceDigest ||
      wrapper.probeDispatchDigest !== dispatch.dispatchDigest || wrapper.probeStartedAt !== dispatch.probeStartedAt ||
      wrapper.probeDeadlineAt !== dispatch.probeDeadlineAt)
    throw new TypeError('publication observation cannot adopt another owner or closed nonce');
  if (!['terminal_receipt', 'path_observation', 'path_ambiguity', 'planned_descendant'].includes(proof.kind))
    throw new TypeError('publication probe cannot substitute a cleanup or aggregate proof for its actual path observation');
  if ('recoveryOriginRef' in proof && proof.kind !== 'path_ambiguity') {
    if (!target.progress || !entry.progress) throw new TypeError('successor publication cleanup has no original durable progress');
    const destination = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, entry.progress.item.destinationEvidenceRef, claim);
    if ('recoveryOriginRef' in destination) throw new TypeError('successor publication cleanup cannot mint its own prerequisite progress');
  }
  if (proof.kind === 'terminal_receipt' && proof.namespaceRetirementEvidenceRef !== undefined) {
    const namespace = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, proof.namespaceRetirementEvidenceRef, claim);
    if (namespace.kind !== 'arena_namespace_absence') throw new TypeError('namespace receipt has no actual namespace retirement');
    const destination = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, namespace.destinationObservationRef, claim);
    if (destination.kind !== 'path_observation') throw new TypeError('namespace retirement has no fresh desired path observation');
    for (const observation of [namespace, destination]) if (observation.observedAt < dispatch.probeStartedAt ||
        observation.observedAt > proof.observedAt || observation.inspectorIdentityRef !== proof.inspectorIdentityRef ||
        observation.inspectorIdentityDigest !== proof.inspectorIdentityDigest || observation.recoveryOriginRef !== proof.recoveryOriginRef ||
        observation.recoveryOriginDigest !== proof.recoveryOriginDigest)
      throw new TypeError('namespace revalidation cannot borrow a late or prior-probe fact');
  }
  return { wrapper, wait, target, dispatch, proof, unknown, settlement };
}

/** The exact original inspection target, independent of any eventual probe
 * result. Native setup consumes this before its first descriptor I/O. */
export async function readPublicationProbeTarget(artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  entry: RetainedPublicationOperation, frozen?: PublicationInspectionTargetV1) {
  const claim = entry.claim, unknown = entry.history.find(value => value.phase === 'unknown');
  if (!claim || !entry.birth || !unknown?.budgetSettlementRef || !unknown.evidenceRef ||
      entry.history.filter(value => value.phase === 'unknown').length !== 1)
    throw new TypeError('publication inspection requires its one original charged UNKNOWN');
  for (const row of [entry.prepared, claim, unknown])
    requireEqual(cut.journal.find(value => value.seq === row.seq), row, 'publication inspection original actual Journal');
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, unknown.budgetSettlementRef));
  if (settlement.runId !== cut.run.id || settlement.opId !== claim.opId || settlement.attempt !== claim.attempt ||
      settlement.preparedJournalSeq !== entry.prepared.seq || settlement.terminalJournalSeq !== unknown.seq ||
      settlement.terminalPhase !== 'unknown' || settlement.settledAt !== unknown.timestamp)
    throw new TypeError('publication inspection has no original once-only UNKNOWN BudgetSettlement');
  requireEqual(settlement.consumed, unknown.budgetDelta, 'publication original UNKNOWN accounting');
  const target = decodePublicationInspectionTarget({ schemaVersion: 1, format: 'cliq-publication-inspection-target-v1', runId: cut.run.id,
    subject: { kind: 'publication_path', deliveryPlanRef: entry.planRef, pathOperationId: entry.operation.operationId, attempt: claim.attempt },
    preparedJournalSeq: entry.prepared.seq, claimJournalSeq: claim.seq, unknownJournalSeq: unknown.seq,
    unknownEvidenceRef: unknown.evidenceRef, unknownBudgetSettlementRef: unknown.budgetSettlementRef,
    ...(frozen ? frozen.progress ? { progress: frozen.progress } : {} : entry.progress ? { progress: { itemRef: entry.progress.row.payloadRef,
      checkpointId: identityHash('cliq-publication-progress-checkpoint-v1', cut.run.id, claim.opId, String(claim.attempt)) } } : {}) });
  if (frozen) {
    requireEqual(frozen, target, 'publication fixed original inspection target');
    if (frozen.progress && (!entry.progress || frozen.progress.itemRef !== entry.progress.row.payloadRef ||
        frozen.progress.checkpointId !== identityHash('cliq-publication-progress-checkpoint-v1', cut.run.id, claim.opId, String(claim.attempt))))
      throw new TypeError('publication frozen target substituted its actual original durable progress');
  }
  return { target, unknown, settlement };
}

/** Iterative original-wait chain. Every dispatch references the actual
 * predecessor pending/exhausted wait; every closed wait references that exact
 * in-flight nonce. No event cache, CAS enumeration or new ledger is involved. */
export async function validatePublicationProbeWait(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  admission: Admission, entry: RetainedPublicationOperation, input: PublicationPathWait): Promise<void> {
  const { target, unknown } = await readPublicationProbeTarget(artifacts, cut, entry);
  let wait = input;
  const visited = new Set<string>();
  const { readOwnedPublicationProof, readPublicationInspector } = await import('./delivery-publication-progress.js');
  while (true) {
    artifacts.assertReadActive();
    const ref = canonicalSha256(wait);
    if (visited.has(ref)) throw new TypeError('publication probe wait history is cyclic');
    visited.add(ref);
    if (wait.runId !== cut.run.id || wait.frontierRef !== entry.request.frontierRef || wait.createdAt < unknown.timestamp ||
        wait.createdFromRevision >= cut.run.revision || wait.createdAt > cut.run.updatedAt)
      throw new TypeError('publication probe wait changed its original Run, frontier or lifetime');
    requireEqual(wait.subject, target.subject, 'publication probe original fixed subject');
    const state = wait.probeState;
    if (state.phase === 'automatic_pending' && state.automaticProbeCount === 0) return;
    if (state.phase === 'automatic_in_flight' || state.phase === 'user_in_flight') {
      const dispatch = state.dispatch;
      if (dispatch.subjectKind !== 'publication') throw new TypeError('publication probe has another subject target');
      requireEqual(await readCanonicalArtifact(artifacts, canonicalSha256(dispatch)), dispatch, 'publication original persisted dispatch');
      const frozen = decodePublicationInspectionTarget(await readCanonicalArtifact(artifacts, dispatch.inspectionTargetDigest));
      await readPublicationProbeTarget(artifacts, cut, entry, frozen);
      if (frozen.progress && readCheckpoint(driver, frozen.progress.checkpointId).createdAt > dispatch.probeStartedAt)
        throw new TypeError('publication frozen probe target names a later progress checkpoint');
      const previous = decodePublicationPathWait(await readCanonicalArtifact(artifacts, dispatch.previousWaitingSubjectRef));
      requireEqual({ ...previous, probeState: state }, wait, 'publication exact dispatch predecessor subject');
      if (state.phase === 'automatic_in_flight') {
        if (previous.probeState.phase !== 'automatic_pending' || previous.probeState.automaticProbeCount + 1 !== state.automaticProbeCount ||
            dispatch.probeStartedAt < previous.probeState.nextProbeAt)
          throw new TypeError('publication automatic dispatch skipped its exact ordinal or backoff');
      } else {
        await readPublicationUserProbeSource(driver, artifacts, cut, wait);
        if (previous.probeState.phase !== 'automatic_exhausted' || previous.probeState.userProbeCount + 1 !== state.userProbeCount)
          throw new TypeError('publication user dispatch skipped its exact exhausted predecessor');
      }
      wait = previous; continue;
    }
    if (state.phase !== 'automatic_pending' && state.phase !== 'automatic_exhausted')
      throw new TypeError('publication probe has no supported closed state');
    const wrapper = decodePublicationProbeEvidence(await readCanonicalArtifact(artifacts, state.lastProbeEvidenceRef!));
    const prior = decodePublicationPathWait(await readCanonicalArtifact(artifacts, wrapper.waitingSubjectRef));
    const priorState = prior.probeState;
    requireEqual({ ...prior, probeState: state }, wait, 'publication exact closed probe subject');
    if (priorState.phase !== 'automatic_in_flight' && priorState.phase !== 'user_in_flight')
      throw new TypeError('publication closed probe has no original in-flight nonce');
    const dispatch = priorState.dispatch;
    if (dispatch.subjectKind !== 'publication' || wrapper.evidenceDigest !== state.lastProbeEvidenceDigest ||
        wrapper.probeKind !== dispatch.probeKind || wrapper.probeOrdinal !== dispatch.probeOrdinal ||
        wrapper.probeNonceDigest !== dispatch.probeNonceDigest || wrapper.probeDispatchDigest !== dispatch.dispatchDigest ||
        wrapper.probeStartedAt !== dispatch.probeStartedAt || wrapper.probeDeadlineAt !== dispatch.probeDeadlineAt ||
        priorState.automaticProbeCount !== state.automaticProbeCount || priorState.userProbeCount !== state.userProbeCount ||
        wrapper.observedAt > cut.run.updatedAt ||
        state.phase === 'automatic_pending' && state.nextProbeAt !== addCanonicalDuration(wrapper.observedAt,
          WORKER_PROBE_BACKOFF_MS[state.automaticProbeCount - 1]!))
      throw new TypeError('publication closed probe changed its exact nonce, time or bounded schedule');
    if (wrapper.outcome === 'subject_observation') {
      const proof = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, wrapper.subjectEvidenceRef, entry.claim);
      if (proof.kind !== 'path_ambiguity' || proof.proofDigest !== wrapper.subjectEvidenceDigest || proof.observedAt !== wrapper.observedAt ||
          proof.inspectorIdentityRef !== wrapper.inspectorIdentityRef || proof.inspectorIdentityDigest !== wrapper.inspectorIdentityDigest)
        throw new TypeError('publication closed wait cannot hide an actual known receipt or unrelated observation');
      const inspector = await readCanonicalArtifact<SupervisorInspectorIdentityV1>(artifacts, proof.inspectorIdentityRef);
      if (inspector.supervisorInstanceId !== dispatch.owningSupervisorInstanceId)
        throw new TypeError('publication unresolved observation cannot adopt another owner nonce');
    } else {
      const cancellation = wrapper.outcome === 'probe_cancelled';
      const closure = decodePublicationProbeClosure(await readCanonicalArtifact(artifacts,
        cancellation ? wrapper.cancellationClosureRef : wrapper.timeoutClosureRef));
      const inspected = await readPublicationInspector(driver, artifacts, admission, wrapper);
      const pair = { inspectorIdentityRef: wrapper.inspectorIdentityRef, inspectorIdentityDigest: wrapper.inspectorIdentityDigest };
      const common = { schemaVersion: 1, runId: cut.run.id, waitingSubjectRef: wrapper.waitingSubjectRef,
        probeKind: dispatch.probeKind, probeOrdinal: dispatch.probeOrdinal, probeNonceDigest: dispatch.probeNonceDigest,
        probeDispatchDigest: dispatch.dispatchDigest, probeDeadlineAt: dispatch.probeDeadlineAt, ...pair, closedAt: wrapper.observedAt,
        subjectKind: 'publication', deliveryPlanRef: wait.subject.deliveryPlanRef, pathOperationId: wait.subject.pathOperationId,
        attempt: wait.subject.attempt, inspectorTaskId: dispatch.inspectorTaskId };
      if (closure.taskClosure.closureKind === 'cancelled_and_joined') {
        if (inspected.owner.supervisorInstanceId !== dispatch.owningSupervisorInstanceId || dispatch.probeStartedAt < inspected.owner.acquiredAt)
          throw new TypeError('only the original task owner may attest actual cancellation and join');
      } else {
        const death = await readStateOwnerDeath(artifacts, driver,
          { supervisorInstanceId: dispatch.owningSupervisorInstanceId, ownedAt: dispatch.probeStartedAt });
        if (inspected.owner.ownerEpoch < death.successorOwner.ownerEpoch || wrapper.observedAt < death.successorOwner.acquiredAt ||
            closure.taskClosure.ownerDeathAcquisitionEvidenceRef !== death.acquisitionEvidenceRef ||
            closure.taskClosure.ownerDeathAcquisitionEvidenceDigest !== death.acquisitionEvidenceDigest)
          throw new TypeError('publication timeout has no actual original probe-owner death');
      }
      requireEqual(closure, { ...common, format: cancellation ? 'cliq-reconciliation-probe-cancellation-closure-v1' :
        'cliq-reconciliation-probe-timeout-closure-v1', closureDigest: cancellation ? wrapper.cancellationClosureDigest : wrapper.timeoutClosureDigest,
        taskClosure: closure.taskClosure, ...(cancellation ? { reason: 'owning_supervisor_shutdown' } : {}) }, 'publication exact actual task closure');
    }
    wait = prior;
  }
}
