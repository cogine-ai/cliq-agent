import { canonicalSha256 } from '../kernel/canonical.js';
import { decodePublicationLateObservationItem, publicationLateObservationCheckpointId,
  type PublicationLateObservationItem } from '../kernel/publication.js';
import type { Checkpoint, RecoveryClosureV1, Run, RunItemReferenceV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readOwnedPublicationProof, readPublicationInspector, readPublicationPathCheckpoint, readPublicationPathRetirement,
  validateCompletedReceipt, validatePublicationPlannedDescendant, validateRetirementReceipt,
  type RetainedPublicationOperation } from './delivery-publication-progress.js';
import { readPublicationActualPreimage } from './publication-actual-preimage.js';
import { decodePublicationPathWait } from './publication-reconciliation-artifacts.js';
import { validatePublicationProbeWait } from './publication-reconciliation-history.js';
import type { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { readCheckpoint } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

/** Necessary one-item data equations, not native observation or permission.
 * The writer first authenticates its original opaque producer and SQL cut. */
export function projectPublicationLateObservation(cut: Pick<RecoveryClosureV1, 'run' | 'latestCheckpoint' | 'items' | 'journal'>,
  value: PublicationLateObservationItem, checkpoint: Checkpoint, run: Run) {
  const item = decodePublicationLateObservationItem(value), ref = canonicalSha256(item), previous = cut.latestCheckpoint;
  const unknown = cut.journal.find(row => row.phase === 'unknown' && row.opId === item.opId && row.attempt === item.attempt);
  if (!unknown || !unknown.budgetSettlementRef || cut.run.status !== 'waiting' || cut.run.waitingReason !== 'reconciliation' ||
      cut.run.waitingOnRef !== item.probeWaitingSubjectRef || cut.run.nextStep !== 'delivery' || item.runId !== cut.run.id ||
      previous.runItemSeq !== cut.items.length || checkpoint.id !== publicationLateObservationCheckpointId(item.runId, item.opId,
        item.attempt, item.probeDispatchDigest, item.evidenceRef) || checkpoint.runId !== item.runId || checkpoint.schemaVersion !== 1 ||
      checkpoint.reason !== 'auto' || checkpoint.basedOnRunRevision !== cut.run.revision || checkpoint.runItemSeq !== cut.items.length + 1 ||
      checkpoint.journalSeq !== cut.journal.length || checkpoint.workspaceStateRef !== previous.workspaceStateRef ||
      checkpoint.contextManifestRef === previous.contextManifestRef || checkpoint.createdAt < item.createdAt ||
      checkpoint.createdAt < cut.run.updatedAt || checkpoint.createdAt < previous.createdAt)
    throw new TypeError('late audit changed its original wait, Journal, W_M or one excluded-control Checkpoint');
  requireEqual(run, { ...cut.run, latestCheckpointId: checkpoint.id, revision: cut.run.revision + 1, updatedAt: checkpoint.createdAt },
    'late audit cannot change status, nonce, frontier or once-only accounting');
  return { run: immutableSnapshot(run), latestCheckpoint: immutableSnapshot(checkpoint), items: [...cut.items,
    { schemaVersion: 1 as const, itemId: item.itemId, itemSeq: checkpoint.runItemSeq, payloadRef: ref, payloadDigest: ref, createdAt: item.createdAt }] };
}

/** Retained audit only. An expired fact never supplies a current probe result,
 * native owner, cleanup permission or replacement for the original UNKNOWN. */
export async function readPublicationLateObservation(driver: SqliteDriver, artifacts: ArtifactCatalog,
  admission: Awaited<ReturnType<typeof readDeliveryRunAdmission>>, cut: RecoveryClosureV1,
  entry: RetainedPublicationOperation, entries: ReadonlyMap<string, RetainedPublicationOperation>, row: RunItemReferenceV1, previous: Checkpoint) {
  const item = decodePublicationLateObservationItem(await readCanonicalArtifact(artifacts, row.payloadRef));
  const claim = entry.claim, unknown = entry.history.find(value => value.phase === 'unknown');
  if (!claim || !entry.birth || !unknown?.budgetSettlementRef || item.runId !== cut.run.id || item.itemId !== row.itemId ||
      item.createdAt !== row.createdAt || row.payloadDigest !== row.payloadRef || item.opId !== claim.opId || item.attempt !== claim.attempt ||
      item.dispatchId !== claim.dispatchId || item.claimJournalSeq !== claim.seq || item.deliveryPlanRef !== entry.planRef ||
      item.sequence !== entry.sequence || item.operationId !== entry.operation.operationId || item.operationIndex !== entry.operation.index ||
      row.itemSeq !== previous.runItemSeq + 1 || entry.result?.item.outcome !== 'unknown' || entry.receivedHandoff)
    throw new TypeError('late audit lost its original unresolved claim, row or ordered prefix');
  const wait = decodePublicationPathWait(await readCanonicalArtifact(artifacts, item.probeWaitingSubjectRef));
  await validatePublicationProbeWait(driver, artifacts, cut, admission, entry, wait);
  const state = wait.probeState;
  if (state.phase !== 'automatic_in_flight' && state.phase !== 'user_in_flight' || state.dispatch.subjectKind !== 'publication' ||
      state.dispatch.dispatchDigest !== item.probeDispatchDigest)
    throw new TypeError('late audit substituted its original persisted probe nonce');
  const proof = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, item.evidenceRef, claim);
  const inspector = await readPublicationInspector(driver, artifacts, admission, proof);
  if (proof.proofDigest !== item.evidenceDigest || item.completedAt <= state.dispatch.probeDeadlineAt || proof.observedAt > item.completedAt ||
      proof.observedAt < state.dispatch.probeStartedAt ||
      inspector.owner.supervisorInstanceId !== state.dispatch.owningSupervisorInstanceId || inspector.owner.acquiredAt > state.dispatch.probeStartedAt ||
      inspector.owner.state === 'terminal' && item.completedAt > inspector.owner.releasedAt)
    throw new TypeError('late audit is not the original expired task observation');
  if (item.disposition === 'received' ? proof.kind !== 'terminal_receipt' : item.disposition === 'unknown' ? proof.kind !== 'path_ambiguity' :
      item.disposition === 'stopped_before_effect' ? proof.kind !== 'path_observation' : proof.kind !== 'planned_descendant')
    throw new TypeError('late audit changed the actual producer disposition');
  if (proof.kind === 'terminal_receipt' || proof.kind === 'path_ambiguity') {
    if (proof.sequence !== entry.sequence || proof.operationId !== entry.operation.operationId || proof.operationIndex !== entry.operation.index ||
        proof.opId !== claim.opId || proof.attempt !== claim.attempt || proof.kind === 'path_ambiguity' && proof.launchDispatchId !== claim.dispatchId)
      throw new TypeError('late audit evidence belongs to a different original operation');
  } else if (proof.kind === 'path_observation') {
    if (proof.observation.location.kind !== 'workspace' || proof.observation.location.path !== entry.operation.path)
      throw new TypeError('late no-effect observation names a different destination');
  } else if (proof.kind === 'planned_descendant' && proof.abortOperationId !== entry.operation.operationId)
    throw new TypeError('late planned descendant names a different maintenance operation');
  if (proof.kind === 'terminal_receipt') await validateCompletedReceipt(driver, artifacts, admission, entry, entries, proof, item.createdAt);
  if (proof.kind === 'planned_descendant') await validatePublicationPlannedDescendant(driver, artifacts, admission, entry, entries, proof);
  if (proof.kind === 'path_ambiguity') await readPublicationActualPreimage(artifacts, proof, { operation: entry.operation, birth: entry.birth, claim });
  const retirement = item.disposition === 'unknown' ? undefined : await readPublicationPathRetirement(driver, artifacts, admission,
    entry, item.retirement, item.createdAt, item.createdAt);
  if (retirement?.kind === 'current_namespace' &&
      [retirement.namespaceEvidence.proof, retirement.destinationEvidence.proof].some(observation => observation.observedAt < state.dispatch.probeStartedAt))
    throw new TypeError('late namespace audit substituted a prior-probe fact');
  if (retirement && retirement.latestObservedAt > item.completedAt)
    throw new TypeError('late audit changed its actual received retirement');
  if (retirement && proof.kind === 'terminal_receipt' && item.retirement)
    validateRetirementReceipt(proof, item.retirement, retirement);
  const checkpoint = readCheckpoint(driver, publicationLateObservationCheckpointId(item.runId, item.opId, item.attempt,
    item.probeDispatchDigest, item.evidenceRef));
  if (inspector.owner.state === 'terminal' && checkpoint.createdAt > inspector.owner.releasedAt)
    throw new TypeError('late audit Checkpoint was not committed in its original inspector lifetime');
  await readPublicationPathCheckpoint(artifacts, cut, checkpoint, previous, [{ row, item }], unknown.seq);
  return { item, row, proof, wait, retirement, checkpoint };
}
