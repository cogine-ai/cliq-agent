import { canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeDeliveryCaptureTopology, decodePublicationArenaBirth, decodePublicationDirectoryPreimage, decodePublicationPathProgressItem, decodePublicationPreparationClosure,
  decodePublicationLateObservationItem, decodePublicationPathResultItem, decodePublicationProof, publicationDirectoryIdentityDigest, publicationLocationKey,
  type PublicationAbortOperation, type PublicationArenaBirthV1, type PublicationLocationV1, type PublicationOperation, type PublicationPathObservationV1,
  type PublicationPathRetirementV1, type PublicationPreparationClosureV1, type PublicationProofV1 } from '../kernel/publication.js';
import type { Checkpoint, ContinuationItem, InvocationJournalEntry, RecoveryClosureV1, RunItemReferenceV1 } from '../kernel/types.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { contextSourceDigest, validateContextItems } from '../runtime/context-compaction.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeBudgetSettlement, decodeContextManifest, decodeRunSpec, decodeStateLockIdentity,
  decodeStateRootIdentity, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence } from './decoders.js';
import { readDeliveryAuthorization } from './delivery-approval.js';
import { validatePublicationInvocationHistory } from './delivery-publication-authority.js';
import { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { createDeliveryReadData } from './delivery-read-data.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readCheckpoint, readRun, ZERO_BUDGET } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { readSupervisorInspector } from './supervisor-inspector.js';
import { readPublicationActualPreimage } from './publication-actual-preimage.js';
import { validateRetainedWorkerSeal } from './tool-checkpoint.js';
import { readPublicationReconciliationEvidence, readPublicationRecoveryOrigin } from './publication-reconciliation-history.js';
import { readRetiredGenerationSource } from './generation-retirement.js';
import { validateRetainedWorkerQuarantines } from './worker-recovery.js';
import type { PublicationGenerationResourcesV1 } from '../kernel/publication.js';

export const publicationProgressItemId = (runId: string, opId: string, attempt: number) =>
  identityHash('cliq-publication-progress-item-v1', runId, opId, String(attempt));
export const publicationProgressCheckpointId = (runId: string, opId: string, attempt: number) =>
  identityHash('cliq-publication-progress-checkpoint-v1', runId, opId, String(attempt));
export const publicationReceivedHandoffItemId = (runId: string, opId: string) =>
  identityHash('cliq-publication-received-handoff-item-v1', runId, opId, '0');
export const deliveryPublicationTerminalCheckpointId = (runId: string, planRef: string) =>
  identityHash('cliq-delivery-publication-terminal-checkpoint-v1', runId, planRef);
export const publicationResultItemId = (runId: string, opId: string, attempt: number, evidenceRef: string) =>
  identityHash('cliq-publication-result-item-v1', runId, opId, String(attempt), evidenceRef);
export const publicationResultCheckpointId = (runId: string, opId: string, attempt: number, evidenceRef: string) =>
  identityHash('cliq-publication-result-checkpoint-v1', runId, opId, String(attempt), evidenceRef);
// The genuine M seal must bind its intended checkpoint before the later fresh
// root projection exists. Exact projection authority is a retained SQL edge,
// not a digest encoded in this stable lifecycle identity.
export const deliveryPublicationCheckpointId = (runId: string, planRef: string) =>
  identityHash('cliq-delivery-publication-checkpoint-v1', runId, planRef);

/** A caller's structurally valid RecoveryClosure is not the owning SQL cut. */
export async function assertPublicationReadCut(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'delivery') throw new TypeError('publication requires a delivery Run');
  requireEqual(decodeRunSpec(await readCanonicalArtifact(artifacts, cut.run.specRef)), cut.runSpec, 'publication exact original RunSpec');
  requireEqual(readRun(driver, cut.run.id), cut.run, 'publication exact owning Run');
  requireEqual(readCheckpoint(driver, cut.run.latestCheckpointId), cut.latestCheckpoint, 'publication exact current Checkpoint');
  requireEqual(readInvocationJournal(driver, cut.run.id), cut.journal, 'publication exact Journal cut');
  const rows = driver.prepare('SELECT item_id,item_seq,payload_ref,created_at FROM items WHERE run_id=? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; payload_ref: string; created_at: string }>(cut.run.id);
  requireEqual(rows.map(row => ({ schemaVersion: 1, itemId: row.item_id, itemSeq: Number(row.item_seq), payloadRef: row.payload_ref,
    payloadDigest: row.payload_ref, createdAt: row.created_at })), cut.items, 'publication exact item cut');
  requireEqual(readWorkerLaunchesForRun(driver, cut.run.id).filter(row => row.phase !== 'retired'), cut.workerLaunches,
    'publication exact current WorkerLaunch cut');
  requireEqual(readWorkspaceGenerationsForRun(driver, cut.run.id), cut.workspaceGenerations, 'publication exact generation cut');
  if (cut.childAllocations.length || driver.prepare('SELECT 1 FROM child_allocations WHERE parent_run_id=? OR child_run_id=? LIMIT 1')
    .get(cut.run.id, cut.run.id) || driver.prepare('SELECT 1 FROM runs WHERE parent_run_id=? LIMIT 1').get(cut.run.id))
    throw new TypeError('publication cannot acquire child authority');
}

type Preparation = Awaited<ReturnType<typeof validatePublicationInvocationHistory>> extends Map<string, infer Value> ? Value : never;
type Admission = Awaited<ReturnType<typeof readDeliveryRunAdmission>>;
type OwnedItem<T extends ContinuationItem> = { row: RunItemReferenceV1; item: T };
type Progress = OwnedItem<Extract<ContinuationItem, { kind: 'publication_path_progress'; state: 'desired_committed_cleanup_pending' }>>;
type ReceivedHandoff = OwnedItem<Extract<ContinuationItem, { kind: 'publication_path_progress'; state: 'received_handoff' }>>;
type Result = OwnedItem<Extract<ContinuationItem, { kind: 'publication_path_result' }>>;

export type RetainedPublicationOperation = Omit<Preparation, 'operation'> & {
  operation: PublicationOperation | PublicationAbortOperation;
  birth?: PublicationArenaBirthV1; progress?: Progress; result?: Result; results: Result[]; checkpoint?: Checkpoint;
  receivedHandoff?: ReceivedHandoff;
  lateObservations: Array<OwnedItem<Extract<ContinuationItem, { kind: 'publication_late_observation' }>>>;
  /** Scheduling fact derived only after the complete retained handoff graph. */
  pendingReceivedHandoff: boolean;
  preparationClosure?: { closure: PublicationPreparationClosureV1; closureRef: string; terminal: InvocationJournalEntry };
};

/** Every component belongs to an actual original claim, never an unstarted
 * plan entry or a guessed directory recovered by matching a pathname/hash. */
export function publicationEnvelopeLocations(entry: Pick<RetainedPublicationOperation, 'birth' | 'operation'>): PublicationLocationV1[] {
  if (!entry.birth) return [];
  const operation = entry.operation;
  const components = operation.kind === 'abort_rmdir' ? [operation.quarantineName] : operation.kind === 'mkdir' ? ['desired'] :
    operation.kind === 'create' ? [operation.stagingName] : operation.kind === 'replace'
      ? [operation.stagingName, operation.quarantineName] : [operation.quarantineName];
  return components.map(component => ({ kind: 'publication_arena' as const, arenaId: entry.birth!.arenaId, component }))
    .sort((left, right) => Buffer.compare(Buffer.from(publicationLocationKey(left)), Buffer.from(publicationLocationKey(right))));
}

export async function readPublicationInspector(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  proof: { inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string }, claim?: InvocationJournalEntry) {
  const selected = await readCanonicalArtifact<{ stateOwnerEpoch: number }>(artifacts, proof.inspectorIdentityRef);
  const owner = readStateOwner(driver, selected.stateOwnerEpoch), observed = parseCanonicalTime(proof.observedAt);
  if (!owner || observed < parseCanonicalTime(owner.acquiredAt) ||
      owner.state === 'terminal' && observed > parseCanonicalTime(owner.releasedAt) || claim &&
      (owner.ownerEpoch !== claim.stateOwnerEpoch || owner.supervisorInstanceId !== claim.supervisorInstanceId ||
        proof.observedAt < claim.timestamp))
    throw new TypeError('publication observation lost its original owning StateOwner lifetime');
  const inspector = await readSupervisorInspector(artifacts, owner, admission.source.assembly, proof);
  const lock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, owner.stateLockIdentityRef));
  const originalOwner = readStateOwner(driver, admission.inspection.stateOwnerEpoch);
  if (!originalOwner) throw new TypeError('publication lost its original source-inspection owner');
  const originalLock = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, originalOwner.stateLockIdentityRef));
  if (lock.stateRootIdentityRef !== originalLock.stateRootIdentityRef || lock.stateRootIdentityDigest !== originalLock.stateRootIdentityDigest)
    throw new TypeError('publication observation belongs to a different original StateRoot');
  return { owner, inspector, lock };
}

async function readBirth(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission, entry: Preparation) {
  const claim = entry.claim;
  if (!claim) return undefined;
  if (!claim.evidenceRef || !claim.evidenceDigest) throw new TypeError('publication claim has no original native arena birth');
  const birth = decodePublicationArenaBirth(await readCanonicalArtifact(artifacts, claim.evidenceRef));
  const { lock } = await readPublicationInspector(driver, artifacts, admission, birth);
  const root = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, birth.stateRootIdentityRef));
  const captured = admission.inspection.outcome;
  if (captured.kind !== 'captured') throw new TypeError('publication birth lost its actual original workspace capture');
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(artifacts, captured.captureTopologyRef));
  if (birth.deliveryRunId !== admission.run.id || birth.deliveryPlanRef !== entry.planRef || birth.sequence !== entry.sequence ||
      birth.operationIndex !== entry.operation.index || birth.operationId !== entry.operation.operationId || birth.opId !== claim.opId ||
      birth.attempt !== claim.attempt || birth.dispatchId !== claim.dispatchId || birth.birthDigest !== claim.evidenceDigest ||
      birth.workspaceIdentityRef !== admission.target.workspaceIdentityRef || birth.workspaceIdentityDigest !== admission.target.workspaceIdentityDigest ||
      birth.stateRootIdentityRef !== lock.stateRootIdentityRef || birth.stateRootIdentityDigest !== lock.stateRootIdentityDigest ||
      birth.observedAt < entry.prepared.timestamp || birth.observedAt > claim.timestamp ||
      parseCanonicalTime(claim.timestamp) - parseCanonicalTime(birth.observedAt) > 5000 ||
      root.identityDigest !== birth.stateRootIdentityDigest || birth.arenaIdentity.deviceId !== root.deviceId ||
      birth.arenaIdentity.ownerUid !== root.ownerUid || birth.parentIdentity.ownerUid !== root.ownerUid ||
      birth.arenaIdentity.deviceId !== topology.rootIdentity.deviceId)
    throw new TypeError('publication birth does not close its exact original claim, StateRoot and captured workspace');
  const inspector = await readCanonicalArtifact<{ stateOwnerEpoch: number; supervisorInstanceId: string }>(artifacts, birth.inspectorIdentityRef);
  if (inspector.stateOwnerEpoch !== claim.stateOwnerEpoch || inspector.supervisorInstanceId !== claim.supervisorInstanceId)
    throw new TypeError('publication arena birth substituted its original native owner');
  return birth;
}

export async function readOwnedPublicationProof(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  planRef: string, ref: string, claim?: InvocationJournalEntry): Promise<PublicationProofV1> {
  const proof = decodePublicationProof(await readCanonicalArtifact(artifacts, ref));
  if (proof.deliveryRunId !== admission.run.id || proof.deliveryPlanRef !== planRef ||
      proof.workspaceIdentityRef !== admission.target.workspaceIdentityRef || proof.workspaceIdentityDigest !== admission.target.workspaceIdentityDigest)
    throw new TypeError('publication proof substituted its owning Run, Plan or original captured root');
  if ('recoveryOriginRef' in proof) {
    if (!claim?.evidenceRef || !claim.evidenceDigest) throw new TypeError('current-inspector publication proof has no exact original claim');
    const birth = decodePublicationArenaBirth(await readCanonicalArtifact(artifacts, claim.evidenceRef!));
    await readPublicationRecoveryOrigin(driver, artifacts, admission, claim, birth, proof);
  } else await readPublicationInspector(driver, artifacts, admission, proof, claim);
  return proof;
}

function slotObservation(entry: RetainedPublicationOperation, observation: PublicationPathObservationV1) {
  if (!entry.birth || !publicationEnvelopeLocations(entry).some(location => publicationLocationKey(location) === publicationLocationKey(observation.location)) ||
      observation.parentDeviceId !== entry.birth.arenaIdentity.deviceId || observation.parentFileId !== entry.birth.arenaIdentity.fileId)
    throw new TypeError('publication slot does not belong to its original native arena birth');
}

async function preserve(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission, entry: RetainedPublicationOperation,
  entries: ReadonlyMap<string, RetainedPublicationOperation>, preserved: string | undefined, actualBefore?: PublicationPathObservationV1) {
  const operation = entry.operation;
  const created = operation.kind === 'abort_rmdir' ? await readAbortCreator(driver, artifacts, admission, entry, entries) : undefined;
  const expected = created ? { ...created.state, empty: true as const } : operation.kind === 'abort_rmdir' ? undefined : operation.expected;
  if (!expected) throw new TypeError('publication abort lost its actual completed directory creator');
  if (expected.kind === 'absent') {
    if (preserved !== undefined) throw new TypeError('publication created path has an unrelated preserved preimage');
    return;
  }
  if (!preserved) throw new TypeError('publication discarded its actual displaced preimage');
  if (expected.kind !== 'directory') {
    if (preserved !== expected.digest) throw new TypeError('publication preimage is not its actual displaced bytes');
    const size = expected.kind === 'symlink' ? Buffer.byteLength(expected.target) :
      (await artifacts.describe(preserved, 'application/octet-stream', 'cliq-workspace-file-v1')).byteLength;
    for await (const _ of artifacts.readChunks(preserved, size)) { /* full original CAS hash/close */ }
    return;
  }
  const directory = decodePublicationDirectoryPreimage(await readCanonicalArtifact(artifacts, preserved));
  if (directory.deliveryRunId !== admission.run.id || directory.deliveryPlanRef !== entry.planRef ||
      directory.operationId !== operation.operationId || directory.opId !== entry.prepared.opId || directory.attempt !== entry.prepared.attempt)
    throw new TypeError('publication directory preimage has a different original operation');
  const before = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, directory.beforeObservationRef, entry.claim);
  const quarantined = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, directory.quarantineObservationRef, entry.claim);
  if (before.kind !== 'path_observation' || quarantined.kind !== 'path_observation') throw new TypeError('directory preimage lacks exact descriptor observations');
  if (before.observation.location.kind !== 'workspace' || before.observation.location.path !== operation.path ||
      quarantined.observation.location.kind !== 'publication_arena' ||
      !('quarantineName' in operation) || quarantined.observation.location.component !== operation.quarantineName)
    throw new TypeError('publication directory preimage substituted its original workspace or quarantine slot');
  if (actualBefore) requireEqual(before.observation, actualBefore, 'publication original empty-directory preimage');
  requireEqual(before.observation.state, expected, 'publication original planned empty-directory preimage');
  if (created && (before.observation.entryDeviceId !== created.entryDeviceId || before.observation.entryFileId !== created.entryFileId))
    throw new TypeError('publication abort preimage replaced its actual original created directory');
  slotObservation(entry, quarantined.observation);
  requireEqual(quarantined.observation.state, expected, 'publication actual preserved empty directory state');
  if (quarantined.observation.state.kind !== 'directory' || !quarantined.observation.state.empty ||
      quarantined.observation.entryDeviceId !== before.observation.entryDeviceId || quarantined.observation.entryFileId !== before.observation.entryFileId)
    throw new TypeError('publication preserved a substituted or nonempty directory');
  const manifest = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, directory.entriesRef));
  if (manifest.entries.length || manifest.entryCount || manifest.byteCount) throw new TypeError('publication empty-directory preimage contains children');
}

/** Immutable evidence of this original claim's completed retirement. It is
 * not a current native owner, a lookup by arena name, or cleanup permission. */
async function readResultRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  entry: RetainedPublicationOperation, result: Result['item'], terminal: InvocationJournalEntry, evidence: PublicationProofV1, probeDeadlineAt?: string) {
  if (result.outcome === 'unknown' || result.outcome === 'not_created') {
    if (result.retirement !== undefined) throw new TypeError('unresolved or unclaimed publication cannot assert retired resources');
    return;
  }
  const { claim, birth } = entry;
  if (!claim || !birth) throw new TypeError('publication retirement has no exact original claim and arena birth');
  const retirement = result.retirement;
  if (!retirement) throw new TypeError('known claimed publication lost its durable original retirement edge');
  const retired = await readRetirementGraph(driver, artifacts, admission, entry, birth, retirement, result.createdAt, terminal.timestamp, claim);
  if (probeDeadlineAt !== undefined && retired.latestObservedAt > probeDeadlineAt)
    throw new TypeError('publication actual joined retirement completed after its original probe deadline');
  if (evidence.kind === 'terminal_receipt') {
    validateRetirementReceipt(evidence, retirement, retired);
  }
}

export function validateRetirementReceipt(evidence: Extract<PublicationProofV1, { kind: 'terminal_receipt' }>,
  retirement: PublicationPathRetirementV1, retired: Awaited<ReturnType<typeof readRetirementGraph>>) {
  if (retired.kind === 'descriptor') {
    if ('kind' in retirement || evidence.transientFinalObservations === undefined)
      throw new TypeError('original descriptor retirement cannot borrow namespace evidence');
    requireEqual(evidence.transientFinalObservations, retired.slotObservations.map(slot => slot.proof.observation),
      'publication receipt exact durable original slot observations');
  } else {
    if (!('kind' in retirement) || evidence.namespaceRetirementEvidenceRef !== retirement.namespaceEvidenceRef ||
        evidence.recoveryOriginRef !== retired.namespaceEvidence.proof.recoveryOriginRef ||
        evidence.recoveryOriginDigest !== retired.namespaceEvidence.proof.recoveryOriginDigest ||
        evidence.inspectorIdentityRef !== retired.namespaceEvidence.proof.inspectorIdentityRef ||
        evidence.inspectorIdentityDigest !== retired.namespaceEvidence.proof.inspectorIdentityDigest)
      throw new TypeError('namespace receipt lost its exact fresh namespace retirement');
    requireEqual(evidence.after, retired.destinationEvidence.proof.observation, 'namespace receipt actual current destination');
  }
  if (retired.latestObservedAt > evidence.observedAt)
    throw new TypeError('publication receipt preceded its actual retirement');
}

/** Full retained evidence only, never an original FD owner or cleanup permit.
 * The namespace branch deliberately returns no fabricated old slot or unlink. */
export async function readPublicationPathRetirement(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  entry: Pick<RetainedPublicationOperation, 'prepared' | 'planRef' | 'operation' | 'progress' | 'birth' | 'claim'>,
  retirement: PublicationPathRetirementV1, closedAt: string, terminalAt: string, claim = entry.claim) {
  if (!entry.birth || !claim) throw new TypeError('retirement lost its original claimed native birth');
  return readRetirementGraph(driver, artifacts, admission, entry, entry.birth, retirement, closedAt, terminalAt, claim);
}

async function readRetirementGraph(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  entry: Pick<RetainedPublicationOperation, 'prepared' | 'planRef' | 'operation' | 'progress'>, birth: PublicationArenaBirthV1,
  retirement: PublicationPathRetirementV1, closedAt: string, terminalAt: string, claim?: InvocationJournalEntry) {
  const locations = publicationEnvelopeLocations({ ...entry, birth });
  if ('kind' in retirement) {
    if (!claim || !entry.progress) throw new TypeError('namespace retirement requires its original claim and durable progress');
    const namespace = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, retirement.namespaceEvidenceRef, claim);
    if (namespace.kind !== 'arena_namespace_absence' || namespace.arenaId !== birth.arenaId ||
        namespace.stateRootIdentityRef !== birth.stateRootIdentityRef || namespace.stateRootIdentityDigest !== birth.stateRootIdentityDigest ||
        namespace.observedAt < birth.observedAt || namespace.observedAt > terminalAt || namespace.observedAt > closedAt)
      throw new TypeError('namespace retirement changed its original birth, StateRoot or closing order');
    requireEqual(namespace.registeredArenaIdentity, birth.arenaIdentity, 'namespace original registered arena, not a held old FD');
    requireEqual(namespace.namespaceParentIdentity, birth.parentIdentity, 'namespace actual original private parent identity');
    requireEqual(namespace.coveredLocations, locations, 'namespace covers all and only original claimed slots');
    const checkpoint = readCheckpoint(driver, publicationProgressCheckpointId(entry.prepared.runId, entry.prepared.opId, entry.prepared.attempt));
    if (namespace.observedAt < checkpoint.createdAt) throw new TypeError('namespace maintenance preceded durable progress');
    const destination = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, namespace.destinationObservationRef, claim);
    const original = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, entry.progress.item.destinationEvidenceRef, claim);
    if (destination.kind !== 'path_observation' || original.kind !== 'path_observation' ||
        destination.recoveryOriginRef !== namespace.recoveryOriginRef || destination.recoveryOriginDigest !== namespace.recoveryOriginDigest ||
        destination.inspectorIdentityRef !== namespace.inspectorIdentityRef || destination.inspectorIdentityDigest !== namespace.inspectorIdentityDigest ||
        destination.observedAt < checkpoint.createdAt || destination.observedAt > namespace.observedAt ||
        destination.observation.location.kind !== 'workspace' || destination.observation.location.path !== entry.operation.path)
      throw new TypeError('namespace retirement lost its fresh original-inode desired observation');
    // Parent nlink may change as other planned children are published. The
    // original desired leaf inode/state and descriptor parent must not change.
    for (const key of ['location', 'state', 'parentDeviceId', 'parentFileId', 'entryDeviceId', 'entryFileId', 'entryLinkCount'] as const)
      requireEqual(destination.observation[key], original.observation[key], 'namespace same original desired leaf and parent');
    if (destination.observation.state.kind === 'file' && destination.observation.entryLinkCount !== 1)
      throw new TypeError('namespace desired file is multiply linked');
    return { kind: 'current_namespace' as const,
      namespaceEvidence: { ref: retirement.namespaceEvidenceRef, proof: namespace },
      destinationEvidence: { ref: namespace.destinationObservationRef, proof: destination }, latestObservedAt: namespace.observedAt };
  }
  if (retirement.slotObservationRefs.length !== locations.length)
    throw new TypeError('publication retirement lost an original private slot');
  const arena = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, retirement.arenaRetirementRef, claim);
  if (arena.kind !== 'arena_retirement' || arena.arenaId !== birth.arenaId ||
      arena.stateRootIdentityRef !== birth.stateRootIdentityRef || arena.stateRootIdentityDigest !== birth.stateRootIdentityDigest ||
      arena.observedAt < birth.observedAt || arena.observedAt > terminalAt || arena.observedAt > closedAt)
    throw new TypeError('publication result substituted its original native arena retirement or settlement order');
  const recovered = 'recoveryOriginRef' in arena;
  if (recovered ? !entry.progress : arena.inspectorIdentityRef !== birth.inspectorIdentityRef || arena.inspectorIdentityDigest !== birth.inspectorIdentityDigest)
    throw new TypeError('publication retirement lost its original owner or durable pre-cleanup barrier');
  requireEqual(arena.arenaIdentity, birth.arenaIdentity, 'publication result original retired arena identity');
  requireEqual(arena.parentIdentity, birth.parentIdentity, 'publication result original private arena parent');
  const stateRoot = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, birth.stateRootIdentityRef));
  if (arena.retirementObservation.kind !== (stateRoot.platform === 'linux' ? 'linux_unlinked' : 'darwin_unlinked'))
    throw new TypeError('publication result retired its original arena using a different platform observation');
  const slotObservations: Array<{ ref: string; proof: Extract<PublicationProofV1, { kind: 'path_observation' }> }> = [];
  const cleanupBarrier = entry.progress
    ? readCheckpoint(driver, publicationProgressCheckpointId(entry.prepared.runId, entry.prepared.opId, entry.prepared.attempt)).createdAt : undefined;
  for (let index = 0; index < locations.length; index++) {
    const slot = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, retirement.slotObservationRefs[index]!, claim);
    if (slot.kind !== 'path_observation' || slot.observation.state.kind !== 'absent' ||
        slot.inspectorIdentityRef !== arena.inspectorIdentityRef || slot.inspectorIdentityDigest !== arena.inspectorIdentityDigest ||
        ('recoveryOriginRef' in slot ? slot.recoveryOriginRef : undefined) !== (recovered ? arena.recoveryOriginRef : undefined) ||
        ('recoveryOriginDigest' in slot ? slot.recoveryOriginDigest : undefined) !== (recovered ? arena.recoveryOriginDigest : undefined) ||
        slot.observation.parentDeviceId !== birth.arenaIdentity.deviceId || slot.observation.parentFileId !== birth.arenaIdentity.fileId ||
        slot.observedAt < birth.observedAt || slot.observedAt > arena.observedAt ||
        cleanupBarrier !== undefined && slot.observedAt < cleanupBarrier)
      throw new TypeError('publication result private-slot absence lost its original owner, inode or retirement order');
    requireEqual(slot.observation.location, locations[index], 'publication result exact ordered original private slot');
    slotObservations.push({ ref: retirement.slotObservationRefs[index]!, proof: slot });
  }
  return { kind: 'descriptor' as const, slotObservations,
    arenaRetirement: { ref: retirement.arenaRetirementRef, proof: arena }, latestObservedAt: arena.observedAt };
}

async function readPreparationClosure(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission, entry: Preparation) {
  const terminal = entry.history[1], prepared = entry.prepared;
  if (entry.claim || entry.history.length !== 2 || !terminal || terminal.phase !== 'failed' || !terminal.errorRef || !terminal.budgetSettlementRef ||
      terminal.dispatchId !== undefined || terminal.supervisorInstanceId !== undefined || terminal.stateOwnerEpoch !== undefined ||
      terminal.resultRef !== undefined || terminal.evidenceRef !== undefined || terminal.evidenceDigest !== undefined || terminal.receiptRef !== undefined)
    throw new TypeError('publication preparation closure cannot substitute a dispatch or terminal observation');
  const closure = decodePublicationPreparationClosure(await readCanonicalArtifact(artifacts, terminal.errorRef));
  if (closure.deliveryRunId !== prepared.runId || closure.deliveryPlanRef !== entry.planRef || closure.sequence !== entry.sequence ||
      closure.operationIndex !== entry.operation.index || closure.operationId !== entry.operation.operationId || closure.opId !== prepared.opId ||
      closure.attempt !== prepared.attempt || closure.preparedJournalSeq !== prepared.seq || closure.requestRef !== prepared.requestRef ||
      closure.targetRef !== prepared.target || closure.grantRef !== prepared.grantRef || closure.leaseEpoch !== prepared.leaseEpoch ||
      closure.observedAt < prepared.timestamp || closure.observedAt > terminal.timestamp)
    throw new TypeError('publication preparation closure changed its original prepared envelope');
  const { owner, lock } = await readPublicationInspector(driver, artifacts, admission, closure);
  if (owner.ownerEpoch !== closure.stateOwnerEpoch || owner.supervisorInstanceId !== closure.supervisorInstanceId || owner.acquiredAt > prepared.timestamp)
    throw new TypeError('publication preparation closure has no original owning StateOwner');
  if (entry.sequence === 'forward') {
    const launches = readWorkerLaunchesForRun(driver, prepared.runId).filter(launch => launch.phase !== 'preparing' &&
      launch.leaseEpoch === prepared.leaseEpoch && launch.supervisorInstanceId === owner.supervisorInstanceId &&
      launch.activatedAt !== undefined && launch.activatedAt <= prepared.timestamp &&
      (launch.phase !== 'retired' || launch.retiredAt !== undefined && launch.retiredAt >= prepared.timestamp));
    if (launches.length !== 1) throw new TypeError('publication preparation closure lost its original activated worker lifetime');
  }
  if (closure.retirement.kind === 'retired') {
    const birth = decodePublicationArenaBirth(await readCanonicalArtifact(artifacts, closure.retirement.arenaBirthRef));
    await readPublicationInspector(driver, artifacts, admission, birth);
    const stateRoot = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, birth.stateRootIdentityRef));
    const capture = admission.inspection.outcome;
    if (capture.kind !== 'captured') throw new TypeError('preparation retirement lost its original captured workspace');
    const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(artifacts, capture.captureTopologyRef));
    if (birth.deliveryRunId !== prepared.runId || birth.deliveryPlanRef !== entry.planRef || birth.sequence !== entry.sequence ||
        birth.operationIndex !== entry.operation.index || birth.operationId !== entry.operation.operationId || birth.opId !== prepared.opId ||
        birth.attempt !== prepared.attempt || birth.dispatchId !== closure.dispatchId ||
        birth.inspectorIdentityRef !== closure.inspectorIdentityRef || birth.inspectorIdentityDigest !== closure.inspectorIdentityDigest ||
        birth.workspaceIdentityRef !== admission.target.workspaceIdentityRef || birth.workspaceIdentityDigest !== admission.target.workspaceIdentityDigest ||
        birth.stateRootIdentityRef !== lock.stateRootIdentityRef || birth.stateRootIdentityDigest !== lock.stateRootIdentityDigest ||
        birth.observedAt < prepared.timestamp || birth.observedAt > closure.observedAt ||
        stateRoot.identityDigest !== birth.stateRootIdentityDigest || birth.arenaIdentity.deviceId !== stateRoot.deviceId ||
        birth.arenaIdentity.ownerUid !== stateRoot.ownerUid || birth.parentIdentity.ownerUid !== stateRoot.ownerUid ||
        birth.arenaIdentity.deviceId !== topology.rootIdentity.deviceId)
      throw new TypeError('preparation retirement substituted its original returned native birth');
    await readRetirementGraph(driver, artifacts, admission, entry, birth, closure.retirement, closure.observedAt, terminal.timestamp);
  }
  const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, terminal.budgetSettlementRef));
  requireEqual(terminal.budgetDelta, ZERO_BUDGET, 'unclaimed publication preparation terminal charge');
  requireEqual(settlement.consumed, ZERO_BUDGET, 'unclaimed publication preparation zero consumption');
  requireEqual(settlement.reserved, prepared.budgetDelta, 'unclaimed publication preparation original reservation');
  requireEqual(settlement.released, prepared.budgetDelta, 'unclaimed publication preparation exact refund');
  if (settlement.runId !== prepared.runId || settlement.opId !== prepared.opId || settlement.attempt !== prepared.attempt ||
      settlement.preparedJournalSeq !== prepared.seq || settlement.terminalJournalSeq !== terminal.seq ||
      settlement.terminalPhase !== 'failed' || settlement.settledAt !== terminal.timestamp || terminal.seq <= prepared.seq)
    throw new TypeError('publication preparation closure changed its original once-only zero settlement');
  return { closure, closureRef: terminal.errorRef, terminal };
}

async function readAbortCreator(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission, entry: RetainedPublicationOperation,
  entries: ReadonlyMap<string, RetainedPublicationOperation>): Promise<PublicationPathObservationV1 & { state: Extract<PublicationPathObservationV1['state'], { kind: 'directory' }> }> {
  const operation = entry.operation;
  if (operation.kind !== 'abort_rmdir') throw new TypeError('publication maintenance requires its exact abort operation');
  const creator = [...entries.values()].find(value => value.sequence === 'forward' && value.operation.operationId === operation.createdByOperationId);
  if (!creator?.claim || creator.result?.item.outcome !== 'completed' || creator.planRef !== entry.planRef ||
      creator.operation.kind === 'abort_rmdir' || creator.operation.path !== operation.path || creator.operation.desired.kind !== 'directory' ||
      creator.operation.expected.kind === 'directory') throw new TypeError('publication abort lacks its actual earlier completed directory creator');
  const receipt = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, creator.result.item.receiptRef, creator.claim);
  if (receipt.kind !== 'terminal_receipt' || receipt.sequence !== 'forward' || receipt.operationId !== creator.operation.operationId ||
      receipt.operationIndex !== creator.operation.index || receipt.opId !== creator.claim.opId || receipt.attempt !== creator.claim.attempt ||
      receipt.after.location.kind !== 'workspace' || receipt.after.location.path !== operation.path || receipt.after.state.kind !== 'directory' ||
      receipt.after.entryDeviceId === undefined || receipt.after.entryFileId === undefined || receipt.after.state.mode !== creator.operation.desired.mode)
    throw new TypeError('publication abort creator lost its exact original physical directory receipt');
  return receipt.after as PublicationPathObservationV1 & { state: Extract<PublicationPathObservationV1['state'], { kind: 'directory' }> };
}

export async function readPublicationPathCheckpoint(artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  checkpoint: Checkpoint, previous: Checkpoint, added: Array<OwnedItem<ContinuationItem>>, journalSeq: number) {
  const last = added.at(-1)!;
  if (checkpoint.runId !== cut.run.id || checkpoint.reason !== 'auto' || checkpoint.runItemSeq !== last.row.itemSeq ||
      checkpoint.journalSeq !== journalSeq || checkpoint.workspaceStateRef !== previous.workspaceStateRef ||
      checkpoint.basedOnRunRevision <= previous.basedOnRunRevision || checkpoint.basedOnRunRevision >= cut.run.revision ||
      checkpoint.createdAt < last.item.createdAt || checkpoint.createdAt < previous.createdAt)
    throw new TypeError('publication item lost its exact original atomic Checkpoint');
  const context = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  const base = decodeContextManifest(await readCanonicalArtifact(artifacts, previous.contextManifestRef));
  const expected = { ...base, segments: [...base.segments, ...added.map(({ row, item }) => ({ kind: 'excluded_control' as const,
    fromItemSeq: row.itemSeq, throughItemSeq: row.itemSeq,
    sourceItemsDigest: contextSourceDigest([{ itemSeq: row.itemSeq, itemRef: row.payloadRef, item }]) }))],
    throughItemSeq: last.row.itemSeq, projectionDigest: '' };
  const { projectionDigest: _digest, ...core } = expected; expected.projectionDigest = canonicalSha256(core);
  requireEqual(context, expected, 'publication exact excluded-control context append');
  const items = [];
  for (const row of cut.items.slice(0, checkpoint.runItemSeq)) items.push({ itemSeq: row.itemSeq,
    itemRef: row.payloadRef, item: await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef) });
  validateContextItems(context, items);
}

async function readParent(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  entry: RetainedPublicationOperation, entries: ReadonlyMap<string, RetainedPublicationOperation>) {
  const selected = entry.operation;
  const operation = selected.kind === 'abort_rmdir' ? entry.plan.forwardOperations.find(value =>
    value.operationId === selected.createdByOperationId) : selected;
  if (!operation) throw new TypeError('publication abort lost its original directory creator');
  const capture = admission.inspection.outcome;
  if (capture.kind !== 'captured') throw new TypeError('publication lost its original topology capture');
  const topology = decodeDeliveryCaptureTopology(await readCanonicalArtifact(artifacts, capture.captureTopologyRef));
  if (operation.parent.kind === 'existing_directory') {
    const path = operation.path.slice(0, Math.max(0, operation.path.lastIndexOf('/')));
    const parent = path ? topology.directories.find(value => value.path === path) : topology.rootIdentity;
    if (!parent || parent.identityDigest !== operation.parent.expectedIdentityDigest)
      throw new TypeError('publication parent differs from its admitted topology');
    return parent;
  }
  const creatorId = operation.parent.createdByOperationId;
  const creator = [...entries.values()].find(value => value.sequence === 'forward' && value.operation.operationId === creatorId);
  if (creator?.result?.item.outcome !== 'completed') throw new TypeError('publication parent lacks its exact earlier completed creator');
  const receipt = await readOwnedPublicationProof(driver, artifacts, admission, creator.planRef, creator.result.item.receiptRef, creator.claim);
  if (receipt.kind !== 'terminal_receipt' || receipt.after.state.kind !== 'directory' ||
      receipt.after.entryDeviceId === undefined || receipt.after.entryFileId === undefined)
    throw new TypeError('publication created parent lost its actual birth identity');
  const identity = { deviceId: receipt.after.entryDeviceId, fileId: receipt.after.entryFileId,
    ownerUid: topology.rootIdentity.ownerUid, mode: receipt.after.state.mode };
  return { ...identity, identityDigest: publicationDirectoryIdentityDigest(admission.target.workspaceIdentityDigest, identity) };
}

export async function validateCompletedReceipt(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  entry: RetainedPublicationOperation, entries: ReadonlyMap<string, RetainedPublicationOperation>,
  proof: Extract<PublicationProofV1, { kind: 'terminal_receipt' }>, closedAt: string) {
  if (proof.sequence !== entry.sequence || proof.operationIndex !== entry.operation.index || proof.operationId !== entry.operation.operationId ||
      proof.opId !== entry.prepared.opId || proof.attempt !== entry.prepared.attempt || proof.observedAt > closedAt ||
      proof.before.location.kind !== 'workspace' || proof.before.location.path !== entry.operation.path ||
      proof.after.location.kind !== 'workspace' || proof.after.location.path !== entry.operation.path)
    throw new TypeError('publication completion is not its original operation receipt');
  if (entry.operation.kind !== 'abort_rmdir') {
    requireEqual(proof.before.state, entry.operation.expected, 'publication receipt original expected state');
    if (entry.operation.desired.kind === 'directory') {
      if (proof.after.state.kind !== 'directory' || proof.after.state.mode !== entry.operation.desired.mode)
        throw new TypeError('publication receipt lacks its desired directory');
    } else requireEqual(proof.after.state, entry.operation.desired, 'publication receipt desired state');
  } else if (proof.after.state.kind !== 'absent') throw new TypeError('publication abort completion did not remove its exact empty directory');
  if (proof.transientFinalObservations !== undefined) {
    requireEqual(proof.transientFinalObservations.map(value => value.location), publicationEnvelopeLocations(entry), 'publication exact private slot absence set');
    for (const observation of proof.transientFinalObservations) slotObservation(entry, observation);
  } else if (!entry.progress || !proof.recoveryOriginRef || !proof.recoveryOriginDigest)
    throw new TypeError('namespace receipt has no original progress and actual original-owner death');
  const parent = await readParent(driver, artifacts, admission, entry, entries);
  for (const observation of [proof.before, proof.after]) if (observation.parentDeviceId !== parent.deviceId || observation.parentFileId !== parent.fileId)
    throw new TypeError('publication receipt substituted its exact descriptor parent');
  if (proof.parentIdentityBeforeDigest !== parent.identityDigest || proof.parentIdentityAfterDigest !== parent.identityDigest ||
      proof.before.state.kind === 'file' && proof.before.entryLinkCount !== 1 || proof.after.state.kind === 'file' && proof.after.entryLinkCount !== 1)
    throw new TypeError('publication receipt changed its original parent or multiply linked a regular file');
  await preserve(driver, artifacts, admission, entry, entries, proof.preservedPreimageRef, proof.before);
  if (entry.progress && entry.progress.item.preservedPreimageRef !== proof.preservedPreimageRef)
    throw new TypeError('publication completion lost its retained actual preimage association');
  if (entry.progress) {
    const before = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, entry.progress.item.beforeObservationRef, entry.claim);
    if (before.kind !== 'path_observation' || 'recoveryOriginRef' in before || before.observedAt > proof.observedAt)
      throw new TypeError('publication completion lost its actual original pre-effect observation');
    requireEqual(proof.before, before.observation, 'publication receipt exact original durable before observation');
  }
  if ((entry.operation.kind === 'abort_rmdir' || entry.operation.expected.kind !== 'absent') && !entry.progress)
    throw new TypeError('publication deleted its preimage before the original durable progress barrier');
}

/** Retained all-and-only planned descendants; not permission to remove them. */
export async function validatePublicationPlannedDescendant(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  entry: RetainedPublicationOperation, entries: ReadonlyMap<string, RetainedPublicationOperation>,
  proof: Extract<PublicationProofV1, { kind: 'planned_descendant' }>) {
  if (entry.operation.kind !== 'abort_rmdir' || proof.abortOperationId !== entry.operation.operationId ||
      proof.retainedDescendantOperationIds.length !== proof.observationRefs.length)
    throw new TypeError('publication retained descendants do not bind their exact abort operation');
  const actual: string[] = [], paths: string[] = [];
  for (const ref of proof.observationRefs) {
    const observed = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, ref, entry.claim);
    if (observed.kind !== 'path_observation' || observed.observation.location.kind !== 'workspace' ||
        observed.observation.state.kind === 'absent' || !observed.observation.location.path.startsWith(`${entry.operation.path}/`))
      throw new TypeError('publication retained descendant lacks an actual present descriptor observation');
    const path = observed.observation.location.path;
    const original = [...entries.values()].find(value => value.sequence === 'forward' && value.operation.path === path);
    if (original?.result?.item.outcome !== 'completed' || original.operation.kind === 'abort_rmdir' || original.operation.desired.kind === 'absent')
      throw new TypeError('publication retained descendant is not an original completed desired plan path');
    const receipt = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, original.result.item.receiptRef, original.claim);
    if (receipt.kind !== 'terminal_receipt' || observed.observedAt > proof.observedAt ||
        observed.observation.entryDeviceId !== receipt.after.entryDeviceId || observed.observation.entryFileId !== receipt.after.entryFileId ||
        observed.observation.state.kind !== receipt.after.state.kind)
      throw new TypeError('publication retained descendant substituted its original completed inode');
    if (observed.observation.state.kind === 'directory' && receipt.after.state.kind === 'directory') {
      if (observed.observation.state.mode !== receipt.after.state.mode || observed.observation.state.identityDigest !== receipt.after.state.identityDigest)
        throw new TypeError('publication retained directory changed its stable original birth identity');
    } else {
      requireEqual(observed.observation.state, receipt.after.state, 'publication retained complete original leaf state');
      if (observed.observation.entryLinkCount !== receipt.after.entryLinkCount)
        throw new TypeError('publication retained leaf changed its original link count');
    }
    actual.push(original.operation.operationId); paths.push(path);
  }
  requireEqual(proof.retainedDescendantOperationIds, actual, 'publication exact retained completed descendant ids');
  if (paths.some((path, index) => index > 0 && Buffer.compare(Buffer.from(paths[index - 1]!), Buffer.from(path)) >= 0))
    throw new TypeError('publication retained descendant observations are not unique canonical paths');
  const expected = [...entries.values()].filter(value => value.sequence === 'forward' &&
    value.operation.path.startsWith(`${entry.operation.path}/`) && value.result?.item.outcome === 'completed' &&
    value.operation.kind !== 'abort_rmdir' && value.operation.desired.kind !== 'absent' &&
    ![...entries.values()].some(abort => abort.sequence === 'abort' && abort.operation.path === value.operation.path && abort.result?.item.outcome === 'completed'))
    .sort((left, right) => Buffer.compare(Buffer.from(left.operation.path), Buffer.from(right.operation.path))).map(value => value.operation.operationId);
  requireEqual(actual, expected, 'publication retained all-and-only remaining completed descendant set');
}

/** Retained resource graph only. No source Checkpoint or retired SQL row can
 * manufacture an M seal, live native owner or permission to create a worker. */
export async function readPublicationGenerationResources(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  cut: RecoveryClosureV1, entry: RetainedPublicationOperation, resources: PublicationGenerationResourcesV1,
  checkpoint: Checkpoint, observedAt: string) {
  const claim = entry.claim;
  if (!claim || entry.sequence !== 'forward') throw new TypeError('publication resources have no original productive claim');
  requireEqual(readRun(driver, cut.run.id), cut.run, 'publication resources same actual Run cut');
  requireEqual(readCheckpoint(driver, checkpoint.id), checkpoint, 'publication resources actual Checkpoint');
  const launch = readWorkerLaunchesForRun(driver, cut.run.id).find(value => value.launchId === resources.workerLaunchId);
  const generation = readWorkspaceGenerationsForRun(driver, cut.run.id).find(value => value.generationRef === resources.generationRef);
  if (!launch || !generation || launch.phase !== 'retired' || launch.retirementKind === 'preparation' ||
      launch.workspaceGenerationRef !== generation.generationRef || launch.supervisorInstanceId !== claim.supervisorInstanceId ||
      launch.leaseEpoch !== claim.leaseEpoch || !launch.activatedAt || launch.activatedAt > entry.prepared.timestamp ||
      checkpoint.runId !== cut.run.id || checkpoint.workspaceStateRef !== entry.authorization.verified.checkpoint.workspaceStateRef ||
      generation.sourceWorkspaceStateRef !== checkpoint.workspaceStateRef)
    throw new TypeError('publication resources lost their original worker, verified M or actual Checkpoint');
  parseCanonicalTime(observedAt);
  if (resources.kind === 'sealed') {
    if (generation.phase !== 'sealed' || launch.retiredAt !== checkpoint.createdAt ||
        generation.snapshotEvidenceRef !== resources.snapshotEvidenceRef)
      throw new TypeError('publication sealed resources lost their exact original snapshot');
    const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await readCanonicalArtifact(artifacts, resources.snapshotEvidenceRef));
    if (snapshot.checkpointId !== checkpoint.id || snapshot.runId !== cut.run.id || snapshot.generationRef !== generation.generationRef ||
        snapshot.workspaceStateRef !== checkpoint.workspaceStateRef || snapshot.observedAt > observedAt)
      throw new TypeError('publication resources substituted their genuine sealed M snapshot');
    await validateRetainedWorkerSeal(driver, artifacts, { run: cut.run, spec: cut.runSpec, assembly: admission.source.assembly, launch, generation });
  } else {
    if (generation.phase !== 'retired' || generation.sourceCheckpointId !== resources.sourceCheckpointId ||
        generation.retirementEvidenceRef !== resources.retirementEvidenceRef || launch.generationWriteState !== 'fenced_reconciling' ||
        generation.updatedAt > observedAt || !launch.retiredAt || launch.retiredAt > generation.updatedAt)
      throw new TypeError('publication recovered resources are not their actually retired original M');
    const sourceCheckpoint = readCheckpoint(driver, resources.sourceCheckpointId);
    if (sourceCheckpoint.runId !== cut.run.id || sourceCheckpoint.workspaceStateRef !== checkpoint.workspaceStateRef)
      throw new TypeError('publication retired resources changed the verified restorable M');
    const retained = await readRetiredGenerationSource(driver, artifacts,
      { run: cut.run, spec: cut.runSpec, assembly: admission.source.assembly, generation });
    if (retained.source.phase !== 'quarantined' || retained.source.quarantineEvidenceRef !== resources.quarantineEvidenceRef)
      throw new TypeError('publication retired resources lost their original quarantine lineage');
    await validateRetainedWorkerQuarantines(artifacts,
      { run: cut.run, journal: cut.journal, workerLaunches: [launch], workspaceGenerations: [retained.source] }, driver);
  }
  return { launch, generation };
}

async function readReceivedHandoff(driver: SqliteDriver, artifacts: ArtifactCatalog, admission: Admission,
  cut: RecoveryClosureV1, entry: RetainedPublicationOperation, entries: ReadonlyMap<string, RetainedPublicationOperation>,
  handoff: ReceivedHandoff, previous: Checkpoint) {
  const { item, row } = handoff, { claim, birth } = entry;
  const unknown = entry.history.find(value => value.phase === 'unknown');
  const reconciled = item.reconciliationEvidenceRef !== undefined;
  if (!claim || !birth || !entry.progress || entry.receivedHandoff || entry.result && entry.result.item.outcome !== 'unknown' || entry.sequence !== 'forward' ||
      entry.operation.index !== entry.plan.forwardOperations.length - 1 || item.dispatchId !== claim.dispatchId ||
      item.claimJournalSeq !== claim.seq || item.itemId !== publicationReceivedHandoffItemId(cut.run.id, item.opId) ||
      reconciled !== !!unknown || reconciled && (!entry.result || entry.result.item.outcome !== 'unknown') ||
      !reconciled && entry.history.some(value => value.seq > claim.seq && value.timestamp < item.createdAt))
    throw new TypeError('publication received handoff is not its original pending last forward claim');
  const proof = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, item.receiptRef, claim);
  if (proof.kind !== 'terminal_receipt' || proof.proofDigest !== item.receiptDigest)
    throw new TypeError('publication received handoff lost its actual original receipt');
  let probeDeadlineAt: string | undefined;
  if (reconciled) {
    const recovery = await readPublicationReconciliationEvidence(driver, artifacts,
      { cut, admission, entry, ref: item.reconciliationEvidenceRef!, digest: item.reconciliationEvidenceDigest! });
    if (recovery.wrapper.subjectEvidenceRef !== item.receiptRef || recovery.wrapper.subjectEvidenceDigest !== item.receiptDigest ||
        recovery.wrapper.observedAt > item.createdAt)
      throw new TypeError('publication recovered handoff replaced its exact probe receipt or actual receive time');
    probeDeadlineAt = recovery.dispatch.probeDeadlineAt;
  }
  await validateCompletedReceipt(driver, artifacts, admission, entry, entries, proof, item.createdAt);
  const retired = await readRetirementGraph(driver, artifacts, admission, entry, birth, item.retirement, item.createdAt, item.createdAt, claim);
  if (probeDeadlineAt !== undefined && retired.latestObservedAt > probeDeadlineAt)
    throw new TypeError('publication received handoff actual retirement missed its original probe deadline');
  validateRetirementReceipt(proof, item.retirement, retired);
  const checkpoint = readCheckpoint(driver, deliveryPublicationCheckpointId(cut.run.id, entry.planRef));
  const journalCursor = reconciled ? unknown!.seq : claim.seq;
  await readPublicationPathCheckpoint(artifacts, cut, checkpoint, previous, [handoff], journalCursor);
  if (checkpoint.runItemSeq !== row.itemSeq || entry.history.some(value => value.seq > journalCursor && value.timestamp < checkpoint.createdAt))
    throw new TypeError('publication received handoff replaced a terminal Journal or resource Checkpoint');
  await readPublicationGenerationResources(driver, artifacts, admission, cut, entry, item.generationResources, checkpoint, item.createdAt);
  return checkpoint;
}

/** Full retained prefix only, never native release/cleanup authority. Every
 * claim first closes its actual durable birth and historical owner graph. */
export async function readPublicationPrefix(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  return createDeliveryReadData(driver, artifacts, cut).prefix();
}

/** Internal data flow only. The standalone reader above never accepts it. */
export async function readPublicationPrefixData(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  data: {
    admission(): ReturnType<typeof readDeliveryRunAdmission>;
    authorization(): ReturnType<typeof readDeliveryAuthorization>;
    histories(): ReturnType<typeof validatePublicationInvocationHistory>;
    stop(ref?: string): ReturnType<typeof import('./stop-recovery.js')['readAgentStop']>;
  }) {
  await assertPublicationReadCut(driver, artifacts, cut);
  const admission = await data.admission();
  requireEqual(admission.run, cut.run, 'publication original delivery admission cut');
  const authorization = await data.authorization();
  const histories = await data.histories();
  const entries = new Map<string, RetainedPublicationOperation>();
  for (const [opId, history] of histories) {
    const phases = history.history.map(value => value.phase).join(',');
    if (!['prepared', 'prepared,failed', 'prepared,dispatch_claimed', 'prepared,dispatch_claimed,completed',
      'prepared,dispatch_claimed,failed', 'prepared,dispatch_claimed,unknown',
      'prepared,dispatch_claimed,unknown,completed', 'prepared,dispatch_claimed,unknown,failed'].includes(phases) ||
        history.claim && history.history.slice(2).some(value => value.dispatchId !== history.claim!.dispatchId ||
          value.supervisorInstanceId !== history.claim!.supervisorInstanceId || value.stateOwnerEpoch !== history.claim!.stateOwnerEpoch))
      throw new TypeError('publication history changed its original phase graph or permanent claim');
    if (history.sequence === 'abort') {
      if (history.grant.format !== 'cliq-publication-maintenance-authority-v1')
        throw new TypeError('abort prefix has no exact original maintenance authority');
      await data.stop(history.grant.subject.stopIntentRef);
    }
    entries.set(opId, { ...history, birth: await readBirth(driver, artifacts, admission, history), results: [], lateObservations: [], pendingReceivedHandoff: false,
      ...(!history.claim && phases === 'prepared,failed'
        ? { preparationClosure: await readPreparationClosure(driver, artifacts, admission, history) } : {}) });
  }
  let previous = authorization?.checkpoint;
  const resultRefs = new Set<string>();
  const abortObservations = new Map<string, { operation: PublicationAbortOperation; result: Result }>();
  for (const row of cut.items) {
    const value = await readCanonicalArtifact<ContinuationItem>(artifacts, row.payloadRef);
    if (value.kind === 'publication_late_observation') {
      const item = decodePublicationLateObservationItem(value), entry = entries.get(item.opId);
      if (!entry || !previous) throw new TypeError('late publication audit has no original claimed ordered prefix');
      const { readPublicationLateObservation } = await import('./publication-late-observation.js');
      const audit = await readPublicationLateObservation(driver, artifacts, admission, cut, entry, entries, row, previous);
      previous = audit.checkpoint; entry.lateObservations.push({ row, item: audit.item });
      // Intentionally no result/history/frontier/receivedHandoff mutation:
      // the original UNKNOWN and its budget remain the sole active outcome.
      continue;
    }
    if (value.kind !== 'publication_path_progress' && value.kind !== 'publication_path_result') continue;
    const item = value.kind === 'publication_path_progress' ? decodePublicationPathProgressItem(value) : decodePublicationPathResultItem(value);
    const entry = entries.get(item.opId);
    if (!entry && item.kind === 'publication_path_result' && item.sequence === 'abort' && item.outcome === 'not_created') {
      const operation = authorization?.context.plan.abortOperations[item.operationIndex];
      if (!operation || !previous || operation.operationId !== item.operationId || abortObservations.has(item.operationId) ||
          item.runId !== cut.run.id || item.itemId !== row.itemId || item.createdAt !== row.createdAt || row.payloadDigest !== row.payloadRef ||
          item.deliveryPlanRef !== authorization!.context.planRef || item.attempt !== 0 ||
          item.opId !== identityHash('cliq-publication-abort-observation-v1', cut.run.id, operation.operationId) ||
          item.itemId !== publicationResultItemId(cut.run.id, item.opId, 0, item.evidenceRef) || row.itemSeq !== previous.runItemSeq + 1 ||
          !cut.run.stopIntentRef || [...entries.values()].some(value => value.operation.operationId === operation.operationId ||
            value.sequence === 'forward' && value.operation.operationId === operation.createdByOperationId &&
              value.history.some(journal => journal.phase === 'completed')))
        throw new TypeError('publication absent-creator observation substituted a claim, creator or original abort operation');
      const proof = await readOwnedPublicationProof(driver, artifacts, admission, item.deliveryPlanRef, item.evidenceRef);
      const ancestor = proof.kind === 'ancestor_projection_absence'
        ? await readOwnedPublicationProof(driver, artifacts, admission, item.deliveryPlanRef, proof.ancestorObservationRef) : undefined;
      const { validatePublicationTerminalPathState } = await import('./delivery-publication-recovery.js');
      const actual = validatePublicationTerminalPathState(proof, ancestor);
      const observation = proof.kind === 'path_observation' ? proof.observation :
        ancestor?.kind === 'path_observation' ? ancestor.observation : undefined;
      const location = observation?.location;
      const original = location?.kind === 'workspace'
        ? authorization!.context.plan.forwardOperations.find(value => value.path === location.path) : undefined;
      const unchangedLeaf = original?.desired.kind === 'directory' &&
        (original.expected.kind === 'file' || original.expected.kind === 'symlink') &&
        canonicalSha256(original.expected) === canonicalSha256(observation!.state) &&
        (original.expected.kind !== 'file' || observation!.entryLinkCount === 1);
      if (actual.path !== operation.path || observation?.state.kind !== 'absent' && !unchangedLeaf || proof.observedAt > item.createdAt)
        throw new TypeError('publication not-created result lost its original absence or unchanged captured leaf');
      const creator = [...entries.values()].find(value => value.sequence === 'forward' &&
        value.operation.operationId === operation.createdByOperationId);
      // No later failure may retroactively turn a pending create into an
      // earlier not-created observation. Only its already joined preparation
      // or earlier fully settled no-effect result closes that original owner.
      const creatorTerminal = creator?.preparationClosure?.terminal ??
        (creator?.result?.item.outcome === 'failed' && !creator.progress && creator.result.row.itemSeq < row.itemSeq
          ? creator.history.at(-1) : undefined);
      if (creator && (!creatorTerminal || creatorTerminal.phase !== 'failed' || creatorTerminal.timestamp > proof.observedAt))
        throw new TypeError('publication not-created observation overlaps an unresolved original creator');
      await data.stop();
      const checkpoint = readCheckpoint(driver, publicationResultCheckpointId(cut.run.id, item.opId, 0, item.evidenceRef));
      if (checkpoint.journalSeq < previous.journalSeq || checkpoint.journalSeq > cut.journal.length ||
          creatorTerminal && creatorTerminal.seq > checkpoint.journalSeq ||
          cut.journal.slice(0, checkpoint.journalSeq).some(journal => journal.timestamp > checkpoint.createdAt))
        throw new TypeError('publication absent-creator Checkpoint replaced its original Journal prefix');
      await readPublicationPathCheckpoint(artifacts, cut, checkpoint, previous, [{ row, item }], checkpoint.journalSeq);
      abortObservations.set(operation.operationId, { operation, result: { row, item } }); resultRefs.add(row.payloadRef); previous = checkpoint;
      continue;
    }
    if (!entry?.claim || !entry.birth || !previous || item.runId !== cut.run.id || item.itemId !== row.itemId ||
        row.payloadDigest !== row.payloadRef || item.createdAt !== row.createdAt || item.createdAt < entry.claim.timestamp ||
        item.deliveryPlanRef !== entry.planRef || item.operationIndex !== entry.operation.index || item.operationId !== entry.operation.operationId ||
        item.attempt !== entry.prepared.attempt || row.itemSeq !== previous.runItemSeq + 1)
      throw new TypeError('publication item has no exact original claim, birth and contiguous prefix');
    if (item.kind === 'publication_path_progress' && item.state === 'received_handoff') {
      const handoff = { row, item };
      previous = await readReceivedHandoff(driver, artifacts, admission, cut, entry, entries, handoff, previous);
      entry.receivedHandoff = handoff;
    } else if (item.kind === 'publication_path_progress') {
      if (entry.progress || entry.result && entry.result.item.outcome !== 'unknown' || item.itemId !== publicationProgressItemId(cut.run.id, item.opId, item.attempt))
        throw new TypeError('publication progress replaced its original one-use barrier');
      const destination = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, item.destinationEvidenceRef, entry.claim);
      if (destination.kind !== 'path_observation' || destination.observation.location.kind !== 'workspace' ||
          destination.observation.location.path !== entry.operation.path)
        throw new TypeError('publication progress has a different actual destination');
      const parent = await readParent(driver, artifacts, admission, entry, entries);
      const before = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, item.beforeObservationRef, entry.claim);
      if (before.kind !== 'path_observation' || 'recoveryOriginRef' in before || before.observedAt > destination.observedAt ||
          before.observedAt > item.createdAt || before.observation.location.kind !== 'workspace' ||
          before.observation.location.path !== entry.operation.path || before.observation.parentDeviceId !== parent.deviceId ||
          before.observation.parentFileId !== parent.fileId)
        throw new TypeError('publication progress lost its original claimed pre-effect path and parent observation');
      if (entry.operation.kind !== 'abort_rmdir') requireEqual(before.observation.state, entry.operation.expected,
        'publication progress original expected raw state');
      else {
        const created = await readAbortCreator(driver, artifacts, admission, entry, entries);
        if (before.observation.state.kind !== 'directory' || !before.observation.state.empty ||
            before.observation.entryDeviceId !== created.entryDeviceId || before.observation.entryFileId !== created.entryFileId ||
            before.observation.state.mode !== created.state.mode || before.observation.state.identityDigest !== created.state.identityDigest)
          throw new TypeError('publication maintenance progress lost its actual original exact-empty creator');
      }
      if (before.observation.state.kind === 'file' && before.observation.entryLinkCount !== 1)
        throw new TypeError('publication pre-effect observation multiply linked its original regular file');
      if (destination.observation.parentDeviceId !== parent.deviceId || destination.observation.parentFileId !== parent.fileId)
        throw new TypeError('publication progress substituted its exact descriptor parent');
      if (entry.operation.kind === 'abort_rmdir') {
        if (destination.observation.state.kind !== 'absent' || !item.preservedPreimageRef || !item.transientObservationRef)
          throw new TypeError('publication abort progress lacks its actual absence and preserved original private directory');
      } else if (entry.operation.desired.kind === 'directory') {
        if (destination.observation.state.kind !== 'directory' || destination.observation.state.mode !== entry.operation.desired.mode)
          throw new TypeError('publication progress lacks its desired directory');
      } else requireEqual(destination.observation.state, entry.operation.desired, 'publication progress desired state');
      if (item.transientObservationRef) {
        const transient = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, item.transientObservationRef, entry.claim);
        if (transient.kind !== 'path_observation' || transient.observation.state.kind === 'absent')
          throw new TypeError('publication progress retained no actual pending private slot');
        slotObservation(entry, transient.observation);
        if (entry.operation.kind === 'abort_rmdir') {
          const created = await readAbortCreator(driver, artifacts, admission, entry, entries);
          requireEqual(transient.observation.state, { ...created.state, empty: true }, 'publication abort exact pending empty directory');
          if (transient.observation.entryDeviceId !== created.entryDeviceId || transient.observation.entryFileId !== created.entryFileId)
            throw new TypeError('publication abort progress substituted its actual created directory inode');
        }
      }
      await preserve(driver, artifacts, admission, entry, entries, item.preservedPreimageRef);
      entry.progress = { row, item };
      const checkpoint = readCheckpoint(driver, publicationProgressCheckpointId(cut.run.id, item.opId, item.attempt));
      const retainedPhase = entry.history.find(value => value.seq === checkpoint.journalSeq);
      if (!retainedPhase || !['dispatch_claimed', 'unknown'].includes(retainedPhase.phase) || retainedPhase.timestamp > checkpoint.createdAt)
        throw new TypeError('publication progress replaced its original pending Journal prefix');
      await readPublicationPathCheckpoint(artifacts, cut, checkpoint, previous, [{ row, item }], retainedPhase.seq);
      previous = checkpoint;
    } else {
      if (entry.result && entry.result.item.outcome !== 'unknown' || entry.results.some(value => value.item.evidenceRef === item.evidenceRef) ||
          item.itemId !== publicationResultItemId(cut.run.id, item.opId, item.attempt, item.evidenceRef) || item.sequence !== entry.sequence)
        throw new TypeError('publication result replaced its original one-use outcome');
      const proof = await readOwnedPublicationProof(driver, artifacts, admission, entry.planRef, item.evidenceRef, entry.claim);
      const originalUnknown = entry.history.find(value => value.phase === 'unknown');
      const paired = 'reconciliationEvidenceRef' in item ? { ref: item.reconciliationEvidenceRef, digest: item.reconciliationEvidenceDigest } : {};
      let probeDeadlineAt: string | undefined;
      if ((item.outcome === 'completed' || item.outcome === 'failed' || item.outcome === 'retained_planned_descendant') && originalUnknown) {
        if (!item.reconciliationEvidenceRef || !item.reconciliationEvidenceDigest || !entry.result || entry.result.item.outcome !== 'unknown')
          throw new TypeError('publication known result cannot erase its original UNKNOWN audit without the exact probe');
        const recovery = await readPublicationReconciliationEvidence(driver, artifacts,
          { cut, admission, entry, ref: item.reconciliationEvidenceRef, digest: item.reconciliationEvidenceDigest });
        if (recovery.wrapper.subjectEvidenceRef !== item.evidenceRef || recovery.wrapper.subjectEvidenceDigest !== proof.proofDigest ||
            recovery.wrapper.observedAt > item.createdAt)
          throw new TypeError('publication known result substituted the original observed probe outcome');
        probeDeadlineAt = recovery.dispatch.probeDeadlineAt;
      } else if (paired.ref !== undefined)
        throw new TypeError('publication result supplied a probe wrapper without its original UNKNOWN');
      if (entry.receivedHandoff && (item.outcome !== 'completed' || item.receiptRef !== entry.receivedHandoff.item.receiptRef ||
          item.evidenceRef !== entry.receivedHandoff.item.receiptRef || proof.proofDigest !== entry.receivedHandoff.item.receiptDigest))
        throw new TypeError('publication result reinterpreted its original durably received receipt');
      if (entry.receivedHandoff) requireEqual(item.retirement, entry.receivedHandoff.item.retirement,
        'publication result exact original handoff retirement');
      if (entry.receivedHandoff) requireEqual(
        paired,
        { ref: entry.receivedHandoff.item.reconciliationEvidenceRef, digest: entry.receivedHandoff.item.reconciliationEvidenceDigest },
        'publication result exact original received probe association');
      const terminal = entry.history.find(value => value.phase === (item.outcome === 'completed' ? 'completed' : item.outcome === 'unknown' ? 'unknown' : 'failed') &&
        value.evidenceRef === item.evidenceRef);
      // Only the fully validated original-UNKNOWN probe branch writes the
      // new terminal row at SQL commit time, after preparing its fixed item.
      // Initial settlements keep their original settledAt-before-item rule.
      if (!terminal || (probeDeadlineAt === undefined ? terminal.timestamp > item.createdAt : terminal.timestamp < item.createdAt) || terminal.seq <= entry.claim.seq ||
          entry.result && (entry.result.row.itemSeq >= row.itemSeq || item.outcome === 'unknown'))
        throw new TypeError('publication result has no later original-claim terminal Journal observation');
      if (item.outcome === 'completed') {
        if (proof.kind !== 'terminal_receipt' || proof.sequence !== entry.sequence || proof.operationIndex !== entry.operation.index ||
            proof.operationId !== entry.operation.operationId || proof.opId !== item.opId || proof.attempt !== item.attempt ||
            terminal.phase !== 'completed' || terminal.receiptRef !== item.receiptRef || terminal.evidenceRef !== item.evidenceRef ||
            terminal.resultRef !== undefined && terminal.resultRef !== item.receiptRef || terminal.evidenceDigest !== proof.proofDigest || proof.observedAt > item.createdAt ||
            proof.before.location.kind !== 'workspace' || proof.before.location.path !== entry.operation.path ||
            proof.after.location.kind !== 'workspace' || proof.after.location.path !== entry.operation.path)
          throw new TypeError('publication completion is not its original Journal-backed native receipt');
        await validateCompletedReceipt(driver, artifacts, admission, entry, entries, proof, item.createdAt);
      } else if (item.outcome === 'unknown') {
        if (proof.kind !== 'path_ambiguity' || terminal.phase !== 'unknown' || proof.launchDispatchId !== entry.claim.dispatchId ||
            proof.sequence !== entry.sequence || proof.operationIndex !== item.operationIndex || proof.operationId !== item.operationId ||
            proof.opId !== item.opId || proof.attempt !== item.attempt || terminal.evidenceRef !== item.evidenceRef || terminal.evidenceDigest !== proof.proofDigest)
          throw new TypeError('publication unknown is not its exact original ambiguous dispatch');
        await readPublicationActualPreimage(artifacts, proof, { operation: entry.operation, birth: entry.birth, claim: entry.claim });
      } else {
        if (terminal.phase !== 'failed' || terminal.evidenceRef !== item.evidenceRef || terminal.evidenceDigest !== proof.proofDigest ||
            proof.observedAt > terminal.timestamp ||
            item.outcome === 'not_created' ||
            (item.outcome === 'retained_planned_descendant' ? proof.kind !== 'planned_descendant' : proof.kind !== 'path_observation'))
          throw new TypeError('publication noncompletion lacks its exact retained terminal observation');
        if (proof.kind === 'path_observation' && (proof.observation.location.kind !== 'workspace' ||
            proof.observation.location.path !== entry.operation.path))
          throw new TypeError('publication failed result observed an unrelated destination');
        if (proof.kind === 'planned_descendant') await validatePublicationPlannedDescendant(driver, artifacts, admission, entry, entries, proof);
      }
      const firstTerminal = entry.history.find(value => ['completed', 'failed', 'unknown'].includes(value.phase));
      if (!firstTerminal?.budgetSettlementRef) throw new TypeError('publication result lost its original once-only settlement');
      const settlement = decodeBudgetSettlement(await readCanonicalArtifact(artifacts, firstTerminal.budgetSettlementRef));
      const charged = entry.sequence === 'forward' ? { ...ZERO_BUDGET, toolCalls: 1 } : ZERO_BUDGET;
      requireEqual(settlement.consumed, charged, 'publication single original dispatch charge');
      requireEqual(firstTerminal.budgetDelta, charged, 'publication actual original settlement charge');
      if (settlement.runId !== cut.run.id || settlement.opId !== item.opId || settlement.attempt !== item.attempt ||
          settlement.preparedJournalSeq !== entry.prepared.seq || settlement.terminalJournalSeq !== firstTerminal.seq ||
          settlement.terminalPhase !== firstTerminal.phase || settlement.settledAt !== firstTerminal.timestamp ||
          entry.history.some(value => value.seq >= firstTerminal.seq && value.budgetSettlementRef !== firstTerminal.budgetSettlementRef))
        throw new TypeError('publication changed its original single settlement');
      if (terminal.seq !== firstTerminal.seq) requireEqual(terminal.budgetDelta, ZERO_BUDGET,
        'publication later same-claim observation must not charge the original UNKNOWN again');
      await readResultRetirement(driver, artifacts, admission, entry, item, terminal, proof, probeDeadlineAt);
      entry.result = { row, item }; entry.results.push(entry.result); resultRefs.add(row.payloadRef);
      const isLastForward = entry.sequence === 'forward' && entry.operation.index === entry.plan.forwardOperations.length - 1 && item.outcome === 'completed';
      const resultCheckpointId = publicationResultCheckpointId(cut.run.id, item.opId, item.attempt, item.evidenceRef);
      const lastAbortHandoff = isLastForward && item.abortStopIntentRef !== undefined;
      if (probeDeadlineAt !== undefined) {
        const atomicCheckpoint = readCheckpoint(driver, isLastForward && !lastAbortHandoff
          ? deliveryPublicationTerminalCheckpointId(cut.run.id, entry.planRef) : resultCheckpointId);
        if (terminal.timestamp !== atomicCheckpoint.createdAt)
          throw new TypeError('publication recovered terminal is not its exact original atomic result Checkpoint time');
      }
      if (item.abortStopIntentRef) {
        if (!cut.run.stopIntentRef || cut.run.resultRef) throw new TypeError('publication abort handoff has no monotonic stopping branch');
        const originalStop = await data.stop(item.abortStopIntentRef);
        if (originalStop.createdAt > item.createdAt) throw new TypeError('publication result predates its explicitly selected original StopIntent');
      } else if (isLastForward && driver.prepare('SELECT 1 FROM checkpoints WHERE id=? AND run_id=?').get(resultCheckpointId, cut.run.id)) {
        throw new TypeError('publication last-path result Checkpoint lost its explicit original abort StopIntent');
      }
      if (!isLastForward || lastAbortHandoff) {
        const checkpoint = readCheckpoint(driver, resultCheckpointId);
        await readPublicationPathCheckpoint(artifacts, cut, checkpoint, previous, [{ row, item }], terminal.seq);
        entry.checkpoint = checkpoint; previous = checkpoint;
      }
    }
  }
  for (const entry of entries.values()) entry.pendingReceivedHandoff = !!entry.receivedHandoff &&
    (!entry.result || entry.result.item.outcome === 'unknown');
  const forward = [...entries.values()].filter(entry => entry.sequence === 'forward' && !entry.preparationClosure)
    .sort((left, right) => left.operation.index - right.operation.index);
  const abort = [...entries.values()].filter(entry => entry.sequence === 'abort' && !entry.preparationClosure)
    .sort((left, right) => left.operation.index - right.operation.index);
  for (const sequence of [forward]) for (let index = 0; index < sequence.length; index++) {
    const entry = sequence[index]!;
    if (entry.operation.index !== index || index && (!sequence[index - 1]!.result ||
        sequence[index - 1]!.result!.item.outcome === 'unknown' || entry.sequence === 'forward' && sequence[index - 1]!.result!.item.outcome !== 'completed') ||
        index && sequence[index - 1]!.result?.item.abortStopIntentRef !== undefined ||
        index && sequence[index - 1]!.history.at(-1)!.seq >= entry.prepared.seq)
      throw new TypeError('publication operations do not form their exact settled ordered prefix');
  }
  const abortResults = [...abort.map(entry => {
    if (entry.operation.kind !== 'abort_rmdir') throw new TypeError('publication maintenance selected a productive operation');
    return { operation: entry.operation, result: entry.result, claimed: entry };
  }),
    ...[...abortObservations.values()].map(value => ({ ...value, claimed: undefined }))].sort((left, right) => left.operation.index - right.operation.index);
  for (let index = 0; index < abortResults.length; index++) if (abortResults[index]!.operation.index !== index ||
      index && (!abortResults[index - 1]!.result ||
        !['completed', 'not_created', 'retained_planned_descendant'].includes(abortResults[index - 1]!.result!.item.outcome)))
    throw new TypeError('publication abort observations and maintenance do not form one exact ordered prefix');
  if (abortResults.length && forward.some(entry => !entry.result || entry.result.item.outcome === 'unknown') ||
      abort.some(entry => forward.some(original => original.history.at(-1)!.seq >= entry.prepared.seq)))
    throw new TypeError('publication maintenance cannot overlap an unresolved or later semantic forward envelope');
  for (const entry of entries.values()) if (entry.preparationClosure) {
    const active = entry.sequence === 'forward' ? forward : abort;
    if (entry.claim || entry.result || entry.progress || entry.operation.index !== active.length ||
        active.some(original => original.history.at(-1)!.seq >= entry.prepared.seq))
      throw new TypeError('unclaimed publication preparation is not the exact closed unstarted suffix');
  }
  for (const entry of entries.values()) {
    if (entry.history.length > 2 && !entry.result) throw new TypeError('publication terminal Journal lost its owned result item');
    if (entry.claim) for (const terminal of entry.history.filter(value => ['completed', 'failed', 'unknown'].includes(value.phase))) {
      const results = entry.results.filter(value => value.item.evidenceRef === terminal.evidenceRef &&
        (terminal.phase === 'completed' ? value.item.outcome === 'completed' : terminal.phase === 'unknown'
          ? value.item.outcome === 'unknown' : ['failed', 'retained_planned_descendant'].includes(value.item.outcome)));
      if (results.length !== 1) throw new TypeError('publication terminal Journal is not covered by its one exact immutable result item');
    }
    if (entry.history.length === 2 && entry.history[1]!.phase === 'failed' && !entry.preparationClosure)
      throw new TypeError('publication unclaimed preparation failure lacks its complete original closure');
  }
  await assertPublicationReadCut(driver, artifacts, cut);
  return { admission, authorization, entries, forward, abort, abortResults, previousCheckpoint: previous, resultRefs };
}
