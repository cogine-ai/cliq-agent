import { canonicalSha256 } from './canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, normalizeBoundedText, parseCanonicalTime, sha256Bytes } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Retained data only. Neither capture metadata nor a plan is a native writer,
 * approval, active StateOwner, claim, or proof that an effect happened. */
export type PublicationDirectoryIdentityV1 = Readonly<{
  deviceId: string; fileId: string; ownerUid: number; mode: number; identityDigest: string;
}>;
export type DeliveryCaptureTopologyV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-delivery-capture-topology-v1'; inspectionId: string;
  capturedWorkspaceRef: string; workspaceIdentityRef: string; workspaceIdentityDigest: string;
  rootIdentity: PublicationDirectoryIdentityV1;
  directories: readonly (PublicationDirectoryIdentityV1 & { path: string })[];
  fileModes: readonly Readonly<{ path: string; mode: number }>[];
  capturedAt: string; topologyDigest: string;
}>;
export type PublicationPathState =
  | { kind: 'absent' }
  | { kind: 'directory'; mode: number; identityDigest: string; empty: boolean }
  | { kind: 'file'; digest: string; mode: number }
  | { kind: 'symlink'; target: string; digest: string };
export type PublicationExpectedEntry = Exclude<PublicationPathState, { kind: 'absent' } | { kind: 'directory' }> |
  { kind: 'directory'; mode: number; identityDigest: string; empty: true };
export type PublicationDesiredEntry = Exclude<PublicationExpectedEntry, { kind: 'directory' }> | { kind: 'directory'; mode: 493 };
export type PublicationParent = { kind: 'existing_directory'; expectedIdentityDigest: string } |
  { kind: 'planned_directory'; createdByOperationId: string };
type OperationBase = { index: number; operationId: string; path: string; parent: PublicationParent };
export type PublicationOperation = OperationBase & (
  | { kind: 'mkdir'; expected: { kind: 'absent' }; desired: { kind: 'directory'; mode: 493 } }
  | { kind: 'create'; expected: { kind: 'absent' }; desired: Exclude<PublicationDesiredEntry, { kind: 'directory' }>;
      stagingName: string; stagingExpected: { kind: 'absent' } }
  | { kind: 'replace'; expected: PublicationExpectedEntry; desired: PublicationDesiredEntry;
      stagingName: string; stagingExpected: { kind: 'absent' }; quarantineName: string; quarantineExpected: { kind: 'absent' } }
  | { kind: 'delete'; expected: PublicationExpectedEntry; desired: { kind: 'absent' };
      quarantineName: string; quarantineExpected: { kind: 'absent' } }
);
export type PublicationAbortOperation = { index: number; operationId: string; kind: 'abort_rmdir'; path: string; createdByOperationId: string;
  quarantineName: 'preimage'; quarantineExpected: { kind: 'absent' } };
export type DeliveryPlan = {
  schemaVersion: 1; deliveryRunId: string; sourceRunResultRef: string; sourceBaseRef: string; sourceDesiredRef: string;
  capturedWorkspaceRef: string; captureTopologyRef: string; captureTopologyDigest: string;
  desiredSourceRef: string; diffRef: string; mergeAlgorithm: 'cliq-diff3-v1'; publicationStateMachine: 'cliq-publish-v1';
  forwardOperations: PublicationOperation[]; abortOperations: PublicationAbortOperation[];
};
export type PublicationLocationV1 = { kind: 'workspace'; path: string } |
  { kind: 'publication_arena'; arenaId: string; component: string };
export type PublicationArenaBirthV1 = {
  schemaVersion: 1; format: 'cliq-publication-arena-birth-v1'; deliveryRunId: string; deliveryPlanRef: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; stateRootIdentityRef: string; stateRootIdentityDigest: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; sequence: 'forward' | 'abort'; operationIndex: number;
  operationId: string; opId: string; attempt: number; dispatchId: string; arenaId: string;
  arenaIdentity: { deviceId: string; fileId: string; ownerUid: number; mode: 448 };
  parentIdentity: { deviceId: string; fileId: string; ownerUid: number; mode: 448 };
  observedAt: string; birthDigest: string;
};
export type PublicationPathObservationV1 = {
  location: PublicationLocationV1; state: PublicationPathState; parentDeviceId: string; parentFileId: string; parentLinkCount: number;
  entryDeviceId?: string; entryFileId?: string; entryLinkCount?: number;
};
export type PublicationArenaRetirementObservation = { kind: 'linux_unlinked'; linkCount: 0 } |
  { kind: 'darwin_unlinked'; heldPathUnchanged: true; parentPathUnchanged: true; observedLinkCount: number };
type ProofBase = { schemaVersion: 1; format: 'cliq-publication-proof-v1'; deliveryRunId: string; deliveryPlanRef: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string; proofDigest: string };
export type PublicationRecoveryOriginAssociation =
  | { recoveryOriginRef?: never; recoveryOriginDigest?: never }
  | { recoveryOriginRef: string; recoveryOriginDigest: string };
export type PublicationReconciliationAssociation =
  | { reconciliationEvidenceRef?: never; reconciliationEvidenceDigest?: never }
  | { reconciliationEvidenceRef: string; reconciliationEvidenceDigest: string };
export type PublicationProofV1 = ProofBase & (
  | ({ kind: 'path_observation'; observation: PublicationPathObservationV1 } & PublicationRecoveryOriginAssociation)
  | { kind: 'ancestor_projection_absence'; path: string; ancestorPath: string; ancestorObservationRef: string }
  | ({ kind: 'terminal_receipt'; sequence: 'forward' | 'abort'; operationIndex: number; operationId: string; opId: string;
      attempt: number; before: PublicationPathObservationV1; after: PublicationPathObservationV1;
      preservedPreimageRef?: string; parentIdentityBeforeDigest: string; parentIdentityAfterDigest: string; directoryFsyncCompleted: true } & PublicationRecoveryOriginAssociation &
      ({ transientFinalObservations: PublicationPathObservationV1[]; namespaceRetirementEvidenceRef?: never } |
       { namespaceRetirementEvidenceRef: string; transientFinalObservations?: never; recoveryOriginRef: string; recoveryOriginDigest: string }))
  | ({ kind: 'path_ambiguity'; sequence: 'forward' | 'abort'; operationIndex: number; operationId: string; opId: string;
      attempt: number; launchDispatchId: string; failure: 'descriptor_unreadable' | 'entry_identity_changed_during_observation' |
        'transient_state_ambiguous' | 'parent_fsync_unconfirmed'; lastKnownObservationRefs: string[]; preservedActualPreimageRef?: string } & PublicationRecoveryOriginAssociation)
  | { kind: 'planned_descendant'; abortOperationId: string; retainedDescendantOperationIds: string[]; observationRefs: string[] }
  | ({ kind: 'arena_retirement'; arenaId: string; stateRootIdentityRef: string; stateRootIdentityDigest: string;
      arenaIdentity: PublicationArenaBirthV1['arenaIdentity']; parentIdentity: PublicationArenaBirthV1['parentIdentity'];
      arenaAbsent: true; arenaParentFsyncCompleted: true; retirementObservation: PublicationArenaRetirementObservation } & PublicationRecoveryOriginAssociation)
  | { kind: 'arena_namespace_absence'; arenaId: string; stateRootIdentityRef: string; stateRootIdentityDigest: string;
      registeredArenaIdentity: PublicationArenaBirthV1['arenaIdentity']; namespaceParentIdentity: PublicationArenaBirthV1['parentIdentity'];
      coveredLocations: PublicationLocationV1[]; destinationObservationRef: string;
      arenaAbsent: true; arenaParentFsyncCompleted: true; workspaceParentFsyncCompleted: true; namespaceHandlesJoined: true;
      recoveryOriginRef: string; recoveryOriginDigest: string }
  | ({ kind: 'transient_absence'; transientLocations: PublicationLocationV1[] } &
      ({ observationRefs: string[]; arenaRetirementRefs: string[]; envelopeRetirements?: never } |
       { envelopeRetirements: PublicationTransientEnvelopeRetirementV1[]; observationRefs?: never; arenaRetirementRefs?: never }))
  | { kind: 'projection_closure'; selectedBranch: 'forward_finalize' | 'abort'; observedSourceRef: string;
      observedPathEvidenceRefs: string[]; forwardResultItemRefs: string[]; unstartedForwardOperationIds: string[]; abortResultItemRefs: string[] }
  | { kind: 'git_index_unchanged'; repositoryKind: 'non_git' }
);
export type PublicationDirectoryPreimageV1 = {
  schemaVersion: 1; format: 'cliq-publication-directory-preimage-v1'; deliveryRunId: string; deliveryPlanRef: string;
  operationId: string; opId: string; attempt: number; beforeObservationRef: string; quarantineObservationRef: string;
  entriesRef: string; preimageDigest: string;
};
/** Complete data preservation only. Even a rehashed payload never proves the
 * expected preimage, a completed operation, a native effect or safe cleanup. */
export type PublicationActualPreimageV1 = {
  schemaVersion: 1; format: 'cliq-publication-actual-preimage-v1'; deliveryRunId: string; deliveryPlanRef: string;
  sequence: 'forward'; operationIndex: number; operationId: string; opId: string; attempt: number; dispatchId: string;
  arenaBirthRef: string; location: Extract<PublicationLocationV1, { kind: 'publication_arena' }>;
  physical: { identity: { deviceId: string; fileId: string; ownerUid: number }; mode: number; linkCount: number; byteCount: string };
  payload: { kind: 'file' | 'symlink'; bytesRef: string; bytesDigest: string; byteCount: number } |
    { kind: 'empty_directory'; entriesRef: string };
  preimageDigest: string;
};
export type PublicationPathProgressItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'publication_path_progress'; deliveryPlanRef: string;
  operationIndex: number; operationId: string; opId: string; attempt: number; createdAt: string;
} & ({ state: 'desired_committed_cleanup_pending'; beforeObservationRef: string; destinationEvidenceRef: string; preservedPreimageRef?: string; transientObservationRef?: string } |
  { state: 'received_handoff'; sequence: 'forward'; attempt: 0; dispatchId: string; claimJournalSeq: number;
    receiptRef: string; receiptDigest: string; retirement: PublicationPathRetirementV1;
    generationResources: PublicationGenerationResourcesV1 } & PublicationReconciliationAssociation);
export type PublicationGenerationResourcesV1 =
  | { kind: 'sealed'; workerLaunchId: string; generationRef: string; snapshotEvidenceRef: string }
  | { kind: 'genuinely_retired_from_verified_checkpoint'; workerLaunchId: string; generationRef: string;
      sourceCheckpointId: string; quarantineEvidenceRef: string; retirementEvidenceRef: string };
/** Durable association with an already retired original claim. These refs
 * never reconstruct its native owner or authorize a new cleanup/release. */
export type PublicationDescriptorRetirementV1 = { slotObservationRefs: string[]; arenaRetirementRef: string };
export type PublicationPathRetirementV1 = PublicationDescriptorRetirementV1 |
  { kind: 'current_namespace'; namespaceEvidenceRef: string };
export type PublicationTransientEnvelopeRetirementV1 = { arenaId: string; retirement: PublicationPathRetirementV1 };
export type PublicationPreparationClosureV1 = {
  schemaVersion: 1; format: 'cliq-publication-preparation-closure-v1'; deliveryRunId: string; deliveryPlanRef: string;
  sequence: 'forward' | 'abort'; operationIndex: number; operationId: string; opId: string; attempt: 0;
  preparedJournalSeq: number; requestRef: string; targetRef: string; grantRef: string; dispatchId: string;
  stateOwnerEpoch: number; supervisorInstanceId: string; leaseEpoch: number;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string; closureDigest: string;
  retirement: { kind: 'no_birth' } | ({ kind: 'retired'; arenaBirthRef: string } & PublicationDescriptorRetirementV1);
};
export type PublicationPathResultItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'publication_path_result'; deliveryPlanRef: string;
  sequence: 'forward' | 'abort'; operationIndex: number; operationId: string; opId: string; attempt: number;
  evidenceRef: string; abortStopIntentRef?: string; createdAt: string;
} & (({ outcome: 'completed'; receiptRef: string; retirement: PublicationPathRetirementV1 } & PublicationReconciliationAssociation) |
  ({ outcome: 'retained_planned_descendant' | 'failed'; receiptRef?: never; retirement: PublicationPathRetirementV1 } & PublicationReconciliationAssociation) |
  { outcome: 'not_created' | 'unknown'; receiptRef?: never; retirement?: never });
/** A fact received after its own probe deadline. This excluded-control item
 * neither settles the claim nor changes the waiting nonce or publication path. */
export type PublicationLateObservationItem = {
  schemaVersion: 1; itemId: string; runId: string; kind: 'publication_late_observation'; deliveryPlanRef: string;
  sequence: 'forward' | 'abort'; operationIndex: number; operationId: string; opId: string; attempt: 0;
  dispatchId: string; claimJournalSeq: number; probeWaitingSubjectRef: string; probeDispatchDigest: string;
  evidenceRef: string; evidenceDigest: string; completedAt: string; createdAt: string;
} & ({ disposition: 'unknown'; retirement?: never } |
  { disposition: 'received' | 'stopped_before_effect' | 'retained_planned_descendant'; retirement: PublicationPathRetirementV1 });
export type DeliveryTerminalProjectionEvidence = {
  schemaVersion: 1; deliveryRunId: string; deliveryPlanRef: string; selectedBranch: 'forward_finalize' | 'abort'; observedSourceRef: string;
  observedPathStates: Array<{ path: string; state: PublicationPathState; evidenceRef: string }>;
  forwardResultItemRefs: string[]; unstartedForwardOperationIds: string[]; abortResultItemRefs: string[];
  transientAbsenceEvidenceRef: string; projectionClosureEvidenceRef: string; gitIndexUnchangedEvidenceRef: string;
  observedAt: string; evidenceDigest: string;
};

function closed(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    throw new TypeError('publication data must be a closed plain record');
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).length !== fields.length || fields.some(field => !Object.hasOwn(properties, field)) ||
      Object.values(properties).some(property => !property.enumerable || !Object.hasOwn(property, 'value') || property.value === undefined))
    throw new TypeError('publication data has unknown, missing or non-data fields');
  return value as Record<string, unknown>;
}
function text(value: unknown, maximum = 128): string {
  if (typeof value !== 'string' || normalizeBoundedText(value, 1, maximum) !== value) throw new TypeError('publication text is not canonical');
  return value;
}
function reference(value: unknown): string { const result = text(value, 64); assertArtifactRef(result); return result; }
function array(value: unknown): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError('publication array is not plain');
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).length !== value.length + 1) throw new TypeError('publication array has extra or missing fields');
  for (let index = 0; index < value.length; index++) {
    const property = properties[index];
    if (!property || !property.enumerable || !Object.hasOwn(property, 'value') || property.value === undefined)
      throw new TypeError('publication array has sparse or non-data entries');
  }
  return value;
}
function workspacePath(value: unknown): string {
  const path = text(value, 4096);
  if (path.includes('\\') || path.split('/').some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255))
    throw new TypeError('publication workspace path is not canonical');
  return path;
}
function physicalMode(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 0o7777) throw new TypeError('invalid publication physical mode');
  return value as number;
}
function operationId(value: unknown): string {
  const id = text(value); if (!/^[A-Za-z0-9_-]{43}$/u.test(id)) throw new TypeError('invalid publication operation id'); return id;
}
export function publicationArenaId(runId: string, operation: string, opId: string, attempt: number, dispatchId: string): string {
  text(runId); operationId(operation); text(opId); integer(attempt); text(dispatchId);
  return identityHash('cliq-publication-arena-v1', runId, operation, opId, String(attempt), dispatchId);
}
function location(value: unknown): PublicationLocationV1 {
  if (!value || typeof value !== 'object') throw new TypeError('publication location must be a record');
  const kind = Object.getOwnPropertyDescriptor(value, 'kind')?.value;
  if (kind === 'workspace') workspacePath(closed(value, ['kind', 'path']).path);
  else if (kind === 'publication_arena') {
    const data = closed(value, ['kind', 'arenaId', 'component']); operationId(data.arenaId);
    if (workspacePath(data.component).includes('/')) throw new TypeError('publication arena location requires one component');
  } else throw new TypeError('unknown publication location domain');
  return value as PublicationLocationV1;
}
export function publicationLocationKey(value: PublicationLocationV1): string {
  return value.kind === 'workspace' ? `workspace:${value.path}` : `publication_arena:${value.arenaId}:${value.component}`;
}
export function decodePublicationArenaBirth(value: unknown): PublicationArenaBirthV1 {
  const data = closed(value, ['schemaVersion', 'format', 'deliveryRunId', 'deliveryPlanRef', 'workspaceIdentityRef', 'workspaceIdentityDigest',
    'stateRootIdentityRef', 'stateRootIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'sequence', 'operationIndex',
    'operationId', 'opId', 'attempt', 'dispatchId', 'arenaId', 'arenaIdentity', 'parentIdentity', 'observedAt', 'birthDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-arena-birth-v1' || data.sequence !== 'forward' && data.sequence !== 'abort')
    throw new TypeError('invalid publication arena birth schema or sequence');
  text(data.deliveryRunId); operationId(data.operationId); text(data.opId); integer(data.attempt); integer(data.operationIndex); text(data.dispatchId);
  for (const field of ['deliveryPlanRef', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'birthDigest']) reference(data[field]);
  for (const field of ['arenaIdentity', 'parentIdentity']) {
    privateDirectoryIdentity(data[field]);
  }
  if ((data.arenaIdentity as Record<string, unknown>).deviceId !== (data.parentIdentity as Record<string, unknown>).deviceId ||
      (data.arenaIdentity as Record<string, unknown>).ownerUid !== (data.parentIdentity as Record<string, unknown>).ownerUid ||
      data.arenaId !== publicationArenaId(data.deliveryRunId as string, data.operationId as string, data.opId as string, data.attempt as number, data.dispatchId as string))
    throw new TypeError('publication arena birth does not bind its original dispatch or physical parent');
  parseCanonicalTime(text(data.observedAt));
  if (digestOmitting(data, 'birthDigest') !== data.birthDigest) throw new TypeError('publication arena birth digest differs');
  return immutableSnapshot(data) as PublicationArenaBirthV1;
}
function integer(value: unknown, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new TypeError('invalid publication integer');
  return value as number;
}
function unsignedId(value: unknown): string {
  const id = text(value);
  if (!/^(0|[1-9]\d*)$/u.test(id) || BigInt(id) > 0xffffffffffffffffn) throw new TypeError('invalid publication physical id');
  return id;
}
function privateDirectoryIdentity(value: unknown): PublicationArenaBirthV1['arenaIdentity'] {
  const identity = closed(value, ['deviceId', 'fileId', 'ownerUid', 'mode']);
  unsignedId(identity.deviceId); unsignedId(identity.fileId); integer(identity.ownerUid);
  if ((identity.ownerUid as number) > 0xffffffff || identity.mode !== 448) throw new TypeError('publication arena must name an actual private directory');
  return value as PublicationArenaBirthV1['arenaIdentity'];
}
export function decodePublicationActualPreimage(value: unknown): PublicationActualPreimageV1 {
  const data = closed(value, ['schemaVersion', 'format', 'deliveryRunId', 'deliveryPlanRef', 'sequence', 'operationIndex', 'operationId',
    'opId', 'attempt', 'dispatchId', 'arenaBirthRef', 'location', 'physical', 'payload', 'preimageDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-actual-preimage-v1' || data.sequence !== 'forward')
    throw new TypeError('invalid actual publication preimage schema or sequence');
  text(data.deliveryRunId); operationId(data.operationId); text(data.opId); integer(data.attempt); integer(data.operationIndex); text(data.dispatchId);
  reference(data.deliveryPlanRef); reference(data.arenaBirthRef); reference(data.preimageDigest);
  const where = location(data.location);
  if (where.kind !== 'publication_arena' || where.arenaId !== publicationArenaId(data.deliveryRunId as string, data.operationId as string,
    data.opId as string, data.attempt as number, data.dispatchId as string)) throw new TypeError('actual preimage substituted its original private arena');
  const physical = closed(data.physical, ['identity', 'mode', 'linkCount', 'byteCount']);
  const identity = closed(physical.identity, ['deviceId', 'fileId', 'ownerUid']);
  unsignedId(identity.deviceId); unsignedId(identity.fileId); integer(identity.ownerUid);
  if ((identity.ownerUid as number) > 0xffffffff) throw new TypeError('actual preimage owner is not a physical uid');
  physicalMode(physical.mode); integer(physical.linkCount, 1); unsignedId(physical.byteCount);
  if (!data.payload || typeof data.payload !== 'object') throw new TypeError('actual preimage requires a closed complete payload');
  const kind = Object.getOwnPropertyDescriptor(data.payload, 'kind')?.value;
  if (kind === 'file' || kind === 'symlink') {
    const payload = closed(data.payload, ['kind', 'bytesRef', 'bytesDigest', 'byteCount']);
    reference(payload.bytesRef); reference(payload.bytesDigest); integer(payload.byteCount, kind === 'symlink' ? 1 : 0);
    if (payload.bytesRef !== payload.bytesDigest || physical.byteCount !== String(payload.byteCount) ||
        (payload.byteCount as number) > (kind === 'file' ? 268435456 : 4096) || kind === 'file' && physical.linkCount !== 1)
      throw new TypeError('actual preimage bytes are incomplete, unbounded or multiply linked');
  } else if (kind === 'empty_directory') reference(closed(data.payload, ['kind', 'entriesRef']).entriesRef);
  else throw new TypeError('unsupported or incomplete actual preimage payload');
  if (digestOmitting(data, 'preimageDigest') !== data.preimageDigest) throw new TypeError('actual preimage digest differs');
  return immutableSnapshot(data) as PublicationActualPreimageV1;
}
function optionalClosed(value: unknown, required: readonly string[], optional: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object') throw new TypeError('publication data must be a record');
  return closed(value, [...required, ...optional.filter(field => Object.hasOwn(value, field))]);
}
function references(value: unknown): string[] {
  const values = array(value).map(reference);
  if (new Set(values).size !== values.length) throw new TypeError('publication reference array contains duplicates');
  return values;
}
function operationIds(value: unknown): string[] {
  const values = array(value).map(operationId);
  if (new Set(values).size !== values.length) throw new TypeError('publication operation array contains duplicates');
  return values;
}
export function publicationDirectoryIdentityDigest(workspaceIdentityDigest: string,
  identity: Omit<PublicationDirectoryIdentityV1, 'identityDigest'>): string {
  return canonicalSha256({ workspaceIdentityDigest, deviceId: identity.deviceId, fileId: identity.fileId,
    ownerUid: identity.ownerUid, mode: identity.mode });
}
export function decodeDeliveryCaptureTopology(value: unknown): DeliveryCaptureTopologyV1 {
  const data = closed(value, ['schemaVersion', 'format', 'inspectionId', 'capturedWorkspaceRef', 'workspaceIdentityRef',
    'workspaceIdentityDigest', 'rootIdentity', 'directories', 'fileModes', 'capturedAt', 'topologyDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-delivery-capture-topology-v1' || !Array.isArray(data.directories) || !Array.isArray(data.fileModes))
    throw new TypeError('invalid delivery topology format');
  operationId(data.inspectionId); reference(data.capturedWorkspaceRef); reference(data.workspaceIdentityRef); reference(data.workspaceIdentityDigest);
  parseCanonicalTime(text(data.capturedAt)); reference(data.topologyDigest);
  const directory = (value: unknown, path: boolean) => {
    const identity = closed(value, ['deviceId', 'fileId', 'ownerUid', 'mode', 'identityDigest', ...(path ? ['path'] : [])]);
    for (const field of ['deviceId', 'fileId']) if (!/^(0|[1-9]\d*)$/u.test(text(identity[field])) || BigInt(identity[field] as string) > 0xffffffffffffffffn)
      throw new TypeError('invalid directory physical id');
    if (!Number.isSafeInteger(identity.ownerUid) || (identity.ownerUid as number) < 0 || (identity.ownerUid as number) > 0xffffffff ||
        !Number.isSafeInteger(identity.mode) || (identity.mode as number) < 0 || (identity.mode as number) > 0o7777)
      throw new TypeError('invalid directory physical owner or mode');
    reference(identity.identityDigest);
    if (identity.identityDigest !== publicationDirectoryIdentityDigest(data.workspaceIdentityDigest as string,
      identity as unknown as PublicationDirectoryIdentityV1)) throw new TypeError('directory identity digest differs');
    return identity;
  };
  directory(data.rootIdentity, false);
  let previous: string | undefined;
  const directories = new Set<string>();
  for (const value of array(data.directories)) {
    const entry = directory(value, true), path = workspacePath(entry.path);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(path)) >= 0) throw new TypeError('directory topology is not canonical and ordered');
    directories.add(path);
    previous = path;
  }
  previous = undefined;
  for (const value of array(data.fileModes)) {
    const entry = closed(value, ['path', 'mode']), path = workspacePath(entry.path); physicalMode(entry.mode);
    if (directories.has(path) ||
        previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(path)) >= 0) throw new TypeError('file raw modes are not canonical and ordered');
    previous = path;
  }
  if (digestOmitting(data, 'topologyDigest') !== data.topologyDigest) throw new TypeError('delivery topology digest differs');
  return immutableSnapshot(data) as DeliveryCaptureTopologyV1;
}

/** Closed retained-data decoding only. The owning reader still verifies Plan
 * refs, the complete A/M/diff/topology graph, approval and original claim. */
export function decodeDeliveryPlan(value: unknown): DeliveryPlan {
  const data = closed(value, ['schemaVersion', 'deliveryRunId', 'sourceRunResultRef', 'sourceBaseRef', 'sourceDesiredRef',
    'capturedWorkspaceRef', 'captureTopologyRef', 'captureTopologyDigest', 'desiredSourceRef', 'diffRef', 'mergeAlgorithm',
    'publicationStateMachine', 'forwardOperations', 'abortOperations']);
  if (data.schemaVersion !== 1 || data.mergeAlgorithm !== 'cliq-diff3-v1' || data.publicationStateMachine !== 'cliq-publish-v1')
    throw new TypeError('invalid publication plan schema or algorithm');
  text(data.deliveryRunId);
  for (const field of ['sourceRunResultRef', 'sourceBaseRef', 'sourceDesiredRef', 'capturedWorkspaceRef', 'captureTopologyRef',
    'captureTopologyDigest', 'desiredSourceRef', 'diffRef']) reference(data[field]);
  const forward = array(data.forwardOperations), abort = array(data.abortOperations), ids = new Set<string>(), paths = new Map<string, PublicationOperation>();
  const state = (value: unknown, desired: boolean, absence: boolean): PublicationPathState | PublicationDesiredEntry => {
    if (!value || typeof value !== 'object') throw new TypeError('publication state must be a record');
    const kind = Object.getOwnPropertyDescriptor(value, 'kind');
    if (!kind || !Object.hasOwn(kind, 'value')) throw new TypeError('publication state kind must be data');
    if (kind.value === 'absent') { closed(value, ['kind']); if (!absence) throw new TypeError('unexpected publication absence'); return value as { kind: 'absent' }; }
    if (absence) throw new TypeError('publication state must be absent');
    if (kind.value === 'directory') {
      const directory = closed(value, desired ? ['kind', 'mode'] : ['kind', 'mode', 'identityDigest', 'empty']); physicalMode(directory.mode);
      if (desired ? directory.mode !== 493 : directory.empty !== true) throw new TypeError('publication directory must be normalized desired or proven empty expected');
      if (!desired) reference(directory.identityDigest);
      return value as PublicationDesiredEntry;
    }
    if (kind.value === 'file') {
      const file = closed(value, ['kind', 'mode', 'digest']); physicalMode(file.mode); reference(file.digest);
      if (desired && file.mode !== 420 && file.mode !== 493) throw new TypeError('publication desired file mode is not normalized');
      return value as PublicationDesiredEntry;
    }
    if (kind.value === 'symlink') {
      const link = closed(value, ['kind', 'target', 'digest']), target = text(link.target, 4096); reference(link.digest);
      if (target.startsWith('/') || target.includes('\\') || target.split('/').some(part => part.toLowerCase() === '.git') ||
          sha256Bytes(Buffer.from(target)) !== link.digest) throw new TypeError('publication symlink target differs from its raw digest');
      return value as PublicationDesiredEntry;
    }
    throw new TypeError('unknown publication path state');
  };
  for (let index = 0; index < forward.length; index++) {
    const raw = forward[index];
    if (!raw || typeof raw !== 'object') throw new TypeError('invalid publication operation');
    const kind = Object.getOwnPropertyDescriptor(raw, 'kind')?.value;
    const fields = ['index', 'operationId', 'path', 'parent', 'kind', 'expected', 'desired'];
    if (kind === 'create' || kind === 'replace') fields.push('stagingName', 'stagingExpected');
    if (kind === 'delete' || kind === 'replace') fields.push('quarantineName', 'quarantineExpected');
    if (!['mkdir', 'create', 'replace', 'delete'].includes(kind)) throw new TypeError('unknown publication operation kind');
    const operation = closed(raw, fields), id = operationId(operation.operationId), path = workspacePath(operation.path);
    if (operation.index !== index || ids.has(id) || paths.has(path)) throw new TypeError('publication indices, paths or ids are not unique and contiguous');
    ids.add(id);
    const expected = state(operation.expected, false, kind === 'mkdir' || kind === 'create');
    const desired = state(operation.desired, true, kind === 'delete');
    if (kind === 'mkdir' && desired.kind !== 'directory' || kind === 'create' && desired.kind === 'directory') throw new TypeError('publication creation kind does not match its entry');
    if (!operation.parent || typeof operation.parent !== 'object') throw new TypeError('publication parent must be a record');
    const parentKind = Object.getOwnPropertyDescriptor(operation.parent, 'kind')?.value;
    const parentPath = path.slice(0, Math.max(0, path.lastIndexOf('/')));
    if (parentKind === 'existing_directory') reference(closed(operation.parent, ['kind', 'expectedIdentityDigest']).expectedIdentityDigest);
    else if (parentKind === 'planned_directory') {
      const parent = closed(operation.parent, ['kind', 'createdByOperationId']), creator = paths.get(parentPath);
      operationId(parent.createdByOperationId);
      if (!creator || creator.operationId !== parent.createdByOperationId || creator.desired.kind !== 'directory' || creator.expected.kind === 'directory')
        throw new TypeError('publication parent does not bind its earlier exact creator');
    } else throw new TypeError('unknown publication parent kind');
    for (const name of ['staging', 'quarantine']) if (Object.hasOwn(operation, `${name}Name`)) {
      const component = workspacePath(operation[`${name}Name`]);
      if (component.includes('/')) throw new TypeError('publication transient must be one private arena component');
      state(operation[`${name}Expected`], false, true);
    }
    if (operation.stagingName !== undefined && operation.stagingName === operation.quarantineName)
      throw new TypeError('publication private staging aliases its preimage');
    paths.set(path, operation as unknown as PublicationOperation); void expected;
  }
  for (const operation of paths.values()) {
    const parentPath = operation.path.slice(0, Math.max(0, operation.path.lastIndexOf('/'))), parent = paths.get(parentPath);
    if (operation.expected.kind !== 'absent' && parent?.expected.kind === 'directory' && parent.desired.kind !== 'directory' && parent.index < operation.index)
      throw new TypeError('publication removes a directory before its planned child');
  }
  const directories = [...paths.values()].filter(operation => operation.desired.kind === 'directory' && operation.expected.kind !== 'directory')
    .sort((a, b) => b.path.split('/').length - a.path.split('/').length || Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  if (directories.length !== abort.length) throw new TypeError('publication abort does not cover exactly created directories');
  for (let index = 0; index < abort.length; index++) {
    const operation = closed(abort[index], ['index', 'operationId', 'kind', 'path', 'createdByOperationId', 'quarantineName', 'quarantineExpected']), id = operationId(operation.operationId);
    if (operation.index !== index || operation.kind !== 'abort_rmdir' || ids.has(id) || workspacePath(operation.path) !== directories[index].path ||
        operation.createdByOperationId !== directories[index].operationId || operation.quarantineName !== 'preimage')
      throw new TypeError('publication abort directory order, creator or private quarantine differs');
    state(operation.quarantineExpected, false, true);
    ids.add(id);
  }
  return immutableSnapshot(data) as DeliveryPlan;
}

const itemFields = ['schemaVersion', 'itemId', 'runId', 'kind', 'deliveryPlanRef', 'operationIndex', 'operationId', 'opId', 'attempt', 'createdAt'] as const;
function item(data: Record<string, unknown>, kind: string): void {
  if (data.schemaVersion !== 1 || data.kind !== kind) throw new TypeError('invalid publication item schema or kind');
  for (const field of ['itemId', 'runId', 'opId']) text(data[field]);
  reference(data.deliveryPlanRef); integer(data.operationIndex); operationId(data.operationId); integer(data.attempt); parseCanonicalTime(text(data.createdAt));
}
function referencePair(data: Record<string, unknown>, first: string, second: string): boolean {
  const present = Object.hasOwn(data, first);
  if (present !== Object.hasOwn(data, second)) throw new TypeError('publication evidence requires its complete reference and digest pair');
  if (present) { reference(data[first]); reference(data[second]); }
  return present;
}
export function decodePublicationPathRetirement(value: unknown): PublicationPathRetirementV1 {
  const kind = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'kind')?.value : undefined;
  if (kind === 'current_namespace') {
    reference(closed(value, ['kind', 'namespaceEvidenceRef']).namespaceEvidenceRef);
  } else {
    const retirement = closed(value, ['slotObservationRefs', 'arenaRetirementRef']);
    const slots = references(retirement.slotObservationRefs); reference(retirement.arenaRetirementRef);
    if (slots.length < 1 || slots.length > 2 || slots.includes(retirement.arenaRetirementRef as string))
      throw new TypeError('publication retirement must name its exact original private observations and separate retired arena');
  }
  return immutableSnapshot(value) as PublicationPathRetirementV1;
}
export function publicationRetirementReferences(value: PublicationPathRetirementV1): string[] {
  return 'kind' in value ? [value.namespaceEvidenceRef] : [...value.slotObservationRefs, value.arenaRetirementRef];
}
export const publicationLateObservationItemId = (runId: string, opId: string, attempt: number, dispatchDigest: string, evidenceRef: string) =>
  identityHash('cliq-publication-late-observation-item-v1', runId, opId, String(attempt), dispatchDigest, evidenceRef);
export const publicationLateObservationCheckpointId = (runId: string, opId: string, attempt: number, dispatchDigest: string, evidenceRef: string) =>
  identityHash('cliq-publication-late-observation-checkpoint-v1', runId, opId, String(attempt), dispatchDigest, evidenceRef);
export function decodePublicationLateObservationItem(value: unknown): PublicationLateObservationItem {
  const disposition = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'disposition')?.value : undefined;
  const data = closed(value, [...itemFields, 'sequence', 'dispatchId', 'claimJournalSeq', 'probeWaitingSubjectRef',
    'probeDispatchDigest', 'evidenceRef', 'evidenceDigest', 'completedAt', 'disposition', ...(disposition === 'unknown' ? [] : ['retirement'])]);
  item(data, 'publication_late_observation');
  if (data.sequence !== 'forward' && data.sequence !== 'abort' || data.attempt !== 0 ||
      !['received', 'stopped_before_effect', 'retained_planned_descendant', 'unknown'].includes(disposition as string))
    throw new TypeError('invalid late publication observation branch');
  text(data.dispatchId); integer(data.claimJournalSeq, 1);
  for (const field of ['probeWaitingSubjectRef', 'probeDispatchDigest', 'evidenceRef', 'evidenceDigest']) reference(data[field]);
  parseCanonicalTime(text(data.completedAt));
  if ((data.completedAt as string) > (data.createdAt as string)) throw new TypeError('late audit predates its actual producer completion');
  if (disposition !== 'unknown') decodePublicationPathRetirement(data.retirement);
  if (data.itemId !== publicationLateObservationItemId(data.runId as string, data.opId as string, 0,
      data.probeDispatchDigest as string, data.evidenceRef as string)) throw new TypeError('late publication audit identity differs');
  return immutableSnapshot(data) as PublicationLateObservationItem;
}
export function decodePublicationPathProgressItem(value: unknown): PublicationPathProgressItem {
  const branch = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'state')?.value : undefined;
  if (branch === 'received_handoff') {
    const data = optionalClosed(value, [...itemFields, 'state', 'sequence', 'dispatchId', 'claimJournalSeq', 'receiptRef', 'receiptDigest', 'retirement', 'generationResources'],
      ['reconciliationEvidenceRef', 'reconciliationEvidenceDigest']);
    item(data, 'publication_path_progress');
    if (data.sequence !== 'forward' || data.attempt !== 0) throw new TypeError('received publication handoff requires its original last forward attempt');
    text(data.dispatchId); integer(data.claimJournalSeq, 1); reference(data.receiptRef); reference(data.receiptDigest);
    decodePublicationPathRetirement(data.retirement);
    const reconciled = referencePair(data, 'reconciliationEvidenceRef', 'reconciliationEvidenceDigest');
    const raw = data.generationResources;
    const kind = raw && typeof raw === 'object' ? Object.getOwnPropertyDescriptor(raw, 'kind')?.value : undefined;
    if (kind === 'sealed') {
      const generation = closed(raw, ['kind', 'workerLaunchId', 'generationRef', 'snapshotEvidenceRef']);
      text(generation.workerLaunchId); reference(generation.generationRef); reference(generation.snapshotEvidenceRef);
    } else if (kind === 'genuinely_retired_from_verified_checkpoint') {
      const generation = closed(raw, ['kind', 'workerLaunchId', 'generationRef', 'sourceCheckpointId', 'quarantineEvidenceRef', 'retirementEvidenceRef']);
      text(generation.workerLaunchId); text(generation.sourceCheckpointId);
      reference(generation.generationRef); reference(generation.quarantineEvidenceRef); reference(generation.retirementEvidenceRef);
      if (!reconciled) throw new TypeError('retired received resources require their exact reconciliation evidence');
    } else throw new TypeError('unknown received publication generation resource branch');
    return immutableSnapshot(data) as PublicationPathProgressItem;
  }
  const data = optionalClosed(value, [...itemFields, 'state', 'beforeObservationRef', 'destinationEvidenceRef'], ['preservedPreimageRef', 'transientObservationRef']);
  item(data, 'publication_path_progress');
  if (data.state !== 'desired_committed_cleanup_pending') throw new TypeError('invalid publication progress state');
  for (const field of ['beforeObservationRef', 'destinationEvidenceRef', 'preservedPreimageRef', 'transientObservationRef']) if (Object.hasOwn(data, field)) reference(data[field]);
  return immutableSnapshot(data) as PublicationPathProgressItem;
}
export function decodePublicationPathResultItem(value: unknown): PublicationPathResultItem {
  const data = optionalClosed(value, [...itemFields, 'sequence', 'outcome', 'evidenceRef'],
    ['receiptRef', 'abortStopIntentRef', 'retirement', 'reconciliationEvidenceRef', 'reconciliationEvidenceDigest']); item(data, 'publication_path_result');
  if (data.sequence !== 'forward' && data.sequence !== 'abort' || !['completed', 'not_created', 'retained_planned_descendant', 'failed', 'unknown'].includes(data.outcome as string))
    throw new TypeError('invalid publication result branch or outcome');
  reference(data.evidenceRef);
  if (referencePair(data, 'reconciliationEvidenceRef', 'reconciliationEvidenceDigest') &&
      (data.outcome === 'unknown' || data.outcome === 'not_created'))
    throw new TypeError('unknown or unclaimed absence cannot assert a known-result reconciliation');
  if (Object.hasOwn(data, 'abortStopIntentRef')) {
    reference(data.abortStopIntentRef);
    if (data.sequence !== 'forward' || data.outcome !== 'completed' && data.outcome !== 'failed')
      throw new TypeError('only a stopped forward result can carry an abort handoff');
  }
  if (data.outcome === 'completed') {
    reference(data.receiptRef); if (data.receiptRef !== data.evidenceRef) throw new TypeError('publication completion has a different receipt and evidence');
  } else if (Object.hasOwn(data, 'receiptRef')) throw new TypeError('noncompleted publication result has a terminal receipt');
  if (['completed', 'failed', 'retained_planned_descendant'].includes(data.outcome as string)) {
    decodePublicationPathRetirement(data.retirement);
  } else if (Object.hasOwn(data, 'retirement')) throw new TypeError('unknown or unclaimed publication cannot assert original retirement');
  return immutableSnapshot(data) as PublicationPathResultItem;
}
export function decodePublicationPreparationClosure(value: unknown): PublicationPreparationClosureV1 {
  const data = closed(value, ['schemaVersion', 'format', 'deliveryRunId', 'deliveryPlanRef', 'sequence', 'operationIndex', 'operationId',
    'opId', 'attempt', 'preparedJournalSeq', 'requestRef', 'targetRef', 'grantRef', 'dispatchId', 'stateOwnerEpoch',
    'supervisorInstanceId', 'leaseEpoch', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'closureDigest', 'retirement']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-preparation-closure-v1' ||
      data.sequence !== 'forward' && data.sequence !== 'abort' || data.attempt !== 0)
    throw new TypeError('invalid publication preparation closure branch');
  text(data.deliveryRunId); text(data.opId); operationId(data.operationId); text(data.dispatchId); text(data.supervisorInstanceId);
  integer(data.operationIndex); integer(data.preparedJournalSeq); integer(data.stateOwnerEpoch); integer(data.leaseEpoch);
  if ((data.preparedJournalSeq as number) < 1 || (data.stateOwnerEpoch as number) < 1)
    throw new TypeError('publication preparation closure lost its original prepared sequence or owner');
  for (const field of ['deliveryPlanRef', 'requestRef', 'targetRef', 'grantRef', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'closureDigest']) reference(data[field]);
  parseCanonicalTime(text(data.observedAt));
  const raw = data.retirement;
  const kind = raw && typeof raw === 'object' ? Object.getOwnPropertyDescriptor(raw, 'kind')?.value : undefined;
  if (kind === 'no_birth') closed(raw, ['kind']);
  else if (kind === 'retired') {
    const retirement = closed(raw, ['kind', 'arenaBirthRef', 'slotObservationRefs', 'arenaRetirementRef']);
    reference(retirement.arenaBirthRef); reference(retirement.arenaRetirementRef);
    const slots = references(retirement.slotObservationRefs);
    if (slots.length < 1 || slots.length > 2 || slots.includes(retirement.arenaRetirementRef as string))
      throw new TypeError('publication preparation closure lost its actual original retired slots');
  } else throw new TypeError('unknown or incomplete publication birth cannot close preparation');
  if (digestOmitting(data, 'closureDigest') !== data.closureDigest) throw new TypeError('publication preparation closure digest differs');
  return immutableSnapshot(data) as PublicationPreparationClosureV1;
}
function observedState(value: unknown): PublicationPathState {
  if (!value || typeof value !== 'object') throw new TypeError('publication observation state must be a record');
  const kind = Object.getOwnPropertyDescriptor(value, 'kind')?.value;
  if (kind === 'absent') closed(value, ['kind']);
  else if (kind === 'file') { const state = closed(value, ['kind', 'mode', 'digest']); physicalMode(state.mode); reference(state.digest); }
  else if (kind === 'directory') {
    const state = closed(value, ['kind', 'mode', 'identityDigest', 'empty']); physicalMode(state.mode); reference(state.identityDigest);
    if (typeof state.empty !== 'boolean') throw new TypeError('publication directory observation lacks a definite empty state');
  } else if (kind === 'symlink') {
    const state = closed(value, ['kind', 'target', 'digest']), target = text(state.target, 4096); reference(state.digest);
    // Observed divergence is data, not eligibility: an absolute or dangling
    // unexpected link may be recorded but never becomes desired-plan authority.
    if (sha256Bytes(Buffer.from(target)) !== state.digest) throw new TypeError('publication observation link bytes differ');
  } else throw new TypeError('unsupported publication observed entry state');
  return value as PublicationPathState;
}
function observation(value: unknown): PublicationPathObservationV1 {
  const data = optionalClosed(value, ['location', 'state', 'parentDeviceId', 'parentFileId', 'parentLinkCount'], ['entryDeviceId', 'entryFileId', 'entryLinkCount']);
  location(data.location); unsignedId(data.parentDeviceId); unsignedId(data.parentFileId); integer(data.parentLinkCount, 1);
  const state = observedState(data.state);
  const entryFields = ['entryDeviceId', 'entryFileId', 'entryLinkCount'];
  if (state.kind === 'absent') {
    if (entryFields.some(field => Object.hasOwn(data, field))) throw new TypeError('absent publication observation carries an entry identity');
  } else {
    if (entryFields.some(field => !Object.hasOwn(data, field))) throw new TypeError('present publication observation lacks a complete entry identity');
    unsignedId(data.entryDeviceId); unsignedId(data.entryFileId); integer(data.entryLinkCount, 1);
  }
  return data as PublicationPathObservationV1;
}
const proofFields = ['schemaVersion', 'format', 'kind', 'deliveryRunId', 'deliveryPlanRef', 'workspaceIdentityRef', 'workspaceIdentityDigest',
  'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'proofDigest'] as const;
export function decodePublicationProof(value: unknown): PublicationProofV1 {
  if (!value || typeof value !== 'object') throw new TypeError('publication proof must be a record');
  const kind = Object.getOwnPropertyDescriptor(value, 'kind')?.value;
  const operationFields = ['sequence', 'operationIndex', 'operationId', 'opId', 'attempt'];
  let fields: string[], optional: string[] = [];
  if (kind === 'path_observation') fields = ['observation'];
  else if (kind === 'ancestor_projection_absence') fields = ['path', 'ancestorPath', 'ancestorObservationRef'];
  else if (kind === 'terminal_receipt') {
    fields = [...operationFields, 'before', 'after', Object.hasOwn(value, 'namespaceRetirementEvidenceRef') ? 'namespaceRetirementEvidenceRef' : 'transientFinalObservations',
      'parentIdentityBeforeDigest', 'parentIdentityAfterDigest', 'directoryFsyncCompleted'];
    optional = ['preservedPreimageRef'];
  } else if (kind === 'path_ambiguity') {
    fields = [...operationFields, 'launchDispatchId', 'failure', 'lastKnownObservationRefs']; optional = ['preservedActualPreimageRef'];
  }
  else if (kind === 'planned_descendant') fields = ['abortOperationId', 'retainedDescendantOperationIds', 'observationRefs'];
  else if (kind === 'arena_retirement') fields = ['arenaId', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'arenaIdentity', 'parentIdentity',
    'arenaAbsent', 'arenaParentFsyncCompleted', 'retirementObservation'];
  else if (kind === 'arena_namespace_absence') fields = ['arenaId', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'registeredArenaIdentity', 'namespaceParentIdentity', 'coveredLocations', 'destinationObservationRef',
    'arenaAbsent', 'arenaParentFsyncCompleted', 'workspaceParentFsyncCompleted', 'namespaceHandlesJoined', 'recoveryOriginRef', 'recoveryOriginDigest'];
  else if (kind === 'transient_absence') fields = ['transientLocations', ...(Object.hasOwn(value, 'envelopeRetirements')
    ? ['envelopeRetirements'] : ['observationRefs', 'arenaRetirementRefs'])];
  else if (kind === 'projection_closure') fields = ['selectedBranch', 'observedSourceRef', 'observedPathEvidenceRefs', 'forwardResultItemRefs', 'unstartedForwardOperationIds', 'abortResultItemRefs'];
  else if (kind === 'git_index_unchanged') fields = ['repositoryKind'];
  else throw new TypeError('unknown publication proof kind');
  if (['path_observation', 'terminal_receipt', 'path_ambiguity', 'arena_retirement'].includes(kind))
    optional.push('recoveryOriginRef', 'recoveryOriginDigest');
  const data = optionalClosed(value, [...proofFields, ...fields], optional);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-proof-v1') throw new TypeError('invalid publication proof schema');
  text(data.deliveryRunId); parseCanonicalTime(text(data.observedAt));
  for (const field of ['deliveryPlanRef', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'proofDigest']) reference(data[field]);
  referencePair(data, 'recoveryOriginRef', 'recoveryOriginDigest');
  if (kind === 'path_observation') observation(data.observation);
  else if (kind === 'ancestor_projection_absence') {
    const path = workspacePath(data.path), ancestor = workspacePath(data.ancestorPath);
    if (!path.startsWith(`${ancestor}/`)) throw new TypeError('publication absent ancestor is not a strict workspace path prefix');
    reference(data.ancestorObservationRef);
  }
  else if (kind === 'terminal_receipt' || kind === 'path_ambiguity') {
    if (data.sequence !== 'forward' && data.sequence !== 'abort') throw new TypeError('invalid publication proof sequence');
    integer(data.operationIndex); operationId(data.operationId); text(data.opId); integer(data.attempt);
    if (kind === 'terminal_receipt') {
      if (observation(data.before).location.kind !== 'workspace' || observation(data.after).location.kind !== 'workspace')
        throw new TypeError('publication terminal destination must be in the workspace domain');
      if (Object.hasOwn(data, 'preservedPreimageRef')) reference(data.preservedPreimageRef);
      reference(data.parentIdentityBeforeDigest); reference(data.parentIdentityAfterDigest);
      if (data.directoryFsyncCompleted !== true) throw new TypeError('publication terminal receipt lacks definite parent sync');
      if (Object.hasOwn(data, 'namespaceRetirementEvidenceRef')) {
        reference(data.namespaceRetirementEvidenceRef);
        if (!Object.hasOwn(data, 'recoveryOriginRef')) throw new TypeError('namespace receipt requires actual original claim-owner death');
      }
      let previous: string | undefined;
      for (const raw of Object.hasOwn(data, 'transientFinalObservations') ? array(data.transientFinalObservations) : []) {
        const entry = observation(raw);
        const key = publicationLocationKey(entry.location);
        if (entry.location.kind !== 'publication_arena' || entry.state.kind !== 'absent' || previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(key)) >= 0)
          throw new TypeError('publication terminal transients are not unique ordered absences');
        previous = key;
      }
    } else {
      text(data.launchDispatchId);
      if (Object.hasOwn(data, 'preservedActualPreimageRef')) {
        reference(data.preservedActualPreimageRef);
        if (data.sequence !== 'forward') throw new TypeError('abort maintenance cannot retain a displaced forward preimage');
      }
      if (!['descriptor_unreadable', 'entry_identity_changed_during_observation', 'transient_state_ambiguous', 'parent_fsync_unconfirmed'].includes(data.failure as string))
        throw new TypeError('unknown publication ambiguity reason');
      const refs = references(data.lastKnownObservationRefs);
      if (refs.some((ref, index) => index > 0 && refs[index - 1] >= ref)) throw new TypeError('publication ambiguity refs are not byte-sorted');
    }
  } else if (kind === 'planned_descendant') {
    operationId(data.abortOperationId); if (!operationIds(data.retainedDescendantOperationIds).length) throw new TypeError('retained publication descendants are empty');
    references(data.observationRefs);
  } else if (kind === 'arena_retirement') {
    operationId(data.arenaId); reference(data.stateRootIdentityRef); reference(data.stateRootIdentityDigest);
    const arena = privateDirectoryIdentity(data.arenaIdentity), parent = privateDirectoryIdentity(data.parentIdentity);
    if (arena.deviceId !== parent.deviceId || arena.ownerUid !== parent.ownerUid || data.arenaAbsent !== true || data.arenaParentFsyncCompleted !== true)
      throw new TypeError('publication arena retirement has no exact parent, absence or completed sync');
    const raw = data.retirementObservation;
    if (!raw || typeof raw !== 'object') throw new TypeError('publication arena retirement lacks a platform observation');
    const observationKind = Object.getOwnPropertyDescriptor(raw, 'kind')?.value;
    if (observationKind === 'linux_unlinked') {
      if (closed(raw, ['kind', 'linkCount']).linkCount !== 0) throw new TypeError('Linux publication arena remains linked');
    } else if (observationKind === 'darwin_unlinked') {
      const observation = closed(raw, ['kind', 'heldPathUnchanged', 'parentPathUnchanged', 'observedLinkCount']);
      integer(observation.observedLinkCount);
      if (observation.heldPathUnchanged !== true || observation.parentPathUnchanged !== true)
        throw new TypeError('Darwin publication arena lacks original held-path observations');
    } else throw new TypeError('unknown publication arena retirement platform');
  } else if (kind === 'arena_namespace_absence') {
    operationId(data.arenaId); reference(data.stateRootIdentityRef); reference(data.stateRootIdentityDigest); reference(data.destinationObservationRef);
    const registered = privateDirectoryIdentity(data.registeredArenaIdentity), parent = privateDirectoryIdentity(data.namespaceParentIdentity);
    const locations = array(data.coveredLocations).map(location), keys = locations.map(publicationLocationKey);
    if (registered.deviceId !== parent.deviceId || registered.ownerUid !== parent.ownerUid ||
        data.arenaAbsent !== true || data.arenaParentFsyncCompleted !== true || data.workspaceParentFsyncCompleted !== true ||
        data.namespaceHandlesJoined !== true || locations.length < 1 || locations.length > 2 ||
        locations.some(value => value.kind !== 'publication_arena' || value.arenaId !== data.arenaId) ||
        keys.some((key, index) => index > 0 && Buffer.compare(Buffer.from(keys[index - 1]!), Buffer.from(key)) >= 0))
      throw new TypeError('publication namespace absence lost its current private namespace, complete coverage or actual maintenance join');
  } else if (kind === 'transient_absence') {
    const locations = array(data.transientLocations).map(location);
    const keys = locations.map(publicationLocationKey);
    if (locations.some(value => value.kind !== 'publication_arena') ||
        keys.some((key, index) => index > 0 && Buffer.compare(Buffer.from(keys[index - 1]), Buffer.from(key)) >= 0))
      throw new TypeError('publication transient absence locations are not private and ordered');
    if (Object.hasOwn(data, 'envelopeRetirements')) {
      let previous: string | undefined;
      const arenas: string[] = [];
      for (const raw of array(data.envelopeRetirements)) {
        const envelope = closed(raw, ['arenaId', 'retirement']), id = operationId(envelope.arenaId);
        if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(id)) >= 0)
          throw new TypeError('publication transient envelopes are not unique and byte ordered');
        decodePublicationPathRetirement(envelope.retirement); previous = id; arenas.push(id);
      }
      const expected = [...new Set(locations.map(value => (value as Extract<PublicationLocationV1, { kind: 'publication_arena' }>).arenaId))].sort();
      if (canonicalSha256(arenas) !== canonicalSha256(expected)) throw new TypeError('publication transient envelopes do not cover their exact private locations');
    } else {
      if (locations.length !== references(data.observationRefs).length)
        throw new TypeError('publication transient absence locations are not parallel to their descriptor observations');
      references(data.arenaRetirementRefs);
    }
  } else if (kind === 'projection_closure') {
    if (data.selectedBranch !== 'forward_finalize' && data.selectedBranch !== 'abort') throw new TypeError('invalid publication projection branch');
    reference(data.observedSourceRef); references(data.observedPathEvidenceRefs); references(data.forwardResultItemRefs);
    operationIds(data.unstartedForwardOperationIds); references(data.abortResultItemRefs);
  } else if (data.repositoryKind !== 'non_git') throw new TypeError('Git publication proof is not implemented');
  if (digestOmitting(data, 'proofDigest') !== data.proofDigest) throw new TypeError('publication proof digest differs');
  return immutableSnapshot(data) as PublicationProofV1;
}
export function decodePublicationDirectoryPreimage(value: unknown): PublicationDirectoryPreimageV1 {
  const data = closed(value, ['schemaVersion', 'format', 'deliveryRunId', 'deliveryPlanRef', 'operationId', 'opId', 'attempt',
    'beforeObservationRef', 'quarantineObservationRef', 'entriesRef', 'preimageDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-publication-directory-preimage-v1') throw new TypeError('invalid publication directory preimage schema');
  text(data.deliveryRunId); operationId(data.operationId); text(data.opId); integer(data.attempt);
  for (const field of ['deliveryPlanRef', 'beforeObservationRef', 'quarantineObservationRef', 'entriesRef', 'preimageDigest']) reference(data[field]);
  if (digestOmitting(data, 'preimageDigest') !== data.preimageDigest) throw new TypeError('publication directory preimage digest differs');
  return immutableSnapshot(data) as PublicationDirectoryPreimageV1;
}
export function decodeDeliveryTerminalProjectionEvidence(value: unknown): DeliveryTerminalProjectionEvidence {
  const data = closed(value, ['schemaVersion', 'deliveryRunId', 'deliveryPlanRef', 'selectedBranch', 'observedSourceRef', 'observedPathStates',
    'forwardResultItemRefs', 'unstartedForwardOperationIds', 'abortResultItemRefs', 'transientAbsenceEvidenceRef', 'projectionClosureEvidenceRef',
    'gitIndexUnchangedEvidenceRef', 'observedAt', 'evidenceDigest']);
  if (data.schemaVersion !== 1 || data.selectedBranch !== 'forward_finalize' && data.selectedBranch !== 'abort')
    throw new TypeError('invalid publication terminal projection schema or branch');
  text(data.deliveryRunId); parseCanonicalTime(text(data.observedAt));
  for (const field of ['deliveryPlanRef', 'observedSourceRef', 'transientAbsenceEvidenceRef', 'projectionClosureEvidenceRef', 'gitIndexUnchangedEvidenceRef', 'evidenceDigest']) reference(data[field]);
  let previous: string | undefined;
  for (const raw of array(data.observedPathStates)) {
    const entry = closed(raw, ['path', 'state', 'evidenceRef']), path = workspacePath(entry.path); observedState(entry.state); reference(entry.evidenceRef);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(path)) >= 0) throw new TypeError('publication observed projection paths are not unique and ordered');
    previous = path;
  }
  references(data.forwardResultItemRefs); const unstarted = operationIds(data.unstartedForwardOperationIds), abort = references(data.abortResultItemRefs);
  if (data.selectedBranch === 'forward_finalize' && (unstarted.length || abort.length)) throw new TypeError('forward publication projection retains abort or unstarted operations');
  if (digestOmitting(data, 'evidenceDigest') !== data.evidenceDigest) throw new TypeError('publication terminal projection digest differs');
  return immutableSnapshot(data) as DeliveryTerminalProjectionEvidence;
}
