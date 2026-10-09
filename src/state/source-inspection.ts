import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { addCanonicalDuration, assertAdmissionKey, assertRequestId, digestOmitting, identityHash, normalizeAbsolutePath, normalizeBoundedText,
  parseCanonicalTime, requiredSafeInteger } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError } from './errors.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, readTimeFence } from './canonical-time.js';
import { readSourceInspectionStaging, type HeldSourceInspectionStaging } from './native-owner.js';
import { readAdmissionReplay, readControlRequest } from './rows.js';
import { assertVerifiedSourceInspectionTargetCut, readVerifiedSourceInspectionTarget,
  recheckVerifiedSourceInspectionTarget, type VerifiedSourceInspectionTarget } from './source-target.js';
import type { StateOwnerContext } from './state-owner.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';

export type SourceInspectionReplayKey = Readonly<{
  principalId: string;
  admissionKey: string;
  admissionIntentDigest: string;
}>;
type Value = Record<string, unknown>;
type SqlRow = {
  inspection_id: string; principal_id: string; method: string; admission_key: string;
  original_request_id: string; original_request_digest: string;
  admission_intent_digest: string; workspace_identity_digest: string; phase: string;
  row_version: unknown; row_json: string | null;
};
const BASE = ['schemaVersion', 'inspectionId', 'attempt', 'principalId', 'method', 'admissionKey',
  'admissionIntentDigest', 'targetRef', 'targetDigest', 'workspaceIdentityDigest', 'stateOwnerEpoch',
  'supervisorInstanceId', 'stagingNonceDigest', 'stagingIdentity', 'cancelRequested', 'rowVersion',
  'createdAt', 'deadlineAt', 'updatedAt', 'rowDigest'];
const SELECT = `SELECT inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
  workspace_identity_digest, phase, row_version,
  CASE WHEN length(CAST(row_json AS BLOB)) <= 1048576 THEN row_json ELSE NULL END AS row_json
  FROM source_inspection_attempts`;

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function record(value: unknown, keys: readonly string[], label: string): Value {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !keys.includes(key))) invalid(`${label} has unknown fields or is not its closed schema`);
  return value as Value;
}
function text(value: unknown, label: string, max = 128): string {
  if (typeof value !== 'string') invalid(`${label} must be a string`);
  try { if (normalizeBoundedText(value, 1, max) !== value) invalid(`${label} is not canonical NFC text`); }
  catch { invalid(`${label} is not bounded canonical text`); }
  return value;
}
function digest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) invalid(`${label} must be a canonical digest/ref`);
  return value;
}
function integer(value: unknown, label: string, min = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) invalid(`${label} must be a bounded safe integer`);
  return value;
}
function time(value: unknown, label: string): number {
  if (typeof value !== 'string') invalid(`${label} must be a canonical time`);
  try { return parseCanonicalTime(value); } catch { invalid(`${label} must be a canonical time`); }
}
function descriptor(value: unknown, mode: 448 | 384, label: string, disk = false): void {
  const data = record(value, ['deviceId', 'fileId', 'ownerUid', 'mode', ...(disk ? ['linkCount', 'byteCount'] : [])], label);
  for (const key of ['deviceId', 'fileId']) {
    const field = text(data[key], `${label}.${key}`);
    if (!/^(0|[1-9][0-9]*)$/.test(field)) invalid(`${label}.${key} is not unsigned decimal`);
  }
  if (integer(data.ownerUid, `${label}.ownerUid`) > 0xffffffff || data.mode !== mode) invalid(`${label} owner/mode differs`);
  if (disk && (data.linkCount !== 1 || integer(data.byteCount, `${label}.byteCount`, 1) < 1)) invalid(`${label} must be a held private disk`);
}
function plan(value: unknown): void {
  const data = record(value, ['launchNonceDigest', 'containmentPlanRef', 'containmentPlanDigest',
    'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'reservedBackendIdentity'], 'source inspection plan');
  for (const key of ['launchNonceDigest', 'containmentPlanRef', 'containmentPlanDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest'])
    digest(data[key], key);
  const backend = record(data.reservedBackendIdentity, ['kind', 'cgroupPath', 'cgroupId', 'deviceId', 'fileId', 'ownerUid',
    'pidNamespaceReservationId', 'subreaperStartToken', 'vmReservationId', 'guestImageRef', 'guestImageDigest', 'guestBootNonceDigest', 'privateDisk'],
  'source inspection reserved backend');
  if (backend.kind === 'linux') {
    record(backend, ['kind', 'cgroupPath', 'cgroupId', 'deviceId', 'fileId', 'ownerUid', 'pidNamespaceReservationId', 'subreaperStartToken'], 'Linux reservation');
    const cgroup = text(backend.cgroupPath, 'cgroupPath', 4096);
    try { if (normalizeAbsolutePath(cgroup) !== cgroup) invalid('cgroup path is not canonical'); }
    catch { invalid('cgroup path is not canonical'); }
    for (const key of ['cgroupId', 'deviceId', 'fileId'])
      if (!/^(0|[1-9][0-9]*)$/.test(text(backend[key], key))) invalid(`${key} must be unsigned decimal`);
    if (integer(backend.ownerUid, 'reserved owner uid') > 0xffffffff) invalid('reserved owner uid exceeds the native uid range');
    text(backend.pidNamespaceReservationId, 'namespace reservation');
    if (!/^[\x20-\x7e]+$/.test(text(backend.subreaperStartToken, 'subreaper token'))) invalid('subreaper token must be native ASCII');
  } else if (backend.kind === 'macos-vm') {
    record(backend, ['kind', 'vmReservationId', 'guestImageRef', 'guestImageDigest', 'guestBootNonceDigest', 'privateDisk'], 'VM reservation');
    text(backend.vmReservationId, 'VM reservation id');
    for (const key of ['guestImageRef', 'guestImageDigest', 'guestBootNonceDigest']) digest(backend[key], key);
    if (backend.guestImageRef !== backend.guestImageDigest) invalid('reserved guest image ref/digest differs');
    descriptor(backend.privateDisk, 384, 'reserved private disk', true);
  } else invalid('source inspection reserved backend is not supported');
}
function decode(value: unknown): SourceInspectionAttemptV1 {
  const data = record(value, [...BASE, 'phase', 'inputRef', 'inputDigest', 'plan', 'processContainmentRef',
    'retirementEvidenceRef', 'retiredAt', 'outcome'], 'source inspection row');
  if (data.schemaVersion !== 1 || data.attempt !== 1 || data.method !== 'run.submit') invalid('source inspection identity schema differs');
  for (const key of ['inspectionId', 'principalId', 'supervisorInstanceId']) text(data[key], key);
  const admissionKey = text(data.admissionKey, 'admission key');
  try { assertAdmissionKey(admissionKey); } catch { invalid('source inspection admission key is invalid'); }
  for (const key of ['admissionIntentDigest', 'targetRef', 'targetDigest', 'workspaceIdentityDigest', 'stagingNonceDigest', 'rowDigest']) digest(data[key], key);
  if (data.inspectionId !== identityHash('cliq-source-inspection-v1', data.principalId, 'run.submit', data.admissionKey, data.admissionIntentDigest))
    invalid('source inspection id does not bind its exact admission key/intent');
  integer(data.stateOwnerEpoch, 'source inspection owner epoch', 1);
  const version = integer(data.rowVersion, 'source inspection row version', 1);
  descriptor(data.stagingIdentity, 448, 'source inspection staging identity');
  if (typeof data.cancelRequested !== 'boolean') invalid('source inspection cancellation must be boolean');
  const created = time(data.createdAt, 'source inspection createdAt'), updated = time(data.updatedAt, 'source inspection updatedAt');
  if (updated < created || time(data.deadlineAt, 'source inspection deadline') <= created) invalid('source inspection times are inconsistent');
  if (data.phase === 'capturing') record(data, [...BASE, 'phase'], 'capturing source inspection');
  else if (data.phase === 'prepared' || data.phase === 'active') {
    record(data, [...BASE, 'phase', 'inputRef', 'inputDigest', 'plan', ...(data.phase === 'active' ? ['processContainmentRef'] : [])], `${data.phase} source inspection`);
    if (version < (data.phase === 'active' ? 3 : 2)) invalid('source inspection phase precedes its reservation');
    digest(data.inputRef, 'inspection input ref'); digest(data.inputDigest, 'inspection input digest'); plan(data.plan);
    if (data.phase === 'active') digest(data.processContainmentRef, 'inspection actual containment');
  } else if (data.phase === 'retired') {
    if (version < 2 || time(data.retiredAt, 'source inspection retiredAt') < created || time(data.retiredAt, 'source inspection retiredAt') > updated)
      invalid('source inspection retirement cut is invalid');
    digest(data.retirementEvidenceRef, 'inspection retirement evidence');
    if (Object.hasOwn(data, 'inputRef') || Object.hasOwn(data, 'inputDigest') || Object.hasOwn(data, 'plan')) {
      digest(data.inputRef, 'inspection input ref'); digest(data.inputDigest, 'inspection input digest'); plan(data.plan);
      if (Object.hasOwn(data, 'processContainmentRef')) digest(data.processContainmentRef, 'inspection actual containment');
    } else if (Object.hasOwn(data, 'processContainmentRef')) invalid('retired inspection actual containment lacks its input/plan');
    const result = record(data.outcome, ['kind', 'sourceManifestRef', 'sourceManifestDigest', 'privateGitStateRef', 'errorResponseRef'], 'inspection outcome');
    if (result.kind === 'captured') {
      record(result, ['kind', 'sourceManifestRef', 'sourceManifestDigest', 'privateGitStateRef'], 'captured inspection outcome');
      digest(result.sourceManifestRef, 'source manifest ref'); digest(result.sourceManifestDigest, 'source manifest digest');
      if (Object.hasOwn(result, 'privateGitStateRef')) digest(result.privateGitStateRef, 'private Git state ref');
    } else if (result.kind === 'failed' || result.kind === 'cancelled') {
      record(result, ['kind', 'errorResponseRef'], 'failed inspection outcome'); digest(result.errorResponseRef, 'inspection error response');
    } else invalid('inspection outcome is not part of its closed schema');
  } else invalid('source inspection phase is not part of its closed schema');
  if (digestOmitting(data, 'rowDigest') !== data.rowDigest) invalid('source inspection row digest differs');
  return immutableSnapshot(data as SourceInspectionAttemptV1);
}
function fromRow(row: SqlRow): SourceInspectionAttemptV1 {
  let decoded: SourceInspectionAttemptV1;
  try {
    if (typeof row.row_json !== 'string') invalid('source inspection row exceeds its metadata bound');
    decoded = decode(JSON.parse(row.row_json));
    assertRequestId(row.original_request_id); digest(row.original_request_digest, 'source original request digest');
    if (canonicalJsonBytes(decoded).toString() !== row.row_json) invalid('source inspection row is not canonical JSON');
    if (decoded.inspectionId !== row.inspection_id || decoded.principalId !== row.principal_id || decoded.method !== row.method ||
        decoded.admissionKey !== row.admission_key || decoded.admissionIntentDigest !== row.admission_intent_digest ||
        decoded.workspaceIdentityDigest !== row.workspace_identity_digest || decoded.phase !== row.phase ||
        decoded.rowVersion !== requiredSafeInteger(row.row_version, 'source inspection row version'))
      invalid('source inspection columns differ from its exact row');
  } catch (error) {
    if (error instanceof KernelStorageError) throw error;
    invalid(`source inspection row is invalid: ${error instanceof Error ? error.message : 'unknown metadata error'}`);
  }
  return decoded;
}

/** Read-only metadata, not a native resource capability or retirement proof. */
export function readSourceInspectionAttempt(connection: SqliteConnection | SqliteDriver,
  key: SourceInspectionReplayKey): SourceInspectionAttemptV1 | undefined {
  text(key.principalId, 'principal'); digest(key.admissionIntentDigest, 'admission intent');
  try { assertAdmissionKey(text(key.admissionKey, 'admission key')); } catch { invalid('admission key is invalid'); }
  const row = connection.prepare(`${SELECT} WHERE principal_id = ? AND method = 'run.submit' AND admission_key = ?`)
    .get<SqlRow>(key.principalId, key.admissionKey);
  if (!row) return undefined;
  if (row.admission_intent_digest !== key.admissionIntentDigest)
    throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'source inspection admission key belongs to a different original intent');
  return fromRow(row);
}

/** Startup walks the owning ledger one bounded row at a time, not source
 * paths or directory inventories. Every returned row is strictly decoded. */
export function readNextUnretiredSourceInspection(connection: SqliteConnection | SqliteDriver,
  afterInspectionId = ''): SourceInspectionAttemptV1 | undefined {
  const row = connection.prepare(`${SELECT} WHERE phase != 'retired' AND inspection_id > ? ORDER BY inspection_id LIMIT 1`)
    .get<SqlRow>(afterInspectionId);
  return row && fromRow(row);
}

/** Bounded original-request index only. Async replay still verifies that the
 * retained target/request bytes derive these columns before adopting a row. */
export function readSourceInspectionRequest(connection: SqliteConnection | SqliteDriver,
  principalId: string, requestId: string): { attempt: SourceInspectionAttemptV1; originalRequestId: string; originalRequestDigest: string } | undefined {
  const row = connection.prepare(`${SELECT} WHERE principal_id = ? AND method = 'run.submit' AND original_request_id = ?`)
    .get<SqlRow>(principalId, requestId);
  if (!row) return undefined;
  return { attempt: fromRow(row), originalRequestId: row.original_request_id, originalRequestDigest: row.original_request_digest };
}
export function readSourceInspectionOriginalRequest(connection: SqliteConnection | SqliteDriver,
  inspectionId: string): { originalRequestId: string; originalRequestDigest: string } {
  const row = connection.prepare(`SELECT original_request_id, original_request_digest FROM source_inspection_attempts WHERE inspection_id = ?`)
    .get<{ original_request_id: string; original_request_digest: string }>(inspectionId);
  if (!row) invalid('source inspection has no original request index');
  assertRequestId(row.original_request_id); digest(row.original_request_digest, 'source original request digest');
  return { originalRequestId: row.original_request_id, originalRequestDigest: row.original_request_digest };
}

/** The only fresh owning-row producer: native staging and a live verified
 * target must agree before the first byte can be captured. This cannot plan
 * or activate a process and accepts no generic phase/authority setter. */
export async function reserveSourceInspectionAttempt(driver: SqliteDriver, _artifacts: ArtifactCatalog,
  owner: StateOwnerContext, target: VerifiedSourceInspectionTarget, staging: HeldSourceInspectionStaging):
Promise<Extract<SourceInspectionAttemptV1, { phase: 'capturing' }>> {
  await recheckVerifiedSourceInspectionTarget(owner, target);
  const held = readVerifiedSourceInspectionTarget(owner, target);
  const key = { principalId: held.target.principalId, admissionKey: held.target.admissionKey,
    admissionIntentDigest: held.target.admissionIntentDigest };
  let result: Extract<SourceInspectionAttemptV1, { phase: 'capturing' }> | undefined;
  let clockRejected = false;
  driver.transaction(connection => {
    assertVerifiedSourceInspectionTargetCut(connection, owner, target);
    const physical = readSourceInspectionStaging(owner.filesystem, staging);
    if (physical.inspectionId !== held.inspectionId || physical.stagingIdentity.ownerUid !== owner.filesystem.root.ownerUid)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'source staging is not the verified target reservation');
    const existing = readSourceInspectionAttempt(connection, key);
    const sameRequest = readSourceInspectionRequest(connection, key.principalId, held.request.requestId);
    if (sameRequest && (sameRequest.originalRequestDigest !== held.request.requestDigest || sameRequest.attempt.inspectionId !== held.inspectionId))
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'source request id belongs to a different original intent');
    const control = readControlRequest(connection, key.principalId, 'run.submit', held.request.requestId);
    if (control && control.requestDigest !== held.request.requestDigest)
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'source request id already has a different first response');
    if (control) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'source request already has a terminal response; replay it without capture');
    const admitted = readAdmissionReplay(connection, 'runs', key.principalId, 'run.submit', key.admissionKey);
    if (admitted && admitted.admissionIntentDigest !== key.admissionIntentDigest)
      throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.submit key names a different intent');
    if (existing || admitted) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'source intent already owns a retained attempt or Run');
    if (connection.prepare(`SELECT inspection_id FROM source_inspection_attempts
      WHERE workspace_identity_digest = ? AND phase != 'retired' LIMIT 1`).get(held.workspace.identityDigest))
      throw new KernelStorageError('STATE_TRANSITION_INVALID', 'the exact workspace still owns an unretired source capture');
    // Persist clock-regression detection even when no reservation is admitted.
    if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
    const now = readTimeFence(connection)!.lastAcceptedAt;
    const row: Extract<SourceInspectionAttemptV1, { phase: 'capturing' }> = {
      schemaVersion: 1, inspectionId: held.inspectionId, attempt: 1, ...key, method: 'run.submit',
      targetRef: held.targetRef, targetDigest: held.target.targetDigest, workspaceIdentityDigest: held.workspace.identityDigest,
      stateOwnerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId,
      stagingNonceDigest: physical.stagingNonceDigest, stagingIdentity: physical.stagingIdentity,
      phase: 'capturing', cancelRequested: false, rowVersion: 1,
      createdAt: now, deadlineAt: addCanonicalDuration(now, held.request.budgets.wallTimeMs), updatedAt: now, rowDigest: '' };
    row.rowDigest = digestOmitting(row, 'rowDigest');
    decode(row);
    for (const metadata of held.metadata) insertArtifactMetadata(connection, metadata, now);
    connection.prepare(`INSERT INTO source_inspection_attempts
      (inspection_id, principal_id, method, admission_key, admission_intent_digest, original_request_id, original_request_digest,
       workspace_identity_digest, phase, row_version, row_json)
      VALUES (?, ?, 'run.submit', ?, ?, ?, ?, ?, 'capturing', 1, ?)`).run(row.inspectionId, row.principalId, row.admissionKey,
      row.admissionIntentDigest, held.request.requestId, held.request.requestDigest, row.workspaceIdentityDigest, canonicalJsonBytes(row).toString());
    result = immutableSnapshot(row);
  });
  if (clockRejected) throw new KernelStorageError('INVALID_REQUEST', 'canonical clock is regressed; source capture is paused');
  if (!result) throw new KernelStorageError('RECOVERY_REQUIRED', 'source reservation committed no owning row');
  return result;
}
