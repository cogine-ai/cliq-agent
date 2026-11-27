import { canonicalJsonBytes } from './canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { assertRequestId, digestOmitting, normalizeAbsolutePath, parseCanonicalTime } from './identity.js';
import { assertBoundedJsonValue } from './json.js';
import { immutableSnapshot } from '../model/immutable.js';

export type OwnedLegacyImportRequestV1 = Readonly<{ protocolVersion: 1; method: 'state.migrate'; requestId: string;
  migrationId: string; legacyRootCanonicalAbsolutePath: string }>;
export type OwnedLegacyImportResponseV1 = Readonly<{ protocolVersion: 1; method: 'state.migrate'; status: 'completed';
  requestId: string; migrationId: string; preparationRef: string; preparationDigest: string; receiptRef: string; receiptDigest: string;
  completedAt: string }>;
export type KernelRollbackCommandV1 = Readonly<{ protocolVersion: 1; method: 'state.rollback'; requestId: string;
  migrationId: string; allowPlaintextLegacyCredentials: boolean }>;
export type LegacyRollbackReceiptV1 = Readonly<{ schemaVersion: 1; format: 'cliq-migration-receipt-v1'; migrationId: string;
  kind: 'legacy_rollback'; rollbackRequestRef: string; rollbackRequestDigest: string; backupRef: string; backupDigest: string;
  legacyGenerationRef: string; legacyGenerationDigest: string; archivedKernelGenerationRef: string; archivedKernelGenerationDigest: string;
  completedAt: string; receiptDigest: string }>;

function invalid(): never { throw new TypeError('invalid installed migration control data'); }
function migrationId(value: unknown): void { if (!/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(value, 43))) invalid(); }
function importRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  assertControlWireJson(value);
  assertBoundedJsonValue(value);
  if (canonicalJsonBytes(value).length > 1_048_576) invalid();
  const data = controlWireRecord(value, fields);
  if (data.protocolVersion !== 1 || data.method !== 'state.migrate') invalid();
  assertRequestId(controlWireText(data.requestId));
  migrationId(data.migrationId);
  return data;
}
export function decodeOwnedLegacyImportRequest(value: unknown): OwnedLegacyImportRequestV1 {
  const data = importRecord(value, ['protocolVersion', 'method', 'requestId', 'migrationId', 'legacyRootCanonicalAbsolutePath']);
  const location = controlWireText(data.legacyRootCanonicalAbsolutePath, 4096);
  if (normalizeAbsolutePath(location) !== location) invalid();
  return immutableSnapshot(data) as OwnedLegacyImportRequestV1;
}
export function decodeOwnedLegacyImportResponse(value: unknown): OwnedLegacyImportResponseV1 {
  const data = importRecord(value, ['protocolVersion', 'method', 'status', 'requestId', 'migrationId', 'preparationRef',
    'preparationDigest', 'receiptRef', 'receiptDigest', 'completedAt']);
  if (data.status !== 'completed') invalid();
  for (const field of ['preparationRef', 'preparationDigest', 'receiptRef', 'receiptDigest']) controlWireRef(data[field]);
  parseCanonicalTime(controlWireText(data.completedAt));
  return immutableSnapshot(data) as OwnedLegacyImportResponseV1;
}
export function decodeInstalledRollbackRequest(value: unknown): KernelRollbackCommandV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'migrationId', 'allowPlaintextLegacyCredentials']);
  if (data.protocolVersion !== 1 || data.method !== 'state.rollback' || typeof data.allowPlaintextLegacyCredentials !== 'boolean') invalid();
  assertRequestId(controlWireText(data.requestId));
  migrationId(data.migrationId);
  return immutableSnapshot(data) as KernelRollbackCommandV1;
}
export function decodeLegacyRollbackReceipt(value: unknown): LegacyRollbackReceiptV1 {
  assertControlWireJson(value);
  const references = ['rollbackRequestRef', 'rollbackRequestDigest', 'backupRef', 'backupDigest', 'legacyGenerationRef',
    'legacyGenerationDigest', 'archivedKernelGenerationRef', 'archivedKernelGenerationDigest', 'receiptDigest'] as const;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'migrationId', 'kind', 'completedAt', ...references]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-migration-receipt-v1' || data.kind !== 'legacy_rollback') invalid();
  migrationId(data.migrationId);
  for (const field of references) controlWireRef(data[field]);
  if (digestOmitting(data, 'receiptDigest') !== data.receiptDigest) invalid();
  parseCanonicalTime(controlWireText(data.completedAt));
  return immutableSnapshot(data) as LegacyRollbackReceiptV1;
}
