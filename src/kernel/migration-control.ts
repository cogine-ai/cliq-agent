// Fixed migration rendezvous data. Decoding can only stop an unsupported entry;
// it never installs an Owner, grants authority or proves physical publication.
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting, normalizeAbsolutePath, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { canonicalSha256 } from './canonical.js';

export type OwnedImportControlPhase = 'cutover_preflight' | 'cutover_candidate_ready' | 'credential_cutover' | 'cutover_import_committed';
type ControlBase = Readonly<{ schemaVersion: 1; format: 'cliq-migration-control-v1'; migrationId: string; controlRevision: number;
  sourceGenerationDigest: string; targetGenerationId: string; stateRootIdentityRef: string; stateRootIdentityDigest: string;
  stateRootCanonicalAbsolutePath: string; preparationRef: string; preparationDigest: string;
  createdAt: string; updatedAt: string; controlDigest: string }>;
type Candidate = Readonly<{ inventoryRef: string; inventoryDigest: string; credentialReadyRef: string; credentialReadyDigest: string;
  backupRef: string; backupDigest: string; candidateRef: string; candidateDigest: string;
  previousControlRef: string; previousControlDigest: string }>;
export type OwnedLegacyImportControl =
  | (ControlBase & Readonly<{ phase: 'cutover_preflight' }>)
  | (ControlBase & Candidate & Readonly<{ phase: 'cutover_candidate_ready' }>)
  | (ControlBase & Candidate & Readonly<{ phase: 'credential_cutover'; legacyAuthMarkerDigest: string }>)
  | (ControlBase & Candidate & Readonly<{ phase: 'cutover_import_committed'; legacyAuthMarkerDigest: string;
      committedReceiptRef: string; committedReceiptDigest: string; committedResponseRef: string; committedResponseDigest: string }>);
type MarkerBase = Readonly<{ schemaVersion: 1; format: 'cliq-state-authority-v1'; generationId: string; migrationId: string;
  receiptRef: string; receiptDigest: string; stateRootIdentityRef: string; stateRootIdentityDigest: string;
  stateRootCanonicalAbsolutePath: string; publishedAt: string; markerDigest: string }>;
export type MigrationAuthorityMarker = MarkerBase & (
  | Readonly<{ authority: 'kernel'; candidateRef: string; candidateDigest: string;
      kernelGenerationIdentityRef: string; kernelGenerationIdentityDigest: string }>
  | Readonly<{ authority: 'legacy'; legacyGenerationRef: string; legacyGenerationDigest: string }>);

const BASE = ['schemaVersion', 'format', 'migrationId', 'controlRevision', 'sourceGenerationDigest', 'targetGenerationId',
  'stateRootIdentityRef', 'stateRootIdentityDigest', 'stateRootCanonicalAbsolutePath', 'preparationRef', 'preparationDigest',
  'createdAt', 'updatedAt', 'controlDigest', 'phase'];
const CANDIDATE = ['inventoryRef', 'inventoryDigest', 'credentialReadyRef', 'credentialReadyDigest', 'backupRef', 'backupDigest', 'candidateRef', 'candidateDigest'] as const;
const PHASES = ['cutover_preflight', 'cutover_candidate_ready', 'credential_cutover', 'cutover_import_committed'] as const;
function invalid(): never { throw new TypeError('migration control differs from its closed original-root contract'); }
function id(value: unknown): string {
  const text = controlWireText(value); if (!/^[A-Za-z0-9_-]{43}$/u.test(text)) return invalid(); return text;
}
function path(value: unknown): void { const text = controlWireText(value, 4096); if (normalizeAbsolutePath(text) !== text) return invalid(); }
function time(value: unknown): string { const text = controlWireText(value); parseCanonicalTime(text); return text; }

export function decodeOwnedLegacyImportControl(value: unknown): Readonly<OwnedLegacyImportControl> {
  assertControlWireJson(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const phase = (value as Record<string, unknown>).phase;
  const ordinal = PHASES.indexOf(phase as OwnedImportControlPhase); if (ordinal < 0) return invalid();
  const fields = [...BASE, ...(ordinal > 0 ? [...CANDIDATE, 'previousControlRef', 'previousControlDigest'] : []), ...(ordinal > 1 ? ['legacyAuthMarkerDigest'] : []),
    ...(ordinal > 2 ? ['committedReceiptRef', 'committedReceiptDigest', 'committedResponseRef', 'committedResponseDigest'] : [])];
  const data = controlWireRecord(value, fields);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-migration-control-v1' || controlWireInteger(data.controlRevision, 1) !== ordinal + 1) return invalid();
  id(data.migrationId); id(data.targetGenerationId); path(data.stateRootCanonicalAbsolutePath);
  for (const field of fields) if (field.endsWith('Ref') || field.endsWith('Digest')) controlWireRef(data[field]);
  const created = time(data.createdAt), updated = time(data.updatedAt);
  if (created > updated || ordinal === 0 && created !== updated || digestOmitting(data, 'controlDigest') !== data.controlDigest) return invalid();
  return immutableSnapshot(data) as Readonly<OwnedLegacyImportControl>;
}

/** One contiguous current control, not an alternative timestamp-selected
 * state machine. Original initial bytes remain at the Legacy rendezvous. */
export function assertOwnedImportControlSuccessor(previous: OwnedLegacyImportControl, next: OwnedLegacyImportControl): void {
  const before = decodeOwnedLegacyImportControl(previous), after = decodeOwnedLegacyImportControl(next);
  if (after.controlRevision !== before.controlRevision + 1 || before.updatedAt > after.updatedAt) return invalid();
  if (after.phase === 'cutover_preflight' || after.previousControlRef !== canonicalSha256(before) ||
      after.previousControlDigest !== before.controlDigest) return invalid();
  for (const field of ['migrationId', 'sourceGenerationDigest', 'targetGenerationId', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'stateRootCanonicalAbsolutePath', 'preparationRef', 'preparationDigest', 'createdAt'] as const) if (before[field] !== after[field]) return invalid();
  if (before.phase !== 'cutover_preflight') for (const field of CANDIDATE)
    if (before[field] !== after[field]) return invalid();
  if (before.phase === 'credential_cutover' && after.phase === 'cutover_import_committed' && before.legacyAuthMarkerDigest !== after.legacyAuthMarkerDigest) return invalid();
}

export function decodeMigrationAuthorityMarker(value: unknown): Readonly<MigrationAuthorityMarker> {
  assertControlWireJson(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const authority = (value as Record<string, unknown>).authority;
  if (authority !== 'kernel' && authority !== 'legacy') return invalid();
  const fields = ['schemaVersion', 'format', 'authority', 'generationId', 'migrationId', 'receiptRef', 'receiptDigest',
    'stateRootIdentityRef', 'stateRootIdentityDigest', 'stateRootCanonicalAbsolutePath', 'publishedAt', 'markerDigest',
    ...(authority === 'kernel' ? ['candidateRef', 'candidateDigest', 'kernelGenerationIdentityRef', 'kernelGenerationIdentityDigest'] :
      ['legacyGenerationRef', 'legacyGenerationDigest'])];
  const data = controlWireRecord(value, fields);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-state-authority-v1') return invalid();
  id(data.generationId); id(data.migrationId); path(data.stateRootCanonicalAbsolutePath); time(data.publishedAt);
  for (const field of fields) if (field.endsWith('Ref') || field.endsWith('Digest')) controlWireRef(data[field]);
  if (digestOmitting(data, 'markerDigest') !== data.markerDigest) return invalid();
  return immutableSnapshot(data) as Readonly<MigrationAuthorityMarker>;
}

export type LegacyMigrationRendezvous = Extract<OwnedLegacyImportControl, { phase: 'cutover_preflight' }> | MigrationAuthorityMarker;
export function decodeLegacyMigrationRendezvous(value: unknown): Readonly<LegacyMigrationRendezvous> {
  assertControlWireJson(value);
  const format = value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>).format : undefined;
  if (format === 'cliq-state-authority-v1') return decodeMigrationAuthorityMarker(value);
  const control = decodeOwnedLegacyImportControl(value); if (control.phase !== 'cutover_preflight') return invalid(); return control;
}
