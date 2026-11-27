// Complete data audit of the actual sealed preview. This module creates no
// Owner, Run, clock, native scope or authority marker. The owning entry point
// obtains the projection itself from the original installed runtime.
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { controlWireText } from '../kernel/control-wire-data.js';
import { identityHash, parseCanonicalTime, requiredSafeInteger, assertArtifactRef } from '../kernel/identity.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeLegacyContextPayload, isLegacySessionContextKind, legacySessionItemId } from '../kernel/legacy-context.js';
import { decodeSessionContextHeadV2 } from '../kernel/session-context-pages.js';
import { walkSessionContextSegments, walkSessionContextPageEdges } from '../kernel/session-context-page-reader.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeRetainedWorkspaceIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import type { HeldMigrationBackupEntry } from './native-owner.js';
import type { PreparedImportArtifactRow, PreparedImportBaseline, PreparedImportProjection, PreparedImportRow,
  PreparedImportTable, PreparedLegacyItemRow, PreparedLegacySessionRow } from './prepared-import-candidate.js';
import { KERNEL_AUTHORITY_TABLES } from './schema.js';
import type { OwnedImportRetainedDataBudget } from './owned-import-budget.js';

const SESSION_COLUMNS = ['id', 'workspace_identity_ref', 'name', 'parent_session_id', 'forked_through_item_seq',
  'context_revision', 'latest_item_seq', 'context_projection_ref', 'created_at', 'updated_at', 'principal_id',
  'admission_method', 'admission_key', 'admission_intent_digest', 'admission_request_id'] as const;
const ITEM_COLUMNS = ['item_id', 'session_id', 'run_id', 'item_seq', 'kind', 'payload_ref', 'created_at'] as const;
const ARTIFACT_COLUMNS = ['ref', 'media_type', 'schema_kind', 'byte_length', 'created_at'] as const;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function columns(row: PreparedImportRow, expected: readonly string[]): void {
  if (!row || typeof row !== 'object' || types.isProxy(row) || ![Object.prototype, null].includes(Object.getPrototypeOf(row)))
    invalid('owned import rows require original plain scalar data');
  const fields = Object.getOwnPropertyDescriptors(row);
  if (Reflect.ownKeys(fields).length !== expected.length || expected.some(name => !Object.hasOwn(fields, name)) ||
      Reflect.ownKeys(fields).some(name => typeof name !== 'string' || !fields[name]!.enumerable ||
        !Object.hasOwn(fields[name]!, 'value') || fields[name]!.value !== null &&
          !['string', 'bigint'].includes(typeof fields[name]!.value)))
    invalid('owned import row differs from every exact signed-schema column');
  for (const field of Object.values(fields)) if (typeof field.value === 'string' &&
      Buffer.from(field.value, 'utf8').toString('utf8') !== field.value)
    invalid('owned import row cannot replace original SQL UTF-8 scalar bytes');
}
function text(value: unknown, maximum = 128): string { return controlWireText(value, maximum); }
function time(value: unknown): string { const result = text(value); parseCanonicalTime(result); return result; }
function integer(value: unknown, minimum: number): bigint {
  if (typeof value !== 'bigint' || value < BigInt(minimum) || value > BigInt(Number.MAX_SAFE_INTEGER))
    invalid('owned import row integer is not a lossless supported original value');
  return value;
}
export function encodeOwnedImportRow(row: PreparedImportRow): unknown {
  return Object.keys(row).sort().map(key => [key, typeof row[key] === 'bigint' ? { integer: row[key]!.toString() } : row[key]]);
}
export function decodePreparedLegacySessionRow(row: PreparedImportRow): PreparedLegacySessionRow {
  columns(row, SESSION_COLUMNS);
  text(row.id); text(row.principal_id); assertArtifactRef(text(row.workspace_identity_ref));
  assertArtifactRef(text(row.context_projection_ref)); assertArtifactRef(text(row.admission_intent_digest));
  if (!/^[A-Za-z0-9_-]{43}$/u.test(text(row.admission_key))) invalid('owned import Session admission key has the wrong original identity encoding');
  if (row.name !== null) controlWireText(row.name, 256, 0);
  if (row.parent_session_id !== null || row.forked_through_item_seq !== null || row.context_revision !== 1n ||
      row.admission_method !== 'state.migrate' || row.admission_request_id !== null)
    invalid('owned import Session cannot restore lifecycle or a fork/admission authority');
  integer(row.latest_item_seq, 0);
  if (time(row.created_at) > time(row.updated_at)) invalid('owned import Session time is noncausal');
  return row as PreparedLegacySessionRow;
}
export function decodePreparedLegacyItemRow(row: PreparedImportRow): PreparedLegacyItemRow {
  columns(row, ITEM_COLUMNS); text(row.item_id); text(row.session_id); assertArtifactRef(text(row.payload_ref));
  integer(row.item_seq, 1); time(row.created_at);
  if (row.run_id !== null || !isLegacySessionContextKind(row.kind))
    invalid('owned import item must be one of five context-only kinds without Run authority');
  return row as PreparedLegacyItemRow;
}
export function decodePreparedImportArtifactRow(row: PreparedImportRow): PreparedImportArtifactRow {
  columns(row, ARTIFACT_COLUMNS); assertArtifactRef(text(row.ref)); text(row.media_type); text(row.schema_kind);
  integer(row.byte_length, 0); time(row.created_at); return row as PreparedImportArtifactRow;
}
function same(left: PreparedImportRow, right: PreparedImportRow): boolean {
  return canonicalSha256(encodeOwnedImportRow(left)) === canonicalSha256(encodeOwnedImportRow(right));
}
function addCount(value: number): number {
  if (!Number.isSafeInteger(value + 1)) invalid('owned import count exceeds exact safe range'); return value + 1;
}
export type OwnedImportPreviewAudit = Readonly<{ importedRowSetDigest: string;
  sessions: number; items: number; newArtifacts: number; artifacts: number }>;
/** Digest is over all fixed imported scalar rows in their original BINARY/PK
 * order. The first metadata declaration is retained, including a same-byte
 * object which later receives a different typed use. */
export function digestOwnedImportRows(projection: PreparedImportProjection, baseline: PreparedImportBaseline): string {
  const hash = createHash('sha256').update('cliq-owned-import-row-set-v1\n');
  const originalRefs = new Set(baseline.artifacts.map(row => row.ref));
  for (const table of ['sessions', 'items', 'artifacts'] as const) {
    hash.update(canonicalJsonBytes(table)).update('\n');
    for (const row of projection.rows(table)) {
      if (table === 'artifacts' && originalRefs.has(row.ref)) continue;
      hash.update(canonicalJsonBytes(encodeOwnedImportRow(row))).update('\n');
    }
  }
  projection.assertHeld(); return hash.digest('hex');
}

/** The full candidate is traversed, even if a previous count/digest happened
 * to match. Every actual (ref,purpose) use rehashes bytes through the original
 * CAS and runs its own production decoder. schema_kind never selects a decoder. */
export async function auditSealedOwnedImportPreview(projection: PreparedImportProjection, artifacts: ArtifactCatalog,
  baseline: PreparedImportBaseline, input: Readonly<{ migrationId: string; principalId: string; stagedAt: string;
    sourceEntries: readonly HeldMigrationBackupEntry[]; permittedOriginalArtifactRefs: ReadonlySet<string>;
    retainedBudget: OwnedImportRetainedDataBudget;
    signal?: AbortSignal }>): Promise<OwnedImportPreviewAudit> {
  const current = () => { input.signal?.throwIfAborted(); artifacts.assertReadActive(); projection.assertHeld(); };
  current(); parseCanonicalTime(input.stagedAt);
  const baselineFamilies = { canonical_time_fence: baseline.canonicalTimeFence, state_owners: baseline.stateOwners };
  for (const table of ['canonical_time_fence', 'state_owners'] as const) {
    const expected = baselineFamilies[table], iterator = projection.rows(table);
    try {
      for (const row of expected) { const actual = iterator.next(); if (actual.done || !same(actual.value, row)) invalid('preview substituted original owner or time fence'); }
      if (!iterator.next().done) invalid('preview added an original owner or time fence');
    } finally { iterator.return?.(); }
  }
  for (const table of KERNEL_AUTHORITY_TABLES) if (!['canonical_time_fence', 'state_owners', 'artifacts', 'sessions', 'items'].includes(table))
    for (const _row of projection.rows(table)) invalid('preview restores a forbidden business or execution family');
  const original = new Map(baseline.artifacts.map(row => [row.ref, row]));
  for (const row of baseline.artifacts) {
    if (typeof row.ref !== 'string' || !input.permittedOriginalArtifactRefs.has(row.ref))
      invalid('original artifact catalog contains an unclassified retained authority/data family');
    const found = projection.artifact(String(row.ref)); if (!found || !same(found, row)) invalid('preview changed an original first artifact declaration');
  }
  const descriptor = (ref: string) => {
    const row = projection.artifact(ref); if (!row) invalid('preview omitted metadata for a referenced complete object');
    return decodePreparedImportArtifactRow(row);
  };
  const readBytes = async (ref: string, maximum: number): Promise<Buffer> => {
    current(); const row = descriptor(ref), bytes = await artifacts.readBoundedBytes(ref, maximum); current();
    if (BigInt(bytes.length) !== row.byte_length) invalid('preview metadata length differs from fully rehashed reference bytes');
    return bytes;
  };
  const readCanonical = async (ref: string, maximum = 1_048_576): Promise<unknown> => {
    const bytes = await readBytes(ref, maximum);
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!canonicalJsonBytes(value).equals(bytes)) invalid('preview typed reference is not exact canonical bytes');
    return value;
  };
  const pageReader = { readBoundedBytes: readBytes, assertReadActive: current };
  let artifactCount = 0, newArtifacts = 0, itemCount = 0, sessions = 0, indexedItems = 0;
  for (const raw of projection.rows('artifacts')) {
    current(); const row = decodePreparedImportArtifactRow(raw); artifactCount = addCount(artifactCount);
    if (!original.has(row.ref)) { newArtifacts = addCount(newArtifacts);
      if (row.created_at !== input.stagedAt) invalid('preview introduced metadata outside its exact stage time'); }
    // Full arbitrary backup/orphan bytes are retained without guessing a schema.
    // An authoritative purpose below still needs its independent typed read.
    for await (const _chunk of artifacts.readChunks(row.ref, requiredSafeInteger(row.byte_length, 'preview object size'))) current();
  }
  const sessionSources = new Map<string, Extract<HeldMigrationBackupEntry, { kind: 'regular_file' }>>();
  const contextSources = new Map<string, HeldMigrationBackupEntry>();
  for (const entry of input.sourceEntries) if (entry.kind === 'regular_file' && entry.purpose === 'portable_context') {
    input.retainedBudget.reserve(entry.canonicalRootRelativePath);
    contextSources.set(entry.canonicalRootRelativePath, entry);
  }
  const artifactSources = new Set<string>();
  for (const entry of input.sourceEntries) {
    const match = /^sessions\/[0-9]{4}\/[0-9]{2}\/[0-9]{2}\/([A-Za-z0-9_-]{1,128})\.json$/u.exec(entry.canonicalRootRelativePath);
    if (!match) continue;
    if (entry.kind !== 'regular_file' || entry.purpose !== 'portable_context' || sessionSources.has(match[1]!))
      invalid('source inventory has ambiguous/nonregular Session source');
    input.retainedBudget.reserve(match[1]!); sessionSources.set(match[1]!, entry);
  }
  // Independent complete items traversal catches orphan rows even when they
  // are absent from every otherwise valid Session graph.
  for (const raw of projection.rows('items')) {
    current(); const row = decodePreparedLegacyItemRow(raw); itemCount = addCount(itemCount);
    if (!projection.session(row.session_id)) invalid('preview item has no imported Session');
  }
  for (const raw of projection.rows('sessions')) {
    current(); const session = decodePreparedLegacySessionRow(raw); sessions = addCount(sessions);
    const source = sessionSources.get(session.id);
    if (!source || session.principal_id !== input.principalId || session.updated_at !== input.stagedAt ||
        session.admission_key !== identityHash('cliq-owned-legacy-session-admission-v1', input.migrationId, session.id) ||
        session.admission_intent_digest !== canonicalSha256({ method: 'state.migrate', migrationId: input.migrationId,
          sourcePath: source.canonicalRootRelativePath, sourceDigest: source.contentDigest, legacySessionId: session.id }))
      invalid('preview Session lost its original complete source/admission binding');
    const workspace = decodeRetainedWorkspaceIdentity(await readCanonical(session.workspace_identity_ref));
    if (workspace.ownerPrincipalId !== input.principalId || workspace.platform !== 'linux' ||
        workspace.kind === 'legacy_unavailable' && workspace.observedAt > input.stagedAt ||
        workspace.kind === 'live' && workspace.rootIdentity.ownerUid !== projection.image.stateRoot.ownerUid)
      invalid('preview workspace observation changed principal/platform or predates its cause');
    const head = decodeSessionContextHeadV2(await readCanonical(session.context_projection_ref, 262_144));
    if (head.sessionId !== session.id || head.contextRevision !== 1 || BigInt(head.throughItemSeq) !== session.latest_item_seq)
      invalid('preview Session graph changed its exact initial complete tail');
    // This separate edge walk verifies every retained page metadata row, even
    // for same-byte pages used more than once with distinct ranges/purposes.
    for await (const _edge of walkSessionContextPageEdges(pageReader, head, { signal: input.signal })) current();
    const items = projection.sessionItems(session.id); let through = 0n;
    const nextOrdinal = new Map<string, number>();
    try {
      for await (const segment of walkSessionContextSegments(pageReader, head, { signal: input.signal })) {
        current(); if (segment.kind !== 'raw') invalid('initial import graph may contain only raw context-only Legacy edges');
        for (const sourceItem of segment.items) {
          const next = items.next(); if (next.done) invalid('preview graph names an omitted SQL item');
          const item = decodePreparedLegacyItemRow(next.value); through++; indexedItems = addCount(indexedItems);
          if (item.session_id !== session.id || item.item_seq !== through || item.created_at !== input.stagedAt ||
              sourceItem.sourceSessionId !== session.id || BigInt(sourceItem.itemSeq) !== through ||
              sourceItem.itemId !== item.item_id || sourceItem.kind !== item.kind || sourceItem.payloadRef !== item.payload_ref)
            invalid('preview graph is not exactly its complete contiguous imported SQL index');
          const payload = decodeLegacyContextPayload(await readCanonical(item.payload_ref));
          if (payload.kind !== item.kind || payload.legacySessionId !== session.id || legacySessionItemId(payload) !== item.item_id)
            invalid('preview Legacy payload lost its own exact kind, Session or deterministic item identity');
          if (!contextSources.has(payload.sourceCanonicalRootRelativePath))
            invalid('preview Legacy payload names a source outside the complete portable inventory');
          if (payload.kind === 'legacy_record' || payload.kind === 'legacy_compaction' || payload.kind === 'legacy_bookmark') {
            const ordinal = nextOrdinal.get(payload.kind) ?? 0;
            if (payload.sourceCanonicalRootRelativePath !== source.canonicalRootRelativePath || payload.sourceOrdinal !== ordinal)
              invalid('preview Session payload names another original source');
            nextOrdinal.set(payload.kind, ordinal + 1);
          } else {
            if (payload.sourceOrdinal !== 0 || artifactSources.has(payload.sourceCanonicalRootRelativePath))
              invalid('preview auxiliary payload duplicates an original source or changed its ordinal');
            input.retainedBudget.reserve(payload.sourceCanonicalRootRelativePath);
            artifactSources.add(payload.sourceCanonicalRootRelativePath);
            if (payload.kind === 'legacy_plan') {
              const match = /^plans\/([A-Za-z0-9_-]{1,128})\/([A-Za-z0-9_-]{1,128})\/([A-Za-z0-9_-]{1,128})\/plan\.json$/u.exec(payload.sourceCanonicalRootRelativePath);
              if (!match || match[2] !== session.id || match[3] !== payload.content.planId)
                invalid('preview plan changed its original path/Session/plan identity');
            } else {
              const match = /^handoffs\/([A-Za-z0-9_-]{1,128})\/handoff\.json$/u.exec(payload.sourceCanonicalRootRelativePath);
              if (!match || match[1] !== payload.content.handoffId || payload.content.createdAt < session.created_at)
                invalid('preview handoff changed its original path/id or predates its Session');
            }
          }
          const historical = payload.kind === 'legacy_record' ? payload.content.recordedAt :
            payload.kind === 'legacy_compaction' || payload.kind === 'legacy_handoff' || payload.kind === 'legacy_bookmark' ? payload.content.createdAt : undefined;
          if (historical !== undefined && historical > input.stagedAt) invalid('preview Legacy historical time is in the future');
        }
      }
      if (!items.next().done || through !== session.latest_item_seq) invalid('preview graph omitted a complete imported SQL suffix');
    } finally { items.return?.(); }
  }
  for (const path of contextSources.keys()) if ((/^plans\/[^/]+\/[^/]+\/[^/]+\/plan\.json$/u.test(path) ||
      /^handoffs\/[^/]+\/handoff\.json$/u.test(path)) && !artifactSources.has(path))
    invalid('preview omitted a complete recognized auxiliary portable source');
  if (sessions !== sessionSources.size || indexedItems !== itemCount) invalid('preview omitted source Sessions or contains orphaned context items');
  current(); return Object.freeze({ importedRowSetDigest: digestOwnedImportRows(projection, baseline),
    sessions, items: itemCount, newArtifacts, artifacts: artifactCount });
}

