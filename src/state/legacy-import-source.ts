// One production source-to-candidate pipeline. Native retains the original
// EX/Owner/root and fixes both source passes; the Store's sole transaction and
// marker-last publication remain separate authority boundaries.
import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { controlWireText } from '../kernel/control-wire-data.js';
import { digestOmitting, identityHash, normalizeAbsolutePath, parseCanonicalTime, requiredSafeInteger } from '../kernel/identity.js';
import type { SignedKernelSchemaV1 } from '../kernel/runtime-upgrade.js';
import type { SessionContextSegment, WorkspaceIdentityV1 } from '../kernel/types.js';
import { decodeRetainedWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { stageAndVerifyInstalledImportCandidate, type HeldInstalledRuntime } from './installed-runtime.js';
import { copyHeldMigrationBackup, readHeldMigrationContextSources, beginHeldMigrationContextProjection,
  verifyHeldMigrationSourceSnapshot, type HeldMigrationFilesystem, type HeldMigrationSourceFile,
  assertHeldMigrationSourceRoot, observeHeldMigrationWorkspaceIdentity,
  type PreparedImportStageSink } from './native-owner.js';
import type { PreparedImportArtifactRow, PreparedImportBaseline, PreparedLegacyItemRow } from './prepared-import-candidate.js';
import { LegacySessionSourceStream, type LegacySessionSourceItem } from './legacy-source-stream.js';
import { projectLegacySessionItem, projectLegacySessionMetadata, legacyWorkspaceLookupPath,
  type ImportedLegacySessionMetadata, type ProjectedLegacyItem } from './legacy-source-context.js';
import { decodeLegacyArtifactSource, projectLegacyPlanSource, projectLegacyHandoffSource, validateLegacyPlanProgress } from './legacy-source-artifacts.js';
import { LegacyControlPreflight } from './legacy-source-preflight.js';
import { publishSessionContextGraph } from './session-context-graph.js';

const SMALL_SOURCE_BYTES = 1_048_576;
type ImportInput = Readonly<{ migrationId: string; principalId: string; legacyRootPath: string;
  publicationPreparedAt: string; signal?: AbortSignal }>;
type PassSummary = Readonly<{ sources: number; sessions: number; payloads: number; sourceDigest: string }>;
function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function sessionId(path: string): string | undefined {
  return /^sessions\/[0-9]{4}\/[0-9]{2}\/[0-9]{2}\/([A-Za-z0-9_-]{1,128})\.json$/u.exec(path)?.[1];
}
function artifactRow(artifact: PublishedArtifact, at: string): PreparedImportArtifactRow {
  return { ref: artifact.ref, media_type: artifact.mediaType, schema_kind: artifact.schemaKind,
    byte_length: BigInt(artifact.byteLength), created_at: at };
}
function nextCounter(value: number): number {
  if (!Number.isSafeInteger(value + 1)) throw new RangeError('Legacy import exact counter is exhausted'); return value + 1;
}
function historicalTime(item: ProjectedLegacyItem): string | undefined {
  return item.payload.kind === 'legacy_record' ? item.payload.content.recordedAt :
    item.payload.kind === 'legacy_compaction' || item.payload.kind === 'legacy_bookmark' ? item.payload.content.createdAt : undefined;
}
function missing(error: unknown): boolean {
  let current = error;
  for (let depth = 0; depth < 4 && current && typeof current === 'object'; depth++) {
    if ('code' in current && current.code === 'ENOENT') return true;
    current = 'cause' in current ? current.cause : undefined;
  }
  return false;
}
async function workspace(scope: HeldMigrationFilesystem, metadata: ImportedLegacySessionMetadata, input: ImportInput): Promise<WorkspaceIdentityV1> {
  const originalLookup = legacyWorkspaceLookupPath(metadata);
  let reason: 'missing' | 'identity_unverifiable' = 'identity_unverifiable';
  if (originalLookup !== undefined) {
    try {
      // Physical no-follow observation only. This neither reads repo config
      // nor grants Workspace Trust, tool permission or execution admission.
      const result = observeHeldMigrationWorkspaceIdentity(scope, originalLookup, input.principalId);
      input.signal?.throwIfAborted(); return result;
    } catch (error) {
      if (error instanceof ResourceRetirementError || input.signal?.aborted || !(error instanceof KernelStorageError) || error.code !== 'INVALID_REQUEST') throw error;
      if (missing(error)) reason = 'missing';
    }
  }
  // The NFD original is never used via its NFC display locator. This branch
  // is permanently non-executable until the user creates a new live Session.
  const value = { schemaVersion: 1, format: 'cliq-workspace-identity-v1', kind: 'legacy_unavailable', platform: 'linux',
    ownerPrincipalId: input.principalId, legacyCanonicalRootPath: metadata.legacyWorkspaceDisplayPath,
    unavailableReason: reason, observedAt: input.publicationPreparedAt, identityDigest: '' };
  value.identityDigest = digestOmitting(value, 'identityDigest'); return decodeRetainedWorkspaceIdentity(value);
}

/** Exactly one native EOF/hash/close is required for each source. A small
 * auxiliary source is bounded before allocation; raw Session records are
 * projected incrementally and never assembled into a giant JavaScript tree. */
async function consumeSourcePass(scope: HeldMigrationFilesystem, input: ImportInput,
  stage?: Readonly<{ sink: PreparedImportStageSink; artifacts: ArtifactCatalog; selected: HeldInstalledRuntime }>): Promise<PassSummary> {
  const controls = new LegacyControlPreflight(input.publicationPreparedAt), sourceHash = createHash('sha256');
  let source: HeldMigrationSourceFile | undefined, stream: LegacySessionSourceStream | undefined;
  let small: Buffer[] = [], smallBytes = 0, maxHistoricalTime: string | undefined, nextSeq = 0n;
  let sources = 0, sessions = 0, payloads = 0;
  let markdown: Readonly<{ directory: string; text: string }> | undefined;
  const current = () => { input.signal?.throwIfAborted(); scope.assertHeld(); stage?.artifacts.assertReadActive(); };
  const publish = async (item: ProjectedLegacyItem, seq: bigint) => {
    if (!stage) return;
    current(); const published = await stage.artifacts.publishCanonical(item.payload, item.payload.format); current();
    if (published.ref !== item.payloadRef) return mismatch('Legacy projected payload publication changed its complete bytes');
    stage.sink.append({ sessions: [], artifacts: [artifactRow(published, input.publicationPreparedAt)], items: [{
      item_id: item.itemId, session_id: item.payload.legacySessionId, run_id: null, item_seq: seq,
      kind: item.payload.kind, payload_ref: published.ref, created_at: item.createdAt }] });
  };
  const sourceItem = async (item: LegacySessionSourceItem) => {
    if (!source) return mismatch('Legacy item lost its actual current source');
    const id = sessionId(source.canonicalRootRelativePath); if (!id) return mismatch('Legacy item appeared outside a Session source');
    const projected = projectLegacySessionItem({ sourcePath: source.canonicalRootRelativePath, item, publicationPreparedAt: input.publicationPreparedAt });
    controls.sessionItem(id, item);
    const at = historicalTime(projected); if (at && (maxHistoricalTime === undefined || at > maxHistoricalTime)) maxHistoricalTime = at;
    payloads = nextCounter(payloads); nextSeq++;
    if (nextSeq > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('Legacy Session item sequence is exhausted');
    await publish(projected, nextSeq);
  };
  for await (const event of readHeldMigrationContextSources(scope, input.signal)) {
    current();
    if (event.kind === 'source_begin') {
      if (source) return mismatch('Legacy native source began before its predecessor actually joined');
      source = event.source; stream = undefined; small = []; smallBytes = 0; maxHistoricalTime = undefined; nextSeq = 0n;
      if (sessionId(source.canonicalRootRelativePath)) stream = new LegacySessionSourceStream({
        byteCount: source.byteCount, contentDigest: source.contentDigest });
      else if (source.byteCount > SMALL_SOURCE_BYTES) throw new RangeError('Legacy auxiliary source exceeds the supported fixed small-source profile');
    } else if (event.kind === 'source_chunk') {
      if (!source) return mismatch('Legacy bytes have no genuine current native source');
      if (stream) for (const item of stream.feed(event.bytes)) { await sourceItem(item); current(); }
      else {
        smallBytes += event.bytes.byteLength;
        if (smallBytes > source.byteCount || smallBytes > SMALL_SOURCE_BYTES) return mismatch('Legacy auxiliary source exceeded its captured byte bound');
        small.push(Buffer.from(event.bytes));
      }
    } else {
      if (!source || canonicalSha256(source) !== canonicalSha256(event.source)) return mismatch('Legacy native source completion differs from its original identity');
      sources = nextCounter(sources); sourceHash.update(canonicalJsonBytes(source)).update('\n');
      const path = source.canonicalRootRelativePath;
      if (stream) {
        const metadata = projectLegacySessionMetadata(path, stream.finish(), input.publicationPreparedAt);
        controls.sessionControls(stream.preflightControls());
        if (maxHistoricalTime !== undefined && maxHistoricalTime > metadata.originalUpdatedAt)
          return mismatch('Legacy history contains an item later than its original Session header');
        sessions = nextCounter(sessions);
        if (stage) {
          const captured = await workspace(scope, metadata, input); current();
          const descriptor = await stage.artifacts.publishCanonical(captured, captured.format); current();
          const empty = await publishSessionContextGraph(stage.artifacts, { sessionId: metadata.legacySessionId,
            contextRevision: 1, throughItemSeq: 0, segments: [] }, { signal: input.signal,
              onPublished: artifact => stage.sink.append({ sessions: [], items: [], artifacts: [artifactRow(artifact, input.publicationPreparedAt)] }) });
          const admissionKey = identityHash('cliq-owned-legacy-session-admission-v1', input.migrationId, metadata.legacySessionId);
          stage.sink.append({ items: [], artifacts: [artifactRow(descriptor, input.publicationPreparedAt)], sessions: [{
            id: metadata.legacySessionId, workspace_identity_ref: descriptor.ref, name: metadata.name ?? null,
            parent_session_id: null, forked_through_item_seq: null, context_revision: 1n, latest_item_seq: 0n,
            context_projection_ref: empty.artifact.ref, created_at: metadata.createdAt, updated_at: metadata.updatedAt,
            principal_id: input.principalId, admission_method: 'state.migrate', admission_key: admissionKey,
            admission_intent_digest: canonicalSha256({ method: 'state.migrate', migrationId: input.migrationId,
              sourcePath: path, sourceDigest: source.contentDigest, legacySessionId: metadata.legacySessionId }), admission_request_id: null }] });
        }
      } else {
        if (smallBytes !== source.byteCount) return mismatch('Legacy auxiliary source did not finish all captured bytes');
        const bytes = Buffer.concat(small, smallBytes); small = []; smallBytes = 0;
        if (path.endsWith('/plan.md')) {
          const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
          markdown = { directory: path.slice(0, -7), text };
        } else if (path.endsWith('/plan.json')) {
          const directory = path.slice(0, -9), value = decodeLegacyArtifactSource(bytes);
          const item = projectLegacyPlanSource({ sourcePath: path, value, legacyRootPath: input.legacyRootPath,
            publicationPreparedAt: input.publicationPreparedAt, ...(markdown?.directory === directory ? { markdown: markdown.text } : {}) });
          markdown = undefined; payloads = nextCounter(payloads);
          if (stage) {
            if (!stage.sink.session(item.payload.legacySessionId)) return mismatch('Legacy plan names a Session outside the complete captured Session inventory');
            await publish(item, stage.sink.sessionItemTail(item.payload.legacySessionId) + 1n);
          }
        } else if (path.endsWith('/progress.json') && path.startsWith('plans/')) {
          validateLegacyPlanProgress({ sourcePath: path, value: decodeLegacyArtifactSource(bytes), legacyRootPath: input.legacyRootPath,
            publicationPreparedAt: input.publicationPreparedAt });
        } else if (path.startsWith('handoffs/')) {
          const item = projectLegacyHandoffSource({ sourcePath: path, value: decodeLegacyArtifactSource(bytes), legacyRootPath: input.legacyRootPath,
            publicationPreparedAt: input.publicationPreparedAt });
          payloads = nextCounter(payloads);
          if (stage) {
            const parent = stage.sink.session(item.payload.legacySessionId);
            if (!parent || item.payload.kind !== 'legacy_handoff' || item.payload.content.createdAt < parent.created_at)
              return mismatch('Legacy handoff names an absent or noncausal original Session');
            await publish(item, stage.sink.sessionItemTail(item.payload.legacySessionId) + 1n);
          }
        } else {
          if (source.purpose !== 'validation_only') return mismatch('unknown portable Legacy source cannot be imported as empty data');
          controls.source(path, decodeLegacyArtifactSource(bytes));
        }
      }
      source = undefined; stream = undefined; maxHistoricalTime = undefined;
      await setImmediate(); current();
    }
  }
  if (source) return mismatch('Legacy source pipeline ended without its actual native completion');
  controls.finish();
  return Object.freeze({ sources, sessions, payloads, sourceDigest: sourceHash.digest('hex') });
}

/** Bounded data projection used by the real candidate producer. Grouping raw
 * tuples preserves every source edge while using the existing 256-tuple page
 * capacity instead of exhausting 64 segment slots with single-item ranges. */
export async function* legacyImportContextSegments(sessionId: string,
  source: AsyncIterable<PreparedLegacyItemRow> | Iterable<PreparedLegacyItemRow>, signal?: AbortSignal): AsyncIterableIterator<SessionContextSegment> {
  type Tuple = Extract<SessionContextSegment, { kind: 'raw' }>['items'][number];
  let pending: Tuple[] = [], next = 1;
  for await (const item of source) {
    signal?.throwIfAborted();
    const itemSeq = requiredSafeInteger(item.item_seq, 'Legacy candidate Session item sequence');
    if (item.session_id !== sessionId || item.run_id !== null || itemSeq !== next++)
      return mismatch('Legacy context projection requires its complete original Session item prefix');
    pending.push({ sourceSessionId: sessionId, itemSeq, itemId: item.item_id, kind: item.kind, payloadRef: item.payload_ref });
    if (pending.length === 64) {
      yield { kind: 'raw', fromItemSeq: pending[0]!.itemSeq, throughItemSeq: pending.at(-1)!.itemSeq, items: pending };
      pending = [];
    }
  }
  signal?.throwIfAborted();
  if (pending.length) yield { kind: 'raw', fromItemSeq: pending[0]!.itemSeq, throughItemSeq: pending.at(-1)!.itemSeq, items: pending };
}

async function finishContexts(scope: HeldMigrationFilesystem, sink: PreparedImportStageSink, artifacts: ArtifactCatalog,
  input: ImportInput, expectedSessions: number): Promise<void> {
  let count = 0;
  for await (const original of sink.sessions()) {
    input.signal?.throwIfAborted(); scope.assertHeld();
    const through = sink.sessionItemTail(original.id), throughItemSeq = requiredSafeInteger(through, 'Legacy candidate Session complete item tail');
    async function* items(): AsyncIterableIterator<PreparedLegacyItemRow> {
      for await (const item of sink.sessionItems(original.id)) {
        input.signal?.throwIfAborted(); scope.assertHeld();
        yield item;
      }
    }
    const graph = await publishSessionContextGraph(artifacts, { sessionId: original.id, contextRevision: 1,
      throughItemSeq, segments: legacyImportContextSegments(original.id, items(), input.signal) }, { signal: input.signal,
        onPublished: artifact => sink.append({ sessions: [], items: [], artifacts: [artifactRow(artifact, input.publicationPreparedAt)] }) });
    sink.finalizeSession(original, { contextProjectionRef: graph.artifact.ref, throughItemSeq: through }); count = nextCounter(count);
  }
  if (count !== expectedSessions) return mismatch('Legacy candidate context construction omitted or added a captured Session');
}

/** The caller has already durably installed the owned preparation/stop spine
 * and completed the existing private credential stage under the original EX.
 * This function cannot create either authority. It performs real full backup,
 * semantic read-only pass, second native projection pass, closed preview seal
 * and actual original-FD SQL readback through the selected signed runtime. */
export async function buildInstalledLegacyImportCandidate(selected: HeldInstalledRuntime, scope: HeldMigrationFilesystem,
  artifacts: ArtifactCatalog, schema: SignedKernelSchemaV1, baseline: PreparedImportBaseline, input: ImportInput) {
  controlWireText(input.principalId); parseCanonicalTime(input.publicationPreparedAt);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(input.migrationId) || normalizeAbsolutePath(input.legacyRootPath) !== input.legacyRootPath)
    throw new TypeError('Legacy import requires its fixed migration id and actual canonical source root');
  assertHeldMigrationSourceRoot(scope, input.migrationId, input.legacyRootPath);
  const backup = createHash('sha256'); let backupEntries = 0, backupBytes = 0;
  for await (const entry of copyHeldMigrationBackup(scope, input.signal)) {
    backup.update(canonicalJsonBytes(entry)).update('\n'); backupEntries = nextCounter(backupEntries);
    if (entry.kind === 'regular_file') { backupBytes += entry.byteCount; if (!Number.isSafeInteger(backupBytes)) throw new RangeError('Legacy backup byte counter is exhausted'); }
  }
  const checked = await consumeSourcePass(scope, input);
  await verifyHeldMigrationSourceSnapshot(scope, input.signal);
  const result = await stageAndVerifyInstalledImportCandidate(selected, scope, schema, baseline, async (sink, signal) => {
    const stagedInput = { ...input, signal };
    beginHeldMigrationContextProjection(scope);
    const projected = await consumeSourcePass(scope, stagedInput, { sink, artifacts: artifacts.withReadSignal(signal), selected });
    if (canonicalSha256(projected) !== canonicalSha256(checked)) return mismatch('Legacy projection pass differs from its complete original source pass');
    await finishContexts(scope, sink, artifacts.withReadSignal(signal), stagedInput, projected.sessions);
    await verifyHeldMigrationSourceSnapshot(scope, signal);
    return projected;
  }, input.signal);
  // An observation digest is not a typed BackupManifest or old creator proof.
  // The final import receipt must retain the real complete physical manifest.
  return Object.freeze({ ...result, backupObservation: Object.freeze({ entries: backupEntries, byteCount: backupBytes,
    observationDigest: backup.digest('hex') }) });
}
