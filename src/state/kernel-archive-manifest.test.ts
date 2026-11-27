import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import { decodeKernelRollbackDrainingControl } from '../kernel/kernel-archive-data.js';
import { decodeKernelArchiveCasEntry, decodeKernelArchiveCasIdentity, assertKernelArchiveCasEntries,
  type KernelArchiveCasEntry } from '../kernel/kernel-archive-namespace.js';
import { decodeKernelArchiveSqlCut } from './kernel-archive-cut.js';
import { CompleteKernelArchiveManifestStream } from './kernel-archive-manifest-stream.js';
import { encodeCurrentArchiveManifestSelection, encodeCurrentArchivePayload, encodeCurrentArchiveCasEntry } from '../kernel/current-kernel-archive-data.js';
import { KERNEL_AUTHORITY_TABLES } from './schema.js';
import { decodeCompleteKernelArchiveManifest, encodeCompleteKernelArchiveManifest,
  type CompleteKernelArchiveManifest } from './kernel-archive-manifest.js';

// Only closed data and independent encoding. These values establish no native
// birth, held Owner, archive, signed schema, drain or rollback permission.
function fixture(count = 0): Omit<CompleteKernelArchiveManifest, 'manifestDigest'> {
  const request = { schemaVersion: 1, format: 'cliq-kernel-rollback-control-v1', phase: 'rollback_draining', controlRevision: 1,
    migrationId: 'a'.repeat(43), archiveId: 'b'.repeat(43), kernelGenerationId: 'c'.repeat(43),
    stateRootIdentityRef: 'd'.repeat(64), stateRootIdentityDigest: 'e'.repeat(64), stateRootCanonicalAbsolutePath: '/data-only/root',
    requestRef: 'f'.repeat(64), requestDigest: '0'.repeat(64), originalImportControlRef: '1'.repeat(64), originalImportControlDigest: '2'.repeat(64),
    originalKernelAuthorityRef: '3'.repeat(64), originalKernelAuthorityDigest: '4'.repeat(64), preparedAt: '2026-10-02T00:00:00.000Z' };
  const control = decodeKernelRollbackDrainingControl({ ...request, controlDigest: canonicalSha256(request) });
  const cut = { schemaVersion: 1, format: 'cliq-kernel-archive-productive-cut-v1', stateSchemaVersion: 8,
    excludedTable: 'canonical_time_fence', tables: KERNEL_AUTHORITY_TABLES.filter(table => table !== 'canonical_time_fence')
      .map(table => ({ table, rowCount: 0, rowsDigest: canonicalSha256(table) })) };
  const entries: KernelArchiveCasEntry[] = Array.from({ length: count }, (_, index) => {
    const sha256 = canonicalSha256(['inert-bytes', index]);
    return decodeKernelArchiveCasEntry({ name: sha256, kind: 'published', sha256, byteCount: index,
      sourceFileId: String(index + 10), archiveFileId: String(index + 1000), sourceMode: 0o400 });
  }).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  const hash = createHash('sha256'); let totalBytes = 0;
  for (const entry of entries) {
    hash.update(entry.name).update('\0').update(entry.kind).update('\0').update(entry.sha256).update('\0').update(String(entry.byteCount)).update('\n');
    totalBytes += entry.byteCount;
  }
  return { schemaVersion: 1, format: 'cliq-owned-kernel-archive-v1',
    snapshotBoundary: 'globally_quiescent_rollback_draining_original_online_copy',
    excludedTail: 'canonical_time_fence_and_post_capture_rollback_audit', control,
    archiveDirectory: { deviceId: '1', fileId: '2', ownerUid: 1000 },
    database: { file: { deviceId: '1', fileId: '3', ownerUid: 1000 }, mode: 0o400, linkCount: 1, byteCount: 512,
      sha256: canonicalSha256('data-only-image'), copyMethod: 'original_node_sqlite_online_backup', stateSchemaVersion: 8,
      signedSchemaRef: canonicalSha256('data-only-schema'), signedSchemaDigest: canonicalSha256('data-only-schema-profile'),
      completeSqlDigest: canonicalSha256('data-only-complete-sql'), productiveCut: decodeKernelArchiveSqlCut({ ...cut, cutDigest: canonicalSha256(cut) }) },
    localInferenceRuntime: { kind: 'absent' }, localModelStore: { kind: 'absent' },
    cas: decodeKernelArchiveCasIdentity({ layout: 'cliq-flat-cas-v1', sourceDirectory: { deviceId: '1', fileId: '4', ownerUid: 1000 },
      archiveDirectory: { deviceId: '1', fileId: '5', ownerUid: 1000 }, entryCount: entries.length, totalBytes,
      combinedPayloadBytes: totalBytes + 512, entriesDigest: hash.digest('hex') }), entries };
}
async function* pages(entries: readonly KernelArchiveCasEntry[]) { for (let index = 0; index < entries.length; index += 64) yield entries.slice(index, index + 64); }
test('current archive packets preserve complete closed identities and reject selected paths or authority flags', async () => {
  const { entries, ...head } = fixture(3), encoded = await encodeCompleteKernelArchiveManifest(head, pages(entries));
  const selection = { archiveCollection: { deviceId: '18446744073709551615', fileId: '18446744073709551615', ownerUid: 1000 },
    archiveDirectory: encoded.header.archiveDirectory, manifest: { file: { deviceId: '1', fileId: '90', ownerUid: 1000 },
      byteCount: encoded.bytes.length, sha256: createHash('sha256').update(encoded.bytes).digest('hex') } };
  const manifest = encodeCurrentArchiveManifestSelection(selection), payload = encodeCurrentArchivePayload(encoded.header);
  assert.equal(manifest.subarray(0, 8).toString(), 'CLQMA001'); assert.equal(manifest.length, 104);
  assert.equal(manifest.readBigUInt64LE(8), (1n << 64n) - 1n); assert.equal(manifest.readBigUInt64LE(16), (1n << 64n) - 1n);
  assert.equal(manifest.readBigUInt64LE(56), BigInt(encoded.bytes.length)); assert.equal(manifest.readUInt32LE(68), 0);
  assert.equal(manifest.subarray(72).toString('hex'), selection.manifest.sha256);
  assert.equal(payload.subarray(0, 8).toString(), 'CLQMH001'); assert.equal(payload.length, 160);
  assert.equal(payload.readBigUInt64LE(24), BigInt(head.database.byteCount)); assert.equal(payload.readBigUInt64LE(96), 3n);
  assert.equal(payload.readBigUInt64LE(104), BigInt(head.cas.totalBytes)); assert.equal(payload.readUInt32LE(124), 0);
  for (const entry of entries) {
    const packet = encodeCurrentArchiveCasEntry(entry); assert.equal(packet.subarray(0, 8).toString(), 'CLQMC001');
    assert.equal(packet.readBigUInt64LE(16), BigInt(entry.archiveFileId)); assert.equal(packet.readBigUInt64LE(24), BigInt(entry.sourceFileId));
    assert.equal(packet.readBigUInt64LE(32), BigInt(entry.byteCount)); assert.equal(packet.readUInt32LE(44), 0);
    assert.equal(packet.subarray(48, 80).toString('hex'), entry.sha256); assert.equal(packet.subarray(80).toString(), entry.name);
  }
  assert.throws(() => encodeCurrentArchiveManifestSelection({ ...selection, path: '/caller/selected' } as typeof selection), TypeError);
  assert.throws(() => encodeCurrentArchiveManifestSelection({ ...selection, manifest: { ...selection.manifest, verified: true } } as typeof selection), TypeError);
  assert.throws(() => encodeCurrentArchivePayload({ ...encoded.header, writable: true } as typeof encoded.header), TypeError);
  assert.throws(() => encodeCurrentArchiveCasEntry({ ...entries[0]!, sourceFileId: '18446744073709551616' }), TypeError);
  let invoked = 0; const proxy = new Proxy(selection, { get() { invoked++; throw new Error('caller trap'); } });
  assert.throws(() => encodeCurrentArchiveManifestSelection(proxy), TypeError); assert.equal(invoked, 0);
});
test('bounded archive encoder emits complete JCS over empty and multiple actual data pages', async () => {
  for (const count of [0, 1, 130]) {
    const core = fixture(count), { entries, ...head } = core, encoded = await encodeCompleteKernelArchiveManifest(head, pages(entries));
    const manifest = { ...encoded.header, entries };
    assert.equal(encoded.header.manifestDigest, canonicalSha256(core));
    assert.deepEqual(encoded.bytes, canonicalJsonBytes(manifest));
    assert.deepEqual(decodeCompleteKernelArchiveManifest(JSON.parse(encoded.bytes.toString('utf8'))), manifest);
    assert.equal(digestOmitting(manifest, 'manifestDigest'), encoded.header.manifestDigest);
  }
});
test('archive metadata never infers membership from refs and rejects omitted, reordered or changed entries', async () => {
  const core = fixture(130);
  for (const changed of [
    { ...core, entries: core.entries.slice(1) },
    { ...core, entries: [...core.entries].reverse() },
    { ...core, entries: core.entries.map((entry, index) => index === 129 ? { ...entry, byteCount: entry.byteCount + 1 } : entry) },
    { ...core, cas: { ...core.cas, layout: 'fanout-not-observed' } },
    { ...core, database: { ...core.database, copyMethod: 'closed-source-not-observed' } },
    { ...core, unknown: true }
  ]) { const { entries, ...head } = changed; await assert.rejects(encodeCompleteKernelArchiveManifest(head as Omit<typeof core, 'entries'>, pages(entries))); }
  assert.throws(() => assertKernelArchiveCasEntries(core.cas, [...core.entries, core.entries[0]!], core.database.byteCount));
});
test('both actual temporary classes remain explicit raw orphan bytes', () => {
  const hash = canonicalSha256('unpublished'), suffix = '1'.repeat(32);
  for (const entry of [
    { name: `.tmp-${hash}-${suffix}`, kind: 'temporary_ref', sourceMode: 0o400 },
    { name: `.tmp-stream-${suffix}`, kind: 'temporary_stream', sourceMode: 0o600 },
    { name: `.tmp-stream-${suffix}`, kind: 'temporary_stream', sourceMode: 0o400 }
  ]) assert.equal(decodeKernelArchiveCasEntry({ ...entry, sha256: hash, byteCount: 1, sourceFileId: '1', archiveFileId: '2' }).kind, entry.kind);
  for (const entry of [
    { name: hash, kind: 'published', sourceMode: 0o600 },
    { name: `.tmp-${'0'.repeat(64)}-${suffix}`, kind: 'temporary_ref', sourceMode: 0o400 },
    { name: `../${hash}`, kind: 'published', sourceMode: 0o400 }
  ]) assert.throws(() => decodeKernelArchiveCasEntry({ ...entry, sha256: hash, byteCount: 1, sourceFileId: '1', archiveFileId: '2' }));
});
test('archive encoding obeys original cancellation before any complete result exists', async () => {
  const abort = new AbortController(), reason = new Error('original data encoding cancellation'); abort.abort(reason);
  const { entries, ...head } = fixture(130);
  await assert.rejects(encodeCompleteKernelArchiveManifest(head, pages(entries), abort.signal), error => error === reason);
});

// Finite inert byte fixtures, never a physical archive or original-FD EOF/join.
function streamManifest(bytes: Buffer, chunkSize: number, expectedDigest = createHash('sha256').update(bytes).digest('hex')) {
  const reader = new CompleteKernelArchiveManifestStream({ byteCount: bytes.length, sha256: expectedDigest });
  const entries: KernelArchiveCasEntry[] = [];
  for (let offset = 0; offset < bytes.length; offset += chunkSize) entries.push(...reader.feed(bytes.subarray(offset, offset + chunkSize)));
  return { reader, entries };
}
test('complete manifest stream reads exact JCS across every small fragment boundary without retaining entries', async () => {
  for (const count of [0, 1, 130]) {
    const original = fixture(count), { controlDigest: _digest, ...oldControl } = original.control;
    const changedControl = { ...oldControl, stateRootCanonicalAbsolutePath: '/data-only/é/核' };
    const core = { ...original, control: decodeKernelRollbackDrainingControl({ ...changedControl, controlDigest: canonicalSha256(changedControl) }) };
    const { entries, ...head } = core, encoded = await encodeCompleteKernelArchiveManifest(head, pages(entries));
    for (const chunkSize of [1, 7, 65536]) {
      const result = streamManifest(encoded.bytes, chunkSize);
      assert.deepEqual(result.entries, entries); assert.deepEqual(result.reader.finish(), encoded.header);
      assert.throws(() => result.reader.finish(), TypeError); assert.throws(() => result.reader.feed(Buffer.from('x')), TypeError);
    }
  }
});
test('manifest stream rejects noncanonical fields, duplicate/unknown keys, incomplete data and wrong complete hashes', async () => {
  const { entries, ...head } = fixture(3), encoded = await encodeCompleteKernelArchiveManifest(head, pages(entries));
  const text = encoded.bytes.toString('utf8');
  for (const bytes of [Buffer.from(' ' + text), Buffer.from(text + '\n'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), encoded.bytes]),
    Buffer.from(text.replace('"entries":[', '"entries":[ ')), Buffer.from(text.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')),
    Buffer.from(text.replace('"schemaVersion":1', '"schemaVersion":1,"unknown":true')), encoded.bytes.subarray(0, encoded.bytes.length - 1)])
    assert.throws(() => streamManifest(bytes, 7).reader.finish(), TypeError);
  assert.throws(() => streamManifest(encoded.bytes, 7, '0'.repeat(64)).reader.finish(), TypeError);
  const short = new CompleteKernelArchiveManifestStream({ byteCount: encoded.bytes.length + 1, sha256: createHash('sha256').update(encoded.bytes).digest('hex') });
  for (let offset = 0; offset < encoded.bytes.length; offset += 65536) short.feed(encoded.bytes.subarray(offset, offset + 65536));
  assert.throws(() => short.finish(), TypeError);
});
test('late corrupt manifest bytes cannot turn streamed entry observations into a complete header', async () => {
  const { entries, ...head } = fixture(130), encoded = await encodeCompleteKernelArchiveManifest(head, pages(entries));
  const changed = Buffer.from(encoded.bytes.toString().replace('"snapshotBoundary":"globally_', '"snapshotBoundary":"invalid_'));
  const result = streamManifest(changed, 65536); assert.equal(result.entries.length, entries.length);
  assert.throws(() => result.reader.finish(), TypeError, 'early entry data is not complete source/manifest proof');
});
