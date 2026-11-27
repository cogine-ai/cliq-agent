import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { KERNEL_AUTHORITY_TABLES } from './schema.js';
import { assertPreparedImportRowSet, updatePreparedImportInputDigests, type PreparedImportArtifactRow, type PreparedImportBaseline,
  type PreparedImportRow, type PreparedImportTable, type PreparedLegacyImportRows } from './prepared-import-candidate.js';

// Pure scalar comparison only. No SQLite, native object, StateOwner/Run,
// candidate identity or physical qualification is constructed by these tests.
const artifact = (ref: string, length = 1n): PreparedImportArtifactRow => ({
  ref, byte_length: length, media_type: 'text/plain', schema_kind: 'source-file', created_at: '2026-01-01T00:00:00.000Z'
});
const baseline = (artifacts: readonly PreparedImportArtifactRow[] = []): PreparedImportBaseline => ({
  canonicalTimeFence: [], stateOwners: [], artifacts, digest: 'unused-by-pure-row-comparison'
});
const imported = (artifacts: readonly PreparedImportArtifactRow[] = []): PreparedLegacyImportRows => ({ sessions: [], items: [], artifacts });
const read = (artifacts: readonly PreparedImportRow[]) => (table: PreparedImportTable): Iterable<PreparedImportRow> => table === 'artifacts' ? artifacts : [];

test('complete preview comparison visits all twenty-one families including the empty audit tail', () => {
  const seen: string[] = [];
  assertPreparedImportRowSet(table => { seen.push(table); return []; }, baseline(), imported());
  assert.deepEqual(seen, [...KERNEL_AUTHORITY_TABLES]);
  assert.ok(seen.includes('control_requests')); assert.ok(seen.includes('canonical_time_fence'));
});

test('preview retains the first artifact declaration across different typed uses of the same bytes', () => {
  const first = artifact('a'.repeat(64));
  const later = { ...first, schema_kind: 'session_legacy', media_type: 'application/json', created_at: '2026-02-01T00:00:00.000Z' };
  assert.doesNotThrow(() => assertPreparedImportRowSet(read([first]), baseline([first]), imported([later])));
  assert.throws(() => assertPreparedImportRowSet(read([later]), baseline([first]), imported([later])), /extra|changed/);
  assert.throws(() => assertPreparedImportRowSet(read([first]), baseline([first]), imported([{ ...later, byte_length: 2n }])), /length/);
});

test('complete comparison catches a late extra row rather than accepting a matching prefix', () => {
  const original = Array.from({ length: 2048 }, (_, index) => artifact(index.toString(16).padStart(64, '0')));
  assert.throws(() => assertPreparedImportRowSet(read([...original, artifact('f'.repeat(64))]), baseline(original), imported()), /extra|changed/);
  assert.throws(() => assertPreparedImportRowSet(read(original.slice(0, -1)), baseline(original), imported()), /omitted/);
});

test('preview equality preserves exact integers beyond JavaScript number precision', () => {
  const original = artifact('b'.repeat(64), 9007199254740993n);
  assert.doesNotThrow(() => assertPreparedImportRowSet(read([original]), baseline([original]), imported()));
  assert.throws(() => assertPreparedImportRowSet(read([{ ...original, byte_length: 9007199254740992n }]), baseline([original]), imported()), /changed/);
});

test('staging data hashes retain all input across batch boundaries and do not reset counters', () => {
  const make = () => ({ artifacts: createHash('sha256'), sessions: createHash('sha256'), items: createHash('sha256') });
  const artifacts = [artifact('c'.repeat(64)), artifact('d'.repeat(64))];
  const item = { item_id: 'context-row', session_id: 'data-only-session-id', run_id: null, item_seq: 1n,
    kind: 'legacy_record' as const, payload_ref: 'e'.repeat(64), created_at: '2026-01-01T00:00:00.000Z' };
  const whole = make(), divided = make();
  updatePreparedImportInputDigests(whole, { sessions: [], artifacts, items: [item] });
  updatePreparedImportInputDigests(divided, { sessions: [], artifacts: artifacts.slice(0, 1), items: [item] });
  updatePreparedImportInputDigests(divided, { sessions: [], artifacts: artifacts.slice(1), items: [] });
  for (const family of ['sessions', 'items', 'artifacts'] as const)
    assert.equal(whole[family].digest('hex'), divided[family].digest('hex'));
});

test('stage data cannot be silently changed by Node UTF-8 replacement', () => {
  const hashes = { artifacts: createHash('sha256'), sessions: createHash('sha256'), items: createHash('sha256') };
  assert.throws(() => updatePreparedImportInputDigests(hashes, imported([{ ...artifact('f'.repeat(64)), media_type: '\ud800' }])), /surrogate/);
});
