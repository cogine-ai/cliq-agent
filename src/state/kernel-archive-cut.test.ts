import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../kernel/canonical.js';
import { KERNEL_AUTHORITY_TABLES } from './schema.js';
import { decodeKernelArchiveSqlCut, assertSameKernelArchiveSqlCut } from './kernel-archive-cut.js';

function cut() {
  const data = { schemaVersion: 1, format: 'cliq-kernel-archive-productive-cut-v1', stateSchemaVersion: 8,
    excludedTable: 'canonical_time_fence', tables: KERNEL_AUTHORITY_TABLES.filter(table => table !== 'canonical_time_fence')
      .map(table => ({ table, rowCount: 0, rowsDigest: canonicalSha256(table) })) };
  return { ...data, cutDigest: canonicalSha256(data) };
}
test('archive productive cut includes all twenty non-clock families in fixed order', () => {
  const value = decodeKernelArchiveSqlCut(cut()); assert.equal(value.tables.length, 20);
  assertSameKernelArchiveSqlCut(value, value);
  for (const change of [
    { ...cut(), unknown: true }, { ...cut(), excludedTable: 'state_owners' },
    { ...cut(), tables: cut().tables.slice(1) }, { ...cut(), tables: [...cut().tables].reverse() },
    { ...cut(), tables: cut().tables.map((row, index) => index === 0 ? { ...row, rowCount: 1 } : row) }
  ]) assert.throws(() => decodeKernelArchiveSqlCut(change));
});
test('a changed valid archive cut never passes original productive equivalence', () => {
  const before = decodeKernelArchiveSqlCut(cut()), raw = cut();
  raw.tables[19] = { ...raw.tables[19]!, rowCount: 1 }; const { cutDigest: _, ...core } = raw;
  const after = decodeKernelArchiveSqlCut({ ...core, cutDigest: canonicalSha256(core) });
  assert.throws(() => assertSameKernelArchiveSqlCut(before, after));
});
