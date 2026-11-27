import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { assertDependencyUnmanagedEntries, decodeDependencyRetirement, dependencyInstalledTreeDigest, type DependencyRetirementV1 } from './dependency-retirement.js';
const ref = (s: string) => canonicalSha256({ inertData: s });
function entries(values: WorkspaceEntry[]): WorkspaceEntryManifest {
  const entries = [...values].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries, entryCount: entries.length,
    byteCount: entries.reduce((size, entry) => size + (entry.kind === 'file' ? entry.size : 0), 0),
    treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) };
}
test('ready-tree data binds the actual complete managed entries while all other files remain exact', () => {
  const source = { path: 'source.ts', kind: 'file', mode: 0o644, size: 1, blobRef: ref('source') } as const;
  const directory = { path: 'node_modules', kind: 'directory', mode: 0o755 } as const;
  const before = entries([source]);
  const after = entries([directory, { path: 'node_modules/package.js', kind: 'file', mode: 0o644, size: 1, blobRef: ref('package') }, source]);
  assert.doesNotThrow(() => assertDependencyUnmanagedEntries(before, after));
  assert.equal(dependencyInstalledTreeDigest(after), dependencyInstalledTreeDigest(structuredClone(after)));
  const packageChanged = entries([directory, { path: 'node_modules/package.js', kind: 'file', mode: 0o755, size: 1, blobRef: ref('package') }, source]);
  assert.notEqual(dependencyInstalledTreeDigest(after), dependencyInstalledTreeDigest(packageChanged));
  for (const extra of [{ ...source, blobRef: ref('changed') }, { ...source, mode: 0o755 as const },
    { ...source, path: 'generated/output.js' }]) assert.throws(() => assertDependencyUnmanagedEntries(before, entries([directory, extra])));
  assert.throws(() => dependencyInstalledTreeDigest(before));
  assert.throws(() => dependencyInstalledTreeDigest(entries([{ path: 'node_modules', kind: 'file', mode: 0o644, size: 1, blobRef: ref('file') }])));
});
test('retirement data cannot lose its original source, result, cache, Checkpoint or exact fields', () => {
  const value: DependencyRetirementV1 = { schemaVersion: 1, format: 'cliq-dependency-retirement-v1', runId: 'run', opId: 'op', attempt: 0,
    dispatchId: 'dispatch', leaseEpoch: 1, dependencyPlanRef: ref('plan'), packageCacheManifestRef: ref('cache'), captureRef: ref('capture'),
    captureDigest: ref('capture meaning'), checkpointId: 'checkpoint', workspaceStateRef: ref('M'), snapshotEvidenceRef: ref('snapshot'),
    parentRetirementEvidenceRef: ref('parent death'), sourceAfterRef: ref('source'), sourceAfterDigest: ref('source meaning'), installedTreeDigest: ref('installed'), evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); assert.deepEqual(decodeDependencyRetirement(value), value);
  for (const changed of [{ ...value, evidenceDigest: ref('other') }, { ...value, unknown: true }, { ...value, attempt: 2 },
    { ...value, sourceAfterRef: 'path' }, { ...value, parentRetirementEvidenceRef: undefined }]) assert.throws(() => decodeDependencyRetirement(changed));
  for (const pair of [{ integrityEvidenceRef: ref('actual drift') }, { integrityEvidenceDigest: ref('drift meaning') },
    { integrityEvidenceRef: ref('actual drift'), integrityEvidenceDigest: 'path' }]) {
    const changed = { ...value, ...pair }; changed.evidenceDigest = digestOmitting(changed, 'evidenceDigest');
    assert.throws(() => decodeDependencyRetirement(changed));
  }
  let getters = 0; const foreign = new Proxy({}, { ownKeys() { getters++; throw new Error('foreign'); }, get() { getters++; throw new Error('foreign'); } });
  assert.throws(() => decodeDependencyRetirement(foreign)); assert.equal(getters, 0);
});
