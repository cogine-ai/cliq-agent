import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalSha256 } from './canonical.js';
import { dependencyProtectedEntryChanges, decodeDependencyIntegrityEvidence, type DependencyIntegrityEvidenceV1 } from './dependency-integrity.js';
import { digestOmitting } from './identity.js';
import type { WorkspaceEntryManifest, WorkspaceEntry } from './types.js';
const ref = (value: string) => canonicalSha256({ inert: value });
function manifest(entries: WorkspaceEntry[]): WorkspaceEntryManifest {
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries, entryCount: entries.length,
    byteCount: entries.reduce((sum, e) => sum + (e.kind === 'file' ? e.size : 0), 0),
    treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) };
}
test('protected dependency drift binds full M independently of unchanged projected source refs', () => {
  const original = { kind: 'file', path: 'ignored-install-input.js', mode: 420, size: 1, blobRef: ref('original') } as const;
  const before = manifest([original]);
  const after = manifest([{ ...original, blobRef: ref('changed') }, { kind: 'directory', path: 'node_modules', mode: 493 }]);
  const changed = dependencyProtectedEntryChanges(before, after);
  assert.equal(changed.length, 2);
  assert.deepEqual(dependencyProtectedEntryChanges(before, manifest([original, { kind: 'directory', path: 'node_modules', mode: 493 }])), []);
  const value: DependencyIntegrityEvidenceV1 = { schemaVersion: 1, format: 'cliq-dependency-integrity-evidence-v1', runId: 'run', opId: 'op', attempt: 0,
    dependencyPlanRef: ref('plan'), claimEvidenceRef: ref('claim'), captureRef: ref('capture'), workspaceGenerationRef: ref('generation'),
    workspaceBeforeRef: ref('before M'), workspaceAfterRef: ref('after M'), sourceBeforeRef: ref('same source'), sourceBeforeDigest: ref('same digest'),
    sourceAfterRef: ref('same source'), sourceAfterDigest: ref('same digest'), inspectorIdentityRef: ref('inspector'), inspectorIdentityDigest: ref('inspector meaning'),
    observationSource: 'trusted_out_of_containment_rehash', changedEntryDigests: changed, observedAt: '2026-10-27T00:00:00.000Z', evidenceDigest: '' };
  value.evidenceDigest = digestOmitting(value, 'evidenceDigest'); assert.deepEqual(decodeDependencyIntegrityEvidence(value), value);
  for (const change of [{ changedEntryDigests: [] }, { changedEntryDigests: [...changed, changed[0]!] }, { workspaceAfterRef: value.workspaceBeforeRef },
    { observationSource: 'permission_denied' }, { sourceBeforeRef: 'filtered fake ref' }, { outputPermit: true }]) {
    const bad = { ...value, ...change }; bad.evidenceDigest = digestOmitting(bad, 'evidenceDigest'); assert.throws(() => decodeDependencyIntegrityEvidence(bad));
  }
  const git = { ...value, changedEntryDigests: [], privateGitBeforeRef: ref('old Git'), privateGitAfterRef: ref('new Git') };
  git.evidenceDigest = digestOmitting(git, 'evidenceDigest'); assert.doesNotThrow(() => decodeDependencyIntegrityEvidence(git));
});
