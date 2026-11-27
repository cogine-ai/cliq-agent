import { canonicalSha256 } from './canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { isManagedNodeDependencyPath } from './dependency-source.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import type { WorkspaceEntryManifest } from './types.js';
import { immutableSnapshot } from '../model/immutable.js';

/** A trusted full-M rehash, distinct from a projected source change. An
 * ignored protected input can change while both real SourceManifest refs stay
 * equal. Neither this data nor its digest substitutes for native retirement. */
export type DependencyIntegrityEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-dependency-integrity-evidence-v1'; runId: string; opId: string; attempt: 0;
  dependencyPlanRef: string; claimEvidenceRef: string; captureRef: string; workspaceGenerationRef: string;
  workspaceBeforeRef: string; workspaceAfterRef: string; sourceBeforeRef: string; sourceBeforeDigest: string;
  sourceAfterRef: string; sourceAfterDigest: string; inspectorIdentityRef: string; inspectorIdentityDigest: string;
  observationSource: 'trusted_out_of_containment_rehash'; changedEntryDigests: string[];
  privateGitBeforeRef?: string; privateGitAfterRef?: string; observedAt: string; evidenceDigest: string;
};
export function dependencyProtectedEntryChanges(before: WorkspaceEntryManifest, after: WorkspaceEntryManifest): string[] {
  const values = [before, after].map(manifest => new Map(manifest.entries.filter(entry => !isManagedNodeDependencyPath(entry.path))
    .map(entry => [entry.path, canonicalSha256(entry)])));
  const changed = new Set<string>();
  for (const path of new Set([...values[0]!.keys(), ...values[1]!.keys()])) {
    const old = values[0]!.get(path), next = values[1]!.get(path);
    if (old !== next) { if (old) changed.add(old); if (next) changed.add(next); }
  }
  return [...changed].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}
export function decodeDependencyIntegrityEvidence(value: unknown): DependencyIntegrityEvidenceV1 {
  assertControlWireJson(value);
  const v = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dependencyPlanRef', 'claimEvidenceRef',
    'captureRef', 'workspaceGenerationRef', 'workspaceBeforeRef', 'workspaceAfterRef', 'sourceBeforeRef', 'sourceBeforeDigest',
    'sourceAfterRef', 'sourceAfterDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'observationSource',
    'changedEntryDigests', 'observedAt', 'evidenceDigest'], ['privateGitBeforeRef', 'privateGitAfterRef']);
  if (v.schemaVersion !== 1 || v.format !== 'cliq-dependency-integrity-evidence-v1' ||
      v.observationSource !== 'trusted_out_of_containment_rehash' || v.evidenceDigest !== digestOmitting(v, 'evidenceDigest'))
    throw new TypeError('dependency integrity evidence has another observation');
  controlWireText(v.runId, 256); controlWireText(v.opId, 256); controlWireInteger(v.attempt, 0, 0);
  for (const key of ['dependencyPlanRef', 'claimEvidenceRef', 'captureRef', 'workspaceGenerationRef', 'workspaceBeforeRef', 'workspaceAfterRef',
    'sourceBeforeRef', 'sourceBeforeDigest', 'sourceAfterRef', 'sourceAfterDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest']) controlWireRef(v[key]);
  for (const key of ['privateGitBeforeRef', 'privateGitAfterRef']) if (Object.hasOwn(v, key)) controlWireRef(v[key]);
  parseCanonicalTime(controlWireText(v.observedAt, 24));
  if (!Array.isArray(v.changedEntryDigests)) throw new TypeError('dependency integrity changed entries are absent');
  let prior = '';
  for (const digest of v.changedEntryDigests) { controlWireRef(digest); if (digest <= prior) throw new TypeError('dependency integrity entries are not exact sorted unique digests'); prior = digest; }
  if (v.workspaceBeforeRef === v.workspaceAfterRef || !v.changedEntryDigests.length && v.privateGitBeforeRef === v.privateGitAfterRef)
    throw new TypeError('dependency integrity evidence has no protected workspace change');
  return immutableSnapshot(v) as DependencyIntegrityEvidenceV1;
}
