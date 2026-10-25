import { canonicalSha256 } from '../kernel/canonical.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import type { FrozenIgnoreRulesV1, GitIndexSnapshotV1, SourceManifest, SourceProjectionSpec, WorkspaceEntry } from '../kernel/types.js';
import { createFrozenIgnoreMatcher, readFrozenIgnoreRules } from '../workspace/frozen-ignore.js';
import { readGitIndexData } from '../workspace/private-git-data.js';
import type { ArtifactCatalog } from './artifacts.js';
import { KernelStorageError } from './errors.js';
import { checkProjection, checkSourceManifest } from './source-validation.js';

/** Complete immutable classification only: no live Git/config/rule reads,
 * worker evidence, permissions or execution authority. */
export type SourceProjectionReader = Pick<ArtifactCatalog, 'readCanonical' | 'readBoundedBytes' | 'readChunks' | 'assertReadActive'> & {
  withReadSignal(signal: AbortSignal): SourceProjectionReader;
};
export async function readSourceProjectionData(artifacts: SourceProjectionReader, source: SourceManifest,
  projection: SourceProjectionSpec, resources: SandboxResourceSpec, signal?: AbortSignal) {
  checkSourceManifest(source); checkProjection(projection);
  const rules = await readFrozenIgnoreRules(artifacts, source.frozenIgnoreRulesRef, source.git?.repositoryIdentityDigest, signal);
  if (projection.projectionDigest !== source.sourceProjectionDigest || projection.frozenIgnoreRulesRef !== source.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== source.frozenIgnoreRulesDigest || rules.rulesDigest !== source.frozenIgnoreRulesDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained source projection and original rule closure differ');
  let index: GitIndexSnapshotV1 | undefined, classificationIndex: GitIndexSnapshotV1 | undefined;
  if (source.git) {
    if (!projection.classificationIndexRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'Git projection lost its original classification index');
    index = await readGitIndexData(artifacts, source.git.indexRef,
      { repositoryIdentityDigest: source.git.repositoryIdentityDigest, resources }, signal);
    if (index.indexTreeObjectId !== source.git.indexTreeObjectId || source.git.head.kind !== 'unborn' &&
        source.git.head.objectId.length !== (index.objectFormat === 'sha1' ? 40 : 64))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'source Git HEAD and admitted canonical index differ');
    classificationIndex = projection.classificationIndexRef === source.git.indexRef ? index : await readGitIndexData(artifacts,
      projection.classificationIndexRef, { repositoryIdentityDigest: source.git.repositoryIdentityDigest, resources }, signal);
    if (classificationIndex.objectFormat !== index.objectFormat) throw new KernelStorageError('ARTIFACT_MISMATCH', 'Git classification and current metadata object formats differ');
  } else if (projection.classificationIndexRef !== undefined) throw new KernelStorageError('ARTIFACT_MISMATCH', 'non-Git projection carries a Git classification index');
  return Object.freeze({ rules, index, classificationIndex, includes: sourceEntrySelector(projection, rules, classificationIndex) });
}

export function sourceEntrySelector(projection: SourceProjectionSpec, rules: FrozenIgnoreRulesV1, index?: GitIndexSnapshotV1) {
  const ignored = createFrozenIgnoreMatcher(rules), paths = index?.entries.map(entry => entry.canonicalRootRelativePath) ?? [];
  const tracked = new Set(paths);
  const ancestor = new Set<string>();
  for (const path of paths) { const parts = path.split('/'); parts.pop(); while (parts.length) { ancestor.add(parts.join('/')); parts.pop(); } }
  return (entry: WorkspaceEntry): boolean => !projection.explicitExcludes.some(selector => selector.path === entry.path ||
    selector.scope === 'subtree' && entry.path.startsWith(`${selector.path}/`)) &&
    (!ignored(entry.path, entry.kind === 'directory') || tracked.has(entry.path) || entry.kind === 'directory' && ancestor.has(entry.path));
}

export function sameSourceGit(left: SourceManifest, right: SourceManifest): boolean {
  return left.git === undefined || right.git === undefined ? left.git === right.git : canonicalSha256(left.git) === canonicalSha256(right.git);
}
