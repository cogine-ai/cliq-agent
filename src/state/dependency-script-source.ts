import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyScriptConditions, type DependencyScriptConditionsV1 } from '../kernel/dependency.js';
import type { SourceManifest, WorkspaceEntryManifest } from '../kernel/types.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { isManagedNodeDependencyPath } from '../kernel/dependency-source.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readPrivateGitData, privateGitSourceHead } from '../workspace/private-git-data.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries } from './decoders.js';
import { readSourceProjectionData } from './source-projection-data.js';
import { checkEntries, checkSourceManifest } from './source-validation.js';

function fail(): never { throw new TypeError('dependency script conditions differ from their complete source inputs'); }

/** Complete CAS data only. The capture owner/Run reducer must independently
 * require its genuine original retirement or current sealed M and SQL cut.
 * In particular, a retained refusal can never substitute for this read. */
export async function readDependencyScriptSourceConditions(artifacts: ArtifactCatalog, input: {
  sourceManifestRef: string; workspaceEntriesRef: string; privateGitStateRef?: string;
  workspaceIdentityDigest: string;
  resources: SandboxResourceSpec; packageManifestDigest: string; lockfileDigest: string;
  bindingGyp: DependencyScriptConditionsV1['bindingGyp']; execution: DependencyScriptConditionsV1['execution'];
}): Promise<DependencyScriptConditionsV1> {
  input = immutableSnapshot(input); artifacts.assertReadActive();
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, input.sourceManifestRef));
  const projected = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, source.entriesRef));
  return readDerivedDependencyScriptSourceConditions(artifacts, { ...input, source, projected });
}

/** The owning Checkpoint reader proves this derived projection against its
 * actual original M. Conditions name that derivation honestly and grant no
 * capture identity or script execution right. No CAS write occurs here. */
export async function readDerivedDependencyScriptSourceConditions(artifacts: ArtifactCatalog, input: {
  source: SourceManifest; projected: WorkspaceEntryManifest; workspaceEntriesRef: string; privateGitStateRef?: string;
  workspaceIdentityDigest: string; resources: SandboxResourceSpec; packageManifestDigest: string; lockfileDigest: string;
  bindingGyp: DependencyScriptConditionsV1['bindingGyp']; execution: DependencyScriptConditionsV1['execution'];
}): Promise<DependencyScriptConditionsV1> {
  input = immutableSnapshot(input); artifacts.assertReadActive();
  const source = decodeSourceManifest(input.source); checkSourceManifest(source);
  const projected = decodeWorkspaceEntries(input.projected); checkEntries(projected);
  if (canonicalSha256(projected) !== source.entriesRef) fail();
  const projection = decodeSourceProjection(await readCanonicalArtifact(artifacts, source.sourceProjectionRef));
  const selected = await readSourceProjectionData(artifacts, source, projection, input.resources);
  const workspace = decodeWorkspaceEntries(await readCanonicalArtifact(artifacts, input.workspaceEntriesRef)); checkEntries(workspace);
  if (source.workspaceIdentityDigest !== input.workspaceIdentityDigest || workspace!.byteCount > input.resources.maxGenerationBytes ||
      projected!.treeDigest !== source.treeDigest || canonicalSha256(workspace!.entries.filter(selected.includes)) !== canonicalSha256(projected!.entries)) fail();
  const root = workspace!.entries.find(entry => entry.path === 'package.json'), lock = workspace!.entries.find(entry => entry.path === 'package-lock.json');
  const gyp = workspace!.entries.find(entry => entry.path === 'binding.gyp');
  if (root?.kind !== 'file' || lock?.kind !== 'file' || root.blobRef !== input.packageManifestDigest || lock.blobRef !== input.lockfileDigest ||
      !projected!.entries.some(entry => entry.path === root.path && entry.kind === 'file' && entry.blobRef === root.blobRef) ||
      !projected!.entries.some(entry => entry.path === lock.path && entry.kind === 'file' && entry.blobRef === lock.blobRef) ||
      (input.bindingGyp.kind === 'absent' ? gyp !== undefined : gyp?.kind !== 'file' || gyp.blobRef !== input.bindingGyp.contentDigest) ||
      workspace!.entries.some(entry => entry.path === '.npmrc')) fail();
  // Include ignored/restorable data too: a lifecycle may read arbitrary repo
  // code, even when that file is absent from the projected FinalCandidate.
  await artifacts.mapReads(workspace!.entries.filter(entry => entry.kind === 'file'), async entry => {
    if (entry.kind !== 'file' || entry.size > input.resources.maxSingleFileBytes) fail();
    let count = 0;
    for await (const bytes of artifacts.readChunks(entry.blobRef, entry.size)) { artifacts.assertReadActive(); count += bytes.length; }
    if (count !== entry.size) fail();
  });
  if ((source.git !== undefined) !== (input.privateGitStateRef !== undefined)) fail();
  if (source.git && input.privateGitStateRef) {
    const git = await readPrivateGitData(artifacts, input.privateGitStateRef,
      { repositoryIdentityDigest: source.git.repositoryIdentityDigest, resources: input.resources });
    if (git.manifest.indexRef !== source.git.indexRef || git.index.indexTreeObjectId !== source.git.indexTreeObjectId ||
        canonicalSha256(privateGitSourceHead(git)) !== canonicalSha256(source.git.head)) fail();
  }
  artifacts.assertReadActive();
  return immutableSnapshot(decodeDependencyScriptConditions({ profile: 'npm-ci-v1', lockfilePath: 'package-lock.json',
    lockfileDigest: input.lockfileDigest, packageManifestDigest: input.packageManifestDigest, bindingGyp: input.bindingGyp,
    source: { sourceManifestRef: canonicalSha256(source), sourceManifestDigest: source.manifestDigest, sourceRole: source.role,
      projectedEntriesRef: source.entriesRef, projectedTreeDigest: source.treeDigest, sourceProjectionRef: source.sourceProjectionRef,
      sourceProjectionDigest: source.sourceProjectionDigest, workspaceEntriesRef: input.workspaceEntriesRef, workspaceTreeDigest: workspace!.treeDigest,
      scriptInputTreeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1',
        entries: workspace!.entries.filter(entry => !isManagedNodeDependencyPath(entry.path)) }),
      privateGit: input.privateGitStateRef ? { kind: 'present', stateRef: input.privateGitStateRef } : { kind: 'absent' } }, execution: input.execution }));
}

/** Explicit content-condition relation, never source identity equality. Both
 * actual manifest refs/roles remain bound separately in the owning history;
 * callers must first independently read the complete original/current graph.
 * This is also the only relation permitted for immutable child-ready reuse. */
export function sameDependencyScriptInputs(original: DependencyScriptConditionsV1, current: DependencyScriptConditionsV1): boolean {
  const content = (value: DependencyScriptConditionsV1) => {
    const data = decodeDependencyScriptConditions(value);
    const { sourceManifestRef: _ref, sourceManifestDigest: _digest, sourceRole: _role, workspaceEntriesRef: _workspaceRef,
      workspaceTreeDigest: _workspaceTree, ...source } = data.source;
    return { ...data, source };
  };
  return canonicalSha256(content(original)) === canonicalSha256(content(current));
}

/** Immutable ready data reuse only; never a script grant or physical proof.
 * The default ci/ignore-scripts profile executes no repo lifecycle and its
 * single-root registry graph is determined by these complete actual inputs.
 * Both source graphs are still independently fully read above, and original
 * provenance/full-M refs remain separately retained by the ready reader. */
export function sameDependencyReadyInputs(original: DependencyScriptConditionsV1, current: DependencyScriptConditionsV1, allowInstallScripts: boolean): boolean {
  if (typeof allowInstallScripts !== 'boolean') throw new TypeError('dependency ready reuse requires its original closed script mode');
  if (allowInstallScripts) return sameDependencyScriptInputs(original, current);
  const executionInputs = (value: DependencyScriptConditionsV1) => {
    const data = decodeDependencyScriptConditions(value);
    return { profile: data.profile, lockfilePath: data.lockfilePath, lockfileDigest: data.lockfileDigest,
      packageManifestDigest: data.packageManifestDigest, bindingGyp: data.bindingGyp, execution: data.execution };
  };
  return canonicalSha256(executionInputs(original)) === canonicalSha256(executionInputs(current));
}
