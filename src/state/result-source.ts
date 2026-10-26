import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { WorkspaceDiffOperationV1, WorkspaceDiffV1 } from '../kernel/result.js';
import type { RunSpec, SourceManifest, WorkspaceEntryManifest } from '../kernel/types.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries, decodeWorkspaceState } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { checkedPath, checkEntries, checkProjection, checkSourceManifest } from './source-validation.js';
import { readSourceProjectionData, type SourceProjectionReader } from './source-projection-data.js';
import { loadFrozenPrivateGit } from '../workspace/run-workspace/private-git.js';
import { decodeSandboxProfile } from './execution-closure.js';

/** A reproducible data limit, not a StopIntent or proof of physical retirement. */
export class CandidateSourceLimitError extends KernelStorageError {
  constructor(readonly reason: 'changed_paths' | 'changed_bytes', readonly observed: number, readonly limit: number) {
    super('STATE_TRANSITION_INVALID', 'candidate source exceeds its frozen result limit');
    this.name = 'CandidateSourceLimitError';
  }
}

function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
const comparePaths = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const covers = (root: string, value: string) => value === root || value.startsWith(`${root}/`);

type CandidateSourceGraph = {
  source: SourceManifest; sourceRef: string; diff: WorkspaceDiffV1; diffRef: string; metadata: PublishedArtifact[];
};
type CandidateSourceLimit = { reason: 'changed_paths' | 'changed_bytes'; observed: number; limit: number };
export type CandidateSourceReader = Pick<ArtifactCatalog, 'readCanonical' | 'readChunks'> & Partial<SourceProjectionReader>;
function completeReader(value: CandidateSourceReader): value is SourceProjectionReader {
  return typeof value.readBoundedBytes === 'function' && typeof value.withReadSignal === 'function' && typeof value.assertReadActive === 'function';
}

async function planCandidateSource(artifacts: CandidateSourceReader, spec: RunSpec, workspaceStateRef: string, signal?: AbortSignal): Promise<
  | { kind: 'ready'; graph: CandidateSourceGraph; publications: Array<{ value: unknown; artifact: PublishedArtifact }> }
  | { kind: 'limited'; limit: CandidateSourceLimit }
> {
  signal?.throwIfAborted();
  const metadata = new Map<string, PublishedArtifact>();
  const publications: Array<{ value: unknown; artifact: PublishedArtifact }> = [];
  const remember = (artifact: PublishedArtifact) => {
    const prior = metadata.get(artifact.ref);
    if (prior && prior.byteLength !== artifact.byteLength) mismatch('candidate source artifact byte lengths conflict');
    // The structured and ordinary-file views have each already verified their
    // own complete bytes. Identical bytes retain one first descriptor, not one
    // exclusive schema role; neither view can substitute for the other's checks.
    if (!prior) metadata.set(artifact.ref, artifact);
  };
  const read = async <T>(ref: string, schemaKind: string): Promise<T> => {
    signal?.throwIfAborted();
    const value = await readCanonicalArtifact<T>(artifacts, ref);
    signal?.throwIfAborted();
    remember({ ref, mediaType: 'application/json', schemaKind, byteLength: canonicalJsonBytes(value).byteLength });
    return value;
  };
  const plan = (value: unknown, schemaKind: string): PublishedArtifact => {
    const artifact = { ref: canonicalSha256(value), mediaType: 'application/json', schemaKind,
      byteLength: canonicalJsonBytes(value).byteLength };
    publications.push({ value, artifact }); remember(artifact); return artifact;
  };
  const workspace = decodeWorkspaceState(await read(workspaceStateRef, 'cliq-workspace-state-v1'));
  const base = decodeSourceManifest(await read(spec.baseWorkspaceManifestRef, 'cliq-source-manifest-v1'));
  if (!exactKeys(base, ['schemaVersion', 'format', 'role', 'workspaceIdentityDigest', 'entriesRef', 'sourceProjectionRef',
    'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest', 'treeDigest', 'manifestDigest', ...(base.git ? ['git'] : [])]) || base.role !== 'base' ||
      workspace.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef || base.sourceProjectionRef !== spec.sourceProjectionRef ||
      workspace.sourceProjectionDigest !== base.sourceProjectionDigest)
    mismatch('candidate source does not preserve its admitted base and projection');
  checkSourceManifest(base);
  const projection = decodeSourceProjection(await read(spec.sourceProjectionRef, 'cliq-source-projection-v1'));
  checkProjection(projection);
  if (!base.git && projection.classificationIndexRef !== undefined) mismatch('non-Git candidate carries a Git classification index');
  const rules = decodeFrozenIgnoreRules(await read(base.frozenIgnoreRulesRef, 'cliq-frozen-ignore-rules-v1'));
  if (projection.projectionDigest !== base.sourceProjectionDigest || projection.frozenIgnoreRulesRef !== base.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== base.frozenIgnoreRulesDigest || rules.rulesDigest !== base.frozenIgnoreRulesDigest)
    mismatch('candidate source frozen projection and ignore identities differ');
  if (!exactKeys(rules, ['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest', ...(base.git ? ['repositoryIdentityDigest'] : [])]) ||
      rules.matcherVersion !== 'cliq-git-wildmatch-v1' || !Array.isArray(rules.sources) || !Array.isArray(rules.rules))
    mismatch('candidate source ignore manifest has invalid fields');
  let selectedByFrozenSource: ((entry: import('../kernel/types.js').WorkspaceEntry) => boolean) | undefined;
  if (base.git || rules.sources.length || rules.rules.length || workspace.privateGitStateRef) {
    if (!completeReader(artifacts)) mismatch('candidate Git source requires complete bounded cancellable CAS reads');
    const profile = decodeSandboxProfile(await read(spec.sandboxProfileRef, 'cliq-sandbox-profile-v1'));
    const classification = await readSourceProjectionData(artifacts, base, projection, profile.resources, signal);
    selectedByFrozenSource = classification.includes;
    if (!base.git || !workspace.privateGitStateRef) mismatch('candidate Git source lost its original Checkpoint graph');
    const current = await loadFrozenPrivateGit(artifacts, base, workspace, classification.rules, signal, profile.resources);
    if (!current || current.index.objectFormat !== classification.index!.objectFormat) mismatch('candidate private Git format differs from its admitted source');
  }
  const baseEntries = decodeWorkspaceEntries(await read(base.entriesRef, 'cliq-workspace-entries-v1'));
  const currentEntries = decodeWorkspaceEntries(await read(workspace.entriesRef, 'cliq-workspace-entries-v1'));
  if (base.treeDigest !== baseEntries.treeDigest) mismatch('candidate source base tree digest differs');
  checkEntries(baseEntries); checkEntries(currentEntries);
  const excluded = (path: string) => projection.explicitExcludes.some(selector =>
    path === selector.path || selector.scope === 'subtree' && covers(selector.path, path));
  if (baseEntries.entries.some(entry => selectedByFrozenSource ? !selectedByFrozenSource(entry) : excluded(entry.path)))
    mismatch('candidate source admitted base includes a frozen excluded path');
  let priorInvalidated: string | undefined;
  for (const path of workspace.invalidatedEphemeralPaths) {
    checkedPath(path);
    if (priorInvalidated !== undefined && comparePaths(priorInvalidated, path) >= 0 ||
        currentEntries.entries.some(entry => covers(path, entry.path)))
      mismatch('candidate source invalidated ephemeral paths are not unique, sorted and disjoint');
    priorInvalidated = path;
  }
  const files = new Map<string, number>();
  for (const manifest of [baseEntries, currentEntries]) for (const entry of manifest.entries) {
    if (entry.kind !== 'file') continue;
    const prior = files.get(entry.blobRef);
    if (prior !== undefined && prior !== entry.size) mismatch('candidate source file size conflicts for the same blob');
    files.set(entry.blobRef, entry.size);
  }
  // Exhaustion rehashes every complete object with bounded memory. Identical
  // base/current blobs are read once and never copied back into CAS.
  for (const [ref, byteLength] of files) {
    signal?.throwIfAborted();
    for await (const _chunk of artifacts.readChunks(ref, byteLength)) { signal?.throwIfAborted(); }
    remember({ ref, byteLength, mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1' });
  }
  const selected = currentEntries.entries.filter(entry => selectedByFrozenSource ? selectedByFrozenSource(entry) : !excluded(entry.path));
  const entries: WorkspaceEntryManifest = { ...currentEntries, entries: selected, entryCount: selected.length,
    byteCount: selected.reduce((sum, entry) => sum + (entry.kind === 'file' ? entry.size :
      entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0), 0),
    treeDigest: canonicalSha256({ schemaVersion: 1, format: currentEntries.format, entries: selected }) };
  checkEntries(entries);
  const before = new Map(baseEntries.entries.map(entry => [entry.path, entry])), after = new Map(selected.map(entry => [entry.path, entry]));
  const paths = [...new Set([...before.keys(), ...after.keys()])].sort(comparePaths);
  const operations: WorkspaceDiffOperationV1[] = [];
  let changedBytes = 0;
  for (const path of paths) {
    const old = before.get(path), next = after.get(path);
    if (old && next && canonicalSha256(old) === canonicalSha256(next)) continue;
    operations.push(!old ? { path, kind: 'add', after: next! } : !next ? { path, kind: 'delete', before: old } :
      { path, kind: 'modify', before: old, after: next });
    if (next?.kind === 'file' && (old?.kind !== 'file' || old.blobRef !== next.blobRef || old.size !== next.size)) {
      changedBytes += next.size;
      if (!Number.isSafeInteger(changedBytes)) mismatch('candidate source changed byte count overflows');
    }
  }
  if (operations.length > projection.maxChangedPaths)
    return { kind: 'limited', limit: { reason: 'changed_paths', observed: operations.length, limit: projection.maxChangedPaths } };
  if (changedBytes > projection.maxChangedBytes)
    return { kind: 'limited', limit: { reason: 'changed_bytes', observed: changedBytes, limit: projection.maxChangedBytes } };
  let entriesRef = workspace.entriesRef;
  if (selected.length !== currentEntries.entries.length) entriesRef = plan(entries, entries.format).ref;
  const source: SourceManifest = { ...base, role: 'result', entriesRef, treeDigest: entries.treeDigest, manifestDigest: '' };
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  const publishedSource = plan(source, source.format);
  const diff: WorkspaceDiffV1 = { schemaVersion: 1, format: 'cliq-workspace-diff-v1', baseSourceRef: spec.baseWorkspaceManifestRef,
    resultSourceRef: publishedSource.ref, operations, diffDigest: '' };
  diff.diffDigest = digestOmitting(diff, 'diffDigest');
  const publishedDiff = plan(diff, diff.format);
  signal?.throwIfAborted();
  return { kind: 'ready', graph: { source, sourceRef: publishedSource.ref, diff, diffRef: publishedDiff.ref, metadata: [...metadata.values()] }, publications };
}

/** Immutable data only. This cannot propose a stop or adopt a worker snapshot. */
export async function readCandidateSourceLimit(artifacts: ArtifactCatalog, spec: RunSpec, workspaceStateRef: string) {
  const plan = await planCandidateSource(artifacts, spec, workspaceStateRef);
  return plan.kind === 'limited' ? plan.limit : undefined;
}

function requireReady(plan: Awaited<ReturnType<typeof planCandidateSource>>) {
  if (plan.kind === 'limited') throw new CandidateSourceLimitError(plan.limit.reason, plan.limit.observed, plan.limit.limit);
  return plan;
}

/** Pure retained-data reconstruction for historical recovery. No CAS object,
 * SQL row, execution permission or physical proof is created by this read. */
export async function readCandidateSource(artifacts: CandidateSourceReader, spec: RunSpec, workspaceStateRef: string, signal?: AbortSignal): Promise<CandidateSourceGraph> {
  return requireReady(await planCandidateSource(artifacts, spec, workspaceStateRef, signal)).graph;
}

/** The owning reducer independently validates the Run, original worker seal
 * and current SQL cut before committing the artifact-first projected graph. */
export async function prepareCandidateSource(artifacts: ArtifactCatalog, spec: RunSpec, workspaceStateRef: string) {
  const { graph, publications } = requireReady(await planCandidateSource(artifacts, spec, workspaceStateRef));
  const published = new Set<string>();
  return { graph, async publish(): Promise<CandidateSourceGraph> {
    for (const { value, artifact } of publications) if (!published.has(artifact.ref)) {
      const result = await artifacts.publishCanonical(value, artifact.schemaKind);
      if (canonicalSha256(result) !== canonicalSha256(artifact)) mismatch('candidate source publication differs from its retained plan');
      published.add(artifact.ref);
    }
    return graph;
  } };
}

/** Complete immutable fork data. It carries neither source-read permission
 * nor a generation birth; the ordinary new child preparing path owns both
 * materialization and its independent physical verification. */
export async function planChildForkSource(artifacts: ArtifactCatalog, spec: RunSpec, workspaceStateRef: string, signal?: AbortSignal) {
  const { graph, publications } = requireReady(await planCandidateSource(artifacts, spec, workspaceStateRef, signal));
  const source: SourceManifest = { ...graph.source, role: 'base', manifestDigest: '' };
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  const plan = planCanonicalArtifact(source, source.format);
  const retained = graph.metadata.filter(metadata => metadata.ref !== graph.sourceRef && metadata.ref !== graph.diffRef);
  return { source, sourceRef: plan.ref, metadata: retained,
    plans: [...publications.filter(value => value.artifact.ref !== graph.sourceRef && value.artifact.ref !== graph.diffRef)
      .map(value => planCanonicalArtifact(value.value, value.artifact.schemaKind)), plan] };
}
