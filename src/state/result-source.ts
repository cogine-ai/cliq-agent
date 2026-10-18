import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { WorkspaceDiffOperationV1, WorkspaceDiffV1 } from '../kernel/result.js';
import type { RunSpec, SourceManifest, SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries, decodeWorkspaceState } from './decoders.js';
import { KernelStorageError } from './errors.js';

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

function checkedPath(value: string): void {
  if (typeof value !== 'string' || !value || value !== value.normalize('NFC') ||
      Buffer.from(value).toString('utf8') !== value || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part =>
        !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255))
    mismatch('candidate source has a noncanonical workspace path');
}

function checkSymlinks(entries: Map<string, WorkspaceEntry>): void {
  for (const entry of entries.values()) {
    if (entry.kind !== 'symlink') continue;
    if (!entry.target || entry.target !== entry.target.normalize('NFC') ||
        Buffer.from(entry.target).toString('utf8') !== entry.target || entry.target.startsWith('/') ||
        entry.target.includes('\\') || entry.target.includes('\0') || Buffer.byteLength(entry.target) > 4096 ||
        entry.mode !== 0o777 || sha256Bytes(Buffer.from(entry.target)) !== entry.targetDigest)
      mismatch('candidate source has an invalid symlink target');
    const resolved = entry.path.split('/').slice(0, -1), active = new Set([entry.path]);
    const frames = [{ link: entry.path, parts: entry.target.split('/'), index: 0 }];
    let dangling = false;
    while (frames.length) {
      const frame = frames[frames.length - 1];
      if (frame.index === frame.parts.length) { active.delete(frame.link); frames.pop(); continue; }
      const part = frame.parts[frame.index++];
      if (!part || part === '.') continue;
      if (part === '..') {
        if (!resolved.length) mismatch('candidate source symlink escapes its workspace');
        resolved.pop(); continue;
      }
      if (part.toLowerCase() === '.git') mismatch('candidate source symlink references Git metadata');
      const target = dangling ? undefined : entries.get([...resolved, part].join('/'));
      if (target?.kind === 'symlink') {
        if (active.has(target.path)) mismatch('candidate source symlink graph contains a cycle');
        active.add(target.path); frames.push({ link: target.path, parts: target.target.split('/'), index: 0 }); continue;
      }
      if (target?.kind === 'file' && frames.some(pending => pending.index < pending.parts.length))
        mismatch('candidate source symlink traverses a regular file');
      if (!target) dangling = true;
      resolved.push(part);
    }
  }
}

function checkEntries(manifest: WorkspaceEntryManifest): void {
  const entries = new Map<string, WorkspaceEntry>(), folded = new Set<string>();
  for (const entry of manifest.entries) {
    checkedPath(entry.path);
    if (folded.has(entry.path.toLowerCase())) mismatch('candidate source has a case-colliding path');
    folded.add(entry.path.toLowerCase());
    for (let slash = entry.path.indexOf('/'); slash >= 0; slash = entry.path.indexOf('/', slash + 1))
      if (entries.get(entry.path.slice(0, slash))?.kind !== 'directory')
        mismatch('candidate source lacks an exact directory ancestor');
    if (entry.kind === 'directory' && entry.mode !== 0o755 ||
        entry.kind === 'file' && entry.mode !== 0o644 && entry.mode !== 0o755)
      mismatch('candidate source entry mode is not normalized');
    entries.set(entry.path, entry);
  }
  checkSymlinks(entries);
}

function checkProjection(projection: SourceProjectionSpec): void {
  if (!exactKeys(projection, ['schemaVersion', 'matcherVersion', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest',
    'explicitIncludes', 'explicitExcludes', 'maxChangedPaths', 'maxChangedBytes', 'projectionDigest']) ||
      !Array.isArray(projection.explicitIncludes) || !Array.isArray(projection.explicitExcludes) ||
      projection.explicitExcludes.length > 128 || !Number.isSafeInteger(projection.maxChangedPaths) ||
      projection.maxChangedPaths < 0 || projection.maxChangedPaths > 100_000 ||
      !Number.isSafeInteger(projection.maxChangedBytes) || projection.maxChangedBytes < 0 || projection.maxChangedBytes > 4 * 1024 ** 3)
    mismatch('candidate source projection has invalid fields or limits');
  if (projection.explicitIncludes.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'candidate source includes require their implemented authorization closure');
  const seen = new Set<string>();
  for (const selector of projection.explicitExcludes) {
    if (!selector || !exactKeys(selector, ['path', 'scope']) || !['entry', 'subtree'].includes(selector.scope))
      mismatch('candidate source exclude has invalid fields');
    checkedPath(selector.path);
    const key = `${selector.path}\0${selector.scope}`;
    if (seen.has(key)) mismatch('candidate source has duplicate excludes');
    seen.add(key);
  }
}

type CandidateSourceGraph = {
  source: SourceManifest; sourceRef: string; diff: WorkspaceDiffV1; diffRef: string; metadata: PublishedArtifact[];
};
type CandidateSourceLimit = { reason: 'changed_paths' | 'changed_bytes'; observed: number; limit: number };

async function planCandidateSource(artifacts: ArtifactCatalog, spec: RunSpec, workspaceStateRef: string, signal?: AbortSignal): Promise<
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
  if (base.git !== undefined || workspace.privateGitStateRef !== undefined)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'candidate source Git projection requires its implemented index and object closure');
  if (!exactKeys(base, ['schemaVersion', 'format', 'role', 'workspaceIdentityDigest', 'entriesRef', 'sourceProjectionRef',
    'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest', 'treeDigest', 'manifestDigest']) || base.role !== 'base' ||
      workspace.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef || base.sourceProjectionRef !== spec.sourceProjectionRef ||
      workspace.sourceProjectionDigest !== base.sourceProjectionDigest)
    mismatch('candidate source does not preserve its admitted base and projection');
  for (const ref of [base.workspaceIdentityDigest, base.entriesRef, base.sourceProjectionRef, base.sourceProjectionDigest,
    base.frozenIgnoreRulesRef, base.frozenIgnoreRulesDigest, base.treeDigest, base.manifestDigest]) assertArtifactRef(ref);
  const projection = decodeSourceProjection(await read(spec.sourceProjectionRef, 'cliq-source-projection-v1'));
  checkProjection(projection);
  const rules = decodeFrozenIgnoreRules(await read(base.frozenIgnoreRulesRef, 'cliq-frozen-ignore-rules-v1'));
  if (projection.projectionDigest !== base.sourceProjectionDigest || projection.frozenIgnoreRulesRef !== base.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== base.frozenIgnoreRulesDigest || rules.rulesDigest !== base.frozenIgnoreRulesDigest)
    mismatch('candidate source frozen projection and ignore identities differ');
  if (!exactKeys(rules, ['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest']) ||
      rules.matcherVersion !== 'cliq-git-wildmatch-v1' || !Array.isArray(rules.sources) || !Array.isArray(rules.rules))
    mismatch('candidate source non-Git ignore manifest has invalid fields');
  if (rules.sources.length || rules.rules.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'candidate source nonempty ignore rules require their implemented matcher');
  const baseEntries = decodeWorkspaceEntries(await read(base.entriesRef, 'cliq-workspace-entries-v1'));
  const currentEntries = decodeWorkspaceEntries(await read(workspace.entriesRef, 'cliq-workspace-entries-v1'));
  if (base.treeDigest !== baseEntries.treeDigest) mismatch('candidate source base tree digest differs');
  checkEntries(baseEntries); checkEntries(currentEntries);
  const excluded = (path: string) => projection.explicitExcludes.some(selector =>
    path === selector.path || selector.scope === 'subtree' && covers(selector.path, path));
  if (baseEntries.entries.some(entry => excluded(entry.path)))
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
  const selected = currentEntries.entries.filter(entry => !excluded(entry.path));
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
export async function readCandidateSource(artifacts: ArtifactCatalog, spec: RunSpec, workspaceStateRef: string, signal?: AbortSignal): Promise<CandidateSourceGraph> {
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
