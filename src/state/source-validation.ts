import { assertArtifactRef, digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { SourceManifest, SourceProjectionSpec, WorkspaceEntry, WorkspaceEntryManifest } from '../kernel/types.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { KernelStorageError } from './errors.js';

function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }

/** Internal shared source-data checks. They confer no capture or execution authority. */
export function checkedPath(value: string): void {
  if (typeof value !== 'string' || !value || value !== value.normalize('NFC') ||
      Buffer.from(value).toString('utf8') !== value || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part =>
        !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255))
    mismatch('candidate source has a noncanonical workspace path');
}

export function checkSymlinks(entries: Map<string, WorkspaceEntry>): void {
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

export function checkEntries(manifest: WorkspaceEntryManifest): void {
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

export function checkProjection(projection: SourceProjectionSpec): void {
  if (!exactKeys(projection, ['schemaVersion', 'matcherVersion', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest',
    'explicitIncludes', 'explicitExcludes', 'maxChangedPaths', 'maxChangedBytes', 'projectionDigest',
    ...(projection.classificationIndexRef !== undefined ? ['classificationIndexRef'] : [])]) ||
      !Array.isArray(projection.explicitIncludes) || !Array.isArray(projection.explicitExcludes) ||
      projection.explicitExcludes.length > 128 || !Number.isSafeInteger(projection.maxChangedPaths) ||
      projection.maxChangedPaths < 0 || projection.maxChangedPaths > 100_000 ||
      !Number.isSafeInteger(projection.maxChangedBytes) || projection.maxChangedBytes < 0 || projection.maxChangedBytes > 4 * 1024 ** 3)
    mismatch('candidate source projection has invalid fields or limits');
  if (projection.classificationIndexRef !== undefined) assertArtifactRef(projection.classificationIndexRef);
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

/** The caller also binds the exact role and workspace/projection identities. */
export function checkNonGitSourceManifest(source: SourceManifest): void {
  if (!exactKeys(source, ['schemaVersion', 'format', 'role', 'workspaceIdentityDigest', 'entriesRef', 'sourceProjectionRef',
    'sourceProjectionDigest', 'frozenIgnoreRulesRef', 'frozenIgnoreRulesDigest', 'treeDigest', 'manifestDigest']) ||
      source.schemaVersion !== 1 || source.format !== 'cliq-source-manifest-v1' || !['base', 'result'].includes(source.role) ||
      digestOmitting(source, 'manifestDigest') !== source.manifestDigest) mismatch('candidate source manifest has invalid fields');
  for (const ref of [source.workspaceIdentityDigest, source.entriesRef, source.sourceProjectionRef, source.sourceProjectionDigest,
    source.frozenIgnoreRulesRef, source.frozenIgnoreRulesDigest, source.treeDigest, source.manifestDigest]) assertArtifactRef(ref);
}

/** Exact source schema. Git identity is independently closed against its
 * canonical admitted index; it is never inferred from a current private index. */
export function checkSourceManifest(source: SourceManifest): void {
  if (!source.git) return checkNonGitSourceManifest(source);
  const { git, ...ordinary } = source;
  checkNonGitSourceManifest({ ...ordinary, manifestDigest: digestOmitting(ordinary, 'manifestDigest') });
  if (!exactKeys(git, ['repositoryIdentityDigest', 'head', 'indexRef', 'indexTreeObjectId'])) mismatch('source Git identity has extra fields');
  assertArtifactRef(git.repositoryIdentityDigest); assertArtifactRef(git.indexRef);
  const head = git.head;
  const objectId = (value: unknown) => typeof value === 'string' && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value);
  const name = (value: unknown) => typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096 &&
    value !== '@' && Buffer.from(value).toString('utf8') === value && value === value.normalize('NFC') && !/[\x00-\x20\x7f~^:?*\[\\]/u.test(value) && !value.includes('..') && !value.includes('@{') &&
    !value.startsWith('-') && !value.endsWith('.') && value.split('/').every(part => !!part && !part.startsWith('.') && !part.endsWith('.lock'));
  if (!head || (head.kind === 'unborn' ? !exactKeys(head, ['kind', 'branch']) || !name(head.branch) :
      head.kind === 'detached' ? !exactKeys(head, ['kind', 'objectId']) || !objectId(head.objectId) :
      head.kind === 'symbolic' ? !exactKeys(head, ['kind', 'ref', 'objectId']) || !name(head.ref) || !head.ref.startsWith('refs/') || !objectId(head.objectId) : true) ||
      !objectId(git.indexTreeObjectId)) mismatch('source Git HEAD or index tree is invalid');
  // ordinary's digest still covers the original complete source, including Git.
  if (digestOmitting(source, 'manifestDigest') !== source.manifestDigest) mismatch('source Git digest differs');
}
