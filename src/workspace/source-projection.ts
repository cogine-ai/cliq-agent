import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import type { SourceSelectorRequest } from '../kernel/control-submit.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../state/artifacts.js';
import { decodeWorkspaceEntries } from '../state/decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, stateRootIdentityForLock,
  type HeldStateOwnerLock, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from '../state/native-owner.js';
import { captureWorkspaceEntries } from './source-capture.js';

export type NonGitSourceProjectionInput = Readonly<{
  workspaceRoot: HeldWorkspaceRoot;
  controlledHome: HeldWorkspaceRoot;
  stateOwnerLock: HeldStateOwnerLock;
  workspaceIdentityDigest: string;
  artifacts: ArtifactCatalog;
  sourceIncludes: readonly SourceSelectorRequest[];
  sourceExcludes: readonly Omit<SourceSelectorRequest, 'readGrantId'>[];
  maxChangedPaths: number;
  maxChangedBytes: number;
  /** Trusted capture ceilings, independent of the later changed-result limits. */
  maxEntries: number;
  maxBytes: number;
  maxSingleFileBytes: number;
  signal?: AbortSignal;
}>;
export type PublishedNonGitSourceProjection = Readonly<{
  baseWorkspaceManifestRef: string; manifestDigest: string;
  entriesRef: string; treeDigest: string; entryCount: number; byteCount: number;
  sourceProjectionRef: string; sourceProjectionDigest: string;
  frozenIgnoreRulesRef: string; frozenIgnoreRulesDigest: string;
  metadata: readonly PublishedArtifact[];
}>;
function invalid(message: string): never { throw new KernelStorageError('INVALID_REQUEST', message); }
function checkedPath(value: string): string {
  if (typeof value !== 'string' || !value || value !== value.normalize('NFC') || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part => !part || part === '.' || part === '..' ||
        Buffer.byteLength(part) > 255 || part.toLowerCase() === '.git'))
    invalid('source selector must be a canonical root-relative path outside Git metadata');
  return value;
}
function covered(value: string, root: string): boolean { return value === root || value.startsWith(`${root}/`); }
function sameIdentity(left: HeldWorkspaceRoot['identity'], right: HeldWorkspaceRoot['identity']): boolean {
  return left.deviceId === right.deviceId && left.fileId === right.fileId;
}
function relativeHardRoot(workspace: string, forbidden: string): string | undefined {
  const relative = path.relative(workspace, forbidden);
  if (!relative || relative === '..' || workspace.startsWith(`${forbidden}/`)) invalid('source workspace is inside a controlled hard-excluded root');
  return relative.startsWith('../') || path.isAbsolute(relative) ? undefined : relative;
}
function retire(resources: readonly { close(): void }[], operationError?: unknown): void {
  const failures: unknown[] = [];
  for (const resource of [...resources].reverse()) { try { resource.close(); } catch (error) { failures.push(error); } }
  if (failures.length) throw new ResourceRetirementError('source projection descriptor retirement did not complete',
    new AggregateError(operationError === undefined ? failures : [operationError, ...failures]));
}
function checkHardExcludedLinks(manifest: WorkspaceEntryManifest, hardRoots: readonly string[]): void {
  const entries = new Map(manifest.entries.map(entry => [entry.path, entry]));
  for (const entry of manifest.entries) {
    if (entry.kind !== 'symlink') continue;
    const resolved = entry.path.split('/').slice(0, -1), active = new Set([entry.path]);
    const frames = [{ link: entry.path, parts: entry.target.split('/'), index: 0 }];
    let dangling = false;
    while (frames.length) {
      const frame = frames[frames.length - 1];
      if (frame.index === frame.parts.length) { active.delete(frame.link); frames.pop(); continue; }
      const part = frame.parts[frame.index++];
      if (!part || part === '.') continue;
      if (part === '..') { if (!resolved.length) invalid('source symlink escapes the workspace'); resolved.pop(); continue; }
      const candidatePath = [...resolved, part].join('/');
      // Check each lookup component, not only the final lexical destination:
      // a link through managed-state/../ordinary still traverses that root.
      if (hardRoots.some(root => covered(candidatePath, root))) invalid('source symlink references a hard-excluded root');
      const candidate = dangling ? undefined : entries.get(candidatePath);
      if (candidate?.kind === 'symlink') {
        if (active.has(candidate.path)) invalid('source symlink graph contains a cycle');
        active.add(candidate.path); frames.push({ link: candidate.path, parts: candidate.target.split('/'), index: 0 }); continue;
      }
      if (!candidate) dangling = true;
      resolved.push(part);
    }
  }
}

/** Physical ordinary/nonignored non-Git projection for trusted composition.
 * The caller establishes authentication, Trust and the durable capture owner
 * first. A returned graph is neither an accepted Run nor a permission grant.
 * No payload is opened until the complete metadata selection is classified. */
export async function publishNonGitSourceProjection(input: NonGitSourceProjectionInput): Promise<PublishedNonGitSourceProjection> {
  const { workspaceRoot, controlledHome, stateOwnerLock, artifacts, signal, workspaceIdentityDigest,
    maxEntries, maxBytes, maxSingleFileBytes, maxChangedPaths, maxChangedBytes } = input;
  assertHeldWorkspaceRoot(workspaceRoot); assertHeldWorkspaceRoot(controlledHome);
  const stateRoot = stateRootIdentityForLock(stateOwnerLock);
  assertArtifactRef(workspaceIdentityDigest);
  if (workspaceRoot.repositoryDirectory !== undefined) invalid('Git source inspection is not implemented by the non-Git projection');
  if (![maxEntries, maxBytes, maxSingleFileBytes, maxChangedPaths, maxChangedBytes].every(Number.isSafeInteger) ||
      maxEntries < 1 || maxEntries > 100_000 || maxBytes < 0 || maxSingleFileBytes < 0 ||
      maxChangedPaths < 0 || maxChangedPaths > 100_000 || maxChangedBytes < 0 || maxChangedBytes > 4 * 1024 ** 3)
    invalid('source projection limits are outside the fixed capture/result bounds');
  if (!Array.isArray(input.sourceIncludes) || input.sourceIncludes.length)
    invalid('explicit source includes and read-grant admission are not implemented');
  if (!Array.isArray(input.sourceExcludes) || input.sourceExcludes.length > 128) invalid('source excludes exceed their selector bound');
  const seenSelectors = new Set<string>();
  const excludes = input.sourceExcludes.map(selector => {
    if (!selector || typeof selector !== 'object' || Object.keys(selector).some(key => key !== 'path' && key !== 'scope') ||
        (selector.scope !== 'entry' && selector.scope !== 'subtree')) invalid('source exclude has unknown fields or scope');
    const item = { path: checkedPath(selector.path), scope: selector.scope }, key = `${item.path}\0${item.scope}`;
    if (seenSelectors.has(key)) invalid('source excludes contain duplicate selectors');
    seenSelectors.add(key); return item;
  });
  const hardRoots = [relativeHardRoot(heldWorkspaceRootPath(workspaceRoot), heldWorkspaceRootPath(controlledHome)),
    relativeHardRoot(heldWorkspaceRootPath(workspaceRoot), stateRoot.canonicalAbsolutePath)]
    .filter((root): root is string => root !== undefined);
  const assertSelectors = () => {
    for (const selector of excludes) if (hardRoots.some(root => covered(selector.path, root)))
      invalid('source selector addresses a hard-excluded root');
  };
  assertSelectors();
  const cursors: HeldWorkspaceCursor[] = [], observed: Array<{ entry: HeldWorkspaceEntry; pruned: boolean }> = [];
  const selected: string[] = [], directoryEntryExcludes = new Set<string>(), folded = new Set<string>();
  let inventoryCount = 0, fileBytes = 0, operationError: unknown;
  const assertCurrent = () => {
    signal?.throwIfAborted(); assertHeldWorkspaceRoot(workspaceRoot); assertHeldWorkspaceRoot(controlledHome);
    stateRootIdentityForLock(stateOwnerLock);
    for (const cursor of cursors) cursor.assertComplete();
    for (const { entry, pruned } of observed) { if (pruned) entry.assertPathHeld(); else entry.assertHeld(); }
  };
  try {
    signal?.throwIfAborted();
    const top = workspaceRoot.openSnapshot(); cursors.push(top);
    const stack: Array<{ cursor: HeldWorkspaceCursor; path: string; children: number; excludedEntry: boolean }> =
      [{ cursor: top, path: '', children: 0, excludedEntry: false }];
    while (stack.length) {
      await setImmediate(); signal?.throwIfAborted();
      const frame = stack[stack.length - 1], entry = frame.cursor.next();
      if (!entry) {
        frame.cursor.assertComplete(); stack.pop();
        if (frame.path && frame.children === 0 && !frame.excludedEntry) selected.push(frame.path);
        continue;
      }
      frame.children++;
      const observation = { entry, pruned: true }; observed.push(observation);
      if (++inventoryCount > maxEntries) invalid('source metadata inventory exceeds the entry limit');
      checkedPath(entry.path);
      const foldedPath = entry.path.toLowerCase();
      if (folded.has(foldedPath)) invalid('source metadata contains a case-colliding path');
      folded.add(foldedPath);
      const hard = hardRoots.some(root => covered(entry.path, root)) || entry.identity.deviceId !== workspaceRoot.identity.deviceId ||
        entry.kind === 'unsupported' || sameIdentity(entry.identity, controlledHome.identity) ||
        (entry.identity.deviceId === stateRoot.deviceId && entry.identity.fileId === stateRoot.directoryFileId);
      if (hard) { if (!hardRoots.includes(entry.path)) hardRoots.push(entry.path); assertSelectors(); continue; }
      const excluding = excludes.filter(selector => selector.path === entry.path ||
        (selector.scope === 'subtree' && covered(entry.path, selector.path)));
      if (excluding.some(selector => selector.scope === 'subtree') || (excluding.length && entry.kind !== 'directory')) continue;
      observation.pruned = false;
      if (entry.kind === 'directory') {
        if (excluding.length) directoryEntryExcludes.add(entry.path);
        const child = entry.openDirectory(); cursors.push(child);
        stack.push({ cursor: child, path: entry.path, children: 0, excludedEntry: excluding.length > 0 });
      } else {
        if (entry.kind === 'file') {
          if (!Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 || entry.byteCount > maxSingleFileBytes ||
              entry.byteCount > maxBytes - fileBytes) invalid('ordinary source bytes exceed the capture file/total limit');
          fileBytes += entry.byteCount;
        }
        selected.push(entry.path);
      }
    }
    for (const directory of directoryEntryExcludes) if (selected.some(value => covered(value, directory)))
      invalid('entry-only exclusion of a required directory ancestor is unsupported; use subtree');
    assertCurrent();
    const entriesArtifact = await captureWorkspaceEntries(workspaceRoot, artifacts,
      { selectedPaths: selected, maxEntries, maxBytes, maxSingleFileBytes, signal });
    assertCurrent();
    const entries = decodeWorkspaceEntries(await artifacts.readCanonical(entriesArtifact.ref));
    checkHardExcludedLinks(entries, hardRoots); assertCurrent();
    const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1',
      sources: [], rules: [], rulesDigest: '' };
    rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
    const rulesArtifact = await artifacts.publishCanonical(rules, rules.format); assertCurrent();
    const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
      frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: excludes,
      maxChangedPaths, maxChangedBytes, projectionDigest: '' };
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionArtifact = await artifacts.publishCanonical(projection, 'cliq-source-projection-v1'); assertCurrent();
    const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base', workspaceIdentityDigest,
      entriesRef: entriesArtifact.ref, sourceProjectionRef: projectionArtifact.ref, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: entries.treeDigest, manifestDigest: '' };
    source.manifestDigest = digestOmitting(source, 'manifestDigest');
    const sourceArtifact = await artifacts.publishCanonical(source, source.format); assertCurrent();
    const metadata = new Map<string, PublishedArtifact>();
    for (const entry of entries.entries) if (entry.kind === 'file') metadata.set(entry.blobRef, Object.freeze({ ref: entry.blobRef,
      byteLength: entry.size, mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1' }));
    for (const artifact of [entriesArtifact, rulesArtifact, projectionArtifact, sourceArtifact]) metadata.set(artifact.ref, Object.freeze({ ...artifact }));
    return Object.freeze({ baseWorkspaceManifestRef: sourceArtifact.ref, manifestDigest: source.manifestDigest,
      entriesRef: entriesArtifact.ref, treeDigest: entries.treeDigest, entryCount: entries.entryCount, byteCount: entries.byteCount,
      sourceProjectionRef: projectionArtifact.ref, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest, metadata: Object.freeze([...metadata.values()]) });
  } catch (error) { operationError = error; throw error; }
  finally { retire([...cursors, ...observed.map(item => item.entry)], operationError); }
}
