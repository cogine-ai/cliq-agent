import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SourceSelectorRequest } from '../kernel/control-submit.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../state/artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceProjection, decodeWorkspaceEntries } from '../state/decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, stateRootIdentityForLock,
  type HeldStateOwnerLock, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from '../state/native-owner.js';
import { captureWorkspaceEntries } from './source-capture.js';
import { decodeDeliveryCaptureTopology, publicationDirectoryIdentityDigest,
  type DeliveryCaptureTopologyV1 } from '../kernel/publication.js';
import { checkProjection } from '../state/source-validation.js';

export const MAX_SOURCE_PROJECTION_ENTRIES = 100_000;

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
  /** Internal apply capture provenance only; this is not publication or
   * physical-generation evidence. Observations use this same held scan. */
  deliveryCapture?: { inspectionId: string; workspaceIdentityRef: string; capturedAt: string };
  signal?: AbortSignal;
}>;
export type PublishedNonGitSourceProjection = Readonly<{
  baseWorkspaceManifestRef: string; manifestDigest: string;
  entriesRef: string; treeDigest: string; entryCount: number; byteCount: number;
  sourceProjectionRef: string; sourceProjectionDigest: string;
  frozenIgnoreRulesRef: string; frozenIgnoreRulesDigest: string;
  captureTopologyRef?: string; captureTopologyDigest?: string;
  metadata: readonly PublishedArtifact[];
}>;
type SourceProjectionCaptureInput = Pick<NonGitSourceProjectionInput, 'workspaceRoot' | 'controlledHome' | 'stateOwnerLock' |
  'workspaceIdentityDigest' | 'artifacts' | 'maxEntries' | 'maxBytes' | 'maxSingleFileBytes' | 'signal'>;
export type FrozenSourceProjectionInput = SourceProjectionCaptureInput & Readonly<{
  sourceProjectionRef: string; sourceProjectionDigest: string;
}>;
type PublishedSourceProjectionCapture = Omit<PublishedNonGitSourceProjection, 'baseWorkspaceManifestRef'> & Readonly<{ sourceManifestRef: string }>;
export type CapturedFrozenSourceProjection = Omit<PublishedNonGitSourceProjection,
  'baseWorkspaceManifestRef' | 'captureTopologyRef' | 'captureTopologyDigest'> & Readonly<{ resultWorkspaceManifestRef: string }>;
type ProjectionCaptureMode = {
  kind: 'initial'; sourceIncludes: NonGitSourceProjectionInput['sourceIncludes'];
  sourceExcludes: NonGitSourceProjectionInput['sourceExcludes']; maxChangedPaths: number; maxChangedBytes: number;
  deliveryCapture?: NonGitSourceProjectionInput['deliveryCapture'];
} | {
  kind: 'frozen'; projection: SourceProjectionSpec; projectionArtifact: PublishedArtifact;
  rules: FrozenIgnoreRulesV1; rulesArtifact: PublishedArtifact;
};
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
  const { sourceManifestRef, ...capture } = await captureSourceProjection(input, { kind: 'initial',
    sourceIncludes: input.sourceIncludes, sourceExcludes: input.sourceExcludes,
    maxChangedPaths: input.maxChangedPaths, maxChangedBytes: input.maxChangedBytes, deliveryCapture: input.deliveryCapture });
  return Object.freeze({ baseWorkspaceManifestRef: sourceManifestRef, ...capture });
}

/** Capture the complete current ordinary tree under the original immutable
 * non-Git projection, including paths born after admission. This reads no live
 * configuration or ignore files as rules and grants no snapshot, publication,
 * Trust or execution authority. The caller owns the actual snapshot gate. */
export async function captureFrozenSourceProjection(input: FrozenSourceProjectionInput): Promise<CapturedFrozenSourceProjection> {
  // Retained refs never substitute for the original opaque directory/lock
  // handles, even during the preliminary frozen-data reads.
  assertHeldWorkspaceRoot(input.workspaceRoot); assertHeldWorkspaceRoot(input.controlledHome);
  stateRootIdentityForLock(input.stateOwnerLock);
  const { sourceProjectionRef, sourceProjectionDigest, signal } = input;
  assertArtifactRef(sourceProjectionRef); assertArtifactRef(sourceProjectionDigest);
  const artifacts = signal ? input.artifacts.withReadSignal(signal) : input.artifacts;
  const read = async (ref: string): Promise<unknown> => {
    signal?.throwIfAborted();
    const value = await artifacts.readCanonical(ref);
    if (canonicalSha256(value) !== ref) throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen source artifact is not canonical JSON');
    signal?.throwIfAborted(); return value;
  };
  const projection = decodeSourceProjection(await read(sourceProjectionRef)); checkProjection(projection);
  if (projection.projectionDigest !== sourceProjectionDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen source projection differs from its retained digest');
  assertArtifactRef(projection.frozenIgnoreRulesRef); assertArtifactRef(projection.frozenIgnoreRulesDigest);
  const rules = decodeFrozenIgnoreRules(await read(projection.frozenIgnoreRulesRef));
  if (Object.keys(rules).length !== 6 || !['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest']
    .every(key => Object.hasOwn(rules, key)) || rules.matcherVersion !== 'cliq-git-wildmatch-v1' ||
      !Array.isArray(rules.sources) || !Array.isArray(rules.rules))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen non-Git ignore rules have invalid fields');
  if (rules.rulesDigest !== projection.frozenIgnoreRulesDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen source ignore rules differ from their retained digest');
  if (rules.sources.length || rules.rules.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'frozen nonempty ignore matching is not implemented');
  const { sourceManifestRef, captureTopologyRef: _topologyRef, captureTopologyDigest: _topologyDigest, ...capture } =
    await captureSourceProjection({ ...input, artifacts }, { kind: 'frozen', projection, rules,
      projectionArtifact: { ref: sourceProjectionRef, byteLength: canonicalJsonBytes(projection).byteLength,
        mediaType: 'application/json', schemaKind: 'cliq-source-projection-v1' },
      rulesArtifact: { ref: projection.frozenIgnoreRulesRef, byteLength: canonicalJsonBytes(rules).byteLength,
        mediaType: 'application/json', schemaKind: rules.format } });
  return Object.freeze({ resultWorkspaceManifestRef: sourceManifestRef, ...capture });
}

/** One metadata classification and descriptor lifetime for both first source
 * admission and later frozen-projection capture. */
async function captureSourceProjection(input: SourceProjectionCaptureInput, mode: ProjectionCaptureMode): Promise<PublishedSourceProjectionCapture> {
  const { workspaceRoot, controlledHome, stateOwnerLock, artifacts, signal, workspaceIdentityDigest,
    maxEntries, maxBytes, maxSingleFileBytes } = input;
  const { maxChangedPaths, maxChangedBytes } = mode.kind === 'initial' ? mode : mode.projection;
  assertHeldWorkspaceRoot(workspaceRoot); assertHeldWorkspaceRoot(controlledHome);
  const stateRoot = stateRootIdentityForLock(stateOwnerLock);
  assertArtifactRef(workspaceIdentityDigest);
  if (workspaceRoot.repositoryDirectory !== undefined) invalid('Git source inspection is not implemented by the non-Git projection');
  if (![maxEntries, maxBytes, maxSingleFileBytes, maxChangedPaths, maxChangedBytes].every(Number.isSafeInteger) ||
      maxEntries < 1 || maxEntries > MAX_SOURCE_PROJECTION_ENTRIES || maxBytes < 0 || maxSingleFileBytes < 0 ||
      maxChangedPaths < 0 || maxChangedPaths > 100_000 || maxChangedBytes < 0 || maxChangedBytes > 4 * 1024 ** 3)
    invalid('source projection limits are outside the fixed capture/result bounds');
  if (mode.kind === 'initial' && (!Array.isArray(mode.sourceIncludes) || mode.sourceIncludes.length))
    invalid('explicit source includes and read-grant admission are not implemented');
  const sourceExcludes = mode.kind === 'initial' ? mode.sourceExcludes : mode.projection.explicitExcludes;
  if (!Array.isArray(sourceExcludes) || sourceExcludes.length > 128) invalid('source excludes exceed their selector bound');
  const seenSelectors = new Set<string>();
  const excludes = sourceExcludes.map(selector => {
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
    const rules: FrozenIgnoreRulesV1 = mode.kind === 'frozen' ? mode.rules : { schemaVersion: 1,
      format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
    if (mode.kind === 'initial') rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
    const rulesArtifact = mode.kind === 'frozen' ? mode.rulesArtifact : await artifacts.publishCanonical(rules, rules.format); assertCurrent();
    const projection: SourceProjectionSpec = mode.kind === 'frozen' ? mode.projection : { schemaVersion: 1,
      matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest,
      explicitIncludes: [], explicitExcludes: excludes, maxChangedPaths, maxChangedBytes, projectionDigest: '' };
    if (mode.kind === 'initial') projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionArtifact = mode.kind === 'frozen' ? mode.projectionArtifact : await artifacts.publishCanonical(projection, 'cliq-source-projection-v1'); assertCurrent();
    const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: mode.kind === 'initial' ? 'base' : 'result', workspaceIdentityDigest,
      entriesRef: entriesArtifact.ref, sourceProjectionRef: projectionArtifact.ref, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: entries.treeDigest, manifestDigest: '' };
    source.manifestDigest = digestOmitting(source, 'manifestDigest');
    const sourceArtifact = await artifacts.publishCanonical(source, source.format); assertCurrent();
    let topologyArtifact: PublishedArtifact | undefined, topology: DeliveryCaptureTopologyV1 | undefined;
    if (mode.kind === 'initial' && mode.deliveryCapture) {
      const required = new Set<string>();
      for (const entry of entries.entries) {
        const parts = entry.path.split('/'); if (entry.kind !== 'directory') parts.pop();
        for (let index = 1; index <= parts.length; index++) required.add(parts.slice(0, index).join('/'));
      }
      const selectedObservations = new Map(observed.filter(item => !item.pruned).map(item => [item.entry.path, item.entry]));
      const rootIdentity = { ...workspaceRoot.identity, mode: workspaceRoot.mode };
      const body: DeliveryCaptureTopologyV1 = { schemaVersion: 1, format: 'cliq-delivery-capture-topology-v1',
        inspectionId: mode.deliveryCapture.inspectionId, capturedWorkspaceRef: sourceArtifact.ref,
        workspaceIdentityRef: mode.deliveryCapture.workspaceIdentityRef, workspaceIdentityDigest,
        rootIdentity: { ...rootIdentity, identityDigest: publicationDirectoryIdentityDigest(workspaceIdentityDigest, rootIdentity) },
        directories: [...required].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))).map(path => {
          const entry = selectedObservations.get(path);
          if (!entry || entry.kind !== 'directory') invalid('captured source directory has no observation from its original held scan');
          entry.assertHeld(); const identity = { ...entry.identity, mode: entry.mode };
          return { ...identity, identityDigest: publicationDirectoryIdentityDigest(workspaceIdentityDigest, identity), path };
        }), fileModes: entries.entries.filter(entry => entry.kind === 'file').map(selected => {
          const observedEntry = selectedObservations.get(selected.path);
          if (!observedEntry || observedEntry.kind !== 'file') invalid('captured file has no observation from its original held scan');
          observedEntry.assertHeld(); return { path: selected.path, mode: observedEntry.mode };
        }), capturedAt: mode.deliveryCapture.capturedAt, topologyDigest: '' };
      topology = decodeDeliveryCaptureTopology({ ...body, topologyDigest: digestOmitting(body, 'topologyDigest') });
      assertCurrent(); topologyArtifact = await artifacts.publishCanonical(topology, topology.format); assertCurrent();
    }
    const metadata = new Map<string, PublishedArtifact>();
    for (const entry of entries.entries) if (entry.kind === 'file') metadata.set(entry.blobRef, Object.freeze({ ref: entry.blobRef,
      byteLength: entry.size, mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1' }));
    for (const artifact of [entriesArtifact, rulesArtifact, projectionArtifact, sourceArtifact, ...(topologyArtifact ? [topologyArtifact] : [])])
      metadata.set(artifact.ref, Object.freeze({ ...artifact }));
    return Object.freeze({ sourceManifestRef: sourceArtifact.ref, manifestDigest: source.manifestDigest,
      entriesRef: entriesArtifact.ref, treeDigest: entries.treeDigest, entryCount: entries.entryCount, byteCount: entries.byteCount,
      sourceProjectionRef: projectionArtifact.ref, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest,
      ...(topologyArtifact && topology ? { captureTopologyRef: topologyArtifact.ref, captureTopologyDigest: topology.topologyDigest } : {}),
      metadata: Object.freeze([...metadata.values()]) });
  } catch (error) { operationError = error; throw error; }
  finally { retire([...cursors, ...observed.map(item => item.entry)], operationError); }
}
