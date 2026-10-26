import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SourceSelectorRequest } from '../kernel/control-submit.js';
import { assertArtifactRef, digestOmitting } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, GitIndexSnapshotV1, SourceManifest, SourceProjectionSpec, WorkspaceEntryManifest } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../state/artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries } from '../state/decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../state/errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, stateRootIdentityForLock,
  type HeldStateOwnerLock, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot } from '../state/native-owner.js';
import { captureWorkspaceEntries, captureWorkspaceEntriesWithManifestPublication } from './source-capture.js';
import { decodeDeliveryCaptureTopology, publicationDirectoryIdentityDigest,
  type DeliveryCaptureTopologyV1 } from '../kernel/publication.js';
import { checkProjection } from '../state/source-validation.js';
import { readFrozenIgnoreRules } from './frozen-ignore.js';
import { createFrozenIgnoreMatcher } from './frozen-ignore.js';
import { readPrivateGitData, privateGitSourceHead, type PrivateGitData } from './private-git-data.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { readSourceProjectionData } from '../state/source-projection-data.js';

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
  privateGitStateRef?: string;
}>;
type SourceProjectionCaptureInput = Pick<NonGitSourceProjectionInput, 'workspaceRoot' | 'controlledHome' | 'stateOwnerLock' |
  'workspaceIdentityDigest' | 'artifacts' | 'maxEntries' | 'maxBytes' | 'maxSingleFileBytes' | 'signal'>;
export type FrozenSourceProjectionInput = SourceProjectionCaptureInput & Readonly<{
  sourceProjectionRef: string; sourceProjectionDigest: string;
  git?: { capturedSourceRef: string; classificationSourceRef: string; resources: SandboxResourceSpec };
}>;
type PublishedSourceProjectionCapture = Omit<PublishedNonGitSourceProjection, 'baseWorkspaceManifestRef'> & Readonly<{ sourceManifestRef: string }>;
export type CapturedFrozenSourceProjection = Omit<PublishedNonGitSourceProjection,
  'baseWorkspaceManifestRef' | 'captureTopologyRef' | 'captureTopologyDigest'> & Readonly<{ resultWorkspaceManifestRef: string }>;
type ProjectionCaptureMode = {
  kind: 'initial'; sourceIncludes: NonGitSourceProjectionInput['sourceIncludes'];
  sourceExcludes: NonGitSourceProjectionInput['sourceExcludes']; maxChangedPaths: number; maxChangedBytes: number;
  deliveryCapture?: NonGitSourceProjectionInput['deliveryCapture'];
  git?: { data: PrivateGitData; rules: FrozenIgnoreRulesV1; rulesArtifact: PublishedArtifact;
    classificationIndex?: GitIndexSnapshotV1; projection?: SourceProjectionSpec; projectionRef?: string };
} | {
  kind: 'frozen'; projection: SourceProjectionSpec; projectionArtifact: PublishedArtifact;
  rules: FrozenIgnoreRulesV1; rulesArtifact: PublishedArtifact;
  gitIdentity?: NonNullable<SourceManifest['git']>; classificationIndex?: GitIndexSnapshotV1;
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

/** Physical ordinary tree plus a complete previously produced fixed-Git
 * data closure. The original source owner separately proves that producer,
 * consent, sealed capture and retirement; these artifacts grant none of it. */
export async function publishGitSourceProjection(input: NonGitSourceProjectionInput & Readonly<{
  git: { privateGitStateRef: string; repositoryIdentityDigest: string; resources: SandboxResourceSpec; frozenIgnoreRulesRef: string;
    inheritedSourceRef?: string };
}>): Promise<PublishedNonGitSourceProjection> {
  const { git, signal, artifacts } = input;
  const data = await readPrivateGitData(artifacts, git.privateGitStateRef,
    { repositoryIdentityDigest: git.repositoryIdentityDigest, resources: git.resources }, signal);
  const rules = await readFrozenIgnoreRules(artifacts, git.frozenIgnoreRulesRef, git.repositoryIdentityDigest, signal);
  const rulesArtifact: PublishedArtifact = { ref: git.frozenIgnoreRulesRef, byteLength: canonicalJsonBytes(rules).length,
    mediaType: 'application/json', schemaKind: rules.format };
  let inherited: { classificationIndex?: GitIndexSnapshotV1; projection?: SourceProjectionSpec; projectionRef?: string } = {};
  if (git.inheritedSourceRef) {
    const source = decodeSourceManifest(await artifacts.readCanonical(git.inheritedSourceRef));
    const projection = decodeSourceProjection(await artifacts.readCanonical(source.sourceProjectionRef));
    const classification = await readSourceProjectionData(artifacts, source, projection, git.resources, signal);
    if (!source.git || source.git.repositoryIdentityDigest !== git.repositoryIdentityDigest || source.frozenIgnoreRulesRef !== git.frozenIgnoreRulesRef ||
        projection.maxChangedPaths !== input.maxChangedPaths || projection.maxChangedBytes !== input.maxChangedBytes ||
        canonicalSha256(projection.explicitExcludes) !== canonicalSha256(input.sourceExcludes))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'delivery capture differs from its admitted frozen Git projection');
    inherited = { classificationIndex: classification.classificationIndex, projection, projectionRef: source.sourceProjectionRef };
  }
  const { sourceManifestRef, ...capture } = await captureSourceProjection(input, { kind: 'initial',
    sourceIncludes: input.sourceIncludes, sourceExcludes: input.sourceExcludes, maxChangedPaths: input.maxChangedPaths,
    maxChangedBytes: input.maxChangedBytes, deliveryCapture: input.deliveryCapture, git: { data, rules, rulesArtifact, ...inherited } });
  return Object.freeze({ ...capture, baseWorkspaceManifestRef: sourceManifestRef, privateGitStateRef: data.manifestRef });
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
  if (!input.git && projection.classificationIndexRef !== undefined)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'non-Git frozen capture carries a Git classification index');
  if (projection.projectionDigest !== sourceProjectionDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen source projection differs from its retained digest');
  assertArtifactRef(projection.frozenIgnoreRulesRef); assertArtifactRef(projection.frozenIgnoreRulesDigest);
  let gitIdentity: SourceManifest['git'], classificationIndex: GitIndexSnapshotV1 | undefined;
  if (input.git) {
    const captured = decodeSourceManifest(await read(input.git.capturedSourceRef)), admitted = decodeSourceManifest(await read(input.git.classificationSourceRef));
    const original = await readSourceProjectionData(artifacts, admitted, projection, input.git.resources, signal);
    await readSourceProjectionData(artifacts, captured, projection, input.git.resources, signal);
    if (!captured.git || !admitted.git || captured.git.repositoryIdentityDigest !== admitted.git.repositoryIdentityDigest ||
        captured.workspaceIdentityDigest !== input.workspaceIdentityDigest || admitted.workspaceIdentityDigest !== input.workspaceIdentityDigest)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen Git capture lost its original repository/classification');
    gitIdentity = captured.git; classificationIndex = original.classificationIndex;
  }
  const rules = await readFrozenIgnoreRules(artifacts, projection.frozenIgnoreRulesRef, gitIdentity?.repositoryIdentityDigest, signal);
  if (Object.keys(rules).length !== (gitIdentity ? 7 : 6) || !['schemaVersion', 'format', 'matcherVersion', 'sources', 'rules', 'rulesDigest']
    .every(key => Object.hasOwn(rules, key)) || rules.matcherVersion !== 'cliq-git-wildmatch-v1' ||
      !Array.isArray(rules.sources) || !Array.isArray(rules.rules))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen non-Git ignore rules have invalid fields');
  if (rules.rulesDigest !== projection.frozenIgnoreRulesDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'frozen source ignore rules differ from their retained digest');
  const { sourceManifestRef, captureTopologyRef: _topologyRef, captureTopologyDigest: _topologyDigest, ...capture } =
    await captureSourceProjection({ ...input, artifacts }, { kind: 'frozen', projection, rules, gitIdentity, classificationIndex,
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
  const git = mode.kind === 'initial' ? mode.git : undefined;
  const hasGit = git !== undefined || mode.kind === 'frozen' && mode.gitIdentity !== undefined;
  if (workspaceRoot.repositoryDirectory !== undefined && !hasGit) invalid('Git source inspection is not implemented by the non-Git projection');
  if (workspaceRoot.repositoryDirectory === undefined && hasGit) invalid('Git projection has no original repository descriptor');
  const ignored = git ? createFrozenIgnoreMatcher(git.rules) : mode.kind === 'frozen' ? createFrozenIgnoreMatcher(mode.rules) : undefined;
  const classificationIndex = mode.kind === 'frozen' ? mode.classificationIndex : git?.classificationIndex ?? git?.data.index;
  const tracked = classificationIndex ? new Set(classificationIndex.entries.map(entry => entry.canonicalRootRelativePath)) : undefined;
  const trackedPaths = classificationIndex?.entries.map(entry => entry.canonicalRootRelativePath) ?? [];
  const trackedBelow = (path: string) => {
    const prefix = `${path}/`, bytes = Buffer.from(prefix); let left = 0, right = trackedPaths.length;
    while (left < right) { const middle = (left + right) >>> 1;
      if (Buffer.compare(Buffer.from(trackedPaths[middle]!), bytes) < 0) left = middle + 1; else right = middle; }
    return trackedPaths[left]?.startsWith(prefix) === true;
  };
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
      if (ignored?.(entry.path, entry.kind === 'directory') && !tracked?.has(entry.path) &&
          !(entry.kind === 'directory' && trackedBelow(entry.path))) continue;
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
    const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
    const rereadEntries = async (entriesArtifact: PublishedArtifact) => decodeWorkspaceEntries(await reads.readCanonical(entriesArtifact.ref));
    if (mode.kind === 'initial' && !git && !mode.deliveryCapture) {
      // One natural inert graph. Native capture resources stay held through
      // the complete fixed group and the original full manifest reread.
      let completed: PublishedSourceProjectionCapture | undefined;
      await captureWorkspaceEntriesWithManifestPublication(workspaceRoot, artifacts,
        { selectedPaths: selected, maxEntries, maxBytes, maxSingleFileBytes, signal }, async entries => {
          checkHardExcludedLinks(entries, hardRoots); assertCurrent();
          const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
            matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
          rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
          const rulesRef = canonicalSha256(rules);
          const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
            frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: excludes,
            maxChangedPaths, maxChangedBytes, projectionDigest: '' };
          projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
          const projectionRef = canonicalSha256(projection);
          const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base', workspaceIdentityDigest,
            entriesRef: canonicalSha256(entries), sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
            frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: entries.treeDigest, manifestDigest: '' };
          source.manifestDigest = digestOmitting(source, 'manifestDigest');
          const values = [{ value: entries, schemaKind: 'cliq-workspace-entries-v1' }, { value: rules, schemaKind: rules.format },
            { value: projection, schemaKind: 'cliq-source-projection-v1' }, { value: source, schemaKind: source.format }] as const;
          const expected = values.map(({ value, schemaKind }) => ({ ref: canonicalSha256(value), byteLength: canonicalJsonBytes(value).length,
            mediaType: 'application/json', schemaKind }));
          const group = await artifacts.publishCanonicalFour(values);
          assertCurrent();
          if (group.length !== 4 || group.some((artifact, index) => canonicalSha256(artifact) !== canonicalSha256(expected[index])))
            invalid('source graph differs from its complete original four objects');
          const [entriesArtifact, rulesArtifact, projectionArtifact, sourceArtifact] = group;
          const verifiedEntries = await rereadEntries(entriesArtifact);
          if (canonicalSha256(verifiedEntries) !== canonicalSha256(entries)) invalid('source entries reread differs from the native-read manifest');
          checkHardExcludedLinks(verifiedEntries, hardRoots); assertCurrent();
          const metadata = new Map<string, PublishedArtifact>();
          for (const entry of entries.entries) if (entry.kind === 'file') metadata.set(entry.blobRef, Object.freeze({ ref: entry.blobRef,
            byteLength: entry.size, mediaType: 'application/octet-stream', schemaKind: 'cliq-workspace-file-v1' }));
          for (const artifact of group) metadata.set(artifact.ref, Object.freeze({ ...artifact }));
          completed = Object.freeze({ sourceManifestRef: sourceArtifact.ref, manifestDigest: source.manifestDigest,
            entriesRef: entriesArtifact.ref, treeDigest: entries.treeDigest, entryCount: entries.entryCount, byteCount: entries.byteCount,
            sourceProjectionRef: projectionArtifact.ref, sourceProjectionDigest: projection.projectionDigest,
            frozenIgnoreRulesRef: rulesArtifact.ref, frozenIgnoreRulesDigest: rules.rulesDigest, metadata: Object.freeze([...metadata.values()]) });
          return entriesArtifact;
        });
      assertCurrent();
      if (!completed) invalid('source graph did not complete its original native capture');
      return completed;
    }
    const entriesArtifact = await captureWorkspaceEntries(workspaceRoot, artifacts,
      { selectedPaths: selected, maxEntries, maxBytes, maxSingleFileBytes, signal });
    assertCurrent();
    const entries = await rereadEntries(entriesArtifact);
    checkHardExcludedLinks(entries, hardRoots); assertCurrent();
    const rules: FrozenIgnoreRulesV1 = mode.kind === 'frozen' ? mode.rules : git?.rules ?? { schemaVersion: 1,
      format: 'cliq-frozen-ignore-rules-v1', matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
    if (mode.kind === 'initial' && !git) rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
    const initialNonGit = mode.kind === 'initial' && !git;
    let rulesArtifact = mode.kind === 'frozen' ? mode.rulesArtifact : git?.rulesArtifact;
    const rulesRef = rulesArtifact?.ref ?? canonicalSha256(rules); assertCurrent();
    const projection: SourceProjectionSpec = mode.kind === 'frozen' ? mode.projection : git?.projection ?? { schemaVersion: 1,
      matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
      explicitIncludes: [], explicitExcludes: excludes, maxChangedPaths, maxChangedBytes,
      ...(git ? { classificationIndexRef: git.data.manifest.indexRef } : {}), projectionDigest: '' };
    if (mode.kind === 'initial' && !git?.projection) projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    let projectionArtifact = mode.kind === 'frozen' ? mode.projectionArtifact : initialNonGit ? undefined
      : await artifacts.publishCanonical(projection, 'cliq-source-projection-v1');
    const projectionRef = projectionArtifact?.ref ?? canonicalSha256(projection); assertCurrent();
    const gitIdentity = mode.kind === 'frozen' ? mode.gitIdentity : git ? { repositoryIdentityDigest: git.data.index.repositoryIdentityDigest,
      head: privateGitSourceHead(git.data), indexRef: git.data.manifest.indexRef, indexTreeObjectId: git.data.index.indexTreeObjectId } : undefined;
    const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: mode.kind === 'initial' ? 'base' : 'result', workspaceIdentityDigest,
      entriesRef: entriesArtifact.ref, sourceProjectionRef: projectionRef, sourceProjectionDigest: projection.projectionDigest,
      frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest, treeDigest: entries.treeDigest,
      ...(gitIdentity ? { git: gitIdentity } : {}), manifestDigest: '' };
    source.manifestDigest = digestOmitting(source, 'manifestDigest');
    let sourceArtifact = initialNonGit ? undefined : await artifacts.publishCanonical(source, source.format);
    const sourceRef = sourceArtifact?.ref ?? canonicalSha256(source); assertCurrent();
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
        inspectionId: mode.deliveryCapture.inspectionId, capturedWorkspaceRef: sourceRef,
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
      assertCurrent();
      if (!initialNonGit) topologyArtifact = await artifacts.publishCanonical(topology, topology.format);
      assertCurrent();
    }
    if (initialNonGit) {
      // Canonical refs above plan inert data, never durability or authority.
      // The whole original graph returns only after its fixed three/four
      // objects complete every CAS stage and actual descriptor retirement.
      const values = [{ value: rules, schemaKind: rules.format }, { value: projection, schemaKind: 'cliq-source-projection-v1' },
        { value: source, schemaKind: source.format }] as const;
      if (topology) [rulesArtifact, projectionArtifact, sourceArtifact, topologyArtifact] =
        await artifacts.publishCanonicalFour([...values, { value: topology, schemaKind: topology.format }]);
      else [rulesArtifact, projectionArtifact, sourceArtifact] = await artifacts.publishCanonicalTriple(values);
      assertCurrent();
    }
    if (!rulesArtifact || !projectionArtifact || !sourceArtifact || sourceArtifact.ref !== sourceRef ||
        rulesArtifact.ref !== rulesRef || projectionArtifact.ref !== projectionRef)
      invalid('source graph differs from its completely published canonical data');
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
