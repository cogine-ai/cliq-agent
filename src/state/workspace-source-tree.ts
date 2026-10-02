import path from 'node:path';

import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertAdmissionKey, digestOmitting, normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, WorkspaceEntry,
  WorkspaceEntryManifest, WorkspaceIdentityV1
} from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { publishVerifiedChunkStreamToCas, type HeldCasRoot } from '../runtime-bundle/native-package-reader.js';
import type { PublishedArtifact } from './artifacts.js';
import {
  decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection,
  decodeWorkspaceEntries, decodeWorkspaceIdentity
} from './decoders.js';
import { KernelStorageError } from './errors.js';
import type { HeldStateOwnerLock, WorkspaceSourceDirectoryEntry } from './native-owner.js';
import { sourcePathCollisionKey } from './source-path-collision.js';
import { assertCurrentLiveWorkspaceIdentity } from './workspace-identity.js';
import {
  assertLiveWorkspaceSourceFile, assertSameSourceObservation, captureObservedWorkspaceSourceFile
} from './workspace-source-blob.js';

type Selector = { path: string; scope: 'entry' | 'subtree' };
type LiveWorkspace = Extract<WorkspaceIdentityV1, { kind: 'live' }>;

/** Supervisor-selected inspection limits, distinct from the result's changed
 * byte/path ceilings. They are required so capture cannot allocate unbounded
 * metadata or publish an unbounded base image. No source truncation is legal. */
export type NonGitSourceCapturePolicy = {
  knownCredentialRoots: readonly string[];
  declaredEphemeralPaths: readonly string[];
  limits: { maxEntries: number; maxBytes: number };
  explicitExcludes?: readonly Selector[];
  maxChangedPaths?: number;
  maxChangedBytes?: number;
};

export type SourceCaptureBinding = {
  principalId: string;
  sessionId: string;
  expectedContextRevision: number;
  admissionKey: string;
};

/** A process-local capture handle, not wire input or a durable authority. The
 * private provenance below binds it to the continuously held StateOwner. */
export type CapturedWorkspaceSourceTree = Readonly<{
  sourceProjectionRef: string;
  frozenIgnoreRulesRef: string;
  baseWorkspaceManifestRef: string;
  entries: WorkspaceEntryManifest;
}>;

type Inventory = Map<string, WorkspaceSourceDirectoryEntry>;
type CaptureProvenance = {
  filesystem: HeldStateOwnerLock;
  workspace: LiveWorkspace;
  binding: SourceCaptureBinding;
  policy: NonGitSourceCapturePolicy;
  hardExcludes: readonly string[];
  observations: Inventory;
  metadata: readonly PublishedArtifact[];
};
type ExpectedCapture = SourceCaptureBinding & {
  workspacePath: string; workspaceIdentityDigest: string;
  sourceProjectionRef: string; frozenIgnoreRulesRef: string; baseWorkspaceManifestRef: string;
};
const captures = new WeakMap<CapturedWorkspaceSourceTree, CaptureProvenance>();
const CHUNK_BYTES = 1024 * 1024;

function relativeSourcePath(value: string): void {
  if (typeof value !== 'string' || !value || normalizeCanonicalText(value) !== value ||
      value.includes('\\') || Buffer.byteLength(value, 'utf8') > 4096 ||
      value.split('/').some((part) => !part || part === '.' || part === '..' ||
        part.toLowerCase() === '.git' || Buffer.byteLength(part, 'utf8') > 255)) {
    throw new KernelStorageError('INVALID_REQUEST', 'source exclusion must be a canonical in-root path');
  }
}

function under(candidate: string, root: string): boolean {
  return candidate === root || candidate.startsWith(`${root}/`);
}

// A trusted credential locator may have a case alias on the host volume.
// Hard privacy boundaries conservatively exclude that alias too; requested
// selectors retain their separate byte-exact RFC semantics.
function underHardRoot(candidate: string, root: string): boolean {
  return under(sourcePathCollisionKey(candidate), sourcePathCollisionKey(root));
}

function hardExcludedPaths(workspacePath: string, stateRoot: string,
  policy: NonGitSourceCapturePolicy): string[] {
  const relative = new Set<string>();
  for (const root of [stateRoot, ...policy.knownCredentialRoots]) {
    if (normalizeAbsolutePath(root) !== root) {
      throw new KernelStorageError('INVALID_REQUEST', 'hard-excluded root must be a canonical absolute path');
    }
    // Inspecting a root inside Cliq state or a credential store is forbidden.
    if (root === '/' || underHardRoot(workspacePath, root)) {
      throw new KernelStorageError('INVALID_REQUEST', 'workspace is inside a hard-excluded root');
    }
    if (underHardRoot(root, workspacePath)) {
      const value = root.split('/').slice(workspacePath.split('/').length).join('/');
      relativeSourcePath(value);
      relative.add(value);
    }
  }
  for (const value of policy.declaredEphemeralPaths) {
    relativeSourcePath(value);
    relative.add(value);
  }
  return [...relative].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function excluded(candidate: string, hard: readonly string[], selectors: readonly Selector[]): boolean {
  return candidate.split('/').some((part) => part.toLowerCase() === '.git') ||
    hard.some((root) => underHardRoot(candidate, root)) ||
    selectors.some((selector) => candidate === selector.path ||
      (selector.scope === 'subtree' && candidate.startsWith(`${selector.path}/`)));
}

function enumerate(provenance: Omit<CaptureProvenance, 'observations' | 'metadata'>): Inventory {
  const { filesystem, workspace, policy, hardExcludes } = provenance;
  const observations: Inventory = new Map();
  const pending = [''];
  let byteCount = 0;
  while (pending.length) {
    const parent = pending.pop()!;
    const children = filesystem.listWorkspaceSourceDirectory(workspace.canonicalRootPath,
      workspace.rootIdentity, parent);
    const spellings = new Set<string>();
    for (const child of children) {
      const spelling = sourcePathCollisionKey(child.name);
      if (spellings.has(spelling)) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'source directory has a case collision');
      }
      spellings.add(spelling);
      const relative = parent ? `${parent}/${child.name}` : child.name;
      if (excluded(relative, hardExcludes, policy.explicitExcludes ?? [])) {
        if (child.kind === 'directory' && !hardExcludes.some((root) => underHardRoot(relative, root)) &&
            (policy.explicitExcludes ?? []).some((selector) =>
              selector.path === relative && selector.scope === 'entry')) {
          // A restoration manifest requires parent directories. Do not widen
          // an entry exclusion to its descendants or silently retain the entry.
          throw new KernelStorageError('INVALID_REQUEST',
            'directory entry exclusions need structural-parent design; use a subtree exclusion');
        }
        continue;
      }
      relativeSourcePath(relative);
      if (observations.size >= policy.limits.maxEntries) {
        throw new KernelStorageError('INVALID_REQUEST', 'source capture entry limit exceeded');
      }
      if (child.kind === 'file') {
        if (!Number.isSafeInteger(child.size) || child.size! < 0) {
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'source file has an invalid size');
        }
        byteCount += child.size!;
        if (!Number.isSafeInteger(byteCount) || byteCount > policy.limits.maxBytes) {
          throw new KernelStorageError('INVALID_REQUEST', 'source capture byte limit exceeded');
        }
      }
      observations.set(relative, child);
      if (child.kind === 'directory') pending.push(relative);
    }
  }
  return new Map([...observations].sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
}

function assertInventory(expected: Inventory, observed: Inventory): void {
  if (expected.size !== observed.size) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace source path set changed');
  }
  for (const [relative, before] of expected) {
    const after = observed.get(relative);
    if (!after || after.kind !== before.kind) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `workspace source path ${relative} changed`);
    }
    assertSameSourceObservation(after, before, relative);
  }
}

function manifest(entries: WorkspaceEntry[]): WorkspaceEntryManifest {
  return decodeWorkspaceEntries({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries,
    entryCount: entries.length,
    byteCount: entries.reduce((bytes, entry) => bytes + (entry.kind === 'file' ? entry.size :
      entry.kind === 'symlink' ? Buffer.byteLength(entry.target, 'utf8') : 0), 0),
    treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) });
}

function assertHardExcludedLinkTargets(entries: readonly WorkspaceEntry[], hard: readonly string[]): void {
  const links = new Map(entries.filter((entry) => entry.kind === 'symlink').map((entry) => [entry.path, entry.target]));
  for (const [relative, target] of links) {
    const parent = path.posix.dirname(relative);
    const components = parent === '.' ? [] : parent.split('/');
    const pending = target.split('/');
    let followed = 0;
    for (let cursor = 0; cursor < pending.length; cursor += 1) {
      const component = pending[cursor]!;
      if (component === '' || component === '.') continue;
      if (component === '..') { components.pop(); continue; }
      components.push(component);
      if (hard.some((root) => underHardRoot(components.join('/'), root))) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', `source symlink ${relative} reaches a hard-excluded root`);
      }
      const next = links.get(components.join('/'));
      if (next !== undefined) {
        if (++followed > 40) {
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'source symlink has an excessive link chain');
        }
        components.pop();
        pending.splice(cursor + 1, 0, ...next.split('/'));
      }
    }
  }
}

async function publishCanonical(cas: HeldCasRoot, value: unknown, schemaKind: string,
  filesystem: HeldStateOwnerLock): Promise<PublishedArtifact> {
  const bytes = canonicalJsonBytes(value);
  const ref = sha256Bytes(bytes);
  await publishVerifiedChunkStreamToCas(cas, { digest: ref, byteCount: bytes.byteLength }, (write) => {
    for (let offset = 0; offset < bytes.byteLength; offset += CHUNK_BYTES) {
      write(bytes.subarray(offset, offset + CHUNK_BYTES));
    }
  }, () => { filesystem.assertHeld(); });
  return { ref, byteLength: bytes.byteLength, mediaType: 'application/json', schemaKind };
}

/** Complete non-Git base capture. This is inspection, not a workerless Run:
 * the later Supervisor coordinator must separately qualify strong containment
 * and resolve assembly/permissions before publishing Run authority. */
export async function captureHeldNonGitWorkspaceSourceTree(options: {
  filesystem: HeldStateOwnerLock;
  cas: HeldCasRoot;
  workspace: LiveWorkspace;
  stateRoot: string;
  binding: SourceCaptureBinding;
  policy: NonGitSourceCapturePolicy;
}): Promise<CapturedWorkspaceSourceTree> {
  const { filesystem, cas } = options;
  const workspace = immutableSnapshot(decodeWorkspaceIdentity(options.workspace)) as LiveWorkspace;
  const binding = immutableSnapshot(options.binding);
  const policy = immutableSnapshot(options.policy);
  if (workspace.kind !== 'live' || workspace.repositoryIdentityDigest !== undefined) {
    throw new KernelStorageError('INVALID_REQUEST', 'this capture producer requires a live non-Git Session');
  }
  assertAdmissionKey(binding.admissionKey);
  if (binding.principalId !== workspace.ownerPrincipalId || !binding.sessionId ||
      !Number.isSafeInteger(binding.expectedContextRevision) || binding.expectedContextRevision < 0 ||
      !Array.isArray(policy.knownCredentialRoots) || !Array.isArray(policy.declaredEphemeralPaths) ||
      !Number.isSafeInteger(policy.limits.maxEntries) || policy.limits.maxEntries < 0 ||
      !Number.isSafeInteger(policy.limits.maxBytes) || policy.limits.maxBytes < 0) {
    throw new KernelStorageError('INVALID_REQUEST', 'source capture binding or policy is invalid');
  }
  const hardExcludes = hardExcludedPaths(workspace.canonicalRootPath, options.stateRoot, policy);
  const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  decodeFrozenIgnoreRules(rules);
  const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: canonicalSha256(rules), frozenIgnoreRulesDigest: rules.rulesDigest,
    explicitIncludes: [], explicitExcludes: [...(policy.explicitExcludes ?? [])],
    maxChangedPaths: policy.maxChangedPaths ?? 10_000, maxChangedBytes: policy.maxChangedBytes ?? 512 * 1024 * 1024,
    projectionDigest: '' };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  decodeSourceProjection(projection);
  const provenance = { filesystem, workspace, binding, policy, hardExcludes };
  assertCurrentLiveWorkspaceIdentity(workspace, workspace.canonicalRootPath, filesystem);
  const observations = enumerate(provenance);
  // Validate the entire topology before capturing any regular-file content.
  const entries: WorkspaceEntry[] = [];
  let bytes = 0;
  for (const [relative, observation] of observations) {
    if (observation.kind === 'directory') entries.push({ path: relative, kind: 'directory', mode: 0o755 });
    else if (observation.kind === 'file') {
      bytes += observation.size!;
      entries.push({ path: relative, kind: 'file', mode: observation.mode & 0o111 ? 0o755 : 0o644,
        size: observation.size!, blobRef: '0'.repeat(64) });
    } else {
      const link = filesystem.readWorkspaceSourceSymlink(workspace.canonicalRootPath, workspace.rootIdentity, relative);
      assertSameSourceObservation(link, observation, relative);
      bytes += Buffer.byteLength(link.target, 'utf8');
      entries.push({ path: relative, kind: 'symlink', mode: 0o777, target: link.target,
        targetDigest: sha256Bytes(Buffer.from(link.target, 'utf8')) });
    }
  }
  if (!Number.isSafeInteger(bytes) || bytes > policy.limits.maxBytes) {
    throw new KernelStorageError('INVALID_REQUEST', 'source capture byte limit exceeded');
  }
  manifest(entries);
  assertHardExcludedLinkTargets(entries, hardExcludes);
  assertInventory(observations, enumerate(provenance));
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]!;
    if (entry.kind !== 'file') continue;
    entries[index] = (await captureObservedWorkspaceSourceFile(filesystem, workspace.canonicalRootPath,
      workspace.rootIdentity, entry.path, observations.get(entry.path)!, cas)).entry;
  }
  const entryManifest = immutableSnapshot(manifest(entries));
  const metadata = [await publishCanonical(cas, rules, 'cliq-frozen-ignore-rules-v1', filesystem),
    await publishCanonical(cas, projection, 'cliq-source-projection-v1', filesystem),
    await publishCanonical(cas, entryManifest, 'cliq-workspace-entries-v1', filesystem)];
  const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base',
    workspaceIdentityDigest: workspace.identityDigest, entriesRef: metadata[2]!.ref,
    sourceProjectionRef: metadata[1]!.ref, sourceProjectionDigest: projection.projectionDigest,
    frozenIgnoreRulesRef: metadata[0]!.ref, frozenIgnoreRulesDigest: rules.rulesDigest,
    treeDigest: entryManifest.treeDigest, manifestDigest: '' };
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  decodeSourceManifest(source);
  metadata.push(await publishCanonical(cas, source, 'cliq-source-manifest-v1', filesystem));
  const capture: CapturedWorkspaceSourceTree = Object.freeze({ sourceProjectionRef: metadata[1]!.ref,
    frozenIgnoreRulesRef: metadata[0]!.ref, baseWorkspaceManifestRef: metadata[3]!.ref, entries: entryManifest });
  captures.set(capture, { ...provenance, observations, metadata: immutableSnapshot(metadata) });
  assertCapturedWorkspaceSourceTree(capture, filesystem, { ...binding,
    workspacePath: workspace.canonicalRootPath, workspaceIdentityDigest: workspace.identityDigest, ...capture });
  return capture;
}

function boundCapture(capture: CapturedWorkspaceSourceTree,
  filesystem: HeldStateOwnerLock, expected: ExpectedCapture): CaptureProvenance {
  const proof = captures.get(capture);
  if (!proof || proof.filesystem !== filesystem ||
      proof.workspace.canonicalRootPath !== expected.workspacePath ||
      proof.workspace.identityDigest !== expected.workspaceIdentityDigest ||
      proof.binding.principalId !== expected.principalId || proof.binding.sessionId !== expected.sessionId ||
      proof.binding.expectedContextRevision !== expected.expectedContextRevision ||
      proof.binding.admissionKey !== expected.admissionKey ||
      capture.sourceProjectionRef !== expected.sourceProjectionRef ||
      capture.frozenIgnoreRulesRef !== expected.frozenIgnoreRulesRef ||
      capture.baseWorkspaceManifestRef !== expected.baseWorkspaceManifestRef) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source capture is not bound to this owner and Run admission');
  }
  return proof;
}

/** Bind retained refs before asynchronous admission publication. All live
 * bytes/path checks still run synchronously at the final transaction boundary. */
export function validateCapturedWorkspaceSourceTreeBinding(capture: CapturedWorkspaceSourceTree,
  filesystem: HeldStateOwnerLock, expected: ExpectedCapture): readonly PublishedArtifact[] {
  return boundCapture(capture, filesystem, expected).metadata;
}

/** Only a trusted factory handle on this exact live StateOwner may close the
 * admission source seam. Rehash every selected file, then enumerate again so a
 * same-size write after an earlier read, or a new/deleted path, cannot hide. */
export function assertCapturedWorkspaceSourceTree(capture: CapturedWorkspaceSourceTree,
  filesystem: HeldStateOwnerLock, expected: ExpectedCapture): readonly PublishedArtifact[] {
  const proof = boundCapture(capture, filesystem, expected);
  assertCurrentLiveWorkspaceIdentity(proof.workspace, expected.workspacePath, filesystem);
  assertInventory(proof.observations, enumerate(proof));
  for (const entry of capture.entries.entries) {
    const observation = proof.observations.get(entry.path)!;
    if (entry.kind === 'file') {
      assertLiveWorkspaceSourceFile(filesystem, expected.workspacePath, proof.workspace.rootIdentity, entry, observation);
    } else if (entry.kind === 'symlink') {
      const link = filesystem.readWorkspaceSourceSymlink(expected.workspacePath, proof.workspace.rootIdentity, entry.path);
      assertSameSourceObservation(link, observation, entry.path);
      if (link.target !== entry.target) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace source symlink target changed');
      }
    }
  }
  assertInventory(proof.observations, enumerate(proof));
  assertCurrentLiveWorkspaceIdentity(proof.workspace, expected.workspacePath, filesystem);
  return proof.metadata;
}
