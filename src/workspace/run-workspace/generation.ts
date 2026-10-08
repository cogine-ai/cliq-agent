import { randomBytes } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../../kernel/identity.js';
import type { Checkpoint, WorkspaceEntry, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1,
  WorkspaceGenerationSnapshotEvidenceV1, WorkspaceStateManifest } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../../state/artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries,
  decodeWorkspaceGenerationIdentity, decodeWorkspaceState } from '../../state/decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../../state/errors.js';
import { borrowGenerationForExecution, openGenerationFileWriter, openGenerationSnapshot, stateRootIdentityForLock, writeGenerationEntry,
  type BorrowedGenerationForExecution, type HeldGenerationTree, type HeldStateOwnerLock } from '../../state/native-owner.js';
import { loadFrozenPrivateGit, observedPrivateGit, type FrozenPrivateGit } from './private-git.js';

export type WorkspaceTreeObservation = Readonly<{
  entriesRef: string;
  treeDigest: string;
  workspaceStateRef: string;
  workspaceStateDigest: string;
  privateGitStateRef?: string;
  descriptorRewalkComplete: true;
  fileFsyncComplete: true;
  directoryFsyncComplete: true;
}>;
export type MaterializedGenerationAuthority = Readonly<{
  generationRef: string;
  generationIdentityDigest: string;
  snapshotEvidenceRef: string;
  snapshotEvidenceDigest: string;
}>;
/** One private physical tree. No paths, file descriptors, mutation callback,
 * platform qualification or StateStore transition is exposed to a client.
 * Cancellation rejects only after the operation's file/cursor/CAS cleanup;
 * it never mints a tree observation or containment-death evidence. A factory
 * signal remains binding for the lifetime of this handle. */
export type RunWorkspaceGeneration = Readonly<{
  generationId: string;
  observe(options?: { signal?: AbortSignal }): Promise<WorkspaceTreeObservation>;
  publishMaterializedAuthority(options?: { signal?: AbortSignal }): Promise<MaterializedGenerationAuthority>;
  close(): void;
}>;
const generationTrees = new WeakMap<RunWorkspaceGeneration, HeldGenerationTree>();
declare const retainedObservationBrand: unique symbol;
export type RetainedWorkspaceObservation = Readonly<{ [retainedObservationBrand]: true }>;
type RetainedObservationData = Readonly<WorkspaceTreeObservation & {
  generationRef: string; generationIdentityDigest: string; observedAt: string;
  observedState: Readonly<{ kind: 'complete_tree'; treeDigest: string }>;
}>;
const retainedObservations = new WeakMap<RetainedWorkspaceObservation,
  { owner: HeldStateOwnerLock; data: RetainedObservationData }>();

/** Trusted recovery code consumes only an actual minted observation. This is
 * filesystem evidence, never containment death or permission to clear a wait. */
export function readRetainedWorkspaceObservation(observation: RetainedWorkspaceObservation): RetainedObservationData {
  const retained = retainedObservations.get(observation);
  if (!retained) throw new TypeError('invalid retained private workspace observation');
  retained.owner.assertHeld();
  return retained.data;
}

export function borrowRunWorkspaceForExecution(generation: RunWorkspaceGeneration): BorrowedGenerationForExecution {
  const tree = generationTrees.get(generation);
  if (!tree) throw new TypeError('invalid Run workspace generation');
  return borrowGenerationForExecution(tree);
}
function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function closeWorkspaceDescriptor(resource: { close(): void }): void {
  try { resource.close(); }
  catch (cause) { throw new ResourceRetirementError('private workspace descriptor retirement failed', cause); }
}

function checkedPath(value: string): string {
  if (typeof value !== 'string' || value !== value.normalize('NFC') || Buffer.byteLength(value) > 4096 ||
      value.includes('\\') || value.includes('\0') || value.split('/').some(part => !part || part === '.' || part === '..' ||
        Buffer.byteLength(part) > 255) || value.split('/').some(part => part.toLowerCase() === '.git')) {
    mismatch('workspace entry must be a canonical NFC root-relative path outside .git');
  }
  return value;
}
function checkedEntries(manifest: WorkspaceEntryManifest): void {
  const kinds = new Map<string, WorkspaceEntry['kind']>();
  const casePaths = new Set<string>();
  for (const entry of manifest.entries) {
    checkedPath(entry.path);
    const folded = entry.path.toLowerCase();
    if (casePaths.has(folded)) mismatch('workspace entry case collision is unsupported');
    casePaths.add(folded);
    for (let slash = entry.path.indexOf('/'); slash >= 0; slash = entry.path.indexOf('/', slash + 1)) {
      if (kinds.get(entry.path.slice(0, slash)) !== 'directory') mismatch('workspace entry lacks its exact declared directory ancestor');
    }
    if (entry.kind === 'symlink') checkedSymlink(entry);
    if ((entry.kind === 'directory' && entry.mode !== 0o755) ||
        (entry.kind === 'file' && entry.mode !== 0o644 && entry.mode !== 0o755)) mismatch('workspace entry mode is not normalized');
    kinds.set(entry.path, entry.kind);
  }
  const paths = new Map(manifest.entries.map(entry => [entry.path, entry]));
  for (const entry of manifest.entries) if (entry.kind === 'symlink') checkedSymlinkGraph(entry, paths);
}
function checkedSymlink(entry: Extract<WorkspaceEntry, { kind: 'symlink' }>): void {
  const target = entry.target;
  if (typeof target !== 'string' || !target || target !== target.normalize('NFC') || target.startsWith('/') ||
      target.includes('\\') || target.includes('\0') || Buffer.byteLength(target) > 4096 || entry.mode !== 0o777 ||
      sha256Bytes(Buffer.from(target)) !== entry.targetDigest) mismatch('workspace symlink target text/digest/mode differs');
  const resolved = entry.path.split('/').slice(0, -1);
  for (const part of target.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') { if (!resolved.length) mismatch('workspace symlink escapes the generation'); resolved.pop(); }
    else { if (part.toLowerCase() === '.git') mismatch('workspace symlink may not reference Git metadata'); resolved.push(part); }
  }
}
/** Expand links in POSIX lookup order before applying a following `..`.
 * Iterative frames avoid a JavaScript stack bound on admitted graph depth.
 * Missing targets remain safe dangling links; declared files cannot be
 * traversed and a cycle is not a resolvable in-root target. */
function checkedSymlinkGraph(entry: Extract<WorkspaceEntry, { kind: 'symlink' }>, paths: Map<string, WorkspaceEntry>): void {
  const resolved = entry.path.split('/').slice(0, -1);
  const active = new Set([entry.path]);
  const frames = [{ link: entry.path, parts: entry.target.split('/'), index: 0 }];
  let dangling = false;
  while (frames.length) {
    const frame = frames[frames.length - 1];
    if (frame.index === frame.parts.length) { active.delete(frame.link); frames.pop(); continue; }
    const part = frame.parts[frame.index++];
    if (!part || part === '.') continue;
    if (part === '..') {
      if (!resolved.length) mismatch('workspace symlink chain escapes the generation');
      resolved.pop(); continue;
    }
    if (part.toLowerCase() === '.git') mismatch('workspace symlink chain may not reference Git metadata');
    const candidate = dangling ? undefined : paths.get([...resolved, part].join('/'));
    if (candidate?.kind === 'symlink') {
      if (active.has(candidate.path)) mismatch('workspace symlink graph contains a cycle');
      active.add(candidate.path);
      frames.push({ link: candidate.path, parts: candidate.target.split('/'), index: 0 });
      continue;
    }
    if (candidate?.kind === 'file' && frames.some(pending => pending.index < pending.parts.length)) {
      mismatch('workspace symlink graph traverses a non-directory');
    }
    if (!candidate) dangling = true;
    resolved.push(part);
  }
}
function entriesManifest(entries: WorkspaceEntry[]): WorkspaceEntryManifest {
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  let byteCount = 0;
  for (const entry of entries) {
    byteCount += entry.kind === 'file' ? entry.size : entry.kind === 'symlink' ? Buffer.byteLength(entry.target) : 0;
    if (!Number.isSafeInteger(byteCount)) mismatch('workspace entry byte count overflow');
  }
  return { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries, entryCount: entries.length, byteCount,
    treeDigest: canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries }) };
}

async function readFrozenWorkspace(artifacts: ArtifactCatalog, stateRef: string, signal?: AbortSignal) {
  signal?.throwIfAborted();
  const sourceState = decodeWorkspaceState(await artifacts.readCanonical(stateRef));
  signal?.throwIfAborted();
  const source = decodeSourceManifest(await artifacts.readCanonical(sourceState.baseWorkspaceManifestRef));
  signal?.throwIfAborted();
  const sourceEntries = decodeWorkspaceEntries(await artifacts.readCanonical(source.entriesRef));
  signal?.throwIfAborted();
  const entries = decodeWorkspaceEntries(await artifacts.readCanonical(sourceState.entriesRef));
  signal?.throwIfAborted();
  const projection = decodeSourceProjection(await artifacts.readCanonical(source.sourceProjectionRef));
  signal?.throwIfAborted();
  const rules = decodeFrozenIgnoreRules(await artifacts.readCanonical(source.frozenIgnoreRulesRef));
  signal?.throwIfAborted();
  if (source.role !== 'base' || sourceState.sourceProjectionDigest !== source.sourceProjectionDigest ||
      projection.projectionDigest !== source.sourceProjectionDigest || source.treeDigest !== sourceEntries.treeDigest ||
      projection.frozenIgnoreRulesRef !== source.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== source.frozenIgnoreRulesDigest || rules.rulesDigest !== source.frozenIgnoreRulesDigest) {
    mismatch('ready Checkpoint workspace/source/projection closure differs');
  }
  const privateGit = await loadFrozenPrivateGit(artifacts, source, sourceState, rules, signal);
  signal?.throwIfAborted();
  checkedEntries(sourceEntries); checkedEntries(entries);
  let priorInvalidated: string | undefined;
  for (const invalidated of sourceState.invalidatedEphemeralPaths) {
    checkedPath(invalidated);
    if ((priorInvalidated !== undefined && Buffer.compare(Buffer.from(priorInvalidated), Buffer.from(invalidated)) >= 0) ||
        entries.entries.some(entry => entry.path === invalidated || entry.path.startsWith(`${invalidated}/`))) {
      mismatch('invalidated ephemeral paths must be sorted, unique and absent from materialized entries');
    }
    priorInvalidated = invalidated;
  }
  return { sourceState, source, entries, privateGit };
}

async function observeTree(tree: HeldGenerationTree, artifacts: ArtifactCatalog, sourceState: WorkspaceStateManifest,
  privateGit: FrozenPrivateGit | undefined, signal?: AbortSignal): Promise<WorkspaceTreeObservation> {
  signal?.throwIfAborted();
  const snapshot = openGenerationSnapshot(tree);
  const observedEntries: WorkspaceEntry[] = [];
  const gitDirectories = new Set<string>(), gitFiles = new Map<string, Buffer>();
  try {
    for (;;) {
      signal?.throwIfAborted();
      const entry = snapshot.next();
      if (entry === null) break;
      if (entry.path === '.git' || entry.path.startsWith('.git/')) {
        if (!privateGit) mismatch('non-Git generation contains private Git metadata');
        if (entry.kind === 'directory') {
          if (entry.mode !== 0o700 || !privateGit.directories.includes(entry.path)) mismatch('private Git directory closure differs');
          gitDirectories.add(entry.path);
        } else if (entry.kind === 'file') {
          try {
            const expected = privateGit.files.get(entry.path);
            if (entry.mode !== 0o600 || !expected || entry.byteCount !== expected.length) mismatch('private Git file closure differs');
            const chunks: Buffer[] = [];
            for (;;) {
              signal?.throwIfAborted();
              const chunk = entry.file.readChunk();
              if (chunk === null) break;
              chunks.push(chunk);
              await setImmediate();
              signal?.throwIfAborted();
              entry.file.assertHeld();
            }
            gitFiles.set(entry.path, Buffer.concat(chunks));
          } finally { closeWorkspaceDescriptor(entry.file); }
        } else mismatch('private Git metadata may not contain symlinks');
        await setImmediate();
        signal?.throwIfAborted();
        tree.assertHeld();
        continue;
      }
      checkedPath(entry.path);
      if (entry.kind === 'directory') observedEntries.push({ path: entry.path, kind: 'directory', mode: entry.mode });
      else if (entry.kind === 'file') {
        try {
          const chunks = (async function* () {
            for (;;) {
              signal?.throwIfAborted();
              const chunk = entry.file.readChunk();
              if (chunk === null) break;
              yield chunk;
              await setImmediate();
              signal?.throwIfAborted();
              entry.file.assertHeld();
            }
          })();
          const blob = await artifacts.publishChunks(chunks, 'application/octet-stream', 'cliq-workspace-file-v1', entry.byteCount);
          signal?.throwIfAborted();
          if (blob.byteLength !== entry.byteCount) mismatch('native snapshot file was not completely read');
          observedEntries.push({ path: entry.path, kind: 'file', mode: entry.mode, size: entry.byteCount, blobRef: blob.ref });
        } finally { closeWorkspaceDescriptor(entry.file); }
      } else observedEntries.push({ path: entry.path, kind: 'symlink', mode: entry.mode, target: entry.target,
        targetDigest: sha256Bytes(Buffer.from(entry.target)) });
      await setImmediate();
      signal?.throwIfAborted();
      tree.assertHeld();
    }
    snapshot.assertComplete();
  } finally { closeWorkspaceDescriptor(snapshot); }
  signal?.throwIfAborted();
  const observed = entriesManifest(observedEntries);
  checkedEntries(observed);
  const entriesRef = (await artifacts.publishCanonical(observed, observed.format)).ref;
  signal?.throwIfAborted();
  const privateGitStateRef = privateGit ? await observedPrivateGit(artifacts, privateGit, gitDirectories, gitFiles, signal) : undefined;
  signal?.throwIfAborted();
  const state: WorkspaceStateManifest = { ...sourceState, entriesRef,
    ...(privateGitStateRef === undefined ? {} : { privateGitStateRef }), stateDigest: '' };
  state.stateDigest = digestOmitting(state, 'stateDigest');
  const workspaceStateRef = (await artifacts.publishCanonical(state, state.format)).ref;
  signal?.throwIfAborted();
  tree.assertHeld();
  return Object.freeze({ entriesRef, treeDigest: observed.treeDigest, workspaceStateRef, workspaceStateDigest: state.stateDigest,
    ...(privateGitStateRef === undefined ? {} : { privateGitStateRef }),
    descriptorRewalkComplete: true, fileFsyncComplete: true, directoryFsyncComplete: true });
}

/** Internal recovery factory supplies the current retained generation. A
 * successful complete rewalk is minted; unreadable/unsupported trees throw,
 * never fabricate partial-failure evidence or an older recovery cut. */
export async function observeRetainedRunWorkspace(input: { filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog;
  identity: WorkspaceGenerationIdentityV1; sourceRowVersion: number; signal?: AbortSignal }): Promise<RetainedWorkspaceObservation> {
  const { filesystem, artifacts, signal } = input;
  signal?.throwIfAborted();
  filesystem.assertHeld();
  if (!Number.isSafeInteger(input.sourceRowVersion) || input.sourceRowVersion < 1) {
    mismatch('retained generation observation requires its fixed positive source version');
  }
  const identity = decodeWorkspaceGenerationIdentity(structuredClone(input.identity));
  const { sourceState, source, entries, privateGit } = await readFrozenWorkspace(artifacts, identity.sourceWorkspaceStateRef, signal);
  signal?.throwIfAborted();
  if (sourceState.runId !== identity.runId || sourceState.stateDigest !== identity.sourceWorkspaceStateDigest ||
      entries.treeDigest !== identity.sourceTreeDigest || source.workspaceIdentityDigest !== identity.workspaceIdentityDigest) {
    mismatch('retained generation source Checkpoint closure differs');
  }
  const tree = filesystem.openGenerationTree(identity, input.sourceRowVersion);
  try {
    const observed = await observeTree(tree, artifacts, sourceState, privateGit, signal);
    signal?.throwIfAborted();
    filesystem.assertHeld();
    const observation = Object.freeze({}) as RetainedWorkspaceObservation;
    retainedObservations.set(observation, { owner: filesystem, data: Object.freeze({ ...observed,
      generationRef: canonicalSha256(identity), generationIdentityDigest: identity.identityDigest,
      observedAt: new Date().toISOString(), observedState: Object.freeze({ kind: 'complete_tree', treeDigest: observed.treeDigest }) }) });
    return observation;
  } finally { closeWorkspaceDescriptor(tree); }
}

async function mintRunWorkspace(tree: HeldGenerationTree, filesystem: HeldStateOwnerLock, artifacts: ArtifactCatalog,
  checkpoint: Checkpoint, frozen: Awaited<ReturnType<typeof readFrozenWorkspace>>, nonce: string, createdAt: string,
  retainedIdentity?: WorkspaceGenerationIdentityV1, lifetimeSignal?: AbortSignal): Promise<RunWorkspaceGeneration> {
  const { sourceState, source, entries, privateGit } = frozen;
  const generationId = identityHash(checkpoint.runId, checkpoint.id, checkpoint.workspaceStateRef, nonce);
  const observe = (signal?: AbortSignal) => observeTree(tree, artifacts, sourceState, privateGit,
    lifetimeSignal && signal ? AbortSignal.any([lifetimeSignal, signal]) : lifetimeSignal ?? signal);
  const initial = await observe();
  if (initial.entriesRef !== sourceState.entriesRef || initial.treeDigest !== entries.treeDigest ||
      initial.workspaceStateRef !== checkpoint.workspaceStateRef) mismatch('physical generation does not exactly reproduce the frozen ready Checkpoint');
  const generation: RunWorkspaceGeneration = Object.freeze({
    generationId,
    async observe(options) { if (this !== generation) throw new TypeError('invalid Run workspace generation'); return observe(options?.signal); },
    async publishMaterializedAuthority(options) {
      if (this !== generation) throw new TypeError('invalid Run workspace generation');
      const signal = options?.signal;
      lifetimeSignal?.throwIfAborted(); signal?.throwIfAborted();
      if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'a host staging directory is not a Linux generation or macOS VM volume');
      const observed = await observe(signal);
      if (observed.workspaceStateRef !== checkpoint.workspaceStateRef || observed.treeDigest !== entries.treeDigest) {
        mismatch('materialized generation authority requires unchanged frozen source bytes');
      }
      const root = stateRootIdentityForLock(filesystem);
      const identity: WorkspaceGenerationIdentityV1 = retainedIdentity ?? { schemaVersion: 1, format: 'cliq-workspace-generation-identity-v1',
        generationId, runId: checkpoint.runId, workspaceIdentityDigest: source.workspaceIdentityDigest,
        sourceCheckpointId: checkpoint.id, sourceWorkspaceStateRef: checkpoint.workspaceStateRef,
        sourceWorkspaceStateDigest: sourceState.stateDigest, sourceTreeDigest: entries.treeDigest, creationNonceDigest: nonce,
        locator: { kind: 'linux_directory', stateRootIdentityRef: canonicalSha256(root), stateRootIdentityDigest: root.identityDigest,
          canonicalRootRelativePath: `runs/${checkpoint.runId}/generations/${generationId}`, deviceId: tree.identity.deviceId,
          directoryFileId: tree.identity.fileId, ownerUid: tree.identity.ownerUid, mode: 448 }, createdAt, identityDigest: '' };
      identity.identityDigest = digestOmitting(identity, 'identityDigest');
      const generationRef = (await artifacts.publishCanonical(identity, identity.format)).ref;
      lifetimeSignal?.throwIfAborted(); signal?.throwIfAborted();
      const evidence: WorkspaceGenerationSnapshotEvidenceV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-snapshot-evidence-v1',
        purpose: 'materialized_from_checkpoint', runId: checkpoint.runId, generationRef, generationIdentityDigest: identity.identityDigest,
        checkpointId: checkpoint.id, workspaceStateRef: checkpoint.workspaceStateRef, workspaceStateDigest: sourceState.stateDigest,
        entriesRef: sourceState.entriesRef, treeDigest: entries.treeDigest, descriptorRewalkComplete: true, fileFsyncComplete: true,
        ...(observed.privateGitStateRef === undefined ? {} : { privateGitStateRef: observed.privateGitStateRef }),
        directoryFsyncComplete: true, observedAt: new Date().toISOString(), evidenceDigest: '' };
      evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest');
      const snapshotEvidenceRef = (await artifacts.publishCanonical(evidence, evidence.format)).ref;
      lifetimeSignal?.throwIfAborted(); signal?.throwIfAborted();
      tree.assertHeld();
      return Object.freeze({ generationRef, generationIdentityDigest: identity.identityDigest,
        snapshotEvidenceRef, snapshotEvidenceDigest: evidence.evidenceDigest });
    },
    close() { if (this !== generation) throw new TypeError('invalid Run workspace generation'); closeWorkspaceDescriptor(tree); }
  });
  generationTrees.set(generation, tree);
  return generation;
}

/** Reopening does not adopt a mutable tree or choose a Checkpoint. The trusted
 * factory supplies the sole retained preactivated row and its owning ready
 * cut; exact identity plus a fresh complete rewalk must agree before minting. */
export async function reopenRunWorkspace(input: { filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog;
  identity: WorkspaceGenerationIdentityV1; checkpoint: Checkpoint; signal?: AbortSignal }): Promise<RunWorkspaceGeneration> {
  const { filesystem, artifacts, signal } = input;
  signal?.throwIfAborted();
  filesystem.assertHeld();
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'private generation reopen requires a qualified Linux directory');
  const identity = decodeWorkspaceGenerationIdentity(structuredClone(input.identity));
  const checkpoint = structuredClone(input.checkpoint);
  if (checkpoint.schemaVersion !== 1 || checkpoint.runId !== identity.runId || checkpoint.id !== identity.sourceCheckpointId ||
      checkpoint.workspaceStateRef !== identity.sourceWorkspaceStateRef) mismatch('reopened generation requires its exact owning ready Checkpoint');
  const frozen = await readFrozenWorkspace(artifacts, checkpoint.workspaceStateRef, signal);
  signal?.throwIfAborted();
  if (frozen.sourceState.runId !== identity.runId || frozen.sourceState.stateDigest !== identity.sourceWorkspaceStateDigest ||
      frozen.entries.treeDigest !== identity.sourceTreeDigest || frozen.source.workspaceIdentityDigest !== identity.workspaceIdentityDigest) {
    mismatch('reopened generation source identity differs');
  }
  const tree = filesystem.openGenerationTree(identity);
  try { return await mintRunWorkspace(tree, filesystem, artifacts, checkpoint, frozen, identity.creationNonceDigest, identity.createdAt, identity, signal); }
  catch (error) { closeWorkspaceDescriptor(tree); throw error; }
}

/** Trusted factory supplies one frozen ready Checkpoint. Materialization reads
 * only that immutable CAS closure, never recaptures or links the live source.
 * A failed attempt leaves its exact orphan in place for typed quarantine/GC;
 * it never recursively deletes a potentially replaced path. */
export async function materializeRunWorkspace(input: {
  filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog; checkpoint: Checkpoint; signal?: AbortSignal;
}): Promise<RunWorkspaceGeneration> {
  const { filesystem, artifacts, signal } = input;
  signal?.throwIfAborted();
  const checkpoint = structuredClone(input.checkpoint);
  filesystem.assertHeld();
  if (checkpoint.schemaVersion !== 1 || !/^[A-Za-z0-9_-]{1,128}$/.test(checkpoint.runId) || !checkpoint.id ||
      ![checkpoint.basedOnRunRevision, checkpoint.runItemSeq, checkpoint.journalSeq].every(n => Number.isSafeInteger(n) && n >= 0)) {
    mismatch('materialization requires a frozen owning ready Checkpoint');
  }
  parseCanonicalTime(checkpoint.createdAt);
  assertArtifactRef(checkpoint.workspaceStateRef);
  const frozen = await readFrozenWorkspace(artifacts, checkpoint.workspaceStateRef, signal);
  signal?.throwIfAborted();
  const { sourceState, entries, privateGit } = frozen;
  if (sourceState.runId !== checkpoint.runId) mismatch('ready Checkpoint belongs to a different Run');
  const nonce = sha256Bytes(randomBytes(32));
  const generationId = identityHash(checkpoint.runId, checkpoint.id, checkpoint.workspaceStateRef, nonce);
  const createdAt = new Date().toISOString();
  const tree = filesystem.createGenerationTree(checkpoint.runId, generationId);
  try {
    for (const entry of entries.entries) {
      signal?.throwIfAborted();
      tree.assertHeld();
      if (entry.kind === 'directory') writeGenerationEntry(tree, { kind: 'directory', path: entry.path });
      else if (entry.kind === 'file') {
        const writer = openGenerationFileWriter(tree, entry.path, entry.mode as 420 | 493, entry.size);
        try {
          for await (const chunk of artifacts.readChunks(entry.blobRef, entry.size)) {
            signal?.throwIfAborted();
            writer.assertHeld(); writer.writeChunk(chunk);
            await setImmediate();
            signal?.throwIfAborted();
            writer.assertHeld();
          }
          signal?.throwIfAborted();
          writer.finish();
        } finally { closeWorkspaceDescriptor(writer); }
      } else writeGenerationEntry(tree, { kind: 'symlink', path: entry.path, target: entry.target });
      await setImmediate();
      signal?.throwIfAborted();
    }
    if (privateGit) {
      for (const path of privateGit.directories) {
        signal?.throwIfAborted();
        writeGenerationEntry(tree, { kind: 'directory', path });
        await setImmediate();
        signal?.throwIfAborted();
      }
      for (const [path, bytes] of privateGit.files) {
        signal?.throwIfAborted();
        const writer = openGenerationFileWriter(tree, path, 0o600, bytes.length);
        try {
          for (let offset = 0; offset < bytes.length; offset += 65_536) {
            writer.writeChunk(bytes.subarray(offset, offset + 65_536));
            await setImmediate();
            signal?.throwIfAborted();
            writer.assertHeld();
          }
          writer.finish();
        } finally { closeWorkspaceDescriptor(writer); }
      }
    }
    return await mintRunWorkspace(tree, filesystem, artifacts, checkpoint, frozen, nonce, createdAt, undefined, signal);
  } catch (error) { closeWorkspaceDescriptor(tree); throw error; }
}
