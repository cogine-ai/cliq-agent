import { createHash, randomBytes } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import type { SandboxResourceSpec } from '../../kernel/execution.js';
import { readPreparingGitCompletion, type PreparingGitCompletion } from '../../sandbox/preparation-git.js';
import { privateGitInspectionOutput } from '../private-git-data.js';
import { readFrozenIgnoreRules } from '../frozen-ignore.js';
import { readSourceProjectionData } from '../../state/source-projection-data.js';
import { checkProjection } from '../../state/source-validation.js';
import { assertArtifactRef, digestOmitting, identityHash, parseCanonicalTime, sha256Bytes } from '../../kernel/identity.js';
import type { Checkpoint, WorkspaceEntry, WorkspaceEntryManifest, WorkspaceGenerationIdentityV1,
  WorkspaceGenerationSnapshotEvidenceV1, WorkspaceGenerationQuarantineEvidenceV1, WorkspaceStateManifest } from '../../kernel/types.js';
import type { ArtifactCatalog } from '../../state/artifacts.js';
import { decodeFrozenIgnoreRules, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries,
  decodeWorkspaceGenerationIdentity, decodeWorkspaceState } from '../../state/decoders.js';
import { KernelStorageError, ResourceRetirementError } from '../../state/errors.js';
import { assertRetiredGenerationTree, borrowGenerationForExecution, openGenerationFileWriter, openGenerationSnapshot, stateRootIdentityForLock, writeGenerationEntry,
  openPreparingGitInput, type PreparingGitInputBinding, type HeldPreparingGitInput, type HeldWorkerReservation,
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
const generationTrees = new WeakMap<RunWorkspaceGeneration,
  { tree: HeldGenerationTree; lifetimeSignal?: AbortSignal }>();
declare const workspaceBirthBrand: unique symbol;
export type RunWorkspaceBirth = Readonly<{ [workspaceBirthBrand]: true }>;
export type RunWorkspaceBirthData = Readonly<{
  generationId: string; runId: string; workspaceIdentityDigest: string;
  sourceCheckpointId: string; sourceWorkspaceStateRef: string;
  sourceWorkspaceStateDigest: string; sourceTreeDigest: string;
  creationNonceDigest: string; createdAt: string;
  stateRootIdentity: ReturnType<typeof stateRootIdentityForLock>;
  directoryIdentity: HeldGenerationTree['identity'];
}>;
export type RunWorkspaceMaterialization = Readonly<{
  birth(): Promise<RunWorkspaceBirth>;
  finish(options?: { gitPreparation?: PreparingGitCompletion }): Promise<RunWorkspaceGeneration>;
  close(): Promise<void>;
}>;
export type UnallocatedRunWorkspaceRetirement = Readonly<{ runId: string; generationId: string;
  sourceCheckpointId: string; sourceWorkspaceStateRef: string; creationNonceDigest: string;
  allocationRequested: false; operationsJoined: true; observedAt: string }>;
const unallocatedMaterializations = new WeakMap<RunWorkspaceMaterialization,
  { filesystem: HeldStateOwnerLock; read(): UnallocatedRunWorkspaceRetirement }>();
type WorkspaceOperations = { pending: Set<Promise<unknown>>; retirementFailure?: ResourceRetirementError };
const workspaceBirths = new WeakMap<RunWorkspaceBirth,
  { filesystem: HeldStateOwnerLock; tree: HeldGenerationTree; data: RunWorkspaceBirthData;
    operations: WorkspaceOperations; joined: boolean; privateGit?: FrozenPrivateGit; gitResources?: SandboxResourceSpec;
    preparingGitInput?: HeldPreparingGitInput }>();

function trackWorkspaceOperation<T>(operations: WorkspaceOperations | undefined, pending: Promise<T>): Promise<T> {
  if (operations) {
    operations.pending.add(pending);
    void pending.then(() => { operations.pending.delete(pending); }, error => {
      operations.pending.delete(pending);
      if (error instanceof ResourceRetirementError) operations.retirementFailure ??= error;
    });
  }
  return pending;
}

/** Actual held directory birth only, not Linux qualification or permission to
 * copy, mount, activate or retire it. A data/ref substitute cannot mint it. */
export function readRunWorkspaceBirth(filesystem: HeldStateOwnerLock, birth: RunWorkspaceBirth): RunWorkspaceBirthData {
  const held = workspaceBirths.get(birth);
  if (!held || held.filesystem !== filesystem) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace birth requires its exact original StateOwner filesystem');
  }
  filesystem.assertHeld(); held.tree.assertHeld();
  return held.data;
}
/** Program-domain closure only: the exact original producer joined before it
 * ever requested a native allocation. This is not a filesystem absence scan. */
export function readUnallocatedRunWorkspaceRetirement(filesystem: HeldStateOwnerLock,
  materialization: RunWorkspaceMaterialization): UnallocatedRunWorkspaceRetirement {
  const held = unallocatedMaterializations.get(materialization);
  if (!held || held.filesystem !== filesystem)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'unallocated workspace retirement requires its original physical producer');
  filesystem.assertHeld();
  return held.read();
}
/** Bind the actual empty directory before payload I/O. This identity is not a
 * materialization snapshot, a mount grant or permission to execute the tree. */
function workspaceBirthIdentity(data: RunWorkspaceBirthData): WorkspaceGenerationIdentityV1 {
  const identity: WorkspaceGenerationIdentityV1 = { schemaVersion: 1, format: 'cliq-workspace-generation-identity-v1',
    generationId: data.generationId, runId: data.runId, workspaceIdentityDigest: data.workspaceIdentityDigest,
    sourceCheckpointId: data.sourceCheckpointId, sourceWorkspaceStateRef: data.sourceWorkspaceStateRef,
    sourceWorkspaceStateDigest: data.sourceWorkspaceStateDigest, sourceTreeDigest: data.sourceTreeDigest,
    creationNonceDigest: data.creationNonceDigest, createdAt: data.createdAt,
    locator: { kind: 'linux_directory', stateRootIdentityRef: canonicalSha256(data.stateRootIdentity),
      stateRootIdentityDigest: data.stateRootIdentity.identityDigest,
      canonicalRootRelativePath: `runs/${data.runId}/generations/${data.generationId}`,
      deviceId: data.directoryIdentity.deviceId, directoryFileId: data.directoryIdentity.fileId,
      ownerUid: data.directoryIdentity.ownerUid, mode: 448 }, identityDigest: '' };
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  return identity;
}
export async function publishRunWorkspaceBirthIdentity(filesystem: HeldStateOwnerLock, artifacts: ArtifactCatalog,
  birth: RunWorkspaceBirth): Promise<Pick<MaterializedGenerationAuthority, 'generationRef' | 'generationIdentityDigest'>> {
  const data = readRunWorkspaceBirth(filesystem, birth);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'preparation requires its implemented Linux directory birth');
  const identity = workspaceBirthIdentity(data);
  const artifact = await artifacts.publishCanonical(identity, identity.format);
  readRunWorkspaceBirth(filesystem, birth);
  return Object.freeze({ generationRef: artifact.ref, generationIdentityDigest: identity.identityDigest });
}

/** Original actual birth friend only. This grants no Git result, worker or
 * materialization authority. The same native lock independently checks the
 * genuine reservation/tree C tags; no numerical FD or locator is accepted. */
export function openRunWorkspacePreparingGitInput(filesystem: HeldStateOwnerLock, birth: RunWorkspaceBirth,
  reservation: HeldWorkerReservation, input: PreparingGitInputBinding): HeldPreparingGitInput {
  const held = workspaceBirths.get(birth);
  if (!held || held.filesystem !== filesystem) throw new KernelStorageError('ARTIFACT_MISMATCH', 'preparing Git requires its original actual workspace birth');
  const data = readRunWorkspaceBirth(filesystem, birth);
  if (held.joined || held.preparingGitInput) throw new KernelStorageError('STATE_TRANSITION_INVALID', 'workspace birth already owns its preparation input or has joined');
  if (!input || typeof input !== 'object' || types.isProxy(input) || ![Object.prototype, null].includes(Object.getPrototypeOf(input)))
    throw new TypeError('preparing Git requires closed original binding data');
  const keys = ['runId', 'generationId', 'launchId', 'spawnNonceDigest', 'activationNonceDigest', 'generationCreationNonceDigest', 'generationRef', 'inputIntentRef'];
  const fields = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] || !fields[key]!.enumerable ||
      !Object.hasOwn(fields[key]!, 'value') || typeof fields[key]!.value !== 'string')) throw new TypeError('preparing Git requires closed original binding data');
  const binding = Object.fromEntries(keys.map(key => [key, fields[key]!.value])) as PreparingGitInputBinding;
  if (binding.runId !== data.runId || binding.generationId !== data.generationId ||
      binding.generationCreationNonceDigest !== data.creationNonceDigest || binding.generationRef !== canonicalSha256(workspaceBirthIdentity(data)) ||
      !held.privateGit?.data || binding.inputIntentRef !== canonicalSha256(privateGitInspectionOutput(held.privateGit.data)))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'preparing Git binding substitutes its original physical generation identity');
  const native = openPreparingGitInput(filesystem, reservation, held.tree, binding);
  held.preparingGitInput = native; return native;
}
/** Only original, fully read CAS data held by this genuine birth. The leaf is
 * not a Git verification result and grants no execution authority. */
export function readRunWorkspacePreparingGit(filesystem: HeldStateOwnerLock, birth: RunWorkspaceBirth):
  Readonly<{ privateGitStateRef: string; repositoryIdentityDigest: string; metadataRef: string; metadata: Buffer }> | undefined {
  readRunWorkspaceBirth(filesystem, birth);
  const held = workspaceBirths.get(birth)!;
  if (!held.privateGit?.requiresPreparation) return undefined;
  const data = held.privateGit.data;
  if (!data) mismatch('nonempty private Git lacks its complete retained input');
  const metadata = canonicalJsonBytes(privateGitInspectionOutput(data));
  return Object.freeze({ privateGitStateRef: data.manifestRef, repositoryIdentityDigest: data.index.repositoryIdentityDigest,
    metadataRef: sha256Bytes(metadata), metadata });
}
/** Physical resource retirement only. Directory quarantine, containment death
 * and a committed lifecycle transition require their separate producers. */
export function readRunWorkspaceBirthRetirement(filesystem: HeldStateOwnerLock, birth: RunWorkspaceBirth):
  RunWorkspaceBirthData & { observedAt: string; resourcesRetired: true } {
  const held = workspaceBirths.get(birth);
  if (!held || held.filesystem !== filesystem) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace retirement requires its exact original StateOwner filesystem');
  }
  filesystem.assertHeld();
  if (held.operations.retirementFailure) throw held.operations.retirementFailure;
  if (!held.joined || held.operations.pending.size !== 0)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'workspace materialization has not completely joined');
  const observed = assertRetiredGenerationTree(held.tree);
  if (!Number.isSafeInteger(observed) || observed < 1) mismatch('native generation retirement time is invalid');
  const observedAt = new Date(observed).toISOString();
  if (observedAt < held.data.createdAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement clock precedes workspace birth');
  return Object.freeze({ ...held.data, observedAt, resourcesRetired: true });
}
declare const retainedObservationBrand: unique symbol;
export type RetainedWorkspaceObservation = Readonly<{ [retainedObservationBrand]: true }>;
type RetainedObservationData = Readonly<{
  generationRef: string; generationIdentityDigest: string; observedAt: string;
  observedState: WorkspaceGenerationQuarantineEvidenceV1['observedState'];
}>;
const retainedObservations = new WeakMap<RetainedWorkspaceObservation,
  { owner: HeldStateOwnerLock; tree: HeldGenerationTree; data: RetainedObservationData }>();

/** Trusted recovery code consumes only an actual minted observation. This is
 * filesystem evidence, never containment death or permission to clear a wait. */
export function readRetainedWorkspaceObservation(observation: RetainedWorkspaceObservation): RetainedObservationData {
  const retained = retainedObservations.get(observation);
  if (!retained) throw new TypeError('invalid retained private workspace observation');
  retained.owner.assertHeld();
  return retained.data;
}
/** Retirement consumes the closed native resource owner of this exact lock,
 * not a data projection obtained under a predecessor or foreign StateOwner. */
export function readRetainedWorkspaceRetirement(owner: HeldStateOwnerLock, observation: RetainedWorkspaceObservation):
  RetainedObservationData & { treeObservedAt: string } {
  const retained = retainedObservations.get(observation);
  if (!retained || retained.owner !== owner) throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace retirement does not belong to this exact StateOwner');
  const observed = assertRetiredGenerationTree(retained.tree);
  if (!Number.isSafeInteger(observed) || observed < 1) mismatch('native generation retirement time is invalid');
  const data = readRetainedWorkspaceObservation(observation);
  const observedAt = new Date(observed).toISOString();
  if (observedAt < data.observedAt) throw new KernelStorageError('RECOVERY_REQUIRED', 'native retirement clock precedes the actual tree observation');
  return Object.freeze({ ...data, treeObservedAt: data.observedAt, observedAt });
}

export function borrowRunWorkspaceForExecution(generation: RunWorkspaceGeneration): BorrowedGenerationForExecution {
  const held = generationTrees.get(generation);
  if (!held) throw new TypeError('invalid Run workspace generation');
  held.lifetimeSignal?.throwIfAborted();
  return borrowGenerationForExecution(held.tree);
}
function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
/** Only pure validation of actually observed entries can mint this failure.
 * CAS, source, native identity/IO, abort and retirement failures never do. */
class InvalidObservedEntries extends KernelStorageError {
  constructor(cause: KernelStorageError) { super('ARTIFACT_MISMATCH', cause.message, { cause }); }
}
function checkObservedEntries<T>(check: () => T): T {
  try { return check(); }
  catch (error) {
    if (error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH') throw new InvalidObservedEntries(error);
    throw error;
  }
}
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

async function readFrozenWorkspace(artifacts: ArtifactCatalog, stateRef: string, signal?: AbortSignal, gitResources?: SandboxResourceSpec) {
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
  checkProjection(projection);
  if ((!source.git && projection.classificationIndexRef !== undefined) || source.git && !projection.classificationIndexRef)
    mismatch('workspace projection lost its exact original Git classification');
  signal?.throwIfAborted();
  const classification = source.git && gitResources ? await readSourceProjectionData(artifacts, source, projection, gitResources, signal) : undefined;
  const rules = classification?.rules ?? await readFrozenIgnoreRules(artifacts, source.frozenIgnoreRulesRef, source.git?.repositoryIdentityDigest, signal);
  signal?.throwIfAborted();
  if (source.role !== 'base' || sourceState.sourceProjectionDigest !== source.sourceProjectionDigest ||
      projection.projectionDigest !== source.sourceProjectionDigest || source.treeDigest !== sourceEntries.treeDigest ||
      projection.frozenIgnoreRulesRef !== source.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== source.frozenIgnoreRulesDigest || rules.rulesDigest !== source.frozenIgnoreRulesDigest) {
    mismatch('ready Checkpoint workspace/source/projection closure differs');
  }
  const privateGit = await loadFrozenPrivateGit(artifacts, source, sourceState, rules, signal, gitResources);
  if (source.git && !gitResources && (privateGit?.requiresPreparation || projection.classificationIndexRef !== source.git.indexRef))
    mismatch('Git classification beyond a genuine empty graph requires its frozen resource profile');
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
  const gitDirectories = new Set<string>(), gitFiles = new Map<string, { sha256: string; byteCount: number }>();
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
            if (entry.mode !== 0o600 || !expected || entry.byteCount !== expected.byteCount) mismatch('private Git file closure differs');
            const hash = createHash('sha256'); let byteCount = 0;
            for (;;) {
              signal?.throwIfAborted();
              const chunk = entry.file.readChunk();
              if (chunk === null) break;
              hash.update(chunk); byteCount += chunk.length;
              if (!Number.isSafeInteger(byteCount) || byteCount > expected.byteCount) mismatch('private Git file grew during observation');
              await setImmediate();
              signal?.throwIfAborted();
              entry.file.assertHeld();
            }
            gitFiles.set(entry.path, { sha256: hash.digest('hex'), byteCount });
          } finally { closeWorkspaceDescriptor(entry.file); }
        } else mismatch('private Git metadata may not contain symlinks');
        await setImmediate();
        signal?.throwIfAborted();
        tree.assertHeld();
        continue;
      }
      checkObservedEntries(() => checkedPath(entry.path));
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
  const observed = checkObservedEntries(() => {
    const manifest = entriesManifest(observedEntries);
    checkedEntries(manifest);
    return manifest;
  });
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

/** Internal recovery factory supplies the current retained generation. Only an
 * actual complete rewalk or a closed physical-entry validation failure is
 * minted; unknown source/identity/IO/retirement failures still block recovery. */
export async function observeRetainedRunWorkspace(input: { filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog;
  identity: WorkspaceGenerationIdentityV1; sourceRowVersion: number; signal?: AbortSignal; gitResources?: SandboxResourceSpec }): Promise<RetainedWorkspaceObservation> {
  const { filesystem, artifacts, signal } = input;
  signal?.throwIfAborted();
  filesystem.assertHeld();
  if (!Number.isSafeInteger(input.sourceRowVersion) || input.sourceRowVersion < 1) {
    mismatch('retained generation observation requires its fixed positive source version');
  }
  const identity = decodeWorkspaceGenerationIdentity(structuredClone(input.identity));
  const { sourceState, source, entries, privateGit } = await readFrozenWorkspace(artifacts, identity.sourceWorkspaceStateRef, signal, input.gitResources);
  signal?.throwIfAborted();
  if (sourceState.runId !== identity.runId || sourceState.stateDigest !== identity.sourceWorkspaceStateDigest ||
      entries.treeDigest !== identity.sourceTreeDigest || source.workspaceIdentityDigest !== identity.workspaceIdentityDigest) {
    mismatch('retained generation source Checkpoint closure differs');
  }
  const tree = filesystem.openGenerationTree(identity, input.sourceRowVersion);
  try {
    let observedState: RetainedObservationData['observedState'];
    try {
      const observed = await observeTree(tree, artifacts, sourceState, privateGit, signal);
      observedState = Object.freeze({ kind: 'complete_tree', treeDigest: observed.treeDigest });
    } catch (error) {
      if (!(error instanceof InvalidObservedEntries)) throw error;
      // observeTree has already closed its cursor/files. This is not a complete
      // snapshot and has no tree/state/entries digest or fsync success claims.
      observedState = Object.freeze({ kind: 'unreadable_partial', failureCode: 'path_or_entry_invalid' });
    }
    signal?.throwIfAborted();
    filesystem.assertHeld();
    tree.assertHeld();
    const observation = Object.freeze({}) as RetainedWorkspaceObservation;
    retainedObservations.set(observation, { owner: filesystem, tree, data: Object.freeze({
      generationRef: canonicalSha256(identity), generationIdentityDigest: identity.identityDigest,
      observedAt: new Date().toISOString(), observedState }) });
    return observation;
  } finally { closeWorkspaceDescriptor(tree); }
}

async function mintRunWorkspace(tree: HeldGenerationTree, filesystem: HeldStateOwnerLock, artifacts: ArtifactCatalog,
  checkpoint: Checkpoint, frozen: Awaited<ReturnType<typeof readFrozenWorkspace>>, nonce: string, createdAt: string,
  retainedIdentity?: WorkspaceGenerationIdentityV1, lifetimeSignal?: AbortSignal,
  operations?: WorkspaceOperations): Promise<RunWorkspaceGeneration> {
  const { sourceState, source, entries, privateGit } = frozen;
  const generationId = identityHash(checkpoint.runId, checkpoint.id, checkpoint.workspaceStateRef, nonce);
  const observe = (signal?: AbortSignal) => observeTree(tree, artifacts, sourceState, privateGit,
    lifetimeSignal && signal ? AbortSignal.any([lifetimeSignal, signal]) : lifetimeSignal ?? signal);
  const initial = await observe();
  if (initial.entriesRef !== sourceState.entriesRef || initial.treeDigest !== entries.treeDigest ||
      initial.workspaceStateRef !== checkpoint.workspaceStateRef) mismatch('physical generation does not exactly reproduce the frozen ready Checkpoint');
  const publishAuthority = async (signal?: AbortSignal): Promise<MaterializedGenerationAuthority> => {
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
  };
  const generation: RunWorkspaceGeneration = Object.freeze({
    generationId,
    async observe(options) {
      if (this !== generation) throw new TypeError('invalid Run workspace generation');
      return trackWorkspaceOperation(operations, observe(options?.signal));
    },
    async publishMaterializedAuthority(options) {
      if (this !== generation) throw new TypeError('invalid Run workspace generation');
      return trackWorkspaceOperation(operations, publishAuthority(options?.signal));
    },
    close() { if (this !== generation) throw new TypeError('invalid Run workspace generation'); closeWorkspaceDescriptor(tree); }
  });
  generationTrees.set(generation, { tree, lifetimeSignal });
  return generation;
}

/** Reopening does not adopt a mutable tree or choose a Checkpoint. The trusted
 * factory supplies the sole retained preactivated row and its owning ready
 * cut; exact identity plus a fresh complete rewalk must agree before minting. */
export async function reopenRunWorkspace(input: { filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog;
  identity: WorkspaceGenerationIdentityV1; checkpoint: Checkpoint; signal?: AbortSignal; gitResources?: SandboxResourceSpec }): Promise<RunWorkspaceGeneration> {
  const { filesystem, artifacts, signal } = input;
  signal?.throwIfAborted();
  filesystem.assertHeld();
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'private generation reopen requires a qualified Linux directory');
  const identity = decodeWorkspaceGenerationIdentity(structuredClone(input.identity));
  const checkpoint = structuredClone(input.checkpoint);
  if (checkpoint.schemaVersion !== 1 || checkpoint.runId !== identity.runId || checkpoint.id !== identity.sourceCheckpointId ||
      checkpoint.workspaceStateRef !== identity.sourceWorkspaceStateRef) mismatch('reopened generation requires its exact owning ready Checkpoint');
  const frozen = await readFrozenWorkspace(artifacts, checkpoint.workspaceStateRef, signal, input.gitResources);
  signal?.throwIfAborted();
  if (frozen.sourceState.runId !== identity.runId || frozen.sourceState.stateDigest !== identity.sourceWorkspaceStateDigest ||
      frozen.entries.treeDigest !== identity.sourceTreeDigest || frozen.source.workspaceIdentityDigest !== identity.workspaceIdentityDigest) {
    mismatch('reopened generation source identity differs');
  }
  const tree = filesystem.openGenerationTree(identity);
  try { return await mintRunWorkspace(tree, filesystem, artifacts, checkpoint, frozen, identity.creationNonceDigest, identity.createdAt, identity, signal); }
  catch (error) { closeWorkspaceDescriptor(tree); throw error; }
}

async function populateGenerationTree(tree: HeldGenerationTree, artifacts: ArtifactCatalog,
  frozen: Awaited<ReturnType<typeof readFrozenWorkspace>>, signal: AbortSignal): Promise<void> {
  for (const entry of frozen.entries.entries) {
    signal.throwIfAborted();
    tree.assertHeld();
    if (entry.kind === 'directory') writeGenerationEntry(tree, { kind: 'directory', path: entry.path });
    else if (entry.kind === 'file') {
      const writer = openGenerationFileWriter(tree, entry.path, entry.mode as 420 | 493, entry.size);
      try {
        for await (const chunk of artifacts.readChunks(entry.blobRef, entry.size)) {
          signal.throwIfAborted();
          writer.assertHeld(); writer.writeChunk(chunk);
          await setImmediate();
          signal.throwIfAborted();
          writer.assertHeld();
        }
        signal.throwIfAborted();
        writer.finish();
      } finally { closeWorkspaceDescriptor(writer); }
    } else writeGenerationEntry(tree, { kind: 'symlink', path: entry.path, target: entry.target });
    await setImmediate();
    signal.throwIfAborted();
  }
  if (frozen.privateGit) {
    for (const path of frozen.privateGit.directories) {
      signal.throwIfAborted();
      writeGenerationEntry(tree, { kind: 'directory', path });
      await setImmediate();
      signal.throwIfAborted();
    }
    for (const [path, file] of frozen.privateGit.files) {
      signal.throwIfAborted();
      const writer = openGenerationFileWriter(tree, path, 0o600, file.byteCount);
      try {
        const chunks = file.kind === 'cas' ? artifacts.readChunks(file.ref, file.byteCount) : (async function* () {
          for (let offset = 0; offset < file.bytes.length; offset += 65_536) yield file.bytes.subarray(offset, offset + 65_536);
        })();
        for await (const chunk of chunks) {
          signal.throwIfAborted(); writer.assertHeld(); writer.writeChunk(chunk);
          await setImmediate();
          signal.throwIfAborted();
          writer.assertHeld();
        }
        writer.finish();
      } finally { closeWorkspaceDescriptor(writer); }
    }
  }
}

/** Internal physical owner. Construction is synchronous and resource-free so
 * the installed composition can register it before calling birth. Database
 * binding belongs to that composition, never an injected persistence callback. */
export function createRunWorkspaceMaterialization(input: {
  filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog; checkpoint: Checkpoint;
  generationCreationNonceDigest?: string; signal?: AbortSignal; gitResources?: SandboxResourceSpec;
}): RunWorkspaceMaterialization {
  const { filesystem, artifacts } = input;
  const checkpoint = structuredClone(input.checkpoint);
  filesystem.assertHeld();
  const root = stateRootIdentityForLock(filesystem);
  if (checkpoint.schemaVersion !== 1 || !/^[A-Za-z0-9_-]{1,128}$/.test(checkpoint.runId) || !checkpoint.id ||
      ![checkpoint.basedOnRunRevision, checkpoint.runItemSeq, checkpoint.journalSeq].every(n => Number.isSafeInteger(n) && n >= 0)) {
    mismatch('materialization requires a frozen owning ready Checkpoint');
  }
  parseCanonicalTime(checkpoint.createdAt); assertArtifactRef(checkpoint.workspaceStateRef);
  const nonce = input.generationCreationNonceDigest === undefined ? sha256Bytes(randomBytes(32)) : input.generationCreationNonceDigest;
  if (typeof nonce !== 'string') throw new TypeError('generation creation nonce must be a canonical digest');
  assertArtifactRef(nonce);
  const generationId = identityHash(checkpoint.runId, checkpoint.id, checkpoint.workspaceStateRef, nonce);
  const cancellation = new AbortController();
  const signal = input.signal ? AbortSignal.any([input.signal, cancellation.signal]) : cancellation.signal;
  const operations: WorkspaceOperations = { pending: new Set() };
  let tree: HeldGenerationTree | undefined, opening: Promise<RunWorkspaceBirth> | undefined;
  let frozen: Awaited<ReturnType<typeof readFrozenWorkspace>> | undefined, born: RunWorkspaceBirth | undefined;
  let finishing: Promise<RunWorkspaceGeneration> | undefined;
  let closed = false, joined = false, allocationRequested = false, closing: Promise<void> | undefined;
  const materialization: RunWorkspaceMaterialization = Object.freeze({
    birth() {
      if (this !== materialization) throw new TypeError('invalid workspace materialization owner');
      if (closed) return Promise.reject(new KernelStorageError('LEASE_FENCED', 'workspace materialization is closed'));
      return opening ??= Promise.resolve().then(async () => {
        signal.throwIfAborted();
        frozen = await readFrozenWorkspace(artifacts, checkpoint.workspaceStateRef, signal, input.gitResources);
        signal.throwIfAborted();
        if (frozen.sourceState.runId !== checkpoint.runId) mismatch('ready Checkpoint belongs to a different Run');
        // Never reset this latch, even if the native creator throws before it
        // can return birth facts. Such a cut cannot prove no allocation.
        allocationRequested = true;
        tree = filesystem.createGenerationTree(checkpoint.runId, generationId);
        tree.assertHeld();
        // Canonical registration sampled after actual create/fstat, not an
        // intent timestamp or a claim of native CLOCK_REALTIME evidence.
        const createdAt = new Date().toISOString();
        const birth = Object.freeze({}) as RunWorkspaceBirth;
        workspaceBirths.set(birth, { filesystem, tree, operations, joined: false, privateGit: frozen.privateGit,
          ...(input.gitResources ? { gitResources: Object.freeze({ ...input.gitResources }) } : {}), data: Object.freeze({ generationId, runId: checkpoint.runId,
          workspaceIdentityDigest: frozen.source.workspaceIdentityDigest, sourceCheckpointId: checkpoint.id,
          sourceWorkspaceStateRef: checkpoint.workspaceStateRef, sourceWorkspaceStateDigest: frozen.sourceState.stateDigest,
          sourceTreeDigest: frozen.entries.treeDigest, creationNonceDigest: nonce, createdAt,
          stateRootIdentity: Object.freeze({ ...root }), directoryIdentity: Object.freeze({ ...tree.identity }) }) });
        // No cancellation check after creation: the installed owner must be
        // able to bind this actual birth before respecting stop for copying.
        born = birth; return birth;
      });
    },
    finish(options) {
      if (this !== materialization) throw new TypeError('invalid workspace materialization owner');
      if (closed) return Promise.reject(new KernelStorageError('LEASE_FENCED', 'workspace materialization is closed'));
      if (!born || !tree || !frozen) return Promise.reject(new TypeError('materialization requires its actual completed birth'));
      const currentTree = tree, currentFrozen = frozen, birth = born;
      if (currentFrozen.privateGit?.requiresPreparation) {
        const input = workspaceBirths.get(birth)!.preparingGitInput;
        if (!input || !options?.gitPreparation) return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'nonempty private Git requires its original native preparation completion'));
        const completed = readPreparingGitCompletion(options.gitPreparation, input);
        const expected = readRunWorkspacePreparingGit(filesystem, birth)!;
        const held = workspaceBirths.get(birth)!;
        if (completed.privateGit.manifestRef !== expected.privateGitStateRef || completed.metadataRef !== expected.metadataRef ||
            completed.recipe.sourceCheckpointId !== held.data.sourceCheckpointId ||
            completed.recipe.sourceWorkspaceStateRef !== held.data.sourceWorkspaceStateRef || !held.gitResources ||
            Object.entries(held.gitResources).some(([key, value]) => completed.recipe[key as keyof SandboxResourceSpec] !== value))
          return Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'Git completion substitutes the original frozen generation'));
      } else if (options?.gitPreparation) return Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'unexpected Git completion on a generation without Git preparation'));
      return finishing ??= Promise.resolve().then(async () => {
        try {
          signal.throwIfAborted();
          await populateGenerationTree(currentTree, artifacts, currentFrozen, signal);
          return await mintRunWorkspace(currentTree, filesystem, artifacts, checkpoint, currentFrozen, nonce,
            readRunWorkspaceBirth(filesystem, birth).createdAt, undefined, signal, operations);
        } catch (error) { closeWorkspaceDescriptor(currentTree); throw error; }
      });
    },
    close() {
      if (this !== materialization) throw new TypeError('invalid workspace materialization owner');
      if (closing) return closing;
      closed = true; cancellation.abort(new KernelStorageError('LEASE_FENCED', 'workspace materialization is closed'));
      closing = (async () => {
        const results = await Promise.allSettled([...(opening ? [opening] : []), ...(finishing ? [finishing] : []), ...operations.pending]);
        const failed = results.find(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError);
        if (tree) closeWorkspaceDescriptor(tree);
        if (failed?.status === 'rejected') throw failed.reason;
        if (operations.retirementFailure) throw operations.retirementFailure;
        if (born) workspaceBirths.get(born)!.joined = true;
        joined = true;
      })();
      return closing;
    }
  });
  unallocatedMaterializations.set(materialization, { filesystem, read() {
    if (!closed || !joined || allocationRequested || born || tree || operations.pending.size || operations.retirementFailure)
      throw operations.retirementFailure ?? new KernelStorageError('RECOVERY_REQUIRED', 'workspace allocation absence is not positively joined');
    return Object.freeze({ runId: checkpoint.runId, generationId, sourceCheckpointId: checkpoint.id,
      sourceWorkspaceStateRef: checkpoint.workspaceStateRef, creationNonceDigest: nonce,
      allocationRequested: false, operationsJoined: true, observedAt: new Date().toISOString() });
  } });
  return materialization;
}

/** Trusted factory supplies one frozen ready Checkpoint. Materialization reads
 * only that immutable CAS closure, never recaptures or links the live source.
 * A failed attempt leaves its exact orphan in place for typed quarantine/GC;
 * it never recursively deletes a potentially replaced path. */
export async function materializeRunWorkspace(input: {
  filesystem: HeldStateOwnerLock; artifacts: ArtifactCatalog; checkpoint: Checkpoint; signal?: AbortSignal;
}): Promise<RunWorkspaceGeneration> {
  const materialization = createRunWorkspaceMaterialization(input);
  try {
    await materialization.birth();
    return await materialization.finish();
  } catch (error) { await materialization.close(); throw error; }
}
