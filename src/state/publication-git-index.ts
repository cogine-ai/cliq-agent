import { createHash } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { decodePublicationProof, type PublicationProofV1 } from '../kernel/publication.js';
import type { WorkspaceIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { normalizeGitIndex } from '../workspace/git-index.js';
import { readGitIndexData, type PrivateGitReader } from '../workspace/private-git-data.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceManifest } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, openHeldPublicationGitIndex, stateRootIdentityForLock,
  type HeldStateOwnerLock, type HeldWorkspaceRoot } from './native-owner.js';
import { decodeRepositoryIdentity } from './repository-identity.js';
import { checkSourceManifest } from './source-validation.js';

type IndexProof = Extract<PublicationProofV1, { kind: 'git_index_unchanged' }>;
type IndexFields<T = IndexProof> = T extends IndexProof ? Pick<T, Exclude<keyof T,
  'schemaVersion' | 'format' | 'deliveryRunId' | 'deliveryPlanRef' | 'workspaceIdentityRef' | 'workspaceIdentityDigest' |
  'inspectorIdentityRef' | 'inspectorIdentityDigest' | 'proofDigest' | 'observedAt'>> : never;
declare const indexObservationBrand: unique symbol;
export type PublicationGitIndexObservation = Readonly<{ readonly [indexObservationBrand]: true }>;
const observations = new WeakMap<PublicationGitIndexObservation,
  { owner: HeldStateOwnerLock; root: HeldWorkspaceRoot; fields: IndexFields }>();
function invalid(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'publication Git index differs from its original complete capture'); }
function emptyIndex(format: 'sha1' | 'sha256'): Buffer {
  const body = Buffer.from('444952430000000200000000', 'hex'); return Buffer.concat([body, createHash(format).update(body).digest()]);
}

/** Actual bounded fixed-path read only, after the owning publication task has
 * checked its original approval/claim. This supplies no read grant, source
 * inspection, workspace write or finalization authority. */
export async function observePublicationGitIndex(owner: HeldStateOwnerLock, root: HeldWorkspaceRoot, artifacts: ArtifactCatalog,
  input: { workspace: Extract<WorkspaceIdentityV1, { kind: 'live' }>; capturedSourceRef: string; resources: SandboxResourceSpec },
  signal?: AbortSignal): Promise<PublicationGitIndexObservation> {
  assertHeldWorkspaceRoot(root); stateRootIdentityForLock(owner); signal?.throwIfAborted();
  if (canonicalSha256(root.identity) !== canonicalSha256(input.workspace.rootIdentity) || heldWorkspaceRootPath(root) !== input.workspace.canonicalRootPath) return invalid();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const source = decodeSourceManifest(await readCanonicalArtifact(reads, input.capturedSourceRef)); checkSourceManifest(source);
  if (input.workspace.kind !== 'live' || source.role !== 'base' || source.workspaceIdentityDigest !== input.workspace.identityDigest) return invalid();
  let fields: IndexFields;
  if (!source.git) {
    if (root.repositoryDirectory || input.workspace.repositoryIdentityRef || input.workspace.repositoryIdentityDigest) return invalid();
    fields = { kind: 'git_index_unchanged', repositoryKind: 'non_git' };
  } else {
    const repositoryRef = input.workspace.repositoryIdentityRef;
    if (!repositoryRef || source.git.repositoryIdentityDigest !== input.workspace.repositoryIdentityDigest) return invalid();
    const repository = decodeRepositoryIdentity(await readCanonicalArtifact(reads, repositoryRef));
    if (repository.schemaVersion !== 2 || repository.platform !== input.workspace.platform || repository.repositoryIdentityDigest !== source.git.repositoryIdentityDigest || !root.repositoryDirectory ||
        canonicalSha256(root.repositoryDirectory) !== canonicalSha256(repository.gitDirectoryIdentity)) return invalid();
    const original = await readGitIndexData(reads, source.git.indexRef,
      { repositoryIdentityDigest: repository.repositoryIdentityDigest, resources: input.resources }, signal);
    if (original.indexTreeObjectId !== source.git.indexTreeObjectId) return invalid();
    const expectedBytes = await reads.readBoundedBytes(original.canonicalIndexBytesRef, original.canonicalIndexByteCount);
    signal?.throwIfAborted();
    const held = openHeldPublicationGitIndex(owner, root,
      { repositoryDirectory: repository.gitDirectoryIdentity, maxBytes: input.resources.maxSingleFileBytes });
    const chunks: Buffer[] = []; let count = 0, primary: unknown;
    const digest = createHash('sha256');
    try {
      for (;;) {
        signal?.throwIfAborted(); held.assertHeld(); const bytes = held.readChunk(); if (bytes === null) break;
        count += bytes.byteLength;
        if (!Number.isSafeInteger(count) || count > input.resources.maxSingleFileBytes || count > held.byteCount) return invalid();
        digest.update(bytes); chunks.push(bytes); await setImmediate();
      }
      held.assertComplete();
      if (count !== held.byteCount || held.present && !held.identity || !held.present && (held.identity !== undefined || count !== 0)) return invalid();
    } catch (error) { primary = error; throw error; }
    finally {
      try { held.close(); }
      catch (error) { throw error instanceof ResourceRetirementError ? error : new ResourceRetirementError('publication Git index reader did not join',
        primary === undefined ? error : new AggregateError([primary, error])); }
    }
    signal?.throwIfAborted(); owner.assertHeld(); root.assertHeld();
    const normalized = normalizeGitIndex(held.present ? Buffer.concat(chunks, count) : emptyIndex(original.objectFormat), original.objectFormat,
      { maxBytes: input.resources.maxSingleFileBytes, maxEntries: 100_000 });
    if (!normalized.canonicalBytes.equals(expectedBytes) || normalized.indexTreeObjectId !== original.indexTreeObjectId ||
        canonicalSha256(normalized.entries) !== canonicalSha256(original.entries)) return invalid();
    fields = { kind: 'git_index_unchanged', repositoryKind: 'git', repositoryIdentityRef: repositoryRef,
      repositoryIdentityDigest: repository.repositoryIdentityDigest, capturedSourceRef: input.capturedSourceRef,
      capturedIndexRef: source.git.indexRef, capturedIndexDigest: original.snapshotDigest,
      observedIndexRef: source.git.indexRef, observedIndexDigest: original.snapshotDigest, objectFormat: original.objectFormat,
      canonicalIndexBytesRef: original.canonicalIndexBytesRef, canonicalIndexByteCount: original.canonicalIndexByteCount,
      indexTreeObjectId: original.indexTreeObjectId,
      observedIndex: held.present ? { kind: 'present', ...held.identity!, rawByteCount: count, rawBytesDigest: digest.digest('hex') }
        : { kind: 'absent', rawByteCount: 0 }, descriptorReadComplete: true, readerJoined: true };
  }
  signal?.throwIfAborted(); owner.assertHeld(); root.assertHeld();
  const observation = Object.freeze({}) as PublicationGitIndexObservation;
  observations.set(observation, { owner, root, fields: immutableSnapshot(fields) }); return observation;
}
export function readPublicationGitIndexObservation(value: PublicationGitIndexObservation): IndexFields {
  const held = observations.get(value);
  if (!held) throw new TypeError('publication index requires its genuine completely joined observation');
  held.owner.assertHeld(); held.root.assertHeld(); return held.fields;
}

/** Historical data only. The original task/inspector/Plan and physical proof
 * association are checked by the owning terminal projection reader. */
export async function readPublicationGitIndexClosure(artifacts: PrivateGitReader & Pick<ArtifactCatalog, 'readCanonical'>, proof: IndexProof,
  input: { workspace: Extract<WorkspaceIdentityV1, { kind: 'live' }>; capturedSourceRef: string; resources: SandboxResourceSpec }) {
  const decoded = decodePublicationProof(proof);
  if (decoded.kind !== 'git_index_unchanged') return invalid();
  proof = decoded;
  const source = decodeSourceManifest(await readCanonicalArtifact(artifacts, input.capturedSourceRef)); checkSourceManifest(source);
  if (input.workspace.kind !== 'live' || source.role !== 'base' || source.workspaceIdentityDigest !== input.workspace.identityDigest ||
      proof.workspaceIdentityRef !== canonicalSha256(input.workspace) || proof.workspaceIdentityDigest !== input.workspace.identityDigest) return invalid();
  if (!source.git) { if (proof.repositoryKind !== 'non_git' || input.workspace.repositoryIdentityRef || input.workspace.repositoryIdentityDigest) return invalid(); return; }
  if (proof.repositoryKind !== 'git' || !input.workspace.repositoryIdentityRef || proof.capturedSourceRef !== input.capturedSourceRef ||
      proof.repositoryIdentityRef !== input.workspace.repositoryIdentityRef || proof.repositoryIdentityDigest !== source.git.repositoryIdentityDigest ||
      proof.repositoryIdentityDigest !== input.workspace.repositoryIdentityDigest || proof.capturedIndexRef !== source.git.indexRef) return invalid();
  const repository = decodeRepositoryIdentity(await readCanonicalArtifact(artifacts, proof.repositoryIdentityRef));
  const original = await readGitIndexData(artifacts, proof.capturedIndexRef,
    { repositoryIdentityDigest: proof.repositoryIdentityDigest, resources: input.resources });
  if (repository.schemaVersion !== 2 || repository.platform !== input.workspace.platform || repository.repositoryIdentityDigest !== proof.repositoryIdentityDigest ||
      proof.capturedIndexDigest !== original.snapshotDigest ||
      proof.objectFormat !== original.objectFormat || proof.canonicalIndexBytesRef !== original.canonicalIndexBytesRef ||
      proof.canonicalIndexByteCount !== original.canonicalIndexByteCount || proof.indexTreeObjectId !== original.indexTreeObjectId ||
      source.git.indexTreeObjectId !== original.indexTreeObjectId) return invalid();
  if (proof.observedIndex.kind === 'present') {
    if (proof.observedIndex.deviceId !== repository.gitDirectoryIdentity.deviceId || proof.observedIndex.ownerUid !== repository.gitDirectoryIdentity.ownerUid ||
        proof.observedIndex.fileId === repository.gitDirectoryIdentity.fileId || proof.observedIndex.rawByteCount > input.resources.maxSingleFileBytes) return invalid();
  } else {
    const bytes = await artifacts.readBoundedBytes(original.canonicalIndexBytesRef, original.canonicalIndexByteCount);
    if (original.entries.length || !bytes.equals(emptyIndex(original.objectFormat))) return invalid();
  }
}
