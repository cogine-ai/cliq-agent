import { createHash } from 'node:crypto';

import { canonicalSha256 } from '../kernel/canonical.js';
import { sha256Bytes } from '../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1, GitIndexSnapshotV1, SourceIncludeClassificationEvidenceV1,
  SourceProjectionSpec,
  WorkspaceEntry, WorkspaceEntryManifest
} from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import {
  decodeSourceIncludeAuthorization, decodeSourceIncludeClassificationEvidence,
  decodeWorkspaceEntries
} from './decoders.js';
import { KernelStorageError } from './errors.js';
import { compileFrozenIgnoreMatcher } from './frozen-ignore-matcher.js';
import type {
  DescriptorIdentity, HeldStateOwnerLock, WorkspaceSourceDirectoryEntry
} from './native-owner.js';

type ValidateSourceIncludesInput = Readonly<{
  principalId: string;
  runId: string;
  sessionId: string;
  workspaceIdentityRef: string;
  workspaceIdentityDigest: string;
  admissionIntentDigest: string;
  projection: SourceProjectionSpec;
  entries: WorkspaceEntryManifest;
  frozenIgnoreRulesRef: string;
  frozenIgnoreRules: FrozenIgnoreRulesV1;
  git?: Readonly<{ indexRef: string; snapshot: GitIndexSnapshotV1 }>;
}>;

function mismatch(message: string): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', message);
}

function matchesSelector(path: string, selector: SourceProjectionSpec['explicitIncludes'][number]): boolean {
  return path === selector.path ||
    (selector.scope === 'subtree' && path.startsWith(`${selector.path}/`));
}

/** Validate the retained builtin include graph against the exact admitted
 * entry tree, frozen ignore rules, and canonical Git index. Descriptor
 * observations are checked by the trusted source-capture producer and must
 * be rechecked at the admission commit; this retained-artifact check never
 * treats an evidence JSON object as a substitute for a live descriptor. */
export async function validateBuiltinSourceIncludes(
  artifacts: ArtifactCatalog,
  input: ValidateSourceIncludesInput
): Promise<{ metadata: PublishedArtifact[]; evidences: SourceIncludeClassificationEvidenceV1[] }> {
  const entries = decodeWorkspaceEntries(input.entries);
  const matcher = compileFrozenIgnoreMatcher(input.frozenIgnoreRules);
  const indexPaths = new Set(input.git?.snapshot.entries.map((entry) => entry.canonicalRootRelativePath) ?? []);
  const metadata: PublishedArtifact[] = [];
  const evidences: SourceIncludeClassificationEvidenceV1[] = [];
  for (const selector of input.projection.explicitIncludes) {
    const authorization = decodeSourceIncludeAuthorization(
      await artifacts.readCanonical(selector.authorizationRef)
    );
    if (authorization.kind !== 'builtin_nonignored') {
      throw new KernelStorageError('INVALID_REQUEST',
        'consumed source read grants are not yet supported by Run admission');
    }
    if (authorization.principalId !== input.principalId ||
        authorization.runId !== input.runId ||
        authorization.sessionId !== input.sessionId ||
        authorization.workspaceIdentityRef !== input.workspaceIdentityRef ||
        authorization.workspaceIdentityDigest !== input.workspaceIdentityDigest ||
        authorization.admissionIntentDigest !== input.admissionIntentDigest ||
        authorization.selector.path !== selector.path ||
        authorization.selector.scope !== selector.scope ||
        authorization.frozenIgnoreRulesRef !== input.frozenIgnoreRulesRef ||
        authorization.frozenIgnoreRulesDigest !== input.frozenIgnoreRules.rulesDigest) {
      mismatch('source include authorization is not bound to the admitted Run and projection');
    }
    const evidence = decodeSourceIncludeClassificationEvidence(
      await artifacts.readCanonical(authorization.classificationEvidenceRef)
    );
    if (evidence.evidenceDigest !== authorization.classificationEvidenceDigest ||
        evidence.principalId !== authorization.principalId ||
        evidence.runId !== authorization.runId ||
        evidence.sessionId !== authorization.sessionId ||
        evidence.workspaceIdentityRef !== authorization.workspaceIdentityRef ||
        evidence.workspaceIdentityDigest !== authorization.workspaceIdentityDigest ||
        evidence.selector.path !== selector.path || evidence.selector.scope !== selector.scope ||
        evidence.admissionIntentDigest !== authorization.admissionIntentDigest ||
        evidence.frozenIgnoreRulesRef !== input.frozenIgnoreRulesRef ||
        evidence.frozenIgnoreRulesDigest !== input.frozenIgnoreRules.rulesDigest) {
      mismatch('source include classification evidence does not match its authorization');
    }
    if ((evidence.gitIndexRef === undefined) !== (evidence.gitIndexTreeObjectId === undefined) ||
        (evidence.gitIndexRef !== undefined &&
          (evidence.gitIndexRef !== input.git?.indexRef ||
           evidence.gitIndexTreeObjectId !== input.git.snapshot.indexTreeObjectId))) {
      mismatch('source include evidence does not match the admitted Git index');
    }
    const selectedEntries = entries.entries.filter((entry) => matchesSelector(entry.path, selector));
    if (selectedEntries.length !== evidence.entries.length) {
      mismatch('source include evidence does not cover the selected entry set');
    }
    for (const [index, observed] of evidence.entries.entries()) {
      const entry = selectedEntries[index] as WorkspaceEntry | undefined;
      if (entry === undefined || observed.path !== entry.path ||
          observed.workspaceEntryDigest !== canonicalSha256(entry)) {
        mismatch('source include evidence differs from the captured WorkspaceEntry');
      }
      if (observed.classification === 'tracked_in_git_index') {
        if (entry.kind === 'directory' || !indexPaths.has(entry.path) ||
            evidence.gitIndexRef === undefined) {
          mismatch('source include evidence claims a path absent from the canonical Git index');
        }
      } else if (matcher(entry.path, entry.kind === 'directory')) {
        mismatch('source include evidence classifies an ignored path as nonignored');
      }
    }
    metadata.push(
      await artifacts.describe(selector.authorizationRef, 'application/json',
        'cliq-source-include-authorization-v1'),
      await artifacts.describe(authorization.classificationEvidenceRef, 'application/json',
        'cliq-source-include-classification-v1')
    );
    evidences.push(evidence);
  }
  return { metadata, evidences };
}

function sameIdentity(left: DescriptorIdentity, right: DescriptorIdentity): boolean {
  return left.deviceId === right.deviceId && left.fileId === right.fileId && left.ownerUid === right.ownerUid;
}

function listedEntry(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  root: DescriptorIdentity,
  path: string
): WorkspaceSourceDirectoryEntry {
  const lastSlash = path.lastIndexOf('/');
  const parent = lastSlash < 0 ? '' : path.slice(0, lastSlash);
  const name = lastSlash < 0 ? path : path.slice(lastSlash + 1);
  const matches = filesystem.listWorkspaceSourceDirectory(workspacePath, root, parent)
    .filter((entry) => entry.name === name);
  if (matches.length !== 1) mismatch(`source include ${path} is missing or ambiguous in its held directory`);
  return matches[0]!;
}

function assertObservedEntry(
  observed: WorkspaceSourceDirectoryEntry,
  expected: WorkspaceEntry,
  claim: SourceIncludeClassificationEvidenceV1['entries'][number],
  root: DescriptorIdentity
): void {
  if (observed.kind !== expected.kind || observed.identity.deviceId !== claim.deviceId ||
      observed.identity.fileId !== claim.fileId || observed.identity.ownerUid !== root.ownerUid ||
      observed.linkCount !== claim.linkCount ||
      (expected.kind === 'file' && observed.size !== expected.size)) {
    mismatch(`live source include ${expected.path} differs from its descriptor evidence`);
  }
  if (expected.kind === 'file' &&
      (observed.mode & 0o111 ? 0o755 : 0o644) !== expected.mode) {
    mismatch(`live source include ${expected.path} has a changed executable mode`);
  }
}

/** Reopen every included path under held no-follow descriptors, verify exact
 * bytes/target and identity, then recheck its literal parent listing. Called
 * again under the admission transaction after all asynchronous publication. */
export function assertLiveSourceIncludeEvidence(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  root: DescriptorIdentity,
  entries: WorkspaceEntryManifest,
  evidences: readonly SourceIncludeClassificationEvidenceV1[]
): void {
  const byPath = new Map(entries.entries.map((entry) => [entry.path, entry]));
  const uniqueClaims = new Map<string, SourceIncludeClassificationEvidenceV1['entries'][number]>();
  for (const evidence of evidences) {
    for (const claim of evidence.entries) {
      const previous = uniqueClaims.get(claim.path);
      if (previous !== undefined &&
          (previous.workspaceEntryDigest !== claim.workspaceEntryDigest ||
           previous.deviceId !== claim.deviceId || previous.fileId !== claim.fileId ||
           previous.linkCount !== claim.linkCount)) {
        mismatch(`overlapping source includes disagree on the descriptor for ${claim.path}`);
      }
      uniqueClaims.set(claim.path, claim);
    }
  }
  try {
    for (const claim of uniqueClaims.values()) {
      const expected = byPath.get(claim.path);
      if (expected === undefined) mismatch(`source include ${claim.path} has no captured WorkspaceEntry`);
      const first = listedEntry(filesystem, workspacePath, root, claim.path);
      assertObservedEntry(first, expected, claim, root);
      if (expected.kind === 'file') {
        const held = filesystem.openWorkspaceSourceFile(workspacePath, root, claim.path);
        try {
          if (!sameIdentity(first.identity, held.identity) ||
              first.linkCount !== held.linkCount || first.mode !== held.mode ||
              first.size !== held.size) {
            mismatch(`source include ${claim.path} changed between listing and file opening`);
          }
          const hash = createHash('sha256');
          let remaining = held.size;
          while (remaining > 0) {
            const request = Math.min(remaining, 1024 * 1024);
            const chunk = held.readChunk(request);
            if (!Buffer.isBuffer(chunk) || chunk.byteLength === 0 || chunk.byteLength > request) {
              mismatch(`source include ${claim.path} ended before its captured byte count`);
            }
            hash.update(chunk);
            remaining -= chunk.byteLength;
          }
          held.assertStable();
          if (hash.digest('hex') !== expected.blobRef) {
            mismatch(`source include ${claim.path} live bytes differ from the admitted CAS blob`);
          }
          const second = listedEntry(filesystem, workspacePath, root, claim.path);
          assertObservedEntry(second, expected, claim, root);
          if (!sameIdentity(first.identity, second.identity) ||
              first.mode !== second.mode || first.size !== second.size) {
            mismatch(`source include ${claim.path} changed during the held recheck`);
          }
          held.assertStable();
        } finally {
          held.close();
        }
      } else {
        if (expected.kind === 'symlink') {
          const held = filesystem.readWorkspaceSourceSymlink(workspacePath, root, claim.path);
          if (!sameIdentity(first.identity, held.identity) ||
              first.linkCount !== held.linkCount || first.mode !== held.mode ||
              held.target !== expected.target ||
              sha256Bytes(Buffer.from(held.target, 'utf8')) !== expected.targetDigest) {
            mismatch(`source include ${claim.path} link target differs from the admitted entry`);
          }
        } else {
          filesystem.listWorkspaceSourceDirectory(workspacePath, root, claim.path);
        }
        const second = listedEntry(filesystem, workspacePath, root, claim.path);
        assertObservedEntry(second, expected, claim, root);
        if (!sameIdentity(first.identity, second.identity) || first.mode !== second.mode) {
          mismatch(`source include ${claim.path} changed during the held recheck`);
        }
      }
    }
  } catch (error) {
    if (error instanceof KernelStorageError) throw error;
    try { filesystem.assertHeld(); }
    catch {
      throw new KernelStorageError('RECOVERY_REQUIRED',
        'StateOwner lock changed during live source include validation', { cause: error });
    }
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `held source include changed: ${(error as Error).message}`, { cause: error });
  }
}
