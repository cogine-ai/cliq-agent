import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, RepositoryIdentityV1, WorkspaceEntryManifest } from '../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { decodeFrozenIgnoreRules, decodeRepositoryIdentity, decodeWorkspaceEntries } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { MAX_FROZEN_IGNORE_SOURCE_BYTES, parseFrozenIgnoreSourceBytes } from './frozen-ignore-sources.js';
import { parseSanitizedGitConfig } from './git-config.js';
import type {
  DescriptorIdentity, HeldStateOwnerLock, LiveWorkspaceInspection, WorkspaceSourceDirectoryEntry
} from './native-owner.js';

const READ_CHUNK_BYTES = 1024 * 1024;
const FROZEN_IGNORE_SOURCE_MEDIA_TYPE = 'text/plain; charset=utf-8';
const FROZEN_IGNORE_SOURCE_SCHEMA_KIND = 'cliq-frozen-ignore-source-v1';

function sameIdentity(left: DescriptorIdentity, right: DescriptorIdentity): boolean {
  return left.deviceId === right.deviceId && left.fileId === right.fileId && left.ownerUid === right.ownerUid;
}

function assertMatchingWorkspace(
  observed: LiveWorkspaceInspection,
  root: DescriptorIdentity,
  git: DescriptorIdentity
): void {
  if (!sameIdentity(observed.root, root) || !observed.git ||
      !sameIdentity(observed.git.identity, git)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'workspace or Git directory changed during ignore-source capture');
  }
}

function assertMatchingConfig(before: LiveWorkspaceInspection, after: LiveWorkspaceInspection): void {
  const first = before.git?.configBytes;
  const second = after.git?.configBytes;
  if ((first === undefined) !== (second === undefined) ||
      (first !== undefined && !first.equals(second!))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'Git config changed during ignore-source capture');
  }
}

/** Capture the optional fixed Git exclude file from the held source root.
 * This binds the bytes (or exact absence) to the Session repository and a
 * stable sanitized Git config observation. The caller must revalidate the
 * source graph at the admission commit boundary. */
export function readHeldSourceGitInfoExclude(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  expectedRoot: DescriptorIdentity,
  expectedRepository: RepositoryIdentityV1
): Buffer | null {
  const repository = decodeRepositoryIdentity(expectedRepository);
  const before = filesystem.inspectWorkspaceIdentity(workspacePath);
  assertMatchingWorkspace(before, expectedRoot, repository.gitDirectoryIdentity);
  if (before.git?.configBytes === undefined) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'Git config is absent during ignore-source capture');
  }
  const config = parseSanitizedGitConfig(before.git.configBytes);
  if ((config.extensions?.objectFormat ?? 'sha1') !== repository.objectFormat) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'Git config object format differs from the Session repository');
  }

  const bytes = filesystem.readWorkspaceGitInfoExclude(workspacePath, expectedRoot,
    repository.gitDirectoryIdentity);
  const after = filesystem.inspectWorkspaceIdentity(workspacePath);
  assertMatchingWorkspace(after, expectedRoot, repository.gitDirectoryIdentity);
  assertMatchingConfig(before, after);
  const repeated = filesystem.readWorkspaceGitInfoExclude(workspacePath, expectedRoot,
    repository.gitDirectoryIdentity);
  if ((bytes === null) !== (repeated === null) ||
      (bytes !== null && !bytes.equals(repeated!))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'Git info exclude changed during ignore-source capture');
  }
  const final = filesystem.inspectWorkspaceIdentity(workspacePath);
  assertMatchingWorkspace(final, expectedRoot, repository.gitDirectoryIdentity);
  assertMatchingConfig(before, final);
  return bytes;
}

function literalGitignoreEntry(entries: readonly WorkspaceSourceDirectoryEntry[]):
  WorkspaceSourceDirectoryEntry | undefined {
  const matches = entries.filter((entry) => entry.name === '.gitignore');
  if (matches.length > 1) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'workspace directory listed a duplicate literal .gitignore source');
  }
  return matches[0];
}

/** Read one literal .gitignore under a directory already selected for source
 * capture. Both presence and absence are checked through held no-follow
 * directory observations; the caller proves that the selected directory set
 * is complete and revalidates it at admission. */
export function readHeldGitignoreFromDirectory(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  expectedRoot: DescriptorIdentity,
  directoryPath: string
): Buffer | null {
  const first = literalGitignoreEntry(
    filesystem.listWorkspaceSourceDirectory(workspacePath, expectedRoot, directoryPath)
  );
  if (first === undefined) {
    const second = literalGitignoreEntry(
      filesystem.listWorkspaceSourceDirectory(workspacePath, expectedRoot, directoryPath)
    );
    if (second !== undefined) {
      throw new KernelStorageError('ARTIFACT_MISMATCH',
        'literal .gitignore appeared during source capture');
    }
    return null;
  }
  if (first.kind !== 'file' || first.size === undefined ||
      first.size > MAX_FROZEN_IGNORE_SOURCE_BYTES) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'literal .gitignore is not a bounded regular source file');
  }
  const relativePath = directoryPath === '' ? '.gitignore' : `${directoryPath}/.gitignore`;
  const file = filesystem.openWorkspaceSourceFile(workspacePath, expectedRoot, relativePath);
  try {
    if (!sameIdentity(first.identity, file.identity) ||
        first.size !== file.size || first.mode !== file.mode ||
        first.linkCount !== file.linkCount) {
      throw new KernelStorageError('ARTIFACT_MISMATCH',
        'literal .gitignore changed between directory scan and source opening');
    }
    const bytes = Buffer.alloc(file.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const requested = Math.min(READ_CHUNK_BYTES, bytes.byteLength - offset);
      const chunk = file.readChunk(requested);
      if (!Buffer.isBuffer(chunk) || chunk.byteLength === 0 || chunk.byteLength > requested) {
        throw new KernelStorageError('ARTIFACT_MISMATCH',
          'literal .gitignore ended before its observed byte count');
      }
      chunk.copy(bytes, offset);
      offset += chunk.byteLength;
    }
    file.assertStable();
    const second = literalGitignoreEntry(
      filesystem.listWorkspaceSourceDirectory(workspacePath, expectedRoot, directoryPath)
    );
    if (second?.kind !== 'file' || second.size !== first.size || second.mode !== first.mode ||
        second.linkCount !== first.linkCount ||
        !sameIdentity(second.identity, first.identity)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH',
        'literal .gitignore changed during directory recheck');
    }
    file.assertStable();
    return bytes;
  } finally {
    file.close();
  }
}

function assertSourceMatches(
  actual: Buffer | null,
  source: FrozenIgnoreRulesV1['sources'][number] | undefined,
  path: string
): void {
  if (actual === null && source === undefined) return;
  if (actual === null || source === undefined || sha256Bytes(actual) !== source.contentRef) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      `live frozen ignore source differs from its retained bytes: ${path}`);
  }
}

function selectedDirectories(entries: WorkspaceEntryManifest): string[] {
  const directories = new Set<string>(['']);
  for (const entry of entries.entries) {
    const components = entry.path.split('/');
    for (let depth = 1; depth < components.length; depth += 1) {
      directories.add(components.slice(0, depth).join('/'));
    }
    if (entry.kind === 'directory') directories.add(entry.path);
  }
  return [...directories].sort((left, right) => {
    const depth = left.split('/').length - right.split('/').length;
    return depth || Buffer.compare(Buffer.from(left), Buffer.from(right));
  });
}

export type CapturedFrozenIgnoreRules = Readonly<{
  rules: FrozenIgnoreRulesV1;
  rulesArtifact: PublishedArtifact;
  sourceArtifacts: readonly PublishedArtifact[];
}>;

/** Construct the exact retained rule graph from held source files. The entry
 * manifest must already come from the trusted descriptor walk; this producer
 * verifies its shape, source order, and all source bytes before returning.
 * Admission still repeats the live-source check at its commit boundary. */
export async function captureHeldFrozenIgnoreRules(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  expectedRoot: DescriptorIdentity,
  expectedRepository: RepositoryIdentityV1 | undefined,
  selectedEntries: WorkspaceEntryManifest,
  artifacts: ArtifactCatalog
): Promise<CapturedFrozenIgnoreRules> {
  const entries = decodeWorkspaceEntries(selectedEntries);
  const repository = expectedRepository === undefined ? undefined : decodeRepositoryIdentity(expectedRepository);
  const observed = filesystem.inspectWorkspaceIdentity(workspacePath);
  if (!sameIdentity(observed.root, expectedRoot) ||
      (repository === undefined ? observed.git !== undefined :
        observed.git === undefined || !sameIdentity(observed.git.identity,
          repository.gitDirectoryIdentity))) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'workspace identity changed before frozen ignore capture');
  }
  const sources: FrozenIgnoreRulesV1['sources'] = [];
  const rules: FrozenIgnoreRulesV1['rules'] = [];
  const sourceArtifacts: PublishedArtifact[] = [];
  const add = async (kind: 'git_info_exclude' | 'gitignore', relativePath: string,
    baseDirectory: string, bytes: Buffer): Promise<void> => {
    const contentRef = sha256Bytes(bytes);
    const source: FrozenIgnoreRulesV1['sources'][number] = {
      index: sources.length, kind, canonicalRootRelativePath: relativePath,
      baseDirectory, contentRef, contentDigest: contentRef
    };
    const parsed = parseFrozenIgnoreSourceBytes(bytes, source, rules.length);
    const published = await artifacts.publishBytes(bytes, FROZEN_IGNORE_SOURCE_MEDIA_TYPE,
      FROZEN_IGNORE_SOURCE_SCHEMA_KIND);
    if (published.ref !== contentRef) {
      throw new KernelStorageError('ARTIFACT_MISMATCH',
        `published frozen ignore source has a different digest: ${relativePath}`);
    }
    sources.push(source);
    rules.push(...parsed);
    sourceArtifacts.push(published);
  };

  if (repository !== undefined) {
    const exclude = readHeldSourceGitInfoExclude(filesystem, workspacePath,
      expectedRoot, repository);
    if (exclude !== null) await add('git_info_exclude', '.git/info/exclude', '', exclude);
    for (const directory of selectedDirectories(entries)) {
      const bytes = readHeldGitignoreFromDirectory(filesystem, workspacePath,
        expectedRoot, directory);
      if (bytes === null) continue;
      const relativePath = directory === '' ? '.gitignore' : `${directory}/.gitignore`;
      await add('gitignore', relativePath, directory, bytes);
    }
  }
  const candidate: FrozenIgnoreRulesV1 = {
    schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1',
    ...(repository === undefined ? {} : {
      repositoryIdentityDigest: repository.repositoryIdentityDigest
    }),
    sources, rules, rulesDigest: ''
  };
  candidate.rulesDigest = digestOmitting(candidate, 'rulesDigest');
  const frozen = decodeFrozenIgnoreRules(candidate);
  const rulesArtifact = await artifacts.publishCanonical(frozen, frozen.format);
  assertLiveFrozenIgnoreSources(filesystem, workspacePath, expectedRoot,
    repository, frozen, entries);
  return { rules: frozen, rulesArtifact, sourceArtifacts };
}

/** Revalidate the exact ignore files applying to admitted workspace entries.
 * A Run submission calls this before artifact publication and again under the
 * StateOwner transaction just before its durable admission commit. */
export function assertLiveFrozenIgnoreSources(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  expectedRoot: DescriptorIdentity,
  expectedRepository: RepositoryIdentityV1 | undefined,
  frozenRules: FrozenIgnoreRulesV1,
  entries: WorkspaceEntryManifest
): void {
  const rules = decodeFrozenIgnoreRules(frozenRules);
  if (expectedRepository === undefined) {
    if (rules.repositoryIdentityDigest !== undefined) {
      throw new KernelStorageError('ARTIFACT_MISMATCH',
        'non-Git workspace cannot retain Git ignore sources');
    }
    return;
  }
  const repository = decodeRepositoryIdentity(expectedRepository);
  if (rules.repositoryIdentityDigest !== repository.repositoryIdentityDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'frozen ignore sources name another repository');
  }
  const observedExclude = readHeldSourceGitInfoExclude(filesystem, workspacePath,
    expectedRoot, repository);
  const declaredExclude = rules.sources[0]?.kind === 'git_info_exclude' ? rules.sources[0] : undefined;
  assertSourceMatches(observedExclude, declaredExclude, '.git/info/exclude');

  const gitignoreSources = new Map(
    rules.sources.filter((source) => source.kind === 'gitignore')
      .map((source) => [source.canonicalRootRelativePath, source] as const)
  );
  for (const directory of selectedDirectories(entries)) {
    const path = directory === '' ? '.gitignore' : `${directory}/.gitignore`;
    const actual = readHeldGitignoreFromDirectory(filesystem, workspacePath,
      expectedRoot, directory);
    assertSourceMatches(actual, gitignoreSources.get(path), path);
    gitignoreSources.delete(path);
  }
  if (gitignoreSources.size !== 0) {
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      'frozen ignore rules contain a source outside admitted workspace directories');
  }
}
