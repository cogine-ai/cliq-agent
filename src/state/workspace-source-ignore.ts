import { sha256Bytes } from '../kernel/identity.js';
import type { FrozenIgnoreRulesV1, RepositoryIdentityV1, WorkspaceEntryManifest } from '../kernel/types.js';
import { decodeFrozenIgnoreRules, decodeRepositoryIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { MAX_FROZEN_IGNORE_SOURCE_BYTES } from './frozen-ignore-sources.js';
import { parseSanitizedGitConfig } from './git-config.js';
import type {
  DescriptorIdentity, HeldStateOwnerLock, LiveWorkspaceInspection, WorkspaceSourceDirectoryEntry
} from './native-owner.js';

const READ_CHUNK_BYTES = 1024 * 1024;

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
        first.size !== file.size || first.mode !== file.mode) {
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

  const directories = new Set<string>(['']);
  for (const entry of entries.entries) {
    const components = entry.path.split('/');
    for (let depth = 1; depth < components.length; depth += 1) {
      directories.add(components.slice(0, depth).join('/'));
    }
    if (entry.kind === 'directory') directories.add(entry.path);
  }
  const gitignoreSources = new Map(
    rules.sources.filter((source) => source.kind === 'gitignore')
      .map((source) => [source.canonicalRootRelativePath, source] as const)
  );
  for (const directory of directories) {
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
