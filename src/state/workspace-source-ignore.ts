import type { RepositoryIdentityV1 } from '../kernel/types.js';
import { decodeRepositoryIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { parseSanitizedGitConfig } from './git-config.js';
import type { DescriptorIdentity, HeldStateOwnerLock, LiveWorkspaceInspection } from './native-owner.js';

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
