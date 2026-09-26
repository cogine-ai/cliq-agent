import type { RepositoryIdentityV1, SanitizedGitConfigV1 } from '../kernel/types.js';
import { decodeRepositoryIdentity } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { parseSanitizedGitConfig } from './git-config.js';
import type { DescriptorIdentity, HeldStateOwnerLock } from './native-owner.js';

function sameIdentity(left: DescriptorIdentity, right: DescriptorIdentity): boolean {
  return left.deviceId === right.deviceId && left.fileId === right.fileId && left.ownerUid === right.ownerUid;
}

/** One observation for the Git branch of source capture. The caller must
 * revalidate the source and repository at the admission commit boundary. */
export function readHeldSanitizedGitConfig(
  filesystem: HeldStateOwnerLock,
  workspacePath: string,
  expectedRoot: DescriptorIdentity,
  expectedRepository: RepositoryIdentityV1
): SanitizedGitConfigV1 {
  const repository = decodeRepositoryIdentity(expectedRepository);
  const observed = filesystem.inspectWorkspaceIdentity(workspacePath);
  if (!sameIdentity(observed.root, expectedRoot) || !observed.git ||
      !sameIdentity(observed.git.identity, repository.gitDirectoryIdentity) ||
      observed.git.configBytes === undefined) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace or Git config identity changed during source capture');
  }
  const config = parseSanitizedGitConfig(observed.git.configBytes);
  if ((config.extensions?.objectFormat ?? 'sha1') !== repository.objectFormat) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Git config object format differs from the Session repository');
  }
  return config;
}
