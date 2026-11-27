import { digestOmitting, normalizeAbsolutePath } from '../kernel/identity.js';
import type { RepositoryIdentityV2, WorkspaceIdentityV1 } from '../kernel/types.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { loadNativeStateOwner, type HeldWorkspaceRoot, type NativeStateOwner } from './native-owner.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';

export type HostPlatform = 'macos' | 'linux';

export function hostPlatform(): HostPlatform {
  if (process.platform === 'darwin') return 'macos';
  if (process.platform === 'linux') return 'linux';
  throw new KernelStorageError('UNSUPPORTED_PLATFORM', `workspace identity is unsupported on ${process.platform}`);
}

function sourceError(error: unknown, opening: boolean): never {
  if (error instanceof KernelStorageError) throw error;
  if (error && typeof error === 'object' && 'code' in error && error.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
    throw new ResourceRetirementError('source workspace descriptor retirement failed', error);
  }
  throw new KernelStorageError(opening ? 'INVALID_REQUEST' : 'ARTIFACT_MISMATCH',
    opening ? 'workspace must be a same-user no-follow root with safe in-root Git metadata'
      : 'workspace descriptor identity or Git directory changed during capture', { cause: error });
}

/** Physical identity only. This does not load runtime configuration or grant
 * Workspace Trust, source-read permission, tool permission or execution. */
export async function captureLiveWorkspaceIdentity(options: {
  workspacePath: string;
  ownerPrincipalId: string;
}): Promise<{
  identity: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  repository?: RepositoryIdentityV2;
}> {
  const workspacePath = normalizeAbsolutePath(options.workspacePath);
  const native = await loadNativeStateOwner();
  return captureWorkspaceIdentity({ ...options, workspacePath }, native);
}

/** Installed physical observation uses only its genuine held signed image;
 * no development addon pathname or caller-supplied native factory is used. */
export async function captureInstalledWorkspaceIdentity(selected: HeldInstalledRuntime,
  options: { workspacePath: string; ownerPrincipalId: string }) {
  const native = await withHeldInstalledRuntime(selected, async installed => {
    await installed.revalidate(); return installed.loadStateOwner();
  });
  const captured = await captureWorkspaceIdentity(options, native);
  await selected.assertHeld(); return captured;
}

async function captureWorkspaceIdentity(options: { workspacePath: string; ownerPrincipalId: string }, native: NativeStateOwner): Promise<{
  identity: Extract<WorkspaceIdentityV1, { kind: 'live' }>; repository?: RepositoryIdentityV2;
}> {
  const workspacePath = normalizeAbsolutePath(options.workspacePath);
  const platform = hostPlatform();
  let opened: HeldWorkspaceRoot;
  try { opened = native.openWorkspaceRoot(workspacePath); }
  catch (error) { return sourceError(error, true); }
  try {
    let repository: RepositoryIdentityV2 | undefined;
    if (opened.repositoryDirectory !== undefined) {
      repository = {
        schemaVersion: 2, format: 'cliq-repository-identity-v2', platform,
        gitDirectoryRelativePath: '.git', gitDirectoryIdentity: opened.repositoryDirectory,
        repositoryIdentityDigest: ''
      };
      repository.repositoryIdentityDigest = digestOmitting(repository, 'repositoryIdentityDigest');
    }
    opened.assertHeld();
    const identity: Extract<WorkspaceIdentityV1, { kind: 'live' }> = {
      schemaVersion: 1, format: 'cliq-workspace-identity-v1', ownerPrincipalId: options.ownerPrincipalId,
      platform, kind: 'live', canonicalRootPath: workspacePath, rootIdentity: opened.identity,
      ...(repository === undefined ? {} : { repositoryIdentityDigest: repository.repositoryIdentityDigest }), identityDigest: ''
    };
    identity.identityDigest = digestOmitting(identity, 'identityDigest');
    return { identity, repository };
  } catch (error) { return sourceError(error, false); }
  finally {
    try { opened.close(); }
    catch (error) { throw new ResourceRetirementError('source workspace descriptor retirement failed', error); }
  }
}

export async function recaptureLiveWorkspaceIdentity(
  expected: Extract<WorkspaceIdentityV1, { kind: 'live' }>, workspacePath: string, selected?: HeldInstalledRuntime
): Promise<Extract<WorkspaceIdentityV1, { kind: 'live' }>> {
  const input = { workspacePath, ownerPrincipalId: expected.ownerPrincipalId };
  const captured = selected ? await captureInstalledWorkspaceIdentity(selected, input) : await captureLiveWorkspaceIdentity(input);
  if (captured.identity.canonicalRootPath !== expected.canonicalRootPath) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace path does not match the live Session identity');
  }
  if (captured.identity.rootIdentity.deviceId !== expected.rootIdentity.deviceId ||
      captured.identity.rootIdentity.fileId !== expected.rootIdentity.fileId ||
      captured.identity.rootIdentity.ownerUid !== expected.rootIdentity.ownerUid) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace root identity changed; create a new Session');
  }
  if ((captured.identity.repositoryIdentityDigest ?? null) !== (expected.repositoryIdentityDigest ?? null)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace repository identity changed; create a new Session');
  }
  return captured.identity;
}
