import { digestOmitting, normalizeAbsolutePath } from '../kernel/identity.js';
import type { RepositoryIdentityV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import type { HeldStateOwnerLock, LiveWorkspaceInspection } from './native-owner.js';

export type HostPlatform = 'macos' | 'linux';

export function hostPlatform(): HostPlatform {
  if (process.platform === 'darwin') return 'macos';
  if (process.platform === 'linux') return 'linux';
  throw new KernelStorageError('UNSUPPORTED_PLATFORM', `workspace identity is unsupported on ${process.platform}`);
}

function requireEffectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'workspace identity requires a POSIX effective uid');
  }
  return process.geteuid();
}

function parseGitObjectFormat(configBytes?: Buffer): 'sha1' | 'sha256' {
  if (configBytes === undefined) return 'sha1';
  if (configBytes.includes(0) || (configBytes.length >= 3 &&
      configBytes[0] === 0xef && configBytes[1] === 0xbb && configBytes[2] === 0xbf)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace .git/config has invalid text bytes');
  }
  let config: string;
  try {
    config = new TextDecoder('utf-8', { fatal: true }).decode(configBytes);
  } catch {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace .git/config is not UTF-8');
  }
  let section = '';
  let format: 'sha1' | 'sha256' | undefined;
  for (const line of config.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    if (trimmed.startsWith('[')) {
      const match = /^\[([A-Za-z][A-Za-z0-9.-]*)(?:\s+("[^"\r\n]*"))?\]$/u.exec(trimmed);
      if (!match) throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace .git/config has an invalid section');
      section = match[2] === undefined ? match[1]!.toLowerCase() : '';
      continue;
    }
    const assignment = /^([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*?)\s*$/u.exec(trimmed);
    if (!assignment) continue;
    if (section === 'extensions' && assignment[1]!.toLowerCase() === 'objectformat') {
      const value = assignment[2]!.toLowerCase();
      if (format !== undefined || (value !== 'sha1' && value !== 'sha256')) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace .git/config has an invalid or duplicate object format');
      }
      format = value;
    }
  }
  return format ?? 'sha1';
}

function captureRepositoryIdentity(
  inspected: LiveWorkspaceInspection,
  platform: HostPlatform
): RepositoryIdentityV1 | undefined {
  if (inspected.git === undefined) return undefined;
  const identity: RepositoryIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-repository-identity-v1',
    platform,
    gitDirectoryRelativePath: '.git',
    gitDirectoryIdentity: inspected.git.identity,
    objectFormat: parseGitObjectFormat(inspected.git.configBytes),
    repositoryIdentityDigest: ''
  };
  identity.repositoryIdentityDigest = digestOmitting(identity, 'repositoryIdentityDigest');
  return identity;
}

type CaptureLiveWorkspaceOptions = {
  workspacePath: string;
  ownerPrincipalId: string;
  filesystem: HeldStateOwnerLock;
};

type CapturedLiveWorkspace = {
  identity: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  repository?: RepositoryIdentityV1;
};

function captureLiveWorkspaceIdentityNow(options: CaptureLiveWorkspaceOptions): CapturedLiveWorkspace {
  const workspacePath = normalizeAbsolutePath(options.workspacePath);
  const platform = hostPlatform();
  const effectiveUid = requireEffectiveUid();
  const inspected = options.filesystem.inspectWorkspaceIdentity(workspacePath);
  if (inspected.root.ownerUid !== effectiveUid) {
    throw new KernelStorageError(
      'INVALID_REQUEST',
      'workspace root must be owned by the effective uid of the local principal'
    );
  }
  const repository = captureRepositoryIdentity(inspected, platform);
  const identity: Extract<WorkspaceIdentityV1, { kind: 'live' }> = {
    schemaVersion: 1,
    format: 'cliq-workspace-identity-v1',
    ownerPrincipalId: options.ownerPrincipalId,
    platform,
    kind: 'live',
    canonicalRootPath: workspacePath,
    rootIdentity: inspected.root,
    identityDigest: ''
  };
  if (repository !== undefined) {
    identity.repositoryIdentityDigest = repository.repositoryIdentityDigest;
  }
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  return { identity, repository };
}

export async function captureLiveWorkspaceIdentity(options: CaptureLiveWorkspaceOptions): Promise<CapturedLiveWorkspace> {
  return captureLiveWorkspaceIdentityNow(options);
}

function recaptureLiveWorkspaceIdentityNow(
  expected: Extract<WorkspaceIdentityV1, { kind: 'live' }>,
  workspacePath: string,
  filesystem: HeldStateOwnerLock
): Extract<WorkspaceIdentityV1, { kind: 'live' }> {
  let captured: CapturedLiveWorkspace;
  try {
    captured = captureLiveWorkspaceIdentityNow({
      workspacePath,
      ownerPrincipalId: expected.ownerPrincipalId,
      filesystem
    });
  } catch (error) {
    if (error instanceof KernelStorageError && error.code === 'INVALID_REQUEST') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', `live workspace identity changed: ${error.message}`);
    }
    throw error;
  }
  if (captured.identity.canonicalRootPath !== expected.canonicalRootPath) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace path does not match the live Session identity');
  }
  if (
    captured.identity.rootIdentity.deviceId !== expected.rootIdentity.deviceId ||
    captured.identity.rootIdentity.fileId !== expected.rootIdentity.fileId ||
    captured.identity.rootIdentity.ownerUid !== expected.rootIdentity.ownerUid
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace root identity changed; create a new Session');
  }
  if ((captured.identity.repositoryIdentityDigest ?? null) !== (expected.repositoryIdentityDigest ?? null)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'workspace repository identity changed; create a new Session');
  }
  return captured.identity;
}

/** Call inside the owner-gated SQLite commit after all asynchronous artifact
 * publication, so a source-root or literal .git swap cannot commit an earlier
 * identity observation as current. */
export function assertCurrentLiveWorkspaceIdentity(
  expected: Extract<WorkspaceIdentityV1, { kind: 'live' }>,
  workspacePath: string,
  filesystem: HeldStateOwnerLock
): void {
  recaptureLiveWorkspaceIdentityNow(expected, workspacePath, filesystem);
}

export async function recaptureLiveWorkspaceIdentity(
  expected: Extract<WorkspaceIdentityV1, { kind: 'live' }>,
  workspacePath: string,
  filesystem: HeldStateOwnerLock
): Promise<Extract<WorkspaceIdentityV1, { kind: 'live' }>> {
  return recaptureLiveWorkspaceIdentityNow(expected, workspacePath, filesystem);
}
