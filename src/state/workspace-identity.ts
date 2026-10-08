import { setImmediate } from 'node:timers/promises';
import { digestOmitting, normalizeAbsolutePath } from '../kernel/identity.js';
import type { RepositoryIdentityV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { loadNativeStateOwner, type HeldWorkspaceRoot } from './native-owner.js';

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
      : 'workspace descriptor identity or Git config changed during capture', { cause: error });
}

function parseGitObjectFormat(configUtf8: string): 'sha1' | 'sha256' {
  let section = '', format: 'sha1' | 'sha256' = 'sha1';
  // A continued value can contain text resembling a section. Comments and
  // escaped quotes must therefore be handled before recognizing section lines.
  const lines: string[] = [];
  let line = '', quoted = false, escaped = false, comment = false;
  for (const char of configUtf8.replace(/\r\n/gu, '\n') + '\n') {
    if (char === '\n') {
      if (escaped && !comment) { line = line.slice(0, -1); escaped = false; continue; }
      if (quoted) throw new TypeError('unterminated Git config quote');
      lines.push(line); line = ''; comment = false; escaped = false;
    } else if (!comment) {
      if (escaped) { line += char; escaped = false; }
      else if (!quoted && (char === '#' || char === ';')) comment = true;
      else { line += char; if (char === '\\') escaped = true; else if (char === '"') quoted = !quoted; }
    }
  }
  for (const logicalLine of lines) {
    const header = /^\s*\[([A-Za-z0-9.-]+)(?:\s+"(?:[^"\\]|\\.)*")?\]\s*$/u.exec(logicalLine);
    if (header) section = /^\s*\[extensions\]\s*$/iu.test(logicalLine) ? 'extensions' : '';
    else if (section === 'extensions') {
      const variable = /^\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)$/u.exec(logicalLine);
      if (variable?.[1].toLowerCase() === 'objectformat') {
        const match = /^(?:"(sha1|sha256)"|(sha1|sha256))\s*$/u.exec(variable[2]);
        if (!match) throw new TypeError('unsupported Git object-format literal');
        format = (match[1] ?? match[2]) as 'sha1' | 'sha256';
      }
    }
  }
  return format;
}

/** Physical identity only. This does not load runtime configuration or grant
 * Workspace Trust, source-read permission, tool permission or execution. */
export async function captureLiveWorkspaceIdentity(options: {
  workspacePath: string;
  ownerPrincipalId: string;
}): Promise<{
  identity: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  repository?: RepositoryIdentityV1;
}> {
  const workspacePath = normalizeAbsolutePath(options.workspacePath);
  const platform = hostPlatform();
  const native = await loadNativeStateOwner();
  let opened: HeldWorkspaceRoot;
  try { opened = native.openWorkspaceRoot(workspacePath); }
  catch (error) { return sourceError(error, true); }
  try {
    let repository: RepositoryIdentityV1 | undefined;
    if (opened.repositoryDirectory !== undefined) {
      const chunks: Buffer[] = [];
      for (;;) {
        await setImmediate();
        const chunk = opened.readGitConfigChunk();
        if (chunk === null) break;
        chunks.push(chunk);
      }
      const config = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
      if (config.includes('\0')) throw new TypeError('Git config contains NUL');
      repository = {
        schemaVersion: 1, format: 'cliq-repository-identity-v1', platform,
        gitDirectoryRelativePath: '.git', gitDirectoryIdentity: opened.repositoryDirectory,
        objectFormat: parseGitObjectFormat(config), repositoryIdentityDigest: ''
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
  expected: Extract<WorkspaceIdentityV1, { kind: 'live' }>, workspacePath: string
): Promise<Extract<WorkspaceIdentityV1, { kind: 'live' }>> {
  const captured = await captureLiveWorkspaceIdentity({ workspacePath, ownerPrincipalId: expected.ownerPrincipalId });
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
