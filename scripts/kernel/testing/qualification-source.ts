// Build provenance only. This never authenticates a runtime, Store or release.
import { constants } from 'node:fs';
import { lstat, open, readdir, readlink, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { assertArtifactRef, normalizeAbsolutePath, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { ResourceRetirementError } from '../../../src/state/errors.js';
import { hasQualificationDependencies, readQualificationDependencies } from './qualification-dependencies.js';
export type FrozenQualificationSource = Readonly<{ root: string; manifestPath: string; manifestSha256: string }>;
export async function readQualificationSource(input: FrozenQualificationSource) {
  assertArtifactRef(input.manifestSha256);
  if (normalizeAbsolutePath(input.root) !== input.root || normalizeAbsolutePath(input.manifestPath) !== input.manifestPath)
    throw new TypeError('qualification source requires canonical owned locators');
  if (await realpath(input.root) !== input.root || await realpath(input.manifestPath) !== input.manifestPath)
    throw new TypeError('qualification source locators cannot traverse aliases');
  const root = await open(input.root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const rootInfo = await root.stat({ bigint: true });
  const fields = ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
  const same = (a: typeof rootInfo, b: typeof rootInfo) => fields.every(key => a[key] === b[key]);
  if (!rootInfo.isDirectory() || (rootInfo.mode & 0o022n) !== 0n) { await root.close(); throw new TypeError('qualification source root is not protected'); }
  const directories = new Map<string, typeof rootInfo>([[input.root, rootInfo]]);
  const physical: Array<Record<string, string>> = [];
  const currentDirectories = async (file?: string) => {
    if (!same(rootInfo, await root.stat({ bigint: true }))) throw new TypeError('qualification source root changed');
    for (const [directory, original] of directories) {
      if (file && directory !== input.root && !file.startsWith(directory + path.sep)) continue;
      if (!same(original, await lstat(directory, { bigint: true }))) throw new TypeError('qualification source directory changed');
    }
  };
  const read = async (file: string, maximum: number, declaredMode?: string, ownerUid = rootInfo.uid) => {
    await currentDirectories(file);
    const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let primary: unknown;
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.nlink !== 1n || ![ownerUid, BigInt(process.geteuid!())].includes(before.uid) ||
          (before.mode & 0o022n) !== 0n || before.size < 0n || before.size > BigInt(maximum))
        throw new TypeError('qualification source is not its complete bounded owned file');
      if (declaredMode) {
        const expected = declaredMode === '100755' ? 0o755n : 0o644n, actual = before.mode & 0o7777n;
        if (actual !== expected && actual !== (expected & ~0o222n)) throw new TypeError('qualification source logical mode differs');
      }
      const bytes = Buffer.alloc(Number(before.size) + 1); let count = 0;
      for (;;) {
        const result = await handle.read(bytes, count, Math.min(262144, bytes.length - count), null); count += result.bytesRead;
        if (count === bytes.length) throw new TypeError('qualification source grew beyond its complete byte bound');
        if (!result.bytesRead) break;
      }
      const after = await handle.stat({ bigint: true }), named = await lstat(file, { bigint: true });
      if (!same(before, after) || !same(after, named) || BigInt(count) !== before.size)
        throw new TypeError('qualification source changed during its complete read');
      await currentDirectories(file);
      physical.push(Object.fromEntries(fields.map(key => [key, String(before[key])])));
      return bytes.subarray(0, count);
    } catch (error) { primary = error; throw error; }
    finally { try { await handle.close(); } catch (cause) { throw new ResourceRetirementError('qualification source descriptor did not join',
      primary === undefined ? cause : new AggregateError([primary, cause])); } }
  };
  let primary: unknown;
  try {
  const manifestBytes = await read(input.manifestPath, 4 * 1024 * 1024);
  if (sha256Bytes(manifestBytes) !== input.manifestSha256) throw new TypeError('qualification source manifest digest differs');
  const manifest = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(manifestBytes)) as { inventory?: unknown };
  if (!Array.isArray(manifest.inventory) || manifest.inventory.length < 1 || manifest.inventory.length > 4096)
    throw new TypeError('qualification source has no complete bounded inventory');
  let config = '', totalBytes = 0;
  const names = new Set<string>();
  const expectedDirectories = new Set<string>();
  for (const item of manifest.inventory as Array<{ path: string; mode: string; size: number; sha256: string }>) {
    if (!item || typeof item.path !== 'string' || item.path.includes('\\') || item.path.startsWith('/') ||
        item.path.includes('\0') || item.path.normalize('NFC') !== item.path ||
        item.path.split('/').some(part => !part || part === '.' || part === '..') || names.has(item.path) ||
        !['100644', '100755'].includes(item.mode) ||
        !Number.isSafeInteger(item.size) || item.size < 0 || item.size > 16 * 1024 * 1024)
      throw new TypeError('qualification source member is not its exact bounded inventory');
    assertArtifactRef(item.sha256); names.add(item.path); totalBytes += item.size;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > 128 * 1024 * 1024) throw new TypeError('qualification source exceeds its complete source-byte bound');
    const parts = item.path.split('/'); parts.pop();
    for (let index = 1; index <= parts.length; index++) expectedDirectories.add(parts.slice(0, index).join('/'));
  }
  const currentRepository = fileURLToPath(new URL('../../..', import.meta.url));
  const dependencyRoot = await realpath(path.join(currentRepository, 'node_modules'));
  let dependencyLink: { filename: string; target: string; identity: typeof rootInfo } | undefined;
  let installedDependencies: string | undefined;
  const visit = async (relative: string) => {
    for (const name of (await readdir(path.join(input.root, relative))).sort()) {
      const rel = relative ? relative + '/' + name : name, filename = path.join(input.root, rel), info = await lstat(filename, { bigint: true });
      if (!relative && name === 'node_modules' && hasQualificationDependencies(input) && (!info.isDirectory() || info.isSymbolicLink()))
        throw new TypeError('independently installed build dependencies cannot switch to a borrowed tree');
      if (!relative && name === 'node_modules' && info.isDirectory() && !info.isSymbolicLink()) {
        installedDependencies = await readQualificationDependencies(input); continue;
      }
      if (!relative && name === 'node_modules' && info.isSymbolicLink() && info.uid === rootInfo.uid && await realpath(filename) === dependencyRoot) {
        dependencyLink = { filename, target: await readlink(filename), identity: info }; continue;
      }
      if (info.isDirectory() && !info.isSymbolicLink() && info.uid === rootInfo.uid && (info.mode & 0o022n) === 0n && expectedDirectories.has(rel)) {
        directories.set(filename, info); await visit(rel);
      } else if (!info.isFile() || info.isSymbolicLink() || !names.has(rel)) throw new TypeError('qualification source contains an undeclared member or alias');
    }
  };
  await visit(''); await currentDirectories();
  for (const item of manifest.inventory as Array<{ path: string; mode: string; size: number; sha256: string }>) {
    const bytes = await read(path.join(input.root, item.path), item.size, item.mode);
    if (bytes.length !== item.size || sha256Bytes(bytes) !== item.sha256) throw new TypeError('qualification source member differs');
    if (item.path === 'src/config.ts') config = bytes.toString('utf8');
  }
  if (dependencyLink) {
    if (!same(dependencyLink.identity, await lstat(dependencyLink.filename, { bigint: true })) ||
        await readlink(dependencyLink.filename) !== dependencyLink.target || await realpath(dependencyLink.filename) !== dependencyRoot)
      throw new TypeError('qualification build dependency link changed');
    const sourceLock = (manifest.inventory as Array<{ path: string; sha256: string }>).find(item => item.path === 'package-lock.json');
    const repositoryOwner = (await lstat(currentRepository, { bigint: true })).uid;
    if (!sourceLock || sha256Bytes(await read(path.join(currentRepository, 'package-lock.json'), 16 * 1024 * 1024, undefined, repositoryOwner)) !== sourceLock.sha256)
      throw new TypeError('qualification build dependencies do not match the original frozen lock');
  }
  if (installedDependencies !== undefined) {
    if (await readQualificationDependencies(input) !== installedDependencies) throw new TypeError('installed build dependency cut changed');
    physical.push({ independentLockedDependencies: installedDependencies });
  }
  const versions = [...config.matchAll(/^export const KERNEL_STATE_SCHEMA_VERSION = (7|8);$/gmu)];
  if (versions.length !== 1) throw new TypeError('qualification source has no exact implemented schema version');
  const schemaVersion = Number(versions[0]![1]) as 7 | 8;
  await currentDirectories();
  for (const [directory, info] of [...directories].sort(([a], [b]) => a.localeCompare(b)))
    physical.push({ directory: path.relative(input.root, directory), ...Object.fromEntries(fields.map(key => [key, String(info[key])])) });
  return Object.freeze({ root: input.root, manifestSha256: input.manifestSha256, memberCount: names.size, totalBytes, schemaVersion, physicalCutDigest: canonicalSha256(physical) });
  } catch (error) { primary = error; throw error; }
  finally { try { await root.close(); } catch (cause) { throw new ResourceRetirementError('qualification source root descriptor did not join',
    primary === undefined ? cause : new AggregateError([primary, cause])); } }
}
