// Exact old product build input. This digest authenticates build provenance;
// it is never a runtime release root or an execution permission.
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { normalizeAbsolutePath, sha256Bytes } from '../../../src/kernel/identity.js';
import { ResourceRetirementError } from '../../../src/state/errors.js';
import { readQualificationSource, type FrozenQualificationSource } from './qualification-source.js';
import { installQualificationDependencies } from './qualification-dependencies.js';
import { LEGACY_UPGRADE_SOURCE } from './legacy-upgrade-source-data.js';
export { LEGACY_UPGRADE_SOURCE } from './legacy-upgrade-source-data.js';
type Member = { path: string; mode: '100644' | '100755'; size: number; sha256: string };
const metadataFields = ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const byteOrder = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));

/** Read every actual member before accepting the fixed aggregate digest. No
 * manifest, trust roots or build dependencies can be supplied by the source. */
export async function readLegacyUpgradeSource(rootName: string) {
  if (normalizeAbsolutePath(rootName) !== rootName || await realpath(rootName) !== rootName)
    throw new TypeError('legacy source requires its canonical non-aliased directory');
  const root = await open(rootName, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let primary: unknown;
  try {
    const original = await root.stat({ bigint: true });
    if (!original.isDirectory() || (original.mode & 0o022n)) throw new TypeError('legacy source directory is not protected');
    const same = (a: typeof original, b: typeof original) => metadataFields.every(key => a[key] === b[key]);
    const directories = new Map([[rootName, original]]);
    const members: Member[] = [], contents = new Map<string, Buffer>();
    let totalBytes = 0;
    const assertDirectories = async (filename?: string) => {
      if (!same(original, await root.stat({ bigint: true }))) throw new TypeError('legacy source root changed');
      for (const [directory, before] of directories) {
        if (filename && directory !== rootName && !filename.startsWith(directory + path.sep)) continue;
        if (!same(before, await lstat(directory, { bigint: true }))) throw new TypeError('legacy source directory changed');
      }
    };
    const visit = async (relative: string, depth: number) => {
      if (depth > 32 || directories.size > 4096) throw new TypeError('legacy source directory bounds exceeded');
      for (const name of (await readdir(path.join(rootName, relative))).sort(byteOrder)) {
        if (!relative && ['.git', 'dist', 'node_modules'].includes(name))
          throw new TypeError('legacy source contains an undeclared build or repository directory');
        if (!name || name === '.' || name === '..' || name.includes('\\') || name.includes('\0') || name.normalize('NFC') !== name)
          throw new TypeError('legacy source member name is not canonical');
        const rel = relative ? relative + '/' + name : name, filename = path.join(rootName, rel);
        const named = await lstat(filename, { bigint: true });
        if (named.uid !== original.uid || (named.mode & 0o022n) || named.isSymbolicLink())
          throw new TypeError('legacy source member is not its protected original object');
        if (named.isDirectory()) { directories.set(filename, named); await visit(rel, depth + 1); continue; }
        if (!named.isFile() || named.nlink !== 1n || named.size < 0n || named.size > 16n * 1024n * 1024n || members.length >= 4096)
          throw new TypeError('legacy source member is not a bounded single-link regular file');
        const permissions = named.mode & 0o7777n;
        const mode = permissions === 0o644n || permissions === 0o444n ? '100644'
          : permissions === 0o755n || permissions === 0o555n ? '100755' : undefined;
        if (!mode) throw new TypeError('legacy source member has an unsupported logical mode');
        totalBytes += Number(named.size);
        if (totalBytes > 128 * 1024 * 1024) throw new TypeError('legacy source exceeds its complete byte bound');
        await assertDirectories(filename);
        const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        let readFailure: unknown;
        try {
          const before = await handle.stat({ bigint: true });
          if (!same(named, before)) throw new TypeError('legacy source member was replaced');
          const bytes = Buffer.alloc(Number(before.size) + 1); let count = 0;
          for (;;) {
            const next = await handle.read(bytes, count, Math.min(262144, bytes.length - count), null); count += next.bytesRead;
            if (count === bytes.length) throw new TypeError('legacy source member grew');
            if (!next.bytesRead) break;
          }
          if (count !== Number(before.size) || !same(before, await handle.stat({ bigint: true })) || !same(before, await lstat(filename, { bigint: true })))
            throw new TypeError('legacy source member changed during its complete read');
          await assertDirectories(filename);
          const complete = bytes.subarray(0, count);
          members.push({ path: rel, mode, size: count, sha256: sha256Bytes(complete) }); contents.set(rel, complete);
        } catch (error) { readFailure = error; throw error; }
        finally { try { await handle.close(); } catch (cause) { throw new ResourceRetirementError('legacy source file did not join',
          readFailure === undefined ? cause : new AggregateError([readFailure, cause])); } }
      }
    };
    await visit('', 0); await assertDirectories(); members.sort((a, b) => byteOrder(a.path, b.path));
    if (members.length !== LEGACY_UPGRADE_SOURCE.memberCount || totalBytes !== LEGACY_UPGRADE_SOURCE.totalBytes ||
        canonicalSha256(members) !== LEGACY_UPGRADE_SOURCE.inventorySha256)
      throw new TypeError('legacy source differs from the complete fixed product inventory');
    const config = contents.get('src/config.ts')!.toString('utf8');
    if ((config.match(/^export const KERNEL_STATE_SCHEMA_VERSION = 7;$/gmu) ?? []).length !== 1)
      throw new TypeError('legacy source is not the actual schema7 product');
    return { members, contents, physicalCutDigest: canonicalSha256([...directories].sort(([a], [b]) => byteOrder(a, b)).map(([directory, info]) =>
      ({ directory: path.relative(rootName, directory), ...Object.fromEntries(metadataFields.map(key => [key, String(info[key])])) }))) };
  } catch (error) { primary = error; throw error; }
  finally { try { await root.close(); } catch (cause) { throw new ResourceRetirementError('legacy source root did not join',
    primary === undefined ? cause : new AggregateError([primary, cause])); } }
}

/** Create an independently owned, immutable build copy only after all 1178
 * original bytes/modes match. The returned sidecar is outside the source tree. */
export async function prepareLegacyUpgradeSource(sourceRoot: string, buildRoot: string): Promise<FrozenQualificationSource> {
  if (normalizeAbsolutePath(buildRoot) !== buildRoot || await realpath(path.dirname(buildRoot)) !== path.dirname(buildRoot))
    throw new TypeError('legacy build copy requires a canonical owned parent');
  const first = await readLegacyUpgradeSource(sourceRoot);
  await mkdir(buildRoot, { mode: 0o700 });
  const manifestPath = buildRoot + '.inventory.json';
  const manifestBytes = canonicalJsonBytes({ inventory: first.members });
  await writeFile(manifestPath, manifestBytes, { flag: 'wx', mode: 0o400 });
  for (const member of first.members) {
    const filename = path.join(buildRoot, member.path);
    await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
    await writeFile(filename, first.contents.get(member.path)!, { flag: 'wx', mode: member.mode === '100755' ? 0o555 : 0o444 });
  }
  const copied = await readLegacyUpgradeSource(buildRoot);
  if (canonicalSha256(copied.members) !== canonicalSha256(first.members)) throw new TypeError('legacy source copy differs');
  const original = await readLegacyUpgradeSource(sourceRoot);
  if (original.physicalCutDigest !== first.physicalCutDigest) throw new TypeError('legacy source origin changed while copying');
  const source = Object.freeze({ root: buildRoot, manifestPath, manifestSha256: sha256Bytes(manifestBytes) });
  await installQualificationDependencies(source);
  const freezeDirectories = async (directory: string): Promise<void> => {
    for (const name of await readdir(directory)) {
      const filename = path.join(directory, name), info = await lstat(filename);
      if (info.isDirectory() && !info.isSymbolicLink()) await freezeDirectories(filename);
    }
    if (((await lstat(directory)).mode & 0o7777) !== 0o555) await chmod(directory, 0o555);
  };
  await freezeDirectories(buildRoot);
  const verified = await readQualificationSource(source);
  if (verified.memberCount !== LEGACY_UPGRADE_SOURCE.memberCount || verified.schemaVersion !== 7)
    throw new TypeError('legacy build copy did not verify as the original product');
  return source;
}
