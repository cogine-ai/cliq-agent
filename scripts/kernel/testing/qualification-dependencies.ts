// Private build provenance only. This is not a runtime dependency acquisition
// backend, registry permission, release root, credential or execution grant.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, readlink, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { ResourceRetirementError } from '../../../src/state/errors.js';
import type { FrozenQualificationSource } from './qualification-source.js';

const originals = new WeakMap<FrozenQualificationSource, { cut: string; sourceRoot: string }>();
const fields = ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
export function hasQualificationDependencies(source: FrozenQualificationSource): boolean { return originals.has(source); }
type DependencyInventory = Readonly<{ physicalDigest: string; contentDigest: string }>;
async function readTree(rootName: string): Promise<DependencyInventory> {
  const root = await open(rootName, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let failure: unknown;
  try {
    const info = await root.stat({ bigint: true }), directories = new Map([[rootName, info]]);
    if (!info.isDirectory() || (info.mode & 0o022n)) throw new TypeError('build dependencies are not protected');
    const same = (a: typeof info, b: typeof info) => fields.every(key => a[key] === b[key]);
    const rows: Record<string, unknown>[] = []; let total = 0;
    const visit = async (directory: string, depth: number): Promise<void> => {
      if (depth > 32 || directories.size > 10000) throw new TypeError('build dependency directory bounds exceeded');
      for (const name of (await readdir(directory)).sort()) {
        if (name.includes('\\') || name.includes('\0') || name.normalize('NFC') !== name) throw new TypeError('build dependency name differs');
        const filename = path.join(directory, name), before = await lstat(filename, { bigint: true }), relative = path.relative(rootName, filename);
        if (before.uid !== info.uid || (!before.isSymbolicLink() && (before.mode & 0o022n))) throw new TypeError('build dependency ownership differs');
        const metadata = Object.fromEntries(fields.map(key => [key, String(before[key])]));
        if (before.isDirectory() && !before.isSymbolicLink()) { directories.set(filename, before); rows.push({ path: relative, kind: 'directory', ...metadata }); await visit(filename, depth + 1); }
        else if (before.isSymbolicLink()) {
          const target = await readlink(filename), resolved = await realpath(filename);
          if (path.basename(directory) !== '.bin' || path.isAbsolute(target) || !resolved.startsWith(rootName + path.sep) ||
              !same(before, await lstat(filename, { bigint: true })) || target !== await readlink(filename))
            throw new TypeError('build dependency has a nonlocal package bin alias');
          rows.push({ path: relative, kind: 'package_bin_link', target, ...metadata });
        } else {
          if (!before.isFile() || before.nlink !== 1n || before.size < 0n || before.size > 32n * 1024n * 1024n)
            throw new TypeError('build dependency is not a bounded single-link regular file');
          total += Number(before.size); if (total > 512 * 1024 * 1024 || rows.length > 100000) throw new TypeError('build dependency inventory exceeded its bound');
          const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); let primary: unknown;
          try {
            if (!same(before, await held.stat({ bigint: true }))) throw new TypeError('build dependency was replaced');
            const hash = createHash('sha256'), buffer = Buffer.alloc(262144); let count = 0;
            for (;;) { const next = await held.read(buffer, 0, buffer.length, null); if (!next.bytesRead) break;
              count += next.bytesRead; if (count > Number(before.size)) throw new TypeError('build dependency grew'); hash.update(buffer.subarray(0, next.bytesRead)); }
            if (count !== Number(before.size) || !same(before, await held.stat({ bigint: true })) || !same(before, await lstat(filename, { bigint: true })))
              throw new TypeError('build dependency changed during its full read');
            rows.push({ path: relative, kind: 'file', sha256: hash.digest('hex'), ...metadata });
          } catch (error) { primary = error; throw error; }
          finally { try { await held.close(); } catch (cause) { throw new ResourceRetirementError('build dependency descriptor did not join',
            primary === undefined ? cause : new AggregateError([primary, cause])); } }
        }
      }
    };
    await visit(rootName, 0);
    for (const [directory, before] of directories) if (!same(before, await lstat(directory, { bigint: true }))) throw new TypeError('build dependency directory changed');
    if (!same(info, await root.stat({ bigint: true }))) throw new TypeError('build dependency root changed');
    return Object.freeze({ physicalDigest: canonicalSha256({ root: Object.fromEntries(fields.map(key => [key, String(info[key])])), rows, total }),
      contentDigest: canonicalSha256({ rows: rows.map(row => ({ path: row.path, kind: row.kind, mode: row.mode,
        ...(row.kind === 'file' ? { sha256: row.sha256, byteCount: row.size } :
          row.kind === 'package_bin_link' ? { target: row.target } : {}) })), total }) });
  } catch (error) { failure = error; throw error; }
  finally { try { await root.close(); } catch (cause) { throw new ResourceRetirementError('build dependency root did not join',
    failure === undefined ? cause : new AggregateError([failure, cause])); } }
}

async function readOriginalDependencyInventory(source: FrozenQualificationSource): Promise<DependencyInventory> {
  const original = originals.get(source);
  if (!original || original.sourceRoot !== source.root) throw new TypeError('independent build dependencies require their original installation session');
  const actual = await readTree(path.join(source.root, 'node_modules'));
  if (actual.physicalDigest !== original.cut) throw new TypeError('independent build dependencies changed'); return actual;
}
export async function readQualificationDependencies(source: FrozenQualificationSource): Promise<string> {
  return (await readOriginalDependencyInventory(source)).physicalDigest;
}
/** One original integrity-installed tree, freshly and completely reread. The
 * content digest compares two independent inputs without merging their owners. */
export async function readQualificationDependencyInventory(source: FrozenQualificationSource): Promise<DependencyInventory> {
  return readOriginalDependencyInventory(source);
}

/** Execute the real old lock's npm-ci integrity checks in an isolated HOME and
 * cache. No inherited npmrc, auth token, lifecycle script or target lock enters
 * this source. This tool is used before constructing any signed product. */
export async function installQualificationDependencies(source: FrozenQualificationSource): Promise<void> {
  if (originals.has(source)) throw new TypeError('build dependencies were already installed');
  const { readQualificationSource } = await import('./qualification-source.js');
  const before = await readQualificationSource(source);
  const cli = path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js');
  const cliInfo = await lstat(cli);
  if (!cliInfo.isFile() || cliInfo.isSymbolicLink() || cliInfo.nlink !== 1 || await realpath(cli) !== cli)
    throw new TypeError('expected the selected Node distribution actual npm CLI');
  const home = source.root + '.npm-home'; await mkdir(home, { mode: 0o700 });
  const userConfig = path.join(home, 'user.npmrc'), globalConfig = path.join(home, 'global.npmrc');
  await writeFile(userConfig, '', { flag: 'wx', mode: 0o400 }); await writeFile(globalConfig, '', { flag: 'wx', mode: 0o400 });
  const result = spawnSync(process.execPath, [cli, 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error',
    '--registry=https://registry.npmjs.org/', '--userconfig=' + userConfig, '--globalconfig=' + globalConfig, '--cache=' + path.join(home, 'cache')],
  { cwd: source.root, env: { HOME: home, PATH: path.dirname(process.execPath) + ':/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
    timeout: 60000, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024 });
  if (result.error || result.signal || result.status !== 0) throw new Error('original locked public build dependencies did not install and join');
  await mkdir(path.join(source.root, 'node_modules'), { mode: 0o700, recursive: true });
  const freeze = async (directory: string): Promise<void> => {
    for (const name of await readdir(directory)) {
      const filename = path.join(directory, name), info = await lstat(filename);
      if (info.isDirectory() && !info.isSymbolicLink()) await freeze(filename);
      else if (info.isFile() && !info.isSymbolicLink()) await chmod(filename, (info.mode & 0o111) ? 0o555 : 0o444);
    }
    await chmod(directory, 0o555);
  };
  await freeze(path.join(source.root, 'node_modules'));
  const cut = await readTree(path.join(source.root, 'node_modules')); originals.set(source, { cut: cut.physicalDigest, sourceRoot: source.root });
  const after = await readQualificationSource(source);
  if (before.manifestSha256 !== after.manifestSha256 || before.memberCount !== after.memberCount || before.totalBytes !== after.totalBytes ||
      before.schemaVersion !== after.schemaVersion) throw new TypeError('original source changed while installing its locked dependencies');
}
