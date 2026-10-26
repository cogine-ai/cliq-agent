import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);
export const BUBBLEWRAP_SOURCE = Object.freeze({
  version: '0.12.0',
  url: 'https://github.com/containers/bubblewrap/releases/download/v0.12.0/bubblewrap-0.12.0.tar.xz',
  sha256: '9760d007363e3abba7c747489910f9f82d9fca53ba3bd3282e396fa3c97a3314',
  byteCount: 126452,
});
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function assertBubblewrapSource(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== BUBBLEWRAP_SOURCE.byteCount ||
      digest(bytes) !== BUBBLEWRAP_SOURCE.sha256) throw new Error('The fixed official bubblewrap source does not match its complete archive hash');
}
async function command(binary, args, cwd) {
  return execute(binary, args, { cwd, timeout: 60000, maxBuffer: 1024 * 1024,
    env: { ...process.env, CC: 'cc', LC_ALL: 'C', LANG: 'C', PYTHONDONTWRITEBYTECODE: '1' } });
}

/** Actual argument parsing only. No namespace is created by --help, and this
 * cannot establish that a tmpfs mount, process boundary or Run is qualified. */
export async function assertBubblewrapRecipeSyntax(binary) {
  const before = await lstat(binary);
  if (!before.isFile() || before.nlink !== 1 || ![0, process.getuid()].includes(before.uid) ||
      (before.mode & 0o6022) !== 0 || (before.mode & 0o111) === 0) throw new Error('The bubblewrap build is not a protected non-setuid executable');
  const bytes = await readFile(binary);
  const result = await command(binary, ['--size', '4096', '--tmpfs', '/', '--help']);
  if (result.stderr.length !== 0 || !result.stdout.includes('--size BYTES')) throw new Error('The fixed bubblewrap recipe syntax is unsupported');
  const after = await lstat(binary);
  for (const field of ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(after[field], before[field]);
  assert((await readFile(binary)).equals(bytes));
  return { sha256: digest(bytes), byteCount: bytes.byteLength };
}

/** Developer/package build only. The official archive is fixed and fully
 * verified before extraction or execution. There is no host-PATH fallback.
 * The original RuntimeBundle publisher signs the actual resulting image. */
export async function buildBubblewrap(outputDirectory, stagingParent, offlineSourceBytes) {
  if (process.platform !== 'linux' || !path.isAbsolute(outputDirectory) || !path.isAbsolute(stagingParent))
    throw new Error('The fixed bubblewrap build requires Linux and absolute owned build directories');
  const work = await mkdtemp(path.join(stagingParent, 'bubblewrap-'));
  try {
    // Offline component builds may supply only these same fully pinned bytes;
    // they cannot select another URL, source, version, flags or executable.
    let archive;
    if (offlineSourceBytes !== undefined) { assertBubblewrapSource(offlineSourceBytes); archive = Buffer.from(offlineSourceBytes); }
    else {
      const response = await fetch(BUBBLEWRAP_SOURCE.url, { signal: AbortSignal.timeout(30000) });
      if (!response.ok || !response.body) {
        await response.body?.cancel();
        throw new Error('The fixed official bubblewrap source could not be downloaded');
      }
      const parts = []; let size = 0;
      try {
        for await (const part of response.body) {
          size += part.byteLength;
          if (size > BUBBLEWRAP_SOURCE.byteCount) throw new Error('The bubblewrap source exceeds its fixed archive length');
          parts.push(Buffer.from(part));
        }
      } catch (error) { await response.body.cancel().catch(() => {}); throw error; }
      archive = Buffer.concat(parts); assertBubblewrapSource(archive);
    }
    const archivePath = path.join(work, 'source.tar.xz'), source = path.join(work, 'source'), build = path.join(work, 'build');
    await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 }); await mkdir(source, { mode: 0o700 });
    // Only the complete pinned upstream archive is accepted. Its two license
    // aliases point to COPYING within this fresh, private extraction tree.
    await command('tar', ['--extract', '--xz', '--file', archivePath, '--directory', source, '--strip-components=1',
      '--no-same-owner', '--no-same-permissions', '--keep-old-files'], work);
    const options = ['--buildtype=release', '--wrap-mode=nodownload', '-Dman=disabled', '-Dtests=false',
      '-Dbash_completion=disabled', '-Dzsh_completion=disabled', '-Dselinux=enabled', '-Dassume_kernel=5.6.0'];
    await command('meson', ['setup', build, source, ...options], work);
    await command('meson', ['compile', '-C', build, '--jobs', '1'], work);
    const built = path.join(build, 'bwrap');
    const image = await assertBubblewrapRecipeSyntax(built);
    const destination = path.join(outputDirectory, 'cliq-linux-bubblewrap');
    await copyFile(built, destination, constants.COPYFILE_EXCL); await chmod(destination, 0o500);
    assert.deepEqual(await assertBubblewrapRecipeSyntax(destination), image);
    const compiler = await command('cc', ['--version'], work), meson = await command('meson', ['--version'], work);
    const libcap = await command('pkg-config', ['--modversion', 'libcap'], work);
    const selinux = await command('pkg-config', ['--modversion', 'libselinux'], work);
    const provenance = { format: 'cliq-bubblewrap-build-provenance-v1', source: BUBBLEWRAP_SOURCE,
      build: { options, jobs: 1, compilerVersion: compiler.stdout, mesonVersion: meson.stdout.trim(), libcapVersion: libcap.stdout.trim(), selinuxVersion: selinux.stdout.trim(),
        environmentFlags: { CFLAGS: process.env.CFLAGS ?? '', CPPFLAGS: process.env.CPPFLAGS ?? '', LDFLAGS: process.env.LDFLAGS ?? '',
          CPATH: process.env.CPATH ?? '', LIBRARY_PATH: process.env.LIBRARY_PATH ?? '' } },
      image, syntaxProbeExecuted: true, namespaceAndTmpfsQualificationClaimed: false, hostFallbackUsed: false, setuidSupported: false };
    await writeFile(path.join(outputDirectory, 'cliq-linux-bubblewrap.provenance.json'), JSON.stringify(provenance, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return provenance;
  } finally { await rm(work, { recursive: true, force: true }); }
}
