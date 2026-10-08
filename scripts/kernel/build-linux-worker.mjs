import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rename, rm, stat } from 'node:fs/promises';
import { constants, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// An independent production build. Never modifies the loaded StateOwner addon
// or the disposable execution probe installation.
if (process.platform !== 'linux') throw new Error('Production Linux worker images must be built on Linux');
const repository = fileURLToPath(new URL('../..', import.meta.url));
const output = process.argv[2];
if (!output || !path.isAbsolute(output)) throw new Error('usage: build-linux-worker.mjs ABSOLUTE_NEW_OUTPUT_DIRECTORY');
await mkdir(output, { recursive: false, mode: 0o700 });
const staging = await mkdtemp(path.join(output, '.build-'));
const include = process.argv[3] ?? path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
const compiler = process.env.CLIQ_WORKER_CC ?? 'musl-gcc';
const triple = spawnSync(compiler, ['-dumpmachine'], { encoding: 'utf8' });
if (triple.status !== 0 || !/^[a-z0-9_-]+\n?$/u.test(triple.stdout ?? '')) throw new Error('Cannot resolve the Linux compiler header architecture');
const kernelIncludes = ['-idirafter', '/usr/include', '-idirafter', path.join('/usr/include', triple.stdout.trim())];
function compile(compiler, arguments_) {
  const result = spawnSync(compiler, arguments_, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Linux production worker compilation failed');
}
try {
  for (const name of ['cliq-linux-worker-controller', 'cliq-linux-worker', 'cliq-linux-edit']) {
    const binary = path.join(staging, name);
    compile(compiler, [
      '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-fno-ident',
      ...kernelIncludes,
      `-ffile-prefix-map=${repository}=.`, '-Wl,--build-id=none', '-s',
      path.join(repository, 'native/linux', `${name}.c`), '-o', binary
    ]);
    await chmod(binary, 0o500);
    await rename(binary, path.join(output, name));
  }
  const addon = path.join(staging, 'linux-worker.node');
  compile(process.env.CLIQ_WORKER_ADDON_CC ?? 'cc', [
    '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-I', include,
    path.join(repository, 'native/linux/worker-native.c'), '-o', addon
  ]);
  await chmod(addon, 0o500);
  await rename(addon, path.join(output, 'linux-worker.node'));
  let bubblewrap;
  for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!path.isAbsolute(directory)) continue;
    try {
      const candidate = realpathSync(path.join(directory, 'bwrap'));
      const metadata = await stat(candidate);
      if (metadata.isFile() && (metadata.mode & 0o111) !== 0 && (metadata.mode & 0o022) === 0) { bubblewrap = candidate; break; }
    } catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error; }
  }
  if (!bubblewrap) throw new Error('A protected installed bubblewrap executable is required');
  await copyFile(bubblewrap, path.join(output, 'cliq-linux-bubblewrap'), constants.COPYFILE_EXCL);
  await chmod(path.join(output, 'cliq-linux-bubblewrap'), 0o500);
} finally {
  await rm(staging, { recursive: true, force: true });
}
console.log(`LINUX_WORKER_INSTALLATION=${output}`);
const entries = [];
for (const [entryId, role, relativePath] of [
  ['linux_worker_native', 'platform_helper', 'linux-worker.node'],
  ['linux_worker_controller', 'platform_helper', 'cliq-linux-worker-controller'],
  ['linux_bubblewrap', 'platform_helper', 'cliq-linux-bubblewrap'],
  ['linux_worker', 'worker', 'cliq-linux-worker'],
  ['edit', 'tool_adapter', 'cliq-linux-edit']
]) {
  const bytes = await readFile(path.join(output, relativePath));
  entries.push({ entryId, role, relativePath, version: '1', executable: true,
    digest: createHash('sha256').update(bytes).digest('hex'), byteCount: bytes.length });
}
console.log(`LINUX_WORKER_ENTRIES=${JSON.stringify(entries)}`);
console.log('Images are built, not qualified or release-signed. Publish their actual digests through the existing RuntimeBundle release authority.');
