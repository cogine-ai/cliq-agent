import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rename, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildBubblewrap } from './build-bubblewrap.mjs';

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
  // Guest-only helper: ordinary worker/edit loading never links libext2fs.
  // Its protected OS library dependencies follow the existing GIO helper
  // build model; the guest itself receives only same-image extracted files.
  const ext2 = spawnSync('pkg-config', ['--cflags', '--libs', 'ext2fs'], { encoding: 'utf8', timeout: 10000 });
  if (ext2.error || ext2.status !== 0 || ext2.stdout.length > 8192)
    throw new Error('The guest extractor needs the actual libext2fs development package');
  const extractor = path.join(staging, 'linux-guest-extractor.node');
  compile(process.env.CLIQ_WORKER_ADDON_CC ?? 'cc', [
    '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-pthread', '-I', include,
    path.join(repository, 'native/linux/guest-extractor.c'), '-o', extractor,
    ...ext2.stdout.trim().split(/\s+/u), '-lcom_err'
  ]);
  await chmod(extractor, 0o500);
  await rename(extractor, path.join(output, 'linux-guest-extractor.node'));
  const bubblewrap = await buildBubblewrap(output, staging);
  console.log(`LINUX_BUBBLEWRAP_SOURCE_VERSION=${bubblewrap.source.version}`);
  console.log(`LINUX_BUBBLEWRAP_SOURCE_SHA256=${bubblewrap.source.sha256}`);
  console.log(`LINUX_BUBBLEWRAP_IMAGE_SHA256=${bubblewrap.image.sha256}`);
  console.log(`LINUX_BUBBLEWRAP_IMAGE_BYTES=${bubblewrap.image.byteCount}`);
} finally {
  await rm(staging, { recursive: true, force: true });
}
console.log(`LINUX_WORKER_INSTALLATION=${output}`);
const entries = [];
for (const [entryId, role, relativePath] of [
  ['linux_worker_native', 'platform_helper', 'linux-worker.node'],
  ['linux_guest_extractor', 'platform_helper', 'linux-guest-extractor.node'],
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
