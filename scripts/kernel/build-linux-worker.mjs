import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildBubblewrap, createWorkerBuildScope } from './build-bubblewrap.mjs';

// An independent production build. Never modifies the loaded StateOwner addon
// or the disposable execution probe installation.
if (process.platform !== 'linux') throw new Error('Production Linux worker images must be built on Linux');
const repository = fileURLToPath(new URL('../..', import.meta.url));
const output = process.argv[2];
if (!output || !path.isAbsolute(output)) throw new Error('usage: build-linux-worker.mjs ABSOLUTE_NEW_OUTPUT_DIRECTORY');
// Preserve the original new-output reservation: an old partial/prebuilt set
// can never become successful input to this invocation.
await mkdir(output, { recursive: false, mode: 0o700 });
const reservation = await lstat(output);
const scope = createWorkerBuildScope();
let staging, bubblewrap, entries;
const tasks = [];
const guard = promise => promise.catch(error => { scope.abort(error); throw error; });
try {
  // A sibling is on the same filesystem. Final rename replaces only our
  // original, still-empty reservation; it never renames a child over a parent.
  staging = await mkdtemp(path.join(path.dirname(output), '.cliq-worker-build-'));
  const images = path.join(staging, 'images');
  await mkdir(images, { mode: 0o700 });
  const include = process.argv[3] ?? path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
  const compiler = process.env.CLIQ_WORKER_CC ?? 'musl-gcc';
  const addonCompiler = process.env.CLIQ_WORKER_ADDON_CC ?? 'cc';
  async function compile(binary, arguments_, name) {
    await scope.run(binary, arguments_, { inherit: true });
    await chmod(path.join(images, name), 0o500);
  }
  async function nativeImages() {
    const [triple, ext2] = await Promise.all([
      scope.run(compiler, ['-dumpmachine']),
      scope.run('pkg-config', ['--cflags', '--libs', 'ext2fs'], { timeout: 10000 }),
    ]);
    if (!/^[a-z0-9_-]+\n?$/u.test(triple.stdout)) throw new Error('Cannot resolve the Linux compiler header architecture');
    if (ext2.stdout.length > 8192) throw new Error('The guest extractor needs the actual libext2fs development package');
    const kernelIncludes = ['-idirafter', '/usr/include', '-idirafter', path.join('/usr/include', triple.stdout.trim())];
    const staticImage = name => compile(compiler, [
      '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-fno-ident',
      ...kernelIncludes,
      `-ffile-prefix-map=${repository}=.`, '-Wl,--build-id=none', '-s',
      path.join(repository, 'native/linux', `${name}.c`), '-o', path.join(images, name),
    ], name);
    // Queue the two large translation units first. The same fixed two lanes
    // also service every sequential Bubblewrap command (Meson keeps jobs=1).
    const builds = [
      guard(staticImage('cliq-linux-worker-controller')),
      guard(compile(addonCompiler, [
        '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-I', include,
        path.join(repository, 'native/linux/worker-native.c'), '-o', path.join(images, 'linux-worker.node'),
      ], 'linux-worker.node')),
      guard(staticImage('cliq-linux-worker')),
      guard(staticImage('cliq-linux-edit')),
      // Guest-only helper: ordinary worker/edit loading never links libext2fs.
      // Its protected OS library dependencies follow the existing GIO helper
      // build model; the guest receives only same-image extracted files.
      guard(compile(addonCompiler, [
        '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-pthread', '-I', include,
        path.join(repository, 'native/linux/guest-extractor.c'), '-o', path.join(images, 'linux-guest-extractor.node'),
        ...ext2.stdout.trim().split(/\s+/u), '-lcom_err',
      ], 'linux-guest-extractor.node')),
    ];
    const results = await Promise.allSettled(builds);
    const failure = results.find(result => result.status === 'rejected');
    if (failure) throw failure.reason;
  }
  // Source download starts while native work is active; extraction/configure/
  // compile/probes still acquire the very same two process slots.
  tasks.push(guard(nativeImages()), guard(buildBubblewrap(images, staging, undefined, scope)));
  const results = await Promise.allSettled(tasks);
  const failure = results.find(result => result.status === 'rejected');
  if (failure) throw failure.reason;
  bubblewrap = results[1].value;
  await scope.join();
  scope.assertActive();
  entries = [];
  for (const [entryId, role, relativePath] of [
    ['linux_worker_native', 'platform_helper', 'linux-worker.node'],
    ['linux_guest_extractor', 'platform_helper', 'linux-guest-extractor.node'],
    ['linux_worker_controller', 'platform_helper', 'cliq-linux-worker-controller'],
    ['linux_bubblewrap', 'platform_helper', 'cliq-linux-bubblewrap'],
    ['linux_worker', 'worker', 'cliq-linux-worker'],
    ['edit', 'tool_adapter', 'cliq-linux-edit'],
  ]) {
    const bytes = await readFile(path.join(images, relativePath));
    entries.push({ entryId, role, relativePath, version: '1', executable: true,
      digest: createHash('sha256').update(bytes).digest('hex'), byteCount: bytes.length });
  }
  const current = await lstat(output);
  if (!current.isDirectory() || ['dev', 'ino', 'uid', 'gid', 'mode'].some(field => current[field] !== reservation[field]) ||
      (await readdir(output)).length) throw new Error('The original empty worker output reservation changed');
  scope.assertActive();
  // POSIX directory rename atomically replaces an existing EMPTY directory.
  // No unlink/remove gap, existing image adoption or per-image early publish.
  await rename(images, output);
} catch (error) { scope.abort(error); throw error; }
finally {
  await Promise.allSettled(tasks);
  try { await scope.join(); scope.assertActive(); }
  finally {
    scope.dispose();
    // Uncertain process-group retirement keeps its private work for recovery;
    // no build/installation success is emitted on that branch.
    if (staging && scope.retired()) await rm(staging, { recursive: true, force: true });
  }
}
console.log(`LINUX_BUBBLEWRAP_SOURCE_VERSION=${bubblewrap.source.version}`);
console.log(`LINUX_BUBBLEWRAP_SOURCE_SHA256=${bubblewrap.source.sha256}`);
console.log(`LINUX_BUBBLEWRAP_IMAGE_SHA256=${bubblewrap.image.sha256}`);
console.log(`LINUX_BUBBLEWRAP_IMAGE_BYTES=${bubblewrap.image.byteCount}`);
console.log(`LINUX_WORKER_INSTALLATION=${output}`);
console.log(`LINUX_WORKER_ENTRIES=${JSON.stringify(entries)}`);
console.log('Images are built, not qualified or release-signed. Publish their actual digests through the existing RuntimeBundle release authority.');
