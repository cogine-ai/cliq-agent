import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rename, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!['darwin', 'linux'].includes(process.platform)) {
  console.log('StateOwner native helper is unsupported on this platform; Kernel execution remains unavailable.');
  process.exit(0);
}

const repository = fileURLToPath(new URL('../..', import.meta.url));
const printIncludes = process.argv[2] === '--print-includes';
const include = (printIncludes ? undefined : process.argv[2]) ?? path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
// Official Node headers include libuv. Shared-libuv distributions (e.g.
// Homebrew) keep its matching headers under an ancestor's include directory.
// Use the running Node's exact version: a different uv handle layout is unsafe.
async function libuvInclude() {
  const candidates = [process.argv[3], include];
  let ancestor = path.dirname(realpathSync(process.execPath));
  while (ancestor !== path.dirname(ancestor)) {
    candidates.push(path.join(ancestor, 'include'));
    ancestor = path.dirname(ancestor);
  }
  for (const candidate of [...new Set(candidates.filter(Boolean))]) {
    try {
      await readFile(path.join(candidate, 'uv.h'));
      const version = await readFile(path.join(candidate, 'uv/version.h'), 'utf8');
      const observed = ['MAJOR', 'MINOR', 'PATCH'].map(part => version.match(new RegExp(`^#define UV_VERSION_${part}\\s+(\\d+)`, 'm'))?.[1]).join('.');
      if (observed === process.versions.uv) return candidate;
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
    }
  }
  throw new Error(`Matching libuv ${process.versions.uv} headers are required; provide their include directory as the second build argument.`);
}
const uvInclude = await libuvInclude();
// Fault-injection builds use the same header selection as the real helper.
// This read-only query never stages or replaces a loaded native binary.
if (printIncludes) {
  console.log(JSON.stringify([include, uvInclude]));
  process.exit(0);
}
const output = path.join(repository, 'dist/native', `${process.platform}-${process.arch}`);
await mkdir(output, { recursive: true });
const staging = await mkdtemp(path.join(output, '.state-owner-build-'));
try {
  const binary = path.join(staging, 'state-owner.node');
  const flags = process.platform === 'darwin' ? ['-bundle', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC'];
  const compiled = spawnSync('cc', [
    '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', ...flags,
    '-I', include, '-I', uvInclude, path.join(repository, 'native/state-owner/state-owner.c'), '-o', binary
  ], { stdio: 'inherit' });
  if (compiled.error) throw compiled.error;
  if (compiled.status !== 0) throw new Error('StateOwner native build failed; a C compiler and matching Node headers are required.');
  await chmod(binary, 0o500);
  // Never truncate a helper image that another local test process has loaded.
  await rename(binary, path.join(output, 'state-owner.node'));
} finally {
  await rm(staging, { recursive: true, force: true });
}
