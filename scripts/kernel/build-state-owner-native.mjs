import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!['darwin', 'linux'].includes(process.platform)) {
  console.log('StateOwner native helper is unsupported on this platform; Kernel execution remains unavailable.');
  process.exit(0);
}

const repository = fileURLToPath(new URL('../..', import.meta.url));
const include = process.argv[2] ?? path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
const output = path.join(repository, 'dist/native', `${process.platform}-${process.arch}`);
await mkdir(output, { recursive: true });
const staging = await mkdtemp(path.join(output, '.state-owner-build-'));
try {
  const binary = path.join(staging, 'state-owner.node');
  const flags = process.platform === 'darwin' ? ['-bundle', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC'];
  const compiled = spawnSync('cc', [
    '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', ...flags,
    '-I', include, path.join(repository, 'native/state-owner/state-owner.c'), '-o', binary
  ], { stdio: 'inherit' });
  if (compiled.error) throw compiled.error;
  if (compiled.status !== 0) throw new Error('StateOwner native build failed; a C compiler and matching Node headers are required.');
  await chmod(binary, 0o500);
  // Never truncate a helper image that another local test process has loaded.
  await rename(binary, path.join(output, 'state-owner.node'));
} finally {
  await rm(staging, { recursive: true, force: true });
}
