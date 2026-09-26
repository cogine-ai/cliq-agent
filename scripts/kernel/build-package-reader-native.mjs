import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!['darwin', 'linux'].includes(process.platform)) {
  process.stdout.write('RuntimeBundle native package reader is unsupported on this platform.\n');
  process.exit(0);
}

const repository = fileURLToPath(new URL('../..', import.meta.url));
const include = process.argv[2] ?? path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
const output = path.join(repository, 'dist/native', `${process.platform}-${process.arch}`);
await mkdir(output, { recursive: true });
const staging = await mkdtemp(path.join(output, '.package-reader-build-'));
try {
  const binary = path.join(staging, 'package-reader.node');
  const flags = process.platform === 'darwin' ? ['-bundle', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC'];
  const compiled = spawnSync('cc', [
    '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', ...flags,
    '-I', include, path.join(repository, 'native/runtime-bundle/package-reader.c'), '-o', binary
  ], { stdio: 'inherit', timeout: 30_000 });
  if (compiled.error) throw compiled.error;
  if (compiled.status !== 0) throw new Error('RuntimeBundle native package reader build failed.');
  await chmod(binary, 0o500);
  await rename(binary, path.join(output, 'package-reader.node'));
} finally {
  await rm(staging, { recursive: true, force: true });
}
