import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

if (!['darwin', 'linux'].includes(process.platform)) {
  process.stdout.write('Native local control is unavailable on this platform.\n');
  process.exit(0);
}

const repository = fileURLToPath(new URL('../..', import.meta.url));
const output = path.join(repository, 'dist/native', `${process.platform}-${process.arch}`);
await mkdir(output, { recursive: true });
const staging = await mkdtemp(path.join(output, '.control-listener-build-'));
try {
  const binary = path.join(staging, 'control-listener');
  const source = path.join(repository, 'native/control/control-listener.c');
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', binary], {
    stdio: 'inherit', timeout: 30_000
  });
  if (compiled.error) throw compiled.error;
  if (compiled.status !== 0) throw new Error('Native local control listener build failed.');
  await chmod(binary, 0o500);
  await rename(binary, path.join(output, 'control-listener'));
} finally {
  await rm(staging, { recursive: true, force: true });
}
