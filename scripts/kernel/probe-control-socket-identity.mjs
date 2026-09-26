import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Use a short, real temporary path: sockaddr_un is only 104 bytes on macOS.
// Nothing in the user's StateRoot or installed runtime is opened.
if (!['darwin', 'linux'].includes(process.platform)) {
  throw new Error(`Unix socket characterization is unsupported on ${process.platform}`);
}
const scratch = await mkdtemp(path.join(await realpath('/tmp'), 'cliq-uds-'));
try {
  const binary = path.join(scratch, 'socket-identity-probe');
  const source = fileURLToPath(new URL('../../native/control/socket-identity-probe.c', import.meta.url));
  const build = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-o', binary], {
    encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024
  });
  if (build.error || build.status !== 0) throw new Error(`Socket probe build failed: ${build.error?.message ?? build.stderr}`);
  const result = spawnSync(binary, [scratch], { encoding: 'utf8', timeout: 10_000, maxBuffer: 64 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`Socket probe failed: ${result.error?.message ?? result.stderr}`);
  process.stdout.write(result.stdout);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
