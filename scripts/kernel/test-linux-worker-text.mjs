import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Portable contract seam only. No controller launch or containment claim.
const repository = fileURLToPath(new URL('../..', import.meta.url));
const staging = await mkdtemp(path.join(os.tmpdir(), 'cliq-worker-text-'));
function run(executable, arguments_) {
  const result = spawnSync(executable, arguments_, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Builtin edit native text contract failed');
}
try {
  const binary = path.join(staging, 'edit-text-test');
  run(process.env.CLIQ_WORKER_TEST_CC ?? 'cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
    path.join(repository, 'native/linux/edit-text.test.c'), '-o', binary]);
  run(binary, []);
} finally { await rm(staging, { recursive: true, force: true }); }
