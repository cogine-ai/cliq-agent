import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Portable contract seams only. No controller launch or containment claim.
const repository = fileURLToPath(new URL('../..', import.meta.url));
const staging = await mkdtemp(path.join(os.tmpdir(), 'cliq-worker-text-'));
function run(executable, arguments_) {
  const result = spawnSync(executable, arguments_, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Portable native worker contract failed');
}
try {
  for (const name of ['edit-text', 'verifier-node', 'verifier-setup']) {
    const binary = path.join(staging, `${name}-test`);
    run(process.env.CLIQ_WORKER_TEST_CC ?? 'cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      path.join(repository, 'native/linux', `${name}.test.c`), '-o', binary]);
    run(binary, name === 'verifier-node' ? [staging] : []);
  }
} finally { await rm(staging, { recursive: true, force: true }); }
