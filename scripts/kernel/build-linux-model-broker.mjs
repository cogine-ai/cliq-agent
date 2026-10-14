import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Separate signed provider image. The ordinary credential-platform build has
// no OpenSSL dependency and does not expose this native transport interface.
if (process.platform !== 'linux' || process.arch !== 'x64')
  throw new Error('Linux model broker requires the qualified Linux x64 build host');
const [output, headers = path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node'), ...extra] = process.argv.slice(2);
if (!output || !path.isAbsolute(output) || !path.isAbsolute(headers) || extra.length)
  throw new Error('usage: build-linux-model-broker.mjs ABSOLUTE_NEW_OUTPUT_DIRECTORY [ABSOLUTE_NODE_HEADERS]');
const repository = fileURLToPath(new URL('../..', import.meta.url));
const flags = spawnSync('pkg-config', ['--cflags', '--libs', 'gio-2.0', 'openssl'], { encoding: 'utf8', timeout: 10000 });
if (flags.error || flags.status !== 0)
  throw new Error('Linux model broker needs the actual GIO and OpenSSL development packages');
await mkdir(output, { mode: 0o700 });
const staging = await mkdtemp(path.join(output, '.build-'));
try {
  const binary = path.join(staging, 'linux-model-broker.node');
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
    '-pthread', '-shared', '-fPIC', '-DCLIQ_MODEL_BROKER_MODULE', '-I', headers,
    path.join(repository, 'native/linux/credential-platform.c'), '-o', binary,
    ...flags.stdout.trim().split(/\s+/u)], { stdio: 'inherit', timeout: 60000 });
  if (compiled.error || compiled.status !== 0) throw new Error('Linux model broker compilation failed');
  await chmod(binary, 0o500);
  await rename(binary, path.join(output, 'linux-model-broker.node'));
} finally { await rm(staging, { recursive: true, force: true }); }
