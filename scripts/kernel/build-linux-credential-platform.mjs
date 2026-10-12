import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Production recipe. GIO is needed only for this separate Linux image, never
// for StateOwner builds or ordinary credential metadata reads/replays.
if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Linux credential platform requires the qualified Linux x64 build host');
const [output, headers = path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node'), ...extra] = process.argv.slice(2);
if (!output || !path.isAbsolute(output) || !path.isAbsolute(headers) || extra.length)
  throw new Error('usage: build-linux-credential-platform.mjs ABSOLUTE_NEW_OUTPUT_DIRECTORY [ABSOLUTE_NODE_HEADERS]');
const repository = fileURLToPath(new URL('../..', import.meta.url));
const flags = spawnSync('pkg-config', ['--cflags', '--libs', 'gio-2.0'], { encoding: 'utf8', timeout: 10000 });
if (flags.error || flags.status !== 0) throw new Error('Linux credential platform needs the actual GIO development package');
await mkdir(output, { mode: 0o700 });
const staging = await mkdtemp(path.join(output, '.build-'));
try {
  const binary = path.join(staging, 'linux-credential-platform.node');
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-shared', '-fPIC',
    '-I', headers, path.join(repository, 'native/linux/credential-platform.c'), '-o', binary,
    ...flags.stdout.trim().split(/\s+/u)], { stdio: 'inherit', timeout: 60000 });
  if (compiled.error || compiled.status !== 0) throw new Error('Linux credential platform compilation failed');
  await chmod(binary, 0o500);
  await rename(binary, path.join(output, 'linux-credential-platform.node'));
} finally { await rm(staging, { recursive: true, force: true }); }
