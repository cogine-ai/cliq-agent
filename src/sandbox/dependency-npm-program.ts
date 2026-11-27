// One signed, non-executable JS adapter interpreted by the exact signed Node.
// Native claim/release, mount/exec policy and whole-domain join remain outside
// this program. There is no host execution fallback or caller-selected path.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { constants as osConstants } from 'node:os';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { decodeDependencyNpmInput, type DependencyNpmInputV1 } from './dependency-npm-data.js';
import { fixedDependencyNpmPackageInputs } from './dependency-npm-package-input.js';
import { NPM_DATA_RECIPE } from './npm-data-image.js';
import { NPM_DEPENDENCY_RECIPE } from './dependency-recipe.js';
import { assertFixedNpmProjectConfigAbsent } from './dependency-npm-config.js';

// This standalone program is Linux-only (checked before opening any path).
// Node omits O_CLOEXEC from its public constants while Linux fixes this value.
const CLOEXEC = 0o2000000;

const sameStat = (before: ReturnType<typeof fstatSync>, after: ReturnType<typeof fstatSync>) => {
  for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'nlink', 'mtimeMs', 'ctimeMs'] as const)
    if (before[key] !== after[key]) throw new TypeError('fixed dependency input changed');
};
function fixedInput(): DependencyNpmInputV1 {
  try {
    const before = fstatSync(3);
    if (!before.isFile() || before.size < 1 || before.size > 1_048_576) throw new TypeError('fixed dependency input size');
    const bytes = Buffer.alloc(before.size); let offset = 0;
    while (offset < bytes.length) { const n = readSync(3, bytes, offset, bytes.length - offset, offset); if (!n) throw new TypeError('short fixed input'); offset += n; }
    if (readSync(3, Buffer.alloc(1), 0, 1, offset) !== 0) throw new TypeError('long fixed input');
    sameStat(before, fstatSync(3)); return decodeDependencyNpmInput(bytes);
  } finally { closeSync(3); }
}
function confined(): void {
  if (process.platform !== 'linux' || process.pid !== 2 || process.ppid !== 1 || process.getuid!() !== 0 || process.getgid!() !== 0 ||
      process.cwd() !== '/work' || process.umask() !== 0o022 || process.argv.length !== 2 || process.execArgv.length !== 1 || process.execArgv[0] !== '--no-addons') throw new TypeError('fixed dependency guest required');
  const status = readFileSync('/proc/self/status', 'utf8');
  if (Buffer.byteLength(status) > 16_384 || !/^NoNewPrivs:\s+1$/mu.test(status) ||
      ['CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'].some(key => !new RegExp(`^${key}:\\s+0+$`, 'mu').test(status))) throw new TypeError('fixed dependency confinement differs');
  const expected = NPM_DEPENDENCY_RECIPE.environment;
  if (Object.keys(process.env).length !== Object.keys(expected).length || Object.entries(expected).some(([key, value]) => process.env[key] !== value)) throw new TypeError('fixed dependency environment differs');
  // --userconfig and --globalconfig alone do NOT disable npm's project file.
  // The native recipe holds /work read-only throughout this exact check+use.
  assertFixedNpmProjectConfigAbsent();
  for (const path of ['/runtime/npm-config/user', '/runtime/npm-config/global']) {
    const fd = openSync(path, constants.O_RDONLY | CLOEXEC | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try { const before = fstatSync(fd); if (!before.isFile() || before.nlink !== 1 || before.size !== 0 || readSync(fd, Buffer.alloc(1), 0, 1, 0) !== 0) throw new TypeError('npm config is not empty'); sameStat(before, fstatSync(fd)); }
    finally { closeSync(fd); }
  }
}
async function checkRootFile(path: '/work/package.json' | '/work/package-lock.json' | '/work/binding.gyp', digest: string): Promise<void> {
  const file = await open(path, constants.O_RDONLY | CLOEXEC | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat(), maximum = path === '/work/binding.gyp' ? 268_435_456 : 1_048_576;
    if (!before.isFile() || before.nlink !== 1 || before.uid !== process.getuid!() || before.size < (path === '/work/binding.gyp' ? 0 : 1) || before.size > maximum)
      throw new TypeError('fixed root package file');
    sameStat(before, await lstat(path));
    const bytes = Buffer.alloc(Math.min(65_536, Math.max(1, before.size))), hash = createHash('sha256'); let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await file.read(bytes, 0, Math.min(bytes.length, before.size - offset), offset);
      if (!bytesRead) throw new TypeError('short root input'); hash.update(bytes.subarray(0, bytesRead)); offset += bytesRead;
    }
    if ((await file.read(Buffer.alloc(1), 0, 1, offset)).bytesRead || hash.digest('hex') !== digest) throw new TypeError('root package input differs');
    sameStat(before, await file.stat()); sameStat(before, await lstat(path));
  } finally { await file.close(); }
}
async function execute(): Promise<void> {
  confined(); const input = fixedInput();
  await checkRootFile('/work/package.json', input.packageManifestDigest);
  await checkRootFile('/work/package-lock.json', input.lockfileDigest);
  if (input.bindingGyp.kind === 'present') await checkRootFile('/work/binding.gyp', input.bindingGyp.contentDigest);
  else {
    let present = false;
    try { await lstat('/work/binding.gyp'); present = true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (present) throw new TypeError('fixed binding.gyp absence differs');
  }
  // This resolution is rooted only in the already completely verified signed
  // npm image. It never uses workspace node_modules, host npm or NODE_PATH.
  const cacache = createRequire('/runtime/npm/package.json')('cacache') as { put: { stream(path: string, key: string,
    options: { algorithms: string[]; integrity: string }): NodeJS.WritableStream } };
  // FD4 was made and sealed by the same native owner from its original
  // registered descriptors plus actual successful GET facts. Its framing is
  // bounded per record; no complete graph is reparsed as one JSON value.
  for (const entry of fixedDependencyNpmPackageInputs(input)) {
    const path = `/scratch/package-cache/${entry.blobSha256}.tgz`;
    const file = await open(path, constants.O_RDONLY | CLOEXEC | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await file.stat();
      if (!before.isFile() || before.nlink !== 1 || before.size !== entry.blobBytes) throw new TypeError('fixed cached package metadata differs');
      const hash = createHash('sha256'), integrity = createHash(entry.integrityAlgorithm);
      async function* bytes() {
        const chunk = Buffer.alloc(65_536); let offset = 0;
        while (offset < entry.blobBytes) {
          const { bytesRead } = await file.read(chunk, 0, Math.min(chunk.length, entry.blobBytes - offset), offset);
          if (!bytesRead) throw new TypeError('short cached package');
          offset += bytesRead; hash.update(chunk.subarray(0, bytesRead)); integrity.update(chunk.subarray(0, bytesRead));
          yield Buffer.from(chunk.subarray(0, bytesRead));
        }
        if ((await file.read(chunk, 0, 1, offset)).bytesRead || hash.digest('hex') !== entry.blobSha256 || integrity.digest('base64') !== entry.integrityDigest) throw new TypeError('cached package integrity differs');
        sameStat(before, await file.stat());
      }
      await pipeline(Readable.from(bytes()), cacache.put.stream('/scratch/npm-cache/_cacache', `cliq:${entry.blobSha256}`,
        { algorithms: [entry.integrityAlgorithm], integrity: `${entry.integrityAlgorithm}-${entry.integrityDigest}` }));
    } finally { await file.close(); }
  }
  // A malformed or unjoined suffix can only leave private cache data: no
  // npm process or root/dependency lifecycle can start before full EOF/join.
  const child = spawn('/usr/bin/node', ['--no-addons', NPM_DATA_RECIPE.cliPath, 'ci', '--offline=true',
    `--ignore-scripts=${!input.allowInstallScripts}`, '--audit=false', '--fund=false', '--update-notifier=false', '--fetch-retries=0',
    '--cache=/scratch/npm-cache', '--userconfig=/runtime/npm-config/user', '--globalconfig=/runtime/npm-config/global',
    '--script-shell=/bin/bash', '--node-options=', '--include=dev', '--include=peer', '--include=optional', '--no-save'], {
    cwd: '/work', env: NPM_DEPENDENCY_RECIPE.environment, stdio: ['ignore', 'inherit', 'inherit'] });
  const ended = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    let failure: Error | undefined;
    child.once('error', error => { failure = error; });
    child.once('close', (code, signal) => failure ? reject(failure) : resolve({ code, signal }));
  });
  process.exitCode = ended.signal ? 128 + osConstants.signals[ended.signal] : ended.code ?? 70;
}
await execute().catch(() => { process.stderr.write('FIXED_DEPENDENCY_EXECUTION_FAILED\n'); process.exitCode = 70; });
