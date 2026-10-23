import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { constants, realpathSync } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { guestImageLayout, GUEST_IMAGE_MAX_BYTES } from './guest-image-layout.mjs';

// Build/publisher input only. No image is mounted or executed as a verifier,
// no release signature/qualification/Run authority is manufactured here.
if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Guest toolchain build requires the qualified Linux x64 host');
const [output, workerDirectory, nodeSource = process.execPath, ...extra] = process.argv.slice(2);
if (!output || !workerDirectory || extra.length > 1 || extra.length === 1 && extra[0] !== '--qualification-max' ||
    ![output, workerDirectory, nodeSource].every(path.isAbsolute))
  throw new Error('usage: build-linux-guest-toolchain.mjs NEW_ABSOLUTE_OUTPUT_DIRECTORY ABSOLUTE_BUILT_WORKER_DIRECTORY [ABSOLUTE_NODE] [--qualification-max]');
await mkdir(output, { mode: 0o700 });
const staging = await mkdtemp(path.join(output, '.build-'));
const tree = path.join(staging, 'tree');
await mkdir(tree, { mode: 0o700 });
const copied = new Map();
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function command(program, arguments_) {
  const result = spawnSync(program, arguments_, { encoding: 'utf8', timeout: 60_000, maxBuffer: 1_048_576,
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } });
  if (result.error || result.status !== 0) throw new Error(`Guest image build command failed: ${path.basename(program)}`);
  return result.stdout;
}
async function protectedSource(filename) {
  const source = realpathSync(filename), info = await stat(source);
  if (!path.isAbsolute(source) || !info.isFile() || info.size <= 0 || info.size > GUEST_IMAGE_MAX_BYTES ||
      info.mode & 0o022 || info.uid !== 0 && info.uid !== process.getuid()) throw new Error('Guest build source is not a protected regular image');
  return source;
}
async function install(source, target) {
  if (!target.startsWith('/') || target.includes('\\') || path.posix.normalize(target) !== target || target.endsWith('/'))
    throw new Error('Guest image target is not canonical');
  source = await protectedSource(source);
  const bytes = await readFile(source), hash = digest(bytes), prior = copied.get(target);
  if (prior) {
    if (prior.digest !== hash) throw new Error('Guest image has conflicting executable/library paths');
    return prior;
  }
  const destination = path.join(tree, target.slice(1));
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
  await copyFile(source, destination, constants.COPYFILE_EXCL);
  await chmod(destination, 0o555);
  const info = await lstat(destination);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || digest(await readFile(destination)) !== hash)
    throw new Error('Guest image staging failed exact regular-file verification');
  const identity = { path: target, digest: hash, byteCount: bytes.length };
  copied.set(target, identity);
  return identity;
}
async function executable(source, target, logicalName, version) {
  const regular = await protectedSource(source), identity = await install(regular, target);
  const headers = command('/usr/bin/readelf', ['-l', '-d', regular]);
  const dependencies = /\bINTERP\b/u.test(headers) || /\(NEEDED\)/u.test(headers)
    ? command('/usr/bin/ldd', [regular]) : '';
  for (const line of dependencies.split('\n')) {
    const text = line.trim();
    if (!text || /^linux-vdso\.so\.1 \(0x[0-9a-f]+\)$/u.test(text) || text === 'statically linked') continue;
    const dependency = /^(?:[A-Za-z0-9_.+-]+ => )?(\/[^\s]+) \(0x[0-9a-f]+\)$/u.exec(text);
    if (!dependency) throw new Error('Guest dependency resolver returned an unsupported or unresolved library');
    await install(dependency[1], dependency[1]);
  }
  return { logicalName, canonicalGuestPath: target, digest: identity.digest, version };
}
try {
  const selectedNode = await protectedSource(nodeSource);
  const nodeVersion = command(selectedNode, ['--version']).trim();
  if (nodeVersion !== 'v24.21.0') throw new Error('Guest image requires the exact qualified Node v24.21.0');
  const worker = await executable(path.join(workerDirectory, 'cliq-linux-worker'), '/runtime/cliq-linux-worker', 'cliq-worker', '1');
  const shellSource = await protectedSource('/bin/sh');
  // The source binary is measured; its build-host pathname/version text never
  // becomes runtime lookup authority. The staged /bin/sh is a regular file.
  const shell = await executable(shellSource, '/bin/sh', 'sh', digest(await readFile(shellSource)));
  const gitSource = await protectedSource('/usr/bin/git');
  const gitVersion = command(gitSource, ['--version']).trim();
  if (!/^git version [A-Za-z0-9.+_-]+$/u.test(gitVersion)) throw new Error('Guest Git version is not bounded fixed output');
  const git = await executable(gitSource, '/usr/bin/git', 'git', gitVersion);
  const node = await executable(selectedNode, '/usr/bin/node', 'node', nodeVersion.slice(1));
  const files = [...copied.values()].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const totalBytes = files.reduce((sum, file) => sum + file.byteCount, 0);
  if (files.length > 32)
    throw new Error('Actual guest toolchain cannot fit the fixed image/file bound');
  const imageLayout = guestImageLayout(totalBytes, extra.length ? 'qualification_max' : 'compact');
  const { imageByteCount } = imageLayout;
  const filename = path.join(staging, 'guest-toolchain.ext4');
  const image = await open(filename, 'wx', 0o600);
  try { await image.truncate(imageByteCount); await image.sync(); } finally { await image.close(); }
  command('/usr/sbin/mke2fs', ['-q', '-t', 'ext4', '-b', '4096', '-O', '^has_journal,metadata_csum', '-E', 'lazy_itable_init=0', '-d', tree, filename]);
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let imageDigest;
  try {
    const hash = createHash('sha256'), bytes = Buffer.alloc(65_536); let offset = 0;
    for (;;) {
      const read = await handle.read(bytes, 0, bytes.length, offset);
      if (!read.bytesRead) break;
      hash.update(bytes.subarray(0, read.bytesRead)); offset += read.bytesRead;
    }
    if (offset !== imageByteCount) throw new Error('Raw guest image is not complete');
    imageDigest = hash.digest('hex');
  } finally { await handle.close(); }
  await chmod(filename, 0o400);
  const metadata = { schemaVersion: 1, format: 'cliq-guest-toolchain-publisher-input-v1',
    guestImageRef: imageDigest, guestImageDigest: imageDigest, guestImageByteCount: imageByteCount,
    guestImageFormat: 'raw-ext4-v1', architecture: 'x86_64', kernelAbi: 'linux-x86_64-v1',
    userspaceAbi: 'linux-x86_64-glibc-v1', worker, shell, git, node,
    searchTools: [], verifiers: [], admittedExecutables: [], files, extractedFileBytes: totalBytes, imageLayout,
    scope: 'actual build bytes only; not release-signed, execution-qualified or a Run proof' };
  const metadataFile = path.join(staging, 'guest-toolchain-input.json');
  await writeFile(metadataFile, JSON.stringify(metadata), { flag: 'wx', mode: 0o400 });
  await rename(filename, path.join(output, 'guest-toolchain.ext4'));
  await rename(metadataFile, path.join(output, 'guest-toolchain-input.json'));
} finally { await rm(staging, { recursive: true, force: true }); }
