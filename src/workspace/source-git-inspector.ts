// This entry point is bundled as the one measured source_git_inspector asset.
// It runs only after the original source native owner seals input and the
// second SQL fence releases this fixed program. It is not a host Git adapter.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, readSync } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { decodeSandboxResourceOptions } from '../kernel/control-submit.js';
import type { SandboxResourceSpec } from '../kernel/execution.js';
import { sha256Bytes } from '../kernel/identity.js';
import { normalizeGitIndex } from './git-index.js';
import { classifySourceGitConfig, sanitizedGitConfigText } from './source-git-config.js';
import { decodeSourceGitInspectionOutput, sourceGitObjectId, sourceGitRefName, type SourceGitInspectionOutputV1 } from './source-git-output.js';

const INPUT = '/scratch/input', REPOSITORY = '/scratch/repository', OUTPUT = '/scratch/output';
const ENV = Object.freeze({ HOME: '/scratch/home', TMPDIR: '/scratch/tmp', PATH: '/usr/bin', LANG: 'C', LC_ALL: 'C',
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ATTR_NOSYSTEM: '1',
  GIT_OPTIONAL_LOCKS: '0', GIT_NO_REPLACE_OBJECTS: '1', GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: '', GIT_PROTOCOL_FROM_USER: '0' });
function refused(): never { throw new TypeError('fixed source Git inspection failed'); }
const sorted = (left: string, right: string) => Buffer.compare(Buffer.from(left), Buffer.from(right));
function dataFd(fd: 3 | 4, maximum: number): Buffer {
  let failure: unknown, result: Buffer | undefined;
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.size < 0n || before.size > BigInt(maximum)) refused();
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const got = readSync(fd, bytes, offset, bytes.length - offset, offset); if (!got) refused(); offset += got; }
    if (readSync(fd, Buffer.alloc(1), 0, 1, bytes.length) !== 0) refused();
    const after = fstatSync(fd, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mode !== after.mode || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) refused();
    result = bytes;
  } catch (error) { failure = error; }
  try { closeSync(fd); } catch { refused(); }
  if (failure !== undefined) throw failure;
  return result!;
}
type InputIntent = { schemaVersion: 1; recipe: 'cliq-source-git-inspection-v1' | 'cliq-private-git-preparation-v1';
  repositoryIdentityDigest: string; resources: SandboxResourceSpec };
function intent(bytes: Buffer): InputIntent {
  let value: InputIntent;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return refused(); }
  if (!canonicalJsonBytes(value).equals(bytes) || !value || Object.keys(value).sort().join() !== 'recipe,repositoryIdentityDigest,resources,schemaVersion' ||
      value.schemaVersion !== 1 || value.recipe !== 'cliq-source-git-inspection-v1' && value.recipe !== 'cliq-private-git-preparation-v1' || typeof value.repositoryIdentityDigest !== 'string' ||
      value.repositoryIdentityDigest.length !== 64 || !/^[0-9a-f]+$/u.test(value.repositoryIdentityDigest)) refused();
  const resources = decodeSandboxResourceOptions(value.resources);
  if (canonicalJsonBytes(resources).compare(canonicalJsonBytes(value.resources)) !== 0) refused();
  return { ...value, resources };
}
async function boundedFile(filename: string, maximum: number): Promise<Buffer> {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let failure: unknown, result: Buffer | undefined;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) refused();
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const read = await handle.read(bytes, offset, bytes.length - offset, offset); if (!read.bytesRead) refused(); offset += read.bytesRead; }
    if ((await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead !== 0) refused();
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mode !== after.mode ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) refused();
    result = bytes;
  } catch (error) { failure = error; }
  try { await handle.close(); } catch { refused(); }
  if (failure !== undefined) throw failure;
  return result!;
}
async function fileDigest(filename: string, maximum: number) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let failure: unknown, result: { byteCount: number; sha256: string } | undefined;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) refused();
    const hash = createHash('sha256'), buffer = Buffer.alloc(65_536); let count = 0;
    for (;;) { const read = await handle.read(buffer, 0, buffer.length, count); if (!read.bytesRead) break;
      hash.update(buffer.subarray(0, read.bytesRead)); count += read.bytesRead; if (count > maximum) refused(); }
    const after = await handle.stat({ bigint: true });
    if (BigInt(count) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.mode !== after.mode ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) refused();
    result = { byteCount: count, sha256: hash.digest('hex') };
  } catch (error) { failure = error; }
  try { await handle.close(); } catch { refused(); }
  if (failure !== undefined) throw failure;
  return result!;
}

/** Only fixed plumbing below calls this private transport. Error text is
 * always discarded; all three pipes and actual child close are joined. */
async function git(args: readonly string[], resources: SandboxResourceSpec, input?: Buffer,
  output?: 'reachable.pack'): Promise<Buffer> {
  const child = spawn('/usr/bin/git', [`--git-dir=${REPOSITORY}`, ...args], { cwd: REPOSITORY, env: ENV, stdio: ['pipe', 'pipe', 'pipe'] });
  let processError: unknown, outputError: unknown, stderrBytes = 0, stdoutBytes = 0;
  const closed = new Promise<void>((resolve, reject) => {
    child.once('error', error => { processError = error; });
    child.once('close', (code, signal) => code === 0 && signal === null && processError === undefined ? resolve() : reject(new TypeError('fixed Git plumbing failed')));
  });
  void closed.catch(() => {}); // Observation is retained below even during output-file open.
  const kill = () => { try { child.kill('SIGKILL'); } catch { /* Actual close below remains mandatory. */ } };
  for (const stream of [child.stdin, child.stdout, child.stderr]) stream.on('error', error => { outputError ??= error; kill(); });
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  const chunks: Buffer[] = [];
  try {
    if (output) destination = await open(path.join(OUTPUT, output), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const stdout = (async () => {
      for await (const chunk of child.stdout) {
        const bytes = Buffer.from(chunk); stdoutBytes += bytes.length;
        if (stdoutBytes > (output ? resources.maxSingleFileBytes : resources.maxInvocationOutputBytes)) refused();
        if (destination) { let offset = 0; while (offset < bytes.length) {
          const written = await destination.write(bytes, offset, bytes.length - offset); if (!written.bytesWritten) refused(); offset += written.bytesWritten;
        } } else chunks.push(bytes);
      }
    })();
    const stderr = (async () => { for await (const chunk of child.stderr) {
      stderrBytes += Buffer.byteLength(chunk); if (stderrBytes > resources.maxInvocationOutputBytes) refused();
    } })();
    const stdin = new Promise<void>((resolve, reject) => {
      child.stdin.once('error', reject); child.stdin.end(input, resolve);
    });
    const guarded = [stdout, stderr, stdin, closed].map(promise => promise.catch(error => { outputError ??= error; kill(); throw error; }));
    await Promise.allSettled(guarded);
    if (outputError !== undefined) throw outputError;
    if (destination) await destination.sync();
  } catch (error) {
    outputError ??= error; kill();
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    await Promise.allSettled([closed]);
  } finally {
    if (destination) try { await destination.close(); } catch { refused(); }
  }
  if (outputError !== undefined) throw outputError;
  return Buffer.concat(chunks);
}

async function copySnapshot(resources: SandboxResourceSpec, format: 'sha1' | 'sha256'): Promise<void> {
  let count = 0, total = 0;
  const root = path.join(INPUT, '.git'), queue = [''];
  for (let index = 0; index < queue.length; index++) {
    const relative = queue[index]!, directory = path.join(root, relative);
    const observed = await lstat(directory);
    if (!observed.isDirectory() || observed.isSymbolicLink()) refused();
    for (const name of (await readdir(directory)).sort(sorted)) {
      if (++count > 100_000 || !name || name !== name.normalize('NFC') || Buffer.byteLength(name) > 255 || name === '.' || name === '..') refused();
      const member = relative ? `${relative}/${name}` : name, from = path.join(root, member), stat = await lstat(from);
      const directoryAllowed = member === 'refs' || member.startsWith('refs/') || member === 'objects' ||
        member === 'objects/pack' || member === 'objects/info' || /^objects\/[0-9a-f]{2}$/u.test(member);
      const fileAllowed = member === 'HEAD' || member === 'index' || member === 'packed-refs' || member.startsWith('refs/') ||
        new RegExp(`^objects/[0-9a-f]{2}/[0-9a-f]{${format === 'sha1' ? 38 : 62}}$`, 'u').test(member) ||
        new RegExp(`^objects/pack/pack-[0-9a-f]{${format === 'sha1' ? 40 : 64}}\\.(pack|idx)$`, 'u').test(member);
      if (stat.isDirectory() && directoryAllowed) {
        await mkdir(path.join(REPOSITORY, member), { mode: 0o700 }); queue.push(member); continue;
      }
      if (!stat.isFile() || stat.isSymbolicLink() || !fileAllowed || stat.nlink !== 1 || stat.size > resources.maxSingleFileBytes ||
          total + stat.size > resources.maxGenerationBytes) refused();
      total += stat.size;
      const source = await open(from, constants.O_RDONLY | constants.O_NOFOLLOW);
      let destination: Awaited<ReturnType<typeof open>> | undefined;
      let failure: unknown;
      try {
        destination = await open(path.join(REPOSITORY, member), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        const before = await source.stat({ bigint: true }), chunk = Buffer.alloc(65_536); let copied = 0;
        if (!before.isFile() || before.nlink !== 1n || before.dev !== BigInt(stat.dev) || before.ino !== BigInt(stat.ino) || before.size !== BigInt(stat.size)) refused();
        for (;;) { const read = await source.read(chunk, 0, chunk.length, copied); if (!read.bytesRead) break;
          copied += read.bytesRead; if (copied > stat.size) refused();
          let offset = 0; while (offset < read.bytesRead) { const written = await destination.write(chunk, offset, read.bytesRead - offset);
            if (!written.bytesWritten) refused(); offset += written.bytesWritten; }
        }
        const after = await source.stat({ bigint: true });
        if (copied !== stat.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mode !== after.mode ||
            before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) refused();
        await destination.sync();
      } catch (error) { failure = error; }
      const closes = await Promise.allSettled([source.close(), ...(destination ? [destination.close()] : [])]);
      if (closes.some(result => result.status === 'rejected')) refused();
      if (failure !== undefined) throw failure;
    }
  }
}

async function readRefs(format: 'sha1' | 'sha256', resources: SandboxResourceSpec) {
  const refs = new Map<string, string>();
  const add = (name: string, id: string, loose: boolean) => {
    sourceGitRefName(name); sourceGitObjectId(id, format);
    if (!loose && refs.has(name)) refused(); refs.set(name, id);
  };
  try {
    const packed = await boundedFile(path.join(REPOSITORY, 'packed-refs'), Math.min(resources.maxSingleFileBytes, resources.maxInvocationOutputBytes));
    const text = new TextDecoder('utf-8', { fatal: true }).decode(packed);
    if (text && !text.endsWith('\n')) refused(); let previous: string | undefined;
    for (const line of text.split('\n').slice(0, -1)) {
      if (line.startsWith('#')) { if (!/^# pack-refs with:(?: peeled| fully-peeled| sorted)* ?$/u.test(line)) refused(); continue; }
      if (line.startsWith('^')) { if (!previous) refused(); sourceGitObjectId(line.slice(1), format); previous = undefined; continue; }
      const cells = line.split(' '); if (cells.length !== 2) refused(); add(cells[1]!, cells[0]!, false); previous = cells[1];
    }
  } catch (error) { if ((error as { code?: unknown })?.code !== 'ENOENT') throw error; }
  const directories = ['refs'];
  for (let index = 0; index < directories.length; index++) {
    let names: string[];
    try { names = await readdir(path.join(REPOSITORY, directories[index]!)); }
    catch (error) { if ((error as { code?: unknown })?.code === 'ENOENT') continue; throw error; }
    for (const name of names.sort(sorted)) {
      const relative = `${directories[index]}/${name}`, file = path.join(REPOSITORY, relative), stat = await lstat(file);
      if (stat.isDirectory()) { directories.push(relative); continue; }
      const bytes = await boundedFile(file, 4096), text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      if (!text.endsWith('\n') || text.indexOf('\n') !== text.length - 1) refused(); add(relative, text.slice(0, -1), true);
    }
  }
  return [...refs].sort(([left], [right]) => sorted(left, right)).map(([name, objectId]) => ({ name, objectId }));
}

async function copyPreparedPack(from: string, to: string, expected: SourceGitInspectionOutputV1['pack']): Promise<void> {
  const source = await open(from, constants.O_RDONLY | constants.O_NOFOLLOW);
  let destination: Awaited<ReturnType<typeof open>> | undefined, failure: unknown;
  try {
    const before = await source.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(expected.byteCount)) refused();
    destination = await open(to, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const chunk = Buffer.alloc(65_536), hash = createHash('sha256'); let count = 0;
    for (;;) {
      const next = await source.read(chunk, 0, chunk.length, count); if (!next.bytesRead) break;
      if (next.bytesRead > expected.byteCount - count) refused();
      const bytes = chunk.subarray(0, next.bytesRead); count += next.bytesRead; hash.update(bytes);
      let offset = 0; while (offset < bytes.length) { const written = await destination.write(bytes, offset, bytes.length - offset);
        if (!written.bytesWritten) refused(); offset += written.bytesWritten; }
    }
    const after = await source.stat({ bigint: true });
    if (count !== expected.byteCount || hash.digest('hex') !== expected.sha256 || before.dev !== after.dev || before.ino !== after.ino ||
        before.mode !== after.mode || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) refused();
    await destination.sync();
  } catch (error) { failure = error; }
  const closed = await Promise.allSettled([source.close(), ...(destination ? [destination.close()] : [])]);
  if (closed.some(result => result.status === 'rejected')) refused(); if (failure !== undefined) throw failure;
}

/** Fixed CAS-only reconstruction. Every leaf is newly read inside this
 * original preparing domain; no source root, raw config, caller path or old
 * successful inspection is accepted. All handles join before any Git child. */
async function prepareSnapshot(metadata: SourceGitInspectionOutputV1, resources: SandboxResourceSpec): Promise<void> {
  const indexBytes = await boundedFile(`${INPUT}/canonical.index`, resources.maxSingleFileBytes);
  const packIndexBytes = await boundedFile(`${INPUT}/reachable.idx`, resources.maxSingleFileBytes);
  if (indexBytes.length !== metadata.index.byteCount || sha256Bytes(indexBytes) !== metadata.index.sha256 ||
      packIndexBytes.length !== metadata.pack.indexByteCount || sha256Bytes(packIndexBytes) !== metadata.pack.indexSha256) refused();
  const normalized = normalizeGitIndex(indexBytes, metadata.objectFormat, { maxBytes: resources.maxSingleFileBytes, maxEntries: 100_000 });
  if (!normalized.canonicalBytes.equals(indexBytes) || normalized.indexTreeObjectId !== metadata.index.indexTreeObjectId ||
      !canonicalJsonBytes(normalized.entries).equals(canonicalJsonBytes(metadata.index.entries))) refused();
  for (const directory of ['objects', 'objects/info', 'objects/pack', 'refs']) await mkdir(`${REPOSITORY}/${directory}`, { mode: 0o700 });
  const name = `pack-${metadata.pack.trailerObjectHash}`;
  await copyPreparedPack(`${INPUT}/reachable.pack`, `${REPOSITORY}/objects/pack/${name}.pack`, metadata.pack);
  await writeFile(`${REPOSITORY}/objects/pack/${name}.idx`, packIndexBytes, { flag: 'wx', mode: 0o600 });
  await writeFile(`${REPOSITORY}/index`, indexBytes, { flag: 'wx', mode: 0o600 });
  const head = metadata.head.kind === 'detached' ? `${metadata.head.objectId}\n` :
    `ref: ${metadata.head.kind === 'unborn' ? `refs/heads/${metadata.head.branch}` : metadata.head.ref}\n`;
  await writeFile(`${REPOSITORY}/HEAD`, head, { flag: 'wx', mode: 0o600 });
  await writeFile(`${REPOSITORY}/packed-refs`, `# pack-refs with: sorted\n${metadata.refs.map(ref => `${ref.objectId} ${ref.name}\n`).join('')}`,
    { flag: 'wx', mode: 0o600 });
  await writeFile(`${REPOSITORY}/config`, sanitizedGitConfigText(metadata.sanitizedConfig), { flag: 'wx', mode: 0o600 });
  // This fresh actual index-pack checks the original supplied pack, CRCs,
  // offsets and all object bodies. A stored parser/old source result is not
  // substituted for this process. The only temporary filename is fixed.
  const verifiedIndex = `${OUTPUT}/input.verified.idx`;
  await git(['index-pack', '--strict', '--index-version=2', '-o', verifiedIndex, `${REPOSITORY}/objects/pack/${name}.pack`], resources);
  const verifiedBytes = await boundedFile(verifiedIndex, resources.maxSingleFileBytes);
  if (!verifiedBytes.equals(packIndexBytes)) refused();
  const hashSize = metadata.objectFormat === 'sha1' ? 20 : 32;
  if (verifiedBytes.length < 8 + 1024 + hashSize * 2 || verifiedBytes.readUInt32BE() !== 0xff744f63 || verifiedBytes.readUInt32BE(4) !== 2 ||
      verifiedBytes.readUInt32BE(8 + 255 * 4) !== metadata.pack.objectIds.length ||
      8 + 1024 + metadata.pack.objectIds.length * (hashSize + 8) + hashSize * 2 > verifiedBytes.length) refused();
  for (const [ordinal, id] of metadata.pack.objectIds.entries())
    if (verifiedBytes.subarray(8 + 1024 + ordinal * hashSize, 8 + 1024 + (ordinal + 1) * hashSize).toString('hex') !== id) refused();
  await unlink(verifiedIndex);
}

async function inspect(): Promise<void> {
  if ((process.argv.length !== 2 && !(process.argv.length === 3 && process.argv[2] === '--prepare-private-git')) ||
      process.argv[1] !== '/runtime/cliq-source-git-inspector.mjs' ||
      process.cwd() !== INPUT || await realpath(INPUT) !== INPUT) refused();
  const preparing = process.argv[2] === '--prepare-private-git';
  // Both native-owned data FDs are closed before any Git process exists.
  let raw: Buffer | undefined, rawFailure: unknown, definition: InputIntent | undefined;
  try { definition = intent(dataFd(4, 4096)); } catch (error) { rawFailure ??= error; }
  try { raw = dataFd(3, preparing && definition ? Math.min(definition.resources.maxInvocationOutputBytes, definition.resources.maxSingleFileBytes) : 1_048_576); }
  catch (error) { rawFailure ??= error; }
  if (rawFailure !== undefined) throw rawFailure;
  const selected = definition!, resources = selected.resources;
  if (selected.recipe !== (preparing ? 'cliq-private-git-preparation-v1' : 'cliq-source-git-inspection-v1')) refused();
  const preparation = preparing ? decodeSourceGitInspectionOutput(raw!, { repositoryIdentityDigest: selected.repositoryIdentityDigest, resources }) : undefined;
  const safe = preparation ? { objectFormat: preparation.objectFormat, config: preparation.sanitizedConfig,
    gitConfigUtf8: sanitizedGitConfigText(preparation.sanitizedConfig) } : classifySourceGitConfig(raw!);
  raw = undefined; // No physical JS erasure claim; no child inherits this heap.
  await mkdir(REPOSITORY, { mode: 0o700 }); await mkdir(OUTPUT, { mode: 0o700 });
  if (preparation) await prepareSnapshot(preparation, resources);
  else {
    await copySnapshot(resources, safe.objectFormat);
    await writeFile(path.join(REPOSITORY, 'config'), safe.gitConfigUtf8, { flag: 'wx', mode: 0o600 });
  }
  const refs = await readRefs(safe.objectFormat, resources), refMap = new Map(refs.map(ref => [ref.name, ref.objectId]));
  const headBytes = await boundedFile(path.join(REPOSITORY, 'HEAD'), 4096), headText = new TextDecoder('utf-8', { fatal: true }).decode(headBytes);
  if (!headText.endsWith('\n') || headText.indexOf('\n') !== headText.length - 1) refused();
  let head: SourceGitInspectionOutputV1['head'];
  if (headText.startsWith('ref: ')) {
    const ref = sourceGitRefName(headText.slice(5, -1));
    if (refMap.has(ref)) head = { kind: 'symbolic', ref };
    else { if (!ref.startsWith('refs/heads/')) refused(); head = { kind: 'unborn', branch: ref.slice(11) }; }
  } else head = { kind: 'detached', objectId: sourceGitObjectId(headText.slice(0, -1), safe.objectFormat) };
  let indexBytes: Buffer;
  try { indexBytes = await boundedFile(path.join(REPOSITORY, 'index'), resources.maxSingleFileBytes); }
  catch (error) {
    if ((error as { code?: unknown })?.code !== 'ENOENT') throw error;
    const header = Buffer.from('444952430000000200000000', 'hex'); indexBytes = Buffer.concat([header, createHash(safe.objectFormat).update(header).digest()]);
  }
  const normalized = normalizeGitIndex(indexBytes, safe.objectFormat, { maxBytes: resources.maxSingleFileBytes, maxEntries: 100_000 });
  await writeFile(path.join(OUTPUT, 'canonical.index'), normalized.canonicalBytes, { flag: 'wx', mode: 0o600 });
  await writeFile(path.join(REPOSITORY, 'index'), normalized.canonicalBytes, { flag: 'w', mode: 0o600 });
  await git(['fsck', '--full', '--strict', '--no-reflogs', '--no-dangling'], resources);
  const indexObjects = [...new Set(normalized.entries.map(entry => entry.objectId))].sort(sorted);
  if (indexObjects.length) {
    const observedTypes = await git(['cat-file', '--batch-check=%(objectname) %(objecttype)'], resources,
      Buffer.from(indexObjects.map(id => `${id}\n`).join('')));
    if (!observedTypes.equals(Buffer.from(indexObjects.map(id => `${id} blob\n`).join('')))) refused();
  }
  const actualRefs = await git(['for-each-ref', '--format=%(refname)%00%(objectname)%00'], resources);
  const expectedRefs = Buffer.from(refs.map(ref => `${ref.name}\0${ref.objectId}\0\n`).join(''));
  if (!actualRefs.equals(expectedRefs)) refused();
  const tree = await git(['write-tree'], resources);
  if (!tree.equals(Buffer.from(`${normalized.indexTreeObjectId}\n`))) refused();
  const roots = [...new Set([...refs.map(ref => ref.objectId), ...normalized.entries.map(entry => entry.objectId),
    ...(head.kind === 'detached' ? [head.objectId] : [])])].sort(sorted);
  const rootBytes = Buffer.from(roots.map(id => `${id}\n`).join(''));
  const reached = await git(['rev-list', '--objects', '--no-object-names', '--stdin'], resources, rootBytes);
  const ids = reached.length ? reached.toString('ascii').trimEnd().split('\n').map(id => sourceGitObjectId(id, safe.objectFormat)).sort(sorted) : [];
  if (new Set(ids).size !== ids.length) refused();
  if (preparation && !canonicalJsonBytes(ids).equals(canonicalJsonBytes(preparation.pack.objectIds))) refused();
  if (preparation) {
    // Preparation proves this exact retained closure afresh. It does not
    // replace the Checkpoint's pack with an equivalent repack whose compressed
    // bytes/order may differ. Return the original four input identities only
    // after all fresh original-pack/index/type/reachability checks above.
    await copyPreparedPack(`${REPOSITORY}/objects/pack/pack-${preparation.pack.trailerObjectHash}.pack`, `${OUTPUT}/reachable.pack`, preparation.pack);
    const originalIndex = await boundedFile(`${REPOSITORY}/objects/pack/pack-${preparation.pack.trailerObjectHash}.idx`, resources.maxSingleFileBytes);
    if (originalIndex.length !== preparation.pack.indexByteCount || sha256Bytes(originalIndex) !== preparation.pack.indexSha256) refused();
    await writeFile(`${OUTPUT}/reachable.idx`, originalIndex, { flag: 'wx', mode: 0o600 });
    await writeFile(`${OUTPUT}/inspection.json`, canonicalJsonBytes(preparation), { flag: 'wx', mode: 0o600 });
    return;
  }
  await git(['pack-objects', '--stdout', '--revs', '--delta-base-offset', '--threads=1', '--window=0'], resources, rootBytes, 'reachable.pack');
  await git(['index-pack', '--strict', '--index-version=2', '-o', `${OUTPUT}/reachable.idx`, `${OUTPUT}/reachable.pack`], resources);
  await git(['verify-pack', `${OUTPUT}/reachable.idx`], resources);
  const index = await boundedFile(`${OUTPUT}/reachable.idx`, resources.maxSingleFileBytes);
  const hashSize = safe.objectFormat === 'sha1' ? 20 : 32;
  if (index.length < 8 + 1024 + hashSize * 2 || index.readUInt32BE() !== 0xff744f63 || index.readUInt32BE(4) !== 2) refused();
  const count = index.readUInt32BE(8 + 255 * 4), packIds: string[] = [];
  if (count > 100_000 || 8 + 1024 + count * (hashSize + 8) + hashSize * 2 > index.length) refused();
  for (let ordinal = 0; ordinal < count; ordinal++) packIds.push(sourceGitObjectId(index.subarray(8 + 1024 + ordinal * hashSize, 8 + 1024 + (ordinal + 1) * hashSize).toString('hex'), safe.objectFormat));
  if (JSON.stringify(packIds) !== JSON.stringify(ids)) refused();
  const pack = await fileDigest(`${OUTPUT}/reachable.pack`, resources.maxSingleFileBytes);
  const output: SourceGitInspectionOutputV1 = { schemaVersion: 1, format: 'cliq-source-git-inspection-output-v1',
    repositoryIdentityDigest: selected.repositoryIdentityDigest, objectFormat: safe.objectFormat, head, refs,
    index: { entries: [...normalized.entries], indexTreeObjectId: normalized.indexTreeObjectId,
      byteCount: normalized.canonicalBytes.length, sha256: sha256Bytes(normalized.canonicalBytes) },
    pack: { ...pack, trailerObjectHash: index.subarray(index.length - hashSize * 2, index.length - hashSize).toString('hex'),
      indexByteCount: index.length, indexSha256: sha256Bytes(index), objectIds: ids }, sanitizedConfig: safe.config };
  const bytes = canonicalJsonBytes(output); decodeSourceGitInspectionOutput(bytes, {
    repositoryIdentityDigest: selected.repositoryIdentityDigest, resources });
  await writeFile(`${OUTPUT}/inspection.json`, bytes, { flag: 'wx', mode: 0o600 });
  // Output paths are fixed. The original native producer reopens, fully hashes,
  // seals and joins all four files only after this complete process scope dies.
}

void inspect().catch(() => { process.exitCode = 74; });
