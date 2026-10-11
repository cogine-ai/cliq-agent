// Closed Linux storage experiment. This is not a credential authority or a release image.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, readdir, stat, writeFile, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { buildCredentialVfsProbe } from './sqlite-vfs-mechanism-build.js';
import { buildSupervisorSeaImage } from './supervisor-sea-builder.js';

const modes = ['normal', 'main_before_open', 'parent_after_open', 'main_after_open',
  'wal_after_open', 'journal_after_open', 'lock_after_open'] as const;
type Mode = typeof modes[number];
type Action = 'seed' | 'mutate' | 'primary' | 'reopen';
type Fixture = { username: string; uid: number; gid: number; home: string;
  sqlitePaths: { buildFixture: string; caseRoot: string } };
const roles = ['root', 'credentials', 'lock', 'main', 'wal', 'journal'] as const;
type Role = typeof roles[number];
const dataRoles = ['main', 'wal', 'journal'] as const;
const leaves = { lock: 'authority.lock', main: 'authority.sqlite', wal: 'authority.sqlite-wal',
  journal: 'authority.sqlite-journal' } as const;
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
function identity(info: BigIntStats) {
  return { dev: String(info.dev), ino: String(info.ino), size: String(info.size), uid: String(info.uid),
    gid: String(info.gid), mode: String(info.mode), nlink: String(info.nlink),
    mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs) };
}
type Identity = ReturnType<typeof identity>;
type ObjectProof = { filename: string; identity: Identity; sha256?: string };
type Originals = Record<Role, ObjectProof>;
type Replacements = Record<keyof typeof leaves, ObjectProof>;
type Snapshot = { prepared: boolean; registered: boolean; fenced: boolean; uncertain: boolean;
  retired: boolean; liveFiles: number; defaultUnchanged: boolean; sourceId: string;
  counts: Record<string, number>; descriptors: Record<Role, { fd: number; dev: string; ino: string } | null> };
type Event = Record<string, unknown>;
const sameObject = (a: Identity, b: Identity) => a.dev === b.dev && a.ino === b.ino;
function procFields(text: string) { return text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/u); }
function physicalMapping(line: string, image: Identity) {
  const fields = line.trim().split(/\s+/u), [major, minor] = (fields[3] ?? '').split(':');
  if (!major || !minor || fields[4] !== image.ino) return false;
  const dev = BigInt(image.dev);
  return BigInt(`0x${major}`) === (((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn))
    && BigInt(`0x${minor}`) === ((dev & 0xffn) | ((dev >> 12n) & ~0xffn));
}

export function describeCredentialVfsStorage() {
  return { diagnosticOnly: true, modes, completed: false,
    scope: 'fixed signed diagnostic, same Node engine, original six FDs and seven namespace cuts',
    descriptorIoCutsQualified: false, physicalBindingQualified: false, replacementIoAbsenceQualified: false,
    replacementIoAbsenceScope: 'seven fixed diagnostic cuts only',
    productionCredentialAuthorityQualified: false, installedI1Qualified: false, powerLossDurabilityQualified: false };
}

async function construct(ledger: Fixture, carrier: { nodeRoot: string; carrier: string }) {
  const fixture = path.join(ledger.sqlitePaths.buildFixture, 'credential-vfs-storage');
  await mkdir(fixture, { mode: 0o755 });
  const directory = await lstat(fixture, { bigint: true });
  assert(directory.isDirectory() && directory.uid === 0n && directory.gid === 0n && (directory.mode & 0o7777n) === 0o755n);
  const built = await buildCredentialVfsProbe(fixture, carrier.nodeRoot);
  const claim = path.join(fixture, 'credential-vfs-storage-claim.json');
  await writeFile(claim, JSON.stringify(built.claim), { flag: 'wx', mode: 0o600 });
  const executable = path.join(fixture, 'credential-vfs-storage-diagnostic');
  await buildSupervisorSeaImage({ fixture, carrier: carrier.carrier,
    entryPoint: fileURLToPath(new URL('./credential-vfs-storage-probe.ts', import.meta.url)), executable,
    variant: 'credential-vfs-storage-image', assets: { 'cliq-credential-vfs-storage-claim': claim } });
  await chmod(executable, 0o555);
  const image = await readFile(executable), key = generateKeyPairSync('ed25519');
  const signature = sign(null, image, key.privateKey); assert(verify(null, image, key.publicKey, signature));
  const inspect = (args: string[]) => {
    const result = spawnSync('/usr/bin/readelf', args, { env: environment, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.error, undefined); assert.equal(result.status, 0, result.stderr); return result.stdout;
  };
  const dynamic = inspect(['-d', built.helper]), symbols = inspect(['--dyn-syms', '--wide', built.helper]);
  assert(!/sqlite|NODELETE/iu.test(dynamic)); assert(!/\bUND\s+sqlite3_/u.test(symbols));
  const imageIdentity = identity(await lstat(executable, { bigint: true }));
  const helperIdentity = identity(await lstat(built.helper, { bigint: true }));
  for (const info of [imageIdentity, helperIdentity]) {
    assert.equal(info.uid, '0'); assert.equal(info.gid, '0'); assert.equal(info.nlink, '1');
    assert.equal(BigInt(info.mode) & 0o7777n, 0o555n);
  }
  return { executable, imageIdentity, helperIdentity, imageDigest: digest(image),
    construction: { ...built.construction, helperClaim: built.claim, helperIdentity, helperDynamicSection: dynamic,
      helperDynamicSymbols: symbols, bundledApplicationSha256: digest(await readFile(path.join(fixture, 'credential-vfs-storage-image.cjs'))),
      finalImageIdentity: imageIdentity, finalImageSha256: digest(image), diagnosticSignature: signature.toString('hex'),
      diagnosticPublicKey: key.publicKey.export({ type: 'spki', format: 'pem' }),
      signatureScope: 'final ephemeral diagnostic image with fixed helper claim; not release installation authority' } };
}
type Built = Awaited<ReturnType<typeof construct>>;

function validateEvent(event: Event, ledger: Fixture, action: Action, mode: Mode) {
  assert.equal(event.protocol, 'cliq-credential-vfs-storage-v1'); assert.equal(event.diagnosticOnly, true);
  assert.notEqual(event.phase, 'fatal', String(event.error));
  assert.equal(event.action, action); assert.equal(event.mode, mode); assert.equal(event.nodeVersion, 'v24.21.0');
  assert.equal(event.uid, ledger.uid); assert.equal(event.euid, ledger.uid);
  assert.equal(event.gid, ledger.gid); assert.equal(event.egid, ledger.gid); assert.deepEqual(event.groups, [ledger.gid]);
  assert(Number.isSafeInteger(event.pid) && Number(event.pid) > 0); assert.match(String(event.startTicks), /^[1-9][0-9]*$/u);
}
async function joinedLifetime(pid: number, start: string) {
  const text = await readFile(`/proc/${pid}/stat`, 'utf8').catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return undefined; throw error;
  });
  assert(text === undefined || procFields(text)[19] !== start, 'exact diagnostic lifetime has not joined');
}
function command(ledger: Fixture, built: Built, home: string, args: string[]) {
  return ['--user', ledger.username, '--', '/usr/bin/env', '-i', `HOME=${home}`,
    'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', ...args, built.executable];
}
async function independentAction(ledger: Fixture, built: Built, home: string, action: 'seed' | 'mutate', mode: Mode,
  report: Record<string, unknown>) {
  Object.assign(report, { completed: false, actualProcessJoined: false, launcherJoined: false });
  const child = spawn('/usr/sbin/runuser', [...command(ledger, built, home, []), action, mode],
    { cwd: home, env: environment, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', error: Error | undefined, timedOut = false;
  const cleanupErrors: string[] = []; report.cleanupErrors = cleanupErrors;
  function kill() {
    if (child.pid) try { process.kill(-child.pid, 'SIGKILL'); }
    catch (caught) { if ((caught as NodeJS.ErrnoException).code !== 'ESRCH') cleanupErrors.push(String(caught)); }
  }
  const joined = new Promise<void>(resolve => { child.once('error', caught => { error = caught; }); child.once('close', () => resolve()); });
  child.stdout.on('data', bytes => { stdout += bytes.toString(); if (stdout.length > 65536) kill(); });
  child.stderr.on('data', bytes => { stderr += bytes.toString(); if (stderr.length > 65536) kill(); });
  const timer = setTimeout(() => { timedOut = true; kill(); }, 30000);
  try {
    await joined; assert.equal(error, undefined); assert.equal(timedOut, false);
    assert.equal(child.signalCode, null); assert.equal(child.exitCode, 0, stderr + stdout);
    const lines = stdout.trim().split('\n'); assert.equal(lines.length, 1);
    const event = structuredClone(parseJsonStrict(lines[0]!)) as Event; report.event = event;
    validateEvent(event, ledger, action, mode); assert.equal(event.phase, action === 'seed' ? 'seeded' : 'mutated');
    await joinedLifetime(Number(event.pid), String(event.startTicks)); report.actualProcessJoined = true; report.completed = true;
  } finally {
    clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) kill(); await joined;
    Object.assign(report, { stdout, stderr, timedOut, exitCode: child.exitCode, signalCode: child.signalCode, launcherJoined: true });
    assert.equal(cleanupErrors.length, 0, cleanupErrors.join('\n'));
  }
}

async function objectProof(filename: string, ledger: Fixture, directory = false): Promise<ObjectProof> {
  const info = await lstat(filename, { bigint: true });
  assert(directory ? info.isDirectory() : info.isFile()); assert(!info.isSymbolicLink());
  assert.equal(info.uid, BigInt(ledger.uid)); assert.equal(info.gid, BigInt(ledger.gid));
  assert.equal(info.mode & 0o7777n, directory ? 0o700n : 0o600n);
  if (!directory) assert.equal(info.nlink, 1n);
  const proof: ObjectProof = { filename, identity: identity(info) };
  if (!directory) proof.sha256 = digest(await readFile(filename));
  assert.deepEqual(identity(await lstat(filename, { bigint: true })), proof.identity);
  return proof;
}
async function inventory(home: string, ledger: Fixture) {
  const root = path.join(home, 'probe/credential-vfs'), credentials = path.join(root, 'credentials');
  const original = { root: await objectProof(root, ledger, true), credentials: await objectProof(credentials, ledger, true) } as Originals;
  const replacement = {} as Replacements;
  for (const role of Object.keys(leaves) as (keyof typeof leaves)[]) {
    original[role] = await objectProof(path.join(credentials, leaves[role]), ledger);
    replacement[role] = await objectProof(path.join(root, 'replacement', leaves[role]), ledger);
    assert(!sameObject(original[role].identity, replacement[role].identity));
  }
  return { original, replacement };
}
function replacementPath(home: string, mode: Mode, role: keyof typeof leaves) {
  const root = path.join(home, 'probe/credential-vfs');
  const replaced = mode === 'parent_after_open' || mode.startsWith(`${role}_`);
  return path.join(root, replaced ? 'credentials' : 'replacement', leaves[role]);
}
async function replacementInventory(home: string, mode: Mode, ledger: Fixture, expected: Replacements) {
  const actual = {} as Replacements;
  for (const role of Object.keys(leaves) as (keyof typeof leaves)[]) {
    actual[role] = await objectProof(replacementPath(home, mode, role), ledger);
    // A rename changes ctime, not the physical identity or contents of the replacement.
    assert(sameObject(actual[role].identity, expected[role].identity)); assert.equal(actual[role].sha256, expected[role].sha256);
    assert.equal(actual[role].identity.size, expected[role].identity.size);
  }
  return actual;
}

async function observe(proc: FileHandle, pid: number, start: string, group: number, ledger: Fixture,
  built: Built, originals: Originals, replacements: Replacements, phase: string, snapshot: Snapshot) {
  const base = `/proc/self/fd/${proc.fd}`, before = procFields(await readFile(`${base}/stat`, 'utf8'));
  assert.equal(before[19], start); assert.equal(before[2], String(group));
  const status = await readFile(`${base}/status`, 'utf8');
  for (const [name, expected] of [['Uid', ledger.uid], ['Gid', ledger.gid]] as const) {
    const match = new RegExp(`^${name}:\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)$`, 'mu').exec(status);
    assert(match); assert.deepEqual(match.slice(1), Array(4).fill(String(expected)));
  }
  const groups = /^Groups:\s*([^\n]*)$/mu.exec(status); assert(groups);
  assert.deepEqual(groups[1]!.trim().split(/\s+/u), [String(ledger.gid)]);
  assert.deepEqual(identity(await stat(`${base}/exe`, { bigint: true })), built.imageIdentity);
  assert.equal(digest(await readFile(`${base}/exe`)), built.imageDigest);
  const rawMaps = await readFile(`${base}/maps`, 'utf8'); assert(!/libsqlite/iu.test(rawMaps));
  const helperMappings = rawMaps.split('\n').filter(line => physicalMapping(line, built.helperIdentity));
  assert(helperMappings.some(line => line.trim().split(/\s+/u)[1] === 'r-xp'));
  const fds: { fd: number; actual: Identity; kind: string }[] = [];
  for (const name of await readdir(`${base}/fd`)) {
    const info = await stat(`${base}/fd/${name}`, { bigint: true }).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined; throw error;
    });
    if (info) fds.push({ fd: Number(name), actual: identity(info), kind: info.isFile() ? 'file' : info.isDirectory() ? 'directory' : 'other' });
  }
  assert(!fds.some(fd => sameObject(fd.actual, built.helperIdentity)), 'helper image FD must already be consumed');
  for (const proof of Object.values(replacements)) assert(!fds.some(fd => sameObject(fd.actual, proof.identity)), 'replacement must not be held');
  assert.equal(snapshot.registered, true); assert.equal(snapshot.defaultUnchanged, true);
  assert.equal(typeof snapshot.sourceId, 'string'); assert(snapshot.sourceId.length > 0); assert.equal(snapshot.uncertain, false);
  const nativeDescriptors: Partial<Record<Role, { fd: number; actual: Identity }>> = {};
  for (const role of roles) {
    const matching = fds.filter(fd => sameObject(fd.actual, originals[role].identity));
    const claimed = snapshot.descriptors[role];
    if (phase === 'retired') { assert.equal(claimed, null); assert.equal(matching.length, 0); continue; }
    assert(claimed && Number.isSafeInteger(claimed.fd)); assert.equal(matching.length, 1, `${phase}: one original ${role} FD required`);
    const actual = matching[0]!; assert.equal(actual.fd, claimed.fd);
    assert.equal(actual.actual.dev, claimed.dev); assert.equal(actual.actual.ino, claimed.ino);
    for (const field of ['uid', 'gid', 'mode', 'nlink'] as const) assert.equal(actual.actual[field], originals[role].identity[field]);
    assert.equal(actual.kind, role === 'root' || role === 'credentials' ? 'directory' : 'file');
    nativeDescriptors[role] = { fd: actual.fd, actual: actual.actual };
  }
  assert.equal(snapshot.prepared, phase !== 'retired'); assert.equal(snapshot.retired, phase === 'retired');
  assert.equal(snapshot.fenced, phase === 'refused');
  if (phase === 'prepared' || phase === 'refused' || phase === 'retired') assert.equal(snapshot.liveFiles, 0);
  else assert(snapshot.liveFiles > 0);
  const tids = (await readdir(`${base}/task`)).map(Number); assert(tids.includes(pid));
  assert.equal(procFields(await readFile(`${base}/stat`, 'utf8'))[19], start);
  return { pid, startTicks: start, phase, nativeDescriptors, fds, tids, credentials: status,
    helperMappings, rawMaps, actualImage: built.imageIdentity, actualImageSha256: built.imageDigest };
}
type Cut = Awaited<ReturnType<typeof observe>>;

// This parser accepts only this closed producer's syscall corpus. Ambiguity is
// failed evidence, never an absence-of-I/O result.
const tracedCalls = ['open', 'openat', 'openat2', 'newfstatat', 'fstat', 'statx', 'readlink', 'readlinkat',
  'fcntl', 'flock', 'fsync', 'fdatasync', 'close', 'close_range', 'dup', 'dup2', 'dup3', 'mmap', 'mremap', 'munmap',
  'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2', 'truncate', 'ftruncate',
  'read', 'readv', 'pread64', 'preadv', 'preadv2', 'write', 'writev', 'pwrite64', 'pwritev', 'pwritev2',
  'sendfile', 'copy_file_range', 'splice', 'tee', 'vmsplice', 'io_uring_setup', 'io_submit', 'io_setup',
  'clone', 'clone3', 'fork', 'vfork', 'execve', 'execveat'];
type Call = { tid: number; start: bigint; end: bigint; name: string; args: string; result: string; text: string };
function timestamp(text: string) {
  const [seconds, fraction] = text.split('.'); return BigInt(seconds!) * 1000000000n + BigInt(fraction!.padEnd(9, '0'));
}
function parseTrace(tid: number, raw: string): Call[] {
  const calls: Call[] = []; let pending: { name: string; text: string; start: bigint } | undefined, terminated = false;
  for (const line of raw.split('\n').filter(Boolean)) {
    assert(!terminated, `record after terminal in TID ${tid}`);
    const timed = /^(\d+\.\d{6,9})\s+(.*)$/u.exec(line); assert(timed, `un-timestamped trace: ${line}`);
    const time = timestamp(timed[1]!); let text = timed[2]!, begin = time;
    if (text.startsWith('--- ')) { assert(!text.includes('detached')); continue; }
    if (text.startsWith('+++ ')) {
      assert.equal(pending, undefined, `incomplete syscall in TID ${tid}`);
      assert.match(text, /^\+\+\+ exited with 0 \+\+\+$/u, `unexpected terminal in TID ${tid}`);
      terminated = true; continue;
    }
    const resumed = /^<\.\.\. ([a-z0-9_]+) resumed>(.*)$/u.exec(text);
    if (resumed) {
      assert(pending && pending.name === resumed[1], `unmatched resumed trace: ${line}`);
      begin = pending.start; text = pending.text + resumed[2]; pending = undefined;
    } else if (text.endsWith('<unfinished ...>')) {
      assert.equal(pending, undefined); const name = /^([a-z0-9_]+)\(/u.exec(text); assert(name);
      pending = { name: name[1]!, text: text.slice(0, -'<unfinished ...>'.length), start: time }; continue;
    }
    const call = /^([a-z0-9_]+)\((.*)\)\s+=\s+(.+)$/u.exec(text); assert(call, `unparsed trace: ${line}`);
    calls.push({ tid, start: begin, end: time, name: call[1]!, args: call[2]!, result: call[3]!, text });
  }
  assert.equal(pending, undefined, `incomplete syscall in TID ${tid}`);
  assert(terminated, `missing terminal in TID ${tid}`); return calls;
}
function argumentsOf(text: string) {
  const result: string[] = [], stack: string[] = [];
  const closing: Record<string, string> = { ')': '(', '}': '{', ']': '[', '>': '<' };
  let begin = 0, quoted = false, escaped = false;
  for (let index = 0; index < text.length; index++) {
    const byte = text[index]!;
    if (quoted) { if (escaped) escaped = false; else if (byte === '\\') escaped = true; else if (byte === '"') quoted = false; continue; }
    if (byte === '"') quoted = true;
    else if ('({[<'.includes(byte)) stack.push(byte);
    else if (closing[byte]) {
      if (byte === '>' && text[index - 1] === '=') continue; // strace in/out structure: {...} => {...}
      // -yy renders socket peers inside the FD annotation as [local->peer].
      // That arrow is not the closing delimiter of the outer <annotation>.
      if (byte === '>' && text[index - 1] === '-' && stack.includes('<')) continue;
      assert.equal(stack.pop(), closing[byte], 'ambiguous trace delimiters');
    } else if (byte === ',' && stack.length === 0) { result.push(text.slice(begin, index).trim()); begin = index + 1; }
  }
  assert.equal(quoted, false); assert.equal(stack.length, 0, 'incomplete trace delimiters');
  result.push(text.slice(begin).trim()); return result;
}
const fdNumber = (text: string | undefined) => text === undefined ? undefined : /^([0-9]+)(?:<.*>)?$/u.exec(text)?.[1];
const success = (call: Call) => !call.result.startsWith('-1 ');
export function isCredentialVfsTraceMarker(call: Call, phase: string, action: Action, mode: Mode) {
  if (call.name !== 'write' || !success(call)) return false;
  const args = argumentsOf(call.args); if (fdNumber(args[0]) !== '1' || !args[1]?.startsWith('"')) return false;
  let text: string; try { text = JSON.parse(args[1]) as string; } catch { return false; }
  if (!text.endsWith('\n') || Number.parseInt(call.result, 10) !== Buffer.byteLength(text)) return false;
  let event: Event; try { event = structuredClone(parseJsonStrict(text.trim())) as Event; } catch { return false; }
  return event.protocol === 'cliq-credential-vfs-storage-v1' && event.phase === phase && event.action === action && event.mode === mode;
}
export function isCredentialVfsHousekeepingOpen(call: Call) {
  if (!['open', 'openat', 'openat2'].includes(call.name) || !success(call)) return false;
  const args = argumentsOf(call.args), pathname = args[call.name === 'open' ? 0 : 1]!;
  // Recorded glibc CPU query only, not a general /sys or writable-file exception.
  const cpuRead = call.name === 'openat' && args.length === 3 && /^AT_FDCWD(?:<.*>)?$/u.test(args[0]!)
    && pathname === '"/sys/devices/system/cpu/online"' && args[2] === 'O_RDONLY|O_CLOEXEC';
  return cpuRead || /^"(?:\/proc\/(?:self|thread-self|[0-9]+)\/(?:stat|status|maps)|\/dev\/(?:u?random))"$/u.test(pathname);
}
async function traceCorpus(home: string, action: 'primary' | 'reopen', ledger: Fixture, evidence: Record<string, unknown>) {
  const names = (await readdir(home)).filter(name => new RegExp(`^${action}\\.trace\\.[0-9]+$`, 'u').test(name));
  const corpus: { tid: number; filename: string; identity: Identity; sha256: string; raw: string }[] = [];
  evidence.corpus = corpus; let bytesSeen = 0n;
  assert(names.length <= 64, 'closed producer trace exceeded its thread bound');
  for (const name of names) {
    const filename = path.join(home, name), info = await lstat(filename, { bigint: true });
    assert(info.isFile() && info.nlink === 1n && info.uid === BigInt(ledger.uid) && info.gid === BigInt(ledger.gid));
    bytesSeen += info.size; assert(bytesSeen <= 8n * 1024n * 1024n, 'closed producer trace exceeded its byte bound');
    const bytes = await readFile(filename);
    corpus.push({ tid: Number(name.split('.').at(-1)), filename, identity: identity(info), sha256: digest(bytes), raw: bytes.toString('utf8') });
    assert.deepEqual(identity(await lstat(filename, { bigint: true })), identity(info));
  }
  return corpus;
}
// Pure closed-corpus check, also used by parser regression tests. No OS or
// authority qualification follows from synthetic parser inputs.
export function checkedThreadCalls(corpus: readonly { tid: number; raw: string }[], pid: number) {
  assert(corpus.some(item => item.tid === pid));
  const calls = corpus.flatMap(item => parseTrace(item.tid, item.raw));
  for (const call of calls) argumentsOf(call.args);
  assert(!calls.some(call => ['fork', 'vfork'].includes(call.name) && success(call)),
    'closed producer must create only threads sharing its FD table');
  const reachable = new Set([pid]);
  for (let previous = -1; previous !== reachable.size;) {
    previous = reachable.size;
    for (const call of calls) if (reachable.has(call.tid) && ['clone', 'clone3'].includes(call.name) && success(call)) {
      assert(call.args.includes('CLONE_THREAD') && call.args.includes('CLONE_FILES'), 'closed producer must create only threads sharing its FD table');
      const child = Number.parseInt(call.result, 10); assert(child > 0); reachable.add(child);
    }
  }
  assert(corpus.every(item => reachable.has(item.tid)), 'trace contains an unbound process/TID');
  assert([...reachable].every(tid => corpus.some(item => item.tid === tid)), 'a created TID has no complete trace');
  return calls;
}
async function traceEvidence(home: string, action: 'primary' | 'reopen', mode: Mode, pid: number, cuts: Cut[], ledger: Fixture,
  evidence: Record<string, unknown>) {
  const corpus = await traceCorpus(home, action, ledger, evidence);
  const calls = checkedThreadCalls(corpus, pid);
  for (const cut of cuts) assert(cut.tids.every(tid => corpus.some(item => item.tid === tid)), 'an observed TID has no complete trace');
  const prepared = calls.filter(call => call.tid === pid && isCredentialVfsTraceMarker(call, 'prepared', action, mode)); assert.equal(prepared.length, 1);
  const begin = prepared[0]!.start;
  const window = calls.filter(call => call.end >= begin).sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : a.tid - b.tid);
  const live = new Map<number, Role>();
  for (const role of roles) live.set(cuts[0]!.nativeDescriptors[role]!.fd, role);
  const positive = Object.fromEntries(dataRoles.map(role => [role, { reads: 0, writes: 0, syncs: 0 }])) as Record<typeof dataRoles[number], { reads: number; writes: number; syncs: number }>;
  const closes: { role: Role; tid: number; trace: string }[] = [];
  for (const call of window) {
    assert(call.start >= begin, `syscall overlaps the prepared cut: ${call.text}`);
    const args = argumentsOf(call.args), first = Number(fdNumber(args[0])), role = live.get(first);
    if (['open', 'openat', 'openat2'].includes(call.name)) {
      const pathname = args[call.name === 'open' ? 0 : 1]!;
      assert(!/authority\.(?:sqlite(?:-wal|-journal)?|lock)/u.test(pathname), `authority leaf reopen: ${call.text}`);
      for (const fd of live.keys()) assert(!new RegExp(`/proc/(?:self|thread-self|[0-9]+)/fd/${fd}(?:["/])`, 'u').test(pathname), `original FD reopen: ${call.text}`);
      if (success(call) && !call.args.includes('O_DIRECTORY')) {
        assert(isCredentialVfsHousekeepingOpen(call),
          `unbound regular-file open after prepared: ${call.text}`);
      }
    }
    assert(!['fork', 'vfork', 'execve', 'execveat', 'close_range', 'io_uring_setup', 'io_submit', 'io_setup', 'mremap'].includes(call.name), `unsupported lifecycle/I/O channel: ${call.text}`);
    if (['dup', 'dup2', 'dup3'].includes(call.name)) {
      assert.equal(role, undefined, `original FD duplicated: ${call.text}`);
      if (call.name !== 'dup') assert(!live.has(Number(fdNumber(args[1]))), `original FD overwritten: ${call.text}`);
    }
    if (call.name === 'fcntl' && role) assert(!/F_DUPFD|F_UNLCK/u.test(call.args), `original guard/FD changed: ${call.text}`);
    if (call.name === 'flock' && role) assert(!call.args.includes('LOCK_UN'), `original gate unlocked: ${call.text}`);
    if (['unlink', 'unlinkat', 'rename', 'renameat', 'renameat2', 'truncate'].includes(call.name)) {
      assert(!/authority\.(?:sqlite(?:-wal|-journal)?|lock)/u.test(call.args), `namespace data operation: ${call.text}`);
    }
    if (call.name === 'mmap') assert(!live.has(Number(fdNumber(args[4]))), `original data mapping: ${call.text}`);
    if (['sendfile', 'copy_file_range', 'splice', 'tee', 'vmsplice'].includes(call.name)) {
      assert(!args.some(arg => live.has(Number(fdNumber(arg)))), `unsupported original FD content channel: ${call.text}`);
    }
    if (call.name === 'close' && role) {
      assert(success(call)); live.delete(first); closes.push({ role, tid: call.tid, trace: call.text }); continue;
    }
    if (role && dataRoles.includes(role as typeof dataRoles[number]) && success(call)) {
      const io = positive[role as typeof dataRoles[number]], bytes = Number.parseInt(call.result, 10);
      if (['read', 'readv', 'pread64', 'preadv', 'preadv2'].includes(call.name) && bytes > 0) io.reads++;
      if (['write', 'writev', 'pwrite64', 'pwritev', 'pwritev2'].includes(call.name) && bytes > 0) io.writes++;
      if (['fsync', 'fdatasync'].includes(call.name)) { assert.equal(bytes, 0); io.syncs++; }
    }
  }
  if (mode === 'normal') {
    assert.deepEqual(closes.map(item => item.role), ['journal', 'wal', 'credentials', 'root', 'main', 'lock']); assert.equal(live.size, 0);
    if (action === 'primary') {
      assert(positive.main.reads > 0 && positive.main.writes > 0 && positive.main.syncs > 0, 'normal requires actual original MAIN read/write/sync');
      assert(positive.wal.writes > 0 && positive.wal.syncs > 0, 'normal requires actual original WAL write/sync');
    }
  } else { assert.deepEqual(closes, []); assert.equal(live.size, roles.length); }
  Object.assign(evidence, { completed: true, ownerPid: pid, traceTids: corpus.map(item => item.tid),
    preparedMarkerTimestampNs: String(begin), positiveOriginalIo: positive, actualCloseOrder: closes,
    replacementContentIoObserved: false, authorityDataReopensObserved: false,
    scope: 'complete observed fixed producer lifetime after independently bound prepared cut; no general adversarial or power-loss claim' });
}

async function runOwner(ledger: Fixture, built: Built, home: string, mode: Mode, action: 'primary' | 'reopen',
  originals: Originals, replacements: Replacements, report: Record<string, unknown>) {
  const events: Event[] = [], cuts: Cut[] = [], trace: Record<string, unknown> = { completed: false };
  Object.assign(report, { action, completed: false, events, cuts, trace, actualProcessJoined: false, tracerJoined: false, cleanupErrors: [] });
  const args = command(ledger, built, home, ['/usr/bin/strace', '-I', '1', '-ff', '-yy', '-ttt', '-s', '65536',
    '-o', path.join(home, `${action}.trace`), '-e', `trace=${tracedCalls.join(',')}`]);
  const child = spawn('/usr/sbin/runuser', [...args, action, mode], { cwd: home, env: environment, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '', spawnError: Error | undefined, stdinError: Error | undefined, timedOut = false;
  let proc: FileHandle | undefined, pid: number | undefined, start: string | undefined;
  const cleanupErrors = report.cleanupErrors as string[];
  const joined = new Promise<void>(resolve => { child.once('error', error => { spawnError = error; }); child.once('close', () => resolve()); });
  function kill() {
    if (!child.pid) return;
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') cleanupErrors.push(String(error)); }
  }
  child.stdin.on('error', error => {
    stdinError = error;
    if (child.exitCode === null && child.signalCode === null) kill();
  });
  child.stderr.on('data', bytes => { stderr += bytes.toString(); if (stderr.length > 65536) kill(); });
  const timer = setTimeout(() => { timedOut = true; kill(); }, 60000);
  try {
    const expected = mode === 'normal' ? ['prepared', 'opened', 'retired', 'completed']
      : mode === 'main_before_open' ? ['prepared', 'refused', 'completed'] : ['prepared', 'opened', 'refused', 'completed'];
    for await (const line of createInterface({ input: child.stdout })) {
      assert(Buffer.byteLength(line) <= 65536); const event = structuredClone(parseJsonStrict(line)) as Event; events.push(event);
      validateEvent(event, ledger, action, mode); assert.equal(event.phase, expected[events.length - 1]);
      if (pid === undefined) {
        pid = Number(event.pid); start = String(event.startTicks);
        proc = await open(`/proc/${pid}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      }
      assert.equal(event.pid, pid); assert.equal(event.startTicks, start);
      if (event.phase === 'completed') {
        for (const key of ['productionCredentialAuthorityQualified', 'installedI1Qualified', 'powerLossDurabilityQualified']) assert.equal(event[key], false);
        continue;
      }
      assert(proc && child.pid); const snapshot = event.snapshot as Snapshot;
      cuts.push(await observe(proc, pid, start!, child.pid, ledger, built, originals, replacements, String(event.phase), snapshot));
      if (event.phase === 'refused') {
        const baseline = events[events.length - 2]!.snapshot as Snapshot;
        for (const count of ['reads', 'writes', 'truncates', 'syncs']) assert.equal(snapshot.counts[count], baseline.counts[count]);
      }
      if (action === 'primary' && (mode === 'main_before_open' && event.phase === 'prepared'
        || mode !== 'normal' && mode !== 'main_before_open' && event.phase === 'opened')) {
        const mutation: Record<string, unknown> = {}; report.mutation = mutation;
        await independentAction(ledger, built, home, 'mutate', mode, mutation);
        report.replacementsAfterMutation = await replacementInventory(home, mode, ledger, replacements);
      }
      child.stdin.write('continue\n');
    }
    await joined; report.tracerJoined = true;
    assert.equal(spawnError, undefined); assert.equal(stdinError, undefined); assert.equal(timedOut, false);
    assert.equal(child.signalCode, null); assert.equal(child.exitCode, 0, stderr); assert.deepEqual(events.map(event => event.phase), expected);
    assert(pid !== undefined && start !== undefined); await joinedLifetime(pid, start); report.actualProcessJoined = true;
    await traceEvidence(home, action, mode, pid, cuts, ledger, trace);
    report.replacementsAfterJoin = await replacementInventory(home, mode, ledger, replacements);
    report.completed = true;
  } finally {
    clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) kill(); await joined;
    report.stderr = stderr; report.stdinError = stdinError?.message; report.timedOut = timedOut;
    report.exitCode = child.exitCode; report.signalCode = child.signalCode; report.tracerJoined = true;
    if (pid !== undefined && start !== undefined) {
      try { await joinedLifetime(pid, start); report.actualProcessJoined = true; } catch (error) { cleanupErrors.push(String(error)); }
    }
    try { await proc?.close(); } catch (error) { cleanupErrors.push(String(error)); }
    if (trace.completed !== true) {
      try {
        if (pid !== undefined && cuts[0]) await traceEvidence(home, action, mode, pid, cuts, ledger, trace);
        else await traceCorpus(home, action, ledger, trace);
      } catch (error) { trace.error = String((error as Error).stack ?? error); }
    }
    assert.equal(cleanupErrors.length, 0, cleanupErrors.join('\n'));
  }
}

export async function qualifyCredentialVfsStorage(ledger: Fixture, carrier: { nodeRoot: string; carrier: string }) {
  const results: Record<string, unknown>[] = [], report: Record<string, unknown> = { ...describeCredentialVfsStorage(), results };
  try {
    assert.equal(process.platform, 'linux'); assert.equal(process.geteuid!(), 0); assert.equal(process.getegid!(), 0);
    const built = await construct(ledger, carrier); report.construction = built.construction;
    for (const mode of modes) {
      const result: Record<string, unknown> = { mode, completed: false }; results.push(result); report.currentMode = mode;
      const home = path.join(ledger.sqlitePaths.caseRoot, `credential-vfs-${mode}`); result.home = home;
      await mkdir(home, { mode: 0o700 }); const held = await open(home, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      try { await held.chown(ledger.uid, ledger.gid); assert.deepEqual(identity(await held.stat({ bigint: true })), identity(await lstat(home, { bigint: true }))); }
      finally { await held.close(); }
      const seed: Record<string, unknown> = {}; result.seed = seed;
      await independentAction(ledger, built, home, 'seed', mode, seed);
      const seeded = await inventory(home, ledger); result.seededInventory = seeded;
      const primary: Record<string, unknown> = {}; result.primary = primary;
      await runOwner(ledger, built, home, mode, 'primary', seeded.original, seeded.replacement, primary);
      if (mode === 'normal') {
        const beforeReopen = await inventory(home, ledger); result.beforeReopenInventory = beforeReopen;
        for (const role of roles) assert(sameObject(beforeReopen.original[role].identity, seeded.original[role].identity));
        const reopen: Record<string, unknown> = {}; result.reopen = reopen;
        await runOwner(ledger, built, home, mode, 'reopen', beforeReopen.original, seeded.replacement, reopen);
        const afterReopen = await inventory(home, ledger); result.afterReopenInventory = afterReopen;
        for (const role of roles) assert(sameObject(afterReopen.original[role].identity, seeded.original[role].identity));
      }
      result.completed = true;
    }
    delete report.currentMode; report.completed = true; report.descriptorIoCutsQualified = true;
    report.replacementIoAbsenceQualified = true;
  } catch (error) { report.error = String((error as Error).stack ?? error); }
  return report;
}
