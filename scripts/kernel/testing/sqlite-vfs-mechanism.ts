// Fixed signed-image mechanism diagnostic; does not implement a credential VFS.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, readdir, stat, writeFile, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { buildSqliteVfsMechanismHelper } from './sqlite-vfs-mechanism-build.js';
import { buildSupervisorSeaImage } from './supervisor-sea-builder.js';

const modes = ['unregistered', 'scoped', 'permanent', 'dual', 'tampered'] as const;
type Mode = typeof modes[number];
type Fixture = { username: string; uid: number; gid: number; home: string;
  sqlitePaths: { buildFixture: string; caseRoot: string } };
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
function identity(info: BigIntStats) {
  return { dev: String(info.dev), ino: String(info.ino), size: String(info.size), uid: String(info.uid),
    gid: String(info.gid), mode: String(info.mode), nlink: String(info.nlink),
    mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs) };
}
type Identity = ReturnType<typeof identity>;
function procStart(text: string) { return text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/u)[19]!; }
function physicalMapping(line: string, image: Identity) {
  const fields = line.trim().split(/\s+/u);
  const [major, minor] = (fields[3] ?? '').split(':');
  if (!major || !minor || fields[4] !== image.ino) return false;
  const dev = BigInt(image.dev);
  const expectedMajor = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn);
  const expectedMinor = (dev & 0xffn) | ((dev >> 12n) & ~0xffn);
  return BigInt(`0x${major}`) === expectedMajor && BigInt(`0x${minor}`) === expectedMinor;
}
export function describeSqliteVfsMechanism() {
  return { diagnosticOnly: true, modes, callback: 'fixed native xOpen marker then SQLITE_CANTOPEN; no database opens',
    registrationAndLoadingMechanismQualified: false,
    physicalBindingQualified: false, replacementIoAbsenceQualified: false,
    productionCredentialAuthorityQualified: false, installedI1Qualified: false };
}

async function construct(ledger: Fixture, carrier: { nodeRoot: string; carrier: string }) {
  const fixture = ledger.sqlitePaths.buildFixture;
  const built = await buildSqliteVfsMechanismHelper(fixture, carrier.nodeRoot);
  const bytes = await readFile(built.helper);
  const corrupt = Buffer.from(bytes); corrupt[0] = corrupt[0]! ^ 1;
  const corruptFile = path.join(fixture, 'sqlite-vfs-mechanism-corrupt.node');
  await writeFile(corruptFile, corrupt, { flag: 'wx', mode: 0o555 }); await chmod(corruptFile, 0o555);
  const claim = path.join(fixture, 'sqlite-vfs-mechanism-claim.json');
  await writeFile(claim, JSON.stringify(built.claim), { flag: 'wx', mode: 0o600 });
  const executable = path.join(fixture, 'sqlite-vfs-mechanism-diagnostic');
  await buildSupervisorSeaImage({ fixture, carrier: carrier.carrier,
    entryPoint: fileURLToPath(new URL('./sqlite-vfs-mechanism-probe.ts', import.meta.url)),
    executable, variant: 'sqlite-vfs-mechanism-image', assets: { 'cliq-vfs-mechanism-claim': claim } });
  await chmod(executable, 0o555);
  const image = await readFile(executable);
  const key = generateKeyPairSync('ed25519'); const signature = sign(null, image, key.privateKey);
  assert(verify(null, image, key.publicKey, signature));
  const elf = spawnSync('/usr/bin/readelf', ['-d', built.helper], { env: environment, encoding: 'utf8', timeout: 10000 });
  assert.equal(elf.error, undefined); assert.equal(elf.status, 0, elf.stderr);
  assert(!/sqlite|NODELETE/iu.test(elf.stdout), 'helper cannot retain an ordinary-load mapping or link another SQLite');
  const symbols = spawnSync('/usr/bin/readelf', ['--dyn-syms', '--wide', built.helper],
    { env: environment, encoding: 'utf8', timeout: 10000 });
  assert.equal(symbols.error, undefined); assert.equal(symbols.status, 0, symbols.stderr);
  assert(!/\bUND\s+sqlite3_/u.test(symbols.stdout), 'SQLite functions must come from the received API table');
  const digest = createHash('sha256').update(image).digest('hex');
  return { executable, digest, imageIdentity: identity(await lstat(executable, { bigint: true })),
    helperIdentity: identity(await lstat(built.helper, { bigint: true })),
    corruptIdentity: identity(await lstat(corruptFile, { bigint: true })), claim: built.claim,
    construction: { ...built.construction, helperClaim: built.claim, helperDynamicSection: elf.stdout,
      helperDynamicSymbols: symbols.stdout, bundledApplicationSha256: createHash('sha256')
        .update(await readFile(path.join(fixture, 'sqlite-vfs-mechanism-image.cjs'))).digest('hex'),
      finalImageSha256: digest, diagnosticSignature: signature.toString('hex'),
      diagnosticPublicKey: key.publicKey.export({ type: 'spki', format: 'pem' }),
      signatureScope: 'final ephemeral diagnostic SEA embeds fixed helper claim; not release or credential authority' } };
}
type Built = Awaited<ReturnType<typeof construct>>;

async function observe(proc: FileHandle, pid: number, start: string, ledger: Fixture, built: Built,
  mode: Mode, phase: string, helperFd?: number) {
  const base = `/proc/self/fd/${proc.fd}`;
  assert.equal(procStart(await readFile(`${base}/stat`, 'utf8')), start);
  const status = await readFile(`${base}/status`, 'utf8');
  for (const field of ['Uid', 'Gid']) {
    const found = new RegExp(`^${field}:\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)$`, 'mu').exec(status);
    assert(found); assert.deepEqual(found.slice(1), Array(4).fill(String(ledger.uid)));
  }
  const groups = /^Groups:\s*([^\n]*)$/mu.exec(status); assert(groups);
  assert.deepEqual(groups[1]!.trim().split(/\s+/u), [String(ledger.gid)]);
  assert.deepEqual(identity(await stat(`${base}/exe`, { bigint: true })), built.imageIdentity);
  assert.equal(createHash('sha256').update(await readFile(`${base}/exe`)).digest('hex'), built.digest);
  const rawMaps = await readFile(`${base}/maps`, 'utf8');
  assert(!/libsqlite/iu.test(rawMaps), 'no second SQLite library may be mapped');
  const mapped = rawMaps.split('\n').filter(line => physicalMapping(line, built.helperIdentity));
  const corruptedMapped = rawMaps.split('\n').filter(line => physicalMapping(line, built.corruptIdentity));
  assert.equal(corruptedMapped.length, 0);
  const expectedMapping = phase === 'loaded' || (mode === 'permanent' || mode === 'dual')
    && (phase === 'bootstrap_and_image_fd_closed' || phase === 'callback_refused');
  assert.equal(mapped.some(line => line.trim().split(/\s+/u)[1] === 'r-xp'), expectedMapping,
    `${mode}/${phase}: exact helper executable mapping mismatch`);
  if (!expectedMapping) assert.equal(mapped.length, 0);
  const helperDescriptors: { fd: number; actual: Identity }[] = [];
  for (const name of await readdir(`${base}/fd`)) {
    const info = await stat(`${base}/fd/${name}`, { bigint: true }).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined; throw error;
    });
    if (info && (info.ino.toString() === built.helperIdentity.ino || info.ino.toString() === built.corruptIdentity.ino)) {
      const actual = identity(info);
      if (actual.dev === built.helperIdentity.dev) helperDescriptors.push({ fd: Number(name), actual });
    }
  }
  const imageFdHeld = phase === 'loaded' || phase === 'signature_bound_digest_refused';
  assert.equal(helperDescriptors.length, imageFdHeld ? 1 : 0);
  if (imageFdHeld) {
    assert.equal(helperDescriptors[0]!.fd, helperFd);
    assert.deepEqual(helperDescriptors[0]!.actual, mode === 'tampered' ? built.corruptIdentity : built.helperIdentity);
    const expectedDigest = mode === 'tampered' ? undefined : built.claim.sha256;
    if (expectedDigest) assert.equal(createHash('sha256').update(await readFile(`${base}/fd/${helperFd}`)).digest('hex'), expectedDigest);
  }
  assert.equal(procStart(await readFile(`${base}/stat`, 'utf8')), start);
  return { pid, startTicks: start, phase, helperDescriptors, helperMappings: mapped, corruptHelperMappings: corruptedMapped,
    actualImage: built.imageIdentity, actualImageSha256: built.digest, rawMaps, credentials: status };
}

async function runCase(ledger: Fixture, built: Built, mode: Mode) {
  const directory = path.join(ledger.sqlitePaths.caseRoot, `vfs-${mode}`);
  await mkdir(directory, { mode: 0o700 });
  const created = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const before = await created.stat({ bigint: true }); assert.equal(before.uid, 0n); assert.equal(before.gid, 0n);
    await created.chown(ledger.uid, ledger.gid);
    assert.deepEqual(identity(await lstat(directory, { bigint: true })), identity(await created.stat({ bigint: true })));
  } finally { await created.close(); }
  const child = spawn('/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
    `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', built.executable, mode],
  { cwd: ledger.home, env: environment, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = ''; let spawnError: Error | undefined; let proc: FileHandle | undefined; let start: string | undefined;
  let pid: number | undefined; let timedOut = false;
  child.stderr.on('data', bytes => { stderr += bytes.toString(); if (stderr.length > 65536) kill(); });
  const joined = new Promise<void>(resolve => { child.once('error', error => { spawnError = error; }); child.once('close', () => resolve()); });
  function kill() {
    if (child.pid && child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
    }
  }
  const timer = setTimeout(() => { timedOut = true; kill(); }, 30000);
  const events: Record<string, unknown>[] = []; const cuts: Awaited<ReturnType<typeof observe>>[] = [];
  try {
    for await (const line of createInterface({ input: child.stdout })) {
      assert(Buffer.byteLength(line) <= 65536);
      const event = structuredClone(parseJsonStrict(line)) as Record<string, unknown>;
      assert.equal(event.protocol, 'cliq-sqlite-vfs-mechanism-v1'); assert.equal(event.diagnosticOnly, true);
      assert.notEqual(event.phase, 'fatal', String(event.error)); events.push(event);
      if (event.phase === 'completed') continue;
      assert.equal(event.nodeVersion, 'v24.21.0'); assert.equal(event.mode, mode);
      assert.equal(event.uid, ledger.uid); assert.equal(event.euid, ledger.uid);
      assert.equal(event.gid, ledger.gid); assert.equal(event.egid, ledger.gid); assert.deepEqual(event.groups, [ledger.gid]);
      if (!proc) {
        assert(Number.isSafeInteger(event.pid) && Number(event.pid) > 0); pid = Number(event.pid); start = String(event.startTicks);
        proc = await open(`/proc/${pid}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      }
      assert.equal(event.pid, pid); assert.equal(event.startTicks, start);
      cuts.push(await observe(proc, pid!, start!, ledger, built, mode, String(event.phase), Number(event.helperFd)));
      child.stdin.write('continue\n');
    }
    await joined; assert.equal(spawnError, undefined); assert.equal(timedOut, false);
    assert.equal(child.signalCode, null); assert.equal(child.exitCode, 0, stderr);
    const expected = mode === 'unregistered' ? ['unregistered', 'completed']
      : mode === 'tampered' ? ['signature_bound_digest_refused', 'completed']
        : ['loaded', 'bootstrap_and_image_fd_closed', mode === 'scoped' ? 'unregistered_after_unload' : 'callback_refused', 'completed'];
    assert.deepEqual(events.map(event => event.phase), expected);
    assert.equal(stderr.split('\n').filter(line => line === 'CLIQ_SQLITE_VFS_MECHANISM_OPEN').length,
      mode === 'permanent' || mode === 'dual' ? 2 : 0);
    assert.deepEqual(await readdir(directory), [], 'refusing mechanism must create no database or sidecars');
    const ended = await readFile(`/proc/${pid}/stat`, 'utf8').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined; throw error;
    });
    assert(ended === undefined || procStart(ended) !== start, 'the exact diagnostic process lifetime must join');
    return { mode, completed: true, events, cuts, stderr, actualProcessJoined: true, databaseAndSidecarInventory: [] };
  } finally { clearTimeout(timer); kill(); await joined; await proc?.close(); }
}

export async function qualifySqliteVfsMechanism(ledger: Fixture, carrier: { nodeRoot: string; carrier: string }) {
  const results: Awaited<ReturnType<typeof runCase>>[] = [];
  const report: Record<string, unknown> = { ...describeSqliteVfsMechanism(), completed: false, results };
  try {
    const built = await construct(ledger, carrier); report.construction = built.construction;
    for (const mode of modes) { report.currentMode = mode; results.push(await runCase(ledger, built, mode)); }
    delete report.currentMode;
    report.completed = true; report.registrationAndLoadingMechanismQualified = true;
  } catch (error) { report.error = String((error as Error).stack ?? error); }
  return report;
}
