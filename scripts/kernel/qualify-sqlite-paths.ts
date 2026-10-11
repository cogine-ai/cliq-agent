// Test-only path/VFS behavior diagnostic. Never credential or installed I1 authority.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, stat, writeFile,
  type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { buildSupervisorSeaImage, prepareSupervisorSeaCarrier,
  SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

type PathKind = 'canonical' | 'held_parent';
type Cut = 'normal' | 'parent_before_open' | 'parent_after_open' | 'leaf_before_open';
const cases = (['canonical', 'held_parent'] as const).flatMap(pathKind =>
  (['normal', 'parent_before_open', 'parent_after_open', 'leaf_before_open'] as const).map(cut => ({ pathKind, cut })));
const repository = fileURLToPath(new URL('../..', import.meta.url));
const protocol = 'cliq-sqlite-path-v1';
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
type Ledger = { diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string;
  sqlitePaths: { buildFixture: string; caseRoot: string; reportFile: string } };
type Identity = ReturnType<typeof identity>;
type Message = Record<string, unknown> & { protocol: string; diagnosticOnly: true; phase: string };
type ObservedDescriptor = { fd: number; diagnosticOriginalFd: boolean; actual: Identity;
  physicalDatabase: 'original' | 'replacement' | 'sidecar'; link: string; fdinfo: string };
const tracedCalls = 'open,openat,openat2,newfstatat,fstat,statx,readlink,readlinkat,fcntl,fsync,fdatasync,close,mmap,munmap,unlink,unlinkat,ftruncate,pread64,pwrite64,write';

function identity(info: BigIntStats) {
  return { dev: String(info.dev), ino: String(info.ino), size: String(info.size), uid: String(info.uid),
    gid: String(info.gid), mode: String(info.mode), nlink: String(info.nlink),
    mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs) };
}
function sameObject(a: Identity, b: Identity) { return a.dev === b.dev && a.ino === b.ino; }
function privateFile(info: BigIntStats, ledger: Ledger) {
  assert(info.isFile()); assert.equal(info.uid, BigInt(ledger.uid)); assert.equal(info.gid, BigInt(ledger.gid));
  assert.equal(info.nlink, 1n); assert.equal(info.mode & 0o7777n, 0o600n);
}
function parseMessage(line: string): Message {
  assert(Buffer.byteLength(line) <= 65536, 'diagnostic message exceeded bound');
  const message = parseJsonStrict(line) as Message;
  assert(message && typeof message === 'object'); assert.equal(message.protocol, protocol);
  assert.equal(message.diagnosticOnly, true); assert.equal(typeof message.phase, 'string');
  // Strict decoding uses null-prototype records. Diagnostic comparisons care
  // about the observed JSON values, not that decoder implementation detail.
  return structuredClone(message);
}

async function ledgerFrom(filename: string): Promise<Ledger> {
  assert.equal(process.platform, 'linux', 'campaign requires actual Linux');
  assert.equal(process.geteuid!(), 0, 'campaign requires the existing root fixture orchestrator');
  assert.equal(process.getegid!(), 0);
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let ledger: Ledger;
  try {
    const info = await held.stat();
    assert(info.isFile()); assert.equal(info.uid, 0); assert.equal(info.nlink, 1);
    assert.equal(info.mode & 0o7777, 0o444); assert(info.size <= 65536);
    ledger = parseJsonStrict(await held.readFile('utf8')) as Ledger;
  } finally { await held.close(); }
  assert.equal(ledger.diagnosticOnly, true);
  for (const number of [ledger.uid, ledger.gid, ledger.runnerUid]) assert(Number.isSafeInteger(number) && number > 0);
  assert.notEqual(ledger.uid, ledger.runnerUid); assert.equal(ledger.uid, ledger.gid);
  assert.match(ledger.fixture, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+$/u);
  const fixture = await lstat(ledger.fixture, { bigint: true });
  assert(fixture.isDirectory() && !fixture.isSymbolicLink()); assert.equal(fixture.uid, 0n);
  assert.equal(fixture.mode & 0o7777n, 0o755n);
  assert.equal(`${fixture.dev}:${fixture.ino}:${fixture.uid}`, ledger.fixtureIdentity);
  const suffix = ledger.fixture.slice(ledger.fixture.lastIndexOf('.') + 1);
  assert.equal(ledger.username, `cliq-probe-${suffix.toLowerCase()}`);
  assert.equal(ledger.home, path.join(ledger.fixture, 'home'));
  assert(ledger.sqlitePaths && typeof ledger.sqlitePaths === 'object');
  assert.deepEqual(Object.keys(ledger.sqlitePaths).sort(), ['buildFixture', 'caseRoot', 'reportFile']);
  assert.equal(ledger.sqlitePaths.buildFixture, path.join(ledger.fixture, 'sqlite-path-build'));
  assert.equal(ledger.sqlitePaths.caseRoot, path.join(ledger.home, 'probe/sqlite-path-cases'));
  assert(path.isAbsolute(ledger.sqlitePaths.reportFile) && path.basename(ledger.sqlitePaths.reportFile) === 'sqlite-paths.json');
  const output = await lstat(path.dirname(ledger.sqlitePaths.reportFile));
  assert(output.isDirectory() && !output.isSymbolicLink()); assert.equal(output.uid, 0); assert.equal(output.gid, 0);
  assert.equal(output.mode & 0o7777, 0o755);
  for (const directory of [ledger.home, path.join(ledger.home, 'probe')]) {
    const info = await lstat(directory);
    assert(info.isDirectory() && !info.isSymbolicLink()); assert.equal(info.uid, ledger.uid); assert.equal(info.gid, ledger.gid);
    assert.equal(info.mode & 0o7777, 0o700);
  }
  const account = spawnSync('/usr/bin/getent', ['passwd', ledger.username], { env: environment, encoding: 'utf8' });
  assert.equal(account.status, 0); const fields = account.stdout.trim().split(':');
  assert.equal(fields[0], ledger.username); assert.equal(fields[2], String(ledger.uid));
  assert.equal(fields[3], String(ledger.gid)); assert.equal(fields[5], ledger.home);
  return ledger;
}

async function buildDiagnostic(ledger: Ledger) {
  const stage = ledger.sqlitePaths.buildFixture;
  await mkdir(stage, { mode: 0o755 }); // Exclusive fresh stage, never adopt or chown a shared tree.
  const carrier = await prepareSupervisorSeaCarrier(stage);
  const sourcePath = path.join(repository, 'src/state/sqlite-driver.ts');
  const original = await readFile(sourcePath, 'utf8');
  const needle = '  prepareDatabasePath(databasePath);';
  assert.equal(original.split(needle).length, 2, 'diagnostic preopen seam must uniquely match the production call-site');
  const insertion = '\n  (globalThis as typeof globalThis & { __cliqSqlitePathPreopen?: () => void }).__cliqSqlitePathPreopen?.();';
  const transformed = original.replace(needle, needle + insertion);
  let matches = 0;
  const bundle = path.join(stage, 'sqlite-path-diagnostic-input.cjs');
  const built = await build({ entryPoints: [fileURLToPath(new URL('./testing/sqlite-path-probe.ts', import.meta.url))],
    outfile: bundle, bundle: true, format: 'cjs', platform: 'node', target: 'node24.21', metafile: true,
    plugins: [{ name: 'unique-diagnostic-preopen-barrier', setup(builder) {
      builder.onLoad({ filter: /sqlite-driver\.ts$/u }, async input => {
        assert.equal(input.path, sourcePath); assert.equal(await readFile(input.path, 'utf8'), original);
        matches++; return { contents: transformed, loader: 'ts', resolveDir: path.dirname(sourcePath) };
      });
    } }] });
  assert.equal(matches, 1, 'production driver variant must be transformed exactly once');
  for (const emitted of Object.values(built.metafile!.outputs))
    assert(emitted.imports.every(item => item.external && item.path.startsWith('node:')));
  const executable = path.join(stage, 'sqlite-path-diagnostic');
  await buildSupervisorSeaImage({ fixture: stage, carrier: carrier.carrier, entryPoint: bundle, executable,
    variant: 'sqlite-path-diagnostic-image', assets: {} });
  const held = await open(executable, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await held.stat(); assert(info.isFile()); assert.equal(info.uid, 0); assert.equal(info.gid, 0); assert.equal(info.nlink, 1);
    await held.chmod(0o555); // Diagnostic only: allow the disposable UID to execute/read this root-owned image.
  } finally { await held.close(); }
  const image = await readFile(executable);
  const key = generateKeyPairSync('ed25519');
  const signature = sign(null, image, key.privateKey);
  assert(verify(null, image, key.publicKey, signature), 'final diagnostic image signature must verify before execution');
  const digest = createHash('sha256').update(image).digest('hex');
  return { executable, digest, imageIdentity: identity(await lstat(executable, { bigint: true })),
    construction: { diagnosticOnly: true, originalDriverSha256: createHash('sha256').update(original).digest('hex'),
      transformedDriverSha256: createHash('sha256').update(transformed).digest('hex'), uniquePreopenInsertionCount: matches,
      bundledInputSha256: createHash('sha256').update(await readFile(bundle)).digest('hex'),
      finalImageSha256: digest, diagnosticSignature: signature.toString('hex'),
      diagnosticPublicKey: key.publicKey.export({ type: 'spki', format: 'pem' }),
      signatureScope: 'ephemeral diagnostic image only; not release signature, credential authority, or installed I1' } };
}

function userArgs(ledger: Ledger, executable: string, args: string[]) {
  return ['--user', ledger.username, '--', '/usr/bin/env', '-i', `HOME=${ledger.home}`,
    'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', executable, ...args];
}
function traceArguments(prefix: string, executable: string, args: string[]) {
  // Jammy strace 5.16 supports -I 1, but not the later --kill-on-exit.
  // Tracer, child and runuser remain in this new owned spawn group; failed
  // primary joins kill only that group, then the frozen shell ledger cleans up.
  return ['-I', '1', '-ff', '-yy', '-s', '256', '-o', prefix, '-e', `trace=${tracedCalls}`, executable, ...args];
}
function joinedDiagnostic(ledger: Ledger, executable: string, args: string[], expected: string, tracePrefix?: string) {
  const result = spawnSync('/usr/sbin/runuser', userArgs(ledger, tracePrefix ? '/usr/bin/strace' : executable,
    tracePrefix ? traceArguments(tracePrefix, executable, args) : args), { cwd: ledger.home,
    env: environment, encoding: 'utf8', timeout: 30000, maxBuffer: 131072 });
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr + result.stdout);
  const lines = result.stdout.trim().split('\n'); assert.equal(lines.length, 1);
  const message = parseMessage(lines[0]!); assert.equal(message.phase, expected);
  assert.equal(message.nodeVersion, `v${SUPERVISOR_SEA_NODE_VERSION}`);
  for (const field of ['uid', 'euid', 'gid', 'egid']) assert.equal(message[field], ledger.uid);
  assert.deepEqual(message.groups, [ledger.gid]);
  return { message, stderr: result.stderr, joined: true, traced: tracePrefix !== undefined };
}

async function filesAt(caseDirectory: string, ledger: Ledger) {
  const result: Record<string, Identity> = {};
  for (const parent of ['credentials', 'replacement', 'retired-credentials']) {
    const directory = path.join(caseDirectory, parent);
    const info = await lstat(directory, { bigint: true }).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined; throw error;
    });
    if (!info) continue;
    assert(info.isDirectory() && !info.isSymbolicLink()); assert.equal(info.uid, BigInt(ledger.uid)); assert.equal(info.gid, BigInt(ledger.gid));
    assert.equal(info.mode & 0o7777n, 0o700n); result[parent] = identity(info);
    for (const name of await readdir(directory)) {
      assert(/^(?:original-)?authority\.sqlite(?:-journal|-wal|-shm)?$/u.test(name), 'unregistered diagnostic leaf');
      const leaf = await lstat(path.join(directory, name), { bigint: true });
      assert(!leaf.isSymbolicLink()); privateFile(leaf, ledger); result[`${parent}/${name}`] = identity(leaf);
    }
  }
  return result;
}
function procStart(text: string) {
  const fields = text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert.match(fields[19]!, /^[1-9][0-9]*$/u); return fields[19]!;
}
async function observe(proc: FileHandle, pid: number, start: string, ledger: Ledger,
  diagnostic: Awaited<ReturnType<typeof buildDiagnostic>>, parentFd: number, originalParent: Identity,
  excludedFd: number, original: Identity, replacement: Identity, verifyImageBytes = false) {
  const base = `/proc/self/fd/${proc.fd}`;
  assert.equal(procStart(await readFile(`${base}/stat`, 'utf8')), start);
  const status = await readFile(`${base}/status`, 'utf8');
  for (const field of ['Uid', 'Gid']) {
    const found = new RegExp(`^${field}:\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)$`, 'mu').exec(status);
    assert(found); assert.deepEqual(found.slice(1), Array(4).fill(String(ledger.uid)));
  }
  const groups = /^Groups:\s*([^\n]*)$/mu.exec(status); assert(groups);
  assert.deepEqual(groups[1]!.trim().split(/\s+/u), [String(ledger.gid)]);
  const exe = identity(await stat(`${base}/exe`, { bigint: true }));
  assert.deepEqual(exe, diagnostic.imageIdentity, 'actual process must hold the exact final signed diagnostic image');
  if (verifyImageBytes) assert.equal(createHash('sha256').update(await readFile(`${base}/exe`)).digest('hex'), diagnostic.digest);
  const parent = await stat(`${base}/fd/${parentFd}`, { bigint: true });
  assert(parent.isDirectory()); assert(sameObject(identity(parent), originalParent));
  assert.equal(parent.uid, BigInt(ledger.uid)); assert.equal(parent.gid, BigInt(ledger.gid));
  assert.equal(parent.mode & 0o7777n, 0o700n);
  const heldOriginal = await stat(`${base}/fd/${excludedFd}`, { bigint: true });
  privateFile(heldOriginal, ledger); assert(sameObject(identity(heldOriginal), original));
  const descriptors: ObservedDescriptor[] = [];
  for (const name of await readdir(`${base}/fd`)) {
    assert.match(name, /^(0|[1-9][0-9]*)$/u);
    const fd = Number(name);
    const info = await stat(`${base}/fd/${name}`, { bigint: true }).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined; throw error;
    });
    if (!info?.isFile()) continue;
    const actual = identity(info);
    const link = await readlink(`${base}/fd/${name}`);
    if (!sameObject(actual, original) && !sameObject(actual, replacement) && !/authority\.sqlite-(journal|wal|shm)(?: \(deleted\))?$/u.test(link)) continue;
    privateFile(info, ledger);
    descriptors.push({ fd, diagnosticOriginalFd: fd === excludedFd, actual,
      physicalDatabase: sameObject(actual, original) ? 'original' : sameObject(actual, replacement) ? 'replacement' : 'sidecar',
      link, fdinfo: await readFile(`${base}/fdinfo/${name}`, 'utf8') });
  }
  assert.equal(procStart(await readFile(`${base}/stat`, 'utf8')), start);
  return { pid, startTicks: start, fullCredentials: { uid: ledger.uid, gid: ledger.gid, groups: [ledger.gid] },
    actualImage: exe, imageObservation: verifyImageBytes ? 'fresh_full9_and_actual_byte_digest' : 'fresh_full9_matches_preopen_hashed_image',
    heldParent: { fd: parentFd, actual: identity(parent), link: await readlink(`${base}/fd/${parentFd}`) }, descriptors };
}

async function runCase(ledger: Ledger, diagnostic: Awaited<ReturnType<typeof buildDiagnostic>>, selected: { pathKind: PathKind; cut: Cut }) {
  const id = `${selected.pathKind}-${selected.cut}`;
  const caseDirectory = path.join(ledger.sqlitePaths.caseRoot, id);
  const argumentsFor = (mode: string) => [mode, caseDirectory, selected.pathKind, selected.cut];
  const seeded = joinedDiagnostic(ledger, diagnostic.executable, argumentsFor('--seed'), 'seeded');
  const original = seeded.message.original as Identity, replacement = seeded.message.replacement as Identity;
  assert(!sameObject(original, replacement));
  const before = await filesAt(caseDirectory, ledger);
  assert.deepEqual(before['credentials/authority.sqlite'], original);
  assert.deepEqual(before['replacement/authority.sqlite'], replacement);
  const tracePrefix = path.join(caseDirectory, 'syscalls');
  const child = spawn('/usr/sbin/runuser', userArgs(ledger, '/usr/bin/strace',
    traceArguments(tracePrefix, diagnostic.executable, argumentsFor('--primary'))), { cwd: ledger.home, env: environment, detached: true,
    stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '', proc: FileHandle | undefined, actualPid: number | undefined, start: string | undefined;
  let outcome: Message | undefined, mutation: ReturnType<typeof joinedDiagnostic> | undefined;
  const orderedPhases = ['preopen', 'after_open', 'delete_active', 'wal_open', 'wal_active', 'wal_committed', 'checkpointed'];
  let phaseIndex = 0;
  const cuts: { phase: string; event: Message; filesystem: Awaited<ReturnType<typeof filesAt>>;
    process?: Awaited<ReturnType<typeof observe>> }[] = [];
  child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); if (stderr.length > 131072) child.kill('SIGKILL'); });
  child.stdin.on('error', () => undefined); // Exit is checked after the close event, never accepted as a continuation.
  const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const timer = setTimeout(() => {
    if (child.pid && child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    }
  }, 60000);
  try {
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    for await (const line of lines) {
      const event = parseMessage(line);
      assert.notEqual(event.phase, 'fatal', String(event.error));
      assert.equal(outcome, undefined, 'no events may follow the final joined-close report');
      if (event.phase === 'outcome') { outcome = event; continue; }
      assert.equal(event.phase, orderedPhases[phaseIndex++], 'primary must reach each fixed cut once, in order');
      if (!proc) {
        assert.equal(event.phase, 'preopen');
        assert(Number.isSafeInteger(event.pid) && Number(event.pid) > 0); actualPid = Number(event.pid);
        assert.match(String(event.startTicks), /^[1-9][0-9]*$/u); start = String(event.startTicks);
        proc = await open(`/proc/${actualPid}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        assert.deepEqual(event.original, original); assert.deepEqual(event.parent, before.credentials);
      }
      const first = cuts[0]?.event ?? event;
      assert(Number.isSafeInteger(first.originalFd) && Number(first.originalFd) >= 3);
      assert(Number.isSafeInteger(first.parentFd) && Number(first.parentFd) >= 3 && first.parentFd !== first.originalFd);
      assert.equal(first.databasePath, selected.pathKind === 'canonical' ? path.join(caseDirectory, 'credentials/authority.sqlite')
        : `/proc/self/fd/${first.parentFd}/authority.sqlite`);
      const processCut = await observe(proc, actualPid!, start!, ledger, diagnostic, Number(first.parentFd), before.credentials!,
        Number(first.originalFd), original, replacement, event.phase === 'preopen');
      if (event.phase !== 'preopen') assert(processCut.descriptors.some(fd => !fd.diagnosticOriginalFd && fd.physicalDatabase !== 'sidecar'),
        'an open SQLite connection must be observed through its own actual database descriptor');
      cuts.push({ phase: event.phase, event, filesystem: await filesAt(caseDirectory, ledger), process: processCut });
      if ((event.phase === 'preopen' && ['parent_before_open', 'leaf_before_open'].includes(selected.cut)) ||
        (event.phase === 'after_open' && selected.cut === 'parent_after_open')) {
        assert.equal(mutation, undefined); mutation = joinedDiagnostic(ledger, diagnostic.executable, argumentsFor('--mutate'), 'mutated');
        assert(sameObject(mutation.message.original as Identity, original)); assert(sameObject(mutation.message.replacement as Identity, replacement));
        cuts.push({ phase: 'mutated', event: mutation.message, filesystem: await filesAt(caseDirectory, ledger),
          process: await observe(proc, actualPid!, start!, ledger, diagnostic, Number(first.parentFd), before.credentials!,
            Number(first.originalFd), original, replacement) });
      }
      child.stdin.write('continue\n');
    }
    const exit = await joined; assert.equal(exit.signal, null, stderr); assert.equal(exit.code, 0, stderr);
    assert(outcome, 'primary must report its joined close order');
    assert.equal(outcome.closeOrder, 'sqlite_then_extra_database_fd_then_parent_fd');
    assert.equal(outcome.pid, actualPid); assert.equal(outcome.startTicks, start);
    if (outcome.operation === 'completed') assert.equal(phaseIndex, orderedPhases.length);
    await assert.rejects(readFile(`/proc/self/fd/${proc!.fd}/stat`, 'utf8'),
      (error: NodeJS.ErrnoException) => ['ENOENT', 'ESRCH'].includes(error.code!), 'the traced original lifetime must be absent after join');
    if (selected.cut !== 'normal') assert(mutation, 'interference must actually have executed at its fixed barrier');
    // Join the entire tracing process before any independent SQLite reopen.
    const afterPrimary = await filesAt(caseDirectory, ledger);
    const reopenOriginal = joinedDiagnostic(ledger, diagnostic.executable, [...argumentsFor('--reopen'), 'original'], 'reopened',
      path.join(caseDirectory, 'reopen-original'));
    const reopenReplacement = joinedDiagnostic(ledger, diagnostic.executable, [...argumentsFor('--reopen'), 'replacement'], 'reopened',
      path.join(caseDirectory, 'reopen-replacement'));
    assert.equal((reopenOriginal.message.marker as { value: string }).value, 'A');
    assert.equal((reopenReplacement.message.marker as { value: string }).value, 'B');
    assert(sameObject(reopenOriginal.message.identity as Identity, original));
    assert(sameObject(reopenReplacement.message.identity as Identity, replacement));
    for (const result of [reopenOriginal, reopenReplacement]) {
      assert.deepEqual(result.message.integrity, [{ integrity_check: 'ok' }]);
      assert.notEqual(result.message.pid, actualPid);
    }
    const traces: { filename: string; sha256: string; raw: string }[] = [];
    for (const filename of (await readdir(caseDirectory)).filter(name => /^(?:syscalls|reopen-original|reopen-replacement)\.[1-9][0-9]*$/u.test(name)).sort()) {
      const info = await lstat(path.join(caseDirectory, filename)); assert(info.isFile() && !info.isSymbolicLink());
      assert.equal(info.uid, ledger.uid); assert.equal(info.gid, ledger.gid); assert.equal(info.nlink, 1);
      assert(info.size > 0 && info.size <= 2 * 1024 * 1024);
      const raw = await readFile(path.join(caseDirectory, filename), 'utf8');
      traces.push({ filename, sha256: createHash('sha256').update(raw).digest('hex'), raw });
    }
    assert(traces.some(trace => trace.filename === `syscalls.${actualPid}`), 'actual SQLite PID must have an independently retained syscall trace');
    for (const [kind, result] of [['original', reopenOriginal], ['replacement', reopenReplacement]] as const)
      assert(traces.some(trace => trace.filename === `reopen-${kind}.${result.message.pid}`), 'each independent reopen must retain its actual PID trace');
    const raw = traces.find(trace => trace.filename === `syscalls.${actualPid}`)!.raw;
    const traceLines = raw.split('\n');
    const preopenWrite = traceLines.findIndex(line => line.startsWith('write(1') && line.includes('\\"phase\\":\\"preopen\\"'));
    const outcomeWrite = traceLines.findIndex(line => line.startsWith('write(1') && line.includes('\\"phase\\":\\"outcome\\"'));
    assert(preopenWrite >= 0 && outcomeWrite > preopenWrite, 'actual trace must delimit the SQLite lifetime');
    const lastClose = (fd: number, actualLink: string) => {
      let found = -1;
      for (let index = preopenWrite + 1; index < outcomeWrite; index++) {
        const match = /^close\(([0-9]+)<([^>]*)>\)\s+=\s+0\b/u.exec(traceLines[index]!);
        if (match && Number(match[1]) === fd && match[2] === actualLink) found = index;
      }
      return found;
    };
    const firstEvent = cuts[0]!.event;
    const lastProcessCut = cuts.at(-1)!.process!;
    const extraDatabase = lastProcessCut.descriptors.find(fd => fd.diagnosticOriginalFd)!;
    assert(extraDatabase);
    const extraDatabaseClose = lastClose(extraDatabase.fd, extraDatabase.link);
    const parentClose = lastClose(lastProcessCut.heldParent.fd, lastProcessCut.heldParent.link);
    assert(extraDatabaseClose > preopenWrite && parentClose > extraDatabaseClose,
      'trace must show the extra DB descriptor closing before its parent descriptor');
    const sqliteFds = new Map<number, ObservedDescriptor>();
    for (const cut of cuts) for (const fd of cut.process?.descriptors ?? [])
      if (!fd.diagnosticOriginalFd && fd.physicalDatabase !== 'sidecar') sqliteFds.set(fd.fd, fd);
    const sqliteCloses = [...sqliteFds.values()].map(fd => ({ fd: fd.fd, actualLink: fd.link, traceLine: lastClose(fd.fd, fd.link) }));
    for (const close of sqliteCloses) assert(close.traceLine > preopenWrite && close.traceLine < extraDatabaseClose,
      'trace must independently show every observed SQLite DB descriptor closing before the extra DB descriptor');
    const calls = ['open', 'openat', 'openat2', 'fcntl', 'fsync', 'fdatasync', 'close', 'mmap', 'munmap', 'unlink', 'unlinkat', 'ftruncate', 'pread64', 'pwrite64'];
    const syscallCounts = Object.fromEntries(calls.map(call => [call, raw.split('\n').filter(line => line.startsWith(`${call}(`)).length]));
    const originalWrites = reopenOriginal.message.writes as { kind: string; marker: string }[];
    const replacementWrites = reopenReplacement.message.writes as { kind: string; marker: string }[];
    for (const writes of [originalWrites, replacementWrites]) assert(!writes.some(row => row.kind === 'delete-rollback'));
    if (selected.cut === 'normal') {
      assert.equal(outcome.operation, 'completed');
      assert.deepEqual(originalWrites, [{ kind: 'delete-committed', marker: 'A' }, { kind: 'wal-committed', marker: 'A' }]);
      assert.deepEqual(replacementWrites, []);
      assert((syscallCounts.openat! + syscallCounts.open!) > 0 && syscallCounts.fcntl! > 0 && syscallCounts.close! > 0);
      assert((syscallCounts.fsync! + syscallCounts.fdatasync!) > 0, 'normal FULL transactions must show actual sync syscalls');
      assert(cuts.some(cut => Object.keys(cut.filesystem).some(name => name.endsWith('-journal'))));
      assert(cuts.some(cut => Object.keys(cut.filesystem).some(name => name.endsWith('-wal'))));
      assert(cuts.some(cut => Object.keys(cut.filesystem).some(name => name.endsWith('-shm'))));
    }
    const replacementUsed = replacementWrites.length > 0 || cuts.some(cut => cut.process?.descriptors.some(fd =>
      !fd.diagnosticOriginalFd && fd.physicalDatabase === 'replacement')) || outcome.marker === 'B';
    const sidecarOutsideOriginalParent = cuts.some(cut => Object.entries(cut.filesystem).some(([relative]) => {
      if (!/authority\.sqlite-(journal|wal|shm)$/u.test(relative)) return false;
      const parent = cut.filesystem[path.dirname(relative)]!;
      return !sameObject(parent, before.credentials!);
    }));
    const mutationPhase = selected.cut === 'parent_after_open' ? 'after_open' : 'preopen';
    const mutationBoundary = selected.cut === 'normal' ? -1 : traceLines.findIndex(line =>
      line.startsWith('write(1') && line.includes(`\\"phase\\":\\"${mutationPhase}\\"`));
    const replacementPath = path.join(caseDirectory, 'credentials/authority.sqlite');
    // A positive trace proves transient named replacement access even when it
    // disappeared before a barrier. Absence of these path annotations cannot
    // prove zero I/O; raw traces and physical FD cuts remain the evidence.
    const postMutationReplacementPathSyscalls = mutationBoundary < 0 ? [] : traceLines.slice(mutationBoundary + 1, outcomeWrite)
      .filter(line => /^(?:open|openat|openat2|newfstatat|statx|readlink|readlinkat|fcntl|fsync|fdatasync|close|mmap|munmap|unlink|unlinkat|ftruncate|pread64|pwrite64)\(/u.test(line)
        && line.includes(replacementPath) && /\)\s+=\s+(?:0|[1-9][0-9]*)(?:<|\s|$)/u.test(line));
    const completeOriginalWriteSet = JSON.stringify(originalWrites) === JSON.stringify([
      { kind: 'delete-committed', marker: 'A' }, { kind: 'wal-committed', marker: 'A' }]);
    return { ...selected, completed: true, seeded, before, cuts, outcome, afterPrimary,
      independentReopens: [reopenOriginal, reopenReplacement], afterReopen: await filesAt(caseDirectory, ledger),
      replacementUsed, sidecarOutsideOriginalParent, postMutationReplacementPathSyscalls, completeOriginalWriteSet,
      descriptorProtectionQualified: false, transientIoAbsenceQualified: false,
      descriptorProtectionObservation: selected.cut === 'normal' ? 'baseline_only'
        : replacementUsed || sidecarOutsideOriginalParent || postMutationReplacementPathSyscalls.length > 0 ? 'replacement_access_observed'
          : outcome.operation === 'completed' && completeOriginalWriteSet && replacementWrites.length === 0
            ? 'no_replacement_access_in_recorded_cuts_not_zero_io_proof' : 'refused_or_incomplete',
      tracedPrimaryJoined: true, syscallCounts, actualDatabaseAndSidecarTrace: raw.split('\n').filter(line => line.includes('authority.sqlite')),
      observedCloseOrder: { sqliteCloses, extraDatabaseFd: Number(firstEvent.originalFd), extraDatabaseClose,
        parentFd: Number(firstEvent.parentFd), parentClose, outcomeWrite }, traces, stderr };
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null && child.pid) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
    }
    await joined;
    await proc?.close(); // This observer never opened a same-process SQLite DB descriptor.
  }
}

async function campaign(filename: string) {
  const ledger = await ledgerFrom(filename);
  const report: Record<string, unknown> = { ...describe(), completed: false,
    fixtureIdentity: ledger.fixtureIdentity, uid: ledger.uid, gid: ledger.gid,
    limitations: ['Path/VFS diagnostic only; no credential lock or authority binding',
      'No installed production I1 qualification', 'fsync observation is not power-loss qualification'], results: [] };
  try {
    const tracer = spawnSync('/usr/bin/strace', ['--version'], { env: environment, encoding: 'utf8', timeout: 10000 });
    assert.equal(tracer.error, undefined); assert.equal(tracer.status, 0); report.straceVersion = tracer.stdout.trim();
    const diagnostic = await buildDiagnostic(ledger); report.construction = diagnostic.construction;
    await mkdir(ledger.sqlitePaths.caseRoot, { mode: 0o700 });
    const casesRoot = await open(ledger.sqlitePaths.caseRoot, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      const created = await casesRoot.stat({ bigint: true });
      assert(created.isDirectory()); assert.equal(created.uid, 0n); assert.equal(created.gid, 0n);
      assert.equal(created.mode & 0o7777n, 0o700n);
      await casesRoot.chown(ledger.uid, ledger.gid);
      assert(sameObject(identity(await lstat(ledger.sqlitePaths.caseRoot, { bigint: true })), identity(created)),
        'never transfer a replacement case root');
    } finally { await casesRoot.close(); }
    const results = report.results as Awaited<ReturnType<typeof runCase>>[];
    for (const selected of cases) results.push(await runCase(ledger, diagnostic, selected));
    assert.equal(results.length, 8); report.completed = true;
  } catch (error) { report.error = String((error as Error).stack ?? error); process.exitCode = 1; }
  finally { await writeFile(ledger.sqlitePaths.reportFile, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o644 }); }
  process.stdout.write(JSON.stringify({ diagnosticOnly: true, completed: report.completed,
    productionCredentialAuthorityQualified: false, installedI1Qualified: false, reportFile: ledger.sqlitePaths.reportFile }) + '\n');
}

function describe() {
  return { diagnosticOnly: true, productionCredentialAuthorityQualified: false, installedI1Qualified: false,
    carrierVersion: SUPERVISOR_SEA_NODE_VERSION, cases,
    preopenBarrier: 'test-only unique call-site insertion after production prepareDatabasePath',
    observerDescriptorCloseOrder: 'all SQLite connections close before extra DB descriptors' };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const usage = 'usage: qualify-sqlite-paths --describe | --campaign ROOT_OWNED_LEDGER';
    if (process.argv.length === 3 && process.argv[2] === '--describe') process.stdout.write(JSON.stringify(describe()) + '\n');
    else { assert(process.argv.length === 4 && process.argv[2] === '--campaign', usage); await campaign(process.argv[3]!); }
  } catch (error) { process.stderr.write(String((error as Error).message) + '\n'); process.exitCode = 1; }
}
