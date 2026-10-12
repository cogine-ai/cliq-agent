// Actual signed credential journey plus one joined prepared-SIGKILL retry.
// Not the complete crash campaign, live-producer/clock proof or installed I1.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chown, lstat, mkdir, open, readFile, readdir, readlink, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRecord, decodeCredentialAuthorityRevokeOperation, decodeEndpointAuthorityOperation,
  type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { installedReadClientScript } from './installed-read-control.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';
import { crashPreparedCredentialWrite, inspectPreparedCredentialCrashFacts } from './credential-write-crash.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { scanCredentialSecretCorpus } from './credential-secret-corpus.js';

type Recipe = { buildFixture: string; packageRoot: string; installerEntry: string; stateRoot: string;
  releaseKeysFile: string; controlDirectory: string; observer: string; reportFile: string };
type Ledger = { diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string; credentials: Recipe };
type Observation = { clientPid: number; busUniqueName: string; nameOwner: string; serviceUid: number;
  servicePid: number; collection: string; items: string[]; connectionClosed: true;
  item?: string; readback?: true; logicalItemIdMatched?: true };
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const properties = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ExecMainPID', 'ControlGroup',
  'InvocationID', 'FragmentPath', 'Type', 'WorkingDirectory', 'Delegate', 'KillMode', 'Restart', 'NRestarts',
  'Slice', 'Requires', 'After', 'Before', 'Conflicts'] as const;

async function readLedger(filename: string): Promise<Ledger> {
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let ledger: Ledger;
  try {
    const info = await held.stat();
    assert(info.isFile()); assert.equal(info.uid, 0); assert.equal(info.nlink, 1);
    assert.equal(info.mode & 0o7777, 0o444); assert(info.size <= 65536);
    ledger = parseJsonStrict(await held.readFile('utf8')) as Ledger;
  } finally { await held.close(); }
  assert.equal(ledger.diagnosticOnly, true);
  for (const value of [ledger.uid, ledger.gid, ledger.runnerUid]) assert(Number.isSafeInteger(value) && value > 0);
  assert.notEqual(ledger.uid, ledger.runnerUid); assert.equal(ledger.uid, ledger.gid);
  assert.match(ledger.fixture, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+$/u);
  const fixture = await lstat(ledger.fixture, { bigint: true });
  assert(fixture.isDirectory() && !fixture.isSymbolicLink()); assert.equal(fixture.uid, 0n);
  assert.equal(fixture.mode & 0o7777n, 0o755n);
  assert.equal(`${fixture.dev}:${fixture.ino}:${fixture.uid}`, ledger.fixtureIdentity);
  assert.equal(ledger.username, `cliq-probe-${ledger.fixture.split('.').at(-1)!.toLowerCase()}`);
  assert.equal(ledger.home, path.join(ledger.fixture, 'home'));
  const recipe = ledger.credentials;
  assert.deepEqual(Object.keys(recipe).sort(), ['buildFixture', 'controlDirectory', 'installerEntry', 'observer',
    'packageRoot', 'releaseKeysFile', 'reportFile', 'stateRoot'].sort());
  assert.equal(recipe.buildFixture, path.join(ledger.fixture, 'credential-package-build'));
  assert.equal(recipe.packageRoot, path.join(recipe.buildFixture, 'package'));
  assert.equal(recipe.installerEntry, path.join(recipe.buildFixture, 'installed-runtime-installer.mjs'));
  assert.equal(recipe.stateRoot, path.join(ledger.home, 'probe/credential-state'));
  assert.equal(recipe.releaseKeysFile, path.join(ledger.fixture, 'credential-release-keys.json'));
  assert.equal(recipe.controlDirectory, path.join(ledger.home, 'probe/credential-secret-service-control'));
  assert.equal(recipe.observer, path.join(ledger.fixture, 'cliq-credential-journey-observer'));
  assert(path.isAbsolute(recipe.reportFile) && path.basename(recipe.reportFile) === 'credential-journey.json');
  const output = await lstat(path.dirname(recipe.reportFile));
  assert(output.isDirectory() && !output.isSymbolicLink()); assert.equal(output.uid, 0);
  assert.equal(output.mode & 0o7777, 0o755);
  return ledger;
}

// Same post-order, no-follow transfer as the qualified installed fixture. Only
// the newly built package changes owner; never its stage/carrier or StateRoot.
async function transferPackage(filename: string, uid: number, gid: number): Promise<void> {
  const before = await lstat(filename);
  assert(!before.isSymbolicLink() && (before.isDirectory() || before.isFile()));
  assert.equal(before.uid, 0); assert.equal(before.gid, 0);
  if (before.isDirectory()) {
    assert.equal(before.mode & 0o7777, 0o700);
    for (const name of await readdir(filename)) await transferPackage(path.join(filename, name), uid, gid);
  } else { assert.equal(before.nlink, 1); assert([0o400, 0o500].includes(before.mode & 0o7777)); }
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW |
    (before.isDirectory() ? constants.O_DIRECTORY : 0));
  try {
    const actual = await held.stat();
    assert.equal(actual.dev, before.dev); assert.equal(actual.ino, before.ino);
    assert.equal(actual.uid, 0); assert.equal(actual.gid, 0); await held.chown(uid, gid);
  } finally { await held.close(); }
}

async function stageInstaller(recipe: Recipe): Promise<void> {
  const result = await build({ entryPoints: [fileURLToPath(new URL('./installed-runtime-installer.ts', import.meta.url))],
    outfile: recipe.installerEntry, bundle: true, platform: 'node', format: 'esm', target: 'node22.13',
    metafile: true, write: false });
  const imports = Object.values(result.metafile!.outputs).flatMap(output => output.imports);
  assert(imports.every(item => item.external && item.path.startsWith('node:')));
  assert.equal(result.outputFiles!.length, 1);
  const bytes = result.outputFiles![0]!.contents;
  assert(bytes.length > 0 && bytes.length <= 16 * 1024 * 1024);
  await writeFile(recipe.installerEntry, bytes, { flag: 'wx', mode: 0o444 });
}

async function campaign(filename: string): Promise<void> {
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.credentials;
  const report: Record<string, unknown> = { diagnosticOnly: true, qualified: false, phase: 'installation', uid: ledger.uid,
    scope: 'genuine signed credential journey, explicit cleanup, first-prepared same-core retry and prepared-only attempts 1..3 cap with actual user-manager autostart and independent Secret Service byte comparisons; not full crash campaign, live-producer presence, clock regression, broker or I1' };
  const secret = randomBytes(32), rotatedSecret = randomBytes(32), abandonedSecret = randomBytes(32), resubmittedSecret = randomBytes(32),
    password = Buffer.from(randomBytes(32).toString('hex'));
  const capSecrets = [randomBytes(32), randomBytes(32), randomBytes(32)];
  const scanner = createCredentialSecretScanner([secret, rotatedSecret, abandonedSecret, resubmittedSecret, ...capSecrets, password],
    { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 });
  const evidenceDirs: string[] = [];
  const scanBytes = (bytes: Uint8Array) => {
    const stream = scanner.openStream(); try { stream.scan(bytes); } finally { stream.close(); }
  };
  const userPrefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', `HOME=${ledger.home}`,
    'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`];
  const command = (executable: string, args: string[], input?: Buffer, timeout = 30000) => {
    const result = spawnSync('/usr/sbin/runuser', [...userPrefix, executable, ...args],
      { env: environment, cwd: ledger.home, timeout, killSignal: 'SIGKILL', maxBuffer: 256 * 1024, input });
    assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr), 'actual disposable-user command has no joined output');
    scanBytes(result.stdout); scanBytes(result.stderr);
    assert.equal(result.error, undefined, 'actual disposable-user command did not join');
    assert.equal(result.signal, null, 'actual disposable-user command was signaled');
    return { status: result.status, stdout: result.stdout.toString('utf8'), stderr: result.stderr.toString('utf8') };
  };
  // Fixture cleanup facts only, never production producer-death evidence.
  const processFact = async (pid: number) => {
    try {
      const raw = await readFile(`/proc/${pid}/stat`, 'utf8');
      assert(raw.startsWith(`${pid} (`) && raw.length <= 8192);
      const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
      assert(fields.length > 19); assert.match(fields[19]!, /^[1-9][0-9]*$/u);
      const status = await readFile(`/proc/${pid}/status`, 'utf8');
      const uid = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu);
      assert(uid, 'fixture process UID must be observed');
      const confirmed = await readFile(`/proc/${pid}/stat`, 'utf8');
      assert(confirmed.startsWith(`${pid} (`));
      const fresh = confirmed.slice(confirmed.lastIndexOf(')') + 2).trim().split(/\s+/u);
      assert.equal(fresh[19], fields[19], 'fixture process changed during identity observation');
      return { pid, parent: Number(fields[1]), group: Number(fields[2]), session: Number(fields[3]),
        start: fields[19]!, uids: uid.slice(1).map(Number) };
    } catch (error) {
      // A short-lived owned fixture process may exit after /proc was opened.
      // ENOENT and ESRCH both mean this diagnostic read has no current fact;
      // production producer death is still decided by its native observer.
      if (['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) return undefined;
      throw error;
    }
  };
  const waitGone = async (original: NonNullable<Awaited<ReturnType<typeof processFact>>>) => {
    const deadline = Date.now() + 5000;
    for (;;) {
      const current = await processFact(original.pid);
      if (!current || current.start !== original.start) return;
      assert(Date.now() < deadline, 'original fixture process lifetime did not retire'); await delay(20);
    }
  };
  const openInputCommand = async (executable: string, args: string[]) => {
    const outputScans: ReturnType<typeof scanner.openStream>[] = [];
    try { for (let index = 0; index < 2; index++) outputScans.push(scanner.openStream()); }
    catch (error) { for (const scan of outputScans) scan.close(); throw error; }
    const child = (() => {
      try { return spawn('/usr/sbin/runuser', [...userPrefix, executable, ...args],
        { env: environment, cwd: ledger.home, detached: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
      catch (error) { for (const scan of outputScans) scan.close(); throw error; }
    })();
    const streams = [child.stdin, child.stdout, child.stderr] as const;
    const streamsClosed = Promise.all(streams.map(stream => new Promise<void>(resolve => stream.once('close', resolve))));
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    let scanFailure: unknown;
    let capturedBytes = 0, finished = false, spawnFailed = false, outputExceeded = false;
    let launcher: Awaited<ReturnType<typeof processFact>>, auth: Awaited<ReturnType<typeof processFact>>;
    const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
      child.once('close', (code, signal) => { finished = true; resolve({ code, signal }); });
    });
    child.once('error', () => { spawnFailed = true; }); child.stdin.on('error', () => {});
    const capture = (chunks: Buffer[], bytes: Buffer, index: number) => {
      if (scanFailure) return;
      try { outputScans[index]!.scan(bytes); } catch (error) { scanFailure = error; return; }
      if (outputExceeded || capturedBytes + bytes.length > 256 * 1024) { outputExceeded = true; return; }
      capturedBytes += bytes.length; chunks.push(bytes);
    };
    child.stdout.on('data', (bytes: Buffer) => capture(stdout, bytes, 0));
    child.stderr.on('data', (bytes: Buffer) => capture(stderr, bytes, 1));
    const bounded = async <T>(pending: Promise<T>, milliseconds: number): Promise<T> => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try { return await Promise.race([pending, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('owned open-input fixture did not join')), milliseconds);
      })]); } finally { clearTimeout(timer); }
    };
    let primary: unknown;
    try {
      const deadline = Date.now() + 30000;
      while (!finished) {
        if (scanFailure) throw scanFailure;
        assert(!spawnFailed, 'actual open-input signed entry did not spawn');
        assert(!outputExceeded, 'actual open-input signed entry exceeded its output bound');
        assert(Date.now() < deadline, 'committed replay waited for open secret input or unavailable services');
        if (child.pid) {
          const current = await processFact(child.pid);
          if (!launcher && current?.parent === process.pid && current.group === child.pid && current.session === child.pid) launcher = current;
          if (current && launcher?.start === current.start) {
            const children = await readFile(`/proc/${child.pid}/task/${child.pid}/children`, 'utf8').catch((error: NodeJS.ErrnoException) => {
              if (error.code === 'ENOENT') return ''; throw error;
            });
            const pids = children.trim() ? children.trim().split(/\s+/u).map(Number) : [];
            assert(pids.length <= 1, 'trusted runuser must own only the signed auth child');
            if (pids[0]) {
              const observed = await processFact(pids[0]);
              if (observed?.parent === child.pid) auth = observed;
            }
          }
        }
        await Promise.race([joined, delay(20)]);
      }
      const exit = await joined;
      if (scanFailure) throw scanFailure;
      assert(!spawnFailed && !outputExceeded, 'actual open-input signed entry failed');
      assert.equal(exit.signal, null, 'actual open-input signed entry was signaled');
      assert.equal(child.stdin.writableEnded, false, 'fixture must never end or write the secret-input pipe');
      assert.equal(child.stdin.writableLength, 0);
      return { status: exit.code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
    } catch (error) { primary = error; throw error; }
    finally {
      const failures: unknown[] = [];
      if (!finished) {
        let authSignaled = false;
        try {
          const currentAuth = auth && await processFact(auth.pid);
          if (currentAuth && auth && currentAuth.start === auth.start) {
            assert.deepEqual(currentAuth.uids, auth.uids); process.kill(currentAuth.pid, 'SIGKILL'); authSignaled = true;
          }
        } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') failures.push(error); }
        // Let the trusted launcher reap its auth child before a group fallback.
        if (authSignaled) { try { await bounded(joined, 5000); } catch {} }
        if (!finished) {
          try {
            const current = child.pid === undefined ? undefined : await processFact(child.pid);
            if (!launcher && current?.parent === process.pid && current.group === child.pid && current.session === child.pid) launcher = current;
            if (launcher && current?.start === launcher.start && current.group === launcher.pid && current.session === launcher.pid)
              process.kill(-launcher.pid, 'SIGKILL');
            else if (current) throw new Error('owned launcher identity unavailable for safe group retirement');
          } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') failures.push(error); }
        }
        try { await bounded(joined, 5000); } catch (error) { failures.push(error); }
        if (auth) { try { await waitGone(auth); } catch (error) { failures.push(error); } }
      }
      // The pipe remains open until a result or timeout is decided above.
      for (const stream of streams) stream.destroy();
      try { await bounded(streamsClosed, 5000); } catch (error) { failures.push(error); }
      for (const stream of outputScans) stream.close();
      if (scanFailure && primary !== scanFailure) failures.push(scanFailure);
      if (failures.length) throw new AggregateError([primary, ...failures].filter(Boolean), 'owned open-input fixture retirement failed');
    }
  };
  const success = (result: ReturnType<typeof command>, field: string): unknown => {
    // Do not print/store a secret-bearing command's arbitrary stderr/stdout on
    // refusal. A diagnostic may only select one fixed source-owned reason;
    // unknown message/path/stack bytes never become a retained observation.
    if (result.status !== 0) {
      const line = result.stderr.trim().split('\n').at(-1);
      if (line && Buffer.byteLength(line) <= 2048) try {
        const value = parseJsonStrict(line) as Record<string, unknown>;
        assert.equal(value.diagnosticOnly, true); assert.equal(value.scope, 'installed-read-startup');
        const reasons = ['installed service dependencies differ from the fixed profiles',
          'installed service effective configuration drifted; explicit installation remediation is required',
          'installed credential platform rejected an operation',
          'installed credential services are not in a current running invocation',
          'installed keeper did not publish its bounded startup locator',
          'installed Supervisor startup did not reach authenticated readiness',
          'installed Supervisor refused the authenticated credential operation',
          'installed Supervisor hello is incompatible with credential finalization',
          'credential store did not complete a fresh secret round-trip'];
        const reason = reasons.find(candidate => candidate === value.message);
        report.entryRefusal = { diagnosticOnly: true, reason: reason ?? 'unclassified_closed_entry_refusal' };
      } catch { report.entryDiagnosticUnavailable = true; }
    }
    assert.equal(result.status, 0, `actual signed entry refused during ${String(report.phase)}`);
    const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
    assert.deepEqual(Object.keys(value).sort(), [field, 'schemaVersion'].sort()); assert.equal(value.schemaVersion, 1);
    assert.equal(result.stdout, `${canonicalJsonBytes(value).toString('utf8')}\n`);
    return value[field];
  };
  const credential = (metadata: Record<string, unknown>, secret?: Buffer) => {
    const bytes = canonicalJsonBytes(metadata); assert(bytes.length <= 65536);
    return command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential', bytes.toString('base64url')], secret, 60000);
  };
  const show = (unit: string) => {
    const result = command('/usr/bin/systemctl', ['--user', 'show', unit, `--property=${properties.join(',')}`, '--no-pager']);
    assert.equal(result.status, 0, 'actual user manager could not observe installed unit');
    const values: Record<string, string> = {};
    for (const line of result.stdout.trim().split('\n')) {
      const separator = line.indexOf('='); assert(separator > 0);
      const key = line.slice(0, separator); assert(!Object.hasOwn(values, key)); values[key] = line.slice(separator + 1);
    }
    for (const key of properties) assert(Object.hasOwn(values, key)); return values;
  };
  const observe = (mode: 'list' | 'compare', item?: string, logicalId?: string, secret?: Buffer): Observation => {
    const result = command(recipe.observer, [mode, ...(item === undefined ? [] : [item, logicalId!])], secret);
    assert.equal(result.status, 0, 'independent actual Secret Service observer refused');
    const value = parseJsonStrict(result.stdout.trim()) as Observation;
    assert.equal(value.serviceUid, ledger.uid); assert.equal(value.connectionClosed, true);
    for (const pid of [value.clientPid, value.servicePid]) assert(Number.isSafeInteger(pid) && pid > 0);
    for (const name of [value.busUniqueName, value.nameOwner]) assert.match(name, /^:\d+\.\d+$/u);
    assert.match(value.collection, /^\/org\/freedesktop\/secrets\/collection\/[A-Za-z0-9_]+$/u);
    assert.notEqual(value.collection, '/org/freedesktop/secrets/collection/session');
    assert(Array.isArray(value.items));
    for (const named of value.items) assert.match(named, new RegExp(`^${value.collection}/[A-Za-z0-9_]+$`, 'u'));
    return value;
  };
  const serviceName = () => command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call',
    'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']);
  const serviceOwner = () => {
    const result = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call',
      'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.secrets']);
    assert.equal(result.status, 0, 'actual fixture Secret Service owner must be observed');
    const owner = result.stdout.trim().match(/^s "(:[0-9]+\.[0-9]+)"$/u); assert(owner); return owner[1]!;
  };
  let daemon: ReturnType<typeof spawn> | undefined;
  let daemonExit: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
  let daemonClosing: Promise<void> | undefined;
  let daemonFact: Awaited<ReturnType<typeof processFact>>, daemonLauncher: Awaited<ReturnType<typeof processFact>>;
  const stopDaemon = (actualPid?: number): Promise<void> => daemonClosing ??= (async () => {
    if (!daemon || !daemonExit) return;
    if (actualPid !== undefined) {
      assert(daemonFact && daemonLauncher); assert.equal(actualPid, daemonFact.pid);
      assert.equal(daemon.exitCode, null); assert.equal(daemon.signalCode, null);
    }
    if (daemon.exitCode === null && daemon.signalCode === null) {
      if (daemonFact) {
        const current = await processFact(daemonFact.pid), launcher = await processFact(daemon.pid!);
        assert(current && launcher && daemonLauncher, 'actual fixture daemon identity is unavailable');
        assert.equal(current.start, daemonFact.start); assert.deepEqual(current.uids, daemonFact.uids);
        assert.equal(current.parent, daemonLauncher.pid); assert.equal(launcher.start, daemonLauncher.start);
        assert.equal(await readlink(`/proc/${current.pid}/exe`), '/usr/bin/gnome-keyring-daemon');
        process.kill(current.pid, 'SIGTERM');
      } else daemon.kill('SIGTERM');
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      report.daemonExit = await Promise.race([daemonExit, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('actual fixture Secret Service daemon did not join')), 10000);
      })]);
      if (daemonFact) await waitGone(daemonFact);
      report.daemonJoined = true;
    } finally { clearTimeout(timer); }
  })();
  const startDaemon = async (): Promise<Observation> => {
    if (daemon) {
      assert(daemonClosing, 'fixture restart requires the original daemon join'); await daemonClosing;
      assert(daemon.exitCode !== null || daemon.signalCode !== null);
      if (daemonFact) await waitGone(daemonFact);
    }
    daemonClosing = undefined; daemonFact = undefined; daemonLauncher = undefined; report.daemonJoined = false;
    daemon = spawn('/usr/sbin/runuser', [...userPrefix, '/usr/bin/gnome-keyring-daemon', '--foreground', '--components=secrets',
      '--unlock', `--control-directory=${recipe.controlDirectory}`], { env: environment, stdio: ['pipe', 'ignore', 'ignore'] });
    daemonExit = new Promise(resolve => daemon!.once('close', (code, signal) => resolve({ code, signal })));
    daemon.on('error', () => { report.daemonSpawnFailed = true; });
    daemon.stdin!.on('error', () => { report.passwordPipeFailed = true; }); daemon.stdin!.end(password);
    const deadline = Date.now() + 10000;
    for (;;) {
      const owned = serviceName(); assert.equal(owned.status, 0);
      if (owned.stdout.trim() === 'b true') break;
      assert.equal(daemon.exitCode, null); assert(Date.now() < deadline, 'actual platform service did not acquire its name'); await delay(20);
    }
    const owner = serviceOwner(), observation = observe('list'); assert.equal(observation.nameOwner, owner);
    daemonLauncher = await processFact(daemon.pid!); daemonFact = await processFact(observation.servicePid);
    assert(daemonLauncher && daemonFact, 'fixture Secret Service process identity must be observed');
    assert.equal(daemonLauncher.parent, process.pid); assert(daemonLauncher.uids.every(uid => uid === 0));
    assert.equal(daemonFact.parent, daemonLauncher.pid); assert(daemonFact.uids.every(uid => uid === ledger.uid));
    assert.equal(await readlink(`/proc/${observation.servicePid}/exe`), '/usr/bin/gnome-keyring-daemon');
    const actual = await stat(`/proc/${observation.servicePid}/exe`, { bigint: true });
    const named = await lstat('/usr/bin/gnome-keyring-daemon', { bigint: true });
    for (const key of imageFields) assert.equal(actual[key], named[key]);
    assert.equal(serviceOwner(), owner);
    return observation;
  };
  let primary: unknown;
  try {
    await mkdir(recipe.buildFixture, { mode: 0o755 });
    const signed = await buildInstalledSupervisorPackage(recipe.buildFixture);
    assert.equal(signed.packageRoot, recipe.packageRoot);
    await stageInstaller(recipe);
    await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(signed.releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(recipe.packageRoot, ledger.uid, ledger.gid);
    const install = command(process.execPath, [recipe.installerEntry, recipe.packageRoot, recipe.stateRoot, recipe.releaseKeysFile]);
    assert.equal(install.status, 0, 'real disposable-user installation refused');
    const bundleDigest = (parseJsonStrict(install.stdout.trim()) as { bundleDigest: string }).bundleDigest;
    assert.equal(bundleDigest, canonicalSha256(signed.bundle)); report.bundleDigest = bundleDigest;
    const expectedImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
    const absent = serviceName(); assert.equal(absent.status, 0); assert.equal(absent.stdout.trim(), 'b false');
    const helper = await lstat(recipe.observer);
    assert(helper.isFile() && !helper.isSymbolicLink()); assert.equal(helper.uid, 0);
    assert.equal(helper.nlink, 1); assert.equal(helper.mode & 0o7777, 0o555);
    await mkdir(recipe.controlDirectory, { mode: 0o700 }); await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
    const before = await startDaemon(); report.platformBefore = before; assert.deepEqual(before.items, []);
    const originalDaemon = daemonFact; assert(originalDaemon);

    const root = await lstat(recipe.stateRoot, { bigint: true });
    assert(root.isDirectory()); assert.equal(root.uid, BigInt(ledger.uid)); assert.equal(root.mode & 0o7777n, 0o700n);
    const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: root.dev.toString(), directoryFileId: root.ino.toString(),
      mode: 448, openedNoFollow: true, layoutVersion: 1 });
    report.phase = 'install_services';
    const setupResponse = credential({ schemaVersion: 1, kind: 'install_services' });
    report.setupExitStatus = setupResponse.status;
    // Setup has no secret input. Retain only the signed entry's bounded closed
    // diagnostic, never arbitrary subprocess output or a later secret's error.
    if (setupResponse.status !== 0) {
      const line = setupResponse.stderr.trim().split('\n').at(-1);
      if (line && Buffer.byteLength(line) <= 2048) {
        try {
          const diagnostic = parseJsonStrict(line) as Record<string, unknown>;
          assert.equal(diagnostic.diagnosticOnly, true); assert.equal(diagnostic.scope, 'installed-read-startup');
          assert(Object.keys(diagnostic).every(key => ['diagnosticOnly', 'scope', 'code', 'path', 'message'].includes(key)));
          assert.equal(typeof diagnostic.message, 'string'); assert((diagnostic.message as string).length <= 1024);
          assert(diagnostic.code === undefined || typeof diagnostic.code === 'string' && /^[A-Z_]{1,80}$/u.test(diagnostic.code));
          report.setupDiagnostic = { code: diagnostic.code, message: diagnostic.message };
        } catch { report.setupDiagnosticUnavailable = true; }
      }
    }
    assert.equal(setupResponse.status, 0, 'signed install_services must install production profiles before enrollment');
    const setup = parseJsonStrict(setupResponse.stdout.trim()) as { schemaVersion: number; keeperUnit: string; supervisorUnit: string };
    assert.deepEqual(Object.keys(setup).sort(), ['keeperUnit', 'schemaVersion', 'supervisorUnit']); assert.equal(setup.schemaVersion, 1);
    assert.equal(setupResponse.stdout, `${canonicalJsonBytes(setup).toString('utf8')}\n`);
    assert.notEqual(setup.keeperUnit, setup.supervisorUnit); report.services = setup;
    for (const [unit, role] of [[setup.keeperUnit, 'keeper'], [setup.supervisorUnit, 'supervisor']] as const) {
      assert.match(unit, /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,240}\.service$/u);
      const filename = path.join(ledger.home, '.config/systemd/user', unit), profile = await lstat(filename);
      assert(profile.isFile() && !profile.isSymbolicLink()); assert.equal(profile.uid, ledger.uid); assert.equal(profile.nlink, 1);
      assert.equal(profile.mode & 0o022, 0); assert((await readFile(filename, 'utf8')).includes(`ExecStart=${recipe.stateRoot}/runtime/bootstrap --bootstrap-${role}\n`));
      const inactive = show(unit); assert.equal(inactive.FragmentPath, filename);
      assert.equal(inactive.WorkingDirectory, '/');
      assert.equal(inactive.Slice, 'app.slice'); assert(inactive.After.split(' ').includes('-.mount'));
      assert(!inactive.Requires.split(' ').includes('-.mount'), 'fixed roles must not acquire a root-mount startup dependency');
      assert.equal(inactive.ActiveState, 'inactive'); assert.equal(inactive.MainPID, '0');
      report[`${role}Before`] = inactive;
    }
    report.phase = 'endpoint_register';
    const ownerPrincipalId = identityHash('cliq-local-principal-v1', rootDigest, 'linux', ledger.uid);
    const trust = signed.bundle.entries.find(entry => entry.entryId === 'default_https_trust_store')!;
    const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1',
      endpointRegistrationId: 'credential-journey-endpoint', registrationKind: 'user', ownerPrincipalId, purposes: ['model_endpoint'],
      target: { scheme: 'https', hostAscii: 'endpoint.invalid', port: 443, basePath: '/v1', redirectPolicy: 'reject_all' },
      tls: { serverNameAscii: 'endpoint.invalid', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: bundleDigest,
        trustStoreRuntimeBundleManifestDigest: signed.bundle.manifestDigest, trustStoreEntryId: 'default_https_trust_store',
        trustStoreRef: trust.digest, trustStoreDigest: trust.digest, spkiSha256Pins: ['4'.repeat(64)] },
      endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: '2026-10-11T00:00:00.000Z', registrationDigest: '' };
    registration.tlsPolicyDigest = canonicalSha256(registration.tls);
    registration.endpointIdentityDigest = canonicalSha256({ target: registration.target, tlsPolicyDigest: registration.tlsPolicyDigest });
    registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
    const endpointCore = { schemaVersion: 1, kind: 'register', ownerPrincipalId, registration,
      expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' } as const;
    const endpointOperation = decodeEndpointAuthorityOperation(success(command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'],
      canonicalJsonBytes({ schemaVersion: 1, kind: 'commit', requestId: '019a0012-0000-7000-8000-000000000021',
        commandCore: { ...endpointCore, commandDigest: digestOmitting(endpointCore, 'commandDigest') } })), 'operation'));
    assert.equal(endpointOperation.disposition, 'registered');
    const metadata = { schemaVersion: 1, kind: 'enroll', requestId: '019a0012-0000-7000-8000-000000000022',
      credentialGrantId: 'credential-journey-grant', purpose: 'model_endpoint', endpointRegistrationId: registration.endpointRegistrationId,
      secretSubmissionId: 'credential-journey-submission', expiresAt: '2099-01-01T00:00:00.000Z' };
    report.phase = 'enroll';
    const enrolled = credential(metadata, secret);
    const operation = decodeCredentialAuthorityOperation(success(enrolled, 'operation'));
    assert.equal(operation.phase, 'committed'); assert.equal(operation.kind, 'enroll'); assert.equal(operation.attempt, 1);
    assert.equal(operation.requestId, metadata.requestId); assert.equal(operation.credentialGrantId, metadata.credentialGrantId);
    assert.equal(operation.ownerPrincipalId, ownerPrincipalId); assert.equal(operation.commandCore.secretSubmissionId, metadata.secretSubmissionId);
    assert.equal(operation.intendedAuthorityRevision, 1); assert.equal(operation.intendedSecretGeneration, 1);
    report.operation = operation;
    report.phase = 'read';
    const record = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: metadata.credentialGrantId }), 'record'));
    assert.equal(record.state, 'active'); assert.equal(record.authorityRevision, 1); assert.equal(record.secretGeneration, 1);
    assert.equal(record.credentialGrantId, metadata.credentialGrantId); assert.equal(record.ownerPrincipalId, ownerPrincipalId);
    assert.equal(record.purpose, metadata.purpose); assert.equal(record.endpointRegistrationRef, canonicalSha256(registration));
    assert.equal(record.expiresAt, metadata.expiresAt);
    assert.equal(record.endpointIdentityDigest, registration.endpointIdentityDigest); assert.equal(record.tlsPolicyDigest, registration.tlsPolicyDigest);
    assert.deepEqual(record.platformItem, operation.platformItem); assert.deepEqual(record.externalSubject, operation.commandCore.externalSubject);
    assert.equal(record.externalSubjectDigest, operation.intendedExternalSubjectDigest); assert.equal(record.externalSubject.subject.kind, 'opaque_generation');
    assert.deepEqual(record.externalSubject.subject.scopes, ['endpoint_exact_only']); assert.deepEqual(record.externalSubject.subject.audiences, []);
    assert.equal(record.createdAt, operation.finishedAt); assert.equal(operation.committedAuthorityRevision, record.authorityRevision);
    assert(parseCanonicalTime(record.createdAt) >= parseCanonicalTime(operation.createdAt));
    assert(parseCanonicalTime(record.createdAt) >= parseCanonicalTime(record.externalSubject.observedAt));
    assert(parseCanonicalTime(record.createdAt) >= parseCanonicalTime(endpointOperation.committedAt)); report.record = record;

    report.phase = 'actual_manager_and_platform';
    const processCut = async (unit: string, role: 'keeper' | 'supervisor') => {
      const current = show(unit); assert.equal(current.ActiveState, 'active'); assert.equal(current.SubState, 'running');
      assert.equal(current.ExecMainPID, current.MainPID); assert.match(current.InvocationID!, /^[a-f0-9]{32}$/u);
      assert.equal(current.Type, 'exec'); assert.equal(current.Delegate, 'yes'); assert.equal(current.KillMode, 'control-group');
      assert.equal(current.WorkingDirectory, '/');
      assert.equal(current.Restart, role === 'keeper' ? 'no' : 'on-failure'); assert.equal(current.NRestarts, '0');
      const pid = Number(current.MainPID); assert(Number.isSafeInteger(pid) && pid > 0);
      assert.equal(await readlink(`/proc/${pid}/exe`), expectedImage);
      const actual = await stat(`/proc/${pid}/exe`, { bigint: true }), selected = await lstat(expectedImage, { bigint: true });
      for (const key of imageFields) assert.equal(actual[key], selected[key]);
      const status = await readFile(`/proc/${pid}/status`, 'utf8');
      for (const [kind, id] of [['Uid', ledger.uid], ['Gid', ledger.gid]] as const) {
        const fields = status.match(new RegExp(`^${kind}:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)$`, 'mu'));
        assert(fields); assert(fields.slice(1).every(value => Number(value) === id));
      }
      const raw = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(raw.startsWith(`${pid} (`));
      const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u); assert(!['Z', 'X', 'x'].includes(fields[0]!));
      assert.match(fields[19]!, /^[0-9]+$/u);
      // The installed native exec deliberately supplies a closed environment.
      // Bind the live manager invocation to MainPID/start/image instead; do not
      // require its ambient INVOCATION_ID to survive the signed exec boundary.
      assert(current.ControlGroup.startsWith('/') && current.ControlGroup.endsWith(`/${unit}`));
      const groups = (await readFile(`/proc/${pid}/cgroup`, 'utf8')).trim().split('\n').filter(line => line.startsWith('0::'));
      assert.equal(groups.length, 1); assert(groups[0] === `0::${current.ControlGroup}` || groups[0]!.startsWith(`0::${current.ControlGroup}/`));
      const confirmed = show(unit); assert.equal(confirmed.InvocationID, current.InvocationID); assert.equal(confirmed.MainPID, current.MainPID);
      return { unit: current, processStartToken: `linux-proc-start-ticks:${fields[19]}` };
    };
    const keeper = await processCut(setup.keeperUnit, 'keeper'), supervisor = await processCut(setup.supervisorUnit, 'supervisor');
    // Running units retain their real references. Inactive LoadUnit/show calls
    // alone do not pin both units against the manager's garbage collection.
    assert(keeper.unit.Before.split(' ').includes(setup.supervisorUnit));
    assert(supervisor.unit.After.split(' ').includes(setup.keeperUnit));
    assert(!keeper.unit.Requires.split(' ').includes(setup.supervisorUnit));
    report.keeper = keeper; report.supervisor = supervisor;
    const readyPath = path.join(recipe.stateRoot, 'runtime/keeper.ready'), ready = await lstat(readyPath, { bigint: true });
    assert(ready.isFile() && !ready.isSymbolicLink()); assert.equal(ready.uid, BigInt(ledger.uid));
    assert.equal(ready.mode & 0o7777n, 0o600n); assert.equal(ready.size, 40n); assert.equal(ready.nlink, 1n);
    const readyBytes = await readFile(readyPath);
    const control = command(process.execPath, ['--input-type=module', '-e', installedReadClientScript, path.join(recipe.stateRoot, 'runtime/control-v1.sock')]);
    assert.equal(control.status, 0, 'actual owner hello/status must remain available after finalization');
    const exchanges = parseJsonStrict(control.stdout.trim()) as Array<{ hello: string; status: string }>;
    assert.equal(exchanges.length, 2);
    for (const exchange of exchanges) {
      const hello = parseJsonStrict(exchange.hello) as { ok: boolean; result: { supervisorInstanceId: string; activeRuntimeBundle: { bundleDigest: string } } };
      const status = parseJsonStrict(exchange.status) as { ok: boolean; result: { supervisorInstanceId: string } };
      assert.equal(hello.ok, true); assert.equal(status.ok, true);
      assert.equal(hello.result.activeRuntimeBundle.bundleDigest, bundleDigest);
      assert.equal(hello.result.supervisorInstanceId, status.result.supervisorInstanceId);
    }
    const after = observe('list'); assert.deepEqual(after.items.length, 1);
    assert.equal(after.nameOwner, before.nameOwner); assert.equal(after.servicePid, before.servicePid); assert.equal(after.collection, before.collection);
    assert.equal(record.platformItem.kind, 'linux_secret_service');
    if (record.platformItem.kind !== 'linux_secret_service') throw new Error('Linux enrollment must use Secret Service');
    assert(!record.platformItem.itemId.startsWith('/'), 'platform authority identity must not be a returned D-Bus path');
    const compared = observe('compare', after.items[0]!, record.platformItem.itemId, secret);
    assert.equal(compared.readback, true); assert.equal(compared.logicalItemIdMatched, true); assert.equal(compared.item, after.items[0]);
    assert.equal(compared.nameOwner, before.nameOwner); assert.equal(compared.servicePid, before.servicePid);
    assert.notEqual(compared.busUniqueName, before.busUniqueName); report.platformAfter = after; report.platformReadback = compared;
    assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
    assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
    assert.deepEqual(await readFile(readyPath), readyBytes);
    const readyAfter = await lstat(readyPath, { bigint: true });
    for (const key of imageFields) assert.equal(readyAfter[key], ready[key]);

    report.phase = 'orphan_first_prepared_sigkill';
    const orphanMetadata = { schemaVersion: 1, kind: 'enroll', requestId: '019a0012-0000-7000-8000-000000000027',
      credentialGrantId: 'credential-journey-orphan-grant', purpose: 'model_endpoint',
      endpointRegistrationId: registration.endpointRegistrationId, secretSubmissionId: 'credential-journey-orphan-submission',
      expiresAt: metadata.expiresAt } as const;
    assert(!abandonedSecret.equals(resubmittedSecret), 'fixture retry must submit different input bytes');
    const selectedEntry = signed.bundle.entries.find(entry => entry.role === 'supervisor' && entry.relativePath === 'supervisor');
    assert(selectedEntry);
    const preparedCut = await crashPreparedCredentialWrite({ fixture: ledger.fixture, username: ledger.username,
      uid: ledger.uid, gid: ledger.gid, home: ledger.home, stateRoot: recipe.stateRoot,
      ownerPrincipalId: record.ownerPrincipalId, selectedImage: expectedImage, selectedImageDigest: selectedEntry.digest,
      request: orphanMetadata, secret: abandonedSecret, scanner });
    evidenceDirs.push(preparedCut.evidence);
    report.orphanPreparedCut = preparedCut;
    const prepared = preparedCut.prepared;
    assert.equal(prepared.intendedAuthorityRevision, 1); assert.equal(prepared.intendedSecretGeneration, 1);
    assert.equal(prepared.commandCore.purpose, record.purpose);
    assert.equal(prepared.commandCore.endpointRegistrationRef, record.endpointRegistrationRef);
    assert.equal(prepared.commandCore.endpointIdentityDigest, record.endpointIdentityDigest);
    assert.equal(prepared.commandCore.tlsPolicyDigest, record.tlsPolicyDigest);
    report.phase = 'orphan_read_does_not_promote';
    assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: orphanMetadata.credentialGrantId }), 'record'), null,
      'ordinary read must not promote the joined prepared orphan');
    assert.deepEqual(observe('list').items, after.items, 'prepared cut must precede an actual platform item');
    report.phase = 'orphan_automatic_same_request_retry';
    const recovered = decodeCredentialAuthorityOperation(success(credential(orphanMetadata, resubmittedSecret), 'operation'));
    assert.equal(recovered.phase, 'committed'); assert.equal(recovered.attempt, 2);
    assert.equal(recovered.requestId, orphanMetadata.requestId); assert.equal(recovered.credentialGrantId, orphanMetadata.credentialGrantId);
    assert.deepEqual(recovered.commandCore, prepared.commandCore, 'automatic retry must freeze the complete original core and subject');
    for (const key of ['ownerPrincipalId', 'kind', 'requestDigest', 'credentialTargetDigest', 'intendedAuthorityRevision',
      'intendedSecretGeneration', 'intendedExternalSubjectDigest'] as const) assert.equal(recovered[key], prepared[key]);
    assert.notEqual(recovered.operationId, prepared.operationId); assert.notEqual(recovered.channelIdentityRef, prepared.channelIdentityRef);
    assert.notEqual(recovered.channelIdentityDigest, prepared.channelIdentityDigest);
    assert.notDeepEqual(recovered.platformItem, prepared.platformItem, 'replacement producer requires a fresh planned item');
    assert.equal(recovered.committedAuthorityRevision, 1); assert(parseCanonicalTime(recovered.createdAt) >= parseCanonicalTime(prepared.createdAt));
    const orphanRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: orphanMetadata.credentialGrantId }), 'record'));
    assert.equal(orphanRecord.state, 'active'); assert.equal(orphanRecord.authorityRevision, 1); assert.equal(orphanRecord.secretGeneration, 1);
    assert.deepEqual(orphanRecord.platformItem, recovered.platformItem); assert.deepEqual(orphanRecord.externalSubject, prepared.commandCore.externalSubject);
    if (orphanRecord.platformItem.kind !== 'linux_secret_service') throw new Error('Linux orphan retry must use Secret Service');
    const orphanInventory = observe('list'); assert.equal(orphanInventory.items.length, 2);
    assert(orphanInventory.items.includes(compared.item!));
    assert.equal(orphanInventory.nameOwner, before.nameOwner); assert.equal(orphanInventory.servicePid, before.servicePid);
    assert.equal(orphanInventory.collection, before.collection);
    const orphanItems = orphanInventory.items.filter(item => item !== compared.item); assert.equal(orphanItems.length, 1);
    const orphanCompared = observe('compare', orphanItems[0]!, orphanRecord.platformItem.itemId, resubmittedSecret);
    assert.equal(orphanCompared.readback, true); assert.equal(orphanCompared.logicalItemIdMatched, true);
    assert.equal(orphanCompared.item, orphanItems[0]); assert.equal(orphanCompared.nameOwner, before.nameOwner);
    assert.equal(orphanCompared.servicePid, before.servicePid);
    report.orphanRecoveredOperation = recovered; report.orphanRecoveredRecord = orphanRecord; report.orphanPlatformReadback = orphanCompared;
    report.phase = 'revoke_recovered_fixture_grant';
    const orphanRevocation = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'revoke',
      requestId: '019a0012-0000-7000-8000-000000000028', credentialGrantId: orphanMetadata.credentialGrantId,
      expectedAuthorityRevision: 1 }), 'operation'));
    assert.equal(orphanRevocation.disposition, 'revoked'); assert.equal(orphanRevocation.cleanupPhase, 'cleanup_complete');
    assert.equal(orphanRevocation.committedAuthorityRevision, 2); assert.deepEqual(orphanRevocation.platformItem, orphanRecord.platformItem);
    assert.deepEqual(observe('list').items, after.items, 'recovered fixture revoke must restore the original inventory');
    assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record')), record, 'orphan workflow must not modify the original grant');
    assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
    assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
    report.orphanFixtureRevocation = orphanRevocation;
    report.preparedOrphanRetry = { firstActualPreparedCutJoined: true, readDidNotPromote: true, frozenCoreAndSubjectMatched: true,
      attemptTwoCommitted: true, actualLatestSecretReadbackMatched: true, originalInventoryRestored: true,
      attemptCapQualified: false, liveProducerPresenceQualified: false, fullCrashCampaignQualified: false };

    const capMetadata = { ...orphanMetadata, requestId: '019a0012-0000-7000-8000-000000000029',
      credentialGrantId: 'credential-journey-attempt-cap-grant', secretSubmissionId: 'credential-journey-attempt-cap-submission' } as const;
    const capCuts: Awaited<ReturnType<typeof crashPreparedCredentialWrite>>[] = [];
    report.attemptCapCuts = capCuts;
    for (const expectedAttempt of [1, 2, 3] as const) {
      report.phase = `attempt_cap_prepared_${expectedAttempt}_sigkill`;
      const cut = await crashPreparedCredentialWrite({ fixture: ledger.fixture, username: ledger.username,
        uid: ledger.uid, gid: ledger.gid, home: ledger.home, stateRoot: recipe.stateRoot,
        ownerPrincipalId: record.ownerPrincipalId, selectedImage: expectedImage, selectedImageDigest: selectedEntry.digest,
        request: capMetadata, secret: capSecrets[expectedAttempt - 1]!, expectedAttempt, previous: capCuts.at(-1), scanner });
      evidenceDirs.push(cut.evidence);
      capCuts.push(cut);
      assert.equal(cut.prepared.attempt, expectedAttempt); assert.equal(cut.prepared.intendedAuthorityRevision, 1);
      assert.equal(cut.prepared.intendedSecretGeneration, 1);
      assert.deepEqual(cut.prepared.commandCore, capCuts[0]!.prepared.commandCore);
      assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: capMetadata.credentialGrantId }), 'record'), null);
      assert.deepEqual(observe('list').items, after.items, 'prepared-only cap attempts must never create an actual item');
    }
    const thirdCut = capCuts[2]!;
    const capCommand = canonicalJsonBytes(capMetadata).toString('base64url');
    const exhaustedRefusal = (result: Awaited<ReturnType<typeof openInputCommand>>) => {
      assert.equal(result.status, 1, 'a fourth attempt must be refused before secret input');
      assert.equal(result.stdout, '', 'exhaustion must not publish an operation');
      let confirmed = false;
      const line = result.stderr.trim().split('\n').at(-1);
      if (line && Buffer.byteLength(line) <= 2048) try {
        const refusal = parseJsonStrict(line) as Record<string, unknown>;
        confirmed = refusal.diagnosticOnly === true && refusal.scope === 'installed-read-startup' &&
          refusal.code === 'STATE_TRANSITION_INVALID' &&
          refusal.message === 'credential request exhausted its three attempts; a new request id is required' &&
          Object.keys(refusal).every(key => ['diagnosticOnly', 'scope', 'code', 'path', 'message'].includes(key));
      } catch { /* No arbitrary output becomes the bounded closed-refusal evidence. */ }
      assert(confirmed, 'only the exact exhaustion refusal qualifies the cap, not generic contention or failure');
    };
    report.phase = 'attempt_cap_fourth_refused';
    exhaustedRefusal(await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential', capCommand]));
    const exhaustedFacts = await inspectPreparedCredentialCrashFacts(thirdCut);
    assert.equal(exhaustedFacts.length, 6); assert(exhaustedFacts.length <= 9);
    assert.deepEqual(exhaustedFacts.slice(0, thirdCut.facts.length), thirdCut.facts, 'recovery must not rewrite any original fact');
    assert(exhaustedFacts.every(fact => fact.attempt <= 3));
    const terminalThird = exhaustedFacts.at(-1)!;
    assert.equal(terminalThird.attempt, 3); assert.equal(terminalThird.phase, 'aborted');
    assert.equal(terminalThird.abortReason, 'recovered_orphan');
    assert.deepEqual(terminalThird.commandCore, thirdCut.prepared.commandCore);
    assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: capMetadata.credentialGrantId }), 'record'), null);
    assert.deepEqual(observe('list').items, after.items);
    report.phase = 'attempt_cap_repeated_refusal';
    exhaustedRefusal(await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential', capCommand]));
    assert.deepEqual(await inspectPreparedCredentialCrashFacts(thirdCut), exhaustedFacts, 'exhausted replay must not spend another fact or attempt');
    assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: capMetadata.credentialGrantId }), 'record'), null);
    const capInventory = observe('list'); assert.deepEqual(capInventory.items, after.items);
    assert.equal(capInventory.nameOwner, before.nameOwner); assert.equal(capInventory.servicePid, before.servicePid);
    assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
    assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
    report.attemptCap = { threeRealPreparedCutsJoined: true, completeCoreFrozen: true, previousFactsUnchanged: true,
      thirdDeadProducerRecoveredToAborted: true, exactFourthRefusal: true, exactRepeatedRefusal: true,
      noAttemptFourInActualSnapshot: true, originalInventoryUnchanged: true, secretInputPipeUnwrittenAndUnended: true,
      offlinePlatformZeroCallsQualified: false, liveProducerPresenceQualified: false, fullCrashCampaignQualified: false };

    report.phase = 'cleanup_current_active_refusal';
    const activeCleanup = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
      canonicalJsonBytes({ schemaVersion: 1, kind: 'cleanup', requestId: metadata.requestId }).toString('base64url')]);
    assert.equal(activeCleanup.status, 1, 'explicit cleanup must refuse the current active generation');
    assert(activeCleanup.stdout.length === 0, 'active cleanup refusal must not return a result envelope');
    let activeRefused = false;
    const activeRefusalLine = activeCleanup.stderr.trim().split('\n').at(-1);
    if (activeRefusalLine && Buffer.byteLength(activeRefusalLine) <= 2048) try {
      const refusal = parseJsonStrict(activeRefusalLine) as Record<string, unknown>;
      activeRefused = refusal.diagnosticOnly === true && refusal.scope === 'installed-read-startup' &&
        refusal.code === 'STATE_TRANSITION_INVALID' && typeof refusal.message === 'string' && refusal.message.length <= 1024 &&
        Object.keys(refusal).every(key => ['diagnosticOnly', 'scope', 'code', 'path', 'message'].includes(key));
    } catch { /* Only the closed refusal code is retained, never arbitrary output. */ }
    assert(activeRefused, 'active cleanup must return the closed state-transition refusal without secret input');
    assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record')), record);
    const protectedInventory = observe('list'); assert.deepEqual(protectedInventory.items, after.items);
    assert.equal(protectedInventory.nameOwner, before.nameOwner); assert.equal(protectedInventory.servicePid, before.servicePid);
    assert.equal(protectedInventory.collection, before.collection);
    assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
    assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
    report.activeCleanupRefusal = { diagnosticOnly: true, code: 'STATE_TRANSITION_INVALID', metadataUnchanged: true,
      actualInventoryUnchanged: true, secretInputPipeUnwrittenAndUnended: true };

    report.phase = 'rotate';
    const rotateMetadata = { schemaVersion: 1, kind: 'rotate', requestId: '019a0012-0000-7000-8000-000000000023',
      credentialGrantId: metadata.credentialGrantId, expectedAuthorityRevision: 1, secretSubmissionId: 'credential-journey-rotation-submission' };
    const rotatedOperation = decodeCredentialAuthorityOperation(success(credential(rotateMetadata, rotatedSecret), 'operation'));
    assert.equal(rotatedOperation.phase, 'committed'); assert.equal(rotatedOperation.kind, 'rotate'); assert.equal(rotatedOperation.attempt, 1);
    assert.equal(rotatedOperation.requestId, rotateMetadata.requestId); assert.equal(rotatedOperation.credentialGrantId, metadata.credentialGrantId);
    assert.equal(rotatedOperation.ownerPrincipalId, ownerPrincipalId);
    assert.equal(rotatedOperation.commandCore.secretSubmissionId, rotateMetadata.secretSubmissionId);
    assert.equal(rotatedOperation.intendedAuthorityRevision, 2); assert.equal(rotatedOperation.intendedSecretGeneration, 2);
    assert.equal(rotatedOperation.committedAuthorityRevision, 2); assert.notEqual(rotatedOperation.operationId, operation.operationId);
    assert.notEqual(rotatedOperation.credentialTargetDigest, operation.credentialTargetDigest);
    report.rotatedOperation = rotatedOperation;
    report.phase = 'read_rotated';
    const rotatedRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record'));
    assert.equal(rotatedRecord.state, 'active'); assert.equal(rotatedRecord.authorityRevision, 2); assert.equal(rotatedRecord.secretGeneration, 2);
    for (const key of ['credentialGrantId', 'ownerPrincipalId', 'credentialServiceRevision', 'credentialHandleIdentityDigest',
      'purpose', 'endpointRegistrationRef', 'endpointIdentityDigest', 'tlsPolicyDigest', 'expiresAt'] as const)
      assert.equal(rotatedRecord[key], record[key], `rotation must preserve ${key}`);
    assert.equal(rotatedOperation.commandCore.purpose, record.purpose);
    assert.equal(rotatedOperation.commandCore.endpointRegistrationRef, record.endpointRegistrationRef);
    assert.equal(rotatedOperation.commandCore.endpointIdentityDigest, record.endpointIdentityDigest);
    assert.equal(rotatedOperation.commandCore.tlsPolicyDigest, record.tlsPolicyDigest);
    assert.equal(rotatedOperation.commandCore.expiresAt, record.expiresAt);
    assert.deepEqual(rotatedRecord.platformItem, rotatedOperation.platformItem);
    assert.deepEqual(rotatedRecord.externalSubject, rotatedOperation.commandCore.externalSubject);
    assert.equal(rotatedRecord.externalSubjectDigest, rotatedOperation.intendedExternalSubjectDigest);
    assert.notEqual(rotatedRecord.externalSubjectDigest, record.externalSubjectDigest);
    const oldSubject = record.externalSubject.subject, newSubject = rotatedRecord.externalSubject.subject;
    if (oldSubject.kind !== 'opaque_generation' || newSubject.kind !== 'opaque_generation')
      throw new Error('installed rotation must produce a fresh opaque generation');
    assert.notEqual(newSubject.opaqueSubjectId, oldSubject.opaqueSubjectId);
    assert.deepEqual(newSubject.scopes, ['endpoint_exact_only']); assert.deepEqual(newSubject.audiences, []);
    assert.equal(rotatedRecord.createdAt, rotatedOperation.finishedAt);
    for (const time of [record.createdAt, rotatedOperation.createdAt, rotatedRecord.externalSubject.observedAt])
      assert(parseCanonicalTime(rotatedRecord.createdAt) >= parseCanonicalTime(time));
    assert.equal(rotatedRecord.platformItem.kind, 'linux_secret_service');
    if (rotatedRecord.platformItem.kind !== 'linux_secret_service') throw new Error('Linux rotation must use Secret Service');
    assert.notEqual(rotatedRecord.platformItem.itemId, record.platformItem.itemId);
    assert(!rotatedRecord.platformItem.itemId.startsWith('/'), 'rotated item identity must remain logical');
    report.rotatedRecord = rotatedRecord;
    report.phase = 'actual_rotated_platform';
    const afterRotate = observe('list'); assert.equal(afterRotate.items.length, 1);
    assert.equal(afterRotate.nameOwner, before.nameOwner); assert.equal(afterRotate.servicePid, before.servicePid);
    assert.equal(afterRotate.collection, before.collection); assert.notEqual(afterRotate.items[0], compared.item);
    const rotatedCompared = observe('compare', afterRotate.items[0]!, rotatedRecord.platformItem.itemId, rotatedSecret);
    assert.equal(rotatedCompared.readback, true); assert.equal(rotatedCompared.logicalItemIdMatched, true);
    assert.equal(rotatedCompared.item, afterRotate.items[0]); assert.equal(rotatedCompared.nameOwner, before.nameOwner);
    assert.equal(rotatedCompared.servicePid, before.servicePid);
    report.platformAfterRotate = afterRotate; report.platformRotateReadback = rotatedCompared;
    assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
    assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
    assert.deepEqual(await readFile(readyPath), readyBytes);

    report.phase = 'committed_submission_reuse';
    const reused = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
      canonicalJsonBytes({ ...rotateMetadata, requestId: '019a0012-0000-7000-8000-000000000024',
        expectedAuthorityRevision: 2, secretSubmissionId: metadata.secretSubmissionId }).toString('base64url')]);
    assert.equal(reused.status, 1, 'a new rotation must not reuse any committed generation submission id');
    let submissionRefused = false;
    const refusalLine = reused.stderr.trim().split('\n').at(-1);
    if (refusalLine && Buffer.byteLength(refusalLine) <= 2048) try {
      const refusal = parseJsonStrict(refusalLine) as Record<string, unknown>;
      submissionRefused = refusal.diagnosticOnly === true && refusal.scope === 'installed-read-startup' &&
        refusal.code === 'INVALID_REQUEST' && refusal.message === 'credential rotation requires a fresh secret submission id';
    } catch { /* Never retain arbitrary secret-command output or parser diagnostics. */ }
    assert(submissionRefused, 'submission reuse must return only the fixed input-refusal diagnostic');
    assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record')), rotatedRecord);
    assert.deepEqual(observe('list').items, afterRotate.items);
    report.committedSubmissionReuseRefused = { fixedInputRefusal: true, secretInputPipeUnwrittenAndUnended: true };

    report.phase = 'exact_replay_without_services_or_secret_input';
    const stopped = command('/usr/bin/systemctl', ['--user', 'stop', setup.supervisorUnit, setup.keeperUnit]);
    assert.equal(stopped.status, 0, 'actual installed services must stop before replay');
    const inactive = () => [setup.supervisorUnit, setup.keeperUnit].map(unit => {
      const current = show(unit); assert.equal(current.ActiveState, 'inactive'); assert.equal(current.MainPID, '0');
      return { unit, activeState: current.ActiveState, mainPid: current.MainPID };
    });
    report.servicesBeforeReplay = inactive();
    await stopDaemon(compared.servicePid);
    const noStore = () => {
      const owned = serviceName(); assert.equal(owned.status, 0); assert.equal(owned.stdout.trim(), 'b false');
    };
    noStore();
    const replayBytes = canonicalJsonBytes(metadata);
    const replay = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
      ['--bootstrap-credential', replayBytes.toString('base64url')]);
    const replayed = decodeCredentialAuthorityOperation(success(replay, 'operation'));
    assert.deepEqual(replayed, operation, 'new-process replay must retain the original committed result and provenance');
    assert.equal(replay.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation }).toString('utf8')}\n`);
    const rotateReplay = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
      ['--bootstrap-credential', canonicalJsonBytes(rotateMetadata).toString('base64url')]);
    assert.deepEqual(decodeCredentialAuthorityOperation(success(rotateReplay, 'operation')), rotatedOperation,
      'rotation replay must retain its original committed result and provenance without new input');
    assert.equal(rotateReplay.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation: rotatedOperation }).toString('utf8')}\n`);
    const reread = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record'));
    assert.deepEqual(reread, rotatedRecord, 'read without services must retain exact latest rotated metadata');
    report.servicesAfterReplay = inactive(); noStore();
    report.exactReplay = { originalOperationMatched: true, rotatedOperationMatched: true, latestRotatedRecordMatched: true,
      secretInputPipeUnwrittenAndUnended: true, authLauncherJoined: true, secretServiceOwnerAbsent: true };

    report.phase = 'revoke_without_services_or_secret_input';
    const revokeMetadata = { schemaVersion: 1, kind: 'revoke', requestId: '019a0012-0000-7000-8000-000000000025',
      credentialGrantId: metadata.credentialGrantId, expectedAuthorityRevision: 2 };
    const revokeBytes = canonicalJsonBytes(revokeMetadata);
    const revoked = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
      ['--bootstrap-credential', revokeBytes.toString('base64url')]);
    const revocation = decodeCredentialAuthorityRevokeOperation(success(revoked, 'operation'));
    assert.equal(revocation.requestId, revokeMetadata.requestId); assert.equal(revocation.credentialGrantId, metadata.credentialGrantId);
    assert.equal(revocation.ownerPrincipalId, ownerPrincipalId); assert.equal(revocation.disposition, 'revoked');
    assert.equal(revocation.commandCore.expectedAuthorityRevision, 2); assert.equal(revocation.committedAuthorityRevision, 3);
    assert.equal(revocation.credentialTargetDigest, rotatedOperation.credentialTargetDigest);
    assert.deepEqual(revocation.platformItem, rotatedRecord.platformItem);
    if (revocation.cleanupPhase !== 'cleanup_failed') throw new Error('unavailable actual store must retain a failed cleanup receipt');
    assert.equal(revocation.cleanupErrorCode, 'platform_store_unavailable');
    assert(parseCanonicalTime(revocation.metadataCommittedAt) >= parseCanonicalTime(rotatedRecord.createdAt));
    assert(parseCanonicalTime(revocation.cleanupFinishedAt) >= parseCanonicalTime(revocation.metadataCommittedAt));
    const revokedRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record'));
    const { recordDigest: _activeDigest, ...activeBody } = rotatedRecord;
    const { recordDigest: _revokedDigest, ...revokedBody } = revokedRecord;
    assert.deepEqual(revokedBody, { ...activeBody, state: 'revoked', authorityRevision: 3,
      revokedAt: revocation.metadataCommittedAt, revokedByRequestId: revokeMetadata.requestId,
      revokedByRequestDigest: revocation.requestDigest }, 'terminal revoke must preserve the exact generation and immutable target');
    assert.equal(revocation.revokedRecordDigest, revokedRecord.recordDigest);
    report.revocation = revocation; report.revokedRecord = revokedRecord;
    report.servicesAfterRevoke = inactive(); noStore();
    for (const [originalMetadata, originalOperation] of [[metadata, operation], [rotateMetadata, rotatedOperation]] as const) {
      const historical = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
        ['--bootstrap-credential', canonicalJsonBytes(originalMetadata).toString('base64url')]);
      assert.deepEqual(decodeCredentialAuthorityOperation(success(historical, 'operation')), originalOperation,
        'terminal revoke must not rewrite or block historical committed replay');
      assert.equal(historical.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation: originalOperation }).toString('utf8')}\n`);
    }
    report.phase = 'revoke_retry_without_store';
    const retry = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
      ['--bootstrap-credential', revokeBytes.toString('base64url')]);
    const retriedRevocation = decodeCredentialAuthorityRevokeOperation(success(retry, 'operation'));
    const receiptIdentity = (value: ReturnType<typeof decodeCredentialAuthorityRevokeOperation>) => {
      const { operationDigest: _digest, cleanupPhase: _phase, cleanupEvidenceDigest: _evidence,
        cleanupErrorCode: _error, cleanupFinishedAt: _finished, ...identity } = value; return identity;
    };
    assert.deepEqual(receiptIdentity(retriedRevocation), receiptIdentity(revocation),
      'cleanup retry must retain the original revoke identity, core, channel, metadata commit and result');
    if (retriedRevocation.cleanupPhase !== 'cleanup_failed') throw new Error('absent actual store must keep cleanup failed on retry');
    assert.equal(retriedRevocation.cleanupErrorCode, 'platform_store_unavailable');
    assert(parseCanonicalTime(retriedRevocation.cleanupFinishedAt) >= parseCanonicalTime(revocation.metadataCommittedAt));
    assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
    report.servicesAfterRevokeRetry = inactive(); noStore();
    report.revocationRetry = retriedRevocation;
    report.terminalRevoke = { metadataRemainsRevoked: true, originalReceiptIdentityMatched: true,
      historicalOperationsMatched: true, secretInputPipeUnwrittenAndUnended: true, secretServiceOwnerAbsent: true };

    report.phase = 'restore_fixture_secret_service';
    const restored = await startDaemon();
    assert.notEqual(restored.nameOwner, before.nameOwner); assert.equal(restored.collection, before.collection);
    assert(daemonFact && (daemonFact.pid !== originalDaemon.pid || daemonFact.start !== originalDaemon.start),
      'restored fixture daemon must be a new positively observed lifetime');
    assert.equal(restored.items.length, 1);
    const restoredCompared = observe('compare', restored.items[0]!, rotatedRecord.platformItem.itemId, rotatedSecret);
    assert.equal(restoredCompared.readback, true); assert.equal(restoredCompared.logicalItemIdMatched, true);
    assert.equal(restoredCompared.item, restored.items[0]); assert.equal(restoredCompared.nameOwner, restored.nameOwner);
    assert.equal(restoredCompared.servicePid, restored.servicePid); assert.equal(restoredCompared.collection, restored.collection);
    report.platformRestored = restored; report.platformRestoredReadback = restoredCompared;
    report.servicesBeforeCleanup = inactive();
    report.phase = 'revoke_retry_with_restored_store';
    const cleanup = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
      ['--bootstrap-credential', revokeBytes.toString('base64url')]);
    const completedRevocation = decodeCredentialAuthorityRevokeOperation(success(cleanup, 'operation'));
    assert.equal(completedRevocation.cleanupPhase, 'cleanup_complete');
    assert.deepEqual(receiptIdentity(completedRevocation), receiptIdentity(revocation));
    assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
    const cleared = observe('list'); assert.deepEqual(cleared.items, []);
    assert.equal(cleared.nameOwner, restored.nameOwner); assert.equal(cleared.servicePid, restored.servicePid);
    assert.equal(cleared.collection, restored.collection);
    report.cleanupComplete = completedRevocation; report.platformAfterCleanup = cleared;
    report.phase = 'completed_revoke_exact_replay';
    const completedReplay = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
      ['--bootstrap-credential', revokeBytes.toString('base64url')]);
    assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(completedReplay, 'operation')), completedRevocation,
      'completed cleanup replay must not regenerate receipt cleanup fields');
    assert.equal(completedReplay.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation: completedRevocation }).toString('utf8')}\n`);
    assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), restored.nameOwner);
    report.servicesAfterCompletedReplay = inactive();
    report.successfulCleanupRetry = { originalReceiptIdentityMatched: true, revokedRecordUnchanged: true,
      actualInventoryEmpty: true, completedReceiptExactReplay: true, secretInputPipeUnwrittenAndUnended: true };

    report.phase = 'explicit_completed_revoke_cleanup';
    const explicitRevoke = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
      canonicalJsonBytes({ schemaVersion: 1, kind: 'cleanup', requestId: revokeMetadata.requestId }).toString('base64url')]);
    assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(explicitRevoke, 'operation')), completedRevocation,
      'explicit cleanup must retain the exact completed revoke receipt');
    assert.equal(explicitRevoke.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation: completedRevocation }).toString('utf8')}\n`);
    assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
      credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
    assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), restored.nameOwner);
    assert.deepEqual(inactive(), report.servicesBeforeCleanup);
    for (const [requestId, originalOperation] of [[metadata.requestId, operation], [rotateMetadata.requestId, rotatedOperation]] as const) {
      report.phase = originalOperation.kind === 'enroll' ? 'explicit_superseded_enroll_cleanup' : 'explicit_revoked_rotate_cleanup';
      const explicit = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
        canonicalJsonBytes({ schemaVersion: 1, kind: 'cleanup', requestId }).toString('base64url')]);
      assert.deepEqual(decodeCredentialAuthorityOperation(success(explicit, 'operation')), originalOperation,
        'explicit cleanup must not rewrite the original committed credential operation');
      assert.equal(explicit.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation: originalOperation }).toString('utf8')}\n`);
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
      assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), restored.nameOwner);
      assert.deepEqual(inactive(), report.servicesBeforeCleanup);
    }
    report.explicitCleanup = { completedRevokeReceiptMatched: true, originalCommittedOperationsMatched: true,
      revokedRecordUnchanged: true, actualInventoryEmpty: true, servicesRemainInactive: true,
      secretInputPipeUnwrittenAndUnended: true };
    report.phase = 'complete'; report.qualified = true;
  } catch (error) { primary = error; }
  finally {
    secret.fill(0); rotatedSecret.fill(0); abandonedSecret.fill(0); resubmittedSecret.fill(0); password.fill(0);
    for (const bytes of capSecrets) bytes.fill(0);
    try { await stopDaemon(); }
    catch (error) { primary = new AggregateError([primary, error].filter(Boolean), 'fixture platform daemon retirement failed'); }
    if (!primary) {
      report.phase = 'secret_corpus';
      try {
        const corpus = await scanCredentialSecretCorpus({ stateRoot: recipe.stateRoot, uid: ledger.uid, evidenceDirs, scanner });
        assert.equal(corpus.sqliteDatabasesScanned, 2); assert.equal(corpus.evidenceDirectoriesScanned, 4);
        report.secretCorpus = corpus; report.phase = 'complete';
      } catch (error) { primary = error; }
    }
    if (primary) {
      report.qualified = false;
      // Assertion messages and causes may contain compared data. Retain only
      // source-owned frame locations, never their arbitrary message/stack text.
      const stack = primary instanceof Error ? primary.stack ?? '' : '';
      report.error = { diagnosticOnly: true, kind: 'credential_journey_failed', sourceFrames: [...stack.matchAll(
        /\b(credential-installed-journey|credential-write-crash|credential-secret-scan|credential-secret-corpus)\.ts:([1-9][0-9]*):([1-9][0-9]*)/gu)]
        .slice(0, 8).map(match => ({ file: `${match[1]}.ts`, line: Number(match[2]), column: Number(match[3]) })) };
    }
    let publicationBytes: Buffer, scannedBytes: Buffer | undefined;
    try {
      scannedBytes = Buffer.from(JSON.stringify(report, null, 2) + '\n'); scanBytes(scannedBytes);
      scanner.close();
      report.secretOutputScan = scanner.stats();
      publicationBytes = Buffer.from(JSON.stringify(report, null, 2) + '\n');
    } catch {
      scanner.close(); report.qualified = false;
      // A tainted/oversized report is discarded before any publication.
      publicationBytes = Buffer.from(JSON.stringify({ diagnosticOnly: true, qualified: false,
        phase: 'secret_scan_or_report_failure', scope: report.scope, secretOutputScan: scanner.stats() }) + '\n',
      'utf8');
      primary ??= new Error('credential journey secret scan did not qualify');
    } finally { scannedBytes?.fill(0); }
    try {
      // One create-only write: a write failure never retries an unknown or
      // partially published outcome, and never overwrites an older report.
      await writeFile(recipe.reportFile, publicationBytes, { flag: 'wx', mode: 0o644 });
      console.log(`Actual installed credential journey report: ${recipe.reportFile}`);
    } catch { primary ??= new Error('credential journey report publication failed'); }
    finally { publicationBytes.fill(0); }
  }
  if (primary) throw new Error('actual installed credential journey failed; see the closed diagnostic report');
}

assert.equal(process.platform, 'linux', 'installed credential journey requires Linux');
assert.equal(process.arch, 'x64', 'no installed credential carrier qualified for this architecture');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--campaign'); assert(filename && extra.length === 0);
await campaign(filename);
