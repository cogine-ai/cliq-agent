// Actual signed credential journey plus one joined prepared-SIGKILL retry.
// Not the complete crash campaign, live-producer/clock proof or installed I1.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chown, lstat, mkdir, open, readFile, readdir, readlink, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRecord, decodeCredentialAuthorityRevokeOperation, decodeEndpointAuthorityOperation, decodeEndpointAuthorityRecord,
  type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { installedReadClientScript } from './installed-read-control.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';
import { crashPreparedCredentialWrite, inspectPreparedCredentialCrashFacts } from './credential-write-crash.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { CredentialSecretCorpusError, scanCredentialSecretCorpus } from './credential-secret-corpus.js';
import { observeInitialCredentialHello } from './credential-input-observation.js';

type Recipe = { buildFixture: string; packageRoot: string; installerEntry: string; stateRoot: string;
  releaseKeysFile: string; controlDirectory: string; observer: string; storeFixture: string; reportFile: string };
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

export async function readLedger(filename: string): Promise<Ledger> {
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
    'packageRoot', 'releaseKeysFile', 'reportFile', 'stateRoot', 'storeFixture'].sort());
  assert.equal(recipe.buildFixture, path.join(ledger.fixture, 'credential-package-build'));
  assert.equal(recipe.packageRoot, path.join(recipe.buildFixture, 'package'));
  assert.equal(recipe.installerEntry, path.join(recipe.buildFixture, 'installed-runtime-installer.mjs'));
  assert.equal(recipe.stateRoot, path.join(ledger.home, 'probe/credential-state'));
  assert.equal(recipe.releaseKeysFile, path.join(ledger.fixture, 'credential-release-keys.json'));
  assert.equal(recipe.controlDirectory, path.join(ledger.home, 'probe/credential-secret-service-control'));
  assert.equal(recipe.observer, path.join(ledger.fixture, 'cliq-credential-journey-observer'));
  assert.equal(recipe.storeFixture, path.join(ledger.fixture, 'cliq-credential-store-fixture'));
  assert(path.isAbsolute(recipe.reportFile) && path.basename(recipe.reportFile) === 'credential-journey.json');
  const output = await lstat(path.dirname(recipe.reportFile));
  assert(output.isDirectory() && !output.isSymbolicLink()); assert.equal(output.uid, 0);
  assert.equal(output.mode & 0o7777, 0o755);
  return ledger;
}

// Same post-order, no-follow transfer as the qualified installed fixture. Only
// the newly built package changes owner; never its stage/carrier or StateRoot.
export async function transferPackage(filename: string, uid: number, gid: number): Promise<void> {
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

export async function stageInstaller(recipe: Recipe): Promise<void> {
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

async function campaign(filename: string, campaignKind: 'authority_lifecycle' | 'model_input'): Promise<void> {
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.credentials;
  const report: Record<string, unknown> = { diagnosticOnly: true, qualified: false, phase: 'installation', uid: ledger.uid, campaignKind,
    scope: campaignKind === 'model_input'
      ? 'genuine signed model-input-only credential enrollment, six bearer enroll refusals, one bearer rotate refusal, four protocol enroll and four protocol rotate refusals, exact original-record/platform/service checks, genuine rotate/readback/revoke/cleanup, joined services and complete secret corpus; not authority-lifecycle crash/replay/endpoint qualification or full I1'
      : 'independent authority-lifecycle coverage; model-input negative coverage requires its separate successful campaign; genuine signed credential journey, completed-schema endpoint preservation, preparation-only expiry, extra-item-attribute/full-selector ambiguity/default-alias cleanup refusal, offline completed-receipt replay and fresh-sweep refusal, initial-gate/input endpoint-revocation refusal and revoked-endpoint static admission refusal, explicit cleanup, first-prepared same-core retry and prepared-only attempts 1..3 cap with actual user-manager autostart and independent Secret Service byte comparisons; not full crash campaign, finalizer expiry/drift/concurrent revoke/ambiguity, live-pending producer presence, ABA, clock regression, broker or I1' };
  const phaseStartedAt = performance.now();
  let phaseLogCount = 0;
  const markPhase = (value: string): void => {
    report.phase = value;
    if (phaseLogCount >= 64) return;
    phaseLogCount++;
    // Only fixed source-owned stages and monotonic elapsed time. Diagnostic
    // output never changes acceptance, even if the output stream has failed.
    try { console.log(`I1 credential phase ${value} elapsedMs=${Math.floor(performance.now() - phaseStartedAt)}`); }
    catch { /* Diagnostic only. */ }
  };
  markPhase('installation');
  // Preserve the observer and duplicate fixture's exact 32-byte contract.
  // Model samples use printable bytes; the first actual roundtrip also
  // covers both accepted edge bytes. These are test-only random secrets.
  const secret = Buffer.from(`!${randomBytes(22).toString('base64url')}~`), rotatedSecret = Buffer.from(randomBytes(24).toString('base64url')),
    abandonedSecret = Buffer.from(randomBytes(24).toString('base64url')), resubmittedSecret = Buffer.from(randomBytes(24).toString('base64url')),
    negativeSecret = Buffer.from(randomBytes(24).toString('base64url')), password = Buffer.from(randomBytes(32).toString('hex'));
  const capSecrets = [0, 1, 2].map(() => Buffer.from(randomBytes(24).toString('base64url')));
  const invalidModelSecrets = [0x00, 0x20, 0x7f, 0x80, 0x0a, 0x0d].map(byte => {
    const bytes = Buffer.from(randomBytes(24).toString('base64url')); bytes[16] = byte; return bytes;
  });
  const scanner = createCredentialSecretScanner([secret, rotatedSecret, abandonedSecret, resubmittedSecret, ...capSecrets,
    negativeSecret, password, ...invalidModelSecrets],
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
  const openInputCommand = async (executable: string, args: string[], inputPlan?: Readonly<{
    secret: Buffer;
    diagnostic: { launcherObserved: boolean; directChildrenSeen: number | null; completeInputWriteJoined: boolean };
    ready(auth: NonNullable<Awaited<ReturnType<typeof processFact>>>): Promise<boolean>;
    beforeInput(auth: NonNullable<Awaited<ReturnType<typeof processFact>>>): Promise<void>;
  }>) => {
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
    let submittedAuth: NonNullable<typeof auth> | undefined;
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
          if (inputPlan) inputPlan.diagnostic.launcherObserved = launcher !== undefined;
          if (current && launcher?.start === current.start) {
            const children = await readFile(`/proc/${child.pid}/task/${child.pid}/children`, 'utf8').catch((error: NodeJS.ErrnoException) => {
              if (error.code === 'ENOENT') return ''; throw error;
            });
            const pids = children.trim() ? children.trim().split(/\s+/u).map(Number) : [];
            assert(pids.length <= 1, 'trusted runuser must own only the signed auth child');
            if (inputPlan) inputPlan.diagnostic.directChildrenSeen = pids.length;
            if (pids[0]) {
              const observed = await processFact(pids[0]);
              if (observed?.parent === child.pid) auth = observed;
            }
          }
        }
        if (inputPlan && !submittedAuth && auth && await inputPlan.ready(auth)) {
          const original = auth;
          assert(original.uids.every(uid => uid === ledger.uid));
          assert.equal(child.stdin.writableEnded, false); assert.equal(child.stdin.writableLength, 0);
          await inputPlan.beforeInput(original);
          const current = await processFact(original.pid);
          assert(current && current.start === original.start && current.parent === original.parent);
          assert.deepEqual(current.uids, original.uids);
          assert(inputPlan.secret.length > 0 && inputPlan.secret.length <= 65536);
          await bounded(new Promise<void>((resolve, reject) => {
            const failed = (error: Error) => reject(error);
            child.stdin.once('error', failed);
            child.stdin.end(inputPlan.secret, (error?: Error | null) => {
              child.stdin.off('error', failed); error ? reject(error) : resolve();
            });
          }), 5000);
          inputPlan.diagnostic.completeInputWriteJoined = true;
          submittedAuth = original;
        }
        await Promise.race([joined, delay(20)]);
      }
      const exit = await joined;
      if (scanFailure) throw scanFailure;
      assert(!spawnFailed && !outputExceeded, 'actual open-input signed entry failed');
      assert.equal(exit.signal, null, 'actual open-input signed entry was signaled');
      if (inputPlan) {
        assert(submittedAuth && launcher, 'input race must observe the original auth before supplying complete input');
        assert.equal(child.stdin.writableEnded, true);
        await waitGone(submittedAuth); await waitGone(launcher);
      } else assert.equal(child.stdin.writableEnded, false, 'fixture must never end or write the secret-input pipe');
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
    for (const filename of [recipe.observer, recipe.storeFixture]) {
      const helper = await lstat(filename);
      assert(helper.isFile() && !helper.isSymbolicLink()); assert.equal(helper.uid, 0);
      assert.equal(helper.nlink, 1); assert.equal(helper.mode & 0o7777, 0o555);
    }
    await mkdir(recipe.controlDirectory, { mode: 0o700 }); await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
    const before = await startDaemon(); report.platformBefore = before; assert.deepEqual(before.items, []);
    const originalDaemon = daemonFact; assert(originalDaemon);

    const root = await lstat(recipe.stateRoot, { bigint: true });
    assert(root.isDirectory()); assert.equal(root.uid, BigInt(ledger.uid)); assert.equal(root.mode & 0o7777n, 0o700n);
    const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: root.dev.toString(), directoryFileId: root.ino.toString(),
      mode: 448, openedNoFollow: true, layoutVersion: 1 });
    markPhase('install_services');
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
    markPhase('endpoint_register');
    const ownerPrincipalId = identityHash('cliq-local-principal-v1', rootDigest, 'linux', ledger.uid);
    const trust = signed.bundle.entries.find(entry => entry.entryId === 'default_https_trust_store')!;
    const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1',
      endpointRegistrationId: 'credential-journey-endpoint', registrationKind: 'user', ownerPrincipalId,
      purposes: ['dependency_registry', 'model_endpoint'],
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
    const endpointRequestBytes = canonicalJsonBytes({ schemaVersion: 1, kind: 'commit', requestId: '019a0012-0000-7000-8000-000000000021',
      commandCore: { ...endpointCore, commandDigest: digestOmitting(endpointCore, 'commandDigest') } });
    const endpointCommitted = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], endpointRequestBytes);
    const endpointOperation = decodeEndpointAuthorityOperation(success(endpointCommitted, 'operation'));
    assert.equal(endpointOperation.disposition, 'registered');
    const endpointReadBytes = canonicalJsonBytes({ schemaVersion: 1, kind: 'read', endpointRegistrationId: registration.endpointRegistrationId });
    const endpointBeforeUpgrade = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], endpointReadBytes);
    const endpointBeforeRecord = decodeEndpointAuthorityRecord(success(endpointBeforeUpgrade, 'record'));
    assert.equal(endpointBeforeRecord.state, 'active'); assert.equal(endpointBeforeRecord.authorityRevision, 1);
    assert.equal(endpointBeforeRecord.recordDigest, endpointOperation.resultRecordDigest);
    const metadata = { schemaVersion: 1, kind: 'enroll', requestId: '019a0012-0000-7000-8000-000000000022',
      credentialGrantId: 'credential-journey-grant', purpose: 'model_endpoint', endpointRegistrationId: registration.endpointRegistrationId,
      secretSubmissionId: 'credential-journey-submission', expiresAt: '2099-01-01T00:00:00.000Z' };
    markPhase('enroll');
    const enrolled = credential(metadata, secret);
    const operation = decodeCredentialAuthorityOperation(success(enrolled, 'operation'));
    assert.equal(operation.phase, 'committed'); assert.equal(operation.kind, 'enroll'); assert.equal(operation.attempt, 1);
    assert.equal(operation.requestId, metadata.requestId); assert.equal(operation.credentialGrantId, metadata.credentialGrantId);
    assert.equal(operation.ownerPrincipalId, ownerPrincipalId); assert.equal(operation.commandCore.secretSubmissionId, metadata.secretSubmissionId);
    assert.equal(operation.intendedAuthorityRevision, 1); assert.equal(operation.intendedSecretGeneration, 1);
    report.operation = operation;
    markPhase('completed_schema_upgrade_replay');
    // The actual endpoint entry created v1; the genuine credential write
    // completed v2. Compare public retained results, not SQL-seeded authority.
    const endpointReplay = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], endpointRequestBytes);
    assert.deepEqual(decodeEndpointAuthorityOperation(success(endpointReplay, 'operation')), endpointOperation);
    assert.equal(endpointReplay.stdout, endpointCommitted.stdout);
    const endpointAfterUpgrade = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], endpointReadBytes);
    assert.deepEqual(decodeEndpointAuthorityRecord(success(endpointAfterUpgrade, 'record')), endpointBeforeRecord);
    assert.equal(endpointAfterUpgrade.stdout, endpointBeforeUpgrade.stdout);
    report.completedSchemaUpgradeReplay = { originalEndpointOperationUnchanged: true, originalEndpointRecordUnchanged: true,
      exactResponseBytesMatched: true, migrationCrashCutsQualified: false };
    markPhase('read');
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

    markPhase('actual_manager_and_platform');
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

    const exactRefusal = (response: ReturnType<typeof credential>, code: string, message: string) => {
      assert.equal(response.status, 1); assert.equal(response.stdout, '');
      const line = response.stderr.trim().split('\n').at(-1); assert(line && Buffer.byteLength(line) <= 2048);
      assert.deepEqual(parseJsonStrict(line), Object.assign(Object.create(null),
        { diagnosticOnly: true, scope: 'installed-read-startup', code, message }));
    };
    const originalItemId = record.platformItem.itemId;
    const originalCredentialUnchanged = async () => {
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: metadata.credentialGrantId }), 'record')), record);
      const inventory = observe('list'); assert.deepEqual(inventory.items, after.items);
      for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection'] as const) assert.equal(inventory[key], after[key]);
      const readback = observe('compare', after.items[0]!, originalItemId, secret);
      assert.equal(readback.readback, true); assert.equal(readback.logicalItemIdMatched, true);
      assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
      assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
      assert.deepEqual(await readFile(readyPath), readyBytes);
    };
    const inactive = () => [setup.supervisorUnit, setup.keeperUnit].map(unit => {
      const current = show(unit); assert.equal(current.ActiveState, 'inactive'); assert.equal(current.MainPID, '0');
      return { unit, activeState: current.ActiveState, mainPid: current.MainPID };
    });
    // Both independent campaigns use the same real rotation and complete
    // record, endpoint, platform-byte and original-service verification.
    const rotateAndVerify = async () => {
      markPhase('rotate');
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
      markPhase('read_rotated');
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
      assert.notEqual(rotatedRecord.platformItem.itemId, originalItemId);
      assert(!rotatedRecord.platformItem.itemId.startsWith('/'), 'rotated item identity must remain logical');
      report.rotatedRecord = rotatedRecord;
      markPhase('actual_rotated_platform');
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

      return { rotateMetadata, rotatedOperation, rotatedRecord, rotatedItemId: rotatedRecord.platformItem.itemId, afterRotate };
    };
    const modelInputCampaign = async () => {
      markPhase('model_bearer_input_refusal');
      for (const [index, invalidSecret] of invalidModelSecrets.entries()) {
        const invalidMetadata = { ...metadata, requestId: `019a0012-0000-7000-8000-${String(60 + index).padStart(12, '0')}`,
          credentialGrantId: `credential-journey-invalid-model-${index}`, secretSubmissionId: `credential-journey-invalid-model-submission-${index}` };
        const response = credential(invalidMetadata, invalidSecret);
        let returnedCommittedOperation = false;
        if (response.status === 0) try {
          const observed = decodeCredentialAuthorityOperation(success(response, 'operation'));
          returnedCommittedOperation = observed.phase === 'committed' && observed.kind === 'enroll' &&
            observed.requestId === invalidMetadata.requestId && observed.credentialGrantId === invalidMetadata.credentialGrantId &&
            observed.commandCore.purpose === 'model_endpoint';
        } catch { /* Diagnostic only: never retain arbitrary returned bytes or errors. */ }
        report.modelBearerInputAttempt = { caseIndex: index, commandExitStatus: response.status, returnedCommittedOperation };
        exactRefusal(response, 'INVALID_REQUEST',
          'model credential secret is outside the installed bearer byte range');
        assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: invalidMetadata.credentialGrantId }), 'record'), null);
        exactRefusal(credential({ schemaVersion: 1, kind: 'cleanup', requestId: invalidMetadata.requestId }),
          'NOT_FOUND', 'credential cleanup request has no retained operation');
        await originalCredentialUnchanged();
      }
      report.modelBearerInputRefusal = { invalidEnrollCases: 6, noActiveRecordOrPreparedOperation: true,
        originalRecordItemAndServicesUnchanged: true, acceptedBoundaryBytesRoundtripped: true };

      // These are public, fixed invalid protocol literals, not newly generated
      // credential material. Keep the existing private-key scanner/corpus intact:
      // registering '{' as a private needle would necessarily reject all JSON.
      const protocolConflicts = ['{', 'application/json', '[', ']'] as const;
      const protocolConflictRefusal = async (input: Record<string, unknown>, caseIndex: number) => {
        const bytes = Buffer.from(protocolConflicts[caseIndex]!, 'ascii');
        try {
          const response = credential(input, bytes);
          let returnedCommittedOperation = false;
          if (response.status === 0) try {
            const observed = decodeCredentialAuthorityOperation(success(response, 'operation'));
            returnedCommittedOperation = observed.phase === 'committed' && observed.requestId === input.requestId &&
              observed.credentialGrantId === input.credentialGrantId && observed.kind === input.kind;
          } catch { /* Retain only fixed diagnostic facts, never arbitrary returned bytes. */ }
          report.modelProtocolConflictAttempt = { caseIndex, kind: input.kind,
            commandExitStatus: response.status, returnedCommittedOperation };
          exactRefusal(response, 'INVALID_REQUEST', 'model credential secret conflicts with the installed protocol');
          if (input.kind === 'enroll')
            assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: input.credentialGrantId }), 'record'), null);
          exactRefusal(credential({ schemaVersion: 1, kind: 'cleanup', requestId: input.requestId }),
            'NOT_FOUND', 'credential cleanup request has no retained operation');
          await originalCredentialUnchanged();
        } finally { bytes.fill(0); }
      };
      markPhase('model_protocol_conflict_enroll_refusal');
      for (const index of protocolConflicts.keys()) await protocolConflictRefusal({ ...metadata,
        requestId: `019a0012-0000-7000-8000-${String(71 + index).padStart(12, '0')}`,
        credentialGrantId: `credential-journey-protocol-conflict-${index}`,
        secretSubmissionId: `credential-journey-protocol-conflict-submission-${index}` }, index);
      report.modelProtocolConflictEnrollRefusal = { cases: protocolConflicts.length, noActiveRecordOrPreparedOperation: true,
        originalRecordItemAndServicesUnchanged: true, nativeBrokerRedemptionQualified: false };

      markPhase('model_bearer_rotate_refusal');
      const rotateMetadata = { schemaVersion: 1, kind: 'rotate', requestId: '019a0012-0000-7000-8000-000000000023',
        credentialGrantId: metadata.credentialGrantId, expectedAuthorityRevision: 1, secretSubmissionId: 'credential-journey-rotation-submission' };
      const invalidRotate = { ...rotateMetadata, requestId: '019a0012-0000-7000-8000-000000000066',
        secretSubmissionId: 'credential-journey-invalid-model-rotation-submission' };
      exactRefusal(credential(invalidRotate, invalidModelSecrets[4]!), 'INVALID_REQUEST',
        'model credential secret is outside the installed bearer byte range');
      exactRefusal(credential({ schemaVersion: 1, kind: 'cleanup', requestId: invalidRotate.requestId }),
        'NOT_FOUND', 'credential cleanup request has no retained operation');
      await originalCredentialUnchanged();
      report.modelBearerRotateRefusal = { purposeDerivedFromActiveRecord: true, noPreparedOperation: true,
        originalRevisionGenerationSubjectItemAndServicesUnchanged: true };
      markPhase('model_protocol_conflict_rotate_refusal');
      for (const index of protocolConflicts.keys()) await protocolConflictRefusal({ ...rotateMetadata,
        requestId: `019a0012-0000-7000-8000-${String(75 + index).padStart(12, '0')}`,
        secretSubmissionId: `credential-journey-protocol-conflict-rotation-${index}` }, index);
      report.modelProtocolConflictRotateRefusal = { cases: protocolConflicts.length, purposeDerivedFromActiveRecord: true,
        noPreparedOperation: true, originalRevisionGenerationSubjectItemAndServicesUnchanged: true,
        nativeBrokerRedemptionQualified: false };
      const { rotatedOperation, rotatedRecord } = await rotateAndVerify();
      markPhase('model_input_revoke_cleanup');
      const revokeMetadata = { schemaVersion: 1, kind: 'revoke', requestId: '019a0012-0000-7000-8000-000000000025',
        credentialGrantId: metadata.credentialGrantId, expectedAuthorityRevision: 2 };
      const revocation = decodeCredentialAuthorityRevokeOperation(success(credential(revokeMetadata), 'operation'));
      assert.equal(revocation.requestId, revokeMetadata.requestId); assert.equal(revocation.credentialGrantId, metadata.credentialGrantId);
      assert.equal(revocation.ownerPrincipalId, ownerPrincipalId); assert.equal(revocation.disposition, 'revoked');
      assert.equal(revocation.commandCore.expectedAuthorityRevision, 2); assert.equal(revocation.committedAuthorityRevision, 3);
      assert.equal(revocation.credentialTargetDigest, rotatedOperation.credentialTargetDigest);
      assert.deepEqual(revocation.platformItem, rotatedRecord.platformItem);
      assert.equal(revocation.cleanupPhase, 'cleanup_complete');
      assert(parseCanonicalTime(revocation.metadataCommittedAt) >= parseCanonicalTime(rotatedRecord.createdAt));
      assert(parseCanonicalTime(revocation.cleanupFinishedAt) >= parseCanonicalTime(revocation.metadataCommittedAt));
      assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'cleanup',
        requestId: revokeMetadata.requestId }), 'operation')), revocation);
      const revokedRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: metadata.credentialGrantId }), 'record'));
      const { recordDigest: _activeDigest, ...activeBody } = rotatedRecord;
      const { recordDigest: _revokedDigest, ...revokedBody } = revokedRecord;
      assert.deepEqual(revokedBody, { ...activeBody, state: 'revoked', authorityRevision: 3,
        revokedAt: revocation.metadataCommittedAt, revokedByRequestId: revokeMetadata.requestId,
        revokedByRequestDigest: revocation.requestDigest });
      assert.equal(revocation.revokedRecordDigest, revokedRecord.recordDigest);
      const cleaned = observe('list'); assert.deepEqual(cleaned.items, []);
      assert.equal(cleaned.nameOwner, before.nameOwner); assert.equal(cleaned.servicePid, before.servicePid);
      assert.equal(cleaned.collection, before.collection);
      assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
      assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
      assert.deepEqual(await readFile(readyPath), readyBytes);
      report.revocation = revocation; report.revokedRecord = revokedRecord;
      const stopped = command('/usr/bin/systemctl', ['--user', 'stop', setup.supervisorUnit, setup.keeperUnit]);
      assert.equal(stopped.status, 0, 'actual installed services must join before the model-input corpus');
      report.servicesAfterModelInputs = inactive();
      markPhase('complete'); report.qualified = true;
    };

    const authorityLifecycleCampaign = async () => {
      markPhase('expired_preparation_refusal');
      // Real wall time and the same signed entry. This is preparation expiry,
      // not a finalizer cut: no test clock or delayed/pause hook is introduced.
      const expiredMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000040',
        credentialGrantId: 'credential-journey-expired-grant', secretSubmissionId: 'credential-journey-expired-submission',
        expiresAt: '2000-01-01T00:00:00.000Z' };
      exactRefusal(credential(expiredMetadata, secret), 'STATE_TRANSITION_INVALID', 'credential preparation time or expiry is invalid');
      assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: expiredMetadata.credentialGrantId }), 'record'), null);
      exactRefusal(credential({ schemaVersion: 1, kind: 'cleanup', requestId: expiredMetadata.requestId }),
        'NOT_FOUND', 'credential cleanup request has no retained operation');
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: metadata.credentialGrantId }), 'record')), record);
      const expiredInventory = observe('list'); assert.deepEqual(expiredInventory.items, after.items);
      for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection'] as const) assert.equal(expiredInventory[key], after[key]);
      const expiredReadback = observe('compare', after.items[0]!, originalItemId, secret);
      assert.equal(expiredReadback.readback, true); assert.equal(expiredReadback.logicalItemIdMatched, true);
      assert.deepEqual(await processCut(setup.keeperUnit, 'keeper'), keeper);
      assert.deepEqual(await processCut(setup.supervisorUnit, 'supervisor'), supervisor);
      assert.deepEqual(await readFile(readyPath), readyBytes);
      report.expiredPreparationRefusal = { noReturnedAuthority: true, noRetainedOperation: true, originalRecordUnchanged: true,
        originalItemUnchanged: true, actualServicesUnchanged: true, finalizerExpiryQualified: false, clockRegressionQualified: false };

      markPhase('opaque_dependency_secret_roundtrip');
      // The same approved FD0 seam must still accept opaque bytes for a
      // different purpose. This is platform roundtrip, not dependency dispatch.
      const opaqueMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000067',
        credentialGrantId: 'credential-journey-opaque-grant', purpose: 'dependency_registry',
        secretSubmissionId: 'credential-journey-opaque-submission' };
      const opaqueOperation = decodeCredentialAuthorityOperation(success(credential(opaqueMetadata, invalidModelSecrets[0]!), 'operation'));
      assert.equal(opaqueOperation.phase, 'committed'); assert.equal(opaqueOperation.intendedAuthorityRevision, 1);
      assert.equal(opaqueOperation.intendedSecretGeneration, 1); assert.equal(opaqueOperation.commandCore.purpose, 'dependency_registry');
      const opaqueRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: opaqueMetadata.credentialGrantId }), 'record'));
      assert.equal(opaqueRecord.state, 'active'); assert.equal(opaqueRecord.purpose, 'dependency_registry');
      assert.equal(opaqueRecord.authorityRevision, 1); assert.equal(opaqueRecord.secretGeneration, 1);
      assert.deepEqual(opaqueRecord.platformItem, opaqueOperation.platformItem);
      assert.equal(opaqueRecord.platformItem.kind, 'linux_secret_service');
      if (opaqueRecord.platformItem.kind !== 'linux_secret_service') throw new Error('Linux opaque enrollment must use Secret Service');
      const opaqueInventory = observe('list'); assert.equal(opaqueInventory.items.length, 2);
      assert(opaqueInventory.items.includes(after.items[0]!));
      const opaqueItems = opaqueInventory.items.filter(item => item !== after.items[0]); assert.equal(opaqueItems.length, 1);
      const opaqueReadback = observe('compare', opaqueItems[0]!, opaqueRecord.platformItem.itemId, invalidModelSecrets[0]!);
      assert.equal(opaqueReadback.readback, true); assert.equal(opaqueReadback.logicalItemIdMatched, true);
      const opaqueRevocation = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'revoke',
        requestId: '019a0012-0000-7000-8000-000000000068', credentialGrantId: opaqueMetadata.credentialGrantId,
        expectedAuthorityRevision: 1 }), 'operation'));
      assert.equal(opaqueRevocation.disposition, 'revoked'); assert.equal(opaqueRevocation.cleanupPhase, 'cleanup_complete');
      assert.equal(opaqueRevocation.committedAuthorityRevision, 2); assert.deepEqual(opaqueRevocation.platformItem, opaqueRecord.platformItem);
      assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'cleanup',
        requestId: opaqueRevocation.requestId }), 'operation')), opaqueRevocation);
      await originalCredentialUnchanged();
      report.opaqueDependencySecret = { actualBinaryRoundtrip: true, exactItemRevokedAndCleaned: true,
        originalModelRecordAndItemUnchanged: true, dependencyDispatchQualified: false };

      markPhase('orphan_first_prepared_sigkill');
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
      markPhase('orphan_read_does_not_promote');
      assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: orphanMetadata.credentialGrantId }), 'record'), null,
        'ordinary read must not promote the joined prepared orphan');
      assert.deepEqual(observe('list').items, after.items, 'prepared cut must precede an actual platform item');
      markPhase('orphan_automatic_same_request_retry');
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
      markPhase('revoke_recovered_fixture_grant');
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
        markPhase(`attempt_cap_prepared_${expectedAttempt}_sigkill`);
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
      markPhase('attempt_cap_fourth_refused');
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
      markPhase('attempt_cap_repeated_refusal');
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

      markPhase('cleanup_current_active_refusal');
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

      const { rotateMetadata, rotatedOperation, rotatedRecord, rotatedItemId, afterRotate } = await rotateAndVerify();

      markPhase('committed_submission_reuse');
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

      markPhase('exact_replay_without_services_or_secret_input');
      const stopped = command('/usr/bin/systemctl', ['--user', 'stop', setup.supervisorUnit, setup.keeperUnit]);
      assert.equal(stopped.status, 0, 'actual installed services must stop before replay');
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
      markPhase('permanent_request_intent_conflict');
      for (let repeated = 0; repeated < 2; repeated++) {
        const conflict = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
          canonicalJsonBytes({ ...metadata, expiresAt: '2098-01-01T00:00:00.000Z' }).toString('base64url')]);
        assert.equal(conflict.status, 1); assert.equal(conflict.stdout, '');
        const line = conflict.stderr.trim().split('\n').at(-1); assert(line && Buffer.byteLength(line) <= 2048);
        const refusal = parseJsonStrict(line) as Record<string, unknown>;
        assert.equal(refusal.diagnosticOnly, true); assert.equal(refusal.scope, 'installed-read-startup');
        assert.equal(refusal.code, 'REQUEST_ID_CONFLICT'); assert.equal(refusal.message, 'credential request already names different intent');
        assert.deepEqual(inactive(), report.servicesBeforeReplay); noStore();
        assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: metadata.credentialGrantId }), 'record')), rotatedRecord);
      }
      report.permanentIntentConflict = { exactRepeatedRefusal: true, latestRecordUnchanged: true,
        servicesRemainInactive: true, secretServiceOwnerAbsent: true, secretInputPipeUnwrittenAndUnended: true };

      markPhase('revoke_without_services_or_secret_input');
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
      markPhase('revoke_retry_without_store');
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

      markPhase('restore_fixture_secret_service');
      const restored = await startDaemon();
      assert.notEqual(restored.nameOwner, before.nameOwner); assert.equal(restored.collection, before.collection);
      assert(daemonFact && (daemonFact.pid !== originalDaemon.pid || daemonFact.start !== originalDaemon.start),
        'restored fixture daemon must be a new positively observed lifetime');
      assert.equal(restored.items.length, 1);
      const restoredCompared = observe('compare', restored.items[0]!, rotatedItemId, rotatedSecret);
      assert.equal(restoredCompared.readback, true); assert.equal(restoredCompared.logicalItemIdMatched, true);
      assert.equal(restoredCompared.item, restored.items[0]); assert.equal(restoredCompared.nameOwner, restored.nameOwner);
      assert.equal(restoredCompared.servicePid, restored.servicePid); assert.equal(restoredCompared.collection, restored.collection);
      report.platformRestored = restored; report.platformRestoredReadback = restoredCompared;
      report.servicesBeforeCleanup = inactive();
      markPhase('revoke_retry_with_restored_store');
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
      markPhase('completed_revoke_exact_replay');
      const completedReplay = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
        ['--bootstrap-credential', revokeBytes.toString('base64url')]);
      assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(completedReplay, 'operation')), completedRevocation,
        'completed cleanup replay must not regenerate receipt cleanup fields');
      assert.equal(completedReplay.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation: completedRevocation }).toString('utf8')}\n`);
      assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), restored.nameOwner);
      report.servicesAfterCompletedReplay = inactive();
      report.successfulCleanupRetry = { originalReceiptIdentityMatched: true, revokedRecordUnchanged: true,
        actualInventoryEmpty: true, completedReceiptExactReplay: true, secretInputPipeUnwrittenAndUnended: true };

      markPhase('explicit_completed_revoke_cleanup');
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
        markPhase(originalOperation.kind === 'enroll' ? 'explicit_superseded_enroll_cleanup' : 'explicit_revoked_rotate_cleanup');
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

      // These are actual adversarial store preconditions, not fabricated native
      // observations or SQL authority. The administrative helper cannot run on
      // an ordinary account's vault and never reads the original secret. The
      // separate duplicate commands own only their positively identified item.
      const storeFixture = (action: 'lock' | 'alias-session' | 'alias-restore' | 'item-extra' | 'item-restore', locator?: string, itemId?: string) => {
        const result = command(recipe.storeFixture, [action, ...(locator ? [locator] : []), ...(itemId ? [itemId] : [])]);
        assert.equal(result.status, 0, 'actual disposable store precondition did not complete');
        const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
        const flag = action === 'lock' ? 'locked' : action === 'alias-session' ? 'defaultAliasSession'
          : action === 'item-extra' ? 'itemAttributesExtra' : action === 'item-restore' ? 'itemAttributesRestored' : 'defaultAliasMatched';
        assert.deepEqual(Object.keys(value).sort(), ['diagnosticOnly', 'action', 'collection', flag, 'connectionClosed'].sort());
        assert.equal(value.diagnosticOnly, true); assert.equal(value.action, action);
        assert.equal(value[flag], true); assert.equal(value.connectionClosed, true);
        if (action === 'alias-session') {
          assert.equal(typeof value.collection, 'string'); assert.notEqual(value.collection, restored.collection);
          assert.match(value.collection as string, /^\/org\/freedesktop\/secrets\/collection\/[A-Za-z0-9_]+$/u);
        } else assert.equal(value.collection, restored.collection);
        return value;
      };
      const platformWriteRefused = (result: ReturnType<typeof credential>) => {
        report.platformRefusalDiagnostic = { diagnosticOnly: true, actualExitStatus: result.status,
          stdoutPresent: result.stdout.length > 0 };
        assert.equal(result.status, 1); assert.equal(result.stdout, '');
        const line = result.stderr.trim().split('\n').at(-1); assert(line && Buffer.byteLength(line) <= 2048);
        const value = parseJsonStrict(line) as Record<string, unknown>;
        assert.equal(value.diagnosticOnly, true); assert.equal(value.scope, 'installed-read-startup');
        assert.equal(value.code, 'RECOVERY_REQUIRED');
        assert.equal(value.message, 'credential store did not complete a fresh secret round-trip');
      };
      const stopRoles = () => {
        assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', setup.supervisorUnit, setup.keeperUnit]).status, 0);
        return inactive();
      };
      markPhase('item_attribute_drift_setup');
      const driftMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000041',
        credentialGrantId: 'credential-journey-attribute-grant', secretSubmissionId: 'credential-journey-attribute-submission' };
      const driftOperation = decodeCredentialAuthorityOperation(success(credential(driftMetadata, negativeSecret), 'operation'));
      assert.equal(driftOperation.phase, 'committed'); assert.equal(driftOperation.attempt, 1);
      assert.equal(driftOperation.requestId, driftMetadata.requestId); assert.equal(driftOperation.credentialGrantId, driftMetadata.credentialGrantId);
      const driftRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: driftMetadata.credentialGrantId }), 'record'));
      assert.equal(driftRecord.state, 'active'); assert.equal(driftRecord.authorityRevision, 1);
      assert.equal(driftRecord.credentialGrantId, driftMetadata.credentialGrantId);
      assert.deepEqual(driftRecord.platformItem, driftOperation.platformItem);
      const driftItem = driftRecord.platformItem; assert.equal(driftItem.kind, 'linux_secret_service');
      if (driftItem.kind !== 'linux_secret_service') throw new Error('Linux drift fixture requires a Secret Service item');
      const driftBefore = observe('list'); assert.equal(driftBefore.items.length, 1);
      assert.equal(driftBefore.nameOwner, restored.nameOwner); assert.equal(driftBefore.servicePid, restored.servicePid);
      assert.equal(observe('compare', driftBefore.items[0]!, driftItem.itemId, negativeSecret).readback, true);
      const driftServices = stopRoles();
      markPhase('item_attribute_drift');
      report.itemAttributesExtra = storeFixture('item-extra', driftBefore.items[0]!, driftItem.itemId);
      let driftPrimary: unknown, driftRevoke: ReturnType<typeof decodeCredentialAuthorityRevokeOperation> | undefined;
      let driftRevoked: ReturnType<typeof decodeCredentialAuthorityRecord> | undefined;
      try {
        const result = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
          canonicalJsonBytes({ schemaVersion: 1, kind: 'revoke', requestId: '019a0012-0000-7000-8000-000000000042',
            credentialGrantId: driftMetadata.credentialGrantId, expectedAuthorityRevision: 1 }).toString('base64url')]);
        driftRevoke = decodeCredentialAuthorityRevokeOperation(success(result, 'operation'));
        assert.equal(driftRevoke.requestId, '019a0012-0000-7000-8000-000000000042');
        assert.equal(driftRevoke.credentialGrantId, driftMetadata.credentialGrantId); assert.equal(driftRevoke.committedAuthorityRevision, 2);
        assert.deepEqual(driftRevoke.platformItem, driftItem);
        assert.equal(driftRevoke.cleanupPhase, 'cleanup_failed');
        assert.equal(driftRevoke.cleanupErrorCode, 'platform_store_unavailable');
        driftRevoked = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: driftMetadata.credentialGrantId }), 'record'));
        const { recordDigest: _beforeDigest, ...beforeBody } = driftRecord;
        const { recordDigest: _afterDigest, ...afterBody } = driftRevoked;
        assert.deepEqual(afterBody, { ...beforeBody, state: 'revoked', authorityRevision: 2, revokedAt: driftRevoke.metadataCommittedAt,
          revokedByRequestId: driftRevoke.requestId, revokedByRequestDigest: driftRevoke.requestDigest });
        assert.equal(driftRevoke.revokedRecordDigest, driftRevoked.recordDigest);
        assert.deepEqual(observe('list').items, driftBefore.items);
        assert.equal(observe('compare', driftBefore.items[0]!, driftItem.itemId, negativeSecret).readback, true);
        assert.equal(serviceOwner(), driftBefore.nameOwner); assert.deepEqual(inactive(), driftServices);
      } catch (error) { driftPrimary = error; throw error; }
      finally {
        try { report.itemAttributesRestored = storeFixture('item-restore', driftBefore.items[0]!, driftItem.itemId); }
        catch (error) { throw new AggregateError([driftPrimary, error].filter(Boolean), 'actual item test and restoration failed'); }
      }
      assert(driftRevoke && driftRevoked);
      markPhase('item_attribute_drift_cleanup');
      const driftCleanup = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'cleanup',
        requestId: driftRevoke.requestId }), 'operation'));
      assert.equal(driftCleanup.cleanupPhase, 'cleanup_complete');
      assert.deepEqual(receiptIdentity(driftCleanup), receiptIdentity(driftRevoke));
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: driftMetadata.credentialGrantId }), 'record')), driftRevoked);
      assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), driftBefore.nameOwner);
      assert.deepEqual(inactive(), driftServices);
      report.itemAttributeCleanupRefusal = { terminalRevokeWithoutSupervisor: true, mismatchedItemNotDeleted: true,
        originalReceiptIdentityMatched: true, revokedRecordUnchanged: true, restoredCleanupComplete: true,
        secretInputPipeUnwrittenAndUnended: true, finalizerDriftQualified: false, ambiguityQualified: false };

      markPhase('ambiguous_store_setup');
      const ambiguousMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000045',
        credentialGrantId: 'credential-journey-ambiguous-grant', secretSubmissionId: 'credential-journey-ambiguous-submission' };
      const ambiguousOperation = decodeCredentialAuthorityOperation(success(credential(ambiguousMetadata, negativeSecret), 'operation'));
      assert.equal(ambiguousOperation.phase, 'committed'); assert.equal(ambiguousOperation.requestId, ambiguousMetadata.requestId);
      const ambiguousRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: ambiguousMetadata.credentialGrantId }), 'record'));
      assert.equal(ambiguousRecord.state, 'active'); assert.equal(ambiguousRecord.authorityRevision, 1);
      assert.equal(ambiguousRecord.credentialGrantId, ambiguousMetadata.credentialGrantId);
      assert.deepEqual(ambiguousRecord.platformItem, ambiguousOperation.platformItem);
      const ambiguousItem = ambiguousRecord.platformItem;
      assert(ambiguousItem.kind === 'linux_secret_service');
      const ambiguousBefore = observe('list'); assert.equal(ambiguousBefore.items.length, 1);
      assert.equal(ambiguousBefore.nameOwner, restored.nameOwner); assert.equal(ambiguousBefore.collection, restored.collection);
      const originalItem = ambiguousBefore.items[0]!;
      assert.equal(observe('compare', originalItem, ambiguousItem.itemId, negativeSecret).readback, true);
      assert.equal(secret.equals(negativeSecret), false);
      const ambiguousServices = stopRoles(), duplicateNonce = randomBytes(16).toString('hex');
      const duplicateFixture = (action: 'duplicate-create' | 'duplicate-remove', duplicate?: string) => {
        const result = command(recipe.storeFixture, [action, originalItem, ambiguousItem.itemId, duplicateNonce,
          ...(duplicate ? [duplicate] : [])], action === 'duplicate-create' ? secret : undefined);
        assert.equal(result.status, 0, 'owned duplicate store precondition did not complete');
        const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
        const flag = action === 'duplicate-create' ? 'duplicateCreated' : 'duplicateRemoved';
        assert.deepEqual(Object.keys(value).sort(), ['diagnosticOnly', 'action', 'collection', 'duplicateItem', flag, 'connectionClosed'].sort());
        assert.equal(value.diagnosticOnly, true); assert.equal(value.action, action); assert.equal(value.collection, restored.collection);
        assert.equal(value[flag], true); assert.equal(value.connectionClosed, true); assert.equal(typeof value.duplicateItem, 'string');
        const locator = value.duplicateItem as string;
        assert(locator.startsWith(`${restored.collection}/`)); assert.match(locator.slice(restored.collection.length + 1), /^[A-Za-z0-9_]+$/u);
        assert(Buffer.byteLength(locator) <= 1024); assert.notEqual(locator, originalItem);
        if (duplicate) assert.equal(locator, duplicate);
        report[action === 'duplicate-create' ? 'duplicateCreated' : 'duplicateRemoved'] = value;
        return locator;
      };
      let duplicateItem: string | undefined, ambiguousPrimary: unknown;
      let ambiguousRevoke: ReturnType<typeof decodeCredentialAuthorityRevokeOperation> | undefined;
      let ambiguousRevoked: ReturnType<typeof decodeCredentialAuthorityRecord> | undefined;
      try {
        markPhase('ambiguous_store_create'); duplicateItem = duplicateFixture('duplicate-create');
        const expectedItems = [originalItem, duplicateItem].sort();
        const unchangedItems = () => {
          const current = observe('list'); assert.deepEqual(current.items, expectedItems);
          for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection'] as const) assert.equal(current[key], ambiguousBefore[key]);
          assert.equal(observe('compare', originalItem, ambiguousItem.itemId, negativeSecret).readback, true);
          assert.equal(observe('compare', duplicateItem!, ambiguousItem.itemId, secret).readback, true);
          assert.deepEqual(inactive(), ambiguousServices);
        };
        unchangedItems(); markPhase('ambiguous_store_revoke');
        ambiguousRevoke = decodeCredentialAuthorityRevokeOperation(success(await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
          ['--bootstrap-credential', canonicalJsonBytes({ schemaVersion: 1, kind: 'revoke', requestId: '019a0012-0000-7000-8000-000000000046',
            credentialGrantId: ambiguousMetadata.credentialGrantId, expectedAuthorityRevision: 1 }).toString('base64url')]), 'operation'));
        assert.equal(ambiguousRevoke.requestId, '019a0012-0000-7000-8000-000000000046');
        assert.equal(ambiguousRevoke.credentialGrantId, ambiguousMetadata.credentialGrantId); assert.equal(ambiguousRevoke.committedAuthorityRevision, 2);
        assert.equal(ambiguousRevoke.cleanupPhase, 'cleanup_failed'); assert.equal(ambiguousRevoke.cleanupErrorCode, 'platform_store_unavailable');
        assert.deepEqual(ambiguousRevoke.platformItem, ambiguousItem);
        ambiguousRevoked = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: ambiguousMetadata.credentialGrantId }), 'record'));
        const { recordDigest: _beforeDigest, ...beforeBody } = ambiguousRecord;
        const { recordDigest: _afterDigest, ...afterBody } = ambiguousRevoked;
        assert.deepEqual(afterBody, { ...beforeBody, state: 'revoked', authorityRevision: 2, revokedAt: ambiguousRevoke.metadataCommittedAt,
          revokedByRequestId: ambiguousRevoke.requestId, revokedByRequestDigest: ambiguousRevoke.requestDigest });
        assert.equal(ambiguousRevoke.revokedRecordDigest, ambiguousRevoked.recordDigest); unchangedItems();
        const repeated = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'cleanup', requestId: ambiguousRevoke.requestId }), 'operation'));
        assert.equal(repeated.cleanupPhase, 'cleanup_failed'); assert.equal(repeated.cleanupErrorCode, 'platform_store_unavailable');
        assert.deepEqual(receiptIdentity(repeated), receiptIdentity(ambiguousRevoke));
        assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: ambiguousMetadata.credentialGrantId }), 'record')), ambiguousRevoked); unchangedItems();
      } catch (error) { ambiguousPrimary = error; throw error; }
      finally {
        if (duplicateItem) try { duplicateFixture('duplicate-remove', duplicateItem); }
        catch (error) { throw new AggregateError([ambiguousPrimary, error].filter(Boolean), 'actual ambiguity test and duplicate retirement failed'); }
      }
      assert(ambiguousRevoke && ambiguousRevoked); markPhase('ambiguous_store_cleanup');
      assert.deepEqual(observe('list').items, [originalItem]);
      assert.equal(observe('compare', originalItem, ambiguousItem.itemId, negativeSecret).readback, true);
      const ambiguousCleanup = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'cleanup', requestId: ambiguousRevoke.requestId }), 'operation'));
      assert.equal(ambiguousCleanup.cleanupPhase, 'cleanup_complete'); assert.deepEqual(receiptIdentity(ambiguousCleanup), receiptIdentity(ambiguousRevoke));
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: ambiguousMetadata.credentialGrantId }), 'record')), ambiguousRevoked);
      assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), ambiguousBefore.nameOwner); assert.deepEqual(inactive(), ambiguousServices);
      report.ambiguousStoreCleanup = { terminalRevokeWithoutSupervisor: true, bothMatchingItemsPreserved: true,
        explicitAmbiguousCleanupRefused: true, ownedDuplicateOnlyRetired: true, originalReceiptIdentityMatched: true,
        revokedRecordUnchanged: true, uniqueOriginalCleanupComplete: true, secretInputPipeUnwrittenAndUnended: true,
        finalizerAmbiguityQualified: false };

      markPhase('locked_store_setup');
      const negativeMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000030',
        credentialGrantId: '019a0012-0000-7000-8000-000000000031', secretSubmissionId: '019a0012-0000-7000-8000-000000000130' };
      const negativeOperation = decodeCredentialAuthorityOperation(success(credential(negativeMetadata, negativeSecret), 'operation'));
      assert.equal(negativeOperation.phase, 'committed'); assert.equal(negativeOperation.attempt, 1);
      assert.equal(negativeOperation.requestId, negativeMetadata.requestId);
      const negativeRecord = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: negativeMetadata.credentialGrantId }), 'record'));
      assert.equal(negativeRecord.credentialGrantId, negativeMetadata.credentialGrantId);
      assert.equal(negativeRecord.state, 'active'); assert.equal(negativeRecord.authorityRevision, 1);
      const negativeItem = negativeRecord.platformItem; assert(negativeItem.kind === 'linux_secret_service');
      const negativeBefore = observe('list'); assert.equal(negativeBefore.items.length, 1);
      assert.equal(negativeBefore.nameOwner, restored.nameOwner); assert.equal(negativeBefore.collection, restored.collection);
      assert.equal(observe('compare', negativeBefore.items[0]!, negativeItem.itemId, negativeSecret).readback, true);
      report.servicesBeforeLockedStore = stopRoles();
      markPhase('locked_store'); report.lockedStore = storeFixture('lock');
      assert.equal(serviceOwner(), negativeBefore.nameOwner);
      const lockedItems = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'get-property',
        negativeBefore.nameOwner, negativeBefore.collection, 'org.freedesktop.Secret.Collection', 'Items']);
      assert.equal(lockedItems.status, 0);
      assert.equal(lockedItems.stdout.trim(), `ao 1 "${negativeBefore.items[0]}"`);
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: negativeMetadata.credentialGrantId }), 'record')), negativeRecord);
      assert.deepEqual(inactive(), report.servicesBeforeLockedStore);
      const lockedRequest = { ...negativeMetadata, requestId: '019a0012-0000-7000-8000-000000000032',
        credentialGrantId: '019a0012-0000-7000-8000-000000000033', secretSubmissionId: '019a0012-0000-7000-8000-000000000132' };
      platformWriteRefused(credential(lockedRequest, negativeSecret));
      assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: lockedRequest.credentialGrantId }), 'record'), null);
      report.servicesBeforeLockedRevoke = stopRoles();
      const negativeRevoke = { schemaVersion: 1, kind: 'revoke', requestId: '019a0012-0000-7000-8000-000000000034',
        credentialGrantId: negativeMetadata.credentialGrantId, expectedAuthorityRevision: 1 };
      const lockedRevoke = decodeCredentialAuthorityRevokeOperation(success(credential(negativeRevoke), 'operation'));
      assert.equal(lockedRevoke.cleanupPhase, 'cleanup_failed');
      const negativeRevoked = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: negativeMetadata.credentialGrantId }), 'record'));
      assert.equal(negativeRevoked.state, 'revoked'); assert.equal(negativeRevoked.authorityRevision, 2);
      assert.equal(negativeRevoked.secretGeneration, 1);
      assert.deepEqual(inactive(), report.servicesBeforeLockedRevoke); assert.equal(serviceOwner(), negativeBefore.nameOwner);
      const retainedLockedItems = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'get-property',
        negativeBefore.nameOwner, negativeBefore.collection, 'org.freedesktop.Secret.Collection', 'Items']);
      assert.equal(retainedLockedItems.status, 0); assert.equal(retainedLockedItems.stdout, lockedItems.stdout);
      report.lockedStoreRefusal = { noNewAuthority: true, originalReadUnchanged: true, originalItemStillPresent: true,
        terminalRevokeWithoutSupervisor: true, revokedRevision: 2, cleanupFailed: true };
      markPhase('locked_store_restore');
      await stopDaemon(negativeBefore.servicePid);
      const unlockedAgain = await startDaemon(); assert.equal(unlockedAgain.items.length, 1);
      assert.notEqual(unlockedAgain.nameOwner, negativeBefore.nameOwner);
      assert.equal(observe('compare', unlockedAgain.items[0]!, negativeItem.itemId, negativeSecret).readback, true);
      assert.deepEqual(inactive(), report.servicesBeforeLockedRevoke);
      markPhase('nondurable_default_alias');
      const aliasFixture = storeFixture('alias-session'); report.nondurableDefaultAlias = aliasFixture;
      let aliasPrimary: unknown;
      try {
        assert.equal(serviceOwner(), unlockedAgain.nameOwner);
        const alias = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call',
          unlockedAgain.nameOwner, '/org/freedesktop/secrets', 'org.freedesktop.Secret.Service', 'ReadAlias', 's', 'default']);
        assert.equal(alias.status, 0);
        const locator = /^o "(\/[A-Za-z0-9_/]*)"$/u.exec(alias.stdout.trim()); assert(locator);
        const session = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call',
          unlockedAgain.nameOwner, '/org/freedesktop/secrets', 'org.freedesktop.Secret.Service', 'ReadAlias', 's', 'session']);
        assert.equal(session.status, 0);
        const sessionLocator = /^o "(\/[A-Za-z0-9_/]*)"$/u.exec(session.stdout.trim()); assert(sessionLocator);
        report.defaultAliasBeforeAuth = { diagnosticOnly: true, collection: locator[1], sessionCollection: sessionLocator[1], nameOwner: serviceOwner() };
        assert.notEqual(locator[1], '/'); assert.equal(locator[1], sessionLocator[1],
          'nondurable alias must remain the actual session collection in a fresh connection');
        assert.equal(locator[1], aliasFixture.collection);
        const unchangedAliasItems = () => {
          const currentAlias = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call',
            unlockedAgain.nameOwner, '/org/freedesktop/secrets', 'org.freedesktop.Secret.Service', 'ReadAlias', 's', 'default']);
          assert.equal(currentAlias.status, 0); assert.equal(currentAlias.stdout.trim(), `o "${sessionLocator[1]}"`);
          const items = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'get-property',
            unlockedAgain.nameOwner, unlockedAgain.collection, 'org.freedesktop.Secret.Collection', 'Items']);
          assert.equal(items.status, 0); assert.equal(items.stdout.trim(), `ao 1 "${unlockedAgain.items[0]}"`);
          const sessionItems = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'get-property',
            unlockedAgain.nameOwner, sessionLocator[1]!, 'org.freedesktop.Secret.Collection', 'Items']);
          assert.equal(sessionItems.status, 0); assert.equal(sessionItems.stdout.trim(), 'ao 0');
          assert.equal(serviceOwner(), unlockedAgain.nameOwner); assert.deepEqual(inactive(), report.servicesBeforeLockedRevoke);
        };
        unchangedAliasItems(); markPhase('nondurable_alias_known_cleanup');
        const aliasRevoke = decodeCredentialAuthorityRevokeOperation(success(await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
          ['--bootstrap-credential', canonicalJsonBytes(negativeRevoke).toString('base64url')]), 'operation'));
        assert.equal(aliasRevoke.cleanupPhase, 'cleanup_failed'); assert.equal(aliasRevoke.cleanupErrorCode, 'platform_store_unavailable');
        assert.deepEqual(receiptIdentity(aliasRevoke), receiptIdentity(lockedRevoke)); unchangedAliasItems();
        const aliasCleanup = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'cleanup',
          requestId: negativeRevoke.requestId }), 'operation'));
        assert.equal(aliasCleanup.cleanupPhase, 'cleanup_failed'); assert.equal(aliasCleanup.cleanupErrorCode, 'platform_store_unavailable');
        assert.deepEqual(receiptIdentity(aliasCleanup), receiptIdentity(lockedRevoke));
        assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: negativeMetadata.credentialGrantId }), 'record')), negativeRevoked); unchangedAliasItems();
        report.nondurableAliasKnownCleanup = { terminalReadAndCleanupWithoutSupervisor: true, originalItemStillPresent: true,
          sessionInventoryEmpty: true, originalReceiptIdentityMatched: true, revokedRecordUnchanged: true,
          secretInputPipeUnwrittenAndUnended: true, finalizerAliasDriftQualified: false };
        markPhase('nondurable_alias_admission');
        const nondurableRequest = { ...negativeMetadata, requestId: '019a0012-0000-7000-8000-000000000035',
          credentialGrantId: '019a0012-0000-7000-8000-000000000036', secretSubmissionId: '019a0012-0000-7000-8000-000000000135' };
        platformWriteRefused(credential(nondurableRequest, negativeSecret));
        assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: nondurableRequest.credentialGrantId }), 'record'), null);
        assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: negativeMetadata.credentialGrantId }), 'record')), negativeRevoked);
        assert.equal(serviceOwner(), unlockedAgain.nameOwner);
        report.nondurableAliasRefusal = { noNewAuthority: true, revokedRecordUnchanged: true, missingAliasQualified: false };
      } catch (error) { aliasPrimary = error; throw error; }
      finally {
        try { report.defaultAliasRestored = storeFixture('alias-restore', unlockedAgain.collection); }
        catch (error) { throw new AggregateError([aliasPrimary, error].filter(Boolean), 'actual alias test and restoration failed'); }
      }
      markPhase('restored_alias_known_cleanup');
      const restoredAliasItem = observe('list'); assert.deepEqual(restoredAliasItem.items, unlockedAgain.items);
      for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection'] as const) assert.equal(restoredAliasItem[key], unlockedAgain[key]);
      assert.equal(observe('compare', restoredAliasItem.items[0]!, negativeItem.itemId, negativeSecret).readback, true);
      const unlockedRevoke = decodeCredentialAuthorityRevokeOperation(success(credential(negativeRevoke), 'operation'));
      assert.equal(unlockedRevoke.cleanupPhase, 'cleanup_complete');
      assert.deepEqual(receiptIdentity(unlockedRevoke), receiptIdentity(lockedRevoke));
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: negativeMetadata.credentialGrantId }), 'record')), negativeRevoked);
      report.nondurableAliasCleanupRestored = { originalItemBytesUnchanged: true, originalReceiptIdentityMatched: true,
        cleanupComplete: true, revokedRecordUnchanged: true, finalizerAliasDriftQualified: false };
      assert.deepEqual(observe('list').items, []);
      markPhase('initial_gate_endpoint_revocation');
      // Reuse the Supervisor genuinely started by nondurableRequest above.
      // Cold autostart is covered earlier; this cut tests the input interval,
      // not another startup plus two commands within the replay fixture budget.
      const raceUnits = [setup.keeperUnit, setup.supervisorUnit], raceServices = raceUnits.map(show);
      for (const service of raceServices) {
        assert.equal(service.ActiveState, 'active'); assert.equal(service.SubState, 'running');
        assert.match(service.MainPID!, /^[1-9][0-9]*$/u); assert.equal(service.MainPID, service.ExecMainPID);
        assert.match(service.InvocationID!, /^[0-9a-f]{32}$/u);
      }
      const raceMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000047',
        credentialGrantId: 'credential-journey-input-revocation-grant', secretSubmissionId: 'credential-journey-input-revocation-submission' };
      const raceInventory = observe('list'); assert.deepEqual(raceInventory.items, []);
      const baselineCASrefs = (await readdir(path.join(recipe.stateRoot, 'cas'))).filter(ref => /^[0-9a-f]{64}$/u.test(ref));
      const endpointRevokeCore = { schemaVersion: 1, kind: 'revoke', ownerPrincipalId,
        endpointRegistrationId: registration.endpointRegistrationId, expectedAuthorityRevision: 1, commandDigest: '' } as const;
      let endpointRevocation: ReturnType<typeof decodeEndpointAuthorityOperation> | undefined;
      let initialHello: Extract<Awaited<ReturnType<typeof observeInitialCredentialHello>>, { kind: 'observed' }>['hello'] | undefined;
      const inputObservation: { diagnosticOnly: true; launcherObserved: boolean; directChildrenSeen: number | null;
        authObserved: boolean; readyChecks: number;
        helloObserved: boolean; completeInputWriteJoined: boolean;
        lastPending?: Extract<Awaited<ReturnType<typeof observeInitialCredentialHello>>, { kind: 'pending' }> } = {
          diagnosticOnly: true, launcherObserved: false, directChildrenSeen: null,
          authObserved: false, readyChecks: 0, helloObserved: false, completeInputWriteJoined: false };
      report.initialGateObservation = inputObservation;
      const racedInput = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
        canonicalJsonBytes(raceMetadata).toString('base64url')], {
        secret: negativeSecret,
        diagnostic: inputObservation,
        async ready(auth) {
          inputObservation.authObserved = true; inputObservation.readyChecks++;
          assert(inputObservation.readyChecks <= 2048, 'initial credential observation exceeded its diagnostic bound');
          const observation = await observeInitialCredentialHello({ stateRoot: recipe.stateRoot,
            originalAuth: { pid: auth.pid, start: auth.start, uid: ledger.uid },
            selectedImage: expectedImage, selectedImageDigest: selectedEntry.digest,
            expectedRootDigest: rootDigest, expectedPrincipalId: ownerPrincipalId, baselineCASrefs });
          if (observation.kind === 'pending') { inputObservation.lastPending = observation; return false; }
          initialHello = observation.hello; inputObservation.helloObserved = true; return true;
        },
        async beforeInput() {
          assert(initialHello);
          endpointRevocation = decodeEndpointAuthorityOperation(success(command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'],
            canonicalJsonBytes({ schemaVersion: 1, kind: 'commit', requestId: '019a0012-0000-7000-8000-000000000043',
              commandCore: { ...endpointRevokeCore, commandDigest: digestOmitting(endpointRevokeCore, 'commandDigest') } })), 'operation'));
          assert.equal(endpointRevocation.kind, 'revoke'); assert.equal(endpointRevocation.disposition, 'revoked');
          assert.equal(endpointRevocation.committedAuthorityRevision, 2);
        }
      });
      assert(initialHello && endpointRevocation);
      exactRefusal(racedInput, 'STATE_TRANSITION_INVALID', 'credential requires a current active endpoint of its purpose');
      assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: raceMetadata.credentialGrantId }), 'record'), null);
      exactRefusal(credential({ schemaVersion: 1, kind: 'cleanup', requestId: raceMetadata.requestId }),
        'NOT_FOUND', 'credential cleanup request has no retained operation');
      const inventoryAfterRace = observe('list'); assert.deepEqual(inventoryAfterRace.items, raceInventory.items);
      for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection'] as const) assert.equal(inventoryAfterRace[key], raceInventory[key]);
      for (const [index, unit] of raceUnits.entries()) {
        const after = show(unit); assert.equal(after.ActiveState, 'active'); assert.equal(after.SubState, 'running');
        for (const key of ['MainPID', 'ExecMainPID', 'InvocationID', 'ControlGroup'] as const) assert.equal(after[key], raceServices[index]![key]);
      }
      report.servicesAfterStoreNegatives = stopRoles();
      report.preInputEndpointRevocation = { diagnosticOnly: true, initialHello,
        initialClassifierBeforeRevocation: true, fullInputAcceptedAfterRevocation: true, authNaturallyJoined: true,
        exactPostInputRefusal: true, noRetainedOperationOrAttempt: true, noCredentialRecord: true,
        platformInventoryRemainedEmpty: true, platformOwnerAndCollectionUnchanged: true,
        existingServiceInvocationsUnchanged: true, coldAutostartQualified: false,
        exactReadSecretEntryQualified: false, livePendingQualified: false, concurrentFinalizerRevokeQualified: false };
      markPhase('unknown_credential_schema');
      // Corrupt only this disposable, fully closed v2 fixture. This does not
      // seed valid authority: the same signed read must reject an extra legal
      // user table, and removing it must preserve the actual committed history.
      const schemaCommand = (change: 'add' | 'remove') => {
        const result = command(process.execPath, ['--no-warnings', '-e', `
          const { DatabaseSync } = require('node:sqlite');
          const database = new DatabaseSync(${JSON.stringify(path.join(recipe.stateRoot, 'credentials/authority.sqlite'))});
          try {
            if (database.prepare('PRAGMA user_version').get().user_version !== 2) throw new Error('expected actual v2 fixture');
            database.exec(${JSON.stringify(change === 'add' ? 'CREATE TABLE sqlitex(value TEXT) STRICT' : 'DROP TABLE sqlitex')});
            const present = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name='sqlitex'").all().length;
            if (present !== ${change === 'add' ? 1 : 0}) throw new Error('actual extra table state differs');
          } finally { database.close(); }
        `]);
        assert.equal(result.status, 0, 'disposable schema precondition did not complete'); assert.equal(result.stdout, '');
      };
      schemaCommand('add');
      let schemaPrimary: unknown;
      try {
        const refused = credential({ schemaVersion: 1, kind: 'read', credentialGrantId: negativeMetadata.credentialGrantId });
        assert.equal(refused.status, 1); assert.equal(refused.stdout, '');
        const line = refused.stderr.trim().split('\n').at(-1); assert(line && Buffer.byteLength(line) <= 2048);
        const actual = parseJsonStrict(line);
        const fields = actual && typeof actual === 'object' && !Array.isArray(actual) ? actual as Record<string, unknown> : undefined;
        // Only source-owned labels and booleans survive. Never copy arbitrary
        // error text, code, paths, keys or assertion differences into artifacts.
        const codes = [['RECOVERY_REQUIRED', 'recovery_required'], ['ARTIFACT_MISMATCH', 'artifact_mismatch'],
          ['UNSUPPORTED_PLATFORM', 'unsupported_platform'], ['ERR_CLIQ_CREDENTIAL_BUSY', 'credential_busy'],
          ['ERR_SQLITE_ERROR', 'sqlite_error']] as const;
        const messageClass = fields?.message === 'endpoint authority schema is not supported' ? 'schema_unsupported'
          : fields?.message === 'credential scope could not hold its original physical bindings' ? 'native_bindings'
          : ['credential scope descriptors did not retire', 'credential native scope did not retire', 'credential SQLite bootstrap did not retire',
            'credential authority database did not retire'].includes(fields?.message as string) ? 'credential_retirement'
          : ['installed runtime descriptor retirement failed', 'installed runtime retirement did not join']
            .includes(fields?.message as string) ? 'installed_retirement'
          : fields?.message === 'credential authority requires exclusive pager mode' ? 'pager_mode'
          : fields?.message === 'credential authority requires fixed exclusive-mode WAL' ? 'wal_mode' : 'other';
        report.unknownV2SchemaDiagnostic = { diagnosticOnly: true, objectExpected: !!fields,
          diagnosticOnlyExpected: fields?.diagnosticOnly === true, scopeExpected: fields?.scope === 'installed-read-startup',
          codeExpected: fields?.code === 'RECOVERY_REQUIRED', messageExpected: fields?.message === 'endpoint authority schema is not supported',
          keysetExpected: !!fields && JSON.stringify(Object.keys(fields).sort()) === '["code","diagnosticOnly","message","scope"]',
          pathPresent: !!fields && Object.hasOwn(fields, 'path'),
          codeClass: codes.find(([code]) => code === fields?.code)?.[1] ?? (fields && !Object.hasOwn(fields, 'code') ? 'absent' : 'other'),
          messageClass };
        // Strict JSON deliberately returns null-prototype objects. Match that
        // representation without dropping any actual fields from the comparison.
        assert.deepEqual(actual, Object.assign(Object.create(null), { diagnosticOnly: true, scope: 'installed-read-startup',
          code: 'RECOVERY_REQUIRED', message: 'endpoint authority schema is not supported' }));
        assert.deepEqual(inactive(), report.servicesAfterStoreNegatives);
        report.unknownV2SchemaRefusal = { noReturnedAuthority: true, servicesRemainInactive: true };
      } catch (error) { schemaPrimary = error; throw error; }
      finally {
        try { schemaCommand('remove'); }
        catch (error) { throw new AggregateError([schemaPrimary, error].filter(Boolean), 'actual schema test and restoration failed'); }
      }
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: negativeMetadata.credentialGrantId }), 'record')), negativeRevoked);

      markPhase('revoked_endpoint_admission');
      // Keep the separate genuine static refusal, not a concurrent finalizer cut.
      assert.equal(endpointRevocation.kind, 'revoke'); assert.equal(endpointRevocation.disposition, 'revoked');
      assert.equal(endpointRevocation.committedAuthorityRevision, 2);
      const endpointRevoked = decodeEndpointAuthorityRecord(success(command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'],
        canonicalJsonBytes({ schemaVersion: 1, kind: 'read', endpointRegistrationId: registration.endpointRegistrationId })), 'record'));
      assert.equal(endpointRevoked.state, 'revoked'); assert.equal(endpointRevoked.authorityRevision, 2);
      assert.equal(endpointRevoked.recordDigest, endpointRevocation.resultRecordDigest);
      const revokedEndpointMetadata = { ...metadata, requestId: '019a0012-0000-7000-8000-000000000044',
        credentialGrantId: 'credential-journey-revoked-endpoint-grant', secretSubmissionId: 'credential-journey-revoked-endpoint-submission' };
      exactRefusal(await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
        canonicalJsonBytes(revokedEndpointMetadata).toString('base64url')]), 'STATE_TRANSITION_INVALID',
        'credential requires a current active endpoint of its purpose');
      assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: revokedEndpointMetadata.credentialGrantId }), 'record'), null);
      exactRefusal(credential({ schemaVersion: 1, kind: 'cleanup', requestId: revokedEndpointMetadata.requestId }),
        'NOT_FOUND', 'credential cleanup request has no retained operation');
      const historicalAfterEndpoint = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
        ['--bootstrap-credential', canonicalJsonBytes(metadata).toString('base64url')]);
      assert.deepEqual(decodeCredentialAuthorityOperation(success(historicalAfterEndpoint, 'operation')), operation);
      assert.equal(historicalAfterEndpoint.stdout, `${canonicalJsonBytes({ schemaVersion: 1, operation }).toString('utf8')}\n`);
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
      assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), unlockedAgain.nameOwner);
      assert.deepEqual(inactive(), report.servicesAfterStoreNegatives);
      report.revokedEndpointAdmission = { noReturnedAuthority: true, noRetainedOperation: true,
        originalOperationReplayUnchanged: true, terminalRecordUnchanged: true, servicesRemainInactive: true,
        secretInputPipeUnwrittenAndUnended: true, concurrentFinalizerRevokeQualified: false };
      markPhase('offline_completed_receipt');
      await stopDaemon(); noStore();
      const completedBytes = `${canonicalJsonBytes({ schemaVersion: 1, operation: completedRevocation }).toString('utf8')}\n`;
      const completedReplayWithoutStore = async () => {
        const replay = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'),
          ['--bootstrap-credential', revokeBytes.toString('base64url')]);
        assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(replay, 'operation')), completedRevocation);
        assert.equal(replay.stdout, completedBytes);
        assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
          credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
        assert.deepEqual(inactive(), report.servicesAfterStoreNegatives); noStore();
      };
      await completedReplayWithoutStore();
      exactRefusal(await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
        canonicalJsonBytes({ schemaVersion: 1, kind: 'cleanup', requestId: revokeMetadata.requestId }).toString('base64url')]),
        'RECOVERY_REQUIRED', 'credential completed receipt fresh sweep did not prove absence or deletion');
      await completedReplayWithoutStore();
      markPhase('completed_receipt_store_restored');
      const finalStore = await startDaemon(); assert.notEqual(finalStore.nameOwner, unlockedAgain.nameOwner);
      assert.equal(finalStore.collection, unlockedAgain.collection); assert.deepEqual(finalStore.items, []);
      const completedFreshSweep = await openInputCommand(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential',
        canonicalJsonBytes({ schemaVersion: 1, kind: 'cleanup', requestId: revokeMetadata.requestId }).toString('base64url')]);
      assert.deepEqual(decodeCredentialAuthorityRevokeOperation(success(completedFreshSweep, 'operation')), completedRevocation);
      assert.equal(completedFreshSweep.stdout, completedBytes);
      assert.deepEqual(decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read',
        credentialGrantId: metadata.credentialGrantId }), 'record')), revokedRecord);
      assert.deepEqual(observe('list').items, []); assert.equal(serviceOwner(), finalStore.nameOwner);
      assert.deepEqual(inactive(), report.servicesAfterStoreNegatives);
      report.offlineCompletedReceipt = { exactOfflineReplayBeforeAndAfterFailedSweep: true, failedFreshSweepRefused: true,
        completedReceiptUnchanged: true, terminalRecordUnchanged: true, restoredFreshSweepExactReplay: true,
        servicesRemainInactive: true, secretInputPipeUnwrittenAndUnended: true };
      markPhase('complete'); report.qualified = true;
    };
    // Dispatch complete campaigns, never return past the shared join/scan.
    await (campaignKind === 'model_input' ? modelInputCampaign() : authorityLifecycleCampaign());
  } catch (error) { primary = error; }
  finally {
    secret.fill(0); rotatedSecret.fill(0); abandonedSecret.fill(0); resubmittedSecret.fill(0); negativeSecret.fill(0); password.fill(0);
    for (const bytes of [...capSecrets, ...invalidModelSecrets]) bytes.fill(0);
    try { await stopDaemon(); }
    catch (error) { primary = new AggregateError([primary, error].filter(Boolean), 'fixture platform daemon retirement failed'); }
    if (!primary) {
      markPhase('secret_corpus');
      try {
        const corpus = await scanCredentialSecretCorpus({ stateRoot: recipe.stateRoot, uid: ledger.uid, evidenceDirs, scanner });
        // Initial enrollment creates both real databases in either mode.
        // Only the lifecycle campaign creates the four actual crash directories.
        assert.equal(corpus.sqliteDatabasesScanned, 2);
        assert.equal(evidenceDirs.length, campaignKind === 'model_input' ? 0 : 4);
        assert.equal(corpus.evidenceDirectoriesScanned, campaignKind === 'model_input' ? 0 : 4);
        report.secretCorpus = corpus; markPhase('complete');
      } catch (error) {
        if (error instanceof CredentialSecretCorpusError && error.databaseFailure)
          report.secretCorpusDatabaseFailure = error.databaseFailure;
        primary = error;
      }
    }
    if (primary) {
      report.qualified = false;
      // Assertion messages and causes may contain compared data. Retain only
      // source-owned frame locations, never their arbitrary message/stack text.
      const sourceFrames: { file: string; line: number; column: number }[] = [], pending = [primary];
      for (let visited = 0; pending.length && visited < 8 && sourceFrames.length < 8; visited++) {
        const error = pending.shift(); if (!(error instanceof Error)) continue;
        for (const match of (error.stack ?? '').matchAll(
          /\b(credential-installed-journey|credential-write-crash|credential-secret-scan|credential-secret-corpus|credential-input-observation)\.ts:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})/gu)) {
          sourceFrames.push({ file: `${match[1]}.ts`, line: Number(match[2]), column: Number(match[3]) });
          if (sourceFrames.length === 8) break;
        }
        if (error instanceof AggregateError && Array.isArray(error.errors)) pending.unshift(...error.errors.slice(0, 4));
      }
      report.error = { diagnosticOnly: true, kind: 'credential_journey_failed', sourceFrames };
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

// The fixed systemd recipe invokes this source through tsx. The basename
// guard also keeps these preparation helpers inert if another driver bundles
// them, where esbuild would otherwise rewrite both import.meta.url values.
if (process.argv[1] && path.basename(process.argv[1]) === 'credential-installed-journey.ts' &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.platform, 'linux', 'installed credential journey requires Linux');
  assert.equal(process.arch, 'x64', 'no installed credential carrier qualified for this architecture');
  const [mode, filename, ...extra] = process.argv.slice(2);
  assert(mode === '--campaign' || mode === '--model-input-campaign'); assert(filename && extra.length === 0);
  await campaign(filename, mode === '--model-input-campaign' ? 'model_input' : 'authority_lifecycle');
}
