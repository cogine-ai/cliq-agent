// Actual platform prerequisite only. No credential record, binding or Run authority.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chown, lstat, mkdir, open, readFile, readlink, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { parseJsonStrict } from '../../src/kernel/json.js';

type Ledger = {
  diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string;
  secretService: { helper: string; controlDirectory: string; generation: string; reportFile: string };
};
type Observation = {
  clientPid: number; busUniqueName: string; collection: string; item: string;
  nameOwner: string; serviceUid: number; servicePid: number;
  create: boolean; readback: boolean; deleted: boolean; absent: boolean; connectionClosed: boolean;
};
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;

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
  const recipe = ledger.secretService;
  assert.deepEqual(Object.keys(recipe).sort(), ['controlDirectory', 'generation', 'helper', 'reportFile']);
  assert.equal(recipe.helper, path.join(ledger.fixture, 'cliq-secret-service-probe'));
  assert.equal(recipe.controlDirectory, path.join(ledger.home, 'probe/secret-service-control'));
  assert.match(recipe.generation, /^[0-9a-f]{64}$/u);
  assert(path.isAbsolute(recipe.reportFile) && path.basename(recipe.reportFile) === 'secret-service.json');
  const output = await lstat(path.dirname(recipe.reportFile));
  assert(output.isDirectory() && !output.isSymbolicLink()); assert.equal(output.uid, 0);
  assert.equal(output.mode & 0o7777, 0o755);
  return ledger;
}

async function campaign(filename: string): Promise<void> {
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.secretService;
  const report: Record<string, unknown> = { diagnosticOnly: true, qualified: false,
    scope: 'actual same-principal default Secret Service collection and independent-process roundtrip only; not credential authority, TLS, model or I1',
    uid: ledger.uid, generation: recipe.generation };
  const userArguments = ['/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
    `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C']] as const;
  const command = (executable: string, args: string[], input?: Buffer) => {
    const result = spawnSync(userArguments[0], [...userArguments[1], executable, ...args],
      { env: environment, encoding: 'utf8', timeout: 30_000, maxBuffer: 65536, input });
    // Secret-bearing input must never become a command argument or diagnostic.
    assert.equal(result.error, undefined, 'actual platform client did not join');
    return { status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr };
  };
  const busOwner = () => command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`,
    'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.secrets']);
  const secret = randomBytes(32), password = Buffer.from(randomBytes(32).toString('hex'));
  let daemon: ReturnType<typeof spawn> | undefined;
  let daemonExit: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
  let joined = false, primary: unknown;
  let lifetime: { pid: number; startTicks: string } | undefined;
  const joinDaemon = async () => {
    assert(daemonExit);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([daemonExit, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('actual Secret Service daemon did not join')), 10000);
      })]);
      report.daemonExit = result; joined = true;
    } finally { clearTimeout(timer); }
  };
  const processCut = async (pid: number) => {
    const raw = await readFile(`/proc/${pid}/stat`, 'utf8');
    assert(raw.startsWith(`${pid} (`));
    const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
    assert(!['Z', 'X', 'x'].includes(fields[0]!)); assert.match(fields[19]!, /^(0|[1-9][0-9]*)$/u);
    const credentials = await readFile(`/proc/${pid}/status`, 'utf8');
    for (const [kind, expected] of [['Uid', ledger.uid], ['Gid', ledger.gid]] as const) {
      const match = credentials.match(new RegExp(`^${kind}:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)$`, 'mu'));
      assert(match); assert(match.slice(1).every(value => Number(value) === expected));
    }
    assert.equal(await readlink(`/proc/${pid}/exe`), '/usr/bin/gnome-keyring-daemon');
    const actual = await stat(`/proc/${pid}/exe`, { bigint: true });
    const named = await lstat('/usr/bin/gnome-keyring-daemon', { bigint: true });
    assert(named.isFile() && !named.isSymbolicLink()); assert.equal(named.uid, 0n);
    for (const key of imageFields) assert.equal(actual[key], named[key]);
    return { pid, startTicks: fields[19]! };
  };
  try {
    const helper = await lstat(recipe.helper);
    assert(helper.isFile() && !helper.isSymbolicLink()); assert.equal(helper.uid, 0);
    assert.equal(helper.nlink, 1); assert.equal(helper.mode & 0o7777, 0o555);
    const absent = busOwner(); assert.notEqual(absent.status, 0, 'fresh fixture must not adopt an existing Secret Service');
    await mkdir(recipe.controlDirectory, { mode: 0o700 });
    await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
    daemon = spawn(userArguments[0], [...userArguments[1], `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`,
      `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`, '/usr/bin/gnome-keyring-daemon',
      '--foreground', '--components=secrets', '--unlock', `--control-directory=${recipe.controlDirectory}`],
    { env: environment, stdio: ['pipe', 'ignore', 'ignore'] });
    daemonExit = new Promise(resolve => daemon!.once('close', (code, signal) => resolve({ code, signal })));
    daemon.on('error', () => { report.daemonSpawnFailed = true; });
    daemon.stdin!.on('error', () => { report.passwordPipeFailed = true; });
    daemon.stdin!.end(password);
    const deadline = Date.now() + 10000;
    let owner: ReturnType<typeof busOwner>;
    for (;;) {
      owner = busOwner();
      if (owner.status === 0) break;
      assert.equal(daemon.exitCode, null, 'actual platform daemon exited before owning its name');
      assert(Date.now() < deadline, 'actual platform daemon did not acquire its name'); await delay(20);
    }
    assert.match(owner.stdout.trim(), /^s ":\d+\.\d+"$/u);
    report.ownerBefore = owner.stdout.trim();
    const invoke = (mode: 'create' | 'consume', item?: string) => {
      const result = command(recipe.helper, [mode, recipe.generation, ...(item === undefined ? [] : [item])], secret);
      report[`${mode}Client`] = result;
      assert.equal(result.status, 0, 'real same-principal Secret Service client refused its roundtrip');
      const observation = parseJsonStrict(result.stdout.trim()) as Observation;
      assert.equal(observation.serviceUid, ledger.uid);
      for (const pid of [observation.clientPid, observation.servicePid]) assert(Number.isSafeInteger(pid) && pid > 0);
      assert.match(observation.busUniqueName, /^:\d+\.\d+$/u); assert.match(observation.nameOwner, /^:\d+\.\d+$/u);
      assert.equal(`s "${observation.nameOwner}"`, owner.stdout.trim());
      assert.match(observation.collection, /^\/org\/freedesktop\/secrets\/collection\/[A-Za-z0-9_]+$/u);
      assert.notEqual(observation.collection, '/org/freedesktop/secrets/collection/session');
      assert.match(observation.item, new RegExp(`^${observation.collection}/[A-Za-z0-9_]+$`, 'u'));
      assert.equal(observation.connectionClosed, true); assert.equal(observation.readback, true);
      assert.equal(observation.create, mode === 'create'); assert.equal(observation.deleted, mode === 'consume');
      assert.equal(observation.absent, mode === 'consume');
      return observation;
    };
    const created = invoke('create'); report.created = created;
    lifetime = await processCut(created.servicePid); report.daemon = lifetime;
    const consumed = invoke('consume', created.item); report.consumed = consumed;
    for (const key of ['collection', 'item', 'nameOwner', 'serviceUid', 'servicePid'] as const) assert.equal(consumed[key], created[key]);
    assert.notEqual(consumed.busUniqueName, created.busUniqueName, 'a second process must use its own actual D-Bus connection');
    assert.deepEqual(await processCut(created.servicePid), lifetime);
    report.roundtripQualified = true;
  } catch (error) { primary = error; }
  finally {
    secret.fill(0); password.fill(0);
    if (daemon && daemonExit) {
      try {
        if (daemon.exitCode === null && daemon.signalCode === null) daemon.kill('SIGTERM');
        await joinDaemon();
        if (lifetime) {
          const after = await readFile(`/proc/${lifetime.pid}/stat`, 'utf8').catch((error: NodeJS.ErrnoException) => {
            if (error.code === 'ENOENT' || error.code === 'ESRCH') return undefined; throw error;
          });
          if (after !== undefined) {
            assert(after.startsWith(`${lifetime.pid} (`));
            const fields = after.slice(after.lastIndexOf(')') + 2).trim().split(/\s+/u);
            assert.notEqual(fields[19], lifetime.startTicks);
          }
          report.daemonLifetimeGone = true;
        }
        const gone = busOwner(); assert.notEqual(gone.status, 0, 'stopped platform service still owns its bus name');
        report.serviceNameAbsent = true;
      } catch (error) { primary = new AggregateError([primary, error].filter(Boolean), 'platform prerequisite cleanup did not join'); }
    }
    report.daemonJoined = joined;
    report.qualified = primary === undefined && report.roundtripQualified === true && joined;
    if (primary) report.error = String((primary as Error).stack ?? primary).slice(0, 8192);
    await writeFile(recipe.reportFile, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  }
  if (primary) throw primary;
}

assert.equal(process.platform, 'linux', 'actual Secret Service qualification requires Linux');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--campaign'); assert(filename && extra.length === 0);
await campaign(filename);
