// Actual signed installed keeper startup under a disposable real user manager.
// A refusal is RED, never qualification success or containment-death authority.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, stat, statfs, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import type { ReleaseTrustKey } from '../../src/policy/runtime-authority.js';
import { createInstalledRuntime } from '../../src/state/installed-runtime.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

type InstalledFixture = {
  buildFixture: string; packageRoot: string; stateRoot: string; releaseKeysFile: string;
  preloadLibrary: string; preloadMarker: string;
  keeperUnit: string; supervisorUnit: string; keeperUnitFile: string; supervisorUnitFile: string; reportFile: string;
};
type Ledger = {
  diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string; installed: InstalledFixture;
};
const repository = fileURLToPath(new URL('../..', import.meta.url));
const self = fileURLToPath(import.meta.url);
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
// Known loading inputs for the fixed glibc 2.35 / Node 24.21 carrier and its
// OpenSSL. Matching unit text is not hostile-manager qualification; actual
// injection with positive controls remains required.
const loaderVariables = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG', 'LD_DEBUG_OUTPUT',
  'LD_PROFILE', 'LD_PROFILE_OUTPUT', 'LD_ORIGIN_PATH', 'LD_TRACE_LOADED_OBJECTS', 'LD_TRACE_PRELINKING',
  'LD_WARN', 'LD_VERBOSE', 'LD_BIND_NOW', 'LD_BIND_NOT', 'LD_DYNAMIC_WEAK', 'LD_HWCAP_MASK',
  'LD_SHOW_AUXV', 'LD_USE_LOAD_BIAS', 'LD_ASSUME_KERNEL', 'GCONV_PATH', 'LOCPATH', 'GLIBC_TUNABLES',
  'NODE_COMPILE_CACHE', 'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_ICU_DATA',
  'NODE_REDIRECT_WARNINGS', 'NODE_REPL_EXTERNAL_MODULE', 'NODE_V8_COVERAGE', 'OPENSSL_CONF',
  'OPENSSL_CONF_INCLUDE', 'OPENSSL_MODULES', 'OPENSSL_ENGINES', 'SSL_CERT_DIR', 'SSL_CERT_FILE'];
const propertyNames = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ExecMainPID', 'ControlGroup',
  'InvocationID', 'Result', 'ExecMainCode', 'ExecMainStatus', 'FragmentPath', 'Type', 'Delegate', 'KillMode', 'Restart'];

function command(executable: string, args: string[], milliseconds = 30_000) {
  const result = spawnSync(executable, args, { cwd: repository, env: environment,
    encoding: 'utf8', timeout: milliseconds, maxBuffer: 256 * 1024 });
  assert.equal(result.error, undefined, `${executable}: ${result.error}`);
  assert.equal(result.signal, null, `${executable}: ${result.signal}`);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

async function readLedger(filename: string): Promise<Ledger> {
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let ledger: Ledger;
  try {
    const metadata = await file.stat();
    assert(metadata.isFile()); assert.equal(metadata.uid, 0); assert.equal(metadata.nlink, 1);
    assert.equal(metadata.mode & 0o7777, 0o444); assert(metadata.size <= 64 * 1024);
    ledger = parseJsonStrict(await file.readFile('utf8')) as Ledger;
  } finally { await file.close(); }
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
  const installed = ledger.installed;
  assert(installed && typeof installed === 'object');
  const keeperUnit = `cliq-probe-${suffix}-installed-keeper.service`;
  const supervisorUnit = `cliq-probe-${suffix}-installed-supervisor.service`;
  assert.deepEqual(Object.keys(installed).sort(), ['buildFixture', 'keeperUnit', 'keeperUnitFile', 'packageRoot',
    'preloadLibrary', 'preloadMarker', 'releaseKeysFile', 'reportFile', 'stateRoot', 'supervisorUnit', 'supervisorUnitFile'].sort());
  assert.equal(installed.buildFixture, path.join(ledger.fixture, 'installed-package-build'));
  assert.equal(installed.packageRoot, path.join(installed.buildFixture, 'package'));
  assert.equal(installed.preloadLibrary, path.join(installed.buildFixture, 'installed-loader-preload.so'));
  assert.equal(installed.preloadMarker, path.join(ledger.home, 'probe/installed-loader-preload.marker'));
  assert.equal(installed.stateRoot, path.join(ledger.home, 'probe/installed-state'));
  assert.equal(installed.releaseKeysFile, path.join(ledger.fixture, 'installed-release-keys.json'));
  assert.equal(installed.keeperUnit, keeperUnit); assert.equal(installed.supervisorUnit, supervisorUnit);
  assert.equal(installed.keeperUnitFile, path.join(ledger.home, '.config/systemd/user', keeperUnit));
  assert.equal(installed.supervisorUnitFile, path.join(ledger.home, '.config/systemd/user', supervisorUnit));
  assert(path.isAbsolute(installed.reportFile) && path.basename(installed.reportFile) === 'report.json');
  const output = await lstat(path.dirname(installed.reportFile));
  assert(output.isDirectory() && !output.isSymbolicLink()); assert.equal(output.uid, 0);
  assert.equal(output.mode & 0o7777, 0o755);
  return ledger;
}

// Transfer only this fresh root-created package, post-order through exact
// no-follow descriptors. Never chown its root-owned stage, the checkout, a
// carrier tree, manager ancestors or the independently installed StateRoot.
async function transferPackage(filename: string, uid: number, gid: number): Promise<void> {
  const metadata = await lstat(filename);
  assert(!metadata.isSymbolicLink() && (metadata.isDirectory() || metadata.isFile()));
  assert.equal(metadata.uid, 0); assert.equal(metadata.gid, 0);
  if (metadata.isDirectory()) {
    assert.equal(metadata.mode & 0o7777, 0o700);
    for (const name of await readdir(filename)) await transferPackage(path.join(filename, name), uid, gid);
  } else {
    assert.equal(metadata.nlink, 1); assert([0o400, 0o500].includes(metadata.mode & 0o7777));
  }
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW |
    (metadata.isDirectory() ? constants.O_DIRECTORY : 0));
  try {
    const actual = await held.stat();
    assert.equal(actual.dev, metadata.dev); assert.equal(actual.ino, metadata.ino);
    assert.equal(actual.uid, 0); assert.equal(actual.gid, 0);
    await held.chown(uid, gid);
  } finally { await held.close(); }
}

async function authorityAbsent(stateRoot: string) {
  const facts: Record<string, boolean> = {};
  for (const relative of [KERNEL_DATABASE_FILENAME, `${KERNEL_DATABASE_FILENAME}-wal`, `${KERNEL_DATABASE_FILENAME}-shm`,
    'runtime/state-owner.lock', 'runtime/control-v1.sock']) {
    facts[relative] = await lstat(path.join(stateRoot, relative)).then(() => false, (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return true;
      throw error;
    });
  }
  return facts;
}

async function preloadMarkerAbsent(filename: string): Promise<boolean> {
  return lstat(filename).then(() => false, (error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return true;
    throw error;
  });
}

async function positivePreloadControl(ledger: Ledger) {
  const { installed } = ledger;
  // The checksum-verified, unmodified carrier produced by the shared recipe,
  // not the runner's Node 22 client or a different ELF/Node implementation.
  const ordinaryNode = path.join(installed.buildFixture, `node-v${SUPERVISOR_SEA_NODE_VERSION}-linux-x64/bin/node`);
  const carrier = await lstat(ordinaryNode);
  assert(carrier.isFile() && !carrier.isSymbolicLink());
  // The official tar retains iojs (1001) ownership under root extraction. The
  // disposable UID must not own it; do not chown or alter the carrier tree.
  assert.notEqual(carrier.uid, ledger.uid); assert.notEqual(carrier.gid, ledger.gid);
  assert.equal(carrier.mode & 0o7777, 0o755); assert.equal(carrier.nlink, 1);
  const directory = await lstat(path.dirname(installed.preloadMarker));
  assert(directory.isDirectory() && !directory.isSymbolicLink());
  assert.equal(directory.uid, ledger.uid); assert.equal(directory.gid, ledger.gid);
  assert.equal(directory.mode & 0o7777, 0o700);
  assert(await preloadMarkerAbsent(installed.preloadMarker), 'never adopt an existing preload marker');
  const source = fileURLToPath(new URL('./testing/installed-loader-preload.c', import.meta.url));
  const sourceMetadata = await lstat(source);
  assert(sourceMetadata.isFile() && !sourceMetadata.isSymbolicLink());
  assert(await preloadMarkerAbsent(installed.preloadLibrary), 'never replace an existing preload library');
  const compilation = command('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
    `-DCLIQ_INSTALLED_PRELOAD_MARKER=${JSON.stringify(installed.preloadMarker)}`, source, '-o', installed.preloadLibrary]);
  assert.equal(compilation.status, 0, compilation.stderr);
  const library = await open(installed.preloadLibrary, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = await library.stat();
    assert(metadata.isFile()); assert.equal(metadata.uid, 0); assert.equal(metadata.gid, 0); assert.equal(metadata.nlink, 1);
    await library.chmod(0o555);
    assert.equal((await library.stat()).mode & 0o7777, 0o555);
  } finally { await library.close(); }
  // env execs the actual ordinary Node in place, preserving spawn's observed
  // PID. Only that nonroot child receives LD_PRELOAD, not env or runuser/root.
  const child = spawnSync('/usr/bin/env', ['-i', `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
    `LD_PRELOAD=${installed.preloadLibrary}`, ordinaryNode, '--input-type=module', '-e',
    'console.log(JSON.stringify({pid:process.pid,uid:process.getuid(),euid:process.geteuid(),gid:process.getgid(),egid:process.getegid(),nodeVersion:process.version}));'],
  { uid: ledger.uid, gid: ledger.gid, cwd: ledger.home, env: environment, encoding: 'utf8', timeout: 30_000, maxBuffer: 4096 });
  assert.equal(child.error, undefined, `ordinary Node: ${child.error}`);
  assert.equal(child.signal, null); assert.equal(child.status, 0, child.stderr); assert.equal(child.stderr, '');
  assert(Number.isSafeInteger(child.pid) && child.pid > 0);
  const actual = parseJsonStrict(child.stdout.trim());
  assert(actual !== null && typeof actual === 'object' && !Array.isArray(actual));
  // The strict parser deliberately returns null-prototype records. Compare
  // their exact own data, not that defensive representation's prototype.
  assert.deepEqual({ ...actual }, { pid: child.pid, uid: ledger.uid, euid: ledger.uid, gid: ledger.gid, egid: ledger.gid,
    nodeVersion: `v${SUPERVISOR_SEA_NODE_VERSION}` });
  const expected = `cliq-installed-loader-preload-v1\npid=${child.pid}\nuid=${ledger.uid}\n`;
  const marker = await open(installed.preloadMarker, constants.O_RDONLY | constants.O_NOFOLLOW);
  let identity: { device: string; inode: string };
  try {
    const metadata = await marker.stat({ bigint: true });
    assert(metadata.isFile()); assert.equal(metadata.uid, BigInt(ledger.uid)); assert.equal(metadata.gid, BigInt(ledger.gid));
    assert.equal(metadata.mode & 0o7777n, 0o600n); assert.equal(metadata.nlink, 1n);
    assert.equal(metadata.size, BigInt(Buffer.byteLength(expected)));
    assert.equal(await marker.readFile('utf8'), expected);
    // The child has joined. Recheck the held file and exact named inode before
    // deleting this one validated marker; leave any changed identity for cleanup.
    for (const observed of [await marker.stat({ bigint: true }), await lstat(installed.preloadMarker, { bigint: true })]) {
      for (const key of ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const) assert.equal(observed[key], metadata[key]);
    }
    identity = { device: metadata.dev.toString(), inode: metadata.ino.toString() };
    await unlink(installed.preloadMarker);
  } finally { await marker.close(); }
  assert(await preloadMarkerAbsent(installed.preloadMarker));
  return { ordinaryNode, nodeVersion: `v${SUPERVISOR_SEA_NODE_VERSION}`, pid: child.pid, uid: ledger.uid,
    markerContent: expected, markerIdentity: identity, joined: true, markerRemoved: true };
}

async function installer(packageRoot: string, stateRoot: string, releaseKeysFile: string): Promise<void> {
  assert(process.geteuid!() > 0 && process.getegid!() > 0, 'installer must run as the disposable nonroot UID');
  assert(path.isAbsolute(packageRoot) && path.isAbsolute(stateRoot) && path.isAbsolute(releaseKeysFile));
  const releaseKeys = parseJsonStrict(await readFile(releaseKeysFile, 'utf8')) as ReleaseTrustKey[];
  const selected = await createInstalledRuntime({ releaseKeys }).installInitial({ packageRoot, stateRoot });
  assert(Object.values(await authorityAbsent(stateRoot)).every(Boolean), 'installation cannot acquire StateOwner');
  console.log(JSON.stringify({ bundleDigest: selected.bundleDigest }));
}

async function campaign(ledgerFile: string): Promise<void> {
  assert.equal(process.geteuid!(), 0, 'only the frozen-ledger root orchestrator may stage this fixture');
  const ledger = await readLedger(ledgerFile), installed = ledger.installed;
  const report: Record<string, unknown> = { diagnosticOnly: true, qualified: false,
    scope: 'actual signed installed keeper startup only; not Supervisor restart, Run, worker, admission or complete I1',
    embeddedNodeVersion: SUPERVISOR_SEA_NODE_VERSION, uid: ledger.uid, keeperUnit: installed.keeperUnit };
  const userCommand = (args: string[]) => command('/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
    `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`, '/usr/bin/systemctl', '--user', ...args]);
  const show = () => {
    const result = userCommand(['show', installed.keeperUnit, `--property=${propertyNames.join(',')}`, '--no-pager']);
    assert.equal(result.status, 0, result.stderr);
    const values: Record<string, string> = {};
    for (const line of result.stdout.trim().split('\n')) {
      const separator = line.indexOf('='); assert(separator > 0, 'invalid systemd property');
      const key = line.slice(0, separator); assert(!Object.hasOwn(values, key), 'duplicate systemd property');
      values[key] = line.slice(separator + 1);
    }
    for (const name of propertyNames) assert(Object.hasOwn(values, name), `systemd omitted ${name}`);
    return values;
  };
  const journal = (invocationId: string) => {
    if (!/^[a-f0-9]{32}$/u.test(invocationId)) return [];
    const result = command('/usr/bin/journalctl', ['--no-pager', '--all', '--output=json', '--lines=80',
      `_UID=${ledger.uid}`, `_SYSTEMD_INVOCATION_ID=${invocationId}`]);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim().split('\n').filter(Boolean).map(line => parseJsonStrict(line) as Record<string, unknown>);
  };
  let shown: Record<string, string> | undefined;
  let preloadEnvironmentTouched = false, managerPreloadConfirmed = false, keeperStartAttempted = false, keeperImageObserved = false;
  try {
    await mkdir(installed.buildFixture, { mode: 0o755 }); // Exclusive: never adopt a build/package tree.
    const stage = await lstat(installed.buildFixture);
    assert(stage.isDirectory() && !stage.isSymbolicLink()); assert.equal(stage.uid, 0); assert.equal(stage.gid, 0);
    assert.equal(stage.mode & 0o7777, 0o755);
    const { packageRoot, releaseKeys, bundle, contents } = await buildInstalledSupervisorPackage(installed.buildFixture);
    assert.equal(packageRoot, installed.packageRoot);
    report.preloadPositiveControl = await positivePreloadControl(ledger);
    await writeFile(installed.releaseKeysFile, canonicalJsonBytes(releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(packageRoot, ledger.uid, ledger.gid);
    const install = command('/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
      `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', process.execPath,
      '--import', import.meta.resolve('tsx'), self, '--install', packageRoot, installed.stateRoot, installed.releaseKeysFile]);
    report.installation = install;
    assert.equal(install.status, 0, install.stderr);
    const selection = parseJsonStrict(install.stdout.trim()) as { bundleDigest: string };
    assert.equal(selection.bundleDigest, canonicalSha256(bundle));
    report.bundleDigest = selection.bundleDigest; report.manifestDigest = bundle.manifestDigest;
    const expectedImage = path.join(installed.stateRoot, 'runtime/bundles', selection.bundleDigest, 'supervisor');
    const image = contents.find(entry => entry.role === 'supervisor')!;
    const imageDigest = createHash('sha256').update(image.bytes).digest('hex');
    report.expectedImage = { path: expectedImage, digest: imageDigest };
    const state = await lstat(installed.stateRoot);
    assert.equal(state.uid, ledger.uid); assert.equal(state.mode & 0o7777, 0o700);
    const before = await authorityAbsent(installed.stateRoot);
    report.authorityBeforeKeeper = before;
    assert(Object.values(before).every(Boolean));
    for (const [unit, filename, role] of [[installed.keeperUnit, installed.keeperUnitFile, 'keeper'],
      [installed.supervisorUnit, installed.supervisorUnitFile, 'supervisor']] as const) {
      const metadata = await lstat(filename);
      assert(metadata.isFile() && !metadata.isSymbolicLink()); assert.equal(metadata.uid, 0);
      assert.equal(metadata.mode & 0o7777, 0o444); assert.equal(metadata.nlink, 1);
      const definition = await readFile(filename, 'utf8');
      assert(definition.includes(`ExecStart=${installed.stateRoot}/runtime/bootstrap --bootstrap-${role}\n`));
      assert(definition.includes(`UnsetEnvironment=${loaderVariables.join(' ')}\n`));
      assert(definition.includes('Type=exec\n') && definition.includes('Delegate=cpu memory pids\n') && definition.includes('Restart=no\n'));
      assert(!definition.includes('PartOf=') && !definition.includes('BindsTo='));
      if (unit === installed.supervisorUnit) assert(definition.includes(`Requires=${installed.keeperUnit}\nAfter=${installed.keeperUnit}\n`));
    }
    const reload = userCommand(['daemon-reload']); assert.equal(reload.status, 0, reload.stderr);
    const beforeEnvironment = userCommand(['show-environment']);
    assert.equal(beforeEnvironment.status, 0, beforeEnvironment.stderr);
    assert(!beforeEnvironment.stdout.split('\n').some(line => line.startsWith('LD_PRELOAD=')), 'fresh manager already has LD_PRELOAD');
    // Set the cleanup flag before the mutating command: a timeout may follow
    // a committed environment change. Never mutate the original runner manager.
    preloadEnvironmentTouched = true;
    const setEnvironment = userCommand(['set-environment', `LD_PRELOAD=${installed.preloadLibrary}`]);
    assert.equal(setEnvironment.status, 0, setEnvironment.stderr);
    const injectedEnvironment = userCommand(['show-environment']);
    assert.equal(injectedEnvironment.status, 0, injectedEnvironment.stderr);
    assert.deepEqual(injectedEnvironment.stdout.split('\n').filter(line => line.startsWith('LD_PRELOAD=')),
      [`LD_PRELOAD=${installed.preloadLibrary}`]);
    managerPreloadConfirmed = true;
    report.managerPreload = { library: installed.preloadLibrary, confirmed: true };
    keeperStartAttempted = true;
    report.startCommand = userCommand(['start', installed.keeperUnit]);
    const deadline = Date.now() + 30_000;
    for (;;) {
      shown = show(); report.unit = shown;
      assert.equal(shown.FragmentPath, installed.keeperUnitFile);
      assert.equal(shown.LoadState, 'loaded'); assert.equal(shown.Type, 'exec');
      assert.equal(shown.Delegate, 'yes'); assert.equal(shown.KillMode, 'control-group'); assert.equal(shown.Restart, 'no');
      assert.match(shown.InvocationID!, /^[a-f0-9]{32}$/u, 'keeper must have a real systemd invocation');
      if (shown.ActiveState === 'failed' || shown.ActiveState === 'inactive') {
        let records = journal(shown.InvocationID);
        for (let attempt = 0; attempt < 20 && !records.some(record => typeof record.MESSAGE === 'string' && record.MESSAGE.includes('expected a fixed installed Supervisor role')); attempt++) {
          await delay(50); records = journal(shown.InvocationID);
        }
        report.journal = records;
        const closedRoleError = records.flatMap(record => {
          if (typeof record.MESSAGE !== 'string') return [];
          try { return [parseJsonStrict(record.MESSAGE)]; } catch { return []; }
        }).find(value => value !== null && typeof value === 'object' &&
          (value as { message?: string }).message === 'expected a fixed installed Supervisor role');
        report.startupRefusal = { invocationId: shown.InvocationID, result: shown.Result,
          execMainCode: shown.ExecMainCode, execMainStatus: shown.ExecMainStatus, closedRoleError: closedRoleError ?? null };
        keeperImageObserved = Boolean(closedRoleError) && Number(shown.ExecMainPID) > 0;
        throw new Error(`installed keeper exited before actual delegated readiness: ${JSON.stringify(report.startupRefusal)}`);
      }
      const pid = Number(shown.MainPID);
      if (shown.ActiveState === 'active' && Number.isSafeInteger(pid) && pid > 0) {
        const actualImage = await readlink(`/proc/${pid}/exe`).catch((error: NodeJS.ErrnoException) => {
          if (error.code === 'ENOENT' || error.code === 'ESRCH') return undefined; throw error;
        });
        if (actualImage === expectedImage) {
          const memberships = (await readFile(`/proc/${pid}/cgroup`, 'utf8')).trim().split('\n').filter(line => line.startsWith('0::'));
          assert.equal(memberships.length, 1);
          assert(shown.ControlGroup.startsWith('/') && !shown.ControlGroup.split('/').includes('..'));
          const root = `/sys/fs/cgroup${shown.ControlGroup}`, keeper = path.join(root, 'keeper');
          if (memberships[0] === `0::${shown.ControlGroup}/keeper`) {
            const selected = await lstat(expectedImage, { bigint: true });
            const actual = await stat(`/proc/${pid}/exe`, { bigint: true });
            for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const) assert.equal(actual[key], selected[key]);
            assert.equal(createHash('sha256').update(await readFile(`/proc/${pid}/exe`)).digest('hex'), imageDigest);
            const procStatus = await readFile(`/proc/${pid}/status`, 'utf8');
            for (const [name, id] of [['Uid', ledger.uid], ['Gid', ledger.gid]] as const) {
              const fields = procStatus.match(new RegExp(`^${name}:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)$`, 'm'));
              assert(fields); assert(fields.slice(1).every(value => Number(value) === id));
            }
            const procStat = await readFile(`/proc/${pid}/stat`, 'utf8');
            const fields = procStat.slice(procStat.lastIndexOf(')') + 2).trim().split(/\s+/u);
            assert.notEqual(fields[0], 'Z'); assert.match(fields[19]!, /^[0-9]+$/u);
            const roots: Array<{ path: string; device: string; inode: string }> = [];
            for (const directory of [root, keeper]) {
              const metadata = await lstat(directory, { bigint: true });
              assert(metadata.isDirectory() && !metadata.isSymbolicLink()); assert.equal(metadata.uid, BigInt(ledger.uid));
              assert.equal(metadata.gid, BigInt(ledger.gid)); assert.equal(metadata.mode & 0o7777n, 0o700n);
              assert.equal(Number((await statfs(directory)).type), 0x63677270);
              roots.push({ path: directory, device: metadata.dev.toString(), inode: metadata.ino.toString() });
            }
            assert.equal((await readFile(path.join(root, 'cgroup.procs'), 'utf8')).trim(), '');
            assert.equal((await readFile(path.join(keeper, 'cgroup.procs'), 'utf8')).trim(), `${pid}`);
            assert.equal((await readFile(path.join(root, 'cgroup.type'), 'utf8')).trim(), 'domain');
            const enabled = (await readFile(path.join(root, 'cgroup.subtree_control'), 'utf8')).trim().split(/\s+/u);
            for (const controller of ['cpu', 'memory', 'pids']) assert(enabled.includes(controller));
            assert.deepEqual((await readdir(root, { withFileTypes: true })).filter(entry => entry.isDirectory()).map(entry => entry.name), ['keeper']);
            const confirmed = show(); assert.equal(confirmed.InvocationID, shown.InvocationID); assert.equal(confirmed.MainPID, shown.MainPID);
            keeperImageObserved = true;
            report.qualified = true; report.result = { pid, processStartToken: `linux-proc-start-ticks:${fields[19]}`,
              actualImage, roots, enabled, invocationId: shown.InvocationID };
            break;
          }
        }
      }
      assert(Date.now() < deadline, 'installed keeper did not initialize its actual delegated root');
      await delay(20);
    }
  } catch (error) {
    report.error = String((error as Error).stack ?? error).slice(0, 16_384);
    throw error;
  } finally {
    let observationError: unknown;
    // Observe protection independently even when the actual keeper is RED.
    // Qualification also needs real image startup, not merely a start attempt
    // that could fail before exec; it never upgrades a keeper refusal to GREEN.
    try {
      const markerAbsent = await preloadMarkerAbsent(installed.preloadMarker);
      report.protectedPreload = { marker: installed.preloadMarker, markerAbsent, keeperStartAttempted,
        managerPreloadConfirmed, keeperImageObserved,
        verified: Boolean(report.preloadPositiveControl) && managerPreloadConfirmed && keeperImageObserved && markerAbsent };
      // A failed positive control may leave its own marker. Do not replace
      // that failure with a claim about a keeper that was never started.
      if (report.preloadPositiveControl && managerPreloadConfirmed && keeperStartAttempted)
        assert(markerAbsent, 'signed keeper initial ELF executed the injected preload library');
      if (report.qualified) assert(managerPreloadConfirmed && keeperImageObserved && report.preloadPositiveControl,
        'keeper qualification needs the actual loader positive control and manager injection');
    } catch (error) {
      observationError = error; report.qualified = false;
      report.preloadObservationError = String((error as Error).stack ?? error).slice(0, 8192);
    }
    if (preloadEnvironmentTouched) {
      try {
        const unset = userCommand(['unset-environment', 'LD_PRELOAD']);
        report.preloadEnvironmentCleanup = unset; assert.equal(unset.status, 0, unset.stderr);
        const cleared = userCommand(['show-environment']); assert.equal(cleared.status, 0, cleared.stderr);
        assert(!cleared.stdout.split('\n').some(line => line.startsWith('LD_PRELOAD=')), 'fresh manager retained LD_PRELOAD');
        report.preloadEnvironmentCleared = true;
      } catch (error) {
        observationError ??= error; report.qualified = false;
        report.preloadEnvironmentCleanupError = String((error as Error).stack ?? error).slice(0, 8192);
      }
    }
    if (shown && !report.journal) {
      try { report.journal = journal(shown.InvocationID); }
      catch (error) {
        observationError ??= error; report.qualified = false;
        report.journalError = String((error as Error).stack ?? error).slice(0, 8192);
      }
    }
    let after: Record<string, boolean> | undefined;
    try {
      after = await authorityAbsent(installed.stateRoot);
      report.authorityAfterKeeper = after;
      if (!Object.values(after).every(Boolean)) { report.qualified = false; report.authorityViolation = true; }
    } catch (error) {
      observationError ??= error; report.qualified = false;
      report.authorityObservationError = String((error as Error).stack ?? error).slice(0, 8192);
    }
    await writeFile(installed.reportFile, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
    console.log(`Actual installed keeper report: ${installed.reportFile}`);
    if (observationError) throw observationError;
    assert(after && Object.values(after).every(Boolean), 'keeper must not acquire database/StateOwner/control authority');
  }
}

assert.equal(process.platform, 'linux', 'installed keeper qualification requires a real Linux runner');
assert.equal(process.arch, 'x64', 'no installed keeper carrier qualified for this architecture');
const [mode, ...args] = process.argv.slice(2);
if (mode === '--install' && args.length === 3) await installer(args[0]!, args[1]!, args[2]!);
else if (mode === '--campaign' && args.length === 1) await campaign(args[0]!);
else throw new Error('expected the closed --campaign LEDGER or --install PACKAGE STATE_ROOT RELEASE_KEYS mode');
