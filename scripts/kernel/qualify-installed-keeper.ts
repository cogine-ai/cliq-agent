// Actual signed installed keeper startup/source publication under a real user manager.
// A refusal is RED, never qualification success or containment-death authority.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, readlink, stat, statfs, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { qualifyInstalledAnchorSource } from './testing/installed-anchor-source.js';
import { qualifyInstalledAnchorConsumer } from './testing/installed-anchor-consumer.js';
import { qualifyInstalledGenesis } from './testing/installed-genesis.js';
import { qualifyInstalledInspectorSignal, type InstalledInspectorSignalReport } from './testing/installed-inspector-signal.js';
import { assertInstalledReadExchanges, inspectInstalledOwner, installedReadClientScript } from './testing/installed-read-control.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { SUPERVISOR_SEA_NODE_VERSION } from './testing/supervisor-sea-builder.js';

type InstalledFixture = {
  buildFixture: string; packageRoot: string; stateRoot: string; releaseKeysFile: string;
  preloadLibrary: string; preloadMarker: string; installerEntry: string;
  keeperUnit: string; supervisorUnit: string; keeperUnitFile: string; supervisorUnitFile: string; reportFile: string;
};
type Ledger = {
  diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string; installed: InstalledFixture;
};
const repository = fileURLToPath(new URL('../..', import.meta.url));
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
  assert.deepEqual(Object.keys(installed).sort(), ['buildFixture', 'installerEntry', 'keeperUnit', 'keeperUnitFile', 'packageRoot',
    'preloadLibrary', 'preloadMarker', 'releaseKeysFile', 'reportFile', 'stateRoot', 'supervisorUnit', 'supervisorUnitFile'].sort());
  assert.equal(installed.buildFixture, path.join(ledger.fixture, 'installed-package-build'));
  assert.equal(installed.packageRoot, path.join(installed.buildFixture, 'package'));
  assert.equal(installed.preloadLibrary, path.join(installed.buildFixture, 'installed-loader-preload.so'));
  assert.equal(installed.preloadMarker, path.join(ledger.home, 'probe/installed-loader-preload.marker'));
  assert.equal(installed.installerEntry, path.join(installed.buildFixture, 'installed-runtime-installer.mjs'));
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

async function stageInstaller(installed: InstalledFixture) {
  // The disposable UID never needs permission to traverse the checkout or its
  // tsx tree. Bundle only this real installer; preserve its ordinary ESM URLs.
  const result = await build({ entryPoints: [fileURLToPath(new URL('./testing/installed-runtime-installer.ts', import.meta.url))],
    outfile: installed.installerEntry, bundle: true, platform: 'node', format: 'esm', target: 'node22.13',
    metafile: true, write: false });
  const imports = Object.values(result.metafile!.outputs).flatMap(output => output.imports);
  assert(imports.every(item => item.external && item.path.startsWith('node:')),
    'staged installer must have no runtime JavaScript filesystem dependency');
  assert.equal(result.outputFiles!.length, 1);
  const output = result.outputFiles![0]!;
  assert.equal(output.path, installed.installerEntry);
  assert(output.contents.byteLength > 0 && output.contents.byteLength <= 16 * 1024 * 1024);
  const file = await open(installed.installerEntry,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const before = await file.stat({ bigint: true });
    assert(before.isFile()); assert.equal(before.uid, 0n); assert.equal(before.gid, 0n);
    assert.equal(before.nlink, 1n); assert.equal(before.mode & 0o7777n, 0o600n); assert.equal(before.size, 0n);
    await file.writeFile(output.contents);
    await file.chmod(0o444);
    const held = await file.stat({ bigint: true });
    assert(held.isFile()); assert.equal(held.dev, before.dev); assert.equal(held.ino, before.ino);
    assert.equal(held.uid, 0n); assert.equal(held.gid, 0n); assert.equal(held.nlink, 1n);
    assert.equal(held.mode & 0o7777n, 0o444n); assert.equal(held.size, BigInt(output.contents.byteLength));
    const named = await lstat(installed.installerEntry, { bigint: true });
    for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const)
      assert.equal(named[key], held[key]);
  } finally { await file.close(); }
  return { path: installed.installerEntry, byteCount: output.contents.byteLength,
    externalImports: [...new Set(imports.map(item => item.path))].sort() };
}

async function campaign(ledgerFile: string): Promise<void> {
  assert.equal(process.geteuid!(), 0, 'only the frozen-ledger root orchestrator may stage this fixture');
  const ledger = await readLedger(ledgerFile), installed = ledger.installed;
  const report: Record<string, unknown> = { diagnosticOnly: true, qualified: false,
    scope: 'actual signed installed keeper source publication and Supervisor original-pin acquisition only; not restart, Run, worker, admission or complete I1',
    embeddedNodeVersion: SUPERVISOR_SEA_NODE_VERSION, uid: ledger.uid, keeperUnit: installed.keeperUnit };
  const userCommand = (args: string[]) => command('/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
    `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`, '/usr/bin/systemctl', '--user', ...args]);
  const show = (unit = installed.keeperUnit) => {
    const result = userCommand(['show', unit, `--property=${propertyNames.join(',')}`, '--no-pager']);
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
  let keeperStartedAt: number | undefined;
  const journal = (invocationId: string, execMainPid: string, unit = installed.keeperUnit) => {
    if (!/^[a-f0-9]{32}$/u.test(invocationId)) return [];
    assert(keeperStartedAt !== undefined);
    const matches = [`_UID=${ledger.uid}`, `_SYSTEMD_INVOCATION_ID=${invocationId}`];
    // A fast exit may remove the cgroup/invocation symlink before journald
    // enriches the stream record. Its trusted sender credentials still bind
    // stderr to this actual ExecMainPID; no application-supplied PID is used.
    if (/^[1-9][0-9]*$/u.test(execMainPid) && Number.isSafeInteger(Number(execMainPid)))
      matches.push('+', `_UID=${ledger.uid}`, `_PID=${execMainPid}`, '_TRANSPORT=stdout');
    matches.push('+', `_UID=${ledger.uid}`, `USER_UNIT=${unit}`, `USER_INVOCATION_ID=${invocationId}`);
    const result = command('/usr/bin/journalctl', ['--no-pager', '--all', '--output=json', '--lines=80', '--boot=0',
      `--since=@${Math.floor(keeperStartedAt / 1000)}`, `--until=@${Math.ceil(Date.now() / 1000)}`, ...matches]);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim().split('\n').filter(Boolean).map(line => parseJsonStrict(line) as Record<string, unknown>);
  };
  let shown: Record<string, string> | undefined;
  let supervisorStartAttempted = false;
  let keeperAuthorityAfter: Record<string, boolean> | undefined;
  let preloadEnvironmentTouched = false, managerPreloadConfirmed = false, keeperStartAttempted = false, keeperImageObserved = false;
  try {
    await mkdir(installed.buildFixture, { mode: 0o755 }); // Exclusive: never adopt a build/package tree.
    const stage = await lstat(installed.buildFixture);
    assert(stage.isDirectory() && !stage.isSymbolicLink()); assert.equal(stage.uid, 0); assert.equal(stage.gid, 0);
    assert.equal(stage.mode & 0o7777, 0o755);
    const { packageRoot, releaseKeys, bundle, contents, carrier } = await buildInstalledSupervisorPackage(installed.buildFixture);
    assert.equal(packageRoot, installed.packageRoot);
    report.installer = await stageInstaller(installed);
    report.preloadPositiveControl = await positivePreloadControl(ledger);
    await writeFile(installed.releaseKeysFile, canonicalJsonBytes(releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(packageRoot, ledger.uid, ledger.gid);
    const install = command('/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
      `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', process.execPath,
      installed.installerEntry, packageRoot, installed.stateRoot, installed.releaseKeysFile]);
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
    keeperStartedAt = Date.now();
    report.startCommand = userCommand(['start', installed.keeperUnit]);
    const deadline = Date.now() + 30_000;
    for (;;) {
      shown = show(); report.unit = shown;
      assert.equal(shown.FragmentPath, installed.keeperUnitFile);
      assert.equal(shown.LoadState, 'loaded'); assert.equal(shown.Type, 'exec');
      assert.equal(shown.Delegate, 'yes'); assert.equal(shown.KillMode, 'control-group'); assert.equal(shown.Restart, 'no');
      assert.match(shown.InvocationID!, /^[a-f0-9]{32}$/u, 'keeper must have a real systemd invocation');
      if (shown.ActiveState === 'failed' || shown.ActiveState === 'inactive') {
        let records = journal(shown.InvocationID, shown.ExecMainPID!);
        for (let attempt = 0; attempt < 20 && !records.some(record => typeof record.MESSAGE === 'string' && record.MESSAGE.includes('expected a fixed installed Supervisor role')); attempt++) {
          await delay(50); records = journal(shown.InvocationID, shown.ExecMainPID!);
        }
        report.journal = records;
        const closedRoleError = records.flatMap(record => {
          if (record._UID !== String(ledger.uid) || record._PID !== shown!.ExecMainPID ||
            record._TRANSPORT !== 'stdout' || typeof record.MESSAGE !== 'string') return [];
          try { return [parseJsonStrict(record.MESSAGE)]; } catch { return []; }
        }).find(value => value !== null && typeof value === 'object' &&
          (value as { diagnosticOnly?: boolean; scope?: string }).diagnosticOnly === true &&
          (value as { scope?: string }).scope === 'installed-read-startup' &&
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
            report.result = { pid, processStartToken: `linux-proc-start-ticks:${fields[19]}`,
              actualImage, roots, enabled, invocationId: shown.InvocationID };
            const sourcePublication: Record<string, unknown> = { diagnosticOnly: true };
            report.sourcePublication = sourcePublication;
            await qualifyInstalledAnchorSource({ pid, startTicks: fields[19]!, uid: ledger.uid, gid: ledger.gid,
              stateRoot: installed.stateRoot, bundleDigest: selection.bundleDigest, selectedImage: expectedImage,
              selectedMetadata: selected, root: roots[0]!, report: sourcePublication });
            const sourceConfirmed = show();
            assert.equal(sourceConfirmed.InvocationID, shown.InvocationID); assert.equal(sourceConfirmed.MainPID, shown.MainPID);
            // Seal the keeper-only authority observation before the Supervisor
            // legitimately opens StateOwner. Never delete a database to pass it.
            keeperAuthorityAfter = await authorityAbsent(installed.stateRoot);
            report.authorityAfterKeeper = keeperAuthorityAfter;
            assert(Object.values(keeperAuthorityAfter).every(Boolean));
            supervisorStartAttempted = true;
            report.supervisorStartCommand = userCommand(['start', installed.supervisorUnit]);
            const supervisorDeadline = Date.now() + 30_000;
            const socketPath = path.join(installed.stateRoot, 'runtime/control-v1.sock');
            let supervisorUnit: Record<string, string>;
            for (;;) {
              supervisorUnit = show(installed.supervisorUnit); report.supervisorUnit = supervisorUnit;
              assert.equal(supervisorUnit.FragmentPath, installed.supervisorUnitFile);
              assert.equal(supervisorUnit.LoadState, 'loaded'); assert.equal(supervisorUnit.Type, 'exec');
              assert.equal(supervisorUnit.Delegate, 'yes'); assert.equal(supervisorUnit.KillMode, 'control-group');
              assert.equal(supervisorUnit.Restart, 'no');
              assert(!['failed', 'inactive'].includes(supervisorUnit.ActiveState!), 'actual Supervisor exited before UDS readiness');
              const socket = await lstat(socketPath).catch((error: NodeJS.ErrnoException) => {
                if (error.code === 'ENOENT') return undefined; throw error;
              });
              if (socket) { assert(socket.isSocket()); assert.equal(socket.uid, ledger.uid); break; }
              assert(Date.now() < supervisorDeadline, 'actual Supervisor did not open its UDS');
              await delay(20);
            }
            const supervisorPid = Number(supervisorUnit.MainPID);
            assert(Number.isSafeInteger(supervisorPid) && supervisorPid > 0 && supervisorPid <= 0x7fffffff);
            assert.equal(supervisorUnit.ExecMainPID, String(supervisorPid));
            assert.match(supervisorUnit.InvocationID!, /^[a-f0-9]{32}$/u);
            const genesis: Record<string, unknown> = { diagnosticOnly: true }; report.genesis = genesis;
            const { owner, identity } = await qualifyInstalledGenesis({ stateRoot: installed.stateRoot, pid: supervisorPid,
              uid: ledger.uid, selectedImage: expectedImage, bundle, contents, report: genesis });
            const checkControl = async (): Promise<void> => {
              const currentUnit = show(installed.supervisorUnit);
              assert.equal(currentUnit.InvocationID, supervisorUnit.InvocationID); assert.equal(currentUnit.MainPID, String(supervisorPid));
              const client = command('/usr/sbin/runuser', ['--user', ledger.username, '--', '/usr/bin/env', '-i',
                `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', process.execPath,
                '--input-type=module', '-e', installedReadClientScript, socketPath]);
              report.supervisorReadClient = client; assert.equal(client.status, 0, client.stderr);
              assertInstalledReadExchanges(client.stdout, owner, bundle);
              assert.deepEqual(inspectInstalledOwner(installed.stateRoot), owner);
              const confirmedUnit = show(installed.supervisorUnit);
              assert.equal(confirmedUnit.InvocationID, supervisorUnit.InvocationID); assert.equal(confirmedUnit.MainPID, String(supervisorPid));
            };
            await checkControl();
            report.supervisorReadPositive = { pid: supervisorPid, ownerEpoch: owner.ownerEpoch,
              supervisorInstanceId: owner.supervisorInstanceId, reconnects: 1 };
            const consumer: Record<string, unknown> = { diagnosticOnly: true }; report.consumer = consumer;
            await qualifyInstalledAnchorConsumer({ pid: supervisorPid, source: { pid, startTicks: fields[19]!, uid: ledger.uid,
              gid: ledger.gid, stateRoot: installed.stateRoot, bundleDigest: selection.bundleDigest,
              selectedImage: expectedImage, selectedMetadata: selected, root: roots[0]!, report: sourcePublication }, report: consumer });
            const finalSource = show(), finalSupervisor = show(installed.supervisorUnit);
            assert.equal(finalSource.InvocationID, shown.InvocationID); assert.equal(finalSource.MainPID, shown.MainPID);
            assert.equal(finalSupervisor.InvocationID, supervisorUnit.InvocationID); assert.equal(finalSupervisor.MainPID, supervisorUnit.MainPID);
            const inspectorSignal: InstalledInspectorSignalReport = { diagnosticOnly: true };
            report.inspectorSignal = inspectorSignal;
            await qualifyInstalledInspectorSignal({ carrier, cwd: installed.buildFixture, pid: supervisorPid,
              selectedImage: expectedImage, processStartToken: identity.processStartToken,
              stderr: () => journal(supervisorUnit.InvocationID!, String(supervisorPid), installed.supervisorUnit)
                .filter(record => record._UID === String(ledger.uid) && record._PID === String(supervisorPid) &&
                  record._TRANSPORT === 'stdout' && typeof record.MESSAGE === 'string')
                .map(record => record.MESSAGE).join('\n'), checkControl, report: inspectorSignal });
            report.supervisorReadPositive = { pid: supervisorPid, ownerEpoch: owner.ownerEpoch,
              supervisorInstanceId: owner.supervisorInstanceId, reconnects: 3 };
            const stopSupervisor = userCommand(['stop', installed.supervisorUnit]);
            report.supervisorStopCommand = stopSupervisor; assert.equal(stopSupervisor.status, 0, stopSupervisor.stderr);
            const stoppedSupervisor = show(installed.supervisorUnit); report.supervisorStopped = stoppedSupervisor;
            assert.equal(stoppedSupervisor.MainPID, '0'); assert.equal(stoppedSupervisor.ActiveState, 'inactive');
            assert.equal(stoppedSupervisor.Result, 'success');
            // Inactive units may be unloaded, losing historical ExecMain*
            // and InvocationID. Check the actual prior process lifetime instead.
            const stoppedProcess = await readFile(`/proc/${supervisorPid}/stat`, 'utf8').catch((error: NodeJS.ErrnoException) => {
              if (error.code === 'ENOENT' || error.code === 'ESRCH') return undefined; throw error;
            });
            if (stoppedProcess !== undefined) {
              assert(stoppedProcess.startsWith(`${supervisorPid} (`));
              const stoppedFields = stoppedProcess.slice(stoppedProcess.lastIndexOf(') ') + 2).trim().split(/\s+/u);
              assert.match(stoppedFields[19]!, /^[1-9][0-9]*$/u);
              assert.notEqual(`linux-proc-start-ticks:${stoppedFields[19]}`, identity.processStartToken);
            }
            report.supervisorStoppedProcess = { pid: supervisorPid, priorProcessStartToken: identity.processStartToken,
              priorLifetimeGone: true, procStat: stoppedProcess ?? null };
            const terminal = inspectInstalledOwner(installed.stateRoot);
            assert(terminal?.state === 'terminal'); assert.equal(terminal.ownerEpoch, 1);
            assert.equal(terminal.terminalReason, 'graceful_release');
            await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
            const sourceAfterStop: Record<string, unknown> = { diagnosticOnly: true }; report.sourceAfterStop = sourceAfterStop;
            await qualifyInstalledAnchorSource({ pid, startTicks: fields[19]!, uid: ledger.uid, gid: ledger.gid,
              stateRoot: installed.stateRoot, bundleDigest: selection.bundleDigest, selectedImage: expectedImage,
              selectedMetadata: selected, root: roots[0]!, report: sourceAfterStop });
            const keeperAfterStop = show();
            assert.equal(keeperAfterStop.InvocationID, shown.InvocationID); assert.equal(keeperAfterStop.MainPID, shown.MainPID);
            // One real fault after the genuine positive: a legal FD locator
            // which the complete actual source inventory proves unavailable.
            // The physical named root remains intact, so fallback would fail
            // this pre-StateOwner refusal rather than satisfy the test.
            const invalidSource: Record<string, unknown> = { diagnosticOnly: true, qualified: false };
            report.invalidSourceDescriptor = invalidSource;
            const readyPath = path.join(installed.stateRoot, 'runtime/keeper.ready');
            const ready = await open(readyPath, constants.O_RDWR | constants.O_NONBLOCK | constants.O_NOFOLLOW);
            try {
              const readyInfo = await ready.stat({ bigint: true });
              const expectedReady = sourceAfterStop.ready as { metadata: Record<string, string> };
              const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
              for (const key of imageFields) assert.equal(readyInfo[key].toString(), expectedReady.metadata[key]);
              assert(readyInfo.isFile()); assert.equal(readyInfo.size, 40n); assert.equal(readyInfo.nlink, 1n);
              assert.equal(readyInfo.uid, BigInt(ledger.uid)); assert.equal(readyInfo.gid, BigInt(ledger.gid));
              assert.equal(readyInfo.mode & 0o7777n, 0o600n);
              const original = await ready.readFile();
              assert.equal(original.length, 40); assert.equal(original.toString('hex'), sourceAfterStop.readyBytes);
              const checkReady = async () => {
                const held = await ready.stat({ bigint: true }), named = await lstat(readyPath, { bigint: true });
                for (const key of ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink'] as const) assert.equal(held[key], readyInfo[key]);
                for (const key of imageFields) assert.equal(named[key], held[key]);
                return Object.fromEntries(imageFields.map(key => [key, held[key].toString()]));
              };
              await checkReady();
              const inventory = sourceAfterStop.afterInventory as { descriptors: Array<{ descriptor: string }> };
              assert(!inventory.descriptors.some(value => value.descriptor === '2147483647'));
              const corrupted = Buffer.from(original); corrupted.writeUInt32LE(0x7fffffff, 12);
              const casPath = path.join(installed.stateRoot, KERNEL_CAS_DIRECTORY);
              const casBefore = (await readdir(casPath)).sort();
              const writeReady = async (bytes: Buffer) => {
                await checkReady();
                let written = 0;
                while (written < bytes.length) {
                  const result = await ready.write(bytes, written, bytes.length - written, written);
                  assert(result.bytesWritten > 0); written += result.bytesWritten;
                }
                await ready.sync();
                const observed = Buffer.alloc(40);
                const result = await ready.read(observed, 0, 40, 0);
                assert.equal(result.bytesRead, 40); assert.deepEqual(observed, bytes);
                return await checkReady();
              };
              try {
                invalidSource.faultedMetadata = await writeReady(corrupted);
                invalidSource.originalBytes = original.toString('hex'); invalidSource.faultedBytes = corrupted.toString('hex');
                invalidSource.startCommand = userCommand(['start', installed.supervisorUnit]);
                const deadline = Date.now() + 30_000;
                let refused: Record<string, string>;
                for (;;) {
                  refused = show(installed.supervisorUnit); invalidSource.unit = refused;
                  if (['failed', 'inactive'].includes(refused.ActiveState!)) break;
                  assert(Date.now() < deadline, 'faulted locator did not refuse before StateOwner'); await delay(20);
                }
                assert.equal(refused.ActiveState, 'failed'); assert.equal(refused.MainPID, '0');
                assert.equal(refused.ExecMainCode, '1'); assert.equal(refused.ExecMainStatus, '1');
                assert.equal(refused.Result, 'exit-code'); assert.match(refused.InvocationID!, /^[a-f0-9]{32}$/u);
                assert.notEqual(refused.InvocationID, supervisorUnit.InvocationID);
                assert.match(refused.ExecMainPID!, /^[1-9][0-9]*$/u); assert.notEqual(refused.ExecMainPID, String(supervisorPid));
                let records: Record<string, unknown>[] = [];
                let exactRefusal = false;
                for (let attempt = 0; attempt < 20 && !exactRefusal; attempt++) {
                  records = journal(refused.InvocationID!, refused.ExecMainPID!, installed.supervisorUnit);
                  exactRefusal = records.some(record => {
                    if (record._UID !== String(ledger.uid) || record._PID !== refused.ExecMainPID ||
                      record._TRANSPORT !== 'stdout' || typeof record.MESSAGE !== 'string') return false;
                    try {
                      const value = parseJsonStrict(record.MESSAGE) as Record<string, unknown>;
                      return value.diagnosticOnly === true && value.scope === 'installed-read-startup' &&
                        value.code === 'ARTIFACT_MISMATCH' && value.message === 'installed keeper original source descriptor is unavailable';
                    } catch { return false; }
                  });
                  if (!exactRefusal) await delay(50);
                }
                invalidSource.journal = records; invalidSource.exactRefusal = exactRefusal;
                assert(exactRefusal, 'actual source-FD refusal must survive selected-image exec');
                invalidSource.ownerAfter = inspectInstalledOwner(installed.stateRoot);
                assert.deepEqual(invalidSource.ownerAfter, terminal, 'unavailable original FD must not acquire the next StateOwner');
                assert.deepEqual((await readdir(casPath)).sort(), casBefore);
                await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
              } finally {
                invalidSource.restoredMetadata = await writeReady(original);
                invalidSource.originalRestored = true;
              }
            } finally { await ready.close(); }
            const sourceAfterRefusal: Record<string, unknown> = { diagnosticOnly: true }; report.sourceAfterRefusal = sourceAfterRefusal;
            await qualifyInstalledAnchorSource({ pid, startTicks: fields[19]!, uid: ledger.uid, gid: ledger.gid,
              stateRoot: installed.stateRoot, bundleDigest: selection.bundleDigest, selectedImage: expectedImage,
              selectedMetadata: selected, root: roots[0]!, report: sourceAfterRefusal });
            assert.deepEqual(sourceAfterRefusal.after, sourceAfterStop.before);
            assert.deepEqual(sourceAfterRefusal.source, sourceAfterStop.source);
            const keeperAfterRefusal = show();
            assert.equal(keeperAfterRefusal.InvocationID, shown.InvocationID); assert.equal(keeperAfterRefusal.MainPID, shown.MainPID);
            invalidSource.qualified = true;
            report.qualified = true;
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
      try { report.journal = journal(shown.InvocationID, shown.ExecMainPID!); }
      catch (error) {
        observationError ??= error; report.qualified = false;
        report.journalError = String((error as Error).stack ?? error).slice(0, 8192);
      }
    }
    if (supervisorStartAttempted) {
      try {
        const supervisorUnit = show(installed.supervisorUnit);
        report.supervisorJournal = journal(supervisorUnit.InvocationID!, supervisorUnit.ExecMainPID!, installed.supervisorUnit);
      } catch (error) {
        observationError ??= error; report.qualified = false;
        report.supervisorJournalError = String((error as Error).stack ?? error).slice(0, 8192);
      }
    }
    let after: Record<string, boolean> | undefined;
    try {
      after = supervisorStartAttempted ? keeperAuthorityAfter : await authorityAbsent(installed.stateRoot);
      report.authorityAfterKeeper = after;
      if (!after || !Object.values(after).every(Boolean)) { report.qualified = false; report.authorityViolation = true; }
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
if (mode === '--campaign' && args.length === 1) await campaign(args[0]!);
else throw new Error('expected the closed --campaign LEDGER mode');
