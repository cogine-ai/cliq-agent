// One actual signed installation/enrollment tracer. This is not the complete
// credential lifecycle, crash qualification, broker redemption or installed I1.
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
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRecord, decodeEndpointAuthorityOperation,
  type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { installedReadClientScript } from './installed-read-control.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';

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
  'InvocationID', 'FragmentPath', 'Type', 'Delegate', 'KillMode', 'Restart', 'NRestarts'] as const;

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
    scope: 'one genuine signed installed enroll/read with actual user-manager autostart and independent Secret Service byte comparison; not replay, rotation, revoke, crash, broker or I1' };
  const userPrefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', `HOME=${ledger.home}`,
    'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`];
  const command = (executable: string, args: string[], input?: Buffer, timeout = 30000) => {
    const result = spawnSync('/usr/sbin/runuser', [...userPrefix, executable, ...args],
      { env: environment, cwd: ledger.home, encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 256 * 1024, input });
    assert.equal(result.error, undefined, 'actual disposable-user command did not join');
    assert.equal(result.signal, null, 'actual disposable-user command was signaled');
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  const success = (result: ReturnType<typeof command>, field: string): unknown => {
    // Do not print/store a secret-bearing command's arbitrary stderr/stdout on
    // refusal. Only successful closed metadata becomes an observation.
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
  const secret = randomBytes(32), password = Buffer.from(randomBytes(32).toString('hex'));
  let daemon: ReturnType<typeof spawn> | undefined;
  let daemonExit: Promise<{ code: number | null; signal: NodeJS.Signals | null }> | undefined;
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
    const serviceName = () => command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call',
      'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']);
    const absent = serviceName(); assert.equal(absent.status, 0); assert.equal(absent.stdout.trim(), 'b false');
    const helper = await lstat(recipe.observer);
    assert(helper.isFile() && !helper.isSymbolicLink()); assert.equal(helper.uid, 0);
    assert.equal(helper.nlink, 1); assert.equal(helper.mode & 0o7777, 0o555);
    await mkdir(recipe.controlDirectory, { mode: 0o700 }); await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
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
    const before = observe('list'); report.platformBefore = before; assert.deepEqual(before.items, []);
    assert.equal(await readlink(`/proc/${before.servicePid}/exe`), '/usr/bin/gnome-keyring-daemon');
    const daemonImage = await stat(`/proc/${before.servicePid}/exe`, { bigint: true });
    const daemonNamed = await lstat('/usr/bin/gnome-keyring-daemon', { bigint: true });
    for (const key of imageFields) assert.equal(daemonImage[key], daemonNamed[key]);

    report.phase = 'install_services';
    const setupResponse = credential({ schemaVersion: 1, kind: 'install_services' });
    report.setupExitStatus = setupResponse.status;
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
      assert.equal(inactive.ActiveState, 'inactive'); assert.equal(inactive.MainPID, '0');
      report[`${role}Before`] = inactive;
    }
    report.phase = 'endpoint_register';
    const root = await lstat(recipe.stateRoot, { bigint: true });
    assert(root.isDirectory()); assert.equal(root.uid, BigInt(ledger.uid)); assert.equal(root.mode & 0o7777n, 0o700n);
    const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: root.dev.toString(), directoryFileId: root.ino.toString(),
      mode: 448, openedNoFollow: true, layoutVersion: 1 });
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
      secretSubmissionId: 'credential-journey-submission' };
    report.phase = 'enroll';
    const operation = decodeCredentialAuthorityOperation(success(credential(metadata, secret), 'operation'));
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
    report.phase = 'complete'; report.qualified = true;
  } catch (error) { primary = error; }
  finally {
    secret.fill(0); password.fill(0);
    if (daemon && daemonExit) {
      try {
        if (daemon.exitCode === null && daemon.signalCode === null) daemon.kill('SIGTERM');
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          report.daemonExit = await Promise.race([daemonExit, new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error('actual fixture Secret Service daemon did not join')), 10000);
          })]);
        } finally { clearTimeout(timer); }
        report.daemonJoined = true;
      } catch (error) { primary = new AggregateError([primary, error].filter(Boolean), 'fixture platform daemon retirement failed'); }
    }
    if (primary) { report.qualified = false; report.error = String((primary as Error).stack ?? primary).slice(0, 8192); }
    await writeFile(recipe.reportFile, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
    console.log(`Actual installed credential journey report: ${recipe.reportFile}`);
  }
  if (primary) throw primary;
}

assert.equal(process.platform, 'linux', 'installed credential journey requires Linux');
assert.equal(process.arch, 'x64', 'no installed credential carrier qualified for this architecture');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--campaign'); assert(filename && extra.length === 0);
await campaign(filename);
