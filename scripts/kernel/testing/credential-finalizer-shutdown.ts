// Genuine installed finalizer shutdown, using an owned external Secret Service
// on the actual disposable-user manager bus. Not GNOME Keyring qualification,
// a precise private commit cut, provider qualification, or complete installed I1.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat, readFile, readlink, stat, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRecord, decodeCredentialAuthorityRevokeOperation,
  decodeEndpointAuthorityOperation, type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { readLedger, stageInstaller, transferPackage } from './credential-installed-journey.js';
import { createCredentialSecretScanner } from './credential-secret-scan.js';
import { scanCredentialSecretCorpus } from './credential-secret-corpus.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';
import { inspectInstalledOwnerHistory, installedReadClientScript } from './installed-read-control.js';
import { qualifyInstalledOwnerLinks, qualifyInstalledOwnerProcess } from './installed-owner-history.js';

const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const properties = ['ActiveState', 'SubState', 'MainPID', 'ExecMainPID', 'InvocationID', 'Result', 'ExecMainCode', 'ExecMainStatus',
  'TimeoutStopUSec', 'KillSignal', 'FinalKillSignal', 'SendSIGKILL'] as const;

async function bounded<T>(pending: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([pending, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('owned finalizer fixture did not join')), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

async function campaign(filename: string): Promise<void> {
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.credentials;
  const secret = Buffer.from(randomBytes(24).toString('base64url'));
  const scanner = createCredentialSecretScanner([secret], { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 });
  const report: Record<string, any> = { diagnosticOnly: true, qualified: false, phase: 'installation',
    scope: 'actual signed enrollment producer and original Supervisor finalizer; owned external Secret Service on the actual user-manager bus; ordinary two-second SIGTERM and real orphan cleanup; not GNOME Keyring, precise private commit-cut or complete I1 qualification',
    exactPrivateCommitCutQualified: false, gnomeKeyringQualified: false, installedI1Qualified: false };
  const started = performance.now();
  const mark = (phase: string) => {
    report.phase = phase;
    try { console.log(`I1 finalizer shutdown phase ${phase} elapsedMs=${Math.floor(performance.now() - started)}`); }
    catch { /* Fixed diagnostics never change acceptance. */ }
  };
  const scan = (bytes: Uint8Array) => { const held = scanner.openStream(); try { held.scan(bytes); } finally { held.close(); } };
  const prefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin',
    'LANG=C', 'LC_ALL=C', `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`];
  const command = (executable: string, args: string[], input?: Buffer, timeout = 30000) => {
    const result = spawnSync('/usr/sbin/runuser', [...prefix, executable, ...args],
      { cwd: ledger.home, env: environment, input, timeout, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
    assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr)); scan(result.stdout); scan(result.stderr);
    assert.equal(result.error, undefined, 'actual installed command must join'); assert.equal(result.signal, null);
    return { status: result.status, stdout: result.stdout.toString('utf8'), stderr: result.stderr.toString('utf8') };
  };
  const success = (result: ReturnType<typeof command>, field: string): any => {
    assert.equal(result.status, 0, `actual signed entry refused during ${String(report.phase)}`);
    const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
    assert.deepEqual(Object.keys(value).sort(), [field, 'schemaVersion'].sort()); assert.equal(value.schemaVersion, 1);
    assert.equal(result.stdout, `${canonicalJsonBytes(value).toString('utf8')}\n`); return value[field];
  };
  const credential = (metadata: Record<string, unknown>, bytes?: Buffer) => command(path.join(recipe.stateRoot, 'runtime/bootstrap'),
    ['--bootstrap-credential', canonicalJsonBytes(metadata).toString('base64url')], bytes, 60000);
  const show = (unit: string) => {
    const result = command('/usr/bin/systemctl', ['--user', 'show', unit, `--property=${properties.join(',')}`, '--no-pager']);
    assert.equal(result.status, 0); const values: Record<string, string> = {};
    for (const line of result.stdout.trim().split('\n')) {
      const separator = line.indexOf('='); assert(separator > 0); const key = line.slice(0, separator);
      assert(!Object.hasOwn(values, key)); values[key] = line.slice(separator + 1);
    }
    for (const key of properties) assert(Object.hasOwn(values, key)); return values;
  };
  const processFact = async (pid: number) => {
    try {
      const raw = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(raw.startsWith(`${pid} (`) && raw.length <= 8192);
      const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u); assert(fields.length > 19);
      assert.match(fields[19]!, /^[1-9][0-9]*$/u);
      const status = await readFile(`/proc/${pid}/status`, 'utf8');
      const uid = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu); assert(uid);
      const fresh = await readFile(`/proc/${pid}/stat`, 'utf8');
      assert.equal(fresh.slice(fresh.lastIndexOf(')') + 2).trim().split(/\s+/u)[19], fields[19]);
      return { pid, parent: Number(fields[1]), group: Number(fields[2]), session: Number(fields[3]), start: fields[19]!, uids: uid.slice(1).map(Number) };
    } catch (error) { if (['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) return undefined; throw error; }
  };
  const owned: { retire(): Promise<void> }[] = [];
  function spawnOwned(executable: string, args: string[], input?: Buffer, role: 'service' | 'unit-history' = 'service') {
    const outputScans = [scanner.openStream(), scanner.openStream()];
    let child: ReturnType<typeof spawn>;
    try { child = spawn('/usr/sbin/runuser', [...prefix, executable, ...args],
      { cwd: ledger.home, env: environment, detached: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
    catch (error) { for (const held of outputScans) held.close(); throw error; }
    const stdout: Buffer[] = [], stderr: Buffer[] = []; let total = 0, failure: unknown, done = false, joinedAt: number | undefined;
    const joined = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => {
      done = true; joinedAt = performance.now(); resolve({ code, signal });
    }));
    const closed = Promise.all([child.stdin!, child.stdout!, child.stderr!].map(stream => new Promise<void>(resolve => stream.once('close', resolve))));
    child.on('error', () => { failure = new Error('owned finalizer command did not spawn'); }); child.stdin!.on('error', () => {});
    const capture = (chunks: Buffer[], bytes: Buffer, index: number) => {
      if (failure) return;
      try { outputScans[index]!.scan(bytes); assert(total + bytes.length <= 256 * 1024); total += bytes.length; chunks.push(bytes); }
      catch (error) { failure = error; }
    };
    child.stdout!.on('data', (bytes: Buffer) => capture(stdout, bytes, 0));
    child.stderr!.on('data', (bytes: Buffer) => capture(stderr, bytes, 1));
    if (input) child.stdin!.end(input);
    let original: Awaited<ReturnType<typeof processFact>>;
    const observe = async () => {
      assert(child.pid); const current = await processFact(child.pid);
      if (!original) { assert(current && current.parent === process.pid && current.group === child.pid && current.session === child.pid); original = current; }
      else if (current) assert.equal(current.start, original.start);
      return original;
    };
    const check = () => { if (failure) throw failure; };
    const text = () => { check(); return Buffer.concat(stdout).toString('utf8'); };
    let waitFailure: 'deadline_reached' | 'service_exited' | undefined;
    const waitEvent = async (event: string, entryDeadline?: number) => {
      // Genuine signed bootstrap/profile validation belongs to the existing
      // whole-entry budget. Only the observed CreateItem setup milestone may
      // use its remainder; the inspection observation window stays ten seconds.
      assert(event !== 'helper-create-started' || entryDeadline !== undefined);
      const deadline = event === 'helper-create-started' ? entryDeadline!
        : Math.min(performance.now() + 10000, entryDeadline ?? Infinity);
      const frames = role === 'unit-history' ? ['systemd_units_retained', 'systemd_units_released']
        : ['ready', 'armed', 'producer-armed', 'helper-create-started', 'inspection-started', 'inspection-held', 'inspection-retired', 'closed'];
      assert(frames.includes(event));
      const complete = `${frames.join('\n')}\n`;
      for (;;) {
        check(); const output = text(); assert(complete.startsWith(output), 'owned fixture emitted an invalid fixed frame');
        if (output.split('\n').slice(0, -1).includes(event)) return;
        if (done) { waitFailure = 'service_exited'; throw new Error('actual external service exited before its event'); }
        if (performance.now() >= deadline) { waitFailure = 'deadline_reached'; throw new Error('actual external service event deadline was reached'); }
        await delay(10);
      }
    };
    const join = async (entryDeadline?: number) => {
      if (!done) await bounded(joined, Math.max(0, Math.min(10000, (entryDeadline ?? Infinity) - performance.now())));
      const exit = await joined;
      if (entryDeadline !== undefined) assert(joinedAt !== undefined && joinedAt <= entryDeadline, 'actual enrollment exceeded its existing whole-entry budget');
      await bounded(closed, 5000); check(); return exit;
    };
    const diagnostic = () => {
      check();
      const output = Buffer.concat(stdout).toString('utf8'), errors = Buffer.concat(stderr).toString('utf8');
      const sourceStages = ['alias-default', 'alias-session', 'caller-other', 'caller-original', 'search-absent', 'search-present',
        'open-session', 'create-item', 'item-created', 'get-secret', 'secret-returned', 'collections', 'collection-locked', 'collection-items',
        'item-attributes', 'item-locked', 'original-identity-refused', 'method-refused', 'property-refused', 'fixture-refused'];
      const externalStages: string[] = [];
      let externalOtherOutput = false;
      for (const line of errors.trim().split('\n').filter(Boolean)) {
        const stage = sourceStages.find(candidate => line === `finalizer-stage:${candidate}`);
        if (stage && !externalStages.includes(stage)) externalStages.push(stage);
        else externalOtherOutput = true;
      }
      let entryCodeClass = errors.length ? 'unclassified' : 'absent', entryMessageClass = errors.length ? 'unclassified' : 'absent';
      if (errors.length && Buffer.byteLength(errors) <= 2048) try {
        const value = parseJsonStrict(errors.trim()) as Record<string, unknown>;
        if (value.diagnosticOnly === true && value.scope === 'installed-read-startup' &&
            Object.keys(value).every(key => ['diagnosticOnly', 'scope', 'code', 'message', 'path'].includes(key))) {
          const codes = ['RECOVERY_REQUIRED', 'INVALID_REQUEST', 'STATE_TRANSITION_INVALID', 'ARTIFACT_MISMATCH',
            'UNSUPPORTED_PLATFORM', 'ERR_CLIQ_CREDENTIAL_BUSY'] as const;
          entryCodeClass = codes.find(code => value.code === code) ?? 'other';
          const messages = [
            ['credential store did not complete a fresh secret round-trip', 'create_roundtrip_refused'],
            ['credential scope could not hold its original physical bindings', 'credential_bindings_refused'],
            ['installed Supervisor refused the authenticated credential operation', 'finalizer_refused'],
            ['installed Supervisor hello is incompatible with credential finalization', 'hello_incompatible'],
            ['installed service dependencies differ from the fixed profiles', 'service_dependencies_refused'],
            ['installed service effective configuration drifted; explicit installation remediation is required', 'service_profile_refused'],
            ['installed credential services are not in a current running invocation', 'service_invocation_refused'],
            ['installed Supervisor startup did not reach authenticated readiness', 'supervisor_readiness_refused'],
          ] as const;
          entryMessageClass = messages.find(([message]) => value.message === message)?.[1] ?? 'other';
        }
      } catch { /* Unknown entry output remains a fixed class, never retained bytes. */ }
      let returnedOperationPhase = output.length ? 'unclassified' : 'absent';
      if (output.length && Buffer.byteLength(output) <= 65536) try {
        const value = parseJsonStrict(output.trim()) as Record<string, unknown>;
        if (value.schemaVersion === 1 && Object.keys(value).sort().join(',') === 'operation,schemaVersion')
          returnedOperationPhase = decodeCredentialAuthorityOperation(value.operation).phase;
      } catch { /* No arbitrary returned payload becomes evidence. */ }
      return { exited: done, exitCode: child.exitCode, signal: child.signalCode === null ? 'none'
        : ['SIGTERM', 'SIGKILL'].includes(child.signalCode) ? child.signalCode : 'other',
        stdoutBytes: Buffer.byteLength(output), stderrBytes: Buffer.byteLength(errors), returnedOperationPhase,
        entryCodeClass, entryMessageClass, externalStages, externalFixtureRefused: externalStages.includes('fixture-refused'),
        externalOtherOutput, waitFailure: waitFailure ?? 'none' };
    };
    const retire = async () => {
      let retirementFailure: unknown;
      try {
        if (!done && child.pid) {
          const current = await processFact(child.pid);
          if (!original && current?.parent === process.pid && current.group === child.pid && current.session === child.pid) original = current;
          if (current) {
            assert(original && current.start === original.start && current.group === child.pid && current.session === child.pid);
            process.kill(-child.pid, 'SIGTERM');
          }
        }
        await bounded(joined, 5000);
      } catch (error) { retirementFailure = error; }
      finally {
        for (const stream of [child.stdin!, child.stdout!, child.stderr!]) stream.destroy();
        try { await bounded(closed, 5000); } catch (error) { retirementFailure ??= error; }
        for (const held of outputScans) held.close();
      }
      if (retirementFailure) throw retirementFailure;
      check();
    };
    const value = { child, observe, waitEvent, text, join, retire, diagnostic,
      result: () => ({ status: child.exitCode, stdout: text(), stderr: Buffer.concat(stderr).toString('utf8') }) };
    owned.push(value); return value;
  }
  let services: { keeperUnit: string; supervisorUnit: string } | undefined, primary: unknown;
  let historyObserver: { release(): Promise<void> } | undefined;
  // Reuse the existing actual-manager RefUnit observer. Each narrow lifetime
  // retains the original fixed ten-second input deadline; no unit is changed.
  const retainUnitHistory = async () => {
    assert(services && !historyObserver);
    const observer = spawnOwned(recipe.observer, ['retain-systemd', services.supervisorUnit, services.keeperUnit], undefined, 'unit-history');
    let releasing: Promise<void> | undefined;
    historyObserver = { release: () => releasing ??= (async () => {
      observer.child.stdin!.end('R');
      assert.deepEqual(await observer.join(), { code: 0, signal: null });
      assert.equal(observer.text(), 'systemd_units_retained\nsystemd_units_released\n');
      assert.equal(observer.result().stderr, '');
    })() };
    await observer.observe(); await observer.waitEvent('systemd_units_retained');
    assert.equal(observer.text(), 'systemd_units_retained\n');
  };
  const releaseUnitHistory = async () => { assert(historyObserver); await historyObserver.release(); historyObserver = undefined; };
  try {
    await mkdir(recipe.buildFixture, { mode: 0o755 }); const signed = await buildInstalledSupervisorPackage(recipe.buildFixture);
    assert.equal(signed.packageRoot, recipe.packageRoot); await stageInstaller(recipe);
    await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(signed.releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(recipe.packageRoot, ledger.uid, ledger.gid);
    const installed = command(process.execPath, [recipe.installerEntry, recipe.packageRoot, recipe.stateRoot, recipe.releaseKeysFile]);
    assert.equal(installed.status, 0); const bundleDigest = (parseJsonStrict(installed.stdout.trim()) as { bundleDigest: string }).bundleDigest;
    assert.equal(bundleDigest, canonicalSha256(signed.bundle)); report.bundleDigest = bundleDigest;
    const selectedImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
    const selected = signed.bundle.entries.find(entry => entry.role === 'supervisor' && entry.relativePath === 'supervisor'); assert(selected);
    const servicePath = path.join(ledger.fixture, 'cliq-credential-finalizer-service');
    const helper = await lstat(servicePath); assert(helper.isFile() && !helper.isSymbolicLink() && helper.uid === 0 && helper.nlink === 1 && (helper.mode & 0o7777) === 0o555);
    const absent = command('/usr/bin/busctl', ['--user', 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
      'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']);
    assert.equal(absent.status, 0); assert.equal(absent.stdout.trim(), 'b false');
    mark('original_external_service');
    const service = spawnOwned(servicePath, [selectedImage]); await service.observe(); await service.waitEvent('ready');
    const observe = () => {
      const result = command(recipe.observer, ['list']); assert.equal(result.status, 0);
      const value = parseJsonStrict(result.stdout.trim()) as Record<string, any>;
      assert.equal(value.serviceUid, ledger.uid); assert.equal(value.connectionClosed, true);
      assert.match(value.nameOwner, /^:\d+\.\d+$/u); assert(Array.isArray(value.items)); return value;
    };
    const initialStore = observe(); assert.deepEqual(initialStore.items, []);
    assert.equal(await readlink(`/proc/${initialStore.servicePid}/exe`), servicePath);
    const actualService = await stat(`/proc/${initialStore.servicePid}/exe`, { bigint: true }), helperImage = await lstat(servicePath, { bigint: true });
    for (const key of imageFields) assert.equal(actualService[key], helperImage[key]);
    report.platform = { actualUserManagerBus: true, sameUid: true, nameOwner: initialStore.nameOwner, servicePid: initialStore.servicePid,
      collection: initialStore.collection, unchangedThroughoutEnrollmentAndCleanup: false };
    const setup = credential({ schemaVersion: 1, kind: 'install_services' }); assert.equal(setup.status, 0);
    const parsedSetup = parseJsonStrict(setup.stdout.trim()) as { schemaVersion: number; keeperUnit: string; supervisorUnit: string };
    assert.equal(parsedSetup.schemaVersion, 1); services = parsedSetup;
    for (const unit of [services.keeperUnit, services.supervisorUnit]) assert.match(unit, /^cliq-[0-9a-f]{64}-(?:keeper|supervisor)\.service$/u);
    assert.equal(command('/usr/bin/systemctl', ['--user', 'start', services.supervisorUnit]).status, 0);
    const readyBy = Date.now() + 30000;
    for (;;) {
      const control = command(process.execPath, ['--input-type=module', '-e', installedReadClientScript, path.join(recipe.stateRoot, 'runtime/control-v1.sock')]);
      if (control.status === 0) { const replies = parseJsonStrict(control.stdout.trim()) as Array<{ status: string }>;
        assert.equal(replies.length, 2); assert(replies.every(reply => (parseJsonStrict(reply.status) as { ok: boolean }).ok)); break; }
      assert(Date.now() < readyBy, 'actual signed Supervisor did not become ready'); await delay(20);
    }
    const original = show(services.supervisorUnit), keeper = show(services.keeperUnit);
    assert.equal(original.ActiveState, 'active'); assert.equal(original.SubState, 'running');
    assert.equal(original.TimeoutStopUSec, '2s'); assert.equal(original.KillSignal, '15'); assert.equal(original.FinalKillSignal, '9'); assert.equal(original.SendSIGKILL, 'yes');
    const originalPid = Number(original.MainPID); assert(Number.isSafeInteger(originalPid) && originalPid > 0);
    const owners = inspectInstalledOwnerHistory(recipe.stateRoot).owners; assert.equal(owners.length, 1); const originalOwner = owners[0]!;
    const processEvidence: Record<string, unknown> = {};
    const identity = await qualifyInstalledOwnerProcess({ stateRoot: recipe.stateRoot, uid: ledger.uid, pid: originalPid,
      selectedImage, imageDigest: selected.digest }, originalOwner, processEvidence);
    const keeperReady = await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready'));
    const root = await lstat(recipe.stateRoot, { bigint: true });
    assert(root.isDirectory() && !root.isSymbolicLink() && root.uid === BigInt(ledger.uid) && (root.mode & 0o7777n) === 0o700n);
    const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux', canonicalAbsolutePath: recipe.stateRoot,
      ownerUid: ledger.uid, deviceId: String(root.dev), directoryFileId: String(root.ino), mode: 448, openedNoFollow: true, layoutVersion: 1 });
    const ownerPrincipalId = identityHash('cliq-local-principal-v1', rootDigest, 'linux', ledger.uid);
    const trust = signed.bundle.entries.find(entry => entry.entryId === 'default_https_trust_store'); assert(trust);
    const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'credential-finalizer-endpoint',
      registrationKind: 'user', ownerPrincipalId, purposes: ['model_endpoint'],
      target: { scheme: 'https', hostAscii: 'endpoint.invalid', port: 443, basePath: '/v1', redirectPolicy: 'reject_all' },
      tls: { serverNameAscii: 'endpoint.invalid', minimumVersion: 'TLSv1.3', trustStoreRuntimeBundleRef: bundleDigest,
        trustStoreRuntimeBundleManifestDigest: signed.bundle.manifestDigest, trustStoreEntryId: 'default_https_trust_store',
        trustStoreRef: trust.digest, trustStoreDigest: trust.digest, spkiSha256Pins: ['4'.repeat(64)] },
      endpointIdentityDigest: '', tlsPolicyDigest: '', createdAt: '2026-10-11T00:00:00.000Z', registrationDigest: '' };
    registration.tlsPolicyDigest = canonicalSha256(registration.tls);
    registration.endpointIdentityDigest = canonicalSha256({ target: registration.target, tlsPolicyDigest: registration.tlsPolicyDigest });
    registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
    const core = { schemaVersion: 1, kind: 'register', ownerPrincipalId, registration, expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' };
    const endpoint = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], canonicalJsonBytes({ schemaVersion: 1, kind: 'commit',
      requestId: '019a0012-0000-7000-8000-000000000081', commandCore: { ...core, commandDigest: digestOmitting(core, 'commandDigest') } }));
    assert.equal(decodeEndpointAuthorityOperation(success(endpoint, 'operation')).disposition, 'registered');
    mark('genuine_enrollment_original_finalizer');
    const metadata = { schemaVersion: 1, kind: 'enroll', requestId: '019a0012-0000-7000-8000-000000000082',
      credentialGrantId: 'credential-finalizer-grant', purpose: 'model_endpoint', endpointRegistrationId: registration.endpointRegistrationId,
      secretSubmissionId: 'credential-finalizer-submission', expiresAt: '2099-01-01T00:00:00.000Z' };
    service.child.stdin!.write(`arm ${originalPid} ${identity.processStartToken.slice('linux-proc-start-ticks:'.length)}\n`);
    await service.waitEvent('armed');
    const entryStarted = performance.now(), entryDeadline = entryStarted + 60000;
    report.entryBudget = { milliseconds: 60000 };
    const enrollment = spawnOwned(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-credential', canonicalJsonBytes(metadata).toString('base64url')], secret);
    await enrollment.observe();
    const launcher = await enrollment.observe();
    let producer: NonNullable<Awaited<ReturnType<typeof processFact>>> | undefined;
    try {
      // Observe the real auth child after its signed selected-image exec.
      // No PID, image, continuation or database phase is supplied to production.
      for (;;) {
        assert(performance.now() < entryDeadline, 'actual signed credential setup exceeded its existing whole-entry budget');
        assert.equal(enrollment.child.exitCode, null, 'actual signed enrollment exited before its create milestone');
        const children = await readFile(`/proc/${launcher.pid}/task/${launcher.pid}/children`, 'utf8');
        const childPids = children.trim() ? children.trim().split(/\s+/u).map(Number) : [];
        assert(childPids.length <= 1);
        if (childPids.length) {
          const observed = await processFact(childPids[0]!);
          if (observed && observed.parent === launcher.pid && observed.uids.every(uid => uid === ledger.uid) &&
              await readlink(`/proc/${observed.pid}/exe`).catch((error: NodeJS.ErrnoException) => {
                if (error.code === 'ENOENT') return ''; throw error;
              }) === selectedImage) {
            const actual = await stat(`/proc/${observed.pid}/exe`, { bigint: true }), expected = await lstat(selectedImage, { bigint: true });
            for (const key of imageFields) assert.equal(actual[key], expected[key]);
            const confirmed = await processFact(observed.pid); assert(confirmed && confirmed.start === observed.start);
            producer = observed; break;
          }
        }
        await delay(10);
      }
      report.entryBudget.selectedImageObservedAfterMs = Math.floor(performance.now() - entryStarted);
      service.child.stdin!.write(`producer ${producer.pid} ${producer.start}\n`);
      await service.waitEvent('producer-armed', entryDeadline);
      await service.waitEvent('helper-create-started', entryDeadline);
      report.entryBudget.actualCreateObservedAfterMs = Math.floor(performance.now() - entryStarted);
      await service.waitEvent('inspection-started', entryDeadline);
      report.entryBudget.actualInspectionObservedAfterMs = Math.floor(performance.now() - entryStarted);
    }
    catch (error) {
      // This is a refused/unreached cut, never a SIGTERM result. Preserve only
      // fixed stage classes and independently observed child exit facts.
      report.unreachedInspection = { enrollment: enrollment.diagnostic(), externalService: service.diagnostic() };
      throw error;
    }
    assert(producer);
    // Retain real inactive-unit history only after the actual finalizer cut,
    // not during potentially lengthy signed bootstrap/profile validation.
    await retainUnitHistory();
    const currentProducer = await processFact(producer.pid);
    assert(currentProducer && currentProducer.start === producer.start && currentProducer.parent === launcher.pid && currentProducer.uids.every(uid => uid === ledger.uid));
    assert.equal(await readlink(`/proc/${producer.pid}/exe`), selectedImage);
    const beforeStop = observe(); assert.equal(beforeStop.items.length, 1);
    for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection']) assert.equal(beforeStop[key], initialStore[key]);
    assert.equal(show(services.supervisorUnit).InvocationID, original.InvocationID);
    service.child.stdin!.write('confirm\n'); await service.waitEvent('inspection-held', entryDeadline);
    report.cut = { actualOriginalSupervisorInspectionEntered: true, originalProducerStillPresent: true, originalProducerPid: producer.pid,
      originalProducerStartTicks: producer.start, originalSupervisorPid: originalPid, originalSupervisorStartToken: identity.processStartToken,
      actualPlatformItemCreated: true, exactOriginalHelperCreateObserved: true,
      originalInspectionStillUnansweredAfterUnitRetention: true, noFixtureReplyOrServiceReplacement: true };
    mark('ordinary_two_second_sigterm');
    const stop = command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit]);
    const exit = show(services.supervisorUnit); report.serviceExit = exit;
    assert.equal(stop.status, 0); assert.equal(exit.ActiveState, 'inactive'); assert.equal(exit.MainPID, '0');
    assert.equal(exit.Result, 'success'); assert.equal(exit.ExecMainCode, '1'); assert.equal(exit.ExecMainStatus, '0');
    await releaseUnitHistory(); report.targetUnitExitHistoryObserverJoined = true;
    await service.waitEvent('inspection-retired');
    const enrollmentExit = await enrollment.join(entryDeadline); report.enrollmentExit = enrollmentExit;
    assert.equal(enrollmentExit.signal, null); assert.equal(enrollmentExit.code, 1);
    const refusal = enrollment.result(); assert.equal(refusal.stdout, '');
    const diagnostic = parseJsonStrict(refusal.stderr.trim()) as Record<string, unknown>;
    assert.equal(diagnostic.diagnosticOnly, true); assert.equal(diagnostic.scope, 'installed-read-startup'); assert.equal(diagnostic.code, 'RECOVERY_REQUIRED');
    assert(Object.keys(diagnostic).every(key => ['diagnosticOnly', 'scope', 'code', 'message', 'path'].includes(key)));
    assert.equal(await processFact(producer.pid), undefined); assert.equal(await processFact(originalPid), undefined);
    const released = inspectInstalledOwnerHistory(recipe.stateRoot).owners; assert.equal(released.length, 1);
    const terminal = released[0]!; assert.equal(terminal.state, 'terminal');
    if (terminal.state !== 'terminal') throw new Error('original finalizer owner did not retire');
    assert.equal(terminal.terminalReason, 'graceful_release'); assert.equal(terminal.ownerEpoch, originalOwner.ownerEpoch);
    assert.equal(terminal.processIdentityRef, originalOwner.processIdentityRef);
    assert.equal(show(services.keeperUnit).InvocationID, keeper.InvocationID);
    assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
    assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: metadata.credentialGrantId }), 'record'), null);
    mark('actual_successor_and_original_orphan_cleanup');
    assert.equal(command('/usr/bin/systemctl', ['--user', 'start', services.supervisorUnit]).status, 0);
    const successorBy = Date.now() + 30000;
    for (;;) {
      const latest = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      if (latest.length === 2 && latest[1]!.state === 'active') break;
      assert(Date.now() < successorBy, 'actual finalizer successor did not acquire'); await delay(20);
    }
    const links: Record<string, unknown> = {};
    const history = await qualifyInstalledOwnerLinks({ stateRoot: recipe.stateRoot, uid: ledger.uid, bundle: signed.bundle, imageDigest: selected.digest, report: links });
    assert.equal(links.qualified, true); assert.equal(history.owners.length, 2); assert.deepEqual(history.owners[0], terminal);
    const successor = show(services.supervisorUnit); assert.notEqual(successor.InvocationID, original.InvocationID);
    assert.equal(show(services.keeperUnit).InvocationID, keeper.InvocationID);
    const aborted = decodeCredentialAuthorityOperation(success(credential({ schemaVersion: 1, kind: 'cleanup', requestId: metadata.requestId }), 'operation'));
    assert.equal(aborted.phase, 'aborted'); assert.equal(aborted.attempt, 1);
    if (aborted.phase !== 'aborted') throw new Error('original orphan was not aborted');
    assert.equal(aborted.abortReason, 'recovered_orphan'); assert.equal(aborted.requestId, metadata.requestId);
    assert.equal(aborted.credentialGrantId, metadata.credentialGrantId); assert.equal(aborted.ownerPrincipalId, ownerPrincipalId);
    assert.equal(aborted.commandCore.secretSubmissionId, metadata.secretSubmissionId);
    assert.equal(aborted.platformItem.kind, 'linux_secret_service');
    if (aborted.platformItem.kind !== 'linux_secret_service') throw new Error('orphan lost its real Linux platform item');
    const cleaned = observe(); assert.deepEqual(cleaned.items, []);
    for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection']) assert.equal(cleaned[key], initialStore[key]);
    assert.equal(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: metadata.credentialGrantId }), 'record'), null);
    assert.deepEqual(decodeCredentialAuthorityOperation(success(credential({ schemaVersion: 1, kind: 'cleanup', requestId: metadata.requestId }), 'operation')), aborted);
    report.platform.unchangedThroughoutEnrollmentAndCleanup = true;
    report.recovery = { originalOwnerGracefulRelease: true, strictSuccessorLineageQualified: true, ownerHistory: links,
      originalHelperJoinedWithoutSignal: true, orphanAbortReason: aborted.abortReason, originalAttempt: aborted.attempt,
      realKnownItemDeleted: true, absentGrantBeforeAndAfterCleanup: true, exactCleanupReplay: true };
    // A fresh real attempt uses the same retained core, not a fabricated
    // continuation. This checks normal native operations after revocation.
    mark('same_core_retry_and_exact_committed_replay');
    const committed = decodeCredentialAuthorityOperation(success(credential(metadata, secret), 'operation'));
    assert.equal(committed.phase, 'committed'); assert.equal(committed.attempt, 2); assert.deepEqual(committed.commandCore, aborted.commandCore);
    const replay = credential(metadata); assert.deepEqual(decodeCredentialAuthorityOperation(success(replay, 'operation')), committed);
    const record = decodeCredentialAuthorityRecord(success(credential({ schemaVersion: 1, kind: 'read', credentialGrantId: metadata.credentialGrantId }), 'record'));
    assert.equal(record.state, 'active'); assert.equal(record.authorityRevision, 1); assert.equal(record.secretGeneration, 1);
    assert.deepEqual(record.platformItem, committed.platformItem);
    assert.equal(record.createdAt, committed.finishedAt);
    const revoked = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'revoke',
      requestId: '019a0012-0000-7000-8000-000000000083', credentialGrantId: metadata.credentialGrantId, expectedAuthorityRevision: 1 }), 'operation'));
    assert.equal(revoked.cleanupPhase, 'cleanup_complete');
    const finalStore = observe(); assert.deepEqual(finalStore.items, []);
    for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection']) assert.equal(finalStore[key], initialStore[key]);
    report.recovery.successorNormalNativeOperationsQualified = true; report.recovery.exactCommittedReplay = true;
    await retainUnitHistory();
    service.child.stdin!.end('finish\n'); assert.deepEqual(await service.join(), { code: 0, signal: null }); await service.waitEvent('closed');
    assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit, services.keeperUnit]).status, 0);
    report.finalServiceExits = [];
    for (const unit of [services.supervisorUnit, services.keeperUnit]) {
      const finalExit = show(unit); report.finalServiceExits.push(finalExit);
      assert.equal(finalExit.ActiveState, 'inactive'); assert.equal(finalExit.MainPID, '0');
      assert.equal(finalExit.Result, 'success'); assert.equal(finalExit.ExecMainCode, '1'); assert.equal(finalExit.ExecMainStatus, '0');
    }
    await releaseUnitHistory(); report.finalUnitExitHistoryObserverJoined = true;
    report.ordinaryStopQualified = true;
  } catch (error) { primary = error; }
  finally {
    secret.fill(0);
    if (historyObserver) try { await releaseUnitHistory(); } catch (error) { primary ??= error; }
    for (const child of [...owned].reverse()) try { await child.retire(); } catch (error) { primary ??= error; }
    if (services) try { assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit, services.keeperUnit]).status, 0); }
    catch (error) { primary ??= error; }
    if (!primary) try {
      mark('joined_secret_corpus');
      report.secretCorpus = await scanCredentialSecretCorpus({ stateRoot: recipe.stateRoot, uid: ledger.uid, evidenceDirs: [], scanner });
      assert.equal(report.secretCorpus.sqliteDatabasesScanned, 2); assert.equal(report.secretCorpus.evidenceDirectoriesScanned, 0);
      report.qualified = true; mark('complete');
    } catch (error) { primary = error; }
    if (primary) {
      report.qualified = false; const frames: { file: string; line: number; column: number }[] = [];
      if (primary instanceof Error) for (const match of (primary.stack ?? '').matchAll(/\b(credential-finalizer-shutdown|credential-secret-scan|credential-secret-corpus|installed-owner-history)\.ts:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})/gu)) {
        frames.push({ file: `${match[1]}.ts`, line: Number(match[2]), column: Number(match[3]) }); if (frames.length >= 8) break;
      }
      report.error = { diagnosticOnly: true, kind: 'credential_finalizer_shutdown_failed', sourceFrames: frames };
    }
    let bytes: Buffer | undefined, publication: Buffer;
    try {
      bytes = Buffer.from(JSON.stringify(report, null, 2) + '\n'); assert(bytes.length <= 262144); scan(bytes); scanner.close();
      report.secretOutputScan = scanner.stats();
      publication = Buffer.from(JSON.stringify(report, null, 2) + '\n');
    } catch {
      primary ??= new Error('closed finalizer report scan did not qualify'); scanner.close();
      publication = Buffer.from(JSON.stringify({ diagnosticOnly: true, qualified: false, phase: 'secret_scan_or_report_failure',
        installedI1Qualified: false, secretOutputScan: scanner.stats() }) + '\n');
    }
    finally { bytes?.fill(0); }
    try { await writeFile(recipe.reportFile, publication, { flag: 'wx', mode: 0o644 }); }
    catch { primary ??= new Error('closed finalizer report did not publish'); }
    finally { publication.fill(0); }
  }
  if (primary) throw new Error('actual installed finalizer shutdown failed; see the bounded diagnostic report');
}

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert.equal(mode, '--campaign'); assert(filename && extra.length === 0);
await campaign(filename);
