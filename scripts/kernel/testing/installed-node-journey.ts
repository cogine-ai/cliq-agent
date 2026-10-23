// Actual signed Linux installation, public authenticated v1 control, real Node
// verifier and owned HTTPS replies. Not a paid provider, complete fault matrix,
// default/ask policy, macOS, reboot or release-publisher qualification.
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chown, lstat, mkdir, open, readFile, readdir, readlink, stat, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { InstalledClientConsumerDeadlineError, InstalledClientDriverError, openInstalledClientConsumer } from './installed-client-consumer.js';
import { fixtureCommandJoinDiagnostic } from './fixture-command-diagnostic.js';
import { runOwnedEnrollDiagnostic, type InstalledEnrollDiagnostic } from './installed-enroll-diagnostic.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import type { AuthorizationGrantSummaryV1, VerifierIdentityCreateRequest } from '../../../src/kernel/authorization.js';
import { decodeCredentialAuthorityOperation, decodeEndpointAuthorityOperation, type EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { ArtifactDescriptorV1 } from '../../../src/kernel/types.js';
import { decodeRunResult, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';
import { CredentialSecretScanError, createCredentialSecretScanner } from './credential-secret-scan.js';
import { CredentialSecretCorpusError, scanCredentialSecretCorpus } from './credential-secret-corpus.js';
import { inspectInstalledWorkerIdentity, inspectInstalledWorkerRetirement, inspectInstalledWorkerRetirementHistory, inspectInstalledWorkerLaunchIds, type InstalledWorkerIdentityInspection, type InstalledWorkerRetirementBinding } from './installed-worker-lease.js';
import { inspectInstalledOwnerHistory } from './installed-read-control.js';
import { assertInstalledVerifierOutcome, InstalledVerifierOutcomeError } from './installed-verifier-result.js';
import { runInstalledDeliveryCases } from './installed-delivery-journey.js';
import { InstalledDeliveryOutcomeError } from './installed-delivery-result.js';
import type { InstalledVerifierRetirementIdentity } from './installed-verifier-evidence.js';
import { qualifyInstalledOwnerLinks, qualifyInstalledOwnerProcess } from './installed-owner-history.js';
import { startPublicationCrashObserver } from './installed-publication-crash-observer.js';
import { assertInstalledPublicationCleanupRecovery } from './installed-publication-recovery.js';
import { readInstalledNamespaceRetirementJournal } from './installed-publication-journal.js';
import { inspectInstalledPublicationClaim, inspectInstalledRecoveredWorkerRetirement } from './installed-worker-lease.js';

type Recipe = { buildFixture: string; packageRoot: string; installerEntry: string; stateRoot: string; releaseKeysFile: string;
  controlDirectory: string; observer: string; storeFixture: string; publicationObserver: string; workspace: string; reportFile: string };
type Ledger = { diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string; runJourney: Recipe };
type Response = { protocolVersion: 1; ok: boolean; method?: string; result?: Record<string, any>; error?: Record<string, unknown> };
type CaseKind = 'required_pass' | 'required_repair' | 'advisory_failure' | 'required_timeout';
type SourceCaseKind = CaseKind | 'delivery_publish' | 'delivery_merge' | 'delivery_cancel';
const sourceBehavior = (kind: SourceCaseKind): CaseKind =>
  kind === 'delivery_publish' || kind === 'delivery_merge' || kind === 'delivery_cancel' ? 'required_pass' : kind;
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const model = 'installed-node-verifier-fixture';
const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const sourceMetadata = (info: BigIntStats) => Object.fromEntries(imageFields.map(field => [field, info[field].toString()]));
const beforeText = "before the private edit\n";
const afterText = "after the private edit\n";
const fixedText = "fixed after the verifier feedback\n";
const cases: readonly CaseKind[] = ['required_pass', 'required_repair', 'advisory_failure', 'required_timeout'];
const deliverySources = ['delivery_publish', 'delivery_merge', 'delivery_cancel'] as const;

async function bounded<T>(pending: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  // Retain the actual awaiting callsite, not just the later timer callback,
  // for the existing closed source-frame diagnostic.
  const expired = new Error(label);
  try { return await Promise.race([pending, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(expired), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

async function readLedger(filename: string): Promise<Ledger> {
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  let ledger: Ledger;
  try {
    const info = await held.stat();
    assert(info.isFile() && info.uid === 0 && info.nlink === 1 && (info.mode & 0o7777) === 0o444 && info.size <= 65536);
    ledger = parseJsonStrict(await held.readFile('utf8')) as Ledger;
  } finally { await held.close(); }
  assert.equal(ledger.diagnosticOnly, true);
  for (const uid of [ledger.uid, ledger.gid, ledger.runnerUid]) assert(Number.isSafeInteger(uid) && uid > 0);
  assert.equal(ledger.uid, ledger.gid); assert.notEqual(ledger.uid, ledger.runnerUid);
  assert.match(ledger.fixture, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+$/u);
  const info = await lstat(ledger.fixture, { bigint: true });
  assert(info.isDirectory() && !info.isSymbolicLink() && info.uid === 0n && (info.mode & 0o7777n) === 0o755n);
  assert.equal(`${info.dev}:${info.ino}:${info.uid}`, ledger.fixtureIdentity);
  assert.equal(ledger.home, path.join(ledger.fixture, 'home'));
  assert.equal(ledger.username, `cliq-probe-${ledger.fixture.split('.').at(-1)!.toLowerCase()}`);
  const recipe = ledger.runJourney;
  assert.deepEqual(Object.keys(recipe).sort(), ['buildFixture', 'controlDirectory', 'installerEntry', 'observer',
    'packageRoot', 'publicationObserver', 'releaseKeysFile', 'reportFile', 'stateRoot', 'storeFixture', 'workspace'].sort());
  assert.equal(recipe.buildFixture, path.join(ledger.fixture, 'run-package-build'));
  assert.equal(recipe.packageRoot, path.join(recipe.buildFixture, 'package'));
  assert.equal(recipe.installerEntry, path.join(recipe.buildFixture, 'installed-runtime-installer.mjs'));
  assert.equal(recipe.stateRoot, path.join(ledger.home, '.cliq/kernel-v1'));
  assert.equal(recipe.releaseKeysFile, path.join(ledger.fixture, 'run-release-keys.json'));
  assert.equal(recipe.controlDirectory, path.join(ledger.home, 'probe/run-secret-service-control'));
  assert.equal(recipe.observer, path.join(ledger.fixture, 'cliq-credential-journey-observer'));
  assert.equal(recipe.storeFixture, path.join(ledger.fixture, 'cliq-credential-store-fixture'));
  assert.equal(recipe.publicationObserver, path.join(ledger.fixture, 'cliq-publication-cleanup-crash-observer'));
  const publicationObserver = await lstat(recipe.publicationObserver);
  assert(publicationObserver.isFile() && !publicationObserver.isSymbolicLink() && publicationObserver.uid === 0 && publicationObserver.gid === 0 &&
    publicationObserver.nlink === 1 && (publicationObserver.mode & 0o7777) === 0o555);
  const storeFixture = await lstat(recipe.storeFixture);
  assert(storeFixture.isFile() && !storeFixture.isSymbolicLink() && storeFixture.uid === 0 && storeFixture.gid === 0 &&
    storeFixture.nlink === 1 && (storeFixture.mode & 0o7777) === 0o555);
  assert.equal(recipe.workspace, path.join(ledger.home, 'probe/run-workspace'));
  assert(path.isAbsolute(recipe.reportFile) && path.basename(recipe.reportFile) === 'installed-run-journey.json');
  const output = await lstat(path.dirname(recipe.reportFile));
  assert(output.isDirectory() && !output.isSymbolicLink() && output.uid === 0 && (output.mode & 0o7777) === 0o755);
  return ledger;
}

async function transferPackage(filename: string, uid: number, gid: number): Promise<void> {
  const before = await lstat(filename);
  assert(!before.isSymbolicLink() && (before.isDirectory() || before.isFile()));
  assert.equal(before.uid, 0); assert.equal(before.gid, 0);
  if (before.isDirectory()) {
    assert.equal(before.mode & 0o7777, 0o700);
    for (const name of await readdir(filename)) await transferPackage(path.join(filename, name), uid, gid);
  } else { assert.equal(before.nlink, 1); assert([0o400, 0o500].includes(before.mode & 0o7777)); }
  const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | (before.isDirectory() ? constants.O_DIRECTORY : 0));
  try {
    const actual = await held.stat(); assert.equal(actual.dev, before.dev); assert.equal(actual.ino, before.ino);
    assert.equal(actual.uid, 0); assert.equal(actual.gid, 0); await held.chown(uid, gid);
  } finally { await held.close(); }
}




export async function runInstalledNodeJourney(filename: string, journeyKind: 'verifier' | 'delivery',
  options: Readonly<{ publicationRetirementDiagnostics?: true }> = {}): Promise<void> {
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
  assert(journeyKind === 'verifier' || journeyKind === 'delivery');
  assert.deepEqual(Object.keys(options), options.publicationRetirementDiagnostics === true ? ['publicationRetirementDiagnostics'] : []);
  if (options.publicationRetirementDiagnostics) assert.equal(journeyKind, 'delivery');
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.runJourney;
  const installedClientDriver = path.join(recipe.buildFixture, 'installed-control-client-driver.mjs');
  const report: Record<string, any> = { diagnosticOnly: true, qualified: false, phase: 'installation',
    scope: 'actual signed Linux installed Node required/advisory verifier, repair and exhausted timeout using public v1 UDS and owned HTTPS; not actual provider, release, default/ask policy or complete I2/I1 fault qualification',
    actualProviderQualified: false, actualProviderBillingQualified: false, completeI1Qualified: false, completeI2Qualified: false,
    beforeVerifierReleaseStopCutQualified: false, allCrashCutsQualified: false, macosQualified: false, rebootQualified: false };
  if (journeyKind === 'delivery') Object.assign(report, {
    scope: 'actual signed Linux explicit Delivery from verified yolo sources, direct-policy publication, noOp, real verifier merge, cancel and public reconnect/restart; not interactive ask/deny, paid provider, release, reboot or complete I1 qualification',
    interactiveApprovalQualified: false, preciseClaimedCloseCutQualified: false,
  });
  if (options.publicationRetirementDiagnostics) Object.assign(report, {
    // Requested recipe only. The separately retained root-owned filesystem
    // receipt and completed physical lifecycle must establish the real volume.
    storageDelayRequest: { diagnosticOnly: true, kind: 'dm-delay', scope: 'complete-home', readMs: 50, writeMs: 50, flushMs: 50 },
    latePublicationResultQualified: false, preciseInFlightPublicationStopQualified: false,
  });
  const secret = Buffer.from(randomBytes(32).toString('hex')), password = Buffer.from(randomBytes(32).toString('hex'));
  const scanner = createCredentialSecretScanner([secret, password], { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 });
  const scanBytes = (bytes: Uint8Array) => { const stream = scanner.openStream(); try { stream.scan(bytes); } finally { stream.close(); } };
  const mark = (phase: string) => { report.phase = phase; console.log('Installed verifier journey phase ' + phase); };
  const prefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', 'HOME=' + ledger.home, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
    'XDG_RUNTIME_DIR=/run/user/' + ledger.uid, 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + ledger.uid + '/bus'];
  const command = (executable: string, args: string[], input?: Buffer, timeout = 30000) => {
    const started = performance.now();
    const result = spawnSync('/usr/sbin/runuser', [...prefix, executable, ...args], { env: environment, cwd: ledger.home,
      timeout, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, input });
    assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr));
    scanBytes(result.stdout); scanBytes(result.stderr);
    const failure = fixtureCommandJoinDiagnostic(result, timeout, started);
    if (failure) report.commandJoinFailure ??= failure;
    assert.equal(result.error, undefined, 'actual fixture command must join'); assert.equal(result.signal, null);
    return { status: result.status, stdout: result.stdout.toString('utf8'), stderr: result.stderr.toString('utf8') };
  };
  const success = (result: ReturnType<typeof command>, field: string) => {
    assert.equal(result.status, 0, 'same-user installed command refused');
    const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
    assert.deepEqual(Object.keys(value).sort(), ['schemaVersion', field].sort()); assert.equal(value.schemaVersion, 1);
    assert.equal(result.stdout, canonicalJsonBytes(value).toString('utf8') + '\n'); return value[field];
  };
  const credential = (metadata: Record<string, unknown>, input?: Buffer) => command(path.join(recipe.stateRoot, 'runtime/bootstrap'),
    ['--bootstrap-credential', canonicalJsonBytes(metadata).toString('base64url')], input, 60000);
  let requestOrdinal = 0;
  const nextId = () => '019a0013-0000-7000-8000-' + String(++requestOrdinal).padStart(12, '0');
  const request = <T extends Record<string, unknown>>(core: T): T & { requestDigest: string } => ({ ...core, requestDigest: canonicalSha256(core) });
  const accepted = (response: Response, method: string) => {
    if (!response.ok) report.lastRefusal = { method,
      code: ['INVALID_REQUEST', 'INTERNAL', 'AUTHORIZATION_REQUIRED', 'UNSUPPORTED_EXECUTION_IDENTITY', 'ARTIFACT_MISMATCH',
        'UNSUPPORTED_PLATFORM', 'REVISION_CONFLICT', 'BUDGET_EXHAUSTED', 'RATE_LIMITED'].includes(response.error?.code as string)
        ? response.error!.code : 'unclassified' };
    assert.equal(response.protocolVersion, 1); assert.equal(response.ok, true, 'actual installed method must be accepted: ' + method);
    assert(response.result && response.result.method === method); return response.result;
  };
  const persistentClient = async () => {
    const client = await openInstalledClientConsumer({ executable: '/usr/sbin/runuser',
      args: [...prefix, process.execPath, '--disable-warning=ExperimentalWarning', installedClientDriver, filename], cwd: ledger.home, env: environment,
      openScan: () => scanner.openStream(), onJoined: () => { report.originalPublicClientJoined = true; } });
    assert(Array.isArray(client.hello.enabledFeatureIds) && client.hello.enabledFeatureIds.includes('artifact.get'));
    return client;
  };
  const withRetainedUnitHistory = async (units: readonly [string, string], body: (assertRetained: () => void) => Promise<void>): Promise<void> => {
    assert.equal(units.length, 2);
    const observers: Record<string, unknown>[] = report.unitExitHistoryObservers ??= [];
    assert(observers.length < 8, 'unit-history observations exceed their fixed diagnostic bound');
    const diagnostic: Record<string, unknown> = { diagnosticOnly: true, ordinal: observers.length + 1,
      phaseWhenStarted: report.phase, fixedInputDeadlineMs: 10000, retainedFrameObserved: false,
      exitObservedBeforeRelease: false, releaseInputRefused: false, processAndPipesJoined: false, qualified: false };
    observers.push(diagnostic);
    report.unitExitHistoryObserverJoined = false;
    const outScan = scanner.openStream();
    let errorScan: ReturnType<typeof scanner.openStream>;
    try { errorScan = scanner.openStream(); } catch (error) { outScan.close(); throw error; }
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn('/usr/sbin/runuser', [...prefix, recipe.observer, 'retain-systemd', ...units],
        { env: environment, cwd: ledger.home, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (error) { outScan.close(); errorScan.close(); throw error; }
    const retained = 'systemd_units_retained\n', released = `${retained}systemd_units_released\n`;
    let output = '', bytes = 0, errorBytes = 0, errorText = '', observationError: unknown, releasing = false;
    let readyResolve!: () => void, readyReject!: (error: unknown) => void;
    const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const refuse = (error: unknown) => { observationError ??= error; readyReject(error); };
    child.stdout.on('data', (chunk: Buffer) => {
      try {
        outScan.scan(chunk); bytes += chunk.length; assert(bytes <= 1024, 'unit-history observer output exceeded its bound');
        output += chunk.toString('utf8');
        assert(released.startsWith(output), 'unit-history observer emitted an invalid fixed frame');
        assert(releasing || output.length <= retained.length, 'unit-history observer released before exit observation');
        if (output === retained) { diagnostic.retainedFrameObserved = true; readyResolve(); }
      } catch (error) { refuse(error); }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      try {
        errorScan.scan(chunk); errorBytes += chunk.length; assert(errorBytes <= 1024, 'unit-history observer errors exceeded their bound');
        // Retain only this fixed source-owned classification, never stderr.
        errorText += chunk.toString('utf8');
        if (errorText.includes('secret-service-probe: phase=observer-systemd-release-input errorDomain='))
          diagnostic.releaseInputRefused = true;
      }
      catch (error) { refuse(error); }
    });
    child.stdin.on('error', refuse); child.stdout.on('error', refuse); child.stderr.on('error', refuse);
    const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
      child.once('error', refuse);
      child.once('close', (code, signal) => {
        outScan.close(); errorScan.close();
        diagnostic.exitCode = code;
        diagnostic.signal = signal === null || signal === 'SIGTERM' || signal === 'SIGKILL' ? signal : 'other';
        diagnostic.exitObservedBeforeRelease = !releasing;
        diagnostic.processAndPipesJoined = true;
        if (!releasing) refuse(new Error('unit-history observer exited before release'));
        resolve({ code, signal });
      });
    });
    const failures: unknown[] = [];
    try {
      await bounded(Promise.race([ready, closed.then(() => { throw new Error('unit-history observer closed before readiness'); })]),
        10000, 'unit-history observer did not retain the actual units');
      await body(() => {
        assert.equal(observationError, undefined, 'original unit-history observer must remain healthy before stop');
        assert.equal(child.exitCode, null); assert.equal(child.signalCode, null);
        assert.equal(output, retained); assert.equal(errorBytes, 0);
      });
    } catch (error) { failures.push(error); }
    finally {
      releasing = true;
      try {
        child.stdin.end('R');
        const exit = await bounded(closed, 10000, 'unit-history observer did not release and join');
        assert.equal(exit.signal, null); assert.equal(exit.code, 0); assert.equal(observationError, undefined);
        assert.equal(output, released); assert.equal(errorBytes, 0);
        diagnostic.qualified = true;
      } catch (error) { failures.push(error); }
      report.unitExitHistoryObserverJoined = observers.every(observation => observation.qualified === true);
      errorText = '';
    }
    if (failures.length) throw new AggregateError(failures, 'actual unit exit history was not retained and joined');
  };

  const show = (unit: string): Record<string, string> => {
    const result = command('/usr/bin/systemctl', ['--user', 'show', unit,
      '--property=Id,ActiveState,SubState,MainPID,ExecMainPID,InvocationID,ControlGroup,Type,Delegate,KillMode,Result,ExecMainCode,ExecMainStatus,TimeoutStopUSec', '--no-pager']);
    assert.equal(result.status, 0);
    return Object.fromEntries(result.stdout.trim().split('\n').map(line => { const at = line.indexOf('='); assert(at > 0); return [line.slice(0, at), line.slice(at + 1)]; }));
  };
  const processStart = async (pid: number) => {
    assert(Number.isSafeInteger(pid) && pid > 0);
    const text = await readFile('/proc/' + pid + '/stat', 'utf8'); assert(text.length <= 8192 && text.startsWith(pid + ' ('));
    const fields = text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/u); assert(!['Z', 'X', 'x'].includes(fields[0]!));
    assert.match(fields[19]!, /^[1-9][0-9]*$/u); return fields[19]!;
  };
  const assertVerifierProcessesAbsent = async (retirement: InstalledVerifierRetirementIdentity) => {
    assert.equal(retirement.processes.length, 3);
    for (const identity of retirement.processes) {
      // A retained native death object does not itself observe /proc.
      // Independently reject this exact process lifetime if still live.
      try { assert.notEqual(await processStart(identity.pid), identity.startTicks); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
  };
  const fixtureProcess = async (pid: number, uid: number, parent?: number) => {
    const original = await processStart(pid), text = await readFile('/proc/' + pid + '/status', 'utf8'); assert(text.length <= 65536);
    const actualUid = text.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu), actualParent = text.match(/^PPid:\s+(\d+)$/mu);
    assert(actualUid && actualUid.slice(1).every(value => Number(value) === uid));
    if (parent !== undefined) assert(actualParent && Number(actualParent[1]) === parent);
    assert.equal(await processStart(pid), original); return original;
  };
  const readCas = async (ref: string): Promise<Buffer> => {
    assert.match(ref, /^[0-9a-f]{64}$/u);
    const name = path.join(recipe.stateRoot, 'cas', ref), held = await open(name, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await held.stat({ bigint: true }); assert(before.isFile() && before.uid === BigInt(ledger.uid) &&
        before.nlink === 1n && (before.mode & 0o7777n) === 0o400n && before.size <= 1048576n);
      const bytes = await held.readFile(), after = await held.stat({ bigint: true }), named = await lstat(name, { bigint: true });
      for (const field of imageFields) { assert.equal(after[field], before[field]); assert.equal(named[field], before[field]); }
      assert.equal(sha256Bytes(bytes), ref); scanBytes(bytes); return bytes;
    } finally { await held.close(); }
  };
  const observeSecretService = () => {
    const result = command(recipe.observer, ['list']); assert.equal(result.status, 0);
    const value = parseJsonStrict(result.stdout.trim()) as Record<string, any>;
    assert.equal(value.serviceUid, ledger.uid); assert.equal(value.connectionClosed, true); assert(Array.isArray(value.items)); return value;
  };
  let server: Server | undefined, daemon: ChildProcess | undefined, daemonExit: Promise<void> | undefined;
  let daemonPid: number | undefined, daemonStart: string | undefined;
  let services: { supervisorUnit: string; keeperUnit: string } | undefined;
  let client: Awaited<ReturnType<typeof persistentClient>> | undefined, inspectionClient: Awaited<ReturnType<typeof persistentClient>> | undefined;
  let primary: unknown, responderFailure = false, acceptedTcp = 0, acceptedTls = 0, postCount = 0;
  const responderErrors: unknown[] = [];
  const noteResponderFailure = (error: unknown) => {
    responderFailure = true;
    if (!responderErrors.length) responderErrors.push(error);
  };
  const sockets: Promise<void>[] = [];
  const activeCases = new Map<SourceCaseKind, { runId: string; posts: number; identities: InstalledWorkerIdentityInspection[] }>();
  const completed: Array<{ kind: CaseKind; cut: Record<string, any>; sessionCut: Record<string, any>; submit: Record<string, unknown>;
    admission: Response; resultQueries: Response[]; files: readonly { path: string; before: string; after: string }[];
    workspace: string; sourceIdentity: Map<string, Record<string, string>> }> = [];
  const send = async (body: Record<string, unknown>, method: string, timeout = 5000) => {
    assert(client); return accepted(await client.send(body, timeout), method);
  };
  // Retained comparison bytes only: every fresh/restarted client must still
  // download the complete object again. Never use this map as an I/O shortcut.
  const originalPublicResultBytes = new Map<string, Buffer>();
  const readPublicArtifact = async (ref: string, expectedDescriptor?: ArtifactDescriptorV1): Promise<Buffer> => {
    assert(client); assert.match(ref, /^[a-f0-9]{64}$/u);
    let artifact: ArtifactDescriptorV1 | undefined, bytes: Buffer | undefined;
    let offset = 0, pages = 0;
    for (;;) {
      assert(++pages <= 18, 'bounded public result download must make progress');
      // Force a real non-EOF first page even for these small typed artifacts;
      // subsequent 4 MiB requests exercise the unchanged short-response cap.
      const length = offset === 0 ? 17 : 4 * 1024 * 1024;
      const response = await client.send({ protocolVersion: 1, method: 'artifact.get', digest: ref, offset, length });
      assert(canonicalJsonBytes(response).length < 1_048_576);
      const result = accepted(response, 'artifact.get');
      artifact ??= result.artifact;
      assert(artifact && artifact.schemaVersion === 1 && artifact.ref === ref && artifact.digest === ref &&
        typeof artifact.mediaType === 'string' && artifact.mediaType.length > 0 && Buffer.byteLength(artifact.mediaType) <= 128 && Number.isSafeInteger(artifact.sizeBytes) &&
        artifact.sizeBytes >= 0 && artifact.sizeBytes <= 1_048_576);
      if (expectedDescriptor) assert.equal(canonicalSha256(artifact), canonicalSha256(expectedDescriptor));
      bytes ??= Buffer.alloc(artifact.sizeBytes);
      assert.equal(typeof result.bytesBase64, 'string'); assert(result.bytesBase64.length <= 87_384);
      const chunk = Buffer.from(result.bytesBase64, 'base64');
      assert.equal(chunk.toString('base64'), result.bytesBase64, 'artifact bytes must use canonical base64');
      assert(chunk.length <= Math.min(length, 65_536, artifact.sizeBytes - offset));
      const nextOffset = offset + chunk.length, eof = nextOffset === artifact.sizeBytes;
      assert.equal(canonicalSha256(response), canonicalSha256({ protocolVersion: 1, ok: true, result: {
        method: 'artifact.get', artifact, offset, bytesBase64: result.bytesBase64, nextOffset, eof } }));
      chunk.copy(bytes, offset); offset = nextOffset;
      if (eof) break;
      assert(chunk.length > 0, 'a non-EOF artifact page must advance the exact offset');
    }
    assert(artifact && bytes); assert.equal(offset, artifact.sizeBytes); if (expectedDescriptor) assert(pages >= 2);
    assert.equal(sha256Bytes(bytes), ref); scanBytes(bytes); return bytes;
  };
  const downloadArtifact = async (artifact: ArtifactDescriptorV1, expected: Buffer): Promise<Buffer> => {
    assert.match(artifact.ref, /^[a-f0-9]{64}$/u); assert.equal(artifact.digest, artifact.ref);
    assert.equal(artifact.schemaVersion, 1); assert.equal(artifact.mediaType, 'application/json');
    assert.equal(artifact.sizeBytes, expected.length); assert(expected.length > 0 && expected.length <= 1_048_576);
    const bytes = await readPublicArtifact(artifact.ref, artifact); assert(bytes.equals(expected));
    const original = originalPublicResultBytes.get(artifact.ref);
    if (original) assert(bytes.equals(original), 'reconnect/restart must preserve the exact original downloaded bytes');
    else { originalPublicResultBytes.set(artifact.ref, Buffer.from(bytes)); assert(originalPublicResultBytes.size <= 6); }
    return bytes;
  };
  const resultQueries = async (cut: Record<string, any>): Promise<Response[]> => {
    const run = cut.snapshot.run; assert(client);
    const expectedResultBytes = run.resultRef ? await readCas(run.resultRef) : undefined;
    const expectedResult = expectedResultBytes
      ? decodeRunResult(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(expectedResultBytes))) : undefined;
    if (expectedResult) { assert.equal(expectedResult.runId, run.id); assert(canonicalJsonBytes(expectedResult).equals(expectedResultBytes!)); }
    const replies: Response[] = [];
    for (const method of ['run.result', 'run.diff']) {
      const response = await client.send({ protocolVersion: 1, method, runId: run.id }); replies.push(response);
      if (!run.resultRef) {
        assert.equal(canonicalSha256(response), canonicalSha256({ protocolVersion: 1, ok: false, method, error: {
          schemaVersion: 1, code: 'RESULT_UNAVAILABLE', messageCode: 'run.result_unavailable', retryable: false,
          runId: run.id, status: run.status, terminalDetailRef: run.terminalDetailRef } }));
      } else {
        assert(expectedResult && expectedResultBytes); const result = expectedResult;
        const ref = method === 'run.result' ? run.resultRef : result.diffRef;
        const expected = method === 'run.result' ? expectedResultBytes : await readCas(ref);
        const descriptor: ArtifactDescriptorV1 = { schemaVersion: 1, ref, digest: ref, sizeBytes: expected.length, mediaType: 'application/json' };
        assert.equal(canonicalSha256(response), canonicalSha256({ protocolVersion: 1, ok: true, result: method === 'run.result'
          ? { method, runId: run.id, result: descriptor, verificationClosureRef: result.verificationClosureRef }
          : { method, runId: run.id, diff: descriptor } }));
        const downloaded = await downloadArtifact(descriptor, expected);
        const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(downloaded));
        assert(canonicalJsonBytes(value).equals(downloaded));
        if (method === 'run.result') assert.deepEqual(decodeRunResult(value), result);
        else {
          const diff = decodeWorkspaceDiff(value);
          assert.equal(diff.baseSourceRef, result.baseSourceRef); assert.equal(diff.resultSourceRef, result.resultSourceRef);
          assert.deepEqual(diff, decodeWorkspaceDiff(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(expected))));
        }
      }
    }
    assert.deepEqual(await send({ protocolVersion: 1, method: 'run.get', runId: run.id }, 'run.get'), cut,
      'public artifact reads must not append a Journal, execute a tool or change the terminal Run');
    return replies;
  };
  const selectedSupervisor = async (unit: string, shown: Record<string, string>, image: string, by: number) => {
    const pid = Number(shown.MainPID), start = await fixtureProcess(pid, ledger.uid);
    for (;;) {
      assert(Date.now() < by, 'installed image handoff exceeded the original 30-second restart budget');
      assert.equal(await fixtureProcess(pid, ledger.uid), start);
      const actual = await readlink('/proc/' + pid + '/exe');
      if (actual === image) break;
      assert.equal(actual, path.join(recipe.stateRoot, 'runtime/bootstrap')); await delay(50);
    }
    const actual = await stat('/proc/' + pid + '/exe', { bigint: true }), named = await lstat(image, { bigint: true });
    for (const field of imageFields) assert.equal(actual[field], named[field]);
    for (;;) {
      assert(Date.now() < by, 'public control readiness exceeded the original restart budget');
      try { const socket = await lstat(path.join(recipe.stateRoot, 'runtime/control-v1.sock')); assert(socket.isSocket() && socket.uid === ledger.uid); break; }
      catch (error) { assert.equal((error as NodeJS.ErrnoException).code, 'ENOENT'); await delay(50); }
    }
    const confirmed = show(unit); for (const field of ['MainPID', 'ExecMainPID', 'InvocationID', 'ActiveState']) assert.equal(confirmed[field], shown[field]);
    assert.equal(await fixtureProcess(pid, ledger.uid), start); assert.equal(await readlink('/proc/' + pid + '/exe'), image);
    return start;
  };

  try {
    mark('owned_https_and_signed_guest_package');
    await mkdir(recipe.buildFixture, { mode: 0o755 });
    const keyPath = path.join(recipe.buildFixture, 'owned-https-key.pem'), certPath = path.join(recipe.buildFixture, 'owned-https-cert.pem');
    const certificate = spawnSync('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
      '-days', '2', '-subj', '/CN=installed-verifier-fixture.invalid', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:installed-verifier-fixture.invalid'],
    { env: environment, timeout: 10000, maxBuffer: 65536 });
    assert.equal(certificate.error, undefined); assert.equal(certificate.signal, null); assert.equal(certificate.status, 0);
    const key = await readFile(keyPath), cert = await readFile(certPath);
    server = createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', maxHeaderSize: 65536 }, async (incoming, outgoing) => {
      try {
        assert.equal(incoming.method, 'POST'); assert.equal(incoming.url, '/v1/chat/completions');
        assert.equal(incoming.headers.authorization, 'Bearer ' + secret.toString('utf8'));
        assert.equal(incoming.headers['content-type'], 'application/json');
        const chunks: Buffer[] = []; let size = 0;
        for await (const value of incoming) { size += value.length; assert(size <= 1048576); chunks.push(Buffer.from(value)); }
        const bytes = Buffer.concat(chunks); scanBytes(bytes); assert.equal(Number(incoming.headers['content-length']), bytes.length);
        const body = parseJsonStrict(bytes.toString('utf8')) as Record<string, any>;
        assert.equal(body.model, model); assert.equal(body.stream, false); assert.equal(body.max_tokens, 4096);
        assert.deepEqual(body.tools.map((entry: any) => entry.function.name), ['edit']);
        const matches = [...cases, ...deliverySources].filter(kind => body.messages.some((entry: any) => entry.role === 'user' &&
          typeof entry.content === 'string' && entry.content.includes('Owned installed verifier case: ' + kind + '.')));
        assert.equal(matches.length, 1); const sourceKind = matches[0]!, kind = sourceBehavior(sourceKind);
        const registeredBy = Date.now() + 5000;
        while (!activeCases.has(sourceKind)) { assert(Date.now() < registeredBy); await delay(10); }
        const active = activeCases.get(sourceKind)!; const ordinal = ++active.posts; postCount++;
        assert(ordinal <= (kind === 'required_repair' ? 4 : kind === 'required_pass' ? 2 : 1), 'completed or unknown claims must not resend model requests');
        const edit = kind === 'required_pass' && ordinal === 1 || kind === 'required_repair' && (ordinal === 1 || ordinal === 3);
        const callId = 'owned-verifier-edit-' + ordinal;
        if (ordinal > 1) {
          assert.equal(body.messages.filter((entry: any) => entry.role === 'tool' && entry.tool_call_id === 'owned-verifier-edit-' + (ordinal % 2 === 0 ? ordinal - 1 : 1)).length, 1);
        }
        if (kind === 'required_repair' && ordinal === 3) {
          assert(body.messages.some((entry: any) => typeof entry.content === 'string' &&
            entry.content.includes('Verifier "node-tests" failed an assertion (exit 1). Revise the candidate and try again.')), 'the second model turn must consume the actual bounded repair diagnostic');
        }
        // Hold only this real response while observing the already-running
        // original worker. No process pause, fake launch, SQL write or proof.
        if (!edit) {
          assert(inspectionClient);
          const cut = accepted(await inspectionClient.send({ protocolVersion: 1, method: 'run.get', runId: active.runId }), 'run.get');
          const run = cut.snapshot.run; assert(run.activeWorkerLaunchId);
          const status = accepted(await inspectionClient.send({ protocolVersion: 1, method: 'supervisor.status' }), 'supervisor.status');
          const observed = inspectInstalledWorkerIdentity(recipe.stateRoot, { uid: ledger.uid, runId: run.id,
            launchId: run.activeWorkerLaunchId, leaseEpoch: run.leaseEpoch, runRevision: run.revision,
            supervisorInstanceId: status.supervisorInstanceId, deadlineAt: run.deadlineAt });
          assert.equal('linux-proc-start-ticks:' + await fixtureProcess(observed.pid, ledger.uid), observed.processStartToken);
          active.identities.push(observed);
          for (const method of ['run.result', 'run.diff']) {
            const unavailable = await inspectionClient.send({ protocolVersion: 1, method, runId: run.id });
            assert.equal(canonicalSha256(unavailable), canonicalSha256({ protocolVersion: 1, ok: false, method, error: {
              schemaVersion: 1, code: 'RESULT_UNAVAILABLE', messageCode: 'run.result_unavailable', retryable: true,
              runId: run.id, status: run.status, currentRevision: run.revision } }));
          }
        }
        const payload = { id: 'owned-' + kind + '-' + ordinal, object: 'chat.completion', model,
          choices: [{ index: 0, finish_reason: edit ? 'tool_calls' : 'stop', message: edit
            ? { role: 'assistant', content: '', tool_calls: [{ id: callId, type: 'function', function: { name: 'edit',
              arguments: JSON.stringify({ path: 'example.txt', old_text: ordinal === 3 ? afterText : beforeText,
                new_text: ordinal === 3 ? fixedText : afterText }) } }] }
            : { role: 'assistant', content: 'The owned candidate is ready for its frozen Node verifier.' } }],
          usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
        const response = Buffer.from(JSON.stringify(payload)); scanBytes(response);
        outgoing.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(response.length), Connection: 'close' }); outgoing.end(response);
        report.transport = { postCount, acceptedTcp, acceptedTls, tls13: true, exactCredentialMatched: true };
      } catch (error) { noteResponderFailure(error); incoming.destroy(); outgoing.destroy(); }
    });
    server.on('connection', socket => { acceptedTcp++; sockets.push(new Promise<void>(resolve => socket.once('close', resolve))); });
    server.on('secureConnection', socket => { acceptedTls++; if (socket.getProtocol() !== 'TLSv1.3') { noteResponderFailure(new Error('owned responder TLS version refused')); socket.destroy(); } });
    server.on('tlsClientError', () => { noteResponderFailure(new Error('owned responder TLS handshake refused')); });
    await new Promise<void>((resolve, reject) => { server!.once('error', reject); server!.listen(0, '127.0.0.1', resolve); });
    key.fill(0); const address = server.address(); assert(address && typeof address === 'object');
    const pin = sha256Bytes(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' }));
    const signed = await buildInstalledSupervisorPackage(recipe.buildFixture, 'complete', { provider: 'openai-compatible', model,
      target: { hostAscii: '127.0.0.1', port: address.port, basePath: '/v1' },
      tls: { serverNameAscii: 'installed-verifier-fixture.invalid', caPem: cert, spkiSha256Pins: [pin] },
      claims: { nativeToolCalling: true, streaming: false, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 4096 },
      requestTokenCeiling: { inputTokens: 32768, outputTokens: 4096, cacheReadTokens: 0, cacheWriteTokens: 0 },
      validFrom: new Date(Date.now() - 60000).toISOString(), validThrough: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() },
    { guestToolchain: 'node-test-v1', publicationRetirementDiagnostics: options.publicationRetirementDiagnostics });
    assert(signed.guestToolchain && signed.modelAuthority);
    const installer = await build({ entryPoints: [fileURLToPath(new URL('./installed-runtime-installer.ts', import.meta.url))],
      outfile: recipe.installerEntry, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', metafile: true, write: false });
    assert(Object.values(installer.metafile!.outputs).flatMap(value => value.imports).every(value => value.external && value.path.startsWith('node:')));
    assert.equal(installer.outputFiles!.length, 1);
    await writeFile(recipe.installerEntry, installer.outputFiles![0]!.contents, { flag: 'wx', mode: 0o444 });
    const consumer = await build({ entryPoints: [fileURLToPath(new URL('./installed-control-client-driver.ts', import.meta.url))],
      outfile: installedClientDriver, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', metafile: true, write: false });
    assert(Object.values(consumer.metafile!.outputs).flatMap(value => value.imports).every(value => value.external && value.path.startsWith('node:')));
    assert.equal(consumer.outputFiles!.length, 1); assert(consumer.outputFiles![0]!.contents.length <= 16 * 1024 * 1024);
    await writeFile(installedClientDriver, consumer.outputFiles![0]!.contents, { flag: 'wx', mode: 0o444 });
    await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(signed.releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(recipe.packageRoot, ledger.uid, ledger.gid);
    const cliqHome = path.join(ledger.home, '.cliq'); await mkdir(cliqHome, { mode: 0o700 }); await chown(cliqHome, ledger.uid, ledger.gid);
    const installation = command(process.execPath, [recipe.installerEntry, recipe.packageRoot, recipe.stateRoot, recipe.releaseKeysFile]);
    assert.equal(installation.status, 0);
    const bundleDigest = (parseJsonStrict(installation.stdout.trim()) as { bundleDigest: string }).bundleDigest;
    assert.equal(bundleDigest, canonicalSha256(signed.bundle));
    const imageRef = signed.guestToolchain.manifest.guestImageRef;
    const guestImageEntry = signed.bundle.entries.filter(entry => entry.digest === imageRef);
    assert.equal(guestImageEntry.length, 1); assert.equal(guestImageEntry[0]!.executable, false);
    const imageCopies = [
      { filename: path.join(recipe.buildFixture, 'guest-image/guest-toolchain.ext4'), uid: 0 },
      { filename: path.join(recipe.packageRoot, guestImageEntry[0]!.relativePath), uid: ledger.uid },
      { filename: path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, guestImageEntry[0]!.relativePath), uid: ledger.uid },
      { filename: path.join(recipe.stateRoot, 'cas', imageRef), uid: ledger.uid },
    ];
    const imageInodes = new Set<string>();
    for (const copy of imageCopies) {
      const metadata = await lstat(copy.filename, { bigint: true });
      assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.uid === BigInt(copy.uid) && metadata.nlink === 1n &&
        (metadata.mode & 0o7777n) === 0o400n && metadata.size === BigInt(signed.guestToolchain.manifest.guestImageByteCount));
      imageInodes.add(metadata.dev + ':' + metadata.ino);
    }
    assert.equal(imageInodes.size, 4, 'the build, source package, installed package and single CAS image must be distinct real files');
    report.bundle = { bundleDigest, manifestDigest: signed.bundle.manifestDigest,
      guestToolchainManifestRef: signed.guestToolchain.manifestRef, guestImageRef: signed.guestToolchain.manifest.guestImageRef,
      guestImageByteCount: signed.guestToolchain.manifest.guestImageByteCount,
      actualReadOnlyImageCopies: imageCopies.length, totalImageCopyBytes: imageCopies.length * signed.guestToolchain.manifest.guestImageByteCount,
      imageCopiesInCompleteSecretWriterCorpus: 1, unchangedCorpusByteLimit: 512 * 1024 * 1024, unchangedCorpusStreamLimit: 4096 };
    mark('actual_secret_service_and_credential');
    await mkdir(recipe.controlDirectory, { mode: 0o700 }); await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
    daemon = spawn('/usr/sbin/runuser', [...prefix, '/usr/bin/gnome-keyring-daemon', '--foreground', '--components=secrets', '--unlock',
      '--control-directory=' + recipe.controlDirectory], { env: environment, stdio: ['pipe', 'ignore', 'ignore'] });
    daemonExit = new Promise<void>((resolve, reject) => { daemon!.once('close', () => resolve()); daemon!.once('error', reject); });
    daemon.stdin!.on('error', () => {}); daemon.stdin!.end(password);
    const serviceBy = Date.now() + 10000;
    for (;;) {
      const owner = command('/usr/bin/busctl', ['--address=unix:path=/run/user/' + ledger.uid + '/bus', 'call', 'org.freedesktop.DBus',
        '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']);
      assert.equal(owner.status, 0); if (owner.stdout.trim() === 'b true') break;
      assert(Date.now() < serviceBy && daemon.exitCode === null); await delay(20);
    }
    const platform = observeSecretService(); assert.deepEqual(platform.items, []); assert(daemon.pid);
    await fixtureProcess(daemon.pid, 0, process.pid);
    daemonPid = platform.servicePid; daemonStart = await fixtureProcess(daemonPid!, ledger.uid, daemon.pid);
    assert.equal(await readlink('/proc/' + daemonPid + '/exe'), '/usr/bin/gnome-keyring-daemon');
    const daemonImage = await stat('/proc/' + daemonPid + '/exe', { bigint: true }), namedDaemon = await lstat('/usr/bin/gnome-keyring-daemon', { bigint: true });
    for (const field of imageFields) assert.equal(daemonImage[field], namedDaemon[field]);
    const setup = credential({ schemaVersion: 1, kind: 'install_services' }); assert.equal(setup.status, 0);
    const installed = parseJsonStrict(setup.stdout.trim()) as { schemaVersion: 1; supervisorUnit: string; keeperUnit: string };
    assert.deepEqual(Object.keys(installed).sort(), ['schemaVersion', 'supervisorUnit', 'keeperUnit'].sort()); assert.equal(installed.schemaVersion, 1);
    for (const unit of [installed.supervisorUnit, installed.keeperUnit]) assert.match(unit, /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,240}\.service$/u);
    services = installed;
    const root = await lstat(recipe.stateRoot, { bigint: true });
    const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: root.dev.toString(), directoryFileId: root.ino.toString(),
      mode: 448, openedNoFollow: true, layoutVersion: 1 });
    const principal = identityHash('cliq-local-principal-v1', rootDigest, 'linux', ledger.uid);
    const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1',
      endpointRegistrationId: 'installed-verifier-endpoint', registrationKind: 'user', ownerPrincipalId: principal,
      purposes: ['model_endpoint'], ...signed.modelAuthority.endpoint, createdAt: new Date().toISOString(), registrationDigest: '' };
    registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
    const registerCore = { schemaVersion: 1, kind: 'register', ownerPrincipalId: principal, registration,
      expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' };
    const registered = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], canonicalJsonBytes({
      schemaVersion: 1, kind: 'commit', requestId: nextId(), commandCore: { ...registerCore, commandDigest: digestOmitting(registerCore, 'commandDigest') } }));
    assert.equal(decodeEndpointAuthorityOperation(success(registered, 'operation')).disposition, 'registered');
    const credentialId = 'installed-verifier-credential';
    const enrollment = { schemaVersion: 1, kind: 'enroll', requestId: nextId(), credentialGrantId: credentialId,
      purpose: 'model_endpoint', endpointRegistrationId: registration.endpointRegistrationId,
      secretSubmissionId: 'installed-verifier-fixture-secret', expiresAt: '2099-01-01T00:00:00.000Z' };
    const enrollDiagnostic = {} as InstalledEnrollDiagnostic;
    report.enrollDiagnostic = enrollDiagnostic;
    const summarizeUnits = () => {
      const precedingFailure = report.commandJoinFailure;
      const summary = (unit: string) => {
        const value = show(unit);
        const activeState = ['active', 'activating', 'inactive', 'deactivating', 'failed', 'reloading', 'maintenance'].includes(value.ActiveState!)
          ? value.ActiveState : 'other';
        const subState = ['running', 'dead', 'failed', 'start', 'start-pre', 'start-post', 'exited', 'auto-restart',
          'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-sigterm', 'final-sigkill'].includes(value.SubState!) ? value.SubState : 'other';
        return { activeState, subState };
      };
      try { return { keeper: summary(installed.keeperUnit), supervisor: summary(installed.supervisorUnit) }; }
      catch { return { kind: 'unavailable' }; }
      finally {
        // Diagnostic-only probes do not replace the main command's original
        // failure classification or invent a new admission requirement.
        if (precedingFailure === undefined) delete report.commandJoinFailure;
        else report.commandJoinFailure = precedingFailure;
      }
    };
    // Live sampling performs no synchronous external command. These two fixed
    // manager cuts lie outside the original 60s enroll lifetime, not inside a
    // timer callback that could prevent it from firing on time.
    report.enrollUnitStates = { before: summarizeUnits(), liveObserved: false, afterJoin: { kind: 'unavailable' } };
    let enrollmentResult: Awaited<ReturnType<typeof runOwnedEnrollDiagnostic>>;
    const enrollmentStarted = performance.now();
    try {
      enrollmentResult = await runOwnedEnrollDiagnostic({ command: { executable: '/usr/sbin/runuser',
        args: [...prefix, path.join(recipe.stateRoot, 'runtime/bootstrap'), '--bootstrap-credential', canonicalJsonBytes(enrollment).toString('base64url')],
        env: environment, cwd: ledger.home }, input: secret, uid: ledger.uid,
        bootstrapImage: path.join(recipe.stateRoot, 'runtime/bootstrap'),
        installedImage: path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor'), originalDeadlineMs: 60000,
        scanner, diagnostic: enrollDiagnostic, observeOwner: () => {
          try {
            const owners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
            if (owners.length > 2) return { kind: 'unavailable' };
            const owner = owners.at(-1);
            return owner ? { kind: owner.state === 'active' ? 'active' : 'terminal', epoch: owner.ownerEpoch } : { kind: 'absent' };
          } catch (error) {
            const value = error as { code?: unknown; errcode?: unknown };
            return { kind: value?.code === 'ERR_SQLITE_ERROR' && typeof value.errcode === 'number' && (value.errcode & 255) === 5 ? 'busy' : 'unavailable' };
          }
        } });
      const enrollmentFailure = fixtureCommandJoinDiagnostic(enrollmentResult, 60000, enrollmentStarted);
      if (enrollmentFailure) report.commandJoinFailure ??= enrollmentFailure;
    } finally {
      if (enrollDiagnostic.processAndPipesJoined && enrollDiagnostic.authJoined) report.enrollUnitStates.afterJoin = summarizeUnits();
      // A plain Node SQLite path cannot honestly guarantee both no-follow and
      // the original live WAL identity. Never open the main FD with a wrong
      // sidecar path, create raw snapshots, or call unreadable state absent.
      report.enrollCredentialAfterJoin = { kind: 'unavailable', reason: 'no_safe_readonly_wal_reader' };
    }
    assert.equal(enrollmentResult.error, undefined, 'actual fixture command must join'); assert.equal(enrollmentResult.signal, null);
    const enrolled = decodeCredentialAuthorityOperation(success(enrollmentResult, 'operation'));
    assert.equal(enrolled.phase, 'committed'); assert.equal(enrolled.ownerPrincipalId, principal); assert.equal(enrolled.attempt, 1);
    const enrolledPlatform = observeSecretService(); assert.equal(enrolledPlatform.items.length, 1);
    assert.equal(enrolledPlatform.servicePid, platform.servicePid); assert.equal(enrolledPlatform.nameOwner, platform.nameOwner);
    const keeperBefore = show(services.keeperUnit), supervisorBefore = show(services.supervisorUnit);
    const installedImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
    for (const shown of [keeperBefore, supervisorBefore]) {
      assert.equal(shown.ActiveState, 'active'); assert.equal(shown.SubState, 'running'); assert.equal(shown.MainPID, shown.ExecMainPID);
      assert.equal(shown.Type, 'exec'); assert.equal(shown.Delegate, 'yes'); assert.equal(shown.KillMode, 'control-group');
      assert.equal(shown.TimeoutStopUSec, '2s'); assert.match(shown.InvocationID!, /^[0-9a-f]{32}$/u);
      assert.equal(await readlink('/proc/' + shown.MainPID + '/exe'), installedImage);
    }
    const keeperReady = await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready'));
    client = await persistentClient(); inspectionClient = await persistentClient();
    assert.equal((await send({ protocolVersion: 1, method: 'supervisor.status' }, 'supervisor.status')).health, 'ready');
    const originalOwner = inspectInstalledOwnerHistory(recipe.stateRoot); assert.equal(originalOwner.owners.length, 1);
    assert.equal(originalOwner.owners[0]!.state, 'active'); assert.equal(originalOwner.owners[0]!.runtimeBundleRef, bundleDigest);
    const initialOwnerImage = parseJsonStrict((await readCas(originalOwner.owners[0]!.processIdentityRef)).toString('utf8')) as Record<string, any>;
    assert.equal(initialOwnerImage.pid, Number(supervisorBefore.MainPID));
    report.cases = [];
    await mkdir(recipe.workspace, { mode: 0o700 }); await chown(recipe.workspace, ledger.uid, ledger.gid);
    const createSource = async (sourceKind: SourceCaseKind) => {
      assert(client && signed.guestToolchain);
      const kind = sourceBehavior(sourceKind);
      mark(sourceKind);
      assert(!responderFailure);
      const workspace = path.join(recipe.workspace, sourceKind); await mkdir(workspace, { mode: 0o700 }); await chown(workspace, ledger.uid, ledger.gid);
      const expected = kind === 'required_pass' ? afterText : kind === 'required_repair' ? fixedText : beforeText;
      let check = kind === 'required_timeout'
        ? "import test from 'node:test'; test('owned timeout',async()=>{await new Promise(resolve=>setTimeout(resolve,60000));});\n"
        : "import test from 'node:test'; import assert from 'node:assert/strict'; import {readFile} from 'node:fs/promises';\n" +
          "test('owned exact private bytes',async()=>assert.equal(await readFile(new URL('./example.txt',import.meta.url),'utf8')," +
          JSON.stringify(kind === 'advisory_failure' ? 'this advisory assertion must fail\n' : expected) + "));\n";
      if (sourceKind === 'delivery_cancel') check += "import {existsSync} from 'node:fs';\n" +
        "test('owned delivery cancellation trigger',async()=>{if(existsSync(new URL('./cancel.flag',import.meta.url)))await new Promise(resolve=>setTimeout(resolve,60000));});\n";
      const files = [{ path: 'check.test.mjs', before: check, after: check }, { path: 'example.txt', before: beforeText, after: expected }];
      const sourceIdentity = new Map<string, Record<string, string>>();
      for (const entry of files) {
        const filename = path.join(workspace, entry.path); await writeFile(filename, entry.before, { flag: 'wx', mode: 0o644 });
        await chown(filename, ledger.uid, ledger.gid); sourceIdentity.set(entry.path, sourceMetadata(await lstat(filename, { bigint: true })));
      }
      const workspaceId = sha256Bytes(Buffer.from(workspace)), trustDirectory = path.join(cliqHome, 'workspaces', workspaceId);
      await mkdir(trustDirectory, { recursive: true, mode: 0o700 });
      for (const directory of [path.dirname(trustDirectory), trustDirectory]) await chown(directory, ledger.uid, ledger.gid);
      const trust = path.join(trustDirectory, 'trust.json');
      await writeFile(trust, canonicalJsonBytes({ version: 1, workspaceId, workspaceRealPath: workspace,
        decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trust, ledger.uid, ledger.gid);
      const session = (await send(request({ protocolVersion: 1, method: 'session.create', requestId: nextId(),
        admissionKey: randomBytes(32).toString('base64url'), workspacePath: workspace, name: 'Installed ' + kind }), 'session.create', 30000)).snapshot.session;
      assert.equal(session.contextRevision, 1); assert.equal(session.latestItemSeq, 0);
      const authorization: VerifierIdentityCreateRequest = request({ protocolVersion: 1, method: 'authorization.create', requestId: nextId(), decision: {
        kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain',
          guestToolchainManifestId: signed.guestToolchain.manifestId, toolId: 'node' } } });
      const grant: AuthorizationGrantSummaryV1 = (await send(authorization, 'authorization.create', 30000)).grant;
      assert.equal(grant.state, 'active'); assert.equal(grant.targetKind, 'execution_identity_read');
      assert.equal(grant.purpose, 'verifier'); assert.equal(grant.useCount, 0);
      const submit: Record<string, unknown> = request({ protocolVersion: 1, method: 'run.submit', requestId: nextId(),
        admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
        workspacePath: workspace, objective: 'Owned installed verifier case: ' + sourceKind + '. Make only the specified example.txt edit; retain all verifier files.',
        model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: registration.endpointRegistrationId },
          modelCredentialGrantIds: [credentialId] }, policyMode: 'yolo',
        budgets: { wallTimeMs: 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000,
          repairAttempts: kind === 'required_repair' ? 1 : 0, childDepth: 0, childConcurrency: 1 },
        verifiers: [{ id: 'node-tests', version: '1', required: kind !== 'advisory_failure',
          executable: { kind: 'toolchain', toolId: 'node' },
          argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })),
          cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: grant.grantId,
          timeoutMs: kind === 'required_timeout' ? 1000 : 10000, retries: kind === 'required_timeout' ? 1 : 0, outputLimitBytes: 65536 }],
        dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [],
        allowUnverified: kind === 'advisory_failure' });
      const admission: Response = await client.send(submit, 30000);
      const admitted: Record<string, any> = accepted(admission, 'run.submit').snapshot.run;
      activeCases.set(sourceKind, { runId: admitted.id, posts: 0, identities: [] });
      const by = Date.now() + 90000;
      let cut: Record<string, any>;
      for (;;) {
        cut = await send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }, 'run.get');
        assert(!responderFailure, 'owned responder must not refuse the literal expected request');
        if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(cut.snapshot.run.status)) break;
        assert(Date.now() < by, 'actual candidate/verifier/result did not reach terminal within its fixed 90-second qualification window');
        await delay(50);
      }
      const sessionCut = await send({ protocolVersion: 1, method: 'session.get', sessionId: session.id }, 'session.get');
      const proof = await assertInstalledVerifierOutcome({ cut, sessionCut, readCas, caseKind: kind, expectedFiles: files, principalId: principal,
        readOwnerHistory: async () => inspectInstalledOwnerHistory(recipe.stateRoot).owners });
      const queries = await resultQueries(cut);
      assert.equal(proof.retirementIdentities.length, kind === 'required_repair' || kind === 'required_timeout' ? 2 : 1);
      for (const retirement of proof.retirementIdentities) await assertVerifierProcessesAbsent(retirement);
      const active = activeCases.get(sourceKind)!;
      assert.equal(active.posts, kind === 'required_pass' ? 2 : kind === 'required_repair' ? 4 : 1);
      const editCount = kind === 'required_pass' ? 1 : kind === 'required_repair' ? 2 : 0;
      const verifierCount = kind === 'required_repair' || kind === 'required_timeout' ? 2 : 1;
      const claims = cut.journal.filter((entry: any) => entry.phase === 'dispatch_claimed');
      assert.equal(claims.filter((entry: any) => entry.opKind === 'model').length, active.posts);
      assert.equal(claims.filter((entry: any) => entry.opKind === 'tool').length, editCount);
      assert.equal(claims.filter((entry: any) => entry.opKind === 'verifier').length, verifierCount);
      assert.equal(claims.length, active.posts + editCount + verifierCount);
      assert.equal(canonicalSha256(cut.snapshot.run.budgetConsumed), canonicalSha256({ modelTokens: active.posts * 36864,
        costMicros: 0, toolCalls: editCount + verifierCount, repairAttempts: kind === 'required_repair' ? 1 : 0 }));
      assert.equal(canonicalSha256(cut.snapshot.run.budgetReserved), canonicalSha256({ modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }));
      assert.equal(active.identities.length, kind === 'required_repair' ? 2 : 1);
      const retirements = active.identities.map(identity => inspectInstalledWorkerRetirement(recipe.stateRoot, ledger.uid, identity));
      // The original active identity was independently observed before the
      // actual final model response, then real native sealed retirement read.
      for (const identity of retirements) {
        try { assert.notEqual('linux-proc-start-ticks:' + await processStart(identity.pid), identity.processStartToken); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      }
      const revocation = request({ protocolVersion: 1, method: 'authorization.revoke', requestId: nextId(), grantId: grant.grantId });
      const consumed = await send(revocation, 'authorization.revoke'); assert.equal(consumed.disposition, 'already_consumed');
      assert.equal(consumed.grant.state, 'consumed'); assert.equal(consumed.grant.useCount, 1);
      assert.deepEqual(await client.send(submit, 30000), admission);
      assert.deepEqual(await send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }, 'run.get'), cut);
      const cancellation = await client.send(request({ protocolVersion: 1, method: 'run.cancel', requestId: nextId(),
        runId: admitted.id, expectedRevision: cut.snapshot.run.revision }));
      assert.equal(cancellation.ok, false); assert.equal(cancellation.error?.code, 'RUN_TERMINAL');
      assert.deepEqual(await send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }, 'run.get'), cut);
      assert.deepEqual(await send({ protocolVersion: 1, method: 'session.get', sessionId: session.id }, 'session.get'), sessionCut);
      for (const file of files) {
        assert.deepEqual(sourceMetadata(await lstat(path.join(workspace, file.path), { bigint: true })), sourceIdentity.get(file.path));
        assert.equal(await readFile(path.join(workspace, file.path), 'utf8'), file.before);
      }
      const completedSource = { kind, cut, sessionCut, submit, admission, resultQueries: queries, files, workspace, sourceIdentity };
      completed.push(completedSource);
      report.cases.push({ kind: sourceKind, qualified: true, runId: admitted.id, resultRef: cut.snapshot.run.resultRef ?? null,
        posts: active.posts, actualOriginalWorkersRetired: retirements.length,
        exactVerifierProcessLifetimesIndependentlyAbsent: true, proof });
      return completedSource;
    };
    if (journeyKind === 'verifier') {
    for (const kind of cases) await createSource(kind);
    assert.equal(postCount, 8); assert.equal(acceptedTcp, postCount); assert.equal(acceptedTls, postCount); assert(!responderFailure);
    assert.equal(originalPublicResultBytes.size, 6, 'all three successful Runs must download their own result and diff');
    mark('fresh_client_reconnect_and_actual_restart');
    await client.close(); client = await persistentClient();
    for (const entry of completed) {
      assert.deepEqual(await send({ protocolVersion: 1, method: 'run.get', runId: entry.cut.snapshot.run.id }, 'run.get'), entry.cut);
      assert.deepEqual(await client.send(entry.submit, 30000), entry.admission);
      assert.deepEqual(await resultQueries(entry.cut), entry.resultQueries);
    }
    await client.close(); client = undefined; await inspectionClient.close(); inspectionClient = undefined;
    assert.equal(command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit]).status, 0);
    const afterRestart = show(services.supervisorUnit), restartBy = Date.now() + 30000;
    assert.notEqual(afterRestart.InvocationID, supervisorBefore.InvocationID); assert.notEqual(afterRestart.MainPID, supervisorBefore.MainPID);
    await selectedSupervisor(services.supervisorUnit, afterRestart, installedImage, restartBy);
    client = await persistentClient();
    for (const entry of completed) {
      const cut = await send({ protocolVersion: 1, method: 'run.get', runId: entry.cut.snapshot.run.id }, 'run.get');
      const sessionCut = await send({ protocolVersion: 1, method: 'session.get', sessionId: entry.cut.snapshot.run.sessionId }, 'session.get');
      assert.deepEqual(cut, entry.cut); assert.deepEqual(sessionCut, entry.sessionCut);
      assert.deepEqual(await client.send(entry.submit, 30000), entry.admission);
      assert.deepEqual(await resultQueries(cut), entry.resultQueries);
      await assertInstalledVerifierOutcome({ cut, sessionCut, readCas, caseKind: entry.kind, expectedFiles: entry.files, principalId: principal,
        readOwnerHistory: async () => inspectInstalledOwnerHistory(recipe.stateRoot).owners });
      for (const file of entry.files) {
        assert.deepEqual(sourceMetadata(await lstat(path.join(entry.workspace, file.path), { bigint: true })), entry.sourceIdentity.get(file.path));
        assert.equal(await readFile(path.join(entry.workspace, file.path), 'utf8'), file.before);
      }
    }
    const ownerHistory = inspectInstalledOwnerHistory(recipe.stateRoot);
    assert.equal(ownerHistory.owners.length, 2); assert.equal(ownerHistory.owners[0]!.state, 'terminal');
    assert.equal(ownerHistory.owners[0]!.terminalReason, 'graceful_release'); assert.equal(ownerHistory.owners[1]!.state, 'active');
    assert.equal(ownerHistory.owners[1]!.runtimeBundleRef, bundleDigest);
    assert.equal(show(services.keeperUnit).MainPID, keeperBefore.MainPID);
    assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
    assert.equal(postCount, 8); assert.equal(acceptedTcp, postCount); assert.equal(acceptedTls, postCount); assert(!responderFailure);
    report.reconnectAndRestart = { qualified: true, sameKeeper: true, sameTerminalRunAndSession: true, noRedispatch: true,
      exactOriginalAdmissionReplay: true, sourceFilesAndIdentitiesUnchanged: true, gracefulOriginalOwnerReleased: true,
      committedResultAndDiffDescriptorsPreserved: true, liveAndFailedNeverExposeCandidateAsResult: true };
    } else {
      const supported = client.hello.enabledFeatureIds.includes('run.apply') && client.hello.enabledFeatureIds.includes('run.approve');
      report.delivery = { diagnosticOnly: true, qualified: false, attemptStarted: false, capabilityAdvertised: supported,
        reason: supported ? 'not_yet_executed' : 'production_composition_not_advertised' };
      assert(supported,
        'the genuine production composition must advertise explicit Delivery before this campaign can run');
      const assertWorkerRetired = async (runId: string, launchId: string, publicationRetirement?: InstalledWorkerRetirementBinding) => {
        const retired = inspectInstalledWorkerRetirementHistory(recipe.stateRoot, ledger.uid,
          { runId, launchId, ...(publicationRetirement ? { retirement: publicationRetirement } : {}) });
        try { assert.notEqual('linux-proc-start-ticks:' + await processStart(retired.pid), retired.processStartToken); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      };
      // A failed attempt may already have real effects. Do not retain the
      // initial not-started marker as a claim that nothing executed.
      report.delivery = { ...report.delivery, attemptStarted: true, reason: 'in_progress' };
      report.delivery = await runInstalledDeliveryCases({
        createSource: kind => createSource(`delivery_${kind}`),
        send: async (body, timeout = 5000) => { assert(client); return await client.send(body, timeout); },
        nextId, readRetainedArtifact: readCas, downloadPublicArtifact: readPublicArtifact, uid: ledger.uid, gid: ledger.gid, mark,
        readOwnerHistory: async () => inspectInstalledOwnerHistory(recipe.stateRoot).owners,
        assertVerifierProcessesAbsent,
        assertRunWorkersRetired: async (runId, observedLaunchIds, publicationRetirement) => {
          const selected = inspectInstalledWorkerLaunchIds(recipe.stateRoot, ledger.uid, runId);
          assert(observedLaunchIds.every(id => selected.launchIds.includes(id)));
          if (publicationRetirement === null) assert.equal(selected.launchIds.length, 0);
          else if (publicationRetirement) assert(selected.launchIds.includes(publicationRetirement.launchId));
          for (const launchId of selected.launchIds) await assertWorkerRetired(runId, launchId,
            publicationRetirement?.launchId === launchId ? publicationRetirement : undefined);
          const after = inspectInstalledWorkerLaunchIds(recipe.stateRoot, ledger.uid, runId);
          assert.equal(after.databaseIdentity, selected.databaseIdentity); assert.deepEqual(after.launchIds, selected.launchIds);
          return selected.launchIds.length;
        },
        reconnect: async () => { await client!.close(); client = await persistentClient(); },
        restart: async () => {
          await client!.close(); client = undefined; await inspectionClient!.close(); inspectionClient = undefined;
          assert.equal(command('/usr/bin/systemctl', ['--user', 'restart', services!.supervisorUnit]).status, 0);
          const after = show(services!.supervisorUnit), by = Date.now() + 30000;
          assert.notEqual(after.InvocationID, supervisorBefore.InvocationID); assert.notEqual(after.MainPID, supervisorBefore.MainPID);
          await selectedSupervisor(services!.supervisorUnit, after, installedImage, by);
          client = await persistentClient();
          const owners = inspectInstalledOwnerHistory(recipe.stateRoot);
          assert.equal(owners.owners.length, 2); assert.equal(owners.owners[0]!.terminalReason, 'graceful_release');
          assert.equal(owners.owners[1]!.state, 'active'); assert.equal(owners.owners[1]!.runtimeBundleRef, bundleDigest);
          assert.equal(show(services!.keeperUnit).MainPID, keeperBefore.MainPID);
          assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
        },
        cleanupCrash: async source => {
          mark('delivery_cleanup_crash_observer');
          const diagnostic: Record<string, unknown> = { diagnosticOnly: true, qualified: false, stage: 'observer_start',
            originalReceiptCasObjectAbsenceQualified: false, rebootQualified: false };
          report.publicationCleanupCrash = diagnostic;
          const ownersBefore = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
          assert.equal(ownersBefore.length, 2); const original = ownersBefore[1]!; assert.equal(original.state, 'active');
          const shown = show(services!.supervisorUnit), pid = Number(shown.MainPID), supervisorEntry = signed.bundle.entries.find(entry => entry.role === 'supervisor');
          assert(supervisorEntry); const supervisorDigest = supervisorEntry.digest;
          const actual = await qualifyInstalledOwnerProcess({ stateRoot: recipe.stateRoot, uid: ledger.uid,
            pid, selectedImage: installedImage, imageDigest: supervisorDigest }, original, {});
          const image = await lstat(installedImage, { bigint: true });
          const observer = startPublicationCrashObserver({ executable: recipe.publicationObserver, prefix, cwd: ledger.home, env: environment,
            stateRoot: recipe.stateRoot, pid, uid: ledger.uid, startTicks: actual.processStartToken.slice('linux-proc-start-ticks:'.length),
            imageDigest: supervisorDigest, imageDevice: image.dev.toString(), imageInode: image.ino.toString(), imageSize: image.size.toString(), scan: scanBytes });
          let failure: unknown;
          try {
            await bounded(observer.ready, 30000, 'actual cleanup crash observer did not arm its original watch');
            // Fixture-owner change before new admission; no model invocation or
            // productive Run is created by the observer/readonly SQL diagnostic.
            for (const file of source.files.filter(file => file.path === 'example.txt')) {
              const target = path.join(source.workspace, file.path), held = await open(target, constants.O_WRONLY | constants.O_NOFOLLOW);
              try { const before = await held.stat(); assert(before.isFile() && before.uid === ledger.uid && before.nlink === 1);
                await held.truncate(0); await held.writeFile(file.before); await held.sync(); }
              finally { await held.close(); }
            }
            const core = request({ protocolVersion: 1, method: 'run.apply', requestId: nextId(), admissionKey: randomBytes(32).toString('base64url'),
              sourceRunId: source.cut.snapshot.run.id, expectedRunResultRef: source.cut.snapshot.run.resultRef,
              budgets: { wallTimeMs: 300000, toolCalls: 1000 } });
            const admitted = await client!.send(core, 30000), runId = accepted(admitted, 'run.apply').snapshot.run.id;
            const by = Date.now() + 90000; diagnostic.stage = 'original_claim'; diagnostic.runId = runId;
            let claimed: ReturnType<typeof inspectInstalledPublicationClaim>;
            for (;;) {
              claimed = inspectInstalledPublicationClaim(recipe.stateRoot, ledger.uid, runId);
              if (claimed) break;
              assert(Date.now() < by, 'the genuine original publication claim was not observed'); await delay(0);
            }
            assert.equal(claimed.originalReceiptCommitted, false, 'the physical cut was missed: original receipt already committed');
            assert.equal(claimed.journal.length, 2); assert.equal(claimed.claim.supervisorInstanceId, original.supervisorInstanceId);
            assert.equal(claimed.claim.stateOwnerEpoch, original.ownerEpoch); diagnostic.claimCutDigest = claimed.sqlCutDigest;
            diagnostic.originalOwnerEpoch = original.ownerEpoch; diagnostic.originalSupervisorPid = pid;
            diagnostic.arenaBirthRef = claimed.claim.evidenceRef;
            const restartBy = Date.now() + 30000;
            observer.arm(claimed.birth); diagnostic.stage = 'physical_kill';
            await bounded(observer.joined, Math.min(90000, by - Date.now()), 'actual cleanup crash observer did not join');
            const joinedAt = new Date().toISOString(); diagnostic.observerJoined = true;
            // This is the first actual complete original SQL cut after the
            // joined kill, not a reconstruction from eventual terminal bytes.
            const crash = inspectInstalledPublicationClaim(recipe.stateRoot, ledger.uid, runId); assert(crash);
            assert.equal(crash.databaseIdentity, claimed.databaseIdentity); assert.equal(crash.originalReceiptCommitted, false,
              'the physical cut was missed: original receipt/handoff committed before actual kill');
            // An automatically started successor may already have recorded the
            // original UNKNOWN. That is not an original receipt commit, but
            // the two original permanent-claim rows must remain byte-identical.
            assert(crash.journal.length === 2 || crash.journal.length === 3 && crash.journal[2]!.phase === 'unknown');
            assert.deepEqual(crash.journal.slice(0, 2), claimed.journal); assert.deepEqual(crash.birth, claimed.birth);
            assert.equal(crash.progress.filter(value => value.item.state === 'desired_committed_cleanup_pending').length, 1);
            diagnostic.firstPostKillSqlCutDigest = crash.sqlCutDigest; diagnostic.originalReceiptCommitAbsent = true; diagnostic.durableProgressPresent = true;
            await client!.close(); client = undefined; await inspectionClient?.close(); inspectionClient = undefined;
            diagnostic.stage = 'successor';
            let successorUnit: Record<string, string>;
            for (;;) {
              successorUnit = show(services!.supervisorUnit);
              if (successorUnit.MainPID !== '0' && successorUnit.MainPID !== shown.MainPID && successorUnit.InvocationID !== shown.InvocationID) break;
              assert(Date.now() < restartBy, 'actual cleanup crash restart exceeded the original 30-second budget'); await delay(50);
            }
            const successorStart = await selectedSupervisor(services!.supervisorUnit, successorUnit, installedImage, restartBy);
            const history = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
            assert.equal(history.length, 3); assert.equal(history[1]!.terminalReason, 'superseded_after_owner_death');
            assert.equal(history[2]!.state, 'active');
            await qualifyInstalledOwnerLinks({ stateRoot: recipe.stateRoot, uid: ledger.uid, bundle: signed.bundle, imageDigest: supervisorDigest, report: {} });
            assert.equal(show(services!.keeperUnit).MainPID, keeperBefore.MainPID);
            assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
            diagnostic.sameKeeper = true; client = await persistentClient();
            diagnostic.stage = 'current_namespace'; let recovered: Record<string, any>;
            for (;;) {
              recovered = accepted(await client.send({ protocolVersion: 1, method: 'run.get', runId }), 'run.get');
              if (['succeeded', 'failed', 'cancelled', 'completed_unverified'].includes(recovered.snapshot.run.status)) break;
              assert(Date.now() < by, 'actual cleanup crash recovery exceeded its original 90-second window'); await delay(50);
            }
            const proof = await assertInstalledPublicationCleanupRecovery({ cut: recovered, originalBirth: claimed.birth,
              expectedFiles: source.files.map(file => ({ path: file.path, text: file.after })), sourceResultRef: source.cut.snapshot.run.resultRef,
              readRetainedArtifact: readCas, readOwnerHistory: async () => inspectInstalledOwnerHistory(recipe.stateRoot).owners });
            assert(joinedAt <= proof.probeStartedAt, 'external observer process, pipes and FDs must join before the fresh native probe');
            if (options.publicationRetirementDiagnostics) {
              // This observation measures the actual namespace task only. It
              // does not turn either clock into authority or qualify a late
              // result / in-flight stop. The complete CAS proof above and all
              // original physical retirement checks below remain mandatory.
              const successorPid = Number(successorUnit.MainPID), successor = history[2]!;
              const logBy = Date.now() + 5000, since = Date.parse(proof.probeStartedAt);
              assert(Number.isFinite(since));
              const bindCurrentProcess = async () => {
                assert.equal(await fixtureProcess(successorPid, ledger.uid), successorStart);
                const observed = await qualifyInstalledOwnerProcess({ stateRoot: recipe.stateRoot, uid: ledger.uid,
                  pid: successorPid, selectedImage: installedImage, imageDigest: supervisorDigest }, successor, {});
                assert.equal(observed.processStartToken, 'linux-proc-start-ticks:' + successorStart);
                assert.equal(await fixtureProcess(successorPid, ledger.uid), successorStart);
              };
              for (;;) {
                assert(Date.now() < logBy, 'actual namespace retirement timing was not observed within the original five-second window');
                await bindCurrentProcess();
                const remaining = logBy - Date.now(); assert(remaining > 0);
                const started = performance.now();
                const log = spawnSync('/usr/bin/journalctl', ['--no-pager', '--all', '--output=json', '--lines=80', '--boot=0',
                  `--since=@${Math.floor(since / 1000)}`, `--until=@${Math.ceil(Date.now() / 1000)}`,
                  `_UID=${ledger.uid}`, `_PID=${successorPid}`, '_TRANSPORT=stdout'],
                { env: environment, timeout: remaining, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 });
                assert(Buffer.isBuffer(log.stdout) && Buffer.isBuffer(log.stderr));
                scanBytes(log.stdout); scanBytes(log.stderr);
                const joinFailure = fixtureCommandJoinDiagnostic(log, remaining, started);
                if (joinFailure) report.commandJoinFailure ??= joinFailure;
                assert.equal(log.error, undefined, 'actual journal command must join'); assert.equal(log.signal, null); assert.equal(log.status, 0);
                const snapshot = readInstalledNamespaceRetirementJournal(new TextDecoder('utf-8', { fatal: true }).decode(log.stdout), {
                  uid: ledger.uid, pid: successorPid, invocationId: successorUnit.InvocationID!, key: proof.retirementDiagnosticKey });
                await bindCurrentProcess();
                assert(Date.now() < logBy, 'actual namespace retirement timing exceeded the original five-second observation window');
                if (snapshot) {
                  report.publicationRetirementTiming = { diagnosticOnly: true, physicalLateCutQualified: false,
                    probeStartedAt: proof.probeStartedAt, probeDeadlineAt: proof.probeDeadlineAt, snapshot };
                  break;
                }
                await delay(Math.min(50, Math.max(0, logBy - Date.now())));
              }
            }
            const retired = inspectInstalledRecoveredWorkerRetirement(recipe.stateRoot, ledger.uid, { runId,
              supervisorInstanceId: claimed.claim.supervisorInstanceId!, leaseEpoch: claimed.claim.leaseEpoch,
              inspectorIdentityRef: proof.inspectorIdentityRef, inspectorIdentityDigest: proof.inspectorIdentityDigest, resources: proof.generationResources });
            try { assert.notEqual('linux-proc-start-ticks:' + await processStart(retired.pid), retired.processStartToken); }
            catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
            await assert.rejects(lstat(path.join(recipe.stateRoot, retired.quarantinePath)), (error: unknown) => (error as NodeJS.ErrnoException).code === 'ENOENT');
            assert.deepEqual((await readdir(source.workspace)).sort(), source.files.map(file => file.path).sort());
            for (const file of source.files) {
              const target = path.join(source.workspace, file.path), info = await lstat(target);
              assert(info.isFile() && !info.isSymbolicLink() && info.uid === ledger.uid && info.gid === ledger.gid && info.nlink === 1 && (info.mode & 0o7777) === 0o644);
              assert.equal(await readFile(target, 'utf8'), file.after);
            }
            assert.deepEqual(accepted(await client.send({ protocolVersion: 1, method: 'run.get', runId: source.cut.snapshot.run.id }), 'run.get'), source.cut,
              'the preverified original source Run cannot be changed by recovery');
            const queries = [];
            for (const method of ['run.result', 'run.diff']) {
              const response = await client.send({ protocolVersion: 1, method, runId }), result = accepted(response, method);
              const descriptor = method === 'run.result' ? result.result : result.diff;
              const expectedRef = method === 'run.result' ? proof.resultRef : proof.diffRef;
              assert.equal(result.runId, runId); assert.equal(descriptor.ref, expectedRef); assert.equal(descriptor.digest, expectedRef);
              assert.equal(descriptor.mediaType, 'application/json');
              if (method === 'run.result') assert.equal(result.verificationClosureRef, proof.verificationClosureRef);
              const downloaded = await readPublicArtifact(descriptor.ref); assert.equal(downloaded.length, descriptor.sizeBytes);
              assert.equal(sha256Bytes(downloaded), descriptor.digest); queries.push(response);
            }
            const projectionBytes = await readPublicArtifact(proof.projectionRef); assert.equal(sha256Bytes(projectionBytes), proof.projectionRef);
            const events = accepted(await client.send({ protocolVersion: 1, method: 'run.attach', runId, afterEventSeq: 0, limit: 1000 }), 'run.attach');
            assert.equal(events.nextEventSeq, events.highWaterEventSeq);
            const terminals = events.events.filter((event: any) => event.kind === 'state_changed' &&
              ['succeeded', 'failed', 'cancelled', 'completed_unverified'].includes(event.status));
            assert.equal(terminals.length, 1); assert.equal(terminals[0].status, 'succeeded'); assert.equal(terminals[0].resultRef, proof.resultRef);
            await client.close(); client = await persistentClient();
            assert.deepEqual(accepted(await client.send({ protocolVersion: 1, method: 'run.get', runId }), 'run.get'), recovered);
            assert.deepEqual(await client.send(core, 30000), admitted);
            for (const [index, method] of ['run.result', 'run.diff'].entries()) assert.deepEqual(await client.send({ protocolVersion: 1, method, runId }), queries[index]);
            Object.assign(diagnostic, { qualified: true, stage: 'complete', successorOwnerEpoch: proof.successorOwnerEpoch,
              namespaceEvidenceRef: proof.namespaceEvidenceRef, originalUnknownSettlementRef: proof.originalUnknownSettlementRef,
              resolutionBudgetDeltaZero: true, redispatchCount: 0, originalRetiredWorkerObservedAbsent: true, sameReplayAfterReconnect: true });
          } catch (error) { failure = error; throw error; }
          finally {
            try { await observer.close(); }
            catch (error) { if (failure) throw new AggregateError([failure, error], 'cleanup crash observer did not join after its original failure'); throw error; }
          }
        },
      });
      assert.equal(postCount, 6); assert.equal(acceptedTcp, postCount); assert.equal(acceptedTls, postCount); assert(!responderFailure);
      assert.equal(originalPublicResultBytes.size, 6);
    }
    report.qualified = true;
  } catch (error) { primary = error; }
  finally {
    const cleanup: unknown[] = [];
    try { await client?.close(); } catch (error) { cleanup.push(error); }
    try { await inspectionClient?.close(); } catch (error) { cleanup.push(error); }
    try {
      if (server) {
        server.closeAllConnections();
        await bounded(new Promise<void>(resolve => server!.close(() => resolve())), 10000, 'owned HTTPS server did not join');
        await bounded(Promise.all(sockets), 10000, 'owned HTTPS sockets did not join'); report.httpsJoined = true;
      }
    } catch (error) { cleanup.push(error); }
    try {
      if (services) {
        const units = [services.supervisorUnit, services.keeperUnit] as const;
        const before = units.map(unit => show(unit));
        await withRetainedUnitHistory(units, async assertRetained => {
          assertRetained();
          assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', ...units]).status, 0);
          const after = units.map(unit => show(unit));
          for (let index = 0; index < units.length; index++) {
            const stopped = after[index]!;
            assert.equal(stopped.ActiveState, 'inactive'); assert.equal(stopped.MainPID, '0');
            assert.equal(stopped.TimeoutStopUSec, '2s'); assert.equal(stopped.Result, 'success');
            assert.equal(stopped.ExecMainCode, '1'); assert.equal(stopped.ExecMainStatus, '0');
            if (/^[1-9][0-9]*$/u.test(before[index]!.MainPID!)) await assert.rejects(lstat('/proc/' + before[index]!.MainPID), { code: 'ENOENT' });
          }
        });
        report.installedWritersJoined = true;
      }
    } catch (error) { cleanup.push(error); }
    try {
      if (daemon && daemonExit) {
        if (daemonPid && daemonStart) {
          assert.equal(await fixtureProcess(daemonPid, ledger.uid, daemon.pid), daemonStart);
          assert.equal(await readlink('/proc/' + daemonPid + '/exe'), '/usr/bin/gnome-keyring-daemon');
          process.kill(daemonPid, 'SIGTERM');
        } else if (daemon.exitCode === null && daemon.signalCode === null) daemon.kill('SIGTERM');
        await bounded(daemonExit, 10000, 'real Secret Service daemon did not join'); report.daemonJoined = true;
      }
    } catch (error) { cleanup.push(error); }
    if (cleanup.length) primary = new AggregateError([primary, ...cleanup].filter(Boolean), 'actual installed verifier resources did not join');
    if (!primary) {
      try {
        mark('complete_retained_secret_corpus');
        assert.equal(report.installedWritersJoined, true); assert.equal(report.httpsJoined, true); assert.equal(report.daemonJoined, true);
        report.secretCorpus = await scanCredentialSecretCorpus({ stateRoot: recipe.stateRoot, uid: ledger.uid, evidenceDirs: [], scanner });
        assert.equal(report.secretCorpus.sqliteDatabasesScanned, 2); assert.equal(report.secretCorpus.evidenceDirectoriesScanned, 0);
        mark('complete');
      } catch (error) {
        if (error instanceof CredentialSecretCorpusError) {
          if (error.databaseFailure) report.secretCorpusDatabaseFailure = error.databaseFailure;
          if (error.corpusFailure) report.secretCorpusFailure = error.corpusFailure;
        } else if (error instanceof CredentialSecretScanError) report.secretCorpusScanFailure = { code: error.code };
        primary = error;
      }
    }
    if (primary) {
      report.qualified = false;
      const frames: Array<{ file: string; line: number; column: number }> = [];
      const failureKinds: Array<{ kind: 'assertion' } | { kind: 'sqlite'; primaryCode: number } |
        { kind: 'installed_verifier_outcome'; stage: InstalledVerifierOutcomeError['diagnosticStage'] } |
        { kind: 'installed_delivery_outcome'; stage: InstalledDeliveryOutcomeError['diagnosticStage'] } |
        InstalledClientConsumerDeadlineError['diagnostic'] | InstalledClientDriverError['diagnostic']> = [];
      const errors: unknown[] = [...responderErrors, primary];
      for (let index = 0; index < 8 && errors.length; index++) {
        const error = errors.shift(); if (!(error instanceof Error)) continue;
        const diagnostic = error as Error & { code?: unknown; errcode?: unknown };
        if (error instanceof InstalledClientConsumerDeadlineError || error instanceof InstalledClientDriverError) failureKinds.push(error.diagnostic);
        else if (error instanceof InstalledVerifierOutcomeError) failureKinds.push({ kind: 'installed_verifier_outcome', stage: error.diagnosticStage });
        else if (error instanceof InstalledDeliveryOutcomeError) failureKinds.push({ kind: 'installed_delivery_outcome', stage: error.diagnosticStage });
        else if (diagnostic.code === 'ERR_ASSERTION') failureKinds.push({ kind: 'assertion' });
        else if (diagnostic.code === 'ERR_SQLITE_ERROR' && typeof diagnostic.errcode === 'number' && Number.isSafeInteger(diagnostic.errcode) &&
            diagnostic.errcode >= 0 && diagnostic.errcode <= 65535) failureKinds.push({ kind: 'sqlite', primaryCode: diagnostic.errcode & 0xff });
        for (const match of (error.stack ?? '').matchAll(/\b(qualify-installed-verifier-journey|qualify-installed-delivery-journey|installed-node-journey|installed-delivery-journey|installed-delivery-result|installed-verifier-result|installed-guest-package|installed-supervisor-package|installed-model-package|installed-read-control|installed-client-consumer|installed-enroll-diagnostic|installed-worker-lease|installed-publication-recovery|installed-publication-crash-observer)\.ts:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})/gu)) {
          if (frames.length < 8) frames.push({ file: match[1]! + '.ts', line: Number(match[2]), column: Number(match[3]) });
        }
        if (error instanceof AggregateError) errors.unshift(...error.errors.slice(0, 4));
      }
      report.error = { diagnosticOnly: true, kind: journeyKind === 'verifier' ? 'installed_verifier_journey_failed' : 'installed_delivery_journey_failed', sourceFrames: frames, failureKinds };
    }
    let publication: Buffer;
    try {
      const bytes = Buffer.from(JSON.stringify(report, null, 2) + '\n'); scanBytes(bytes); bytes.fill(0); scanner.close();
      report.secretOutputScan = scanner.stats(); publication = Buffer.from(JSON.stringify(report, null, 2) + '\n');
    } catch {
      scanner.close(); report.qualified = false; primary ??= new Error('credential secret scan refused');
      publication = Buffer.from(JSON.stringify({ diagnosticOnly: true, qualified: false, phase: 'secret_scan_or_report_failure', secretOutputScan: scanner.stats() }) + '\n');
    }
    secret.fill(0); password.fill(0);
    try { await writeFile(recipe.reportFile, publication, { flag: 'wx', mode: 0o644 }); } finally { publication.fill(0); }
  }
  if (primary) throw new Error(journeyKind === 'verifier' ? 'actual installed verifier journey failed; inspect the closed diagnostic report'
    : 'actual installed Delivery journey failed; inspect the closed diagnostic report');
}

