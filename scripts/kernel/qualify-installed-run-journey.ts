// Real signed installation, user manager, Secret Service and public v1 UDS.
// The owned HTTPS responder qualifies transport mechanics, never a provider,
// model capability/billing bound, I2 result, macOS or the full I1 fault matrix.
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import { chown, lstat, mkdir, open, readFile, readdir, readlink, stat, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRevokeOperation,
  decodeEndpointAuthorityOperation, type EndpointRegistrationV1 } from '../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../src/kernel/identity.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { createCredentialSecretScanner } from './testing/credential-secret-scan.js';
import { scanCredentialSecretCorpus } from './testing/credential-secret-corpus.js';
import { assertInstalledWorkerLeaseRenewed, inspectInstalledWorkerLease } from './testing/installed-worker-lease.js';
import { projectInstalledRunProgress, projectInstalledServiceExit, projectInstalledSupervisorStatus } from '../../src/sandbox/testing/installed-run-progress.js';

type Recipe = { buildFixture: string; packageRoot: string; installerEntry: string; stateRoot: string; releaseKeysFile: string;
  controlDirectory: string; observer: string; storeFixture: string; workspace: string; reportFile: string };
type Ledger = { diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string; runJourney: Recipe };
type Response = { protocolVersion: 1; ok: boolean; method?: string; result?: Record<string, any>; error?: Record<string, unknown> };
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const hostBefore = 'before the private edit\n';
const privateAfter = 'after the private edit\n';
const model = 'installed-run-transport-fixture';
const rejectedResponse = '{"error":{"message":"Owned fixture rejected this request."}}';
type CampaignMode = '--campaign' | '--failure-campaign' | '--retry-campaign';
const requestTokenCeiling = { inputTokens: 32768, outputTokens: 4096, cacheReadTokens: 0, cacheWriteTokens: 0 };
const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;

async function bounded<T>(pending: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([pending, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(label)), milliseconds);
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
    'packageRoot', 'releaseKeysFile', 'reportFile', 'stateRoot', 'storeFixture', 'workspace'].sort());
  assert.equal(recipe.buildFixture, path.join(ledger.fixture, 'run-package-build'));
  assert.equal(recipe.packageRoot, path.join(recipe.buildFixture, 'package'));
  assert.equal(recipe.installerEntry, path.join(recipe.buildFixture, 'installed-runtime-installer.mjs'));
  assert.equal(recipe.stateRoot, path.join(ledger.home, '.cliq/kernel-v1'));
  assert.equal(recipe.releaseKeysFile, path.join(ledger.fixture, 'run-release-keys.json'));
  assert.equal(recipe.controlDirectory, path.join(ledger.home, 'probe/run-secret-service-control'));
  assert.equal(recipe.observer, path.join(ledger.fixture, 'cliq-credential-journey-observer'));
  assert.equal(recipe.storeFixture, path.join(ledger.fixture, 'cliq-credential-store-fixture'));
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

// Independent ordinary unprivileged client. Inputs are bounded secret-free
// requests only. A closed connection cannot cancel or own the accepted Run.
const clientScript = `import assert from 'node:assert/strict'; import net from 'node:net';
const requests=JSON.parse(Buffer.from(process.argv[2],'base64url').toString('utf8'));
const connectBy=Number(process.argv[3]??0);assert(Number.isSafeInteger(connectBy)&&connectBy>=0);
async function connect(){for(;;){assert(!connectBy||Date.now()<connectBy,'startup connection deadline expired');
const socket=net.createConnection(process.argv[1]);
const closed=new Promise(resolve=>socket.once('close',resolve));
try{await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
assert(!connectBy||Date.now()<connectBy,'startup connection deadline expired');return socket;}
catch(failure){socket.destroy();await closed;
if(!connectBy||Date.now()>=connectBy||!['ENOENT','ECONNREFUSED'].includes(failure.code))throw failure;
await new Promise(resolve=>setTimeout(resolve,50));}}}
const socket=await connect();let input=Buffer.alloc(0),waiter,error;
const closed=new Promise(resolve=>socket.once('close',resolve));
socket.on('data',chunk=>{try{input=Buffer.concat([input,chunk]);assert(input.length<=1048580);
while(input.length>=4){const count=input.readUInt32BE(0);assert(count>=1&&count<=1048576);
if(input.length<4+count)break;const text=new TextDecoder('utf-8',{fatal:true}).decode(input.subarray(4,4+count));
input=input.subarray(4+count);assert(waiter);const complete=waiter;waiter=undefined;complete.resolve(text);}}
catch(failure){error=failure;waiter?.reject(failure);socket.destroy();}});
socket.on('error',failure=>{error=failure;waiter?.reject(failure);});
socket.on('close',()=>{error??=new Error('fixed installed client connection closed');waiter?.reject(error);});
const reply=[];try{
for(const bytes of requests){assert(!waiter&&!error);const body=Buffer.from(bytes,'base64url');assert(body.length<=1048576);
const header=Buffer.alloc(4);header.writeUInt32BE(body.length);const response=await new Promise((resolve,reject)=>{
waiter={resolve,reject};socket.write(Buffer.concat([header,body]));});reply.push(response);}}
finally{socket.destroy();await closed;}console.log(JSON.stringify(reply));`;

async function campaign(filename: string, mode: CampaignMode): Promise<void> {
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.runJourney;
  const failureOnly = mode === '--failure-campaign';
  const retryOnly = mode === '--retry-campaign';
  const report: Record<string, any> = { diagnosticOnly: true, qualified: false, phase: 'installation',
    scope: retryOnly
      ? 'independent signed installed Linux Run, real default-alias drift and exact restoration on the same Secret Service lifetime, free pre-dispatch failure and one subsequent owned model response, explicit cancellation and terminal Session publication; not daemon restart, locked-store recovery, post-claim retry, full I1, real provider/billing, I2 or macOS'
      : failureOnly
      ? 'independent signed installed Linux Run, one positively received owned HTTP429 response, exact model-failure stop and physical terminal drain, Session publication and reconnect, then durable source-refusal replay after real credential revocation; not transport retry, cancellation, deadline expiry, full I1, real provider/billing, I2 or macOS'
      : 'signed installed Linux Run admission, native credential HTTPS transport, real private edit, ready Checkpoint, candidate retention with read-only lease-renewal observation across the old expiry, capacity-blocked queued deadline, client reconnect, Supervisor restart and explicit cancellation; not live-worker deadline, full I1, real provider/billing, I2 or macOS',
    completeI1Qualified: false, actualProviderQualified: false, actualProviderCapabilityQualified: false,
    actualProviderBillingQualified: false, artifactGetPublicUxQualified: false, exactFinalizerTimeCutsQualified: false,
    retiredScopeLiveProducerABAQualified: false, fullCrashMatrixQualified: false, macosQualified: false,
    rebootQualified: false, I2VerifiedResultQualified: false, liveWorkerDeadlineQualified: false, candidateLeaseRenewalQualified: false,
    receivedModelFailureQualified: false, preDispatchRetryQualified: false };
  const secret = Buffer.from(randomBytes(32).toString('hex')), password = Buffer.from(randomBytes(32).toString('hex'));
  const scanner = createCredentialSecretScanner([secret, password], { maxBytes: 512 * 1024 * 1024, maxStreams: 4096 });
  const scanBytes = (bytes: Uint8Array) => { const scan = scanner.openStream(); try { scan.scan(bytes); } finally { scan.close(); } };
  const mark = (phase: string) => { report.phase = phase; console.log(`Installed Run journey phase ${phase}`); };
  const prefix = ['--user', ledger.username, '--', '/usr/bin/env', '-i', `HOME=${ledger.home}`, 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
    `XDG_RUNTIME_DIR=/run/user/${ledger.uid}`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${ledger.uid}/bus`];
  const command = (executable: string, args: string[], input?: Buffer, timeout = 30000) => {
    const result = spawnSync('/usr/sbin/runuser', [...prefix, executable, ...args], { env: environment, cwd: ledger.home,
      timeout, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, input });
    assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr), 'disposable command requires joined output');
    scanBytes(result.stdout); scanBytes(result.stderr);
    assert.equal(result.error, undefined, 'disposable command did not join'); assert.equal(result.signal, null, 'disposable command was signaled');
    return { status: result.status, stdout: result.stdout.toString('utf8'), stderr: result.stderr.toString('utf8') };
  };
  const success = (result: ReturnType<typeof command>, field: string) => {
    assert.equal(result.status, 0, 'actual signed command refused');
    const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
    assert.deepEqual(Object.keys(value).sort(), ['schemaVersion', field].sort()); assert.equal(value.schemaVersion, 1);
    assert.equal(result.stdout, `${canonicalJsonBytes(value).toString('utf8')}\n`); return value[field];
  };
  const credential = (metadata: Record<string, unknown>, input?: Buffer) => command(path.join(recipe.stateRoot, 'runtime/bootstrap'),
    ['--bootstrap-credential', canonicalJsonBytes(metadata).toString('base64url')], input, 60000);
  const request = <T extends Record<string, unknown>>(body: T): T & { requestDigest: string } =>
    ({ ...body, requestDigest: canonicalSha256(body) });
  const hello = { protocolVersion: 1, method: 'control.hello', clientBuild: 'installed-run-journey',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
    requestedFeatureIds: ['session.create', 'session.get', 'run.submit', 'run.get', 'run.attach', 'run.cancel', 'supervisor.status'] };
  const exchange = (requests: Record<string, unknown>[], connectBy = 0, timeout = 30000): Response[] => {
    assert(connectBy === 0 || requests.length === 0, 'startup connection retry is hello-only, never a request replay');
    assert(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 30000);
    const entries = [hello, ...requests].map(value => canonicalJsonBytes(value).toString('base64url'));
    const bytes = Buffer.from(JSON.stringify(entries)).toString('base64url'); assert(bytes.length < 65536);
    const remaining = connectBy ? connectBy - Date.now() : 30000;
    assert(remaining > 0, 'startup control readiness exhausted the existing recovery budget');
    const result = command(process.execPath, ['--input-type=module', '-e', clientScript,
      path.join(recipe.stateRoot, 'runtime/control-v1.sock'), bytes, String(connectBy)], undefined, Math.min(timeout, remaining));
    assert.equal(result.status, 0, 'ordinary authenticated v1 client did not join');
    const replies = parseJsonStrict(result.stdout.trim()) as string[]; assert.equal(replies.length, entries.length);
    const parsed = replies.map(text => { const value = parseJsonStrict(text) as Response; assert.equal(text, canonicalJsonBytes(value).toString('utf8')); return value; });
    assert.equal(parsed[0]!.ok, true, 'real compatible hello refused'); assert.equal(parsed[0]!.result!.method, 'control.hello');
    return parsed.slice(1);
  };
  const accepted = (response: Response, method: string) => {
    if (!response.ok) {
      const allowed = ['INVALID_REQUEST', 'INCOMPATIBLE_PROTOCOL', 'EVENT_CURSOR_EXPIRED', 'INTERNAL', 'REVISION_CONFLICT',
        'NOT_FOUND', 'AUTHORIZATION_REQUIRED', 'ARTIFACT_MISMATCH', 'UNSUPPORTED_PLATFORM', 'REQUEST_ID_CONFLICT',
        'ADMISSION_KEY_CONFLICT', 'MODEL_COST_UNKNOWN', 'BUDGET_EXHAUSTED'];
      if (allowed.includes(response.error?.code as string)) report.lastControlRefusal = { method, code: response.error!.code };
    }
    assert.equal(response.protocolVersion, 1); assert.equal(response.ok, true, `actual installed ${method} must be enabled and accepted`);
    assert(response.result && response.result.method === method); return response.result;
  };
  const show = (unit: string) => {
    const result = command('/usr/bin/systemctl', ['--user', 'show', unit, '--property=Id,ActiveState,SubState,MainPID,ExecMainPID,InvocationID,ControlGroup,Type,Delegate,KillMode,Result,ExecMainCode,ExecMainStatus', '--no-pager']);
    assert.equal(result.status, 0); return Object.fromEntries(result.stdout.trim().split('\n').map(line => {
      const at = line.indexOf('='); assert(at > 0); return [line.slice(0, at), line.slice(at + 1)]; }));
  };
  const observe = () => {
    const result = command(recipe.observer, ['list']); assert.equal(result.status, 0);
    const value = parseJsonStrict(result.stdout.trim()) as { serviceUid: number; servicePid: number; nameOwner: string;
      collection: string; items: string[]; connectionClosed: boolean };
    assert.equal(value.serviceUid, ledger.uid); assert.equal(value.connectionClosed, true); return value;
  };
  const storeFixture = (action: 'alias-session' | 'alias-restore', collection?: string) => {
    assert.equal(action === 'alias-restore', collection !== undefined);
    const result = command(recipe.storeFixture, [action, ...(collection === undefined ? [] : [collection])]);
    assert.equal(result.status, 0, 'owned standard Secret Service alias fixture refused');
    const value = parseJsonStrict(result.stdout.trim()) as Record<string, unknown>;
    const field = action === 'alias-session' ? 'defaultAliasSession' : 'defaultAliasMatched';
    assert.deepEqual(Object.keys(value).sort(), ['diagnosticOnly', 'action', 'collection', field, 'connectionClosed'].sort());
    assert.equal(value.diagnosticOnly, true); assert.equal(value.action, action); assert.equal(value[field], true);
    assert.equal(value.connectionClosed, true); assert.equal(typeof value.collection, 'string');
    if (collection !== undefined) assert.equal(value.collection, collection);
    return value;
  };
  // systemd may unload an inactive unreferenced unit and discard its exit
  // history. Hold both actual unit objects on one real user-bus connection
  // until the original stop/show assertions finish; never change the units.
  const withRetainedUnitHistory = async (units: string[], body: () => Promise<void>): Promise<void> => {
    assert.equal(units.length, 2);
    const outScan = scanner.openStream();
    let errorScan: ReturnType<typeof scanner.openStream>;
    try { errorScan = scanner.openStream(); } catch (error) { outScan.close(); throw error; }
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn('/usr/sbin/runuser', [...prefix, recipe.observer, 'retain-systemd', ...units],
        { env: environment, cwd: ledger.home, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (error) { outScan.close(); errorScan.close(); throw error; }
    const retained = 'systemd_units_retained\n', released = `${retained}systemd_units_released\n`;
    let output = '', bytes = 0, errorBytes = 0, observationError: unknown, releasing = false;
    let readyResolve!: () => void, readyReject!: (error: unknown) => void;
    const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const refuse = (error: unknown) => { observationError ??= error; readyReject(error); };
    child.stdout.on('data', (chunk: Buffer) => {
      try {
        outScan.scan(chunk); bytes += chunk.length; assert(bytes <= 1024, 'unit-history observer output exceeded its bound');
        output += chunk.toString('utf8');
        assert(released.startsWith(output), 'unit-history observer emitted an invalid fixed frame');
        assert(releasing || output.length <= retained.length, 'unit-history observer released before exit observation');
        if (output === retained) readyResolve();
      } catch (error) { refuse(error); }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      try { errorScan.scan(chunk); errorBytes += chunk.length; assert(errorBytes <= 1024, 'unit-history observer errors exceeded their bound'); }
      catch (error) { refuse(error); }
    });
    child.stdin.on('error', refuse); child.stdout.on('error', refuse); child.stderr.on('error', refuse);
    const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
      child.once('error', refuse);
      child.once('close', (code, signal) => {
        outScan.close(); errorScan.close();
        if (!releasing) refuse(new Error('unit-history observer exited before release'));
        resolve({ code, signal });
      });
    });
    const failures: unknown[] = [];
    try {
      await bounded(Promise.race([ready, closed.then(() => { throw new Error('unit-history observer closed before readiness'); })]),
        10000, 'unit-history observer did not retain the actual units');
      await body();
    } catch (error) { failures.push(error); }
    finally {
      releasing = true;
      try {
        child.stdin.end('R');
        const exit = await bounded(closed, 10000, 'unit-history observer did not release and join');
        assert.equal(exit.signal, null); assert.equal(exit.code, 0); assert.equal(observationError, undefined);
        assert.equal(output, released); assert.equal(errorBytes, 0);
        report.unitExitHistoryObserverJoined = true;
      } catch (error) { failures.push(error); }
    }
    if (failures.length) throw new AggregateError(failures, 'actual unit exit history was not retained and joined');
  };
  let daemon: ChildProcess | undefined, daemonExit: Promise<void> | undefined, daemonPid: number | undefined, daemonStart: string | undefined;
  let installedServices: { supervisorUnit: string; keeperUnit: string } | undefined;
  let retryPlatform: ReturnType<typeof observe> | undefined, aliasRestoreCollection: string | undefined;
  let server: Server | undefined;
  let primary: unknown, providerFailure = false, requestsReceived = 0, reflectionEnabled = false, shortRunEnabled = false;
  let busySubmit: (Record<string, unknown> & { admissionKey: string }) | undefined;
  const socketClosures: Promise<void>[] = [];
  const processStart = async (pid: number) => {
    assert(Number.isSafeInteger(pid) && pid > 0);
    const text = await readFile(`/proc/${pid}/stat`, 'utf8'); assert(text.startsWith(`${pid} (`) && text.length <= 8192);
    const values = text.slice(text.lastIndexOf(')') + 2).trim().split(/\s+/u); assert(!['Z', 'X', 'x'].includes(values[0]!));
    assert.match(values[19]!, /^[1-9][0-9]*$/u); return values[19]!;
  };
  const fixtureProcess = async (pid: number, uid: number, parent?: number) => {
    const start = await processStart(pid), status = await readFile(`/proc/${pid}/status`, 'utf8');
    assert(status.length <= 65536);
    const uids = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu);
    const ppid = status.match(/^PPid:\s+(\d+)$/mu);
    assert(uids && uids.slice(1).every(value => Number(value) === uid));
    if (parent !== undefined) assert(ppid && Number(ppid[1]) === parent);
    assert.equal(await processStart(pid), start); return start;
  };
  const restoreRetryAlias = async () => {
    if (aliasRestoreCollection === undefined) return;
    // Consume this cleanup obligation once. A failed real restoration remains
    // a failure; it is never replaced with a synthetic observation or unlock.
    const original = aliasRestoreCollection; aliasRestoreCollection = undefined;
    assert(retryPlatform && daemonPid && daemonStart);
    report.retryAliasRestoration = storeFixture('alias-restore', original);
    assert.equal(await fixtureProcess(daemonPid, ledger.uid, daemon!.pid), daemonStart);
    const restored = observe();
    for (const key of ['nameOwner', 'servicePid', 'serviceUid', 'collection'] as const) assert.equal(restored[key], retryPlatform[key]);
    assert.deepEqual(restored.items, retryPlatform.items);
    report.retryAliasRestoration.sameOriginalDaemonAndItem = true;
  };
  const selectedSupervisor = async (unit: string, shown: Record<string, string>, image: string, by: number) => {
    // Type=exec acknowledges bootstrap, not its asynchronous verified exec
    // handoff. Keep the original PID/start pinned and spend the existing
    // recovery budget waiting; never accept a different image or invocation.
    const pid = Number(shown.MainPID), start = await fixtureProcess(pid, ledger.uid);
    for (;;) {
      assert(Date.now() < by, 'restarted bootstrap did not enter the actual selected image');
      assert.equal(await fixtureProcess(pid, ledger.uid), start);
      const actual = await readlink(`/proc/${pid}/exe`);
      if (actual === image) break;
      assert.equal(actual, path.join(recipe.stateRoot, 'runtime/bootstrap'));
      await delay(50);
    }
    const actual = await stat(`/proc/${pid}/exe`, { bigint: true }), selected = await lstat(image, { bigint: true });
    for (const key of imageFields) assert.equal(actual[key], selected[key]);
    exchange([], by); // Only pre-connect absence/refusal may wait, not protocol failures.
    assert(Date.now() < by, 'restarted public control readiness exhausted the existing recovery budget');
    const confirmed = show(unit);
    assert.equal(confirmed.MainPID, shown.MainPID); assert.equal(confirmed.ExecMainPID, shown.ExecMainPID);
    assert.equal(confirmed.InvocationID, shown.InvocationID); assert.equal(confirmed.ActiveState, 'active');
    assert.equal(await fixtureProcess(pid, ledger.uid), start); assert.equal(await readlink(`/proc/${pid}/exe`), image);
    return start;
  };
  const readCas = async (ref: string): Promise<Buffer> => {
    assert.match(ref, /^[0-9a-f]{64}$/u);
    const held = await open(path.join(recipe.stateRoot, 'cas', ref), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = await held.stat({ bigint: true }); assert(before.isFile() && before.uid === BigInt(ledger.uid) &&
        (before.mode & 0o7777n) === 0o400n && before.nlink === 1n && before.size <= 1048576n);
      const bytes = await held.readFile(); const after = await held.stat({ bigint: true });
      for (const key of imageFields) assert.equal(after[key], before[key]);
      assert.equal(sha256Bytes(bytes), ref); scanBytes(bytes); return bytes;
    } finally { await held.close(); }
  };
  const privateCheckpoint = async (checkpoint: Record<string, any>) => {
    // Diagnostic-only immutable bytes selected by the actual public snapshot.
    // Never writes CAS/SQL, mints native authority or creates a Checkpoint.
    const state = parseJsonStrict((await readCas(checkpoint.workspaceStateRef)).toString('utf8')) as Record<string, any>;
    assert.equal(state.stateDigest, digestOmitting(state, 'stateDigest'));
    const entries = parseJsonStrict((await readCas(state.entriesRef)).toString('utf8')) as { entries: Array<Record<string, any>> };
    const file = entries.entries.find(entry => entry.path === 'example.txt'); assert(file && file.kind === 'file');
    assert.equal((await readCas(file.blobRef)).toString('utf8'), privateAfter);
    return { checkpointId: checkpoint.id, workspaceStateRef: checkpoint.workspaceStateRef, entriesRef: state.entriesRef, blobRef: file.blobRef };
  };
  try {
    mark('owned_tls_fixture');
    await mkdir(recipe.buildFixture, { mode: 0o755 });
    const keyFile = path.join(recipe.buildFixture, 'owned-https-key.pem'), certFile = path.join(recipe.buildFixture, 'owned-https-cert.pem');
    const certificate = spawnSync('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile,
      '-out', certFile, '-days', '2', '-subj', '/CN=installed-run-fixture.invalid', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:installed-run-fixture.invalid'],
    { env: environment, timeout: 10000, maxBuffer: 65536 });
    assert.equal(certificate.error, undefined); assert.equal(certificate.status, 0, 'owned TLS certificate generation failed');
    const key = await readFile(keyFile), cert = await readFile(certFile);
    server = createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', maxHeaderSize: 65536 }, async (incoming, outgoing) => {
      try {
        assert.equal(incoming.method, 'POST'); assert.equal(incoming.url, '/v1/chat/completions');
        assert(incoming.headers.authorization === `Bearer ${secret.toString('utf8')}`, 'owned HTTPS authentication mismatch');
        assert.equal(incoming.headers['content-type'], 'application/json');
        const chunks: Buffer[] = []; let size = 0;
        for await (const chunk of incoming) { size += chunk.length; assert(size <= 1048576); chunks.push(Buffer.from(chunk)); }
        const bodyBytes = Buffer.concat(chunks); scanBytes(bodyBytes);
        assert.equal(Number(incoming.headers['content-length']), bodyBytes.length);
        const body = parseJsonStrict(bodyBytes.toString('utf8')) as Record<string, any>;
        assert.equal(body.model, model); assert.equal(body.stream, false); assert.equal(body.max_tokens, 4096);
        assert(Array.isArray(body.messages) && Array.isArray(body.tools));
        assert.deepEqual(body.tools.map((tool: any) => tool.function.name), ['edit']);
        const ordinal = ++requestsReceived;
        if (failureOnly) {
          assert.equal(ordinal, 1, 'a positively received provider rejection must not be retried');
          assert(body.messages.some((message: any) => typeof message.content === 'string' &&
            message.content.includes('Observe the owned caf\u00e9 model failure without using a tool.')),
          'the model must receive the normalized objective, not the original NFD request spelling');
          try {
            // The actual complete POST holds the original credential scope
            // until this responder replies. A fresh UDS connection can refuse
            // without that scope; never ask for queued installation/status work.
            assert(busySubmit);
            const reply = exchange([busySubmit], 0, 5000)[0]!;
            const code = reply.error?.code;
            report.credentialScopeBusy = { observedCode: !reply.ok && (code === 'RATE_LIMITED' || code === 'INVALID_REQUEST')
              ? code : 'unrecognized', exactPayloadMatched: canonicalSha256(reply) === canonicalSha256({
              protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1,
                code: 'RATE_LIMITED', retryable: true, retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' } }) };
          } catch {
            report.credentialScopeBusy = { observedCode: 'unavailable', exactPayloadMatched: false };
          } finally {
            // Even the expected RED must preserve the original positively
            // received rejection, its settlement and physical terminal drain.
            const bytes = Buffer.from(rejectedResponse); scanBytes(bytes);
            outgoing.writeHead(429, { 'Content-Type': 'application/json', 'Content-Length': String(bytes.length), Connection: 'close' }); outgoing.end(bytes);
            report.providerRequests = { received: ordinal, method: 'POST', requestPath: '/v1/chat/completions', tls13: true,
              exactCredentialMatched: true, status: 429, latestBodyDigest: sha256Bytes(bodyBytes), latestBodyBytes: bodyBytes.length };
          }
          return;
        }
        if (retryOnly) {
          assert.equal(ordinal, 1, 'free preparation failures must lead to exactly one actual model dispatch');
          const bytes = Buffer.from(JSON.stringify({ id: 'owned-retry-fixture-turn', object: 'chat.completion', model,
            choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'The restored preparation is complete.' } }],
            usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } }));
          scanBytes(bytes);
          outgoing.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(bytes.length), Connection: 'close' }); outgoing.end(bytes);
          report.providerRequests = { received: ordinal, method: 'POST', requestPath: '/v1/chat/completions', tls13: true,
            exactCredentialMatched: true, status: 200, latestBodyDigest: sha256Bytes(bodyBytes), latestBodyBytes: bodyBytes.length };
          return;
        }
        assert(ordinal <= (shortRunEnabled ? 4 : reflectionEnabled ? 3 : 2), 'replay or restart must not redispatch the completed model attempts');
        if (ordinal === 2) {
          assert.equal(body.messages.filter((message: any) => message.role === 'tool' && message.tool_call_id === 'owned-private-edit-call').length, 1);
        }
        let reflectedArguments: string | undefined;
        if (ordinal === 3) {
          assert(reflectionEnabled);
          // Deliberately hostile owned-server bytes only. No raw authorization
          // header or reflected response is ever logged/persisted. This exact
          // nested string would require a second JSON parse to reveal the key.
          const unicodeKey = [...secret].map(byte => `\\u${byte.toString(16).padStart(4, '0')}`).join('');
          reflectedArguments = `{"path":"example.txt","old_text":${JSON.stringify(hostBefore)},"new_text":"${unicodeKey}"}`;
        }
        if (ordinal === 4) assert(shortRunEnabled, 'only the separately admitted short Run may send the fourth model request');
        const payload = { id: `owned-fixture-turn-${ordinal}`, object: 'chat.completion', model,
          choices: [{ index: 0, finish_reason: ordinal === 1 || ordinal === 3 ? 'tool_calls' : 'stop', message: ordinal === 1 || ordinal === 3
            ? { role: 'assistant', content: '', tool_calls: [{ id: 'owned-private-edit-call', type: 'function',
              function: { name: 'edit', arguments: reflectedArguments ?? JSON.stringify({ path: 'example.txt', old_text: hostBefore, new_text: privateAfter }) } }] }
            : { role: 'assistant', content: 'The private edit is complete.' } }],
          usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
        const bytes = Buffer.from(JSON.stringify(payload)); scanBytes(bytes);
        outgoing.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(bytes.length), Connection: 'close' }); outgoing.end(bytes);
        report.providerRequests = { received: ordinal, method: 'POST', requestPath: '/v1/chat/completions', tls13: true,
          exactCredentialMatched: true, latestBodyDigest: sha256Bytes(bodyBytes), latestBodyBytes: bodyBytes.length };
      } catch { providerFailure = true; incoming.destroy(); outgoing.destroy(); }
    });
    server.on('connection', socket => { socketClosures.push(new Promise(resolve => socket.once('close', resolve))); });
    server.on('secureConnection', socket => { if (socket.getProtocol() !== 'TLSv1.3') { providerFailure = true; socket.destroy(); } });
    server.on('tlsClientError', () => { providerFailure = true; });
    await new Promise<void>((resolve, reject) => { server!.once('error', reject); server!.listen(0, '127.0.0.1', resolve); });
    key.fill(0);
    const address = server.address(); assert(address && typeof address === 'object');
    const pin = sha256Bytes(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' }));
    mark('signed_installation');
    const signed = await buildInstalledSupervisorPackage(recipe.buildFixture, 'complete', { provider: 'openai-compatible', model,
      target: { hostAscii: '127.0.0.1', port: address.port, basePath: '/v1' },
      tls: { serverNameAscii: 'installed-run-fixture.invalid', caPem: cert, spkiSha256Pins: [pin] },
      claims: { nativeToolCalling: true, streaming: false, trustedUsageEvidence: false, contextLimitTokens: 32768, maxOutputTokens: 4096 },
      requestTokenCeiling, validFrom: new Date(Date.now() - 60000).toISOString(), validThrough: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() });
    const staged = await build({ entryPoints: [fileURLToPath(new URL('./testing/installed-runtime-installer.ts', import.meta.url))],
      outfile: recipe.installerEntry, bundle: true, platform: 'node', format: 'esm', target: 'node22.13', metafile: true, write: false });
    assert(Object.values(staged.metafile!.outputs).flatMap(value => value.imports).every(value => value.external && value.path.startsWith('node:')));
    assert.equal(staged.outputFiles!.length, 1); await writeFile(recipe.installerEntry, staged.outputFiles![0]!.contents, { flag: 'wx', mode: 0o444 });
    await writeFile(recipe.releaseKeysFile, canonicalJsonBytes(signed.releaseKeys), { flag: 'wx', mode: 0o444 });
    await transferPackage(recipe.packageRoot, ledger.uid, ledger.gid);
    const home = path.join(ledger.home, '.cliq'); await mkdir(home, { mode: 0o700 }); await chown(home, ledger.uid, ledger.gid);
    const installation = command(process.execPath, [recipe.installerEntry, recipe.packageRoot, recipe.stateRoot, recipe.releaseKeysFile]);
    assert.equal(installation.status, 0, 'actual same-user signed installation refused');
    const bundleDigest = (parseJsonStrict(installation.stdout.trim()) as { bundleDigest: string }).bundleDigest;
    assert.equal(bundleDigest, canonicalSha256(signed.bundle)); assert(signed.modelAuthority);
    report.bundle = { bundleDigest, manifestDigest: signed.bundle.manifestDigest,
      supervisorDigest: signed.bundle.entries.find(entry => entry.role === 'supervisor')!.digest,
      brokerDigest: signed.bundle.entries.find(entry => entry.entryId === 'openai-compatible-broker-v1')!.digest,
      authorityClosureRef: signed.modelAuthority.closure.ref };
    mark('actual_secret_service');
    await mkdir(recipe.controlDirectory, { mode: 0o700 }); await chown(recipe.controlDirectory, ledger.uid, ledger.gid);
    daemon = spawn('/usr/sbin/runuser', [...prefix, '/usr/bin/gnome-keyring-daemon', '--foreground', '--components=secrets', '--unlock',
      `--control-directory=${recipe.controlDirectory}`], { env: environment, stdio: ['pipe', 'ignore', 'ignore'] });
    daemonExit = new Promise<void>((resolve, reject) => { daemon!.once('close', () => resolve()); daemon!.once('error', reject); });
    daemon.stdin!.on('error', () => {}); daemon.stdin!.end(password);
    const deadline = Date.now() + 10000;
    for (;;) {
      const owner = command('/usr/bin/busctl', [`--address=unix:path=/run/user/${ledger.uid}/bus`, 'call', 'org.freedesktop.DBus',
        '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner', 's', 'org.freedesktop.secrets']);
      assert.equal(owner.status, 0);
      if (owner.stdout.trim() === 'b true') break;
      assert(Date.now() < deadline && daemon.exitCode === null); await delay(20);
    }
    const platform = observe(); assert.deepEqual(platform.items, []);
    assert(daemon.pid); await fixtureProcess(daemon.pid, 0, process.pid);
    daemonPid = platform.servicePid; daemonStart = await fixtureProcess(daemonPid, ledger.uid, daemon.pid);
    assert.equal(await readlink(`/proc/${daemonPid}/exe`), '/usr/bin/gnome-keyring-daemon');
    const daemonImage = await stat(`/proc/${daemonPid}/exe`, { bigint: true });
    const namedDaemon = await lstat('/usr/bin/gnome-keyring-daemon', { bigint: true });
    for (const key of imageFields) assert.equal(daemonImage[key], namedDaemon[key]);
    const confirmedPlatform = observe(); assert.equal(confirmedPlatform.nameOwner, platform.nameOwner);
    assert.equal(confirmedPlatform.servicePid, daemonPid); assert.deepEqual(confirmedPlatform.items, []);
    mark('production_service_setup');
    const setupResult = credential({ schemaVersion: 1, kind: 'install_services' }); assert.equal(setupResult.status, 0);
    const services = parseJsonStrict(setupResult.stdout.trim()) as { schemaVersion: 1; keeperUnit: string; supervisorUnit: string };
    assert.deepEqual(Object.keys(services).sort(), ['schemaVersion', 'keeperUnit', 'supervisorUnit'].sort());
    for (const unit of [services.keeperUnit, services.supervisorUnit]) assert.match(unit, /^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,240}\.service$/u);
    installedServices = services;
    report.services = services;
    const root = await lstat(recipe.stateRoot, { bigint: true });
    const rootDigest = canonicalSha256({ schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux',
      canonicalAbsolutePath: recipe.stateRoot, ownerUid: ledger.uid, deviceId: root.dev.toString(), directoryFileId: root.ino.toString(),
      mode: 448, openedNoFollow: true, layoutVersion: 1 });
    const principal = identityHash('cliq-local-principal-v1', rootDigest, 'linux', ledger.uid);
    const registration: EndpointRegistrationV1 = { schemaVersion: 1, format: 'cliq-endpoint-registration-v1', endpointRegistrationId: 'installed-run-endpoint',
      registrationKind: 'user', ownerPrincipalId: principal, purposes: ['model_endpoint'], ...signed.modelAuthority.endpoint,
      createdAt: new Date().toISOString(), registrationDigest: '' };
    registration.registrationDigest = digestOmitting(registration, 'registrationDigest');
    const core = { schemaVersion: 1, kind: 'register', ownerPrincipalId: principal, registration,
      expectedRegistrationArtifactRef: canonicalSha256(registration), commandDigest: '' };
    const endpoint = command(path.join(recipe.stateRoot, 'runtime/bootstrap'), ['--bootstrap-endpoint'], canonicalJsonBytes({ schemaVersion: 1,
      kind: 'commit', requestId: '019a0012-0000-7000-8000-000000000101', commandCore: { ...core, commandDigest: digestOmitting(core, 'commandDigest') } }));
    assert.equal(decodeEndpointAuthorityOperation(success(endpoint, 'operation')).disposition, 'registered');
    const enrollment = { schemaVersion: 1, kind: 'enroll', requestId: '019a0012-0000-7000-8000-000000000102', credentialGrantId: 'installed-run-credential',
      purpose: 'model_endpoint', endpointRegistrationId: registration.endpointRegistrationId, secretSubmissionId: 'installed-run-fixture-secret', expiresAt: '2099-01-01T00:00:00.000Z' };
    const operation = decodeCredentialAuthorityOperation(success(credential(enrollment, secret), 'operation'));
    assert.equal(operation.phase, 'committed'); assert.equal(operation.ownerPrincipalId, principal); assert.equal(operation.attempt, 1);
    assert.equal(observe().items.length, 1); report.credentialEnrolled = true;
    const keeperBefore = show(services.keeperUnit), supervisorBefore = show(services.supervisorUnit);
    for (const state of [keeperBefore, supervisorBefore]) {
      assert.equal(state.ActiveState, 'active'); assert.equal(state.SubState, 'running'); assert.equal(state.MainPID, state.ExecMainPID);
      assert.equal(state.Type, 'exec'); assert.equal(state.Delegate, 'yes'); assert.equal(state.KillMode, 'control-group');
      assert.match(state.InvocationID!, /^[0-9a-f]{32}$/u);
      assert.equal(await readlink(`/proc/${state.MainPID}/exe`), path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor'));
    }
    const keeperReady = await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready'));
    mark('public_session_create');
    await mkdir(recipe.workspace, { mode: 0o700 }); await chown(recipe.workspace, ledger.uid, ledger.gid);
    const source = path.join(recipe.workspace, 'example.txt'); await writeFile(source, hostBefore, { flag: 'wx', mode: 0o644 }); await chown(source, ledger.uid, ledger.gid);
    const sourceBefore = await lstat(source, { bigint: true });
    const workspaceId = sha256Bytes(Buffer.from(recipe.workspace)), trustDirectory = path.join(home, 'workspaces', workspaceId);
    await mkdir(trustDirectory, { recursive: true, mode: 0o700 });
    for (const directory of [path.dirname(trustDirectory), trustDirectory]) await chown(directory, ledger.uid, ledger.gid);
    const trustPath = path.join(trustDirectory, 'trust.json'); await writeFile(trustPath, canonicalJsonBytes({ version: 1, workspaceId,
      workspaceRealPath: recipe.workspace, decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trustPath, ledger.uid, ledger.gid);
    if (failureOnly) {
      mark('session_trust_before_git_config');
      const untrustedWorkspace = path.join(ledger.home, 'untrusted-git-workspace'), git = path.join(untrustedWorkspace, '.git');
      for (const directory of [untrustedWorkspace, git]) {
        await mkdir(directory, { mode: 0o700 }); await chown(directory, ledger.uid, ledger.gid);
      }
      const config = path.join(git, 'config');
      await writeFile(config, '[extensions]\nobjectFormat = unsupported\n', { flag: 'wx', mode: 0o600 }); await chown(config, ledger.uid, ledger.gid);
      const untrustedRequest = request({ protocolVersion: 1, method: 'session.create',
        requestId: '019a0012-0000-7000-8000-000000000122', admissionKey: randomBytes(32).toString('base64url'),
        workspacePath: untrustedWorkspace, name: 'Workspace Trust order' });
      const untrusted = exchange([untrustedRequest])[0]!;
      report.sessionTrustOrder = { qualified: false,
        untrustedObservedCode: ['INVALID_REQUEST', 'ARTIFACT_MISMATCH'].includes(untrusted.error?.code as string)
          ? untrusted.error!.code : 'unrecognized' };
      assert.equal(canonicalSha256(untrusted), canonicalSha256({ protocolVersion: 1, ok: false, method: 'session.create',
        error: { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false, messageCode: 'control.invalid_request',
          issues: [{ path: 'request', issueCode: 'invalid_request' }] } }));
      const gitWorkspaceId = sha256Bytes(Buffer.from(untrustedWorkspace)), gitTrustDirectory = path.join(home, 'workspaces', gitWorkspaceId);
      await mkdir(gitTrustDirectory, { mode: 0o700 }); await chown(gitTrustDirectory, ledger.uid, ledger.gid);
      const gitTrustPath = path.join(gitTrustDirectory, 'trust.json');
      await writeFile(gitTrustPath, canonicalJsonBytes({ version: 1, workspaceId: gitWorkspaceId,
        workspaceRealPath: untrustedWorkspace, decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 });
      await chown(gitTrustPath, ledger.uid, ledger.gid);
      const trusted = exchange([untrustedRequest])[0]!;
      assert.equal(canonicalSha256(trusted), canonicalSha256({ protocolVersion: 1, ok: false, method: 'session.create',
        error: { schemaVersion: 1, code: 'ARTIFACT_MISMATCH', retryable: false, messageCode: 'control.read_rejected' } }));
      report.sessionTrustOrder = { ...report.sessionTrustOrder, qualified: true, untrustedRefusedBeforeGitConfig: true,
        unchangedConfigStillRefusedAfterPersistedTrust: true };
    }
    const sessionRequest = request({ protocolVersion: 1, method: 'session.create', requestId: '019a0012-0000-7000-8000-000000000103',
      admissionKey: randomBytes(32).toString('base64url'), workspacePath: recipe.workspace, name: 'Installed Run journey' });
    const sessionReply = exchange([sessionRequest])[0]!, session = accepted(sessionReply, 'session.create').snapshot.session;
    assert.deepEqual(exchange([sessionRequest])[0], sessionReply, 'new authenticated connection must replay the original Session response');
    const currentSession = () => accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id }])[0]!, 'session.get').snapshot.session;
    mark('public_run_submit');
    const runBudgets = { wallTimeMs: failureOnly || retryOnly ? 45000 : 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000,
      repairAttempts: 0, childDepth: 0, childConcurrency: 1 };
    const submit = request({ protocolVersion: 1, method: 'run.submit', requestId: '019a0012-0000-7000-8000-000000000104',
      admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
      workspacePath: recipe.workspace, objective: retryOnly ? 'Acknowledge restored model preparation without using a tool.'
        : failureOnly ? 'Observe the owned cafe\u0301 model failure without using a tool.'
          : 'Change example.txt from before the private edit to after the private edit, using one edit operation.',
      model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: registration.endpointRegistrationId },
        modelCredentialGrantIds: [enrollment.credentialGrantId] }, policyMode: 'accept-edits',
      budgets: runBudgets,
      verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true });
    const { requestDigest: _resourceDigest, ...resourceCore } = submit;
    if (failureOnly) {
      busySubmit = request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000123',
        admissionKey: randomBytes(32).toString('base64url') });
      report.credentialScopeBusy = { observedCode: 'not_observed', exactPayloadMatched: false };
    }
    if (!failureOnly && !retryOnly) {
      const unauthorized = exchange([request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000114',
        model: { ...resourceCore.model, modelCredentialGrantIds: ['installed-run-absent-credential'] } })])[0]!;
      assert.equal(unauthorized.ok, false, 'an absent credential cannot authorize installed Run admission');
      assert.equal(unauthorized.error!.code, 'AUTHORIZATION_REQUIRED');
      assert.equal(unauthorized.error!.retryable, false);
      assert.equal(unauthorized.error!.messageCode, 'run.model_authority_refused');
      assert.equal(requestsReceived, 0); assert.deepEqual(currentSession(), session);
    }
    const oversized = exchange([request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000113',
      sandboxResources: { maxSingleFileBytes: 2_147_483_648 } })])[0]!;
    assert.equal(oversized.ok, false, 'unsupported explicit file limits must be refused before Run admission');
    assert.equal(oversized.error!.code, 'INVALID_REQUEST'); assert.equal(requestsReceived, 0);
    if (retryOnly) {
      mark('real_default_alias_drift_before_submission');
      retryPlatform = observe(); assert.equal(retryPlatform.items.length, 1);
      assert.match(retryPlatform.collection, /^\/org\/freedesktop\/secrets\/collection\/[A-Za-z0-9_]+$/u);
      assert.notEqual(retryPlatform.collection, '/org/freedesktop/secrets/collection/session');
      aliasRestoreCollection = retryPlatform.collection;
      report.retryAliasDrift = storeFixture('alias-session');
      assert.notEqual(report.retryAliasDrift.collection, retryPlatform.collection);
    }
    const submitReply = exchange([submit])[0]!, admitted = accepted(submitReply, 'run.submit').snapshot.run;
    report.oversizedFileLimitRefused = { requestedBytes: 2_147_483_648, installedLimitBytes: 268_435_456,
      sameAdmissionKeySubsequentlyAccepted: true, silentClampingAllowed: false };
    report.acceptedRun = { id: admitted.id, sessionId: admitted.sessionId, specRef: admitted.specRef, initialCheckpointId: admitted.latestCheckpointId };
    assert.equal(admitted.status, 'queued'); assert.equal(admitted.revision, 1);
    if (!failureOnly && !retryOnly) report.unauthorizedAdmissionRefused = { qualified: true, refusalCode: 'AUTHORIZATION_REQUIRED',
      fixedReason: 'run.model_authority_refused', noProviderRequest: true, sameAdmissionKeySubsequentlyAccepted: true };
    // The submission client has exited and closed its actual socket. All
    // further observation uses a fresh native authenticated connection.
    const read = () => {
      const cut = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: admitted.id }])[0]!, 'run.get');
      report.lastPublicCut = projectInstalledRunProgress(cut, { requestsReceived, providerFailure });
      return cut;
    };
    if (retryOnly) {
      mark('real_pre_dispatch_failure_without_claim');
      assert.equal(Date.parse(admitted.deadlineAt) - Date.parse(admitted.createdAt), 45000);
      const fullCharge = { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
      const zeroCharge = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
      const failedBy = Date.now() + 10000;
      let failedCut: Record<string, any>;
      for (;;) {
        await delay(50); failedCut = read(); assert(!providerFailure); assert.equal(requestsReceived, 0);
        assert(!['failed', 'cancelled', 'succeeded', 'completed_unverified'].includes(failedCut.snapshot.run.status));
        if (failedCut.journal.at(-1)?.phase === 'failed') break;
        assert(Date.now() < failedBy, 'real alias drift did not settle its preparation without dispatch');
      }
      assert(Date.now() < failedBy);
      const originalWorker = failedCut.snapshot.run.activeWorkerLaunchId, originalEpoch = failedCut.snapshot.run.leaseEpoch;
      assert.equal(failedCut.snapshot.run.status, 'running'); assert(originalWorker); assert.equal(originalEpoch, 1);
      assert.equal(failedCut.snapshot.run.stopIntentRef, undefined); assert.equal(failedCut.snapshot.run.resultRef, undefined);
      for (const actual of [failedCut.snapshot.run.budgetConsumed, failedCut.snapshot.run.budgetReserved])
        assert.equal(canonicalSha256(actual), canonicalSha256(zeroCharge));
      const inspectFreeFailures = async (entries: Array<Record<string, any>>) => {
        assert(entries.length >= 2 && entries.length % 2 === 0);
        const first = entries[0];
        for (let index = 0; index < entries.length; index += 2) {
          const prepared = entries[index], failed = entries[index + 1];
          assert.deepEqual([prepared.opKind, prepared.phase, prepared.attempt, failed.opKind, failed.phase, failed.attempt],
            ['model', 'prepared', index / 2, 'model', 'failed', index / 2]);
          assert.equal(prepared.runId, admitted.id); assert.equal(prepared.opId, first.opId); assert.equal(prepared.target, first.target);
          assert.equal(failed.runId, admitted.id); assert.equal(failed.target, first.target);
          assert.equal(failed.opId, prepared.opId); assert.equal(failed.requestRef, prepared.requestRef); assert.equal(failed.seq, prepared.seq + 1);
          assert.equal(canonicalSha256(prepared.budgetDelta), canonicalSha256(fullCharge));
          assert.equal(canonicalSha256(failed.budgetDelta), canonicalSha256(zeroCharge));
          assert.equal(failed.dispatchId, undefined); assert.equal(failed.resultRef, undefined);
          const settlement = parseJsonStrict((await readCas(failed.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
          assert.equal(settlement.runId, admitted.id); assert.equal(settlement.opId, prepared.opId); assert.equal(settlement.attempt, prepared.attempt);
          assert.equal(settlement.preparedJournalSeq, prepared.seq); assert.equal(settlement.terminalJournalSeq, failed.seq);
          assert.equal(settlement.terminalPhase, 'failed'); assert.equal(settlement.settlementDigest, digestOmitting(settlement, 'settlementDigest'));
          for (const actual of [settlement.reserved, settlement.released]) assert.equal(canonicalSha256(actual), canonicalSha256(fullCharge));
          for (const actual of [settlement.consumed, settlement.budgetConsumedBefore, settlement.budgetConsumedAfter, settlement.budgetReservedAfter])
            assert.equal(canonicalSha256(actual), canonicalSha256(zeroCharge));
          assert.equal(canonicalSha256(settlement.budgetReservedBefore), canonicalSha256(fullCharge));
          const error = parseJsonStrict((await readCas(failed.errorRef)).toString('utf8')) as Record<string, any>;
          assert.equal(error.reason, 'installed_model_preparation_refused'); assert.equal(error.requestRef, prepared.requestRef);
        }
      };
      assert.equal(failedCut.nextJournalSeq, failedCut.highWaterJournalSeq); await inspectFreeFailures(failedCut.journal);
      assert.deepEqual(currentSession(), session);
      report.retryPreparationFailure = { qualified: true, runId: admitted.id, attempts: failedCut.journal.length / 2,
        journalPhases: failedCut.journal.map((entry: any) => [entry.phase, entry.attempt, entry.seq]),
        zeroConsumedAndReserved: true, noDispatchClaim: true, noProviderRequest: true,
        originalActiveWorkerLaunchId: originalWorker, originalLeaseEpoch: originalEpoch };
      mark('exact_alias_restoration_then_existing_scheduler_retry');
      await restoreRetryAlias();
      const resumedBy = Date.now() + 15000;
      let resumed: Record<string, any>;
      for (;;) {
        await delay(50); resumed = read(); assert(!providerFailure);
        assert.equal(resumed.snapshot.run.activeWorkerLaunchId, originalWorker); assert.equal(resumed.snapshot.run.leaseEpoch, originalEpoch);
        assert.equal(resumed.snapshot.run.status, 'running'); assert.equal(resumed.snapshot.run.stopIntentRef, undefined);
        if (resumed.journal.at(-1)?.phase === 'completed') break;
        assert(Date.now() < resumedBy, 'restored real preparation was not rescheduled within the independent 15s bound');
      }
      assert(Date.now() < resumedBy);
      assert.equal(requestsReceived, 1); assert.equal(resumed.nextJournalSeq, resumed.highWaterJournalSeq);
      const free = resumed.journal.slice(0, -3), [prepared, claimed, completed] = resumed.journal.slice(-3);
      await inspectFreeFailures(free); assert(free.length >= failedCut.journal.length);
      assert.deepEqual(free.slice(0, failedCut.journal.length), failedCut.journal);
      assert.deepEqual([prepared.opKind, prepared.phase, claimed.opKind, claimed.phase, completed.opKind, completed.phase],
        ['model', 'prepared', 'model', 'dispatch_claimed', 'model', 'completed']);
      assert.equal(prepared.attempt, free.length / 2);
      for (const entry of [prepared, claimed, completed]) {
        assert.equal(entry.runId, admitted.id); assert.equal(entry.opId, free[0].opId); assert.equal(entry.attempt, prepared.attempt);
        assert.equal(entry.requestRef, prepared.requestRef); assert.equal(entry.target, free[0].target);
      }
      assert.equal(claimed.seq, prepared.seq + 1); assert.equal(completed.seq, claimed.seq + 1);
      const originalRequest = parseJsonStrict((await readCas(free[0].requestRef)).toString('utf8')) as Record<string, any>;
      const retriedRequest = parseJsonStrict((await readCas(prepared.requestRef)).toString('utf8')) as Record<string, any>;
      for (const field of ['bodyBytesRef', 'bodyByteCount', 'assemblyRef', 'opId', 'runId', 'kind']) assert.equal(retriedRequest[field], originalRequest[field]);
      assert.equal(retriedRequest.kind, 'normal'); assert.equal(retriedRequest.requestDigest, digestOmitting(retriedRequest, 'requestDigest'));
      const turn = parseJsonStrict((await readCas(completed.resultRef)).toString('utf8')) as Record<string, any>;
      assert.equal(turn.format, 'cliq-agent-model-turn-v1'); assert.equal(turn.stopReason, 'end'); assert.deepEqual(turn.toolCalls, []);
      assert.equal(turn.requestDigest, retriedRequest.requestDigest);
      const settlement = parseJsonStrict((await readCas(completed.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
      assert.equal(settlement.runId, admitted.id); assert.equal(settlement.opId, prepared.opId); assert.equal(settlement.attempt, prepared.attempt);
      assert.equal(settlement.preparedJournalSeq, prepared.seq); assert.equal(settlement.terminalJournalSeq, completed.seq);
      assert.equal(settlement.terminalPhase, 'completed'); assert.equal(settlement.settlementDigest, digestOmitting(settlement, 'settlementDigest'));
      for (const actual of [settlement.reserved, settlement.consumed]) assert.equal(canonicalSha256(actual), canonicalSha256(fullCharge));
      // RFC: released removes the complete reservation; consumed is charged
      // separately. Releasing reserved counters is not a model refund.
      assert.equal(canonicalSha256(settlement.released), canonicalSha256(fullCharge));
      assert.equal(canonicalSha256(resumed.snapshot.run.budgetConsumed), canonicalSha256(fullCharge));
      assert.equal(canonicalSha256(resumed.snapshot.run.budgetReserved), canonicalSha256(zeroCharge));
      assert.equal(resumed.snapshot.run.resultRef, undefined); assert.deepEqual(currentSession(), session);
      const ready = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status'); assert.equal(ready.health, 'ready');
      const cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000115',
        runId: admitted.id, expectedRevision: resumed.snapshot.run.revision });
      accepted(exchange([cancel])[0]!, 'run.cancel');
      const cancelledBy = Date.now() + 15000;
      let terminal: Record<string, any>;
      for (;;) {
        await delay(50); terminal = read(); assert(!providerFailure);
        if (terminal.snapshot.run.status === 'cancelled') break;
        assert(Date.now() < cancelledBy, 'restored-preparation Run did not genuinely join after explicit cancellation');
      }
      assert(Date.now() < cancelledBy);
      const cancelled = terminal.snapshot.run;
      assert.equal(cancelled.terminalReason, 'cancelled_by_user'); assert.equal(cancelled.cancelRequested, true);
      assert.equal(cancelled.activeWorkerLaunchId, undefined); assert.equal(cancelled.resultRef, undefined);
      assert.equal(cancelled.leaseEpoch, originalEpoch); assert(cancelled.updatedAt < cancelled.deadlineAt);
      assert.deepEqual(terminal.journal, resumed.journal); assert.deepEqual(terminal.items, resumed.items);
      assert.deepEqual(cancelled.budgetConsumed, resumed.snapshot.run.budgetConsumed); assert.deepEqual(cancelled.budgetReserved, resumed.snapshot.run.budgetReserved);
      const intent = parseJsonStrict((await readCas(cancelled.stopIntentRef)).toString('utf8')) as Record<string, any>;
      assert.equal(intent.origin, 'user_cancel'); assert.equal(intent.reason, 'cancelled_by_user'); assert.equal(intent.requestId, cancel.requestId);
      const sessionCut = accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id, afterItemSeq: session.latestItemSeq }])[0]!, 'session.get');
      assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + 1);
      assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + 1); assert.equal(sessionCut.items.length, 1);
      const publication = parseJsonStrict((await readCas(sessionCut.items[0].payloadRef)).toString('utf8')) as Record<string, any>;
      assert.equal(canonicalSha256(publication), canonicalSha256({ schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
        itemKey: `run-terminal:${admitted.id}`, runId: admitted.id, operation: 'agent', admittedSessionItemSeq: session.latestItemSeq,
        status: 'cancelled', terminalReason: 'cancelled_by_user', terminalDetailRef: cancelled.terminalDetailRef }));
      assert.deepEqual(read(), terminal); assert.deepEqual(exchange([submit])[0], submitReply);
      assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id, afterItemSeq: session.latestItemSeq }])[0]!, 'session.get'), sessionCut);
      assert.equal(requestsReceived, 1); assert(!providerFailure);
      for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      report.preDispatchRetryQualified = true;
      report.preDispatchRetry = { qualified: true, scope: 'temporary default-alias drift on one original Secret Service lifetime only',
        runId: admitted.id, failedAttempts: free.length / 2, dispatchedAttempt: prepared.attempt, ownedProviderRequests: 1,
        sameWorkerAndEpoch: true, originalBodyAndAuthorityPreserved: true, freeFailuresFullyRefunded: true, oneFullReservationCharged: true,
        candidateRetainedWithoutResult: true, supervisorHealthRecovered: true, explicitCancelGenuineWorkerJoin: true,
        immutableJournalPreserved: true, sessionPublishedOnce: true, reconnectAndAdmissionReplayPreserved: true };
      mark('actual_connect_refusal_after_permanent_claim');
      assert(server?.listening);
      const retiredServer = server;
      retiredServer.closeAllConnections();
      await bounded(new Promise<void>((resolve, reject) => retiredServer.close(error => error ? reject(error) : resolve())),
        10000, 'owned HTTPS listener did not close before the independent connection refusal');
      await bounded(Promise.all(socketClosures), 10000, 'owned TLS sockets did not join before the independent connection refusal');
      assert.equal(retiredServer.listening, false); server = undefined; report.httpsJoined = true;
      const connectionSession = currentSession();
      assert.deepEqual(connectionSession, sessionCut.snapshot.session);
      const connectionSubmit = request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000120',
        admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: connectionSession.contextRevision,
        objective: 'Acknowledge the owned connection-refusal observation without using a tool.' });
      const connectionReply = exchange([connectionSubmit])[0]!, connectionAdmitted = accepted(connectionReply, 'run.submit').snapshot.run;
      assert.equal(connectionAdmitted.status, 'queued'); assert.equal(connectionAdmitted.revision, 1);
      assert.equal(Date.parse(connectionAdmitted.deadlineAt) - Date.parse(connectionAdmitted.createdAt), 45000);
      report.connectionRefusal = { diagnosticOnly: true, qualified: false, runId: connectionAdmitted.id,
        ownedListenerAndSocketsJoined: true, terminalOutcomeQualified: false, preConnectClaimGapQualified: false };
      const readConnection = () => {
        const value = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: connectionAdmitted.id }])[0]!, 'run.get');
        report.lastConnectionRefusalCut = projectInstalledRunProgress(value, { requestsReceived, providerFailure });
        return value;
      };
      const connectionBy = Date.now() + 15000;
      let connectionCut: Record<string, any>;
      for (;;) {
        await delay(50); connectionCut = readConnection();
        assert(Date.now() < connectionBy, 'actual post-claim connection refusal did not settle as conservative unknown');
        assert(!providerFailure); assert.equal(requestsReceived, 1);
        assert(!['failed', 'cancelled', 'succeeded', 'completed_unverified'].includes(connectionCut.snapshot.run.status));
        if (connectionCut.journal.at(-1)?.phase === 'unknown') break;
      }
      assert.equal(connectionCut.nextJournalSeq, connectionCut.highWaterJournalSeq);
      assert.deepEqual(connectionCut.journal.map((entry: any) => [entry.opKind, entry.phase, entry.attempt]),
        [['model', 'prepared', 0], ['model', 'dispatch_claimed', 0], ['model', 'unknown', 0]]);
      const [connectionPrepared, connectionClaimed, connectionUnknown] = connectionCut.journal;
      for (const entry of connectionCut.journal) {
        assert.equal(entry.runId, connectionAdmitted.id); assert.equal(entry.opId, connectionPrepared.opId);
        assert.equal(entry.requestRef, connectionPrepared.requestRef); assert.equal(entry.target, connectionPrepared.target);
      }
      assert.equal(connectionClaimed.seq, connectionPrepared.seq + 1); assert.equal(connectionUnknown.seq, connectionClaimed.seq + 1);
      assert.equal(connectionUnknown.dispatchId, connectionClaimed.dispatchId);
      assert.equal(connectionUnknown.supervisorInstanceId, connectionClaimed.supervisorInstanceId);
      assert.equal(connectionUnknown.stateOwnerEpoch, connectionClaimed.stateOwnerEpoch);
      assert.equal(connectionUnknown.brokerFenceTokenDigest, connectionClaimed.brokerFenceTokenDigest);
      assert.equal(connectionUnknown.resultRef, undefined); assert.equal(connectionUnknown.errorRef, undefined);
      const connectionEvidence = parseJsonStrict((await readCas(connectionUnknown.evidenceRef)).toString('utf8')) as Record<string, any>;
      assert.equal(connectionEvidence.format, 'cliq-invocation-ambiguity-evidence-v1');
      assert.equal(connectionEvidence.ambiguityKind, 'broker_channel_lost_after_claim');
      assert.equal(connectionEvidence.failureCode, 'connection_lost_after_release_possible');
      assert.equal(connectionEvidence.runId, connectionAdmitted.id); assert.equal(connectionEvidence.opId, connectionPrepared.opId);
      assert.equal(connectionEvidence.attempt, 0); assert.equal(connectionEvidence.dispatchId, connectionClaimed.dispatchId);
      assert.equal(connectionEvidence.dispatchJournalSeq, connectionClaimed.seq);
      assert.equal(connectionEvidence.brokerFenceTokenDigest, connectionClaimed.brokerFenceTokenDigest);
      assert.equal(connectionEvidence.claimingSupervisorInstanceId, connectionClaimed.supervisorInstanceId);
      assert.equal(connectionEvidence.claimingStateOwnerEpoch, connectionClaimed.stateOwnerEpoch);
      assert.equal(connectionEvidence.operationRequestRef, connectionPrepared.requestRef);
      assert.equal(connectionEvidence.operationTargetRef, connectionPrepared.target);
      assert.equal(connectionEvidence.operationTargetDigest, registration.registrationDigest);
      assert.equal(connectionEvidence.frontierRef, connectionCut.snapshot.run.frontierRef);
      assert.equal(connectionEvidence.frontierDigest, connectionEvidence.frontierRef);
      assert.equal(connectionEvidence.durableTerminalResultAbsent, true);
      assert.equal(connectionEvidence.observedAt, connectionUnknown.timestamp);
      assert.equal(connectionEvidence.evidenceDigest, connectionUnknown.evidenceDigest);
      assert.equal(connectionEvidence.evidenceDigest, digestOmitting(connectionEvidence, 'evidenceDigest'));
      const connectionSettlement = parseJsonStrict((await readCas(connectionUnknown.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
      assert.equal(connectionSettlement.runId, connectionAdmitted.id); assert.equal(connectionSettlement.opId, connectionPrepared.opId);
      assert.equal(connectionSettlement.attempt, 0); assert.equal(connectionSettlement.preparedJournalSeq, connectionPrepared.seq);
      assert.equal(connectionSettlement.terminalJournalSeq, connectionUnknown.seq); assert.equal(connectionSettlement.terminalPhase, 'unknown');
      assert.equal(connectionSettlement.settledAt, connectionUnknown.timestamp);
      assert.equal(connectionSettlement.settlementDigest, digestOmitting(connectionSettlement, 'settlementDigest'));
      for (const actual of [connectionPrepared.budgetDelta, connectionUnknown.budgetDelta, connectionSettlement.reserved,
        connectionSettlement.released, connectionSettlement.consumed, connectionSettlement.budgetReservedBefore,
        connectionSettlement.budgetConsumedAfter, connectionCut.snapshot.run.budgetConsumed])
        assert.equal(canonicalSha256(actual), canonicalSha256(fullCharge));
      for (const actual of [connectionClaimed.budgetDelta, connectionSettlement.budgetConsumedBefore,
        connectionSettlement.budgetReservedAfter, connectionCut.snapshot.run.budgetReserved])
        assert.equal(canonicalSha256(actual), canonicalSha256(zeroCharge));
      assert.equal(connectionCut.snapshot.run.status, 'running'); assert(connectionCut.snapshot.run.activeWorkerLaunchId);
      assert.equal(connectionCut.snapshot.run.leaseEpoch, 1); assert.equal(connectionCut.snapshot.run.stopIntentRef, undefined);
      assert.equal(connectionCut.snapshot.run.resultRef, undefined);
      // Observe beyond both frozen model retry delays without authorizing a
      // retry, cancelling this unknown or pretending it has terminal proof.
      await delay(2500);
      assert(Date.now() < Date.parse(connectionAdmitted.deadlineAt));
      assert.deepEqual(readConnection(), connectionCut); assert.deepEqual(exchange([connectionSubmit])[0], connectionReply);
      assert.deepEqual(currentSession(), connectionSession); assert.equal(requestsReceived, 1); assert(!providerFailure);
      report.connectionRefusal = { ...report.connectionRefusal, qualified: true,
        originalPermanentClaimPreserved: true, fullReservationCharged: true, zeroReservationRemaining: true,
        noProviderRequestReceived: true, immutableUnknownPreserved: true, providerRedispatches: 0,
        noResultPublished: true, scope: 'real native connection refusal after claim only; not pre-connect claim-gap recovery or terminal cancellation' };
    } else if (failureOnly) {
      mark('received_model_rejection_and_terminal_drain');
      assert.equal(Date.parse(admitted.deadlineAt) - Date.parse(admitted.createdAt), 45000);
      const terminalBy = Date.now() + 30000;
      let terminal: Record<string, any>;
      for (;;) {
        await delay(50); terminal = read(); assert(!providerFailure, 'owned HTTP429 responder observed a protocol failure');
        if (terminal.snapshot.run.status === 'failed') break;
        assert(!['cancelled', 'succeeded', 'completed_unverified'].includes(terminal.snapshot.run.status));
        assert(Date.now() < terminalBy, 'positively received HTTP429 did not stop and physically join before the independent 30s bound');
      }
      assert(Date.now() < terminalBy);
      const failed = terminal.snapshot.run;
      assert.equal(failed.terminalReason, 'runtime_failed'); assert.equal(failed.cancelRequested, false);
      assert.equal(failed.activeWorkerLaunchId, undefined); assert.equal(failed.frontierRef, undefined);
      assert.equal(failed.resultRef, undefined); assert.equal(failed.leaseEpoch, 1);
      assert(failed.updatedAt < failed.deadlineAt, 'received model failure must not wait for deadline expiry');
      assert.equal(requestsReceived, 1); assert.equal(terminal.items.length, 0);
      assert.deepEqual(terminal.journal.map((entry: any) => [entry.opKind, entry.phase, entry.attempt]),
        [['model', 'prepared', 0], ['model', 'dispatch_claimed', 0], ['model', 'completed', 0]]);
      const [prepared, claimed, completed] = terminal.journal;
      for (const entry of terminal.journal) {
        assert.equal(entry.runId, admitted.id); assert.equal(entry.opId, prepared.opId); assert.equal(entry.requestRef, prepared.requestRef);
      }
      assert.equal(claimed.seq, prepared.seq + 1); assert.equal(completed.seq, claimed.seq + 1);
      const fullCharge = { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
      const zeroCharge = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
      for (const actual of [prepared.budgetDelta, failed.budgetConsumed]) assert.equal(canonicalSha256(actual), canonicalSha256(fullCharge));
      assert.equal(canonicalSha256(failed.budgetReserved), canonicalSha256(zeroCharge));
      const modelRequest = parseJsonStrict((await readCas(prepared.requestRef)).toString('utf8')) as Record<string, any>;
      assert.equal(modelRequest.kind, 'normal'); assert.equal(modelRequest.requestDigest, digestOmitting(modelRequest, 'requestDigest'));
      const response = parseJsonStrict((await readCas(completed.resultRef)).toString('utf8')) as Record<string, any>;
      assert.deepEqual(Object.keys(response).sort(), ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'request', 'provider',
        'model', 'negotiatedMode', 'failureCode', 'observedResponse', 'observedAt', 'unusableDigest'].sort());
      assert.equal(response.schemaVersion, 1); assert.equal(response.format, 'cliq-model-unusable-response-v1');
      assert.equal(response.runId, admitted.id); assert.equal(response.opId, prepared.opId); assert.equal(response.attempt, 0);
      assert.equal(response.provider, 'openai-compatible'); assert.equal(response.model, model); assert.equal(response.negotiatedMode, 'native-tools');
      assert.equal(response.failureCode, 'provider_rejected_response'); assert.equal(response.unusableDigest, digestOmitting(response, 'unusableDigest'));
      assert.equal(canonicalSha256(response.request), canonicalSha256({ kind: 'normal', requestRef: prepared.requestRef, requestDigest: modelRequest.requestDigest }));
      assert.equal(canonicalSha256(response.observedResponse), canonicalSha256({ kind: 'complete', mediaType: 'application/json',
        bytesRef: sha256Bytes(Buffer.from(rejectedResponse)), bytesDigest: sha256Bytes(Buffer.from(rejectedResponse)), byteCount: Buffer.byteLength(rejectedResponse) }));
      assert.equal((await readCas(response.observedResponse.bytesRef)).toString('utf8'), rejectedResponse);
      const settlement = parseJsonStrict((await readCas(completed.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
      assert.equal(settlement.runId, admitted.id); assert.equal(settlement.opId, prepared.opId); assert.equal(settlement.attempt, 0);
      assert.equal(settlement.preparedJournalSeq, prepared.seq); assert.equal(settlement.terminalJournalSeq, completed.seq);
      assert.equal(settlement.terminalPhase, 'completed'); assert.equal(settlement.settlementDigest, digestOmitting(settlement, 'settlementDigest'));
      for (const actual of [settlement.reserved, settlement.consumed]) assert.equal(canonicalSha256(actual), canonicalSha256(fullCharge));
      assert.equal(canonicalSha256(settlement.released), canonicalSha256(fullCharge));
      const intent = parseJsonStrict((await readCas(failed.stopIntentRef)).toString('utf8')) as Record<string, any>;
      assert.deepEqual(Object.keys(intent).sort(), ['schemaVersion', 'runId', 'createdAt', 'origin', 'targetStatus', 'reason',
        'runtimeSubtype', 'failingOpId', 'runtimeFailureRef', 'runtimeFailureDigest'].sort());
      assert.equal(intent.schemaVersion, 1); assert.equal(intent.runId, admitted.id); assert.equal(intent.origin, 'runtime');
      assert.equal(intent.targetStatus, 'failed'); assert.equal(intent.reason, 'runtime_failed'); assert.equal(intent.runtimeSubtype, 'runtime');
      assert.equal(intent.failingOpId, prepared.opId); assert(intent.createdAt < failed.deadlineAt);
      const evidence = parseJsonStrict((await readCas(intent.runtimeFailureRef)).toString('utf8')) as Record<string, any>;
      assert.deepEqual(Object.keys(evidence).sort(), ['schemaVersion', 'format', 'runId', 'frontierRef', 'frontierDigest', 'failingOpId',
        'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'evidenceDigest', 'failureKind', 'unusableResponseRef', 'unusableResponseDigest'].sort());
      assert.equal(evidence.schemaVersion, 1); assert.equal(evidence.format, 'cliq-runtime-failure-evidence-v1');
      assert.equal(evidence.runId, admitted.id); assert.equal(evidence.failingOpId, prepared.opId);
      assert.equal(evidence.failureKind, 'model_unusable_response'); assert.equal(evidence.unusableResponseRef, completed.resultRef);
      assert.equal(evidence.unusableResponseDigest, response.unusableDigest); assert.equal(evidence.frontierRef, evidence.frontierDigest);
      assert.equal(evidence.evidenceDigest, digestOmitting(evidence, 'evidenceDigest')); assert.equal(evidence.evidenceDigest, intent.runtimeFailureDigest);
      assert(evidence.observedAt <= intent.createdAt && Date.parse(intent.createdAt) - Date.parse(evidence.observedAt) <= 5000);
      const projection = parseJsonStrict((await readCas(modelRequest.promptProjectionRef)).toString('utf8')) as Record<string, any>;
      assert.equal(evidence.frontierRef, projection.frontierDigest);
      const inspector = parseJsonStrict((await readCas(evidence.inspectorIdentityRef)).toString('utf8')) as Record<string, any>;
      assert.equal(inspector.identityDigest, evidence.inspectorIdentityDigest); assert.equal(inspector.identityDigest, digestOmitting(inspector, 'identityDigest'));
      const failureStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.equal(failureStatus.health, 'ready'); assert.equal(inspector.supervisorInstanceId, failureStatus.supervisorInstanceId);
      const detail = parseJsonStrict((await readCas(failed.terminalDetailRef)).toString('utf8')) as Record<string, any>;
      assert.deepEqual(Object.keys(detail).sort(), ['schemaVersion', 'runId', 'reason', 'reasonDetail', 'primaryEvidenceRef',
        'publicationResultItemRefs', 'abandonedRetryInvocations', 'createdAt'].sort());
      assert.equal(detail.schemaVersion, 1);
      assert.equal(detail.runId, admitted.id); assert.equal(detail.reason, 'runtime_failed'); assert.equal(detail.primaryEvidenceRef, intent.runtimeFailureRef);
      assert.equal(canonicalSha256(detail.reasonDetail), canonicalSha256({ kind: 'runtime', failingOpId: prepared.opId,
        runtimeFailureRef: intent.runtimeFailureRef, runtimeFailureDigest: intent.runtimeFailureDigest }));
      assert.deepEqual(detail.publicationResultItemRefs, []); assert.deepEqual(detail.abandonedRetryInvocations, []);
      const initialCheckpoint = terminal.checkpoints.find((checkpoint: any) => checkpoint.id === admitted.latestCheckpointId);
      const terminalCheckpoint = terminal.checkpoints.find((checkpoint: any) => checkpoint.id === failed.latestCheckpointId);
      assert(initialCheckpoint && terminalCheckpoint); assert.notEqual(terminalCheckpoint.id, initialCheckpoint.id);
      assert.equal(terminalCheckpoint.workspaceStateRef, initialCheckpoint.workspaceStateRef); assert.equal(terminalCheckpoint.runItemSeq, 0);
      const sessionCut = accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id, afterItemSeq: session.latestItemSeq }])[0]!, 'session.get');
      assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + 1);
      assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + 1); assert.equal(sessionCut.items.length, 1);
      const sessionItem = sessionCut.items[0]; assert.equal(sessionItem.kind, 'run_terminal'); assert.equal(sessionItem.itemSeq, session.latestItemSeq + 1);
      const publication = parseJsonStrict((await readCas(sessionItem.payloadRef)).toString('utf8')) as Record<string, any>;
      assert.equal(canonicalSha256(publication), canonicalSha256({ schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
        itemKey: `run-terminal:${admitted.id}`, runId: admitted.id, operation: 'agent', admittedSessionItemSeq: session.latestItemSeq,
        status: 'failed', terminalReason: 'runtime_failed', terminalDetailRef: failed.terminalDetailRef }));
      assert.deepEqual(read(), terminal, 'a fresh authenticated connection must preserve the exact terminal Run');
      assert.deepEqual(exchange([submit])[0], submitReply, 'replaying admission must not repeat the rejected request or Session publication');
      assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id, afterItemSeq: session.latestItemSeq }])[0]!, 'session.get'), sessionCut);
      assert.equal(requestsReceived, 1); assert(!providerFailure);
      for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      report.receivedModelFailureQualified = true;
      report.receivedModelFailure = { qualified: true, status: 'failed', terminalReason: 'runtime_failed', wallTimeMs: 45000,
        stoppedBeforeDeadline: true, receivedHttpStatus: 429, ownedProviderRequests: 1, noProviderRetry: true,
        completedResponseRef: completed.resultRef, runtimeFailureRef: intent.runtimeFailureRef, runtimeFailureDigest: intent.runtimeFailureDigest,
        terminalDetailRef: failed.terminalDetailRef, fullReservationCharged: true, noToolDispatch: true, noResultPublished: true,
        genuineWorkerJoinRequiredByProduction: true, sessionPublishedOnce: true, reconnectAndAdmissionReplayPreserved: true };
      mark('durable_source_refusal_before_credential_revocation');
      const refusalSession = currentSession();
      const refusalCore = { ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000116',
        admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: refusalSession.contextRevision,
        objective: 'Observe a durable cafe\u0301 source refusal without executing a model.',
        // Canonical inline selectors pass generic/installed admission. The
        // existing source projection rejects duplicates after real reservation,
        // then retires its genuine descriptors/staging before this response.
        sourceExcludes: [{ path: 'example.txt', scope: 'entry' }, { path: 'example.txt', scope: 'entry' }] };
      const refusalRequest = request(refusalCore), refusal = exchange([refusalRequest])[0]!;
      assert.equal(canonicalSha256(refusal), canonicalSha256({ protocolVersion: 1, ok: false, method: 'run.submit',
        error: { schemaVersion: 1, messageCode: 'source_capture_rejected', code: 'INVALID_REQUEST', retryable: false,
          issues: [{ path: 'source', issueCode: 'source_changed_or_unsupported' }] } }));
      report.sourceRefusalReplay = { qualified: false, sourceRule: 'duplicate_exclude_selectors',
        originalResponseDigest: canonicalSha256(refusal), initialSourceRefusal: true };
      assert.deepEqual(currentSession(), refusalSession); assert.equal(requestsReceived, 1);
      mark('real_credential_revocation_before_source_refusal_replay');
      assert.equal(operation.committedAuthorityRevision, 1);
      const revocation = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'revoke',
        requestId: '019a0012-0000-7000-8000-000000000117', credentialGrantId: enrollment.credentialGrantId,
        expectedAuthorityRevision: operation.committedAuthorityRevision }), 'operation'));
      assert.equal(revocation.disposition, 'revoked'); assert.equal(revocation.cleanupPhase, 'cleanup_complete');
      assert.equal(revocation.credentialGrantId, enrollment.credentialGrantId); assert.equal(revocation.committedAuthorityRevision, 2);
      assert.deepEqual(revocation.platformItem, operation.platformItem);
      const revokedPlatform = observe(); assert.deepEqual(revokedPlatform.items, []);
      assert.equal(revokedPlatform.nameOwner, platform.nameOwner); assert.equal(revokedPlatform.servicePid, platform.servicePid);
      report.sourceRefusalReplay.credentialRevokedAndSecretDeleted = true;
      mark('retained_source_refusal_and_conflicts_after_revocation');
      const replays = exchange([refusalRequest,
        request({ ...refusalCore, requestId: '019a0012-0000-7000-8000-000000000118',
          objective: 'Observe a durable caf\u00e9 source refusal without executing a model.' }),
        request({ ...refusalCore, objective: 'A conflicting original nonce must remain a conflict.' }),
        request({ ...refusalCore, requestId: '019a0012-0000-7000-8000-000000000119', objective: 'A conflicting admission intent must remain a conflict.' })]);
      // Retain only closed error classes if the real replay regresses. No
      // dynamic diagnostic, source payload or credential is copied to evidence.
      report.sourceRefusalReplay.observedReplies = replays.map(reply => ({ ok: reply.ok,
        code: ['INVALID_REQUEST', 'AUTHORIZATION_REQUIRED', 'REQUEST_ID_CONFLICT', 'ADMISSION_KEY_CONFLICT'].includes(reply.error?.code as string)
          ? reply.error!.code : 'unrecognized' }));
      assert.deepEqual(replays[0], refusal, 'original nonce must replay its durable source refusal despite current credential revocation');
      assert.deepEqual(replays[1], refusal, 'fresh nonce must bind the same original source refusal without reauthorizing capture');
      for (const [index, code] of [[2, 'REQUEST_ID_CONFLICT'], [3, 'ADMISSION_KEY_CONFLICT']] as const) {
        assert.equal(canonicalSha256(replays[index]), canonicalSha256({ protocolVersion: 1, ok: false, method: 'run.submit',
          error: { schemaVersion: 1, code, retryable: false, messageCode: 'control.mutation_refused' } }));
      }
      assert.deepEqual(currentSession(), refusalSession); assert.deepEqual(read(), terminal);
      assert.equal(requestsReceived, 1); assert(!providerFailure);
      for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      report.sourceRefusalReplay.qualified = true;
      report.sourceRefusalReplay.sameNonceAndFreshNoncePreserved = true;
      report.sourceRefusalReplay.requestAndAdmissionConflictsPreserved = true;
      report.sourceRefusalReplay.noNewRunSessionMutationOrProviderRequest = true;
      mark('run_submit_original_wire_identity_and_normalized_intent');
      const normalizedSubmit = request({ ...resourceCore, objective: 'Observe the owned caf\u00e9 model failure without using a tool.' });
      assert.notEqual(submit.requestDigest, normalizedSubmit.requestDigest);
      const wireRunReplies = exchange([submit, normalizedSubmit,
        request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000121',
          objective: 'Observe the owned caf\u00e9 model failure without using a tool.' }),
        request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000121' }),
        { ...submit, requestDigest: normalizedSubmit.requestDigest }]);
      assert.deepEqual(wireRunReplies[0], submitReply, 'the original NFD admission must replay after credential revocation');
      assert.deepEqual(wireRunReplies[2], submitReply, 'a fresh NFC nonce must bind the original admitted Run response');
      for (const index of [1, 3]) assert.equal(canonicalSha256(wireRunReplies[index]), canonicalSha256({ protocolVersion: 1,
        ok: false, method: 'run.submit', error: { schemaVersion: 1, code: 'REQUEST_ID_CONFLICT', retryable: false,
          messageCode: 'control.mutation_refused' } }));
      assert.equal(canonicalSha256(wireRunReplies[4]), canonicalSha256({ protocolVersion: 1, ok: false, method: 'run.submit',
        error: { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false, messageCode: 'control.invalid_request',
          issues: [{ path: 'request', issueCode: 'invalid_request' }] } }));
      const admittedSpec = parseJsonStrict((await readCas(admitted.specRef)).toString('utf8')) as Record<string, any>;
      const objective = parseJsonStrict((await readCas(admittedSpec.objectiveRef)).toString('utf8')) as Record<string, any>;
      assert.equal(objective.utf8, 'Observe the owned caf\u00e9 model failure without using a tool.');
      assert.equal(objective.byteCount, Buffer.byteLength(objective.utf8));
      assert.deepEqual(currentSession(), refusalSession); assert.deepEqual(read(), terminal);
      assert.equal(requestsReceived, 1); assert(!providerFailure);
      report.runSubmitWireIdentity = { qualified: true, originalRequestDigest: submit.requestDigest,
        normalizedSpellingRequestDigest: normalizedSubmit.requestDigest, normalizedObjectiveRef: admittedSpec.objectiveRef,
        originalAndFreshNonceResponsesPreserved: true, exactWireNonceConflictsPreserved: true,
        normalizedDigestSubstitutionRefused: true, normalizedObjectiveRetainedAndSent: true,
        noNewRunSessionMutationOrProviderRequest: true };
      mark('session_create_original_wire_identity_and_normalized_intent');
      const wireSessionCore = { protocolVersion: 1, method: 'session.create',
        requestId: '019a0012-0000-7000-8000-00000000011a', admissionKey: randomBytes(32).toString('base64url'),
        workspacePath: recipe.workspace, name: 'Installed Cafe\u0301' };
      const wireSessionRequest = request(wireSessionCore);
      const normalizedWireSessionRequest = request({ ...wireSessionCore, name: 'Installed Caf\u00e9' });
      assert.notEqual(wireSessionRequest.requestDigest, normalizedWireSessionRequest.requestDigest);
      const wireSessionReply = exchange([wireSessionRequest])[0]!;
      const wireSession = accepted(wireSessionReply, 'session.create').snapshot.session;
      assert.notEqual(wireSession.id, session.id); assert.equal(wireSession.name, 'Installed Caf\u00e9');
      report.sessionCreateWireIdentity = { qualified: false, originalRequestDigest: wireSessionRequest.requestDigest,
        normalizedSpellingRequestDigest: normalizedWireSessionRequest.requestDigest,
        secondSessionCreated: true, normalizedSessionName: true };
      const wireSessionReplies = exchange([wireSessionRequest, normalizedWireSessionRequest,
        request({ ...wireSessionCore, requestId: '019a0012-0000-7000-8000-00000000011b', name: 'Installed Caf\u00e9' }),
        request({ ...wireSessionCore, requestId: '019a0012-0000-7000-8000-00000000011b' }),
        request({ ...wireSessionCore, requestId: '019a0012-0000-7000-8000-00000000011c', name: 'Different installed Session' })]);
      report.sessionCreateWireIdentity.observedReplies = wireSessionReplies.map(reply => ({ ok: reply.ok,
        code: reply.ok ? 'accepted' : ['INVALID_REQUEST', 'REQUEST_ID_CONFLICT', 'ADMISSION_KEY_CONFLICT', 'RECOVERY_REQUIRED'].includes(reply.error?.code as string)
          ? reply.error!.code : 'unrecognized' }));
      assert.deepEqual(wireSessionReplies[0], wireSessionReply, 'the exact original wire request must replay its first Session response');
      for (const [index, code] of [[1, 'REQUEST_ID_CONFLICT'], [3, 'REQUEST_ID_CONFLICT'], [4, 'ADMISSION_KEY_CONFLICT']] as const) {
        assert.equal(canonicalSha256(wireSessionReplies[index]), canonicalSha256({ protocolVersion: 1, ok: false, method: 'session.create',
          error: { schemaVersion: 1, code, retryable: false, messageCode: 'control.mutation_refused' } }));
      }
      assert.deepEqual(wireSessionReplies[2], wireSessionReply, 'a fresh nonce with the same normalized intent must bind the original raw-wire Session response');
      assert.deepEqual(currentSession(), refusalSession); assert.deepEqual(read(), terminal);
      assert.equal(requestsReceived, 1); assert(!providerFailure);
      for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      report.sessionCreateWireIdentity.qualified = true;
      report.sessionCreateWireIdentity.originalAndFreshNonceResponsesPreserved = true;
      report.sessionCreateWireIdentity.exactWireNonceConflictsPreserved = true;
      report.sessionCreateWireIdentity.normalizedIntentConflictPreserved = true;
      report.sessionCreateWireIdentity.originalSessionRunAndProviderCountUnchanged = true;
      mark('concurrent_credential_scope_refusal');
      assert(busySubmit);
      const busyRunId = identityHash('cliq-run-id-v1', operation.ownerPrincipalId, 'run.submit', busySubmit.admissionKey);
      const absentBusyRun = exchange([{ protocolVersion: 1, method: 'run.get', runId: busyRunId }])[0]!;
      assert.equal(canonicalSha256(absentBusyRun), canonicalSha256({ protocolVersion: 1, ok: false, method: 'run.get',
        error: { schemaVersion: 1, code: 'NOT_FOUND', retryable: false, messageCode: 'control.read_rejected' } }),
      'concurrent credential-scope refusal must not admit another Run');
      assert.equal(report.credentialScopeBusy.exactPayloadMatched, true,
        'actual concurrent installed admission must return the fixed retryable RATE_LIMITED response');
    } else {
    mark('real_edit_and_ready_checkpoint');
    let current: Record<string, any> | undefined;
    const completeBy = Date.now() + 90000;
    for (;;) {
      await delay(50); assert(!providerFailure, 'owned TLS responder observed a protocol failure');
      current = read();
      const completed = current.journal.filter((entry: any) => entry.phase === 'completed');
      if ((requestsReceived as number) === 2 && completed.filter((entry: any) => entry.opKind === 'model').length === 2 &&
          completed.filter((entry: any) => entry.opKind === 'tool').length === 1) break;
      assert(Date.now() < completeBy, 'real installed model/edit sequence did not reach its ready Checkpoint');
      assert(!['failed', 'cancelled', 'succeeded', 'completed_unverified'].includes(current.snapshot.run.status), 'I1 mechanics cannot manufacture an I2 terminal result');
    }
    let cut = current!; assert.equal(cut.snapshot.run.id, admitted.id); assert.equal(cut.snapshot.run.resultRef, undefined);
    assert.equal(cut.snapshot.run.status, 'running'); assert(cut.snapshot.run.activeWorkerLaunchId);
    assert.equal(cut.nextJournalSeq, cut.highWaterJournalSeq); assert.equal(cut.nextItemSeq, cut.highWaterItemSeq);
    assert.deepEqual(cut.journal.map((entry: any) => [entry.opKind, entry.phase]), [
      ['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed'],
      ['tool', 'prepared'], ['tool', 'dispatch_claimed'], ['tool', 'completed'],
      ['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed'] ]);
    const completedTool = cut.journal.filter((entry: any) => entry.opKind === 'tool' && entry.phase === 'completed');
    assert.equal(completedTool.length, 1);
    const toolCheckpoint = cut.checkpoints.find((checkpoint: any) => checkpoint.reason === 'auto' && checkpoint.journalSeq === completedTool[0].seq);
    assert(toolCheckpoint, 'real edit must retain its ready completed-Journal Checkpoint');
    report.privateEdit = await privateCheckpoint(toolCheckpoint);
    assert.equal(cut.snapshot.run.budgetConsumed.modelTokens, 73728); assert.equal(cut.snapshot.run.budgetConsumed.costMicros, 0);
    assert.equal(cut.snapshot.run.budgetConsumed.toolCalls, 1); assert.equal(cut.snapshot.run.budgetConsumed.repairAttempts, 0);
    // The strict wire decoder intentionally returns null-prototype records.
    // Keep exact fields/values/prototypes in the assertion, including zeros.
    const zeroBudget = Object.assign(Object.create(null), { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 });
    assert.deepEqual(cut.snapshot.run.budgetReserved, zeroBudget);
    assert.deepEqual(exchange([submit])[0], submitReply, 'completed work must replay original admission, never dispatch another effect');
    const { requestDigest: _submitDigest, ...submitCore } = submit;
    const freshNonceReplay = request({ ...submitCore, requestId: '019a0012-0000-7000-8000-000000000108' });
    assert.deepEqual(exchange([freshNonceReplay])[0], submitReply, 'fresh nonce with the same admission key and intent must replay the first accepted Run');
    const sameNonceChanged = request({ ...submitCore, objective: 'A different objective using the original nonce' });
    const nonceConflict = exchange([sameNonceChanged])[0]!;
    assert.equal(nonceConflict.ok, false); assert.equal(nonceConflict.error!.code, 'REQUEST_ID_CONFLICT');
    const changed = { ...submit, requestId: '019a0012-0000-7000-8000-000000000105', objective: 'A different objective' };
    const { requestDigest: _digest, ...changedCore } = changed;
    const conflict = exchange([request(changedCore)])[0]!; assert.equal(conflict.ok, false); assert.equal(conflict.error!.code, 'ADMISSION_KEY_CONFLICT');
    mark('candidate_worker_across_original_lease');
    const leaseSupervisor = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.equal(leaseSupervisor.health, 'ready');
    const leaseProcessStart = await fixtureProcess(Number(supervisorBefore.MainPID), ledger.uid);
    const leaseExpected = { uid: ledger.uid, runId: admitted.id, launchId: cut.snapshot.run.activeWorkerLaunchId,
      leaseEpoch: cut.snapshot.run.leaseEpoch, runRevision: cut.snapshot.run.revision,
      supervisorInstanceId: leaseSupervisor.supervisorInstanceId, deadlineAt: cut.snapshot.run.deadlineAt };
    // Two independent short read-only connections, not a retained snapshot,
    // StateOwner or clock/dispatch authority. All runtime interaction stays UDS.
    const leaseBefore = inspectInstalledWorkerLease(recipe.stateRoot, leaseExpected);
    report.candidateLeaseMaintenance = { diagnosticOnly: true, leaseRenewalQualified: false, before: leaseBefore };
    const idleStarted = performance.now(), originalCandidateCut = cut;
    let idleObservations = 0;
    do {
      await delay(1000); assert(!providerFailure, 'candidate maintenance cannot redispatch an owned provider effect');
      cut = read(); idleObservations++;
      assert.equal(cut.snapshot.run.status, 'running');
      assert.equal(cut.snapshot.run.revision, originalCandidateCut.snapshot.run.revision);
      assert.equal(cut.snapshot.run.activeWorkerLaunchId, originalCandidateCut.snapshot.run.activeWorkerLaunchId);
      assert.equal(cut.snapshot.run.leaseEpoch, originalCandidateCut.snapshot.run.leaseEpoch);
      assert.equal(cut.snapshot.run.latestCheckpointId, originalCandidateCut.snapshot.run.latestCheckpointId);
      assert.equal(cut.snapshot.run.resultRef, undefined); assert.equal(cut.snapshot.run.stopIntentRef, undefined);
      assert.deepEqual(cut.journal, originalCandidateCut.journal);
      assert.deepEqual(cut.snapshot.run.budgetConsumed, originalCandidateCut.snapshot.run.budgetConsumed);
      assert.deepEqual(cut.snapshot.run.budgetReserved, originalCandidateCut.snapshot.run.budgetReserved);
      assert.equal(requestsReceived, 2);
      const maintenanceStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.equal(maintenanceStatus.supervisorInstanceId, leaseSupervisor.supervisorInstanceId);
      assert.equal(maintenanceStatus.health, 'ready'); assert.equal(maintenanceStatus.queue.capacity, 1);
      assert.equal(maintenanceStatus.queue.runningRuns, 1); assert.equal(maintenanceStatus.incompatiblePinnedRunCount, 0);
    } while (performance.now() - idleStarted < 65000);
    const leaseAfter = inspectInstalledWorkerLease(recipe.stateRoot, leaseExpected);
    report.candidateLeaseMaintenance.after = leaseAfter;
    assertInstalledWorkerLeaseRenewed(leaseBefore, leaseAfter, leaseExpected.deadlineAt);
    const leaseServiceAfter = show(services.supervisorUnit);
    for (const field of ['MainPID', 'ExecMainPID', 'InvocationID', 'ActiveState', 'SubState'])
      assert.equal(leaseServiceAfter[field], supervisorBefore[field]);
    assert.equal(await fixtureProcess(Number(supervisorBefore.MainPID), ledger.uid), leaseProcessStart);
    report.candidateLeaseRenewalQualified = true;
    report.candidateLeaseMaintenance = { originalLeaseDurationMs: 60000, observedIdleMs: Math.floor(performance.now() - idleStarted),
      diagnosticOnly: true, leaseRenewalQualified: true,
      scope: 'same installed worker persisted a later lease version and expiry beyond the observed old expiry; not a physical deadline or clock-regression cut',
      before: leaseBefore, after: leaseAfter, crossedObservedOldExpiry: true, sameSupervisorProcess: true,
      observations: idleObservations, sameActiveWorkerLaunch: true, sameLeaseEpoch: true, noProviderRedispatch: true,
      immutableJournalAndCheckpointPreserved: true, physicalRetirementRequiredBySubsequentRestart: true };
    mark('capacity_blocked_queued_deadline');
    const queuedSubmit = request({ ...submitCore, requestId: '019a0012-0000-7000-8000-000000000110',
      admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: currentSession().contextRevision,
      objective: 'Remain queued behind the existing candidate worker until this Run reaches its own deadline.',
      budgets: { ...runBudgets, wallTimeMs: 3000 } });
    const queuedAdmitted = accepted(exchange([queuedSubmit])[0]!, 'run.submit').snapshot.run;
    assert.notEqual(queuedAdmitted.id, admitted.id); assert.equal(queuedAdmitted.status, 'queued');
    assert.equal(Date.parse(queuedAdmitted.deadlineAt) - Date.parse(queuedAdmitted.createdAt), 3000);
    const readQueued = () => accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: queuedAdmitted.id }])[0]!, 'run.get');
    const initialQueued = readQueued();
    assert.equal(initialQueued.snapshot.run.status, 'queued'); assert.equal(initialQueued.snapshot.run.activeWorkerLaunchId, undefined);
    assert.deepEqual(initialQueued.journal, []); assert.equal(requestsReceived, 2);
    const capacityStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.equal(capacityStatus.health, 'ready'); assert.equal(capacityStatus.queue.capacity, 1);
    assert.equal(capacityStatus.queue.runningRuns, 1); assert.equal(capacityStatus.queue.queuedRuns, 1);
    const queuedDeadlineBy = Date.now() + 30000;
    let deadlineCut: Record<string, any>;
    for (;;) {
      await delay(50); deadlineCut = readQueued(); assert(!providerFailure);
      assert.deepEqual(deadlineCut.journal, []); assert.equal(deadlineCut.snapshot.run.activeWorkerLaunchId, undefined);
      assert.equal(requestsReceived, 2);
      if (deadlineCut.snapshot.run.status === 'failed') break;
      assert.equal(deadlineCut.snapshot.run.status, 'queued');
      assert(Date.now() < queuedDeadlineBy, 'capacity-blocked queued Run did not reach its real deadline terminal cut');
    }
    assert.equal(deadlineCut.snapshot.run.terminalReason, 'budget_exhausted');
    assert.equal(deadlineCut.snapshot.run.resultRef, undefined);
    assert.deepEqual(deadlineCut.snapshot.run.budgetConsumed, zeroBudget);
    assert.deepEqual(deadlineCut.snapshot.run.budgetReserved, zeroBudget);
    const deadlineIntent = parseJsonStrict((await readCas(deadlineCut.snapshot.run.stopIntentRef)).toString('utf8')) as Record<string, any>;
    assert.deepEqual(Object.keys(deadlineIntent).sort(), ['schemaVersion', 'runId', 'createdAt', 'origin', 'targetStatus', 'reason', 'deadlineAt'].sort());
    assert.equal(deadlineIntent.schemaVersion, 1); assert.equal(deadlineIntent.runId, queuedAdmitted.id);
    assert.equal(deadlineIntent.origin, 'deadline'); assert.equal(deadlineIntent.targetStatus, 'failed');
    assert.equal(deadlineIntent.reason, 'budget_exhausted'); assert.equal(deadlineIntent.deadlineAt, queuedAdmitted.deadlineAt);
    assert(Date.parse(deadlineIntent.createdAt) >= Date.parse(deadlineIntent.deadlineAt));
    const deadlineDetail = parseJsonStrict((await readCas(deadlineCut.snapshot.run.terminalDetailRef)).toString('utf8')) as Record<string, any>;
    assert.equal(deadlineDetail.runId, queuedAdmitted.id); assert.equal(deadlineDetail.reason, 'budget_exhausted');
    assert.equal(deadlineDetail.primaryEvidenceRef, deadlineCut.snapshot.run.stopIntentRef);
    assert.deepEqual(deadlineDetail.reasonDetail, Object.assign(Object.create(null),
      { kind: 'budget_exhausted', stopIntentRef: deadlineCut.snapshot.run.stopIntentRef }));
    cut = read();
    assert.equal(cut.snapshot.run.status, 'running');
    assert.equal(cut.snapshot.run.activeWorkerLaunchId, originalCandidateCut.snapshot.run.activeWorkerLaunchId);
    assert.equal(cut.snapshot.run.leaseEpoch, originalCandidateCut.snapshot.run.leaseEpoch);
    assert.equal(cut.snapshot.run.latestCheckpointId, originalCandidateCut.snapshot.run.latestCheckpointId);
    assert.deepEqual(cut.journal, originalCandidateCut.journal);
    assert.deepEqual(cut.snapshot.run.budgetConsumed, originalCandidateCut.snapshot.run.budgetConsumed);
    assert.deepEqual(cut.snapshot.run.budgetReserved, originalCandidateCut.snapshot.run.budgetReserved);
    assert.equal(requestsReceived, 2);
    // Polling can miss a short activation. Check the whole retained public
    // history before claiming this capacity-blocked Run never ran a worker.
    const queuedEvents = accepted(exchange([{ protocolVersion: 1, method: 'run.attach',
      runId: queuedAdmitted.id, afterEventSeq: 0 }])[0]!, 'run.attach');
    assert.equal(queuedEvents.earliestRetainedEventSeq, 1);
    assert.equal(queuedEvents.nextEventSeq, queuedEvents.highWaterEventSeq);
    assert(queuedEvents.events.length > 0);
    for (let index = 0; index < queuedEvents.events.length; index++) {
      const event = queuedEvents.events[index];
      assert.equal(event.eventSeq, index + 1);
      if (event.kind === 'state_changed') assert.notEqual(event.status, 'running', 'queued deadline must never activate a worker');
    }
    assert.equal(queuedEvents.events.at(-1).status, 'failed');
    assert.equal(queuedEvents.events.at(-1).terminalReason, 'budget_exhausted');
    report.queuedDeadline = { qualified: true, scope: 'capacity-blocked queued Run only; not a live-worker deadline cut',
      runId: queuedAdmitted.id, status: 'failed', terminalReason: 'budget_exhausted', wallTimeMs: 3000,
      stopIntentRef: deadlineCut.snapshot.run.stopIntentRef, terminalDetailRef: deadlineCut.snapshot.run.terminalDetailRef,
      attachedHighWater: queuedEvents.highWaterEventSeq, completeEventHistoryChecked: true,
      noWorkerActivated: true, noInvocationPrepared: true, noProviderRequest: true, zeroCharged: true, noResultPublished: true };
    const events = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: admitted.id, afterEventSeq: 0 }])[0]!, 'run.attach');
    assert(events.events.length > 0);
    for (let index = 0; index < events.events.length; index++) assert.equal(events.events[index].eventSeq, index + 1);
    const status = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.equal(status.queue.capacity, 1); assert.equal(status.incompatiblePinnedRunCount, 0);
    assert.equal(events.nextEventSeq, events.highWaterEventSeq);
    report.beforeRestart = { runRevision: cut.snapshot.run.revision, leaseEpoch: cut.snapshot.run.leaseEpoch,
      activeWorkerLaunchId: cut.snapshot.run.activeWorkerLaunchId, supervisorInstanceId: status.supervisorInstanceId,
      latestCheckpointId: cut.snapshot.run.latestCheckpointId,
      consumed: cut.snapshot.run.budgetConsumed, journal: cut.journal, attachedHighWater: events.highWaterEventSeq, supervisor: supervisorBefore, keeper: keeperBefore };
    mark('actual_supervisor_restart');
    const restart = command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit], undefined, 30000); assert.equal(restart.status, 0);
    const recoverBy = Date.now() + 30000;
    const successor = show(services.supervisorUnit), retainedKeeper = show(services.keeperUnit);
    assert.equal(successor.ActiveState, 'active'); assert.notEqual(successor.InvocationID, supervisorBefore.InvocationID);
    assert.equal(successor.MainPID, successor.ExecMainPID); assert.match(successor.MainPID!, /^[1-9][0-9]*$/u);
    const successorImagePath = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
    const successorStart = await selectedSupervisor(services.supervisorUnit, successor, successorImagePath, recoverBy);
    assert.notEqual(successor.MainPID, supervisorBefore.MainPID); assert.equal(retainedKeeper.InvocationID, keeperBefore.InvocationID);
    assert.equal(retainedKeeper.MainPID, keeperBefore.MainPID); assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
    for (;;) {
      assert(Date.now() < recoverBy, 'installed successor did not recover the genuine previous ready cut');
      await delay(50); current = read();
      assert(Date.now() < recoverBy, 'installed successor did not recover the genuine previous ready cut');
      if (current.snapshot.run.revision > cut.snapshot.run.revision && current.snapshot.run.status === 'queued' &&
          current.snapshot.run.activeWorkerLaunchId === undefined && current.snapshot.run.waitingReason === undefined) break;
    }
    const recovered = current!; assert.equal(recovered.snapshot.run.id, admitted.id); assert.equal(recovered.snapshot.run.specRef, admitted.specRef);
    assert.equal(recovered.snapshot.run.leaseEpoch, cut.snapshot.run.leaseEpoch);
    assert.equal(recovered.snapshot.run.latestCheckpointId, cut.snapshot.run.latestCheckpointId);
    assert.deepEqual(recovered.snapshot.run.budgetConsumed, cut.snapshot.run.budgetConsumed);
    assert.deepEqual(recovered.snapshot.run.budgetReserved, cut.snapshot.run.budgetReserved);
    assert.deepEqual(recovered.journal, cut.journal); assert.equal(requestsReceived, 2);
    const checkpointAfter = recovered.checkpoints.find((checkpoint: any) => checkpoint.id === toolCheckpoint.id); assert(checkpointAfter);
    assert.deepEqual(await privateCheckpoint(checkpointAfter), report.privateEdit);
    assert.deepEqual(exchange([submit])[0], submitReply);
    const successorNonceReplay = request({ ...submitCore, requestId: '019a0012-0000-7000-8000-000000000109' });
    assert.deepEqual(exchange([successorNonceReplay])[0], submitReply, 'successor must replay the original frozen admission even with a fresh nonce');
    const replayCut = read();
    assert.deepEqual(replayCut.journal, recovered.journal);
    assert.deepEqual(replayCut.snapshot.run.budgetConsumed, recovered.snapshot.run.budgetConsumed);
    assert.deepEqual(replayCut.snapshot.run.budgetReserved, recovered.snapshot.run.budgetReserved);
    assert.equal(requestsReceived, 2);
    const reattached = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: admitted.id, afterEventSeq: events.nextEventSeq }])[0]!, 'run.attach');
    assert.equal(reattached.nextEventSeq, reattached.highWaterEventSeq);
    for (let index = 0; index < reattached.events.length; index++) assert.equal(reattached.events[index].eventSeq, events.nextEventSeq + index + 1);
    const reconciliationIndex = reattached.events.findIndex((event: any) => event.kind === 'state_changed' &&
      event.status === 'waiting' && event.waitingReason === 'reconciliation');
    assert(reconciliationIndex >= 0);
    assert(reattached.events.slice(reconciliationIndex + 1).some((event: any) => event.kind === 'state_changed' &&
      event.status === 'queued' && event.runRevision === recovered.snapshot.run.revision));
    const successorStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.notEqual(successorStatus.supervisorInstanceId, status.supervisorInstanceId);
    assert.equal(successorStatus.incompatiblePinnedRunCount, 0);
    report.afterRestart = { runRevision: recovered.snapshot.run.revision, leaseEpoch: recovered.snapshot.run.leaseEpoch,
      supervisorInstanceId: successorStatus.supervisorInstanceId, reconciliationEvents: reattached.events,
      oldWorkerLaunchCleared: true, supervisor: successor, keeper: retainedKeeper,
      completedModelCalls: 2, completedPrivateEdits: 1, journalPreserved: true, budgetPreserved: true, noProviderRedispatch: true,
      readyCheckpointPreserved: true, sameRun: true, persistentAnchorRetained: true };
    mark('public_cancel_and_terminal_join');
    const cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000106',
      runId: admitted.id, expectedRevision: recovered.snapshot.run.revision });
    accepted(exchange([cancel])[0]!, 'run.cancel');
    const cancelBy = Date.now() + 30000;
    for (;;) {
      await delay(50); current = read();
      if (current.snapshot.run.status === 'cancelled') break;
      assert(Date.now() < cancelBy, 'real cancellation did not join its worker and publish the terminal cut');
    }
    assert.equal(current.snapshot.run.resultRef, undefined); assert.equal(current.snapshot.run.terminalReason, 'cancelled_by_user');
    assert.equal(current.snapshot.run.budgetConsumed.toolCalls, 1); assert.equal(requestsReceived, 2);
    for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
    assert.equal(await readFile(source, 'utf8'), hostBefore);
    report.sourceWorkspace = { unchangedBytes: true, unchangedDeviceInodeMetadata: true, originalDigest: sha256Bytes(Buffer.from(hostBefore)) };
    report.cancelled = { runId: admitted.id, status: 'cancelled', noResultPublished: true, genuineWorkerJoinRequiredByProduction: true };
    mark('native_nested_unicode_reflection_refusal');
    const reflectionStartedAt = Date.now();
    reflectionEnabled = true;
    const { requestDigest: _positiveDigest, ...positiveCore } = submit;
    const reflectionSubmit = request({ ...positiveCore, requestId: '019a0012-0000-7000-8000-000000000107',
      admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: currentSession().contextRevision,
      objective: 'Perform the authorized private edit with the builtin edit tool.' });
    const reflectionAdmitted = accepted(exchange([reflectionSubmit])[0]!, 'run.submit').snapshot.run;
    assert.notEqual(reflectionAdmitted.id, admitted.id);
    const reflectionBy = Date.now() + 45000;
    let refused: Record<string, any>;
    for (;;) {
      await delay(50); assert(!providerFailure, 'owned reflection fixture observed a protocol failure');
      refused = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }])[0]!, 'run.get');
      if (refused.journal.some((entry: any) => entry.phase === 'unknown')) break;
      assert(Date.now() < reflectionBy, 'native reflection refusal did not reach the conservative permanent unknown cut');
    }
    assert.equal(requestsReceived, 3);
    assert.deepEqual(refused.journal.map((entry: any) => [entry.opKind, entry.phase]),
      [['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'unknown']]);
    assert.equal(refused.snapshot.run.budgetConsumed.modelTokens, 36864);
    assert.equal(refused.snapshot.run.budgetConsumed.costMicros, 0);
    assert.equal(refused.snapshot.run.budgetConsumed.toolCalls, 0);
    assert.deepEqual(refused.snapshot.run.budgetReserved, zeroBudget);
    assert.equal(refused.snapshot.run.resultRef, undefined);
    assert.equal(refused.snapshot.run.terminalReason, undefined);
    const ambiguityEntry = refused.journal[2];
    const ambiguity = parseJsonStrict((await readCas(ambiguityEntry.evidenceRef)).toString('utf8')) as Record<string, any>;
    assert.equal(ambiguity.format, 'cliq-invocation-ambiguity-evidence-v1');
    assert.equal(ambiguity.ambiguityKind, 'broker_channel_lost_after_claim');
    assert.equal(ambiguity.runId, reflectionAdmitted.id); assert.equal(ambiguity.opId, ambiguityEntry.opId);
    assert.equal(ambiguity.attempt, 0); assert.equal(ambiguity.dispatchId, ambiguityEntry.dispatchId);
    assert.equal(ambiguity.dispatchJournalSeq, refused.journal[1].seq);
    assert.equal(ambiguity.brokerFenceTokenDigest, refused.journal[1].brokerFenceTokenDigest);
    assert.equal(ambiguity.durableTerminalResultAbsent, true);
    assert.equal(ambiguity.failureCode, 'response_stream_interrupted');
    assert.equal(ambiguity.observedAt, ambiguityEntry.timestamp);
    assert.equal(ambiguity.evidenceDigest, ambiguityEntry.evidenceDigest);
    assert.equal(ambiguity.evidenceDigest, digestOmitting(ambiguity, 'evidenceDigest'));
    // A generic interrupted connection does not qualify this negative case.
    // Correlate only a fixed diagnostic from the actual signed Supervisor,
    // never remote messages/headers or a new field in the authority artifact.
    let matchingRefusals = 0;
    const logBy = Date.now() + 5000;
    for (;;) {
      // Same bounded actual-journald source used by the keeper qualifier. Root
      // reads only the exact fresh UID + actual manager PID, not global logs;
      // absence of per-user persistent journaling is not an ACL bypass.
      assert.equal(await fixtureProcess(Number(successor.MainPID), ledger.uid), successorStart);
      assert.equal(await readlink(`/proc/${successor.MainPID}/exe`), successorImagePath);
      const log = spawnSync('/usr/bin/journalctl', ['--no-pager', '--all', '--output=json', '--lines=80', '--boot=0',
        `--since=@${Math.floor(reflectionStartedAt / 1000)}`, `--until=@${Math.ceil(Date.now() / 1000)}`,
        `_UID=${ledger.uid}`, `_PID=${successor.MainPID}`, '_TRANSPORT=stdout'],
      { env: environment, timeout: 10000, maxBuffer: 256 * 1024 });
      assert(Buffer.isBuffer(log.stdout) && Buffer.isBuffer(log.stderr)); scanBytes(log.stdout); scanBytes(log.stderr);
      assert.equal(log.error, undefined); assert.equal(log.signal, null); assert.equal(log.status, 0);
      matchingRefusals = 0;
      for (const line of log.stdout.toString('utf8').trim().split('\n').filter(Boolean)) {
        const record = parseJsonStrict(line) as Record<string, unknown>;
        assert.equal(record._UID, String(ledger.uid)); assert.equal(record._PID, successor.MainPID);
        assert.equal(record._TRANSPORT, 'stdout');
        if (typeof record.MESSAGE !== 'string' || !record.MESSAGE.startsWith('{')) continue;
        let message: Record<string, unknown>;
        try { message = parseJsonStrict(record.MESSAGE) as Record<string, unknown>; } catch { continue; }
        if (message.scope !== 'installed-model-broker') continue;
        assert.deepEqual(Object.keys(message).sort(), ['diagnosticOnly', 'scope', 'runId', 'opId', 'attempt', 'dispatchId', 'dispatchJournalSeq', 'reason'].sort());
        if (message.runId !== reflectionAdmitted.id) continue;
        assert.equal(message.diagnosticOnly, true); assert.equal(message.reason, 'broker_response_refused');
        assert.equal(message.opId, ambiguityEntry.opId); assert.equal(message.attempt, 0);
        assert.equal(message.dispatchId, ambiguityEntry.dispatchId); assert.equal(message.dispatchJournalSeq, refused.journal[1].seq);
        // Some actual user-manager/journald combinations omit invocation
        // enrichment. Trusted sender UID/PID + live start/image bracketing are
        // still mandatory; a present invocation field must name this unit.
        if (record._SYSTEMD_INVOCATION_ID !== undefined) assert.equal(record._SYSTEMD_INVOCATION_ID, successor.InvocationID);
        matchingRefusals++;
      }
      assert.equal(await fixtureProcess(Number(successor.MainPID), ledger.uid), successorStart);
      assert.equal(await readlink(`/proc/${successor.MainPID}/exe`), successorImagePath);
      if (matchingRefusals) break;
      assert(Date.now() < logBy, 'actual current-Supervisor refusal diagnostic was not observed'); await delay(50);
    }
    assert.equal(matchingRefusals, 1, 'actual native reflection refusal must have one exact current-Supervisor diagnostic owner');
    report.reflectionRefusal = { runId: reflectionAdmitted.id, journal: refused.journal,
      evidenceRef: ambiguityEntry.evidenceRef, fullReservationCharged: true, noToolDispatch: true,
      currentSupervisorNativeRefusalMatched: true, noResultPublished: true,
      terminalOutcomeQualified: false, arbitraryTransformConfidentialityQualified: false };
    mark('historical_unknown_after_actual_supervisor_restart');
    assert.equal(refused.snapshot.run.status, 'running'); assert(refused.snapshot.run.activeWorkerLaunchId);
    const unknownEvents = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: reflectionAdmitted.id, afterEventSeq: 0 }])[0]!, 'run.attach');
    assert.equal(unknownEvents.nextEventSeq, unknownEvents.highWaterEventSeq);
    const nextRestart = command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit], undefined, 30000);
    assert.equal(nextRestart.status, 0);
    const historicalBy = Date.now() + 30000;
    const afterUnknownSupervisor = show(services.supervisorUnit), afterUnknownKeeper = show(services.keeperUnit);
    assert.equal(afterUnknownSupervisor.ActiveState, 'active'); assert.equal(afterUnknownSupervisor.MainPID, afterUnknownSupervisor.ExecMainPID);
    assert.notEqual(afterUnknownSupervisor.MainPID, successor.MainPID); assert.notEqual(afterUnknownSupervisor.InvocationID, successor.InvocationID);
    assert.equal(afterUnknownKeeper.MainPID, keeperBefore.MainPID); assert.equal(afterUnknownKeeper.InvocationID, keeperBefore.InvocationID);
    assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
    await selectedSupervisor(services.supervisorUnit, afterUnknownSupervisor, successorImagePath, historicalBy);
    let historical: Record<string, any>;
    for (;;) {
      assert(Date.now() < historicalBy, 'successor did not recover the original unknown claim through its historical owner');
      await delay(50); assert(!providerFailure);
      historical = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }])[0]!, 'run.get');
      report.lastHistoricalUnknownCut = projectInstalledRunProgress(historical, { requestsReceived, providerFailure });
      assert(Date.now() < historicalBy, 'successor did not recover the original unknown claim through its historical owner');
      if (historical.snapshot.run.revision > refused.snapshot.run.revision && historical.snapshot.run.status === 'queued' &&
          historical.snapshot.run.activeWorkerLaunchId === undefined && historical.snapshot.run.waitingReason === undefined) break;
    }
    assert.equal(historical.snapshot.run.id, reflectionAdmitted.id); assert.equal(historical.snapshot.run.specRef, refused.snapshot.run.specRef);
    assert.equal(historical.snapshot.run.leaseEpoch, refused.snapshot.run.leaseEpoch);
    assert.equal(historical.snapshot.run.frontierRef, refused.snapshot.run.frontierRef);
    assert.equal(historical.snapshot.run.latestCheckpointId, refused.snapshot.run.latestCheckpointId);
    assert.equal(historical.snapshot.run.resultRef, undefined); assert.equal(historical.snapshot.run.terminalReason, undefined);
    assert.deepEqual(historical.journal, refused.journal);
    assert.deepEqual(historical.snapshot.run.budgetConsumed, refused.snapshot.run.budgetConsumed);
    assert.deepEqual(historical.snapshot.run.budgetReserved, refused.snapshot.run.budgetReserved);
    assert.deepEqual(parseJsonStrict((await readCas(historical.journal[2].evidenceRef)).toString('utf8')), ambiguity);
    assert.equal(requestsReceived, 3);
    const historicalEvents = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: reflectionAdmitted.id,
      afterEventSeq: unknownEvents.nextEventSeq }])[0]!, 'run.attach');
    assert.equal(historicalEvents.nextEventSeq, historicalEvents.highWaterEventSeq);
    for (let index = 0; index < historicalEvents.events.length; index++)
      assert.equal(historicalEvents.events[index].eventSeq, unknownEvents.nextEventSeq + index + 1);
    const oldOwnerWait = historicalEvents.events.findIndex((event: any) => event.kind === 'state_changed' && event.status === 'waiting' && event.waitingReason === 'reconciliation');
    assert(oldOwnerWait >= 0);
    const frozenWait = parseJsonStrict((await readCas(historicalEvents.events[oldOwnerWait].waitingOnRef)).toString('utf8')) as Record<string, any>;
    assert.equal(frozenWait.runId, reflectionAdmitted.id); assert.equal(frozenWait.subject.kind, 'worker_death');
    assert.equal(frozenWait.frontierRef, refused.snapshot.run.frontierRef);
    assert.equal(frozenWait.subject.oldWorkerLaunchId, refused.snapshot.run.activeWorkerLaunchId);
    assert.equal(frozenWait.subject.oldLeaseEpoch, refused.snapshot.run.leaseEpoch);
    assert.deepEqual(frozenWait.subject.openInvocationRefs, [canonicalSha256(refused.journal[0])]);
    assert(historicalEvents.events.slice(oldOwnerWait + 1).some((event: any) => event.kind === 'state_changed' &&
      event.status === 'queued' && event.runRevision === historical.snapshot.run.revision));
    const historicalStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.equal(historicalStatus.health, 'ready'); assert.equal(historicalStatus.queue.capacity, 1);
    assert.notEqual(historicalStatus.supervisorInstanceId, successorStatus.supervisorInstanceId);
    report.reflectionRefusal.historicalOwnerRecovery = { qualified: true, sameRun: true, immutableUnknownPreserved: true,
      fullChargePreserved: true, frozenInvocationWitnessPreserved: true, sameFrontier: true,
      providerRedispatches: 0, terminalOutcomeQualified: false,
      successorInstanceId: historicalStatus.supervisorInstanceId, supervisor: afterUnknownSupervisor,
      runRevision: historical.snapshot.run.revision, events: historicalEvents.events };
    mark('short_run_real_activation_and_cancel');
    shortRunEnabled = true;
    const shortSubmit = request({ ...positiveCore, requestId: '019a0012-0000-7000-8000-000000000111',
      admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: currentSession().contextRevision,
      objective: 'Acknowledge this short transport-only Run without using a tool.', budgets: { ...runBudgets, wallTimeMs: 45000 } });
    const shortAdmitted = accepted(exchange([shortSubmit])[0]!, 'run.submit').snapshot.run;
    assert.notEqual(shortAdmitted.id, admitted.id); assert.notEqual(shortAdmitted.id, reflectionAdmitted.id);
    assert.equal(shortAdmitted.status, 'queued');
    assert.equal(Date.parse(shortAdmitted.deadlineAt) - Date.parse(shortAdmitted.createdAt), 45000);
    const readShort = () => accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: shortAdmitted.id }])[0]!, 'run.get');
    const shortBy = Date.now() + 30000;
    let shortCut: Record<string, any>;
    for (;;) {
      await delay(50); shortCut = readShort(); assert(!providerFailure);
      if (shortCut.journal.some((entry: any) => entry.phase === 'completed')) break;
      assert(!['failed', 'cancelled', 'succeeded', 'completed_unverified'].includes(shortCut.snapshot.run.status));
      assert(Date.now() < shortBy, 'short Run did not activate its genuine worker and complete its owned model transport');
    }
    assert.equal(requestsReceived, 4);
    assert.equal(shortCut.snapshot.run.status, 'running'); assert(shortCut.snapshot.run.activeWorkerLaunchId);
    assert.equal(shortCut.snapshot.run.leaseEpoch, 1);
    assert.deepEqual(shortCut.journal.map((entry: any) => [entry.opKind, entry.phase]),
      [['model', 'prepared'], ['model', 'dispatch_claimed'], ['model', 'completed']]);
    assert.deepEqual(shortCut.snapshot.run.budgetConsumed, Object.assign(Object.create(null),
      { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 }));
    assert.deepEqual(shortCut.snapshot.run.budgetReserved, zeroBudget);
    assert.equal(shortCut.snapshot.run.resultRef, undefined);
    const shortCancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000112',
      runId: shortAdmitted.id, expectedRevision: shortCut.snapshot.run.revision });
    accepted(exchange([shortCancel])[0]!, 'run.cancel');
    const shortCancelBy = Date.now() + 30000;
    let shortTerminal: Record<string, any>;
    for (;;) {
      await delay(50); shortTerminal = readShort(); assert(!providerFailure);
      if (shortTerminal.snapshot.run.status === 'cancelled') break;
      assert(Date.now() < shortCancelBy, 'short activated Run did not physically join through public cancellation');
    }
    assert.equal(shortTerminal.snapshot.run.terminalReason, 'cancelled_by_user');
    assert.equal(shortTerminal.snapshot.run.resultRef, undefined); assert.equal(shortTerminal.snapshot.run.activeWorkerLaunchId, undefined);
    assert.deepEqual(shortTerminal.journal, shortCut.journal);
    assert.deepEqual(shortTerminal.snapshot.run.budgetConsumed, shortCut.snapshot.run.budgetConsumed);
    assert.deepEqual(shortTerminal.snapshot.run.budgetReserved, zeroBudget); assert.equal(requestsReceived, 4);
    const retainedUnknown = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }])[0]!, 'run.get');
    assert.equal(retainedUnknown.snapshot.run.status, 'queued'); assert.equal(retainedUnknown.snapshot.run.activeWorkerLaunchId, undefined);
    assert.deepEqual(retainedUnknown.journal, historical.journal);
    assert.deepEqual(retainedUnknown.snapshot.run.budgetConsumed, historical.snapshot.run.budgetConsumed);
    assert.deepEqual(retainedUnknown.snapshot.run.budgetReserved, historical.snapshot.run.budgetReserved);
    report.shortRunActivation = { qualified: true, scope: '45s Run genuine worker activation, one owned model response, then immediate user cancellation; not deadline expiry',
      runId: shortAdmitted.id, wallTimeMs: 45000, status: 'cancelled', terminalReason: 'cancelled_by_user',
      originalActiveWorkerLaunchId: shortCut.snapshot.run.activeWorkerLaunchId, noToolDispatch: true,
      genuineWorkerJoinRequiredByProduction: true, immutableJournalPreserved: true, noResultPublished: true,
      earlierUnknownNotRedispatched: true, totalOwnedProviderRequests: 4 };
    for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
    assert.equal(await readFile(source, 'utf8'), hostBefore);
    }
    report.qualified = true; mark('run_assertions_complete');
  } catch (error) {
    primary = error;
    // Best-effort public observation only. Diagnostic failure cannot replace
    // the original assertion or manufacture qualification/recovery authority.
    if (report.acceptedRun) {
      try {
        report.failureSupervisorStatus = projectInstalledSupervisorStatus(accepted(exchange([
          { protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status'));
      } catch { report.failureSupervisorStatus = { diagnosticOnly: true, kind: 'supervisor_status_read_refused' }; }
    }
  }
  finally {
    const cleanupFailures: unknown[] = [];
    try { await restoreRetryAlias(); } catch (error) { cleanupFailures.push(error); }
    try {
      if (server) {
        server.closeAllConnections(); await bounded(new Promise<void>(resolve => server!.close(() => resolve())), 10000, 'owned HTTPS fixture did not close');
        await bounded(Promise.all(socketClosures), 10000, 'owned TLS sockets did not close'); report.httpsJoined = true;
      }
    } catch (error) { cleanupFailures.push(error); }
    try {
      if (installedServices) {
        // A stable retained-byte scan must follow real writer retirement.
        // The outer root cleanup still independently checks all UID resources.
        const units = [installedServices.supervisorUnit, installedServices.keeperUnit];
        const before = units.map(unit => show(unit));
        await withRetainedUnitHistory(units, async () => {
          assert.equal(command('/usr/bin/systemctl', ['--user', 'stop', ...units]).status, 0);
          const stoppedUnits = units.map(unit => show(unit));
          report.installedServiceExit = { supervisor: projectInstalledServiceExit(stoppedUnits[0]),
            keeper: projectInstalledServiceExit(stoppedUnits[1]) };
          for (let index = 0; index < units.length; index++) {
            const stopped = stoppedUnits[index]!;
            assert.equal(stopped.ActiveState, 'inactive'); assert.equal(stopped.MainPID, '0');
            assert.equal(stopped.Result, 'success'); assert.equal(stopped.ExecMainCode, '1'); assert.equal(stopped.ExecMainStatus, '0');
            if (/^[1-9][0-9]*$/u.test(before[index]!.MainPID!)) {
              await assert.rejects(lstat(`/proc/${before[index]!.MainPID}`), { code: 'ENOENT' });
            }
          }
        });
        report.installedWritersJoined = true;
      }
    } catch (error) { cleanupFailures.push(error); }
    try {
      if (daemon && daemonExit) {
        if (daemonPid && daemonStart) {
          assert.equal(await fixtureProcess(daemonPid, ledger.uid, daemon.pid), daemonStart);
          assert.equal(await readlink(`/proc/${daemonPid}/exe`), '/usr/bin/gnome-keyring-daemon');
          process.kill(daemonPid, 'SIGTERM');
        } else if (daemon.exitCode === null && daemon.signalCode === null) daemon.kill('SIGTERM');
        await bounded(daemonExit, 10000, 'actual Secret Service daemon did not join'); report.daemonJoined = true;
      }
    } catch (error) { cleanupFailures.push(error); }
    if (cleanupFailures.length) primary = new AggregateError([primary, ...cleanupFailures].filter(Boolean), 'owned journey resources did not retire');
    if (!primary) {
      mark('secret_corpus');
      try {
        assert.equal(report.installedWritersJoined, true); assert.equal(report.httpsJoined, true); assert.equal(report.daemonJoined, true);
        report.secretCorpus = await scanCredentialSecretCorpus({ stateRoot: recipe.stateRoot, uid: ledger.uid, evidenceDirs: [], scanner });
        assert.equal(report.secretCorpus.sqliteDatabasesScanned, 2); assert.equal(report.secretCorpus.evidenceDirectoriesScanned, 0);
        mark('complete');
      }
      catch (error) { primary = error; }
    }
    if (primary) {
      report.qualified = false;
      const sourceFrames: Array<{ file: string; line: number; column: number }> = [];
      const pending = [primary];
      for (let visited = 0; pending.length && visited < 8 && sourceFrames.length < 8; visited++) {
        const error = pending.shift(); if (!(error instanceof Error)) continue;
        for (const match of (error.stack ?? '').matchAll(/\b(qualify-installed-run-journey|installed-supervisor-package|installed-model-package)\.ts:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})/gu)) {
          sourceFrames.push({ file: `${match[1]}.ts`, line: Number(match[2]), column: Number(match[3]) }); if (sourceFrames.length === 8) break;
        }
        if (error instanceof AggregateError) pending.unshift(...error.errors.slice(0, 4));
      }
      report.error = { diagnosticOnly: true, kind: 'installed_run_journey_failed', sourceFrames };
    }
    let publication: Buffer;
    try { const bytes = Buffer.from(JSON.stringify(report, null, 2) + '\n'); scanBytes(bytes); bytes.fill(0); scanner.close();
      report.secretOutputScan = scanner.stats(); publication = Buffer.from(JSON.stringify(report, null, 2) + '\n'); }
    catch { scanner.close(); report.qualified = false; publication = Buffer.from(JSON.stringify({ diagnosticOnly: true, qualified: false,
      phase: 'secret_scan_or_report_failure', scope: report.scope, secretOutputScan: scanner.stats() }) + '\n'); primary ??= new Error('secret scan refused'); }
    secret.fill(0); password.fill(0);
    try { await writeFile(recipe.reportFile, publication, { flag: 'wx', mode: 0o644 }); }
    finally { publication.fill(0); }
  }
  if (primary) throw new Error('actual installed Run journey failed; inspect the closed diagnostic report');
}

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const [mode, filename, ...extra] = process.argv.slice(2);
assert(mode === '--campaign' || mode === '--failure-campaign' || mode === '--retry-campaign'); assert(filename && extra.length === 0);
await campaign(filename, mode);
