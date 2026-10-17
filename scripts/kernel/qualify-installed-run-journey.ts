// Real signed installation, user manager, Secret Service and public v1 UDS.
// The owned HTTPS responder qualifies transport mechanics, never a provider,
// model capability/billing bound, I2 result, macOS or the full I1 fault matrix.
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { chown, link, lstat, mkdir, open, readFile, readdir, readlink, stat, statfs, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { decodeBrokerProcessDomainDeath, decodeBrokerProcessDomainDeathDispatchClosure } from '../../src/kernel/broker-process-domain-death.js';
import { decodeCredentialAuthorityOperation, decodeCredentialAuthorityRevokeOperation,
  decodeEndpointAuthorityOperation, type EndpointRegistrationV1 } from '../../src/kernel/credential-authority.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../src/kernel/identity.js';
import { parseJsonStrict } from '../../src/kernel/json.js';
import type { CredentialFinalizeRequest } from '../../src/state/installed-credential-client.js';
import { MODEL_BROKER_ENTRY_ID, MODEL_BROKER_RELATIVE_PATH } from '../../src/state/model-broker-native.js';
import { buildInstalledSupervisorPackage } from './testing/installed-supervisor-package.js';
import { createCredentialSecretScanner } from './testing/credential-secret-scan.js';
import { scanCredentialSecretCorpus } from './testing/credential-secret-corpus.js';
import { assertInstalledWorkerLeaseRenewed, inspectInstalledWorkerLease } from './testing/installed-worker-lease.js';
import { inspectInstalledOwnerHistory } from './testing/installed-read-control.js';
import { qualifyInstalledOwnerLinks } from './testing/installed-owner-history.js';
import { projectInstalledRunProgress, projectInstalledServiceExit, projectInstalledSupervisorStatus } from '../../src/sandbox/testing/installed-run-progress.js';

type Recipe = { buildFixture: string; packageRoot: string; installerEntry: string; stateRoot: string; releaseKeysFile: string;
  controlDirectory: string; observer: string; storeFixture: string; workspace: string; reportFile: string };
type Ledger = { diagnosticOnly: true; fixture: string; fixtureIdentity: string; username: string;
  uid: number; gid: number; runnerUid: number; home: string; runJourney: Recipe };
type Response = { protocolVersion: 1; ok: boolean; method?: string; result?: Record<string, any>; error?: Record<string, unknown> };
const environment = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' };
const hostBefore = 'before the private edit\n';
const privateAfter = 'after the private edit\n';
const excludedVendorInstruction = 'Ordinary vendor instructions remain independent of source exclusion.\n';
const model = 'installed-run-transport-fixture';
const rejectedResponse = '{"error":{"message":"Owned fixture rejected this request."}}';
type CampaignMode = '--campaign' | '--failure-campaign' | '--retry-campaign' | '--authority-failure-campaign' |
  '--storage-failure-campaign' | '--shutdown-admission-campaign' | '--shutdown-session-campaign' | '--shutdown-preparation-campaign' |
  '--shutdown-received-tool-campaign' | '--shutdown-pending-model-campaign' | '--shutdown-startup-campaign';
const requestTokenCeiling = { inputTokens: 32768, outputTokens: 4096, cacheReadTokens: 0, cacheWriteTokens: 0 };
const imageFields = ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
const receivedToolBefore = 'owned received-tool OLD token';
const receivedToolAfter = 'owned received-tool NEW token';

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

// An ordinary persistent public client, not a private Supervisor test seam.
// Its original authenticated connection remains usable while actual CAS
// creation is refused; new connection identities themselves publish to CAS.
const persistentClientScript = `import assert from 'node:assert/strict';import net from 'node:net';
import {createInterface} from 'node:readline';
const socket=net.createConnection(process.argv[1]);let input=Buffer.alloc(0),waiter,error,count=0;
const closed=new Promise(resolve=>socket.once('close',resolve));
socket.on('data',chunk=>{try{input=Buffer.concat([input,chunk]);assert(input.length<=1048580);
while(input.length>=4){const size=input.readUInt32BE(0);assert(size>=1&&size<=1048576);if(input.length<size+4)break;
const text=new TextDecoder('utf-8',{fatal:true}).decode(input.subarray(4,size+4));input=input.subarray(size+4);
assert(waiter);const pending=waiter;waiter=undefined;pending.resolve(text);}}
catch(failure){error=failure;waiter?.reject(failure);socket.destroy();}});
socket.on('error',failure=>{error=failure;waiter?.reject(failure);});
socket.on('close',()=>{error??=new Error('original public connection closed');waiter?.reject(error);});
try{await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
console.log('connected');const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of lines){assert(++count<=1024&&!waiter&&!error);const body=Buffer.from(line);assert(body.length>=1&&body.length<=1048576);
const header=Buffer.alloc(4);header.writeUInt32BE(body.length);const text=await new Promise((resolve,reject)=>{
waiter={resolve,reject};socket.write(Buffer.concat([header,body]));});console.log(JSON.stringify(text));}}
finally{socket.destroy();await closed;}`;

async function campaign(filename: string, mode: CampaignMode): Promise<void> {
  assert.equal(process.geteuid!(), 0);
  const ledger = await readLedger(filename), recipe = ledger.runJourney;
  const failureOnly = mode === '--failure-campaign';
  const retryOnly = mode === '--retry-campaign';
  const authorityOnly = mode === '--authority-failure-campaign';
  const storageOnly = mode === '--storage-failure-campaign';
  const shutdownAdmissionOnly = mode === '--shutdown-admission-campaign';
  const shutdownSessionOnly = mode === '--shutdown-session-campaign';
  const shutdownPreparationOnly = mode === '--shutdown-preparation-campaign';
  const shutdownReceivedToolOnly = mode === '--shutdown-received-tool-campaign';
  const shutdownStartupOnly = mode === '--shutdown-startup-campaign';
  const shutdownPendingModelOnly = mode === '--shutdown-pending-model-campaign' || shutdownStartupOnly;
  const shutdownEffectsOnly = shutdownReceivedToolOnly || shutdownPendingModelOnly;
  const report: Record<string, any> = { diagnosticOnly: true, qualified: false, phase: 'installation',
    scope: shutdownStartupOnly
      ? 'independent signed installed Linux startup SIGTERM after the actual successor StateOwner and selected native broker executable mapping exist but before v1 control opens, with one genuinely retained unknown model claim, unchanged two-second policy and exact third-owner terminal recovery; not an exact retained-Run loader instruction, provider or complete I1 qualification'
      : shutdownReceivedToolOnly
      ? 'independent signed installed Linux SIGTERM after positively observed original received-tool snapshot progress, unchanged two-second service timeout, original executed result and ready Checkpoint, then successor continuation and terminal cancellation; not an exact private close gate, provider or complete I1 qualification'
      : shutdownPendingModelOnly
      ? 'independent signed installed Linux SIGTERM with one complete owned model POST awaiting a response, unchanged two-second service timeout, original socket join and fully charged UNKNOWN before durable worker fencing, then strict successor terminal cancellation; not an exact native mutex, provider or complete I1 qualification'
      : shutdownPreparationOnly
      ? 'independent signed installed Linux scheduler SIGTERM after actual original Supervisor writes to a queued Run generation, unchanged two-second service timeout, graceful owner join and exact successor cancellation/history; the ordinary observation-to-gate race is retained, not an exact preparing-only, controller, received-tool, provider or complete I1 qualification'
      : shutdownSessionOnly
      ? 'independent signed installed Linux Supervisor SIGTERM during an original pending session.create and positively observed native Trust-directory enumeration, unchanged two-second service timeout, graceful owner join and exact successor replay; not an exact private precommit-abort, Run, provider or complete I1 qualification'
      : shutdownAdmissionOnly
      ? 'independent signed installed Linux Supervisor SIGTERM during positively observed ordinary instruction capture for an in-flight public Run admission, unchanged two-second service timeout, graceful owner join and successor preservation of absence or a legitimately committed admission; not an exact precommit-abort, source-payload, worker-preparation, received-tool, provider or complete I1 qualification'
      : storageOnly
      ? 'independent signed installed Linux Run, real read-preserving CAS write refusal after one actual POST, same-owner typed UNKNOWN settlement after exact restoration, no extra accepted TCP/TLS/POST, then actual successor-owner cancellation and terminal replay; not never-CONNECT guard storage-failure qualification, a provider qualification or complete I1'
      : authorityOnly
      ? 'independent signed installed Linux Runs, real credential revocation after queued admission, exact pre-I/O refusal and terminal retirement, one Session publication per Run and actual Supervisor restart; not a provider qualification, exact finalizer cut or complete I1'
      : retryOnly
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
    requestedFeatureIds: ['session.create', 'session.get', 'run.submit', 'run.get', 'run.attach', 'run.cancel', 'supervisor.status', 'credential.finalize'] };
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
  const persistentClient = async () => {
    const outScan = scanner.openStream();
    let errorScan: ReturnType<typeof scanner.openStream>;
    try { errorScan = scanner.openStream(); } catch (error) { outScan.close(); throw error; }
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn('/usr/sbin/runuser', [...prefix, process.execPath, '--input-type=module', '-e', persistentClientScript,
        path.join(recipe.stateRoot, 'runtime/control-v1.sock')], { env: environment, cwd: ledger.home, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (error) { outScan.close(); errorScan.close(); throw error; }
    let output = '', errorBytes = 0, failure: unknown, readyResolve!: () => void, readyReject!: (error: unknown) => void;
    let pending: { resolve(text: string): void; reject(error: unknown): void } | undefined;
    const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const refuse = (error: unknown) => { failure ??= error; readyReject(error); pending?.reject(error); };
    child.stdout.on('data', (bytes: Buffer) => {
      try {
        outScan.scan(bytes); output += bytes.toString('utf8'); assert(Buffer.byteLength(output) <= 2 * 1048580);
        for (;;) {
          const at = output.indexOf('\n'); if (at < 0) break;
          const line = output.slice(0, at); output = output.slice(at + 1);
          if (line === 'connected') { readyResolve(); continue; }
          assert(pending, 'persistent client emitted an unsolicited response');
          const text = parseJsonStrict(line); assert.equal(typeof text, 'string');
          const original = pending; pending = undefined; original.resolve(text as string);
        }
      } catch (error) { refuse(error); }
    });
    child.stderr.on('data', (bytes: Buffer) => {
      try { errorScan.scan(bytes); errorBytes += bytes.length; assert(errorBytes <= 65536); }
      catch (error) { refuse(error); }
    });
    child.once('error', refuse); child.stdin.on('error', refuse); child.stdout.on('error', refuse); child.stderr.on('error', refuse);
    const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => {
      outScan.close(); errorScan.close(); if (pending) refuse(new Error('original public client closed before its response'));
      resolve({ code, signal });
    }));
    let closing: Promise<void> | undefined;
    const close = () => closing ??= (async () => {
      child.stdin.end();
      let exit: Awaited<typeof closed>;
      try { exit = await bounded(closed, 10000, 'original public client did not join'); }
      catch (error) {
        child.kill('SIGKILL');
        // runuser can have an actual child holding its inherited pipes. Do
        // not turn failed cleanup into an unbounded wait or a positive join;
        // the outer UID-scoped coordinator still owns final child retirement.
        try { await bounded(closed, 10000, 'original public client pipes did not join after wrapper exit'); }
        catch (joinError) { throw new AggregateError([error, joinError], 'original public client retirement failed'); }
        throw error;
      }
      assert.equal(exit.code, 0); assert.equal(exit.signal, null); assert.equal(failure, undefined); assert.equal(output, '');
      assert.equal(errorBytes, 0); report.originalPublicClientJoined = true;
    })();
    const joinAfterPeerShutdown = () => closing ??= (async () => {
      // Only the isolated SIGTERM case calls this after observing the actual
      // service stop and the original pending request's disconnection. The
      // ordinary client still refuses closure rather than reconnecting.
      child.stdin.end();
      const exit = await bounded(closed, 10000, 'disconnected original public client did not join');
      assert.equal(exit.signal, null); assert.equal(exit.code, 1);
      assert(failure instanceof Error); assert.equal(output, '');
      assert(errorBytes > 0 && errorBytes <= 65536); report.originalPublicClientJoined = true;
    })();
    const send = async (value: Record<string, unknown>, timeout = 5000): Promise<Response> => {
      assert(!pending && !failure && !closing); const bytes = canonicalJsonBytes(value); assert(bytes.length <= 1048576);
      const reply = new Promise<string>((resolve, reject) => { pending = { resolve, reject }; });
      child.stdin.write(Buffer.concat([bytes, Buffer.from('\n')]));
      const text = await bounded(reply, timeout, 'original public client request did not complete');
      const response = parseJsonStrict(text) as Response; assert.equal(text, canonicalJsonBytes(response).toString('utf8'));
      return response;
    };
    try {
      await bounded(Promise.race([ready, closed.then(() => { throw new Error('original public client closed before readiness'); })]),
        5000, 'original public client did not connect');
      accepted(await send(hello), 'control.hello'); return { send, close, joinAfterPeerShutdown };
    } catch (error) { try { await close(); } catch {} throw error; }
  };
  const show = (unit: string) => {
    const result = command('/usr/bin/systemctl', ['--user', 'show', unit, '--property=Id,ActiveState,SubState,MainPID,ExecMainPID,InvocationID,ControlGroup,Type,Delegate,KillMode,Result,ExecMainCode,ExecMainStatus', '--no-pager']);
    assert.equal(result.status, 0); return Object.fromEntries(result.stdout.trim().split('\n').map(line => {
      const at = line.indexOf('='); assert(at > 0); return [line.slice(0, at), line.slice(at + 1)]; }));
  };
  const observeShutdownRefusal = (unit: string, pid: string | undefined) => {
    // Read only this disposable unit/process's bounded journal. Never retain
    // arbitrary journal text, error messages, paths, stacks or nested causes.
    const origins = new Map([
      ['worker preparation physical retirement did not complete', 'preparation_retirement'],
      ['Run execution failed and its resources did not retire', 'execution_retirement'],
      ['private workspace descriptor retirement failed', 'workspace_descriptor_retirement'],
      ['StateStore producer revocation did not start cleanly', 'producer_revocation'],
      ['StateStore execution revocation did not start cleanly', 'execution_revocation'],
      ['workspace materialization has not completely joined', 'materialization_join'],
      ['native retirement clock precedes workspace birth', 'workspace_retirement_clock']
    ]);
    if (!pid || !/^[1-9][0-9]*$/u.test(pid)) return { diagnosticOnly: true, available: false };
    const result = spawnSync('/usr/bin/journalctl', ['--no-pager', '--output=cat', '--lines=16',
      `_UID=${ledger.uid}`, `_SYSTEMD_USER_UNIT=${unit}`, `_PID=${pid}`],
    { env: environment, timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 65536 });
    const refusals: Array<{ code: string; origin: string }> = [];
    try {
      if (Buffer.isBuffer(result.stdout)) scanBytes(result.stdout);
      if (Buffer.isBuffer(result.stderr)) scanBytes(result.stderr);
      if (result.error || result.signal || result.status !== 0 || !Buffer.isBuffer(result.stdout))
        return { diagnosticOnly: true, available: false };
      for (const line of result.stdout.toString('utf8').split('\n')) {
        if (!line.startsWith('{') || Buffer.byteLength(line) > 4096 || refusals.length >= 4) continue;
        try {
          const value = parseJsonStrict(line) as Record<string, unknown>;
          if (value?.diagnosticOnly !== true) continue;
          if (value.scope === 'installed-shutdown-retirement' && value.debugTag === '[DEBUG-shutdown-retirement]' &&
              ['preparation', 'retirement', 'worker_join'].includes(value.stage as string) &&
              ['unregistered_controller_birth', 'unregistered_reservation_birth', 'materialization_join_pending',
                'joined_generation_birth_mismatch', 'native_generation_retirement', 'quarantine_identity',
                'worker_stop_channel_fenced', 'preparation_materialization_join', 'preparation_controller_join',
                'preparation_reservation_join', 'preparation_commit', 'preparation_logical_identity',
                'preparation_run_changed', 'preparation_broker_owner', 'preparation_history', 'preparation_logical_cut',
                'preparation_generation_identity', 'preparation_recovery_closure', 'preparation_controller_birth',
                'preparation_resource_assertion', 'preparation_quarantine_move', 'preparation_resource_refresh',
                'preparation_evidence_publication', 'preparation_transaction', 'unclassified'].includes(value.reason as string)) {
            refusals.push({ code: 'diagnostic_only', origin: `${value.stage}.${value.reason}` }); continue;
          }
          if (value.scope !== 'installed-read-startup') continue;
          const code = ['RECOVERY_REQUIRED', 'LEASE_FENCED', 'ARTIFACT_MISMATCH', 'STATE_TRANSITION_INVALID'].includes(value.code as string)
            ? value.code as string : 'unclassified';
          refusals.push({ code, origin: typeof value.message === 'string' ? origins.get(value.message) ?? 'unclassified' : 'unclassified' });
        } catch { /* Non-source journal data supplies no diagnostic fact. */ }
      }
      return { diagnosticOnly: true, available: refusals.length > 0, refusals };
    } finally { result.stdout?.fill(0); result.stderr?.fill(0); }
  };
  const observe = () => {
    const result = command(recipe.observer, ['list']); assert.equal(result.status, 0);
    const value = parseJsonStrict(result.stdout.trim()) as { clientPid: number; busUniqueName: string; serviceUid: number; servicePid: number; nameOwner: string;
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
  const withRetainedUnitHistory = async (units: string[], body: (assertRetained: () => void) => Promise<void>): Promise<void> => {
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
  let daemon: ChildProcess | undefined, daemonExit: Promise<void> | undefined, daemonPid: number | undefined, daemonStart: string | undefined;
  let installedServices: { supervisorUnit: string; keeperUnit: string } | undefined;
  let retryPlatform: ReturnType<typeof observe> | undefined, aliasRestoreCollection: string | undefined;
  let server: Server | undefined;
  let primary: unknown, providerFailure = false, requestsReceived = 0, reflectionEnabled = false, shortRunEnabled = false;
  let busySubmit: (Record<string, unknown> & { admissionKey: string }) | undefined;
  let busyFinalize: CredentialFinalizeRequest | undefined;
  let storageClient: Awaited<ReturnType<typeof persistentClient>> | undefined;
  let queuedObserverClient: Awaited<ReturnType<typeof persistentClient>> | undefined;
  let shutdownClient: Awaited<ReturnType<typeof persistentClient>> | undefined;
  let restoreCasWrite: (() => Promise<void>) | undefined;
  let storagePost: { destroy(): void; closed: Promise<void>; assertPending(): void } | undefined;
  let storagePostResolve!: () => void;
  const storagePostEntered = new Promise<void>(resolve => { storagePostResolve = resolve; });
  let acceptedTcpConnections = 0, acceptedTlsConnections = 0;
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
  // Only the two isolated shutdown campaigns use this real public Journal/CAS
  // inspection. A free failed preparation may precede the first permanent
  // claim; it must not be mistaken for either productive I/O or a refund after
  // a claim. No phase or settlement is invented to fill a missing prefix.
  const inspectShutdownModelClaims = async (cut: Record<string, any>) => {
    assert(shutdownAdmissionOnly || shutdownPreparationOnly);
    assert.equal(cut.nextJournalSeq, cut.highWaterJournalSeq);
    assert.equal(cut.journal.length, cut.highWaterJournalSeq);
    const run = cut.snapshot.run, entries: Array<Record<string, any>> = cut.journal;
    const spec = parseJsonStrict((await readCas(run.specRef)).toString('utf8')) as Record<string, any>;
    const assembly = parseJsonStrict((await readCas(spec.assemblyRef)).toString('utf8')) as Record<string, any>;
    assert.equal(canonicalSha256(assembly.retry.model), canonicalSha256({ maxDispatchedAttempts: 3,
      maxZeroByteTransportRetriesPerAttempt: 0, postAttemptDelaysMs: [500, 2000] }));
    const claims = entries.filter(entry => entry.phase === 'dispatch_claimed'); assert(claims.length <= 1);
    const first = entries[0], fullCharge = { modelTokens: 36864, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
    const zeroCharge = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index]!;
      assert.equal(entry.seq, index + 1); assert.equal(entry.runId, run.id); assert.equal(entry.opKind, 'model');
      assert.equal(entry.opId, first!.opId); assert.equal(entry.target, first!.target); assert.equal(entry.replayClass, 'retry');
    }
    const stableRequest = ({ attempt: _attempt, promptProjectionRef: _projection,
      promptProjectionDigest: _projectionDigest, requestDigest: _digest, ...stable }: Record<string, any>) => stable;
    let originalRequest: Record<string, any> | undefined, index = 0, freeFailures = 0;
    while (index < entries.length) {
      const prepared = entries[index]!;
      assert.equal(prepared.phase, 'prepared'); assert.equal(prepared.attempt, freeFailures);
      assert.equal(canonicalSha256(prepared.budgetDelta), canonicalSha256(fullCharge));
      const modelRequest = parseJsonStrict((await readCas(prepared.requestRef)).toString('utf8')) as Record<string, any>;
      assert.equal(modelRequest.schemaVersion, 1); assert.equal(modelRequest.format, 'cliq-model-request-v1');
      assert.equal(modelRequest.kind, 'normal'); assert.equal(modelRequest.runId, run.id);
      assert.equal(modelRequest.opId, prepared.opId); assert.equal(modelRequest.attempt, prepared.attempt);
      assert.equal(modelRequest.assemblyRef, spec.assemblyRef);
      assert.equal(modelRequest.requestDigest, digestOmitting(modelRequest, 'requestDigest'));
      if (originalRequest) assert.equal(canonicalSha256(stableRequest(modelRequest)), canonicalSha256(stableRequest(originalRequest)));
      else originalRequest = modelRequest;
      const next = entries[index + 1];
      if (!next) { assert.equal(claims.length, 0); break; } // genuinely still prepared at the captured public cut
      if (next.phase === 'dispatch_claimed') {
        assert.equal(claims.length, 1); assert.equal(next.attempt, freeFailures);
        for (const entry of entries.slice(index + 1)) {
          assert.equal(entry.attempt, prepared.attempt); assert.equal(entry.requestRef, prepared.requestRef);
          assert.notEqual(entry.phase, 'prepared');
        }
        break;
      }
      assert.equal(next.phase, 'failed'); assert.equal(next.attempt, prepared.attempt);
      assert.equal(next.requestRef, prepared.requestRef); assert.equal(next.seq, prepared.seq + 1);
      for (const entry of [prepared, next]) for (const key of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest'])
        assert.equal(entry[key], undefined, 'free prefix cannot carry permanent-claim authority');
      assert.equal(next.resultRef, undefined); assert.equal(canonicalSha256(next.budgetDelta), canonicalSha256(zeroCharge));
      const settlement = parseJsonStrict((await readCas(next.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
      assert.equal(settlement.schemaVersion, 1); assert.equal(settlement.format, 'cliq-budget-settlement-v1');
      assert.equal(settlement.runId, run.id); assert.equal(settlement.opId, prepared.opId); assert.equal(settlement.attempt, prepared.attempt);
      assert.equal(settlement.preparedJournalSeq, prepared.seq); assert.equal(settlement.terminalJournalSeq, next.seq);
      assert.equal(settlement.terminalPhase, 'failed'); assert.equal(settlement.settledAt, next.timestamp);
      assert.equal(settlement.settlementDigest, digestOmitting(settlement, 'settlementDigest'));
      for (const actual of [settlement.reserved, settlement.released, settlement.budgetReservedBefore])
        assert.equal(canonicalSha256(actual), canonicalSha256(fullCharge));
      for (const actual of [settlement.consumed, settlement.budgetConsumedBefore, settlement.budgetConsumedAfter, settlement.budgetReservedAfter])
        assert.equal(canonicalSha256(actual), canonicalSha256(zeroCharge));
      const failure = parseJsonStrict((await readCas(next.errorRef)).toString('utf8')) as Record<string, any>;
      assert.equal(failure.format, 'cliq-invocation-error-v1'); assert.equal(failure.reason, 'installed_model_preparation_refused');
      assert.equal(failure.runId, run.id); assert.equal(failure.opId, prepared.opId);
      assert.equal(failure.attempt, prepared.attempt); assert.equal(failure.requestRef, prepared.requestRef);
      freeFailures++; index += 2;
    }
    return { freeFailures, permanentClaims: claims.length, claimedAttempt: claims[0]?.attempt ?? null,
      contiguousFreePrefixQualified: true, frozenAttemptPolicyUnchanged: true };
  };
  const refuseCasWrites = async () => {
    assert(storageOnly && process.geteuid!() === 0 && !restoreCasWrite);
    const name = path.join(recipe.stateRoot, 'cas');
    const held = await open(name, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    let transferred = false;
    try {
      const original = await held.stat({ bigint: true }), home = await lstat(ledger.home, { bigint: true });
      const filesystem = await statfs(name, { bigint: true });
      assert(original.isDirectory() && original.uid === BigInt(ledger.uid) && original.gid === BigInt(ledger.gid) &&
        original.nlink === 2n && (original.mode & 0o7777n) === 0o700n && original.dev === home.dev);
      assert.equal(filesystem.type, 0xef53n, 'write refusal is confined to the existing disposable bounded ext4 volume');
      assert(filesystem.bsize * filesystem.blocks > 0n && filesystem.bsize * filesystem.blocks <= 1024n ** 3n);
      const assertOriginal = async () => {
        const current = await held.stat({ bigint: true }), named = await lstat(name, { bigint: true });
        assert(current.isDirectory() && named.isDirectory() && !named.isSymbolicLink());
        for (const field of ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink'] as const) {
          assert.equal(current[field], original[field]); assert.equal(named[field], original[field]);
        }
      };
      const attributes = (action: 'read' | 'refuse' | 'restore') => {
        // Only the original held CAS inode is inherited as fd3. The final
        // '.' keeps e2fsprogs' O_NOFOLLOW guard intact; no user path is an RPC.
        const result = spawnSync(action === 'read' ? '/usr/bin/lsattr' : '/usr/bin/chattr',
          action === 'read' ? ['-d', '--', '/proc/self/fd/3/.'] : [action === 'refuse' ? '+i' : '-i', '--', '/proc/self/fd/3/.'],
          { env: environment, timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 65536, stdio: ['ignore', 'pipe', 'pipe', held.fd] });
        assert(Buffer.isBuffer(result.stdout) && Buffer.isBuffer(result.stderr)); scanBytes(result.stdout); scanBytes(result.stderr);
        assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, 'owned CAS attribute operation refused');
        if (action !== 'read') { assert.equal(result.stdout.length, 0); assert.equal(result.stderr.length, 0); return ''; }
        const match = /^([A-Za-z-]{1,64})\s+\/proc\/self\/fd\/3\/\.$/u.exec(result.stdout.toString('utf8').trim());
        assert(match && result.stderr.length === 0); return match[1]!;
      };
      await assertOriginal(); const originalFlags = attributes('read'); assert(!originalFlags.includes('i'));
      let restoration: Promise<void> | undefined;
      restoreCasWrite = () => restoration ??= (async () => {
        await assertOriginal(); attributes('restore'); await assertOriginal();
        assert.equal(attributes('read'), originalFlags, 'restore exactly the original CAS flags');
        await held.close(); report.casWritesRestored = true;
      })();
      transferred = true; // Even a partial set failure owes unconditional restoration.
      attributes('refuse'); await assertOriginal();
      const refusedFlags = attributes('read');
      assert(refusedFlags.includes('i')); assert.equal(refusedFlags.replace('i', '-'), originalFlags);
      const probeName = `.cliq-write-refusal-${randomBytes(16).toString('hex')}.tmp`;
      const probePath = path.join(name, probeName);
      await assert.rejects(lstat(probePath), { code: 'ENOENT' });
      const denied = command(process.execPath, ['--input-type=module', '-e',
        `import assert from 'node:assert/strict';import fs from 'node:fs';let fd,created=false,code;
try{fd=fs.openSync(process.argv[1],fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);created=true;}
catch(error){code=error.code;}finally{if(fd!==undefined)fs.closeSync(fd);if(created)fs.unlinkSync(process.argv[1]);}
assert.equal(created,false);assert.equal(code,'EPERM');console.log(JSON.stringify({writeRefused:true,errorCode:code}));`, probePath]);
      assert.equal(denied.status, 0);
      assert.equal(canonicalSha256(parseJsonStrict(denied.stdout.trim())), canonicalSha256({ writeRefused: true, errorCode: 'EPERM' }));
      await assert.rejects(lstat(probePath), { code: 'ENOENT' }); await assertOriginal();
      report.casWriteRefusal = { qualified: false, actualUnprivilegedError: 'EPERM', originalDirectoryMode: '0700',
        originalDirectoryIdentityRetained: true, originalReadAccessRetained: true, privateBoundedExt4Only: true,
        probeObjectAbsent: true, productionAttemptWitnessed: false };
      return async () => { await assertOriginal(); assert.equal(attributes('read'), refusedFlags); };
    } finally { if (!transferred) await held.close(); }
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
        if (storageOnly || shutdownPendingModelOnly) {
          assert.equal(ordinal, 1, 'the retained original failure must never redispatch provider I/O');
          assert.equal(storagePost, undefined);
          const socket = incoming.socket;
          storagePost = { destroy() { incoming.destroy(); outgoing.destroy(); },
            assertPending() { assert(incoming.complete && !socket.destroyed && !outgoing.headersSent && !outgoing.writableEnded); },
            closed: new Promise<void>(resolve => socket.once('close', () => resolve())) };
          report.providerRequests = { received: ordinal, method: 'POST', requestPath: '/v1/chat/completions', tls13: true,
            exactCredentialMatched: true, responseWithheld: true, latestBodyDigest: sha256Bytes(bodyBytes), latestBodyBytes: bodyBytes.length };
          storagePostResolve(); return;
        }
        if (failureOnly) {
          assert.equal(ordinal, 1, 'a positively received provider rejection must not be retried');
          assert(body.messages.some((message: any) => typeof message.content === 'string' &&
            message.content.includes('Observe the owned caf\u00e9 model failure without using a tool.')),
          'the model must receive the normalized objective, not the original NFD request spelling');
          const instructionPrompt = canonicalJsonBytes({ format: 'cliq-workspace-instruction-prompt-v1', entries: [
            { order: 0, canonicalRootRelativePath: 'vendor/AGENTS.md', appliesToSubtree: true,
              instructionUtf8: excludedVendorInstruction }
          ] }).toString('utf8');
          assert(body.messages.some((message: any) => message.role === 'system' && typeof message.content === 'string' &&
            message.content.endsWith(`\n\n${instructionPrompt}`)),
          'the model must receive the exact structured ordinary instruction bytes and excluded-subtree scope');
          report.instructionMetadataExclusion.providerReceivedOrdinaryGuidance = true;
          try {
            // The actual complete POST holds the original credential scope
            // until this responder replies. A fresh UDS connection can refuse
            // without that scope; never ask for queued installation/status work.
            assert(busySubmit && busyFinalize);
            const [reply, finalized] = exchange([busySubmit, busyFinalize], 0, 5000);
            assert(reply && finalized);
            const code = reply.error?.code;
            report.credentialScopeBusy = { observedCode: !reply.ok && (code === 'RATE_LIMITED' || code === 'INVALID_REQUEST')
              ? code : 'unrecognized', exactPayloadMatched: canonicalSha256(reply) === canonicalSha256({
              protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1,
                code: 'RATE_LIMITED', retryable: true, retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' } }) };
            const finalizeCode = finalized.error?.code;
            report.credentialFinalizeScopeBusy = { observedCode: !finalized.ok &&
              (finalizeCode === 'RATE_LIMITED' || finalizeCode === 'INVALID_REQUEST') ? finalizeCode : 'unrecognized',
              exactPayloadMatched: canonicalSha256(finalized) === canonicalSha256({
                protocolVersion: 1, ok: false, method: 'credential.finalize', error: { schemaVersion: 1,
                  code: 'RATE_LIMITED', retryable: true, retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' } }) };
          } catch {
            report.credentialScopeBusy = { observedCode: 'unavailable', exactPayloadMatched: false };
            report.credentialFinalizeScopeBusy = { observedCode: 'unavailable', exactPayloadMatched: false };
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
        if (retryOnly || authorityOnly || shutdownAdmissionOnly || shutdownPreparationOnly) {
          assert.equal(ordinal, 1, 'this independent candidate campaign must release exactly one actual model request');
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
              function: { name: 'edit', arguments: reflectedArguments ?? JSON.stringify(shutdownReceivedToolOnly
                ? { path: 'payload.txt', old_text: receivedToolBefore, new_text: receivedToolAfter }
                : { path: 'example.txt', old_text: hostBefore, new_text: privateAfter }) } }] }
            : { role: 'assistant', content: 'The private edit is complete.' } }],
          usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } };
        const bytes = Buffer.from(JSON.stringify(payload)); scanBytes(bytes);
        outgoing.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(bytes.length), Connection: 'close' }); outgoing.end(bytes);
        report.providerRequests = { received: ordinal, method: 'POST', requestPath: '/v1/chat/completions', tls13: true,
          exactCredentialMatched: true, latestBodyDigest: sha256Bytes(bodyBytes), latestBodyBytes: bodyBytes.length };
      } catch { providerFailure = true; incoming.destroy(); outgoing.destroy(); }
    });
    server.on('connection', socket => { acceptedTcpConnections++; socketClosures.push(new Promise(resolve => socket.once('close', resolve))); });
    server.on('secureConnection', socket => { acceptedTlsConnections++; if (socket.getProtocol() !== 'TLSv1.3') { providerFailure = true; socket.destroy(); } });
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
    busyFinalize = { protocolVersion: 1, method: 'credential.finalize', requestId: operation.requestId,
      operationId: operation.operationId, attempt: operation.attempt, commandDigest: operation.requestDigest };
    const enrolledPlatform = observe();
    assert.equal(enrolledPlatform.items.length, 1); report.credentialEnrolled = true;
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
    if (failureOnly) {
      const vendor = path.join(recipe.workspace, 'vendor'), metadata = path.join(vendor, '.git');
      for (const directory of [vendor, metadata]) {
        await mkdir(directory, { mode: 0o700 }); await chown(directory, ledger.uid, ledger.gid);
      }
      for (const [file, bytes] of [
        [path.join(vendor, 'AGENTS.md'), Buffer.from(excludedVendorInstruction)],
        [path.join(metadata, 'AGENTS.md'), Buffer.from([0xff])]
      ] as const) {
        await writeFile(file, bytes, { flag: 'wx', mode: 0o644 }); await chown(file, ledger.uid, ledger.gid);
      }
      report.instructionMetadataExclusion = { qualified: false, providerReceivedOrdinaryGuidance: false };
    }
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
    if (shutdownEffectsOnly) {
      const effect: Record<string, any> = { diagnosticOnly: true, qualified: false, standardStopTimeoutMs: 2000,
        exactPrivateCloseGateQualified: false, exactNativeMutexOrderQualified: false, completeI1Qualified: false };
      report[shutdownStartupOnly ? 'shutdownStartup' : shutdownReceivedToolOnly ? 'shutdownReceivedTool' : 'shutdownPendingModel'] = effect;
      const fileBytes = 64 * 1024 * 1024, payloadPath = path.join(recipe.workspace, 'payload.txt');
      let payloadBefore: BigIntStats | undefined, originalBlob: string | undefined, editedBlob: string | undefined;
      if (shutdownReceivedToolOnly) {
        mark('ordinary_received_tool_payload');
        assert.equal(Buffer.byteLength(receivedToolBefore), Buffer.byteLength(receivedToolAfter));
        const bytes = Buffer.alloc(fileBytes, 0x5a), offset = fileBytes / 2;
        bytes.write(receivedToolBefore, offset, 'utf8');
        assert.equal(bytes.indexOf(receivedToolBefore), offset); assert.equal(bytes.lastIndexOf(receivedToolBefore), offset);
        originalBlob = sha256Bytes(bytes);
        await writeFile(payloadPath, bytes, { flag: 'wx', mode: 0o644 }); await chown(payloadPath, ledger.uid, ledger.gid);
        payloadBefore = await lstat(payloadPath, { bigint: true });
        bytes.write(receivedToolAfter, offset, 'utf8'); editedBlob = sha256Bytes(bytes); bytes.fill(0);
      }
      // Only the fixed ordinary payload and its exact CAS objects use this
      // streaming diagnostic. Small JSON readCas remains capped at 1 MiB.
      const verifyPayload = async (filename: string, digest: string, original?: BigIntStats) => {
        assert(shutdownReceivedToolOnly && [originalBlob, editedBlob].includes(digest));
        assert.equal(filename, original ? payloadPath : path.join(recipe.stateRoot, 'cas', digest));
        const chunk = Buffer.alloc(65536), hash = createHash('sha256');
        const held = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        let stream: ReturnType<typeof scanner.openStream> | undefined;
        try {
          stream = scanner.openStream();
          const before = await held.stat({ bigint: true });
          assert(before.isFile() && before.uid === BigInt(ledger.uid) && before.nlink === 1n && before.size === BigInt(fileBytes));
          assert.equal(before.mode & 0o7777n, original ? 0o644n : 0o400n);
          if (original) for (const field of imageFields) assert.equal(before[field], original[field]);
          for (let offset = 0; offset < fileBytes;) {
            const { bytesRead } = await held.read(chunk, 0, Math.min(chunk.length, fileBytes - offset), offset);
            assert(bytesRead > 0); const bytes = chunk.subarray(0, bytesRead); hash.update(bytes); stream.scan(bytes); offset += bytesRead;
          }
          assert.equal((await held.read(chunk, 0, 1, fileBytes)).bytesRead, 0); assert.equal(hash.digest('hex'), digest);
          const after = await held.stat({ bigint: true }), named = await lstat(filename, { bigint: true });
          for (const field of imageFields) { assert.equal(after[field], before[field]); assert.equal(named[field], before[field]); }
        } finally { chunk.fill(0); try { stream?.close(); } finally { await held.close(); } }
      };
      const originalPid = Number(supervisorBefore.MainPID), originalStart = await fixtureProcess(originalPid, ledger.uid);
      const selectedImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
      const signedImage = await lstat(selectedImage, { bigint: true });
      const assertOriginalSupervisor = async () => {
        assert.equal(await fixtureProcess(originalPid, ledger.uid), originalStart);
        assert.equal(await readlink(`/proc/${originalPid}/exe`), selectedImage);
        const actual = await stat(`/proc/${originalPid}/exe`, { bigint: true });
        for (const field of imageFields) assert.equal(actual[field], signedImage[field]);
      };
      const originalOwners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      assert.equal(originalOwners.length, 1); const originalOwner = originalOwners[0]!; assert.equal(originalOwner.state, 'active');
      const ownerProcess = parseJsonStrict((await readCas(originalOwner.processIdentityRef)).toString('utf8')) as Record<string, any>;
      assert.equal(ownerProcess.identityDigest, originalOwner.processIdentityDigest);
      assert.equal(ownerProcess.pid, originalPid); assert.equal(ownerProcess.processStartToken, `linux-proc-start-ticks:${originalStart}`);
      assert.equal(ownerProcess.ownerUid, ledger.uid); assert.equal(ownerProcess.executableImageDigest, report.bundle.supervisorDigest);
      const contract = command('/usr/bin/systemctl', ['--user', 'show', services.supervisorUnit,
        '--property=TimeoutStopUSec,KillSignal,FinalKillSignal,SendSIGKILL', '--no-pager']);
      assert.equal(contract.status, 0);
      const policy = Object.fromEntries(contract.stdout.trim().split('\n').map(line => line.split('=')));
      assert.equal(policy.TimeoutStopUSec, '2s'); assert.equal(policy.KillSignal, '15');
      assert.equal(policy.FinalKillSignal, '9'); assert.equal(policy.SendSIGKILL, 'yes');
      shutdownClient = await persistentClient();
      const submit = request({ protocolVersion: 1, method: 'run.submit', requestId: '019a0012-0000-7000-8000-000000000134',
        admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
        workspacePath: recipe.workspace, objective: shutdownReceivedToolOnly ? 'Change the one OLD token in payload.txt to NEW using one edit.'
          : 'Observe one interrupted model request without using a tool.',
        model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: registration.endpointRegistrationId },
          modelCredentialGrantIds: [enrollment.credentialGrantId] }, policyMode: 'accept-edits',
        budgets: { wallTimeMs: 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000,
          repairAttempts: 0, childDepth: 0, childConcurrency: 1 }, verifiers: [], dependency: { mode: 'none' },
        sourceIncludes: [], sourceExcludes: [], registeredMcpServerIds: [], skillIds: [], allowUnverified: true });
      let submitReply!: Response, admitted!: Record<string, any>, beforeStop!: Record<string, any>, originalGenerationRef: string | undefined;
      const publicRead = async () => {
        const cut = accepted(await shutdownClient!.send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }), 'run.get');
        assert.equal(cut.nextJournalSeq, cut.highWaterJournalSeq); assert.equal(cut.journal.length, cut.highWaterJournalSeq);
        for (let index = 0; index < cut.journal.length; index++) {
          assert.equal(cut.journal[index].seq, index + 1); assert.equal(cut.journal[index].runId, admitted.id);
        }
        report.lastPublicCut = projectInstalledRunProgress(cut, { requestsReceived, providerFailure }); return cut;
      };
      mark('public_effect_run_submit'); submitReply = await shutdownClient!.send(submit, 30000);
      admitted = accepted(submitReply, 'run.submit').snapshot.run;
      assert.equal(admitted.status, 'queued'); assert.equal(admitted.revision, 1);
      report.acceptedRun = { id: admitted.id, sessionId: admitted.sessionId, specRef: admitted.specRef, initialCheckpointId: admitted.latestCheckpointId };
      let recheckOriginalEffect!: () => Promise<void>;
      if (shutdownReceivedToolOnly) {
        mark('original_received_tool_snapshot_progress');
        let target: Record<string, any> | undefined, selectedClaim: Record<string, any> | undefined, selectedLaunchId: string | undefined;
        type SnapshotRead = { descriptor: string; device: bigint; inode: bigint; position: bigint };
        const snapshotRead = async (same?: SnapshotRead): Promise<SnapshotRead | undefined> => {
          assert(target); await assertOriginalSupervisor();
          const directory = path.join(recipe.stateRoot, 'runs', admitted.id, 'generations', target.generationId);
          const names = await readdir(`/proc/${originalPid}/fd`); assert(names.length <= 4096);
          for (const descriptor of names) {
            assert.match(descriptor, /^(?:0|[1-9][0-9]*)$/u); if (same && descriptor !== same.descriptor) continue;
            try {
              const fd = `/proc/${originalPid}/fd/${descriptor}`, filename = path.join(directory, 'payload.txt');
              if (await readlink(fd) !== filename) continue;
              const info = await readFile(`/proc/${originalPid}/fdinfo/${descriptor}`, 'utf8'); assert(info.length <= 65536);
              const flags = info.match(/^flags:\s+([0-7]+)$/mu), position = info.match(/^pos:\s+([0-9]+)$/mu); assert(flags && position);
              const access = Number.parseInt(flags[1]!, 8), progress = BigInt(position[1]!);
              if ((access & 3) !== constants.O_RDONLY || !(access & constants.O_NONBLOCK) || progress <= 0n || progress >= BigInt(fileBytes)) continue;
              for (const parent of [path.join(recipe.stateRoot, 'runs'), path.join(recipe.stateRoot, 'runs', admitted.id),
                path.dirname(directory), directory]) {
                const actual = await lstat(parent, { bigint: true });
                assert(actual.isDirectory() && !actual.isSymbolicLink() && actual.uid === BigInt(ledger.uid) && (actual.mode & 0o7777n) === 0o700n);
              }
              const parent = await lstat(directory, { bigint: true }), named = await lstat(filename, { bigint: true }), actual = await stat(fd, { bigint: true });
              assert.equal(parent.dev.toString(), target.locator.deviceId); assert.equal(parent.ino.toString(), target.locator.directoryFileId);
              assert(actual.isFile() && named.isFile() && !named.isSymbolicLink() && actual.uid === BigInt(ledger.uid) &&
                actual.nlink === 1n && actual.size === BigInt(fileBytes) && (actual.mode & 0o7777n) === 0o644n);
              for (const field of imageFields) assert.equal(actual[field], named[field]);
              assert.equal(actual.dev, parent.dev);
              if (same) { assert.equal(actual.dev, same.device); assert.equal(actual.ino, same.inode); assert(progress >= same.position); }
              if (await readlink(fd) !== filename) continue;
              await assertOriginalSupervisor(); return { descriptor, device: actual.dev, inode: actual.ino, position: progress };
            } catch (error) { if (!['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error; }
          }
          return undefined;
        };
        const toolCut = (cut: Record<string, any>) => {
          const completed = cut.journal.some((entry: any) => entry.opKind === 'tool' && entry.phase === 'completed');
          if (completed) { effect.observedCutLost = true; assert.fail('the original received-tool cut completed before positive shutdown observation'); }
          assert.equal(cut.snapshot.run.status, 'running'); assert(cut.snapshot.run.activeWorkerLaunchId);
          assert.equal(cut.snapshot.run.activeWorkerLaunchId, selectedLaunchId); assert.equal(cut.snapshot.run.leaseEpoch, selectedClaim!.leaseEpoch);
          assert.equal(cut.snapshot.run.specRef, admitted.specRef);
          assert.equal(cut.snapshot.run.cancelRequested, false); assert.equal(cut.snapshot.run.stopIntentRef, undefined);
          assert.deepEqual(cut.journal.map((entry: any) => [entry.opKind, entry.phase, entry.attempt]),
            [['model', 'prepared', 0], ['model', 'dispatch_claimed', 0], ['model', 'completed', 0], ['tool', 'prepared', 0], ['tool', 'dispatch_claimed', 0]]);
          assert.equal(canonicalSha256(cut.journal[4]), canonicalSha256(selectedClaim));
        };
        const observeBy = Date.now() + 30000;
        let observed: SnapshotRead | undefined;
        while (!observed) {
          assert(Date.now() < observeBy, 'the real original received-tool snapshot was not positively observed');
          const cut = await publicRead();
          if (cut.journal.some((entry: any) => entry.opKind === 'tool' && entry.phase === 'completed')) {
            effect.observedCutLost = true; assert.fail('the received-tool snapshot finished before its shutdown cut was observed');
          }
          const claims = cut.journal.filter((entry: any) => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed');
          if (!claims.length) { assert(!providerFailure); await delay(1); continue; }
          assert.equal(claims.length, 1);
          if (!selectedClaim) {
            selectedClaim = claims[0];
            const launch = parseJsonStrict((await readCas(selectedClaim!.sandboxLaunchSpecRef)).toString('utf8')) as Record<string, any>;
            assert.equal(launch.owner.runId, admitted.id); assert.equal(launch.owner.workerLaunchId, cut.snapshot.run.activeWorkerLaunchId);
            selectedLaunchId = launch.owner.workerLaunchId; originalGenerationRef = launch.filesystem.generationRef;
            assert.equal(launch.owner.opId, selectedClaim!.opId); assert.equal(launch.owner.dispatchId, selectedClaim!.dispatchId);
            target = parseJsonStrict((await readCas(launch.filesystem.generationRef)).toString('utf8')) as Record<string, any>;
            assert.equal(target.format, 'cliq-workspace-generation-identity-v1'); assert.equal(target.identityDigest, digestOmitting(target, 'identityDigest'));
            assert.equal(target.runId, admitted.id); assert.equal(target.locator.kind, 'linux_directory');
            assert.match(target.generationId, /^[A-Za-z0-9_-]{43}$/u);
            assert.equal(target.locator.canonicalRootRelativePath, `runs/${admitted.id}/generations/${target.generationId}`);
          }
          toolCut(cut); const before = await snapshotRead(); if (!before) continue;
          toolCut(await publicRead()); const bracketed = await snapshotRead(before); if (!bracketed) continue;
          assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
          observed = await snapshotRead(bracketed); beforeStop = cut;
        }
        effect.originalSnapshotProgress = { qualified: true, sameOriginalSupervisor: true, publicToolClaimBracketed: true,
          workerLaunchId: selectedLaunchId, generationId: target!.generationId, generationRef: originalGenerationRef,
          generationIdentityDigest: target!.identityDigest,
          generationDeviceId: target!.locator.deviceId,
          generationDirectoryFileId: target!.locator.directoryFileId, position: observed.position.toString(), byteCount: fileBytes };
        const originalSnapshot = observed;
        recheckOriginalEffect = async () => {
          toolCut(await publicRead());
          const current = await snapshotRead(originalSnapshot);
          if (!current) effect.observedCutLost = true;
          assert(current, 'the same original snapshot descriptor must remain in progress after unit retention and immediately before SIGTERM');
          assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
          effect.originalSnapshotProgress.postRetainSameDescriptorMatched = true;
          effect.originalSnapshotProgress.postRetainPosition = current.position.toString();
        };
      } else {
        mark('original_whole_post_awaiting_response');
        await bounded(storagePostEntered, 15000, 'the actual complete pending POST was not received');
        assert(storagePost); storagePost.assertPending(); beforeStop = await publicRead();
        assert.deepEqual(beforeStop.journal.map((entry: any) => [entry.opKind, entry.phase, entry.attempt]),
          [['model', 'prepared', 0], ['model', 'dispatch_claimed', 0]]);
        assert.equal(beforeStop.snapshot.run.status, 'running'); assert(beforeStop.snapshot.run.activeWorkerLaunchId);
        assert.equal(beforeStop.snapshot.run.cancelRequested, false); assert.equal(beforeStop.snapshot.run.stopIntentRef, undefined);
        assert.equal(beforeStop.snapshot.run.specRef, admitted.specRef);
        assert.equal(beforeStop.journal[1].supervisorInstanceId, originalOwner.supervisorInstanceId);
        assert.equal(beforeStop.journal[1].stateOwnerEpoch, originalOwner.ownerEpoch);
        assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
        await assertOriginalSupervisor(); storagePost.assertPending(); effect.completeOriginalPostPending = true;
        recheckOriginalEffect = async () => {
          const current = await publicRead();
          assert.deepEqual(current.journal, beforeStop.journal);
          for (const field of ['status', 'activeWorkerLaunchId', 'leaseEpoch', 'specRef', 'cancelRequested', 'stopIntentRef'])
            assert.equal(current.snapshot.run[field], beforeStop.snapshot.run[field]);
          await assertOriginalSupervisor(); storagePost!.assertPending();
          assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
          effect.originalPendingPostRecheckedAfterUnitRetention = true;
        };
      }
      // RefUnit's original ten-second input budget is for observing one stop,
      // not source capture/materialization/model latency. Retain only after a
      // real cut exists, then recheck that SAME producer; a lost cut is failure.
      await withRetainedUnitHistory([services.supervisorUnit, services.keeperUnit], async assertRetained => {
        await recheckOriginalEffect(); assertRetained();
        mark('ordinary_sigterm_with_original_effect_producer');
        const stopped = command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit]), exit = show(services.supervisorUnit);
        effect.serviceExit = projectInstalledServiceExit(exit);
        if (exit.Result !== 'success' || exit.ExecMainStatus !== '0') effect.shutdownRefusal = observeShutdownRefusal(services.supervisorUnit, exit.ExecMainPID);
        assert.equal(stopped.status, 0); assert.equal(exit.ActiveState, 'inactive'); assert.equal(exit.MainPID, '0');
        assert.equal(exit.Result, 'success'); assert.equal(exit.ExecMainCode, '1'); assert.equal(exit.ExecMainStatus, '0');
      });
      if (shutdownPendingModelOnly) {
        await bounded(storagePost!.closed, 5000, 'the original native model socket did not join before harness cleanup');
        effect.originalSocketJoinedWithoutTestDestroy = true;
      }
      await shutdownClient!.close(); shutdownClient = undefined;
      await assert.rejects(lstat(`/proc/${originalPid}`), { code: 'ENOENT' });
      const releasedOwners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      assert.equal(releasedOwners.length, 1); const releasedOwner = releasedOwners[0]!; assert.equal(releasedOwner.state, 'terminal');
      if (releasedOwner.state !== 'terminal') throw new Error('effect shutdown did not release its original StateOwner');
      assert.equal(releasedOwner.terminalReason, 'graceful_release');
      for (const key of ['ownerEpoch', 'supervisorInstanceId', 'processIdentityRef', 'processIdentityDigest',
        'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const) assert.equal(releasedOwner[key], originalOwner[key]);
      const sameKeeper = show(services.keeperUnit);
      assert.equal(sameKeeper.MainPID, keeperBefore.MainPID); assert.equal(sameKeeper.InvocationID, keeperBefore.InvocationID);
      assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
      const precedingOwners = [releasedOwner];
      if (shutdownStartupOnly) {
        mark('actual_retained_run_successor_startup');
        const startup: Record<string, any> = { diagnosticOnly: true, qualified: false,
          exactRetainedRunLoaderInstructionQualified: false, standardStopTimeoutMs: 2000 };
        effect.retainedRunStartup = startup;
        const brokerEntry = signed.bundle.entries.find(entry => entry.entryId === MODEL_BROKER_ENTRY_ID);
        assert(brokerEntry && brokerEntry.role === 'provider_adapter' && brokerEntry.executable &&
          brokerEntry.relativePath === MODEL_BROKER_RELATIVE_PATH && brokerEntry.digest === report.bundle.brokerDigest);
        const brokerImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, brokerEntry.relativePath);
        const brokerBefore = await lstat(brokerImage, { bigint: true });
        assert(brokerBefore.isFile() && !brokerBefore.isSymbolicLink() && brokerBefore.uid === BigInt(ledger.uid) && brokerBefore.nlink === 1n);
        const socketPath = path.join(recipe.stateRoot, 'runtime/control-v1.sock');
        await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
        assert.equal(command('/usr/bin/systemctl', ['--user', 'start', services.supervisorUnit]).status, 0);
        const originalStartup = show(services.supervisorUnit), startupBy = Date.now() + 30000;
        const startupPid = Number(originalStartup.MainPID), startupStart = await fixtureProcess(startupPid, ledger.uid);
        assert.notEqual(originalStartup.MainPID, supervisorBefore.MainPID);
        assert.notEqual(originalStartup.InvocationID, supervisorBefore.InvocationID);
        const selectedBefore = await lstat(selectedImage, { bigint: true });
        const originalStartupProcess = async () => {
          assert(Date.now() < startupBy, 'the retained-Run startup cut exceeded the original observation deadline');
          assert.equal(await fixtureProcess(startupPid, ledger.uid), startupStart);
          const image = await readlink(`/proc/${startupPid}/exe`);
          if (image !== selectedImage) {
            assert(image === path.join(recipe.stateRoot, 'runtime/bootstrap'), 'startup executable differs from both fixed installed images'); return false;
          }
          const actual = await stat(`/proc/${startupPid}/exe`, { bigint: true });
          for (const field of imageFields) assert.equal(actual[field], selectedBefore[field]);
          return true;
        };
        const originalStartupCut = async () => {
          if (!await originalStartupProcess()) return undefined;
          // openSelected already holds every signed image FD. An open broker
          // FD therefore proves nothing about scheduler startup. Only its real
          // executable VMA distinguishes loadModelBroker's process.dlopen here:
          // its only other production caller is model dispatch, which cannot
          // run before startInstalledRuns finishes and opens public control.
          const maps = await open(`/proc/${startupPid}/maps`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          const bytes = Buffer.alloc(262145); let count = 0, mapped = false;
          try {
            for (;;) {
              const part = await maps.read(bytes, count, bytes.length - count, null); count += part.bytesRead;
              assert(count < bytes.length, 'original native image mapping inventory exceeded its fixed bound');
              if (!part.bytesRead) break;
            }
            const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, count)).trim().split('\n');
            assert(lines.length <= 4096);
            const major = (brokerBefore.dev >> 8n & 0xfffn) | (brokerBefore.dev >> 32n & 0xfffff000n);
            const minor = (brokerBefore.dev & 0xffn) | (brokerBefore.dev >> 12n & 0xffffff00n);
            for (const line of lines) {
              const mapping = /^([0-9a-f]+)-([0-9a-f]+)\s+([r-][w-][x-][ps])\s+[0-9a-f]+\s+([0-9a-f]+):([0-9a-f]+)\s+([0-9]+)\s*(.*)$/u.exec(line);
              assert(mapping, 'original native image mapping inventory is malformed');
              if (mapping[3] !== 'r-xp' || mapping[7] !== brokerImage) continue;
              assert(BigInt(`0x${mapping[1]!}`) < BigInt(`0x${mapping[2]!}`));
              assert.equal(BigInt(`0x${mapping[4]}`), major); assert.equal(BigInt(`0x${mapping[5]}`), minor);
              assert.equal(BigInt(mapping[6]!), brokerBefore.ino); mapped = true;
            }
          } finally { bytes.fill(0); await maps.close(); }
          if (!mapped) return undefined;
          const currentBroker = await lstat(brokerImage, { bigint: true });
          for (const field of imageFields) assert.equal(currentBroker[field], brokerBefore[field]);
          // This absence is a mandatory cut, not a connect/retry heuristic.
          await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
          const owners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
          assert.equal(owners.length, 2); assert.deepEqual(owners[0], releasedOwner);
          const active = owners[1]!; assert.equal(active.state, 'active');
          assert.equal(active.ownerEpoch, originalOwner.ownerEpoch + 1);
          const identity = parseJsonStrict((await readCas(active.processIdentityRef)).toString('utf8')) as Record<string, any>;
          assert.equal(identity.identityDigest, active.processIdentityDigest); assert.equal(identity.identityDigest, digestOmitting(identity, 'identityDigest'));
          assert.equal(identity.pid, startupPid); assert.equal(identity.ownerUid, ledger.uid);
          assert.equal(identity.processStartToken, `linux-proc-start-ticks:${startupStart}`);
          assert.equal(identity.executableImageDigest, report.bundle.supervisorDigest);
          assert(await originalStartupProcess());
          await assert.rejects(lstat(socketPath), { code: 'ENOENT' });
          return active;
        };
        let startupOwner: ReturnType<typeof inspectInstalledOwnerHistory>['owners'][number] | undefined;
        while (!startupOwner) {
          assert(Date.now() < startupBy, 'the actual retained-Run startup was not positively observed');
          startupOwner = await originalStartupCut(); if (!startupOwner) await delay(10);
        }
        startup.originalProcessAndBrokerMappingMatched = true; startup.publicControlAbsent = true;
        startup.ownerEpoch = startupOwner.ownerEpoch; startup.brokerEntryId = MODEL_BROKER_ENTRY_ID;
        startup.brokerImageDigest = brokerEntry.digest; startup.brokerDeviceId = brokerBefore.dev.toString();
        startup.brokerFileId = brokerBefore.ino.toString();
        await withRetainedUnitHistory([services.supervisorUnit, services.keeperUnit], async assertRetained => {
          assert.deepEqual(await originalStartupCut(), startupOwner); assertRetained();
          mark('ordinary_sigterm_during_retained_run_startup');
          const stopped = command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit]), exit = show(services.supervisorUnit);
          startup.serviceExit = projectInstalledServiceExit(exit);
          if (exit.Result !== 'success' || exit.ExecMainStatus !== '0') startup.shutdownRefusal = observeShutdownRefusal(services.supervisorUnit, exit.ExecMainPID);
          assert.equal(stopped.status, 0); assert.equal(exit.ActiveState, 'inactive'); assert.equal(exit.MainPID, '0');
          assert.equal(exit.Result, 'success'); assert.equal(exit.ExecMainCode, '1'); assert.equal(exit.ExecMainStatus, '0');
        });
        await assert.rejects(lstat(`/proc/${startupPid}`), { code: 'ENOENT' });
        const retired = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
        assert.equal(retired.length, 2); assert.deepEqual(retired[0], releasedOwner);
        const terminal = retired[1]!; assert.equal(terminal.state, 'terminal');
        if (terminal.state !== 'terminal') throw new Error('the original startup StateOwner did not retire');
        assert.equal(terminal.terminalReason, 'graceful_release');
        for (const field of ['ownerEpoch', 'supervisorInstanceId', 'processIdentityRef', 'processIdentityDigest',
          'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const) assert.equal(terminal[field], startupOwner[field]);
        const unchangedKeeper = show(services.keeperUnit);
        assert.equal(unchangedKeeper.MainPID, keeperBefore.MainPID); assert.equal(unchangedKeeper.InvocationID, keeperBefore.InvocationID);
        assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
        assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
        precedingOwners.push(terminal); startup.qualified = true; startup.originalOwnerGracefullyReleased = true;
        startup.noProductiveRedispatch = true; startup.transitionEvidenceRef = terminal.transitionEvidenceRef;
      }
      mark('effect_original_owner_successor');
      assert.equal(command('/usr/bin/systemctl', ['--user', 'start', services.supervisorUnit]).status, 0);
      const successor = show(services.supervisorUnit), recoverBy = Date.now() + 30000;
      assert.notEqual(successor.MainPID, supervisorBefore.MainPID); assert.notEqual(successor.InvocationID, supervisorBefore.InvocationID);
      const successorStart = await selectedSupervisor(services.supervisorUnit, successor, selectedImage, recoverBy);
      const links: Record<string, unknown> = {};
      const history = await qualifyInstalledOwnerLinks({ stateRoot: recipe.stateRoot, uid: ledger.uid, bundle: signed.bundle,
        imageDigest: report.bundle.supervisorDigest, report: links });
      assert.equal(links.qualified, true); assert.equal(history.owners.length, precedingOwners.length + 1);
      assert.deepEqual(history.owners.slice(0, -1), precedingOwners);
      const successorOwner = history.owners.at(-1)!; assert.equal(successorOwner.state, 'active');
      assert.equal(successorOwner.ownerEpoch, precedingOwners.at(-1)!.ownerEpoch + 1);
      const successorProcess = parseJsonStrict((await readCas(successorOwner.processIdentityRef)).toString('utf8')) as Record<string, any>;
      assert.equal(successorProcess.identityDigest, successorOwner.processIdentityDigest);
      assert.equal(successorProcess.pid, Number(successor.MainPID));
      assert.equal(successorProcess.processStartToken, `linux-proc-start-ticks:${successorStart}`);
      effect.ownerLineage = { qualified: true, originalOwnerEpoch: originalOwner.ownerEpoch,
        originalProcessIdentityRef: originalOwner.processIdentityRef, terminalReason: 'graceful_release',
        transitionEvidenceRef: releasedOwner.transitionEvidenceRef, successorOwnerEpoch: successorOwner.ownerEpoch,
        ...(shutdownStartupOnly ? { intermediateStartupOwnerEpoch: precedingOwners[1]!.ownerEpoch,
          finalAcquisitionPredecessorOwnerEpoch: precedingOwners.at(-1)!.ownerEpoch } : {}),
        acquisitionEvidenceRef: successorOwner.acquisitionEvidenceRef, acquisitionKind: 'acquire_after_graceful_release' };
      shutdownClient = await persistentClient();
      let ready: Record<string, any>;
      for (;;) {
        ready = await publicRead(); assert(!providerFailure);
        assert(Date.now() < recoverBy, 'the actual effect successor did not reach its independently cancellable cut');
        if (shutdownReceivedToolOnly ? requestsReceived === 2 && ready.journal.length === 9 && ready.journal[8].phase === 'completed'
          : ready.snapshot.run.status === 'queued' && !ready.snapshot.run.activeWorkerLaunchId && !ready.snapshot.run.waitingReason) break;
        await delay(50);
      }
      const successorStatus = accepted(await shutdownClient.send({ protocolVersion: 1, method: 'supervisor.status' }), 'supervisor.status');
      assert.equal(successorStatus.health, 'ready'); assert.equal(successorStatus.supervisorInstanceId, successorOwner.supervisorInstanceId);
      const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, modelCharge = { ...zero, modelTokens: 36864 };
      const assertBudget = (actual: unknown, expected: unknown) => assert.equal(canonicalSha256(actual), canonicalSha256(expected));
      const settlement = async (prepared: Record<string, any>, terminal: Record<string, any>, consumed: Record<string, number>, before: Record<string, number>) => {
        const claim = ready.journal[prepared.seq]; assert.equal(claim.phase, 'dispatch_claimed');
        for (const field of ['runId', 'opId', 'opKind', 'attempt', 'leaseEpoch', 'requestRef', 'target']) {
          assert.equal(claim[field], prepared[field]); assert.equal(terminal[field], prepared[field]);
        }
        for (const field of ['dispatchId', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest'])
          assert.equal(terminal[field], claim[field]);
        assertBudget(claim.budgetDelta, zero);
        const value = parseJsonStrict((await readCas(terminal.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
        assert.equal(value.format, 'cliq-budget-settlement-v1'); assert.equal(value.settlementDigest, digestOmitting(value, 'settlementDigest'));
        assert.equal(value.runId, admitted.id); assert.equal(value.opId, prepared.opId); assert.equal(value.attempt, prepared.attempt);
        assert.equal(value.preparedJournalSeq, prepared.seq); assert.equal(value.terminalJournalSeq, terminal.seq);
        assert.equal(value.terminalPhase, terminal.phase); assert.equal(value.settledAt, terminal.timestamp);
        assertBudget(value.reserved, prepared.budgetDelta); assertBudget(value.released, prepared.budgetDelta);
        assertBudget(value.budgetReservedBefore, prepared.budgetDelta); assertBudget(value.budgetReservedAfter, zero);
        assertBudget(value.consumed, consumed); assertBudget(terminal.budgetDelta, consumed); assertBudget(value.budgetConsumedBefore, before);
        assertBudget(value.budgetConsumedAfter, Object.fromEntries(Object.keys(zero).map(key => [key, before[key]! + consumed[key]!])));
      };
      if (shutdownReceivedToolOnly) {
        assert.deepEqual(ready.journal.map((entry: any) => [entry.opKind, entry.phase, entry.attempt]),
          [['model', 'prepared', 0], ['model', 'dispatch_claimed', 0], ['model', 'completed', 0],
            ['tool', 'prepared', 0], ['tool', 'dispatch_claimed', 0], ['tool', 'completed', 0],
            ['model', 'prepared', 0], ['model', 'dispatch_claimed', 0], ['model', 'completed', 0]]);
        assert.deepEqual(ready.journal.slice(0, 5), beforeStop.journal);
        const [firstPrepared, firstClaim, firstCompleted, toolPrepared, toolClaim, toolCompleted, nextPrepared, nextClaim, nextCompleted] = ready.journal;
        assert.equal(firstClaim.supervisorInstanceId, originalOwner.supervisorInstanceId);
        assert.equal(toolClaim.supervisorInstanceId, originalOwner.supervisorInstanceId);
        assert.equal(firstClaim.stateOwnerEpoch, originalOwner.ownerEpoch); assert.equal(toolClaim.stateOwnerEpoch, originalOwner.ownerEpoch);
        if (nextClaim.supervisorInstanceId !== successorOwner.supervisorInstanceId) effect.observationToGateAdvanceObserved = true;
        assert.equal(nextClaim.supervisorInstanceId, successorOwner.supervisorInstanceId,
          'the second distinct model turn must belong to the actual successor, not an observation-to-gate advance');
        assert.equal(nextClaim.stateOwnerEpoch, successorOwner.ownerEpoch); assert.notEqual(nextClaim.opId, firstClaim.opId);
        assert.equal(nextClaim.leaseEpoch, ready.snapshot.run.leaseEpoch); assert.equal(ready.snapshot.run.status, 'running');
        assert(ready.snapshot.run.activeWorkerLaunchId); assert.notEqual(ready.snapshot.run.activeWorkerLaunchId, effect.originalSnapshotProgress.workerLaunchId);
        effect.successorWorker = inspectInstalledWorkerLease(recipe.stateRoot, { uid: ledger.uid, runId: admitted.id,
          launchId: ready.snapshot.run.activeWorkerLaunchId, leaseEpoch: nextClaim.leaseEpoch, runRevision: ready.snapshot.run.revision,
          supervisorInstanceId: successorOwner.supervisorInstanceId, deadlineAt: admitted.deadlineAt });
        assert.equal(toolCompleted.dispatchId, toolClaim.dispatchId); assert(toolCompleted.timestamp <= releasedOwner.releasedAt);
        const observation = parseJsonStrict((await readCas(toolCompleted.resultRef)).toString('utf8')) as Record<string, any>;
        assert.equal(observation.format, 'cliq-tool-observation-v1'); assert.equal(observation.outcome, 'executed');
        assert.equal(observation.observationDigest, digestOmitting(observation, 'observationDigest'));
        assert.equal(observation.runId, admitted.id); assert.equal(observation.opId, toolClaim.opId); assert.equal(observation.attempt, toolClaim.attempt);
        assert.equal(observation.dispatchId, toolClaim.dispatchId); assert.equal(observation.requestRef, toolClaim.requestRef);
        assert.equal(observation.grantRef, toolClaim.grantRef); assert.equal(observation.targetRef, toolClaim.target);
        assert(observation.observedAt <= releasedOwner.releasedAt);
        const checkpoints = ready.checkpoints.filter((value: any) => value.reason === 'auto' && value.journalSeq === toolCompleted.seq);
        assert.equal(checkpoints.length, 1); const checkpoint = checkpoints[0]; assert(checkpoint.createdAt <= releasedOwner.releasedAt);
        assert.equal(checkpoint.workspaceStateRef, observation.postEffect.workspaceStateRef);
        const snapshot = parseJsonStrict((await readCas(observation.postEffect.snapshotEvidenceRef)).toString('utf8')) as Record<string, any>;
        assert.equal(snapshot.purpose, 'sealed_to_checkpoint'); assert.equal(snapshot.evidenceDigest, digestOmitting(snapshot, 'evidenceDigest'));
        assert.equal(snapshot.generationRef, originalGenerationRef); assert.equal(snapshot.generationIdentityDigest, effect.originalSnapshotProgress.generationIdentityDigest);
        assert.equal(snapshot.checkpointId, checkpoint.id); assert.equal(snapshot.workspaceStateRef, checkpoint.workspaceStateRef);
        assert.equal(snapshot.descriptorRewalkComplete, true); assert.equal(snapshot.fileFsyncComplete, true); assert.equal(snapshot.directoryFsyncComplete, true);
        const state = parseJsonStrict((await readCas(checkpoint.workspaceStateRef)).toString('utf8')) as Record<string, any>;
        assert.equal(state.stateDigest, digestOmitting(state, 'stateDigest'));
        const entries = parseJsonStrict((await readCas(state.entriesRef)).toString('utf8')) as Record<string, any>;
        assert.equal(entries.treeDigest, canonicalSha256({ schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: entries.entries }));
        assert.deepEqual(entries.entries.map((value: any) => value.path), ['example.txt', 'payload.txt']);
        const unchanged = entries.entries[0]; assert.equal(unchanged.kind, 'file');
        assert.equal(unchanged.blobRef, sha256Bytes(Buffer.from(hostBefore))); assert.equal(unchanged.size, Buffer.byteLength(hostBefore));
        const file = entries.entries.find((value: any) => value.path === 'payload.txt');
        assert(file && file.kind === 'file'); assert.equal(file.size, fileBytes); assert.equal(file.blobRef, editedBlob);
        await verifyPayload(path.join(recipe.stateRoot, 'cas', editedBlob!), editedBlob!);
        const death = parseJsonStrict((await readCas(observation.postEffect.retirementEvidenceRef)).toString('utf8')) as Record<string, any>;
        const inspector = parseJsonStrict((await readCas(death.inspectorIdentityRef)).toString('utf8')) as Record<string, any>;
        assert.equal(inspector.stateOwnerEpoch, originalOwner.ownerEpoch); assert.equal(inspector.processIdentityRef, originalOwner.processIdentityRef);
        const toolCharge = { ...zero, toolCalls: 1 }, afterTool = { ...modelCharge, toolCalls: 1 };
        assertBudget(firstPrepared.budgetDelta, modelCharge); assertBudget(toolPrepared.budgetDelta, toolCharge); assertBudget(nextPrepared.budgetDelta, modelCharge);
        await settlement(firstPrepared, firstCompleted, modelCharge, zero); await settlement(toolPrepared, toolCompleted, toolCharge, modelCharge);
        await settlement(nextPrepared, nextCompleted, modelCharge, afterTool);
        assertBudget(ready.snapshot.run.budgetConsumed, { ...afterTool, modelTokens: 73728 });
        assert.equal(requestsReceived, 2); assert.equal(acceptedTcpConnections, 2); assert.equal(acceptedTlsConnections, 2);
        effect.originalExecutedTool = { qualified: true, originalClaimPreserved: true, resultRef: toolCompleted.resultRef,
          checkpointId: checkpoint.id, workspaceStateRef: checkpoint.workspaceStateRef, blobRef: editedBlob,
          originalInspectorMatched: true, originalOwnerCompletedBeforeGracefulRelease: true, toolClaims: 1, toolCallsCharged: 1,
          actualSuccessorContinuedNextModel: true };
      } else {
        assert.deepEqual(ready.journal.slice(0, 2), beforeStop.journal); assert.equal(ready.journal.length, 3);
        const [prepared, claim, unknown] = ready.journal; assert.equal(unknown.phase, 'unknown');
        for (const key of ['opId', 'attempt', 'dispatchId', 'requestRef', 'target', 'supervisorInstanceId', 'stateOwnerEpoch', 'brokerFenceTokenDigest'])
          assert.equal(unknown[key], claim[key]);
        assert.equal(unknown.resultRef, undefined); assert.equal(unknown.errorRef, undefined); assert(unknown.timestamp <= releasedOwner.releasedAt);
        const ambiguity = parseJsonStrict((await readCas(unknown.evidenceRef)).toString('utf8')) as Record<string, any>;
        assert.equal(ambiguity.format, 'cliq-invocation-ambiguity-evidence-v1'); assert.equal(ambiguity.ambiguityKind, 'broker_channel_lost_after_claim');
        assert.equal(ambiguity.failureCode, 'response_stream_interrupted'); assert.equal(ambiguity.dispatchId, claim.dispatchId);
        assert.equal(ambiguity.claimingStateOwnerEpoch, originalOwner.ownerEpoch); assert.equal(ambiguity.claimingSupervisorInstanceId, originalOwner.supervisorInstanceId);
        assert.equal(ambiguity.dispatchJournalSeq, claim.seq); assert.equal(ambiguity.brokerFenceTokenDigest, claim.brokerFenceTokenDigest);
        assert.equal(ambiguity.evidenceDigest, unknown.evidenceDigest); assert.equal(ambiguity.evidenceDigest, digestOmitting(ambiguity, 'evidenceDigest'));
        assert.equal(ambiguity.runId, admitted.id); assert.equal(ambiguity.opId, claim.opId); assert.equal(ambiguity.attempt, claim.attempt);
        assert.equal(ambiguity.operationRequestRef, prepared.requestRef); assert.equal(ambiguity.operationTargetRef, prepared.target);
        assert.equal(ambiguity.operationTargetDigest, registration.registrationDigest); assert.equal(ambiguity.observedAt, unknown.timestamp);
        assert.equal(ambiguity.durableTerminalResultAbsent, true);
        const inspector = parseJsonStrict((await readCas(ambiguity.inspectorIdentityRef)).toString('utf8')) as Record<string, any>;
        assert.equal(inspector.stateOwnerEpoch, originalOwner.ownerEpoch); assert.equal(inspector.processIdentityRef, originalOwner.processIdentityRef);
        assertBudget(prepared.budgetDelta, modelCharge); await settlement(prepared, unknown, modelCharge, zero);
        assertBudget(ready.snapshot.run.budgetConsumed, modelCharge);
        const events = accepted(await shutdownClient.send({ protocolVersion: 1, method: 'run.attach', runId: admitted.id, afterEventSeq: 0 }), 'run.attach');
        assert.equal(events.earliestRetainedEventSeq, 1); assert.equal(events.nextEventSeq, events.highWaterEventSeq);
        assert.equal(events.events.length, events.highWaterEventSeq);
        let anchor: Record<string, any> | undefined;
        for (let index = 0; index < events.events.length; index++) {
          const event = events.events[index]; assert.equal(event.eventSeq, index + 1);
          if (event.kind !== 'state_changed' || event.waitingReason !== 'reconciliation' || !event.waitingOnRef) continue;
          const wait = parseJsonStrict((await readCas(event.waitingOnRef)).toString('utf8')) as Record<string, any>;
          if (wait.subject.kind !== 'worker_death' || wait.probeState.phase !== 'automatic_in_flight') continue;
          assert.equal(wait.subject.oldWorkerLaunchId, beforeStop.snapshot.run.activeWorkerLaunchId);
          assert.equal(wait.probeState.dispatch.owningSupervisorInstanceId, successorOwner.supervisorInstanceId);
          anchor = parseJsonStrict((await readCas(wait.probeState.dispatch.inspectionTargetDigest)).toString('utf8')) as Record<string, any>;
          assert.equal(anchor.phase, 'fenced_reconciling'); assert.equal(anchor.runId, admitted.id);
          assert.equal(anchor.activeWorkerLaunchId, beforeStop.snapshot.run.activeWorkerLaunchId);
          assert.equal(anchor.leaseEpoch, beforeStop.snapshot.run.leaseEpoch);
          assert(Number.isSafeInteger(anchor.fencedJournalSeq) && anchor.fencedJournalSeq >= unknown.seq);
          assert(anchor.updatedAt <= releasedOwner.releasedAt);
          const initialWait = parseJsonStrict((await readCas(anchor.waitingSubjectRef)).toString('utf8')) as Record<string, any>;
          assert.equal(initialWait.subject.oldWorkerLaunchId, beforeStop.snapshot.run.activeWorkerLaunchId);
          assert.equal(initialWait.probeState.phase, 'automatic_pending'); assert.equal(initialWait.probeState.automaticProbeCount, 0);
          assert(initialWait.createdAt <= releasedOwner.releasedAt); break;
        }
        assert(anchor, 'the actual successor inspection must retain the original post-settlement worker fence');
        effect.originalUnknown = { qualified: true, evidenceRef: unknown.evidenceRef, settlementRef: unknown.budgetSettlementRef,
          originalClaimPreserved: true, fullyCharged: true, settledBeforeOriginalOwnerRelease: true,
          originalFencedJournalSeq: anchor.fencedJournalSeq, unknownJournalSeq: unknown.seq, settledBeforeDurableWorkerFence: true };
      }
      assertBudget(ready.snapshot.run.budgetReserved, zero);
      mark('effect_successor_public_cancel_once');
      const terminalBy = Date.now() + 30000;
      let cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000135',
        runId: admitted.id, expectedRevision: ready.snapshot.run.revision });
      let cancelReply = await shutdownClient.send(cancel), conflicts = 0;
      while (!cancelReply.ok) {
        assert.equal(cancelReply.error?.code, 'REVISION_CONFLICT'); assert.equal(cancelReply.error?.retryable, true);
        assert.equal(cancelReply.error?.messageCode, 'control.revision_conflict'); assert(++conflicts <= 8 && Date.now() < terminalBy);
        const current = await publicRead(); cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: cancel.requestId,
          runId: admitted.id, expectedRevision: current.snapshot.run.revision }); cancelReply = await shutdownClient.send(cancel);
      }
      accepted(cancelReply, 'run.cancel'); let terminal = await publicRead();
      while (terminal.snapshot.run.status !== 'cancelled') {
        assert(Date.now() < terminalBy, 'the effect successor did not complete genuine terminal cancellation');
        await delay(50); terminal = await publicRead();
      }
      assert.equal(terminal.snapshot.run.terminalReason, 'cancelled_by_user'); assert.equal(terminal.snapshot.run.activeWorkerLaunchId, undefined);
      assert.equal(terminal.snapshot.run.resultRef, undefined); assert.deepEqual(terminal.journal, ready.journal);
      assertBudget(terminal.snapshot.run.budgetConsumed, ready.snapshot.run.budgetConsumed); assertBudget(terminal.snapshot.run.budgetReserved, zero);
      if (shutdownPendingModelOnly) {
        const [prepared, claim, unknown] = ready.journal;
        const detail = parseJsonStrict((await readCas(terminal.snapshot.run.terminalDetailRef)).toString('utf8')) as Record<string, any>;
        assert.equal(detail.abandonedRetryInvocations.length, 1); const abandoned = detail.abandonedRetryInvocations[0];
        assert.equal(abandoned.opId, claim.opId); assert.equal(abandoned.unknownJournalSeq, unknown.seq);
        assert.equal(abandoned.budgetSettlementRef, unknown.budgetSettlementRef);
        const closure = decodeBrokerProcessDomainDeathDispatchClosure(parseJsonStrict((await readCas(abandoned.dispatchFenceOrDeathEvidenceRef)).toString('utf8')));
        assert.equal(closure.runId, admitted.id); assert.equal(closure.opId, claim.opId); assert.equal(closure.dispatchId, claim.dispatchId);
        assert.equal(closure.unknownJournalSeq, unknown.seq);
        const death = decodeBrokerProcessDomainDeath(parseJsonStrict((await readCas(closure.closure.brokerProcessDeathEvidenceRef)).toString('utf8')));
        assert.equal(death.evidenceDigest, closure.closure.brokerProcessDeathEvidenceDigest);
        assert.equal(death.claimingStateOwnerEpoch, originalOwner.ownerEpoch); assert.equal(death.claimingSupervisorInstanceId, originalOwner.supervisorInstanceId);
        assert.equal(death.claimingProcessIdentityRef, originalOwner.processIdentityRef); assert.equal(death.operationRequestRef, prepared.requestRef);
        assert.equal(death.brokerFenceTokenDigest, claim.brokerFenceTokenDigest); assert.equal(death.inspectorStateOwnerEpoch, successorOwner.ownerEpoch);
        assert(death.inspectorStateOwnerEpoch > death.claimingStateOwnerEpoch);
        assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1);
        effect.successorBrokerProcessDomainDeath = { qualified: true, originalClaimAndProcessMatched: true,
          dispatchClosureRef: abandoned.dispatchFenceOrDeathEvidenceRef, strictlyNewerInspector: true, noRedispatch: true };
      }
      const sessionCut = accepted(await shutdownClient.send({ protocolVersion: 1, method: 'session.get', sessionId: session.id,
        afterItemSeq: session.latestItemSeq }), 'session.get');
      assert.equal(sessionCut.items.length, 1); assert.equal(sessionCut.items[0].kind, 'run_terminal');
      const publication = parseJsonStrict((await readCas(sessionCut.items[0].payloadRef)).toString('utf8')) as Record<string, any>;
      assert.equal(publication.runId, admitted.id); assert.equal(publication.status, 'cancelled');
      assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + 1);
      assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + 1);
      assert.deepEqual(await shutdownClient.send(cancel), cancelReply); assert.deepEqual(exchange([submit])[0], submitReply);
      assert.deepEqual(exchange([sessionRequest])[0], sessionReply); assert.deepEqual(await publicRead(), terminal);
      if (payloadBefore) await verifyPayload(payloadPath, originalBlob!, payloadBefore);
      for (const field of imageFields) assert.equal((await lstat(source, { bigint: true }))[field], sourceBefore[field]);
      assert.equal(await readFile(source, 'utf8'), hostBefore); assert(!providerFailure);
      const expectedPosts = shutdownReceivedToolOnly ? 2 : 1;
      assert.equal(requestsReceived, expectedPosts); assert.equal(acceptedTcpConnections, expectedPosts); assert.equal(acceptedTlsConnections, expectedPosts);
      await shutdownClient.close(); shutdownClient = undefined;
      effect.qualified = true; effect.gracefulExitZero = true; effect.originalSourceUnchanged = true;
      effect.sessionPublishedOnce = true; effect.publicAdmissionAndCancelReplayPreserved = true;
    } else if (shutdownPreparationOnly) {
      mark('owned_source_before_scheduler_preparation_shutdown');
      const payload = path.join(recipe.workspace, 'payload'), fileCount = 1000;
      const bytes = Buffer.alloc(65536, 0x5a), blobRef = sha256Bytes(bytes);
      await mkdir(payload, { mode: 0o755 }); await chown(payload, ledger.uid, ledger.gid);
      const sourceFiles = new Map<string, BigIntStats>();
      for (let offset = 0; offset < fileCount; offset += 32) {
        await Promise.all(Array.from({ length: Math.min(32, fileCount - offset) }, async (_, index) => {
          const relative = `payload/entry-${String(offset + index).padStart(4, '0')}.txt`, filename = path.join(recipe.workspace, relative);
          await writeFile(filename, bytes, { flag: 'wx', mode: 0o644 }); await chown(filename, ledger.uid, ledger.gid);
          const info = await lstat(filename, { bigint: true });
          assert(info.isFile() && info.nlink === 1n && info.uid === BigInt(ledger.uid) && info.size === BigInt(bytes.length));
          sourceFiles.set(relative, info);
        }));
      }
      const originalPid = Number(supervisorBefore.MainPID), originalStart = await fixtureProcess(originalPid, ledger.uid);
      const selectedImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
      const signedImage = await lstat(selectedImage, { bigint: true });
      const assertOriginalSupervisor = async () => {
        assert.equal(await fixtureProcess(originalPid, ledger.uid), originalStart);
        assert.equal(await readlink(`/proc/${originalPid}/exe`), selectedImage);
        const actual = await stat(`/proc/${originalPid}/exe`, { bigint: true });
        for (const key of imageFields) assert.equal(actual[key], signedImage[key]);
      };
      const originalOwners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      assert.equal(originalOwners.length, 1);
      const originalOwner = originalOwners[0]!; assert.equal(originalOwner.state, 'active');
      const originalStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.equal(originalStatus.health, 'ready'); assert.equal(originalStatus.supervisorInstanceId, originalOwner.supervisorInstanceId);
      shutdownClient = await persistentClient();
      const submit = request({ protocolVersion: 1, method: 'run.submit', requestId: '019a0012-0000-7000-8000-000000000132',
        admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
        workspacePath: recipe.workspace, objective: 'Retain one candidate without using a tool after ordinary preparation.',
        model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: registration.endpointRegistrationId },
          modelCredentialGrantIds: [enrollment.credentialGrantId] }, policyMode: 'accept-edits',
        budgets: { wallTimeMs: 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000,
          repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
        verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
        registeredMcpServerIds: [], skillIds: [], allowUnverified: true });
      const submitReply = exchange([submit])[0]!, admitted = accepted(submitReply, 'run.submit').snapshot.run;
      assert.equal(admitted.status, 'queued'); assert.equal(admitted.revision, 1);
      report.acceptedRun = { id: admitted.id, sessionId: admitted.sessionId, specRef: admitted.specRef,
        initialCheckpointId: admitted.latestCheckpointId };
      const spec = parseJsonStrict((await readCas(admitted.specRef)).toString('utf8')) as Record<string, any>;
      const manifest = parseJsonStrict((await readCas(spec.baseWorkspaceManifestRef)).toString('utf8')) as Record<string, any>;
      const frozen = parseJsonStrict((await readCas(manifest.entriesRef)).toString('utf8')) as Record<string, any>;
      assert.equal(frozen.entries.length, fileCount + 2);
      assert.deepEqual(frozen.entries.map((entry: any) => entry.path).sort(), ['example.txt', 'payload', ...sourceFiles.keys()].sort());
      for (const entry of frozen.entries) if (sourceFiles.has(entry.path)) {
        assert.equal(entry.kind, 'file'); assert.equal(entry.blobRef, blobRef); assert.equal(entry.size, bytes.length); assert.equal(entry.mode, 0o644);
      }
      const prefix = path.join(recipe.stateRoot, 'runs', admitted.id, 'generations') + '/';
      type WriteObservation = { generationId: string; generationPath: string; deviceId: string; directoryFileId: string; relative: string };
      const heldGenerationWrite = async (same?: WriteObservation): Promise<WriteObservation | undefined> => {
        await assertOriginalSupervisor();
        const descriptors = await readdir(`/proc/${originalPid}/fd`);
        assert(descriptors.length <= 4096, 'actual Supervisor descriptor inventory exceeded its fixed observation bound');
        for (const descriptor of descriptors) {
          assert.match(descriptor, /^(?:0|[1-9][0-9]*)$/u);
          try {
            const fd = `/proc/${originalPid}/fd/${descriptor}`, target = await readlink(fd);
            if (!target.startsWith(prefix)) continue;
            const [generationId, ...parts] = target.slice(prefix.length).split('/'), relative = parts.join('/');
            if (!generationId || !/^[A-Za-z0-9_-]{43}$/u.test(generationId) || !sourceFiles.has(relative)) continue;
            if (same && generationId !== same.generationId) continue;
            const info = await readFile(`/proc/${originalPid}/fdinfo/${descriptor}`, 'utf8'); assert(info.length <= 65536);
            const flags = info.match(/^flags:\s+([0-7]+)$/mu); assert(flags);
            if ((Number.parseInt(flags[1]!, 8) & 3) !== constants.O_WRONLY) continue;
            const generationPath = path.join(prefix, generationId);
            for (const directory of [path.join(recipe.stateRoot, 'runs'), path.join(recipe.stateRoot, 'runs', admitted.id),
              prefix.slice(0, -1), generationPath, path.join(generationPath, 'payload')]) {
              const actual = await lstat(directory, { bigint: true });
              assert(actual.isDirectory() && !actual.isSymbolicLink() && actual.uid === BigInt(ledger.uid));
              assert.equal(actual.mode & 0o7777n, directory.endsWith('/payload') ? 0o755n : 0o700n);
            }
            const directory = await lstat(generationPath, { bigint: true }), named = await lstat(target, { bigint: true });
            const actual = await stat(fd, { bigint: true });
            assert(named.isFile() && !named.isSymbolicLink() && named.nlink === 1n && named.uid === BigInt(ledger.uid));
            if ((['dev', 'ino', 'uid', 'gid', 'nlink'] as const).some(key => actual[key] !== named[key])) continue;
            assert(actual.isFile() && actual.size >= 0n && actual.size <= BigInt(bytes.length));
            assert.equal(actual.mode & 0o7777n, 0o644n);
            assert.equal(actual.dev, directory.dev);
            if (same) { assert.equal(directory.dev.toString(), same.deviceId); assert.equal(directory.ino.toString(), same.directoryFileId); }
            if (await readlink(fd) !== target) continue;
            const confirmed = await lstat(generationPath, { bigint: true });
            assert.equal(confirmed.dev, directory.dev); assert.equal(confirmed.ino, directory.ino);
            await assertOriginalSupervisor();
            return { generationId, generationPath, deviceId: directory.dev.toString(), directoryFileId: directory.ino.toString(), relative };
          } catch (error) {
            if (!['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
          }
        }
        await assertOriginalSupervisor(); return undefined;
      };
      const publicRead = async () => accepted(await shutdownClient!.send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }), 'run.get');
      const preparingCut = (cut: Record<string, any>) => {
        const run = cut.snapshot.run;
        assert.equal(run.id, admitted.id); assert.equal(run.status, 'queued'); assert.equal(run.activeWorkerLaunchId, undefined);
        assert.equal(run.leaseEpoch, 0); assert.equal(run.cancelRequested, false); assert.equal(run.stopIntentRef, undefined);
        assert.equal(run.specRef, admitted.specRef); assert.equal(run.latestCheckpointId, admitted.latestCheckpointId);
        assert.equal(cut.highWaterJournalSeq, 0); assert.deepEqual(cut.journal, []);
      };
      let observed: WriteObservation | undefined;
      const contract = command('/usr/bin/systemctl', ['--user', 'show', services.supervisorUnit,
        '--property=TimeoutStopUSec,KillSignal,FinalKillSignal,SendSIGKILL', '--no-pager']);
      assert.equal(contract.status, 0);
      const stopPolicy = Object.fromEntries(contract.stdout.trim().split('\n').map(line => line.split('=')));
      assert.equal(stopPolicy.TimeoutStopUSec, '2s'); assert.equal(stopPolicy.KillSignal, '15');
      assert.equal(stopPolicy.FinalKillSignal, '9'); assert.equal(stopPolicy.SendSIGKILL, 'yes');
      // Retain unit history before observing the short-lived producer, not
      // after it. Starting this independent observer must not consume the
      // actual copy window between our positive cut and the unchanged stop.
      await withRetainedUnitHistory([services.supervisorUnit, services.keeperUnit], async () => {
        mark('actual_scheduler_generation_write_bracketed_by_public_queued_cut');
        const observeBy = Date.now() + 30000;
        while (!observed) {
          assert(Date.now() < observeBy, 'the actual installed scheduler preparation write was not positively observed');
          const before = await heldGenerationWrite();
          if (!before) { await delay(1); continue; }
          preparingCut(await publicRead());
          const bracketed = await heldGenerationWrite(before);
          if (!bracketed) continue;
          assert.equal(requestsReceived, 0); assert(!providerFailure);
          report.shutdownPreparation = { qualified: false, diagnosticOnly: true, sourceFiles: fileCount, bytesPerFile: bytes.length,
            distinctSourceInodes: new Set([...sourceFiles.values()].map(info => `${info.dev}:${info.ino}`)).size,
            deduplicatedSourceBlobRef: blobRef, originalSupervisorProcessMatched: true, originalWritableGenerationMatched: true,
            publicQueuedCutBracketed: true, noActiveWorkerAtObservedPublicCut: true, noJournalAtObservedPublicCut: true,
            generationId: bracketed.generationId, generationDeviceId: bracketed.deviceId, generationDirectoryFileId: bracketed.directoryFileId,
            controllerRetirementQualified: false, receivedToolQualified: false, exactPreparingGateCutQualified: false,
            standardStopTimeoutMs: 2000 };
          assert.equal(report.shutdownPreparation.distinctSourceInodes, fileCount);
          mark('ordinary_systemd_sigterm_during_scheduler_generation_copy');
          // File writers rotate between ordinary entries. Keep all three
          // positive observations in the same bounded sampling attempt;
          // absence between writers is not a positive stop cut. The final
          // real recheck still immediately precedes the unchanged stop.
          observed = await heldGenerationWrite(bracketed);
        }
        assert(observed, 'a genuine same-generation writer must still be observed immediately before ordinary SIGTERM');
        const stopped = command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit]), exit = show(services.supervisorUnit);
        report.shutdownPreparation.serviceExit = projectInstalledServiceExit(exit);
        await shutdownClient!.close();
        assert.equal(stopped.status, 0, 'ordinary two-second scheduler stop must not require forced retirement');
        assert.equal(exit.ActiveState, 'inactive'); assert.equal(exit.MainPID, '0');
        assert.equal(exit.Result, 'success'); assert.equal(exit.ExecMainCode, '1'); assert.equal(exit.ExecMainStatus, '0');
        await assert.rejects(lstat(`/proc/${originalPid}`), { code: 'ENOENT' });
      });
      assert(observed, 'ordinary shutdown must retain its positively observed generation');
      const releasedOwners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      assert.equal(releasedOwners.length, 1);
      const releasedOwner = releasedOwners[0]!; assert.equal(releasedOwner.state, 'terminal');
      if (releasedOwner.state !== 'terminal') throw new Error('scheduler shutdown did not publish its terminal StateOwner');
      assert.equal(releasedOwner.terminalReason, 'graceful_release');
      for (const key of ['ownerEpoch', 'supervisorInstanceId', 'processIdentityRef', 'processIdentityDigest',
        'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const)
        assert.equal(releasedOwner[key], originalOwner[key]);
      assert.equal(show(services.keeperUnit).MainPID, keeperBefore.MainPID);
      assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
      // Read only immutable genuine publications, never create a private SQL
      // owner or infer retirement from a path/closed boolean. This inspection
      // itself is data; the successor's real lifecycle must still validate it.
      const publications = new Map<string, Record<string, any>>();
      const casNames = await readdir(path.join(recipe.stateRoot, 'cas')); assert(casNames.length <= 4096);
      for (const ref of casNames) {
        if (!/^[0-9a-f]{64}$/u.test(ref)) continue;
        const content = await readCas(ref);
        if (content[0] !== 0x7b) continue;
        const value = parseJsonStrict(content.toString('utf8')) as Record<string, any>;
        assert.deepEqual(canonicalJsonBytes(value), content); publications.set(ref, value);
      }
      const identities = [...publications].filter(([, value]) => value.format === 'cliq-workspace-generation-identity-v1' &&
        value.runId === admitted.id && value.generationId === observed!.generationId);
      assert.equal(identities.length, 1);
      const [generationRef, generationIdentity] = identities[0]!;
      assert.equal(generationIdentity.identityDigest, digestOmitting(generationIdentity, 'identityDigest'));
      assert.equal(generationIdentity.sourceCheckpointId, admitted.latestCheckpointId);
      assert.equal(generationIdentity.locator.canonicalRootRelativePath, path.relative(recipe.stateRoot, observed.generationPath));
      assert.equal(generationIdentity.locator.deviceId, observed.deviceId);
      assert.equal(generationIdentity.locator.directoryFileId, observed.directoryFileId);
      const retired = [...publications].filter(([, value]) => value.format === 'cliq-worker-preparation-retirement-evidence-v1' &&
        value.kind === 'born' && value.sourceGeneration?.generationRef === generationRef);
      assert(retired.length <= 1);
      if (retired.length) {
        const [retirementRef, proof] = retired[0]!;
        assert.equal(proof.evidenceDigest, digestOmitting(proof, 'evidenceDigest'));
        assert.equal(proof.launch.phase, 'preparing'); assert.equal(proof.launch.runId, admitted.id);
        assert.equal(proof.launch.supervisorInstanceId, originalOwner.supervisorInstanceId);
        assert.equal(proof.launch.preparation.stateOwnerEpoch, originalOwner.ownerEpoch);
        assert.equal(proof.launch.preparation.generationId, observed.generationId);
        assert.equal(proof.launch.preparation.generation.generationRef, generationRef);
        assert.equal(proof.launch.preparation.generation.generationIdentityDigest, generationIdentity.identityDigest);
        const inspector = publications.get(proof.inspectorIdentityRef); assert(inspector);
        assert.equal(inspector.identityDigest, digestOmitting(inspector, 'identityDigest'));
        assert.equal(inspector.identityDigest, proof.inspectorIdentityDigest);
        assert.equal(inspector.stateOwnerEpoch, originalOwner.ownerEpoch);
        assert.equal(inspector.processIdentityRef, originalOwner.processIdentityRef);
        assert.equal(inspector.processIdentityDigest, originalOwner.processIdentityDigest);
        const quarantine = [...publications].filter(([, value]) => value.format === 'cliq-workspace-generation-quarantine-evidence-v1' &&
          value.generationRef === generationRef && value.preparationRetirementEvidenceRef === retirementRef);
        assert.equal(quarantine.length, 1);
        const receipt = quarantine[0]![1]; assert.equal(receipt.evidenceDigest, digestOmitting(receipt, 'evidenceDigest'));
        assert.equal(receipt.reason, 'preparation_retired'); assert.equal(receipt.observedState.kind, 'unverified_preparation');
        assert.equal(receipt.preparationRetirementEvidenceDigest, proof.evidenceDigest);
        assert.equal(receipt.quarantineDeviceId, observed.deviceId); assert.equal(receipt.quarantineFileId, observed.directoryFileId);
        const archive = path.join(recipe.stateRoot, receipt.quarantineCanonicalRootRelativePath);
        assert.equal(path.dirname(archive), path.join(recipe.stateRoot, 'quarantine/workspace-generations'));
        const physical = await lstat(archive, { bigint: true });
        assert(physical.isDirectory() && !physical.isSymbolicLink());
        assert.equal(physical.dev.toString(), observed.deviceId); assert.equal(physical.ino.toString(), observed.directoryFileId);
        await assert.rejects(lstat(observed.generationPath), { code: 'ENOENT' });
        report.shutdownPreparation.originalPreparationRetirement = { qualified: true, retirementRef,
          retirementDigest: proof.evidenceDigest, generationRef, quarantineRef: quarantine[0]![0],
          sourcePhase: proof.sourceGeneration.phase, originalInspectorMatched: true, samePhysicalDirectoryQuarantined: true };
      } else {
        // SIGTERM follows asynchronous observations. Promotion can legitimately
        // win before the private gate; do not manufacture a preparation-only
        // failure if the complete ordinary drain and successor graph are valid.
        report.shutdownPreparation.originalPreparationRetirement = { qualified: false,
          observationToGatePromotionNotExcluded: true };
      }
      mark('scheduler_shutdown_actual_successor_cancel_and_history');
      assert.equal(command('/usr/bin/systemctl', ['--user', 'start', services.supervisorUnit]).status, 0);
      const successor = show(services.supervisorUnit), successorBy = Date.now() + 30000;
      assert.notEqual(successor.MainPID, supervisorBefore.MainPID); assert.notEqual(successor.InvocationID, supervisorBefore.InvocationID);
      await selectedSupervisor(services.supervisorUnit, successor, selectedImage, successorBy);
      const successorStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.equal(successorStatus.health, 'ready'); assert.notEqual(successorStatus.supervisorInstanceId, originalStatus.supervisorInstanceId);
      const links: Record<string, unknown> = {};
      const history = await qualifyInstalledOwnerLinks({ stateRoot: recipe.stateRoot, uid: ledger.uid, bundle: signed.bundle,
        imageDigest: report.bundle.supervisorDigest, report: links });
      assert.equal(links.qualified, true); assert.equal(history.owners.length, 2); assert.deepEqual(history.owners[0], releasedOwner);
      const successorOwner = history.owners[1]!; assert.equal(successorOwner.state, 'active');
      assert.equal(successorOwner.supervisorInstanceId, successorStatus.supervisorInstanceId);
      assert.equal(successorOwner.ownerEpoch, originalOwner.ownerEpoch + 1);
      report.shutdownPreparation.ownerLineage = { qualified: true, terminalReason: 'graceful_release',
        originalOwnerEpoch: originalOwner.ownerEpoch, originalProcessIdentityRef: originalOwner.processIdentityRef,
        terminalRowDigest: releasedOwner.rowDigest, transitionEvidenceRef: releasedOwner.transitionEvidenceRef,
        transitionEvidenceDigest: releasedOwner.transitionEvidenceDigest, successorOwnerEpoch: successorOwner.ownerEpoch,
        acquisitionKind: 'acquire_after_graceful_release', acquisitionEvidenceRef: successorOwner.acquisitionEvidenceRef,
        acquisitionEvidenceDigest: successorOwner.acquisitionEvidenceDigest, sameStateLock: true, sameSignedRuntime: true };
      assert.deepEqual(exchange([submit])[0], submitReply); assert.deepEqual(exchange([sessionRequest])[0], sessionReply);
      shutdownClient = await persistentClient();
      let beforeCancel = await publicRead();
      assert.equal(beforeCancel.snapshot.run.specRef, admitted.specRef);
      let cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000133',
        runId: admitted.id, expectedRevision: beforeCancel.snapshot.run.revision });
      const terminalBy = Date.now() + 30000;
      let cancelReply = await shutdownClient.send(cancel), revisionConflicts = 0;
      while (!cancelReply.ok) {
        // Only a positively received closed revision refusal permits a new
        // cancellation cut. Transport failures are never retried, and neither
        // this loop nor its counter grants a productive dispatch retry.
        assert.equal(cancelReply.error?.code, 'REVISION_CONFLICT'); assert.equal(cancelReply.error?.retryable, true);
        assert.equal(cancelReply.error?.messageCode, 'control.revision_conflict');
        assert(++revisionConflicts <= 8 && Date.now() < terminalBy);
        beforeCancel = await publicRead(); assert.equal(beforeCancel.snapshot.run.specRef, admitted.specRef);
        cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000133',
          runId: admitted.id, expectedRevision: beforeCancel.snapshot.run.revision });
        cancelReply = await shutdownClient.send(cancel);
      }
      accepted(cancelReply, 'run.cancel');
      let terminal = await publicRead();
      while (terminal.snapshot.run.status !== 'cancelled') {
        assert(Date.now() < terminalBy, 'the actual successor could not complete the original Run cancellation/retirement graph');
        await delay(50); terminal = await publicRead();
      }
      const run = terminal.snapshot.run;
      assert.equal(run.terminalReason, 'cancelled_by_user'); assert.equal(run.activeWorkerLaunchId, undefined);
      assert.equal(run.resultRef, undefined); assert.equal(run.specRef, admitted.specRef);
      report.shutdownPreparation.modelClaimHistory = await inspectShutdownModelClaims(terminal);
      assert(requestsReceived <= 1 && acceptedTcpConnections <= 1 && acceptedTlsConnections <= 1); assert(!providerFailure);
      const sessionCut = accepted(await shutdownClient.send({ protocolVersion: 1, method: 'session.get', sessionId: session.id,
        afterItemSeq: session.latestItemSeq }), 'session.get');
      assert.equal(sessionCut.items.length, 1); assert.equal(sessionCut.items[0].kind, 'run_terminal');
      const publication = parseJsonStrict((await readCas(sessionCut.items[0].payloadRef)).toString('utf8')) as Record<string, any>;
      assert.equal(publication.runId, admitted.id); assert.equal(publication.status, 'cancelled');
      assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + 1);
      assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + 1);
      assert.deepEqual(await shutdownClient.send(cancel), cancelReply); assert.deepEqual(exchange([submit])[0], submitReply);
      assert.deepEqual(await publicRead(), terminal);
      for (const [relative, before] of sourceFiles) {
        const held = await open(path.join(recipe.workspace, relative), constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const after = await held.stat({ bigint: true });
          for (const key of imageFields) assert.equal(after[key], before[key]);
          assert.equal(sha256Bytes(await held.readFile()), blobRef);
          for (const key of imageFields) assert.equal((await held.stat({ bigint: true }))[key], before[key]);
        } finally { await held.close(); }
      }
      for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      await shutdownClient.close();
      report.shutdownPreparation = { ...report.shutdownPreparation, qualified: true, gracefulExitZero: true,
        acceptedAdmissionReplayPreserved: true, genuineSuccessorPublicOwner: true, sameKeeper: true,
        originalSessionCreateResponsePreserved: true, successorCancellationTerminal: true, sessionPublishedOnce: true,
        noDuplicateProductiveClaim: true, cancelRevisionConflicts: revisionConflicts,
        immutableTerminalPublicCutPreserved: true, sourceUnchanged: true, fullI1Qualified: false };
    } else if (shutdownAdmissionOnly || shutdownSessionOnly) {
      mark(shutdownSessionOnly ? 'owned_trust_inventory_before_shutdown_session' : 'owned_instruction_inventory_before_shutdown_admission');
      const inventory = shutdownSessionOnly ? path.dirname(trustDirectory) : path.join(recipe.workspace, 'shutdown-instructions');
      const instruction = shutdownSessionOnly ? trustPath : path.join(inventory, 'AGENTS.md');
      const instructionBytes = shutdownSessionOnly ? await readFile(trustPath) : Buffer.from('Ordinary shutdown qualification guidance.\n');
      if (!shutdownSessionOnly) {
        await mkdir(inventory, { mode: 0o700 }); await chown(inventory, ledger.uid, ledger.gid);
        await writeFile(instruction, instructionBytes, { flag: 'wx', mode: 0o644 }); await chown(instruction, ledger.uid, ledger.gid);
      }
      const seeds = [path.join(inventory, 'ordinary-a.txt'), path.join(inventory, 'ordinary-b.txt')];
      for (const seed of seeds) {
        await writeFile(seed, 'ordinary excluded metadata\n', { flag: 'wx', mode: 0o644 }); await chown(seed, ledger.uid, ledger.gid);
      }
      // Ordinary metadata only: never a blocked special file, linked AGENTS,
      // invalid scan bound or a production pause. Session Trust enumerates
      // its actual controlled-home directory; Run source prunes the ordinary
      // subtree, but independent instruction capture must still enumerate it.
      const metadataEntries = 80_000;
      for (let offset = 0; offset < metadataEntries; offset += 64) {
        await Promise.all(Array.from({ length: Math.min(64, metadataEntries - offset) }, (_, index) => {
          const ordinal = offset + index;
          return link(seeds[ordinal % seeds.length]!, path.join(inventory, `entry-${String(ordinal).padStart(5, '0')}.txt`));
        }));
      }
      const instructionBefore = await lstat(instruction, { bigint: true });
      assert(instructionBefore.isFile() && instructionBefore.nlink === 1n && instructionBefore.uid === BigInt(ledger.uid));
      assert.equal(instructionBefore.size, BigInt(instructionBytes.length));
      const inventoryBefore = await lstat(inventory, { bigint: true });
      assert(inventoryBefore.isDirectory() && !inventoryBefore.isSymbolicLink() && inventoryBefore.uid === BigInt(ledger.uid));
      assert.equal(inventoryBefore.mode & 0o7777n, 0o700n);
      const originalPid = Number(supervisorBefore.MainPID), originalStart = await fixtureProcess(originalPid, ledger.uid);
      const selectedImage = path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor');
      const signedImage = await lstat(selectedImage, { bigint: true });
      const assertOriginalSupervisor = async () => {
        assert.equal(await fixtureProcess(originalPid, ledger.uid), originalStart);
        assert.equal(await readlink(`/proc/${originalPid}/exe`), selectedImage);
        const actual = await stat(`/proc/${originalPid}/exe`, { bigint: true });
        for (const key of imageFields) assert.equal(actual[key], signedImage[key]);
      };
      type AdmissionResource = { descriptor: string; position?: string };
      const resourcePath = shutdownSessionOnly ? inventory : instruction;
      const resourceBefore = shutdownSessionOnly ? inventoryBefore : instructionBefore;
      const heldAdmissionResource = async (only?: AdmissionResource): Promise<AdmissionResource | undefined> => {
        await assertOriginalSupervisor();
        const descriptors = only ? [only.descriptor] : await readdir(`/proc/${originalPid}/fd`);
        assert(descriptors.length <= 4096, 'actual Supervisor descriptor inventory exceeded its fixed observation bound');
        for (const descriptor of descriptors) {
          assert.match(descriptor, /^(?:0|[1-9][0-9]*)$/u);
          try {
            const fd = `/proc/${originalPid}/fd/${descriptor}`;
            if (await readlink(fd) !== resourcePath) continue;
            const actual = await stat(fd, { bigint: true });
            for (const key of imageFields) assert.equal(actual[key], resourceBefore[key]);
            let position: string | undefined;
            if (shutdownSessionOnly) {
              const info = await readFile(`/proc/${originalPid}/fdinfo/${descriptor}`, 'utf8'); assert(info.length <= 65536);
              const flags = info.match(/^flags:\s+([0-7]+)$/mu), observed = info.match(/^pos:\s+([0-9]+)$/mu); assert(flags && observed);
              const access = Number.parseInt(flags[1]!, 8);
              if ((access & 3) !== constants.O_RDONLY || !(access & constants.O_DIRECTORY)) continue;
              position = observed[1]!; assert.match(position, /^(?:0|[1-9][0-9]{0,19})$/u);
            }
            if (await readlink(fd) !== resourcePath) continue;
            await assertOriginalSupervisor(); return { descriptor, ...(position === undefined ? {} : { position }) };
          } catch (error) {
            if (!['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
          }
        }
        await assertOriginalSupervisor(); return undefined;
      };
      const admission: Record<string, any> = shutdownSessionOnly
        ? request({ protocolVersion: 1, method: 'session.create', requestId: '019a0012-0000-7000-8000-000000000136',
          admissionKey: randomBytes(32).toString('base64url'), workspacePath: recipe.workspace, name: 'Original Session Trust shutdown' })
        : request({ protocolVersion: 1, method: 'run.submit', requestId: '019a0012-0000-7000-8000-000000000130',
        admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
        workspacePath: recipe.workspace, objective: 'Qualify ordinary instruction capture shutdown without executing a model or tool.',
        model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: registration.endpointRegistrationId },
          modelCredentialGrantIds: [enrollment.credentialGrantId] }, policyMode: 'accept-edits',
        budgets: { wallTimeMs: 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000,
          repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
        verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [],
        sourceExcludes: [{ path: 'shutdown-instructions', scope: 'subtree' }],
        registeredMcpServerIds: [], skillIds: [], allowUnverified: true });
      const admittedId = identityHash(shutdownSessionOnly ? 'cliq-session-id-v1' : 'cliq-run-id-v1', principal,
        admission.method, admission.admissionKey);
      const readAdmission = shutdownSessionOnly ? { protocolVersion: 1, method: 'session.get', sessionId: admittedId }
        : { protocolVersion: 1, method: 'run.get', runId: admittedId };
      const absent = { protocolVersion: 1, ok: false, method: readAdmission.method, error: { schemaVersion: 1,
        code: 'NOT_FOUND', retryable: false, messageCode: 'control.read_rejected' } };
      const assertAbsent = () => assert.equal(canonicalSha256(exchange([readAdmission])[0]), canonicalSha256(absent));
      assertAbsent();
      const originalStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.equal(originalStatus.health, 'ready');
      const originalOwners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      assert.equal(originalOwners.length, 1);
      const originalOwner = originalOwners[0]!;
      assert.equal(originalOwner.state, 'active'); assert.equal(originalOwner.supervisorInstanceId, originalStatus.supervisorInstanceId);
      shutdownClient = await persistentClient();
      let requestFinished = false;
      const pendingAdmission = shutdownClient.send(admission, 120000).then(response => {
        requestFinished = true; return { kind: 'response' as const, response };
      }, () => { requestFinished = true; return { kind: 'disconnected' as const }; });
      mark(shutdownSessionOnly ? 'actual_trust_cursor_progress_owned_by_original_pending_session'
        : 'actual_instruction_descriptor_owned_by_original_pending_admission');
      const observeBy = Date.now() + 30000;
      let resource: AdmissionResource | undefined, firstCursor: AdmissionResource | undefined;
      while (!resource) {
        assert(!requestFinished, 'the actual producer must remain pending until its original resource is positively observed');
        assert(Date.now() < observeBy, 'the actual original admission resource/progress was not positively observed');
        const current = await heldAdmissionResource(firstCursor);
        if (!current) { firstCursor = undefined; await delay(1); continue; }
        if (shutdownSessionOnly) {
          // source-walk.c uses fdopendir/readdir on this distinct open file
          // description. Its fdinfo position is an opaque getdents cookie,
          // not a file byte offset, percentage or count of validated entries.
          // A changed cookie on the same held directory proves enumeration
          // advanced; merely seeing a pinned directory would prove no work.
          if (!firstCursor) { firstCursor = current; assertAbsent(); continue; }
          if (current.position === firstCursor.position) { await delay(1); continue; }
        }
        resource = current;
      }
      assertAbsent();
      assert(await heldAdmissionResource(resource), 'the exact original resource must remain held at the signal cut');
      assert.equal(requestFinished, false); assert.equal(requestsReceived, 0); assert(!providerFailure);
      report.shutdownAdmission = { qualified: false, diagnosticOnly: true,
        publicMethod: admission.method, originalPendingPublicRequest: true,
        ...(shutdownSessionOnly ? { originalTrustDirectoryMatched: true, originalNativeEnumerationAdvanced: true,
          trustDirectoryDeviceId: inventoryBefore.dev.toString(), trustDirectoryFileId: inventoryBefore.ino.toString(),
          firstDirectoryCookie: firstCursor!.position, laterDirectoryCookie: resource.position, directoryCookiesAreEntryCounts: false }
          : { originalInstructionDescriptorMatched: true, instructionDocuments: 1, instructionBytes: instructionBytes.length, sourceSubtreeExcluded: true }),
        originalSupervisorProcessMatched: true, metadataEntries, inFlightSourcePayloadQualified: false, workerPreparationQualified: false,
        receivedToolQualified: false, immutableResultOrClaimQualified: false };
      const contract = command('/usr/bin/systemctl', ['--user', 'show', services.supervisorUnit,
        '--property=TimeoutStopUSec,KillSignal,FinalKillSignal,SendSIGKILL', '--no-pager']);
      assert.equal(contract.status, 0);
      const stopPolicy = Object.fromEntries(contract.stdout.trim().split('\n').map(line => line.split('=')));
      assert.equal(stopPolicy.TimeoutStopUSec, '2s'); assert.equal(stopPolicy.KillSignal, '15');
      assert.equal(stopPolicy.FinalKillSignal, '9'); assert.equal(stopPolicy.SendSIGKILL, 'yes');
      report.shutdownAdmission.standardStopTimeoutMs = 2000;
      mark(shutdownSessionOnly ? 'ordinary_systemd_sigterm_during_session_trust_enumeration' : 'ordinary_systemd_sigterm_during_instruction_capture');
      let originalAdmissionResponse: Response | undefined;
      await withRetainedUnitHistory([services.supervisorUnit, services.keeperUnit], async () => {
        assert(await heldAdmissionResource(resource));
        assert.equal(requestFinished, false);
        const stopped = command('/usr/bin/systemctl', ['--user', 'stop', services.supervisorUnit]);
        const exit = show(services.supervisorUnit);
        report.shutdownAdmission.serviceExit = projectInstalledServiceExit(exit);
        const pending = await bounded(pendingAdmission, 10000, 'original stopped admission client did not finish');
        if (pending.kind === 'disconnected') await shutdownClient!.joinAfterPeerShutdown();
        else { originalAdmissionResponse = pending.response; await shutdownClient!.close(); }
        report.shutdownAdmission.originalClientJoined = true;
        report.shutdownAdmission.originalClientDisconnected = pending.kind === 'disconnected';
        assert.equal(stopped.status, 0, 'ordinary two-second Supervisor stop must not require forced retirement');
        assert.equal(exit.ActiveState, 'inactive'); assert.equal(exit.MainPID, '0');
        assert.equal(exit.Result, 'success'); assert.equal(exit.ExecMainCode, '1'); assert.equal(exit.ExecMainStatus, '0');
        await assert.rejects(lstat(`/proc/${originalPid}`), { code: 'ENOENT' });
      });
      const releasedOwners = inspectInstalledOwnerHistory(recipe.stateRoot).owners;
      assert.equal(releasedOwners.length, 1);
      const releasedOwner = releasedOwners[0]!;
      assert.equal(releasedOwner.state, 'terminal');
      if (releasedOwner.state !== 'terminal') throw new Error('ordinary SIGTERM did not publish a terminal StateOwner');
      assert.equal(releasedOwner.terminalReason, 'graceful_release');
      for (const key of ['ownerEpoch', 'supervisorInstanceId', 'processIdentityRef', 'processIdentityDigest',
        'stateLockIdentityRef', 'stateLockIdentityDigest', 'instanceNonceDigest', 'acquiredAt'] as const)
        assert.equal(releasedOwner[key], originalOwner[key]);
      assert.equal(show(services.keeperUnit).MainPID, keeperBefore.MainPID);
      assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
      mark('shutdown_admission_actual_successor_and_public_outcome');
      assert.equal(command('/usr/bin/systemctl', ['--user', 'start', services.supervisorUnit]).status, 0);
      const successor = show(services.supervisorUnit), successorBy = Date.now() + 30000;
      assert.notEqual(successor.MainPID, supervisorBefore.MainPID); assert.notEqual(successor.InvocationID, supervisorBefore.InvocationID);
      await selectedSupervisor(services.supervisorUnit, successor, selectedImage, successorBy);
      const successorStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.equal(successorStatus.health, 'ready'); assert.notEqual(successorStatus.supervisorInstanceId, originalStatus.supervisorInstanceId);
      const links: Record<string, unknown> = {};
      const history = await qualifyInstalledOwnerLinks({ stateRoot: recipe.stateRoot, uid: ledger.uid, bundle: signed.bundle,
        imageDigest: report.bundle.supervisorDigest, report: links });
      assert.equal(links.qualified, true); assert.equal(history.owners.length, 2);
      assert.deepEqual(history.owners[0], releasedOwner);
      const successorOwner = history.owners[1]!;
      assert.equal(successorOwner.state, 'active');
      assert.equal(successorOwner.supervisorInstanceId, successorStatus.supervisorInstanceId);
      assert.equal(successorOwner.ownerEpoch, originalOwner.ownerEpoch + 1);
      report.shutdownAdmission.ownerLineage = { qualified: true,
        originalOwnerEpoch: originalOwner.ownerEpoch, originalSupervisorInstanceId: originalOwner.supervisorInstanceId,
        originalProcessIdentityRef: originalOwner.processIdentityRef, originalProcessIdentityDigest: originalOwner.processIdentityDigest,
        terminalReason: 'graceful_release', terminalRowDigest: releasedOwner.rowDigest,
        transitionEvidenceRef: releasedOwner.transitionEvidenceRef, transitionEvidenceDigest: releasedOwner.transitionEvidenceDigest,
        successorOwnerEpoch: successorOwner.ownerEpoch, successorSupervisorInstanceId: successorOwner.supervisorInstanceId,
        acquisitionKind: 'acquire_after_graceful_release', acquisitionEvidenceRef: successorOwner.acquisitionEvidenceRef,
        acquisitionEvidenceDigest: successorOwner.acquisitionEvidenceDigest,
        sameStateLock: true, sameSignedRuntime: true };
      assert.deepEqual(exchange([sessionRequest])[0], sessionReply);
      // The descriptor observation precedes systemctl and the Store's private
      // gate. An admission may legitimately commit in that unobserved gap;
      // SIGTERM is not run.cancel and must not erase that durable response.
      const outcome = exchange([readAdmission])[0]!;
      if (!outcome.ok) {
        assert.equal(canonicalSha256(outcome), canonicalSha256(absent));
        assert.notEqual(originalAdmissionResponse?.ok, true, 'an acknowledged admission cannot disappear during graceful stop');
        assert.deepEqual(currentSession(), session); assert.equal(requestsReceived, 0);
        report.shutdownAdmission.acceptedBeforeGateRace = false;
        report.shutdownAdmission[shutdownSessionOnly ? 'noAcceptedSessionObservedAfterRestart' : 'noAcceptedRunObservedAfterRestart'] = true;
        report.shutdownAdmission.sessionUnchanged = true;
      } else if (shutdownSessionOnly) {
        const cut = accepted(outcome, 'session.get'), created = cut.snapshot.session;
        assert.equal(created.id, admittedId); assert.equal(created.name, admission.name);
        assert.equal(created.contextRevision, 1); assert.equal(created.latestItemSeq, 0); assert.deepEqual(cut.items, []);
        const workspace = parseJsonStrict((await readCas(created.workspaceIdentityRef)).toString('utf8')) as Record<string, any>;
        assert.equal(workspace.kind, 'live'); assert.equal(workspace.canonicalRootPath, recipe.workspace);
        assert.equal(workspace.ownerPrincipalId, principal); assert.equal(workspace.identityDigest, digestOmitting(workspace, 'identityDigest'));
        const replay = exchange([admission, admission]); assert.deepEqual(replay[1], replay[0]);
        if (originalAdmissionResponse) assert.deepEqual(replay[0], originalAdmissionResponse);
        assert.deepEqual(accepted(replay[0]!, 'session.create').snapshot.session, created);
        assert.deepEqual(exchange([admission])[0], replay[0], 'the exact original Session response must survive a fresh connection');
        assert.deepEqual(accepted(exchange([readAdmission])[0]!, 'session.get').snapshot.session, created);
        assert.deepEqual(currentSession(), session); assert.equal(requestsReceived, 0);
        assert.equal(acceptedTcpConnections, 0); assert.equal(acceptedTlsConnections, 0);
        report.shutdownAdmission.acceptedBeforeGateRace = true;
        report.shutdownAdmission.acceptedAdmissionReplayPreserved = true;
        report.shutdownAdmission.sameOriginalSessionOnRepeatedReplay = true;
        report.shutdownAdmission.noRunOrProductiveRequest = true;
      } else {
        const runId = admittedId;
        const cut = accepted(outcome, 'run.get'), run = cut.snapshot.run;
        assert.equal(run.id, runId); assert.equal(run.sessionId, session.id);
        const spec = parseJsonStrict((await readCas(run.specRef)).toString('utf8')) as Record<string, any>;
        assert.equal(spec.schemaVersion, 1); assert.equal(spec.operation, 'agent');
        assert.equal(canonicalSha256(spec.budgets), canonicalSha256(admission.budgets));
        const objective = parseJsonStrict((await readCas(spec.objectiveRef)).toString('utf8')) as Record<string, any>;
        assert.equal(objective.format, 'cliq-run-objective-v1'); assert.equal(objective.utf8, admission.objective);
        assert.equal(objective.objectiveDigest, digestOmitting(objective, 'objectiveDigest'));
        const replay = exchange([admission, admission]); assert.deepEqual(replay[1], replay[0]);
        if (originalAdmissionResponse) assert.deepEqual(replay[0], originalAdmissionResponse);
        const original = accepted(replay[0]!, 'run.submit').snapshot.run;
        assert.equal(original.id, runId); assert.equal(original.sessionId, session.id); assert.equal(original.specRef, run.specRef);
        assert.deepEqual(exchange([admission])[0], replay[0], 'the exact original admission response must survive a fresh connection');
        const latest = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId }])[0]!, 'run.get');
        assert.equal(latest.snapshot.run.specRef, run.specRef);
        report.shutdownAdmission.modelClaimHistory = await inspectShutdownModelClaims(latest);
        const sessionCut = accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
          afterItemSeq: session.latestItemSeq }])[0]!, 'session.get');
        assert(sessionCut.items.length <= 1, 'the admitted Run cannot publish a duplicate Session terminal item');
        for (const item of sessionCut.items) {
          assert.equal(item.kind, 'run_terminal');
          const payload = parseJsonStrict((await readCas(item.payloadRef)).toString('utf8')) as Record<string, any>;
          assert.equal(payload.runId, runId);
        }
        assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + sessionCut.items.length);
        assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + sessionCut.items.length);
        assert(requestsReceived <= 1 && acceptedTcpConnections <= 1 && acceptedTlsConnections <= 1);
        report.shutdownAdmission.acceptedBeforeGateRace = true;
        report.shutdownAdmission.acceptedAdmissionReplayPreserved = true;
        report.shutdownAdmission.noDuplicateProductiveClaimOrSessionPublication = true;
        report.shutdownAdmission.sessionPublications = sessionCut.items.length;
      }
      assert(!providerFailure);
      for (const key of imageFields) {
        assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
        assert.equal((await lstat(instruction, { bigint: true }))[key], instructionBefore[key]);
      }
      assert.equal(await readFile(source, 'utf8'), hostBefore); assert.deepEqual(await readFile(instruction), instructionBytes);
      report.shutdownAdmission = { ...report.shutdownAdmission, qualified: true, gracefulExitZero: true,
        genuineSuccessorPublicOwner: true, sameKeeper: true,
        ...(shutdownSessionOnly ? { baselineSessionCreateResponsePreserved: true, sourceAndTrustDecisionUnchanged: true }
          : { originalSessionCreateResponsePreserved: true, sourceAndInstructionUnchanged: true }),
        precommitAbortCutQualified: false,
        fullI1Qualified: false };
    } else {
    mark('public_run_submit');
    const runBudgets = { wallTimeMs: failureOnly || retryOnly || authorityOnly ? 45000 : 300000, modelTokens: 2000000, costMicros: 10000000, toolCalls: 1000,
      repairAttempts: 0, childDepth: 0, childConcurrency: 1 };
    const submit = request({ protocolVersion: 1, method: 'run.submit', requestId: '019a0012-0000-7000-8000-000000000104',
      admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
      workspacePath: recipe.workspace, objective: storageOnly ? 'Observe exactly one interrupted model transport without executing a tool.'
        : authorityOnly ? 'Retain one candidate without using a tool until the user cancels.'
        : retryOnly ? 'Acknowledge restored model preparation without using a tool.'
        : failureOnly ? 'Observe the owned cafe\u0301 model failure without using a tool.'
          : 'Change example.txt from before the private edit to after the private edit, using one edit operation.',
      model: { provider: 'openai-compatible', model, endpoint: { kind: 'registered', endpointRegistrationId: registration.endpointRegistrationId },
        modelCredentialGrantIds: [enrollment.credentialGrantId] }, policyMode: 'accept-edits',
      budgets: runBudgets,
      verifiers: [], dependency: { mode: 'none' }, sourceIncludes: [],
      sourceExcludes: failureOnly ? [{ path: 'vendor', scope: 'subtree' }] : [],
      registeredMcpServerIds: [], skillIds: [], allowUnverified: true });
    const { requestDigest: _resourceDigest, ...resourceCore } = submit;
    if (failureOnly) {
      busySubmit = request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000123',
        admissionKey: randomBytes(32).toString('base64url') });
      report.credentialScopeBusy = { observedCode: 'not_observed', exactPayloadMatched: false };
      report.credentialFinalizeScopeBusy = { observedCode: 'not_observed', exactPayloadMatched: false };
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
    const defaultPolicy = exchange([request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000124',
      policyMode: 'default' })])[0]!;
    assert.equal(canonicalSha256(defaultPolicy), canonicalSha256({ protocolVersion: 1, ok: false, method: 'run.submit',
      error: { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false, messageCode: 'control.invalid_request',
        issues: [{ path: 'request', issueCode: 'invalid_request' }] } }),
    'the fixed installed recipe must reject unsupported approval rather than auto-allow tools');
    assert.equal(requestsReceived, 0); assert.deepEqual(currentSession(), session);
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
    if (storageOnly) {
      storageClient = await persistentClient();
      const beforeStorage = accepted(await storageClient.send({ protocolVersion: 1, method: 'supervisor.status' }), 'supervisor.status');
      assert.equal(beforeStorage.health, 'ready');
      report.storageInitialSupervisorInstanceId = beforeStorage.supervisorInstanceId;
    }
    const submitReply = exchange([submit])[0]!, admitted = accepted(submitReply, 'run.submit').snapshot.run;
    report.defaultPolicyRefused = { qualified: true, refusalCode: 'INVALID_REQUEST', noProviderRequest: true,
      sessionUnchanged: true, permissionsAutoAllowed: false, sameAdmissionKeySubsequentlyAccepted: true };
    report.oversizedFileLimitRefused = { requestedBytes: 2_147_483_648, installedLimitBytes: 268_435_456,
      sameAdmissionKeySubsequentlyAccepted: true, silentClampingAllowed: false };
    report.acceptedRun = { id: admitted.id, sessionId: admitted.sessionId, specRef: admitted.specRef, initialCheckpointId: admitted.latestCheckpointId };
    if (failureOnly) {
      const spec = parseJsonStrict((await readCas(admitted.specRef)).toString('utf8')) as Record<string, any>;
      const assembly = parseJsonStrict((await readCas(spec.assemblyRef)).toString('utf8')) as Record<string, any>;
      const instructions = parseJsonStrict((await readCas(assembly.instructions.workspaceInstructionsRef)).toString('utf8')) as Record<string, any>;
      assert.deepEqual(instructions.entries.map((entry: any) => entry.canonicalRootRelativePath), ['vendor/AGENTS.md']);
      const content = parseJsonStrict((await readCas(instructions.entries[0].contentRef)).toString('utf8')) as Record<string, any>;
      assert.equal(content.utf8, excludedVendorInstruction);
      const source = parseJsonStrict((await readCas(spec.baseWorkspaceManifestRef)).toString('utf8')) as Record<string, any>;
      const entries = parseJsonStrict((await readCas(source.entriesRef)).toString('utf8')) as Record<string, any>;
      assert.deepEqual(entries.entries.map((entry: any) => entry.path), ['example.txt']);
      report.instructionMetadataExclusion.capturedOrdinaryGuidance = true;
      report.instructionMetadataExclusion.sourceExcludedSubtreeAbsent = true;
      report.instructionMetadataExclusion.gitMetadataAbsentFromInstructions = true;
    }
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
    if (storageOnly) {
      mark('actual_post_and_original_permanent_claim_before_cas_refusal');
      await bounded(storagePostEntered, 15000, 'the original native POST did not reach its owned external server');
      assert(storageClient && storagePost); assert.equal(requestsReceived, 1); assert(!providerFailure);
      const publicRead = async () => accepted(await storageClient!.send({ protocolVersion: 1, method: 'run.get', runId: admitted.id }), 'run.get');
      const beforeFault = await publicRead();
      assert.deepEqual(beforeFault.journal.map((entry: any) => entry.phase), ['prepared', 'dispatch_claimed']);
      const [prepared, claim] = beforeFault.journal;
      assert.equal(beforeFault.snapshot.run.status, 'running'); assert(beforeFault.snapshot.run.activeWorkerLaunchId);
      assert.equal(prepared.attempt, 0); assert.equal(claim.brokerFenceTokenDigest.length, 64);
      assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1);
      assert.deepEqual(currentSession(), session);
      mark('real_read_preserving_cas_write_refusal');
      const assertCasRefused = await refuseCasWrites();
      let refusedCut: Record<string, any>, refusedStatus: Record<string, any>;
      try {
        assert.deepEqual((await publicRead()).journal, beforeFault.journal, 'the actual existing public connection retains CAS read access');
        await assertCasRefused();
        storagePost.destroy();
        await bounded(storagePost.closed, 10000, 'the original owned HTTPS socket did not close');
        mark('failed_settlement_retains_original_claim_while_cas_write_is_refused');
        const refusalBy = Date.now() + 10000;
        for (;;) {
          // This real installation borrow runs only after the original model
          // credential callback yielded. A degraded health cut with the exact
          // unsettled claim proves its genuine failure path returned while
          // publication remained physically refused, not a guessed delay.
          refusedStatus = accepted(await storageClient.send({ protocolVersion: 1, method: 'supervisor.status' }), 'supervisor.status');
          refusedCut = await publicRead(); await assertCasRefused();
          assert.deepEqual(refusedCut.journal, beforeFault.journal);
          assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
          if (refusedStatus.health === 'degraded') break;
          assert(Date.now() < refusalBy, 'the original callback did not expose its genuine failed settlement'); await delay(50);
        }
        assert(Date.now() < refusalBy);
        assert.equal(refusedStatus.supervisorInstanceId, report.storageInitialSupervisorInstanceId);
        assert.equal(refusedCut.snapshot.run.activeWorkerLaunchId, beforeFault.snapshot.run.activeWorkerLaunchId);
        assert.equal(refusedCut.snapshot.run.leaseEpoch, beforeFault.snapshot.run.leaseEpoch);
        assert.equal(refusedCut.snapshot.run.frontierRef, beforeFault.snapshot.run.frontierRef);
        assert.equal(canonicalSha256(refusedCut.snapshot.run.budgetReserved), canonicalSha256(prepared.budgetDelta));
        report.casWriteRefusal.productionAttemptWitnessed = true;
      } finally { await restoreCasWrite!(); }
      mark('same_owner_typed_settlement_after_exact_cas_restoration');
      const settledBy = Date.now() + 15000;
      let settled: Record<string, any>;
      for (;;) {
        await delay(50); settled = await publicRead();
        assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
        if (settled.journal.at(-1)?.phase === 'unknown') break;
        assert.deepEqual(settled.journal, beforeFault.journal);
        assert(Date.now() < settledBy, 'restored CAS did not allow the original same-owner typed settlement');
      }
      assert(Date.now() < settledBy);
      assert.deepEqual(settled.journal.slice(0, 2), beforeFault.journal); assert.equal(settled.journal.length, 3);
      const unknown = settled.journal[2]; assert.equal(unknown.dispatchId, claim.dispatchId); assert.equal(unknown.brokerFenceTokenDigest, claim.brokerFenceTokenDigest);
      assert.equal(unknown.stateOwnerEpoch, claim.stateOwnerEpoch); assert.equal(unknown.supervisorInstanceId, claim.supervisorInstanceId);
      const ambiguity = parseJsonStrict((await readCas(unknown.evidenceRef)).toString('utf8')) as Record<string, any>;
      assert.equal(ambiguity.format, 'cliq-invocation-ambiguity-evidence-v1'); assert.equal(ambiguity.ambiguityKind, 'broker_channel_lost_after_claim');
      assert.equal(ambiguity.failureCode, 'response_stream_interrupted'); assert.equal(ambiguity.dispatchId, claim.dispatchId);
      assert.equal(ambiguity.claimingStateOwnerEpoch, claim.stateOwnerEpoch); assert.equal(ambiguity.evidenceDigest, unknown.evidenceDigest);
      assert.equal(ambiguity.evidenceDigest, digestOmitting(ambiguity, 'evidenceDigest'));
      const charge = parseJsonStrict((await readCas(unknown.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
      for (const usage of [charge.reserved, charge.released, charge.consumed, settled.snapshot.run.budgetConsumed])
        assert.equal(canonicalSha256(usage), canonicalSha256(prepared.budgetDelta));
      const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
      assert.equal(canonicalSha256(settled.snapshot.run.budgetReserved), canonicalSha256(zero));
      const sameSupervisor = show(services.supervisorUnit);
      assert.equal(sameSupervisor.MainPID, supervisorBefore.MainPID); assert.equal(sameSupervisor.InvocationID, supervisorBefore.InvocationID);
      assert.equal(accepted(await storageClient.send({ protocolVersion: 1, method: 'supervisor.status' }), 'supervisor.status').supervisorInstanceId,
        report.storageInitialSupervisorInstanceId);
      assert.deepEqual((await publicRead()).journal, settled.journal); assert.deepEqual(currentSession(), session);
      await storageClient.close(); storageClient = undefined;
      mark('settled_unknown_actual_successor_then_public_cancellation');
      assert.equal(command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit], undefined, 30000).status, 0);
      const successor = show(services.supervisorUnit), recoverBy = Date.now() + 30000;
      assert.notEqual(successor.MainPID, sameSupervisor.MainPID); assert.notEqual(successor.InvocationID, sameSupervisor.InvocationID);
      const retainedKeeper = show(services.keeperUnit);
      assert.equal(retainedKeeper.MainPID, keeperBefore.MainPID); assert.equal(retainedKeeper.InvocationID, keeperBefore.InvocationID);
      await selectedSupervisor(services.supervisorUnit, successor, path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor'), recoverBy);
      let recovered: Record<string, any>;
      for (;;) {
        await delay(50); recovered = read(); assert.deepEqual(recovered.journal, settled.journal);
        if (recovered.snapshot.run.status === 'queued' && !recovered.snapshot.run.activeWorkerLaunchId) break;
        assert(Date.now() < recoverBy, 'the successor did not physically retire the original worker');
      }
      const successorStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
      assert.notEqual(successorStatus.supervisorInstanceId, claim.supervisorInstanceId);
      const cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000131',
        runId: admitted.id, expectedRevision: recovered.snapshot.run.revision });
      const cancelReply = exchange([cancel])[0]!; accepted(cancelReply, 'run.cancel');
      const terminalBy = Date.now() + 15000;
      let terminal: Record<string, any>;
      for (;;) {
        await delay(50); terminal = read(); assert.deepEqual(terminal.journal, settled.journal);
        assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
        if (terminal.snapshot.run.status === 'cancelled') break;
        assert(Date.now() < terminalBy, 'the successor could not complete proof-backed cancellation');
      }
      assert(Date.now() < terminalBy); assert.equal(terminal.snapshot.run.terminalReason, 'cancelled_by_user');
      assert.equal(terminal.snapshot.run.activeWorkerLaunchId, undefined); assert.equal(terminal.snapshot.run.resultRef, undefined);
      const detail = parseJsonStrict((await readCas(terminal.snapshot.run.terminalDetailRef)).toString('utf8')) as Record<string, any>;
      assert.equal(detail.abandonedRetryInvocations.length, 1);
      const closure = decodeBrokerProcessDomainDeathDispatchClosure(parseJsonStrict((await readCas(detail.abandonedRetryInvocations[0].dispatchFenceOrDeathEvidenceRef)).toString('utf8')));
      const death = decodeBrokerProcessDomainDeath(parseJsonStrict((await readCas(closure.closure.brokerProcessDeathEvidenceRef)).toString('utf8')));
      assert.equal(death.claimingStateOwnerEpoch, claim.stateOwnerEpoch); assert.equal(death.claimingSupervisorInstanceId, claim.supervisorInstanceId);
      assert(death.inspectorStateOwnerEpoch > claim.stateOwnerEpoch);
      const sessionCut = accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id, afterItemSeq: session.latestItemSeq }])[0]!, 'session.get');
      assert.equal(sessionCut.items.length, 1); assert.equal(sessionCut.items[0].kind, 'run_terminal');
      const publication = parseJsonStrict((await readCas(sessionCut.items[0].payloadRef)).toString('utf8')) as Record<string, any>;
      assert.equal(publication.runId, admitted.id); assert.equal(publication.status, 'cancelled');
      assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + 1);
      assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + 1);
      assert.deepEqual(exchange([cancel])[0], cancelReply); assert.deepEqual(exchange([submit])[0], submitReply);
      assert.equal(command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit], undefined, 30000).status, 0);
      const terminalSupervisor = show(services.supervisorUnit), terminalReadyBy = Date.now() + 30000;
      assert.notEqual(terminalSupervisor.MainPID, successor.MainPID); assert.notEqual(terminalSupervisor.InvocationID, successor.InvocationID);
      await selectedSupervisor(services.supervisorUnit, terminalSupervisor,
        path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor'), terminalReadyBy);
      assert.deepEqual(read(), terminal); assert.deepEqual(exchange([cancel])[0], cancelReply);
      assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
        afterItemSeq: session.latestItemSeq }])[0]!, 'session.get'), sessionCut);
      assert.equal(requestsReceived, 1); assert.equal(acceptedTcpConnections, 1); assert.equal(acceptedTlsConnections, 1); assert(!providerFailure);
      for (const field of imageFields) assert.equal((await lstat(source, { bigint: true }))[field], sourceBefore[field]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      report.casWriteRefusal = { ...report.casWriteRefusal, qualified: true, sameOwnerSettlementRetried: true,
        originalClaimPreserved: true, originalClaimSettlementRetriedWithoutRedispatch: true, fullUnknownChargePreserved: true,
        settlements: 1, acceptedTcpConnections: 1, acceptedTlsConnections: 1, providerRequests: 1,
        successorOwnerTerminalAndHistoryReplayed: true, sessionPublishedOnce: true,
        nativeObjectIdentityDirectlyObserved: false, exactNeverConnectGuardStorageFailureQualified: false, fullI1Qualified: false };
    } else if (authorityOnly) {
      mark('candidate_holds_real_worker_slot');
      const candidateBy = Date.now() + 15000;
      let candidate: Record<string, any>;
      for (;;) {
        await delay(50); candidate = read(); assert(!providerFailure);
        if (candidate.journal.at(-1)?.phase === 'completed') break;
        assert(Date.now() < candidateBy, 'the original actual worker did not retain its candidate');
      }
      assert.equal(candidate.snapshot.run.status, 'running'); assert(candidate.snapshot.run.activeWorkerLaunchId);
      assert.equal(requestsReceived, 1); assert.deepEqual(currentSession(), session);
      const queuedRequest = request({ ...resourceCore, requestId: '019a0012-0000-7000-8000-000000000125',
        admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: currentSession().contextRevision,
        objective: 'Stop truthfully if the original model credential is revoked before dispatch.' });
      const queuedReply = exchange([queuedRequest])[0]!, queued = accepted(queuedReply, 'run.submit').snapshot.run;
      const readQueued = () => accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: queued.id }])[0]!, 'run.get');
      const beforeRevoke = readQueued();
      assert.equal(beforeRevoke.snapshot.run.status, 'queued'); assert.equal(beforeRevoke.snapshot.run.activeWorkerLaunchId, undefined);
      assert.deepEqual(beforeRevoke.journal, []); assert.equal(requestsReceived, 1);
      mark('revoke_real_credential_after_admission_before_dispatch');
      const revoked = decodeCredentialAuthorityRevokeOperation(success(credential({ schemaVersion: 1, kind: 'revoke',
        requestId: '019a0012-0000-7000-8000-000000000126', credentialGrantId: enrollment.credentialGrantId,
        expectedAuthorityRevision: operation.committedAuthorityRevision }), 'operation'));
      assert.equal(revoked.disposition, 'revoked'); assert.equal(revoked.cleanupPhase, 'cleanup_complete');
      const revokedPlatform = observe(); assert.deepEqual(revokedPlatform.items, []);
      assert.equal(revokedPlatform.nameOwner, enrolledPlatform.nameOwner); assert.equal(revokedPlatform.servicePid, enrolledPlatform.servicePid);
      const cancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000127',
        runId: admitted.id, expectedRevision: read().snapshot.run.revision });
      const cancelReply = exchange([cancel])[0]!; accepted(cancelReply, 'run.cancel');
      mark('refused_queued_run_drains_without_provider_release');
      const terminalBy = Date.now() + 30000;
      let firstTerminal: Record<string, any>, refusedTerminal: Record<string, any>;
      for (;;) {
        await delay(50); firstTerminal = read(); refusedTerminal = readQueued();
        assert(!providerFailure); assert.equal(requestsReceived, 1, 'a revoked credential must never reach the provider');
        if (firstTerminal.snapshot.run.status === 'cancelled' && refusedTerminal.snapshot.run.status === 'failed') break;
        assert(Date.now() < terminalBy, 'authority refusal retained the only execution lane instead of retiring');
      }
      assert(Date.now() < terminalBy);
      const refused = refusedTerminal.snapshot.run;
      assert.equal(refused.terminalReason, 'runtime_failed'); assert.equal(refused.cancelRequested, false);
      assert.equal(refused.activeWorkerLaunchId, undefined); assert.equal(refused.resultRef, undefined);
      assert(refused.updatedAt < refused.deadlineAt, 'authorization refusal must not wait for Run expiry');
      assert.deepEqual(refusedTerminal.journal.map((entry: any) => entry.phase), ['prepared', 'failed']);
      const [prepared, failed] = refusedTerminal.journal;
      assert.equal(failed.requestRef, prepared.requestRef); assert.equal(failed.opId, prepared.opId); assert.equal(failed.attempt, 0);
      for (const entry of refusedTerminal.journal) {
        assert.equal(entry.dispatchId, undefined); assert.equal(entry.brokerFenceTokenDigest, undefined);
      }
      const zero = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
      assert.equal(canonicalSha256(refused.budgetReserved), canonicalSha256(zero));
      assert.equal(canonicalSha256(refused.budgetConsumed), canonicalSha256(zero));
      const refusal = parseJsonStrict((await readCas(failed.errorRef)).toString('utf8')) as Record<string, any>;
      assert.equal(refusal.format, 'cliq-credential-redemption-refusal-v1');
      assert.equal(refusal.credentialAuthorityRecord.state, 'revoked');
      assert.equal(refusal.refusalDigest, digestOmitting(refusal, 'refusalDigest'));
      const intent = parseJsonStrict((await readCas(refused.stopIntentRef)).toString('utf8')) as Record<string, any>;
      assert.equal(intent.reason, 'runtime_failed'); assert.equal(intent.runtimeSubtype, 'runtime'); assert.equal(intent.failingOpId, prepared.opId);
      const evidence = parseJsonStrict((await readCas(intent.runtimeFailureRef)).toString('utf8')) as Record<string, any>;
      assert.equal(evidence.failureKind, 'credential_redemption_failed'); assert.equal(evidence.failureCode, 'revoked');
      assert.equal(evidence.evidenceDigest, digestOmitting(evidence, 'evidenceDigest')); assert.equal(evidence.evidenceDigest, intent.runtimeFailureDigest);
      const sessionCut = accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
        afterItemSeq: session.latestItemSeq }])[0]!, 'session.get');
      assert.equal(sessionCut.snapshot.session.contextRevision, session.contextRevision + 2);
      assert.equal(sessionCut.snapshot.session.latestItemSeq, session.latestItemSeq + 2);
      assert.deepEqual(sessionCut.items.map((item: any) => item.kind), ['run_terminal', 'run_terminal']);
      const published = await Promise.all(sessionCut.items.map(async (item: any) =>
        parseJsonStrict((await readCas(item.payloadRef)).toString('utf8')) as Record<string, any>));
      assert.deepEqual(published.map(item => [item.runId, item.status]), [[admitted.id, 'cancelled'], [queued.id, 'failed']]);
      assert.deepEqual(exchange([queuedRequest])[0], queuedReply); assert.deepEqual(exchange([cancel])[0], cancelReply);
      mark('revoked_credential_terminal_history_after_real_restart');
      assert.equal(command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit], undefined, 30000).status, 0);
      const successor = show(services.supervisorUnit), retainedKeeper = show(services.keeperUnit), recoverBy = Date.now() + 30000;
      assert.notEqual(successor.MainPID, supervisorBefore.MainPID); assert.notEqual(successor.InvocationID, supervisorBefore.InvocationID);
      assert.equal(retainedKeeper.MainPID, keeperBefore.MainPID); assert.equal(retainedKeeper.InvocationID, keeperBefore.InvocationID);
      await selectedSupervisor(services.supervisorUnit, successor,
        path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor'), recoverBy);
      assert.deepEqual(read(), firstTerminal); assert.deepEqual(readQueued(), refusedTerminal);
      assert.deepEqual(exchange([queuedRequest])[0], queuedReply); assert.deepEqual(exchange([cancel])[0], cancelReply);
      assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
        afterItemSeq: session.latestItemSeq }])[0]!, 'session.get'), sessionCut);
      assert.equal(accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status').health, 'ready');
      assert.equal(requestsReceived, 1); assert(!providerFailure);
      for (const key of imageFields) assert.equal((await lstat(source, { bigint: true }))[key], sourceBefore[key]);
      assert.equal(await readFile(source, 'utf8'), hostBefore);
      report.credentialAuthorizationFailure = { qualified: true, revokedAfterAdmission: true, actualPlatformItemRemoved: true,
        originalCandidateCancelled: true, refusedRunStatus: 'failed', terminalReason: 'runtime_failed', failureCode: 'revoked',
        noClaimOrProviderRequest: true, zeroConsumptionAndReservation: true, stoppedBeforeDeadline: true,
        terminalRunAndCredentialHistoryReopenedAfterActualSupervisorRestart: true, sessionPublishedOncePerRun: true,
        originalNativeJoinRequiredByProduction: true, providerRequests: 1, fullI1Qualified: false };
    } else if (retryOnly) {
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
      assert.equal(report.instructionMetadataExclusion.providerReceivedOrdinaryGuidance, true);
      assert.deepEqual(await readFile(path.join(recipe.workspace, 'vendor', '.git', 'AGENTS.md')), Buffer.from([0xff]));
      report.instructionMetadataExclusion.qualified = true;
      report.receivedModelFailure = { qualified: true, status: 'failed', terminalReason: 'runtime_failed', wallTimeMs: 45000,
        stoppedBeforeDeadline: true, receivedHttpStatus: 429, ownedProviderRequests: 1, noProviderRetry: true,
        completedResponseRef: completed.resultRef, runtimeFailureRef: intent.runtimeFailureRef, runtimeFailureDigest: intent.runtimeFailureDigest,
        terminalDetailRef: failed.terminalDetailRef, fullReservationCharged: true, noToolDispatch: true, noResultPublished: true,
        genuineWorkerJoinRequiredByProduction: true, sessionPublishedOnce: true, reconnectAndAdmissionReplayPreserved: true };
      mark('credential_finalizer_replay_after_scope_drain');
      assert(busyFinalize);
      assert.equal(report.credentialFinalizeScopeBusy.exactPayloadMatched, true,
        'actual concurrent installed finalization must return the fixed retryable RATE_LIMITED response');
      const finalizedReplay = accepted(exchange([busyFinalize])[0]!, 'credential.finalize');
      assert.deepEqual(decodeCredentialAuthorityOperation(finalizedReplay.operation), operation,
        'scope-busy refusal must preserve the original committed credential continuation');
      const finalizerPlatform = observe();
      // Each observation owns a fresh client process/connection. Compare all
      // actual platform fields without mistaking that observer lifetime for
      // the original Secret Service, collection or credential item identity.
      const { clientPid: enrolledClientPid, busUniqueName: enrolledClientName, ...enrolledAuthority } = enrolledPlatform;
      const { clientPid: finalizerClientPid, busUniqueName: finalizerClientName, ...finalizerAuthority } = finalizerPlatform;
      for (const pid of [enrolledClientPid, finalizerClientPid]) assert(Number.isSafeInteger(pid) && pid > 0);
      for (const name of [enrolledClientName, finalizerClientName]) assert.match(name, /^:[0-9]+\.[0-9]+$/u);
      assert.deepEqual(finalizerAuthority, enrolledAuthority,
        'scope-busy refusal and committed replay must preserve the same real service, collection and item');
      assert.equal(requestsReceived, 1); assert.deepEqual(read(), terminal);
      report.credentialFinalizeScopeBusy = { ...report.credentialFinalizeScopeBusy, qualified: true,
        originalCommittedContinuationPreserved: true, originalPlatformItemPreserved: true,
        providerRequestsUnchanged: true, terminalRunUnchanged: true,
        singleExplicitBusyRequest: true, manualReplayAfterScopeDrain: true };
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
      // Both read-only frames share this round's fresh authenticated client;
      // their per-connection identity is published once, not once per query.
      const [maintenanceRun, maintenanceSupervisor] = exchange([
        { protocolVersion: 1, method: 'run.get', runId: admitted.id },
        { protocolVersion: 1, method: 'supervisor.status' },
      ]);
      cut = accepted(maintenanceRun!, 'run.get');
      report.lastPublicCut = projectInstalledRunProgress(cut, { requestsReceived, providerFailure });
      idleObservations++;
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
      const maintenanceStatus = accepted(maintenanceSupervisor!, 'supervisor.status');
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
    queuedObserverClient = await persistentClient();
    const queuedSupervisorPid = Number(supervisorBefore.MainPID);
    const queuedImages = async () => {
      // Read-only OS observation of the already authenticated original
      // Supervisor, never execution, retirement or native authority evidence.
      assert.equal(await fixtureProcess(queuedSupervisorPid, ledger.uid), leaseProcessStart);
      assert.equal(await readlink(`/proc/${queuedSupervisorPid}/exe`),
        path.join(recipe.stateRoot, 'runtime/bundles', bundleDigest, 'supervisor'));
      const directory = `/proc/${queuedSupervisorPid}/fd`, descriptors = await readdir(directory);
      assert(descriptors.length <= 4096, 'Supervisor descriptor observation exceeded its bounded inventory');
      const images: string[] = [];
      for (const descriptor of descriptors) {
        assert.match(descriptor, /^(?:0|[1-9][0-9]*)$/u);
        const filename = path.join(directory, descriptor);
        try {
          const target = await readlink(filename);
          if (target !== '/memfd:cliq-runtime-image (deleted)') continue;
          const before = await stat(filename, { bigint: true });
          assert(before.isFile() && before.uid === BigInt(ledger.uid));
          assert.equal(await readlink(filename), target);
          const after = await stat(filename, { bigint: true });
          for (const field of imageFields) assert.equal(after[field], before[field]);
          images.push(`${before.dev}:${before.ino}:${before.size}`);
        } catch (error) {
          // Unrelated transient descriptors may close during a read-only
          // directory walk. Every retained image is compared again below.
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
      }
      assert.equal(await fixtureProcess(queuedSupervisorPid, ledger.uid), leaseProcessStart);
      return images.sort();
    };
    const queuedImagesBefore = await queuedImages();
    assert(queuedImagesBefore.length >= 2, 'the original live worker must retain its actual launcher images');
    let queuedImageObservations = 0;
    const queuedSubmit = request({ ...submitCore, requestId: '019a0012-0000-7000-8000-000000000110',
      admissionKey: randomBytes(32).toString('base64url'), expectedContextRevision: currentSession().contextRevision,
      objective: 'Remain queued behind the existing candidate worker until this Run reaches its own deadline.',
      budgets: { ...runBudgets, wallTimeMs: 3000 } });
    // Preserve the ordinary mutation's original exchange() budget; the new
    // persistent reader's 5s default must not shorten admission to this Run.
    const queuedAdmitted = accepted(await queuedObserverClient.send(queuedSubmit, 30000), 'run.submit').snapshot.run;
    assert.notEqual(queuedAdmitted.id, admitted.id); assert.equal(queuedAdmitted.status, 'queued');
    assert.equal(Date.parse(queuedAdmitted.deadlineAt) - Date.parse(queuedAdmitted.createdAt), 3000);
    const readQueued = async () => accepted(await queuedObserverClient!.send({ protocolVersion: 1, method: 'run.get',
      runId: queuedAdmitted.id }), 'run.get');
    const initialQueued = await readQueued();
    assert.equal(initialQueued.snapshot.run.status, 'queued'); assert.equal(initialQueued.snapshot.run.activeWorkerLaunchId, undefined);
    assert.deepEqual(initialQueued.journal, []); assert.equal(requestsReceived, 2);
    const ordinaryQueued = (value: Record<string, any>) => value.snapshot.run.status === 'queued' &&
      !value.snapshot.run.stopIntentRef && !value.snapshot.run.cancelRequested;
    const observeQueuedImages = async (before: Record<string, any>) => {
      if (!ordinaryQueued(before)) return;
      const images = await queuedImages(), after = await readQueued();
      // A stop may commit while /proc is read. Only the two actual ordinary
      // queued cuts can classify this metadata observation as allocation-free.
      if (!ordinaryQueued(after)) return;
      assert.deepEqual(images, queuedImagesBefore,
        'a capacity-blocked ordinary queued Run must not retain extra launcher images');
      queuedImageObservations++;
    };
    // Observe before unrelated status round trips can consume this unchanged
    // three-second Run budget. Every frame still authenticates the same peer.
    await observeQueuedImages(initialQueued);
    const capacityStatus = accepted(await queuedObserverClient.send({ protocolVersion: 1, method: 'supervisor.status' }), 'supervisor.status');
    assert.equal(capacityStatus.health, 'ready'); assert.equal(capacityStatus.queue.capacity, 1);
    assert.equal(capacityStatus.queue.runningRuns, 1); assert.equal(capacityStatus.queue.queuedRuns, 1);
    const queuedDeadlineBy = Date.now() + 30000;
    let deadlineCut: Record<string, any>;
    for (;;) {
      await delay(50); deadlineCut = await readQueued(); assert(!providerFailure);
      assert.deepEqual(deadlineCut.journal, []); assert.equal(deadlineCut.snapshot.run.activeWorkerLaunchId, undefined);
      assert.equal(requestsReceived, 2);
      if (deadlineCut.snapshot.run.status === 'failed') break;
      assert.equal(deadlineCut.snapshot.run.status, 'queued');
      await observeQueuedImages(deadlineCut);
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
    assert(queuedImageObservations > 0, 'ordinary queued launcher ownership must be observed before its real deadline');
    report.queuedDeadline = { qualified: true, scope: 'capacity-blocked queued Run only; not a live-worker deadline cut',
      runId: queuedAdmitted.id, status: 'failed', terminalReason: 'budget_exhausted', wallTimeMs: 3000,
      stopIntentRef: deadlineCut.snapshot.run.stopIntentRef, terminalDetailRef: deadlineCut.snapshot.run.terminalDetailRef,
      attachedHighWater: queuedEvents.highWaterEventSeq, completeEventHistoryChecked: true,
      launcherImageObservation: { diagnosticOnly: true, sameOriginalSupervisor: true,
        ordinaryQueuedObservations: queuedImageObservations, originalRetainedImages: queuedImagesBefore.length,
        noAdditionalLauncherImagesAtObservedQueuedCuts: true, stopCleanupNotGated: true },
      noWorkerActivated: true, noInvocationPrepared: true, noProviderRequest: true, zeroCharged: true, noResultPublished: true };
    await queuedObserverClient.close(); queuedObserverClient = undefined;
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
    mark('closed_broker_unknown_after_restart_cancel');
    // This broker already joined after the genuine reflection refusal. The
    // existing real restart tests historical domain closure, not a live POST
    // producer crash; that different physical cut remains unqualified.
    const domainReport = report.closedBrokerProcessDomainDeath = { qualified: false,
      scope: 'already-closed native broker unknown, real Supervisor restart and public terminal cancellation only',
      livePostCrashQualified: false, cancelAccepted: false, terminalObserved: false, terminalWaitExpired: false,
      lastPublicCut: projectInstalledRunProgress(retainedUnknown, { requestsReceived, providerFailure }) };
    const beforeDomainSession = currentSession();
    const beforeDomain = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }])[0]!, 'run.get');
    assert.deepEqual(beforeDomain, retainedUnknown); assert.equal(requestsReceived, 4); assert(!providerFailure);
    assert.equal(beforeDomain.nextJournalSeq, beforeDomain.highWaterJournalSeq);
    assert.equal(beforeDomain.nextItemSeq, beforeDomain.highWaterItemSeq);
    assert.equal(beforeDomain.nextCheckpointCursor, beforeDomain.highWaterCheckpointCursor);
    const beforeDomainEvents = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: reflectionAdmitted.id,
      afterEventSeq: 0 }])[0]!, 'run.attach');
    assert.equal(beforeDomainEvents.earliestRetainedEventSeq, 1);
    assert.equal(beforeDomainEvents.nextEventSeq, beforeDomainEvents.highWaterEventSeq);
    assert.equal(beforeDomainEvents.events.length, beforeDomainEvents.highWaterEventSeq);
    for (let index = 0; index < beforeDomainEvents.events.length; index++) assert.equal(beforeDomainEvents.events[index].eventSeq, index + 1);
    const currentDomainSupervisor = show(services.supervisorUnit);
    assert.equal(currentDomainSupervisor.MainPID, afterUnknownSupervisor.MainPID);
    assert.equal(currentDomainSupervisor.InvocationID, afterUnknownSupervisor.InvocationID);
    const currentDomainStart = await fixtureProcess(Number(currentDomainSupervisor.MainPID), ledger.uid);
    assert.equal(await readlink(`/proc/${currentDomainSupervisor.MainPID}/exe`), successorImagePath);
    const domainCancel = request({ protocolVersion: 1, method: 'run.cancel', requestId: '019a0012-0000-7000-8000-000000000125',
      runId: reflectionAdmitted.id, expectedRevision: beforeDomain.snapshot.run.revision });
    const domainBy = Date.now() + 15000;
    const domainRemaining = () => {
      const remaining = domainBy - Date.now();
      if (remaining <= 0) { domainReport.terminalWaitExpired = true; assert.fail('closed broker unknown did not reach proof-backed terminal cancellation within 15 seconds'); }
      return remaining;
    };
    domainRemaining();
    const domainCancelReply = exchange([domainCancel], 0, 5000)[0]!;
    domainRemaining();
    const domainAcknowledged = accepted(domainCancelReply, 'run.cancel').snapshot.run;
    domainReport.cancelAccepted = true;
    assert.equal(domainAcknowledged.cancelRequested, true); assert.equal(domainAcknowledged.id, reflectionAdmitted.id);
    assert.equal(domainAcknowledged.revision, beforeDomain.snapshot.run.revision + 1);
    mark('closed_broker_unknown_after_restart_wait_terminal');
    let domainTerminal: Record<string, any>;
    for (;;) {
      await delay(Math.min(50, domainRemaining()));
      domainRemaining();
      // Keep the original 15-second observation deadline. A last-millisecond
      // fork must still join; its separate bounded RPC time is not permission
      // to accept a late terminal result, which domainRemaining below rejects.
      domainTerminal = accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }], 0, 5000)[0]!, 'run.get');
      domainReport.lastPublicCut = projectInstalledRunProgress(domainTerminal, { requestsReceived, providerFailure });
      report.lastPublicCut = domainReport.lastPublicCut;
      assert.equal(requestsReceived, 4); assert(!providerFailure);
      assert.deepEqual(domainTerminal.journal, beforeDomain.journal); assert.deepEqual(domainTerminal.items, beforeDomain.items);
      assert.deepEqual(domainTerminal.snapshot.run.budgetConsumed, beforeDomain.snapshot.run.budgetConsumed);
      assert.deepEqual(domainTerminal.snapshot.run.budgetReserved, beforeDomain.snapshot.run.budgetReserved);
      assert.equal(domainTerminal.snapshot.run.resultRef, undefined); assert.equal(domainTerminal.snapshot.run.activeWorkerLaunchId, undefined);
      assert.equal(domainTerminal.snapshot.run.leaseEpoch, beforeDomain.snapshot.run.leaseEpoch);
      assert.equal(domainTerminal.snapshot.run.stopIntentRef, domainAcknowledged.stopIntentRef);
      domainRemaining();
      if (domainTerminal.snapshot.run.status === 'cancelled') break;
    }
    domainReport.terminalObserved = true;
    assert.equal(domainTerminal.nextCheckpointCursor, domainTerminal.highWaterCheckpointCursor);
    const domainRun = domainTerminal.snapshot.run;
    assert.equal(domainRun.terminalReason, 'cancelled_by_user'); assert.equal(domainRun.cancelRequested, true);
    assert.equal(domainRun.revision, domainAcknowledged.revision + 1); assert.equal(domainRun.nextStep, null);
    assert.equal(domainRun.frontierRef, undefined); assert.equal(domainRun.waitingReason, undefined); assert.equal(domainRun.waitingOnRef, undefined);
    const domainIntent = parseJsonStrict((await readCas(domainRun.stopIntentRef)).toString('utf8')) as Record<string, any>;
    assert.equal(domainIntent.origin, 'user_cancel'); assert.equal(domainIntent.requestId, domainCancel.requestId);
    assert.equal(domainIntent.runId, reflectionAdmitted.id); assert.equal(domainIntent.reason, 'cancelled_by_user');
    const domainDetail = parseJsonStrict((await readCas(domainRun.terminalDetailRef)).toString('utf8')) as Record<string, any>;
    assert.deepEqual(Object.keys(domainDetail).sort(), ['schemaVersion', 'runId', 'reason', 'reasonDetail', 'primaryEvidenceRef',
      'publicationResultItemRefs', 'abandonedRetryInvocations', 'createdAt'].sort());
    assert.equal(domainDetail.schemaVersion, 1); assert.equal(domainDetail.runId, reflectionAdmitted.id);
    assert.equal(domainDetail.reason, 'cancelled_by_user'); assert.equal(domainDetail.primaryEvidenceRef, domainRun.stopIntentRef);
    assert.equal(canonicalSha256(domainDetail.reasonDetail), canonicalSha256({ kind: 'cancelled', stopIntentRef: domainRun.stopIntentRef }));
    assert.deepEqual(domainDetail.publicationResultItemRefs, []); assert.equal(domainDetail.abandonedRetryInvocations.length, 1);
    const abandoned = domainDetail.abandonedRetryInvocations[0];
    assert.deepEqual(Object.keys(abandoned).sort(), ['opId', 'attempt', 'unknownJournalSeq', 'budgetSettlementRef', 'dispatchFenceOrDeathEvidenceRef'].sort());
    assert.equal(abandoned.opId, ambiguityEntry.opId); assert.equal(abandoned.attempt, ambiguityEntry.attempt);
    assert.equal(abandoned.unknownJournalSeq, ambiguityEntry.seq); assert.equal(abandoned.budgetSettlementRef, ambiguityEntry.budgetSettlementRef);
    const dispatchClosure = decodeBrokerProcessDomainDeathDispatchClosure(parseJsonStrict((await readCas(abandoned.dispatchFenceOrDeathEvidenceRef)).toString('utf8')));
    assert.equal(dispatchClosure.runId, reflectionAdmitted.id); assert.equal(dispatchClosure.opId, ambiguityEntry.opId);
    assert.equal(dispatchClosure.attempt, ambiguityEntry.attempt); assert.equal(dispatchClosure.dispatchId, ambiguityEntry.dispatchId);
    assert.equal(dispatchClosure.unknownJournalSeq, ambiguityEntry.seq);
    const domainDeath = decodeBrokerProcessDomainDeath(parseJsonStrict((await readCas(dispatchClosure.closure.brokerProcessDeathEvidenceRef)).toString('utf8')));
    assert.equal(domainDeath.evidenceDigest, dispatchClosure.closure.brokerProcessDeathEvidenceDigest);
    const originalClaim = refused.journal[1], originalPrepared = refused.journal[0];
    assert.equal(domainDeath.runId, reflectionAdmitted.id); assert.equal(domainDeath.opId, originalClaim.opId);
    assert.equal(domainDeath.attempt, originalClaim.attempt); assert.equal(domainDeath.dispatchId, originalClaim.dispatchId);
    assert.equal(domainDeath.dispatchJournalSeq, originalClaim.seq); assert.equal(domainDeath.operationRequestRef, originalClaim.requestRef);
    assert.equal(domainDeath.operationGrantRef, originalClaim.grantRef); assert.equal(domainDeath.operationTargetDigest, ambiguity.operationTargetDigest);
    assert.equal(domainDeath.claimingSupervisorInstanceId, originalClaim.supervisorInstanceId);
    assert.equal(domainDeath.claimingSupervisorInstanceId, successorStatus.supervisorInstanceId);
    assert.equal(domainDeath.claimingStateOwnerEpoch, originalClaim.stateOwnerEpoch);
    assert.equal(domainDeath.brokerFenceTokenDigest, originalClaim.brokerFenceTokenDigest);
    const originalInspector = parseJsonStrict((await readCas(ambiguity.inspectorIdentityRef)).toString('utf8')) as Record<string, any>;
    assert.equal(originalInspector.identityDigest, ambiguity.inspectorIdentityDigest);
    assert.equal(originalInspector.identityDigest, digestOmitting(originalInspector, 'identityDigest'));
    assert.equal(originalInspector.stateOwnerEpoch, originalClaim.stateOwnerEpoch);
    assert.equal(originalInspector.supervisorInstanceId, originalClaim.supervisorInstanceId);
    assert.equal(domainDeath.claimingProcessIdentityRef, originalInspector.processIdentityRef);
    assert.equal(domainDeath.claimingProcessIdentityDigest, originalInspector.processIdentityDigest);
    const claimingProcess = parseJsonStrict((await readCas(domainDeath.claimingProcessIdentityRef)).toString('utf8')) as Record<string, any>;
    assert.equal(claimingProcess.format, 'cliq-platform-process-identity-v1'); assert.equal(claimingProcess.platform, 'linux');
    assert.equal(claimingProcess.identityDigest, domainDeath.claimingProcessIdentityDigest);
    assert.equal(claimingProcess.identityDigest, digestOmitting(claimingProcess, 'identityDigest'));
    assert.equal(claimingProcess.pid, Number(successor.MainPID)); assert.equal(claimingProcess.processStartToken, `linux-proc-start-ticks:${successorStart}`);
    assert.equal(claimingProcess.ownerUid, ledger.uid); assert.equal(claimingProcess.executableImageDigest, report.bundle.supervisorDigest);
    let retainedProcessStart: string | undefined;
    try { retainedProcessStart = `linux-proc-start-ticks:${await processStart(claimingProcess.pid)}`; }
    catch (error) { assert.equal((error as NodeJS.ErrnoException).code, 'ENOENT'); }
    assert.notEqual(retainedProcessStart, claimingProcess.processStartToken, 'original broker process lifetime must be gone');
    const domainInspector = parseJsonStrict((await readCas(domainDeath.inspectorIdentityRef)).toString('utf8')) as Record<string, any>;
    assert.equal(domainInspector.identityDigest, domainDeath.inspectorIdentityDigest);
    assert.equal(domainInspector.identityDigest, digestOmitting(domainInspector, 'identityDigest'));
    assert.equal(domainInspector.stateOwnerEpoch, domainDeath.inspectorStateOwnerEpoch);
    assert(domainInspector.stateOwnerEpoch > originalClaim.stateOwnerEpoch);
    const domainStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.equal(domainInspector.supervisorInstanceId, domainStatus.supervisorInstanceId);
    assert.equal(domainInspector.supervisorInstanceId, historicalStatus.supervisorInstanceId);
    for (const inspector of [originalInspector, domainInspector]) {
      assert.equal(inspector.runtimeBundleRef, bundleDigest); assert.equal(inspector.runtimeBundleManifestDigest, signed.bundle.manifestDigest);
    }
    assert.equal(domainInspector.stateLockIdentityRef, originalInspector.stateLockIdentityRef);
    assert.equal(domainInspector.stateLockIdentityDigest, originalInspector.stateLockIdentityDigest);
    const inspectingProcess = parseJsonStrict((await readCas(domainInspector.processIdentityRef)).toString('utf8')) as Record<string, any>;
    assert.equal(inspectingProcess.identityDigest, domainInspector.processIdentityDigest);
    assert.equal(inspectingProcess.identityDigest, digestOmitting(inspectingProcess, 'identityDigest'));
    assert.equal(inspectingProcess.pid, Number(currentDomainSupervisor.MainPID)); assert.equal(inspectingProcess.processStartToken, `linux-proc-start-ticks:${currentDomainStart}`);
    assert.equal(inspectingProcess.ownerUid, ledger.uid); assert.equal(inspectingProcess.executableImageDigest, report.bundle.supervisorDigest);
    assert.equal(await fixtureProcess(Number(currentDomainSupervisor.MainPID), ledger.uid), currentDomainStart);
    const domainSpec = parseJsonStrict((await readCas(domainRun.specRef)).toString('utf8')) as Record<string, any>;
    const domainAssembly = parseJsonStrict((await readCas(domainSpec.assemblyRef)).toString('utf8')) as Record<string, any>;
    assert.equal(domainAssembly.runtime.runtimeBundleRef, bundleDigest); assert.equal(domainAssembly.runtime.runtimeBundleManifestDigest, signed.bundle.manifestDigest);
    assert.equal(domainAssembly.provider.adapter.adapterId, 'openai-compatible-broker-v1'); assert.equal(domainAssembly.provider.adapter.version, '1');
    assert.equal(domainAssembly.provider.adapter.codeDigest, report.bundle.brokerDigest);
    const unknownSettlement = parseJsonStrict((await readCas(ambiguityEntry.budgetSettlementRef)).toString('utf8')) as Record<string, any>;
    assert.equal(unknownSettlement.settlementDigest, digestOmitting(unknownSettlement, 'settlementDigest'));
    assert.equal(unknownSettlement.runId, reflectionAdmitted.id); assert.equal(unknownSettlement.opId, originalClaim.opId);
    assert.equal(unknownSettlement.attempt, originalClaim.attempt); assert.equal(unknownSettlement.preparedJournalSeq, originalPrepared.seq);
    assert.equal(unknownSettlement.terminalJournalSeq, ambiguityEntry.seq); assert.equal(unknownSettlement.terminalPhase, 'unknown');
    for (const usage of [unknownSettlement.reserved, unknownSettlement.released, unknownSettlement.consumed]) assert.deepEqual(usage, originalPrepared.budgetDelta);
    assert(domainDeath.observedAt >= ambiguityEntry.timestamp && domainDeath.observedAt >= domainInspector.activatedAt);
    assert(domainDeath.observedAt <= dispatchClosure.observedAt && dispatchClosure.observedAt <= domainDetail.createdAt);
    assert(domainDetail.createdAt <= domainRun.updatedAt && Date.parse(domainRun.updatedAt) - Date.parse(domainDeath.observedAt) <= 5000);
    const addedDomainCheckpoints = domainTerminal.checkpoints.filter((checkpoint: any) =>
      !beforeDomain.checkpoints.some((previous: any) => previous.id === checkpoint.id));
    assert.equal(addedDomainCheckpoints.length, 1); assert.equal(domainTerminal.checkpoints.length, beforeDomain.checkpoints.length + 1);
    const domainCheckpoint = addedDomainCheckpoints[0];
    assert.equal(domainCheckpoint.id, domainRun.latestCheckpointId);
    assert.equal(domainCheckpoint.id, identityHash('cliq-stop-checkpoint-v1', reflectionAdmitted.id, domainRun.stopIntentRef));
    assert.equal(domainCheckpoint.createdAt, domainRun.updatedAt); assert.equal(domainCheckpoint.basedOnRunRevision, domainRun.revision - 1);
    assert.equal(domainCheckpoint.journalSeq, domainTerminal.highWaterJournalSeq); assert.equal(domainCheckpoint.runItemSeq, domainTerminal.highWaterItemSeq);
    assert.equal(domainCheckpoint.workspaceStateRef, beforeDomain.checkpoints.find((checkpoint: any) => checkpoint.id === beforeDomain.snapshot.run.latestCheckpointId)!.workspaceStateRef);
    for (const checkpoint of beforeDomain.checkpoints) assert.deepEqual(domainTerminal.checkpoints.find((candidate: any) => candidate.id === checkpoint.id), checkpoint);
    const afterDomainSession = accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
      afterItemSeq: beforeDomainSession.latestItemSeq }])[0]!, 'session.get');
    assert.equal(afterDomainSession.snapshot.session.contextRevision, beforeDomainSession.contextRevision + 1);
    assert.equal(afterDomainSession.snapshot.session.latestItemSeq, beforeDomainSession.latestItemSeq + 1); assert.equal(afterDomainSession.items.length, 1);
    assert.equal(afterDomainSession.nextItemSeq, afterDomainSession.highWaterItemSeq);
    assert.equal(afterDomainSession.highWaterItemSeq, afterDomainSession.snapshot.session.latestItemSeq);
    const domainSessionItem = afterDomainSession.items[0];
    assert.equal(domainSessionItem.kind, 'run_terminal'); assert.equal(domainSessionItem.itemSeq, beforeDomainSession.latestItemSeq + 1);
    const domainAdmittedContext = parseJsonStrict((await readCas(domainSpec.admittedContextRef)).toString('utf8')) as Record<string, any>;
    const domainPublication = parseJsonStrict((await readCas(domainSessionItem.payloadRef)).toString('utf8')) as Record<string, any>;
    assert.equal(canonicalSha256(domainPublication), canonicalSha256({ schemaVersion: 1, format: 'cliq-session-run-terminal-v1', kind: 'run_terminal',
      itemKey: `run-terminal:${reflectionAdmitted.id}`, runId: reflectionAdmitted.id, operation: 'agent',
      admittedSessionItemSeq: domainAdmittedContext.throughSessionItemSeq, status: 'cancelled', terminalReason: 'cancelled_by_user', terminalDetailRef: domainRun.terminalDetailRef }));
    const domainEvents = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: reflectionAdmitted.id,
      afterEventSeq: beforeDomainEvents.nextEventSeq }])[0]!, 'run.attach');
    assert.equal(domainEvents.nextEventSeq, domainEvents.highWaterEventSeq);
    assert.equal(domainEvents.events.length, domainEvents.highWaterEventSeq - beforeDomainEvents.nextEventSeq);
    for (let index = 0; index < domainEvents.events.length; index++) assert.equal(domainEvents.events[index].eventSeq, beforeDomainEvents.nextEventSeq + index + 1);
    const terminalEvents = [...beforeDomainEvents.events, ...domainEvents.events].filter((event: any) => event.kind === 'state_changed' && event.status === 'cancelled');
    assert.equal(terminalEvents.length, 1); assert.equal(terminalEvents[0].runRevision, domainRun.revision);
    assert.equal(terminalEvents[0].terminalDetailRef, domainRun.terminalDetailRef);
    assert.deepEqual(exchange([domainCancel])[0], domainCancelReply);
    assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }])[0]!, 'run.get'), domainTerminal);
    assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
      afterItemSeq: beforeDomainSession.latestItemSeq }])[0]!, 'session.get'), afterDomainSession);
    const domainEmptyEvents = accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: reflectionAdmitted.id,
      afterEventSeq: domainEvents.nextEventSeq }])[0]!, 'run.attach');
    assert.deepEqual(domainEmptyEvents.events, []); assert.equal(domainEmptyEvents.nextEventSeq, domainEvents.nextEventSeq);
    assert.equal(domainEmptyEvents.highWaterEventSeq, domainEvents.highWaterEventSeq); assert.equal(requestsReceived, 4); assert(!providerFailure);
    const unchangedDomainSupervisor = show(services.supervisorUnit);
    assert.equal(unchangedDomainSupervisor.MainPID, currentDomainSupervisor.MainPID);
    assert.equal(unchangedDomainSupervisor.InvocationID, currentDomainSupervisor.InvocationID);
    mark('closed_broker_terminal_history_after_actual_supervisor_restart');
    const terminalRestart = command('/usr/bin/systemctl', ['--user', 'restart', services.supervisorUnit], undefined, 30000);
    assert.equal(terminalRestart.status, 0);
    const terminalHistoryBy = Date.now() + 30000;
    const terminalHistorySupervisor = show(services.supervisorUnit), terminalHistoryKeeper = show(services.keeperUnit);
    assert.equal(terminalHistorySupervisor.ActiveState, 'active');
    assert.equal(terminalHistorySupervisor.MainPID, terminalHistorySupervisor.ExecMainPID);
    assert.notEqual(terminalHistorySupervisor.MainPID, currentDomainSupervisor.MainPID);
    assert.notEqual(terminalHistorySupervisor.InvocationID, currentDomainSupervisor.InvocationID);
    assert.equal(terminalHistoryKeeper.MainPID, keeperBefore.MainPID);
    assert.equal(terminalHistoryKeeper.InvocationID, keeperBefore.InvocationID);
    assert.deepEqual(await readFile(path.join(recipe.stateRoot, 'runtime/keeper.ready')), keeperReady);
    const terminalHistoryStart = await selectedSupervisor(services.supervisorUnit, terminalHistorySupervisor, successorImagePath, terminalHistoryBy);
    const terminalHistoryStatus = accepted(exchange([{ protocolVersion: 1, method: 'supervisor.status' }])[0]!, 'supervisor.status');
    assert.notEqual(terminalHistoryStatus.supervisorInstanceId, domainInspector.supervisorInstanceId);
    // Historical recovery must retain the THEN-inspector and original charge,
    // not substitute this new live owner or demand a new observation clock.
    assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'run.get', runId: reflectionAdmitted.id }])[0]!, 'run.get'), domainTerminal);
    assert.deepEqual(exchange([domainCancel])[0], domainCancelReply);
    assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'session.get', sessionId: session.id,
      afterItemSeq: beforeDomainSession.latestItemSeq }])[0]!, 'session.get'), afterDomainSession);
    assert.deepEqual(accepted(exchange([{ protocolVersion: 1, method: 'run.attach', runId: reflectionAdmitted.id,
      afterEventSeq: domainEvents.nextEventSeq }])[0]!, 'run.attach'), domainEmptyEvents);
    assert.equal(requestsReceived, 4); assert(!providerFailure);
    assert.equal(await fixtureProcess(Number(terminalHistorySupervisor.MainPID), ledger.uid), terminalHistoryStart);
    assert.equal(await readlink(`/proc/${terminalHistorySupervisor.MainPID}/exe`), successorImagePath);
    assert(Date.now() < terminalHistoryBy, 'terminal history did not revalidate within the original restart budget');
    report.closedBrokerProcessDomainDeath = { ...domainReport, qualified: true, immutableUnknownAndFullChargePreserved: true,
      originalClaimProcessMatched: true, strictlyNewerSameSignedRuntimeInspectorMatched: true, providerRedispatches: 0,
      dispatchClosureRef: abandoned.dispatchFenceOrDeathEvidenceRef, processDeathEvidenceRef: dispatchClosure.closure.brokerProcessDeathEvidenceRef,
      processDeathEvidenceDigest: domainDeath.evidenceDigest, terminalCheckpointPublishedOnce: true, sessionPublishedOnce: true,
      cancelReplayPreserved: true, contiguousAttachPreserved: true, noResultPublished: true,
      terminalHistoryReopenedAfterActualSupervisorRestart: true };
    }
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
    // Restore the one original held CAS inode before any production writer,
    // credential daemon, bounded volume or fixture cleanup can run.
    try { await restoreCasWrite?.(); } catch (error) { cleanupFailures.push(error); }
    try { await restoreRetryAlias(); } catch (error) { cleanupFailures.push(error); }
    try {
      if (server) {
        server.closeAllConnections(); await bounded(new Promise<void>(resolve => server!.close(() => resolve())), 10000, 'owned HTTPS fixture did not close');
        await bounded(Promise.all(socketClosures), 10000, 'owned TLS sockets did not close'); report.httpsJoined = true;
      }
    } catch (error) { cleanupFailures.push(error); }
    try { await storageClient?.close(); } catch (error) { cleanupFailures.push(error); }
    try { await queuedObserverClient?.close(); } catch (error) { cleanupFailures.push(error); }
    try { await shutdownClient?.close(); } catch (error) { cleanupFailures.push(error); }
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
          if (stoppedUnits[0]!.Result !== 'success' || stoppedUnits[0]!.ExecMainStatus !== '0')
            report.shutdownRefusal = observeShutdownRefusal(installedServices!.supervisorUnit, stoppedUnits[0]!.ExecMainPID);
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
assert(mode === '--campaign' || mode === '--failure-campaign' || mode === '--retry-campaign' || mode === '--authority-failure-campaign' ||
  mode === '--storage-failure-campaign' || mode === '--shutdown-admission-campaign' || mode === '--shutdown-session-campaign' || mode === '--shutdown-preparation-campaign' ||
  mode === '--shutdown-received-tool-campaign' || mode === '--shutdown-pending-model-campaign' || mode === '--shutdown-startup-campaign'); assert(filename && extra.length === 0);
await campaign(filename, mode);
