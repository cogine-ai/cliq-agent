// Real ordinary UDS and a separate Node client, not native/authentication or
// installed-Supervisor qualification. Execute the journey's exact inline code.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import { tsImport } from 'tsx/esm/api';

const { InstalledClientConsumerDeadlineError, InstalledClientDriverError } =
  await tsImport('./installed-client-consumer.ts', import.meta.url);
const { canonicalSha256 } = await tsImport('../../../src/kernel/canonical.ts', import.meta.url);

const source = readFileSync(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
const literal = /^const clientScript = (`[\s\S]*?`);/mu.exec(source)?.[1]; assert(literal);
const clientScript = vm.runInNewContext(literal); assert.equal(typeof clientScript, 'string');
const persistentLiteral = /^const persistentClientScript = (`[\s\S]*?`);/mu.exec(source)?.[1]; assert(persistentLiteral);
const persistentClientScript = vm.runInNewContext(persistentLiteral); assert.equal(typeof persistentClientScript, 'string');
const hello = { protocolVersion: 1, method: 'control.hello' };
const mutation = { protocolVersion: 1, method: 'run.submit', requestId: 'test-request-once' };
const helloReply = JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'control.hello', supervisorInstanceId: 'fixture-owner' } });

test('stop diagnosis retains only fixed phases and bounded counts, never journal text or execution evidence', () => {
  // Journal output is ordinary untrusted input here. This parser regression
  // neither stops a service nor qualifies an actual installed lifecycle.
  const start = source.indexOf('  const observeShutdownRefusal = '), end = source.indexOf('\n  const observe =', start);
  assert(start >= 0 && end > start);
  const code = ts.transpileModule(source.slice(start, end) + '\nglobalThis.inspectStop = observeShutdownRefusal;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const counters = { driverTasks: 1, agentLoads: 0, admissions: 0, modelOperations: 0, modelCompletions: 0, modelClosures: 0 };
  const valid = { diagnosticOnly: true, scope: 'installed-shutdown-progress', phases: { result_recovery: 1 }, ...counters };
  const recovery = { ...valid, phases: Object.fromEntries(['spec', 'context', 'journal', 'generations', 'history', 'history_model',
    'history_items', 'history_candidate', 'history_verifier', 'history_tool', 'history_input', 'history_broker', 'seals', 'terminal']
    .map(stage => [`result_recovery_${stage}`, 1])) };
  Object.assign(recovery.phases, Object.fromEntries(['history', 'quarantine_closure', 'native_retirement',
    'workspace_observation', 'retirement_commit', 'resource_join'].map(stage => [`drive_retirement_${stage}`, 1])));
  const untrusted = [valid, { ...valid, phases: { arbitrary_payload: 1 } }, { ...valid, driverTasks: 1001 },
    { ...valid, phases: { result_commit: -1 } }, { ...valid, modelClosures: '1' },
    { ...valid, phases: { result_recovery_history_unknown: 1 } },
    { ...valid, phases: { drive_retirement_unknown: 1 } }, recovery];
  let scans = 0, calls = 0;
  const context = { Buffer, ledger: { uid: 12345 }, environment: {}, parseJsonStrict: JSON.parse,
    scanBytes: bytes => { assert(Buffer.isBuffer(bytes)); scans++; },
    spawnSync: () => { calls++; return { status: 0, signal: null,
      stdout: Buffer.from(untrusted.map(value => JSON.stringify({ ...value, message: 'do-not-retain-this-content' })).join('\n')),
      stderr: Buffer.alloc(0) }; } };
  vm.runInNewContext(code, context);
  const result = JSON.parse(JSON.stringify(context.inspectStop('owned.service', '123')));
  assert.deepEqual(result, { diagnosticOnly: true, available: true, refusals: [],
    progress: [{ phases: { result_recovery: 1 }, ...counters }, { phases: recovery.phases, ...counters }] });
  assert.equal(JSON.stringify(result).includes('do-not-retain-this-content'), false);
  assert.equal(calls, 1); assert.equal(scans, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(context.inspectStop('owned.service', 'untrusted-pid'))),
    { diagnosticOnly: true, available: false });
  assert.equal(calls, 1);
});

test('retirement diagnosis invokes only an inert guarded observer at fixed await boundaries', () => {
  // This exercises the production note's exact source, not a native/Run proof.
  const execution = readFileSync(new URL('../../../src/state/run-execution.ts', import.meta.url), 'utf8');
  const note = /^  const retirementPhase = .*;$/mu.exec(execution)?.[0]; assert(note, 'production retirement note must exist');
  const code = ts.transpileModule(note + '\nglobalThis.note = retirementPhase;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const phases = ['history', 'quarantine_closure', 'native_retirement', 'workspace_observation', 'retirement_commit', 'resource_join'];
  const observed = [];
  const context = { onRetirementPhase: phase => { observed.push(phase); throw phase; } };
  vm.runInNewContext(code, context);
  for (const phase of phases) assert.doesNotThrow(() => context.note(phase));
  assert.deepEqual(observed, phases);
  for (const failure of [undefined, null, new Error('observer only'), Symbol('observer only'), {}]) {
    const throwing = { onRetirementPhase: () => { throw failure; } };
    vm.runInNewContext(code, throwing);
    assert.doesNotThrow(() => throwing.note('history'));
  }
  const absent = {}; vm.runInNewContext(code, absent);
  assert.doesNotThrow(() => absent.note('history'));
  const start = execution.indexOf('    resumeCurrentRetirement: async value => {');
  const end = execution.indexOf('\n    ', execution.indexOf('      return ownOperation(work, abort, true);', start) + 1);
  assert(start >= 0 && end > start);
  const resume = execution.slice(start, end);
  assert.deepEqual([...resume.matchAll(/retirementPhase\('([^']+)'\)/gu)].map(match => match[1]),
    ['history', 'quarantine_closure', 'native_retirement', 'workspace_observation', 'retirement_commit', 'resource_join', 'history']);
  for (const [phase, awaited] of [['history', 'readRecoveryClosure'], ['quarantine_closure', 'readQuarantinedWorkerLaunchClosure'],
    ['native_retirement', 'launcher.startController'], ['workspace_observation', 'observeRetainedRunWorkspace'],
    ['retirement_commit', 'retireQuarantinedGeneration'], ['resource_join', 'retireWorkerResources']])
    assert.match(resume, new RegExp(`retirementPhase\\('${phase}'\\);\\s+(?:const [^=]+ = |let cut = |cut = |controller = )?await ${awaited.replace('.', '\\.')}`));
});
// Observation only: preserve and return the real Socket. This lets the parent
// wait for an actual pre-connect kernel error before publishing the listener.
const observeConnect = `import clientProbeNet from 'node:net';
const clientProbeConnect=clientProbeNet.createConnection;
clientProbeNet.createConnection=function(...args){const socket=clientProbeConnect.apply(this,args);
socket.once('error',error=>process.stderr.write('client-connect-observation:'+error.code+'\\n'));return socket;};\n`;

async function fixture(t) {
  const directory = await mkdtemp('/tmp/cliq-run-client-'), socketPath = path.join(directory, 'control.sock');
  const sockets = new Set(), children = new Set(); let server;
  const requests = []; let connections = 0, closedConnections = 0;
  async function listen(onRequest) {
    assert.equal(server, undefined);
    server = net.createServer(socket => {
      connections++; sockets.add(socket); socket.once('close', () => { sockets.delete(socket); closedConnections++; });
      socket.on('error', () => {});
      let input = Buffer.alloc(0);
      socket.on('data', chunk => {
        input = Buffer.concat([input, chunk]); assert(input.length <= 1048580);
        while (input.length >= 4) {
          const size = input.readUInt32BE(0); assert(size >= 1 && size <= 1048576);
          if (input.length < size + 4) break;
          const request = JSON.parse(input.subarray(4, size + 4).toString('utf8'));
          input = input.subarray(size + 4); requests.push(request); onRequest(socket, request);
        }
      });
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  }
  function client(entries = [hello], connectBy = 0) {
    const encoded = Buffer.from(JSON.stringify(entries.map(value => Buffer.from(JSON.stringify(value)).toString('base64url')))).toString('base64url');
    const child = spawn(process.execPath, ['--input-type=module', '-e', observeConnect + clientScript,
      socketPath, encoded, String(connectBy)], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.add(child);
    let stdout = '', stderr = '', observed = false, resolveObserved, rejectObserved;
    const firstConnectFailure = new Promise((resolve, reject) => { resolveObserved = resolve; rejectObserved = reject; });
    // Some tests need only the result; keep an early close from becoming an
    // unhandled rejection while retaining the observation for tests that do.
    void firstConnectFailure.catch(() => {});
    child.stdout.on('data', bytes => { stdout += bytes.toString('utf8'); assert(stdout.length <= 65536); });
    child.stderr.on('data', bytes => {
      stderr += bytes.toString('utf8'); assert(stderr.length <= 65536);
      if (!observed && /client-connect-observation:(ENOENT|ECONNREFUSED)\n/u.test(stderr)) { observed = true; resolveObserved(); }
    });
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    const result = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => {
        clearTimeout(timer); children.delete(child);
        if (!observed) rejectObserved(new Error('client exited without a pre-connect observation'));
        resolve({ code, signal, stdout, stderr });
      });
    });
    return { result, firstConnectFailure };
  }
  function persistent(requireLiveClose = false) {
    const child = spawn(process.execPath, ['--input-type=module', '-e', persistentClientScript, socketPath,
      ...(requireLiveClose ? ['live-close'] : [])],
      { stdio: ['pipe', 'pipe', 'pipe'] });
    children.add(child);
    let stdout = '', stderr = '', waiting;
    const lines = [];
    child.stdout.on('data', bytes => {
      stdout += bytes.toString('utf8'); assert(stdout.length <= 65536);
      for (;;) {
        const at = stdout.indexOf('\n'); if (at < 0) break;
        const line = stdout.slice(0, at); stdout = stdout.slice(at + 1);
        if (waiting) { const resolve = waiting; waiting = undefined; resolve(line); }
        else lines.push(line);
      }
    });
    child.stderr.on('data', bytes => { stderr += bytes.toString('utf8'); assert(stderr.length <= 65536); });
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    const result = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => {
        clearTimeout(timer); children.delete(child); resolve({ code, signal, stderr });
      });
    });
    const line = async () => {
      if (lines.length) return lines.shift();
      assert(!waiting); return Promise.race([new Promise(resolve => { waiting = resolve; }),
        result.then(() => { throw new Error('persistent client exited before its next line'); })]);
    };
    return { child, result, line };
  }
  t.after(async () => {
    const joins = [...children].map(child => new Promise(resolve => { child.once('close', resolve); child.kill('SIGKILL'); }));
    await Promise.all(joins);
    for (const socket of sockets) socket.destroy();
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await rm(directory, { recursive: true, force: true });
  });
  return { listen, client, persistent, requests, get connections() { return connections; },
    get closedConnections() { return closedConnections; } };
}

function respond(socket, text = helloReply) {
  const body = Buffer.from(text), header = Buffer.alloc(4); header.writeUInt32BE(body.length);
  socket.write(Buffer.concat([header, body]));
}

test('admission absence inspection uses its independent prewarmed socket while the original mutation remains pending', { timeout: 10000 }, async t => {
  // Ordinary UDS/process orchestration only: no installed identity, held
  // instruction descriptor, admission authority or signal cut is fabricated.
  const value = await fixture(t), readAdmission = { protocolVersion: 1, method: 'run.get', runId: 'data-only-admission' };
  const absent = { protocolVersion: 1, ok: false, method: 'run.get', error: { schemaVersion: 1,
    code: 'NOT_FOUND', retryable: false, messageCode: 'control.read_rejected' } };
  let reply = absent, originalSocket, enteredResolve;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  await value.listen((socket, request) => {
    if (request.method === 'control.hello') respond(socket);
    else if (request.method === 'run.submit') { originalSocket = socket; enteredResolve(); }
    else { assert.equal(request.method, 'run.get'); respond(socket, JSON.stringify(reply)); }
  });
  const inspector = value.persistent(); assert.equal(await inspector.line(), 'connected');
  inspector.child.stdin.write(`${JSON.stringify(hello)}\n`); assert.equal(JSON.parse(await inspector.line()), helloReply);
  const original = value.persistent(); assert.equal(await original.line(), 'connected');
  original.child.stdin.write(`${JSON.stringify(hello)}\n`); assert.equal(JSON.parse(await original.line()), helloReply);
  original.child.stdin.write(`${JSON.stringify(mutation)}\n`); await entered;
  const expression = /      const assertAbsent = ([^\n]+);/u.exec(source)?.[1]; assert(expression);
  const code = ts.transpileModule(`globalThis.check = ${expression};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const context = { assert, canonicalSha256, readAdmission, absent,
    exchange() { assert.fail('the resource cut must not start another throwaway client'); },
    shutdownAdmissionInspector: { async send(request, timeout) {
      assert.deepEqual(request, readAdmission); assert.equal(timeout, 30000);
      inspector.child.stdin.write(`${JSON.stringify(request)}\n`); return JSON.parse(JSON.parse(await inspector.line()));
    } } };
  vm.createContext(context); vm.runInContext(code, context);
  await context.check();
  for (const wrong of [{ ...absent, extra: true }, { ...absent, error: { ...absent.error, retryable: true } },
    { ...absent, error: { ...absent.error, code: 'INTERNAL' } }]) {
    reply = wrong; await assert.rejects(async () => context.check());
  }
  assert.equal(value.connections, 2); assert.equal(value.requests.filter(request => request.method === 'run.submit').length, 1);
  assert.deepEqual(value.requests.slice(0, 3), [hello, hello, mutation]);
  respond(originalSocket, JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.submit' } }));
  assert.equal(JSON.parse(JSON.parse(await original.line())).result.method, 'run.submit');
  for (const client of [original, inspector]) {
    client.child.stdin.end(); const exit = await client.result;
    assert.deepEqual(exit, { code: 0, signal: null, stderr: '' });
  }
});

test('admission shutdown keeps the original final resource, pending, provider and two-second assertions after the independent read', () => {
  // Caller wiring only; the actual Linux descriptor/signal cut must still run
  // independently. In particular a missed final resource remains a failure.
  const start = source.indexOf('    } else if (shutdownAdmissionOnly || shutdownSessionOnly) {');
  const end = source.indexOf('\n    } else {', start); assert(start >= 0 && end > start);
  const branch = source.slice(start, end), mutationAt = branch.indexOf('const pendingAdmission = shutdownClient.send(admission, 120000)');
  assert(mutationAt > branch.indexOf("shutdownAdmissionInspector = await persistentClient(undefined, false, 'inspection')"));
  assert(mutationAt > branch.indexOf('const contract = command('));
  assert.equal(branch.match(/shutdownClient\.send\(admission, 120000\)/gu)?.length, 1);
  assert.match(branch, /const observeBy = Date\.now\(\) \+ 30000/u);
  const firstFinal = branch.indexOf("assert(await heldAdmissionResource(resource), 'the exact original resource must remain held at the signal cut')");
  const joined = branch.indexOf('await shutdownAdmissionInspector.close(); shutdownAdmissionInspector = undefined;');
  assert(firstFinal > branch.lastIndexOf('await assertAbsent();', firstFinal)); assert(joined > firstFinal);
  const retained = branch.indexOf('await withRetainedUnitHistory('), signal = branch.indexOf("const stopped = command('/usr/bin/systemctl'");
  assert(retained > firstFinal); assert(signal > retained);
  assert(joined > signal); assert(joined < branch.indexOf('const releasedOwners ='));
  assert.match(branch.slice(retained, signal), /assert\(await heldAdmissionResource\(resource\)\);\s+assert\.equal\(requestFinished, false\);/u);
  assert.match(branch.slice(firstFinal, retained), /assert\.equal\(requestFinished, false\); assert\.equal\(requestsReceived, 0\); assert\(!providerFailure\);/u);
  assert.match(branch, /assert\.equal\(stopPolicy\.TimeoutStopUSec, '2s'\)/u);
  assert.match(branch, /bounded\(pendingAdmission, 10000,/u);
  const cleanup = source.slice(source.indexOf('\n  finally {\n    const cleanupFailures: unknown[] = [];'));
  assert.match(cleanup, /try \{ await shutdownAdmissionInspector\?\.close\(\); \} catch \(error\) \{ cleanupFailures\.push\(error\); \}/u);
  assert.match(cleanup, /try \{ await shutdownClient\?\.close\(\); \} catch \(error\) \{ cleanupFailures\.push\(error\); \}/u);
  const factory = source.slice(source.indexOf('  const persistentClient = async ('), source.indexOf('  const openRunObserverClient ='));
  assert.equal(factory.match(/if \(joinRole === 'original'\) report\.originalPublicClientJoined = true/gu)?.length, 2);
});

async function readObserver(value) {
  const module = ts.transpileModule(readFileSync(new URL('./installed-run-observer.ts', import.meta.url), 'utf8'),
    { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
  const { createInstalledRunObserver } = await import(`data:text/javascript;base64,${Buffer.from(module).toString('base64')}`);
  return createInstalledRunObserver(async () => {
    const client = value.persistent(true); assert.equal(await client.line(), 'connected');
    const send = async (request, timeout) => {
      client.child.stdin.write(`${JSON.stringify(request)}\n`);
      let timer;
      try { return JSON.parse(JSON.parse(await Promise.race([client.line(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('actual observer reply deadline expired')), timeout);
      })]))); } finally { clearTimeout(timer); }
    };
    const handshake = await send(hello, 5000);
    return { send, supervisorInstanceId: handshake.result.supervisorInstanceId, close: async () => {
      client.child.stdin.end(); const exit = await client.result;
      assert.equal(exit.code, 0, exit.stderr); assert.equal(exit.signal, null);
    } };
  });
}

test('ordinary Run observer reads independent cuts on one real socket and joins before it closes', { timeout: 10000 }, async t => {
  const value = await fixture(t); let reads = 0;
  await value.listen((socket, request) => respond(socket, request.method === 'control.hello' ? helloReply
    : JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.get', cut: ++reads } })));
  const observer = await readObserver(value);
  const first = await observer.read('first'), second = await observer.read('second');
  assert.equal(first.response.result.cut, 1); assert.equal(second.response.result.cut, 2);
  assert.equal(first.supervisorInstanceId, 'fixture-owner'); assert.equal(second.supervisorInstanceId, 'fixture-owner');
  await observer.close();
  assert.equal(value.connections, 1);
  assert.deepEqual(value.requests, [hello, { protocolVersion: 1, method: 'run.get', runId: 'first' },
    { protocolVersion: 1, method: 'run.get', runId: 'second' }]);
  await assert.rejects(observer.read('after-close'));
});

test('ordinary Run observer counts hello in its 1024-frame budget and joins before a planned read-only rotation', { timeout: 10000 }, async t => {
  const value = await fixture(t); let ordinal = 0;
  await value.listen((socket, request) => {
    if (value.connections === 2) assert.equal(value.closedConnections, 1, 'the original actual socket must join before the next connection');
    respond(socket, request.method === 'control.hello' ? JSON.stringify({ protocolVersion: 1, ok: true,
      result: { method: 'control.hello', supervisorInstanceId: value.connections === 1 ? 'first-owner' : 'rotated-owner' } })
      : JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.get', cut: ++ordinal } }));
  });
  const observer = await readObserver(value);
  for (let index = 0; index < 1023; index++) assert.equal((await observer.read('retained')).response.result.cut, index + 1);
  assert.equal(value.connections, 1); assert.equal(value.requests.length, 1024);
  const rotated = await observer.read('after-budget');
  assert.equal(rotated.response.result.cut, 1024); assert.equal(rotated.supervisorInstanceId, 'rotated-owner');
  await observer.close();
  assert.equal(value.connections, 2); assert.equal(value.requests.length, 1026);
  assert.equal(value.requests.filter(request => request.method === 'control.hello').length, 2);
  assert.equal(value.requests.every(request => ['control.hello', 'run.get'].includes(request.method)), true);
});

test('ordinary Run observer does not reset its original read deadline while rotating and handshaking', { timeout: 10000 }, async t => {
  const value = await fixture(t);
  await value.listen((socket, request) => {
    if (request.method === 'control.hello' && value.connections === 2) setTimeout(() => respond(socket), 150);
    else respond(socket, request.method === 'control.hello' ? helloReply
      : JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.get' } }));
  });
  const observer = await readObserver(value);
  for (let index = 0; index < 1023; index++) await observer.read('retained');
  await assert.rejects(observer.read('must-not-send-after-deadline', 50), /deadline/u);
  await assert.rejects(observer.read('must-not-reconnect'));
  await observer.close();
  assert.equal(value.connections, 2); assert.equal(value.requests.length, 1025);
  assert.equal(value.requests.at(-1).method, 'control.hello');
});

test('ordinary Run observer never reconnects or resends after its real socket fails', { timeout: 10000 }, async t => {
  const value = await fixture(t);
  await value.listen((socket, request) => request.method === 'control.hello' ? respond(socket) : socket.destroy());
  const observer = await readObserver(value);
  await assert.rejects(observer.read('once'));
  await assert.rejects(observer.read('never-sent'));
  await assert.rejects(observer.close());
  assert.equal(value.connections, 1);
  assert.deepEqual(value.requests, [hello, { protocolVersion: 1, method: 'run.get', runId: 'once' }]);
});

test('ordinary Run observer cannot disguise an already closed peer as a clean budget rotation', { timeout: 10000 }, async t => {
  const value = await fixture(t); let closedResolve;
  const closed = new Promise(resolve => { closedResolve = resolve; });
  await value.listen((socket, request) => {
    respond(socket, request.method === 'control.hello' ? helloReply
      : JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.get' } }));
    if (value.requests.length === 1024) { socket.once('close', closedResolve); socket.end(); }
  });
  const observer = await readObserver(value);
  for (let index = 0; index < 1023; index++) await observer.read('retained');
  await closed;
  await assert.rejects(observer.read('must-not-rotate-after-peer-loss'));
  await assert.rejects(observer.read('must-not-reconnect'));
  await assert.rejects(observer.close());
  assert.equal(value.connections, 1); assert.equal(value.requests.length, 1024);
});

test('ordinary Run observer refuses concurrent reads and joins the actual in-flight read before close', { timeout: 10000 }, async t => {
  const value = await fixture(t); let release, enteredResolve;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  await value.listen((socket, request) => {
    if (request.method === 'control.hello') respond(socket);
    else { release = () => respond(socket, JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.get' } })); enteredResolve(); }
  });
  const observer = await readObserver(value), original = observer.read('original');
  await entered;
  await assert.rejects(observer.read('concurrent'));
  let joined = false; const closing = observer.close().then(() => { joined = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(joined, false);
  assert.equal(value.closedConnections, 0); release();
  await original; await closing;
  assert.equal(value.connections, 1);
  assert.deepEqual(value.requests, [hello, { protocolVersion: 1, method: 'run.get', runId: 'original' }]);
});

test('ordinary non-retrying client fails on absence; hello-only client joins after an observed absent socket becomes ready', { timeout: 10000 }, async t => {
  const value = await fixture(t);
  const original = await value.client().result;
  assert.notEqual(original.code, 0); assert.equal(original.signal, null); assert.match(original.stderr, /ENOENT/u);
  const waiting = value.client([hello], Date.now() + 2000);
  await waiting.firstConnectFailure;
  await value.listen(socket => respond(socket));
  const result = await waiting.result;
  assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null);
  assert.deepEqual(JSON.parse(result.stdout), [helloReply]);
  assert.equal(value.connections, 1); assert.deepEqual(value.requests, [hello]);
});

test('hello readiness never accepts an absent or already-listening socket after its deadline', { timeout: 10000 }, async t => {
  const value = await fixture(t);
  const absent = await value.client([hello], Date.now() + 150).result;
  assert.notEqual(absent.code, 0); assert.equal(absent.signal, null);
  await value.listen(socket => respond(socket));
  const late = await value.client([hello], Date.now() - 1).result;
  assert.notEqual(late.code, 0); assert.equal(late.signal, null);
  assert.equal(value.connections, 0); assert.deepEqual(value.requests, []);
});

for (const failure of ['disconnect', 'invalid_frame']) {
  test(`a connected hello ${failure} is fatal, not another readiness connection`, { timeout: 10000 }, async t => {
    const value = await fixture(t);
    await value.listen(socket => failure === 'disconnect' ? socket.destroy() : socket.write(Buffer.alloc(4)));
    const result = await value.client([hello], Date.now() + 2000).result;
    assert.notEqual(result.code, 0); assert.equal(result.signal, null);
    assert.equal(value.connections, 1); assert.deepEqual(value.requests, [hello]);
  });
}

test('ordinary mutating requests are sent once and never replayed after a connected failure', { timeout: 10000 }, async t => {
  const value = await fixture(t);
  await value.listen((socket, request) => request.method === 'control.hello' ? respond(socket) : socket.destroy());
  const result = await value.client([hello, mutation]).result;
  assert.notEqual(result.code, 0); assert.equal(result.signal, null);
  assert.equal(value.connections, 1); assert.deepEqual(value.requests, [hello, mutation]);
  // Test the actual caller gate as well: no mutating request may enter the
  // special connect-retry branch, even before its first Socket is created.
  const from = source.indexOf('  const exchange = ('), through = source.indexOf('\n  const accepted =', from);
  assert(from >= 0 && through > from);
  const exchange = ts.transpileModule(source.slice(from, through) + '\nglobalThis.exchangeUnderTest = exchange;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  let commands = 0;
  const context = { assert, Buffer, hello, clientScript, process: { execPath: process.execPath }, path,
    recipe: { stateRoot: '/unused-fixture-data' }, canonicalJsonBytes: body => Buffer.from(JSON.stringify(body)),
    command() { commands++; throw new Error('ordinary command boundary'); } };
  vm.createContext(context); vm.runInContext(exchange, context);
  assert.throws(() => context.exchangeUnderTest([mutation], Date.now() + 2000), /startup connection retry is hello-only/u);
  assert.equal(commands, 0);
  assert.throws(() => context.exchangeUnderTest([mutation]), /ordinary command boundary/u);
  assert.equal(commands, 1);
});

test('installed journey failures retain only fixed classifications from actual errors, never error messages or arbitrary frames', () => {
  const from = source.indexOf('      const sourceFrames: Array<{ file: string; line: number; column: number }> = [];');
  const through = source.indexOf('\n    }\n    let publication:', from);
  assert(from >= 0 && through > from);
  const classification = ts.transpileModule(source.slice(from, through),
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const classify = primary => {
    primary.stack = 'Error: private diagnostic must not survive\n at inspect (installed-read-control.ts:24:21)\n at secret-source.ts:99:2';
    const context = { primary, report: {}, Error, AggregateError, Number,
      InstalledClientConsumerDeadlineError, InstalledClientDriverError };
    vm.createContext(context); vm.runInContext(classification, context);
    const result = JSON.parse(JSON.stringify(context.report.error));
    assert.deepEqual(result.sourceFrames, [{ file: 'installed-read-control.ts', line: 24, column: 21 }]);
    assert(!JSON.stringify(result).includes('private')); assert(!JSON.stringify(result).includes('unrecognized-sensitive-code'));
    assert.deepEqual(Object.keys(result).sort(), ['diagnosticOnly', 'failureKinds', 'kind', 'sourceFrames']);
    assert.equal(result.diagnosticOnly, true); assert.equal(result.kind, 'installed_run_journey_failed');
    return result.failureKinds;
  };
  for (const code of ['ERR_SQLITE_ERROR', 'ERR_ASSERTION', 'unrecognized-sensitive-code']) {
    const primary = Object.assign(new Error('Bearer private diagnostic must not survive'), { code, errcode: 261 });
    assert.deepEqual(classify(primary), code === 'ERR_SQLITE_ERROR' ? [{ kind: 'sqlite', primaryCode: 5 }]
      : code === 'ERR_ASSERTION' ? [{ kind: 'assertion' }] : []);
  }
  for (const stage of ['platform', 'composition', 'selection', 'authentication', 'request', 'output', 'retirement']) {
    const primary = new InstalledClientDriverError(stage);
    assert.deepEqual(classify(primary), [{ kind: 'installed_client_driver', stage }]);
  }
  for (const stage of ['ready', 'request', 'close']) {
    const primary = new InstalledClientConsumerDeadlineError(stage, stage === 'request' ? 30000 : stage === 'close' ? 10000 : 5000,
      performance.now(), 17);
    assert.deepEqual(classify(primary), [primary.diagnostic]);
  }
  for (const lastObservedDriverStage of ['platform', 'composition', 'selection', 'authentication', 'request', 'output', 'retirement']) {
    const primary = new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, lastObservedDriverStage);
    assert.deepEqual(classify(primary), [primary.diagnostic]);
    assert.equal(primary.diagnostic.lastObservedDriverStage, lastObservedDriverStage);
  }
  const observed = new InstalledClientConsumerDeadlineError('ready', 5000, performance.now(), 0, 'authentication',
    [{ stage: 'hello_exchange_started', elapsedMs: 12, observedElapsedMs: 15 }]);
  assert.deepEqual(classify(observed), [observed.diagnostic]);
  assert.deepEqual(observed.diagnostic.authentication, [{ stage: 'hello_exchange_started', elapsedMs: 12, observedElapsedMs: 15 }]);
  const impostor = Object.assign(new Error('Bearer private diagnostic must not survive'), {
    diagnostic: { kind: 'installed_client_driver', stage: 'request', private: 'untrusted diagnostic must not survive' },
  });
  assert.deepEqual(classify(impostor), []);
});

test('persistent public client reads separate cuts on its one original socket and never reconnects after refusal', { timeout: 10000 }, async t => {
  const value = await fixture(t);
  const get = { protocolVersion: 1, method: 'run.get', runId: 'ordinary-data-only' };
  let gets = 0;
  await value.listen((socket, request) => {
    if (request.method === 'control.hello') respond(socket);
    else if (++gets === 1) respond(socket, JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'run.get' } }));
    else socket.destroy();
  });
  const original = value.persistent(); assert.equal(await original.line(), 'connected');
  original.child.stdin.write(`${JSON.stringify(hello)}\n`);
  assert.equal(JSON.parse(await original.line()), helloReply);
  original.child.stdin.write(`${JSON.stringify(get)}\n`);
  assert.equal(JSON.parse(JSON.parse(await original.line())).result.method, 'run.get');
  original.child.stdin.write(`${JSON.stringify(get)}\n`);
  const failed = await original.result;
  assert.notEqual(failed.code, 0); assert.equal(failed.signal, null);
  assert.equal(value.connections, 1); assert.deepEqual(value.requests, [hello, get, get]);
});

test('persistent public client closes and joins its original socket when its owning input ends', { timeout: 10000 }, async t => {
  const value = await fixture(t); await value.listen(socket => respond(socket));
  const original = value.persistent(); assert.equal(await original.line(), 'connected');
  original.child.stdin.write(`${JSON.stringify(hello)}\n`);
  assert.equal(JSON.parse(await original.line()), helloReply);
  original.child.stdin.end();
  const joined = await original.result;
  assert.equal(joined.code, 0, joined.stderr); assert.equal(joined.signal, null); assert.equal(joined.stderr, '');
  assert.equal(value.connections, 1); assert.deepEqual(value.requests, [hello]);
});

test('an explicitly closed idle public peer retains the separate shutdown-client join behavior', { timeout: 10000 }, async t => {
  const value = await fixture(t); let closedResolve;
  const closed = new Promise(resolve => { closedResolve = resolve; });
  await value.listen(socket => { socket.once('close', closedResolve); respond(socket); socket.end(); });
  const client = value.persistent(); assert.equal(await client.line(), 'connected');
  client.child.stdin.write(`${JSON.stringify(hello)}\n`);
  assert.equal(JSON.parse(await client.line()), helloReply); await closed;
  client.child.stdin.end(); const exit = await client.result;
  assert.equal(exit.code, 0, exit.stderr); assert.equal(exit.signal, null);
  assert.equal(value.connections, 1); assert.deepEqual(value.requests, [hello]);
});

test('response-time worker diagnostics use the same public hello, not queued installed inventory', () => {
  // Actual caller code, serialized replies only. This does not mint a native
  // identity; Linux independently observes the original worker and retirement.
  const start = source.indexOf('  const exchange = ('), end = source.indexOf('\n  const accepted =', start);
  assert(start >= 0 && end > start);
  const script = ts.transpileModule(source.slice(start, end) + '\nglobalThis.exchangeUnderTest = exchange;',
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const get = { protocolVersion: 1, method: 'run.get', runId: 'data-only-run' };
  const hello = { protocolVersion: 1, method: 'control.hello' };
  const helloResponse = { protocolVersion: 1, ok: true, result: { method: 'control.hello', supervisorInstanceId: 'original-instance' } };
  const getResponse = { protocolVersion: 1, ok: true, result: { method: 'run.get' } };
  let commands = 0, observed;
  const context = { assert, Buffer, hello, clientScript, process: { execPath: process.execPath }, path,
    recipe: { stateRoot: '/unused-fixture-data' }, canonicalJsonBytes: body => Buffer.from(JSON.stringify(body)), parseJsonStrict: JSON.parse,
    command(_executable, arguments_) {
      commands++;
      const sent = JSON.parse(Buffer.from(arguments_[4], 'base64url')).map(text => JSON.parse(Buffer.from(text, 'base64url')));
      assert.deepEqual(sent, [hello, get]);
      return { status: 0, stdout: JSON.stringify([helloResponse, getResponse].map(value => JSON.stringify(value))) };
    } };
  vm.createContext(context); vm.runInContext(script, context);
  const replies = context.exchangeUnderTest([get], 0, 30000, value => { observed = value; });
  assert.equal(commands, 1);
  assert.equal(observed?.supervisorInstanceId, 'original-instance');
  assert.equal(replies.length, 1); assert.equal(replies[0].result.method, 'run.get');
  const callbackFrom = source.indexOf('    captureResponseWorker = async body => {');
  const callbackThrough = source.indexOf('\n    const assertOriginalRetirement', callbackFrom);
  assert(callbackFrom >= 0 && callbackThrough > callbackFrom);
  assert.doesNotMatch(source.slice(callbackFrom, callbackThrough), /method: 'supervisor\.status'/u);
  const resourceFrom = source.indexOf('      observeResourceWorkerBeforeReply = async () => {');
  const resourceThrough = source.indexOf('\n      };', resourceFrom);
  assert(resourceFrom >= 0 && resourceThrough > resourceFrom);
  assert.doesNotMatch(source.slice(resourceFrom, resourceThrough), /method: 'supervisor\.status'/u);
});

test('immutable result assertions compare complete canonical data from the actual strict JSON decoder', async () => {
  const load = async relative => {
    const module = ts.transpileModule(readFileSync(new URL(relative, import.meta.url), 'utf8'),
      { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
    return import(`data:text/javascript;base64,${Buffer.from(module).toString('base64')}`);
  };
  const { parseJsonStrict } = await load('../../../src/kernel/json.ts');
  const { canonicalJsonBytes } = await load('../../../src/kernel/canonical.ts');
  const dependency = source.split('\n').find(line => line.includes('closure.resultSourceRef, candidate.resultSourceRef)'));
  const verification = source.split('\n').find(line => line.includes('closure.verification') && line.includes('unverifiedConsentRef: spec.unverifiedConsentRef'));
  assert(dependency && verification);
  const validate = new Function('assert', 'canonicalJsonBytes', 'closure', 'candidate', 'spec', `${dependency}\n${verification}`);
  const spec = { unverifiedConsentRef: 'consent-data-only' }, candidate = { resultSourceRef: 'result-data-only' };
  const expected = { resultSourceRef: candidate.resultSourceRef, dependency: { kind: 'none' },
    verification: { kind: 'local', outcome: 'unverified', unverifiedConsentRef: spec.unverifiedConsentRef, entries: [] } };
  const decoded = parseJsonStrict(canonicalJsonBytes(expected).toString('utf8'));
  assert.equal(Object.getPrototypeOf(decoded.dependency), null);
  validate(assert, canonicalJsonBytes, decoded, candidate, spec);
  for (const change of [
    value => { value.dependency.extra = true; },
    value => { value.dependency.kind = 'ready'; },
    value => { value.verification.outcome = 'verified'; },
    value => { value.verification.unverifiedConsentRef = 'another-consent'; },
    value => { value.verification.entries.push({ verifierId: 'unexpected' }); },
  ]) {
    const changed = parseJsonStrict(canonicalJsonBytes(expected).toString('utf8')); change(changed);
    assert.throws(() => validate(assert, canonicalJsonBytes, changed, candidate, spec));
  }
  assert.throws(() => parseJsonStrict('{"kind":"none","kind":"ready"}'));
});
