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

const source = readFileSync(new URL('../qualify-installed-run-journey.ts', import.meta.url), 'utf8');
const literal = /^const clientScript = (`[\s\S]*?`);/mu.exec(source)?.[1]; assert(literal);
const clientScript = vm.runInNewContext(literal); assert.equal(typeof clientScript, 'string');
const persistentLiteral = /^const persistentClientScript = (`[\s\S]*?`);/mu.exec(source)?.[1]; assert(persistentLiteral);
const persistentClientScript = vm.runInNewContext(persistentLiteral); assert.equal(typeof persistentClientScript, 'string');
const hello = { protocolVersion: 1, method: 'control.hello' };
const mutation = { protocolVersion: 1, method: 'run.submit', requestId: 'test-request-once' };
const helloReply = JSON.stringify({ protocolVersion: 1, ok: true, result: { method: 'control.hello' } });
// Observation only: preserve and return the real Socket. This lets the parent
// wait for an actual pre-connect kernel error before publishing the listener.
const observeConnect = `import clientProbeNet from 'node:net';
const clientProbeConnect=clientProbeNet.createConnection;
clientProbeNet.createConnection=function(...args){const socket=clientProbeConnect.apply(this,args);
socket.once('error',error=>process.stderr.write('client-connect-observation:'+error.code+'\\n'));return socket;};\n`;

async function fixture(t) {
  const directory = await mkdtemp('/tmp/cliq-run-client-'), socketPath = path.join(directory, 'control.sock');
  const sockets = new Set(), children = new Set(); let server;
  const requests = []; let connections = 0;
  async function listen(onRequest) {
    assert.equal(server, undefined);
    server = net.createServer(socket => {
      connections++; sockets.add(socket); socket.once('close', () => sockets.delete(socket));
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
  function persistent() {
    const child = spawn(process.execPath, ['--input-type=module', '-e', persistentClientScript, socketPath],
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
  return { listen, client, persistent, requests, get connections() { return connections; } };
}

function respond(socket, text = helloReply) {
  const body = Buffer.from(text), header = Buffer.alloc(4); header.writeUInt32BE(body.length);
  socket.write(Buffer.concat([header, body]));
}

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
