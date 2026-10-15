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
  t.after(async () => {
    const joins = [...children].map(child => new Promise(resolve => { child.once('close', resolve); child.kill('SIGKILL'); }));
    await Promise.all(joins);
    for (const socket of sockets) socket.destroy();
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await rm(directory, { recursive: true, force: true });
  });
  return { listen, client, requests, get connections() { return connections; } };
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
