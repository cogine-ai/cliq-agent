import assert from 'node:assert/strict';
import test from 'node:test';
import type { InstalledSupervisorClient } from '../state/installed-control-client.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { observeInstalledRequestFailures, type InstalledRequestFailure } from '../state/installed-request-diagnostics.js';

// Ordinary protocol data at the client I/O seam, never an installed/native
// selection, StateOwner, Run, grant or positive execution fixture.
const hello = { method: 'control.hello', protocolVersion: 1, serverBuild: 'data-only',
  controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 1, max: 1 },
  enabledFeatureIds: ['supervisor.status'], supervisorInstanceId: 'data-only',
  activeRuntimeBundle: { schemaVersion: 1, runtimeBundleRef: 'a'.repeat(64), bundleDigest: 'a'.repeat(64), bundleVersion: '1' } };
const refusal = { protocolVersion: 1, ok: false, method: 'supervisor.status',
  error: { schemaVersion: 1, code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'data_only_refusal' } };
const request = Buffer.from('{"method":"supervisor.status","protocolVersion":1}\n');

test('the installed v1 JSONL adapter serially exchanges canonical frames and EOF never cancels', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  let calls = 0, closes = 0, cancellations = 0;
  const client = { hello, 'supervisor.status': async () => { calls++; return refusal; },
    'run.cancel': async () => { cancellations++; throw new Error('EOF is not a cancellation'); },
    close: async () => { closes++; } } as unknown as InstalledSupervisorClient;
  const output: Buffer[] = [];
  async function* input() { yield request.subarray(0, 11); yield request.subarray(11); yield request; }
  await runInstalledControlJsonl(client, input(), async bytes => { output.push(Buffer.from(bytes)); });
  assert.equal(calls, 2); assert.equal(cancellations, 0); assert.equal(closes, 0, 'the genuine caller retains retirement ownership');
  assert.deepEqual(output, [{ protocolVersion: 1, ok: true, result: hello }, refusal, refusal]
    .map(value => Buffer.concat([canonicalJsonBytes(value), Buffer.from('\n')])));
});

test('JSONL backpressure joins each response before dispatching the next complete request', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  let release!: () => void, helloWritten!: () => void;
  const helloReady = new Promise<void>(resolve => { helloWritten = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  let responseWritten!: () => void, releaseResponse!: () => void;
  const responseReady = new Promise<void>(resolve => { responseWritten = resolve; });
  const responseGate = new Promise<void>(resolve => { releaseResponse = resolve; });
  let calls = 0, writes = 0;
  const client = { hello, 'supervisor.status': async () => { calls++; return refusal; } } as unknown as InstalledSupervisorClient;
  async function* input() { yield Buffer.concat([request, request]); }
  const running = runInstalledControlJsonl(client, input(), async () => {
    writes++; if (writes === 1) { helloWritten(); await gate; }
    if (writes === 2) { responseWritten(); await responseGate; }
  });
  await helloReady; assert.equal(calls, 0); release();
  await responseReady; assert.equal(calls, 1); releaseResponse(); await running;
  assert.equal(calls, 2); assert.equal(writes, 3);
});

test('request-bound result refusals remain closed and an abrupt output joins the input iterator', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  const resultRefusal = { protocolVersion: 1, ok: false, method: 'run.result', error: {
    schemaVersion: 1, code: 'RESULT_UNAVAILABLE', retryable: false, messageCode: 'data_only',
    runId: 'wrong-run', status: 'cancelled', terminalDetailRef: 'a'.repeat(64) } };
  let iteratorJoined = false, calls = 0;
  const client = { hello, 'run.result': async () => { calls++; return resultRefusal; } } as unknown as InstalledSupervisorClient;
  async function* input() {
    try { yield Buffer.from('{"method":"run.result","protocolVersion":1,"runId":"requested-run"}\n'); }
    finally { iteratorJoined = true; }
  }
  await assert.rejects(runInstalledControlJsonl(client, input(), async () => {}), /differs from requested Run/u);
  assert.equal(calls, 1); assert.equal(iteratorJoined, true);
});

test('the production adapter does not inherit the installed campaign total-frame ceiling', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  let calls = 0, writes = 0;
  const client = { hello, 'supervisor.status': async () => { calls++; return refusal; } } as unknown as InstalledSupervisorClient;
  async function* input() { for (let index = 0; index < 1024; index++) yield request; }
  await runInstalledControlJsonl(client, input(), async () => { writes++; });
  assert.equal(calls, 1024); assert.equal(writes, 1025);
});

test('malformed or unsupported requests never reach a client method', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  let calls = 0;
  const client = { hello, 'supervisor.status': async () => { calls++; return refusal; } } as unknown as InstalledSupervisorClient;
  const cases = [Buffer.from('\n'), request.subarray(0, request.length - 1),
    Buffer.from('{"protocolVersion":1,"method":"supervisor.status"}\n'),
    Buffer.from('{"method":"supervisor.status","method":"run.get","protocolVersion":1}\n'),
    Buffer.from('{"method":"supervisor.status","protocolVersion":1,"extra":false}\n'),
    Buffer.from('{"method":"session.list","protocolVersion":1}\n'),
    Buffer.from('{"method":"control.hello","protocolVersion":1}\n'),
    Buffer.concat([Buffer.from([0xc0, 0x80]), Buffer.from('\n')]), Buffer.alloc(1024 * 1024 + 1, 32)];
  for (const bytes of cases) {
    async function* input() { yield bytes; }
    await assert.rejects(runInstalledControlJsonl(client, input(), async () => {}));
  }
  assert.equal(calls, 0);
});

test('response method/association failures and output failures do not replay a dispatched request', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  for (const mode of ['response', 'write', 'request'] as const) {
    let calls = 0, writes = 0;
    const original = new Error('ordinary I/O failure');
    const client = { hello, 'supervisor.status': async () => {
      calls++; if (mode === 'request') throw original;
      return mode === 'response' ? { ...refusal, method: 'run.get' } : refusal;
    } } as unknown as InstalledSupervisorClient;
    async function* input() { yield Buffer.concat([request, request]); }
    let caught: unknown;
    try { await runInstalledControlJsonl(client, input(), async () => { if (++writes === 2 && mode === 'write') throw original; }); }
    catch (error) { caught = error; }
    assert(caught); if (mode !== 'response') assert.equal(caught, original);
    assert.equal(calls, 1);
  }
});

test('actual JSONL request/response/output failures project their executed boundary and preserve the original failure and iterator join', async () => {
  const { runInstalledControlJsonl } = await import('./installed-jsonl.js');
  for (const mode of ['validation', 'response', 'write', 'request', 'refusal'] as const) {
    const observed: InstalledRequestFailure[] = [], close = observeInstalledRequestFailures(value => { observed.push(value); });
    let calls = 0, writes = 0, joined = false, caught: unknown;
    const original = new Error('ordinary data-only I/O failure');
    const client = { hello, 'supervisor.status': async () => {
      calls++; if (mode === 'request') throw original;
      return mode === 'response' ? { ...refusal, method: 'run.get' } : refusal;
    } } as unknown as InstalledSupervisorClient;
    async function* input() {
      try { yield mode === 'validation' ? Buffer.from('{"protocolVersion":1,"method":"supervisor.status","foreign":true}\n') : request; }
      finally { joined = true; }
    }
    try {
      await runInstalledControlJsonl(client, input(), async () => { if (++writes === 2 && mode === 'write') throw original; });
    } catch (error) { caught = error; }
    finally { close(); }
    assert.equal(joined, true); assert.equal(calls, mode === 'validation' ? 0 : 1);
    if (mode === 'refusal') { assert.equal(caught, undefined); assert.deepEqual(observed, []); continue; }
    assert(caught); assert.equal(observed.length, 1);
    assert.equal(observed[0]!.boundary, mode === 'validation' ? 'request_validation' : mode === 'response' ? 'response_decode'
      : mode === 'write' ? 'adapter_output' : 'adapter_dispatch');
    assert.equal(observed[0]!.method, mode === 'validation' ? 'unrecognized' : 'supervisor.status');
    if (mode === 'write' || mode === 'request') assert.equal(caught, original);
  }
});
