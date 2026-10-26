import assert from 'node:assert/strict';
import test from 'node:test';
import { PassThrough, Readable, Writable } from 'node:stream';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseClientInvocation } from './commands.js';
import { clientWriter, runClientInvocation } from './entry.js';
import { hello, protocolClient, outputStream, runSnapshot } from './testing/protocol.js';
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const line = (value: unknown) => Buffer.concat([canonicalJsonBytes(value), Buffer.from('\n')]);
const io = (input: Readable, output = outputStream(), diagnostic = outputStream()) => ({ input, output: output.stream,
  diagnostic: diagnostic.stream, workspacePath: '/workspace' });

test('detached CLI emits only its acknowledged Run id and uses one new admission at the current Session revision', async () => {
  let release!: () => void, entered!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
  const f = protocolClient({ 'run.submit': async () => { entered(); await gate;
    return { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: runSnapshot() } }; } });
  const output = outputStream();
  const invocation = parseClientInvocation(['run', 'A new objective', '--provider', 'ollama', '--model', 'fixture', '--allow-unverified', '--detach'], '/workspace');
  const pending = runClientInvocation(f.session, invocation, io(Readable.from([]), output));
  await ready; assert.equal(output.text(), '');
  assert.deepEqual(f.calls.map(call => call.method), ['session.create', 'session.get', 'run.submit']);
  assert.equal(f.calls[2]!.request.expectedContextRevision, 7);
  release(); assert.equal(await pending, 0); assert.equal(output.text(), 'run\n'); assert.equal(f.closed(), 1);
});

test('uncertain CLI admission retains its original identities without replacement, cancellation or secret echo', async () => {
  const f = protocolClient({ 'run.submit': async () => { throw new Error('inert sensitive transport detail'); } });
  const output = outputStream(), diagnostic = outputStream();
  const invocation = parseClientInvocation(['resume', 'session', 'Continue', '--provider', 'ollama', '--model', 'fixture', '--allow-unverified', '--detach'], '/workspace');
  assert.equal(await runClientInvocation(f.session, invocation, io(Readable.from([]), output, diagnostic)), 1);
  assert.equal(f.calls.filter(call => call.method === 'run.submit').length, 1);
  assert.equal(f.calls.some(call => call.method === 'run.cancel'), false); assert.equal(output.text(), '');
  assert.match(diagnostic.text(), /request .*; admission /u); assert.doesNotMatch(diagnostic.text(), /sensitive transport/u); assert.equal(f.closed(), 1);
});

test('text attach EOF joins its original pending read and detaches without cancel', async () => {
  let entered!: () => void, finish!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { finish = resolve; });
  const f = protocolClient({ close: async () => { finish(); }, 'run.attach': async () => {
    entered(); await gate; return { protocolVersion: 1, ok: true, result: { method: 'run.attach', snapshot: runSnapshot(),
      earliestRetainedEventSeq: 1, latestRetainedEventSeq: 1, highWaterEventSeq: 1, events: [{ schemaVersion: 1, kind: 'progress', runId: 'run', eventSeq: 1, observedRunRevision: 1, phase: 'agent', occurredAt: '2026-10-26T00:00:00.000Z' }], nextEventSeq: 1 } };
  } });
  const input = new PassThrough();
  const pending = runClientInvocation(f.session, parseClientInvocation(['attach', 'run'], '/workspace'), io(input));
  await ready; input.end(); assert.equal(await pending, 0);
  assert.equal(f.calls.some(call => call.method === 'run.cancel'), false);
});

for (const mode of ['jsonl', 'rpc'] as const) test(`${mode} entry preserves the same closed refusal and EOF closes its one connection`, async () => {
  const refusal = { protocolVersion: 1, ok: false, method: 'supervisor.status', error: { schemaVersion: 1,
    code: 'AUTHORIZATION_REQUIRED', retryable: false, messageCode: 'control.authorization_required' } };
  const f = protocolClient({ 'supervisor.status': async () => refusal });
  const request = { schemaVersion: 3, request: { protocolVersion: 1, method: 'supervisor.status' } };
  const greeting = { schemaVersion: 3, request: { protocolVersion: 1, method: 'control.hello', clientBuild: 'inert',
    controlSchemaRange: { min: 1, max: 1 }, headlessSchemaRange: { min: 3, max: 3 }, requestedFeatureIds: ['supervisor.status'] } };
  const bytes = mode === 'jsonl' ? line(request) : Buffer.concat([line({ jsonrpc: '2.0', id: 0, method: 'control.hello', params: greeting }),
    line({ jsonrpc: '2.0', id: 1, method: 'supervisor.status', params: request })]);
  const output = outputStream();
  assert.equal(await runClientInvocation(f.session, { kind: mode }, io(Readable.from([bytes]), output)), 0);
  const records = output.text().trim().split('\n').map(line => JSON.parse(line));
  assert.equal(canonicalJsonBytes(mode === 'jsonl' ? records.at(-1).response : records.at(-1).result.response).toString(), canonicalJsonBytes(refusal).toString());
  assert.equal(f.calls.length, 1); assert.equal(f.closed(), 1);
});

test('client stdout backpressure is real and a failed Writable callback/error emission are fully joined', async () => {
  let done!: (error?: Error | null) => void;
  const stream = new Writable({ write(_chunk, _encoding, next) { done = next; } });
  const writer = clientWriter(stream); let completed = false;
  const pending = writer.write(Buffer.from('one')).then(() => { completed = true; });
  await turn(); assert.equal(completed, false); done(); await pending; await writer.join();
  const failure = new Error('owned write failed');
  const broken = new Writable({ write(_chunk, _encoding, next) { next(failure); } });
  const failed = clientWriter(broken);
  await assert.rejects(failed.write(Buffer.from('two')), error => error === failure);
  await assert.rejects(failed.join(), error => error === failure);
  assert.equal(broken.listenerCount('error'), 0);
});

test('text attach reports an authoritative refusal as failure without retrying or cancelling', async () => {
  for (const code of ['NOT_FOUND', 'EVENT_CURSOR_EXPIRED'] as const) {
    const f = protocolClient({ 'run.attach': async () => ({ protocolVersion: 1, ok: false, method: 'run.attach', error: {
      schemaVersion: 1, code, retryable: false, messageCode: code === 'NOT_FOUND' ? 'control.not_found' : 'expired',
      ...(code === 'EVENT_CURSOR_EXPIRED' ? { earliestEventSeq: 5, latestEventSeq: 7, snapshot: runSnapshot() } : {}) } }) });
    const input = new PassThrough(), output = outputStream();
    try {
      assert.equal(await runClientInvocation(f.session, parseClientInvocation(['attach', 'run'], '/workspace'), io(input, output)), 1);
      assert.equal(f.calls.filter(call => call.method === 'run.attach').length, 1);
      assert.equal(f.calls.some(call => call.method === 'run.cancel'), false);
      assert.match(output.text(), new RegExp(code, 'u'));
      if (code === 'EVENT_CURSOR_EXPIRED') assert.match(output.text(), /--after 4/u);
    } finally { input.destroy(); }
  }
});

test('artifact export returns every original verified binary byte without adding headers, text or a mutation', async () => {
  const { sha256Bytes } = await import('../kernel/identity.js');
  const bytes = Buffer.alloc(65543, 97); bytes[0] = 0; bytes[bytes.length - 1] = 255;
  const digest = sha256Bytes(bytes), output = outputStream();
  const f = protocolClient({ 'artifact.get': async (request: { offset: number; length: number }) => {
    const part = bytes.subarray(request.offset, request.offset + request.length), next = request.offset + part.length;
    return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: { schemaVersion: 1, ref: digest,
      digest, sizeBytes: bytes.length, mediaType: 'application/octet-stream' }, offset: request.offset, nextOffset: next,
      bytesBase64: part.toString('base64'), eof: next === bytes.length } };
  } });
  assert.equal(await runClientInvocation(f.session, parseClientInvocation(['artifact', digest], '/workspace'), io(Readable.from([]), output)), 0);
  assert.deepEqual(output.bytes(), bytes); assert.deepEqual(f.calls.map(call => call.request.offset), [0, 65536]);
  assert.equal(f.calls.some(call => ['run.submit', 'run.cancel'].includes(call.method)), false); assert.equal(f.closed(), 1);
  assert.throws(() => parseClientInvocation(['artifact', digest, '--json'], '/workspace'));
});

test('human inspection exposes independent exact cursors and Session raw-page options without an automatic read loop', () => {
  const parsed = parseClientInvocation(['inspect', 'run', '--after-item', '3', '--after-journal', '7', '--item-limit', '20', '--journal-limit', '30'], '/workspace');
  assert.equal(parsed.kind, 'command');
  if (parsed.kind !== 'command' || parsed.command.kind !== 'request') assert.fail();
  assert.equal(parsed.command.request.method, 'run.get');
  if (parsed.command.request.method !== 'run.get') assert.fail();
  assert.equal(parsed.command.request.afterItemSeq, 3); assert.equal(parsed.command.request.afterJournalSeq, 7);
  assert.equal(parsed.command.request.itemLimit, 20); assert.equal(parsed.command.request.journalLimit, 30);
  const session = parseClientInvocation(['session', 'show', 'session', '--after', '10', '--limit', '50'], '/workspace');
  assert.equal(session.kind, 'command');
  if (session.kind !== 'command' || session.command.kind !== 'request' || session.command.request.method !== 'session.get') assert.fail();
  assert.equal(session.command.request.afterItemSeq, 10); assert.equal(session.command.request.limit, 50);
});

test('explicit detach cancels a genuinely blocked stdout pipe and joins its original writer and client without a mutation', async () => {
  const { spawn } = await import('node:child_process'), { fileURLToPath } = await import('node:url');
  const child = spawn(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('./testing/blocked-output.ts', import.meta.url))],
    { env: { ...process.env, NODE_NO_WARNINGS: '1' }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let returned: Record<string, unknown> | undefined, ready!: () => void, returnReady!: () => void, stderrBytes = 0;
  const pending = new Promise<void>(resolve => { ready = resolve; }), stopped = new Promise<void>(resolve => { returnReady = resolve; });
  child.on('message', value => {
    const message = value as Record<string, unknown>;
    if (message.kind === 'actual_pending_output') ready();
    else if (message.kind === 'returned') { returned = message; returnReady(); }
  });
  child.stderr!.on('data', (bytes: Buffer) => { stderrBytes += bytes.length; assert(stderrBytes <= 65536); });
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bounded = async <T,>(work: Promise<T>, ms: number) => {
    try { return await Promise.race([work, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('owned blocked output did not join')), ms); })]); }
    finally { clearTimeout(timer); }
  };
  let primary: unknown;
  try {
    await bounded(Promise.race([pending, closed.then(() => { throw new Error('owned child exited before actual backpressure'); })]), 10000);
    const start = performance.now(); child.send('abort');
    await bounded(stopped, 2000);
    assert(performance.now() - start < 2000);
    assert.deepEqual(returned, { kind: 'returned', code: 1, failed: false, closed: 1, mutations: 0 });
    assert.equal(stderrBytes, 0);
  } catch (error) { primary = error; throw error; }
  finally {
    // Release the parent's read side only after the actual entry has returned
    // (or after recording failure), never as a way to make the assertion pass.
    child.stdout!.resume();
    try { const result = await bounded(closed, 10000); assert.deepEqual(result, { code: 0, signal: null }); }
    catch (error) {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await closed; throw new AggregateError([primary, error].filter(value => value !== undefined), 'owned output fixture cleanup failed');
    }
  }
});
