// Owned stdio lifecycle component. Inert wire data, never an installed/native
// authority fixture. Only the actual original write and pipe are observed.
import { PassThrough } from 'node:stream';
import { parseClientInvocation } from '../commands.js';
import { runClientInvocation } from '../entry.js';
import { sha256Bytes } from '../../kernel/identity.js';
import { protocolClient } from './protocol.js';

if (!process.send) throw new Error('owned output fixture requires its original IPC parent');
const bytes = Buffer.alloc(1024 * 1024, 97), digest = sha256Bytes(bytes), abort = new AbortController();
const pending = new Set<object>(); let announced = false;
const originalWrite = process.stdout.write;
process.stdout.write = function (this: typeof process.stdout, ...args: unknown[]) {
  const token = {}; pending.add(token);
  const callback = args.at(-1);
  if (typeof callback !== 'function') throw new TypeError('only the original client callback write is expected');
  args[args.length - 1] = (...values: unknown[]) => { pending.delete(token); Reflect.apply(callback, undefined, values); };
  const result = Reflect.apply(originalWrite, this, args) as boolean;
  if (!result && !announced) setImmediate(() => {
    if (pending.has(token) && !announced) { announced = true; process.send!({ kind: 'actual_pending_output' }); }
  });
  return result;
} as typeof process.stdout.write;
process.on('message', message => { if (message === 'abort') abort.abort(); });
const f = protocolClient({ 'artifact.get': async (request: { offset: number; length: number }) => {
  const part = bytes.subarray(request.offset, request.offset + request.length), nextOffset = request.offset + part.length;
  return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: { schemaVersion: 1, ref: digest,
    digest, sizeBytes: bytes.length, mediaType: 'application/octet-stream' }, offset: request.offset, nextOffset,
    bytesBase64: part.toString('base64'), eof: nextOffset === bytes.length } };
} });
let failed = false, code: number | undefined;
try {
  code = await runClientInvocation(f.session, parseClientInvocation(['artifact', digest], '/workspace'),
    { input: new PassThrough(), output: process.stdout, diagnostic: process.stderr, workspacePath: '/workspace', signal: abort.signal });
} catch { failed = true; }
process.send({ kind: 'returned', code, failed, closed: f.closed(), mutations: f.calls.filter(call => call.method !== 'artifact.get').length });
process.disconnect();
