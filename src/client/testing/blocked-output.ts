// Owned stdio lifecycle component. Inert wire data, never an installed/native
// authority fixture. Only the actual original write and pipe are observed.
import { PassThrough } from 'node:stream';
import { fstatSync } from 'node:fs';
import { parseClientInvocation } from '../commands.js';
import { runClientInvocation } from '../entry.js';
import { sha256Bytes } from '../../kernel/identity.js';
import { protocolClient } from './protocol.js';
import { openClientStdio } from '../stdio.js';
import { loadNativeStateOwner } from '../../state/native-owner.js';

if (!process.send) throw new Error('owned output fixture requires its original IPC parent');
// One MiB can fit entirely in an unread socket's kernel/readable buffers.
// Stay within the unchanged 64 MiB export ceiling and retain 64 KiB writes;
// only an actually pending original callback admits the cancellation cut.
const bytes = Buffer.alloc(16 * 1024 * 1024, 97), digest = sha256Bytes(bytes), abort = new AbortController();
const originalIdentity = fstatSync(1, { bigint: true });
const stdio = await (async () => {
  try { return await openClientStdio(await loadNativeStateOwner(), { input: new PassThrough(), output: process.stdout,
    diagnostic: process.stderr, workspacePath: '/workspace', signal: abort.signal }); }
  catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    process.send!({ kind: 'startup_refused', stage: 'owned_stdio', code: typeof code === 'string' && /^[A-Z_]{1,64}$/u.test(code) ? code : 'UNCLASSIFIED' });
    throw error;
  }
})();
if (stdio.io.output === process.stdout) throw new Error('original stdout pipe was not independently owned');
const pending = new Set<object>(); let announced = false, blockedToken: object | undefined;
let enteredAt: number | undefined, abortObservedAt: number | undefined, callbackJoinedAt: number | undefined;
const originalWrite = stdio.io.output.write;
stdio.io.output.write = function (this: typeof stdio.io.output, ...args: unknown[]) {
  const token = {}; pending.add(token);
  const callback = args.at(-1);
  if (typeof callback !== 'function') throw new TypeError('only the original client callback write is expected');
  args[args.length - 1] = (...values: unknown[]) => {
    pending.delete(token); if (blockedToken === token) callbackJoinedAt = performance.now();
    Reflect.apply(callback, undefined, values);
  };
  const result = Reflect.apply(originalWrite, this, args) as boolean;
  if (!result && !announced) setImmediate(() => {
    if (pending.has(token) && !announced) {
      announced = true; blockedToken = token; enteredAt = performance.now(); process.send!({ kind: 'actual_pending_output' });
    }
  });
  return result;
} as typeof stdio.io.output.write;
process.on('message', message => {
  if (message !== 'abort') return;
  if (!blockedToken || !pending.has(blockedToken) || callbackJoinedAt !== undefined) throw new Error('original write no longer pending at cancellation');
  abortObservedAt = performance.now(); abort.abort();
});
const f = protocolClient({ 'artifact.get': async (request: { offset: number; length: number }) => {
  const part = bytes.subarray(request.offset, request.offset + request.length), nextOffset = request.offset + part.length;
  return { protocolVersion: 1, ok: true, result: { method: 'artifact.get', artifact: { schemaVersion: 1, ref: digest,
    digest, sizeBytes: bytes.length, mediaType: 'application/octet-stream' }, offset: request.offset, nextOffset,
    bytesBase64: part.toString('base64'), eof: nextOffset === bytes.length } };
} });
let failed = false, code: number | undefined;
try {
  code = await runClientInvocation(f.session, parseClientInvocation(['artifact', digest], '/workspace'), stdio.io);
} catch { failed = true; }
finally { await stdio.close(); }
const after = fstatSync(1, { bigint: true });
if (pending.size !== 0 || originalIdentity.dev !== after.dev || originalIdentity.ino !== after.ino ||
    originalIdentity.uid !== after.uid || originalIdentity.mode !== after.mode || !stdio.io.output.closed)
  throw new Error('original writer or independently owned stdout did not join');
const entryReturnedAt = performance.now();
if (enteredAt === undefined || abortObservedAt === undefined || callbackJoinedAt === undefined ||
    !(enteredAt <= abortObservedAt && abortObservedAt <= callbackJoinedAt && callbackJoinedAt <= entryReturnedAt))
  throw new Error('original output cancellation cut did not close');
process.send({ kind: 'actual_output_cut', enteredAt, abortObservedAt, callbackJoinedAt, entryReturnedAt });
process.send({ kind: 'returned', code, failed, closed: f.closed(), mutations: f.calls.filter(call => call.method !== 'artifact.get').length });
process.disconnect();
