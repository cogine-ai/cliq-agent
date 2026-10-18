// Qualification-only parent for the production installed-client driver. This
// owns its original JSONL child and scanned pipes, never Run/native authority.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';

type Scan = { scan(bytes: Uint8Array): void; close(): void };
type Response = { protocolVersion: 1; ok: boolean; method?: string;
  result?: Record<string, any>; error?: Record<string, unknown> };
type Input = { executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  openScan(): Scan; onJoined(): void; timeout?: number };

async function bounded<T>(operation: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Error('original installed client consumer deadline expired');
  try { return await Promise.race([operation, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(expired), milliseconds);
  })]); } finally { clearTimeout(timer); }
}

export async function openInstalledClientConsumer(input: Input) {
  const timeout = input.timeout ?? 5000;
  assert(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 5000);
  const by = performance.now() + timeout;
  const outScan = input.openScan(); let errorScan: Scan;
  try { errorScan = input.openScan(); } catch (error) { outScan.close(); throw error; }
  let child;
  try { child = spawn(input.executable, [...input.args], { cwd: input.cwd, env: input.env, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (error) { outScan.close(); errorScan.close(); throw error; }
  let output = Buffer.alloc(0), errorBytes = 0, failure: unknown, frames = 0;
  let pending: { method: string; resolve(value: Response): void; reject(error: unknown): void } | undefined;
  let readyResolve!: (value: Response) => void, readyReject!: (error: unknown) => void;
  const ready = new Promise<Response>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const refuse = (error: unknown) => { failure ??= error; readyReject(error); pending?.reject(error); };
  child.stdout.on('data', (bytes: Buffer) => {
    try {
      outScan.scan(bytes); output = Buffer.concat([output, bytes]); assert(output.length <= 2 * 1048580);
      for (;;) {
        const at = output.indexOf(10); if (at < 0) { assert(output.length <= 1048576); break; }
        assert(at > 0 && at <= 1048576); const line = output.subarray(0, at); output = output.subarray(at + 1);
        const response = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(line)) as Response;
        assert(canonicalJsonBytes(response).equals(line)); assert(++frames <= 1024);
        assert.equal(response.protocolVersion, 1); assert.equal(typeof response.ok, 'boolean');
        if (frames === 1) {
          assert.deepEqual(Object.keys(response).sort(), ['ok', 'protocolVersion', 'result']);
          assert.equal(response.ok, true); assert.equal(response.result?.method, 'control.hello');
          assert.equal(typeof response.result.supervisorInstanceId, 'string');
          readyResolve(response); continue;
        }
        assert(pending, 'installed client driver emitted an unsolicited response');
        if (response.ok) assert.equal(response.result?.method, pending.method);
        else assert.equal(response.method, pending.method);
        const original = pending; pending = undefined; original.resolve(response);
      }
    } catch (error) { refuse(error); }
  });
  child.stderr.on('data', (bytes: Buffer) => {
    try { errorScan.scan(bytes); errorBytes += bytes.length; assert(errorBytes <= 65536); }
    catch (error) { refuse(error); }
  });
  child.once('error', refuse); child.stdin.on('error', refuse); child.stdout.on('error', refuse); child.stderr.on('error', refuse);
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => {
    try { outScan.close(); } catch (error) { refuse(error); }
    try { errorScan.close(); } catch (error) { refuse(error); }
    if (frames === 0 || pending) refuse(new Error('original installed client driver closed before its response'));
    resolve({ code, signal });
  }));
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    child.stdin.end(); let exit: Awaited<typeof closed>;
    try { exit = await bounded(closed, 10000); }
    catch (error) {
      child.kill('SIGKILL');
      // The outer disposable-UID coordinator still owns uncertain descendants.
      // A wrapper exit without original inherited pipe join is never success.
      try { await bounded(closed, 10000); }
      catch (joinError) { throw new AggregateError([error, joinError], 'installed client consumer did not retire'); }
      throw error;
    }
    assert.equal(exit.code, 0); assert.equal(exit.signal, null); assert.equal(failure, undefined);
    assert.equal(output.length, 0); assert.equal(errorBytes, 0); input.onJoined();
  })();
  const send = async (value: Record<string, unknown>, milliseconds = 5000): Promise<Response> => {
    assert(!pending && !failure && !closing && frames >= 1 && frames < 1024);
    assert(Number.isSafeInteger(milliseconds) && milliseconds > 0 && milliseconds <= 30000);
    const by = performance.now() + milliseconds;
    assert.equal(typeof value.method, 'string'); assert.notEqual(value.method, 'control.hello');
    const bytes = canonicalJsonBytes(value); assert(bytes.length > 0 && bytes.length <= 1048576);
    const reply = new Promise<Response>((resolve, reject) => { pending = { method: value.method as string, resolve, reject }; });
    child.stdin.write(Buffer.concat([bytes, Buffer.from('\n')]));
    try { const response = await bounded(reply, milliseconds); assert(performance.now() < by); return response; }
    catch (error) { refuse(error); throw error; }
  };
  try {
    const remaining = by - performance.now(); assert(remaining > 0);
    const greeting = await bounded(Promise.race([ready, closed.then(() => {
      throw new Error('original installed client driver closed before readiness');
    })]), Math.ceil(remaining));
    assert(performance.now() < by);
    return Object.freeze({ send, close, hello: greeting.result!, supervisorInstanceId: greeting.result!.supervisorInstanceId as string });
  } catch (error) { refuse(error); try { await close(); } catch {} throw error; }
}
