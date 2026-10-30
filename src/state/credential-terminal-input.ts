import { createInterface, type Interface, type Key } from 'node:readline';
import { Transform, Writable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

const MAX_SECRET_BYTES = 65536;
const INPUT_DEADLINE_MS = 10000;
const signals = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'] as const;

/** Local hidden-terminal input only. The caller owns authentication, history,
 * readiness and all credential writes; these bytes grant no authority. */
export async function readTerminalCredentialSecret(): Promise<Buffer> {
  const input = process.stdin, output = process.stderr;
  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function')
    throw new KernelStorageError('INVALID_REQUEST', 'credential prompt requires interactive stdin and stderr terminals');
  const wasRaw = input.isRaw, wasFlowing = input.readableFlowing === true;
  const muted = new Writable({ write(_bytes, _encoding, done) { done(); } });
  let reader: Interface | undefined, timer: ReturnType<typeof setTimeout> | undefined;
  let secret: Buffer | undefined, settled = false, rawBytes = 0, promptStarted = false, discarding = false, readerRetired = false;
  let interrupted = false;
  let retirement: unknown;
  let resolve!: (value: Buffer) => void, reject!: (error: unknown) => void;
  const answer = new Promise<Buffer>((accept, refuse) => { resolve = accept; reject = refuse; });
  // A stream can report its first failure while setup or a fixed prompt write
  // is still joining. It must never become an unhandled promise rejection.
  void answer.catch(() => {});
  const closeReader = () => {
    if (!reader || readerRetired) return;
    readerRetired = true;
    try { reader.write('', { ctrl: true, name: 'u' }); }
    catch (error) { retirement ??= error; }
    try { reader.close(); }
    catch (error) { retirement ??= error; }
  };
  const refuse = () => {
    if (settled) return;
    settled = true;
    reject(new KernelStorageError('INVALID_REQUEST', 'credential prompt was cancelled, unavailable or outside its input bound'));
    closeReader();
  };
  const interrupt = () => { interrupted = true; refuse(); };
  // Readline owns editing on a private stream, not terminal mode on stdin.
  // Its keypress decoder/listeners retire with this stream. On overflow the
  // same decoder consumes to Enter/cancel while the real terminal stays hidden;
  // closing the collector must not expose the tail of an in-flight paste.
  const bridge = new Transform({ transform(chunk: Buffer, _encoding, done) {
    rawBytes = Math.min(MAX_SECRET_BYTES + 3, rawBytes + chunk.byteLength);
    if (rawBytes > MAX_SECRET_BYTES + 2 && !discarding) {
      discarding = true; closeReader(); this.resume();
      if (retirement !== undefined) refuse();
    }
    done(null, chunk);
  } });
  const discardKey = (_text: string | undefined, key: Key) => {
    if (discarding && (key.name === 'return' || key.name === 'enter' ||
        key.ctrl && ['c', 'd', 'z'].includes(key.name ?? ''))) refuse();
  };
  const readerClosed = () => { readerRetired = true; if (!discarding) refuse(); };
  const writes: Promise<void>[] = [];
  const write = (text: string) => {
    const work = new Promise<void>((accept, fail) => {
      try { output.write(text, error => error ? fail(error) : accept()); }
      catch (error) { fail(error); }
    });
    writes.push(work); void work.catch(refuse); return work;
  };
  try {
    input.once('end', refuse); input.once('close', refuse); input.on('error', refuse);
    output.on('error', refuse); muted.on('error', refuse); bridge.on('error', refuse);
    for (const signal of signals) process.on(signal, interrupt);
    timer = setTimeout(refuse, INPUT_DEADLINE_MS);
    input.setRawMode(true);
    reader = createInterface({ input: bridge, output: muted, terminal: true, historySize: 0 });
    bridge.on('keypress', discardKey);
    reader.once('close', readerClosed); reader.once('SIGINT', refuse); reader.once('SIGTSTP', refuse);
    reader.question('', value => {
      if (settled) return;
      const bytes = Buffer.from(value, 'utf8');
      if (!bytes.length || bytes.length > MAX_SECRET_BYTES) { bytes.fill(0); refuse(); return; }
      // No trim or line-ending bytes: readline owns terminal editing and the
      // Enter delimiter. Spaces inside the submitted line remain exact data.
      secret = bytes; settled = true; resolve(bytes);
    });
    input.pipe(bridge);
    promptStarted = true;
    await Promise.all([write('API key: '), answer]);
    return secret!;
  } catch {
    secret?.fill(0);
    throw new KernelStorageError('INVALID_REQUEST', 'credential prompt was cancelled, unavailable or outside its input bound');
  } finally {
    clearTimeout(timer);
    closeReader(); input.unpipe(bridge); input.pause();
    input.removeListener('end', refuse); input.removeListener('close', refuse); input.removeListener('error', refuse);
    reader?.removeListener('close', readerClosed); reader?.removeListener('SIGINT', refuse); reader?.removeListener('SIGTSTP', refuse);
    bridge.removeListener('keypress', discardKey);
    if (!bridge.writableEnded) bridge.end(); bridge.resume(); muted.end();
    const joined = await Promise.allSettled([...writes, finished(bridge, { cleanup: true }), finished(muted, { cleanup: true })]);
    const failure = joined.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    retirement ??= failure?.reason;
    try {
      input.setRawMode(wasRaw);
      if (wasFlowing) input.resume(); else input.pause();
    } catch (error) { retirement ??= error; }
    if (promptStarted) {
      try { await write('\n'); } catch (error) { retirement ??= error; }
    }
    // Until all owned work joins and terminal mode is restored, these signals
    // belong to the prompt. A signal after Enter still prevents the returned
    // secret from reaching credential preparation.
    for (const signal of signals) process.removeListener(signal, interrupt);
    output.removeListener('error', refuse); muted.removeListener('error', refuse); bridge.removeListener('error', refuse);
    if (retirement !== undefined) {
      secret?.fill(0);
      throw new ResourceRetirementError('credential prompt streams or terminal state did not retire', retirement);
    }
    if (interrupted) {
      secret?.fill(0);
      throw new KernelStorageError('INVALID_REQUEST', 'credential prompt was cancelled, unavailable or outside its input bound');
    }
  }
}
