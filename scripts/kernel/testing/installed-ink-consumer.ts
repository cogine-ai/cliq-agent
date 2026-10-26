// Test-owned actual PTY and original process/pipe lifetime only. The signed
// selected installation and public wire still perform all authentication.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeHeadlessControlRecord } from '../../../src/control/v1.js';
import { authMarker } from './installed-client-consumer.js';

type Scan = { scan(bytes: Uint8Array): void; close(): void };
type Input = { executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv; runId: string;
  openScan(): Scan; onJoined(): void };
const quote = (value: string) => "'" + value.replace(/'/gu, "'\\''") + "'";
const visible = (value: string) => value.replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, '');
const stages = ['platform', 'composition', 'selection', 'authentication', 'request', 'output', 'retirement'];
/** Never pause, signal-inspect or modify the child. Esc is actual terminal
 * input to the original Ink component. Every issued descriptor and pipe is
 * joined; a timeout is failure and cannot become a detach receipt. */
export async function qualifyInstalledInkDetach(input: Input) {
  assert.match(input.runId, /^[A-Za-z0-9_-]{43}$/u);
  const command = [input.executable, ...input.args].map(quote).join(' ');
  const outScan = input.openScan(); let errScan: Scan;
  try { errScan = input.openScan(); } catch (error) { outScan.close(); throw error; }
  let child;
  try { child = spawn('/usr/bin/script', ['--quiet', '--return', '--flush', '--command', command, '/dev/null'],
    { cwd: input.cwd, env: input.env, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (error) { outScan.close(); errScan.close(); throw error; }
  let failure: unknown, output = Buffer.alloc(0), bytes = 0, errors = 0, hello = false, detached = false;
  const started = performance.now(); let timer: ReturnType<typeof setTimeout> | undefined;
  let shownResolve!: () => void, shownReject!: (error: unknown) => void;
  const shown = new Promise<void>((resolve, reject) => { shownResolve = resolve; shownReject = reject; });
  void shown.catch(() => {});
  const refuse = (error: unknown) => { failure ??= error; shownReject(error); };
  child.stdout.on('data', (chunk: Buffer) => {
    try {
      outScan.scan(chunk); bytes += chunk.length; assert(bytes <= 1048576); output = Buffer.concat([output, chunk]);
      if (!hello) for (;;) {
        const at = output.indexOf(10); if (at < 0) { assert(output.length <= 1048576); break; }
        let line = output.subarray(0, at); output = output.subarray(at + 1);
        if (line.at(-1) === 13) line = line.subarray(0, -1);
        const text = line.toString('ascii');
        if (stages.some(stage => text === `installed control client driver progress phase=${stage}`)) continue;
        if (text.startsWith('CLIQ_INSTALLED_CLIENT_AUTH_')) { authMarker(Buffer.concat([line, Buffer.from('\n')])); continue; }
        const data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(line));
        assert(canonicalJsonBytes(data).equals(line)); const record = decodeHeadlessControlRecord(data);
        assert(record.type === 'response' && record.response.ok && record.response.result.method === 'control.hello');
        hello = true; break;
      }
      if (hello && !detached && visible(output.toString('utf8')).includes(`Run ${input.runId}`)) {
        assert(performance.now() - started < 5000, 'the actual authenticated Ink view exceeded the unchanged READY bound');
        detached = true; child.stdin.write(Buffer.from([27])); shownResolve();
      }
    } catch (error) { refuse(error); }
  });
  child.stderr.on('data', (chunk: Buffer) => {
    try { errScan.scan(chunk); errors += chunk.length; assert(errors <= 65536); if (chunk.length) throw new Error('owned PTY wrapper emitted unexpected stderr'); }
    catch (error) { refuse(error); }
  });
  for (const stream of [child, child.stdin, child.stdout, child.stderr]) stream.once('error', refuse);
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => {
    try { outScan.close(); } catch (error) { refuse(error); }
    try { errScan.close(); } catch (error) { refuse(error); }
    if (!hello || !detached) refuse(new Error('original Ink driver closed before its actual visible state and Esc'));
    resolve({ code, signal });
  }));
  async function bounded<T>(work: Promise<T>, ms: number): Promise<T> {
    assert(ms > 0);
    try { return await Promise.race([work, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('owned Ink consumer deadline expired')), ms); })]); }
    finally { clearTimeout(timer); timer = undefined; }
  }
  let primary: unknown;
  try {
    await bounded(Promise.race([shown, closed.then(() => { if (!detached) throw new Error('Ink closed before the visible original Run'); })]), Math.ceil(5000 - (performance.now() - started)));
    const result = await bounded(closed, 10000);
    assert.equal(result.code, 0); assert.equal(result.signal, null); assert.equal(failure, undefined); input.onJoined();
    return Object.freeze({ qualified: true, actualPty: true, originalAuthenticatedHello: true, originalRunVisible: true,
      escDetached: true, originalProcessAndPipesJoined: true, newExecutionQualified: false });
  } catch (error) { primary = error; throw error; }
  finally {
    clearTimeout(timer);
    // Kill only this still-owned wrapper on failure; the outer disposable UID
    // coordinator still owns any uncertain descendants. Never claim success.
    if (primary !== undefined && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      try { await bounded(closed, 10000); } catch (error) { throw new AggregateError([primary, error], 'Ink fixture process/pipes did not join'); }
    }
  }
}
