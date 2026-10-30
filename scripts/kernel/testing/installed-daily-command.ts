// Test-only owner of the normal signed CLI launcher's actual stdio resources.
// It cannot prove descendant death; the existing disposable UID coordinator
// remains responsible for physical retirement, including every failed launch.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { CredentialSecretScanner } from './credential-secret-scan.js';

export class InstalledDailyCommandError extends Error {
  readonly descendantRetirement = 'outer_uid_coordinator_required' as const;
  constructor(readonly launcherAndPipesJoined: boolean) {
    super('normal installed command failed; descendant retirement remains with the original UID coordinator');
    this.name = 'InstalledDailyCommandError';
  }
}

export async function runInstalledDailyCommand(input: Readonly<{
  executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  input?: Buffer; deadlineMs: number; scanner: CredentialSecretScanner;
}>) {
  assert(Number.isSafeInteger(input.deadlineMs) && input.deadlineMs > 0 && input.deadlineMs <= 90_000);
  const out = input.scanner.openStream(), started = performance.now();
  let err: ReturnType<typeof input.scanner.openStream>;
  try { err = input.scanner.openStream(); } catch { out.close(); throw new InstalledDailyCommandError(false); }
  let child: ReturnType<typeof spawn> & { stdin: NonNullable<ReturnType<typeof spawn>['stdin']>;
    stdout: NonNullable<ReturnType<typeof spawn>['stdout']>; stderr: NonNullable<ReturnType<typeof spawn>['stderr']> };
  try { child = spawn(input.executable, [...input.args], { env: input.env, cwd: input.cwd, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch { out.close(); err.close(); throw new InstalledDailyCommandError(false); }
  const streams = [child.stdin, child.stdout, child.stderr];
  let stdiosJoined = false;
  const streamsClosed = Promise.all(streams.map(stream => new Promise<void>(resolve => stream.once('close', resolve))))
    .then(() => { stdiosJoined = true; });
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  const stdout: Buffer[] = [], stderr: Buffer[] = []; let size = 0, failure = false;
  let rejectFailure!: () => void;
  const failed = new Promise<never>((_, reject) => { rejectFailure = () => reject(new InstalledDailyCommandError(false)); });
  void failed.catch(() => {});
  const refuse = () => { failure = true; rejectFailure(); };
  for (const [stream, parts, scan] of [[child.stdout, stdout, out], [child.stderr, stderr, err]] as const) stream.on('data', (bytes: Buffer) => {
    try { scan.scan(bytes); size += bytes.length; assert(size <= 2 * 1024 * 1024); parts.push(Buffer.from(bytes)); }
    catch { refuse(); }
  });
  for (const stream of [child, ...streams]) stream.on('error', refuse);
  const written = new Promise<void>((resolve, reject) => child.stdin.end(input.input, (error?: Error | null) => error ? reject(error) : resolve()));
  void written.catch(refuse);
  const timer = setTimeout(refuse, Math.max(0, input.deadlineMs - (performance.now() - started)));
  let result: Awaited<typeof closed> | undefined, joined = false;
  try {
    result = await Promise.race([Promise.all([closed, written, streamsClosed]).then(([result]) => result), failed]);
    if (performance.now() - started >= input.deadlineMs || result.code !== 0 || result.signal !== null) failure = true;
  } catch { failure = true; }
  finally {
    clearTimeout(timer);
    // Signal only this still-owned ChildProcess. A real runuser can forward
    // TERM to its own unreaped command; that behavior must be observed on Linux,
    // and neither the signal nor pipe closure proves descendant death.
    if (failure && child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGTERM'); } catch { failure = true; }
    }
    // A descendant can inherit the launcher's pipes. On failure, close our
    // ends immediately so those handles cannot prevent the outer coordinator
    // from running. This is pipe retirement, never descendant-death evidence.
    if (failure) for (const stream of streams) stream.destroy();
    let joinTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([Promise.all([closed, streamsClosed, written.catch(() => {})]), new Promise<never>((_, reject) => {
        joinTimer = setTimeout(() => reject(new InstalledDailyCommandError(false)), 10_000);
      })]);
      joined = true;
    } catch {
      failure = true; for (const stream of streams) stream.destroy();
      // The original launcher is explicitly unjoined. Its process handle must
      // not prevent failure from reaching the outer UID coordinator; unref
      // neither terminates it nor changes the retained failure classification.
      if (stdiosJoined && performance.now() - started >= input.deadlineMs) child.unref();
    }
    finally { clearTimeout(joinTimer); out.close(); err.close(); }
  }
  if (failure || !joined || !result) throw new InstalledDailyCommandError(joined);
  return { stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), elapsedMs: Math.floor(performance.now() - started) };
}
