// Test-only owner of the normal signed CLI launcher's actual stdio resources.
// It cannot prove descendant death; the existing disposable UID coordinator
// remains responsible for physical retirement, including every failed launch.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { CredentialSecretScanner } from './credential-secret-scan.js';

export type InstalledDailyCommandDiagnostic = Readonly<{
  diagnosticOnly: true;
  reason: 'spawn' | 'input' | 'stream' | 'scan' | 'output_bound' | 'deadline' | 'exit' | 'join';
  code: number | null; signal: NodeJS.Signals | null; elapsedMs: number;
  spawned: boolean; childJoined: boolean; inputWriteJoined: boolean;
  stdinJoined: boolean; stdoutJoined: boolean; stderrJoined: boolean;
  stdoutBytes: number; stderrBytes: number;
}>;

export class InstalledDailyCommandError extends Error {
  readonly descendantRetirement = 'outer_uid_coordinator_required' as const;
  constructor(readonly launcherAndPipesJoined: boolean, readonly diagnostic: InstalledDailyCommandDiagnostic) {
    super('normal installed command failed; descendant retirement remains with the original UID coordinator');
    this.name = 'InstalledDailyCommandError';
  }
}

export async function runInstalledDailyCommand(input: Readonly<{
  executable: string; args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv;
  input?: Buffer; deadlineMs: number; scanner: CredentialSecretScanner;
}>) {
  assert(Number.isSafeInteger(input.deadlineMs) && input.deadlineMs > 0 && input.deadlineMs <= 90_000);
  const started = performance.now(), pipesJoined = [false, false, false];
  let spawned = false, childJoined = false, inputWriteJoined = false, stdoutBytes = 0, stderrBytes = 0;
  let result: { code: number | null; signal: NodeJS.Signals | null } | undefined;
  const diagnostic = (reason: InstalledDailyCommandDiagnostic['reason']): InstalledDailyCommandDiagnostic => Object.freeze({
    diagnosticOnly: true, reason, code: result?.code ?? null, signal: result?.signal ?? null,
    elapsedMs: Math.floor(performance.now() - started), spawned, childJoined, inputWriteJoined,
    stdinJoined: pipesJoined[0]!, stdoutJoined: pipesJoined[1]!, stderrJoined: pipesJoined[2]!, stdoutBytes, stderrBytes });
  let out: ReturnType<typeof input.scanner.openStream> | undefined, err: ReturnType<typeof input.scanner.openStream>;
  try { out = input.scanner.openStream(); err = input.scanner.openStream(); }
  catch { out?.close(); throw new InstalledDailyCommandError(false, diagnostic('scan')); }
  let child: ReturnType<typeof spawn> & { stdin: NonNullable<ReturnType<typeof spawn>['stdin']>;
    stdout: NonNullable<ReturnType<typeof spawn>['stdout']>; stderr: NonNullable<ReturnType<typeof spawn>['stderr']> };
  try { child = spawn(input.executable, [...input.args], { env: input.env, cwd: input.cwd, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch { out.close(); err.close(); throw new InstalledDailyCommandError(false, diagnostic('spawn')); }
  child.once('spawn', () => { spawned = true; });
  const streams = [child.stdin, child.stdout, child.stderr];
  let stdiosJoined = false;
  const streamsClosed = Promise.all(streams.map((stream, index) => new Promise<void>(resolve => stream.once('close', () => {
    pipesJoined[index] = true; resolve();
  }))))
    .then(() => { stdiosJoined = true; });
  const closed = new Promise<NonNullable<typeof result>>(resolve => child.once('close', (code, signal) => {
    childJoined = true; result = { code, signal }; resolve(result);
  }));
  const stdout: Buffer[] = [], stderr: Buffer[] = []; let size = 0, failure = false;
  let reason: InstalledDailyCommandDiagnostic['reason'] | undefined;
  let rejectFailure!: () => void;
  // This wake-up is internal. Only the original owner constructs a diagnostic
  // error after its unchanged retirement/join path has actually settled.
  const failed = new Promise<never>((_, reject) => { rejectFailure = () => reject(undefined); });
  void failed.catch(() => {});
  const refuse = (observed: InstalledDailyCommandDiagnostic['reason']) => { failure = true; reason ??= observed; rejectFailure(); };
  for (const [stream, parts, scan] of [[child.stdout, stdout, out], [child.stderr, stderr, err]] as const) stream.on('data', (bytes: Buffer) => {
    if (stream === child.stdout) stdoutBytes += bytes.length; else stderrBytes += bytes.length;
    try { scan.scan(bytes); } catch { refuse('scan'); return; }
    size += bytes.length;
    if (size > 2 * 1024 * 1024) { refuse('output_bound'); return; }
    try { parts.push(Buffer.from(bytes)); } catch { refuse('stream'); }
  });
  child.on('error', () => { if (!spawned) reason = 'spawn'; refuse(spawned ? 'stream' : 'spawn'); });
  child.stdin.on('error', () => refuse('input'));
  for (const stream of [child.stdout, child.stderr]) stream.on('error', () => refuse('stream'));
  const written = new Promise<void>((resolve, reject) => child.stdin.end(input.input, (error?: Error | null) => error ? reject(error) : resolve()));
  void written.then(() => { inputWriteJoined = true; }, () => { inputWriteJoined = true; refuse('input'); });
  const timer = setTimeout(() => refuse('deadline'), Math.max(0, input.deadlineMs - (performance.now() - started)));
  let joined = false;
  try {
    result = await Promise.race([Promise.all([closed, written, streamsClosed]).then(([result]) => result), failed]);
    if (performance.now() - started >= input.deadlineMs) refuse('deadline');
    else if (result.code !== 0 || result.signal !== null) refuse('exit');
  } catch { failure = true; reason ??= 'stream'; }
  finally {
    clearTimeout(timer);
    // Signal only this still-owned ChildProcess. A real runuser can forward
    // TERM to its own unreaped command; that behavior must be observed on Linux,
    // and neither the signal nor pipe closure proves descendant death.
    if (failure && child.exitCode === null && child.signalCode === null) {
      try { child.kill('SIGTERM'); } catch { refuse('stream'); }
    }
    // A descendant can inherit the launcher's pipes. On failure, close our
    // ends immediately so those handles cannot prevent the outer coordinator
    // from running. This is pipe retirement, never descendant-death evidence.
    if (failure) for (const stream of streams) stream.destroy();
    let joinTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([Promise.all([closed, streamsClosed, written.catch(() => {})]), new Promise<never>((_, reject) => {
        joinTimer = setTimeout(() => reject(undefined), 10_000);
      })]);
      joined = true;
    } catch {
      failure = true; reason ??= 'join'; for (const stream of streams) stream.destroy();
      // The original launcher is explicitly unjoined. Its process handle must
      // not prevent failure from reaching the outer UID coordinator; unref
      // neither terminates it nor changes the retained failure classification.
      if (stdiosJoined && performance.now() - started >= input.deadlineMs) child.unref();
    }
    finally { clearTimeout(joinTimer); out.close(); err.close(); }
  }
  if (failure || !joined || !result) {
    stdout.forEach(bytes => bytes.fill(0)); stderr.forEach(bytes => bytes.fill(0));
    throw new InstalledDailyCommandError(joined, diagnostic(reason ?? 'join'));
  }
  return { stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), elapsedMs: Math.floor(performance.now() - started) };
}
