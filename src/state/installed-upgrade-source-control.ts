import { spawn } from 'node:child_process';
import type { FileHandle } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

export const UPGRADE_SOURCE_CONTROL_MODE = '--upgrade-source-control';
export const UPGRADE_SOURCE_CONTROL_RETIREMENT = 'CLIQ_UPGRADE_SOURCE_CONTROL_RETIREMENT_V1\n';

/** Internal fixed readonly child, not a runner or an execution/retirement
 * receipt. The caller holds and fully verifies the signed target SEA image.
 * exec follows its inherited original FD, never a reopened pathname. The old
 * helper lives only in this child; the parent retains its single-image gate. */
export async function joinInstalledUpgradeSourceControl(image: FileHandle, stateRoot: string,
  sourceBundleRef: string, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  const env: NodeJS.ProcessEnv = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' };
  for (const key of ['HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS']) if (process.env[key] !== undefined) env[key] = process.env[key];
  const child = spawn('/proc/self/fd/3', [UPGRADE_SOURCE_CONTROL_MODE, stateRoot, sourceBundleRef],
    { env, stdio: ['ignore', 'pipe', 'pipe', image.fd] });
  let spawnFailure: unknown, overflow = false, stdoutBytes = 0, stderrBytes = 0;
  const errors: Buffer[] = []; let cancellationAt: number | undefined;
  const kill = () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); };
  const cancel = () => { cancellationAt ??= performance.now(); kill(); };
  child.once('error', error => { spawnFailure = error; });
  for (const stream of [child.stdout!, child.stderr!]) stream.once('error', error => { spawnFailure ??= error; kill(); });
  child.stdout!.on('data', (value: Buffer) => { stdoutBytes += value.length; if (stdoutBytes) { overflow = true; kill(); } });
  child.stderr!.on('data', (value: Buffer) => {
    stderrBytes += value.length;
    if (stderrBytes > 4096) { overflow = true; kill(); } else errors.push(Buffer.from(value));
  });
  // close joins exit AND all inherited stdio. An aborted child cannot remain
  // alive beneath a returned promise or its parent's image/source FD close.
  const result = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve =>
    child.once('close', (code, closedSignal) => resolve({ code, signal: closedSignal })));
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) cancel();
  let closed: Awaited<typeof result>;
  try { closed = await result; }
  finally { signal?.removeEventListener('abort', cancel); }
  const diagnostic = Buffer.concat(errors).toString('utf8');
  if (diagnostic.includes(UPGRADE_SOURCE_CONTROL_RETIREMENT) || cancellationAt !== undefined && performance.now() - cancellationAt >= 2000)
    throw new ResourceRetirementError('readonly original control child did not retire within its original limit', spawnFailure);
  if (overflow || spawnFailure) throw new KernelStorageError('ARTIFACT_MISMATCH', 'readonly original control child refused its owned protocol');
  if (cancellationAt !== undefined && closed.signal === 'SIGKILL') { signal!.throwIfAborted(); }
  if (closed.code !== 0 || closed.signal !== null)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'readonly original control child did not authenticate the exact source');
  signal?.throwIfAborted();
}
