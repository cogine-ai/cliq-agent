import { spawn } from 'node:child_process';
import type { FileHandle } from 'node:fs/promises';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

export const INSTALLED_LOCAL_MODEL_MODE = '--installed-models';
// Each of 16,384 entries contains at most 512 UTF-8 bytes of model text.
// JCS can use six bytes per input byte, plus the fixed summary fields.
export const INSTALLED_LOCAL_MODEL_RESPONSE_LIMIT = 64 * 1024 ** 2;
export const INSTALLED_LOCAL_MODEL_EXIT = Object.freeze({
  invalidRequest: 64, unavailable: 69, refused: 70, retirement: 74, cancelled: 75, notFound: 77
});

/** Run only the fixed model registry role on the already-held verified SEA
 * descriptor. The caller owns it through exit and stdio close. */
export async function joinInstalledLocalModelRole(image: FileHandle, stateRoot: string, bundle: string,
  rootLocator: string, command: string, signal?: AbortSignal): Promise<Buffer> {
  signal?.throwIfAborted();
  const child = spawn('/proc/self/fd/3', [INSTALLED_LOCAL_MODEL_MODE, stateRoot, bundle, rootLocator, command], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
    stdio: ['ignore', 'pipe', 'ignore', image.fd]
  });
  const parts: Buffer[] = [];
  let size = 0, failure: unknown, deadline: ReturnType<typeof setTimeout> | undefined;
  let forced = false;
  const stop = () => {
    if (deadline || child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGTERM');
    deadline = setTimeout(() => {
      forced = true;
      child.kill('SIGKILL');
    }, 2000);
  };
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve =>
    child.once('close', (code, exitedSignal) => resolve({ code, signal: exitedSignal })));
  child.once('error', error => { failure ??= error; });
  child.stdout!.once('error', error => { failure ??= error; stop(); });
  child.stdout!.on('data', (part: Buffer) => {
    if (failure !== undefined) return;
    size += part.length;
    if (size > INSTALLED_LOCAL_MODEL_RESPONSE_LIMIT) {
      failure = new TypeError('installed model response exceeds its bound');
      stop();
    } else parts.push(part);
  });
  signal?.addEventListener('abort', stop, { once: true });
  if (signal?.aborted) stop();
  let exit: Awaited<typeof closed>;
  try { exit = await closed; }
  finally { clearTimeout(deadline); signal?.removeEventListener('abort', stop); }
  if (forced || exit.code === INSTALLED_LOCAL_MODEL_EXIT.retirement || exit.signal !== null)
    throw new ResourceRetirementError('installed model operation did not report a clean resource join', failure);
  if (failure !== undefined)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed model operation did not complete its fixed process protocol');
  signal?.throwIfAborted();
  if (exit.code !== 0 || !size) {
    const code = exit.code === INSTALLED_LOCAL_MODEL_EXIT.notFound ? 'NOT_FOUND'
      : exit.code === INSTALLED_LOCAL_MODEL_EXIT.unavailable ? 'UNSUPPORTED_PLATFORM'
      : exit.code === INSTALLED_LOCAL_MODEL_EXIT.invalidRequest ? 'INVALID_REQUEST' : 'RECOVERY_REQUIRED';
    throw new KernelStorageError(code, code === 'NOT_FOUND' ? 'local model is not registered'
      : code === 'UNSUPPORTED_PLATFORM' ? 'the signed local inference recipe is unavailable'
      : 'installed model operation refused its original request');
  }
  return Buffer.concat(parts, size);
}
