// A real PTY consumer for input lifecycle tests only. No installed runtime,
// native credential scope, platform store, provider or usable credential.
import assert from 'node:assert/strict';
import { readTerminalCredentialSecret } from '../credential-terminal-input.js';

const mode = process.argv[2];
assert(['exact', 'edited', 'unicode', 'maximum', 'edited_boundary', 'unicode_boundary', 'oversize', 'overflow', 'eof', 'interrupt', 'signal', 'cleanup_signal', 'timeout', 'prior_raw'].includes(mode!));
process.stdin.pause();
if (mode === 'prior_raw') process.stdin.setRawMode(true);
const rawBefore = process.stdin.isRaw, pausedBefore = process.stdin.isPaused();
const listeners = ['data', 'end', 'close', 'error'].map(name => process.stdin.listenerCount(name));
const processListeners = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'].map(name => process.listenerCount(name));
const started = performance.now();
const originalWrite = process.stderr.write;
if (mode === 'cleanup_signal') process.stderr.write = function (this: typeof process.stderr, chunk: any, ...args: any[]) {
  const callback = args.at(-1);
  if (chunk === '\n' && typeof callback === 'function') args[args.length - 1] = (...values: unknown[]) => {
    // The actual newline was written. Keep its callback outstanding while the
    // real OS delivers a signal during the production prompt's final join.
    process.kill(process.pid, 'SIGTERM'); setTimeout(() => Reflect.apply(callback, undefined, values), 25);
  };
  return Reflect.apply(originalWrite, this, [chunk, ...args]);
} as typeof process.stderr.write;
let bytes: Buffer | undefined, exact = false, outcome = 'refused', code: unknown;
try {
  bytes = await readTerminalCredentialSecret();
  const expected = mode === 'maximum' ? Buffer.alloc(65536, 107)
    : mode === 'edited_boundary' ? Buffer.alloc(2048, 107)
    : mode === 'unicode_boundary' ? Buffer.concat([Buffer.alloc(2047, 107), Buffer.from('终端')])
    : Buffer.from(mode === 'unicode' ? '  fixture-e\u0301-终端  ' : '  fixture-input-bytes  ');
  exact = bytes.equals(expected); expected.fill(0); outcome = 'read';
} catch (error) { code = (error as { code?: unknown }).code; }
finally { bytes?.fill(0); process.stderr.write = originalWrite; }
console.log(JSON.stringify({ outcome, code, exact, byteCount: bytes?.length ?? 0,
  elapsedMs: Math.floor(performance.now() - started), zeroed: bytes === undefined || bytes.every(byte => byte === 0),
  rawRestored: process.stdin.isRaw === rawBefore, pausedRestored: process.stdin.isPaused() === pausedBefore,
  listenersRestored: ['data', 'end', 'close', 'error'].every((name, index) => process.stdin.listenerCount(name) === listeners[index]),
  signalsRestored: ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'].every((name, index) => process.listenerCount(name) === processListeners[index]) }));
