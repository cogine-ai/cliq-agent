// Source-owned, bounded diagnostic of a real fixture command. This is not a
// timeout, cancellation, process-death proof or a replacement for joining it.
import type { SpawnSyncReturns } from 'node:child_process';

export function fixtureCommandJoinDiagnostic(result: Pick<SpawnSyncReturns<Buffer>, 'error' | 'signal' | 'status'>,
  originalDeadlineMs: number, started: number) {
  if (!result.error && result.signal === null) return undefined;
  const errorKind = result.error ? ('code' in result.error && result.error.code === 'ETIMEDOUT' ? 'timeout' as const : 'spawn' as const) : 'signal' as const;
  return Object.freeze({ diagnosticOnly: true as const, errorKind, originalDeadlineMs,
    elapsedMs: Math.floor(performance.now() - started), exitCode: result.status,
    signal: result.signal === null || result.signal === 'SIGTERM' || result.signal === 'SIGKILL' ? result.signal : 'other' as const });
}
