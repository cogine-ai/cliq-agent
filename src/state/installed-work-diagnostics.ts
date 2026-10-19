// Diagnostic data only. No counter, clock or completion grants authority.
import { AsyncLocalStorage } from 'node:async_hooks';
import { channel } from 'node:diagnostics_channel';

export const INSTALLED_WORK_CHANNEL = 'cliq.installed.work.v1';
export type InstalledWorkKind = 'package' | 'revalidate' | 'create_compare';
export type InstalledWorkCounters = Readonly<{ started: number; completed: number; bytesRead: number; spanElapsedMs: number }>;
export type InstalledWorkSnapshot = Readonly<{
  package: InstalledWorkCounters; revalidate: InstalledWorkCounters; createCompare: InstalledWorkCounters;
}>;
type Counters = { started: number; completed: number; bytesRead: number; elapsed: number };
type Span = { kind: InstalledWorkKind; started: number; settled: boolean };
const diagnostic = channel(INSTALLED_WORK_CHANNEL), context = new AsyncLocalStorage<Span>();
const counts = (): Counters => ({ started: 0, completed: 0, bytesRead: 0, elapsed: 0 });
const counters = { package: counts(), revalidate: counts(), create_compare: counts() };
const active = new Set<Span>();
let lastPublished = -Infinity, truncated = false;

function publish(force: boolean): void {
  if (!diagnostic.hasSubscribers) return;
  try {
    const now = performance.now();
    if (!force && now - lastPublished < 1000) return;
    const snapshot = (kind: InstalledWorkKind): InstalledWorkCounters => {
      const value = counters[kind];
      let elapsed = value.elapsed;
      for (const span of active) if (span.kind === kind) elapsed += Math.max(0, now - span.started);
      const row = { started: value.started, completed: value.completed, bytesRead: value.bytesRead, spanElapsedMs: Math.floor(elapsed) };
      if (!Object.values(row).every(number => Number.isSafeInteger(number) && number >= 0)) throw 0;
      return Object.freeze(row);
    };
    if (truncated) return;
    const value: InstalledWorkSnapshot = Object.freeze({ package: snapshot('package'), revalidate: snapshot('revalidate'),
      createCompare: snapshot('create_compare') });
    lastPublished = now; diagnostic.publish(value);
  } catch {
    // A malformed/overflowed measurement is unavailable, never a rounded count.
    truncated = true;
    try { diagnostic.publish('truncated'); } catch { /* Inert diagnostic only. */ }
  }
}

/** Exact returned bytes, not requested lengths or a process-wide IO delta.
 * Nested work owns its reads exclusively; span elapsed time includes nested
 * waits and concurrent spans, so it is neither total wall time nor CPU time. */
export function noteInstalledWorkRead(bytesRead: number): void {
  const span = context.getStore();
  if (!span || span.settled || span.kind === 'create_compare') return;
  try {
    if (!Number.isSafeInteger(bytesRead) || bytesRead < 0) throw 0;
    counters[span.kind].bytesRead += bytesRead; publish(false);
  } catch {
    truncated = true;
    try { diagnostic.publish('truncated'); } catch { /* Inert diagnostic only. */ }
  }
}

/** Completed means settled, including rejection/cancellation, not verified or
 * successful. No subscriber means the original operation runs without an ALS
 * context or diagnostic output. Trusted subscribers must catch their own
 * errors: Node reports subscriber throws independently of publish(). */
export function observeInstalledWork<T>(kind: InstalledWorkKind, operation: () => Promise<T>): Promise<T> {
  if (!diagnostic.hasSubscribers || kind !== 'package' && kind !== 'revalidate' && kind !== 'create_compare') return operation();
  const span: Span = { kind, started: performance.now(), settled: false };
  counters[kind].started++; active.add(span); publish(true);
  return context.run(span, async () => {
    try { return await operation(); }
    finally {
      span.settled = true; active.delete(span);
      counters[kind].completed++; counters[kind].elapsed += Math.max(0, performance.now() - span.started);
      publish(true);
    }
  });
}
