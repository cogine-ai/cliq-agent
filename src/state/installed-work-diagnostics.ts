// Diagnostic data only. No counter, clock or completion grants authority.
import { AsyncLocalStorage } from 'node:async_hooks';
import { channel } from 'node:diagnostics_channel';

export const INSTALLED_WORK_CHANNEL = 'cliq.installed.work.v1';
export const INSTALLED_INSTALL_PHASE_CHANNEL = 'cliq.installed.install.phase.v1';
export const INSTALLED_INSTALL_PHASES = Object.freeze(['source_verify', 'destination_layout', 'signed_entries_copy',
  'manifest_bootstrap_copy', 'cas_roots_publish', 'cas_streams_publish', 'destination_verify', 'bootstrap_verify',
  'source_final_verify', 'cas_final_verify', 'directory_sync', 'source_join', 'bundle_publish',
  'selection_publish', 'destination_join', 'complete_joined'] as const);
export type InstalledInstallPhase = typeof INSTALLED_INSTALL_PHASES[number];
const installPhase = channel(INSTALLED_INSTALL_PHASE_CHANNEL);
/** Fixed data boundaries only. No subscriber means no clock, task or I/O.
 * Trusted qualification subscribers contain their own observation failures. */
export function noteInstalledInstallPhase(phase: InstalledInstallPhase, items = 0): void {
  if (!installPhase.hasSubscribers) return;
  const code = INSTALLED_INSTALL_PHASES.indexOf(phase);
  if (code < 0 || !Number.isSafeInteger(items) || items < 0 || items > 1_048_576) return;
  try { installPhase.publish(Object.freeze({ phase: code + 1, items })); }
  catch { /* Measurement is never an installation decision. */ }
}

export const INSTALLED_ASSEMBLY_WORK_CHANNEL = 'cliq.installed.assembly.work.v1';
export const INSTALLED_ASSEMBLY_WORK_PHASES = Object.freeze(['submit_request', 'submit_assembly_material',
  'submit_assembly_verifier_history', 'submit_assembly_verifier_current', 'submit_assembly_verifier_compose',
  'submit_assembly_verifier_publish', 'submit_assembly_policy', 'submit_assembly_final_check', 'original_store_stop'] as const);
export type InstalledAssemblyWorkPhase = typeof INSTALLED_ASSEMBLY_WORK_PHASES[number];
export type InstalledWorkKind = 'package' | 'revalidate' | 'create_compare';
export type InstalledWorkCounters = Readonly<{ started: number; completed: number; bytesRead: number; spanElapsedMs: number }>;
export type InstalledWorkSnapshot = Readonly<{
  package: InstalledWorkCounters; revalidate: InstalledWorkCounters; createCompare: InstalledWorkCounters;
}>;
type Counters = { started: number; completed: number; bytesRead: number; elapsed: number };
type Span = { kind: InstalledWorkKind; started: number; settled: boolean };
const diagnostic = channel(INSTALLED_WORK_CHANNEL), context = new AsyncLocalStorage<Span>();
const assemblyDiagnostic = channel(INSTALLED_ASSEMBLY_WORK_CHANNEL);
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
  if (!diagnostic.hasSubscribers && !assemblyDiagnostic.hasSubscribers || kind !== 'package' && kind !== 'revalidate' && kind !== 'create_compare') return operation();
  let span: Span;
  try {
    span = { kind, started: performance.now(), settled: false };
    counters[kind].started++; active.add(span); publish(true);
  } catch { truncateObservedWork(); return operation(); }
  return context.run(span, async () => {
    try { return await operation(); }
    finally {
      span.settled = true; active.delete(span);
      try {
        counters[kind].completed++; counters[kind].elapsed += Math.max(0, performance.now() - span.started);
        publish(true);
      } catch { truncateObservedWork(); }
    }
  });
}

type AssemblyWorkKind = 'casRead' | 'publishFour' | 'fileSync' | 'rootSync';
export type InstalledAssemblyWorkSpan = { readonly kind: AssemblyWorkKind; readonly started: number; settled: boolean };
export type InstalledAssemblySpanCounters = Readonly<{ started: number; settled: number; spanElapsedMs: number }>;
export type InstalledAssemblyReadCounters = InstalledAssemblySpanCounters & Readonly<{ bytesRead: number }>;
export type InstalledAssemblyWorkSnapshot = Readonly<{
  phase: InstalledAssemblyWorkPhase; elapsedMs: number; runtime: InstalledWorkSnapshot;
  casRead: InstalledAssemblyReadCounters; publishFour: InstalledAssemblySpanCounters;
  fileSync: InstalledAssemblySpanCounters; rootSync: InstalledAssemblySpanCounters;
}>;
const assemblyCounters = { casRead: counts(), publishFour: counts(), fileSync: counts(), rootSync: counts() };
const assemblyActive = new Set<InstalledAssemblyWorkSpan>();
let firstSubmit = false, submitOpen = false, submitStarted = 0, lastPhase = -1, assemblyTruncated = false;

function truncateAssembly(): void {
  if (assemblyTruncated) return;
  assemblyTruncated = true;
  try { assemblyDiagnostic.publish('truncated'); } catch { /* Never replace an original operation. */ }
}

function truncateObservedWork(): void {
  if (!truncated) {
    truncated = true;
    try { diagnostic.publish('truncated'); } catch { /* A failed diagnostic never replaces the original work. */ }
  }
  truncateAssembly();
}

/** A private measurement token, never a resource owner or authority. With no
 * trusted subscriber there is no token, clock sample, context or extra I/O. */
export function beginInstalledAssemblyWork(kind: AssemblyWorkKind): InstalledAssemblyWorkSpan | undefined {
  if (!assemblyDiagnostic.hasSubscribers) return;
  try {
    const span = { kind, started: performance.now(), settled: false };
    assemblyCounters[kind].started++; assemblyActive.add(span); return span;
  } catch { truncateAssembly(); return; }
}

/** Only actual returned FileHandle.read bytes belong here. No per-chunk clock
 * or output; internal publication verification receives no ordinary-read token. */
export function noteInstalledAssemblyRead(span: InstalledAssemblyWorkSpan, bytesRead: number): void {
  try {
    if (span.settled || !assemblyActive.has(span) || span.kind !== 'casRead') return;
    if (!Number.isSafeInteger(bytesRead) || bytesRead < 0) throw 0;
    assemblyCounters.casRead.bytesRead += bytesRead;
  } catch { truncateAssembly(); }
}

/** Settled includes cancellation, early generator return and failed cleanup.
 * Call only after the original finally/join, without catching its original error. */
export function settleInstalledAssemblyWork(span: InstalledAssemblyWorkSpan): void {
  try {
    if (span.settled || !assemblyActive.delete(span)) return;
    span.settled = true;
    const value = assemblyCounters[span.kind]; value.completed++;
    value.elapsed += Math.max(0, performance.now() - span.started);
  } catch { truncateAssembly(); }
}

function assemblyCut(phase: InstalledAssemblyWorkPhase): void {
  if (!assemblyDiagnostic.hasSubscribers || !submitOpen || assemblyTruncated) return;
  try {
    const index = INSTALLED_ASSEMBLY_WORK_PHASES.indexOf(phase);
    if (index <= lastPhase) return;
    const now = performance.now();
    const numbers = <T extends Record<string, number>>(value: T): Readonly<T> => {
      if (!Object.values(value).every(number => Number.isSafeInteger(number) && number >= 0)) throw 0;
      return Object.freeze(value);
    };
    const runtime = (kind: InstalledWorkKind): InstalledWorkCounters => {
      const value = counters[kind]; let elapsed = value.elapsed;
      for (const span of active) if (span.kind === kind) elapsed += Math.max(0, now - span.started);
      return numbers({ started: value.started, completed: value.completed, bytesRead: value.bytesRead, spanElapsedMs: Math.floor(elapsed) });
    };
    const cas = (kind: AssemblyWorkKind): InstalledAssemblySpanCounters => {
      const value = assemblyCounters[kind]; let elapsed = value.elapsed;
      for (const span of assemblyActive) if (span.kind === kind) elapsed += Math.max(0, now - span.started);
      return numbers({ started: value.started, settled: value.completed, spanElapsedMs: Math.floor(elapsed) });
    };
    const value: InstalledAssemblyWorkSnapshot = Object.freeze({ phase,
      elapsedMs: numbers({ value: index === 0 ? 0 : Math.floor(Math.max(0, now - submitStarted)) }).value,
      runtime: Object.freeze({ package: runtime('package'), revalidate: runtime('revalidate'), createCompare: runtime('create_compare') }),
      casRead: numbers({ ...cas('casRead'), bytesRead: assemblyCounters.casRead.bytesRead }),
      publishFour: cas('publishFour'), fileSync: cas('fileSync'), rootSync: cas('rootSync') });
    lastPhase = index; assemblyDiagnostic.publish(value);
  } catch { truncateAssembly(); }
}

/** Only the first actual submit owns this diagnostic window. Counters remain
 * process-cumulative and overlapping: sync awaits are inside publication, and
 * elapsed span sums must not be added as disjoint percentages of wall time. */
export function beginInstalledAssemblySubmit(): Readonly<{ stage(value: string): void }> | undefined {
  if (!assemblyDiagnostic.hasSubscribers) return;
  if (firstSubmit) { submitOpen = false; return; }
  try {
    firstSubmit = true; submitStarted = performance.now(); submitOpen = true;
    assemblyCut('submit_request');
    return Object.freeze({ stage(value: string): void {
      if (value === 'submit_postcommit_load') { submitOpen = false; return; }
      if (typeof value === 'string' && (INSTALLED_ASSEMBLY_WORK_PHASES as readonly string[]).includes(value))
        assemblyCut(value as InstalledAssemblyWorkPhase);
    } });
  } catch { truncateAssembly(); return; }
}

/** Synchronous original Stop entry, not an exact request-deadline sample. */
export function noteInstalledAssemblyStop(): void {
  if (!assemblyDiagnostic.hasSubscribers || !submitOpen) return;
  assemblyCut('original_store_stop'); submitOpen = false;
}
