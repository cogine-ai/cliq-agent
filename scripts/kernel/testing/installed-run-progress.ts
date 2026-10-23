// Bounded diagnostic data only; never an installed Run or execution proof.
import { types } from 'node:util';
import { CONTROL_FRAME_BYTES, controlWireInteger, controlWireRecord,
  decodeInstalledControlEnvelope, decodeInstalledControlResponse } from '../../../src/kernel/control-wire.js';
import { MAX_JSON_CONTAINER_ENTRIES, MAX_JSON_DEPTH } from '../../../src/kernel/json.js';
import type { InvocationJournalEntry, InvocationPhase, RunNextStep, RunStatus } from '../../../src/kernel/types.js';

const CASES = ['required_pass', 'required_repair', 'advisory_failure', 'required_timeout',
  'delivery_publish', 'delivery_merge', 'delivery_cancel'] as const;
type CaseKind = typeof CASES[number];
export type InstalledRunProgress = Readonly<{
  diagnosticOnly: true; source: 'actual_public_run_get'; caseKind: CaseKind; postCount: number;
  status: RunStatus; nextStep: RunNextStep; revision: number; activeWorkerRecorded: boolean;
  waitingRecorded: boolean; cancelRequested: boolean; completeCut: boolean;
  counts: Readonly<{ items: number; journal: number; checkpoints: number; highWaterItemSeq: number;
    highWaterJournalSeq: number; nextItemSeq: number; nextJournalSeq: number }>;
  phaseCounts: Readonly<Record<InvocationPhase, number>>;
  lastJournal: Readonly<Pick<InvocationJournalEntry, 'opKind' | 'phase' | 'attempt'>> | null;
  recordedElapsed: Readonly<{ latestRunUpdateMs: number; lastJournalMs: number | null }>;
}>;
function invalid(): never { throw new TypeError('invalid bounded installed Run progress data'); }

/** Copy data descriptors before any production decoder can read properties.
 * No getter, Proxy trap, toJSON, sparse entry or caller object is retained. */
function copyData(input: unknown): unknown {
  let entries = 0, stringBytes = 0;
  const ancestors = new Set<object>();
  const text = (value: string) => {
    if (value.length > CONTROL_FRAME_BYTES) invalid();
    stringBytes += Buffer.byteLength(value);
    if (stringBytes > CONTROL_FRAME_BYTES) invalid();
  };
  const copy = (value: unknown, depth: number): unknown => {
    if (typeof value === 'string') { text(value); return value; }
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value !== 'object' || value === null || types.isProxy(value) || depth >= MAX_JSON_DEPTH || ancestors.has(value)) invalid();
    const array = Array.isArray(value), prototype = Object.getPrototypeOf(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) invalid();
    const fields = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(fields);
    const length = array ? fields.length?.value : undefined;
    if (array && (!Number.isSafeInteger(length) || length < 0 || length > MAX_JSON_CONTAINER_ENTRIES || keys.length !== length + 1)) invalid();
    entries += array ? length : keys.length;
    if (entries > MAX_JSON_CONTAINER_ENTRIES) invalid();
    const result: Record<string, unknown> | unknown[] = array ? [] : {};
    ancestors.add(value);
    try {
      for (const key of keys) {
        if (array && key === 'length') continue;
        if (typeof key !== 'string') invalid();
        const field = fields[key]!;
        if (!field.enumerable || !Object.hasOwn(field, 'value')) invalid();
        if (array && (!/^(?:0|[1-9][0-9]*)$/u.test(key) || Number(key) >= length)) invalid();
        if (!array) text(key);
        Object.defineProperty(result, key, { value: copy(field.value, depth + 1), enumerable: true, writable: true, configurable: true });
      }
    } finally { ancestors.delete(value); }
    return result;
  };
  return copy(input, 0);
}

/** Projects one already obtained public response, never queries or repairs it.
 * Prefix pages remain useful diagnostics but cannot claim a complete cut. */
export function projectInstalledRunProgress(input: unknown): InstalledRunProgress {
  const data = controlWireRecord(copyData(input), ['caseKind', 'cut', 'postCount']);
  if (typeof data.caseKind !== 'string' || !(CASES as readonly string[]).includes(data.caseKind)) invalid();
  const postCount = controlWireInteger(data.postCount, 0, 10);
  const envelope = { protocolVersion: 1 as const, ok: true as const, result: data.cut };
  const decoded = decodeInstalledControlEnvelope(envelope, 'run.get');
  if (!decoded.ok) invalid();
  // Retain the production request/page binding as well as the closed envelope.
  // These fixed cursors describe the original from-zero qualification read.
  const response = decodeInstalledControlResponse(envelope, { protocolVersion: 1, method: 'run.get',
    runId: decoded.result.snapshot.run.id, afterItemSeq: 0, afterJournalSeq: 0,
    itemLimit: 1000, journalLimit: 1000, checkpointLimit: 1000 });
  if (!response.ok) invalid();
  const cut = response.result, run = cut.snapshot.run;
  const phaseCounts: Record<InvocationPhase, number> = { prepared: 0, dispatch_claimed: 0, completed: 0, failed: 0, unknown: 0, abandoned: 0 };
  for (const row of cut.journal) phaseCounts[row.phase]++;
  const last = cut.journal.at(-1);
  // Relative retained timestamps only, never a live age or deadline proof.
  const offset = (timestamp: string): number => {
    const elapsed = Date.parse(timestamp) - Date.parse(run.createdAt);
    if (!Number.isSafeInteger(elapsed) || elapsed < 0) invalid();
    return elapsed;
  };
  return Object.freeze({ diagnosticOnly: true, source: 'actual_public_run_get', caseKind: data.caseKind as CaseKind, postCount,
    status: run.status, nextStep: run.nextStep, revision: run.revision, activeWorkerRecorded: run.activeWorkerLaunchId !== undefined,
    waitingRecorded: run.waitingOnRef !== undefined, cancelRequested: run.cancelRequested,
    completeCut: cut.nextItemSeq === cut.highWaterItemSeq && cut.nextJournalSeq === cut.highWaterJournalSeq &&
      cut.nextCheckpointCursor === cut.highWaterCheckpointCursor,
    counts: Object.freeze({ items: cut.items.length, journal: cut.journal.length, checkpoints: cut.checkpoints.length,
      highWaterItemSeq: cut.highWaterItemSeq, highWaterJournalSeq: cut.highWaterJournalSeq,
      nextItemSeq: cut.nextItemSeq, nextJournalSeq: cut.nextJournalSeq }),
    phaseCounts: Object.freeze(phaseCounts),
    lastJournal: last ? Object.freeze({ opKind: last.opKind, phase: last.phase, attempt: last.attempt }) : null,
    recordedElapsed: Object.freeze({ latestRunUpdateMs: offset(run.updatedAt), lastJournalMs: last ? offset(last.timestamp) : null }) });
}
