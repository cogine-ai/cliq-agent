// Fixed retained data only, never process, deadline, permission or join proof.
import assert from 'node:assert/strict';
import { types } from 'node:util';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { INSTALLED_APPLY_DIAGNOSTIC_STAGES, INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES,
  INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES, INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES,
  INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS, INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES,
  INSTALLED_PUBLICATION_DIAGNOSTIC_PHASES } from '../../../src/state/installed-run-diagnostics.js';

const stages: ReadonlySet<string> = new Set(INSTALLED_APPLY_DIAGNOSTIC_STAGES);
const authorizationStages: ReadonlySet<string> = new Set(INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES);
const phases: ReadonlySet<string> = new Set(INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES);
const origins: ReadonlySet<string> = new Set(INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS);
const classes: ReadonlySet<string> = new Set(INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES);
const codes: ReadonlySet<string> = new Set(INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES);
function need(value: unknown): asserts value { assert(value, 'invalid fixed installed Store diagnostic journal'); }
function count(value: string): number {
  need(/^(0|[1-9][0-9]{0,15})$/u.test(value));
  const result = Number(value); need(Number.isSafeInteger(result)); return result;
}
function bit(value: string): boolean { need(value === '0' || value === '1'); return value === '1'; }
function errorFields(errorClass: string, code: string, sqlite: string) {
  need(classes.has(errorClass) && codes.has(code));
  const sqliteCode = sqlite === '-' ? null : count(sqlite);
  need(code === 'ERR_SQLITE_ERROR' ? errorClass === 'sqlite' && (sqliteCode === null || sqliteCode <= 2147483647)
    : errorClass !== 'sqlite' && sqliteCode === null);
  return { errorClass, code, sqliteCode };
}
function failure(closing: string, errorClass: string, code: string, sqlite: string) {
  return { closing: bit(closing), ...errorFields(errorClass, code, sqlite) };
}

type OriginalJournalIdentity = Readonly<{ uid: number; pid: number; invocationId: string }>;
function originalJournalMessages(text: string, expected: OriginalJournalIdentity) {
  need(typeof text === 'string' && Buffer.byteLength(text, 'utf8') <= 256 * 1024);
  need(expected && typeof expected === 'object' && !types.isProxy(expected) && !Array.isArray(expected) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(expected)));
  const fields = Object.getOwnPropertyDescriptors(expected), keys = ['uid', 'pid', 'invocationId'];
  need(Reflect.ownKeys(fields).length === 3);
  for (const key of keys) need(fields[key] && fields[key]!.enumerable && Object.hasOwn(fields[key]!, 'value'));
  const uid = fields.uid!.value!, pid = fields.pid!.value!, invocationId = fields.invocationId!.value;
  need(Number.isSafeInteger(uid) && uid > 0 && Number.isSafeInteger(pid) && pid > 0);
  need(typeof invocationId === 'string' && invocationId.length === 32 && /^[0-9a-f]{32}$/u.test(invocationId));
  const lines = text.trim().split('\n').filter(Boolean); need(lines.length <= 80);
  return lines.map(line => {
    const record = parseJsonStrict(line) as Record<string, unknown>;
    need(record && typeof record === 'object' && !Array.isArray(record));
    need(record._UID === String(uid) && record._PID === String(pid));
    need(record._TRANSPORT === 'stdout' && record._SYSTEMD_INVOCATION_ID === invocationId);
    need(typeof record.MESSAGE === 'string');
    return record.MESSAGE;
  });
}

/** The caller must independently bind the live original image/start and later
 * establish its real stop/join before this one whole-window read. */
export function readInstalledStoreDiagnosticJournal(text: string, expected: OriginalJournalIdentity) {
  const rows: string[][] = [];
  for (const message of originalJournalMessages(text, expected)) {
    if (!message.startsWith('CLIQ_STORE_DIAG_V1')) continue;
    need(message.length <= 255 && /^[\x20-\x7e]+$/u.test(message));
    rows.push(message.split(':'));
  }
  if (!rows.length) return undefined;
  need(rows.length <= 16 && rows.reduce((bytes, row) => bytes + row.join(':').length + 1, 0) <= 4096);
  need(rows.every(row => row[0] === 'CLIQ_STORE_DIAG_V1'));
  const start = rows[0]!; need(start.length === 4 && start[1] === 'begin');
  const applyFailures = count(start[2]!), schedulerFailures = count(start[3]!);
  let cursor = 1;
  let firstApplyFailure: Readonly<ReturnType<typeof failure> & { stage: string }> | null = null;
  let firstSchedulerFailure: Readonly<ReturnType<typeof failure> & { origin: string; phase: string }> | null = null;
  if (applyFailures > 0) {
    const row = rows[cursor++]; need(row && row.length === 7 && row[1] === 'apply' && stages.has(row[2]!));
    firstApplyFailure = Object.freeze({ stage: row[2]!, ...failure(row[3]!, row[4]!, row[5]!, row[6]!) });
  }
  if (schedulerFailures > 0) {
    const row = rows[cursor++]; need(row && row.length === 8 && row[1] === 'scheduler' && origins.has(row[2]!));
    need(row[3] === 'unavailable' || phases.has(row[3]!));
    firstSchedulerFailure = Object.freeze({ origin: row[2]!, phase: row[3]!, ...failure(row[4]!, row[5]!, row[6]!, row[7]!) });
  }
  let schedulerFailuresBeforeStop: number | undefined;
  let lastSchedulerFailure: typeof firstSchedulerFailure = null;
  if (rows[cursor]?.[1] === 'scheduler_window') {
    const window = rows[cursor++]!; need(window.length === 3);
    schedulerFailuresBeforeStop = count(window[2]!); need(schedulerFailuresBeforeStop <= schedulerFailures);
    if (schedulerFailures > 0) {
      const row = rows[cursor++]; need(row && row.length === 8 && row[1] === 'scheduler_last' && origins.has(row[2]!));
      need(row[3] === 'unavailable' || phases.has(row[3]!));
      lastSchedulerFailure = Object.freeze({ origin: row[2]!, phase: row[3]!, ...failure(row[4]!, row[5]!, row[6]!, row[7]!) });
      if (schedulerFailures === 1) need(JSON.stringify(lastSchedulerFailure) === JSON.stringify(firstSchedulerFailure));
    }
  }
  let authorizationFailures: number | undefined;
  let firstAuthorizationFailure: Readonly<ReturnType<typeof errorFields> & { stage: string }> | undefined;
  if (rows[cursor]?.[1] === 'authorization') {
    const row = rows[cursor++]!; need(row.length === 7 && authorizationStages.has(row[3]!));
    authorizationFailures = count(row[2]!); need(authorizationFailures > 0);
    firstAuthorizationFailure = Object.freeze({ stage: row[3]!, ...errorFields(row[4]!, row[5]!, row[6]!) });
  }
  const stopped = rows[cursor++]; need(stopped && stopped.length === 7 && stopped[1] === 'stop');
  const [driverTasks, agentLoads, admissions, retainedFailures] = stopped.slice(2, 6).map(count) as [number, number, number, number];
  const globalFailure = bit(stopped[6]!);
  const phaseCounts: Record<string, number> = {}; let previous = '', total = 0, phaseRows = 0;
  while (rows[cursor]?.[1] === 'phase') {
    const row = rows[cursor++]!;
    need(row.length === 4 && phases.has(row[2]!) && row[2]! > previous && ++phaseRows <= 8);
    const value = count(row[3]!); need(value > 0 && value <= 1000);
    phaseCounts[row[2]!] = value; previous = row[2]!; total += value;
  }
  need(total <= driverTasks && total <= 1000);
  need(rows[cursor]?.length === 2 && rows[cursor]![1] === 'end' && cursor === rows.length - 1);
  return Object.freeze({ applyFailures, schedulerFailures, firstApplyFailure, firstSchedulerFailure,
    stop: Object.freeze({ driverTasks, agentLoads, admissions, retainedFailures, globalFailure, phases: Object.freeze(phaseCounts) }),
    ...(schedulerFailuresBeforeStop === undefined ? {} : { schedulerFailuresBeforeStop, lastSchedulerFailure }),
    ...(firstAuthorizationFailure ? { authorizationFailures: authorizationFailures!, firstAuthorizationFailure } : {}) });
}
export type InstalledStoreDiagnosticSummary = NonNullable<ReturnType<typeof readInstalledStoreDiagnosticJournal>>;

/** First arrival of each fixed phase, not a Run attribution, latest phase,
 * completed task, original resource join or physical publication proof. The
 * caller independently binds the original live image/start and later PID
 * absence; an abnormal exit is allowed only for this inert observation. */
export function readInstalledPublicationStageJournal(text: string, expected: OriginalJournalIdentity) {
  const rows = originalJournalMessages(text, expected).filter(message => message.startsWith('CLIQ_PUBLICATION_STAGE_V1'));
  if (!rows.length) return;
  need(rows.length <= 6 && rows.reduce((bytes, row) => bytes + row.length + 1, 0) <= 512);
  const vocabulary: ReadonlySet<string> = new Set(INSTALLED_PUBLICATION_DIAGNOSTIC_PHASES);
  const phases: string[] = [];
  for (const [index, row] of rows.entries()) {
    need(row.length <= 96 && /^[\x20-\x7e]+$/u.test(row));
    const fields = row.split(':');
    need(fields.length === 3 && fields[0] === 'CLIQ_PUBLICATION_STAGE_V1' && fields[1] === String(index + 1));
    need(vocabulary.has(fields[2]!) && !phases.includes(fields[2]!)); phases.push(fields[2]!);
  }
  return Object.freeze({ phases: Object.freeze(phases) });
}

/** One current driver phase at the original Stop entry, never a Run
 * attribution, completed task, original resource join or stop proof. */
export function readInstalledStoreStopPhaseJournal(text: string, expected: OriginalJournalIdentity) {
  const rows = originalJournalMessages(text, expected).filter(message => message.startsWith('CLIQ_STORE_STOP_PHASE'));
  if (!rows.length) return;
  need(rows.length === 1);
  const row = rows[0]!;
  need(Buffer.byteLength(row, 'utf8') + 1 <= 96 && /^[\x20-\x7e]+$/u.test(row));
  const fields = row.split(':');
  need(fields.length === 2 && fields[0] === 'CLIQ_STORE_STOP_PHASE_V1' && phases.has(fields[1]!));
  return Object.freeze({ phase: fields[1]! });
}
