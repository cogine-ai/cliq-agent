// Qualification diagnosis of already-returned manager data only. This does
// not inspect units, sample clocks, stop resources or establish physical join.
import { types } from 'node:util';

export const UNIT_STOP_ACTIVE_STATES = Object.freeze(['active', 'reloading', 'inactive', 'failed', 'activating',
  'deactivating', 'maintenance', 'unclassified'] as const);
export const UNIT_STOP_SUB_STATES = Object.freeze(['running', 'dead', 'failed', 'exited', 'start', 'start-pre', 'start-post',
  'auto-restart', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-sigterm', 'final-sigkill', 'unclassified'] as const);
export const UNIT_STOP_RESULTS = Object.freeze(['success', 'resources', 'timeout', 'exit-code', 'signal', 'core-dump',
  'watchdog', 'start-limit-hit', 'protocol', 'oom-kill', 'exec-condition', 'unclassified'] as const);
type Snapshot = Readonly<{ activeState: typeof UNIT_STOP_ACTIVE_STATES[number]; subState: typeof UNIT_STOP_SUB_STATES[number];
  result: typeof UNIT_STOP_RESULTS[number]; mainPidZero: boolean; execMainPidZero: boolean; mainPidMatchesExec: boolean;
  execMainCode: number; execMainStatus: number }>;
type Unit = Readonly<{ role: 'supervisor' | 'keeper'; before: Snapshot; after: Snapshot;
  sameNonzeroMainPid: boolean; sameNonemptyInvocation: boolean }>;
export type InstalledUnitStopObservation = Readonly<{ diagnosticOnly: true; kind: 'observed'; units: readonly [Unit, Unit] }> |
  Readonly<{ diagnosticOnly: true; kind: 'unavailable'; reason: 'fixed_unit_projection_refused' }>;
const unavailable = Object.freeze({ diagnosticOnly: true, kind: 'unavailable', reason: 'fixed_unit_projection_refused' } as const);
function refuse(): never { throw new TypeError('fixed unit data unavailable'); }
function pair(value: unknown): readonly [unknown, unknown] {
  if (!Array.isArray(value) || types.isProxy(value) || value.length !== 2 || Reflect.ownKeys(value).length !== 3) return refuse();
  const rows = [0, 1].map(index => {
    const row = Object.getOwnPropertyDescriptor(value, String(index));
    if (!row || !row.enumerable || !Object.hasOwn(row, 'value')) return refuse();
    return row.value as unknown;
  });
  return [rows[0], rows[1]];
}
function data(value: unknown) {
  if (!value || typeof value !== 'object' || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return refuse();
  const field = (key: string): string => {
    const row = Object.getOwnPropertyDescriptor(value, key);
    if (!row || !row.enumerable || !Object.hasOwn(row, 'value') || typeof row.value !== 'string' || row.value.length > 128) return refuse();
    return row.value;
  };
  const number = (key: string, maximum: number): number => {
    const text = field(key); if (!/^(0|[1-9][0-9]{0,9})$/u.test(text)) return refuse();
    const value = Number(text); if (!Number.isSafeInteger(value) || value > maximum) return refuse(); return value;
  };
  const enumeration = <T extends string>(key: string, values: readonly T[]): T => {
    const actual = field(key); return values.find(value => value === actual) ?? 'unclassified' as T;
  };
  const mainPid = number('MainPID', 2147483647), execMainPid = number('ExecMainPID', 2147483647), invocation = field('InvocationID');
  if (invocation !== '' && !/^[a-f0-9]{32}$/u.test(invocation)) return refuse();
  const snapshot: Snapshot = Object.freeze({ activeState: enumeration('ActiveState', UNIT_STOP_ACTIVE_STATES),
    subState: enumeration('SubState', UNIT_STOP_SUB_STATES), result: enumeration('Result', UNIT_STOP_RESULTS),
    mainPidZero: mainPid === 0, execMainPidZero: execMainPid === 0, mainPidMatchesExec: mainPid === execMainPid,
    execMainCode: number('ExecMainCode', 65535), execMainStatus: number('ExecMainStatus', 65535) });
  return { snapshot, mainPid, invocation };
}
/** A malformed observation produces only one closed unavailable variant.
 * The caller retains its original show/stop/assert operations and failures. */
export function projectInstalledUnitStopObservation(before: unknown, after: unknown): InstalledUnitStopObservation {
  try {
    const previous = pair(before), current = pair(after);
    const unit = (role: Unit['role'], index: 0 | 1): Unit => {
      const original = data(previous[index]), stopped = data(current[index]);
      return Object.freeze({ role, before: original.snapshot, after: stopped.snapshot,
        sameNonzeroMainPid: original.mainPid !== 0 && original.mainPid === stopped.mainPid,
        sameNonemptyInvocation: original.invocation !== '' && original.invocation === stopped.invocation });
    };
    return Object.freeze({ diagnosticOnly: true, kind: 'observed', units: Object.freeze([unit('supervisor', 0), unit('keeper', 1)] as const) });
  } catch { return unavailable; }
}
