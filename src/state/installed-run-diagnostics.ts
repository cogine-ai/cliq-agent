import { channel } from 'node:diagnostics_channel';
import { types } from 'node:util';
import { KernelStorageError, ResourceRetirementError } from './errors.js';

export const INSTALLED_RUN_FAILURE_CHANNEL = 'cliq.installed.run.failures.v1';
export const INSTALLED_APPLY_DIAGNOSTIC_STAGES = Object.freeze(['request', 'replay', 'capture_source', 'capture',
  'source', 'prepare', 'admit', 'postcommit_load'] as const);
export type InstalledApplyDiagnosticStage = typeof INSTALLED_APPLY_DIAGNOSTIC_STAGES[number];
const applyStages: ReadonlySet<string> = new Set(INSTALLED_APPLY_DIAGNOSTIC_STAGES);
const diagnostic = channel(INSTALLED_RUN_FAILURE_CHANNEL);
export const INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES = Object.freeze(['scheduled', 'drive_material', 'drive_agent', 'drive_retirement',
  'drive_retirement_history', 'drive_retirement_quarantine_closure', 'drive_retirement_native_retirement',
  'drive_retirement_workspace_observation', 'drive_retirement_retirement_commit', 'drive_retirement_resource_join',
  'drive_verify', 'drive_finalize', 'terminal_retirement', 'result_recovery', 'result_basis', 'result_finalization',
  'result_publication', 'result_session', 'result_commit', 'result_recovery_spec', 'result_recovery_context',
  'result_recovery_journal', 'result_recovery_generations', 'result_recovery_history', 'result_recovery_history_model',
  'result_recovery_history_items', 'result_recovery_history_candidate', 'result_recovery_history_verifier',
  'result_recovery_history_tool', 'result_recovery_history_input', 'result_recovery_history_broker', 'result_recovery_seals',
  'result_recovery_terminal'] as const);
const schedulerPhases: ReadonlySet<string> = new Set(INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES);
export const INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS = Object.freeze(['drive', 'maintenance', 'maintenance_global', 'stop',
  'publication_recovery'] as const);
type SchedulerOrigin = typeof INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS[number];
const origins: ReadonlySet<string> = new Set(INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS);
export const INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES = Object.freeze(['ADMISSION_KEY_CONFLICT', 'REQUEST_ID_CONFLICT', 'ARTIFACT_MISMATCH', 'AGENT_HANDOFF_PENDING',
  'MODEL_RETRY_PENDING', 'BUDGET_EXHAUSTED', 'EVENT_CURSOR_EXPIRED', 'INVALID_REQUEST', 'LEASE_FENCED', 'NOT_FOUND',
  'RECOVERY_REQUIRED', 'REVISION_CONFLICT', 'STATE_TRANSITION_INVALID', 'UNSUPPORTED_PLATFORM', 'ERR_SQLITE_ERROR', 'none'] as const);
export const INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES = Object.freeze(['resource_retirement', 'kernel', 'sqlite', 'type', 'syntax', 'other'] as const);
const codes: ReadonlySet<string> = new Set(INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES);

/** A fixed classification only. Never inspect a message, stack, cause, path or
 * inherited/accessor value; even a proxy rejection remains the original error. */
function projectError(error: unknown) {
  let errorClass = 'other', code = 'none', sqliteCode: number | null = null;
  try {
    if (!error || typeof error !== 'object' || types.isProxy(error) || !types.isNativeError(error))
      return { errorClass, code, sqliteCode };
    const prototype = Object.getPrototypeOf(error), field = Object.getOwnPropertyDescriptor(error, 'code');
    if (prototype === ResourceRetirementError.prototype) errorClass = 'resource_retirement';
    else if (prototype === KernelStorageError.prototype) errorClass = 'kernel';
    else if (prototype === TypeError.prototype) errorClass = 'type';
    else if (prototype === SyntaxError.prototype) errorClass = 'syntax';
    if (field && Object.hasOwn(field, 'value') && typeof field.value === 'string' && codes.has(field.value)) code = field.value;
    if (code === 'ERR_SQLITE_ERROR') {
      errorClass = 'sqlite';
      const sqlite = Object.getOwnPropertyDescriptor(error, 'errcode');
      if (sqlite && Object.hasOwn(sqlite, 'value') && Number.isSafeInteger(sqlite.value) && sqlite.value >= 0 && sqlite.value <= 2147483647)
        sqliteCode = sqlite.value;
    }
  } catch { /* Missing diagnostic data never replaces the original rejection. */ }
  return { errorClass, code, sqliteCode };
}

/** Trusted image subscription only: an ordinary image allocates no tracker,
 * reads no error fields and samples no clock. Subscriber errors must be caught
 * by that trusted composition, as with the existing fixed phase channels. */
export function beginInstalledApplyDiagnostic() {
  if (!diagnostic.hasSubscribers) return;
  let current: InstalledApplyDiagnosticStage = 'request';
  return Object.freeze({
    stage(value: InstalledApplyDiagnosticStage): void {
      if (typeof value === 'string' && applyStages.has(value)) current = value;
    },
    failure(error: unknown, closing: boolean): void {
      try {
        if (typeof closing !== 'boolean') return;
        diagnostic.publish(Object.freeze({ kind: 'apply_failure', stage: current, closing, ...projectError(error) }));
      } catch { /* A diagnostic cannot decide an operation. */ }
    }
  });
}
export type InstalledApplyDiagnostic = NonNullable<ReturnType<typeof beginInstalledApplyDiagnostic>>;

export const INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES = Object.freeze(['request', 'current_channel', 'replay', 'selected_toolchain',
  'publish_request', 'publish_response', 'channel_recheck', 'transaction'] as const);
type AuthorizationDiagnosticStage = typeof INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES[number];
const authorizationStages: ReadonlySet<string> = new Set(INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES);

/** Original authorization failure data only. This module cannot observe the
 * Store's close gate, so it supplies no inferred closing or commit claim. */
export function beginInstalledAuthorizationDiagnostic() {
  if (!diagnostic.hasSubscribers) return;
  let current: AuthorizationDiagnosticStage = 'request';
  return Object.freeze({
    stage(value: AuthorizationDiagnosticStage): void {
      if (typeof value === 'string' && authorizationStages.has(value)) current = value;
    },
    failure(error: unknown): void {
      try { diagnostic.publish(Object.freeze({ kind: 'authorization_failure', stage: current, ...projectError(error) })); }
      catch { /* A diagnostic cannot decide or replace the original failure. */ }
    }
  });
}

export function beginInstalledSchedulerDiagnostic(origin: SchedulerOrigin) {
  if (!diagnostic.hasSubscribers || typeof origin !== 'string' || !origins.has(origin)) return;
  let current = 'unavailable';
  return Object.freeze({
    phase(value: unknown): void {
      current = typeof value === 'string' && schedulerPhases.has(value) ? value : 'unavailable';
    },
    failure(error: unknown, closing: boolean): void {
      try {
        if (typeof closing !== 'boolean') return;
        diagnostic.publish(Object.freeze({ kind: 'scheduler_failure', origin, phase: current, closing, ...projectError(error) }));
      } catch { /* A diagnostic cannot decide an operation. */ }
    }
  });
}

export function installedRunDiagnosticsSubscribed(): boolean { return diagnostic.hasSubscribers; }

/** Called before the existing close gate/revocation. These are a current
 * process-local observation, not a Run status, failure proof or joined result. */
export function noteInstalledStoreStop(input: unknown): void {
  if (!diagnostic.hasSubscribers) return;
  try {
    if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(input))) return;
    const fields = Object.getOwnPropertyDescriptors(input);
    const keys = ['driverTasks', 'agentLoads', 'admissions', 'retainedFailures', 'globalFailure', 'phases'];
    if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] ||
        !fields[key].enumerable || !Object.hasOwn(fields[key], 'value'))) return;
    const counts = keys.slice(0, 4).map(key => fields[key]!.value);
    if (counts.some(count => !Number.isSafeInteger(count) || count < 0) || typeof fields.globalFailure!.value !== 'boolean') return;
    const phases: unknown = fields.phases!.value;
    if (!Array.isArray(phases) || types.isProxy(phases) || Object.getPrototypeOf(phases) !== Array.prototype) return;
    const entries = Object.getOwnPropertyDescriptors(phases) as unknown as Record<string, PropertyDescriptor>;
    const length = entries.length!.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > 1000 || Reflect.ownKeys(entries).length !== length + 1) return;
    const multiplicities = new Map<string, number>();
    for (let index = 0; index < length; index++) {
      const entry = entries[String(index)];
      if (!entry || !entry.enumerable || !Object.hasOwn(entry, 'value') ||
          typeof entry.value !== 'string' || !schedulerPhases.has(entry.value)) return;
      multiplicities.set(entry.value, (multiplicities.get(entry.value) ?? 0) + 1);
    }
    if (length > counts[0]) return;
    diagnostic.publish(Object.freeze({ kind: 'store_stop', driverTasks: counts[0], agentLoads: counts[1], admissions: counts[2],
      retainedFailures: counts[3], globalFailure: fields.globalFailure!.value,
      phases: Object.freeze(Object.fromEntries([...multiplicities].sort(([left], [right]) => left.localeCompare(right)))) }));
  } catch { /* A diagnostic cannot prevent synchronous revocation. */ }
}
