// Qualification-only trusted composition. No runtime option or authority.
import { INSTALLED_APPLY_DIAGNOSTIC_STAGES, INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES,
  INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES, INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES,
  INSTALLED_RUN_FAILURE_CHANNEL, INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS,
  INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES } from '../../../src/state/installed-run-diagnostics.js';

/** Buffer only the first actual failure of each kind and the original stop
 * observation. One bounded synchronous write at real exit is included in the
 * unchanged stop deadline; no timer, await, flush retry or keepalive exists. */
export const INSTALLED_STORE_DIAGNOSTIC_BANNER = `;(() => { try {
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_RUN_FAILURE_CHANNEL)});
  const write = require('node:fs').writeSync, isProxy = require('node:util').types.isProxy;
  const stages = new Set(${JSON.stringify(INSTALLED_APPLY_DIAGNOSTIC_STAGES)});
  const authorizationStages = new Set(${JSON.stringify(INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES)});
  const phases = new Set(${JSON.stringify(INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES)});
  const origins = new Set(${JSON.stringify(INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS)});
  const classes = new Set(${JSON.stringify(INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES)}), codes = new Set(${JSON.stringify(INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES)});
  const prefix = 'CLIQ_STORE_DIAG_V1:';
  let applyFailures = 0, schedulerFailures = 0, authorizationFailures = 0, apply, scheduler, authorization, stop, invalid = false;
  const count = value => Number.isSafeInteger(value) && value >= 0;
  const own = (value, keys) => {
    if (!value || typeof value !== 'object' || isProxy(value) || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return;
    const fields = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] ||
        !Object.hasOwn(fields[key], 'value') || !fields[key].enumerable)) return;
    return Object.fromEntries(keys.map(key => [key, fields[key].value]));
  };
  const failure = (row, hasClosing = true) => {
    if (hasClosing && typeof row.closing !== 'boolean' || typeof row.errorClass !== 'string' || !classes.has(row.errorClass) ||
        typeof row.code !== 'string' || !codes.has(row.code)) return false;
    if (row.code === 'ERR_SQLITE_ERROR') return row.errorClass === 'sqlite' && (row.sqliteCode === null ||
      count(row.sqliteCode) && row.sqliteCode <= 2147483647);
    return row.errorClass !== 'sqlite' && row.sqliteCode === null;
  };
  diagnostic.subscribe(value => { try {
    if (invalid) return;
    if (!value || typeof value !== 'object' || isProxy(value)) { invalid = true; return; }
    const kind = Object.getOwnPropertyDescriptor(value, 'kind');
    if (!kind || !Object.hasOwn(kind, 'value')) { invalid = true; return; }
    if (kind.value === 'apply_failure') {
      const row = own(value, ['kind', 'stage', 'closing', 'errorClass', 'code', 'sqliteCode']);
      if (!row || typeof row.stage !== 'string' || !stages.has(row.stage) || !failure(row) ||
          !count(applyFailures + 1)) { invalid = true; return; }
      applyFailures++; if (!apply) apply = row;
    } else if (kind.value === 'scheduler_failure') {
      const row = own(value, ['kind', 'origin', 'phase', 'closing', 'errorClass', 'code', 'sqliteCode']);
      if (!row || typeof row.origin !== 'string' || !origins.has(row.origin) || typeof row.phase !== 'string' ||
          row.phase !== 'unavailable' && !phases.has(row.phase) || !failure(row) ||
          !count(schedulerFailures + 1)) { invalid = true; return; }
      schedulerFailures++; if (!scheduler) scheduler = row;
    } else if (kind.value === 'authorization_failure') {
      const row = own(value, ['kind', 'stage', 'errorClass', 'code', 'sqliteCode']);
      if (!row || typeof row.stage !== 'string' || !authorizationStages.has(row.stage) || !failure(row, false) ||
          !count(authorizationFailures + 1)) { invalid = true; return; }
      authorizationFailures++; if (!authorization) authorization = row;
    } else if (kind.value === 'store_stop') {
      const row = own(value, ['kind', 'driverTasks', 'agentLoads', 'admissions', 'retainedFailures', 'globalFailure', 'phases']);
      if (!row || stop || !['driverTasks', 'agentLoads', 'admissions', 'retainedFailures'].every(key => count(row[key])) ||
          typeof row.globalFailure !== 'boolean' || !row.phases || typeof row.phases !== 'object' || isProxy(row.phases) ||
          Array.isArray(row.phases) || ![Object.prototype, null].includes(Object.getPrototypeOf(row.phases))) { invalid = true; return; }
      const fields = Object.getOwnPropertyDescriptors(row.phases), keys = Reflect.ownKeys(fields);
      if (keys.length > 8 || keys.some(key => typeof key !== 'string' || !phases.has(key) || !fields[key].enumerable ||
          !Object.hasOwn(fields[key], 'value') || !Number.isSafeInteger(fields[key].value) || fields[key].value < 1 ||
          fields[key].value > 1000)) { invalid = true; return; }
      const sum = keys.reduce((total, key) => total + fields[key].value, 0);
      if (sum > row.driverTasks || sum > 1000) { invalid = true; return; }
      stop = {...row, phases: Object.fromEntries(keys.sort().map(key => [key, fields[key].value]))};
    } else invalid = true;
  } catch { invalid = true; } });
  process.once('exit', () => { try {
    if (!invalid && !stop && !applyFailures && !schedulerFailures && !authorizationFailures) return;
    if (invalid || !stop) { try { write(2, prefix + 'truncated\\n'); } catch {} return; }
    const tuple = row => (row.closing ? '1' : '0') + ':' + row.errorClass + ':' + row.code + ':' + (row.sqliteCode === null ? '-' : row.sqliteCode);
    const rows = [prefix + 'begin:' + applyFailures + ':' + schedulerFailures];
    if (apply) rows.push(prefix + 'apply:' + apply.stage + ':' + tuple(apply));
    if (scheduler) rows.push(prefix + 'scheduler:' + scheduler.origin + ':' + scheduler.phase + ':' + tuple(scheduler));
    if (authorization) rows.push(prefix + 'authorization:' + authorizationFailures + ':' + authorization.stage + ':' +
      authorization.errorClass + ':' + authorization.code + ':' + (authorization.sqliteCode === null ? '-' : authorization.sqliteCode));
    rows.push(prefix + 'stop:' + stop.driverTasks + ':' + stop.agentLoads + ':' + stop.admissions + ':' + stop.retainedFailures + ':' + (stop.globalFailure ? '1' : '0'));
    for (const [phase, count] of Object.entries(stop.phases)) rows.push(prefix + 'phase:' + phase + ':' + count);
    rows.push(prefix + 'end');
    const text = rows.join('\\n') + '\\n';
    if (rows.length > 16 || text.length > 4096 || rows.some(row => row.length > 255)) { try { write(2, prefix + 'truncated\\n'); } catch {} return; }
    try { write(2, text); } catch {}
  } catch {} });
} catch {} })();`;
