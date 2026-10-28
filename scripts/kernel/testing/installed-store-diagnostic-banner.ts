// Qualification-only trusted composition. No runtime option or authority.
import { INSTALLED_APPLY_DIAGNOSTIC_STAGES, INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES,
  INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES, INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES,
  INSTALLED_RUN_FAILURE_CHANNEL, INSTALLED_PUBLICATION_DIAGNOSTIC_PHASES, INSTALLED_PUBLICATION_WORK_V2, INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS,
  INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES } from '../../../src/state/installed-run-diagnostics.js';

/** Buffer the first failures, last scheduler failure and original stop
 * observation. One bounded synchronous write at real exit is included in the
 * unchanged stop deadline; no timer, await, flush retry or keepalive exists.
 * Separately write each of six first-seen publication phases immediately;
 * these fixed progress markers cannot establish completion or resource join.
 * An accepted single-driver Stop entry adds one independent current work label,
 * never a failure, Run attribution, completion or joined result. */
export const INSTALLED_STORE_DIAGNOSTIC_BANNER = `;(() => { try {
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_RUN_FAILURE_CHANNEL)});
  const write = require('node:fs').writeSync, isProxy = require('node:util').types.isProxy;
  const stages = new Set(${JSON.stringify(INSTALLED_APPLY_DIAGNOSTIC_STAGES)});
  const authorizationStages = new Set(${JSON.stringify(INSTALLED_AUTHORIZATION_DIAGNOSTIC_STAGES)});
  const phases = new Set(${JSON.stringify(INSTALLED_SCHEDULER_DIAGNOSTIC_PHASES)});
  const publicationPhases = new Set(${JSON.stringify(INSTALLED_PUBLICATION_DIAGNOSTIC_PHASES)}), publicationSeen = new Set();
  const workNames = new Set(${JSON.stringify(INSTALLED_PUBLICATION_WORK_V2)}), workRuns = new Map();
  const monotonic = require('node:perf_hooks').performance;
  let workInvalid = false;
  const origins = new Set(${JSON.stringify(INSTALLED_SCHEDULER_DIAGNOSTIC_ORIGINS)});
  const classes = new Set(${JSON.stringify(INSTALLED_RUN_DIAGNOSTIC_ERROR_CLASSES)}), codes = new Set(${JSON.stringify(INSTALLED_RUN_DIAGNOSTIC_ERROR_CODES)});
  const prefix = 'CLIQ_STORE_DIAG_V1:';
  let applyFailures = 0, schedulerFailures = 0, authorizationFailures = 0, apply, scheduler, schedulerLast,
    schedulerFailuresBeforeStop, authorization, stop, invalid = false;
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
  // Only the two latest Run observations and six latest issued spans per
  // Run are retained. Old complete spans may be evicted; pending spans never
  // become complete because a new phase starts. The explicit discard count
  // prevents a short diagnostic window being mistaken for a complete trace.
  const workSnapshot = boundary => { try {
    if (!workInvalid && !workRuns.size) return;
    if (workInvalid) { try { write(2, 'CLIQ_PUBLICATION_WORK_V2:truncated\\n'); } catch {} return; }
    const rows = ['CLIQ_PUBLICATION_WORK_V2:begin:' + boundary + ':' + workRuns.size];
    for (const [runId, run] of workRuns) {
      const observed = Math.max(run.latest, Math.floor(monotonic.now() - run.origin));
      if (!count(observed)) return;
      rows.push('CLIQ_PUBLICATION_WORK_V2:run:' + runId + ':' + observed + ':' + run.discarded);
      for (const span of run.spans.values()) rows.push('CLIQ_PUBLICATION_WORK_V2:span:' + runId + ':' + span.id + ':' +
        span.work + ':' + span.started + ':' + (span.ended === null ? '-' : span.ended) + ':' + span.outcome);
    }
    rows.push('CLIQ_PUBLICATION_WORK_V2:end:' + boundary);
    const text = 'CLIQ_PUBLICATION_WORK_V2:' + JSON.stringify(rows) + '\\n';
    if (rows.length > 16 || text.length > 4096 || rows.some(row => row.length > 255)) return;
    try { write(2, text); } catch {}
  } catch {} };
  diagnostic.subscribe(value => { try {
    // Recognizable progress is independent of the original exit summary.
    // An opaque Proxy cannot identify its kind and keeps the old refusal.
    if (value && typeof value === 'object' && !isProxy(value)) {
      const kind = Object.getOwnPropertyDescriptor(value, 'kind');
      if (kind && Object.hasOwn(kind, 'value') && kind.value === 'publication_work_v2') {
        const row = own(value, ['kind', 'runId', 'span', 'work', 'event', 'origin', 'elapsedMs']);
        if (!row || typeof row.runId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(row.runId) ||
            !count(row.span) || row.span < 1 || !workNames.has(row.work) ||
            !['begin', 'fulfilled', 'rejected'].includes(row.event) || !Number.isFinite(row.origin) || row.origin < 0 ||
            !count(row.elapsedMs)) { workInvalid = true; return; }
        let run = workRuns.get(row.runId);
        if (!run) {
          if (row.event !== 'begin') { workInvalid = true; return; }
          if (workRuns.size === 2) {
            const oldest = [...workRuns].find(([, value]) => [...value.spans.values()].every(span => span.ended !== null));
            if (!oldest) { workInvalid = true; return; }
            workRuns.delete(oldest[0]);
          }
          run = {origin:row.origin,latest:0,next:row.span-1,discarded:row.span-1,spans:new Map()};workRuns.set(row.runId,run);
        }
        if (run.origin !== row.origin || row.elapsedMs < run.latest) { workInvalid = true; return; }
        run.latest = row.elapsedMs;
        if (row.event === 'begin') {
          if (row.span !== run.next + 1) { workInvalid = true; return; }
          if (run.spans.size === 6) {
            const oldest = [...run.spans].find(([, span]) => span.ended !== null);
            if (!oldest) { workInvalid = true; return; }
            run.spans.delete(oldest[0]); run.discarded++;
          }
          run.next = row.span;
          run.spans.set(row.span,{id:row.span,work:row.work,started:row.elapsedMs,ended:null,outcome:'pending'});
        } else {
          const span = run.spans.get(row.span);
          if (!span || span.ended !== null || span.work !== row.work || row.elapsedMs < span.started) { workInvalid = true; return; }
          span.ended=row.elapsedMs;span.outcome=row.event;
        }
        return;
      }
      if (kind && Object.hasOwn(kind, 'value') && kind.value === 'publication_phase') {
        const row = own(value, ['kind', 'phase']);
        if (!row || typeof row.phase !== 'string' || !publicationPhases.has(row.phase) || publicationSeen.has(row.phase)) return;
        publicationSeen.add(row.phase);
        try { write(2, 'CLIQ_PUBLICATION_STAGE_V1:' + publicationSeen.size + ':' + row.phase + '\\n'); } catch {}
        return;
      }
    }
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
      schedulerFailures++; if (!scheduler) scheduler = row; schedulerLast = row;
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
      schedulerFailuresBeforeStop = schedulerFailures;
      workSnapshot('stop');
      stop = {...row, phases: Object.fromEntries(keys.sort().map(key => [key, fields[key].value]))};
      if (row.driverTasks === 1 && keys.length === 1 && fields[keys[0]].value === 1) {
        try { write(2, 'CLIQ_STORE_STOP_PHASE_V1:' + keys[0] + '\\n'); } catch {}
      }
    } else invalid = true;
  } catch { invalid = true; } });
  process.once('exit', () => { try {
    workSnapshot('exit');
    if (!invalid && !stop && !applyFailures && !schedulerFailures && !authorizationFailures) return;
    if (invalid || !stop) { try { write(2, prefix + 'truncated\\n'); } catch {} return; }
    const tuple = row => (row.closing ? '1' : '0') + ':' + row.errorClass + ':' + row.code + ':' + (row.sqliteCode === null ? '-' : row.sqliteCode);
    const rows = [prefix + 'begin:' + applyFailures + ':' + schedulerFailures];
    if (apply) rows.push(prefix + 'apply:' + apply.stage + ':' + tuple(apply));
    if (scheduler) rows.push(prefix + 'scheduler:' + scheduler.origin + ':' + scheduler.phase + ':' + tuple(scheduler));
    rows.push(prefix + 'scheduler_window:' + schedulerFailuresBeforeStop);
    if (schedulerLast) rows.push(prefix + 'scheduler_last:' + schedulerLast.origin + ':' + schedulerLast.phase + ':' + tuple(schedulerLast));
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
