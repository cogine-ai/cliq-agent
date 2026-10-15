const phases = ['prepared', 'dispatch_claimed', 'completed', 'failed', 'unknown', 'abandoned'] as const;
const kinds = ['model', 'tool', 'mcp-server', 'mcp', 'verifier', 'publish'] as const;
const statuses = ['queued', 'running', 'waiting', 'succeeded', 'completed_unverified', 'failed', 'cancelled'] as const;

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('not public data');
  return value as Record<string, unknown>;
}

function counter(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new TypeError('not a bounded counter');
  return value;
}

function enumeration<T extends string | null>(value: unknown, allowed: readonly T[]): T {
  if (!allowed.includes(value as T)) throw new TypeError('not a closed public enum');
  return value as T;
}

function page(value: unknown): unknown[] {
  if (!Array.isArray(value) || value.length > 256) throw new TypeError('not a bounded public page');
  return value;
}

function presence(value: unknown): boolean {
  if (value === undefined) return false;
  if (typeof value !== 'string' || !value.length || value.length > 128) throw new TypeError('not optional public metadata');
  return true;
}

/** Secret-free diagnostic data only; never a dispatch, time or recovery gate.
 * Refusal is a distinct diagnostic, not a replacement for the journey error. */
export function projectInstalledRunProgress(value: unknown, observed: unknown): unknown {
  try {
    const cut = record(value), run = record(record(cut.snapshot).run), counters = record(observed);
    const journal = page(cut.journal), checkpoints = page(cut.checkpoints);
    const phaseCounts = { prepared: 0, dispatch_claimed: 0, completed: 0, failed: 0, unknown: 0, abandoned: 0 };
    const opKindCounts = { model: 0, tool: 0, 'mcp-server': 0, mcp: 0, verifier: 0, publish: 0 };
    const tuples = journal.map(value => {
      const row = record(value), kind = enumeration(row.opKind, kinds), phase = enumeration(row.phase, phases);
      phaseCounts[phase]++; opKindCounts[kind]++;
      const seq = counter(row.seq); if (seq < 1) throw new TypeError('Journal sequence is absent');
      return [kind, phase, counter(row.attempt), seq];
    });
    const next = counter(cut.nextJournalSeq), highWater = counter(cut.highWaterJournalSeq);
    if (next > highWater || typeof counters.providerFailure !== 'boolean') throw new TypeError('invalid public observation');
    const revision = counter(run.revision); if (revision < 1) throw new TypeError('Run revision is absent');
    return { diagnosticOnly: true, kind: 'public_progress', requestsReceived: counter(counters.requestsReceived), providerFailure: counters.providerFailure,
      run: { status: enumeration(run.status, statuses), revision,
        nextStep: enumeration(run.nextStep, ['agent', 'tool', 'verify', 'finalize', 'delivery', null] as const), leaseEpoch: counter(run.leaseEpoch),
        waitingReason: run.waitingReason === undefined ? null : enumeration(run.waitingReason, ['approval', 'input', 'child', 'reconciliation'] as const),
        hasActiveWorker: presence(run.activeWorkerLaunchId), hasStopIntent: presence(run.stopIntentRef), hasResult: presence(run.resultRef) },
      journal: { rowCount: journal.length, pageComplete: next === highWater, phaseCounts, opKindCounts, tail: tuples.slice(-16) },
      checkpoints: { count: checkpoints.length, automatic: checkpoints.filter(value =>
        enumeration(record(value).reason, ['initial', 'auto', 'manual', 'pre-effect', 'handoff'] as const) === 'auto').length } };
  } catch { return { diagnosticOnly: true, kind: 'public_progress_projection_refused' }; }
}

export function projectInstalledSupervisorStatus(value: unknown): unknown {
  try {
    const status = record(value), queue = record(status.queue);
    return { diagnosticOnly: true, kind: 'supervisor_status', health: enumeration(status.health, ['ready', 'draining', 'degraded'] as const),
      queue: { queuedRuns: counter(queue.queuedRuns), runningRuns: counter(queue.runningRuns), capacity: counter(queue.capacity) },
      incompatiblePinnedRunCount: counter(status.incompatiblePinnedRunCount) };
  } catch { return { diagnosticOnly: true, kind: 'supervisor_status_projection_refused' }; }
}

/** Actual Manager observations only; an exit code of zero here is not proof
 * of CLD_EXITED (1). The caller must retain its independent exit assertions. */
export function projectInstalledServiceExit(value: unknown): unknown {
  try {
    const status = record(value);
    const integer = (value: unknown, maximum: number): number => {
      if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,9})$/u.test(value) || Number(value) > maximum)
        throw new TypeError('not a closed service counter');
      return Number(value);
    };
    return { diagnosticOnly: true, kind: 'service_exit',
      activeState: enumeration(status.ActiveState, ['active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance'] as const),
      hasMainProcess: integer(status.MainPID, 2147483647) !== 0,
      result: enumeration(status.Result, ['success', 'resources', 'timeout', 'exit-code', 'signal', 'core-dump', 'watchdog', 'start-limit-hit', 'protocol', 'oom-kill'] as const),
      exitCode: integer(status.ExecMainCode, 6), exitStatus: integer(status.ExecMainStatus, 255) };
  } catch { return { diagnosticOnly: true, kind: 'service_exit_projection_refused' }; }
}
