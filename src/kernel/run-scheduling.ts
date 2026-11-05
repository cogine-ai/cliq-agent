import { assertControlWireJson, controlWireRecord } from './control-wire-data.js';

/** Supervisor-local scheduling capacity. This is not a Run budget or grant. */
export const MAX_CONCURRENT_RUNS = 32;
export const DEFAULT_RUN_SCHEDULING = Object.freeze({ schemaVersion: 1 as const, maxConcurrentRuns: 1 });
export type RunSchedulingV1 = Readonly<{ schemaVersion: 1; maxConcurrentRuns: number }>;

export function assertRunConcurrency(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_CONCURRENT_RUNS)
    throw new TypeError('Run concurrency must be an integer from 1 through 32');
}

export function decodeRunScheduling(value: unknown): RunSchedulingV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'maxConcurrentRuns']);
  if (data.schemaVersion !== 1) throw new TypeError('unsupported Run scheduling settings');
  assertRunConcurrency(data.maxConcurrentRuns);
  return Object.freeze({ schemaVersion: 1, maxConcurrentRuns: data.maxConcurrentRuns });
}
