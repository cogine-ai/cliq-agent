import { canonicalJsonBytes } from '../kernel/canonical.js';
import { parseJsonStrict } from '../kernel/json.js';
import { DEFAULT_RUN_SCHEDULING, decodeRunScheduling, type RunSchedulingV1 } from '../kernel/run-scheduling.js';
import type { PrivateClientDirectory } from './private-files.js';

const FILE = 'run-scheduling.json';
const BYTES = 1024;

function previewScheduling(value: unknown): RunSchedulingV1 {
  const settings = decodeRunScheduling(value);
  if (settings.maxConcurrentRuns !== 1)
    throw new TypeError('Linux preview supports one active task; use settings --run-concurrency 1 before starting Supervisor');
  return settings;
}

/** Same actual-account, installation-bound private files as client choices.
 * No workspace configuration, environment override or execution authority. */
export async function readRunScheduling(directory: Pick<PrivateClientDirectory, 'read'>): Promise<RunSchedulingV1> {
  const bytes = await directory.read(FILE, BYTES);
  if (bytes === undefined) return DEFAULT_RUN_SCHEDULING;
  if (!Buffer.isBuffer(bytes) || bytes.length > BYTES) throw new TypeError('Run scheduling settings exceed their fixed byte bound');
  const value = decodeRunScheduling(parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)));
  if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('Run scheduling settings are not canonical');
  return previewScheduling(value);
}

export async function writeRunScheduling(directory: Pick<PrivateClientDirectory, 'replace'>, value: unknown): Promise<RunSchedulingV1> {
  const settings = previewScheduling(value);
  await directory.replace(FILE, canonicalJsonBytes(settings));
  return settings;
}

export function schedulingCommand(argv: readonly string[]): RunSchedulingV1 | undefined {
  if (argv.length === 1 && argv[0] === 'settings') return undefined;
  if (argv.length !== 3 || argv[0] !== 'settings' || argv[1] !== '--run-concurrency' || !/^[1-9][0-9]*$/u.test(argv[2]!))
    throw new TypeError('use settings [--run-concurrency 1]');
  return previewScheduling({ schemaVersion: 1, maxConcurrentRuns: Number(argv[2]) });
}
