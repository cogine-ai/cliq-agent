import { ResourceRetirementError } from '../../../src/state/errors.js';
import { RESOURCE_ROLES, RESOURCE_BOUNDARIES, RESOURCE_BITS, resourceRecord, type ResourceNumbers } from '../../../src/state/installed-resource-kernel.js';
import type { InstalledResourceObservation } from '../../../src/state/installed-resource-diagnostics.js';
export const INSTALLED_RESOURCE_PREFIX = 'CLIQ_RESOURCE_V1:';
const keys = ['mask', 'joined', 'unavailable', 'memory', 'memoryPeak', 'tasks', 'tasksPeak', 'cpu', 'oom', 'oomKill',
  'descriptors', 'nofileSoft', 'nofileHard', 'memoryMax', 'tasksMax', 'cpuQuota', 'cpus', 'machineMemory', 'machineAvailable'] as const;
export function installedResourceLine(value: InstalledResourceObservation): Buffer {
  const checked = resourceRecord(value, ['role', 'boundary', 'numbers']);
  resourceRecord(checked.numbers, keys);
  const role = RESOURCE_ROLES.indexOf(value.role), boundary = RESOURCE_BOUNDARIES.indexOf(value.boundary);
  const numbers = keys.map(key => value.numbers[key]);
  if (role < 0 || boundary < 0 || numbers.some(value => !Number.isSafeInteger(value) || value < 0) || value.numbers.mask > 65535 ||
      value.numbers.joined > 1 || value.numbers.unavailable > 3) throw new TypeError('invalid fixed resource numbers');
  const bits: readonly [number, readonly (keyof ResourceNumbers)[]][] = [[RESOURCE_BITS.memory, ['memory']], [RESOURCE_BITS.memoryPeak, ['memoryPeak']],
    [RESOURCE_BITS.tasks, ['tasks']], [RESOURCE_BITS.tasksPeak, ['tasksPeak']], [RESOURCE_BITS.cpu, ['cpu']],
    [RESOURCE_BITS.events, ['oom', 'oomKill']], [RESOURCE_BITS.memoryMax, ['memoryMax']], [RESOURCE_BITS.tasksMax, ['tasksMax']],
    [RESOURCE_BITS.cpuQuota, ['cpuQuota']], [RESOURCE_BITS.cpus, ['cpus']], [RESOURCE_BITS.machineMemory, ['machineMemory']], [RESOURCE_BITS.machineAvailable, ['machineAvailable']], [RESOURCE_BITS.descriptors, ['descriptors']], [RESOURCE_BITS.nofile, ['nofileSoft', 'nofileHard']]];
  if (bits.some(([bit, fields]) => !(value.numbers.mask & bit) && fields.some(field => value.numbers[field] !== 0)) ||
      value.numbers.unavailable !== 0 && value.numbers.mask !== 0 || (value.numbers.joined === 0) !== (value.numbers.unavailable === 3) ||
      value.numbers.unavailable === 0 && !(value.numbers.mask & RESOURCE_BITS.group) ||
      value.numbers.mask & (RESOURCE_BITS.nofile | RESOURCE_BITS.descriptors) && !(value.numbers.mask & RESOURCE_BITS.process) ||
      value.numbers.mask & RESOURCE_BITS.nofile && value.numbers.nofileSoft > value.numbers.nofileHard)
    throw new TypeError('resource availability or limits differ from their actual observation');
  const bytes = Buffer.from(INSTALLED_RESOURCE_PREFIX + [role, boundary, ...numbers].join(':') + '\n');
  if (bytes.length > 384) throw new TypeError('resource numeric line exceeds bound'); return bytes;
}
export function decodeInstalledResourceLine(bytes: Buffer): InstalledResourceObservation {
  if (!Buffer.isBuffer(bytes) || bytes.length > 384 || !bytes.subarray(0, INSTALLED_RESOURCE_PREFIX.length).equals(Buffer.from(INSTALLED_RESOURCE_PREFIX)) ||
      !/^[0-9]+(?::[0-9]+){20}\n$/u.test(bytes.subarray(INSTALLED_RESOURCE_PREFIX.length).toString('ascii')) || bytes.some(byte => byte > 127))
    throw new TypeError('invalid fixed resource line');
  const values = bytes.subarray(INSTALLED_RESOURCE_PREFIX.length, -1).toString('ascii').split(':').map(value => {
    if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError('noncanonical resource integer'); return Number(value);
  });
  const role = RESOURCE_ROLES[values[0]!], boundary = RESOURCE_BOUNDARIES[values[1]!];
  if (!role || !boundary) throw new TypeError('unknown fixed resource role or boundary');
  const numbers = Object.fromEntries(keys.map((key, index) => [key, values[index + 2]])) as unknown as ResourceNumbers;
  const result = Object.freeze({ role, boundary, numbers: Object.freeze(numbers) });
  if (!installedResourceLine(result).equals(bytes)) throw new TypeError('resource line changed its original bytes'); return result;
}
/** Called only after the original complete stream bytes have been scanned.
 * No normalization, joined stream, new secret stream, reset or extra report. */
export function replayScannedResourceLines(original: Buffer, write: (bytes: Buffer) => void): number {
  if (!Buffer.isBuffer(original) || original.length > 256 * 1024) throw new TypeError('resource journal exceeds original bound');
  let count = 0, emitted = 0, offset = 0; const seen = new Set<string>();
  while (offset < original.length) {
    const newline = original.indexOf(10, offset), end = newline < 0 ? original.length : newline + 1;
    const bytes = original.subarray(offset, end); offset = end;
    if (!bytes.subarray(0, INSTALLED_RESOURCE_PREFIX.length).equals(Buffer.from(INSTALLED_RESOURCE_PREFIX))) continue;
    const value = decodeInstalledResourceLine(bytes), key = value.role + ':' + value.boundary;
    if (!value.numbers.joined) throw new ResourceRetirementError('owned resource measurement descriptors did not join', new Error('actual measurement close returned an error'));
    if (seen.has(key)) throw new TypeError('duplicate original resource role/boundary'); seen.add(key);
    if (++count > 40 || (emitted += bytes.length) > 16384) throw new TypeError('resource observation exceeds its original fixed budget');
    write(bytes);
  }
  return count;
}
