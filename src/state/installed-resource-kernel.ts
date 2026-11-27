// Test-owned read-only kernel observations. These numbers are never a Run,
// permission, birth, death, slot reservation or resource-capability proof.
import { constants, closeSync, fstatSync, statfsSync, lstatSync, openSync, readSync, readlinkSync, opendirSync, type BigIntStats } from 'node:fs';
import { types } from 'node:util';

export const RESOURCE_ROLES = ['supervisor', 'keeper', 'controller', 'run', 'source'] as const;
export const RESOURCE_BOUNDARIES = ['preparation_ready', 'controller_ready', 'active', 'result_received', 'capture_durable',
  'acknowledgement_joined', 'terminal_joined', 'source_joined'] as const;
export type ResourceRole = typeof RESOURCE_ROLES[number];
export type ResourceBoundary = typeof RESOURCE_BOUNDARIES[number];
export const RESOURCE_BITS = Object.freeze({ group: 1, process: 2, memory: 4, memoryPeak: 8,
  tasks: 16, tasksPeak: 32, cpu: 64, events: 128, descriptors: 256, nofile: 512, memoryMax: 1024, tasksMax: 2048, cpuQuota: 4096, cpus: 8192, machineMemory: 16384, machineAvailable: 32768 });
export type ResourceNumbers = Readonly<{ mask: number; joined: 0 | 1; unavailable: number;
  memory: number; memoryPeak: number; tasks: number; tasksPeak: number; cpu: number;
  oom: number; oomKill: number; descriptors: number; nofileSoft: number; nofileHard: number;
  memoryMax: number; tasksMax: number; cpuQuota: number; cpus: number; machineMemory: number; machineAvailable: number }>;
export type OriginalResourceProcess = Readonly<{ pid: number; start: string; uid: number }>;
export type OriginalResourceGroup = Readonly<{ device: string; inode: string }>;
const empty = (unavailable: number, joined: 0 | 1 = 1): ResourceNumbers => Object.freeze({ mask: 0, joined, unavailable,
  memory: 0, memoryPeak: 0, tasks: 0, tasksPeak: 0, cpu: 0, oom: 0, oomKill: 0, descriptors: 0, nofileSoft: 0, nofileHard: 0, memoryMax: 0, tasksMax: 0, cpuQuota: 0, cpus: 0, machineMemory: 0, machineAvailable: 0 });
const CGROUP2 = 0x63677270;
const PROC = 0x9fa0;
export function resourceRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid fixed resource data');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors, key) ||
      !descriptors[key]!.enumerable || !Object.hasOwn(descriptors[key]!, 'value'))) throw new TypeError('invalid fixed resource fields');
  return value as Record<string, unknown>;
}
export function resourceDecimal(value: string): number {
  if (typeof value !== 'string' || value.length > 16 || !/^(0|[1-9][0-9]*)$/u.test(value)) throw new TypeError('invalid kernel resource integer');
  const number = Number(value); if (!Number.isSafeInteger(number)) throw new TypeError('kernel resource integer exceeds bound'); return number;
}
export function resourceProcess(value: unknown): OriginalResourceProcess {
  const data = resourceRecord(value, ['pid', 'start', 'uid']);
  if (!Number.isSafeInteger(data.pid) || (data.pid as number) < 1 || !Number.isSafeInteger(data.uid) || (data.uid as number) < 0 ||
      typeof data.start !== 'string' || data.start.length > 48 || !/^linux-proc-start-ticks:(0|[1-9][0-9]*)$/u.test(data.start)) throw new TypeError('invalid original resource process');
  return Object.freeze({ pid: data.pid as number, uid: data.uid as number, start: data.start });
}
function groupData(value: unknown): OriginalResourceGroup {
  const data = resourceRecord(value, ['device', 'inode']);
  for (const key of ['device', 'inode']) if (typeof data[key] !== 'string' || (data[key] as string).length > 20 || !/^(0|[1-9][0-9]*)$/u.test(data[key] as string) || BigInt(data[key] as string) > 18446744073709551615n)
    throw new TypeError('invalid original resource group');
  return Object.freeze({ device: data.device as string, inode: data.inode as string });
}
export function resourceMembership(bytes: Buffer): string {
  if (!Buffer.isBuffer(bytes) || bytes.length > 4096 || bytes.includes(0)) throw new TypeError('invalid original resource membership');
  const text = bytes.toString('ascii');
  if (!/^0::\/(?:[A-Za-z0-9_.:@-]+\/)*[A-Za-z0-9_.:@-]*\n$/u.test(text) ||
      bytes.some(byte => byte > 127) || text.includes('/../') || text.includes('/./')) throw new TypeError('invalid unified resource membership');
  return text.slice(3, -1);
}
export function resourceStart(bytes: Buffer, pid: number): string {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8192) throw new TypeError('invalid original resource process stat');
  const text = bytes.toString('utf8'), at = text.lastIndexOf(') ');
  if (!text.startsWith(`${pid} (`) || at < 0) throw new TypeError('invalid original resource PID');
  const parts = text.slice(at + 2).trim().split(/\s+/u);
  if (parts.length < 20 || ['Z', 'X', 'x'].includes(parts[0]!) || !/^[1-9][0-9]*$/u.test(parts[19]!))
    throw new TypeError('original resource process is not live');
  return 'linux-proc-start-ticks:' + parts[19];
}
export function resourceNofile(bytes: Buffer): readonly [number, number] {
  const text = bytes.toString('ascii');
  if (bytes.length > 8192 || bytes.some(byte => byte > 127) || text.includes('\0')) throw new TypeError('invalid original resource limits');
  const rows = text.split('\n').filter(row => row.startsWith('Max open files'));
  if (rows.length !== 1) throw new TypeError('original resource NOFILE is unavailable');
  const row = /^Max open files\s+([0-9]+)\s+([0-9]+)\s+files\s*$/u.exec(rows[0]!);
  if (!row) throw new TypeError('original resource NOFILE is unbounded');
  const soft = resourceDecimal(row[1]!), hard = resourceDecimal(row[2]!);
  if (soft > hard) throw new TypeError('original resource NOFILE is inconsistent'); return Object.freeze([soft, hard]);
}
export function resourceCounters(bytes: Buffer): ReadonlyMap<string, number> {
  if (bytes.length > 4096 || bytes.some(byte => byte > 127) || bytes.includes(0)) throw new TypeError('invalid fixed kernel counters');
  const result = new Map<string, number>();
  for (const row of bytes.toString('ascii').trimEnd().split('\n')) {
    // CONFIG_SCHED_CORE emits this literal dotted key in cpu.stat. Keep the
    // rest of the closed counter grammar, integer and duplicate checks.
    const pair = /^([a-z_]+|core_sched\.force_idle_usec) (0|[1-9][0-9]*)$/u.exec(row);
    if (!pair || result.has(pair[1]!)) throw new TypeError('invalid or repeated kernel counter');
    result.set(pair[1]!, resourceDecimal(pair[2]!));
  }
  return result;
}
function errorCode(value: unknown): string | undefined {
  if (!value || typeof value !== 'object' || types.isProxy(value)) return;
  const code = Object.getOwnPropertyDescriptor(value, 'code');
  return code && 'value' in code && typeof code.value === 'string' ? code.value : undefined;
}
function same(a: BigIntStats, b: BigIntStats): boolean {
  return ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => a[key as keyof typeof a] === b[key as keyof typeof b]);
}
/** Root is borrowed only by a fixed test/native friend. No FD is returned.
 * Every opened descriptor is owned here and closed exactly once, including on
 * malformed files, changed PID/start or a substituted cgroup. Missing peak
 * files explicitly clear their bit; sampled maxima are never called peaks. */
export function sampleHeldResourceGroup(root: number, expected: OriginalResourceGroup,
  process?: OriginalResourceProcess, expectedMembership?: string, descriptorsFor: 'trusted' | 'skip' = 'trusted'): ResourceNumbers {
  let closeFailed = false;
  const handles = new Set<number>();
  const own = (fd: number) => { handles.add(fd); return fd; };
  const retire = (fd: number) => { handles.delete(fd); try { closeSync(fd); } catch { closeFailed = true; } };
  const read = (parent: number, name: string, ceiling = 4096) => {
    const fd = own(openSync(`/proc/self/fd/${parent}/${name}`, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
    try {
      const bytes = Buffer.alloc(ceiling + 1); let count = 0;
      for (;;) { const size = readSync(fd, bytes, count, bytes.length - count, null); count += size;
        if (count > ceiling) throw new TypeError('resource kernel file exceeds bound'); if (size === 0) break; }
      return bytes.subarray(0, count);
    } finally { retire(fd); }
  };
  const optional = (parent: number, name: string) => {
    try { return read(parent, name); } catch (error) {
      if (['ENOENT', 'EOPNOTSUPP'].includes(errorCode(error) ?? '')) return undefined; throw error;
    }
  };
  let result = empty(0);
  try {
    if (descriptorsFor !== 'trusted' && descriptorsFor !== 'skip') throw new TypeError('invalid fixed resource descriptor role');
    const original = groupData(expected), proc = process === undefined ? undefined : resourceProcess(process);
    if (!Number.isSafeInteger(root) || root < 0) throw new TypeError('invalid held resource root');
    const before = fstatSync(root, { bigint: true }), system = statfsSync(`/proc/self/fd/${root}`);
    if (!before.isDirectory() || system.type !== CGROUP2 || String(before.dev) !== original.device || String(before.ino) !== original.inode)
      throw new TypeError('original resource root changed');
    const namedGroup = readlinkSync(`/proc/self/fd/${root}`);
    if (namedGroup.length > 4096 || !namedGroup.startsWith('/sys/fs/cgroup')) throw new TypeError('resource group is outside the actual cgroup mount');
    const groupMembership = namedGroup.slice('/sys/fs/cgroup'.length) || '/';
    if (resourceMembership(Buffer.from('0::' + groupMembership + '\n')) !== groupMembership || proc &&
        expectedMembership !== groupMembership && expectedMembership !== (groupMembership === '/' ? '' : groupMembership) + '/worker')
      throw new TypeError('resource process and original group are unrelated');
    let processRoot: number | undefined, processIdentity: BigIntStats | undefined;
    const assertProcess = () => {
      if (!proc || processRoot === undefined || !processIdentity || !same(processIdentity, fstatSync(processRoot, { bigint: true })) ||
          !same(processIdentity, lstatSync(`/proc/${proc.pid}`, { bigint: true })) || resourceStart(read(processRoot, 'stat', 8192), proc.pid) !== proc.start ||
          resourceMembership(read(processRoot, 'cgroup')) !== expectedMembership) throw new TypeError('original resource process changed');
      const status = read(processRoot, 'status', 65536).toString('ascii');
      const uids = /^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$/mu.exec(status);
      if (!uids || !uids.slice(1).every(value => resourceDecimal(value) === proc.uid)) throw new TypeError('original resource UID changed');
    };
    if (proc) {
      if (typeof expectedMembership !== 'string' || resourceMembership(Buffer.from('0::' + expectedMembership + '\n')) !== expectedMembership)
        throw new TypeError('original resource membership is missing');
      processRoot = own(openSync(`/proc/${proc.pid}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
      processIdentity = fstatSync(processRoot, { bigint: true });
      if (!processIdentity.isDirectory() || statfsSync(`/proc/self/fd/${processRoot}`).type !== PROC) throw new TypeError('original resource procfs changed');
      assertProcess();
    }
    let mask = RESOURCE_BITS.group | (proc ? RESOURCE_BITS.process : 0);
    const scalar = (name: string, bit: number) => { const bytes = optional(root, name); if (!bytes) return 0;
      const value = resourceDecimal(bytes.toString('ascii').replace(/\n$/u, '')); mask |= bit; return value; };
    const memory = scalar('memory.current', RESOURCE_BITS.memory), memoryPeak = scalar('memory.peak', RESOURCE_BITS.memoryPeak);
    const tasks = scalar('pids.current', RESOURCE_BITS.tasks), tasksPeak = scalar('pids.peak', RESOURCE_BITS.tasksPeak);
    let cpu = 0, oom = 0, oomKill = 0, descriptors = 0, nofileSoft = 0, nofileHard = 0;
    const cpuBytes = optional(root, 'cpu.stat');
    if (cpuBytes) { const counts = resourceCounters(cpuBytes); if (!counts.has('usage_usec')) throw new TypeError('missing CPU use');
      cpu = counts.get('usage_usec')!; mask |= RESOURCE_BITS.cpu; }
    const events = optional(root, 'memory.events.local');
    if (events) { const counts = resourceCounters(events); if (!counts.has('oom') || !counts.has('oom_kill')) throw new TypeError('missing memory events');
      oom = counts.get('oom')!; oomKill = counts.get('oom_kill')!; mask |= RESOURCE_BITS.events; }
    // These are namespace-visible ancestor upper bounds, never CPU service
    // guarantees or an atomic capacity reservation. Hidden ancestors are not
    // observed or certified by reaching a namespace mount root. Missing/max stays masked.
    let memoryMax = 0, tasksMax = 0, cpuQuota = 0, cpus = 0, machineMemory = 0, machineAvailable = 0;
    const capNodes: { fd: number; info: BigIntStats; values: string[] }[] = [];
    try {
      let current = root, complete = false;
      for (let depth = 0; depth < 32; depth++) {
        const info = fstatSync(current, { bigint: true });
        if (!info.isDirectory() || statfsSync(`/proc/self/fd/${current}`).type !== CGROUP2) throw new TypeError('resource ancestor is not cgroup2');
        const values = ['memory.max', 'pids.max', 'cpu.max'].map(name => optional(current, name)?.toString('ascii') ?? '');
        capNodes.push({ fd: current, info, values });
        if (readlinkSync(`/proc/self/fd/${current}`) === '/sys/fs/cgroup') { complete = true; break; }
        current = own(openSync(`/proc/self/fd/${current}/..`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
      }
      if (!complete) throw new TypeError('resource ancestor bound exceeded');
      const minimum = (values: number[]) => values.length ? Math.min(...values) : 0;
      const memories: number[] = [], taskLimits: number[] = [], quotas: number[] = [];
      for (const node of capNodes) {
        if (!same(node.info, fstatSync(node.fd, { bigint: true }))) throw new TypeError('resource ancestor identity changed');
        for (const [index, name] of ['memory.max', 'pids.max', 'cpu.max'].entries())
          if ((optional(node.fd, name)?.toString('ascii') ?? '') !== node.values[index]) throw new TypeError('resource ancestor controls changed');
        for (const [index, target] of [[0, memories], [1, taskLimits]] as const) {
          const value = node.values[index]!; if (value && value !== 'max\n') target.push(resourceDecimal(value.replace(/\n$/u, '')));
        }
        const quota = node.values[2]!;
        if (quota) {
          const pair = /^(max|[1-9][0-9]*) ([1-9][0-9]*)\n$/u.exec(quota); if (!pair) throw new TypeError('invalid resource CPU limit');
          if (pair[1] !== 'max') {
            const scaled = BigInt(pair[1]!) * 1000000n / BigInt(pair[2]!);
            if (scaled > BigInt(Number.MAX_SAFE_INTEGER)) throw new TypeError('resource CPU limit overflows'); quotas.push(Number(scaled));
          }
        }
      }
      memoryMax = minimum(memories); tasksMax = minimum(taskLimits); cpuQuota = minimum(quotas);
      if (memories.length) mask |= RESOURCE_BITS.memoryMax;
      if (taskLimits.length) mask |= RESOURCE_BITS.tasksMax;
      if (quotas.length) mask |= RESOURCE_BITS.cpuQuota;
    } catch { memoryMax = tasksMax = cpuQuota = 0; }
    finally { for (const node of capNodes) if (node.fd !== root) retire(node.fd); }
    const cpuset = optional(root, 'cpuset.cpus.effective');
    if (cpuset) try {
      let previous = -1;
      for (const range of cpuset.toString('ascii').trimEnd().split(',')) {
        const match = /^(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?$/u.exec(range); if (!match) throw new TypeError('invalid effective cpuset');
        const first = resourceDecimal(match[1]!), last = resourceDecimal(match[2] ?? match[1]!);
        if (last < first || first <= previous || last > 1048575) throw new TypeError('invalid effective CPU range'); previous = last;
        cpus += last - first + 1;
      }
      mask |= RESOURCE_BITS.cpus;
    } catch { cpus = 0; }
    let procSystem = -1;
    try {
      procSystem = own(openSync('/proc', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
      if (statfsSync(`/proc/self/fd/${procSystem}`).type !== PROC) throw new TypeError('system memory is not procfs');
      const text = read(procSystem, 'meminfo', 16384).toString('ascii');
      const total = /^MemTotal:\s+(0|[1-9][0-9]*) kB$/mu.exec(text), available = /^MemAvailable:\s+(0|[1-9][0-9]*) kB$/mu.exec(text);
      if (total) { machineMemory = resourceDecimal(total[1]!) * 1024; if (!Number.isSafeInteger(machineMemory)) throw new TypeError('machine memory overflows'); mask |= RESOURCE_BITS.machineMemory; }
      if (available) { machineAvailable = resourceDecimal(available[1]!) * 1024; if (!Number.isSafeInteger(machineAvailable)) throw new TypeError('available memory overflows'); mask |= RESOURCE_BITS.machineAvailable; }
    } catch { machineMemory = machineAvailable = 0; mask &= ~(RESOURCE_BITS.machineMemory | RESOURCE_BITS.machineAvailable); }
    finally { if (procSystem >= 0) retire(procSystem); }
    if (proc && processRoot !== undefined && descriptorsFor === 'trusted') {
      const directory = opendirSync(`/proc/self/fd/${processRoot}/fd`, { bufferSize: 32 });
      try { for (;;) { const entry = directory.readSync(); if (!entry) break;
        if (++descriptors > 8192 || !/^(0|[1-9][0-9]*)$/u.test(entry.name)) throw new TypeError('trusted descriptor inventory exceeds bound');
      } } finally { try { directory.closeSync(); } catch { closeFailed = true; } }
      mask |= RESOURCE_BITS.descriptors;
      [nofileSoft, nofileHard] = resourceNofile(read(processRoot, 'limits', 8192)); mask |= RESOURCE_BITS.nofile;
    }
    if (proc) assertProcess();
    if (!same(before, fstatSync(root, { bigint: true })) || readlinkSync(`/proc/self/fd/${root}`) !== namedGroup || statfsSync(`/proc/self/fd/${root}`).type !== CGROUP2) throw new TypeError('original resource root changed during observation');
    result = Object.freeze({ mask, joined: 1, unavailable: 0, memory, memoryPeak, tasks, tasksPeak, cpu, oom, oomKill, descriptors, nofileSoft, nofileHard, memoryMax, tasksMax, cpuQuota, cpus, machineMemory, machineAvailable });
  } catch (error) { result = empty(['ENOENT', 'ESRCH'].includes(errorCode(error) ?? '') ? 1 : 2); }
  finally { for (const fd of handles) retire(fd); }
  return closeFailed ? empty(3, 0) : result;
}
