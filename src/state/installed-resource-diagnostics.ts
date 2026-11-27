// Passive fixed numeric diagnostics. No subscription means no kernel reads,
// clocks, process enumeration or output. It cannot release, reserve or retry.
import { constants, closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { types } from 'node:util';
import { ResourceRetirementError } from './errors.js';
import { RESOURCE_ROLES, RESOURCE_BOUNDARIES, sampleHeldResourceGroup, resourceStart, resourceRecord,
  type ResourceRole, type ResourceBoundary, type ResourceNumbers, type OriginalResourceProcess } from './installed-resource-kernel.js';

export type OriginalResourceSubject = Readonly<{ role: 'controller' | 'run' | 'source';
  pid?: number; start?: string; device: string; inode: string; relative: string }>;
export type InstalledResourceObservation = Readonly<{ role: ResourceRole; boundary: ResourceBoundary; numbers: ResourceNumbers }>;
export const installedResourcesObserved = () => observers.size > 0;
const observers = new Set<(value: InstalledResourceObservation) => void>();
export function observeInstalledResources(observer: (value: InstalledResourceObservation) => void): () => void {
  if (typeof observer !== 'function' || types.isProxy(observer)) throw new TypeError('resource observer must be a fixed function');
  observers.add(observer); return () => { observers.delete(observer); };
}
const unavailable = (joined: 0 | 1 = 1): ResourceNumbers => Object.freeze({ mask: 0, joined, unavailable: joined ? 2 : 3,
  memory: 0, memoryPeak: 0, tasks: 0, tasksPeak: 0, cpu: 0, oom: 0, oomKill: 0, descriptors: 0, nofileSoft: 0, nofileHard: 0, memoryMax: 0, tasksMax: 0, cpuQuota: 0, cpus: 0, machineMemory: 0, machineAvailable: 0 });


/** Only the installed adapter calls this inside its already genuine original
 * anchor borrow. The numeric root never enters any observer or wire value.
 * Relative subjects are fixed original source/controller/Run names, with the
 * original kernel inode tuple independently checked by the reader. */
export function noteInstalledResourceBoundary(boundary: ResourceBoundary,
  borrow: (operation: (root: number, path: string) => void) => void, subjects: readonly OriginalResourceSubject[] = []): void {
  if (!observers.size) return;
  const pending: InstalledResourceObservation[] = [];
  let closeFailed = false;
  const readFile = (filename: string, maximum: number): Buffer => {
    const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try { const bytes = Buffer.alloc(maximum + 1); let count = 0;
      for (;;) { const size = readSync(fd, bytes, count, bytes.length - count, null); count += size;
        if (count > maximum) throw new TypeError('fixed resource metadata exceeds bound'); if (!size) return bytes.subarray(0, count); }
    } finally { try { closeSync(fd); } catch { closeFailed = true; } }
  };
  const ownProcess = (pid: number, uid: number): OriginalResourceProcess => Object.freeze({ pid, uid,
    start: resourceStart(readFile(`/proc/${pid}/stat`, 8192), pid) });
  const emit = (role: ResourceRole, numbers: ResourceNumbers) => pending.push(Object.freeze({ role, boundary, numbers }));
  try {
    if (!RESOURCE_BOUNDARIES.includes(boundary) || typeof borrow !== 'function' || types.isProxy(borrow) ||
        types.isProxy(subjects) || !Array.isArray(subjects) || Object.getPrototypeOf(subjects) !== Array.prototype || subjects.length > 3) throw new TypeError('invalid resource boundary');
    const arrayFields = Object.getOwnPropertyDescriptors(subjects);
    if (Reflect.ownKeys(arrayFields).length !== subjects.length + 1 || Array.from({ length: subjects.length }, (_, index) => index).some(index =>
        !Object.hasOwn(arrayFields, String(index)) || !arrayFields[index]!.enumerable || !Object.hasOwn(arrayFields[index]!, 'value'))) throw new TypeError('invalid resource subjects');
    for (const subject of subjects) {
      if (!subject || typeof subject !== 'object' || types.isProxy(subject)) throw new TypeError('invalid resource subject');
      const descriptors = Object.getOwnPropertyDescriptors(subject);
      resourceRecord(subject, ['role', 'device', 'inode', 'relative', ...(Object.hasOwn(descriptors, 'pid') ? ['pid', 'start'] : [])]);
      if (!['controller', 'run', 'source'].includes(subject.role) || typeof subject.relative !== 'string' || subject.relative.length > 128)
        throw new TypeError('invalid resource role or name');
    }
    borrow((root, path) => {
      if (!path.startsWith('/sys/fs/cgroup/') || !/^cliq-[0-9a-f]{64}-keeper\.service$/u.test(path.split('/').at(-1)!))
        throw new TypeError('resource anchor is not the original fixed installed unit');
      const keeperGroup = path.slice('/sys/fs/cgroup'.length), supervisorGroup = keeperGroup.replace(/-keeper\.service$/u, '-supervisor.service');
      const read = (role: ResourceRole, group: number, process: OriginalResourceProcess | undefined, membership: string | undefined,
        expected?: { device: string; inode: string }) => {
        const info = fstatSync(group, { bigint: true });
        emit(role, sampleHeldResourceGroup(group, expected ?? { device: String(info.dev), inode: String(info.ino) }, process, membership,
          role === 'supervisor' || role === 'keeper' || role === 'controller' ? 'trusted' : 'skip'));
      };
      const openGroup = (absolute: string) => {
        const components = absolute.split('/').filter(Boolean); if (components.length > 32 || components.some(value => !/^[A-Za-z0-9_.:@-]+$/u.test(value) || value === '.' || value === '..'))
          throw new TypeError('resource cgroup path exceeds its fixed bound');
        let held = openSync('/sys/fs/cgroup', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        try { for (const name of components) {
          const next = openSync(`/proc/self/fd/${held}/${name}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
          try { closeSync(held); } catch { closeFailed = true; } held = next;
        } return held; } catch (error) { try { closeSync(held); } catch { closeFailed = true; } throw error; }
      };
      const own = ownProcess(process.pid, process.geteuid!());
      let held = -1;
      try { held = openGroup(supervisorGroup); read('supervisor', held, own, supervisorGroup); }
      catch { emit('supervisor', unavailable()); }
      finally { if (held >= 0) try { closeSync(held); } catch { closeFailed = true; } }
      held = -1;
      try {
        held = openSync(`/proc/self/fd/${root}/keeper`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        // The genuine anchor independently pins this exact original Keeper's
        // PID/start before and after the complete synchronous borrow.
        const pids = readFile(`/proc/self/fd/${held}/cgroup.procs`, 4096).toString('ascii');
        if (!/^[1-9][0-9]*\n$/u.test(pids)) throw new TypeError('original Keeper membership is not singular');
        const keeper = ownProcess(Number(pids.trim()), process.geteuid!()); read('keeper', held, keeper, keeperGroup + '/keeper');
      } catch { emit('keeper', unavailable()); }
      finally { if (held >= 0) try { closeSync(held); } catch { closeFailed = true; } }
      for (const subject of subjects) {
        held = -1;
        try {
          const pattern = subject.role === 'controller' ? /^controllers\/controller-[0-9a-f]{32}$/u
            : subject.role === 'run' ? /^cliq-(?:preparation-)?[0-9a-f]{64}$/u : /^cliq-source-[0-9a-f]{64}$/u;
          if (!pattern.test(subject.relative)) throw new TypeError('resource subject is not an original fixed cgroup');
          held = openGroup(keeperGroup + '/' + subject.relative);
          const member = keeperGroup + '/' + subject.relative + (subject.role === 'run' && !subject.relative.startsWith('cliq-preparation-') ? '/worker' : '');
          read(subject.role, held, subject.pid === undefined && subject.start === undefined ? undefined
            : { pid: subject.pid!, start: subject.start!, uid: process.geteuid!() }, subject.pid === undefined ? undefined : member,
            { device: subject.device, inode: subject.inode });
        } catch { emit(subject.role, unavailable()); }
        finally { if (held >= 0) try { closeSync(held); } catch { closeFailed = true; } }
      }
    });
  } catch (error) {
    // A genuine anchor postcheck can expose an existing native retirement
    // failure. Optional measurement must never hide that sticky original error.
    if (error instanceof ResourceRetirementError) throw error;
    pending.length = 0; emit('supervisor', unavailable());
  }
  if (closeFailed || pending.some(value => value.numbers.joined === 0)) {
    pending.length = 0; emit('supervisor', unavailable(0));
  }
  // A postcheck failure discards every observation collected in that borrow.
  const delivery = [...observers];
  for (const observation of pending) for (const observer of delivery) try { observer(observation); } catch { /* Passive sink only. */ }
  if (pending.some(value => value.numbers.joined === 0))
    throw new ResourceRetirementError('installed resource observation descriptors did not join', new Error('actual measurement close returned an error'));
}

export { RESOURCE_ROLES, RESOURCE_BOUNDARIES };
