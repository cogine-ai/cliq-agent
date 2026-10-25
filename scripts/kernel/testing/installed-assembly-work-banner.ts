// Trusted disposable server composition only; not a runtime option or authority.
import { INSTALLED_ASSEMBLY_WORK_CHANNEL, INSTALLED_ASSEMBLY_WORK_PHASES } from '../../../src/state/installed-work-diagnostics.js';

export const INSTALLED_ASSEMBLY_WORK_DIAGNOSTIC_BANNER = `;(() => { try {
  if (process.argv[2] !== '--installed-supervisor') return;
  const diagnostic = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_ASSEMBLY_WORK_CHANNEL)});
  const phases = ${JSON.stringify(INSTALLED_ASSEMBLY_WORK_PHASES)};
  const write = require('node:fs').writeSync, isProxy = require('node:util').types.isProxy;
  const prefix = 'CLIQ_ASSEMBLY_WORK_V1:';
  const truncatedFrame = prefix + 'truncated\\n';
  let emitted = 0, total = 0, stopped = false, previousPhase = -1, previousElapsed = 0, previous, previousCPU;
  const output = frame => { try { if (write(2, frame) !== frame.length) stopped = true; } catch { stopped = true; } };
  const truncate = () => { if (!stopped) { output(truncatedFrame); stopped = true; } };
  const values = (object, keys) => {
    if (!object || typeof object !== 'object' || isProxy(object) || Array.isArray(object) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(object))) throw 0;
    const fields = Object.getOwnPropertyDescriptors(object);
    if (Reflect.ownKeys(fields).length !== keys.length) throw 0;
    return keys.map(key => { const field = fields[key];
      if (!field || !Object.hasOwn(field, 'value') || !field.enumerable) throw 0; return field.value; });
  };
  const safe = value => Number.isSafeInteger(value) && value >= 0;
  diagnostic.subscribe(value => { try {
    if (stopped) return;
    if (value === 'truncated') { truncate(); return; }
    const [phase, elapsed, runtime, casRead, publishFour, fileSync, rootSync] = values(value,
      ['phase', 'elapsedMs', 'runtime', 'casRead', 'publishFour', 'fileSync', 'rootSync']);
    const index = typeof phase === 'string' ? phases.indexOf(phase) : -1;
    if (index < 0 || index <= previousPhase || emitted === 0 && index !== 0 || !safe(elapsed) ||
        elapsed < previousElapsed || emitted === 0 && elapsed !== 0) throw 0;
    const numbers = values(runtime, ['package', 'revalidate', 'createCompare']).flatMap(row => {
      const result = values(row, ['started', 'completed', 'bytesRead', 'spanElapsedMs']);
      if (!result.every(safe) || result[1] > result[0]) throw 0; return result;
    });
    const read = values(casRead, ['started', 'settled', 'bytesRead', 'spanElapsedMs']);
    if (!read.every(safe) || read[1] > read[0]) throw 0;
    numbers.push(...read);
    for (const row of [publishFour, fileSync, rootSync]) {
      const result = values(row, ['started', 'settled', 'spanElapsedMs']);
      if (!result.every(safe) || result[1] > result[0]) throw 0; numbers.push(...result);
    }
    if (numbers[10] !== 0 || previous && numbers.some((value, index) => value < previous[index])) throw 0;
    // Node microseconds, whole-process cumulative including threads. Never
    // label getrusage counters as physical bytes, exclusive stage CPU or success.
    let cpu = ['-', '-'];
    try {
      const sample = process.resourceUsage(), current = [sample.userCPUTime, sample.systemCPUTime];
      if (current.every(safe) && (!previousCPU || current.every((value, index) => value >= previousCPU[index]))) {
        cpu = current; previousCPU = current;
      }
    } catch {}
    const frame = prefix + (emitted + 1) + ':' + phase + ':' + elapsed + ':' + numbers.join(':') + ':' + cpu.join(':') + '\\n';
    if (emitted >= 9 || frame.length > 512 || total + frame.length + truncatedFrame.length > 4096) { truncate(); return; }
    emitted++; total += frame.length; previousPhase = index; previousElapsed = elapsed; previous = numbers; output(frame);
  } catch { truncate(); } });
} catch {} })();`;
