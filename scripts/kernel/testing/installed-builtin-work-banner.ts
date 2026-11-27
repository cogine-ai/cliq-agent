// Trusted disposable image only. Process windows are not exclusive Run costs.
import { BUILTIN_EXECUTION_PHASES } from '../../../src/sandbox/builtin-tool-diagnostics.js';
import { INSTALLED_BUILTIN_WORK_CHANNEL } from '../../../src/state/installed-work-diagnostics.js';

export const INSTALLED_BUILTIN_WORK_DIAGNOSTIC_BANNER = `;(() => { try {
  if (process.argv[2] !== '--installed-supervisor') return;
  const channel = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_BUILTIN_WORK_CHANNEL)});
  const phases = ${JSON.stringify(BUILTIN_EXECUTION_PHASES)}, rows = new Map();
  const isProxy = require('node:util').types.isProxy, write = require('node:fs').writeSync;
  const clock = require('node:perf_hooks').performance, prefix = 'CLIQ_BUILTIN_WORK_V1:';
  let previous, first, stopped = false;
  const safe = n => Number.isSafeInteger(n) && n >= 0;
  const output = frame => { try { write(2, frame); } catch {} };
  const invalid = () => { if (!stopped) { stopped = true; output(prefix + 'truncated\\n'); } };
  channel.subscribe(value => { try {
    if (stopped) return;
    if (!value || typeof value !== 'object' || isProxy(value) || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw 0;
    const keys = ['phase','readsStarted','readsSettled','returnedBytes','revalidatedBytes'];
    const fields = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !fields[key] ||
        !fields[key].enumerable || !Object.hasOwn(fields[key], 'value'))) throw 0;
    const [phase, ...counts] = keys.map(key => fields[key].value);
    if (typeof phase !== 'string' || !phases.includes(phase) && phase !== 'stop_entry' ||
        !counts.every(safe) || counts[1] > counts[0]) throw 0;
    const cpu = process.resourceUsage(), now = Math.floor(clock.now() * 1000);
    const sample = [now, ...counts, cpu.userCPUTime, cpu.systemCPUTime];
    if (!sample.every(safe) || previous && sample.some((n, i) => n < previous.sample[i])) throw 0;
    if (previous) {
      const row = rows.get(previous.phase);
      for (let i = 0; i < sample.length; i++) { row[i + 1] += sample[i] - previous.sample[i]; if (!safe(row[i + 1])) throw 0; }
    } else first = now;
    if (phase === 'stop_entry') {
      stopped = true;
      if (!rows.size) return;
      const ordered = phases.filter(name => rows.has(name)).map(name => name + ',' + rows.get(name).join(','));
      const frame = prefix + (now - first) + ':' + (counts[0] - counts[1]) + ':' + ordered.length + ':' + ordered.join(';') + '\\n';
      if (frame.length > 8192) { output(prefix + 'truncated\\n'); return; }
      output(frame); return;
    }
    if (!rows.has(phase)) rows.set(phase, [0,0,0,0,0,0,0,0]);
    const row = rows.get(phase); row[0]++; if (!safe(row[0])) throw 0;
    previous = {phase, sample};
  } catch { invalid(); } });
} catch {} })();`;
