// Controlled-endpoint test image only. Sampling never pauses a process or
// grants authority. The deliberately shortened run cannot qualify delivery.
import assert from 'node:assert/strict';
import { INSTALLED_BUILTIN_WORK_CHANNEL } from '../../../src/state/installed-work-diagnostics.js';
import { originalJournalMessages } from './installed-store-diagnostic-journal.js';

export const PR532_CPU_DIAGNOSTIC = process.argv[2] === '--pr532-cpu-diagnostic';
export const CPU_BUCKETS = ['canonical', 'snapshot', 'json_read', 'decoder', 'cas', 'sqlite', 'gc', 'idle', 'other'] as const;

export const INSTALLED_CPU_DIAGNOSTIC_BANNER = `;(() => { try {
  if (process.argv[2] !== '--installed-supervisor') return;
  const channel = require('node:diagnostics_channel').channel(${JSON.stringify(INSTALLED_BUILTIN_WORK_CHANNEL)});
  const proxy = require('node:util').types.isProxy, write = require('node:fs').writeSync;
  let prepares = 0, session, started = false, stopped = false, refused = false;
  const refuse = () => { if (refused) return; refused = true; stopped = true;
    try { session?.disconnect(); } catch {} try { write(2, 'CLIQ_CPU_SAMPLE_V1:refused\\n'); } catch {} };
  const post = (method, parameters, next) => { if (refused) return; try {
    session.post(method, parameters, (error,result) => { if (refused) return;
      try { if (error) refuse(); else next(result); } catch { refuse(); } });
  } catch { refuse(); } };
  channel.subscribe(value => { try {
    if (!value || typeof value !== 'object' || proxy(value)) return;
    const field = Object.getOwnPropertyDescriptor(value, 'phase');
    if (!field || !Object.hasOwn(field, 'value')) return;
    if (field.value === 'tool_prepare') prepares++;
    if (field.value === 'tool_prepare' && prepares === 4) {
      session = new (require('node:inspector').Session)(); session.connect();
      post('Profiler.enable', {}, () => post('Profiler.setSamplingInterval', {interval:5000},
        () => post('Profiler.start', {}, () => { started = true; })));
    }
    if (field.value === 'stop_entry' && !stopped && session) {
      stopped = true; session.disconnect(); refuse(); return;
    }
    if (field.value !== 'tool_prepare' || prepares !== 6 || !started || stopped) return;
    // Process the sample before the observer can request the original Stop2.
    stopped = true;
    post('Profiler.stop', {}, result => { try {
      const p = result.profile, nodes = new Map(), parents = new Map(), categories = new Map(), counts = Array(9).fill(0);
      if (!Array.isArray(p.nodes) || p.nodes.length > 16384 || !Array.isArray(p.samples) ||
          !p.samples.length || p.samples.length > 200000) throw 0;
      for (const n of p.nodes) { nodes.set(n.id,n); for (const c of n.children || []) parents.set(c,n.id); }
      for (const id of p.samples) {
        if (categories.has(id)) { counts[categories.get(id)]++; continue; }
        const flags = new Set(); let current = id;
        for (let depth = 0; current !== undefined && depth < 128; depth++) {
          const n = nodes.get(current); if (!n || typeof n.callFrame.functionName !== 'string') throw 0;
          const name = n.callFrame.functionName;
          if (['serializeCanonical','canonicalJsonBytes','canonicalSha256'].includes(name)) flags.add(0);
          if (['immutableSnapshot','freeze','structuredClone'].includes(name)) flags.add(1);
          if (['readCanonical','readCanonicalArtifact'].includes(name)) flags.add(2);
          if (name.startsWith('decode')) flags.add(3);
          if (['readChunks','readBytes','verifyChunks','verifyBytes','withRoot','cachedReadBytes'].includes(name)) flags.add(4);
          if (['readRun','readInvocationJournal','readRows'].includes(name)) flags.add(5);
          if (name === '(garbage collector)') flags.add(6);
          if (name === '(idle)') flags.add(7);
          current = parents.get(current);
        }
        const category = [0,1,2,3,4,5,6,7].find(v => flags.has(v)) ?? 8;
        categories.set(id,category); counts[category]++;
      }
      const duration = Math.round(p.endTime-p.startTime);
      if (!Number.isSafeInteger(duration) || duration <= 0) throw 0;
      session.disconnect();
      write(2, 'CLIQ_CPU_SAMPLE_V1:' + [p.samples.length,duration,...counts].join(':') + '\\n');
    } catch { try { session.disconnect(); } catch {} refuse(); } });
  } catch { try { session?.disconnect(); } catch {} refuse(); } });
} catch {} })();`;

export function readInstalledCpuJournal(text: string, expected: { uid: number; pid: number; invocationId: string }) {
  const rows = originalJournalMessages(text, expected).filter(row => row.startsWith('CLIQ_CPU_SAMPLE_V1:'));
  assert.equal(rows.length, 1);
  const fields = rows[0]!.split(':'); assert.equal(fields.length, 12);
  const numbers = fields.slice(1).map(value => {
    assert(/^(0|[1-9][0-9]{0,15})$/u.test(value)); const n = Number(value); assert(Number.isSafeInteger(n)); return n;
  });
  const [samples, durationMicros, ...counts] = numbers;
  assert(samples! > 0 && samples! <= 200000 && durationMicros! > 0);
  assert.equal(counts.reduce((a,b) => a+b,0), samples);
  return { diagnosticOnly: true, sampler: 'v8-cpu-5000us', scope: 'original_supervisor_main_isolate',
    runAttribution: false, samples, durationMicros,
    buckets: Object.fromEntries(CPU_BUCKETS.map((name,index) => [name,counts[index]])) };
}
