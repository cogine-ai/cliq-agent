// Fixed qualification-only counters. No installation/Run/StateOwner authority,
// payloads, paths, digests, arbitrary callbacks or changed deadlines.
import { channel } from 'node:diagnostics_channel';
import { writeSync } from 'node:fs';
import { types } from 'node:util';
import { INSTALLED_INSTALL_PHASE_CHANNEL, INSTALLED_INSTALL_PHASES, INSTALLED_WORK_CHANNEL } from '../../../src/state/installed-work-diagnostics.js';

const prefix = 'CLIQ_INSTALLED_INSTALL_V1:', maxFrames = 256, maxFrameBytes = 256;
const keys = ['phase', 'items', 'elapsedMs', 'packageStarted', 'packageSettled', 'packageBytesRead', 'packageSpanElapsedMs'] as const;
export type InstalledInstallerDiagnostic = Readonly<Record<typeof keys[number], number>>;
const zero = () => [0, 0, 0, 0];
function fields(value: unknown, names: readonly string[]): unknown[] {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw 0;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== names.length) throw 0;
  return names.map(name => {
    const field = descriptors[name];
    if (!field || !Object.hasOwn(field, 'value') || !field.enumerable) throw 0;
    return field.value;
  });
}
const safe = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
function checked(numbers: readonly unknown[]): InstalledInstallerDiagnostic {
  if (numbers.length !== keys.length || !numbers.every(safe)) throw 0;
  const [phase, items, , started, settled] = numbers as readonly number[];
  if (phase! < 1 || phase! > INSTALLED_INSTALL_PHASES.length || items! > 1_048_576 || settled! > started!) throw 0;
  return Object.freeze(Object.fromEntries(keys.map((name, index) => [name, numbers[index]]))) as InstalledInstallerDiagnostic;
}

/** Reproduce the exact already-scanned canonical ASCII frame, without new
 * JSON keys or formatting literals that were absent from the scanned bytes. */
export function encodeInstalledInstallerDiagnostic(value: InstalledInstallerDiagnostic): string {
  const numbers = fields(value, keys); checked(numbers);
  return prefix + numbers.join(':');
}

/** Only the trusted disposable installer subscribes. The writer is fixed fd2;
 * even observation/write errors cannot reject the actual installation. */
export function observeInstalledInstallerDiagnostics(): () => void {
  const phases = channel(INSTALLED_INSTALL_PHASE_CHANNEL), work = channel(INSTALLED_WORK_CHANNEL);
  let started: number;
  try { started = performance.now(); } catch { return () => {}; }
  let phase = 0, items = 0, emitted = 0, stopped = false, packageCounts = zero();
  const emit = () => {
    if (stopped || phase === 0) return;
    try {
      if (emitted >= maxFrames - 1) {
        stopped = true; const marker = prefix + 'truncated\n'; writeSync(2, marker); return;
      }
      const numbers = [phase, items, Math.floor(Math.max(0, performance.now() - started)), ...packageCounts];
      checked(numbers); const frame = prefix + numbers.join(':') + '\n';
      if (Buffer.byteLength(frame) > maxFrameBytes) throw 0;
      if (writeSync(2, frame) !== Buffer.byteLength(frame)) throw 0;
      emitted++;
    } catch { stopped = true; }
  };
  const onPhase = (value: unknown) => {
    try {
      const next = fields(value, ['phase', 'items']);
      if (!next.every(safe) || next[0]! < phase || next[0]! === phase && next[1]! < items) throw 0;
      phase = next[0] as number; items = next[1] as number; emit();
    } catch { stopped = true; }
  };
  const onWork = (value: unknown) => {
    try {
      if (value === 'truncated') throw 0;
      const rows = fields(value, ['package', 'revalidate', 'createCompare']);
      const values = rows.map(row => fields(row, ['started', 'completed', 'bytesRead', 'spanElapsedMs']));
      if (values.some(row => !row.every(safe) || (row[1] as number) > (row[0] as number))) throw 0;
      packageCounts = values[0] as number[]; emit();
    } catch { stopped = true; }
  };
  const stop = () => {
    stopped = true;
    try { phases.unsubscribe(onPhase); } catch { /* Observation owns no installation resources. */ }
    try { work.unsubscribe(onWork); } catch { /* Observation owns no installation resources. */ }
  };
  try { phases.subscribe(onPhase); work.subscribe(onWork); }
  catch { stop(); }
  return stop;
}

/** Call only after the original secret scanner consumed ALL original stdout
 * and stderr. Unknown lines never escape; any malformed fixed frame rejects
 * this optional journal, never the original command or its qualified=false. */
export function decodeInstalledInstallerDiagnostics(bytes: Buffer): readonly InstalledInstallerDiagnostic[] {
  if (!Buffer.isBuffer(bytes) || types.isProxy(bytes) || bytes.length > 2 * 1024 * 1024) return [];
  const rows: InstalledInstallerDiagnostic[] = [];
  try {
    // Frames are ASCII. No decoding/re-emission of unrelated stderr is needed.
    const lines = bytes.toString('latin1').split('\n');
    if (lines.at(-1)?.startsWith(prefix)) return []; // An interrupted write is not a complete frame.
    for (const line of lines) {
      if (!line.startsWith(prefix)) continue;
      if (rows.length >= maxFrames) throw 0;
      if (line === prefix + 'truncated') return []; // Never present a truncated journal as complete.
      if (line.length + 1 > maxFrameBytes) throw 0;
      const parts = line.slice(prefix.length).split(':');
      if (!parts.every(value => /^(?:0|[1-9][0-9]{0,15})$/u.test(value))) throw 0;
      const row = checked(parts.map(Number)), prior = rows.at(-1);
      if (prior && (row.phase < prior.phase || row.phase === prior.phase && row.items < prior.items ||
          row.elapsedMs < prior.elapsedMs || row.packageStarted < prior.packageStarted || row.packageSettled < prior.packageSettled ||
          row.packageBytesRead < prior.packageBytesRead || row.packageSpanElapsedMs < prior.packageSpanElapsedMs)) throw 0;
      rows.push(row);
    }
    return Object.freeze(rows);
  } catch { return []; }
}
