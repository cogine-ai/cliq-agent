import type { InstalledResourceObservation } from '../../../src/state/installed-resource-diagnostics.js';
import { installedResourceLine } from './installed-resource-wire.js';
export function createInstalledResourceSink(write: (line: Buffer) => number) {
  const seen = new Set<string>(); let bytes = 0, emitted = 0, stopped = false;
  return (observation: InstalledResourceObservation) => {
  try {
    if (stopped) return;
    const line = installedResourceLine(observation), key = observation.role + ':' + observation.boundary;
    const failed = observation.numbers.joined === 0;
    // Reserve the final record for an actual cleanup failure; an earlier
    // ordinary observation of this role/boundary cannot suppress it.
    if (!failed && (seen.has(key) || emitted >= 39 || bytes + line.length + 384 > 16384)) return;
    if (emitted >= 40 || bytes + line.length > 16384) { stopped = true; return; }
    seen.add(key); bytes += line.length; emitted++;
    if (write(line) !== line.length || failed) stopped = true;
  } catch { stopped = true; /* Missing observation never supplies a substitute. */ }
  };
}
