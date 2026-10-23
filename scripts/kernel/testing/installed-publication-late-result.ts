// Pure fixed-data classifier only; a matching tuple grants no authority and
// never substitutes for actual public cuts, native ownership or physical proof.
import assert from 'node:assert/strict';
import { controlWireRecord } from '../../../src/kernel/control-wire.js';
import { parseCanonicalTime } from '../../../src/kernel/identity.js';
import { decodePublicationRetirementDiagnostic, type PublicationRetirementDiagnostic } from '../../../src/state/publication-retirement-diagnostics.js';
import type { InstalledPublicationProbeSample } from './installed-publication-recovery.js';
import { readInstalledLatePublicationRetirementJournal, readInstalledNamespaceRetirementJournal } from './installed-publication-journal.js';

export type InstalledPublicationLateInterval = Readonly<{ diagnosticOnly: true; hit: boolean;
  parentSlot: 1 | 2 | null; monotonicDurationNs: string | null }>;
export type InstalledPublicationLateDiagnostic = {
  diagnosticOnly: true; qualified: boolean;
  stage: 'observer_start' | 'original_claim' | 'physical_kill' | 'successor' | 'sampling' |
    'span_observed' | 'audit_verified' | 'closure_verified' | 'complete';
  physicalLateCutQualified: boolean; realPublicCutsQualified: boolean;
  preciseInFlightPublicationStopQualified: false; currentSealedMDirectoryPhysicalBytesQualified: false;
  runId?: string; beforePublicCutDigest?: string; auditPublicCutDigest?: string;
  windowOpenedAt?: string; currentProcessLifetimeAndImageBound?: true;
  probes?: InstalledPublicationProbeSample['probes'];
  snapshots?: readonly PublicationRetirementDiagnostic[]; interval?: InstalledPublicationLateInterval;
  namespaceWindowProgress?: Readonly<{ diagnosticOnly: true; complete: false; observedGroups: 1 }>;
  originalWaitUnchanged?: true; oldTaskJoinedAndTimedOut?: true; originalBackoffAndFreshNonceVerified?: true;
  resolutionBudgetDeltaZero?: true; redispatchCount?: 0; additionalModelPosts?: 0;
  originalWorkerAndArenaIndependentlyAbsent?: true; sameReplayAfterReconnect?: true;
};

/** A complete known first group is pending data, never a partial success. Every
 * call revalidates one whole window; fragments and different windows are never
 * buffered or assembled, and all unknown errors retain the original refusal. */
export function readInstalledLatePublicationRetirementWindow(text: string,
  expected: Parameters<typeof readInstalledLatePublicationRetirementJournal>[1]): Readonly<{
    diagnosticOnly: true; phase: 'unobserved' | 'first_packet_only' | 'complete';
    snapshots: readonly PublicationRetirementDiagnostic[];
  }> {
  controlWireRecord(expected, ['uid', 'pid', 'invocationId', 'expiredProbeKey', 'freshProbeKey']);
  assert.match(expected.expiredProbeKey, /^[0-9a-f]{64}$/u); assert.match(expected.freshProbeKey, /^[0-9a-f]{64}$/u);
  assert.notEqual(expected.expiredProbeKey, expected.freshProbeKey);
  try {
    const snapshots = readInstalledLatePublicationRetirementJournal(text, expected);
    return Object.freeze({ diagnosticOnly: true, phase: snapshots ? 'complete' : 'unobserved', snapshots: snapshots ?? Object.freeze([]) });
  } catch (original) {
    let prefix: PublicationRetirementDiagnostic | undefined;
    try { prefix = readInstalledNamespaceRetirementJournal(text, { uid: expected.uid, pid: expected.pid,
      invocationId: expected.invocationId, key: expected.expiredProbeKey }); }
    catch { throw original; }
    if (!prefix) throw original;
    return Object.freeze({ diagnosticOnly: true, phase: 'first_packet_only', snapshots: Object.freeze([prefix]) });
  }
}

export function assessInstalledPublicationLateInterval(input: unknown): InstalledPublicationLateInterval {
  const data = controlWireRecord(input, ['snapshot', 'key', 'probeStartedAt', 'probeDeadlineAt', 'completedAt']);
  assert.equal(typeof data.key, 'string'); assert.match(data.key as string, /^[0-9a-f]{64}$/u);
  for (const field of ['probeStartedAt', 'probeDeadlineAt', 'completedAt']) assert.equal(typeof data[field], 'string');
  const start = parseCanonicalTime(data.probeStartedAt as string), deadline = parseCanonicalTime(data.probeDeadlineAt as string),
    completed = parseCanonicalTime(data.completedAt as string);
  assert.equal(deadline - start, 30_000); assert(completed > deadline, 'the original immutable completion must be later than its own deadline');
  const packet = decodePublicationRetirementDiagnostic(data.snapshot);
  assert.equal(packet.kind, 'namespace'); assert.equal(packet.key, data.key);
  const d = BigInt(deadline) * 1_000_000n;
  for (const parentSlot of [1, 2] as const) {
    const span = packet.slots[parentSlot];
    if (span.length === 7 && span[0] === 1 && span[1] === 1 && span[2] === 'ok' &&
        BigInt(span[3]) < BigInt(span[5]) && BigInt(span[4]) < d && d < BigInt(span[6]))
      return Object.freeze({ diagnosticOnly: true, hit: true, parentSlot,
        monotonicDurationNs: String(BigInt(span[5]) - BigInt(span[3])) });
  }
  return Object.freeze({ diagnosticOnly: true, hit: false, parentSlot: null, monotonicDurationNs: null });
}

/** Same live host/process only: cancel-and-join of the old task precedes the
 * fresh nonce. Unavailable stamps supply no evidence; REALTIME is not ordered
 * across tasks and this check grants no physical qualification. */
export function assertInstalledPublicationLateCausalOrder(input: unknown): void {
  const data = controlWireRecord(input, ['expiredSnapshot', 'freshSnapshot']);
  const expired = decodePublicationRetirementDiagnostic(data.expiredSnapshot), fresh = decodePublicationRetirementDiagnostic(data.freshSnapshot);
  assert.equal(expired.kind, 'namespace'); assert.equal(fresh.kind, 'namespace'); assert.notEqual(expired.key, fresh.key);
  for (const old of expired.slots) if (old?.length === 7)
    for (const next of fresh.slots) if (next?.length === 7)
      assert(BigInt(old[5]) <= BigInt(next[3]),
        'the old joined task must return before every available fresh-nonce monotonic entry');
}
