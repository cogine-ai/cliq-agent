import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Retained negative evidence, never a retry, output or process-death permit. */
export type DependencyAmbiguityV1 = {
  schemaVersion: 1; format: 'cliq-dependency-ambiguity-v1'; runId: string; opId: string; attempt: 0;
  dispatchId: string; claimJournalSeq: number; requestRef: string; target: 'builtin:dependency-acquire'; grantRef: string;
  brokerFenceTokenDigest: string;
} & ({ reason: 'original_owner_joined_without_process_result'; brokerDispatchClosureRef: string } |
  { reason: 'claiming_owner_dead_before_result'; acquisitionEvidenceRef: string; acquisitionEvidenceDigest: string });

export function decodeDependencyAmbiguity(value: unknown): DependencyAmbiguityV1 {
  assertControlWireJson(value);
  const v = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'claimJournalSeq',
    'requestRef', 'target', 'grantRef', 'brokerFenceTokenDigest', 'reason'],
  ['brokerDispatchClosureRef', 'acquisitionEvidenceRef', 'acquisitionEvidenceDigest']);
  if (v.schemaVersion !== 1 || v.format !== 'cliq-dependency-ambiguity-v1' || v.target !== 'builtin:dependency-acquire')
    throw new TypeError('dependency ambiguity has another purpose');
  for (const key of ['runId', 'opId', 'dispatchId']) controlWireText(v[key], 256);
  controlWireInteger(v.attempt, 0, 0); controlWireInteger(v.claimJournalSeq, 1);
  for (const key of ['requestRef', 'grantRef', 'brokerFenceTokenDigest']) controlWireRef(v[key]);
  if (v.reason === 'original_owner_joined_without_process_result') {
    if (!Object.hasOwn(v, 'brokerDispatchClosureRef') || Object.hasOwn(v, 'acquisitionEvidenceRef') || Object.hasOwn(v, 'acquisitionEvidenceDigest'))
      throw new TypeError('dependency native fence and owner death are exclusive');
    controlWireRef(v.brokerDispatchClosureRef);
  } else if (v.reason === 'claiming_owner_dead_before_result') {
    if (Object.hasOwn(v, 'brokerDispatchClosureRef') || !Object.hasOwn(v, 'acquisitionEvidenceRef') || !Object.hasOwn(v, 'acquisitionEvidenceDigest'))
      throw new TypeError('dependency owner death cannot invent broker traffic');
    controlWireRef(v.acquisitionEvidenceRef); controlWireRef(v.acquisitionEvidenceDigest);
  } else throw new TypeError('dependency ambiguity has another observation');
  return immutableSnapshot(v) as DependencyAmbiguityV1;
}
