import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Negative execution fact from the original live broker, never a process
 * result, containment death, success, output ACK or permission to retry. */
export type DependencyAcquisitionClosureV1 = {
  schemaVersion: 1; format: 'cliq-dependency-acquisition-closure-v1'; runId: string; opId: string; attempt: number;
  claimEvidenceRef: string; dispatchId: string; dispatchJournalSeq: number; brokerFenceTokenDigest: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string;
  closure: { kind: 'dependency_transport_closed'; tokenRevoked: true; networkStarted: boolean; requestStarted: boolean;
    connectionCount: number; requestCount: number; transferredBytes: number; processClaimed: false; processJoined: false;
    processResultAvailable: false; processResultAcknowledged: false; processResultCustodyRetired: false;
    processResultCustodyOrigin: 'none'; fenceAction: 'original_token_revoked_io_joined_worker_never_acquired' };
  evidenceDigest: string;
};
export function decodeDependencyAcquisitionClosure(value: unknown): DependencyAcquisitionClosureV1 {
  assertControlWireJson(value);
  const v = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'claimEvidenceRef', 'dispatchId',
    'dispatchJournalSeq', 'brokerFenceTokenDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'closure', 'evidenceDigest']);
  if (v.schemaVersion !== 1 || v.format !== 'cliq-dependency-acquisition-closure-v1') throw new TypeError('foreign dependency acquisition closure');
  for (const key of ['runId', 'opId', 'dispatchId']) controlWireText(v[key], 256);
  for (const key of ['claimEvidenceRef', 'brokerFenceTokenDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest']) controlWireRef(v[key]);
  controlWireInteger(v.attempt, 0, 0); controlWireInteger(v.dispatchJournalSeq, 1); parseCanonicalTime(controlWireText(v.observedAt, 24));
  const c = controlWireRecord(v.closure, ['kind', 'tokenRevoked', 'networkStarted', 'requestStarted', 'connectionCount', 'requestCount', 'transferredBytes',
    'processClaimed', 'processJoined', 'processResultAvailable', 'processResultAcknowledged', 'processResultCustodyRetired', 'processResultCustodyOrigin', 'fenceAction']);
  if (c.kind !== 'dependency_transport_closed' || c.tokenRevoked !== true || typeof c.networkStarted !== 'boolean' || typeof c.requestStarted !== 'boolean' ||
      c.processClaimed !== false || c.processJoined !== false || c.processResultAvailable !== false || c.processResultAcknowledged !== false ||
      c.processResultCustodyRetired !== false || c.processResultCustodyOrigin !== 'none' ||
      c.fenceAction !== 'original_token_revoked_io_joined_worker_never_acquired') throw new TypeError('dependency acquisition closure asserts a process fact');
  controlWireInteger(c.connectionCount, 0, 600_000); controlWireInteger(c.requestCount, 0, 600_000); controlWireInteger(c.transferredBytes, 0, 21_474_836_480);
  if ((c.requestCount as number) > (c.connectionCount as number) || c.networkStarted !== (c.connectionCount !== 0) || c.requestStarted !== (c.requestCount !== 0) ||
      !c.requestStarted && c.transferredBytes !== 0 || v.evidenceDigest !== digestOmitting(v, 'evidenceDigest'))
    throw new TypeError('dependency acquisition closure counters or full digest differ');
  return immutableSnapshot(v) as DependencyAcquisitionClosureV1;
}

export type DependencyAcquisitionRetirementV1 = {
  schemaVersion: 1; format: 'cliq-dependency-acquisition-retirement-v1'; runId: string; opId: string; attempt: number;
  dependencyPlanRef: string; acquisitionClosureRef: string; acquisitionClosureDigest: string; checkpointId: string;
  workspaceStateRef: string; snapshotEvidenceRef: string; parentRetirementEvidenceRef: string; evidenceDigest: string;
};
export function decodeDependencyAcquisitionRetirement(value: unknown): DependencyAcquisitionRetirementV1 {
  assertControlWireJson(value);
  const v = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dependencyPlanRef',
    'acquisitionClosureRef', 'acquisitionClosureDigest', 'checkpointId', 'workspaceStateRef', 'snapshotEvidenceRef', 'parentRetirementEvidenceRef', 'evidenceDigest']);
  if (v.schemaVersion !== 1 || v.format !== 'cliq-dependency-acquisition-retirement-v1') throw new TypeError('foreign dependency acquisition retirement');
  for (const key of ['runId', 'opId', 'checkpointId']) controlWireText(v[key], 256);
  controlWireInteger(v.attempt, 0, 0);
  for (const key of ['dependencyPlanRef', 'acquisitionClosureRef', 'acquisitionClosureDigest', 'workspaceStateRef', 'snapshotEvidenceRef', 'parentRetirementEvidenceRef', 'evidenceDigest']) controlWireRef(v[key]);
  if (v.evidenceDigest !== digestOmitting(v, 'evidenceDigest')) throw new TypeError('dependency acquisition retirement digest differs');
  return immutableSnapshot(v) as DependencyAcquisitionRetirementV1;
}

export type DependencyBrokerDispatchClosureV1 = {
  schemaVersion: 1; format: 'cliq-dependency-broker-dispatch-closure-v1'; runId: string; opId: string; attempt: number;
  dispatchId: string; claimJournalSeq: number; claimEvidenceRef: string; brokerFenceTokenDigest: string;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; observedAt: string;
  io: { networkStarted: boolean; requestStarted: boolean; connectionCount: number; requestCount: number; transferredBytes: number;
    processClaimed: boolean; processJoined: boolean; processResultAcknowledged: boolean; processResultCustodyRetired: boolean;
    processResultCustodyOrigin: 'none' | 'acknowledged' | 'controller_joined' };
  fenceAction: 'original_matching_token_revoked_all_io_joined_native_mutex_held'; evidenceDigest: string;
};
export function decodeDependencyBrokerDispatchClosure(value: unknown): DependencyBrokerDispatchClosureV1 {
  assertControlWireJson(value);
  const v = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'claimJournalSeq', 'claimEvidenceRef',
    'brokerFenceTokenDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'observedAt', 'io', 'fenceAction', 'evidenceDigest']);
  if (v.schemaVersion !== 1 || v.format !== 'cliq-dependency-broker-dispatch-closure-v1' ||
      v.fenceAction !== 'original_matching_token_revoked_all_io_joined_native_mutex_held') throw new TypeError('foreign dependency broker closure');
  for (const key of ['runId', 'opId', 'dispatchId']) controlWireText(v[key], 256);
  for (const key of ['claimEvidenceRef', 'brokerFenceTokenDigest', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'evidenceDigest']) controlWireRef(v[key]);
  controlWireInteger(v.attempt, 0, 0); controlWireInteger(v.claimJournalSeq, 1); parseCanonicalTime(controlWireText(v.observedAt, 24));
  const io = controlWireRecord(v.io, ['networkStarted', 'requestStarted', 'connectionCount', 'requestCount', 'transferredBytes', 'processClaimed',
    'processJoined', 'processResultAcknowledged', 'processResultCustodyRetired', 'processResultCustodyOrigin']);
  for (const key of ['networkStarted', 'requestStarted', 'processClaimed', 'processJoined', 'processResultAcknowledged', 'processResultCustodyRetired'])
    if (typeof io[key] !== 'boolean') throw new TypeError('dependency broker closure lacks a real boolean observation');
  controlWireInteger(io.connectionCount, 0, 600000); controlWireInteger(io.requestCount, 0, 600000); controlWireInteger(io.transferredBytes, 0, 21474836480);
  if ((io.requestCount as number) > (io.connectionCount as number) || io.networkStarted !== (io.connectionCount !== 0) || io.requestStarted !== (io.requestCount !== 0) ||
      !io.requestStarted && io.transferredBytes !== 0 || !['none', 'acknowledged', 'controller_joined'].includes(String(io.processResultCustodyOrigin)) ||
      io.processClaimed && (!io.processJoined || !io.processResultCustodyRetired) ||
      !io.processClaimed && (io.processJoined || io.processResultAcknowledged || io.processResultCustodyRetired) ||
      io.processResultAcknowledged !== (io.processResultCustodyOrigin === 'acknowledged') ||
      io.processResultCustodyRetired !== (io.processResultCustodyOrigin !== 'none') || v.evidenceDigest !== digestOmitting(v, 'evidenceDigest'))
    throw new TypeError('dependency broker closure substitutes its actual join, custody or complete digest');
  return immutableSnapshot(v) as DependencyBrokerDispatchClosureV1;
}
