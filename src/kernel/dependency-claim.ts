import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
/** One data root on the original broker-fenced Journal claim. It supplies no
 * native owner and does not change the process/fence XOR or add another claim. */
export type DependencyClaimEvidenceV1 = {
  schemaVersion: 1; format: 'cliq-dependency-claim-evidence-v1'; runId: string; opId: string; attempt: number; dispatchId: string;
  sourceCheckpointId: string; workerLaunchId: string; leaseEpoch: number; stateOwnerEpoch: number; supervisorInstanceId: string;
  dependencyPlanRef: string; dependencyPlanDigest: string; requestRef: string; requestDigest: string; targetRef: string; targetDigest: string;
  grantRef: string; sandboxLaunchSpecRef: string; sandboxLaunchSpecDigest: string; brokerFenceTokenDigest: string;
  createdAt: string; evidenceDigest: string;
};
export function decodeDependencyClaimEvidence(value: unknown): DependencyClaimEvidenceV1 {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'attempt', 'dispatchId', 'sourceCheckpointId',
    'workerLaunchId', 'leaseEpoch', 'stateOwnerEpoch', 'supervisorInstanceId', 'dependencyPlanRef', 'dependencyPlanDigest',
    'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest',
    'brokerFenceTokenDigest', 'createdAt', 'evidenceDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-claim-evidence-v1') throw new TypeError('dependency claim has another purpose');
  for (const key of ['runId', 'opId', 'dispatchId', 'sourceCheckpointId', 'workerLaunchId', 'supervisorInstanceId']) controlWireText(data[key]);
  controlWireInteger(data.attempt, 0, 1); controlWireInteger(data.leaseEpoch, 1); controlWireInteger(data.stateOwnerEpoch, 1);
  for (const key of ['dependencyPlanRef', 'dependencyPlanDigest', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef',
    'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'brokerFenceTokenDigest', 'evidenceDigest']) controlWireRef(data[key]);
  parseCanonicalTime(controlWireText(data.createdAt));
  if (data.evidenceDigest !== digestOmitting(data, 'evidenceDigest')) throw new TypeError('dependency claim digest differs');
  return data as DependencyClaimEvidenceV1;
}
