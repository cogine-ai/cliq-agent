import { types } from 'node:util';
import type { ArtifactRef } from './types.js';
import { controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

export type DerivedChildUnverifiedConsentV1 = {
  schemaVersion: 1; kind: 'derived_child_unverified_consent'; parentRunId: string; childRunId: string;
  delegateBatchItemId: string; delegateCallId: string; delegateCallIndex: number; delegateOpId: string;
  delegateOperationGrantRef: ArtifactRef; childCapabilityGrantCoreDigest: string; childRunSpecCoreDigest: string;
  allowUnverifiedHelper: true; createdAt: string; consentDigest: string;
};

/** Closed retained data only. The child reader must independently bind every
 * member to the original delegate, capability and committed child admission.
 * This decoder grants neither child admission nor verifier execution. */
export function decodeDerivedChildUnverifiedConsent(value: unknown): Readonly<DerivedChildUnverifiedConsentV1> {
  if (value !== null && typeof value === 'object' && types.isProxy(value)) throw new TypeError('child consent must be plain data');
  const data = controlWireRecord(value, ['schemaVersion', 'kind', 'parentRunId', 'childRunId', 'delegateBatchItemId',
    'delegateCallId', 'delegateCallIndex', 'delegateOpId', 'delegateOperationGrantRef', 'childCapabilityGrantCoreDigest',
    'childRunSpecCoreDigest', 'allowUnverifiedHelper', 'createdAt', 'consentDigest']);
  if (data.schemaVersion !== 1 || data.kind !== 'derived_child_unverified_consent' || data.allowUnverifiedHelper !== true)
    throw new TypeError('child consent has the wrong closed schema');
  for (const name of ['parentRunId', 'childRunId', 'delegateBatchItemId', 'delegateCallId', 'delegateOpId']) controlWireText(data[name]);
  controlWireInteger(data.delegateCallIndex);
  for (const name of ['delegateOperationGrantRef', 'childCapabilityGrantCoreDigest', 'childRunSpecCoreDigest', 'consentDigest']) controlWireRef(data[name]);
  parseCanonicalTime(controlWireText(data.createdAt, 24));
  if (data.parentRunId === data.childRunId || data.consentDigest !== digestOmitting(data, 'consentDigest'))
    throw new TypeError('child consent does not bind distinct Runs and its original digest');
  return immutableSnapshot(data) as Readonly<DerivedChildUnverifiedConsentV1>;
}
