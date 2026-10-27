import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { parseCanonicalTime } from './identity.js';

/** Retained data only. The native owner is the sole live issuer; these bytes
 * cannot substitute for a registered endpoint, original GET or reader join. */
export type DependencyPackageFetchObservationV1 = {
  schemaVersion: 1; format: 'cliq-dependency-package-fetch-observation-v1'; runId: string; opId: string;
  invocationAttempt: number; dispatchId: string; brokerFenceTokenDigest: string; packageIndex: number; attempt: 1 | 2 | 3;
  receivedBytes: number; eof: boolean; observedAt: string;
} & ({ kind: 'complete' | 'integrity_mismatch' | 'http_error'; status: number } | {
  kind: 'transport_failed'; brokerCode: 'transport_interrupted'; networkStarted: boolean; requestStarted: boolean;
  ioJoined: true; retryableTransport: true;
});
export function decodeDependencyPackageFetchObservation(value: unknown): DependencyPackageFetchObservationV1 {
  assertControlWireJson(value);
  const kind = value && typeof value === 'object' ? (value as { kind?: unknown }).kind : undefined;
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'invocationAttempt', 'dispatchId',
    'brokerFenceTokenDigest', 'packageIndex', 'attempt', 'receivedBytes', 'eof', 'observedAt', 'kind',
    ...(kind === 'transport_failed' ? ['brokerCode', 'networkStarted', 'requestStarted', 'ioJoined', 'retryableTransport'] : ['status'])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-dependency-package-fetch-observation-v1' ||
      !['complete', 'integrity_mismatch', 'http_error', 'transport_failed'].includes(kind as string)) throw new TypeError('dependency GET observation has another purpose');
  for (const key of ['runId', 'opId', 'dispatchId']) controlWireText(data[key], 256);
  controlWireRef(data.brokerFenceTokenDigest); controlWireInteger(data.invocationAttempt, 0, 1);
  controlWireInteger(data.packageIndex, 0, 199_999); controlWireInteger(data.attempt, 1, 3); controlWireInteger(data.receivedBytes, 0, 67_108_864);
  parseCanonicalTime(controlWireText(data.observedAt));
  if (typeof data.eof !== 'boolean') throw new TypeError('dependency GET observation lacks its actual EOF state');
  if (kind === 'transport_failed') {
    if (data.brokerCode !== 'transport_interrupted' || data.ioJoined !== true || data.retryableTransport !== true ||
        data.attempt === 3 || typeof data.networkStarted !== 'boolean' || typeof data.requestStarted !== 'boolean' ||
        data.requestStarted && !data.networkStarted || data.receivedBytes !== 0 && !data.requestStarted)
      throw new TypeError('dependency transport retry has no original joined bounded failure');
  } else {
    controlWireInteger(data.status, 100, 599);
    if (kind === 'http_error' ? data.status === 200 : data.status !== 200 || data.eof !== true || data.receivedBytes === 0)
      throw new TypeError('dependency GET result substitutes its original HTTP or EOF outcome');
  }
  return data as DependencyPackageFetchObservationV1;
}
