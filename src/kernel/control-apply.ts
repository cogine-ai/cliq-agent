import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { mergeBudgets } from './control-submit.js';
import { assertControlWireJson, controlWireRecord } from './control-wire-data.js';
import { assertAdmissionKey, assertArtifactRef, assertRequestId, normalizeBoundedText } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

/** Explicit delivery selects an existing verified result. Capture paths,
 * source manifests, recovery images, policy and native authority are resolved
 * exclusively by the authenticated Supervisor. */
export type RunApplyRequest = {
  protocolVersion: 1; method: 'run.apply'; requestId: string; requestDigest: string; admissionKey: string;
  sourceRunId: string; expectedRunResultRef: string;
  budgets?: { wallTimeMs?: number; toolCalls?: number };
  verifierExecutionGrantIds?: string[];
};
export type NormalizedRunApplyRequest = Omit<RunApplyRequest, 'budgets' | 'verifierExecutionGrantIds'> & {
  budgets: { wallTimeMs: number; toolCalls: number }; verifierExecutionGrantIds: string[];
};
export class InvalidRunApplyRequestError extends TypeError {}
const text = (value: unknown) => {
  if (typeof value !== 'string') throw new TypeError('delivery text must be a bounded string');
  return normalizeBoundedText(value, 1, 128);
};

/** Raw JCS request identity and normalized/defaulted intent deliberately stay
 * separate. No caller-supplied internal reference enters the resolved closure. */
export function normalizeRunApplyRequest(value: unknown): {
  request: NormalizedRunApplyRequest; originalRequest: object; originalRequestDigest: string;
} {
  try {
    assertControlWireJson(value);
    const data = controlWireRecord(value, ['protocolVersion', 'method', 'requestId', 'requestDigest',
      'admissionKey', 'sourceRunId', 'expectedRunResultRef'], ['budgets', 'verifierExecutionGrantIds']);
    if (data.protocolVersion !== 1 || data.method !== 'run.apply') throw new TypeError('expected protocol-v1 run.apply');
    const requestId = text(data.requestId), admissionKey = text(data.admissionKey), requestDigest = text(data.requestDigest);
    assertRequestId(requestId); assertAdmissionKey(admissionKey); assertArtifactRef(requestDigest);
    const expectedRunResultRef = text(data.expectedRunResultRef); assertArtifactRef(expectedRunResultRef);
    const budgets = data.budgets === undefined ? {} : controlWireRecord(data.budgets, [], ['wallTimeMs', 'toolCalls']);
    const normalizedBudgets = mergeBudgets(budgets);
    const suppliedGrants = data.verifierExecutionGrantIds === undefined ? [] : data.verifierExecutionGrantIds;
    if (!Array.isArray(suppliedGrants) || suppliedGrants.length > 32) throw new TypeError('delivery verifier grants exceed their bounded array');
    const verifierExecutionGrantIds = suppliedGrants.map(text);
    if (new Set(verifierExecutionGrantIds).size !== verifierExecutionGrantIds.length) throw new TypeError('delivery verifier grants must be unique');
    const { requestDigest: _digest, ...originalCore } = data;
    const originalRequest = { ...originalCore, requestDigest };
    if (canonicalJsonBytes(originalRequest).length > 1048576 || canonicalSha256(originalCore) !== requestDigest)
      throw new TypeError('delivery request digest or byte bound differs');
    return immutableSnapshot({ request: { protocolVersion: 1, method: 'run.apply', requestId, requestDigest, admissionKey,
      sourceRunId: text(data.sourceRunId), expectedRunResultRef,
      budgets: { wallTimeMs: normalizedBudgets.wallTimeMs, toolCalls: normalizedBudgets.toolCalls }, verifierExecutionGrantIds },
      originalRequest, originalRequestDigest: requestDigest });
  } catch (cause) {
    if (cause instanceof InvalidRunApplyRequestError) throw cause;
    throw new InvalidRunApplyRequestError('invalid inline run.apply request', { cause });
  }
}

export function runApplyIntentDigest(principalId: string, request: NormalizedRunApplyRequest): string {
  const { protocolVersion: _version, requestId: _requestId, requestDigest: _digest, admissionKey: _key, ...intent } = request;
  return canonicalSha256({ principalId, method: 'run.apply', request: intent });
}
