// Pure retained refusal data; no connection, StateOwner, Run or native proof.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { identityHash } from '../kernel/identity.js';
import { KernelStorageError } from './errors.js';

/** Opaque correlation only. Derive its UUID bits from the original inspection
 * identity so replay cannot borrow another inspection's internal response. */
function internalErrorId(inspectionId: string): string {
  const bytes = Buffer.from(identityHash('cliq-source-inspection-error-v1', inspectionId), 'base64url');
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export type SourceInspectionErrorResponse = { protocolVersion: 1; ok: false; method: 'run.submit' | 'run.apply'; error:
  | { schemaVersion: 1; messageCode: string; code: 'INVALID_REQUEST'; retryable: false; issues: Array<{ path: string; issueCode: string }> }
  | { schemaVersion: 1; messageCode: string; code: 'INTERNAL'; retryable: false; errorId: string }
  | { schemaVersion: 1; messageCode: string; code: 'CANCEL_REQUESTED' | 'BUDGET_EXHAUSTED' | 'ARTIFACT_MISMATCH'; retryable: false } };

export function createSourceInspectionErrorResponse(error: unknown, inspectionId: string, cancelled: boolean, method: SourceInspectionErrorResponse['method']): SourceInspectionErrorResponse {
  if (cancelled) return { protocolVersion: 1, ok: false, method,
    error: { schemaVersion: 1, messageCode: 'source_capture_cancelled', code: 'CANCEL_REQUESTED', retryable: false } };
  if (error instanceof KernelStorageError && (error.code === 'BUDGET_EXHAUSTED' || error.code === 'ARTIFACT_MISMATCH'))
    return { protocolVersion: 1, ok: false, method, error: { schemaVersion: 1,
      messageCode: 'source_capture_rejected', code: error.code, retryable: false } };
  if (error instanceof KernelStorageError || error instanceof TypeError) return { protocolVersion: 1, ok: false, method,
    error: { schemaVersion: 1, messageCode: 'source_capture_rejected', code: 'INVALID_REQUEST', retryable: false,
      issues: [{ path: 'source', issueCode: 'source_changed_or_unsupported' }] } };
  return { protocolVersion: 1, ok: false, method, error: { schemaVersion: 1, messageCode: 'source_capture_failed',
    code: 'INTERNAL', retryable: false, errorId: internalErrorId(inspectionId) } };
}
export function assertSourceInspectionErrorResponse(value: unknown, inspectionId: string, method: SourceInspectionErrorResponse['method']): asserts value is SourceInspectionErrorResponse {
  const data = value as SourceInspectionErrorResponse;
  if (!data || canonicalJsonBytes(data).length > 1_048_576 || Object.keys(data).sort().join() !== 'error,method,ok,protocolVersion' ||
      data.protocolVersion !== 1 || data.ok !== false || data.method !== method || !data.error || data.error.schemaVersion !== 1 ||
      data.error.retryable !== false || typeof data.error.messageCode !== 'string' || !/^[a-z_]{1,128}$/u.test(data.error.messageCode))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has the wrong closed response shape');
  const expected = ['schemaVersion', 'messageCode', 'code', 'retryable'];
  if (data.error.code === 'INVALID_REQUEST') {
    expected.push('issues');
    if (!Array.isArray(data.error.issues) || data.error.issues.length !== 1 ||
        Object.keys(data.error.issues[0]).sort().join() !== 'issueCode,path' || data.error.issues[0].path !== 'source' ||
        data.error.issues[0].issueCode !== 'source_changed_or_unsupported')
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has invalid redacted issues');
  } else if (data.error.code === 'INTERNAL') {
    expected.push('errorId');
    if (data.error.errorId !== internalErrorId(inspectionId))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has invalid correlation id');
  } else if (!['CANCEL_REQUESTED', 'BUDGET_EXHAUSTED', 'ARTIFACT_MISMATCH'].includes(data.error.code))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error is not produced by this recipe');
  if (Object.keys(data.error).sort().join() !== expected.sort().join())
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained source error has unknown fields');
}
