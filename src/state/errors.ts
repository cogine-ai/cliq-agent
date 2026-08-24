export type KernelStorageErrorCode =
  | 'ADMISSION_KEY_CONFLICT'
  | 'REQUEST_ID_CONFLICT'
  | 'ARTIFACT_MISMATCH'
  | 'BUDGET_EXHAUSTED'
  | 'INVALID_REQUEST'
  | 'LEASE_FENCED'
  | 'NOT_FOUND'
  | 'RECOVERY_REQUIRED'
  | 'REVISION_CONFLICT'
  | 'STATE_TRANSITION_INVALID'
  | 'UNSUPPORTED_PLATFORM';

export class KernelStorageError extends Error {
  readonly code: KernelStorageErrorCode;
  readonly retryable = false as const;

  constructor(code: KernelStorageErrorCode, message: string) {
    super(message);
    this.name = 'KernelStorageError';
    this.code = code;
  }
}

export function isKernelStorageError(error: unknown): error is KernelStorageError {
  return error instanceof KernelStorageError;
}
