export type KernelStorageErrorCode =
  | 'ADMISSION_KEY_CONFLICT'
  | 'REQUEST_ID_CONFLICT'
  | 'ARTIFACT_MISMATCH'
  | 'AGENT_HANDOFF_PENDING'
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

  constructor(code: KernelStorageErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'KernelStorageError';
    this.code = code;
  }
}

/** Classify pure validation failures at the state seam; preserve fencing, conflict and infrastructure errors. */
export function stateOperation<Args extends unknown[], Result>(
  code: 'INVALID_REQUEST' | 'RECOVERY_REQUIRED', operation: (...args: Args) => Promise<Result>
): (...args: Args) => Promise<Result> {
  return async (...args) => {
    try { return await operation(...args); }
    catch (error) {
      if (error instanceof TypeError || error instanceof SyntaxError) throw new KernelStorageError(code, error.message, { cause: error });
      throw error;
    }
  };
}

export function isKernelStorageError(error: unknown): error is KernelStorageError {
  return error instanceof KernelStorageError;
}
