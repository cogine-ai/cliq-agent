export type KernelStorageErrorCode =
  | 'ADMISSION_KEY_CONFLICT'
  | 'REQUEST_ID_CONFLICT'
  | 'ARTIFACT_MISMATCH'
  | 'AGENT_HANDOFF_PENDING'
  | 'MODEL_RETRY_PENDING'
  | 'BUDGET_EXHAUSTED'
  | 'EVENT_CURSOR_EXPIRED'
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

/** Internal resource-retirement failure, not an inspection outcome or a
 * caller-supplied proof. It must survive operation error handling so that an
 * unsettled descriptor/process cleanup can never mint a joined receipt. */
export class ResourceRetirementError extends KernelStorageError {
  constructor(message: string, cause: unknown) {
    super('RECOVERY_REQUIRED', message, { cause });
    this.name = 'ResourceRetirementError';
  }
}

/** A failed read must still join its siblings before the resource owner can
 * retire. Cleanup uncertainty takes precedence over ordinary read failures. */
export async function joinResourceOperations<T extends readonly unknown[] | []>(operations: T):
Promise<{ -readonly [P in keyof T]: Awaited<T[P]> }> {
  const results = await Promise.allSettled(operations as readonly unknown[]);
  const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
  const failure = failures.find(result => result.reason instanceof ResourceRetirementError) ?? failures[0];
  if (failure) throw failure.reason;
  return results.map(result => (result as PromiseFulfilledResult<unknown>).value) as { -readonly [P in keyof T]: Awaited<T[P]> };
}

/** Scheduling information, not an instruction to sleep inside a StateStore transaction. */
export class ModelRetryPendingError extends KernelStorageError {
  constructor(readonly nextAttempt: number, readonly notBefore: string) {
    super('MODEL_RETRY_PENDING', `model retry ${nextAttempt} is not eligible before ${notBefore}`);
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
