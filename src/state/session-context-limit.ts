import { KernelStorageError } from './errors.js';
import type { ControlMethodV1, InstalledControlErrorV1 } from '../kernel/control-wire.js';

/** One fixed rejection reason. It carries no source text, mutable count,
 * credential, authorization or permission to retry the original request. */
export class SessionContextRequestLimitError extends KernelStorageError {
  constructor() {
    super('INVALID_REQUEST', 'Session context cannot fit the fixed model request limit; compact the Session before admitting a new Run');
  }
}

/** A fixed admission refusal, never a classification of arbitrary messages. */
export function sessionContextRequestLimitRefusal(method: ControlMethodV1 | undefined, error: unknown):
Extract<InstalledControlErrorV1, { code: 'INVALID_REQUEST' }> | undefined {
  if (method !== 'run.submit' || !(error instanceof SessionContextRequestLimitError)) return undefined;
  return { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false,
    messageCode: 'session.context_requires_compaction',
    issues: [{ path: 'sessionId', issueCode: 'session_context_requires_compaction' }] };
}
