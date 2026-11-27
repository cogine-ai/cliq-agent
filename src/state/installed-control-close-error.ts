import { KernelStorageError } from './errors.js';

// Powerless local cancellation ownership only. Neither this error nor its
// reader proves descriptor/domain retirement, authorizes a retry or grants any
// server operation. Peer/error strings cannot manufacture this identity.
const ownCloseErrors = new WeakSet<object>();
export function installedControlCloseError(): KernelStorageError {
  const error = new KernelStorageError('RECOVERY_REQUIRED', 'installed control client is closing');
  ownCloseErrors.add(error); return error;
}
export function isInstalledControlCloseError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && ownCloseErrors.has(error);
}
