import { decodeCredentialFinalizeRequest, decodeInstalledControlEnvelope, type CredentialFinalizeRequest } from '../kernel/control-wire.js';
import type { CredentialAuthorityOperationV1 } from '../kernel/credential-authority.js';
import { KernelStorageError } from './errors.js';
import { CredentialScopeBusyError, type HeldInstalledRuntime } from './installed-runtime.js';
import { openInstalledControlTransport } from './installed-control-transport.js';

export type { CredentialFinalizeRequest } from '../kernel/control-wire.js';
export type InstalledCredentialSupervisor = Readonly<{
  finalize(request: CredentialFinalizeRequest): Promise<CredentialAuthorityOperationV1>;
  close(): Promise<void>;
}>;
function refuse(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Existing narrow diagnostic projection over the shared closed data decoder.
 * Arbitrary remote fields never become a local exception or diagnostic. */
export function decodeInstalledCredentialControlResult(response: unknown, method: 'control.hello' | 'credential.finalize'): Record<string, unknown> {
  const value = decodeInstalledControlEnvelope(response, method);
  if (!value.ok) {
    const error = value.error;
    if (error.code === 'RATE_LIMITED') throw new CredentialScopeBusyError();
    if (!['INVALID_REQUEST', 'INTERNAL', 'INCOMPATIBLE_PROTOCOL', 'NOT_FOUND', 'AUTHORIZATION_REQUIRED',
      'ARTIFACT_MISMATCH', 'UNSUPPORTED_PLATFORM', 'REQUEST_ID_CONFLICT'].includes(error.code))
      throw new TypeError('invalid installed credential control refusal');
    if (method === 'credential.finalize' && error.code === 'AUTHORIZATION_REQUIRED') {
      if (error.messageCode === 'credential.finalize.noncausal_time')
        refuse('installed Supervisor refused credential finalization because its timestamps are not causal');
      if (error.messageCode === 'credential.finalize.expired') refuse('installed Supervisor refused expired credential finalization');
    }
    refuse('installed Supervisor refused the authenticated credential operation');
  }
  return value.result as unknown as Record<string, unknown>;
}

/** Explicit ensure-start is credential-only; ordinary installed queries use
 * the same authenticated transport without starting a service. */
export async function ensureInstalledCredentialSupervisor(selected: HeldInstalledRuntime): Promise<InstalledCredentialSupervisor> {
  const transport = await openInstalledControlTransport(selected, 'credential');
  let running: Promise<CredentialAuthorityOperationV1> | undefined, closing: Promise<void> | undefined;
  let stopped = false;
  const client: InstalledCredentialSupervisor = Object.freeze({
    finalize(request) {
      if (this !== client) return Promise.reject(new TypeError('invalid installed credential client'));
      if (running || closing || stopped) return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'installed credential client is closed or busy'));
      let candidate: CredentialFinalizeRequest;
      try { candidate = decodeCredentialFinalizeRequest(request); }
      catch (cause) { return Promise.reject(new KernelStorageError('INVALID_REQUEST', 'invalid original credential continuation', { cause })); }
      const pending = (async () => {
        try {
          const response = await transport.request(candidate);
          if (!response.ok) decodeInstalledCredentialControlResult(response, 'credential.finalize');
          if (!response.ok) throw new TypeError('credential refusal projection did not refuse');
          return response.result.operation;
        } catch (error) {
          stopped = true; await transport.close(); throw error;
        }
      })();
      running = pending; void pending.finally(() => { running = undefined; }).catch(() => {}); return pending;
    },
    close() {
      if (this !== client) return Promise.reject(new TypeError('invalid installed credential client'));
      stopped = true;
      return closing ??= (async () => { await transport.close(); await Promise.allSettled(running ? [running] : []); })();
    }
  });
  return client;
}
